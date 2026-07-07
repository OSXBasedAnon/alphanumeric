use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use dashmap::DashMap;

use crate::a9::blockchain::{Blockchain, BlockchainError, Transaction};
use crate::a9::bpos::BlockHeaderInfo;
use crate::a9::codec;

type CheckpointQueue = Arc<RwLock<VecDeque<([u8; 32], u64)>>>;

const MEMPOOL_MAX_BYTES: usize = 50_000_000;
const MEMPOOL_MAX_TRANSACTIONS: usize = 50_000;
const MEMPOOL_MAX_PER_ADDRESS: usize = 100;
const MAX_CHECKPOINT_HEADERS: usize = 1_000;
const CHECKPOINT_INTERVAL: u64 = 300; // 5 minutes

pub const MAX_BLOCK_SIZE: usize = 1_000_000;
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 2_000;

#[derive(Debug, Clone, Copy)]
struct FeePerByte(f64);

impl PartialEq for FeePerByte {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for FeePerByte {}

impl PartialOrd for FeePerByte {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FeePerByte {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.total_cmp(&other.0)
    }
}

#[derive(Debug, PartialEq)]
pub struct MempoolEntry {
    transaction: Transaction,
    tx_id: String,
    timestamp: u64,
    fee_per_byte: FeePerByte,
    size: usize,
}

impl PartialOrd for MempoolEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MempoolEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.fee_per_byte.cmp(&other.fee_per_byte)
    }
}

impl Eq for MempoolEntry {}

// Prune at most this often, NOT on every insert. A full expiry scan on every single insert
// was O(N) per admission (quadratic-fill DoS as the pool grows toward MEMPOOL_MAX_TRANSACTIONS).
const PRUNE_INTERVAL_SECS: usize = 30;

#[derive(Debug)]
pub struct Mempool {
    transactions: DashMap<String, Vec<MempoolEntry>>,
    // tx_id -> sender: an O(1) dedup index so admission no longer scans the entire pool to
    // reject a duplicate (was O(N) on every insert). Kept in lockstep with `transactions` on
    // every add / clear / prune / evict.
    tx_locator: DashMap<String, String>,
    total_size: AtomicUsize,
    total_count: AtomicUsize,
    address_counts: DashMap<String, usize>,
    // Unix-seconds of the last expiry scan, so prune_expired is rate-limited off the hot path.
    last_prune: AtomicUsize,
}

impl Mempool {
    fn mempool_ttl_secs() -> Option<u64> {
        const DEFAULT_TTL_SECS: u64 = 600;
        let ttl = std::env::var("ALPHANUMERIC_MEMPOOL_TTL_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_TTL_SECS);
        if ttl == 0 {
            None
        } else {
            Some(ttl)
        }
    }

    pub fn new() -> Self {
        Self {
            transactions: DashMap::new(),
            tx_locator: DashMap::new(),
            total_size: AtomicUsize::new(0),
            total_count: AtomicUsize::new(0),
            address_counts: DashMap::new(),
            last_prune: AtomicUsize::new(0),
        }
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), BlockchainError> {
        // Rate-limit the expiry scan off the admission hot path (was a full O(N) scan on every
        // insert). Lazy TTL: a stale tx lingers at most PRUNE_INTERVAL_SECS longer, harmless.
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as usize)
            .unwrap_or(0);
        if now_secs.saturating_sub(self.last_prune.load(AtomicOrdering::Relaxed))
            >= PRUNE_INTERVAL_SECS
        {
            self.last_prune.store(now_secs, AtomicOrdering::Relaxed);
            self.prune_expired();
        }
        let tx_id = tx.get_tx_id();
        // O(1) dedup via the locator index instead of scanning the whole pool.
        if self.tx_locator.contains_key(&tx_id) {
            return Ok(());
        }

        // Now do the expensive serialization
        let tx_size = codec::serialize(&tx)
            .map_err(|e| BlockchainError::SerializationError(Box::new(e)))?
            .len();

        if tx_size > MAX_BLOCK_SIZE {
            return Err(BlockchainError::InvalidTransaction);
        }

        // Quick checks first
        let current_total_size = self.total_size.load(AtomicOrdering::SeqCst);
        let current_total_count = self.total_count.load(AtomicOrdering::SeqCst);
        let required_bytes = current_total_size
            .saturating_add(tx_size)
            .saturating_sub(MEMPOOL_MAX_BYTES);
        let required_count = current_total_count
            .saturating_add(1)
            .saturating_sub(MEMPOOL_MAX_TRANSACTIONS);
        if required_bytes > 0 || required_count > 0 {
            self.evict_lowest_fee_transactions(required_bytes, required_count);
        }

        // Rate limit check (cheap)
        match self.address_counts.get(&tx.sender) {
            Some(count) if *count >= MEMPOOL_MAX_PER_ADDRESS => {
                return Err(BlockchainError::RateLimitExceeded(
                    "Too many transactions from this address".into(),
                ))
            }
            _ => {}
        }

        // Final size check after eviction
        let final_size = self.total_size.load(AtomicOrdering::SeqCst) + tx_size;
        let final_count = self.total_count.load(AtomicOrdering::SeqCst) + 1;
        if final_size > MEMPOOL_MAX_BYTES || final_count > MEMPOOL_MAX_TRANSACTIONS {
            return Err(BlockchainError::RateLimitExceeded("Mempool is full".into()));
        }

        // Create entry
        let sender = tx.sender.clone();
        let fee_per_byte = FeePerByte(tx.fee() / tx_size as f64);
        let entry = MempoolEntry {
            transaction: tx,
            tx_id: tx_id.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            fee_per_byte,
            size: tx_size,
        };

        // Batch updates atomically
        self.transactions
            .entry(sender.clone())
            .or_default()
            .push(entry);
        self.tx_locator.insert(tx_id, sender.clone());
        self.address_counts
            .entry(sender)
            .and_modify(|e| *e += 1)
            .or_insert(1);
        self.total_size.fetch_add(tx_size, AtomicOrdering::SeqCst);
        self.total_count.fetch_add(1, AtomicOrdering::SeqCst);

        Ok(())
    }

    pub fn get_transactions_for_block(&self) -> Vec<Transaction> {
        use std::cmp::Reverse;
        use std::collections::{BinaryHeap, HashMap};

        let mut selected = Vec::with_capacity(MAX_TRANSACTIONS_PER_BLOCK);
        let mut total_size = 0usize;

        // Fee-descending ordering of each sender's queued entries, so we can walk a
        // sender's queue best-first with a cursor. Previously only ONE tx per sender
        // was ever offered, so a hot wallet with a long payout queue drained at 1
        // tx/block; the block now fills up to MAX_TRANSACTIONS_PER_BLOCK / MAX_BLOCK_SIZE
        // across all senders. Per-sender solvency is still enforced downstream (the
        // miner's balance-aware tx selection and block validation), so offering
        // multiple txs per sender here cannot produce an overspending block.
        let mut sender_order: HashMap<String, Vec<usize>> = HashMap::new();

        // Max-heap of each sender's NEXT candidate:
        //   (fee_per_byte, older-first, sender, size, entry_idx, cursor_pos)
        let mut heap: BinaryHeap<(FeePerByte, Reverse<u64>, String, usize, usize, usize)> =
            BinaryHeap::new();

        for entry in self.transactions.iter() {
            let sender = entry.key();
            let txs = entry.value();
            if txs.is_empty() {
                continue;
            }
            let mut order: Vec<usize> = (0..txs.len()).collect();
            order.sort_by(|&a, &b| {
                txs[b]
                    .fee_per_byte
                    .cmp(&txs[a].fee_per_byte)
                    .then_with(|| txs[a].timestamp.cmp(&txs[b].timestamp))
            });
            let first = order[0];
            heap.push((
                txs[first].fee_per_byte,
                Reverse(txs[first].timestamp),
                sender.clone(),
                txs[first].size,
                first,
                0usize,
            ));
            sender_order.insert(sender.clone(), order);
        }

        // Greedily take the globally highest-fee candidate, then re-offer that
        // sender's next-best remaining tx (cursor advance) until the block is full.
        while let Some((_, _, sender, size, entry_idx, cursor)) = heap.pop() {
            if selected.len() >= MAX_TRANSACTIONS_PER_BLOCK || total_size >= MAX_BLOCK_SIZE {
                break;
            }

            if total_size + size <= MAX_BLOCK_SIZE {
                if let Some(txs) = self.transactions.get(&sender) {
                    if let Some(entry) = txs.get(entry_idx) {
                        selected.push(entry.transaction.clone());
                        total_size += size;
                    }
                }
            }

            // Re-offer this sender's next-best remaining transaction.
            if let Some(&next_idx) = sender_order
                .get(&sender)
                .and_then(|order| order.get(cursor + 1))
            {
                if let Some(txs) = self.transactions.get(&sender) {
                    if let Some(entry) = txs.get(next_idx) {
                        heap.push((
                            entry.fee_per_byte,
                            Reverse(entry.timestamp),
                            sender.clone(),
                            entry.size,
                            next_idx,
                            cursor + 1,
                        ));
                    }
                }
            }
        }

        selected
    }

    pub fn clear_transaction(&mut self, tx: &Transaction) {
        let tx_id = tx.get_tx_id();
        self.tx_locator.remove(&tx_id);
        if let Some(mut addr_txs) = self.transactions.get_mut(&tx.sender) {
            let mut removed = 0usize;
            let mut removed_size = 0usize;
            addr_txs.retain(|entry| {
                let keep = entry.tx_id != tx_id;
                if !keep {
                    removed += 1;
                    removed_size += entry.size;
                }
                keep
            });
            if removed > 0 {
                self.total_count.fetch_sub(removed, AtomicOrdering::SeqCst);
                self.total_size
                    .fetch_sub(removed_size, AtomicOrdering::SeqCst);
                if let Some(mut count) = self.address_counts.get_mut(&tx.sender) {
                    *count = count.saturating_sub(removed);
                    if *count == 0 {
                        self.address_counts.remove(&tx.sender);
                    }
                }
            }
        }
    }

    pub fn find_transaction_by_id(&self, tx_id: &str) -> Option<Transaction> {
        for entry in self.transactions.iter() {
            for tx in entry.value().iter() {
                if tx.tx_id == tx_id {
                    return Some(tx.transaction.clone());
                }
            }
        }
        None
    }

    pub fn get_all_transactions(&self) -> Vec<Transaction> {
        let mut out = Vec::with_capacity(self.total_count.load(AtomicOrdering::Relaxed));
        for entry in self.transactions.iter() {
            for tx in entry.value().iter() {
                out.push(tx.transaction.clone());
            }
        }
        out
    }

    pub fn prune_expired(&mut self) -> usize {
        let Some(ttl_secs) = Self::mempool_ttl_secs() else {
            return 0;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut to_remove: HashMap<String, HashSet<String>> = HashMap::new();
        for entry in self.transactions.iter() {
            let sender = entry.key();
            for tx in entry.value().iter() {
                if now.saturating_sub(tx.timestamp) > ttl_secs {
                    to_remove
                        .entry(sender.clone())
                        .or_default()
                        .insert(tx.tx_id.clone());
                }
            }
        }

        if to_remove.is_empty() {
            return 0;
        }

        let mut removed = 0usize;
        for (addr, expired_ids) in to_remove {
            if let Some(mut txs) = self.transactions.get_mut(&addr) {
                let mut removed_here = 0usize;
                let mut removed_size = 0usize;
                txs.retain(|entry| {
                    let keep = !expired_ids.contains(&entry.tx_id);
                    if !keep {
                        removed_here += 1;
                        removed_size += entry.size;
                    }
                    keep
                });
                if removed_here > 0 {
                    removed += removed_here;
                    self.total_count
                        .fetch_sub(removed_here, AtomicOrdering::SeqCst);
                    self.total_size
                        .fetch_sub(removed_size, AtomicOrdering::SeqCst);
                    if let Some(mut count) = self.address_counts.get_mut(&addr) {
                        *count = count.saturating_sub(removed_here);
                        if *count == 0 {
                            self.address_counts.remove(&addr);
                        }
                    }
                }
            }
            // Keep the dedup index in lockstep (after dropping the transactions guard above).
            for id in &expired_ids {
                self.tx_locator.remove(id);
            }
        }

        removed
    }

    fn evict_lowest_fee_transactions(&mut self, required_space: usize, required_count: usize) {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        let mut space_freed = 0;
        let mut count_freed = 0;

        // Use a min-heap to efficiently find lowest fee transactions across all senders
        // Store (fee, timestamp, sender, size) - removed idx as it's not used
        let mut candidates = BinaryHeap::new();

        for entry in self.transactions.iter() {
            let sender = entry.key();
            for tx in entry.value().iter() {
                candidates.push(Reverse((
                    tx.fee_per_byte,
                    tx.timestamp,
                    sender.clone(),
                    tx.tx_id.clone(),
                    tx.size,
                )));
            }
        }

        // Evict lowest fee transactions until we have enough space
        let mut to_remove: HashMap<String, HashSet<String>> = HashMap::new();

        while space_freed < required_space || count_freed < required_count {
            if let Some(Reverse((_, _timestamp, sender, tx_id, size))) = candidates.pop() {
                to_remove.entry(sender).or_default().insert(tx_id);
                space_freed += size;
                count_freed += 1;
            } else {
                break;
            }
        }

        // Batch removals
        for (addr, tx_ids) in to_remove {
            if let Some(mut txs) = self.transactions.get_mut(&addr) {
                let mut removed_here = 0usize;
                let mut removed_size = 0usize;
                txs.retain(|entry| {
                    let keep = !tx_ids.contains(&entry.tx_id);
                    if !keep {
                        removed_here += 1;
                        removed_size += entry.size;
                    }
                    keep
                });
                if removed_here > 0 {
                    self.total_size
                        .fetch_sub(removed_size, AtomicOrdering::SeqCst);
                    self.total_count
                        .fetch_sub(removed_here, AtomicOrdering::SeqCst);
                    if let Some(mut count) = self.address_counts.get_mut(&addr) {
                        *count = count.saturating_sub(removed_here);
                        if *count == 0 {
                            self.address_counts.remove(&addr);
                        }
                    }
                }
            }
            // Keep the dedup index in lockstep (after dropping the transactions guard above).
            for id in &tx_ids {
                self.tx_locator.remove(id);
            }
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct TemporalVerification {
    verified_headers: Arc<DashMap<[u8; 32], u64>>,
    checkpoint_hashes: CheckpointQueue,
    last_checkpoint: Arc<RwLock<u64>>,
}

impl TemporalVerification {
    const MAX_VERIFICATIONS: usize = 10_000;
    const VERIFICATION_TIMEOUT: u64 = 3600; // 1 hour in seconds
                                            // Initialize a new TemporalVerification struct
    pub fn new() -> Self {
        Self {
            verified_headers: Arc::new(DashMap::new()),
            checkpoint_hashes: Arc::new(RwLock::new(VecDeque::with_capacity(
                MAX_CHECKPOINT_HEADERS,
            ))),
            last_checkpoint: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn initialize_from_blockchain(
        &self,
        blockchain: &Blockchain,
    ) -> Result<(), BlockchainError> {
        // Get all existing blocks
        let blocks = blockchain.get_blocks();

        // Clear existing verifications
        self.verified_headers.clear();

        // Add all existing blocks to the verification cache
        for block in blocks {
            let header_info = BlockHeaderInfo {
                height: block.index,
                hash: block.hash,
                prev_hash: block.previous_hash,
                timestamp: block.timestamp,
            };
            self.verified_headers.insert(block.hash, block.timestamp);

            // Also add to checkpoint hashes if appropriate
            if self
                .verified_headers
                .len()
                .is_multiple_of(MAX_CHECKPOINT_HEADERS / 10)
            {
                self.update_checkpoint_hashes(&header_info).await;
            }
        }

        Ok(())
    }

    pub fn add_verification(&self, header: &BlockHeaderInfo) {
        let now = self.current_timestamp();

        // Cleanup old verifications
        self.verified_headers
            .retain(|_, timestamp| now.saturating_sub(*timestamp) < Self::VERIFICATION_TIMEOUT);

        // Manage capacity
        if self.verified_headers.len() >= Self::MAX_VERIFICATIONS {
            let mut entries: Vec<_> = self.verified_headers.iter().collect();
            entries.sort_by_key(|entry| *entry.value());

            let to_remove = Self::MAX_VERIFICATIONS / 10;
            for entry in entries.iter().take(to_remove) {
                self.verified_headers.remove(entry.key());
            }
        }

        let should_checkpoint = self
            .last_checkpoint
            .try_read()
            .map(|last| now.saturating_sub(*last) >= CHECKPOINT_INTERVAL)
            .unwrap_or(false);

        // Add new verification
        self.verified_headers.insert(header.hash, now);

        // Trigger checkpoint if needed
        if should_checkpoint {
            let hash = header.hash;
            let checkpoint_hashes = self.checkpoint_hashes.clone();
            let last_checkpoint = self.last_checkpoint.clone();

            tokio::spawn(async move {
                let mut checkpoint_guard = checkpoint_hashes.write().await;
                checkpoint_guard.push_back((hash, now));

                if checkpoint_guard.len() > MAX_CHECKPOINT_HEADERS {
                    checkpoint_guard.pop_front();
                }

                let mut last_guard = last_checkpoint.write().await;
                *last_guard = now;
            });
        }
    }

    // Verify a header based on temporal consistency
    pub fn verify_header(&self, header: &BlockHeaderInfo) -> bool {
        // Special case for genesis block or first block after genesis
        if header.height <= 1 {
            return true;
        }

        // Regular verification
        if let Some(last_verified_timestamp) = self.verified_headers.get(&header.prev_hash) {
            let now = self.current_timestamp();
            header.timestamp > *last_verified_timestamp && header.timestamp <= now
        } else {
            // Only fail if we should have the previous hash
            header.height <= 1
        }
    }

    // Add a verified header to the map and update checkpoint hashes
    pub async fn add_verified_header(&self, header: &BlockHeaderInfo) {
        self.verified_headers.insert(header.hash, header.timestamp);
        self.update_checkpoint_hashes(header).await;
    }

    // Update the list of checkpoint hashes
    async fn update_checkpoint_hashes(&self, header: &BlockHeaderInfo) {
        let mut checkpoint_hashes = self.checkpoint_hashes.write().await; // Use `.await` here
        checkpoint_hashes.push_back((header.hash, header.timestamp));
        // Maintain the fixed size for the checkpoint list
        if checkpoint_hashes.len() > MAX_CHECKPOINT_HEADERS {
            checkpoint_hashes.pop_front();
        }
    }

    // Create a checkpoint based on the time interval
    pub async fn create_checkpoint(&self) {
        let now = self.current_timestamp();
        let mut last_checkpoint = self.last_checkpoint.write().await;

        if now.saturating_sub(*last_checkpoint) < CHECKPOINT_INTERVAL {
            return;
        }
        *last_checkpoint = now;
    }

    // Retrieve the latest checkpoint hash and timestamp
    pub async fn get_last_checkpoint(&self) -> Option<([u8; 32], u64)> {
        let checkpoint_hashes = self.checkpoint_hashes.read().await; // Use `.await` here
        checkpoint_hashes.back().cloned() // Return the most recent checkpoint (if any)
    }

    // Get the current timestamp (seconds since Unix epoch)
    fn current_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Default for TemporalVerification {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BinaryHeap;

    #[test]
    fn fee_per_byte_orders_highest_fee_first() {
        let low = FeePerByte(1.0);
        let mid = FeePerByte(2.5);
        let high = FeePerByte(10.0);

        assert!(high > mid);
        assert!(mid > low);
        assert_eq!(high.partial_cmp(&mid), Some(high.cmp(&mid)));

        let mut heap = BinaryHeap::from([mid, high, low]);
        assert_eq!(heap.pop(), Some(high));
        assert_eq!(heap.pop(), Some(mid));
        assert_eq!(heap.pop(), Some(low));
        assert_eq!(heap.pop(), None);
    }
}
