use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use crate::a9::blockchain::{BlockchainError, Transaction, MIN_RELAY_FEE_UNITS};
use crate::a9::codec;

const MEMPOOL_MAX_BYTES: usize = 50_000_000;
const MEMPOOL_MAX_TRANSACTIONS: usize = 50_000;
/// Per-sender queue depth. 250 lets a 200-recipient pool payout admit in one
/// batch call instead of two-blocks-with-retries; blast radius stays bounded
/// (250 x ~14.6 KB ≈ 3.7 MB queueable per sender against the 50 MB
/// fee-per-byte-priced pool).
const MEMPOOL_MAX_PER_ADDRESS: usize = 250;

/// Producer FEED cap: how many transaction bytes the template selector feeds
/// into one block. Policy, not consensus — consensus has accepted
/// MAX_BLOCK_WEIGHT_BYTES (3.5 MB) since genesis, so every deployed node
/// validates these blocks natively and mixed producer settings coexist.
/// Raised 1 MB -> 2 MB (step 1 of the staged program; ~30 TPS ceiling) with
/// deliberate margin kept below the consensus cap: the operating limit never
/// runs AT the design limit. Step 2 (3.5 MB) stays in reserve behind the
/// program's gates: clean synthetic full-block campaigns (orphan rate,
/// propagation, compact-reconstruction hit rate) and sustained organic demand.
/// Reversible by restarting producers with the old constant.
pub const MAX_BLOCK_SIZE: usize = 2_000_000;
// The producer must never assemble a block heavier than consensus validation
// accepts: a producer cap above the weight limit would mine permanently invalid
// blocks. Pinned at compile time so the staged cap raise (see
// docs/CONSENSUS_DECISIONS.md) cannot overshoot the envelope by edit error.
const _: () = assert!(MAX_BLOCK_SIZE <= crate::a9::blockchain::MAX_BLOCK_WEIGHT_BYTES);
/// Per-TRANSACTION admission cap, deliberately decoupled from the feed cap
/// above: raising the feed must never raise what one transaction may occupy
/// (a single feed-sized transaction could otherwise fill an entire block).
/// Held at the historical 1 MB — orders of magnitude above any legitimate
/// payment (~14.6 KB) — so admission behavior is unchanged by the feed raise.
pub const MAX_MEMPOOL_TX_BYTES: usize = 1_000_000;
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 2_000;

// Exact fee-per-byte ordering key: compares as the rational fee_units / size_bytes via
// integer cross-multiplication — no float division, no rounding, no NaN corner. (The f64
// form this replaces could round two distinct feerates onto the same double, silently
// demoting a strictly-better feerate to a timestamp tie.) Equality is RATIONAL equality
// (10/2 == 5/1), deliberately consistent with Ord: this is a fee VALUE, not a transaction
// identity — identity tie-breaks (timestamp, sender, tx_id) stay at the call sites, per
// the MempoolEntry note below. saturating_mul so absurd inputs clamp instead of wrapping
// the comparison; real values sit far inside i128 (fee_units is balance-bounded below
// 2^50, sizes are transaction-bounded).
#[derive(Debug, Clone, Copy)]
struct FeePerByte {
    fee_units: i128,
    size_bytes: u64,
}

impl PartialEq for FeePerByte {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
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
        self.fee_units
            .saturating_mul(i128::from(other.size_bytes))
            .cmp(&other.fee_units.saturating_mul(i128::from(self.size_bytes)))
    }
}

// Deliberately NO Ord/Eq: two DISTINCT transactions can share a fee_per_byte, so any
// ordered container keyed on the entry would silently collapse them — a paid transaction
// vanishing with no error and no log. (The removed impls claimed exactly that: Ord over
// fee_per_byte alone, with Eq asserted on top, violating the Ord contract for every
// equal-fee pair. Nothing called them; dead_code cannot flag trait impls.) Order per-site
// instead, ending in tx_id when a total order is needed — the selection comparator and
// the eviction heap tuple below both already do this.
#[derive(Debug)]
pub struct MempoolEntry {
    transaction: Transaction,
    tx_id: String,
    timestamp: u64,
    fee_per_byte: FeePerByte,
    size: usize,
}

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
        // Parsed once per process: this sits on the admission/prune paths, and
        // std::env::var takes the process env lock and allocates on every call.
        static TTL: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
        *TTL.get_or_init(|| {
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
        })
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
        self.admit(tx, true)
    }

    /// Re-admit a transaction REVERTED by a reorg. Identical to add_transaction
    /// except the relay fee floor is skipped: a reverted tx was consensus-valid
    /// in a mined block (possibly mined by a pre-floor node), and dropping it
    /// here would silently lose an already-made payment (the reorg re-queue
    /// exists precisely so reverted txs are not lost). All other caps — per-tx
    /// size, per-address, eviction, TTL — still apply, and this node's own
    /// template filter still declines to mine it.
    pub fn readmit_reverted(&mut self, tx: Transaction) -> Result<(), BlockchainError> {
        self.admit(tx, false)
    }

    fn admit(&mut self, tx: Transaction, enforce_floor: bool) -> Result<(), BlockchainError> {
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

        // Relay-policy fee floor (MIN_RELAY_FEE_UNITS): enforced at the mempool
        // choke point too, so the direct callers (reorg re-queue, startup
        // rehydration) can't re-admit a below-floor tx. Admission policy ONLY —
        // never part of block validity (see Blockchain::add_transaction). The
        // coinbase's pinned NETWORK_FEE (0.0005) clears the floor by 5x, so no
        // system tx is affected.
        if enforce_floor && tx.fee_units < MIN_RELAY_FEE_UNITS {
            return Err(BlockchainError::FeeBelowRelayFloor);
        }

        // Now do the expensive serialization
        let tx_size = codec::serialize(&tx)
            .map_err(|e| BlockchainError::SerializationError(Box::new(e)))?
            .len();

        // Admission uses the PER-TRANSACTION cap, not the block feed cap —
        // decoupled so feed raises can never widen single-transaction size.
        if tx_size > MAX_MEMPOOL_TX_BYTES {
            return Err(BlockchainError::InvalidTransaction);
        }

        // Per-address rate limit FIRST — a transaction that will be rejected must never trigger
        // eviction of another sender's transaction. Read the count in its own statement so
        // the DashMap guard is dropped before any eviction below.
        let at_address_cap = self
            .address_counts
            .get(&tx.sender)
            .map(|c| *c >= MEMPOOL_MAX_PER_ADDRESS)
            .unwrap_or(false);
        if at_address_cap {
            return Err(BlockchainError::RateLimitExceeded(
                "Too many transactions from this address".into(),
            ));
        }

        // Incoming fee-per-byte governs eviction: only strictly-cheaper residents are evictable,
        // so a low-fee tx can never displace a higher-fee one.
        let fee_per_byte = FeePerByte {
            fee_units: tx.fee_units,
            size_bytes: tx_size as u64,
        };

        // If the pool is at capacity, try to make room by evicting only strictly-cheaper
        // transactions — all-or-nothing. If that cannot free enough, reject WITHOUT evicting.
        let current_total_size = self.total_size.load(AtomicOrdering::SeqCst);
        let current_total_count = self.total_count.load(AtomicOrdering::SeqCst);
        let required_bytes = current_total_size
            .saturating_add(tx_size)
            .saturating_sub(MEMPOOL_MAX_BYTES);
        let required_count = current_total_count
            .saturating_add(1)
            .saturating_sub(MEMPOOL_MAX_TRANSACTIONS);
        if (required_bytes > 0 || required_count > 0)
            && !self.try_evict_below(required_bytes, required_count, fee_per_byte)
        {
            return Err(BlockchainError::RateLimitExceeded("Mempool is full".into()));
        }

        // Belt-and-suspenders: after a successful eviction plan there is room for the incoming tx.
        let final_size = self.total_size.load(AtomicOrdering::SeqCst) + tx_size;
        let final_count = self.total_count.load(AtomicOrdering::SeqCst) + 1;
        if final_size > MEMPOOL_MAX_BYTES || final_count > MEMPOOL_MAX_TRANSACTIONS {
            return Err(BlockchainError::RateLimitExceeded("Mempool is full".into()));
        }

        // Create entry
        let sender = tx.sender.clone();
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

    /// Decrement a sender's per-address mempool count by `n`, removing the entry when
    /// it reaches zero. CRITICAL: it decides whether to remove under the get_mut guard
    /// and drops that guard BEFORE calling remove — removing a key on the same DashMap
    /// while its RefMut is alive re-locks the shard and deadlocks the whole node. Must
    /// be called with NO other DashMap guard alive (never hold two DashMap guards).
    fn decrement_address_count(&self, addr: &str, n: usize) {
        let now_zero = match self.address_counts.get_mut(addr) {
            Some(mut count) => {
                *count = count.saturating_sub(n);
                *count == 0
            }
            None => false,
        };
        if now_zero {
            self.address_counts.remove(addr);
        }
    }

    pub fn clear_transaction(&mut self, tx: &Transaction) {
        let tx_id = tx.get_tx_id();
        self.tx_locator.remove(&tx_id);

        // Compute the removals under the `transactions` shard guard, then DROP that
        // guard before touching any other map. Holding a DashMap RefMut across a
        // lock acquisition on another shard/map risks a deadlock, and it previously
        // wedged the whole node during block finalization (mempool eviction).
        let (removed, removed_size, became_empty) = {
            let Some(mut addr_txs) = self.transactions.get_mut(&tx.sender) else {
                return;
            };
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
            (removed, removed_size, addr_txs.is_empty())
        };

        if removed == 0 {
            return;
        }
        // Reclaim the now-empty sender bucket so `transactions` never grows with
        // distinct-senders-EVER — its keys are walked on every template build
        // (get_transactions_for_block). The get_mut guard was dropped above; remove_if
        // re-checks emptiness atomically, so it can never delete a live bucket. Mirrors
        // decrement_address_count's decide-under-guard -> drop-guard -> remove pattern.
        if became_empty {
            self.transactions.remove_if(&tx.sender, |_, v| v.is_empty());
        }
        self.total_count.fetch_sub(removed, AtomicOrdering::SeqCst);
        self.total_size
            .fetch_sub(removed_size, AtomicOrdering::SeqCst);
        self.decrement_address_count(&tx.sender, removed);
    }

    pub fn find_transaction_by_id(&self, tx_id: &str) -> Option<Transaction> {
        // Resolve the sender via the O(1) tx_id -> sender locator, then scan only that sender's
        // bounded bucket (<= MEMPOOL_MAX_PER_ADDRESS) instead of the entire pool. The sender is
        // cloned so the locator guard is dropped before touching `transactions` (distinct maps).
        let sender = self.tx_locator.get(tx_id)?.value().clone();
        self.transactions
            .get(&sender)?
            .value()
            .iter()
            .find(|entry| entry.tx_id == tx_id)
            .map(|entry| entry.transaction.clone())
    }

    /// Zero-cost emptiness probe (atomic counter read — no locks, no scan).
    /// The miner's template rebuild runs every tip change (~5s); when the pool
    /// is empty it must not pay the full selection/prune path just to learn so.
    pub fn is_empty(&self) -> bool {
        self.total_count.load(AtomicOrdering::Relaxed) == 0
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
            // Compute removals under the transactions guard, then DROP it before
            // touching address_counts (never hold two DashMap guards; never remove a
            // key on a DashMap whose RefMut is alive — that deadlocks the node).
            let (removed_here, became_empty) =
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
                        self.total_count
                            .fetch_sub(removed_here, AtomicOrdering::SeqCst);
                        self.total_size
                            .fetch_sub(removed_size, AtomicOrdering::SeqCst);
                    }
                    (removed_here, txs.is_empty())
                } else {
                    (0, false)
                };
            // Guard dropped above; reclaim the now-empty bucket (see clear_transaction).
            if became_empty {
                self.transactions.remove_if(&addr, |_, v| v.is_empty());
            }
            if removed_here > 0 {
                removed += removed_here;
                self.decrement_address_count(&addr, removed_here);
            }
            // Keep the dedup index in lockstep (after dropping the transactions guard above).
            for id in &expired_ids {
                self.tx_locator.remove(id);
            }
        }

        removed
    }

    /// Try to free `required_space` bytes and/or `required_count` slots by evicting the
    /// lowest fee-per-byte transactions that are STRICTLY CHEAPER than `incoming_fee`.
    ///
    /// This scans the pool (O(N)) to build the candidate heap. That is DELIBERATE — a
    /// persistent fee-ordered index (O(log N) eviction) was considered and rejected: this only
    /// runs when the pool is already pegged at the FIXED 50k / 50MB cap, so N is a bounded
    /// constant (one O(50k) scan, sub-millisecond on any modern CPU) that does NOT grow as the
    /// chain grows. And it only fires under sustained congestion (inflow above the ~400 tx/s
    /// block-drain rate), where block throughput — not this eviction — is the actual bottleneck.
    /// So the incremental index would save a negligible amount of CPU exactly when CPU isn't the
    /// limit, in exchange for maintaining another structure in lockstep with `transactions` on
    /// every add/evict/prune/clear (a real correctness hazard). Not worth it; leave the scan.
    ///
    /// All-or-nothing: if the strictly-cheaper transactions cannot free enough, nothing is
    /// evicted and this returns `false` (the caller then rejects the incoming transaction).
    /// Two invariants this preserves:
    ///  * eviction is a no-op for a transaction that is about to be rejected — the caller only
    ///    invokes this after the incoming tx has passed the per-address cap, and here we
    ///    plan-then-commit so a doomed incoming tx never destroys a resident.
    ///  * a lower- or equal-fee incoming tx can never displace a higher-fee resident, because
    ///    only entries with `fee_per_byte < incoming_fee` are eviction candidates.
    fn try_evict_below(
        &mut self,
        required_space: usize,
        required_count: usize,
        incoming_fee: FeePerByte,
    ) -> bool {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        // Only transactions strictly cheaper than the incoming one are eviction candidates.
        // Within an equal-fee band the NEWEST goes first (Reverse(timestamp) inside the
        // min-tuple): selection confirms oldest-first, so evicting oldest-first would
        // destroy exactly the band member closest to confirmation while keeping the one
        // furthest from it — inverted queue fairness. Newest-first keeps eviction aligned
        // with the inclusion order the pool already promises.
        let mut candidates = BinaryHeap::new();
        for entry in self.transactions.iter() {
            let sender = entry.key();
            for tx in entry.value().iter() {
                if tx.fee_per_byte < incoming_fee {
                    candidates.push(Reverse((
                        tx.fee_per_byte,
                        Reverse(tx.timestamp),
                        sender.clone(),
                        tx.tx_id.clone(),
                        tx.size,
                    )));
                }
            }
        }

        // Plan removals cheapest-first WITHOUT mutating anything; bail out (evicting nothing)
        // the moment the strictly-cheaper set is exhausted before the requirement is met.
        let mut to_remove: HashMap<String, HashSet<String>> = HashMap::new();
        let mut space_freed = 0usize;
        let mut count_freed = 0usize;
        while space_freed < required_space || count_freed < required_count {
            match candidates.pop() {
                Some(Reverse((_, Reverse(_timestamp), sender, tx_id, size))) => {
                    to_remove.entry(sender).or_default().insert(tx_id);
                    space_freed += size;
                    count_freed += 1;
                }
                None => return false,
            }
        }

        // Requirement is satisfiable — commit the planned removals.
        for (addr, tx_ids) in to_remove {
            // Compute removals under the transactions guard, then DROP it before
            // touching address_counts (never hold two DashMap guards; never remove a
            // key on a DashMap whose RefMut is alive — that deadlocks the node).
            let (removed_here, became_empty) =
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
                    }
                    (removed_here, txs.is_empty())
                } else {
                    (0, false)
                };
            // Guard dropped above; reclaim the now-empty bucket (see clear_transaction).
            if became_empty {
                self.transactions.remove_if(&addr, |_, v| v.is_empty());
            }
            if removed_here > 0 {
                self.decrement_address_count(&addr, removed_here);
            }
            // Keep the dedup index in lockstep (after dropping the transactions guard above).
            for id in &tx_ids {
                self.tx_locator.remove(id);
            }
        }
        true
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BinaryHeap;

    fn rate(fee_units: i128, size_bytes: u64) -> FeePerByte {
        FeePerByte {
            fee_units,
            size_bytes,
        }
    }

    // THE decoupling guarantee behind the feed raise: a transaction larger
    // than the per-tx admission cap must be rejected even though it would fit
    // the (larger) block feed — otherwise raising the feed would let one
    // transaction fill an entire block.
    #[test]
    #[allow(clippy::assertions_on_constants)] // Named invariant: the regression is meaningful only while feed > per-tx cap.
    fn per_tx_admission_is_decoupled_from_the_feed_cap() {
        assert!(
            MAX_BLOCK_SIZE > MAX_MEMPOOL_TX_BYTES,
            "this regression only means something while the feed exceeds the per-tx cap"
        );
        let mut mp = Mempool::new();
        let mut oversize = tx_with("senderZ", 1, 1.0, 0.5);
        oversize.signature = Some("ab".repeat(MAX_MEMPOOL_TX_BYTES / 2 + 1_000));
        let res = mp.add_transaction(oversize);
        assert!(
            matches!(res, Err(BlockchainError::InvalidTransaction)),
            "above the per-tx cap must reject even though it fits the raised feed, got {:?}",
            res
        );
        mp.add_transaction(tx_with("senderZ", 2, 1.0, 0.5))
            .expect("a normal transaction still admits");
    }

    #[test]
    fn fee_per_byte_orders_highest_fee_first() {
        let low = rate(1, 1);
        let mid = rate(5, 2); // 2.5/byte
        let high = rate(10, 1);

        assert!(high > mid);
        assert!(mid > low);
        assert_eq!(high.partial_cmp(&mid), Some(high.cmp(&mid)));

        let mut heap = BinaryHeap::from([mid, high, low]);
        assert_eq!(heap.pop(), Some(high));
        assert_eq!(heap.pop(), Some(mid));
        assert_eq!(heap.pop(), Some(low));
        assert_eq!(heap.pop(), None);
    }

    // FeePerByte is a VALUE: equal rationals from different (fee, size) pairs compare
    // Equal AND eq — the Ord/Eq contract holds by construction (identity tie-breaks live
    // at the call sites, not in this type).
    #[test]
    fn fee_per_byte_equality_is_rational_not_structural() {
        assert_eq!(rate(10, 2), rate(5, 1));
        assert_eq!(rate(10, 2).cmp(&rate(5, 1)), Ordering::Equal);
        assert!(rate(10, 2) > rate(9, 2));
    }

    // The exactness the f64 form could not provide: (2^53 + 1) / 2^53 rounds to exactly
    // 1.0 as a double, so the old comparison saw a TIE between a strictly better feerate
    // and 1.0/byte and fell through to timestamp order. Cross-multiplication keeps them
    // strictly ordered.
    #[test]
    fn fee_per_byte_cross_multiplication_beats_f64_rounding() {
        let base: i128 = 1 << 53;
        let better = rate(base + 1, 1 << 53);
        let exactly_one = rate(1, 1);

        // the double quotients tie — this is the case the integer form exists for
        assert_eq!((base + 1) as f64 / base as f64, 1.0_f64);
        assert!(better > exactly_one);
        assert_ne!(better, exactly_one);
    }

    // Mempool admission does not verify signatures (that is the blockchain layer's job), so a
    // bare unsigned tx is a faithful mempool input. Distinct timestamps => distinct tx_ids.
    fn tx_with(sender: &str, ts: u64, amount: f64, fee: f64) -> Transaction {
        Transaction::new(
            sender.to_string(),
            "recipient".to_string(),
            amount,
            fee,
            ts,
            None,
        )
    }

    // M1: a transaction that is about to be rejected (sender at the per-address cap) must NOT
    // evict another sender's resident. The cap check now precedes eviction.
    #[test]
    fn capped_sender_rejected_without_evicting_others() {
        let mut mp = Mempool::new();
        let victim = tx_with("senderB", 1, 1.0, 0.001); // low fee: the old code's eviction target
        let victim_id = victim.get_tx_id();
        mp.add_transaction(victim).expect("victim admitted");
        for i in 0..MEMPOOL_MAX_PER_ADDRESS {
            mp.add_transaction(tx_with("senderA", 1000 + i as u64, 1.0, 0.001))
                .expect("filling sender A to its per-address cap");
        }
        // Simulate a globally-full pool so eviction WOULD run in the old order.
        mp.total_count
            .store(MEMPOOL_MAX_TRANSACTIONS, AtomicOrdering::SeqCst);
        // Sender A is at its cap; this high-fee tx could have evicted the victim in the old order.
        let res = mp.add_transaction(tx_with("senderA", 9999, 1.0, 100.0));
        assert!(
            matches!(res, Err(BlockchainError::RateLimitExceeded(_))),
            "capped sender must be rejected, got {:?}",
            res
        );
        assert!(
            mp.find_transaction_by_id(&victim_id).is_some(),
            "M1 regression: a doomed (cap-exceeded) tx evicted a resident"
        );
    }

    // Relay-policy floor: below-floor fees are rejected at the mempool choke
    // point (this also covers the direct reorg-requeue / rehydration callers,
    // which bypass Blockchain::add_transaction).
    #[test]
    fn below_floor_fee_rejected_at_mempool() {
        let mut mp = Mempool::new();
        let res = mp.add_transaction(tx_with("senderZ", 1, 1.0, 0.0));
        assert!(
            matches!(res, Err(BlockchainError::FeeBelowRelayFloor)),
            "zero-fee tx must be rejected by the floor, got {:?}",
            res
        );
        // 9_999 units is just under the floor; 10_000 exactly is admitted.
        let res = mp.add_transaction(tx_with("senderZ", 2, 1.0, 0.00009999));
        assert!(matches!(res, Err(BlockchainError::FeeBelowRelayFloor)));
        mp.add_transaction(tx_with("senderZ", 3, 1.0, 0.0001))
            .expect("floor-exact fee must be admitted");
    }

    // Reorg continuity: a REVERTED tx (consensus-valid in a mined block,
    // possibly mined by a pre-floor node) must be re-admittable below the
    // floor — dropping it would silently lose an already-made payment.
    #[test]
    fn reverted_below_floor_tx_is_readmitted() {
        let mut mp = Mempool::new();
        let tx = tx_with("senderR", 1, 1.0, 0.0);
        let id = tx.get_tx_id();
        assert!(matches!(
            mp.add_transaction(tx.clone()),
            Err(BlockchainError::FeeBelowRelayFloor)
        ));
        mp.readmit_reverted(tx)
            .expect("reverted below-floor tx must be readmitted");
        assert!(mp.find_transaction_by_id(&id).is_some());
    }

    // M2: a low-fee incoming tx cannot displace a higher-fee resident when the pool is full.
    #[test]
    fn low_fee_incoming_cannot_evict_higher_fee_resident() {
        let mut mp = Mempool::new();
        let high = tx_with("rich", 1, 1.0, 100.0);
        let high_id = high.get_tx_id();
        mp.add_transaction(high)
            .expect("high-fee resident admitted");
        mp.total_count
            .store(MEMPOOL_MAX_TRANSACTIONS, AtomicOrdering::SeqCst);
        let low = tx_with("poor", 2, 1.0, 0.001);
        let low_id = low.get_tx_id();
        let res = mp.add_transaction(low);
        assert!(
            matches!(res, Err(BlockchainError::RateLimitExceeded(_))),
            "low-fee tx that cannot displace must be rejected, got {:?}",
            res
        );
        assert!(
            mp.find_transaction_by_id(&high_id).is_some(),
            "M2 regression: higher-fee resident evicted by a cheaper tx"
        );
        assert!(mp.find_transaction_by_id(&low_id).is_none());
    }

    // Empty-bucket reclaim: removing a sender's LAST tx must drop its `transactions` key, so the
    // map never accumulates empty buckets for distinct-senders-ever (walked every template build).
    // (1) CONFIRMED path — clear_transaction.
    #[test]
    fn clear_transaction_reclaims_empty_sender_bucket() {
        let mut mp = Mempool::new();
        mp.add_transaction(tx_with("senderA", 1, 1.0, 0.001))
            .expect("admit A1");
        mp.add_transaction(tx_with("senderA", 2, 1.0, 0.001))
            .expect("admit A2");
        mp.add_transaction(tx_with("senderB", 3, 1.0, 0.001))
            .expect("admit B1");
        assert!(mp.transactions.contains_key("senderA"));

        // Remove A's first tx: bucket kept (A still has one).
        mp.clear_transaction(&tx_with("senderA", 1, 1.0, 0.001));
        assert!(
            mp.transactions.contains_key("senderA"),
            "bucket must remain while A still holds a tx"
        );
        // Remove A's last tx: empty bucket must be reclaimed; B's bucket untouched.
        mp.clear_transaction(&tx_with("senderA", 2, 1.0, 0.001));
        assert!(
            !mp.transactions.contains_key("senderA"),
            "an emptied sender bucket must be reclaimed"
        );
        assert!(
            mp.transactions.contains_key("senderB"),
            "a non-empty sender bucket must remain"
        );
    }

    // (2) EXPIRED path — prune_expired (default mempool TTL is 600s).
    #[test]
    fn prune_expired_reclaims_empty_sender_bucket() {
        let mut mp = Mempool::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        mp.add_transaction(tx_with("stale_sender", 1, 1.0, 0.001))
            .expect("admit stale tx");
        mp.add_transaction(tx_with("fresh_sender", 2, 1.0, 0.001))
            .expect("admit fresh tx");
        assert!(mp.transactions.contains_key("stale_sender"));

        // Mempool TTL keys on ARRIVAL time (MempoolEntry.timestamp), not the signed tx ts.
        // Backdate the stale sender's entry past the 600s default TTL so prune_expired evicts it.
        {
            let mut bucket = mp.transactions.get_mut("stale_sender").unwrap();
            for e in bucket.iter_mut() {
                e.timestamp = now.saturating_sub(700);
            }
        } // drop the guard before prune_expired iterates the map

        let pruned = mp.prune_expired();
        assert_eq!(pruned, 1, "only the stale tx should be pruned");
        assert!(
            !mp.transactions.contains_key("stale_sender"),
            "the emptied stale-sender bucket must be reclaimed"
        );
        assert!(
            mp.transactions.contains_key("fresh_sender"),
            "the fresh sender's bucket must remain"
        );
    }

    // (3) EVICTED path — a high-fee incoming displaces a low-fee resident when the pool is full.
    #[test]
    fn eviction_reclaims_empty_sender_bucket() {
        let mut mp = Mempool::new();
        mp.add_transaction(tx_with("poor_sender", 1, 1.0, 0.001))
            .expect("admit low-fee resident");
        assert!(mp.transactions.contains_key("poor_sender"));

        // Simulate a globally-full pool so the incoming high-fee tx triggers eviction.
        mp.total_count
            .store(MEMPOOL_MAX_TRANSACTIONS, AtomicOrdering::SeqCst);
        mp.add_transaction(tx_with("rich_sender", 2, 1.0, 100.0))
            .expect("high-fee tx admitted by displacing the low-fee resident");

        assert!(
            !mp.transactions.contains_key("poor_sender"),
            "the evicted sender's emptied bucket must be reclaimed"
        );
        assert!(
            mp.transactions.contains_key("rich_sender"),
            "the admitted high-fee sender must have a bucket"
        );
    }

    // became_empty==FALSE control for the EVICTION path: evicting SOME (not all) of a sender's txs
    // must KEEP the bucket and the survivor. Guards against a regression to an unconditional
    // remove (which would evaporate the still-populated bucket and silently drop the survivor).
    #[test]
    fn eviction_keeps_bucket_on_partial_removal() {
        let mut mp = Mempool::new();
        // One sender with a high-fee survivor and a low-fee victim.
        let survivor = tx_with("mixed_sender", 1, 1.0, 1.0);
        let survivor_id = survivor.get_tx_id();
        mp.add_transaction(survivor).expect("admit survivor");
        mp.add_transaction(tx_with("mixed_sender", 2, 1.0, 0.001))
            .expect("admit low-fee victim");

        // Full pool: one incoming high-fee tx frees exactly one slot -> only the cheapest tx
        // (mixed_sender's 0.001) is evicted; the 1.0-fee survivor stays.
        mp.total_count
            .store(MEMPOOL_MAX_TRANSACTIONS, AtomicOrdering::SeqCst);
        mp.add_transaction(tx_with("rich_sender", 3, 1.0, 100.0))
            .expect("high-fee tx admitted");

        assert!(
            mp.transactions.contains_key("mixed_sender"),
            "a partially-evicted sender's bucket must be KEPT (became_empty==false)"
        );
        assert!(
            mp.find_transaction_by_id(&survivor_id).is_some(),
            "the higher-fee survivor must remain in the pool"
        );
    }

    // became_empty==FALSE control for the EXPIRY path: expiring one of a sender's two txs keeps
    // the bucket and the fresh survivor.
    #[test]
    fn prune_expired_keeps_bucket_on_partial_removal() {
        let mut mp = Mempool::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let survivor = tx_with("mixed_sender", 1, 1.0, 0.001);
        let survivor_id = survivor.get_tx_id();
        let victim_id = tx_with("mixed_sender", 2, 1.0, 0.001).get_tx_id();
        mp.add_transaction(survivor).expect("admit survivor");
        mp.add_transaction(tx_with("mixed_sender", 2, 1.0, 0.001))
            .expect("admit victim");

        // Backdate ONLY the victim's arrival timestamp past the 600s TTL.
        {
            let mut bucket = mp.transactions.get_mut("mixed_sender").unwrap();
            for e in bucket.iter_mut() {
                if e.tx_id == victim_id {
                    e.timestamp = now.saturating_sub(700);
                }
            }
        }

        let pruned = mp.prune_expired();
        assert_eq!(pruned, 1, "only the backdated victim should be pruned");
        assert!(
            mp.transactions.contains_key("mixed_sender"),
            "a partially-expired sender's bucket must be KEPT (became_empty==false)"
        );
        assert!(
            mp.find_transaction_by_id(&survivor_id).is_some(),
            "the fresh survivor must remain in the pool"
        );
    }

    // M2 (positive): a high-fee incoming tx DOES displace a strictly-cheaper resident.
    #[test]
    fn high_fee_incoming_evicts_lower_fee_resident() {
        let mut mp = Mempool::new();
        let low = tx_with("poor", 1, 1.0, 0.001);
        let low_id = low.get_tx_id();
        mp.add_transaction(low).expect("low-fee resident admitted");
        mp.total_count
            .store(MEMPOOL_MAX_TRANSACTIONS, AtomicOrdering::SeqCst);
        let high = tx_with("rich", 2, 1.0, 100.0);
        let high_id = high.get_tx_id();
        let res = mp.add_transaction(high);
        assert!(
            res.is_ok(),
            "high-fee tx should displace a cheaper resident: {:?}",
            res
        );
        assert!(mp.find_transaction_by_id(&high_id).is_some());
        assert!(
            mp.find_transaction_by_id(&low_id).is_none(),
            "the strictly-cheaper resident should have been evicted"
        );
    }

    // Within an equal-fee band, eviction must take the NEWEST first: selection confirms
    // oldest-first, so the oldest band member is closest to confirmation and is the one
    // the pool should fight to keep.
    #[test]
    fn try_evict_below_evicts_newest_first_within_an_equal_fee_band() {
        let mut mp = Mempool::new();
        // Same amount/fee, same-length senders, timestamps in the same msgpack width
        // class -> identical serialized size, therefore an exactly equal fee-per-byte.
        let older = tx_with("aa", 1_000_000, 1.0, 0.001);
        let newer = tx_with("ab", 1_000_001, 1.0, 0.001);
        let older_id = older.get_tx_id();
        let newer_id = newer.get_tx_id();
        mp.add_transaction(older).expect("older admitted");
        mp.add_transaction(newer).expect("newer admitted");
        // Ordering keys on ARRIVAL time (deliberately: the signed timestamp is
        // sender-chosen, and keying fairness on it would let backdaters jump the queue).
        // Both entries above arrive within the same second, so give the band a real
        // arrival order to exercise the tie-break.
        if let Some(mut txs) = mp.transactions.get_mut("aa") {
            txs[0].timestamp = 100;
        }
        if let Some(mut txs) = mp.transactions.get_mut("ab") {
            txs[0].timestamp = 200;
        }

        let freed = mp.try_evict_below(0, 1, rate(1_000_000, 1));
        assert!(freed, "one slot from two candidates must succeed");
        assert!(
            mp.find_transaction_by_id(&older_id).is_some(),
            "the oldest of the equal-fee band is next in line to confirm and must survive"
        );
        assert!(
            mp.find_transaction_by_id(&newer_id).is_none(),
            "the newest of the equal-fee band is evicted first"
        );
    }

    // The eviction planner is all-or-nothing: if the strictly-cheaper set cannot satisfy the
    // requirement, it evicts nothing and reports failure.
    #[test]
    fn try_evict_below_is_all_or_nothing() {
        let mut mp = Mempool::new();
        let only = tx_with("a", 1, 1.0, 0.001);
        let only_id = only.get_tx_id();
        mp.add_transaction(only).expect("resident admitted");
        // Ask to free TWO slots with an incoming fee above everything; only one cheaper tx exists.
        let freed = mp.try_evict_below(0, 2, rate(1_000_000, 1));
        assert!(!freed, "cannot free 2 slots from a single candidate");
        assert!(
            mp.find_transaction_by_id(&only_id).is_some(),
            "all-or-nothing: nothing must be evicted on a failed plan"
        );
    }
}
