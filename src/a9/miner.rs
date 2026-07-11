use hex;
use indicatif::{ProgressBar, ProgressStyle};
use log::warn;
use num_cpus;
use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::time::interval;

use crate::a9::blockchain::{
    current_finalize_stage, finalize_stage_name, pow_target_bytes, pow_target_from_difficulty,
    set_finalize_stage,
    BlockchainError, NETWORK_FEE,
};
use crate::a9::blockchain::{Block, Blockchain, Transaction};

// Constants for ProgPOW
const PROGPOW_LANES: usize = 16;
const PROGPOW_REGS: usize = 32;
const MINING_PROGRESS_TEMPLATE: &str = "{prefix} {bar:37.cyan/blue} {pos:>7}/{len:7} {msg}";
const MINING_SUCCESS_TEMPLATE: &str = "{prefix} {bar:36.cyan/blue}> {pos:>7}/{len:7} {msg}";
/// How often (in nonces, per thread) the hot loop polls the ATOMIC tip-change
/// counter. One Acquire load — cheap enough to keep tight so a solved block
/// elsewhere aborts wasted work within microseconds.
const TIP_CHANGE_CHECK_INTERVAL: u64 = 256;
/// How often (in nonces, per thread) the loop additionally re-confirms the
/// parent against the DATABASE (try_read + get_last_block = a sled read and a
/// full block decode). This is only a belt-and-braces net under the atomic
/// counter — every commit path bumps the counter — but at the old 256-nonce
/// cadence it was hundreds of thousands of block decodes per second across a
/// many-core miner, throttling the very machines the thread pool freed up.
const DB_TIP_CONFIRM_INTERVAL: u64 = 262_144;

#[derive(Debug, Clone, Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    Encryption,
    #[error("Decryption failed")]
    Decryption,
    #[error("Key generation failed")]
    KeyGeneration,
}

#[derive(Error, Debug)]
pub enum MiningError {
    #[error("Mining timeout exceeded")]
    Timeout,
    #[error("Invalid difficulty target: {0}")]
    InvalidDifficulty(String),
    #[error("Invalid transaction fee")]
    InvalidFee,
    #[error("Insufficient mining reward")]
    InsufficientReward,
    #[error("Crypto operation failed")]
    CryptoError(#[from] CryptoError),
    #[error("Block not found")]
    BlockNotFound,
    #[error("Invalid data: {0}")]
    InvalidData(&'static str),
    #[error("Out of bounds error")]
    OutOfBounds,
    #[error("Transaction Error")]
    TransactionError,
    #[error("Mining failed: {0}")]
    MiningFailed(String),
    #[error("Blockchain error: {0}")]
    BlockchainError(String),
    #[error("Invalid target format")]
    InvalidTargetFormat,
    #[error("Invalid hash format")]
    InvalidHashFormat,
    #[error("Exceeded max nonce limit")]
    MaxNonceExceeded,
    #[error("Serialization error")]
    SerializationError,
    #[error("Validation error")]
    ValidationError,
    #[error("Wallet error")]
    WalletError,
}

impl From<Box<dyn std::error::Error>> for MiningError {
    fn from(error: Box<dyn std::error::Error>) -> Self {
        MiningError::MiningFailed(error.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ProgPowHeader {
    pub number: u32,
    pub parent_hash: [u8; 32],
    pub timestamp: u64,
    pub merkle_root: [u8; 32],
}

#[derive(Debug, Default)]
pub struct ProgPowCache {
    pub mix_state: [u32; PROGPOW_REGS],
    pub lanes: [[u32; PROGPOW_REGS]; PROGPOW_LANES],
    pub dag_entries: Vec<u32>,
}

impl ProgPowCache {
    pub fn initialize_cache() -> ProgPowCache {
        ProgPowCache {
            mix_state: [0; PROGPOW_REGS], // Initialize the mix_state to default values
            lanes: [[0; PROGPOW_REGS]; PROGPOW_LANES], // Initialize lanes to default values
            dag_entries: Vec::new(),      // Initialize an empty Vec for dag_entries
        }
    }
}

#[derive(Clone, Default)]
pub struct ProgPowTransaction {
    pub fee: f64,
    pub sender: String,
    pub recipient: String,
    pub amount: f64,
    pub timestamp: u64,
    pub signature: Option<String>,
    pub pub_key: Option<String>,
    pub sig_hash: Option<String>,
}

impl From<ProgPowTransaction> for Transaction {
    fn from(p: ProgPowTransaction) -> Self {
        Transaction {
            sender: p.sender,
            recipient: p.recipient,
            amount_units: Transaction::to_units(p.amount),
            fee_units: Transaction::to_units(p.fee),
            timestamp: p.timestamp,
            signature: p.signature,
            pub_key: p.pub_key,
            sig_hash: p.sig_hash,
        }
    }
}

#[derive(Debug)]
pub struct MiningManager {
    blockchain: Arc<RwLock<Blockchain>>,
}

impl MiningManager {
    pub fn new(blockchain: Arc<RwLock<Blockchain>>) -> Self {
        Self { blockchain }
    }

    pub async fn mine_block(
        &self,
        header: &mut BlockHeader,
        transactions: &[ProgPowTransaction],
        max_nonce: u64,
        miner_address: String,
        _reward_amount: f64,
    ) -> Result<(u64, String, Block), MiningError> {
        let transactions: Vec<Transaction> = transactions
            .iter()
            .map(|ptx| {
                let mut tx = Transaction::new(
                    ptx.sender.clone(),
                    ptx.recipient.clone(),
                    ptx.amount,
                    ptx.fee,
                    ptx.timestamp,
                    ptx.signature.clone(),
                );
                tx.pub_key = ptx.pub_key.clone();
                tx.sig_hash = ptx.sig_hash.clone();
                tx
            })
            .collect();
        let mining_transactions = transactions;

        let found = Arc::new(AtomicBool::new(false));
        let abort_for_tip_change = Arc::new(AtomicBool::new(false));
        let result_nonce = Arc::new(AtomicU64::new(0));
        let result_timestamp = Arc::new(AtomicU64::new(0));
        let result_difficulty = Arc::new(AtomicU64::new(0));
        let hash_result = Arc::new(Mutex::new(Vec::with_capacity(32)));

        if max_nonce == 0 {
            return Err(MiningError::MaxNonceExceeded);
        }

        // All cores by default. The old hard cap of 32 left big rigs (e.g. a
        // 258-thread EPYC) mining at ~12% capacity; header PoW is embarrassingly
        // parallel, so there is no reason to cap below the machine. Operators
        // who want to keep cores free set ALPHANUMERIC_MINE_THREADS.
        let num_threads = std::env::var("ALPHANUMERIC_MINE_THREADS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map(|n| n.clamp(1, 1024))
            .unwrap_or_else(|| num_cpus::get())
            .max(1);
        let nonces_per_thread = max_nonce.div_ceil(num_threads as u64);

        let progress_bar = Arc::new(Mutex::new(ProgressBar::new(max_nonce)));
        {
            if let Ok(pb) = progress_bar.lock() {
                let style = ProgressStyle::with_template(MINING_PROGRESS_TEMPLATE)
                    .map_err(|e| MiningError::MiningFailed(format!("Progress style error: {}", e)))?
                    .progress_chars("=  ");
                pb.set_style(style);
                pb.set_prefix(format!("Block #{}", header.number));
                pb.enable_steady_tick(Duration::from_millis(100));
            } else {
                return Err(MiningError::MiningFailed(
                    "Progress bar lock poisoned".to_string(),
                ));
            }
        }

        let mut current_nonce: u64 = 0;
        // Progress-bar refresh cadence per thread. try_lock keeps losers from
        // blocking, but with hundreds of threads even the attempts are traffic —
        // 8192 still repaints many times a second while staying off the hot path.
        let update_interval = 8192;
        let tip_change_counter = {
            let blockchain_guard = self.blockchain.read().await;
            blockchain_guard.tip_change_counter_handle()
        };

        'mining: loop {
            let (
                previous_difficulty,
                previous_block_hash,
                previous_block_timestamp,
                current_height,
                template_tip_version,
            ) = {
                let blockchain_guard = self.blockchain.read().await;
                let previous_block = blockchain_guard.get_last_block().ok_or_else(|| {
                    MiningError::BlockchainError("Previous block not found".to_string())
                })?;
                (
                    previous_block.difficulty,
                    previous_block.hash,
                    previous_block.timestamp,
                    previous_block.index.saturating_add(1),
                    blockchain_guard.tip_change_version(),
                )
            };

            if current_height > header.number {
                header.number = current_height;
                if let Ok(pb) = progress_bar.lock() {
                    pb.set_prefix(format!("Block #{}", header.number));
                    pb.set_message("New network tip detected; rebuilding block template...");
                }
                current_nonce = 0;
                continue;
            }

            let block_transactions = {
                // READ, not write: this only reads confirmed balances to select txs
                // (get_confirmed_balance is &self). Holding the EXCLUSIVE write lock here
                // across get_confirmed_balance().await — which lazily runs a full
                // balances-index rebuild right after a competing block advances the tip —
                // starved block-ingest's write() and wedged the write-preferring RwLock,
                // freezing the miner whenever the mempool held a pending tx. A shared read
                // guard lets ingest proceed and never blocks it for the whole rebuild.
                let blockchain_lock = self.blockchain.read().await;
                let mut selected_regular = Vec::with_capacity(mining_transactions.len());
                let mut sender_debits: HashMap<String, i128> = HashMap::new();

                for transaction in &mining_transactions {
                    let confirmed_balance = blockchain_lock
                        .get_confirmed_balance(&transaction.sender)
                        .await?;
                    let confirmed_units = Transaction::to_units(confirmed_balance);
                    let already_selected = sender_debits
                        .get(&transaction.sender)
                        .copied()
                        .unwrap_or_default();
                    let required_units = transaction.total_debit_units();

                    if confirmed_units.saturating_sub(already_selected) >= required_units {
                        selected_regular.push(transaction.clone());
                        *sender_debits.entry(transaction.sender.clone()).or_default() +=
                            required_units;
                    }
                }

                let reward_amount = blockchain_lock.get_block_reward(&selected_regular);
                let reward_timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let reward_tx = Transaction::new(
                    "MINING_REWARDS".to_string(),
                    miner_address.clone(),
                    reward_amount,
                    NETWORK_FEE,
                    reward_timestamp,
                    None,
                );
                let mut selected = Vec::with_capacity(selected_regular.len() + 1);
                selected.push(reward_tx);
                selected.extend(selected_regular);
                selected
            };

            let merkle_root = Blockchain::calculate_merkle_root(&block_transactions)
                .map_err(|e| MiningError::BlockchainError(e.to_string()))?;

            let progress_bar = Arc::clone(&progress_bar);

            found.store(false, Ordering::Release);
            abort_for_tip_change.store(false, Ordering::Release);

            let result_timestamp = Arc::clone(&result_timestamp);
            let result_difficulty = Arc::clone(&result_difficulty);
            let abort_for_tip_change_check = Arc::clone(&abort_for_tip_change);
            let tip_change_counter_check = Arc::clone(&tip_change_counter);
            let blockchain_for_tip_checks = Arc::clone(&self.blockchain);
            let expected_parent_index = header.number.saturating_sub(1);

            let mining_result: Result<(), MiningError> = (0..num_threads as u64)
                .into_par_iter()
                .try_for_each(|thread_id| -> Result<(), MiningError> {
                    let mut local_header = header.clone();
                    local_header.merkle_root = merkle_root;
                    let range_end = current_nonce.saturating_add(max_nonce);
                    let start_nonce =
                        current_nonce.saturating_add(thread_id.saturating_mul(nonces_per_thread));
                    if start_nonce >= range_end {
                        return Ok(());
                    }
                    let end_nonce = start_nonce.saturating_add(nonces_per_thread).min(range_end);
                    let mut cached_timestamp = 0u64;
                    let mut cached_difficulty = 0u64;
                    // Target as fixed-width big-endian bytes: for 256-bit values,
                    // lexicographic [u8; 32] comparison IS numeric comparison, so
                    // the hot loop compares the hash directly and never heap-
                    // allocates a BigUint per nonce (the allocator was the scaling
                    // ceiling on many-core rigs). Equivalence is unit-tested
                    // (pow_byte_compare_matches_biguint_compare in blockchain.rs).
                    let mut cached_target_bytes = [0u8; 32];

                    for nonce in start_nonce..end_nonce {
                        if found.load(Ordering::Relaxed)
                            || abort_for_tip_change_check.load(Ordering::Relaxed)
                        {
                            return Ok(());
                        }

                        // Don't create full Block - just calculate hash directly
                        // We only need the full block when we find a valid nonce
                        let timestamp = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        if timestamp != cached_timestamp {
                            cached_timestamp = timestamp;
                            cached_difficulty = Block::consensus_next_difficulty(
                                previous_difficulty,
                                timestamp.saturating_sub(previous_block_timestamp),
                                local_header.number,
                            );
                            cached_target_bytes =
                                pow_target_bytes(&pow_target_from_difficulty(cached_difficulty));
                        }
                        let hash = {
                            let mut header_data = [0u8; 92];
                            let mut offset = 0;

                            header_data[offset..offset + 4]
                                .copy_from_slice(&local_header.number.to_le_bytes());
                            offset += 4;

                            header_data[offset..offset + 32].copy_from_slice(&previous_block_hash);
                            offset += 32;

                            header_data[offset..offset + 8]
                                .copy_from_slice(&timestamp.to_le_bytes());
                            offset += 8;

                            header_data[offset..offset + 8].copy_from_slice(&nonce.to_le_bytes());
                            offset += 8;

                            header_data[offset..offset + 8]
                                .copy_from_slice(&cached_difficulty.to_le_bytes());
                            offset += 8;

                            header_data[offset..offset + 32].copy_from_slice(&merkle_root);

                            *blake3::hash(&header_data).as_bytes()
                        };

                        if hash <= cached_target_bytes {
                            if !found.swap(true, Ordering::Relaxed) {
                                result_nonce.store(nonce, Ordering::Release);
                                result_timestamp.store(timestamp, Ordering::Release);
                                result_difficulty.store(cached_difficulty, Ordering::Release);
                                if let Ok(mut hash_guard) = hash_result.lock() {
                                    *hash_guard = hash.to_vec();
                                }
                            }
                            return Ok(());
                        }

                        if nonce % TIP_CHANGE_CHECK_INTERVAL == 0 {
                            if tip_change_counter_check.load(Ordering::Acquire)
                                != template_tip_version
                            {
                                abort_for_tip_change_check.store(true, Ordering::Release);
                                return Ok(());
                            }
                        }

                        if nonce % DB_TIP_CONFIRM_INTERVAL == 0 {
                            if let Ok(blockchain) = blockchain_for_tip_checks.try_read() {
                                if let Some(tip) = blockchain.get_last_block() {
                                    if tip.index != expected_parent_index
                                        || tip.hash != previous_block_hash
                                    {
                                        abort_for_tip_change_check.store(true, Ordering::Release);
                                        return Ok(());
                                    }
                                }
                            }
                        }

                        if nonce % update_interval == 0 {
                            if let Ok(pb) = progress_bar.try_lock() {
                                pb.set_position(nonce.saturating_sub(current_nonce));
                                let hash_hex = hex::encode(hash);
                                pb.set_message(format!(
                                    "Hash: {} (Difficulty: {})",
                                    &hash_hex[..16],
                                    cached_difficulty
                                ));
                            }

                            // Avoid blocking inside rayon threads; height changes will be picked
                            // up on the next outer loop iteration.
                        }
                    }
                    Ok(())
                });

            if mining_result.is_err() {
                if let Ok(pb) = progress_bar.lock() {
                    pb.finish_with_message("Mining error occurred");
                }
                return Err(MiningError::MiningFailed(
                    "Mining operation failed".to_string(),
                ));
            }

            if abort_for_tip_change.load(Ordering::Acquire) && !found.load(Ordering::Acquire) {
                let latest_height = {
                    let blockchain_guard = self.blockchain.read().await;
                    blockchain_guard
                        .get_last_block()
                        .map(|block| block.index.saturating_add(1))
                };
                if let Some(height) = latest_height {
                    header.number = height;
                }
                current_nonce = 0;
                if let Ok(pb) = progress_bar.lock() {
                    pb.reset();
                    pb.set_prefix(format!("Block #{}", header.number));
                    pb.set_message("New network tip detected; mining next block...");
                }
                continue;
            }

            if found.load(Ordering::Relaxed) {
                let nonce = result_nonce.load(Ordering::Acquire);
                let found_timestamp = result_timestamp.load(Ordering::Acquire);
                let found_difficulty = result_difficulty.load(Ordering::Acquire);
                let hash = match hash_result.lock() {
                    Ok(guard) => guard.clone(),
                    Err(_) => {
                        return Err(MiningError::MiningFailed(
                            "Hash result lock poisoned".to_string(),
                        ))
                    }
                };
                let hash_string = hex::encode(&hash);
                let mined_index = header.number;

                let mut new_block = Block {
                    index: mined_index,
                    previous_hash: previous_block_hash,
                    timestamp: found_timestamp,
                    transactions: block_transactions,
                    nonce,
                    difficulty: found_difficulty,
                    hash: [0u8; 32],
                    merkle_root,
                };

                // Use the hash found during mining (which met the target)
                new_block.hash = hash
                    .try_into()
                    .map_err(|_| MiningError::InvalidHashFormat)?;
                let mined_block = new_block.clone();

                // Separate verification step with timeout and logging
                match tokio::time::timeout(Duration::from_secs(8), async {
                    let blockchain_lock = self.blockchain.read().await;
                    blockchain_lock.validate_new_block(&new_block).await
                })
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        if let Ok(pb) = progress_bar.lock() {
                            pb.finish_with_message("Block verification failed");
                        }
                        warn!("Block verification failed: {}", e);
                        return Err(MiningError::BlockchainError(e.to_string()));
                    }
                    Err(_) => {
                        if let Ok(pb) = progress_bar.lock() {
                            pb.finish_with_message("Block verification timed out");
                        }
                        warn!("Block verification timed out");
                        return Err(MiningError::BlockchainError(
                            "Block verification timed out".to_string(),
                        ));
                    }
                }

                set_finalize_stage(0);
                let blockchain_lock = self.blockchain.write().await;

                let finalize_future = async {
                    let tip = blockchain_lock.get_last_block();
                    if let Some(tip_block) = tip {
                        if tip_block.hash != previous_block_hash
                            || tip_block.index + 1 != new_block.index
                        {
                            return Err(BlockchainError::InvalidBlockHeader);
                        }
                    }

                    blockchain_lock
                        .finalize_block(new_block, miner_address.clone())
                        .await
                };
                tokio::pin!(finalize_future);
                let mut ticker = interval(Duration::from_millis(750));
                let finalize_start = Instant::now();
                loop {
                    tokio::select! {
                        res = &mut finalize_future => {
                            match res {
                                Ok(()) => {
                                    if let Ok(pb) = progress_bar.lock() {
                                        if let Ok(style) =
                                            ProgressStyle::with_template(MINING_SUCCESS_TEMPLATE)
                                        {
                                            pb.set_style(style.progress_chars("=  "));
                                        }
                                        pb.set_position(max_nonce);
                                        pb.finish_with_message("Block mined successfully!");
                                    }
                                    return Ok((nonce, hash_string, mined_block));
                                }
                                Err(e) => {
                                    if matches!(e, BlockchainError::InvalidBlockHeader) {
                                        // Reuse the write guard already held above (acquired at
                                        // the top of this finalize block). Acquiring a SECOND
                                        // guard on the same RwLock while this task holds the
                                        // write guard is a reentrant self-deadlock on tokio's
                                        // non-reentrant RwLock — this was the permanent freeze
                                        // whenever the miner lost a block race. get_last_block
                                        // is &self, so it is safe under the held guard.
                                        let stale_template = blockchain_lock
                                            .get_last_block()
                                            .map(|block| {
                                                (
                                                    block.index.saturating_add(1),
                                                    block.hash != previous_block_hash
                                                        || block.index.saturating_add(1)
                                                            != mined_index,
                                                )
                                            });
                                        if let Some((height, true)) = stale_template {
                                            header.number = height;
                                            current_nonce = 0;
                                            if let Ok(pb) = progress_bar.lock() {
                                                pb.reset();
                                                pb.set_prefix(format!("Block #{}", header.number));
                                                pb.set_message(
                                                    "Solved a stale height (another miner's block was adopted — no reward); mining the new tip...",
                                                );
                                            }
                                            continue 'mining;
                                        }
                                    }

                                    if let Ok(pb) = progress_bar.lock() {
                                        pb.finish_with_message("Block finalization failed");
                                    }
                                    warn!("Block finalization failed: {}", e);
                                    return Err(MiningError::BlockchainError(e.to_string()));
                                }
                            }
                        }
                        _ = ticker.tick() => {
                            if finalize_start.elapsed() > Duration::from_secs(15) {
                                let stage = current_finalize_stage();
                                let stage_name = finalize_stage_name(stage);
                                if let Ok(pb) = progress_bar.lock() {
                                    pb.finish_with_message(format!(
                                        "Block finalization timed out (stage: {})",
                                        stage_name
                                    ));
                                }
                                warn!(
                                    "Block finalization timed out at stage {} ({})",
                                    stage, stage_name
                                );
                                return Err(MiningError::BlockchainError(format!(
                                    "Block finalization timed out at stage {} ({})",
                                    stage, stage_name
                                )));
                            }
                            if let Ok(pb) = progress_bar.lock() {
                                pb.set_message("Finalizing block...");
                            }
                        }
                    }
                }
            }

            current_nonce = current_nonce
                .checked_add(max_nonce)
                .ok_or(MiningError::MaxNonceExceeded)?;
            if let Ok(pb) = progress_bar.lock() {
                pb.reset();
                pb.set_message("Starting next nonce range...");
            };
        }
    }
}

pub struct Miner {
    manager: MiningManager,
}

impl Miner {
    pub fn new(_blockchain: Arc<RwLock<Blockchain>>, manager: MiningManager) -> Self {
        Miner { manager }
    }

    pub async fn mine_block(
        &self,
        header: &mut BlockHeader,
        transactions: &[ProgPowTransaction],
        max_nonce: u64,
        miner_address: String,
        reward_amount: f64,
    ) -> Result<(u64, String, Block), MiningError> {
        self.manager
            .mine_block(
                header,
                transactions,
                max_nonce,
                miner_address,
                reward_amount,
            )
            .await
            .map_err(|e| MiningError::MiningFailed(e.to_string()))
    }
}

impl From<BlockchainError> for MiningError {
    fn from(error: BlockchainError) -> Self {
        MiningError::BlockchainError(error.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub number: u32,
    pub parent_hash: [u8; 32],
    pub timestamp: u64,
    pub merkle_root: [u8; 32],
    pub difficulty: u64,
}
