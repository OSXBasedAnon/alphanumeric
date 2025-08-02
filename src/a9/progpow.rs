use aes_gcm::KeyInit;
use byteorder::{ByteOrder, LittleEndian};
use futures_util::TryFutureExt;
use hex;
use indicatif::{ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use num_bigint::{BigUint, ToBigUint};
use num_cpus;
use num_traits::ToPrimitive;
use pqcrypto_traits::sign::DetachedSignature;
use rand::Rng;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::a9::blockchain::BlockchainError;
use crate::a9::blockchain::{Block, Blockchain, Transaction};
use crate::a9::wallet::Wallet;

// Constants for ProgPOW
const MAX_NONCE: u64 = 100000000;
const PROGPOW_LANES: usize = 16;
const PROGPOW_REGS: usize = 32;
const PROGPOW_CACHE_BYTES: usize = 16 * 1024;
const PROGPOW_CNT_DAG: u32 = 64;
const PROGPOW_CNT_CACHE: u32 = 12;
const PERIOD_LENGTH: u32 = 50;

pub const MAX_TARGET_BYTES: [u8; 32] = [0xff; 32];
lazy_static! {
    pub static ref MAX_TARGET: BigUint = BigUint::from_bytes_be(&MAX_TARGET_BYTES);
}

#[derive(Debug, Clone, Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionError,
    #[error("Decryption failed")]
    DecryptionError,
    #[error("Key generation failed")]
    KeyGenerationError,
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
pub struct MiningParams {
    pub difficulty: f64,
    pub block_reward: f64,
    pub min_tx_fee: f64,
    pub target_block_time: f64,
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
}

impl From<ProgPowTransaction> for Transaction {
    fn from(p: ProgPowTransaction) -> Self {
        Transaction {
            sender: p.sender,
            recipient: p.recipient,
            amount: p.amount,
            fee: p.fee,
            timestamp: p.timestamp,
            signature: p.signature,
        }
    }
}

#[derive(Debug)]
pub struct MiningManager {
    pub params: Arc<RwLock<MiningParams>>,
    cache: Arc<RwLock<ProgPowCache>>,
    pub last_epoch: Arc<RwLock<u32>>,
    pub wallets: RwLock<HashMap<String, Wallet>>,
    blockchain: Arc<RwLock<Blockchain>>,
}

impl MiningManager {
    // Constructor for MiningManager struct
    pub fn clone_manager(&self) -> MiningManager {
        MiningManager::new(self.blockchain.clone())
    }

    pub fn new(blockchain: Arc<RwLock<Blockchain>>) -> Self {
        Self {
            params: Arc::new(RwLock::new(MiningParams {
                difficulty: 0.0,
                block_reward: 0.0,
                min_tx_fee: 0.0,
                target_block_time: 0.0,
            })),
            cache: Arc::new(RwLock::new(ProgPowCache {
                mix_state: [0; PROGPOW_REGS],
                lanes: [[0; PROGPOW_REGS]; PROGPOW_LANES],
                dag_entries: Vec::new(),
            })),
            last_epoch: Arc::new(RwLock::new(0)),
            wallets: RwLock::new(HashMap::new()),
            blockchain,
        }
    }

    async fn sync_params_with_blockchain(&self) -> Result<(), MiningError> {
        let blockchain = self.blockchain.read().await;
        let mut params = self.params.write().await;

        params.block_reward = blockchain.mining_reward as f64;
        params.min_tx_fee = blockchain.transaction_fee;
        params.target_block_time = blockchain.block_time as f64;
        // Convert blockchain difficulty to our format if needed
        params.difficulty = blockchain.get_current_difficulty().await as f64;

        Ok(())
    }

    pub async fn get_last_epoch(&self) -> Result<u32, MiningError> {
        Ok(*self.last_epoch.read().await)
    }

    pub async fn mine_block(
        &self,
        header: &mut BlockHeader,
        transactions: &[ProgPowTransaction],
        max_nonce: u64,
        miner_address: String,
        reward_amount: f64,
    ) -> Result<(u64, String), MiningError> {
        self.sync_params_with_blockchain().await?;

        let transactions: Vec<Transaction> = transactions
            .iter()
            .map(|ptx| {
                Transaction::new(
                    ptx.sender.clone(),
                    ptx.recipient.clone(),
                    ptx.amount,
                    ptx.fee,
                    ptx.timestamp,
                    ptx.signature.clone(),
                )
            })
            .collect();

        let found = Arc::new(AtomicBool::new(false));
        let result_nonce = Arc::new(AtomicU64::new(0));
        let hash_result = Arc::new(Mutex::new(Vec::with_capacity(32)));

        let num_threads = std::cmp::min(num_cpus::get(), 32);
        let nonces_per_thread = max_nonce / num_threads as u64;

        let progress_bar = Arc::new(Mutex::new(ProgressBar::new(max_nonce)));
        {
            let pb = progress_bar.lock().unwrap();
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{prefix} {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
                    .progress_chars("=> "),
            );
            pb.set_prefix(format!("Block #{}", header.number));
            pb.enable_steady_tick(100);
        }

        let mut current_nonce = 0;
        let update_interval = 1000;

        loop {
            let (
                current_network_difficulty,
                previous_block_hash,
                previous_block_timestamp,
                current_height,
            ) = {
                let blockchain_guard = self.blockchain.read().await;
                let previous_block = blockchain_guard.get_last_block().ok_or_else(|| {
                    MiningError::BlockchainError("Previous block not found".to_string())
                })?;
                (
                    blockchain_guard.get_current_difficulty().await,
                    previous_block.hash.clone(),
                    previous_block.timestamp,
                    blockchain_guard.get_block_count() as u32,
                )
            };

            if current_height > header.number {
                header.number = current_height;
                if let Ok(pb) = progress_bar.lock() {
                    pb.set_prefix(format!("Block #{}", header.number));
                }
                current_nonce = 0;
                continue;
            }

            let merkle_root = if !transactions.is_empty() {
                Blockchain::calculate_merkle_root(&transactions)
                    .map_err(|e| MiningError::BlockchainError(e.to_string()))?
            } else {
                let mut hasher = Sha256::new();
                hasher.update(b"empty_transactions");
                let result = hasher.finalize();
                let mut root = [0u8; 32];
                root.copy_from_slice(&result[0..32]);
                root
            };

            let current_header_number = header.number;
            let blockchain = self.blockchain.clone();
            let progress_bar = Arc::clone(&progress_bar);

            // Calculate target using proper difficulty scaling that handles large values
            let target = if current_network_difficulty == 0 {
                MAX_TARGET.clone()
            } else {
                // Convert everything to BigUint to avoid overflow
                let two = BigUint::from(2u8);
                let sixteen = BigUint::from(16u8);
                let difficulty = BigUint::from(current_network_difficulty);

                // Calculate (difficulty / 16) using BigUint division
                let scaled_difficulty = difficulty / sixteen;

                // Calculate 2^(difficulty/16) using BigUint pow
                let divisor = two.pow(scaled_difficulty.to_u32().unwrap_or(0));

                // Finally divide max_target by the calculated divisor
                MAX_TARGET.clone() / divisor
            };
            let target = Arc::new(target);

            let mining_result: Result<(), MiningError> = (0..num_threads as u64)
                .into_par_iter()
                .try_for_each(|thread_id| -> Result<(), MiningError> {
                    let mut local_header = header.clone();
                    local_header.merkle_root = merkle_root;
                    let start_nonce = current_nonce + (thread_id * nonces_per_thread);
                    let end_nonce = start_nonce + nonces_per_thread;
                    let target = Arc::clone(&target);

                    for nonce in start_nonce..end_nonce {
                        if found.load(Ordering::Relaxed) {
                            return Ok(());
                        }

                        let mut new_block = Block::new(
                            local_header.number,
                            previous_block_hash.clone(),
                            previous_block_timestamp,
                            transactions.clone(),
                            nonce,
                            current_network_difficulty,
                        )?;

                        let hash = new_block.calculate_hash_for_block();
                        new_block.hash = hash;

                        let hash_int = BigUint::from_bytes_be(&hash);
                        if hash_int <= *target {
                            if !found.swap(true, Ordering::Relaxed) {
                                result_nonce.store(nonce, Ordering::Release);
                                if let Ok(mut hash_guard) = hash_result.lock() {
                                    *hash_guard = hash.to_vec();
                                }
                            }
                            return Ok(());
                        }

                        if nonce % update_interval == 0 {
                            if let Ok(pb) = progress_bar.lock() {
                                pb.set_position(nonce - current_nonce);
                                let hash_hex = hex::encode(&hash);
                                pb.set_message(format!(
                                    "Hash: {} (Difficulty: {})",
                                    &hash_hex[..16],
                                    current_network_difficulty
                                ));
                            }

                            let check_height = tokio::task::block_in_place(|| {
                                futures::executor::block_on(async {
                                    let guard = blockchain.read().await;
                                    guard.get_block_count() as u32
                                })
                            });

                            if check_height > current_header_number {
                                return Ok(());
                            }
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

            if found.load(Ordering::Relaxed) {
                let nonce = result_nonce.load(Ordering::Acquire);
                let hash = hash_result.lock().unwrap().clone();
                let hash_string = hex::encode(&hash);

                let blockchain_lock = self.blockchain.write().await;
                let mut valid_transactions = Vec::with_capacity(transactions.len());

                for transaction in &transactions {
                    let sender_balance = blockchain_lock
                        .get_confirmed_balance(&transaction.sender)
                        .await?;
                    if sender_balance >= transaction.amount + transaction.fee {
                        valid_transactions.push(transaction.clone());
                    }
                }

                let mut new_block = Block::new(
                    header.number,
                    previous_block_hash.clone(),
                    previous_block_timestamp,
                    valid_transactions,
                    nonce,
                    current_network_difficulty,
                )?;

                // Use the hash found during mining (which met the target)
                new_block.hash = hash.try_into().map_err(|_| MiningError::InvalidHashFormat)?;

                match blockchain_lock
                    .finalize_block(new_block, miner_address.clone())
                    .await
                {
                    Ok(_) => {
                        if let Ok(pb) = progress_bar.lock() {
                            pb.finish_with_message("Block mined successfully!");
                        }
                        return Ok((nonce, hash_string));
                    }
                    Err(e) => {
                        if let Ok(pb) = progress_bar.lock() {
                            pb.finish_with_message("Block finalization failed");
                        }
                        return Err(MiningError::BlockchainError(e.to_string()));
                    }
                }
            }

            current_nonce += max_nonce;
            if let Ok(pb) = progress_bar.lock() {
                pb.reset();
                pb.set_message("Starting next nonce range...");
            };
        }
    }
}

pub struct Miner {
    blockchain: Arc<RwLock<Blockchain>>,
    manager: MiningManager,
}

impl Miner {
    pub fn new(blockchain: Arc<RwLock<Blockchain>>, manager: MiningManager) -> Self {
        Miner {
            blockchain,
            manager,
        }
    }

    pub async fn mine_block(
        &self,
        header: &mut BlockHeader,
        transactions: &[ProgPowTransaction],
        max_nonce: u64,
        max_time: u64,
        miner_address: String,
        reward_amount: f64,
    ) -> Result<(u64, String), MiningError> {
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
