use bincode::serialize;
use blake3;
use chrono::Utc;
use dashmap::DashMap;
use futures::executor::block_on;
use lazy_static::lazy_static;
use log::error;
use lru::LruCache;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use sled::Db;
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error as StdError;
use std::error::Error;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use parking_lot::Mutex as PLMutex;

use crate::a9::mempool::{Mempool, TemporalVerification};
use crate::a9::oracle::DifficultyOracle;
use crate::a9::progpow::MiningManager;
use crate::a9::wallet::Wallet;

const BLOCKCHAIN_PATH: &str = "blockchain.db";
const BALANCES_TREE: &str = "balances";
const PENDING_DEBITS_TREE: &str = "pending_debits";
const PENDING_TRANSACTIONS_TREE: &str = "pending_transactions";
// Full Dilithium signatures are intentionally NOT stored in the main tx record on disk.
// We keep them in a sidecar tree for pending/mempool durability across restarts, and prune with the same TTL.
const PENDING_FULL_SIGNATURES_TREE: &str = "pending_full_signatures";
const ORPHAN_BLOCKS_TREE: &str = "orphan_blocks";
const ORPHAN_INDEX_TREE: &str = "orphan_index";
const BALANCES_HEIGHT_KEY: &[u8] = b"__height";
const NONCE_MAGIC: u128 = 0xA5A5A5A5A5A5A5A5A;
const DIFFICULTY_MAGIC: u128 = 0x5A5A5A5A5A5A5A5A5A5A5A5A5A;
const MIN_TRANSACTION_AMOUNT: f64 = 0.00000564;
const ORPHAN_MAX_COUNT: usize = 10_000;
const ORPHAN_TTL_SECS: u64 = 6 * 60 * 60;

pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 1; //Base
pub const FEE_PERCENTAGE: f64 = 0.000563063063; // 0.0563063063%
pub const MIN_BLOCK_REWARD: f64 = 1.0;
pub const MAX_BLOCK_REWARD: f64 = 50.0;
pub const NETWORK_FEE: f64 = 0.0005; // Operator fee from mining rewards
pub const MINT_CLIP: f64 = 0.35; // Burned/clipped portion of tx fees (anti self-fee recycling)
pub const SYSTEM_ADDRESSES: [&str; 1] = ["MINING_REWARDS"];
pub const TARGET_BLOCK_TIME: u64 = 5;
pub const MAX_TARGET_BYTES: [u8; 32] = [0xff; 32];
lazy_static! {
    pub static ref MAX_TARGET: BigUint = BigUint::from_bytes_be(&MAX_TARGET_BYTES);
}

static FINALIZE_STAGE: AtomicUsize = AtomicUsize::new(0);

pub fn current_finalize_stage() -> usize {
    FINALIZE_STAGE.load(Ordering::Acquire)
}

pub fn set_finalize_stage(stage: usize) {
    FINALIZE_STAGE.store(stage, Ordering::Release);
}

pub fn finalize_stage_name(stage: usize) -> &'static str {
    match stage {
        0 => "waiting_lock",
        1 => "derive_keys",
        2 => "calc_reward",
        3 => "sign_reward",
        4 => "insert_reward",
        5 => "merkle",
        6 => "prefetch_balances",
        7 => "validate_batch",
        8 => "apply_batch",
        9 => "db_insert",
        10 => "balances_height",
        _ => "unknown",
    }
}

#[derive(Eq, PartialEq)]
pub enum TransactionContext {
    BlockValidation,
    Standard,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SignatureValidationMode {
    /// For blocks received/constructed in-memory where full signatures must be present.
    RequireFull,
    /// For blocks loaded from local storage where signatures may be truncated by design.
    AllowTruncatedStored,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub sender: String,
    pub recipient: String,
    pub fee: f64,
    pub amount: f64,
    pub timestamp: u64,
    pub signature: Option<String>,
    #[serde(default)]
    pub pub_key: Option<String>,
    #[serde(default)]
    pub sig_hash: Option<String>,
}

// Legacy transaction format (pre pub_key/sig_hash)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct LegacyTransaction {
    pub sender: String,
    pub recipient: String,
    pub fee: f64,
    pub amount: f64,
    pub timestamp: u64,
    pub signature: Option<String>,
}

impl Transaction {
    pub fn round_amount(amount: f64) -> f64 {
        (amount * 100_000_000.0).round() / 100_000_000.0
    }

    pub fn new(
        sender: String,
        recipient: String,
        amount: f64,
        fee: f64,
        timestamp: u64,
        signature: Option<String>,
    ) -> Self {
        Transaction {
            sender,
            recipient,
            amount: Self::round_amount(amount),
            fee: Self::round_amount(fee),
            timestamp,
            signature,
            pub_key: None,
            sig_hash: None,
        }
    }


    pub fn create_and_sign(
        sender: String,
        recipient: String,
        amount: f64,
        sender_wallet: &Wallet,
    ) -> Result<Self, String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let fee = amount * FEE_PERCENTAGE;

        let transaction = Self {
            sender,
            recipient,
            amount,
            fee,
            timestamp,
            signature: None,
            pub_key: None,
            sig_hash: None,
        };

        let transaction_data = serde_json::to_vec(&transaction)
            .map_err(|e| format!("Failed to serialize transaction: {}", e))?;

        // Get full signature for verification
        let full_signature = block_on(sender_wallet.get_full_signature(&transaction_data))
            .ok_or("Failed to sign transaction")?;

        // Create new transaction with full signature for verification
        let mut tx_with_full_sig = Self::new(
            transaction.sender.clone(),
            transaction.recipient.clone(),
            transaction.amount,
            transaction.fee,
            transaction.timestamp,
            Some(hex::encode(&full_signature)),
        );
        tx_with_full_sig.sig_hash = Some(Self::signature_hash_hex(&full_signature));
        tx_with_full_sig.pub_key = Some(
            block_on(sender_wallet.get_public_key_hex()).ok_or("Failed to get public key")?,
        );

        // Verify the full signature
        if let Some(pub_key) = &tx_with_full_sig.pub_key {
            if !tx_with_full_sig.is_valid(pub_key) {
                return Err("Signature verification failed".to_string());
            }
        } else {
            return Err("Failed to get public key".to_string());
        }

        Ok(tx_with_full_sig)
    }

    pub fn create_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!(
            "{}:{}:{:.8}:{:.8}:{}",
            self.sender, self.recipient, self.amount, self.fee, self.timestamp
        ));
        hex::encode(hasher.finalize())
    }

    pub fn is_valid(&self, sender_pubkey: &str) -> bool {
        if SYSTEM_ADDRESSES.contains(&self.sender.as_str()) {
            return false;
        }

        if let Some(sig) = &self.signature {
            let message = self.get_message();

            match hex::decode(sig) {
                Ok(full_sig) => match hex::decode(sender_pubkey) {
                    Ok(pub_key_bytes) => {
                        match Wallet::verify_signature(&message, &full_sig, &pub_key_bytes) {
                            Ok(true) => {
                                println!("Signature verification: ✓");
                                true
                            }
                            _ => {
                                println!("Signature verification failed");
                                false
                            }
                        }
                    }
                    Err(e) => {
                        println!("Failed to decode public key: ✗ ({})", e);
                        false
                    }
                },
                Err(e) => {
                    println!("Failed to decode signature: ✗ ({})", e);
                    false
                }
            }
        } else {
            self.sender == "MINING_REWARDS"
        }
    }

    pub fn signature_hash_hex(signature_bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(signature_bytes);
        hex::encode(hasher.finalize())
    }

    pub fn with_truncated_signature(&self, sig_hash: String) -> Self {
        let truncated_signature = self.signature.as_ref().and_then(|sig| {
            hex::decode(sig)
                .ok()
                .map(|full_sig| hex::encode(&full_sig[..full_sig.len().min(64)]))
        });

        Transaction {
            sender: self.sender.clone(),
            recipient: self.recipient.clone(),
            amount: self.amount,
            fee: self.fee,
            timestamp: self.timestamp,
            signature: truncated_signature,
            pub_key: self.pub_key.clone(),
            sig_hash: Some(sig_hash),
        }
    }

    pub async fn validate(
        &self,
        blockchain: &Blockchain,
        block: Option<&Block>,
    ) -> Result<(), BlockchainError> {
        // Special handling for system transactions
        if SYSTEM_ADDRESSES.contains(&self.sender.as_str()) {
            let block = block.ok_or(BlockchainError::InvalidSystemTransaction)?;

            // CRITICAL: Verify proof of work before any system transaction validation
            if !block.verify_pow() {
                return Err(BlockchainError::InvalidHash);
            }

            return SystemKeyDeriver::verify_system_transaction(
                self,
                block,
                if self.sender == "MINING_REWARDS" {
                    SystemTransactionType::MiningReward
                } else {
                    SystemTransactionType::GovernanceDistribution
                },
            )
            .await;
        }

        // Regular transaction validation continues as normal...
        self.verify_balance(blockchain).await?;
        self.verify_signature(blockchain).await?;
        Ok(())
    }

    async fn verify_balance(&self, blockchain: &Blockchain) -> Result<(), BlockchainError> {
        let sender_balance = blockchain.get_confirmed_balance(&self.sender).await?; // Changed this line!

        if self.amount < 0.0 || self.fee < 0.0 {
            return Err(BlockchainError::InvalidTransactionAmount);
        }

        let total_required = self.amount + self.fee;

        if sender_balance < total_required {
            return Err(BlockchainError::InsufficientFunds);
        }

        Ok(())
    }

    async fn verify_signature(&self, _blockchain: &Blockchain) -> Result<(), BlockchainError> {
        // Enforce that a verified tx carries pub_key + signature hash.
        if self.pub_key.is_none() || self.sig_hash.is_none() {
            return Err(BlockchainError::InvalidTransactionSignature);
        }
        if let Some(sig) = &self.signature {
            let decoded =
                hex::decode(sig).map_err(|_| BlockchainError::InvalidTransactionSignature)?;
            if decoded.is_empty() {
                return Err(BlockchainError::InvalidTransactionSignature);
            }
        }
        Ok(())
    }

    pub fn get_tx_id(&self) -> String {
        format!(
            "{}:{}:{:.8}:{:.8}:{}",
            self.sender, self.recipient, self.amount, self.fee, self.timestamp
        )
    }

    fn get_message(&self) -> Vec<u8> {
        format!(
            "{}:{}:{:.8}:{:.8}:{}",
            self.sender, self.recipient, self.amount, self.fee, self.timestamp
        )
        .into_bytes()
    }
}

pub struct BlockHeader {
    pub index: u64,
    pub previous_hash: String,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub index: u32,
    pub previous_hash: [u8; 32],
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub nonce: u64,
    pub difficulty: u64,
    pub hash: [u8; 32],
    pub merkle_root: [u8; 32],
}

// Legacy block format (pre pub_key/sig_hash on Transaction)
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LegacyBlock {
    pub index: u32,
    pub previous_hash: [u8; 32],
    pub timestamp: u64,
    pub transactions: Vec<LegacyTransaction>,
    pub nonce: u64,
    pub difficulty: u64,
    pub hash: [u8; 32],
    pub merkle_root: [u8; 32],
}

impl Block {
    pub fn new(
        index: u32,
        previous_hash: [u8; 32],
        previous_block_timestamp: u64,
        transactions: Vec<Transaction>,
        nonce: u64,
        current_difficulty: u64,
    ) -> Result<Self, Box<dyn Error>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Always adjust difficulty on every block
        let timestamp_diff = timestamp.saturating_sub(previous_block_timestamp);
        let mut difficulty_oracle = DifficultyOracle::new();
        let difficulty = Self::adjust_dynamic_difficulty(
            current_difficulty,
            timestamp_diff,
            index,
            &mut difficulty_oracle,
            timestamp,
        );

        let merkle_root = Blockchain::calculate_merkle_root(&transactions)?;
        let mut block = Self {
            index,
            previous_hash,
            timestamp,
            transactions,
            nonce,
            difficulty,
            hash: [0u8; 32],
            merkle_root,
        };
        block.hash = block.calculate_hash_for_block();
        Ok(block)
    }

    pub fn validate_header(&self) -> Result<(), BlockchainError> {
        // Basic header validation
        if self.index == 0 && self.previous_hash != [0u8; 32] {
            return Err(BlockchainError::InvalidBlockHeader);
        }

        // Timestamp validation
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        const MAX_FUTURE_TIME: u64 = 300;

        if self.timestamp > now + MAX_FUTURE_TIME {
            return Err(BlockchainError::InvalidBlockHeader);
        }

        // Verify the hash matches content
        let calculated_hash = self.calculate_hash_for_block();
        if calculated_hash != self.hash {
            return Err(BlockchainError::InvalidHash);
        }

        // Add proof of work validation
        if !self.verify_difficulty_proof() {
            return Err(BlockchainError::InvalidBlockHeader);
        }

        Ok(())
    }

    pub fn adjust_dynamic_difficulty(
        current_difficulty: u64,
        timestamp_diff: u64,
        _block_index: u32, // Unused parameter, can be prefixed with _
        oracle: &mut DifficultyOracle,
        current_timestamp: u64,
    ) -> u64 {
        const MIN_DIFFICULTY: u64 = 321;
        const MAX_DIFFICULTY: u64 = u64::MAX / 2;
        const MAX_ADJUSTMENT: f64 = 1.15;
        const DAMPENING_FACTOR: f64 = 0.6;
        const EMERGENCY_THRESHOLD: u64 = 5;
        const EMERGENCY_MULTIPLIER: f64 = 0.9;

        // Record metrics
        oracle.record_block_metrics(current_timestamp, current_difficulty);

        // Emergency Reset Condition (from the second version)
        if timestamp_diff > TARGET_BLOCK_TIME * EMERGENCY_THRESHOLD {
            return MIN_DIFFICULTY; // Force reset when blocks are very slow
        }

        // Base time ratio calculation
        let time_ratio = timestamp_diff as f64 / TARGET_BLOCK_TIME as f64;

        // Apply hyperbolic tangent dampening (from the first version)
        let dampened_ratio = 1.0 + (time_ratio - 1.0).tanh() * DAMPENING_FACTOR;

        // Calculate initial adjustment (modified from both versions)
        let base_adjustment = if time_ratio < 1.0 {
            // Blocks are faster than target - increase moderately (like the second version, but bounded by MAX_ADJUSTMENT)
            (1.0 / dampened_ratio).min(MAX_ADJUSTMENT)
        } else {
            // Blocks are slower than target - decrease more aggressively (like the second version, but also using dampening)
            (1.0 / (time_ratio * dampened_ratio)).max(1.0 / MAX_ADJUSTMENT)
        };

        let raw_difficulty = (current_difficulty as f64 * base_adjustment).round() as u64;

        // Aggressive minimum difficulty adjustment (from the second version, adapted)
        if time_ratio > 2.0 {
            return (raw_difficulty / 2).max(MIN_DIFFICULTY); // Cut difficulty in half but respect minimum
        }

        // Ensure bounds (from the first version, but using clamp for conciseness)
        raw_difficulty.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY)
    }

    pub fn verify_difficulty_proof(&self) -> bool {
        // Use the same verification as verify_pow
        self.verify_pow()
    }

    pub fn verify_pow(&self) -> bool {
        let hash = self.calculate_hash_for_block();
        let hash_int = BigUint::from_bytes_be(&hash);

        let target = if self.difficulty == 0 {
            MAX_TARGET.clone()
        } else {
            // Convert everything to BigUint to avoid overflow
            let two = BigUint::from(2u8);
            let sixteen = BigUint::from(16u8);
            let difficulty = BigUint::from(self.difficulty);

            // Calculate (difficulty / 16) using BigUint division
            let scaled_difficulty = difficulty / sixteen;

            // Calculate 2^(difficulty/16) using BigUint pow
            let divisor = two.pow(scaled_difficulty.to_u32().unwrap_or(0));

            // Finally divide max_target by the calculated divisor
            MAX_TARGET.clone() / divisor
        };

        hash_int <= target
    }

    pub fn calculate_hash_for_block(&self) -> [u8; 32] {
        // Use a fixed-size array to avoid heap allocation
        // Total: 4 + 32 + 8 + 8 + 8 + 32 = 92 bytes (fits on stack)
        let mut header_data = [0u8; 92];
        let mut offset = 0;

        header_data[offset..offset+4].copy_from_slice(&self.index.to_le_bytes());
        offset += 4;

        header_data[offset..offset+32].copy_from_slice(&self.previous_hash);
        offset += 32;

        header_data[offset..offset+8].copy_from_slice(&self.timestamp.to_le_bytes());
        offset += 8;

        header_data[offset..offset+8].copy_from_slice(&self.nonce.to_le_bytes());
        offset += 8;

        header_data[offset..offset+8].copy_from_slice(&self.difficulty.to_le_bytes());
        offset += 8;

        header_data[offset..offset+32].copy_from_slice(&self.merkle_root);

        *blake3::hash(&header_data).as_bytes()
    }

    pub async fn validate_transactions_batch(
        &self,
        blockchain: &Blockchain,
    ) -> Result<(), BlockchainError> {
        if self.transactions.is_empty() {
            return Ok(()); // Nothing to validate
        }

        // For single transaction, use direct validation
        if self.transactions.len() == 1 {
            return self.transactions[0].validate(blockchain, Some(self)).await;
        }

        for tx in &self.transactions {
            // Iterate sequentially!
            tx.validate(blockchain, Some(self)).await?; // Use ? for early return on error
        }

        Ok(())
    }

    fn validate_mining_reward(
        &self,
        blockchain: &Blockchain,
        block: &Block,
    ) -> Result<(), BlockchainError> {
        // Find mining reward transaction - must be first transaction
        let reward_txs: Vec<&Transaction> = block
            .transactions
            .iter()
            .filter(|tx| tx.sender == "MINING_REWARDS")
            .collect();

        match reward_txs.len() {
            0 => return Err(BlockchainError::InvalidTransaction),
            1 => {
                let reward_tx = reward_txs[0];

                // Verify reward transaction is the first transaction in block
                if block
                    .transactions
                    .first()
                    .map(|tx| tx.sender.as_str())
                    != Some("MINING_REWARDS")
                {
                    return Err(BlockchainError::InvalidTransaction);
                }

                // Critical security checks
                if reward_tx.fee != NETWORK_FEE
                    || reward_tx.signature.is_some()
                    || reward_tx.sender != "MINING_REWARDS"
                {
                    return Err(BlockchainError::InvalidTransaction);
                }

                // Fixed: Using Block's verify_difficulty_proof instead
                if !block.verify_difficulty_proof() {
                    return Err(BlockchainError::InvalidHash);
                }

                // Fixed: Pass blockchain reference to calculate_block_reward
                let expected_reward = blockchain.calculate_block_reward(block)?;
                if Transaction::round_amount(reward_tx.amount) != expected_reward {
                    return Err(BlockchainError::InvalidTransactionAmount);
                }
            }
            _ => return Err(BlockchainError::InvalidTransaction), // Multiple rewards not allowed
        }

        Ok(())
    }

    pub fn hash_to_hex_string(&self) -> String {
        // Use hex::encode which is optimized for this exact use case
        hex::encode(&self.hash)
    }

    pub fn previous_hash_to_hex_string(&self) -> String {
        // Use hex::encode which is optimized for this exact use case
        hex::encode(&self.previous_hash)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        bincode::serialize(self).map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        deserialize_block(bytes).map_err(|e| Box::new(e) as Box<dyn Error>)
    }
}

#[derive(Debug)]
struct ParallelProcessingError(String);

impl From<sled::Error> for ParallelProcessingError {
    fn from(error: sled::Error) -> Self {
        ParallelProcessingError(error.to_string())
    }
}

#[derive(Debug)]
pub enum BlockchainError {
    BincodeError(Box<bincode::ErrorKind>),
    DatabaseError(sled::Error),
    RateLimitExceeded(String),
    SerializationError(Box<dyn StdError>),
    SelfTransferNotAllowed,
    IoError(std::io::Error),
    FlushError(String),
    MiningError(String),
    WalletNotFound,
    InvalidHash,
    InsufficientFunds,
    InvalidCommand(String),
    InvalidTransaction,
    InvalidBlockHeader,
    InvalidBlockTimestamp,
    InvalidTransactionAmount,
    InvalidTransactionSignature,
    InvalidBlockKeys(String),
    InvalidSystemTransaction,
    BatchValidationFailed(Vec<usize>),
}

impl fmt::Display for BlockchainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockchainError::RateLimitExceeded(ref msg) => {
                write!(f, "Rate limit exceeded: {}", msg)
            }
            BlockchainError::BincodeError(e) => write!(f, "Bincode error: {}", e),
            BlockchainError::DatabaseError(e) => write!(f, "Database error: {}", e),
            BlockchainError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            BlockchainError::SelfTransferNotAllowed => write!(f, "Self-transfers are not allowed"),
            BlockchainError::IoError(e) => write!(f, "IO error: {}", e),
            BlockchainError::FlushError(e) => write!(f, "Flush error: {}", e),
            BlockchainError::MiningError(msg) => write!(f, "Mining error: {}", msg),
            BlockchainError::WalletNotFound => write!(f, "Wallet not found"),
            BlockchainError::InvalidHash => write!(f, "Invalid block hash"),
            BlockchainError::InsufficientFunds => {
                write!(f, "Insufficient funds for the transaction")
            }
            BlockchainError::InvalidCommand(e) => write!(f, "Invalid Command: {}", e),
            BlockchainError::InvalidTransaction => write!(f, "Transaction is invalid"),
            BlockchainError::InvalidBlockHeader => write!(f, "Block header is invalid"),
            BlockchainError::InvalidBlockTimestamp => write!(f, "Timestamp is invalid"),
            BlockchainError::InvalidTransactionAmount => {
                write!(f, "Transaction amount is invalid or negative")
            }
            BlockchainError::InvalidTransactionSignature => {
                write!(f, "Transaction signature is invalid or missing")
            }
            BlockchainError::InvalidBlockKeys(e) => write!(f, "Invalid block keys: {}", e),
            BlockchainError::InvalidSystemTransaction => write!(f, "Invalid system transaction"),
            BlockchainError::BatchValidationFailed(errors) => {
                write!(f, "Batch validation failed with {} errors", errors.len())
            }
        }
    }
}

impl std::error::Error for BlockchainError {}

impl From<sled::Error> for BlockchainError {
    fn from(err: sled::Error) -> Self {
        Self::DatabaseError(err)
    }
}

impl From<serde_json::Error> for BlockchainError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(Box::new(err))
    }
}

impl From<std::io::Error> for BlockchainError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<hex::FromHexError> for BlockchainError {
    fn from(err: hex::FromHexError) -> Self {
        BlockchainError::SerializationError(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Hex decode error: {}", err),
        )))
    }
}

impl From<Box<dyn StdError>> for BlockchainError {
    fn from(error: Box<dyn StdError>) -> Self {
        BlockchainError::SerializationError(error)
    }
}

impl From<Box<bincode::ErrorKind>> for BlockchainError {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        BlockchainError::BincodeError(error)
    }
}

fn deserialize_transaction(bytes: &[u8]) -> Result<Transaction, BlockchainError> {
    if let Ok(tx) = bincode::deserialize::<Transaction>(bytes) {
        return Ok(tx);
    }
    let legacy: LegacyTransaction = bincode::deserialize(bytes)
        .map_err(|e| BlockchainError::SerializationError(Box::new(e)))?;
    Ok(Transaction {
        sender: legacy.sender,
        recipient: legacy.recipient,
        fee: legacy.fee,
        amount: legacy.amount,
        timestamp: legacy.timestamp,
        signature: legacy.signature,
        pub_key: None,
        sig_hash: None,
    })
}

fn deserialize_block(bytes: &[u8]) -> Result<Block, BlockchainError> {
    if let Ok(block) = bincode::deserialize::<Block>(bytes) {
        return Ok(block);
    }
    let legacy: LegacyBlock = bincode::deserialize(bytes)
        .map_err(|e| BlockchainError::SerializationError(Box::new(e)))?;
    Ok(Block {
        index: legacy.index,
        previous_hash: legacy.previous_hash,
        timestamp: legacy.timestamp,
        transactions: legacy
            .transactions
            .into_iter()
            .map(|tx| Transaction {
                sender: tx.sender,
                recipient: tx.recipient,
                fee: tx.fee,
                amount: tx.amount,
                timestamp: tx.timestamp,
                signature: tx.signature,
                pub_key: None,
                sig_hash: None,
            })
            .collect(),
        nonce: legacy.nonce,
        difficulty: legacy.difficulty,
        hash: legacy.hash,
        merkle_root: legacy.merkle_root,
    })
}

#[derive(Debug)]
pub struct RateLimiter {
    windows: DashMap<String, Vec<tokio::time::Instant>>,
    window_size: chrono::Duration,
    max_requests: usize,
}

impl RateLimiter {
    pub fn new(window_secs: u64, max_requests: usize) -> Self {
        Self {
            windows: DashMap::new(),
            window_size: chrono::Duration::seconds(window_secs as i64),
            max_requests,
        }
    }

    pub fn check_limit(&self, address: &str) -> bool {
        let now = tokio::time::Instant::now();
        let mut times = self
            .windows
            .entry(address.to_string())
            .or_insert_with(Vec::new);

        // Optimization: Only cleanup if we have entries to clean
        // Most of the time, the vector will be small and all entries valid
        let window_secs = self.window_size.num_seconds() as u64;
        let cutoff = now - std::time::Duration::from_secs(window_secs);

        // Fast path: check if we need to cleanup at all
        if !times.is_empty() && times[0] < cutoff {
            // Binary search to find first valid entry
            let first_valid = times.iter().position(|&t| t >= cutoff).unwrap_or(times.len());
            // Efficiently remove old entries by draining
            times.drain(0..first_valid);
        }

        if times.len() >= self.max_requests {
            return false;
        }

        times.push(now);
        true
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SystemTransactionType {
    MiningReward,
    GovernanceDistribution,
}

pub struct SystemKeyDeriver;

impl SystemKeyDeriver {
    pub async fn verify_system_transaction(
        tx: &Transaction,
        block: &Block,
        tx_type: SystemTransactionType,
    ) -> Result<(), BlockchainError> {
        // Fast-fail checks
        if tx.sender != "MINING_REWARDS" || tx_type != SystemTransactionType::MiningReward {
            return Err(BlockchainError::InvalidSystemTransaction);
        }

        // CRITICAL: Verify proof of work first
        if !block.verify_pow() {
            return Err(BlockchainError::InvalidHash);
        }

        // Verify transaction is part of the block with exact matching
        if !block.transactions.iter().any(|block_tx| {
            block_tx.sender == tx.sender &&
            block_tx.recipient == tx.recipient &&
            (block_tx.amount - tx.amount).abs() < f64::EPSILON &&  // Use epsilon for float comparison
            (block_tx.fee - tx.fee).abs() < f64::EPSILON &&
            block_tx.timestamp == tx.timestamp
        }) {
            return Err(BlockchainError::InvalidSystemTransaction);
        }

        // Deterministic rule: system rewards are protocol-generated and unsigned.
        // Reject legacy/random-key signature variants to avoid node divergence.
        if tx.signature.is_some() || tx.sig_hash.is_some() {
            return Err(BlockchainError::InvalidTransactionSignature);
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Blockchain {
    pub db: Db,
    pub difficulty: Arc<Mutex<u64>>,
    pub transaction_fee: f64,
    pub mining_reward: f64,
    pub difficulty_adjustment_interval: u64,
    pub block_time: u32,
    pub rate_limiter: Arc<RateLimiter>,
    mempool: Arc<RwLock<Mempool>>,
    pub chain_sentinel: Arc<ChainSentinel>,
    pub temporal_verification: TemporalVerification,
    signature_cache: Arc<PLMutex<LruCache<String, bool>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OrphanStoredBlock {
    block: Block,
    received_at: u64,
}

impl Blockchain {
    fn block_index_from_key(key: &[u8]) -> Option<u32> {
        let key_str = std::str::from_utf8(key).ok()?;
        let index_str = key_str.strip_prefix("block_")?;
        index_str.parse::<u32>().ok()
    }

    fn highest_block_index(&self) -> Option<u32> {
        self.db
            .scan_prefix("block_")
            .filter_map(|entry| entry.ok().and_then(|(k, _)| Self::block_index_from_key(&k)))
            .max()
    }

    fn now_unix_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn orphan_hash_key(hash: &[u8; 32]) -> String {
        hex::encode(hash)
    }

    fn orphan_index_key(prev_hash: &[u8; 32], index: u32, hash: &[u8; 32]) -> String {
        format!(
            "{}:{}:{}",
            hex::encode(prev_hash),
            index,
            Self::orphan_hash_key(hash)
        )
    }

    fn parse_orphan_index_hash(key: &[u8]) -> Option<String> {
        let key_str = std::str::from_utf8(key).ok()?;
        key_str.rsplit(':').next().map(|s| s.to_string())
    }

    fn open_orphan_blocks_tree(&self) -> Result<sled::Tree, BlockchainError> {
        self.db.open_tree(ORPHAN_BLOCKS_TREE).map_err(Into::into)
    }

    fn open_orphan_index_tree(&self) -> Result<sled::Tree, BlockchainError> {
        self.db.open_tree(ORPHAN_INDEX_TREE).map_err(Into::into)
    }

    fn open_pending_debits_tree(&self) -> Result<sled::Tree, BlockchainError> {
        self.db.open_tree(PENDING_DEBITS_TREE).map_err(Into::into)
    }

    async fn get_pending_debit_for(&self, address: &str) -> Result<f64, BlockchainError> {
        let tree = self.open_pending_debits_tree()?;
        if let Some(raw) = tree.get(address.as_bytes())? {
            let debit: f64 = bincode::deserialize(&raw)?;
            Ok(debit)
        } else {
            Ok(0.0)
        }
    }

    fn set_pending_debit_for(
        tree: &sled::Tree,
        address: &str,
        debit: f64,
    ) -> Result<(), BlockchainError> {
        let normalized = Transaction::round_amount(debit.max(0.0));
        if normalized <= 0.0 {
            tree.remove(address.as_bytes())?;
        } else {
            tree.insert(address.as_bytes(), bincode::serialize(&normalized)?)?;
        }
        Ok(())
    }

    async fn rebuild_pending_debits_index(&self) -> Result<(), BlockchainError> {
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let debits_tree = self.open_pending_debits_tree()?;
        debits_tree.clear()?;

        let mut totals: HashMap<String, f64> = HashMap::new();
        for item in pending_tree.iter() {
            let (_, tx_bytes) = item?;
            if let Ok(tx) = deserialize_transaction(&tx_bytes) {
                if tx.sender != "MINING_REWARDS" {
                    *totals.entry(tx.sender.clone()).or_insert(0.0) += tx.amount + tx.fee;
                }
            }
        }

        let mut batch = sled::Batch::default();
        for (address, total) in totals {
            let normalized = Transaction::round_amount(total.max(0.0));
            if normalized > 0.0 {
                batch.insert(address.as_bytes(), bincode::serialize(&normalized)?);
            }
        }
        debits_tree.apply_batch(batch)?;
        debits_tree.flush()?;
        Ok(())
    }

    fn store_orphan_block(&self, block: &Block) -> Result<(), BlockchainError> {
        let orphan_blocks = self.open_orphan_blocks_tree()?;
        let orphan_index = self.open_orphan_index_tree()?;
        let hash_key = Self::orphan_hash_key(&block.hash);

        if orphan_blocks.get(hash_key.as_bytes())?.is_some() {
            return Ok(());
        }

        let orphan_entry = OrphanStoredBlock {
            block: block.clone(),
            received_at: Self::now_unix_secs(),
        };

        orphan_blocks.insert(hash_key.as_bytes(), bincode::serialize(&orphan_entry)?)?;
        orphan_index.insert(
            Self::orphan_index_key(&block.previous_hash, block.index, &block.hash).as_bytes(),
            &[] as &[u8],
        )?;
        orphan_blocks.flush()?;
        orphan_index.flush()?;
        self.prune_orphans()?;
        Ok(())
    }

    fn remove_orphan_by_hash(&self, hash: &[u8; 32]) -> Result<(), BlockchainError> {
        let orphan_blocks = self.open_orphan_blocks_tree()?;
        let orphan_index = self.open_orphan_index_tree()?;
        let hash_key = Self::orphan_hash_key(hash);

        if let Some(raw) = orphan_blocks.remove(hash_key.as_bytes())? {
            if let Ok(entry) = bincode::deserialize::<OrphanStoredBlock>(&raw) {
                let index_key = Self::orphan_index_key(
                    &entry.block.previous_hash,
                    entry.block.index,
                    &entry.block.hash,
                );
                orphan_index.remove(index_key.as_bytes())?;
            }
        }

        Ok(())
    }

    fn orphan_children_of(&self, parent_hash: &[u8; 32]) -> Result<Vec<Block>, BlockchainError> {
        let orphan_blocks = self.open_orphan_blocks_tree()?;
        let orphan_index = self.open_orphan_index_tree()?;
        let prefix = format!("{}:", hex::encode(parent_hash));
        let mut children = Vec::new();

        for item in orphan_index.scan_prefix(prefix.as_bytes()) {
            let (idx_key, _) = item?;
            let Some(orphan_hash_hex) = Self::parse_orphan_index_hash(&idx_key) else {
                continue;
            };
            if let Some(raw) = orphan_blocks.get(orphan_hash_hex.as_bytes())? {
                if let Ok(entry) = bincode::deserialize::<OrphanStoredBlock>(&raw) {
                    if entry.block.previous_hash == *parent_hash {
                        children.push(entry.block);
                    }
                }
            }
        }

        // Deterministic candidate ordering:
        // 1) expected next height first, 2) higher difficulty, 3) earlier timestamp, 4) lexical hash.
        children.sort_by(|a, b| {
            a.index
                .cmp(&b.index)
                .then_with(|| b.difficulty.cmp(&a.difficulty))
                .then_with(|| a.timestamp.cmp(&b.timestamp))
                .then_with(|| a.hash.cmp(&b.hash))
        });

        Ok(children)
    }

    fn best_orphan_child_of(&self, parent: &Block) -> Result<Option<Block>, BlockchainError> {
        let mut children = self.orphan_children_of(&parent.hash)?;
        children.retain(|c| c.index == parent.index.saturating_add(1) && c.previous_hash == parent.hash);
        children.sort_by(|a, b| {
            b.difficulty
                .cmp(&a.difficulty)
                .then_with(|| a.timestamp.cmp(&b.timestamp))
                .then_with(|| a.hash.cmp(&b.hash))
        });
        Ok(children.into_iter().next())
    }

    fn collect_orphan_branch_from(
        &self,
        start: Block,
        max_depth: usize,
    ) -> Result<Vec<Block>, BlockchainError> {
        let mut branch = vec![start.clone()];
        let mut current = start;
        for _ in 0..max_depth {
            let Some(next) = self.best_orphan_child_of(&current)? else {
                break;
            };
            if next.index != current.index.saturating_add(1) || next.previous_hash != current.hash {
                break;
            }
            branch.push(next.clone());
            current = next;
        }
        Ok(branch)
    }

    fn canonical_work_range(&self, start: u32, end: u32) -> Result<u128, BlockchainError> {
        if end < start {
            return Ok(0);
        }
        let mut work: u128 = 0;
        for height in start..=end {
            let block = self.get_block(height)?;
            work = work.saturating_add(block.difficulty as u128);
        }
        Ok(work)
    }

    fn branch_work_to_height(branch: &[Block], max_height: u32) -> u128 {
        branch
            .iter()
            .filter(|b| b.index <= max_height)
            .fold(0u128, |acc, b| acc.saturating_add(b.difficulty as u128))
    }

    fn to_storage_block(block: &Block) -> Block {
        let mut storage_block = block.clone();
        storage_block.transactions = block
            .transactions
            .iter()
            .map(|tx| {
                if tx.sender == "MINING_REWARDS" {
                    return tx.clone();
                }

                let mut full_tx = tx.clone();
                if full_tx.sig_hash.is_none() {
                    if let Some(sig_hex) = &full_tx.signature {
                        if let Ok(sig_bytes) = hex::decode(sig_hex) {
                            full_tx.sig_hash = Some(Transaction::signature_hash_hex(&sig_bytes));
                        }
                    }
                }

                match &full_tx.sig_hash {
                    Some(sig_hash) => full_tx.with_truncated_signature(sig_hash.clone()),
                    None => full_tx,
                }
            })
            .collect();
        storage_block
    }

    async fn try_adopt_orphan_branch(&self) -> Result<bool, BlockchainError> {
        let Some(tip) = self.get_last_block() else {
            return Ok(false);
        };
        let orphan_blocks = self.open_orphan_blocks_tree()?;
        let mut candidates = Vec::new();

        for item in orphan_blocks.iter() {
            let (_, raw) = item?;
            let Ok(entry) = bincode::deserialize::<OrphanStoredBlock>(&raw) else {
                continue;
            };
            let b = entry.block;

            if b.index > tip.index {
                continue;
            }

            if b.index == 0 {
                if b.previous_hash != [0u8; 32] {
                    continue;
                }
            } else {
                let Ok(parent) = self.get_block(b.index.saturating_sub(1)) else {
                    continue;
                };
                if parent.hash != b.previous_hash {
                    continue;
                }
            }

            let Ok(existing) = self.get_block(b.index) else {
                continue;
            };
            if existing.hash == b.hash {
                continue;
            }

            candidates.push(b);
        }

        if candidates.is_empty() {
            return Ok(false);
        }

        let mut best_branch: Option<Vec<Block>> = None;
        let mut best_overlap_advantage: i128 = i128::MIN;
        let mut best_tip_hash: [u8; 32] = [0u8; 32];

        for candidate in candidates {
            let branch = self.collect_orphan_branch_from(candidate, 1024)?;
            let Some(branch_tip) = branch.last() else {
                continue;
            };
            if branch_tip.index <= tip.index {
                continue;
            }

            let fork_height = branch[0].index;
            let canonical_overlap_work = self.canonical_work_range(fork_height, tip.index)?;
            let branch_overlap_work = Self::branch_work_to_height(&branch, tip.index);
            let advantage = branch_overlap_work as i128 - canonical_overlap_work as i128;

            // Deterministic adoption rule:
            // 1) positive overlap work advantage
            // 2) tie-break by lexical tip hash
            let should_replace = if advantage > best_overlap_advantage {
                true
            } else if advantage == best_overlap_advantage {
                branch_tip.hash < best_tip_hash
            } else {
                false
            };

            if should_replace {
                best_tip_hash = branch_tip.hash;
                best_overlap_advantage = advantage;
                best_branch = Some(branch);
            }
        }

        let Some(branch) = best_branch else {
            return Ok(false);
        };
        if best_overlap_advantage < 0 {
            return Ok(false);
        }

        // Apply reorg by rewriting canonical block slots with the selected branch.
        for b in &branch {
            let key = format!("block_{}", b.index);
            let storage = Self::to_storage_block(b);
            self.db.insert(key.as_bytes(), bincode::serialize(&storage)?)?;
        }
        self.db.flush()?;

        // Remove adopted branch blocks from orphan pool.
        for b in &branch {
            let _ = self.remove_orphan_by_hash(&b.hash);
        }
        self.prune_orphans()?;

        // Rebuild balances index after reorg.
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        self.rebuild_balances_index(&balances_tree).await?;
        Self::set_balances_height(&balances_tree, self.get_latest_block_index() as u64)?;
        let _ = self.get_network_difficulty().await?;

        Ok(true)
    }

    fn prune_orphans(&self) -> Result<(), BlockchainError> {
        let orphan_blocks = self.open_orphan_blocks_tree()?;
        let orphan_index = self.open_orphan_index_tree()?;
        let now = Self::now_unix_secs();
        let tip = self.highest_block_index();
        let mut remove_hashes: Vec<[u8; 32]> = Vec::new();

        let mut retained: Vec<OrphanStoredBlock> = Vec::new();
        for item in orphan_blocks.iter() {
            let (_, raw) = item?;
            if let Ok(entry) = bincode::deserialize::<OrphanStoredBlock>(&raw) {
                let expired = now.saturating_sub(entry.received_at) > ORPHAN_TTL_SECS;
                let stale_height = tip.map(|t| entry.block.index <= t).unwrap_or(false);
                if expired || stale_height {
                    remove_hashes.push(entry.block.hash);
                } else {
                    retained.push(entry);
                }
            }
        }

        if retained.len() > ORPHAN_MAX_COUNT {
            retained.sort_by_key(|e| e.received_at);
            let overflow = retained.len().saturating_sub(ORPHAN_MAX_COUNT);
            for entry in retained.into_iter().take(overflow) {
                remove_hashes.push(entry.block.hash);
            }
        }

        for hash in remove_hashes {
            self.remove_orphan_by_hash(&hash)?;
        }

        // Best-effort cleanup for index entries that no longer have backing orphan blocks.
        let mut dangling = Vec::new();
        for item in orphan_index.iter() {
            let (key, _) = item?;
            if let Some(hash_hex) = Self::parse_orphan_index_hash(&key) {
                if orphan_blocks.get(hash_hex.as_bytes())?.is_none() {
                    dangling.push(key);
                }
            }
        }
        for key in dangling {
            orphan_index.remove(key)?;
        }

        Ok(())
    }

    async fn persist_validated_block(&self, block: &Block) -> Result<(), BlockchainError> {
        // Canonical validation gate for all persistence paths.
        self.validate_block_strict(block).await?;

        // Run expensive full-chain integrity checks periodically.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last_integrity = self
            .chain_sentinel
            .last_verification
            .load(Ordering::Relaxed);
        let should_verify_integrity = block.index % 128 == 0 || now.saturating_sub(last_integrity) >= 60;

        if should_verify_integrity {
            if !self.chain_sentinel.verify_chain_integrity(self).await {
                return Err(BlockchainError::InvalidBlockHeader);
            }
            self.chain_sentinel
                .last_verification
                .store(now, Ordering::Relaxed);
        }

        // Verify system transaction positioning and uniqueness
        let system_txs: Vec<_> = block
            .transactions
            .iter()
            .enumerate()
            .filter(|(_, tx)| SYSTEM_ADDRESSES.contains(&tx.sender.as_str()))
            .collect();

        // Rule 1: Mining reward must be first transaction if present
        if let Some((idx, tx)) = system_txs
            .iter()
            .find(|(_, tx)| tx.sender == "MINING_REWARDS")
        {
            if *idx != 0 {
                return Err(BlockchainError::InvalidSystemTransaction);
            }
        }

        // Rule 2: Only one system transaction of each type allowed per block
        let mut seen_types = HashSet::new();
        for (_, tx) in system_txs {
            if !seen_types.insert(tx.sender.as_str()) {
                return Err(BlockchainError::InvalidSystemTransaction);
            }
        }

        // Add this block's verification
        let verifier = match block.transactions.first() {
            Some(tx) if tx.sender == "MINING_REWARDS" => tx.recipient.clone(),
            _ => "network".to_string(),
        };

        self.chain_sentinel.add_block_verification(block, verifier);

        // Only save if block is verified (or quorum is not required)
        let require_quorum = std::env::var("ALPHANUMERIC_REQUIRE_QUORUM")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        let verification_count = self.chain_sentinel.get_verification_count(block);
        if require_quorum {
            if !self.chain_sentinel.is_block_verified(block) {
                return Err(BlockchainError::InvalidBlockHeader);
            }
        } else if verification_count == 0 {
            return Err(BlockchainError::InvalidBlockHeader);
        }

        // Process transactions with BlockValidation context
        self.process_transactions_batch(
            block.transactions.clone(),
            TransactionContext::BlockValidation,
        )
        .await?;

        // Store block with truncated signatures to reduce chain size
        let storage_block = Self::to_storage_block(block);

        // Serialize and save block
        let value = bincode::serialize(&storage_block)
            .map_err(|e| BlockchainError::SerializationError(Box::new(e)))?;

        let key = format!("block_{}", block.index);
        self.db
            .insert(key.as_bytes(), value)
            .map_err(BlockchainError::DatabaseError)?;

        // Remove this hash from orphan pool if present
        self.remove_orphan_by_hash(&block.hash)?;

        // Update network difficulty atomically
        {
            let mut current_difficulty = self.difficulty.lock().await;
            *current_difficulty = block.difficulty;
        }

        // Ensure all changes are persisted
        self.db
            .flush()
            .map_err(|e| BlockchainError::FlushError(e.to_string()))?;

        Ok(())
    }

    async fn promote_orphans_from_tip(&self) -> Result<usize, BlockchainError> {
        let mut attached = 0usize;

        // Safety cap avoids pathological loops if orphan pool contains bad data.
        for _ in 0..256 {
            let Some(tip) = self.get_last_block() else {
                break;
            };

            let candidates = self.orphan_children_of(&tip.hash)?;
            let next_height = tip.index.saturating_add(1);
            let mut progressed = false;

            for candidate in candidates {
                if candidate.index != next_height || candidate.previous_hash != tip.hash {
                    continue;
                }

                match self.persist_validated_block(&candidate).await {
                    Ok(()) => {
                        attached = attached.saturating_add(1);
                        progressed = true;
                        break;
                    }
                    Err(_) => {
                        // Invalid child can never attach.
                        let _ = self.remove_orphan_by_hash(&candidate.hash);
                    }
                }
            }

            if !progressed {
                break;
            }
        }

        self.prune_orphans()?;
        Ok(attached)
    }

    fn pending_tx_ttl_secs() -> Option<u64> {
        const DEFAULT_TTL_SECS: u64 = 7200;
        let raw = std::env::var("ALPHANUMERIC_PENDING_TX_TTL_SECS").ok();
        let ttl = raw
            .as_deref()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_TTL_SECS);
        if ttl == 0 {
            None
        } else {
            Some(ttl)
        }
    }

    fn prune_pending_transactions(&self) -> Result<usize, BlockchainError> {
        let Some(ttl_secs) = Self::pending_tx_ttl_secs() else {
            return Ok(0);
        };
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let full_sigs_tree = self.db.open_tree(PENDING_FULL_SIGNATURES_TREE)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut removed = 0usize;
        for result in pending_tree.iter() {
            let (key, tx_bytes) = result?;
            let remove = match deserialize_transaction(&tx_bytes) {
                Ok(tx) => now.saturating_sub(tx.timestamp) > ttl_secs,
                Err(_) => true,
            };
            if remove {
                pending_tree.remove(key)?;
                // Best-effort: keep sidecar in sync with pending tx removals.
                let _ = full_sigs_tree.remove(&key);
                removed += 1;
            }
        }
        pending_tree.flush()?;
        full_sigs_tree.flush()?;
        Ok(removed)
    }
    fn signature_cache_capacity() -> NonZeroUsize {
        let default_size = 50_000usize;
        let size = std::env::var("ALPHANUMERIC_SIG_CACHE_SIZE")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(default_size);
        NonZeroUsize::new(size)
            .or_else(|| NonZeroUsize::new(default_size))
            .unwrap_or(NonZeroUsize::MIN)
    }

    fn get_balances_height(tree: &sled::Tree) -> Result<Option<u64>, BlockchainError> {
        if let Some(raw) = tree.get(BALANCES_HEIGHT_KEY)? {
            let height: u64 = bincode::deserialize(&raw)?;
            Ok(Some(height))
        } else {
            Ok(None)
        }
    }

    fn set_balances_height(tree: &sled::Tree, height: u64) -> Result<(), BlockchainError> {
        tree.insert(BALANCES_HEIGHT_KEY, bincode::serialize(&height)?)?;
        Ok(())
    }

    pub async fn ensure_balances_index(&self) -> Result<(), BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        let tip = self.get_latest_block_index();
        let force_rebuild = std::env::var("ALPHANUMERIC_REBUILD_BALANCES")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let current_height = Self::get_balances_height(&balances_tree)?;
        let needs_rebuild = force_rebuild
            || current_height.is_none()
            || current_height.unwrap_or(0) != tip;

        if needs_rebuild {
            self.rebuild_balances_index(&balances_tree).await?;
            Self::set_balances_height(&balances_tree, tip)?;
        }

        Ok(())
    }

    async fn rebuild_balances_index(
        &self,
        balances_tree: &sled::Tree,
    ) -> Result<(), BlockchainError> {
        balances_tree.clear()?;

        let mut blocks: Vec<Block> = self
            .db
            .scan_prefix(b"block_")
            .filter_map(|entry| {
                let (_, value) = entry.ok()?;
                Block::from_bytes(value.as_ref()).ok()
            })
            .collect();
        blocks.sort_unstable_by_key(|b| b.index);

        let mut balances: HashMap<String, f64> = HashMap::new();
        for block in blocks {
            for tx in block.transactions {
                if tx.sender != "MINING_REWARDS" {
                    let debit = tx.amount + tx.fee;
                    let entry = balances.entry(tx.sender).or_insert(0.0);
                    *entry = Transaction::round_amount(*entry - debit);
                }
                let entry = balances.entry(tx.recipient).or_insert(0.0);
                *entry = Transaction::round_amount(*entry + tx.amount);
            }
        }

        let mut batch = sled::Batch::default();
        for (address, balance) in balances {
            batch.insert(address.as_bytes(), bincode::serialize(&balance)?);
        }
        balances_tree.apply_batch(batch)?;

        Ok(())
    }
    pub fn new(
        db: Db,
        transaction_fee: f64,
        mining_reward: f64,
        difficulty_adjustment_interval: u64,
        block_time: u32,
        rate_limiter: Arc<RateLimiter>,
        difficulty: Arc<Mutex<u64>>, // Add difficulty parameter
    ) -> Self {
        let chain_sentinel = Arc::new(ChainSentinel::new());
        let signature_cache = Arc::new(PLMutex::new(LruCache::new(Self::signature_cache_capacity())));

        // Create the blockchain instance using passed in difficulty
        let blockchain = Self {
            db: db.clone(),
            difficulty, // Use passed difficulty instead of creating new
            transaction_fee,
            mining_reward,
            difficulty_adjustment_interval,
            block_time,
            rate_limiter,
            mempool: Arc::new(RwLock::new(Mempool::new())),
            chain_sentinel,
            temporal_verification: TemporalVerification::new(),
            signature_cache,
        };

        // Ensure pending tx trees exist (do not clear at startup).
        if let Ok(pending_tree) = db.open_tree(PENDING_TRANSACTIONS_TREE) {
            pending_tree.flush().ok();
        }
        let _ = db.open_tree(PENDING_FULL_SIGNATURES_TREE);
        let _ = db.open_tree(PENDING_DEBITS_TREE);
        // Ensure orphan-management trees exist.
        let _ = db.open_tree(ORPHAN_BLOCKS_TREE);
        let _ = db.open_tree(ORPHAN_INDEX_TREE);

        blockchain
    }

    pub async fn initialize(&self) -> Result<(), BlockchainError> {
        // Get and set the network difficulty first
        self.get_network_difficulty().await?;

        // Sync mempool with sled
        let _ = self.prune_pending_transactions();
        self.sync_mempool_with_sled().await?;
        self.rebuild_pending_debits_index().await?;

        // Ensure balances index is valid (rebuild if needed)
        self.ensure_balances_index().await?;
        self.prune_orphans()?;
        let _ = self.promote_orphans_from_tip().await;

        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let full_sigs_tree = self.db.open_tree(PENDING_FULL_SIGNATURES_TREE)?;
        let mut invalid_txs = Vec::new();

        for result in pending_tree.iter() {
            let (key, tx_bytes) = result?;
            if let Ok(tx) = deserialize_transaction(&tx_bytes) {
                if tx.sender == "MINING_REWARDS" {
                    invalid_txs.push(key.to_vec());
                    continue;
                }

                // Pending txs must be fully verifiable (via sidecar witness) before we keep them.
                if tx.pub_key.is_none() || tx.sig_hash.is_none() || tx.signature.is_none() {
                    invalid_txs.push(key.to_vec());
                    continue;
                }

                let mut full_tx = tx.clone();
                let tx_id = full_tx.get_tx_id();
                let expected_sig_hash = full_tx.sig_hash.as_ref().unwrap().clone();
                let sig_hex = full_tx.signature.as_ref().unwrap();
                let sig_bytes = match hex::decode(sig_hex) {
                    Ok(v) => v,
                    Err(_) => {
                        invalid_txs.push(key.to_vec());
                        continue;
                    }
                };

                if sig_bytes.len() <= 64 {
                    let Some(full_sig_bytes) = full_sigs_tree.get(tx_id.as_bytes())? else {
                        invalid_txs.push(key.to_vec());
                        continue;
                    };
                    let actual_hash = Transaction::signature_hash_hex(&full_sig_bytes);
                    if actual_hash != expected_sig_hash {
                        invalid_txs.push(key.to_vec());
                        continue;
                    }
                    full_tx.signature = Some(hex::encode(&full_sig_bytes));
                }

                if self.verify_transaction_signature(&full_tx).is_err() {
                    invalid_txs.push(key.to_vec());
                    continue;
                }
            } else {
                invalid_txs.push(key.to_vec());
            }
        }

        // Remove invalid transactions
        for key in invalid_txs {
            pending_tree.remove(&key)?;
            let _ = full_sigs_tree.remove(&key);
        }
        pending_tree.flush()?;
        full_sigs_tree.flush()?;
        self.rebuild_pending_debits_index().await?;

        Ok(())
    }

    pub async fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let difficulty = *self.difficulty.lock().await;

        // Retrieve pending transactions from sled
        let pending_transactions = match self.db.open_tree(PENDING_TRANSACTIONS_TREE) {
            Ok(tree) => {
                let mut transactions = Vec::new();
                for item in tree.iter() {
                    if let Ok((_, tx_bytes)) = item {
                    if let Ok(tx) = deserialize_transaction(&tx_bytes) {
                        transactions.push(tx);
                    }
                    }
                }
                transactions
            }
            Err(_) => Vec::new(),
        };

        f.debug_struct("Blockchain")
            .field("db", &self.db)
            .field("difficulty", &difficulty)
            .field("pending_transactions", &pending_transactions)
            .field("transaction_fee", &self.transaction_fee)
            .field("mining_reward", &self.mining_reward)
            .field(
                "difficulty_adjustment_interval",
                &self.difficulty_adjustment_interval,
            )
            .field("block_time", &self.block_time)
            .finish()
    }

    pub async fn save_block(&self, block: &Block) -> Result<(), BlockchainError> {
        // Enforce linear tip extension and park out-of-order blocks as orphans.
        match self.highest_block_index() {
            None => {
                if block.index != 0 || block.previous_hash != [0u8; 32] {
                    self.store_orphan_block(block)?;
                    let _ = self.try_adopt_orphan_branch().await?;
                    return Ok(());
                }
            }
            Some(tip_index) => {
                if block.index <= tip_index {
                    if let Ok(existing) = self.get_block(block.index) {
                        if existing.hash == block.hash {
                            return Ok(());
                        }
                    }
                    self.store_orphan_block(block)?;
                    let _ = self.try_adopt_orphan_branch().await?;
                    return Ok(());
                }
                if block.index != tip_index.saturating_add(1) {
                    self.store_orphan_block(block)?;
                    let _ = self.try_adopt_orphan_branch().await?;
                    return Ok(());
                }
                let prev = self.get_block(tip_index)?;
                if block.previous_hash != prev.hash {
                    self.store_orphan_block(block)?;
                    let _ = self.try_adopt_orphan_branch().await?;
                    return Ok(());
                }
            }
        }

        self.persist_validated_block(block).await?;
        let _ = self.promote_orphans_from_tip().await?;
        let _ = self.try_adopt_orphan_branch().await?;
        Ok(())
    }

    pub async fn finalize_block(
        &self,
        block: Block,
        _miner_address: String,
    ) -> Result<(), BlockchainError> {
        let trace_finalize = std::env::var("ALPHANUMERIC_TRACE_FINALIZE")
            .map(|v| !v.trim().is_empty() && v.trim() != "0")
            .unwrap_or(false);
        let t0 = Instant::now();
        let mut last = t0;
        let mut trace_step = |label: &str| {
            if trace_finalize {
                let now = Instant::now();
                eprintln!(
                    "[finalize] {}: +{}ms (total {}ms)",
                    label,
                    now.duration_since(last).as_millis(),
                    now.duration_since(t0).as_millis()
                );
                last = now;
            }
        };

        trace_step("start");

        // Ensure locally finalized blocks still extend the current canonical tip.
        match self.highest_block_index() {
            None => {
                if block.index != 0 || block.previous_hash != [0u8; 32] {
                    return Err(BlockchainError::InvalidBlockHeader);
                }
            }
            Some(tip_index) => {
                if block.index != tip_index.saturating_add(1) {
                    return Err(BlockchainError::InvalidBlockHeader);
                }
                let prev = self.get_block(tip_index)?;
                if block.previous_hash != prev.hash {
                    return Err(BlockchainError::InvalidBlockHeader);
                }
            }
        }

        // Do not mutate mined header fields here. Mining must include final transactions/root.
        set_finalize_stage(1);
        trace_step("prevalidate");
        self.validate_block_strict(&block).await?;

        // Get all current confirmed balances first
        let mut confirmed_balances: HashMap<String, f64> = HashMap::new();
        let mut pending_effects: HashMap<String, f64> = HashMap::new();

        // First pass: Get all confirmed balances
        for tx in &block.transactions {
            if tx.sender != "MINING_REWARDS" {
                if !confirmed_balances.contains_key(&tx.sender) {
                    let balance = self.get_confirmed_balance(&tx.sender).await?;
                    confirmed_balances.insert(tx.sender.clone(), balance);
                }
            }
        }
        set_finalize_stage(2);
        trace_step("prefetch_balances");

        // Second pass: Validate transactions and track effects
        for tx in &block.transactions {
            if tx.sender == "MINING_REWARDS" {
                continue; // Skip validation for mining rewards
            }

            let confirmed = confirmed_balances.get(&tx.sender).copied().unwrap_or(0.0);
            let pending = pending_effects.get(&tx.sender).copied().unwrap_or(0.0);
            let available = confirmed - pending;
            let required = tx.amount + tx.fee;

            if available < required {
                return Err(BlockchainError::InsufficientFunds);
            }

            // Track this transaction's effect
            *pending_effects.entry(tx.sender.clone()).or_default() += required;
            *pending_effects.entry(tx.recipient.clone()).or_default() -= tx.amount;
        }
        set_finalize_stage(3);
        trace_step("validate_batch");

        // Process transactions atomically
        self.process_transactions_batch(
            block.transactions.clone(),
            TransactionContext::BlockValidation,
        )
        .await?;
        set_finalize_stage(4);
        trace_step("apply_batch");

        // Save block with truncated signatures to reduce on-disk chain size.
        let storage_block = Self::to_storage_block(&block);
        let value = bincode::serialize(&storage_block)?;
        let key = format!("block_{}", block.index);
        self.db.insert(key.as_bytes(), value)?;
        set_finalize_stage(5);
        trace_step("db_insert");
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        Self::set_balances_height(&balances_tree, block.index as u64)?;
        set_finalize_stage(6);
        trace_step("balances_height");
        self.db.flush()?;
        let _ = self.promote_orphans_from_tip().await;

        Ok(())
    }

    pub async fn clear_processed_transactions(
        &self,
        transactions: &[Transaction],
    ) -> Result<(), BlockchainError> {
        // Clear from pending transactions tree
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let full_sigs_tree = self.db.open_tree(PENDING_FULL_SIGNATURES_TREE)?;
        let pending_debits_tree = self.open_pending_debits_tree()?;
        let mut batch = sled::Batch::default();
        let mut full_batch = sled::Batch::default();

        for tx in transactions {
            // Use tx_id instead of string formatting
            let tx_id = tx.get_tx_id();

            // Remove from pending tree
            batch.remove(tx_id.as_bytes());
            full_batch.remove(tx_id.as_bytes());

            if tx.sender != "MINING_REWARDS" {
                let current_debit = self.get_pending_debit_for(&tx.sender).await?;
                let delta = tx.amount + tx.fee;
                let next_debit = Transaction::round_amount((current_debit - delta).max(0.0));
                Self::set_pending_debit_for(&pending_debits_tree, &tx.sender, next_debit)?;
            }
        }

        // Apply batch deletion
        pending_tree.apply_batch(batch)?;
        full_sigs_tree.apply_batch(full_batch)?;

        // Clear from mempool
        let mut mempool = self.mempool.write().await;
        for tx in transactions {
            mempool.clear_transaction(tx);
        }

        // Ensure changes are persisted
        pending_tree.flush()?;
        full_sigs_tree.flush()?;
        pending_debits_tree.flush()?;

        Ok(())
    }

    // Retrieve the latest block's index
    pub fn get_latest_block_index(&self) -> u64 {
        self.highest_block_index().map(u64::from).unwrap_or(0)
    }

    pub fn get_last_block_hash(&self) -> Result<[u8; 32], BlockchainError> {
        let tip = self
            .highest_block_index()
            .ok_or_else(|| BlockchainError::FlushError("No blocks found".to_string()))?;
        self.get_block(tip).map(|b| b.hash)
    }

    pub fn get_latest_block_hash(&self) -> [u8; 32] {
        self.highest_block_index()
            .and_then(|idx| self.get_block(idx).ok())
            .map(|b| b.hash)
            .unwrap_or([0u8; 32])
    }

    pub fn get_last_block(&self) -> Option<Block> {
        self.highest_block_index()
            .and_then(|idx| self.get_block(idx).ok())
    }

    pub fn get_block_count(&self) -> usize {
        self.db.scan_prefix("block_").count()
    }

    pub fn get_blocks(&self) -> Vec<Block> {
        let mut blocks: Vec<_> = self
            .db
            .scan_prefix(b"block_")
            .filter_map(|r| r.ok())
            .filter_map(|(_, value)| Block::from_bytes(&value).ok())
            .collect();
        blocks.sort_unstable_by_key(|b| b.index);
        blocks
    }

    pub fn get_orphan_count(&self) -> usize {
        self.open_orphan_blocks_tree()
            .map(|t| t.len())
            .unwrap_or(0)
    }

    pub async fn get_current_difficulty(&self) -> u64 {
        let last_block = self.get_last_block();
        if let Some(block) = last_block {
            let mut difficulty_oracle = DifficultyOracle::new();
            Block::adjust_dynamic_difficulty(
                block.difficulty,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_sub(block.timestamp),
                block.index + 1,
                &mut difficulty_oracle,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )
        } else {
            *self.difficulty.lock().await
        }
    }

    pub async fn get_network_difficulty(&self) -> Result<u64, BlockchainError> {
        if let Some(last_block) = self.get_last_block() {
            let mut difficulty_lock = self.difficulty.lock().await;
            *difficulty_lock = last_block.difficulty;
            Ok(last_block.difficulty)
        } else {
            Ok(*self.difficulty.lock().await)
        }
    }

    fn detect_difficulty_manipulation(&self, block: &Block) -> Result<(), BlockchainError> {
        // Get recent blocks
        let recent_blocks = self
            .get_blocks()
            .into_iter()
            .rev()
            .take(50)
            .collect::<Vec<_>>();

        if recent_blocks.is_empty() {
            return Ok(());
        }

        // Calculate statistical measures
        let mut difficulties: Vec<u64> = recent_blocks.iter().map(|b| b.difficulty).collect();

        difficulties.sort_unstable();
        let median = difficulties[difficulties.len() / 2];

        // Calculate mean absolute deviation
        let mad: f64 = difficulties
            .iter()
            .map(|&d| (d as i64 - median as i64).abs() as f64)
            .sum::<f64>()
            / difficulties.len() as f64;

        // Check if new difficulty is within acceptable range
        let diff = (block.difficulty as i64 - median as i64).abs() as f64;
        if diff > mad * 3.0 {
            // Using 3 MAD as threshold
            return Err(BlockchainError::InvalidBlockHeader);
        }

        Ok(())
    }

    pub fn get_genesis_block(&self) -> Result<Block, BlockchainError> {
        self.get_block(0)
    }

    pub async fn calculate_wallet_balance(&self, address: &str) -> Result<f64, BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;

        if let Some(balance_bytes) = balances_tree.get(address.as_bytes())? {
            let balance: f64 = bincode::deserialize(&balance_bytes)
                .map_err(|e| BlockchainError::SerializationError(Box::new(e)))?;
            Ok(balance)
        } else {
            Ok(0.0)
        }
    }
    // Validation
    pub async fn validate_chain(
        &self,
        mining_manager: &MiningManager,
    ) -> Result<bool, BlockchainError> {
        let mut previous_block: Option<Block> = None;

        for item in self.db.iter() {
            let (_, value) = item.map_err(BlockchainError::DatabaseError)?;
            let current_block =
                Block::from_bytes(&value).map_err(|e| BlockchainError::SerializationError(e))?;

            let epoch = mining_manager
                .get_last_epoch()
                .await
                .map_err(|e| BlockchainError::MiningError(e.to_string()))?;

            if let Err(e) = self.validate_block(&current_block).await {
                error!("Block validation failed: {:?}", e);
                return Ok(false);
            }

            // Check if the current block's previous_hash matches the previous block's hash
            if let Some(prev) = previous_block {
                if current_block.previous_hash != prev.hash {
                    error!(
                        "Block hash mismatch: expected {:?}, got {:?}",
                        prev.hash, current_block.previous_hash
                    );
                    return Ok(false);
                }
            }

            // Set the current block as the previous block for the next iteration
            previous_block = Some(current_block);
        }

        // If all blocks are validated successfully, return true
        Ok(true)
    }

    pub async fn validate_transaction(
        &self,
        tx: &Transaction,
        block: Option<&Block>,
    ) -> Result<(), BlockchainError> {
        // Special handling for system transactions like mining rewards
        if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
            let block = block.ok_or(BlockchainError::InvalidSystemTransaction)?;
            return SystemKeyDeriver::verify_system_transaction(
                tx,
                block,
                if tx.sender == "MINING_REWARDS" {
                    SystemTransactionType::MiningReward
                } else {
                    SystemTransactionType::GovernanceDistribution
                },
            )
            .await;
        }

        // For regular transactions, validate balance with proper pending tracking
        let confirmed_balance = self.get_confirmed_balance(&tx.sender).await?;
        let pending_amount = if block.is_none() {
            // Only check pending for new transactions, not during block validation
            self.get_pending_amount(&tx.sender).await?
        } else {
            0.0
        };

        let available_balance = Transaction::round_amount(confirmed_balance - pending_amount);
        let required_amount = Transaction::round_amount(tx.amount + tx.fee);

        if available_balance < required_amount {
            return Err(BlockchainError::InsufficientFunds);
        }

        // Continue with signature validation (must be fully verifiable for non-system txs).
        self.verify_transaction_signature(tx)?;
        Ok(())
    }

    pub fn verify_transaction_signature(&self, tx: &Transaction) -> Result<(), BlockchainError> {
        if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
            return Ok(());
        }

        let sig_hex = tx
            .signature
            .as_ref()
            .ok_or(BlockchainError::InvalidTransactionSignature)?;

        let sig_bytes =
            hex::decode(sig_hex).map_err(|_| BlockchainError::InvalidTransactionSignature)?;
        if sig_bytes.is_empty() {
            return Err(BlockchainError::InvalidTransactionSignature);
        }
        let pub_key = match tx.pub_key.as_ref() {
            Some(pk) => pk,
            None => {
                return Err(BlockchainError::InvalidTransactionSignature);
            }
        };
        let actual_hash = Transaction::signature_hash_hex(&sig_bytes);
        let cache_key = format!("{}:{}:{}", tx.get_tx_id(), pub_key, actual_hash);

        if let Some(true) = self.signature_cache.lock().get(&cache_key).copied() {
            return Ok(());
        }

        if !tx.is_valid(pub_key) {
            return Err(BlockchainError::InvalidTransactionSignature);
        }

        // Verify address ownership (pubkey -> address)
        let mut hasher = Sha256::new();
        let pub_key_bytes =
            hex::decode(pub_key).map_err(|_| BlockchainError::InvalidTransactionSignature)?;
        hasher.update(&pub_key_bytes);
        let derived_addr = hex::encode(&hasher.finalize()[..20]);
        if derived_addr != tx.sender {
            return Err(BlockchainError::InvalidTransactionSignature);
        }

        if let Some(expected_hash) = &tx.sig_hash {
            if &actual_hash != expected_hash {
                return Err(BlockchainError::InvalidTransactionSignature);
            }
        }

        self.signature_cache.lock().put(cache_key, true);
        Ok(())
    }

    pub fn get_block_by_timestamp(&self, timestamp: u64) -> Result<Block, BlockchainError> {
        self.get_blocks()
            .into_iter()
            .find(|block| block.timestamp == timestamp)
            .ok_or(BlockchainError::InvalidTransaction)
    }

    fn validate_system_transaction(
        &self,
        tx: &Transaction,
        block: &Block,
    ) -> Result<(), BlockchainError> {
        if tx.sender != "MINING_REWARDS" {
            return Err(BlockchainError::InvalidSystemTransaction); // Handle other system tx types if needed
        }

        if block.transactions.is_empty() || block.transactions[0].sender != "MINING_REWARDS" {
            return Err(BlockchainError::InvalidSystemTransaction); // Not the first transaction
        }

        let reward_tx = &block.transactions[0];

        if reward_tx.fee != NETWORK_FEE || reward_tx.signature.is_some() {
            return Err(BlockchainError::InvalidSystemTransaction);
        }

        let expected_reward = self.calculate_block_reward(block)?; // Calculate expected reward
        if Transaction::round_amount(reward_tx.amount) != expected_reward {
            return Err(BlockchainError::InvalidTransactionAmount);
        }

        Ok(())
    }

    fn is_valid_hash_with_difficulty(&self, hash: &[u8; 32], difficulty: u64) -> bool {
        let hash_int = BigUint::from_bytes_be(hash);

        let target = if difficulty == 0 {
            MAX_TARGET.clone()
        } else {
            // Convert everything to BigUint to avoid overflow
            let two = BigUint::from(2u8);
            let sixteen = BigUint::from(16u8);
            let difficulty = BigUint::from(difficulty);

            // Calculate (difficulty / 16) using BigUint division
            let scaled_difficulty = difficulty / sixteen;

            // Calculate 2^(difficulty/16) using BigUint pow
            let divisor = two.pow(scaled_difficulty.to_u32().unwrap_or(0));

            // Finally divide max_target by the calculated divisor
            MAX_TARGET.clone() / divisor
        };

        hash_int <= target
    }

    pub async fn validate_block(&self, block: &Block) -> Result<(), BlockchainError> {
        self.validate_block_internal(block, SignatureValidationMode::AllowTruncatedStored)
            .await
    }

    async fn validate_block_strict(&self, block: &Block) -> Result<(), BlockchainError> {
        self.validate_block_internal(block, SignatureValidationMode::RequireFull)
            .await
    }

    async fn validate_block_internal(
        &self,
        block: &Block,
        sig_mode: SignatureValidationMode,
    ) -> Result<(), BlockchainError> {
        // First validate block header
        block.validate_header()?;

        // Verify merkle root matches transactions
        let expected_root = Blockchain::calculate_merkle_root(&block.transactions)?;
        if expected_root != block.merkle_root {
            return Err(BlockchainError::InvalidBlockHeader);
        }

        // Check the hash meets the difficulty requirement
        if !self.is_valid_hash_with_difficulty(&block.hash, block.difficulty) {
            return Err(BlockchainError::InvalidHash);
        }

        // Enhanced difficulty validation for non-genesis blocks
        if block.index > 0 {
            let previous_block = self.get_block(block.index - 1)?;
            let expected_difficulty = Block::adjust_dynamic_difficulty(
                previous_block.difficulty,
                block.timestamp.saturating_sub(previous_block.timestamp),
                block.index,
                &mut DifficultyOracle::new(), // Create difficulty oracle once
                block.timestamp,
            );

            // Allow small variance for network synchronization (0.1% tolerance)
            let diff_ratio = (block.difficulty as f64) / (expected_difficulty as f64);
            if (diff_ratio - 1.0).abs() > 0.001 {
                return Err(BlockchainError::InvalidBlockHeader);
            }
        }

        // Validate transactions if present
        let reward_txs: Vec<&Transaction> = block
            .transactions
            .iter()
            .filter(|tx| tx.sender == "MINING_REWARDS")
            .collect();

        if reward_txs.len() != 1 {
            return Err(BlockchainError::InvalidSystemTransaction);
        }

        if block
            .transactions
            .first()
            .map(|tx| tx.sender.as_str())
            != Some("MINING_REWARDS")
        {
            return Err(BlockchainError::InvalidSystemTransaction);
        }

        let reward_tx = reward_txs[0];
        if reward_tx.fee != NETWORK_FEE {
            return Err(BlockchainError::InvalidSystemTransaction);
        }
        let expected_reward = self.calculate_block_reward(block)?;
        if Transaction::round_amount(reward_tx.amount) != expected_reward {
            return Err(BlockchainError::InvalidTransactionAmount);
        }

        for tx in &block.transactions {
            if tx.sender == "MINING_REWARDS" {
                continue;
            }
            if tx.amount < MIN_TRANSACTION_AMOUNT {
                return Err(BlockchainError::InvalidTransactionAmount);
            }
            if tx.signature.is_none() {
                return Err(BlockchainError::InvalidTransactionSignature);
            }
            if tx.pub_key.is_none() || tx.sig_hash.is_none() {
                return Err(BlockchainError::InvalidTransactionSignature);
            }

            let sig_hex = tx
                .signature
                .as_ref()
                .ok_or(BlockchainError::InvalidTransactionSignature)?;
            let sig_bytes =
                hex::decode(sig_hex).map_err(|_| BlockchainError::InvalidTransactionSignature)?;

            // Stored blocks keep truncated sig bytes by design; incoming blocks must be fully verifiable.
            if sig_mode == SignatureValidationMode::RequireFull && sig_bytes.len() <= 64 {
                return Err(BlockchainError::InvalidTransactionSignature);
            }

            // Verify when the full signature is present.
            if sig_bytes.len() > 64 {
                self.verify_transaction_signature(tx)?;
            }
        }

        Ok(())
    }

    async fn get_weighted_average_timestamp(&self) -> Result<u64, BlockchainError> {
        let block_count = self.get_block_count();
        if block_count == 0 {
            return Ok(SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs());
        }

        let num_blocks_to_consider = std::cmp::min(11, block_count as usize); // Same as MTP
        let mut weighted_sum = 0u64;
        let mut total_weight = 0u64;

        for i in 0..num_blocks_to_consider {
            let block = self.get_block((block_count as usize - 1 - i) as u32)?;
            let weight = (num_blocks_to_consider - i) as u64; // Linear weighting
            weighted_sum += block.timestamp * weight;
            total_weight += weight;
        }

        Ok(weighted_sum / total_weight)
    }

    pub async fn validate_new_block(&self, block: &Block) -> Result<(), BlockchainError> {
        // Basic Header Validation
        block.validate_header()?;

        // Get current confirmed balances before validation
        let mut confirmed_balances: HashMap<String, f64> = HashMap::new();
        let mut pending_deductions: HashMap<String, f64> = HashMap::new();

        // Only look at non-mining-reward transactions
        let regular_transactions: Vec<&Transaction> = block
            .transactions
            .iter()
            .filter(|tx| tx.sender != "MINING_REWARDS")
            .collect();

        // Get all unique sender addresses
        let unique_senders: HashSet<&String> =
            regular_transactions.iter().map(|tx| &tx.sender).collect();

        // Fetch all confirmed balances in one pass
        for sender in unique_senders {
            let balance = self.get_confirmed_balance(sender).await?;
            confirmed_balances.insert(sender.clone(), balance);
        }

        // Validate each regular transaction
        for tx in regular_transactions {
            let current_confirmed = confirmed_balances.get(&tx.sender).copied().unwrap_or(0.0);

            let pending_deducted = pending_deductions.get(&tx.sender).copied().unwrap_or(0.0);

            let available_balance = current_confirmed - pending_deducted;
            let required_amount = tx.amount + tx.fee;

            if available_balance < required_amount {
                return Err(BlockchainError::InsufficientFunds);
            }

            // Track this deduction for subsequent transactions
            *pending_deductions.entry(tx.sender.clone()).or_default() += required_amount;
        }

        Ok(())
    }

    // New helper method to calculate confirmed balance without pending transactions
    async fn calculate_confirmed_balance(&self, address: &str) -> Result<f64, BlockchainError> {
        let mut balance = 0.0;

        // Only consider confirmed blocks
        for result in self.db.scan_prefix("block_") {
            if let Ok((_, block_data)) = result {
                if let Ok(block) = Block::from_bytes(&block_data) {
                    for tx in block.transactions {
                        if tx.recipient == address {
                            balance = Transaction::round_amount(balance + tx.amount);
                        }
                        if tx.sender == address && tx.sender != "MINING_REWARDS" {
                            balance = Transaction::round_amount(balance - (tx.amount + tx.fee));
                        }
                    }
                }
            }
        }

        Ok(balance)
    }

    pub async fn add_transaction(&self, transaction: Transaction) -> Result<(), BlockchainError> {
        if transaction.sender == "MINING_REWARDS" {
            return Err(BlockchainError::InvalidTransaction);
        }

        // Rate limit check
        if !self.rate_limiter.check_limit(&transaction.sender) {
            return Err(BlockchainError::RateLimitExceeded(
                "Too many requests".into(),
            ));
        }

        // Check if the transaction amount is below the minimum threshold
        if transaction.amount < MIN_TRANSACTION_AMOUNT {
            return Err(BlockchainError::InvalidTransactionAmount);
        }

        // Get confirmed balance and pending debit index (O(1) lookup)
        let mempool_guard = self.mempool.read().await;
        
        let confirmed_balance = self.get_confirmed_balance(&transaction.sender).await?;
        let pending_amount = self.get_pending_debit_for(&transaction.sender).await?;

        // Calculate available balance considering pending transactions
        let available_balance = confirmed_balance - pending_amount;
        let total_required = transaction.amount + transaction.fee;

        // Check if there's enough available balance
        if available_balance < total_required {
            return Err(BlockchainError::InsufficientFunds);
        }

        // Signature verification with public key binding
        let pub_key = match transaction.pub_key.as_ref() {
            Some(pk) => pk,
            None => {
                return Err(BlockchainError::InvalidTransactionSignature);
            }
        };
        let sig_hex = transaction
            .signature
            .as_ref()
            .ok_or(BlockchainError::InvalidTransactionSignature)?;

        let sig_bytes =
            hex::decode(sig_hex).map_err(|_| BlockchainError::InvalidTransactionSignature)?;
        if !transaction.is_valid(pub_key) {
            return Err(BlockchainError::InvalidTransactionSignature);
        }

        // Verify address ownership (pubkey -> address)
        let mut hasher = Sha256::new();
        let pub_key_bytes =
            hex::decode(pub_key).map_err(|_| BlockchainError::InvalidTransactionSignature)?;
        hasher.update(&pub_key_bytes);
        let derived_addr = hex::encode(&hasher.finalize()[..20]);
        if derived_addr != transaction.sender {
            return Err(BlockchainError::InvalidTransactionSignature);
        }

        let sig_hash = Transaction::signature_hash_hex(&sig_bytes);

        // Ensure mempool has full signature + sig_hash
        let mut mempool_tx = transaction.clone();
        mempool_tx.sig_hash = Some(sig_hash.clone());

        // Create storage version with truncated signature + signature hash
        let storage_tx = mempool_tx.with_truncated_signature(sig_hash);
        let tx_id = storage_tx.get_tx_id();

        // Add to mempool first (faster in-memory operation)
        drop(mempool_guard); // Release read lock before getting write lock
        self.add_to_mempool(mempool_tx).await?;

        // Store full signature witness in sidecar (keyed by tx_id) so mempool can be rehydrated after restart.
        // The main pending tx record remains compact (truncated signature + sig_hash).
        let full_sigs_tree = self.db.open_tree(PENDING_FULL_SIGNATURES_TREE)?;
        full_sigs_tree.insert(tx_id.as_bytes(), sig_bytes)?;
        full_sigs_tree.flush()?;

        // Store in pending transactions
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let pending_debits_tree = self.open_pending_debits_tree()?;
        let tx_bytes = bincode::serialize(&storage_tx)?;

        // Use batch operation for atomic updates
        let mut batch = sled::Batch::default();
        batch.insert(tx_id.as_bytes(), tx_bytes);
        pending_tree.apply_batch(batch)?;

        let current_debit = self.get_pending_debit_for(&transaction.sender).await?;
        let next_debit =
            Transaction::round_amount(current_debit + storage_tx.amount + storage_tx.fee);
        Self::set_pending_debit_for(&pending_debits_tree, &transaction.sender, next_debit)?;

        pending_tree.flush()?;
        pending_debits_tree.flush()?;

        Ok(())
    }

    pub async fn get_pending_amount(&self, address: &str) -> Result<f64, BlockchainError> {
        self.get_pending_debit_for(address).await
    }

    pub async fn get_transactions_for_block(&self) -> Vec<Transaction> {
        let mut mempool = self.mempool.write().await;
        mempool.prune_expired();
        mempool.get_transactions_for_block()
    }

    pub async fn get_mempool_transactions(&self) -> Result<Vec<Transaction>, BlockchainError> {
        let mut mempool = self.mempool.write().await;
        mempool.prune_expired();
        Ok(mempool.get_transactions_for_block())
    }

    pub async fn get_mempool_transaction_by_id(&self, tx_id: &str) -> Option<Transaction> {
        self.mempool.read().await.find_transaction_by_id(tx_id)
    }

    pub async fn add_to_mempool(&self, tx: Transaction) -> Result<(), BlockchainError> {
        self.mempool.write().await.add_transaction(tx)
    }

    pub fn get_transaction_by_hash(&self, hash: &str) -> Option<Transaction> {
        for result in self.db.iter() {
            if let Ok((_, value)) = result {
                if let Ok(block) = Block::from_bytes(&value) {
                    for tx in block.transactions {
                        if tx.create_hash() == hash {
                            return Some(tx);
                        }
                    }
                }
            }
        }
        None
    }

    pub fn calculate_block_reward(&self, block: &Block) -> Result<f64, BlockchainError> {
        const SECONDS_IN_SIX_MONTHS: u64 = 15_768_000; // 182.5 days
        const REDUCTION_RATE: f64 = 0.83; // 17% reduction = multiply by 0.83

        // Calculate periods since genesis for halving
        let genesis = self.get_genesis_block()?;
        let time_since_genesis = block.timestamp.saturating_sub(genesis.timestamp);
        let periods = time_since_genesis / SECONDS_IN_SIX_MONTHS;

        // Apply reduction rate for each period to max reward
        let current_max = MAX_BLOCK_REWARD * REDUCTION_RATE.powi(periods as i32);

        // Get transaction metrics and sum fees in a single pass (excluding mining rewards)
        let (tx_count, total_volume, total_fees) = block
            .transactions
            .iter()
            .filter(|tx| tx.sender != "MINING_REWARDS")
            .fold((0usize, 0.0, 0.0), |(count, volume, fees), tx| {
                (count + 1, volume + tx.amount, fees + tx.fee)
            });

        // Fee-weighted reward to avoid incentivizing spammy tx counts.
        let fee_target = (current_max * 0.05).max(0.0001);
        let effective_fees = total_fees * (1.0 - MINT_CLIP);
        let fee_factor = (effective_fees / fee_target).clamp(0.0, 1.0);

        // Base reward calculation
        let base_reward = if tx_count == 0 {
            current_max * 0.2 // 20% of max reward for empty blocks
        } else {
            MIN_BLOCK_REWARD + ((current_max - MIN_BLOCK_REWARD) * fee_factor)
        };

        // Add transaction fees to the base reward
        let final_reward = Transaction::round_amount(
            (base_reward + effective_fees).clamp(MIN_BLOCK_REWARD, current_max),
        );

        Ok(final_reward)
    }

    // Network hashrate
    pub async fn calculate_network_hashrate(&self) -> f64 {
        if let Some(last_block) = self.get_last_block() {
            if let Ok(prev_block) = self.get_block(last_block.index.saturating_sub(1)) {
                let time_diff = last_block.timestamp.saturating_sub(prev_block.timestamp);
                if time_diff > 0 {
                    let target = if last_block.difficulty == 0 {
                        MAX_TARGET.clone()
                    } else {
                        let mut target = MAX_TARGET.clone();
                        let mut scaled_difficulty = last_block.difficulty / 16;
                        let two = BigUint::from(2u8);

                        while scaled_difficulty > 0 {
                            target /= &two;
                            scaled_difficulty -= 1;
                        }
                        target
                    };
                    let hashrate = MAX_TARGET.to_f64().unwrap_or(0.0)
                        / target.to_f64().unwrap_or(1.0)
                        / time_diff as f64;
                    return hashrate / 1_000_000_000_000.0; // TH/s
                }
            }
        }
        0.0
    }

    pub fn get_block_reward(&self, transactions: &[Transaction]) -> f64 {
        // Create block with proper chain context
        let last_block = self.get_last_block();
        let current_index = last_block.as_ref().map(|b| b.index + 1).unwrap_or(0);
        let previous_hash = last_block.as_ref().map(|b| b.hash).unwrap_or([0u8; 32]);

        match self.calculate_block_reward(&Block {
            index: current_index,
            previous_hash,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            transactions: transactions.to_vec(),
            nonce: 0,
            difficulty: 0,
            hash: [0u8; 32],
            merkle_root: [0u8; 32],
        }) {
            Ok(reward) => reward,
            Err(_) => MIN_BLOCK_REWARD,
        }
    }

    // Genesis block
    pub async fn create_genesis_block(
        &self,
        mining_manager: &MiningManager,
    ) -> Result<(), BlockchainError> {
        let transaction_amount = 17.76;
        let fee = transaction_amount * FEE_PERCENTAGE;

        let sender_address = "1A1zP1eP5QGefi2DMpileTL5SLmv7DivfNa".to_string();
        let recipient_address = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy".to_string();

        let genesis_transaction = Transaction::new(
            sender_address,
            recipient_address,
            transaction_amount,
            fee,
            Utc::now().timestamp() as u64,
            None,
        );

        let genesis_block = Block::new(
            0,                             // Block index
            [0u8; 32],                     // Previous block hash
            Utc::now().timestamp() as u64, // Timestamp
            vec![genesis_transaction],     // Include genesis transaction
            0,                             // Nonce
            100,                           // Initial difficulty
        )?;

        self.save_block(&genesis_block).await.map_err(|e| {
            error!("Failed to save genesis block: {}", e);
            e
        })
    }


    pub async fn sync_mempool_with_sled(&self) -> Result<(), BlockchainError> {
        // Clear existing mempool
        let mut mempool = self.mempool.write().await;

        // Get pending transactions from sled
        let _ = self.prune_pending_transactions();
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let full_sigs_tree = self.db.open_tree(PENDING_FULL_SIGNATURES_TREE)?;

        // Collect all transactions from sled
        let mut transactions = Vec::new();
        for result in pending_tree.iter() {
            let (_, tx_bytes) = result?;
            if let Ok(mut tx) = deserialize_transaction(&tx_bytes) {
                // Pending txs are stored with a truncated signature in the main record. Rehydrate the full signature
                // from the sidecar tree and strictly verify before admitting into the in-memory mempool.
                if tx.sender != "MINING_REWARDS" {
                    if tx.pub_key.is_none() || tx.sig_hash.is_none() || tx.signature.is_none() {
                        continue;
                    }

                    let tx_id = tx.get_tx_id();
                    let expected_sig_hash = tx.sig_hash.as_ref().unwrap();

                    let sig_hex = tx.signature.as_ref().unwrap();
                    let sig_bytes = match hex::decode(sig_hex) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    if sig_bytes.len() <= 64 {
                        let Some(full_sig_bytes) = full_sigs_tree.get(tx_id.as_bytes())? else {
                            // No witness available; do not allow unverifiable tx into the mempool.
                            continue;
                        };

                        let actual_hash = Transaction::signature_hash_hex(&full_sig_bytes);
                        if &actual_hash != expected_sig_hash {
                            continue;
                        }

                        tx.signature = Some(hex::encode(&full_sig_bytes));
                    }

                    if self.verify_transaction_signature(&tx).is_err() {
                        continue;
                    }
                }

                transactions.push(tx);
            }
        }

        // Reset mempool and add all transactions
        *mempool = Mempool::new();
        for tx in transactions {
            mempool.add_transaction(tx)?;
        }
        drop(mempool);
        self.rebuild_pending_debits_index().await?;

        Ok(())
    }

    pub async fn get_pending_transactions(&self) -> Result<Vec<Transaction>, BlockchainError> {
        // First sync mempool with sled
        self.sync_mempool_with_sled().await?;

        // Now get transactions from sled
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let mut transactions = Vec::new();

        for result in pending_tree.iter() {
            let (_, tx_bytes) = result?;
            if let Ok(transaction) = deserialize_transaction(&tx_bytes) {
                transactions.push(transaction);
            }
        }

        Ok(transactions)
    }

    // Temporal Provenance with Causal Linking
    pub async fn get_temporally_verified_balance(
        &self,
        address: &str,
    ) -> Result<f64, BlockchainError> {
        // ... (address decoding as before)

        let blocks = self.get_blocks();
        let mut balance = 0.0;
        let mut causal_chain = Vec::new();

        // Process blocks and build causal chain (as before)
        for block in &blocks {
            let hash = block.calculate_hash_for_block();
            for tx in block.transactions.iter() {
                if tx.sender == address || tx.recipient == address {
                    causal_chain.push((tx.clone(), hash, block.index, block.timestamp));
                }
            }
        }

        causal_chain.sort_by_key(|entry| (entry.2, entry.3));

        for entry in &causal_chain {
            let tx = &entry.0;
            if tx.sender == "MINING_REWARDS" && tx.recipient == address {
                balance += tx.amount;
            } else if tx.sender == address {
                // Transactions in confirmed blocks are assumed validated at acceptance time.
                // Do not re-check signatures here with sender address input.
                balance -= tx.amount + tx.fee;
            } else if tx.recipient == address {
                balance += tx.amount;
            }
        }

        // Handle pending transactions CORRECTLY
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let mut pending_balances: HashMap<String, f64> = HashMap::new(); // Track pending balances

        for result in pending_tree.iter() {
            if let Ok((_, tx_bytes)) = result {
                if let Ok(tx) = deserialize_transaction(&tx_bytes) {
                    if tx.sender == address {
                        let pending_spent = pending_balances.get(address).unwrap_or(&0.0);
                        // Get current balance from confirmed transactions
                        let current_balance = balance;
                        if current_balance + pending_spent < tx.amount + tx.fee {
                            continue; // Skip double-spending transaction
                        }
                        balance -= tx.amount + tx.fee;
                        *pending_balances.entry(address.to_string()).or_insert(0.0) -=
                            tx.amount + tx.fee;
                    } else if tx.recipient == address {
                        balance += tx.amount;
                    }
                }
            }
        }

        Ok(balance)
    }

    // Add to handle distributions
    pub async fn process_transactions_batch(
        &self,
        transactions: Vec<Transaction>,
        context: TransactionContext,
    ) -> Result<(), BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let full_sigs_tree = self.db.open_tree(PENDING_FULL_SIGNATURES_TREE)?;
        let pending_debits_tree = self.open_pending_debits_tree()?;

        // Track cumulative balance changes
        let mut balance_changes: HashMap<String, f64> = HashMap::new();
        let mut current_balances: HashMap<String, f64> = HashMap::new();

        // First pass: Get all current balances for any address touched by this batch
        for tx in &transactions {
            if tx.sender != "MINING_REWARDS" && !current_balances.contains_key(&tx.sender) {
                let balance = self.get_confirmed_balance(&tx.sender).await?;
                current_balances.insert(tx.sender.clone(), balance);
            }
            if !current_balances.contains_key(&tx.recipient) {
                let balance = self.get_confirmed_balance(&tx.recipient).await?;
                current_balances.insert(tx.recipient.clone(), balance);
            }
        }

        // Second pass: Validate and calculate changes
        for tx in &transactions {
            match tx.sender.as_str() {
                "MINING_REWARDS" => {
                    if context == TransactionContext::BlockValidation {
                        *balance_changes.entry(tx.recipient.clone()).or_default() += tx.amount;
                    }
                }
                _ => {
                    if context == TransactionContext::BlockValidation {
                        // BlockValidation must only operate on fully-verifiable transactions.
                        self.verify_transaction_signature(tx)?;
                    }

                    let total_debit = tx.amount + tx.fee;
                    let current_balance = current_balances.get(&tx.sender).copied().unwrap_or(0.0);
                    let pending_change = balance_changes.get(&tx.sender).copied().unwrap_or(0.0);

                    // Check if sufficient funds available
                    if Transaction::round_amount(current_balance + pending_change) < total_debit {
                        return Err(BlockchainError::InsufficientFunds);
                    }

                    *balance_changes.entry(tx.sender.clone()).or_default() -= total_debit;
                    *balance_changes.entry(tx.recipient.clone()).or_default() += tx.amount;
                }
            }
        }

        // Apply all changes atomically
        let mut batch = sled::Batch::default();
        for (address, change) in balance_changes {
            let current = current_balances.get(&address).copied().unwrap_or(0.0);
            let new_balance = Transaction::round_amount(current + change);
            batch.insert(address.as_bytes(), bincode::serialize(&new_balance)?);
        }

        // Commit changes
        balances_tree.apply_batch(batch)?;

        // Clear processed transactions from pending
        if context == TransactionContext::BlockValidation {
            for tx in &transactions {
                if tx.sender != "MINING_REWARDS" {
                    let tx_id = tx.get_tx_id();
                    pending_tree.remove(tx_id.as_bytes())?;
                    let _ = full_sigs_tree.remove(tx_id.as_bytes());
                    let current_debit = self.get_pending_debit_for(&tx.sender).await?;
                    let delta = tx.amount + tx.fee;
                    let next_debit = Transaction::round_amount((current_debit - delta).max(0.0));
                    Self::set_pending_debit_for(&pending_debits_tree, &tx.sender, next_debit)?;
                }
            }
            pending_debits_tree.flush()?;
            full_sigs_tree.flush()?;
        }

        Ok(())
    }

    pub async fn process_pending_transactions(&self) -> Result<(), BlockchainError> {
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let mut transactions = Vec::new();

        for result in pending_tree.iter() {
            let (_, tx_bytes) = result?;
            if let Ok(tx) = deserialize_transaction(&tx_bytes) {
                transactions.push(tx);
            }
        }

        if !transactions.is_empty() {
            self.process_transactions_batch(transactions, TransactionContext::Standard)
                .await?;
        }

        Ok(())
    }

    pub async fn get_confirmed_balance(&self, address: &str) -> Result<f64, BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        let auto_rebuild = std::env::var("ALPHANUMERIC_BALANCES_AUTO_REBUILD")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true);

        let mut index_height = Self::get_balances_height(&balances_tree)?.unwrap_or(0);
        if auto_rebuild {
            let tip = self.get_latest_block_index() as u64;
            if index_height < tip {
                self.ensure_balances_index().await?;
                index_height = Self::get_balances_height(&balances_tree)?.unwrap_or(tip);
            }
        }
        if let Some(balance_bytes) = balances_tree.get(address.as_bytes())? {
            let balance: f64 = bincode::deserialize(&balance_bytes)
                .map_err(|e| BlockchainError::SerializationError(Box::new(e)))?;
            return Ok(balance);
        }
        if auto_rebuild && index_height >= self.get_latest_block_index() as u64 {
            let balance = 0.0;
            balances_tree.insert(address.as_bytes(), bincode::serialize(&balance)?)?;
            return Ok(balance);
        }
        // Slow path: calculate from blocks, then cache in balances tree.
        let mut balance = 0.0;
        let mut current_batch = Vec::with_capacity(1000);

        for result in self.db.scan_prefix(b"block_") {
            if let Ok((_, block_data)) = result {
                current_batch.push(block_data);

                if current_batch.len() >= 200 {
                    // Process current batch
                    for block_data in current_batch.drain(..) {
                        if let Ok(block) = Block::from_bytes(&block_data) {
                            for tx in &block.transactions {
                                if tx.recipient == address {
                                    balance = Transaction::round_amount(balance + tx.amount);
                                }
                                if tx.sender == address {
                                    balance =
                                        Transaction::round_amount(balance - (tx.amount + tx.fee));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Process any remaining blocks
        for block_data in current_batch.drain(..) {
            if let Ok(block) = Block::from_bytes(&block_data) {
                for tx in &block.transactions {
                    if tx.recipient == address {
                        balance = Transaction::round_amount(balance + tx.amount);
                    }
                    if tx.sender == address {
                        balance = Transaction::round_amount(balance - (tx.amount + tx.fee));
                    }
                }
            }
        }

        let balance = Transaction::round_amount(balance);
        balances_tree.insert(address.as_bytes(), bincode::serialize(&balance)?)?;
        Ok(balance)
    }

    // Public method that shows spendable balance to users
    pub async fn get_wallet_balance(&self, address: &str) -> Result<f64, BlockchainError> {
        let confirmed = self.get_confirmed_balance(address).await?;
        let mut spendable = confirmed;

        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        for result in pending_tree.iter() {
            if let Ok((_, tx_bytes)) = result {
                if let Ok(tx) = deserialize_transaction(&tx_bytes) {
                    if tx.sender == address {
                        spendable = Transaction::round_amount(spendable - (tx.amount + tx.fee));
                    }
                    if tx.recipient == address {
                        spendable = Transaction::round_amount(spendable + tx.amount);
                    }
                }
            }
        }

        Ok(spendable)
    }

    pub async fn update_wallet_balance(
        &self,
        address: &str,
        amount: f64,
    ) -> Result<(), BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;

        // Get current balance
        let current_balance = match balances_tree.get(address.as_bytes())? {
            Some(balance_bytes) => bincode::deserialize::<f64>(&balance_bytes)?,
            None => 0.0,
        };

        // Update balance with rounding
        let new_balance = Transaction::round_amount(current_balance + amount);

        // Store new balance
        balances_tree.insert(
            address.as_bytes(),
            bincode::serialize(&new_balance).map_err(|_| BlockchainError::InvalidTransaction)?,
        )?;

        Ok(())
    }

    pub fn calculate_merkle_root(
        transactions: &[Transaction],
    ) -> Result<[u8; 32], BlockchainError> {
        if transactions.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(b"empty_transactions_hash");
            return Ok(hasher.finalize().into());
        }

        let mut current_level: Vec<[u8; 32]> = transactions
            .iter()
            .map(|tx| {
                let tx_bytes =
                    serialize(tx).map_err(|e| BlockchainError::SerializationError(Box::new(e)))?;
                let mut hasher = Sha256::new();
                hasher.update(&tx_bytes);
                Ok(hasher.finalize().into())
            })
            .collect::<Result<Vec<_>, BlockchainError>>()?;

        // Correct handling of single transaction: DUPLICATE the hash
        if current_level.len() == 1 {
            let single_hash = current_level[0];
            let mut hasher = Sha256::new();
            hasher.update(&single_hash);
            hasher.update(&single_hash); // Duplicate the hash!
            return Ok(hasher.finalize().into());
        }

        while current_level.len() > 1 {
            let next_level: Vec<[u8; 32]> = current_level
                .chunks(2)
                .map(|pair| {
                    let mut hasher = Sha256::new();
                    hasher.update(&pair[0]);
                    if pair.len() == 2 {
                        hasher.update(&pair[1]);
                    }
                    hasher.finalize().into()
                })
                .collect();
            current_level = next_level;
        }

        Ok(current_level[0])
    }

    pub fn get_block(&self, index: u32) -> Result<Block, BlockchainError> {
        let key = format!("block_{}", index);

        let block_data = self
            .db
            .get(key.as_bytes())?
            .ok_or(BlockchainError::InvalidTransaction)?;

        deserialize_block(&block_data)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockchainInfo {
    pub height: u32,
    pub total_transactions: usize,
    pub current_difficulty: u64,
    pub pending_transactions: usize,
    pub last_block_hash: String,
    pub last_block_time: u64,
}

#[derive(Debug)]
pub struct ChainSentinel {
    header_cache: Arc<RwLock<VecDeque<HeaderInfo>>>,
    verified_blocks: Arc<DashMap<[u8; 32], BlockVerification>>,
    integrity_score: AtomicU64,
    last_verification: AtomicU64,
}

#[derive(Debug, Clone)]
struct HeaderInfo {
    hash: [u8; 32],
    height: u32,
    timestamp: u64,
    verification_count: u32,
}

#[derive(Debug)]
struct BlockVerification {
    timestamp: u64,
    verifiers: HashSet<String>, // Node IDs that verified
    integrity_confirmed: bool,
}

impl ChainSentinel {
    pub fn new() -> Self {
        Self {
            header_cache: Arc::new(RwLock::new(VecDeque::with_capacity(10000))),
            verified_blocks: Arc::new(DashMap::new()),
            integrity_score: AtomicU64::new(100), // Start at 100%
            last_verification: AtomicU64::new(0),
        }
    }

    pub async fn verify_chain_integrity(&self, blockchain: &Blockchain) -> bool {
        let blocks = blockchain.get_blocks();
        if blocks.is_empty() {
            return true;
        }

        let mut prev_hash = blocks[0].hash;
        let mut prev_timestamp = blocks[0].timestamp;
        let mut difficulty_oracle = DifficultyOracle::new();

        for block in blocks.iter().skip(1) {
            // Hash chain verification
            if block.previous_hash != prev_hash {
                self.integrity_score.fetch_sub(10, Ordering::Relaxed);
                return false;
            }

            // Time verification
            let time_diff = block.timestamp.saturating_sub(prev_timestamp);
            if time_diff > TARGET_BLOCK_TIME * 12 {
                self.integrity_score.fetch_sub(5, Ordering::Relaxed);
                return false;
            }

            // Difficulty verification
            let expected_difficulty = Block::adjust_dynamic_difficulty(
                block.difficulty,
                time_diff,
                block.index,
                &mut difficulty_oracle,
                block.timestamp,
            );

            if block.difficulty < (expected_difficulty as f64 * 0.99) as u64 {
                self.integrity_score.fetch_sub(5, Ordering::Relaxed);
                return false;
            }

            prev_hash = block.hash;
            prev_timestamp = block.timestamp;
        }

        true
    }

    pub fn add_block_verification(&self, block: &Block, verifier: String) {
        self.verified_blocks
            .entry(block.hash)
            .and_modify(|v| {
                v.verifiers.insert(verifier.clone());
                if v.verifiers.len() >= 3 {
                    // Require 3 verifications
                    v.integrity_confirmed = true;
                }
            })
            .or_insert_with(|| {
                let mut verifiers = HashSet::new();
                verifiers.insert(verifier);
                BlockVerification {
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    verifiers,
                    integrity_confirmed: false,
                }
            });
    }

    pub fn is_block_verified(&self, block: &Block) -> bool {
        self.verified_blocks
            .get(&block.hash)
            .map(|v| v.integrity_confirmed)
            .unwrap_or(false)
    }

    pub fn get_verification_count(&self, block: &Block) -> u32 {
        self.verified_blocks
            .get(&block.hash)
            .map(|v| v.verifiers.len() as u32)
            .unwrap_or(0)
    }
}
