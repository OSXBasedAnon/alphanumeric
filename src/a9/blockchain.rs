use bincode::serialize;
use blake3;
use chrono::Utc;
use dashmap::DashMap;
use futures::executor::block_on;
use lazy_static::lazy_static;
use log::error;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use pqcrypto_dilithium::dilithium5::{
    detached_sign, keypair as dilithium_keypair, verify_detached_signature, DetachedSignature,
    PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use sled::Db;
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error as StdError;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};

use crate::a9::mempool::{Mempool, TemporalVerification};
use crate::a9::oracle::DifficultyOracle;
use crate::a9::progpow::MiningManager;
use crate::a9::wallet::Wallet;

const BLOCKCHAIN_PATH: &str = "blockchain.db";
const BALANCES_TREE: &str = "balances";
const BALANCES_HEIGHT_KEY: &[u8] = b"__height";
const NONCE_MAGIC: u128 = 0xA5A5A5A5A5A5A5A5A;
const DIFFICULTY_MAGIC: u128 = 0x5A5A5A5A5A5A5A5A5A5A5A5A5A;
const MIN_TRANSACTION_AMOUNT: f64 = 0.00000564;

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
        let allow_legacy = std::env::var("ALPHANUMERIC_ALLOW_LEGACY_TX")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        // Enforce that a verified tx carries pub_key + signature hash.
        if self.pub_key.is_none() || self.sig_hash.is_none() {
            if allow_legacy {
                return Ok(());
            }
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
        const MAX_PAST_TIME: u64 = 300;

        if self.timestamp > now + MAX_FUTURE_TIME {
            return Err(BlockchainError::InvalidBlockHeader);
        }

        if self.timestamp < now - MAX_PAST_TIME {
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
                if block.transactions.first().unwrap().sender != "MINING_REWARDS" {
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

        // Derive block keys only after PoW verification
        let (_, pub_key) = Self::derive_block_keys(block)?;

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

        // If signature is present, verify it
        if let Some(sig) = &tx.signature {
            let sig_bytes =
                hex::decode(sig).map_err(|_| BlockchainError::InvalidTransactionSignature)?;

            let detached_sig = DetachedSignature::from_bytes(&sig_bytes)
                .map_err(|_| BlockchainError::InvalidTransactionSignature)?;

            // Create message binding transaction to block's proof of work
            let message = [
                block.hash.as_slice(),
                &block.nonce.to_le_bytes(),
                &block.difficulty.to_le_bytes(),
                tx.recipient.as_bytes(),
                tx.amount.to_le_bytes().as_slice(),
            ]
            .concat();

            verify_detached_signature(&detached_sig, &message, &pub_key)
                .map_err(|_| BlockchainError::InvalidTransactionSignature)?;
        } else {
            return Err(BlockchainError::InvalidTransactionSignature);
        }

        Ok(())
    }

    fn derive_block_keys(block: &Block) -> Result<(SecretKey, PublicKey), BlockchainError> {
        // Optimized key derivation using all block data
        let mut hasher = blake3::Hasher::new();
        hasher.update(&block.hash);
        hasher.update(&block.previous_hash);
        hasher.update(&block.index.to_le_bytes());
        hasher.update(&block.nonce.to_le_bytes());
        hasher.update(&block.difficulty.to_le_bytes());
        hasher.update(&block.merkle_root);
        let seed = hasher.finalize();

        let (pub_key, secret_key) = dilithium_keypair();

        // Verify the derived keys with a binding signature
        let message = [
            block.hash.as_slice(),
            &block.index.to_le_bytes(),
            pub_key.as_bytes(),
            &block.nonce.to_le_bytes(),
            &block.difficulty.to_le_bytes(),
        ]
        .concat();

        let binding_sig = detached_sign(&message, &secret_key);

        match verify_detached_signature(&binding_sig, &message, &pub_key) {
            Ok(_) => Ok((secret_key, pub_key)),
            Err(_) => Err(BlockchainError::InvalidBlockKeys(String::from(
                "Key verification failed",
            ))),
        }
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
}

impl Blockchain {
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
        };

        // Initialize the pending transactions tree if it doesn't exist
        if let Ok(pending_tree) = db.open_tree("pending_transactions") {
            // Clear any invalid transactions from previous runs
            pending_tree.clear().ok();
            pending_tree.flush().ok();
        }

        blockchain
    }

    pub async fn initialize(&self) -> Result<(), BlockchainError> {
        // Get and set the network difficulty first
        self.get_network_difficulty().await?;

        // Sync mempool with sled
        self.sync_mempool_with_sled().await?;

        // Ensure balances index is valid (rebuild if needed)
        self.ensure_balances_index().await?;

        let pending_tree = self.db.open_tree("pending_transactions")?;
        let mut invalid_txs = Vec::new();

        for result in pending_tree.iter() {
            let (key, tx_bytes) = result?;
            if let Ok(tx) = deserialize_transaction(&tx_bytes) {
                if let Err(_) = self.validate_transaction(&tx, None).await {
                    invalid_txs.push(key.to_vec());
                }
            } else {
                invalid_txs.push(key.to_vec());
            }
        }

        // Remove invalid transactions
        for key in invalid_txs {
            pending_tree.remove(key)?;
        }
        pending_tree.flush()?;

        Ok(())
    }

    pub async fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let difficulty = *self.difficulty.lock().await;

        // Retrieve pending transactions from sled
        let pending_transactions = match self.db.open_tree("pending_transactions") {
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
        // Verify chain integrity first
        if !self.chain_sentinel.verify_chain_integrity(self).await {
            return Err(BlockchainError::InvalidBlockHeader);
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

        // Serialize and save block
        let value = bincode::serialize(&storage_block)
            .map_err(|e| BlockchainError::SerializationError(Box::new(e)))?;

        let key = format!("block_{}", block.index);
        self.db
            .insert(key.as_bytes(), value)
            .map_err(|e| BlockchainError::DatabaseError(e))?;

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

    pub async fn finalize_block(
        &self,
        mut block: Block,
        miner_address: String,
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

        // Derive block's system keys
        set_finalize_stage(1);
        let (secret_key, _) = SystemKeyDeriver::derive_block_keys(&block)?;
        trace_step("derive_keys");

        // Calculate mining reward first
        set_finalize_stage(2);
        let reward = self.calculate_block_reward(&block)?;
        trace_step("calc_reward");

        // Create reward transaction message with proper binding
        let message = [
            block.hash.as_slice(),
            &block.index.to_le_bytes(),
            miner_address.as_bytes(),
            &reward.to_le_bytes(),
            &[0u8], // MiningReward type
        ]
        .concat();

        // Sign with block's key
        let signature = detached_sign(&message, &secret_key);
        set_finalize_stage(3);
        trace_step("sign_reward");

        // Create reward transaction
        let mut reward_tx = Transaction::new(
            "MINING_REWARDS".to_string(),
            miner_address,
            reward,
            super::blockchain::NETWORK_FEE,
            block.timestamp,
            Some(hex::encode(signature.as_bytes())),
        );
        reward_tx.sig_hash = Some(Transaction::signature_hash_hex(signature.as_bytes()));

        // Insert reward as first transaction
        block.transactions.insert(0, reward_tx);
        set_finalize_stage(4);
        trace_step("insert_reward");

        // Recalculate merkle root with reward included
        set_finalize_stage(5);
        block.merkle_root = Self::calculate_merkle_root(&block.transactions)?;
        trace_step("merkle");

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
        set_finalize_stage(6);
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
        set_finalize_stage(7);
        trace_step("validate_batch");

        // Process transactions atomically
        self.process_transactions_batch(
            block.transactions.clone(),
            TransactionContext::BlockValidation,
        )
        .await?;
        set_finalize_stage(8);
        trace_step("apply_batch");

        // Save block
        let value = bincode::serialize(&block)?;
        let key = format!("block_{}", block.index);
        self.db.insert(key.as_bytes(), value)?;
        set_finalize_stage(9);
        trace_step("db_insert");
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        Self::set_balances_height(&balances_tree, block.index as u64)?;
        set_finalize_stage(10);
        trace_step("balances_height");

        Ok(())
    }

    pub async fn clear_processed_transactions(
        &self,
        transactions: &[Transaction],
    ) -> Result<(), BlockchainError> {
        // Clear from pending transactions tree
        let pending_tree = self.db.open_tree("pending_transactions")?;
        let mut batch = sled::Batch::default();

        for tx in transactions {
            // Use tx_id instead of string formatting
            let tx_id = tx.get_tx_id();

            // Remove from pending tree
            batch.remove(tx_id.as_bytes());

            // Explicitly remove any full signatures from memory
            if let Some(sig) = &tx.signature {
                if let Ok(_) = hex::decode(sig) {
                    // The decoded signature is automatically dropped here
                    // Rust's ownership system ensures cleanup
                    println!(
                        "Cleaned up signature from memory for transaction: {}",
                        tx_id
                    );
                }
            }
        }

        // Apply batch deletion
        pending_tree.apply_batch(batch)?;

        // Clear from mempool
        let mut mempool = self.mempool.write().await;
        for tx in transactions {
            mempool.clear_transaction(tx);
        }

        // Ensure changes are persisted
        pending_tree.flush()?;

        Ok(())
    }

    // Retrieve the latest block's index
    pub fn get_latest_block_index(&self) -> u64 {
        let last_key = self.db.last().ok().flatten().map(|(k, _)| k.to_vec());

        if let Some(key_bytes) = last_key {
            if let Ok(key_str) = String::from_utf8(key_bytes) {
                if let Some(index_str) = key_str.strip_prefix("block_") {
                    return index_str.parse().unwrap_or(0);
                }
            }
        }
        0
    }

    pub fn get_last_block_hash(&self) -> Result<[u8; 32], BlockchainError> {
        let (_, value) = self
            .db
            .last()
            .map_err(BlockchainError::DatabaseError)?
            .ok_or_else(|| BlockchainError::FlushError("No blocks found".to_string()))?;

        Block::from_bytes(&value)
            .map(|b| b.hash)
            .map_err(|e| BlockchainError::SerializationError(e))
    }

    pub fn get_latest_block_hash(&self) -> [u8; 32] {
        self.db
            .last()
            .ok()
            .flatten()
            .and_then(|(_, value)| Block::from_bytes(&value).ok())
            .map(|b| b.hash)
            .unwrap_or([0u8; 32])
    }

    pub fn get_last_block(&self) -> Option<Block> {
        self.db
            .scan_prefix(b"block_")
            .filter_map(|entry| {
                let (_, value) = entry.ok()?;
                Block::from_bytes(value.as_ref()).ok()
            })
            .max_by_key(|block| block.timestamp)
    }

    pub fn get_block_count(&self) -> usize {
        self.db.len()
    }

    pub fn get_blocks(&self) -> Vec<Block> {
        let mut blocks: Vec<_> = self
            .db
            .iter()
            .filter_map(|r| r.ok())
            .filter_map(|(_, value)| Block::from_bytes(&value).ok())
            .collect();
        blocks.sort_unstable_by_key(|b| b.index);
        blocks
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
        // Get the latest block index directly
        let block_count = self.get_block_count();
        if block_count > 0 {
            // Get last block by index
            let last_block = self.get_block((block_count - 1) as u32)?;

            // Update cached difficulty
            let mut difficulty_lock = self.difficulty.lock().await;
            *difficulty_lock = last_block.difficulty;
            Ok(last_block.difficulty)
        } else {
            // No blocks exist yet
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

        // Continue with other validations (signature etc.)
        tx.verify_signature(self).await?;
        Ok(())
    }

    pub fn verify_transaction_signature(&self, tx: &Transaction) -> Result<(), BlockchainError> {
        if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
            return Ok(());
        }

        let pub_key = tx
            .pub_key
            .as_ref()
            .ok_or(BlockchainError::InvalidTransactionSignature)?;
        let sig_hex = tx
            .signature
            .as_ref()
            .ok_or(BlockchainError::InvalidTransactionSignature)?;

        let sig_bytes =
            hex::decode(sig_hex).map_err(|_| BlockchainError::InvalidTransactionSignature)?;

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
            let actual_hash = Transaction::signature_hash_hex(&sig_bytes);
            if &actual_hash != expected_hash {
                return Err(BlockchainError::InvalidTransactionSignature);
            }
        }

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
        for tx in &block.transactions {
            if tx.amount < MIN_TRANSACTION_AMOUNT {
                return Err(BlockchainError::InvalidTransactionAmount);
            }

            // Address validity is verified through signature verification with public key
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

        // Get confirmed balance and check pending transactions
        let mempool_guard = self.mempool.read().await;
        
        let confirmed_balance = self.get_confirmed_balance(&transaction.sender).await?;
        let pending_transactions = mempool_guard.get_transactions_for_block();
        let pending_amount: f64 = pending_transactions
            .iter()
            .filter(|tx| tx.sender == transaction.sender)
            .map(|tx| tx.amount + tx.fee)
            .sum();

        // Calculate available balance considering pending transactions
        let available_balance = confirmed_balance - pending_amount;
        let total_required = transaction.amount + transaction.fee;

        // Check if there's enough available balance
        if available_balance < total_required {
            return Err(BlockchainError::InsufficientFunds);
        }

        // Signature verification with public key binding
        let allow_legacy = std::env::var("ALPHANUMERIC_ALLOW_LEGACY_TX")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);

        let pub_key = match transaction.pub_key.as_ref() {
            Some(pk) => pk,
            None => {
                if allow_legacy {
                    return Err(BlockchainError::InvalidTransactionSignature);
                }
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

        // Store in pending transactions
        let pending_tree = self.db.open_tree("pending_transactions")?;
        let tx_bytes = bincode::serialize(&storage_tx)?;

        // Use batch operation for atomic updates
        let mut batch = sled::Batch::default();
        batch.insert(tx_id.as_bytes(), tx_bytes);
        pending_tree.apply_batch(batch)?;
        pending_tree.flush()?;

        Ok(())
    }

    pub async fn get_pending_amount(&self, address: &str) -> Result<f64, BlockchainError> {
        let pending_tree = self.db.open_tree("pending_transactions")?;
        let mut total = 0.0;

        for item in pending_tree.iter() {
            if let Ok((_, tx_bytes)) = item {
                if let Ok(tx) = deserialize_transaction(&tx_bytes) {
                    if tx.sender == address {
                        total += tx.amount + tx.fee;
                    }
                }
            }
        }

        Ok(total)
    }

    pub async fn get_transactions_for_block(&self) -> Vec<Transaction> {
        self.mempool.read().await.get_transactions_for_block()
    }

    pub async fn get_mempool_transactions(&self) -> Result<Vec<Transaction>, BlockchainError> {
        Ok(self.mempool.read().await.get_transactions_for_block())
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
        let pending_tree = self.db.open_tree("pending_transactions")?;

        // Collect all transactions from sled
        let mut transactions = Vec::new();
        for result in pending_tree.iter() {
            let (_, tx_bytes) = result?;
            if let Ok(tx) = deserialize_transaction(&tx_bytes) {
                transactions.push(tx);
            }
        }

        // Reset mempool and add all transactions
        *mempool = Mempool::new();
        for tx in transactions {
            mempool.add_transaction(tx)?;
        }

        Ok(())
    }

    pub async fn get_pending_transactions(&self) -> Result<Vec<Transaction>, BlockchainError> {
        // First sync mempool with sled
        self.sync_mempool_with_sled().await?;

        // Now get transactions from sled
        let pending_tree = self.db.open_tree("pending_transactions")?;
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
                if !tx.is_valid(&tx.sender) {
                    continue;
                }
                balance -= tx.amount + tx.fee;
            } else if tx.recipient == address {
                balance += tx.amount;
            }
        }

        // Handle pending transactions CORRECTLY
        let pending_tree = self.db.open_tree("pending_transactions")?;
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
        let pending_tree = self.db.open_tree("pending_transactions")?;

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
                }
            }
        }

        Ok(())
    }

    pub async fn process_pending_transactions(&self) -> Result<(), BlockchainError> {
        let pending_tree = self.db.open_tree("pending_transactions")?;
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

        if auto_rebuild {
            let tip = self.get_block_count() as u64;
            let index_height = Self::get_balances_height(&balances_tree)?.unwrap_or(0);
            if index_height < tip {
                self.ensure_balances_index().await?;
            }
        }
        if let Some(balance_bytes) = balances_tree.get(address.as_bytes())? {
            let balance: f64 = bincode::deserialize(&balance_bytes)
                .map_err(|e| BlockchainError::SerializationError(Box::new(e)))?;
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

        let pending_tree = self.db.open_tree("pending_transactions")?;
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
