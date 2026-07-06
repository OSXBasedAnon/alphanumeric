use blake3;
use dashmap::DashMap;
use futures::executor::block_on;
use lazy_static::lazy_static;
use log::{debug, error, warn};
use lru::LruCache;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use parking_lot::Mutex as PLMutex;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use sled::Db;
use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;
use std::error::Error;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{watch, Mutex, RwLock};

use crate::a9::codec;
use crate::a9::mempool::{Mempool, TemporalVerification};
use crate::a9::mldsa;
use crate::a9::oracle::DifficultyOracle;
use crate::a9::wallet::Wallet;

const BALANCES_TREE: &str = "balances";
const PENDING_DEBITS_TREE: &str = "pending_debits";
const PENDING_CREDITS_TREE: &str = "pending_credits";
const PENDING_TRANSACTIONS_TREE: &str = "pending_transactions";
// Full ML-DSA signatures are intentionally NOT stored in the main tx record on disk.
// We keep them in a sidecar tree for pending/mempool durability across restarts, and prune with the same TTL.
const PENDING_FULL_SIGNATURES_TREE: &str = "pending_full_signatures";
// Retained full-signature witnesses for recently-confirmed transactions, so peers
// can serve them for near-tip verification during sync. `CONFIRMED_WITNESSES_TREE`
// maps tx_id -> full-signature Transaction; `CONFIRMED_WITNESS_INDEX_TREE` maps
// height_be(8)||tx_id -> [] for height-ordered pruning. Purely local: these trees
// are never hashed and have no effect on block hashes, merkle roots, or validity.
const CONFIRMED_WITNESSES_TREE: &str = "confirmed_witnesses";
const CONFIRMED_WITNESS_INDEX_TREE: &str = "confirmed_witness_index";
/// How many blocks past confirmation a transaction's full witness is retained so
/// it remains verifiable during near-tip sync. No consensus impact.
pub const WITNESS_RETENTION_BLOCKS: u64 = 256;
const ORPHAN_BLOCKS_TREE: &str = "orphan_blocks";
const ORPHAN_INDEX_TREE: &str = "orphan_index";
const CHAIN_META_TREE: &str = "chain_meta";
const BALANCES_HEIGHT_KEY: &[u8] = b"__height";
const CHAIN_TIP_KEY: &[u8] = b"tip";
const CHAIN_STATE_DIRTY_KEY: &[u8] = b"state_dirty";
const MONEY_SCALE_I128: i128 = 100_000_000;
const MONEY_SCALE_F64: f64 = MONEY_SCALE_I128 as f64;
const MIN_TRANSACTION_AMOUNT_UNITS: i128 = 564;
const ORPHAN_MAX_COUNT: usize = 10_000;
const ORPHAN_TTL_SECS: u64 = 6 * 60 * 60;
const ORPHAN_REORG_DEPTH: u32 = 1024;
const ORPHAN_BRANCH_SEARCH_LIMIT: usize = 4_096;
const GENESIS_LAUNCH_TIMESTAMP: u64 = 1_783_191_900;
const GENESIS_LAUNCH_AMOUNT: f64 = 17.76;
const GENESIS_LAUNCH_RECIPIENT: &str = "ALPHANUMERIC_1776_ARTIFACT";
const GENESIS_LAUNCH_DIFFICULTY: u64 = 0;
const GENESIS_LAUNCH_NONCE: u64 = 7_377;

pub const FEE_PERCENTAGE: f64 = 0.000563063063; // 0.0563063063%
pub const MIN_BLOCK_REWARD: f64 = 1.0;
pub const MAX_BLOCK_REWARD: f64 = 50.0;
pub const NETWORK_FEE: f64 = 0.0005; // Operator fee from mining rewards
pub const MINT_CLIP: f64 = 0.35; // Burned/clipped portion of tx fees (anti self-fee recycling)
pub const SYSTEM_ADDRESSES: [&str; 1] = ["MINING_REWARDS"];
pub const TARGET_BLOCK_TIME: u64 = 5;
// The launch floor maps to roughly 2^29 expected hashes. On the launch reference
// desktop this targets a short solo-mining wait while still keeping single-miner
// throughput bounded.
const NETWORK_MIN_DIFFICULTY: u64 = 464;
const MAX_NETWORK_DIFFICULTY: u64 = 4_080;
const DIFFICULTY_POINTS_PER_HALVING: i128 = 16;
const DIFFICULTY_RETARGET_HALF_LIFE_SECS: i128 = 60;
pub const MAX_BLOCK_FUTURE_TIME: u64 = 300;
pub const CONSENSUS_HEADER_RULES_VERSION: u32 = 3;
pub const MAX_TARGET_BYTES: [u8; 32] = [0xff; 32];
lazy_static! {
    pub static ref MAX_TARGET: BigUint = BigUint::from_bytes_be(&MAX_TARGET_BYTES);
}

pub(crate) fn pow_target_from_difficulty(difficulty: u64) -> BigUint {
    // Deterministic bounded mapping:
    // target = MAX_TARGET / 2^(difficulty/16)
    // For exponent >= 256, target collapses to 0.
    if difficulty == 0 {
        return MAX_TARGET.clone();
    }
    let exponent = difficulty / 16;
    if exponent >= 256 {
        return BigUint::from(0u8);
    }
    MAX_TARGET.clone() >> (exponent as usize)
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
    ReceiptValidation,
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
    #[serde(
        rename = "fee",
        serialize_with = "serialize_units_as_amount",
        deserialize_with = "deserialize_amount_to_units"
    )]
    pub fee_units: i128,
    #[serde(
        rename = "amount",
        serialize_with = "serialize_units_as_amount",
        deserialize_with = "deserialize_amount_to_units"
    )]
    pub amount_units: i128,
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

fn serialize_units_as_amount<S>(units: &i128, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_f64(Transaction::from_units(*units))
}

fn deserialize_amount_to_units<'de, D>(deserializer: D) -> Result<i128, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let amount = f64::deserialize(deserializer)?;
    Ok(Transaction::to_units(amount))
}

impl Transaction {
    pub fn round_amount(amount: f64) -> f64 {
        (amount * MONEY_SCALE_F64).round() / MONEY_SCALE_F64
    }

    pub fn to_units(amount: f64) -> i128 {
        if !amount.is_finite() {
            return 0;
        }
        (Self::round_amount(amount) * MONEY_SCALE_F64).round() as i128
    }

    pub fn from_units(units: i128) -> f64 {
        Self::round_amount(units as f64 / MONEY_SCALE_F64)
    }

    pub fn total_debit_units(&self) -> i128 {
        self.amount_units + self.fee_units
    }

    pub fn has_valid_regular_amounts(&self) -> bool {
        self.amount_units >= MIN_TRANSACTION_AMOUNT_UNITS
            && self.fee_units >= 0
            && self.amount_units.checked_add(self.fee_units).is_some()
    }

    pub fn amount(&self) -> f64 {
        Self::from_units(self.amount_units)
    }

    pub fn fee(&self) -> f64 {
        Self::from_units(self.fee_units)
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
            amount_units: Self::to_units(amount),
            fee_units: Self::to_units(fee),
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
            amount_units: Self::to_units(amount),
            fee_units: Self::to_units(fee),
            timestamp,
            signature: None,
            pub_key: None,
            sig_hash: None,
        };

        let transaction_data = serde_json::to_vec(&transaction)
            .map_err(|e| format!("Failed to serialize transaction: {}", e))?;

        // Sign and decode into bytes for signature hash + verification.
        let full_signature_hex = block_on(sender_wallet.sign_transaction(&transaction_data))
            .ok_or("Failed to sign transaction")?;
        let full_signature = hex::decode(&full_signature_hex)
            .map_err(|e| format!("Invalid signature hex: {}", e))?;

        // Create new transaction with full signature for verification
        let mut tx_with_full_sig = Self::new(
            transaction.sender.clone(),
            transaction.recipient.clone(),
            transaction.amount(),
            transaction.fee(),
            transaction.timestamp,
            Some(full_signature_hex),
        );
        tx_with_full_sig.sig_hash = Some(Self::signature_hash_hex(&full_signature));
        tx_with_full_sig.pub_key =
            Some(block_on(sender_wallet.get_public_key_hex()).ok_or("Failed to get public key")?);

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
            self.sender,
            self.recipient,
            self.amount(),
            self.fee(),
            self.timestamp
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
                                debug!("Transaction signature verification succeeded");
                                true
                            }
                            _ => {
                                debug!("Transaction signature verification failed");
                                false
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to decode transaction public key: {}", e);
                        false
                    }
                },
                Err(e) => {
                    debug!("Failed to decode transaction signature: {}", e);
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
            amount_units: self.amount_units,
            fee_units: self.fee_units,
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

        if !self.has_valid_regular_amounts() {
            return Err(BlockchainError::InvalidTransactionAmount);
        }

        let sender_units = Transaction::to_units(sender_balance);
        let total_required = self.total_debit_units();

        if sender_units < total_required {
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
            self.sender,
            self.recipient,
            self.amount(),
            self.fee(),
            self.timestamp
        )
    }

    fn get_message(&self) -> Vec<u8> {
        format!(
            "{}:{}:{:.8}:{:.8}:{}",
            self.sender,
            self.recipient,
            self.amount(),
            self.fee(),
            self.timestamp
        )
        .into_bytes()
    }
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

        if self.timestamp > now + MAX_BLOCK_FUTURE_TIME {
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
        block_index: u32,
        oracle: &mut DifficultyOracle,
        current_timestamp: u64,
    ) -> u64 {
        oracle.record_block_metrics(current_timestamp, current_difficulty);
        Self::consensus_next_difficulty(current_difficulty, timestamp_diff, block_index)
    }

    pub fn consensus_next_difficulty(
        parent_difficulty: u64,
        timestamp_diff: u64,
        block_index: u32,
    ) -> u64 {
        if block_index == 0 {
            return GENESIS_LAUNCH_DIFFICULTY;
        }

        let current = parent_difficulty.clamp(NETWORK_MIN_DIFFICULTY, MAX_NETWORK_DIFFICULTY);
        let timing_error = TARGET_BLOCK_TIME as i128 - timestamp_diff as i128;
        let numerator = timing_error.saturating_mul(DIFFICULTY_POINTS_PER_HALVING);
        let mut delta =
            Self::div_round_away_from_zero(numerator, DIFFICULTY_RETARGET_HALF_LIFE_SECS);
        if delta == 0 && timing_error != 0 {
            delta = timing_error.signum();
        }

        if delta >= 0 {
            current
                .saturating_add(delta as u64)
                .min(MAX_NETWORK_DIFFICULTY)
        } else {
            let decrease = u64::try_from(delta.unsigned_abs()).unwrap_or(u64::MAX);
            current.saturating_sub(decrease).max(NETWORK_MIN_DIFFICULTY)
        }
    }

    fn div_round_away_from_zero(numerator: i128, denominator: i128) -> i128 {
        if numerator == 0 {
            return 0;
        }
        let abs = numerator.abs();
        let rounded = abs.saturating_add(denominator.saturating_sub(1)) / denominator;
        rounded * numerator.signum()
    }

    pub fn verify_difficulty_proof(&self) -> bool {
        // Use the same verification as verify_pow
        self.verify_pow()
    }

    pub fn verify_pow(&self) -> bool {
        let hash = self.calculate_hash_for_block();
        let hash_int = BigUint::from_bytes_be(&hash);
        let target = pow_target_from_difficulty(self.difficulty);

        hash_int <= target
    }

    pub fn calculate_hash_for_block(&self) -> [u8; 32] {
        // Use a fixed-size array to avoid heap allocation
        // Total: 4 + 32 + 8 + 8 + 8 + 32 = 92 bytes (fits on stack)
        let mut header_data = [0u8; 92];
        let mut offset = 0;

        header_data[offset..offset + 4].copy_from_slice(&self.index.to_le_bytes());
        offset += 4;

        header_data[offset..offset + 32].copy_from_slice(&self.previous_hash);
        offset += 32;

        header_data[offset..offset + 8].copy_from_slice(&self.timestamp.to_le_bytes());
        offset += 8;

        header_data[offset..offset + 8].copy_from_slice(&self.nonce.to_le_bytes());
        offset += 8;

        header_data[offset..offset + 8].copy_from_slice(&self.difficulty.to_le_bytes());
        offset += 8;

        header_data[offset..offset + 32].copy_from_slice(&self.merkle_root);

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

    pub fn hash_to_hex_string(&self) -> String {
        // Use hex::encode which is optimized for this exact use case
        hex::encode(self.hash)
    }

    pub fn previous_hash_to_hex_string(&self) -> String {
        // Use hex::encode which is optimized for this exact use case
        hex::encode(self.previous_hash)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        codec::serialize(self).map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        deserialize_block(bytes).map_err(|e| Box::new(e) as Box<dyn Error>)
    }
}

#[derive(Debug)]
pub enum BlockchainError {
    CodecError(codec::CodecError),
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
            BlockchainError::CodecError(e) => write!(f, "Codec error: {}", e),
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
        BlockchainError::SerializationError(Box::new(std::io::Error::other(format!(
            "Hex decode error: {}",
            err
        ))))
    }
}

impl From<Box<dyn StdError>> for BlockchainError {
    fn from(error: Box<dyn StdError>) -> Self {
        BlockchainError::SerializationError(error)
    }
}

impl From<codec::CodecError> for BlockchainError {
    fn from(error: codec::CodecError) -> Self {
        BlockchainError::CodecError(error)
    }
}

fn deserialize_transaction(bytes: &[u8]) -> Result<Transaction, BlockchainError> {
    if let Ok(tx) = codec::deserialize::<Transaction>(bytes) {
        return Ok(tx);
    }
    let legacy: LegacyTransaction =
        codec::deserialize(bytes).map_err(|e| BlockchainError::SerializationError(Box::new(e)))?;
    Ok(Transaction {
        sender: legacy.sender,
        recipient: legacy.recipient,
        fee_units: Transaction::to_units(legacy.fee),
        amount_units: Transaction::to_units(legacy.amount),
        timestamp: legacy.timestamp,
        signature: legacy.signature,
        pub_key: None,
        sig_hash: None,
    })
}

fn deserialize_block(bytes: &[u8]) -> Result<Block, BlockchainError> {
    if let Ok(block) = codec::deserialize::<Block>(bytes) {
        return Ok(block);
    }
    let legacy: LegacyBlock =
        codec::deserialize(bytes).map_err(|e| BlockchainError::SerializationError(Box::new(e)))?;
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
                fee_units: Transaction::to_units(tx.fee),
                amount_units: Transaction::to_units(tx.amount),
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
        let mut times = self.windows.entry(address.to_string()).or_default();

        // Optimization: Only cleanup if we have entries to clean
        // Most of the time, the vector will be small and all entries valid
        let window_secs = self.window_size.num_seconds() as u64;
        let cutoff = now - std::time::Duration::from_secs(window_secs);

        // Fast path: check if we need to cleanup at all
        if !times.is_empty() && times[0] < cutoff {
            // Binary search to find first valid entry
            let first_valid = times
                .iter()
                .position(|&t| t >= cutoff)
                .unwrap_or(times.len());
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
            block_tx.sender == tx.sender
                && block_tx.recipient == tx.recipient
                && block_tx.amount_units == tx.amount_units
                && block_tx.fee_units == tx.fee_units
                && block_tx.timestamp == tx.timestamp
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
    state_mutation_lock: Arc<Mutex<()>>,
    tip_change_counter: Arc<AtomicU64>,
    tip_watch_tx: watch::Sender<ChainTipSignal>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChainTipSignal {
    pub height: u32,
    pub hash: [u8; 32],
    pub version: u64,
}

impl fmt::Display for Blockchain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blockchain {{ ... }}")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OrphanStoredBlock {
    block: Block,
    received_at: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct ChainTipMetadata {
    height: u32,
    hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct ChainStateDirty {
    block_index: u32,
    reason: String,
    marked_at: u64,
}

impl Blockchain {
    fn block_index_from_key(key: &[u8]) -> Option<u32> {
        let key_str = std::str::from_utf8(key).ok()?;
        let index_str = key_str.strip_prefix("block_")?;
        index_str.parse::<u32>().ok()
    }

    fn highest_block_index_scan(&self) -> Option<u32> {
        self.db
            .scan_prefix("block_")
            .filter_map(|entry| entry.ok().and_then(|(k, _)| Self::block_index_from_key(&k)))
            .max()
    }

    fn highest_block_index(&self) -> Option<u32> {
        self.current_chain_tip_metadata()
            .ok()
            .flatten()
            .map(|tip| tip.height)
            .or_else(|| self.highest_block_index_scan())
    }

    fn now_unix_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn tip_change_counter_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.tip_change_counter)
    }

    pub fn tip_change_version(&self) -> u64 {
        self.tip_change_counter.load(Ordering::Acquire)
    }

    pub fn subscribe_tip_changes(&self) -> watch::Receiver<ChainTipSignal> {
        self.tip_watch_tx.subscribe()
    }

    pub fn current_tip_signal(&self) -> ChainTipSignal {
        *self.tip_watch_tx.borrow()
    }

    fn notify_tip_changed(&self, block: &Block) {
        let version = self.tip_change_counter.fetch_add(1, Ordering::AcqRel) + 1;
        let _ = self.tip_watch_tx.send(ChainTipSignal {
            height: block.index,
            hash: block.hash,
            version,
        });
    }

    fn refresh_tip_signal_from_current_tip(&self) {
        if let Some(block) = self.get_last_block() {
            self.notify_tip_changed(&block);
        }
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

    fn open_chain_meta_tree(&self) -> Result<sled::Tree, BlockchainError> {
        self.db.open_tree(CHAIN_META_TREE).map_err(Into::into)
    }

    fn open_pending_debits_tree(&self) -> Result<sled::Tree, BlockchainError> {
        self.db.open_tree(PENDING_DEBITS_TREE).map_err(Into::into)
    }

    fn open_pending_credits_tree(&self) -> Result<sled::Tree, BlockchainError> {
        self.db.open_tree(PENDING_CREDITS_TREE).map_err(Into::into)
    }

    fn get_orphan_block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<Block>, BlockchainError> {
        let orphan_blocks = self.open_orphan_blocks_tree()?;
        let hash_hex = Self::orphan_hash_key(hash);
        let Some(raw) = orphan_blocks.get(hash_hex.as_bytes())? else {
            return Ok(None);
        };
        let entry: OrphanStoredBlock = codec::deserialize(&raw)?;
        Ok(Some(entry.block))
    }

    fn get_parent_block_for(&self, block: &Block) -> Result<Option<Block>, BlockchainError> {
        if block.index == 0 {
            return Ok(None);
        }

        // Fast path: canonical at height-1 matches prev hash.
        if let Ok(parent) = self.get_block(block.index.saturating_sub(1)) {
            if parent.hash == block.previous_hash {
                return Ok(Some(parent));
            }
        }

        // Otherwise, parent might currently be in the orphan pool.
        self.get_orphan_block_by_hash(&block.previous_hash)
    }

    fn validate_parent_timestamp(block: &Block, parent: &Block) -> Result<(), BlockchainError> {
        if block.timestamp < parent.timestamp {
            return Err(BlockchainError::InvalidBlockHeader);
        }
        Ok(())
    }

    async fn prevalidate_unattached_block(
        &self,
        block: &Block,
        sig_mode: SignatureValidationMode,
    ) -> Result<(), BlockchainError> {
        // Basic header checks include hash self-consistency + PoW proof.
        block.validate_header()?;

        // Merkle must match the normalized tx encoding.
        let expected_root = Blockchain::calculate_merkle_root(&block.transactions)?;
        if expected_root != block.merkle_root {
            return Err(BlockchainError::InvalidBlockHeader);
        }

        // Enforce transaction invariants and full signature presence. Do NOT enforce parent-linked
        // difficulty adjustment here because parent may be missing during out-of-order receipt.
        for tx in &block.transactions {
            if tx.sender == "MINING_REWARDS" {
                continue;
            }
            if !tx.has_valid_regular_amounts() {
                return Err(BlockchainError::InvalidTransactionAmount);
            }
            if tx.signature.is_none() || tx.pub_key.is_none() || tx.sig_hash.is_none() {
                return Err(BlockchainError::InvalidTransactionSignature);
            }
            let sig_hex = tx
                .signature
                .as_ref()
                .ok_or(BlockchainError::InvalidTransactionSignature)?;
            let sig_bytes =
                hex::decode(sig_hex).map_err(|_| BlockchainError::InvalidTransactionSignature)?;
            if sig_mode == SignatureValidationMode::RequireFull && sig_bytes.len() <= 64 {
                return Err(BlockchainError::InvalidTransactionSignature);
            }
            if sig_bytes.len() > 64 {
                self.verify_transaction_signature(tx)?;
            } else {
                Self::verify_transaction_receipt_fields(tx)?;
            }
        }

        Ok(())
    }

    async fn prevalidate_unattached_block_strict(
        &self,
        block: &Block,
    ) -> Result<(), BlockchainError> {
        self.prevalidate_unattached_block(block, SignatureValidationMode::RequireFull)
            .await
    }

    async fn get_pending_debit_for(&self, address: &str) -> Result<f64, BlockchainError> {
        Ok(Transaction::from_units(
            self.get_pending_debit_units(address).await?,
        ))
    }

    async fn get_pending_debit_units(&self, address: &str) -> Result<i128, BlockchainError> {
        let tree = self.open_pending_debits_tree()?;
        if let Some(raw) = tree.get(address.as_bytes())? {
            Ok(Self::deserialize_units_compatible(&raw)?.max(0))
        } else {
            Ok(0)
        }
    }

    async fn get_pending_credit_units(&self, address: &str) -> Result<i128, BlockchainError> {
        let tree = self.open_pending_credits_tree()?;
        if let Some(raw) = tree.get(address.as_bytes())? {
            Ok(Self::deserialize_units_compatible(&raw)?.max(0))
        } else {
            Ok(0)
        }
    }

    fn deserialize_units_compatible(raw: &[u8]) -> Result<i128, BlockchainError> {
        if let Ok(units) = codec::deserialize::<i128>(raw) {
            return Ok(units);
        }
        let legacy_amount: f64 = codec::deserialize(raw)?;
        Ok(Transaction::to_units(legacy_amount))
    }

    fn set_pending_debit_for(
        tree: &sled::Tree,
        address: &str,
        debit_units: i128,
    ) -> Result<(), BlockchainError> {
        let normalized = debit_units.max(0);
        if normalized <= 0 {
            tree.remove(address.as_bytes())?;
        } else {
            tree.insert(address.as_bytes(), codec::serialize(&normalized)?)?;
        }
        Ok(())
    }

    fn set_pending_credit_for(
        tree: &sled::Tree,
        address: &str,
        credit_units: i128,
    ) -> Result<(), BlockchainError> {
        let normalized = credit_units.max(0);
        if normalized <= 0 {
            tree.remove(address.as_bytes())?;
        } else {
            tree.insert(address.as_bytes(), codec::serialize(&normalized)?)?;
        }
        Ok(())
    }

    fn read_chain_tip_metadata(&self) -> Result<Option<ChainTipMetadata>, BlockchainError> {
        let meta_tree = self.open_chain_meta_tree()?;
        let Some(raw) = meta_tree.get(CHAIN_TIP_KEY)? else {
            return Ok(None);
        };
        Ok(Some(codec::deserialize(&raw)?))
    }

    fn write_chain_tip_metadata(&self, block: &Block) -> Result<(), BlockchainError> {
        let meta_tree = self.open_chain_meta_tree()?;
        let tip = ChainTipMetadata {
            height: block.index,
            hash: block.hash,
        };
        meta_tree.insert(CHAIN_TIP_KEY, codec::serialize(&tip)?)?;
        Ok(())
    }

    fn clear_chain_tip_metadata(&self) -> Result<(), BlockchainError> {
        let meta_tree = self.open_chain_meta_tree()?;
        meta_tree.remove(CHAIN_TIP_KEY)?;
        Ok(())
    }

    fn rebuild_chain_tip_metadata(&self) -> Result<Option<ChainTipMetadata>, BlockchainError> {
        let Some(height) = self.highest_block_index_scan() else {
            self.clear_chain_tip_metadata()?;
            return Ok(None);
        };
        let block = self.get_block(height)?;
        self.write_chain_tip_metadata(&block)?;
        self.open_chain_meta_tree()?.flush()?;
        Ok(Some(ChainTipMetadata {
            height,
            hash: block.hash,
        }))
    }

    fn current_chain_tip_metadata(&self) -> Result<Option<ChainTipMetadata>, BlockchainError> {
        let Some(tip) = self.read_chain_tip_metadata()? else {
            return self.rebuild_chain_tip_metadata();
        };

        match self.get_block(tip.height) {
            Ok(block) if block.hash == tip.hash => Ok(Some(tip)),
            _ => self.rebuild_chain_tip_metadata(),
        }
    }

    fn mark_chain_state_dirty(
        &self,
        block_index: u32,
        reason: &str,
    ) -> Result<(), BlockchainError> {
        let meta_tree = self.open_chain_meta_tree()?;
        let marker = ChainStateDirty {
            block_index,
            reason: reason.to_string(),
            marked_at: Self::now_unix_secs(),
        };
        meta_tree.insert(CHAIN_STATE_DIRTY_KEY, codec::serialize(&marker)?)?;
        meta_tree.flush()?;
        Ok(())
    }

    fn clear_chain_state_dirty(&self) -> Result<(), BlockchainError> {
        let meta_tree = self.open_chain_meta_tree()?;
        meta_tree.remove(CHAIN_STATE_DIRTY_KEY)?;
        meta_tree.flush()?;
        Ok(())
    }

    fn chain_state_dirty(&self) -> Result<Option<ChainStateDirty>, BlockchainError> {
        let meta_tree = self.open_chain_meta_tree()?;
        let Some(raw) = meta_tree.get(CHAIN_STATE_DIRTY_KEY)? else {
            return Ok(None);
        };
        Ok(Some(codec::deserialize(&raw)?))
    }

    async fn rebuild_pending_debits_index(&self) -> Result<(), BlockchainError> {
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let debits_tree = self.open_pending_debits_tree()?;
        let credits_tree = self.open_pending_credits_tree()?;
        debits_tree.clear()?;
        credits_tree.clear()?;

        let mut totals: HashMap<String, i128> = HashMap::new();
        let mut incoming: HashMap<String, i128> = HashMap::new();
        for item in pending_tree.iter() {
            let (_, tx_bytes) = item?;
            if let Ok(tx) = deserialize_transaction(&tx_bytes) {
                if tx.sender != "MINING_REWARDS" && tx.has_valid_regular_amounts() {
                    *totals.entry(tx.sender.clone()).or_insert(0) += tx.total_debit_units();
                    *incoming.entry(tx.recipient.clone()).or_insert(0) += tx.amount_units;
                }
            }
        }

        let mut debit_batch = sled::Batch::default();
        for (address, total) in totals {
            let normalized = total.max(0);
            if normalized > 0 {
                debit_batch.insert(address.as_bytes(), codec::serialize(&normalized)?);
            }
        }
        let mut credit_batch = sled::Batch::default();
        for (address, total) in incoming {
            let normalized = total.max(0);
            if normalized > 0 {
                credit_batch.insert(address.as_bytes(), codec::serialize(&normalized)?);
            }
        }
        debits_tree.apply_batch(debit_batch)?;
        credits_tree.apply_batch(credit_batch)?;
        debits_tree.flush()?;
        credits_tree.flush()?;
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

        orphan_blocks.insert(hash_key.as_bytes(), codec::serialize(&orphan_entry)?)?;
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
            if let Ok(entry) = codec::deserialize::<OrphanStoredBlock>(&raw) {
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
                if let Ok(entry) = codec::deserialize::<OrphanStoredBlock>(&raw) {
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

    fn collect_orphan_branches_from(
        &self,
        start: Block,
        max_depth: usize,
        max_branches: usize,
    ) -> Result<Vec<Vec<Block>>, BlockchainError> {
        let mut complete = Vec::new();
        let mut stack = vec![vec![start]];

        while let Some(branch) = stack.pop() {
            let Some(current) = branch.last() else {
                continue;
            };

            if branch.len() >= max_depth {
                complete.push(branch);
                continue;
            }

            let mut children = self.orphan_children_of(&current.hash)?;
            children.retain(|c| {
                c.index == current.index.saturating_add(1) && c.previous_hash == current.hash
            });

            if children.is_empty() {
                complete.push(branch);
                continue;
            }

            let remaining_slots = max_branches.saturating_sub(complete.len() + stack.len());
            if remaining_slots == 0 {
                complete.push(branch);
                break;
            }

            let selected: Vec<Block> = children.into_iter().take(remaining_slots).collect();
            for child in selected.into_iter().rev() {
                let mut next_branch = branch.clone();
                next_branch.push(child);
                stack.push(next_branch);
            }
        }

        Ok(complete)
    }

    fn canonical_work_range(&self, start: u32, end: u32) -> Result<BigUint, BlockchainError> {
        if end < start {
            return Ok(BigUint::from(0u8));
        }
        let mut work = BigUint::from(0u8);
        for height in start..=end {
            let block = self.get_block(height)?;
            work += Self::work_units_for_difficulty(block.difficulty);
        }
        Ok(work)
    }

    fn work_units_for_difficulty(difficulty: u64) -> BigUint {
        let exponent = (difficulty / 16).min(255) as usize;
        BigUint::from(1u8) << exponent
    }

    fn branch_work_to_height(branch: &[Block], max_height: u32) -> BigUint {
        branch
            .iter()
            .filter(|b| b.index <= max_height)
            .fold(BigUint::from(0u8), |acc, b| {
                acc + Self::work_units_for_difficulty(b.difficulty)
            })
    }

    fn compare_work_delta(
        branch_work: &BigUint,
        canonical_work: &BigUint,
        other_branch_work: &BigUint,
        other_canonical_work: &BigUint,
    ) -> std::cmp::Ordering {
        (branch_work + other_canonical_work).cmp(&(other_branch_work + canonical_work))
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
            let Ok(entry) = codec::deserialize::<OrphanStoredBlock>(&raw) else {
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
        let mut best_work_pair: Option<(BigUint, BigUint)> = None;
        let mut best_tip_hash: [u8; 32] = [0u8; 32];

        for candidate in candidates {
            let branches = self.collect_orphan_branches_from(
                candidate,
                ORPHAN_REORG_DEPTH as usize,
                ORPHAN_BRANCH_SEARCH_LIMIT,
            )?;
            for branch in branches {
                let Some(branch_tip) = branch.last() else {
                    continue;
                };
                // Branch may be same-height competitor or longer. Adoption decision is based on work.

                let fork_height = branch[0].index;
                let canonical_work = self.canonical_work_range(fork_height, tip.index)?;
                let branch_work = Self::branch_work_to_height(&branch, branch_tip.index);

                // Deterministic adoption rule:
                // 1) positive overlap work advantage
                // 2) tie-break by lexical tip hash
                let should_replace = match &best_work_pair {
                    None => true,
                    Some((best_branch_work, best_canonical_work)) => {
                        match Self::compare_work_delta(
                            &branch_work,
                            &canonical_work,
                            best_branch_work,
                            best_canonical_work,
                        ) {
                            std::cmp::Ordering::Greater => true,
                            std::cmp::Ordering::Equal => branch_tip.hash < best_tip_hash,
                            std::cmp::Ordering::Less => false,
                        }
                    }
                };

                if should_replace {
                    best_tip_hash = branch_tip.hash;
                    best_work_pair = Some((branch_work, canonical_work));
                    best_branch = Some(branch);
                }
            }
        }

        let Some(branch) = best_branch else {
            return Ok(false);
        };
        let Some((branch_work, canonical_work)) = best_work_pair else {
            return Ok(false);
        };
        if branch_work < canonical_work {
            return Ok(false);
        }
        if branch_work == canonical_work {
            let Some(branch_tip) = branch.last() else {
                return Ok(false);
            };
            if branch_tip.index != tip.index || branch_tip.hash >= tip.hash {
                return Ok(false);
            }
        }

        // Validate the selected branch (including parent-linked difficulty adjustment) before applying.
        for b in &branch {
            self.validate_block_internal(b, SignatureValidationMode::AllowTruncatedStored)
                .await?;
        }

        self.mark_chain_state_dirty(branch[0].index, "orphan_branch_reorg")?;

        // Apply reorg by rewriting canonical block slots with the selected branch.
        for b in &branch {
            let key = format!("block_{}", b.index);
            let storage = Self::to_storage_block(b);
            self.db
                .insert(key.as_bytes(), codec::serialize(&storage)?)?;
        }

        let branch_tip = branch
            .last()
            .ok_or(BlockchainError::InvalidBlockHeader)?
            .clone();
        for stale_height in branch_tip.index.saturating_add(1)..=tip.index {
            let key = format!("block_{}", stale_height);
            self.db.remove(key.as_bytes())?;
        }

        // Remove adopted branch blocks from orphan pool.
        for b in &branch {
            let _ = self.remove_orphan_by_hash(&b.hash);
        }
        self.prune_orphans()?;

        // Rebuild balances index after reorg.
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        self.rebuild_balances_index(&balances_tree).await?;
        Self::set_balances_height(&balances_tree, branch_tip.index as u64)?;
        self.write_chain_tip_metadata(&branch_tip)?;
        let _ = self.get_network_difficulty().await?;
        self.db.flush()?;
        balances_tree.flush()?;
        self.open_chain_meta_tree()?.flush()?;
        self.clear_chain_state_dirty()?;
        self.notify_tip_changed(&branch_tip);

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
            if let Ok(entry) = codec::deserialize::<OrphanStoredBlock>(&raw) {
                let expired = now.saturating_sub(entry.received_at) > ORPHAN_TTL_SECS;
                let stale_height = tip
                    .map(|t| entry.block.index.saturating_add(ORPHAN_REORG_DEPTH) < t)
                    .unwrap_or(false);
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

    async fn persist_validated_block_with_mode(
        &self,
        block: &Block,
        sig_mode: SignatureValidationMode,
    ) -> Result<(), BlockchainError> {
        // Canonical validation gate for all persistence paths.
        self.validate_block_internal(block, sig_mode).await?;

        // Run expensive full-chain integrity checks periodically.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last_integrity = self
            .chain_sentinel
            .last_verification
            .load(Ordering::Relaxed);
        let should_verify_integrity =
            block.index.is_multiple_of(128) || now.saturating_sub(last_integrity) >= 60;

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
        if let Some((idx, _tx)) = system_txs
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
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let verification_count = self.chain_sentinel.get_verification_count(block);
        if require_quorum {
            if !self.chain_sentinel.is_block_verified(block) {
                return Err(BlockchainError::InvalidBlockHeader);
            }
        } else if verification_count == 0 {
            return Err(BlockchainError::InvalidBlockHeader);
        }

        self.mark_chain_state_dirty(block.index, "persist_block")?;

        // Process transactions with BlockValidation context
        let tx_context = match sig_mode {
            SignatureValidationMode::RequireFull => TransactionContext::BlockValidation,
            SignatureValidationMode::AllowTruncatedStored => TransactionContext::ReceiptValidation,
        };
        if let Err(err) = self
            .process_transactions_batch(block.transactions.clone(), tx_context, block.index as u64)
            .await
        {
            warn!(
                "Block {} transaction application failed; dirty marker remains for startup recovery",
                block.index
            );
            return Err(err);
        }

        // Store block with truncated signatures to reduce chain size
        let storage_block = Self::to_storage_block(block);

        // Serialize and save block
        let value = match codec::serialize(&storage_block) {
            Ok(value) => value,
            Err(err) => {
                return Err(BlockchainError::SerializationError(Box::new(err)));
            }
        };

        let key = format!("block_{}", block.index);
        if let Err(err) = self.db.insert(key.as_bytes(), value) {
            return Err(BlockchainError::DatabaseError(err));
        }

        // Remove this hash from orphan pool if present
        if let Err(err) = self.remove_orphan_by_hash(&block.hash) {
            warn!("Failed to remove adopted orphan {}: {}", block.index, err);
        }

        // Update network difficulty atomically
        {
            let mut current_difficulty = self.difficulty.lock().await;
            *current_difficulty = block.difficulty;
        }

        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        Self::set_balances_height(&balances_tree, block.index as u64)?;
        self.write_chain_tip_metadata(block)?;

        // Ensure all changes are persisted
        self.db
            .flush()
            .map_err(|e| BlockchainError::FlushError(e.to_string()))?;
        balances_tree.flush()?;
        self.open_chain_meta_tree()?.flush()?;
        self.clear_chain_state_dirty()?;
        self.notify_tip_changed(block);

        Ok(())
    }

    async fn persist_validated_block(&self, block: &Block) -> Result<(), BlockchainError> {
        self.persist_validated_block_with_mode(block, SignatureValidationMode::RequireFull)
            .await
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
                pending_tree.remove(&key)?;
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
            let height: u64 = codec::deserialize(&raw)?;
            Ok(Some(height))
        } else {
            Ok(None)
        }
    }

    fn set_balances_height(tree: &sled::Tree, height: u64) -> Result<(), BlockchainError> {
        tree.insert(BALANCES_HEIGHT_KEY, codec::serialize(&height)?)?;
        Ok(())
    }

    pub async fn ensure_balances_index(&self) -> Result<(), BlockchainError> {
        self.ensure_balances_index_with_force(false).await
    }

    async fn ensure_balances_index_with_force(
        &self,
        force_rebuild_requested: bool,
    ) -> Result<(), BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        let tip = self.get_latest_block_index();
        let force_rebuild_env = std::env::var("ALPHANUMERIC_REBUILD_BALANCES")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let current_height = Self::get_balances_height(&balances_tree)?;
        let needs_rebuild = force_rebuild_requested
            || force_rebuild_env
            || current_height.is_none()
            || current_height.unwrap_or(0) != tip;

        if needs_rebuild {
            self.rebuild_balances_index(&balances_tree).await?;
            Self::set_balances_height(&balances_tree, tip)?;
            balances_tree.flush()?;
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

        let mut balances: HashMap<String, i128> = HashMap::new();
        for block in blocks {
            for tx in block.transactions {
                if tx.sender != "MINING_REWARDS" {
                    let debit = tx.total_debit_units();
                    let entry = balances.entry(tx.sender).or_insert(0);
                    *entry -= debit;
                }
                let entry = balances.entry(tx.recipient).or_insert(0);
                *entry += tx.amount_units;
            }
        }

        let mut batch = sled::Batch::default();
        for (address, balance) in balances {
            batch.insert(address.as_bytes(), codec::serialize(&balance)?);
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
        let signature_cache = Arc::new(PLMutex::new(LruCache::new(
            Self::signature_cache_capacity(),
        )));
        let tip_change_counter = Arc::new(AtomicU64::new(0));
        let (tip_watch_tx, _) = watch::channel(ChainTipSignal::default());

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
            state_mutation_lock: Arc::new(Mutex::new(())),
            tip_change_counter,
            tip_watch_tx,
        };

        // Ensure pending tx trees exist (do not clear at startup).
        if let Ok(pending_tree) = db.open_tree(PENDING_TRANSACTIONS_TREE) {
            pending_tree.flush().ok();
        }
        let _ = db.open_tree(PENDING_FULL_SIGNATURES_TREE);
        let _ = db.open_tree(PENDING_DEBITS_TREE);
        let _ = db.open_tree(PENDING_CREDITS_TREE);
        // Ensure orphan-management trees exist.
        let _ = db.open_tree(ORPHAN_BLOCKS_TREE);
        let _ = db.open_tree(ORPHAN_INDEX_TREE);
        let _ = db.open_tree(CHAIN_META_TREE);

        blockchain
    }

    pub async fn initialize(&self) -> Result<(), BlockchainError> {
        let dirty_state = self.chain_state_dirty()?;
        if let Some(marker) = dirty_state.as_ref() {
            warn!(
                "Recovering derived chain state after interrupted {} at block {}",
                marker.reason, marker.block_index
            );
        }
        let _ = self.rebuild_chain_tip_metadata()?;

        // Get and set the network difficulty first
        self.get_network_difficulty().await?;

        // Sync mempool with sled
        let _ = self.prune_pending_transactions();
        self.sync_mempool_with_sled().await?;
        self.rebuild_pending_debits_index().await?;

        // Ensure balances index is valid (rebuild if needed)
        self.ensure_balances_index_with_force(dirty_state.is_some())
            .await?;
        if dirty_state.is_some() {
            self.clear_chain_state_dirty()?;
        }
        self.prune_orphans()?;
        let _ = self.promote_orphans_from_tip().await;
        self.refresh_tip_signal_from_current_tip();

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

                if !tx.has_valid_regular_amounts() {
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
                let sig_hex = full_tx.signature.as_ref().unwrap();
                let sig_bytes = match hex::decode(sig_hex) {
                    Ok(v) => v,
                    Err(_) => {
                        invalid_txs.push(key.to_vec());
                        continue;
                    }
                };

                if sig_bytes.len() <= 64 {
                    if tx.sig_hash.is_none() {
                        invalid_txs.push(key.to_vec());
                        continue;
                    }
                    let Some(full_sig_bytes) = full_sigs_tree.get(tx_id.as_bytes())? else {
                        invalid_txs.push(key.to_vec());
                        continue;
                    };
                    if let Some(expected) = tx.sig_hash.as_ref() {
                        let actual_hash = Transaction::signature_hash_hex(&full_sig_bytes);
                        if actual_hash != *expected {
                            invalid_txs.push(key.to_vec());
                            continue;
                        }
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

    pub async fn save_block(&self, block: &Block) -> Result<(), BlockchainError> {
        // Always do basic validation before admitting blocks into orphan storage.
        // This prevents trivial junk from occupying orphan capacity.
        self.prevalidate_unattached_block_strict(block).await?;

        let _state_guard = self.state_mutation_lock.lock().await;

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

    pub async fn save_receipt_verified_block(&self, block: &Block) -> Result<(), BlockchainError> {
        // Historical sync peers serve compact stored blocks. Those blocks carry a
        // signature receipt + full-signature hash, not the full ML-DSA witness.
        self.prevalidate_unattached_block(block, SignatureValidationMode::AllowTruncatedStored)
            .await?;

        let _state_guard = self.state_mutation_lock.lock().await;

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

        self.persist_validated_block_with_mode(
            block,
            SignatureValidationMode::AllowTruncatedStored,
        )
        .await?;
        let _ = self.promote_orphans_from_tip().await?;
        let _ = self.try_adopt_orphan_branch().await?;
        Ok(())
    }

    pub async fn finalize_block(
        &self,
        block: Block,
        _miner_address: String,
    ) -> Result<(), BlockchainError> {
        let _state_guard = self.state_mutation_lock.lock().await;
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
        let mut confirmed_balances: HashMap<String, i128> = HashMap::new();
        let mut pending_effects: HashMap<String, i128> = HashMap::new();

        // First pass: Get all confirmed balances
        for tx in &block.transactions {
            if tx.sender != "MINING_REWARDS" && !confirmed_balances.contains_key(&tx.sender) {
                let balance = self.get_confirmed_balance(&tx.sender).await?;
                confirmed_balances.insert(tx.sender.clone(), Transaction::to_units(balance));
            }
        }
        set_finalize_stage(2);
        trace_step("prefetch_balances");

        // Second pass: Validate transactions and track effects
        for tx in &block.transactions {
            if tx.sender == "MINING_REWARDS" {
                continue; // Skip validation for mining rewards
            }

            let confirmed = confirmed_balances.get(&tx.sender).copied().unwrap_or(0);
            let pending = pending_effects.get(&tx.sender).copied().unwrap_or(0);
            let available = confirmed - pending;
            let required = tx.total_debit_units();

            if available < required {
                return Err(BlockchainError::InsufficientFunds);
            }

            // Track this transaction's effect
            *pending_effects.entry(tx.sender.clone()).or_default() += required;
            *pending_effects.entry(tx.recipient.clone()).or_default() -= tx.amount_units;
        }
        set_finalize_stage(3);
        trace_step("validate_batch");

        self.mark_chain_state_dirty(block.index, "finalize_block")?;

        // Process transactions atomically
        if let Err(err) = self
            .process_transactions_batch(
                block.transactions.clone(),
                TransactionContext::BlockValidation,
                block.index as u64,
            )
            .await
        {
            warn!(
                "Finalized block {} transaction application failed; dirty marker remains for startup recovery",
                block.index
            );
            return Err(err);
        }
        set_finalize_stage(4);
        trace_step("apply_batch");

        // Save block with truncated signatures to reduce on-disk chain size.
        let storage_block = Self::to_storage_block(&block);
        let value = match codec::serialize(&storage_block) {
            Ok(value) => value,
            Err(err) => {
                return Err(BlockchainError::SerializationError(Box::new(err)));
            }
        };
        let key = format!("block_{}", block.index);
        if let Err(err) = self.db.insert(key.as_bytes(), value) {
            return Err(BlockchainError::DatabaseError(err));
        }
        set_finalize_stage(5);
        trace_step("db_insert");
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        Self::set_balances_height(&balances_tree, block.index as u64)?;
        self.write_chain_tip_metadata(&block)?;
        set_finalize_stage(6);
        trace_step("balances_height");
        self.db.flush()?;
        balances_tree.flush()?;
        self.open_chain_meta_tree()?.flush()?;
        self.clear_chain_state_dirty()?;
        self.notify_tip_changed(&block);
        let _ = self.promote_orphans_from_tip().await;

        Ok(())
    }

    pub async fn clear_processed_transactions(
        &self,
        transactions: &[Transaction],
    ) -> Result<(), BlockchainError> {
        let _state_guard = self.state_mutation_lock.lock().await;
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
                let current_debit = self.get_pending_debit_units(&tx.sender).await?;
                let delta = tx.total_debit_units();
                let next_debit = current_debit.saturating_sub(delta);
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
        match self.get_last_block() {
            Some(last) => last.index as usize + 1,
            None => 0,
        }
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

    pub fn get_recent_blocks(&self, limit: usize) -> Vec<Block> {
        let Some(tip) = self.highest_block_index() else {
            return Vec::new();
        };
        let count = limit.min(tip as usize + 1);
        let start = tip as usize + 1 - count;
        let mut blocks = Vec::with_capacity(count);
        for idx in start..=tip as usize {
            if let Ok(block) = self.get_block(idx as u32) {
                blocks.push(block);
            }
        }
        blocks
    }

    pub fn get_orphan_count(&self) -> usize {
        self.open_orphan_blocks_tree().map(|t| t.len()).unwrap_or(0)
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

    pub async fn get_tip_difficulty(&self) -> u64 {
        if let Some(block) = self.get_last_block() {
            block.difficulty
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

    pub fn get_genesis_block(&self) -> Result<Block, BlockchainError> {
        self.get_block(0)
    }

    pub async fn calculate_wallet_balance(&self, address: &str) -> Result<f64, BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;

        if let Some(balance_bytes) = balances_tree.get(address.as_bytes())? {
            let units = Self::deserialize_units_compatible(&balance_bytes)?;
            Ok(Transaction::from_units(units))
        } else {
            Ok(0.0)
        }
    }
    // Validation
    pub async fn validate_chain(&self) -> Result<bool, BlockchainError> {
        let mut previous_block: Option<Block> = None;

        for current_block in self.get_blocks() {
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

        if !tx.has_valid_regular_amounts() {
            return Err(BlockchainError::InvalidTransactionAmount);
        }

        // For regular transactions, validate balance with proper pending tracking
        let confirmed_balance = self.get_confirmed_balance(&tx.sender).await?;
        let pending_amount = if block.is_none() {
            // Only check pending for new transactions, not during block validation
            self.get_pending_amount(&tx.sender).await?
        } else {
            0.0
        };

        let available_balance = Transaction::to_units(confirmed_balance - pending_amount);
        let required_amount = tx.total_debit_units();

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

    fn verify_transaction_receipt_fields(tx: &Transaction) -> Result<(), BlockchainError> {
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

        let pub_key = tx
            .pub_key
            .as_ref()
            .ok_or(BlockchainError::InvalidTransactionSignature)?;
        let pub_key_bytes =
            hex::decode(pub_key).map_err(|_| BlockchainError::InvalidTransactionSignature)?;
        if mldsa::validate_public_key(&pub_key_bytes).is_err() {
            return Err(BlockchainError::InvalidTransactionSignature);
        }
        let mut hasher = Sha256::new();
        hasher.update(&pub_key_bytes);
        let derived_addr = hex::encode(&hasher.finalize()[..20]);
        if derived_addr != tx.sender {
            return Err(BlockchainError::InvalidTransactionSignature);
        }

        let sig_hash = tx
            .sig_hash
            .as_ref()
            .ok_or(BlockchainError::InvalidTransactionSignature)?;
        if sig_hash.len() != 64 || hex::decode(sig_hash).is_err() {
            return Err(BlockchainError::InvalidTransactionSignature);
        }

        Ok(())
    }

    pub fn get_block_by_timestamp(&self, timestamp: u64) -> Result<Block, BlockchainError> {
        for (_, block_data) in self.db.scan_prefix(b"block_").flatten() {
            if let Ok(block) = Block::from_bytes(&block_data) {
                if block.timestamp == timestamp {
                    return Ok(block);
                }
            }
        }
        Err(BlockchainError::InvalidTransaction)
    }

    fn is_valid_hash_with_difficulty(&self, hash: &[u8; 32], difficulty: u64) -> bool {
        let hash_int = BigUint::from_bytes_be(hash);
        let target = pow_target_from_difficulty(difficulty);

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

        // Enhanced difficulty + linkage validation for non-genesis blocks.
        // IMPORTANT: validate against the referenced parent by hash (canonical or orphan), not "whatever is at height-1".
        if block.index > 0 {
            let parent = self
                .get_parent_block_for(block)?
                .ok_or(BlockchainError::InvalidBlockHeader)?;
            if parent.hash != block.previous_hash {
                return Err(BlockchainError::InvalidBlockHeader);
            }
            Self::validate_parent_timestamp(block, &parent)?;

            let expected_difficulty = Block::adjust_dynamic_difficulty(
                parent.difficulty,
                block.timestamp.saturating_sub(parent.timestamp),
                block.index,
                &mut DifficultyOracle::new(),
                block.timestamp,
            );

            if block.difficulty != expected_difficulty {
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

        if block.transactions.first().map(|tx| tx.sender.as_str()) != Some("MINING_REWARDS") {
            return Err(BlockchainError::InvalidSystemTransaction);
        }

        let reward_tx = reward_txs[0];
        if reward_tx.fee_units != Transaction::to_units(NETWORK_FEE) {
            return Err(BlockchainError::InvalidSystemTransaction);
        }
        let expected_reward = self.calculate_block_reward(block)?;
        if reward_tx.amount_units != Transaction::to_units(expected_reward) {
            return Err(BlockchainError::InvalidTransactionAmount);
        }

        for tx in &block.transactions {
            if tx.sender == "MINING_REWARDS" {
                continue;
            }
            if tx.amount_units < MIN_TRANSACTION_AMOUNT_UNITS {
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

            if sig_bytes.len() > 64 {
                self.verify_transaction_signature(tx)?;
            } else {
                Self::verify_transaction_receipt_fields(tx)?;
            }
        }

        Ok(())
    }

    pub async fn validate_new_block(&self, block: &Block) -> Result<(), BlockchainError> {
        // Basic Header Validation
        block.validate_header()?;

        // Get current confirmed balances before validation
        let mut confirmed_balances: HashMap<String, i128> = HashMap::new();
        let mut pending_deductions: HashMap<String, i128> = HashMap::new();

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
            confirmed_balances.insert(sender.clone(), Transaction::to_units(balance));
        }

        // Validate each regular transaction
        for tx in regular_transactions {
            if !tx.has_valid_regular_amounts() {
                return Err(BlockchainError::InvalidTransactionAmount);
            }

            if tx.signature.is_none() || tx.pub_key.is_none() || tx.sig_hash.is_none() {
                return Err(BlockchainError::InvalidTransactionSignature);
            }

            let sig_hex = tx
                .signature
                .as_ref()
                .ok_or(BlockchainError::InvalidTransactionSignature)?;
            let sig_bytes =
                hex::decode(sig_hex).map_err(|_| BlockchainError::InvalidTransactionSignature)?;
            if sig_bytes.len() <= 64 {
                return Err(BlockchainError::InvalidTransactionSignature);
            }
            self.verify_transaction_signature(tx)?;

            let current_confirmed = confirmed_balances.get(&tx.sender).copied().unwrap_or(0);

            let pending_deducted = pending_deductions.get(&tx.sender).copied().unwrap_or(0);

            let available_balance = current_confirmed - pending_deducted;
            let required_amount = tx.total_debit_units();

            if available_balance < required_amount {
                return Err(BlockchainError::InsufficientFunds);
            }

            // Track this deduction for subsequent transactions
            *pending_deductions.entry(tx.sender.clone()).or_default() += required_amount;
        }

        Ok(())
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

        if !transaction.has_valid_regular_amounts() {
            return Err(BlockchainError::InvalidTransactionAmount);
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
        if sig_bytes.is_empty() {
            return Err(BlockchainError::InvalidTransactionSignature);
        }

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

        let _state_guard = self.state_mutation_lock.lock().await;
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let pending_debits_tree = self.open_pending_debits_tree()?;
        let pending_credits_tree = self.open_pending_credits_tree()?;
        let full_sigs_tree = self.db.open_tree(PENDING_FULL_SIGNATURES_TREE)?;
        let sync_pending_writes = std::env::var("ALPHANUMERIC_SYNC_PENDING_WRITES")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if pending_tree.get(tx_id.as_bytes())?.is_some() {
            if full_sigs_tree.get(tx_id.as_bytes())?.is_none() {
                full_sigs_tree.insert(tx_id.as_bytes(), sig_bytes)?;
                if sync_pending_writes {
                    full_sigs_tree.flush()?;
                }
            }
            self.add_to_mempool(mempool_tx).await?;
            return Ok(());
        }

        let confirmed_balance = self.get_confirmed_balance(&transaction.sender).await?;
        let pending_amount = self.get_pending_debit_for(&transaction.sender).await?;

        let available_balance = Transaction::to_units(confirmed_balance - pending_amount);
        let total_required = transaction.total_debit_units();
        if available_balance < total_required {
            return Err(BlockchainError::InsufficientFunds);
        }

        self.add_to_mempool(mempool_tx).await?;

        // Store full signature witness in sidecar (keyed by tx_id) so mempool can be rehydrated after restart.
        // The main pending tx record remains compact (truncated signature + sig_hash).
        full_sigs_tree.insert(tx_id.as_bytes(), sig_bytes)?;

        let tx_bytes = codec::serialize(&storage_tx)?;
        pending_tree.insert(tx_id.as_bytes(), tx_bytes)?;

        let current_debit = self.get_pending_debit_units(&transaction.sender).await?;
        let next_debit = current_debit + storage_tx.total_debit_units();
        Self::set_pending_debit_for(&pending_debits_tree, &transaction.sender, next_debit)?;
        let current_credit = self
            .get_pending_credit_units(&transaction.recipient)
            .await?;
        let next_credit = current_credit + storage_tx.amount_units;
        Self::set_pending_credit_for(&pending_credits_tree, &transaction.recipient, next_credit)?;

        // Hot path durability policy:
        // defer fsync to periodic DB flushing to avoid per-transaction stalls.
        // Set ALPHANUMERIC_SYNC_PENDING_WRITES=true to force immediate pending-tree flushes.
        if sync_pending_writes {
            full_sigs_tree.flush()?;
            pending_tree.flush()?;
            pending_debits_tree.flush()?;
            pending_credits_tree.flush()?;
        }

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
        Ok(mempool.get_all_transactions())
    }

    pub async fn get_mempool_transaction_by_id(&self, tx_id: &str) -> Option<Transaction> {
        self.mempool.read().await.find_transaction_by_id(tx_id)
    }

    pub async fn add_to_mempool(&self, tx: Transaction) -> Result<(), BlockchainError> {
        self.mempool.write().await.add_transaction(tx)
    }

    pub fn get_transaction_by_hash(&self, hash: &str) -> Option<Transaction> {
        for (_, value) in self.db.scan_prefix(b"block_").flatten() {
            if let Ok(block) = Block::from_bytes(&value) {
                for tx in block.transactions {
                    if tx.create_hash() == hash {
                        return Some(tx);
                    }
                }
            }
        }
        None
    }

    pub fn calculate_block_reward(&self, block: &Block) -> Result<f64, BlockchainError> {
        const SECONDS_IN_SIX_MONTHS: u64 = 15_768_000; // 182.5 days
        const REDUCTION_RATE: f64 = 0.83; // 17% reduction = multiply by 0.83

        if block.index == 0 {
            return Ok(GENESIS_LAUNCH_AMOUNT);
        }

        // Calculate periods since genesis for halving
        let genesis = self.get_genesis_block()?;
        let time_since_genesis = block.timestamp.saturating_sub(genesis.timestamp);
        let periods = time_since_genesis / SECONDS_IN_SIX_MONTHS;

        // Apply reduction rate for each period to max reward
        let current_max = MAX_BLOCK_REWARD * REDUCTION_RATE.powi(periods as i32);

        // Get transaction metrics and sum fees in a single pass (excluding mining rewards)
        let (tx_count, _total_volume, total_fees) = block
            .transactions
            .iter()
            .filter(|tx| tx.sender != "MINING_REWARDS")
            .fold((0usize, 0.0, 0.0), |(count, volume, fees), tx| {
                (count + 1, volume + tx.amount(), fees + tx.fee())
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
                    let target = pow_target_from_difficulty(last_block.difficulty);
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

    pub fn genesis_launch_block() -> Result<Block, BlockchainError> {
        let genesis_transaction = Transaction::new(
            "MINING_REWARDS".to_string(),
            GENESIS_LAUNCH_RECIPIENT.to_string(),
            GENESIS_LAUNCH_AMOUNT,
            NETWORK_FEE,
            GENESIS_LAUNCH_TIMESTAMP,
            None,
        );
        let transactions = vec![genesis_transaction];
        let merkle_root = Self::calculate_merkle_root(&transactions)?;
        let mut block = Block {
            index: 0,
            previous_hash: [0u8; 32],
            timestamp: GENESIS_LAUNCH_TIMESTAMP,
            transactions,
            nonce: GENESIS_LAUNCH_NONCE,
            difficulty: GENESIS_LAUNCH_DIFFICULTY,
            hash: [0u8; 32],
            merkle_root,
        };
        block.hash = block.calculate_hash_for_block();
        Ok(block)
    }

    // Frozen launch genesis block. Empty launch DBs create this exact block.
    pub async fn create_genesis_block(&self) -> Result<(), BlockchainError> {
        if self.get_block(0).is_ok() {
            return Ok(());
        }
        let genesis_block = Self::genesis_launch_block()?;
        self.save_receipt_verified_block(&genesis_block)
            .await
            .map_err(|e| {
                error!("Failed to save genesis block: {}", e);
                e
            })
    }

    pub async fn sync_mempool_with_sled(&self) -> Result<(), BlockchainError> {
        let _state_guard = self.state_mutation_lock.lock().await;
        // Clear existing mempool
        let mut mempool = self.mempool.write().await;

        // Get pending transactions from sled
        let _ = self.prune_pending_transactions();
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let full_sigs_tree = self.db.open_tree(PENDING_FULL_SIGNATURES_TREE)?;

        // Collect all transactions from sled, removing any stale malformed rows so
        // pending indexes and future mining attempts cannot stay poisoned.
        let mut transactions = Vec::new();
        let mut invalid_txs = Vec::new();
        for result in pending_tree.iter() {
            let (key, tx_bytes) = result?;
            let Ok(mut tx) = deserialize_transaction(&tx_bytes) else {
                invalid_txs.push(key.to_vec());
                continue;
            };

            // Pending txs are stored with a truncated signature in the main record. Rehydrate the full signature
            // from the sidecar tree and strictly verify before admitting into the in-memory mempool.
            if tx.sender == "MINING_REWARDS" || !tx.has_valid_regular_amounts() {
                invalid_txs.push(key.to_vec());
                continue;
            }

            if tx.pub_key.is_none() || tx.sig_hash.is_none() || tx.signature.is_none() {
                invalid_txs.push(key.to_vec());
                continue;
            }

            let tx_id = tx.get_tx_id();
            let expected_sig_hash = tx.sig_hash.as_ref().cloned();

            let sig_hex = tx.signature.as_ref().unwrap();
            let sig_bytes = match hex::decode(sig_hex) {
                Ok(v) => v,
                Err(_) => {
                    invalid_txs.push(key.to_vec());
                    continue;
                }
            };

            if sig_bytes.len() <= 64 {
                if expected_sig_hash.is_none() {
                    invalid_txs.push(key.to_vec());
                    continue;
                }
                let Some(full_sig_bytes) = full_sigs_tree.get(tx_id.as_bytes())? else {
                    // No witness available; do not allow unverifiable tx into the mempool.
                    invalid_txs.push(key.to_vec());
                    continue;
                };

                let actual_hash = Transaction::signature_hash_hex(&full_sig_bytes);
                if expected_sig_hash.as_deref() != Some(actual_hash.as_str()) {
                    invalid_txs.push(key.to_vec());
                    continue;
                }

                tx.signature = Some(hex::encode(&full_sig_bytes));
            }

            if self.verify_transaction_signature(&tx).is_err() {
                invalid_txs.push(key.to_vec());
                continue;
            }

            transactions.push(tx);
        }

        for key in invalid_txs {
            pending_tree.remove(&key)?;
            let _ = full_sigs_tree.remove(&key);
        }
        pending_tree.flush()?;
        full_sigs_tree.flush()?;

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
        let mut balance_units: i128 = 0;
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
                balance_units += tx.amount_units;
            } else if tx.sender == address {
                // Transactions in confirmed blocks are assumed validated at acceptance time.
                // Do not re-check signatures here with sender address input.
                balance_units -= tx.total_debit_units();
            } else if tx.recipient == address {
                balance_units += tx.amount_units;
            }
        }

        // Handle pending transactions CORRECTLY
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let mut pending_balances: HashMap<String, i128> = HashMap::new(); // Track pending balances

        for (_, tx_bytes) in pending_tree.iter().flatten() {
            if let Ok(tx) = deserialize_transaction(&tx_bytes) {
                if tx.sender == address {
                    let pending_spent = pending_balances.get(address).unwrap_or(&0);
                    // Get current balance from confirmed transactions
                    let current_balance = balance_units;
                    let tx_debit = tx.total_debit_units();
                    if current_balance + pending_spent < tx_debit {
                        continue; // Skip double-spending transaction
                    }
                    balance_units -= tx_debit;
                    *pending_balances.entry(address.to_string()).or_insert(0) -= tx_debit;
                } else if tx.recipient == address {
                    balance_units += tx.amount_units;
                }
            }
        }

        Ok(Transaction::from_units(balance_units))
    }

    // Add to handle distributions
    pub async fn process_transactions_batch(
        &self,
        transactions: Vec<Transaction>,
        context: TransactionContext,
        confirm_height: u64,
    ) -> Result<(), BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        let full_sigs_tree = self.db.open_tree(PENDING_FULL_SIGNATURES_TREE)?;
        let pending_debits_tree = self.open_pending_debits_tree()?;
        let pending_credits_tree = self.open_pending_credits_tree()?;

        // Track cumulative balance changes
        let mut balance_changes: HashMap<String, i128> = HashMap::new();
        let mut current_balances: HashMap<String, i128> = HashMap::new();

        // First pass: Get all current balances for any address touched by this batch
        for tx in &transactions {
            if tx.sender != "MINING_REWARDS" && !current_balances.contains_key(&tx.sender) {
                let balance = self.get_confirmed_balance(&tx.sender).await?;
                current_balances.insert(tx.sender.clone(), Transaction::to_units(balance));
            }
            if !current_balances.contains_key(&tx.recipient) {
                let balance = self.get_confirmed_balance(&tx.recipient).await?;
                current_balances.insert(tx.recipient.clone(), Transaction::to_units(balance));
            }
        }

        // Second pass: Validate and calculate changes
        for tx in &transactions {
            match tx.sender.as_str() {
                "MINING_REWARDS" => {
                    *balance_changes.entry(tx.recipient.clone()).or_default() += tx.amount_units;
                }
                _ => {
                    if context == TransactionContext::BlockValidation {
                        // Live block validation must only operate on fully-verifiable transactions.
                        self.verify_transaction_signature(tx)?;
                    } else {
                        // Historical sync stores/receives receipt commitments after full live validation.
                        Self::verify_transaction_receipt_fields(tx)?;
                    }

                    let total_debit = tx.total_debit_units();
                    let current_balance = current_balances.get(&tx.sender).copied().unwrap_or(0);
                    let pending_change = balance_changes.get(&tx.sender).copied().unwrap_or(0);

                    // Check if sufficient funds available
                    if current_balance + pending_change < total_debit {
                        return Err(BlockchainError::InsufficientFunds);
                    }

                    *balance_changes.entry(tx.sender.clone()).or_default() -= total_debit;
                    *balance_changes.entry(tx.recipient.clone()).or_default() += tx.amount_units;
                }
            }
        }

        // Apply all changes atomically
        let mut batch = sled::Batch::default();
        for (address, change) in balance_changes {
            let current = current_balances.get(&address).copied().unwrap_or(0);
            let new_balance = current + change;
            batch.insert(address.as_bytes(), codec::serialize(&new_balance)?);
        }

        // Commit changes
        balances_tree.apply_batch(batch)?;

        // Clear processed transactions from pending
        if matches!(
            context,
            TransactionContext::BlockValidation | TransactionContext::ReceiptValidation
        ) {
            let cw_tree = self.db.open_tree(CONFIRMED_WITNESSES_TREE)?;
            let cw_index = self.db.open_tree(CONFIRMED_WITNESS_INDEX_TREE)?;
            for tx in &transactions {
                if tx.sender != "MINING_REWARDS" {
                    let tx_id = tx.get_tx_id();
                    // Retain the full witness for a bounded window (before purging the
                    // pending copy) so peers can serve it for near-tip verification during
                    // sync. Local-only: no effect on block hashes, merkle roots, or validity.
                    if let Ok(Some(sig)) = full_sigs_tree.get(tx_id.as_bytes()) {
                        let mut full_tx = tx.clone();
                        full_tx.signature = Some(hex::encode(&sig));
                        if let Ok(bytes) = codec::serialize(&full_tx) {
                            let _ = cw_tree.insert(tx_id.as_bytes(), bytes);
                            let mut idx_key = confirm_height.to_be_bytes().to_vec();
                            idx_key.extend_from_slice(tx_id.as_bytes());
                            let _ = cw_index.insert(idx_key, b"" as &[u8]);
                        }
                    }
                    pending_tree.remove(tx_id.as_bytes())?;
                    let _ = full_sigs_tree.remove(tx_id.as_bytes());
                    let current_debit = self.get_pending_debit_units(&tx.sender).await?;
                    let delta = tx.total_debit_units();
                    let next_debit = current_debit.saturating_sub(delta);
                    Self::set_pending_debit_for(&pending_debits_tree, &tx.sender, next_debit)?;
                    let current_credit = self.get_pending_credit_units(&tx.recipient).await?;
                    let next_credit = current_credit.saturating_sub(tx.amount_units);
                    Self::set_pending_credit_for(
                        &pending_credits_tree,
                        &tx.recipient,
                        next_credit,
                    )?;
                }
            }
            pending_debits_tree.flush()?;
            pending_credits_tree.flush()?;
            full_sigs_tree.flush()?;
            let _ = cw_tree.flush();
            let _ = cw_index.flush();
            self.prune_confirmed_witnesses(confirm_height)?;
        }

        Ok(())
    }

    /// Remove retained confirmed-transaction witnesses older than the retention
    /// window. Index keys are height-big-endian prefixed, so a byte range prunes
    /// everything confirmed at or below `tip_height - WITNESS_RETENTION_BLOCKS`.
    fn prune_confirmed_witnesses(&self, tip_height: u64) -> Result<(), BlockchainError> {
        if tip_height <= WITNESS_RETENTION_BLOCKS {
            return Ok(());
        }
        let cutoff = tip_height - WITNESS_RETENTION_BLOCKS;
        let cw_tree = self.db.open_tree(CONFIRMED_WITNESSES_TREE)?;
        let cw_index = self.db.open_tree(CONFIRMED_WITNESS_INDEX_TREE)?;
        let upper = cutoff.saturating_add(1).to_be_bytes().to_vec();
        let mut stale: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for item in cw_index.range(..upper) {
            let (key, _) = item?;
            let tx_id = if key.len() > 8 {
                key[8..].to_vec()
            } else {
                Vec::new()
            };
            stale.push((key.to_vec(), tx_id));
        }
        for (idx_key, tx_id) in stale {
            let _ = cw_index.remove(&idx_key);
            if !tx_id.is_empty() {
                let _ = cw_tree.remove(&tx_id);
            }
        }
        Ok(())
    }

    /// Full-signature transaction retained for a recently-confirmed tx so this node
    /// can serve it as a witness during a peer's near-tip sync verification. Returns
    /// None once the retention window has pruned it.
    pub fn get_confirmed_witness_tx(&self, tx_id: &str) -> Option<Transaction> {
        let cw_tree = self.db.open_tree(CONFIRMED_WITNESSES_TREE).ok()?;
        let bytes = cw_tree.get(tx_id.as_bytes()).ok().flatten()?;
        codec::deserialize::<Transaction>(&bytes).ok()
    }

    pub async fn get_confirmed_balance(&self, address: &str) -> Result<f64, BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        let auto_rebuild = std::env::var("ALPHANUMERIC_BALANCES_AUTO_REBUILD")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);

        let mut index_height = Self::get_balances_height(&balances_tree)?.unwrap_or(0);
        if auto_rebuild {
            let tip = self.get_latest_block_index();
            if index_height < tip {
                self.ensure_balances_index().await?;
                index_height = Self::get_balances_height(&balances_tree)?.unwrap_or(tip);
            }
        }
        if let Some(balance_bytes) = balances_tree.get(address.as_bytes())? {
            let balance_units = Self::deserialize_units_compatible(&balance_bytes)?;
            return Ok(Transaction::from_units(balance_units));
        }
        if auto_rebuild && index_height >= self.get_latest_block_index() {
            let balance_units: i128 = 0;
            balances_tree.insert(address.as_bytes(), codec::serialize(&balance_units)?)?;
            return Ok(0.0);
        }
        // Slow path: calculate from blocks, then cache in balances tree.
        let mut balance_units: i128 = 0;
        let mut current_batch = Vec::with_capacity(200);

        for (_, block_data) in self.db.scan_prefix(b"block_").flatten() {
            current_batch.push(block_data);

            if current_batch.len() >= 200 {
                // Process current batch
                for block_data in current_batch.drain(..) {
                    if let Ok(block) = Block::from_bytes(&block_data) {
                        for tx in &block.transactions {
                            if tx.recipient == address {
                                balance_units += tx.amount_units;
                            }
                            if tx.sender == address {
                                balance_units -= tx.total_debit_units();
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
                        balance_units += tx.amount_units;
                    }
                    if tx.sender == address {
                        balance_units -= tx.total_debit_units();
                    }
                }
            }
        }

        balances_tree.insert(address.as_bytes(), codec::serialize(&balance_units)?)?;
        Ok(Transaction::from_units(balance_units))
    }

    // Public method that shows spendable balance to users
    pub async fn get_wallet_balance(&self, address: &str) -> Result<f64, BlockchainError> {
        let confirmed = self.get_confirmed_balance(address).await?;
        let pending_debit = self.get_pending_debit_for(address).await?;
        let net_units =
            Transaction::to_units(confirmed).saturating_sub(Transaction::to_units(pending_debit));
        Ok(Transaction::from_units(net_units))
    }

    pub async fn update_wallet_balance(
        &self,
        address: &str,
        amount: f64,
    ) -> Result<(), BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;

        // Get current balance
        let current_balance_units = match balances_tree.get(address.as_bytes())? {
            Some(balance_bytes) => Self::deserialize_units_compatible(&balance_bytes)?,
            None => 0,
        };

        let new_balance_units = current_balance_units + Transaction::to_units(amount);

        // Store new balance
        balances_tree.insert(
            address.as_bytes(),
            codec::serialize(&new_balance_units)
                .map_err(|_| BlockchainError::InvalidTransaction)?,
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

        // Consensus merkle root must be stable across:
        // - in-memory full-signature transactions (used for admission verification)
        // - on-disk truncated-signature blocks (used for storage efficiency)
        //
        // So we hash a normalized transaction encoding where non-system signatures are always truncated to 64 bytes
        // and a `sig_hash` is present (or derivable) for identity binding.
        let mut current_level: Vec<[u8; 32]> = transactions
            .iter()
            .map(|tx| {
                let tx_for_merkle = if tx.sender == "MINING_REWARDS" {
                    tx.clone()
                } else {
                    let mut full_tx = tx.clone();
                    if full_tx.sig_hash.is_none() {
                        if let Some(sig_hex) = &full_tx.signature {
                            if let Ok(sig_bytes) = hex::decode(sig_hex) {
                                if !sig_bytes.is_empty() {
                                    full_tx.sig_hash =
                                        Some(Transaction::signature_hash_hex(&sig_bytes));
                                }
                            }
                        }
                    }

                    match &full_tx.sig_hash {
                        Some(sig_hash) => full_tx.with_truncated_signature(sig_hash.clone()),
                        None => full_tx,
                    }
                };

                let tx_bytes = codec::serialize(&tx_for_merkle)
                    .map_err(|e| BlockchainError::SerializationError(Box::new(e)))?;
                let mut hasher = Sha256::new();
                hasher.update(&tx_bytes);
                Ok(hasher.finalize().into())
            })
            .collect::<Result<Vec<_>, BlockchainError>>()?;

        // Correct handling of single transaction: DUPLICATE the hash
        if current_level.len() == 1 {
            let single_hash = current_level[0];
            let mut hasher = Sha256::new();
            hasher.update(single_hash);
            hasher.update(single_hash); // Duplicate the hash!
            return Ok(hasher.finalize().into());
        }

        while current_level.len() > 1 {
            let next_level: Vec<[u8; 32]> = current_level
                .chunks(2)
                .map(|pair| {
                    let mut hasher = Sha256::new();
                    hasher.update(pair[0]);
                    if pair.len() == 2 {
                        hasher.update(pair[1]);
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
    verified_blocks: Arc<DashMap<[u8; 32], BlockVerification>>,
    integrity_score: AtomicU64,
    last_verification: AtomicU64,
}

#[derive(Debug)]
struct BlockVerification {
    verifiers: HashSet<String>, // Node IDs that verified
    integrity_confirmed: bool,
}

impl ChainSentinel {
    pub fn new() -> Self {
        Self {
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
        let mut prev_difficulty = blocks[0].difficulty;
        let mut difficulty_oracle = DifficultyOracle::new();

        for block in blocks.iter().skip(1) {
            // Hash chain verification
            if block.previous_hash != prev_hash {
                self.integrity_score.fetch_sub(10, Ordering::Relaxed);
                return false;
            }

            // Time verification
            if block.timestamp < prev_timestamp {
                self.integrity_score.fetch_sub(5, Ordering::Relaxed);
                return false;
            }
            let time_diff = block.timestamp.saturating_sub(prev_timestamp);

            // Difficulty verification
            let expected_difficulty = Block::adjust_dynamic_difficulty(
                prev_difficulty,
                time_diff,
                block.index,
                &mut difficulty_oracle,
                block.timestamp,
            );

            if block.difficulty != expected_difficulty {
                self.integrity_score.fetch_sub(5, Ordering::Relaxed);
                return false;
            }

            prev_hash = block.hash;
            prev_timestamp = block.timestamp;
            prev_difficulty = block.difficulty;
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

impl Default for ChainSentinel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn test_blockchain() -> Blockchain {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled db should open");
        Blockchain::new(
            db,
            0.0005,
            1.0,
            10,
            TARGET_BLOCK_TIME as u32,
            Arc::new(RateLimiter::new(60, 1_000)),
            Arc::new(Mutex::new(321)),
        )
    }

    #[test]
    fn confirmed_witness_retention_prunes_below_window_and_serves_recent() {
        let bc = test_blockchain();
        let cw_tree = bc.db.open_tree(CONFIRMED_WITNESSES_TREE).unwrap();
        let cw_index = bc.db.open_tree(CONFIRMED_WITNESS_INDEX_TREE).unwrap();

        // Insert two retained witnesses at very different confirmation heights,
        // mirroring the key layout used by process_transactions_batch.
        let insert_at = |height: u64, tx_id: &str| {
            let tx = metadata_test_block(1, [0u8; 32], "bob", 1.0)
                .transactions
                .remove(0);
            let bytes = codec::serialize(&tx).unwrap();
            cw_tree.insert(tx_id.as_bytes(), bytes).unwrap();
            let mut key = height.to_be_bytes().to_vec();
            key.extend_from_slice(tx_id.as_bytes());
            cw_index.insert(key, b"" as &[u8]).unwrap();
        };
        insert_at(10, "old_tx");
        insert_at(300, "recent_tx");

        // Tip 400 -> cutoff = 400 - 256 = 144. Height <= 144 is pruned; >= 145 kept.
        bc.prune_confirmed_witnesses(400).unwrap();

        assert!(
            bc.get_confirmed_witness_tx("old_tx").is_none(),
            "witness older than the retention window should be pruned"
        );
        assert!(
            bc.get_confirmed_witness_tx("recent_tx").is_some(),
            "witness inside the retention window should still be served"
        );

        // Below the window threshold, nothing is pruned.
        insert_at(5, "tiny_chain_tx");
        bc.prune_confirmed_witnesses(100).unwrap();
        assert!(bc.get_confirmed_witness_tx("tiny_chain_tx").is_some());
    }

    fn metadata_test_block(
        index: u32,
        previous_hash: [u8; 32],
        recipient: &str,
        amount: f64,
    ) -> Block {
        let tx = Transaction {
            sender: "MINING_REWARDS".to_string(),
            recipient: recipient.to_string(),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: Transaction::to_units(amount),
            timestamp: 1_000 + index as u64,
            signature: None,
            pub_key: None,
            sig_hash: None,
        };
        let transactions = vec![tx];
        let merkle_root =
            Blockchain::calculate_merkle_root(&transactions).expect("merkle root should build");
        let mut block = Block {
            index,
            previous_hash,
            timestamp: 1_000 + index as u64,
            transactions,
            nonce: 0,
            difficulty: 0,
            hash: [0u8; 32],
            merkle_root,
        };
        block.hash = block.calculate_hash_for_block();
        block
    }

    fn insert_raw_block(blockchain: &Blockchain, block: &Block) {
        let key = format!("block_{}", block.index);
        blockchain
            .db
            .insert(key.as_bytes(), codec::serialize(block).unwrap())
            .expect("raw block insert should succeed");
    }

    #[test]
    fn tip_signal_counter_and_watch_update_together() {
        let blockchain = test_blockchain();
        let block = metadata_test_block(1, [7u8; 32], "miner1", 1.0);
        let mut receiver = blockchain.subscribe_tip_changes();

        assert_eq!(blockchain.tip_change_version(), 0);

        blockchain.notify_tip_changed(&block);

        assert_eq!(blockchain.tip_change_version(), 1);
        assert!(receiver
            .has_changed()
            .expect("tip receiver should observe update"));
        let signal = *receiver.borrow_and_update();
        assert_eq!(signal.height, block.index);
        assert_eq!(signal.hash, block.hash);
        assert_eq!(signal.version, 1);
        assert_eq!(blockchain.current_tip_signal(), signal);
    }

    fn set_confirmed_balance(blockchain: &Blockchain, address: &str, amount_units: i128) {
        let balances_tree = blockchain
            .db
            .open_tree(BALANCES_TREE)
            .expect("balances tree should open");
        balances_tree
            .insert(address.as_bytes(), codec::serialize(&amount_units).unwrap())
            .expect("balance insert should succeed");
    }

    async fn signed_transfer(
        wallet: &Wallet,
        recipient: &str,
        amount: f64,
        timestamp: u64,
    ) -> Transaction {
        let fee = amount * FEE_PERCENTAGE;
        let message = format!(
            "{}:{}:{:.8}:{:.8}:{}",
            wallet.address, recipient, amount, fee, timestamp
        );
        let signature = wallet
            .sign_transaction(message.as_bytes())
            .await
            .expect("test wallet should sign");
        let mut tx = Transaction::new(
            wallet.address.clone(),
            recipient.to_string(),
            amount,
            fee,
            timestamp,
            Some(signature),
        );
        tx.pub_key = wallet.get_public_key_hex().await;
        tx
    }

    #[test]
    fn pow_target_zero_difficulty_is_max_target() {
        assert_eq!(pow_target_from_difficulty(0), *MAX_TARGET);
    }

    #[test]
    fn pow_target_halves_every_16_difficulty_points() {
        let t0 = pow_target_from_difficulty(0);
        let t16 = pow_target_from_difficulty(16);
        assert_eq!(t16, t0 >> 1usize);
    }

    #[test]
    fn pow_target_saturates_to_zero_for_large_difficulty() {
        // 4096 / 16 == 256 -> shifted past full 256-bit target width.
        assert_eq!(pow_target_from_difficulty(4096), BigUint::from(0u8));
    }

    #[test]
    fn difficulty_floor_applies_from_first_launch_block() {
        assert_eq!(
            Block::adjust_dynamic_difficulty(
                0,
                TARGET_BLOCK_TIME,
                1,
                &mut DifficultyOracle::new(),
                GENESIS_LAUNCH_TIMESTAMP + TARGET_BLOCK_TIME,
            ),
            NETWORK_MIN_DIFFICULTY
        );
    }

    #[test]
    fn consensus_difficulty_uses_only_parent_and_child_time() {
        assert_eq!(
            Block::consensus_next_difficulty(464, TARGET_BLOCK_TIME, 9),
            464
        );
        assert_eq!(Block::consensus_next_difficulty(464, 0, 9), 466);
        assert_eq!(Block::consensus_next_difficulty(480, 65, 9), 464);
        assert_eq!(
            Block::consensus_next_difficulty(MAX_NETWORK_DIFFICULTY, 0, 9),
            MAX_NETWORK_DIFFICULTY
        );
    }

    #[test]
    fn work_units_follow_pow_target_scaling() {
        assert_eq!(
            Blockchain::work_units_for_difficulty(16),
            Blockchain::work_units_for_difficulty(0) * 2u32
        );
        assert_eq!(
            Blockchain::work_units_for_difficulty(64),
            Blockchain::work_units_for_difficulty(32) * 4u32
        );
    }

    #[test]
    fn chain_work_uses_exponential_difficulty_units() {
        let blockchain = test_blockchain();
        let mut low_a = metadata_test_block(0, [0u8; 32], "low_a", 1.0);
        low_a.difficulty = 32;
        low_a.hash = low_a.calculate_hash_for_block();
        let mut low_b = metadata_test_block(1, low_a.hash, "low_b", 1.0);
        low_b.difficulty = 32;
        low_b.hash = low_b.calculate_hash_for_block();
        insert_raw_block(&blockchain, &low_a);
        insert_raw_block(&blockchain, &low_b);

        let mut high = metadata_test_block(1, low_a.hash, "high", 1.0);
        high.difficulty = 64;
        high.hash = high.calculate_hash_for_block();

        let low_work = blockchain.canonical_work_range(1, 1).unwrap();
        let high_work = Blockchain::branch_work_to_height(&[high], 1);

        assert!(high_work > low_work);
        assert_eq!(
            Blockchain::compare_work_delta(&high_work, &low_work, &low_work, &low_work),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn orphan_branch_search_keeps_deeper_non_greedy_branch() {
        let blockchain = test_blockchain();
        let block0 = metadata_test_block(0, [0u8; 32], "miner0", 1.0);
        let start = metadata_test_block(1, block0.hash, "start", 1.0);

        let mut high_child = metadata_test_block(2, start.hash, "high_child", 1.0);
        high_child.difficulty = 64;
        high_child.hash = high_child.calculate_hash_for_block();

        let mut lower_child = metadata_test_block(2, start.hash, "lower_child", 1.0);
        lower_child.difficulty = 32;
        lower_child.timestamp = lower_child.timestamp.saturating_add(1);
        lower_child.hash = lower_child.calculate_hash_for_block();

        let mut lower_grandchild =
            metadata_test_block(3, lower_child.hash, "lower_grandchild", 1.0);
        lower_grandchild.difficulty = 32;
        lower_grandchild.hash = lower_grandchild.calculate_hash_for_block();

        blockchain.store_orphan_block(&high_child).unwrap();
        blockchain.store_orphan_block(&lower_child).unwrap();
        blockchain.store_orphan_block(&lower_grandchild).unwrap();

        let branches = blockchain
            .collect_orphan_branches_from(start, 8, ORPHAN_BRANCH_SEARCH_LIMIT)
            .unwrap();

        assert!(branches.iter().any(|branch| branch.len() == 2));
        assert!(branches.iter().any(|branch| branch.len() == 3));
    }

    #[tokio::test]
    async fn chain_sentinel_allows_idle_launch_gap() {
        let blockchain = test_blockchain();
        let genesis = Blockchain::genesis_launch_block().expect("genesis should build");
        let mut block1 = metadata_test_block(1, genesis.hash, "miner1", 1.0);
        block1.timestamp = genesis.timestamp + TARGET_BLOCK_TIME * 1_000;
        block1.difficulty = NETWORK_MIN_DIFFICULTY;
        block1.hash = block1.calculate_hash_for_block();

        insert_raw_block(&blockchain, &genesis);
        insert_raw_block(&blockchain, &block1);

        assert!(
            ChainSentinel::new()
                .verify_chain_integrity(&blockchain)
                .await
        );
    }

    #[test]
    fn orphan_index_round_trip_extracts_hash() {
        let prev = [0x11u8; 32];
        let hash = [0x22u8; 32];
        let key = Blockchain::orphan_index_key(&prev, 42, &hash);
        let parsed = Blockchain::parse_orphan_index_hash(key.as_bytes())
            .expect("should parse orphan index key");
        assert_eq!(parsed, hex::encode(hash));
    }

    #[test]
    fn transaction_json_uses_legacy_field_names() {
        let tx = Transaction {
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            fee_units: Transaction::to_units(0.0005),
            amount_units: Transaction::to_units(1.23456789),
            timestamp: 1234,
            signature: Some("deadbeef".to_string()),
            pub_key: None,
            sig_hash: None,
        };

        let v: Value = serde_json::to_value(&tx).expect("tx should serialize");
        assert!(v.get("amount").is_some());
        assert!(v.get("fee").is_some());
        assert!(v.get("amount_units").is_none());
        assert!(v.get("fee_units").is_none());
    }

    #[test]
    fn launch_genesis_is_deterministic_and_carries_1776_artifact() {
        let block_a = Blockchain::genesis_launch_block().expect("genesis should build");
        let block_b =
            Blockchain::genesis_launch_block().expect("genesis should rebuild identically");

        assert_eq!(block_a.hash, block_b.hash);
        assert_eq!(block_a.merkle_root, block_b.merkle_root);
        assert_eq!(
            block_a.calculate_hash_for_block(),
            block_b.calculate_hash_for_block()
        );
        assert_eq!(block_a.index, 0);
        assert_eq!(block_a.previous_hash, [0u8; 32]);
        assert_eq!(block_a.timestamp, GENESIS_LAUNCH_TIMESTAMP);
        assert_eq!(block_a.nonce, GENESIS_LAUNCH_NONCE);
        assert_eq!(block_a.difficulty, GENESIS_LAUNCH_DIFFICULTY);
        assert_eq!(block_a.transactions.len(), 1);

        let tx = &block_a.transactions[0];
        assert_eq!(tx.sender, "MINING_REWARDS");
        assert_eq!(tx.recipient, GENESIS_LAUNCH_RECIPIENT);
        assert_eq!(
            tx.amount_units,
            Transaction::to_units(GENESIS_LAUNCH_AMOUNT)
        );
        assert_eq!(tx.fee_units, Transaction::to_units(NETWORK_FEE));
    }

    #[test]
    fn legacy_transaction_codec_envelope_is_deserialized() {
        let legacy = LegacyTransaction {
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            fee: 0.001,
            amount: 2.5,
            timestamp: 999,
            signature: Some("cafebabe".to_string()),
        };
        let bytes = codec::serialize(&legacy).expect("legacy tx should serialize");
        let tx = deserialize_transaction(&bytes).expect("legacy tx should deserialize");

        assert_eq!(tx.sender, legacy.sender);
        assert_eq!(tx.recipient, legacy.recipient);
        assert_eq!(tx.timestamp, legacy.timestamp);
        assert_eq!(tx.signature, legacy.signature);
        assert_eq!(tx.fee_units, Transaction::to_units(legacy.fee));
        assert_eq!(tx.amount_units, Transaction::to_units(legacy.amount));
    }

    #[test]
    fn receipt_validation_accepts_truncated_signature_commitment() {
        let (public_key_bytes, _) = mldsa::generate_keypair();
        let mut hasher = Sha256::new();
        hasher.update(&public_key_bytes);
        let sender = hex::encode(&hasher.finalize()[..20]);

        let tx = Transaction {
            sender,
            recipient: "bob".to_string(),
            fee_units: Transaction::to_units(0.0005),
            amount_units: Transaction::to_units(1.0),
            timestamp: 1234,
            signature: Some("aa".repeat(64)),
            pub_key: Some(hex::encode(&public_key_bytes)),
            sig_hash: Some("bb".repeat(32)),
        };

        assert!(Blockchain::verify_transaction_receipt_fields(&tx).is_ok());
    }

    #[test]
    fn receipt_validation_rejects_pubkey_sender_mismatch() {
        let (public_key_bytes, _) = mldsa::generate_keypair();

        let tx = Transaction {
            sender: "not-derived-from-key".to_string(),
            recipient: "bob".to_string(),
            fee_units: Transaction::to_units(0.0005),
            amount_units: Transaction::to_units(1.0),
            timestamp: 1234,
            signature: Some("aa".repeat(64)),
            pub_key: Some(hex::encode(&public_key_bytes)),
            sig_hash: Some("bb".repeat(32)),
        };

        assert!(Blockchain::verify_transaction_receipt_fields(&tx).is_err());
    }

    #[tokio::test]
    async fn transaction_admission_rejects_negative_fee() {
        let blockchain = test_blockchain();
        let tx = Transaction {
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            fee_units: -1,
            amount_units: MIN_TRANSACTION_AMOUNT_UNITS,
            timestamp: 1234,
            signature: None,
            pub_key: None,
            sig_hash: None,
        };

        let err = blockchain
            .add_transaction(tx)
            .await
            .expect_err("negative fee should be rejected before balance/signature checks");
        assert!(matches!(err, BlockchainError::InvalidTransactionAmount));
    }

    #[tokio::test]
    async fn duplicate_transaction_admission_is_idempotent() {
        let blockchain = test_blockchain();
        let wallet = Wallet::new(None).expect("test wallet should build");
        let tx = signed_transfer(&wallet, "bob", 1.0, 10_000).await;
        set_confirmed_balance(&blockchain, &wallet.address, Transaction::to_units(10.0));

        blockchain
            .add_transaction(tx.clone())
            .await
            .expect("first admission should succeed");
        blockchain
            .add_transaction(tx.clone())
            .await
            .expect("duplicate admission should be idempotent");

        let pending_debit = blockchain
            .get_pending_debit_units(&wallet.address)
            .await
            .expect("pending debit should load");
        assert_eq!(pending_debit, tx.total_debit_units());

        let mempool = blockchain
            .get_mempool_transactions()
            .await
            .expect("mempool should load");
        assert_eq!(mempool.len(), 1);
    }

    #[tokio::test]
    async fn concurrent_same_sender_admission_respects_pending_debits() {
        let blockchain = Arc::new(test_blockchain());
        let wallet = Wallet::new(None).expect("test wallet should build");
        let tx1 = signed_transfer(&wallet, "bob", 1.0, 10_001).await;
        let tx2 = signed_transfer(&wallet, "carol", 1.0, 10_002).await;
        set_confirmed_balance(&blockchain, &wallet.address, tx1.total_debit_units());

        let chain1 = Arc::clone(&blockchain);
        let chain2 = Arc::clone(&blockchain);
        let (res1, res2) = tokio::join!(
            async move { chain1.add_transaction(tx1).await },
            async move { chain2.add_transaction(tx2).await }
        );

        let results = [res1, res2];
        let accepted = results.iter().filter(|res| res.is_ok()).count();
        let insufficient = results
            .iter()
            .filter(|res| matches!(res, Err(BlockchainError::InsufficientFunds)))
            .count();
        assert_eq!(accepted, 1);
        assert_eq!(insufficient, 1);

        let mempool = blockchain
            .get_mempool_transactions()
            .await
            .expect("mempool should load");
        assert_eq!(mempool.len(), 1);
    }

    #[tokio::test]
    async fn new_block_validation_rejects_invalid_regular_amount() {
        let blockchain = test_blockchain();
        let tx = Transaction {
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            fee_units: 0,
            amount_units: -1,
            timestamp: 1234,
            signature: None,
            pub_key: None,
            sig_hash: None,
        };
        let transactions = vec![tx];
        let merkle_root = Blockchain::calculate_merkle_root(&transactions).unwrap();
        let mut block = Block {
            index: 1,
            previous_hash: [0u8; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            transactions,
            nonce: 0,
            difficulty: 0,
            hash: [0u8; 32],
            merkle_root,
        };
        block.hash = block.calculate_hash_for_block();

        let err = blockchain
            .validate_new_block(&block)
            .await
            .expect_err("invalid regular tx amount should be rejected before mining finalization");
        assert!(matches!(err, BlockchainError::InvalidTransactionAmount));
    }

    #[test]
    fn chain_tip_metadata_rebuilds_from_existing_blocks() {
        let blockchain = test_blockchain();
        let block0 = metadata_test_block(0, [0u8; 32], "miner0", 1.0);
        let block1 = metadata_test_block(1, block0.hash, "miner1", 2.0);
        insert_raw_block(&blockchain, &block0);
        insert_raw_block(&blockchain, &block1);

        assert_eq!(blockchain.read_chain_tip_metadata().unwrap(), None);
        assert_eq!(blockchain.get_latest_block_index(), 1);

        let tip = blockchain
            .read_chain_tip_metadata()
            .unwrap()
            .expect("tip metadata should be rebuilt");
        assert_eq!(tip.height, 1);
        assert_eq!(tip.hash, block1.hash);
        assert_eq!(blockchain.get_latest_block_hash(), block1.hash);
    }

    #[tokio::test]
    async fn dirty_state_recovery_rebuilds_tip_and_balances() {
        let blockchain = test_blockchain();
        let block0 = metadata_test_block(0, [0u8; 32], "miner0", 1.0);
        let block1 = metadata_test_block(1, block0.hash, "miner1", 2.0);
        insert_raw_block(&blockchain, &block0);
        insert_raw_block(&blockchain, &block1);

        blockchain
            .write_chain_tip_metadata(&block0)
            .expect("stale tip metadata should write");
        blockchain
            .mark_chain_state_dirty(1, "test_interrupted_commit")
            .expect("dirty marker should write");
        let balances_tree = blockchain
            .db
            .open_tree(BALANCES_TREE)
            .expect("balances tree should open");
        balances_tree
            .insert("miner1".as_bytes(), codec::serialize(&999i128).unwrap())
            .expect("stale balance should write");
        Blockchain::set_balances_height(&balances_tree, 0).unwrap();

        blockchain.initialize().await.unwrap();

        assert_eq!(blockchain.chain_state_dirty().unwrap(), None);
        assert_eq!(blockchain.get_latest_block_index(), 1);
        assert_eq!(blockchain.get_latest_block_hash(), block1.hash);
        assert_eq!(
            blockchain.get_confirmed_balance("miner0").await.unwrap(),
            1.0
        );
        assert_eq!(
            blockchain.get_confirmed_balance("miner1").await.unwrap(),
            2.0
        );
    }

    #[tokio::test]
    async fn validation_rejects_child_timestamp_before_parent() {
        let blockchain = test_blockchain();
        let block0 = metadata_test_block(0, [0u8; 32], "miner0", 10.0);
        insert_raw_block(&blockchain, &block0);

        let mut block1 = metadata_test_block(1, block0.hash, "miner1", 10.0);
        block1.timestamp = block0.timestamp.saturating_sub(1);
        block1.hash = block1.calculate_hash_for_block();

        let err = blockchain
            .validate_block(&block1)
            .await
            .expect_err("child block with backwards timestamp should be rejected");
        assert!(matches!(err, BlockchainError::InvalidBlockHeader));
    }

    #[tokio::test]
    async fn receipt_sync_parks_unattached_future_block_as_orphan() {
        let blockchain = test_blockchain();
        let block0 = metadata_test_block(0, [0u8; 32], "miner0", 1.0);
        let block1 = metadata_test_block(1, block0.hash, "miner1", 2.0);
        insert_raw_block(&blockchain, &block0);
        insert_raw_block(&blockchain, &block1);
        blockchain.rebuild_chain_tip_metadata().unwrap();

        let mut missing_parent_hash = [0x42u8; 32];
        missing_parent_hash[0] = 0x99;
        let future = metadata_test_block(2, missing_parent_hash, "miner2", 3.0);

        blockchain
            .save_receipt_verified_block(&future)
            .await
            .expect("unattached relayed blocks should be parked for later branch adoption");

        assert_eq!(blockchain.get_latest_block_index(), 1);
        assert!(blockchain
            .get_orphan_block_by_hash(&future.hash)
            .unwrap()
            .is_some());
    }

    #[test]
    fn orphan_pruning_retains_recent_same_height_competitors() {
        let blockchain = test_blockchain();
        let block0 = metadata_test_block(0, [0u8; 32], "miner0", 1.0);
        let block1 = metadata_test_block(1, block0.hash, "miner1", 2.0);
        let competing = metadata_test_block(1, block0.hash, "miner2", 3.0);
        insert_raw_block(&blockchain, &block0);
        insert_raw_block(&blockchain, &block1);
        blockchain.rebuild_chain_tip_metadata().unwrap();

        blockchain.store_orphan_block(&competing).unwrap();

        assert!(blockchain
            .get_orphan_block_by_hash(&competing.hash)
            .unwrap()
            .is_some());
    }
}
