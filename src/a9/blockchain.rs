use blake3;
use dashmap::DashMap;
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
/// Replay registry: maps a confirmed non-system transaction's id to the canonical
/// block height that confirmed it. A block that re-includes an already-confirmed
/// transaction (replay) is rejected, so a signed payment cannot be re-mined to
/// drain a wallet. Maintained incrementally on tip extension and reorg.
const CONFIRMED_TX_TREE: &str = "confirmed_tx";
/// Prune index for the replay registry: `confirming_block_timestamp_be || tx_id`,
/// so entries can be range-deleted once their transactions are too old to ever be
/// replayed (see MAX_TX_AGE_SECS). Keeps the registry BOUNDED to a recent window
/// instead of the whole chain.
const CONFIRMED_TX_TS_INDEX: &str = "confirmed_tx_ts_index";
/// Address history index: `address || 0x00 || height_be || tx_position_be` ->
/// compact entry (role flags, amount, fee, timestamp, counterparty). One entry per
/// (transaction, involved address); MINING_REWARDS receipts ARE indexed (unlike the
/// replay registry) — the whole point is answering "what happened to this account",
/// and mining income is most of it. Full-history (never pruned), display/query only:
/// consensus never reads it, and every write is fail-open so an index error can
/// never fail a block commit. Maintained on tip extension and reorg alongside the
/// replay registry; (re)built via ensure_address_tx_index / rebuild_address_tx_index.
const ADDRESS_TX_TREE: &str = "address_tx_index";
/// Transaction-freshness window (Solana-style expiry). A non-system transaction
/// must be mined within this many seconds of its signed timestamp; a block that
/// includes an older one is rejected. This expires stale transactions so the
/// replay registry only ever has to retain this recent window — it never grows
/// with total chain history — while still making replay impossible (an old,
/// already-confirmed transaction can no longer be re-mined either).
pub const MAX_TX_AGE_SECS: u64 = 21_600; // 6 hours
/// How many blocks past confirmation a transaction's full witness is retained so
/// it remains verifiable during near-tip sync. No consensus impact.
pub const WITNESS_RETENTION_BLOCKS: u64 = 256;
/// How far behind the fully-verified frontier the trusted checkpoint trails.
/// Blocks at/below the checkpoint are final: signature-trusted (not re-verified)
/// and not reorgable. The margin preserves normal PoW reorg depth above the
/// finalized point, so only a partition deeper than this could split finality —
/// a scenario in which consensus is already broken.
pub const CHECKPOINT_REORG_MARGIN: u32 = 64;
/// Height of the last block whose full ML-DSA witnesses were permanently lost in
/// a historical DB adoption (blocks 34-35). The frontier signature gate must
/// never require verification at or below this height — those blocks can only be
/// served truncated — so a node lagging beneath it can still receipt-trust its
/// way through and catch up instead of stalling forever. This is a fixed network
/// checkpoint floor; cumulative PoW and the signed bootstrap snapshot secure the
/// history under it, exactly as they secure any block at/below the checkpoint.
pub const WITNESS_LOSS_FLOOR: u32 = 35;
/// Coinbase (MINING_REWARDS) maturity, in blocks (M06). A mined reward credited in
/// block R is spendable only once buried >= MINING_REWARD_MATURITY deep, i.e. at
/// spend height h with h - R >= MINING_REWARD_MATURITY. This is strictly greater
/// than the finality margin (CHECKPOINT_REORG_MARGIN = 64), so a reward can never be
/// spent while the block that minted it is still reorgable — closing the reorg-based
/// reward double-spend. Enforced only as a read-time overlay at the affordability
/// comparison; the stored ledger always holds RAW confirmed totals.
pub const MINING_REWARD_MATURITY: u32 = 100;
/// Activation height for MINING_REWARD_MATURITY (M06). The maturity overlay is a
/// no-op below this height, so all existing history (tip was ~777 at ship time)
/// replays byte-identically and no historical block or in-flight tx is invalidated.
/// The rule is a strict tightening (soft fork): old-binary nodes accept every block a
/// new-binary node produces and converge normally; only an old miner that itself
/// spends an immature reward gets that block orphaned and self-heals via convergence.
pub const MATURITY_ACTIVATION_HEIGHT: u32 = 1500;
/// Frontier window (blocks) for the periodic in-persist integrity check. 256
/// blocks ≈ 21 minutes of history at the 5s target — far deeper than any live
/// reorg surface (reorgs at/below the trusted checkpoint are rejected outright)
/// while keeping the walk's lock-held cost fixed and sub-second regardless of
/// chain length. The full from-genesis walk is NOT bounded by this; it simply
/// never runs on the hot block-apply path (see verify_chain_integrity).
pub const INTEGRITY_FRONTIER_WINDOW: u32 = 256;
const ORPHAN_BLOCKS_TREE: &str = "orphan_blocks";
const ORPHAN_INDEX_TREE: &str = "orphan_index";
const CHAIN_META_TREE: &str = "chain_meta";
const BALANCES_HEIGHT_KEY: &[u8] = b"__height";
const CHAIN_TIP_KEY: &[u8] = b"tip";
const CHAIN_STATE_DIRTY_KEY: &[u8] = b"state_dirty";
/// Highest block height treated as final. At/below it blocks are
/// signature-trusted and cannot be reorged; above it every adopted block must
/// pass full ML-DSA verification. Monotonic. See CHECKPOINT_REORG_MARGIN.
const TRUSTED_CHECKPOINT_KEY: &[u8] = b"trusted_checkpoint";
/// (height, hash) of the last canonical block whose transactions are reflected in
/// ADDRESS_TX_TREE. Missing = index never built; hash mismatch at that height =
/// chain was rewritten while the index was offline (e.g. by an older binary) so it
/// must be rebuilt; height behind tip = catch up incrementally. Advanced on every
/// indexed block, so it is safe for it to lag (re-indexing a block is idempotent).
const ADDRESS_TX_META_KEY: &[u8] = b"address_tx_indexed_tip";
const MONEY_SCALE_I128: i128 = 100_000_000;
const MONEY_SCALE_F64: f64 = MONEY_SCALE_I128 as f64;
const MIN_TRANSACTION_AMOUNT_UNITS: i128 = 564;
const ORPHAN_MAX_COUNT: usize = 10_000;
const ORPHAN_TTL_SECS: u64 = 6 * 60 * 60;
pub const ORPHAN_REORG_DEPTH: u32 = 1024;
const ORPHAN_BRANCH_SEARCH_LIMIT: usize = 4_096;
/// Ceiling on how many competing branches a single reorg attempt will score.
/// Bounds worst-case CPU when an attacker floods the orphan store with many
/// same-fork competitors; candidates are scored best-first so the heaviest real
/// branch is reached well within this budget. Never bites normal operation,
/// where a reorg sees only a handful of branches.
const MAX_REORG_BRANCHES_EVALUATED: usize = 8_192;
/// (G) How long a witness-deferred reorg branch is skipped by try_adopt before it
/// is re-evaluated. Long enough to collapse the per-ingest-tick re-verify/re-log
/// storm (ingest fires every few seconds in a fork storm), short enough that once
/// R rehydrates — which clears the memo immediately — nothing waits on it, and a
/// branch R could not rehydrate is retried on a calm cadence.
const WITNESS_BLOCKED_BACKOFF_SECS: u64 = 45;
/// (G) TTL after which a memo entry is pruned even if never cleared — covers a
/// branch that became canonical by another path or aged out of the orphan pool,
/// so the memo cannot leak unbounded.
const WITNESS_BLOCKED_TTL_SECS: u64 = ORPHAN_TTL_SECS;
const GENESIS_LAUNCH_TIMESTAMP: u64 = 1_783_191_900;
const GENESIS_LAUNCH_AMOUNT: f64 = 17.76;
const GENESIS_LAUNCH_RECIPIENT: &str = "ALPHANUMERIC_1776_ARTIFACT";
const GENESIS_LAUNCH_DIFFICULTY: u64 = 0;
const GENESIS_LAUNCH_NONCE: u64 = 7_377;

pub const FEE_PERCENTAGE: f64 = 0.000563063063; // 0.0563063063%
pub const MIN_BLOCK_REWARD: f64 = 1.0;
pub const MAX_BLOCK_REWARD: f64 = 50.0;
/// Consensus cap on transactions per block. Without it a single block could carry
/// an unbounded number of transactions and stall the serial block-processing loop
/// (a cheap DoS). Generous for throughput (~800 tx/s at the 5s target) and raisable
/// with the network; per-transaction size is bounded by the fixed ML-DSA fields, so
/// this also bounds a block's byte size. The mining-reward transaction counts toward it.
pub const MAX_BLOCK_TX_COUNT: usize = 4096;
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

/// A PoW target as fixed-width big-endian bytes. Targets are always < 2^256, so
/// the 32-byte left-padded form is exact — and for fixed-width big-endian
/// values, lexicographic byte comparison IS numeric comparison. The mining hot
/// loop compares `[u8; 32]` hashes against this directly instead of allocating
/// a BigUint per nonce; equivalence is locked by
/// pow_byte_compare_matches_biguint_compare.
pub(crate) fn pow_target_bytes(target: &BigUint) -> [u8; 32] {
    let raw = target.to_bytes_be();
    let mut bytes = [0u8; 32];
    let len = raw.len().min(32);
    bytes[32 - len..].copy_from_slice(&raw[raw.len() - len..]);
    bytes
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
        // saturating (defense-in-depth): callers already gate on checked_add via
        // has_valid_regular_amounts, but never silently wrap if that guard is bypassed.
        self.amount_units.saturating_add(self.fee_units)
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

    /// Proof-of-work AND the network minimum-difficulty floor. This is the check
    /// ingress paths must use before accepting a network-supplied block: without
    /// the floor a block could declare difficulty 0 and make its PoW a no-op.
    /// Genesis (index 0) is pinned by hash, not PoW, so it is exempt. The exact
    /// parent-linked difficulty is still enforced in validate_block_internal.
    pub fn verify_pow_meets_floor(&self) -> bool {
        if self.index > 0 && self.difficulty < NETWORK_MIN_DIFFICULTY {
            return false;
        }
        self.verify_pow()
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
    calls_since_sweep: std::sync::atomic::AtomicU64,
}

impl RateLimiter {
    pub fn new(window_secs: u64, max_requests: usize) -> Self {
        Self {
            windows: DashMap::new(),
            window_size: chrono::Duration::seconds(window_secs as i64),
            max_requests,
            calls_since_sweep: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn check_limit(&self, address: &str) -> bool {
        let now = tokio::time::Instant::now();
        let window_secs = self.window_size.num_seconds() as u64;
        let cutoff = now - std::time::Duration::from_secs(window_secs);

        // Evict idle keys periodically so `windows` can't grow without bound: a key whose newest
        // timestamp has aged past the window is never revisited otherwise. Swept BEFORE taking the
        // per-key entry guard below — never run a map-wide retain while holding a guard on the
        // same DashMap (that self-deadlocks the shard).
        if self
            .calls_since_sweep
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            >= 1024
        {
            self.calls_since_sweep
                .store(0, std::sync::atomic::Ordering::Relaxed);
            self.windows
                .retain(|_, v| v.last().is_some_and(|&t| t >= cutoff));
        }

        let mut times = self.windows.entry(address.to_string()).or_default();

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
    /// Single-flight gate for balances-index maintenance (rebuild / catch-up).
    /// Concurrent get_confirmed_balance callers finding a stale index WAIT here
    /// and re-check instead of each launching their own O(chain) replay — the
    /// stampede that wedged nodes once 5s blocks outpaced the rebuild. Lock
    /// order where both are held is state_mutation_lock -> balances_index_gate
    /// (writers hold the state lock and read balances inside it); the gate is
    /// never held while acquiring the state lock.
    balances_index_gate: Arc<Mutex<()>>,
    tip_change_counter: Arc<AtomicU64>,
    tip_watch_tx: watch::Sender<ChainTipSignal>,
    /// (G) In-memory memo of reorg branches deferred by the S-01 frontier
    /// signature gate: a branch that is genuinely heavier but whose above-floor
    /// blocks arrived witness-truncated (the common case in a fork storm once the
    /// checkpoint has fallen behind). Keyed by branch-tip hash. Two jobs:
    /// (1) BACKOFF — try_adopt skips re-verifying + re-logging the same dead
    /// branch every ingest tick (the 187k-reject CPU/log storm, 2026-07-11);
    /// (2) WORK QUEUE for R — `needed` is the exact (height, hash) list the
    /// Node layer must rehydrate from the relay so the gate can pass honestly.
    /// In-memory by design: it is live-operation state, rebuilt from the orphan
    /// pool after a restart; no persistence, no new tree, no consensus surface.
    witness_blocked: Arc<PLMutex<HashMap<[u8; 32], WitnessBlockedBranch>>>,
}

/// Memo entry for a reorg branch the S-01 gate deferred (see `witness_blocked`).
#[derive(Clone, Debug)]
pub struct WitnessBlockedBranch {
    /// Unix secs; the branch is not re-evaluated by try_adopt before this.
    pub retry_after: u64,
    /// Consecutive times this branch has been deferred (drives R's give-up → B).
    pub attempts: u32,
    /// Above-floor blocks in the branch that lack full witnesses — exactly what
    /// R fetches from the relay by (height, hash).
    pub needed: Vec<(u32, [u8; 32])>,
    /// Wall-clock of the last time we recorded this branch, for TTL pruning of a
    /// memo entry whose branch has since become canonical or aged out.
    pub recorded_at: u64,
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

/// Display breakdown of get_wallet_balance: the same numbers it nets together, returned
/// separately so UIs can show Total / Spendable / Maturing instead of a bare spendable
/// figure that silently hides fresh coinbases for MINING_REWARD_MATURITY blocks (which
/// users read as "mined a block but got no reward"). Display-only — spendability is
/// still enforced by the consensus gates; `spendable` here is exactly what
/// get_wallet_balance returns (it delegates to this).
#[derive(Clone, Debug)]
pub struct WalletBalanceBreakdown {
    /// RAW confirmed ledger total, including still-immature coinbases.
    pub confirmed: f64,
    /// In-flight mempool debits against this address.
    pub pending_debit: f64,
    /// confirmed − pending_debit − immature: what the address can spend right now.
    pub spendable: f64,
    /// Still-immature MINING_REWARDS credits as (reward_height, amount), ascending by
    /// height. A reward at height rh leaves this set once the tip reaches
    /// rh + MINING_REWARD_MATURITY − 1.
    pub maturing: Vec<(u32, f64)>,
    /// The tip height this breakdown was computed against (for countdown math).
    pub as_of_height: u64,
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

    /// Highest block height the node treats as final. Blocks at/below it are
    /// signature-trusted (vouched for by a verified signed snapshot, or fully
    /// verified locally then aged past the reorg margin) and cannot be reorged;
    /// blocks above it — the unfinalized frontier — MUST pass full ML-DSA
    /// verification to be adopted from a peer or the relay. 0 if never seeded.
    pub fn trusted_checkpoint_height(&self) -> u32 {
        self.open_chain_meta_tree()
            .ok()
            .and_then(|tree| tree.get(TRUSTED_CHECKPOINT_KEY).ok().flatten())
            .and_then(|raw| codec::deserialize::<u32>(&raw).ok())
            .unwrap_or(0)
    }

    /// The height at/below which blocks are receipt-trusted and above which they
    /// must pass full ML-DSA verification: the greater of the local trusted
    /// checkpoint and the network witness-loss floor. Anchoring to the floor lets
    /// a node whose checkpoint sits below the permanently-truncated 34-35 still
    /// sync through them instead of stalling.
    pub fn verification_floor(&self) -> u32 {
        self.trusted_checkpoint_height().max(WITNESS_LOSS_FLOOR)
    }

    /// Raise the trusted checkpoint to `height`. Monotonic — a lower value is
    /// ignored, so finality can never regress. The compare-and-raise runs inside
    /// sled's update_and_fetch so two concurrent sync tasks (relay + p2p) cannot
    /// race a stale read and clobber a higher committed value.
    pub fn raise_trusted_checkpoint(&self, height: u32) -> Result<(), BlockchainError> {
        let meta_tree = self.open_chain_meta_tree()?;
        let encoded = codec::serialize(&height)?;
        meta_tree.update_and_fetch(TRUSTED_CHECKPOINT_KEY, |old| {
            let current = old
                .and_then(|raw| codec::deserialize::<u32>(raw).ok())
                .unwrap_or(0);
            if height > current {
                Some(encoded.clone())
            } else {
                old.map(|o| o.to_vec())
            }
        })?;
        meta_tree.flush()?;
        Ok(())
    }

    /// One-time seed: if no checkpoint has ever been recorded, trust the chain we
    /// already hold as of this upgrade (its tip). Blocks already in the DB were
    /// accepted under the prior rules and are never re-verified; only blocks that
    /// arrive ABOVE this height must prove themselves. Idempotent.
    pub fn seed_trusted_checkpoint_if_unset(&self) -> Result<(), BlockchainError> {
        let meta_tree = self.open_chain_meta_tree()?;
        if meta_tree.get(TRUSTED_CHECKPOINT_KEY)?.is_some() {
            return Ok(());
        }
        let tip = self.get_latest_block_index() as u32;
        meta_tree.insert(TRUSTED_CHECKPOINT_KEY, codec::serialize(&tip)?)?;
        meta_tree.flush()?;
        Ok(())
    }

    /// After a frontier block at `verified_height` is fully verified and applied,
    /// trail the checkpoint behind it by the reorg margin. Keeps the verified
    /// region (and thus the witness-retention requirement) bounded while leaving
    /// normal PoW reorgs possible above the finalized point.
    pub fn advance_checkpoint_behind(&self, verified_height: u32) -> Result<(), BlockchainError> {
        self.raise_trusted_checkpoint(verified_height.saturating_sub(CHECKPOINT_REORG_MARGIN))
    }

    fn open_confirmed_tx_tree(&self) -> Result<sled::Tree, BlockchainError> {
        self.db.open_tree(CONFIRMED_TX_TREE).map_err(Into::into)
    }

    /// The canonical height at which `tx_id` was confirmed, or None if unseen.
    /// True if this transaction is already confirmed in a canonical block. Public
    /// wrapper over the replay registry for mempool-hygiene callers (template
    /// building, tx re-announce) — consensus paths keep using the index directly.
    pub fn is_tx_confirmed(&self, tx_id: &str) -> bool {
        self.confirmed_tx_index(tx_id).is_some()
    }

    /// The canonical height at which `tx_id` was confirmed, or None if not yet
    /// confirmed. Read-only public wrapper over the replay registry, for explorer /
    /// mempool-hygiene callers that want to report *where* a tx already landed
    /// (e.g. the submit-tx duplicate response). Consensus paths use the index directly.
    pub fn confirmed_tx_height(&self, tx_id: &str) -> Option<u32> {
        self.confirmed_tx_index(tx_id)
    }

    /// Remove every mempool transaction that is already confirmed on the canonical
    /// chain. Confirmed txs can re-enter the mempool through gossip echoes or reorg
    /// reconciliation; any block template built while one is present fails
    /// finalization via the replay guard AFTER the full nonce grind — a wasted solve
    /// per attempt (the 2026-07-09 mining-failure loop). Returns how many were
    /// dropped. Cheap: one registry read per pending tx, and mempools are tiny.
    pub async fn drop_confirmed_mempool_txs(&self) -> usize {
        let pending = {
            let mempool = self.mempool.read().await;
            mempool.get_all_transactions()
        };
        let stale: Vec<Transaction> = pending
            .into_iter()
            .filter(|tx| self.confirmed_tx_index(&tx.get_tx_id()).is_some())
            .collect();
        // ALSO sweep the persisted pending tree: `info`, the re-announce, and
        // sync_mempool_with_sled (which REBUILDS the in-memory mempool from sled)
        // all read the tree, so clearing memory alone lets the very next sync
        // re-poison it — the "mempool still shows 1 pending after a clean mine"
        // symptom. The tree can also hold confirmed txs the in-memory set never
        // saw (written by an older binary), so sweep it independently.
        let mut tree_stale: Vec<Transaction> = Vec::new();
        if let Ok(pending_tree) = self.db.open_tree(PENDING_TRANSACTIONS_TREE) {
            for entry in pending_tree.iter().flatten() {
                if let Ok(tx) = deserialize_transaction(&entry.1) {
                    if self.confirmed_tx_index(&tx.get_tx_id()).is_some() {
                        tree_stale.push(tx);
                    }
                }
            }
        }
        if stale.is_empty() && tree_stale.is_empty() {
            return 0;
        }
        {
            let mut mempool = self.mempool.write().await;
            for tx in stale.iter().chain(tree_stale.iter()) {
                mempool.clear_transaction(tx);
            }
        }
        // clear_processed_transactions removes tree rows (pending + signature
        // sidecar + pending-debit index) by tx_id — the same path block
        // confirmation uses, so hygiene cannot diverge from it.
        let all: Vec<Transaction> = stale.into_iter().chain(tree_stale).collect();
        let _ = self.clear_processed_transactions(&all).await;
        all.len()
    }

    fn confirmed_tx_index(&self, tx_id: &str) -> Option<u32> {
        let raw = self
            .open_confirmed_tx_tree()
            .ok()?
            .get(tx_id.as_bytes())
            .ok()??;
        if raw.len() < 4 {
            return None;
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&raw[..4]);
        Some(u32::from_le_bytes(b))
    }

    /// Register a confirmed block's non-system transactions in the replay registry,
    /// plus a timestamp-prefixed prune-index entry so old ones can be range-deleted.
    fn record_confirmed_txs(&self, block: &Block) -> Result<(), BlockchainError> {
        let tree = self.open_confirmed_tx_tree()?;
        let index = self.db.open_tree(CONFIRMED_TX_TS_INDEX)?;
        let idx = block.index.to_le_bytes().to_vec();
        let ts_prefix = block.timestamp.to_be_bytes();
        let mut batch = sled::Batch::default();
        let mut index_batch = sled::Batch::default();
        for tx in &block.transactions {
            if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                continue;
            }
            let tx_id = tx.get_tx_id();
            batch.insert(tx_id.as_bytes(), idx.clone());
            let mut index_key = ts_prefix.to_vec();
            index_key.extend_from_slice(tx_id.as_bytes());
            index_batch.insert(index_key, Vec::<u8>::new());
        }
        tree.apply_batch(batch)?;
        index.apply_batch(index_batch)?;
        tree.flush()?;
        index.flush()?;
        // Address history index rides the same commit sites (tip extension, local
        // mining finalize, reorg branch adoption) but AFTER the registry writes and
        // fail-open, so an address-index error can neither corrupt the replay
        // registry nor fail the block commit. Self-heals via ensure/rebuild.
        if let Err(e) = self.record_address_tx_entries(block) {
            warn!(
                "Address history index update failed at block {} (display-only, will self-heal): {}",
                block.index, e
            );
        }
        Ok(())
    }

    /// Remove a block's non-system transactions from the replay registry (used when
    /// a block is reverted during a reorg).
    fn remove_confirmed_txs(&self, block: &Block) -> Result<(), BlockchainError> {
        let tree = self.open_confirmed_tx_tree()?;
        let index = self.db.open_tree(CONFIRMED_TX_TS_INDEX)?;
        let ts_prefix = block.timestamp.to_be_bytes();
        let mut batch = sled::Batch::default();
        let mut index_batch = sled::Batch::default();
        for tx in &block.transactions {
            if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                continue;
            }
            let tx_id = tx.get_tx_id();
            batch.remove(tx_id.as_bytes());
            let mut index_key = ts_prefix.to_vec();
            index_key.extend_from_slice(tx_id.as_bytes());
            index_batch.remove(index_key);
        }
        tree.apply_batch(batch)?;
        index.apply_batch(index_batch)?;
        tree.flush()?;
        index.flush()?;
        // Mirror the reverted block out of the address history index (fail-open;
        // see record_confirmed_txs).
        if let Err(e) = self.remove_address_tx_entries(block) {
            warn!(
                "Address history index revert failed at block {} (display-only, will self-heal): {}",
                block.index, e
            );
        }
        Ok(())
    }

    /// Drop replay-registry entries whose transactions are older than MAX_TX_AGE and
    /// therefore can never be replayed again (a block re-including them is rejected by
    /// the freshness rule). Keeps the registry bounded to a recent window regardless
    /// of total chain length.
    ///
    /// The entry is keyed on the CONFIRMING BLOCK's timestamp, but the freshness rule
    /// permits a transaction to be post-dated up to MAX_BLOCK_FUTURE_TIME ahead of that
    /// block, so its real replay window closes at tx.timestamp + MAX_TX_AGE_SECS — up
    /// to MAX_BLOCK_FUTURE_TIME LATER than the block-timestamp horizon. We therefore
    /// retain an extra MAX_BLOCK_FUTURE_TIME of history so an entry is never pruned
    /// while a block could still legitimately replay it (which would silently reopen
    /// the double-spend the registry exists to close).
    fn prune_confirmed_txs(&self, tip_timestamp: u64) -> Result<(), BlockchainError> {
        let horizon = MAX_TX_AGE_SECS.saturating_add(MAX_BLOCK_FUTURE_TIME);
        if tip_timestamp <= horizon {
            return Ok(());
        }
        let cutoff = tip_timestamp - horizon;
        let tree = self.open_confirmed_tx_tree()?;
        let index = self.db.open_tree(CONFIRMED_TX_TS_INDEX)?;
        let upper = cutoff.to_be_bytes().to_vec();
        let mut stale: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for item in index.range(..upper) {
            let (key, _) = item?;
            let tx_id = if key.len() > 8 {
                key[8..].to_vec()
            } else {
                Vec::new()
            };
            stale.push((key.to_vec(), tx_id));
        }
        for (idx_key, tx_id) in stale {
            let _ = index.remove(&idx_key);
            if !tx_id.is_empty() {
                let _ = tree.remove(&tx_id);
            }
        }
        Ok(())
    }

    /// True if the block replays a non-system transaction already confirmed at a
    /// DIFFERENT height. A brand-new block's own transactions are not yet registered,
    /// so this is false for legitimate blocks and true only on an actual replay
    /// (re-mining a confirmed payment to drain a wallet).
    fn block_has_replayed_tx(&self, block: &Block) -> bool {
        for tx in &block.transactions {
            if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                continue;
            }
            if let Some(idx) = self.confirmed_tx_index(&tx.get_tx_id()) {
                if idx != block.index {
                    return true;
                }
            }
        }
        false
    }

    /// Build the replay registry from the canonical chain if it has not been built
    /// yet (first run under this feature, or right after a bootstrap import). Existing
    /// history is grandfathered — only newly-adopted blocks are replay-checked.
    pub fn ensure_confirmed_tx_index(&self) -> Result<(), BlockchainError> {
        // Keyed on the prune index: if it's present the registry is already built in
        // the current (prunable) format; if it's absent we (re)build both trees,
        // which also migrates a registry built before the prune index existed.
        let index = self.db.open_tree(CONFIRMED_TX_TS_INDEX)?;
        if index.iter().next().is_some() {
            return Ok(());
        }
        self.rebuild_confirmed_tx_index()
    }

    /// Force-rebuild the replay registry from the canonical chain, unconditionally.
    /// Used by interrupted-commit (dirty-marker) recovery: a crash mid-reorg can commit
    /// the canonical slot rewrite (which IS atomic) yet leave the registry's separate
    /// remove/record loops half-applied. Because ensure_confirmed_tx_index keys on the
    /// index merely being non-empty, it would not detect that inconsistency, so recovery
    /// must rederive the registry from the (now-consistent) canonical blocks. O(chain),
    /// but only on the rare recovery path.
    pub fn rebuild_confirmed_tx_index(&self) -> Result<(), BlockchainError> {
        let index = self.db.open_tree(CONFIRMED_TX_TS_INDEX)?;
        let tree = self.open_confirmed_tx_tree()?;
        tree.clear()?;
        index.clear()?;
        let Some(tip) = self.highest_block_index() else {
            return Ok(());
        };
        let mut batch = sled::Batch::default();
        let mut index_batch = sled::Batch::default();
        for h in 0..=tip {
            if let Ok(block) = self.get_block(h) {
                let idx = block.index.to_le_bytes().to_vec();
                let ts_prefix = block.timestamp.to_be_bytes();
                for tx in &block.transactions {
                    if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                        continue;
                    }
                    let tx_id = tx.get_tx_id();
                    batch.insert(tx_id.as_bytes(), idx.clone());
                    let mut index_key = ts_prefix.to_vec();
                    index_key.extend_from_slice(tx_id.as_bytes());
                    index_batch.insert(index_key, Vec::<u8>::new());
                }
            }
        }
        tree.apply_batch(batch)?;
        index.apply_batch(index_batch)?;
        tree.flush()?;
        index.flush()?;
        // Drop anything already beyond the freshness window on this first build.
        if let Some(tip_block) = self.get_last_block() {
            let _ = self.prune_confirmed_txs(tip_block.timestamp);
        }
        Ok(())
    }

    fn open_address_tx_tree(&self) -> Result<sled::Tree, BlockchainError> {
        self.db.open_tree(ADDRESS_TX_TREE).map_err(Into::into)
    }

    /// `address || 0x00 || height_be || position_be`. Addresses are ASCII (hex or
    /// the MINING_REWARDS literal) so the 0x00 terminator cannot collide and makes
    /// the per-address prefix exact ("abc" never matches "abcd"). Big-endian
    /// height/position keep a prefix scan ordered by confirmation order.
    fn address_tx_key(address: &str, height: u32, position: u32) -> Vec<u8> {
        let mut key = Vec::with_capacity(address.len() + 9);
        key.extend_from_slice(address.as_bytes());
        key.push(0);
        key.extend_from_slice(&height.to_be_bytes());
        key.extend_from_slice(&position.to_be_bytes());
        key
    }

    fn address_tx_prefix(address: &str) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(address.len() + 1);
        prefix.extend_from_slice(address.as_bytes());
        prefix.push(0);
        prefix
    }

    /// Fixed layout, hand-rolled so the entry format never depends on codec
    /// evolution: flags(1) || amount_units_le(16) || fee_units_le(16) ||
    /// timestamp_le(8) || counterparty_utf8(rest). Changing this layout requires a
    /// new tree name — decode tolerates (skips) undersized values, not reshaped ones.
    fn encode_address_tx_value(
        flags: u8,
        amount_units: i128,
        fee_units: i128,
        timestamp: u64,
        counterparty: &str,
    ) -> Vec<u8> {
        let mut value = Vec::with_capacity(41 + counterparty.len());
        value.push(flags);
        value.extend_from_slice(&amount_units.to_le_bytes());
        value.extend_from_slice(&fee_units.to_le_bytes());
        value.extend_from_slice(&timestamp.to_le_bytes());
        value.extend_from_slice(counterparty.as_bytes());
        value
    }

    fn decode_address_tx_entry(prefix_len: usize, key: &[u8], value: &[u8]) -> Option<AddressTxEntry> {
        if key.len() != prefix_len + 8 || value.len() < 41 {
            return None;
        }
        let mut height = [0u8; 4];
        let mut position = [0u8; 4];
        height.copy_from_slice(&key[prefix_len..prefix_len + 4]);
        position.copy_from_slice(&key[prefix_len + 4..]);
        let mut amount = [0u8; 16];
        let mut fee = [0u8; 16];
        let mut ts = [0u8; 8];
        amount.copy_from_slice(&value[1..17]);
        fee.copy_from_slice(&value[17..33]);
        ts.copy_from_slice(&value[33..41]);
        Some(AddressTxEntry {
            height: u32::from_be_bytes(height),
            position: u32::from_be_bytes(position),
            flags: value[0],
            amount_units: i128::from_le_bytes(amount),
            fee_units: i128::from_le_bytes(fee),
            timestamp: u64::from_le_bytes(ts),
            counterparty: String::from_utf8_lossy(&value[41..]).into_owned(),
        })
    }

    /// The (key, value) pairs a block contributes to the address index. Derived
    /// only from fields that survive to_storage_block truncation, so entries built
    /// live at commit time and entries rebuilt from stored blocks are identical —
    /// which is what makes re-indexing idempotent.
    fn address_index_ops(block: &Block) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut ops = Vec::new();
        for (position, tx) in block.transactions.iter().enumerate() {
            let position = position as u32;
            let sender_indexed = !SYSTEM_ADDRESSES.contains(&tx.sender.as_str());
            let recipient_indexed = !SYSTEM_ADDRESSES.contains(&tx.recipient.as_str());
            if sender_indexed && recipient_indexed && tx.sender == tx.recipient {
                ops.push((
                    Self::address_tx_key(&tx.sender, block.index, position),
                    Self::encode_address_tx_value(
                        ADDRESS_TX_FLAG_SENDER | ADDRESS_TX_FLAG_RECIPIENT,
                        tx.amount_units,
                        tx.fee_units,
                        tx.timestamp,
                        &tx.sender,
                    ),
                ));
                continue;
            }
            if sender_indexed {
                ops.push((
                    Self::address_tx_key(&tx.sender, block.index, position),
                    Self::encode_address_tx_value(
                        ADDRESS_TX_FLAG_SENDER,
                        tx.amount_units,
                        tx.fee_units,
                        tx.timestamp,
                        &tx.recipient,
                    ),
                ));
            }
            if recipient_indexed {
                ops.push((
                    Self::address_tx_key(&tx.recipient, block.index, position),
                    Self::encode_address_tx_value(
                        ADDRESS_TX_FLAG_RECIPIENT,
                        tx.amount_units,
                        tx.fee_units,
                        tx.timestamp,
                        &tx.sender,
                    ),
                ));
            }
        }
        ops
    }

    /// Write a block's address-history entries and advance the index meta to it.
    /// Callers treat errors as non-fatal (fail-open): this index is display-only
    /// and must never be able to fail a block commit. A skipped/failed write only
    /// leaves the meta behind the tip, which ensure_address_tx_index heals by
    /// re-indexing — idempotent because keys and values are deterministic.
    fn record_address_tx_entries(&self, block: &Block) -> Result<(), BlockchainError> {
        let tree = self.open_address_tx_tree()?;
        let mut batch = sled::Batch::default();
        for (key, value) in Self::address_index_ops(block) {
            batch.insert(key, value);
        }
        tree.apply_batch(batch)?;
        tree.flush()?;
        let meta = self.open_chain_meta_tree()?;
        meta.insert(
            ADDRESS_TX_META_KEY,
            codec::serialize(&(block.index, block.hash))?,
        )?;
        Ok(())
    }

    /// Remove a reverted block's address-history entries (reorg path). Fail-open
    /// like record: a miss only strands display rows that the dirty-marker force
    /// rebuild (or the next full rebuild) clears.
    fn remove_address_tx_entries(&self, block: &Block) -> Result<(), BlockchainError> {
        let tree = self.open_address_tx_tree()?;
        let mut batch = sled::Batch::default();
        for (key, _) in Self::address_index_ops(block) {
            batch.remove(key);
        }
        tree.apply_batch(batch)?;
        tree.flush()?;
        Ok(())
    }

    /// True once the address index has ever completed a build — the signal the
    /// display paths use to distinguish "no activity" from "index unavailable".
    pub fn address_index_ready(&self) -> bool {
        self.open_chain_meta_tree()
            .ok()
            .and_then(|tree| tree.get(ADDRESS_TX_META_KEY).ok().flatten())
            .is_some()
    }

    /// Force-rebuild the address index from the canonical chain. Invalidates the
    /// meta FIRST so a crash mid-rebuild is detected (missing meta => rebuild) and
    /// batches inserts so a long chain does not accumulate one giant batch in RAM.
    /// O(chain); runs once on first upgrade, then only on dirty-marker recovery.
    pub fn rebuild_address_tx_index(&self) -> Result<(), BlockchainError> {
        let tree = self.open_address_tx_tree()?;
        let meta = self.open_chain_meta_tree()?;
        meta.remove(ADDRESS_TX_META_KEY)?;
        meta.flush()?;
        tree.clear()?;
        let Some(tip) = self.highest_block_index() else {
            return Ok(());
        };
        let started = std::time::Instant::now();
        let mut batch = sled::Batch::default();
        let mut pending = 0usize;
        let mut last_indexed: Option<(u32, [u8; 32])> = None;
        for height in 0..=tip {
            if let Ok(block) = self.get_block(height) {
                for (key, value) in Self::address_index_ops(&block) {
                    batch.insert(key, value);
                    pending += 1;
                }
                last_indexed = Some((block.index, block.hash));
                if pending >= 4096 {
                    tree.apply_batch(std::mem::take(&mut batch))?;
                    pending = 0;
                }
            }
        }
        tree.apply_batch(batch)?;
        tree.flush()?;
        if let Some(indexed_tip) = last_indexed {
            meta.insert(ADDRESS_TX_META_KEY, codec::serialize(&indexed_tip)?)?;
            meta.flush()?;
        }
        debug!(
            "Address history index rebuilt to height {} in {:?}",
            tip,
            started.elapsed()
        );
        Ok(())
    }

    /// Bring the address index in line with the canonical chain: build it on first
    /// run under this feature, rebuild if the chain was rewritten while the index
    /// was offline (meta block no longer canonical — e.g. an older binary reorged
    /// under us), or catch up incrementally when merely behind (blocks committed by
    /// an older binary). No-op when current, so it is cheap to call at every start.
    pub fn ensure_address_tx_index(&self) -> Result<(), BlockchainError> {
        let Some(tip) = self.highest_block_index() else {
            return Ok(());
        };
        let meta = self.open_chain_meta_tree()?;
        let recorded: Option<(u32, [u8; 32])> = meta
            .get(ADDRESS_TX_META_KEY)?
            .and_then(|raw| codec::deserialize::<(u32, [u8; 32])>(&raw).ok());
        let Some((meta_height, meta_hash)) = recorded else {
            return self.rebuild_address_tx_index();
        };
        if meta_height > tip {
            return self.rebuild_address_tx_index();
        }
        match self.get_block(meta_height) {
            Ok(block) if block.hash == meta_hash => {}
            _ => return self.rebuild_address_tx_index(),
        }
        for height in meta_height.saturating_add(1)..=tip {
            if let Ok(block) = self.get_block(height) {
                self.record_address_tx_entries(&block)?;
            }
        }
        Ok(())
    }

    /// Whole-chain history totals for one address, or None while the index has
    /// never finished a build (callers show "unavailable" instead of fake zeros).
    pub fn address_history_summary(
        &self,
        address: &str,
    ) -> Result<Option<AddressHistorySummary>, BlockchainError> {
        if !self.address_index_ready() {
            return Ok(None);
        }
        let tree = self.open_address_tx_tree()?;
        let prefix = Self::address_tx_prefix(address);
        let mut summary = AddressHistorySummary::default();
        for item in tree.scan_prefix(&prefix) {
            let (key, value) = item?;
            let Some(entry) = Self::decode_address_tx_entry(prefix.len(), &key, &value) else {
                continue;
            };
            summary.tx_count += 1;
            if entry.is_sender() {
                summary.sent_units = summary.sent_units.saturating_add(entry.amount_units);
                summary.fees_units = summary.fees_units.saturating_add(entry.fee_units);
            }
            if entry.is_recipient() {
                summary.received_units = summary.received_units.saturating_add(entry.amount_units);
            }
            if summary.first_height.is_none() {
                summary.first_height = Some(entry.height);
            }
            summary.last_height = Some(entry.height);
        }
        Ok(Some(summary))
    }

    /// Newest-first confirmed history for one address straight off the index (no
    /// block loads). `since_timestamp` bounds the scan: entries are height-ordered
    /// and block timestamps are only loosely monotonic (MAX_BLOCK_FUTURE_TIME skew),
    /// so the reverse scan keeps going through stragglers and stops only once an
    /// entry is older than the cutoff by a full skew margin.
    pub fn address_recent_txs(
        &self,
        address: &str,
        limit: usize,
        since_timestamp: Option<u64>,
    ) -> Result<Vec<AddressTxEntry>, BlockchainError> {
        let tree = self.open_address_tx_tree()?;
        let prefix = Self::address_tx_prefix(address);
        let mut entries = Vec::new();
        for item in tree.scan_prefix(&prefix).rev() {
            let (key, value) = item?;
            let Some(entry) = Self::decode_address_tx_entry(prefix.len(), &key, &value) else {
                continue;
            };
            if let Some(cutoff) = since_timestamp {
                if entry.timestamp < cutoff {
                    if entry.timestamp.saturating_add(2 * MAX_BLOCK_FUTURE_TIME) < cutoff {
                        break;
                    }
                    continue;
                }
            }
            entries.push(entry);
            if entries.len() >= limit {
                break;
            }
        }
        Ok(entries)
    }

    /// Cursor-paged confirmed history for one address, newest-first: entries
    /// strictly BELOW the exclusive `(height, position)` cursor, `limit` at a
    /// time. Page 1 = before None (from the newest); the caller passes the last
    /// entry's (height, position) to fetch the next page. Bounded work per call
    /// regardless of how much history the address has — built for the explorer
    /// API, where an unpaged scan would be a free DoS.
    pub fn address_txs_page(
        &self,
        address: &str,
        limit: usize,
        before: Option<(u32, u32)>,
    ) -> Result<Vec<AddressTxEntry>, BlockchainError> {
        let Some((before_height, before_position)) = before else {
            return self.address_recent_txs(address, limit, None);
        };
        let tree = self.open_address_tx_tree()?;
        let prefix = Self::address_tx_prefix(address);
        // Keys in [prefix, cursor) all carry our exact prefix: addresses are
        // ASCII so no other address's keys can sort into that window (the 0x00
        // terminator is smaller than any address byte). The range end is
        // exclusive, which is exactly the cursor semantic.
        let cursor = Self::address_tx_key(address, before_height, before_position);
        let mut entries = Vec::new();
        for item in tree.range(prefix.clone()..cursor).rev() {
            let (key, value) = item?;
            let Some(entry) = Self::decode_address_tx_entry(prefix.len(), &key, &value) else {
                continue;
            };
            entries.push(entry);
            if entries.len() >= limit {
                break;
            }
        }
        Ok(entries)
    }

    /// Confirmed balance in units straight off the balances tree — NO
    /// ensure/rebuild side effects, unlike get_confirmed_balance. The explorer
    /// API must never let an anonymous GET trigger index-rebuild writes; a
    /// missing entry is simply 0.
    pub fn confirmed_balance_units_readonly(&self, address: &str) -> Result<i128, BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        match balances_tree.get(address.as_bytes())? {
            Some(raw) => Self::deserialize_units_compatible(&raw),
            None => Ok(0),
        }
    }

    /// (height, hash) the address index is built through, if it has ever built.
    pub fn address_index_meta(&self) -> Option<(u32, [u8; 32])> {
        self.open_chain_meta_tree()
            .ok()
            .and_then(|tree| tree.get(ADDRESS_TX_META_KEY).ok().flatten())
            .and_then(|raw| codec::deserialize::<(u32, [u8; 32])>(&raw).ok())
    }

    /// Sum of all positive confirmed balances — the actual circulating supply.
    /// Replaces the old "sum every transaction amount in every block" estimate,
    /// which double-counted transfers (a mined 50 sent onward counted as 100) and
    /// decoded the entire chain to do it. One cheap tree scan, no block loads.
    pub fn total_confirmed_supply_units(&self) -> Result<i128, BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        let mut total: i128 = 0;
        for item in balances_tree.iter() {
            let (key, value) = item?;
            if key.as_ref() == BALANCES_HEIGHT_KEY {
                continue;
            }
            if let Ok(address) = std::str::from_utf8(&key) {
                if SYSTEM_ADDRESSES.contains(&address) {
                    continue;
                }
            }
            if let Ok(units) = Self::deserialize_units_compatible(&value) {
                if units > 0 {
                    total = total.saturating_add(units);
                }
            }
        }
        Ok(total)
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

    /// True if `branch` (canonical blocks [ancestor+1 ..= its tip]) carries strictly MORE
    /// proof-of-work than the local canonical chain over the same span [ancestor+1 ..= tip].
    /// Used to gate a convergence reorg BEFORE the finality/depth checks, so a merely
    /// TALLER-but-lighter fork — which an attacker can post to the relay and which
    /// `converge_to_relay_tip` targets by max HEIGHT — cannot trip the depth guard into
    /// NeedsBootstrap and drive the publisher's restart escalation. A non-heavier branch
    /// means we already hold the better chain, so the caller keeps mining instead of
    /// reorging or bootstrapping.
    pub fn external_branch_is_heavier(&self, branch: &[Block], ancestor: u32, tip: u32) -> bool {
        let Some(branch_tip) = branch.last() else {
            return false;
        };
        let canonical_work = match self.canonical_work_range(ancestor.saturating_add(1), tip) {
            Ok(w) => w,
            Err(_) => return false, // can't compute local work -> conservative: don't reorg
        };
        let branch_work = Self::branch_work_to_height(branch, branch_tip.index);
        branch_work > canonical_work
    }

    /// Fork-choice verdict for the convergence (beacon/relay) reorg path. Returns true iff
    /// adopting `branch` (canonical [ancestor+1 ..= its tip]) is warranted over the local
    /// chain over the same span [ancestor+1 ..= tip]:
    ///   * strictly MORE proof-of-work, OR
    ///   * EQUAL work AND a SAME-HEIGHT tip whose hash is strictly lower — the deterministic
    ///     "lowest tip hash wins" tie-break the reorg engine (`try_adopt_orphan_branch`)
    ///     already applies. A same-height equal-work fork whose tip hash is >= ours means we
    ///     already hold the tie winner, so we keep it.
    ///
    /// This exists because `external_branch_is_heavier` uses a strict `>`: on an equal-work
    /// same-height fork (the common case — two miners find a block at the same height and
    /// floor difficulty) it returns false, and the caller short-circuits to AtTipAhead
    /// WITHOUT ever routing the competitor through the engine's tie-break. Beacon/relay-only
    /// nodes then never switch to the canonical lowest-hash block and stay split from the
    /// directly-P2P-meshed nodes (which DO run the engine on ingest) — the "won't catch up /
    /// 3-of-4 agreement" fork. Anything strictly lighter (incl. a taller-but-lighter attacker
    /// fork, or an equal-work fork that is TALLER rather than same-height) returns false, so
    /// the caller keeps mining and never trips the depth-guard/bootstrap escalation.
    pub fn external_branch_wins_fork_choice(
        &self,
        branch: &[Block],
        ancestor: u32,
        tip: u32,
    ) -> bool {
        let Some(branch_tip) = branch.last() else {
            return false;
        };
        let canonical_work = match self.canonical_work_range(ancestor.saturating_add(1), tip) {
            Ok(w) => w,
            Err(_) => return false, // can't compute local work -> conservative: don't reorg
        };
        let branch_work = Self::branch_work_to_height(branch, branch_tip.index);
        if branch_work > canonical_work {
            return true;
        }
        if branch_work == canonical_work {
            // Equal work: adopt ONLY the deterministic lowest-hash winner at the SAME height,
            // exactly as try_adopt_orphan_branch decides once the branch reaches the engine.
            let Ok(local_tip) = self.get_block(tip) else {
                return false;
            };
            return branch_tip.index == tip && branch_tip.hash < local_tip.hash;
        }
        false
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

    /// Adopt an externally-fetched competing branch (pulled from the gateway
    /// during a beacon-driven reorg). The blocks are staged as orphan candidates
    /// and run through the SAME fork-choice reorg as any other adoption — so the
    /// checkpoint-finality guard, balance validation, and frontier-signature gate
    /// all apply — and on success it disconnects the losing blocks, connects the
    /// heavier canonical branch, and fires notify_tip_changed. Never re-downloads.
    pub async fn adopt_external_branch(
        &self,
        blocks: Vec<Block>,
    ) -> Result<bool, BlockchainError> {
        if blocks.is_empty() {
            return Ok(false);
        }
        for block in &blocks {
            let _ = self.store_orphan_block(block);
        }
        self.try_adopt_orphan_branch().await
    }

    // ===== (G) witness-blocked reorg memo =====
    // These maintain `witness_blocked` — the backoff/queue for reorg branches the
    // S-01 gate deferred because their above-floor blocks arrived witness-short.
    // All are cheap in-memory ops under a parking_lot mutex (no await, no I/O).

    /// True while `tip_hash`'s branch is inside its post-defer backoff window — the
    /// signal to try_adopt to skip re-verifying/re-logging it this tick.
    fn witness_branch_backoff_active(&self, tip_hash: &[u8; 32]) -> bool {
        let now = Self::now_unix_secs();
        let map = self.witness_blocked.lock();
        map.get(tip_hash).map(|e| now < e.retry_after).unwrap_or(false)
    }

    /// Record (or refresh) a witness-deferred branch: arm the backoff, bump the
    /// attempt counter, and store the exact blocks R must rehydrate. Also prunes
    /// entries past their TTL so the memo cannot grow unbounded.
    fn record_witness_blocked(&self, tip_hash: [u8; 32], needed: Vec<(u32, [u8; 32])>) {
        let now = Self::now_unix_secs();
        let mut map = self.witness_blocked.lock();
        map.retain(|_, e| now.saturating_sub(e.recorded_at) <= WITNESS_BLOCKED_TTL_SECS);
        let entry = map.entry(tip_hash).or_insert(WitnessBlockedBranch {
            retry_after: 0,
            attempts: 0,
            needed: Vec::new(),
            recorded_at: now,
        });
        entry.retry_after = now.saturating_add(WITNESS_BLOCKED_BACKOFF_SECS);
        entry.attempts = entry.attempts.saturating_add(1);
        entry.needed = needed;
        entry.recorded_at = now;
    }

    /// Drop a memo entry — called by R the instant it rehydrates a branch, so the
    /// next ingest re-evaluates it immediately (no backoff wait) with the now-full
    /// witnesses present in the orphan pool.
    pub fn clear_witness_blocked(&self, tip_hash: &[u8; 32]) {
        self.witness_blocked.lock().remove(tip_hash);
    }

    /// Snapshot of the current witness-blocked branches for the Node-layer
    /// rehydrator (R): (branch_tip_hash, attempts, needed blocks). Prunes expired
    /// entries as a side effect.
    pub fn witness_blocked_snapshot(&self) -> Vec<([u8; 32], u32, Vec<(u32, [u8; 32])>)> {
        let now = Self::now_unix_secs();
        let mut map = self.witness_blocked.lock();
        map.retain(|_, e| now.saturating_sub(e.recorded_at) <= WITNESS_BLOCKED_TTL_SECS);
        map.iter()
            .map(|(tip, e)| (*tip, e.attempts, e.needed.clone()))
            .collect()
    }

    // NOTE (v7.7.8): the relay witness-REHYDRATION path (try_install_rehydrated_orphan,
    // reattempt_orphan_adoption, orphan_is_full_witnessed) and the checkpoint-relative
    // reorg bound live on branch `v779-witness-full`, deferred to v7.7.9 pending the
    // #2 x coinbase-maturity design + a complete adversarial review + soak proof. v7.7.8
    // ships only G (the witness_blocked defer/backoff below, which stops the S-01
    // re-verify/log storm with zero consensus surface); a witness-wedged node still
    // recovers via the escape-hatch re-bootstrap path (converge NeedsBootstrap -> marker).

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

        // Score the most promising forks first: a higher fork height tends to carry
        // more overlap work, then higher difficulty, then lexical hash for a
        // deterministic tie-break. Combined with the per-attempt eval budget below,
        // this stops a flood of low-value orphan competitors from starving
        // evaluation of the genuinely heaviest branch.
        candidates.sort_by(|a, b| {
            b.index
                .cmp(&a.index)
                .then_with(|| b.difficulty.cmp(&a.difficulty))
                .then_with(|| a.hash.cmp(&b.hash))
        });

        // Memoise canonical work per fork height for this attempt. tip.index is
        // fixed, so canonical_work_range(fork, tip) depends only on `fork`; many
        // competing branches share a fork height and would otherwise re-read the
        // same [fork..=tip] slice from sled on every branch. Precompute the suffix
        // sum in a single walk down from the tip so each lookup is O(1) and total
        // canonical block reads are bounded by the reorg window, not branches × span.
        let mut canonical_suffix: HashMap<u32, BigUint> = HashMap::new();
        if let Some(min_fork) = candidates.iter().map(|c| c.index).min() {
            let mut running = BigUint::from(0u8);
            let mut h = tip.index;
            loop {
                let block = self.get_block(h)?;
                running += Self::work_units_for_difficulty(block.difficulty);
                canonical_suffix.insert(h, running.clone());
                if h == min_fork {
                    break;
                }
                h = h.saturating_sub(1);
            }
        }

        let mut best_branch: Option<Vec<Block>> = None;
        let mut best_work_pair: Option<(BigUint, BigUint)> = None;
        let mut best_tip_hash: [u8; 32] = [0u8; 32];
        let mut branches_evaluated: usize = 0;

        'candidate: for candidate in candidates {
            let branches = self.collect_orphan_branches_from(
                candidate,
                ORPHAN_REORG_DEPTH as usize,
                ORPHAN_BRANCH_SEARCH_LIMIT,
            )?;
            for branch in branches {
                if branches_evaluated >= MAX_REORG_BRANCHES_EVALUATED {
                    debug!(
                        "Reorg scan hit branch-eval budget ({} branches); adopting best found so far",
                        MAX_REORG_BRANCHES_EVALUATED
                    );
                    break 'candidate;
                }
                branches_evaluated += 1;

                let Some(branch_tip) = branch.last() else {
                    continue;
                };
                // Branch may be same-height competitor or longer. Adoption decision is based on work.

                let fork_height = branch[0].index;
                // O(1) memoised lookup; the suffix covers every fork height in range.
                let canonical_work = canonical_suffix
                    .get(&fork_height)
                    .cloned()
                    .unwrap_or_else(|| BigUint::from(0u8));
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

        // Checkpoint finality: a reorg may not rewrite history at or below the
        // trusted checkpoint. Those blocks were vouched for by a verified signed
        // snapshot (or locally verified then finalized), so a competing branch
        // forking that deep is rejected outright — this bounds reorg depth and
        // stops a deep-reorg double-spend beneath the finalized point.
        let checkpoint = self.trusted_checkpoint_height();
        if branch[0].index <= checkpoint {
            debug!(
                "Reorg rejected: branch forks at height {} at/below finalized checkpoint {}",
                branch[0].index, checkpoint
            );
            return Ok(false);
        }

        // Frontier signature gate on the reorg path (S-01). The validation above
        // runs in AllowTruncatedStored mode, which only checks structure — so a
        // forged competitor carrying a truncated/invalid user-tx signature could
        // otherwise be adopted via reorg. Any branch block above the verification
        // floor must therefore carry full, valid ML-DSA witnesses.
        //
        // (G) This gate is UNCHANGED as a validity check — a branch that lacks full
        // witnesses is still not adopted. What changed is the failure handling: a
        // genuinely-heavier branch whose above-floor blocks merely arrived
        // witness-TRUNCATED (the fork-storm common case once the checkpoint lags)
        // used to be re-selected, re-verified (expensive ML-DSA), and re-logged on
        // every ingest tick — the 187k-reject CPU/log storm (2026-07-11). Now it is
        // DEFERRED: recorded with a backoff and the exact blocks R must rehydrate
        // from the relay, then skipped until R makes the real witnesses available
        // (which clears the memo) or the backoff elapses. No block is accepted that
        // was not accepted before; block_signatures_fully_verified still gates the
        // eventual adoption on real, verified full witnesses.
        let branch_tip_hash = branch.last().map(|b| b.hash).unwrap_or([0u8; 32]);
        if self.witness_branch_backoff_active(&branch_tip_hash) {
            return Ok(false);
        }
        let floor = self.verification_floor();
        let mut needed: Vec<(u32, [u8; 32])> = Vec::new();
        for b in &branch {
            if b.index > floor && !self.block_signatures_fully_verified(b) {
                needed.push((b.index, b.hash));
            }
        }
        if !needed.is_empty() {
            debug!(
                "Reorg deferred: branch tip {} has {} above-floor block(s) (floor {}) lacking full witnesses; queued for relay rehydration",
                hex::encode(branch_tip_hash),
                needed.len(),
                floor
            );
            self.record_witness_blocked(branch_tip_hash, needed);
            return Ok(false);
        }

        // Enforce transaction semantics on the reorg path exactly like tip
        // extension: a competing branch that double-spends or overspends must be
        // rejected even though it arrived as a same-height competitor. Checked
        // before any slot is rewritten so there is nothing to roll back.
        if !self.branch_is_balance_valid(branch[0].index, &branch).await? {
            debug!(
                "Reorg rejected: branch at height {} fails balance validation (overspend/double-spend)",
                branch[0].index
            );
            return Ok(false);
        }

        // Replay guard (reorg, fork-aware): a branch may legitimately re-include a
        // transaction from the range it replaces, but it must not replay one that is
        // confirmed BELOW the fork point (in the history the branch keeps). Reject a
        // branch that does — this closes replay via a crafted reorg.
        let fork_start = branch[0].index;
        for b in &branch {
            for tx in &b.transactions {
                if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                    continue;
                }
                if let Some(idx) = self.confirmed_tx_index(&tx.get_tx_id()) {
                    if idx < fork_start {
                        debug!(
                            "Reorg rejected: branch replays tx confirmed at {} (below fork {})",
                            idx, fork_start
                        );
                        return Ok(false);
                    }
                }
            }
        }

        self.mark_chain_state_dirty(branch[0].index, "orphan_branch_reorg")?;

        // Transactions the new branch (re-)confirms, so we do not return them to the
        // mempool as if they were dropped.
        let branch_tx_ids: std::collections::HashSet<String> = branch
            .iter()
            .flat_map(|b| b.transactions.iter())
            .filter(|tx| !SYSTEM_ADDRESSES.contains(&tx.sender.as_str()))
            .map(|tx| tx.get_tx_id())
            .collect();

        // Read the canonical blocks being reverted BEFORE they are overwritten:
        // unregister their transactions from the replay registry, and remember the
        // non-system ones the new branch does NOT re-confirm so they can be returned
        // to the mempool — a reverted payment must not be silently lost.
        let mut reverted_txs: Vec<Transaction> = Vec::new();
        for h in fork_start..=tip.index {
            if let Ok(old) = self.get_block(h) {
                let _ = self.remove_confirmed_txs(&old);
                for tx in &old.transactions {
                    if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                        continue;
                    }
                    if !branch_tx_ids.contains(&tx.get_tx_id()) {
                        reverted_txs.push(tx.clone());
                    }
                }
            }
        }

        let branch_tip = branch
            .last()
            .ok_or(BlockchainError::InvalidBlockHeader)?
            .clone();

        // Hold the balances-index gate across the whole mutation window: a lazy
        // catch-up (ensure_balances_index) must never read canonical slots
        // mid-rewrite. The dirty marker (set above) makes a gate-waiter skip once
        // it gets in; this closes the window where one could already be running.
        // Lock order state_mutation_lock -> balances_index_gate, same as the
        // writers' in-lock balance reads; dropped before the mempool reconcile.
        let index_guard = self.balances_index_gate.lock().await;

        // Apply the reorg ATOMICALLY: rewrite the branch's canonical slots and drop
        // any now-stale higher slots in a single batch, so a crash can never leave a
        // half-rewritten chain. The dirty marker (above) + startup recovery re-derive
        // balances if we crash after this point.
        let mut slot_batch = sled::Batch::default();
        for b in &branch {
            let key = format!("block_{}", b.index);
            let storage = Self::to_storage_block(b);
            slot_batch.insert(key.as_bytes(), codec::serialize(&storage)?);
        }
        for stale_height in branch_tip.index.saturating_add(1)..=tip.index {
            let key = format!("block_{}", stale_height);
            slot_batch.remove(key.as_bytes());
        }
        self.db.apply_batch(slot_batch)?;

        // Remove adopted branch blocks from orphan pool.
        for b in &branch {
            let _ = self.remove_orphan_by_hash(&b.hash);
        }
        self.prune_orphans()?;

        // Register the newly-canonical branch's transactions in the replay registry,
        // then prune anything now past the freshness window.
        for b in &branch {
            let _ = self.record_confirmed_txs(b);
        }
        let _ = self.prune_confirmed_txs(branch_tip.timestamp);

        // Rebuild balances index after reorg (the marker commits atomically inside
        // the rebuild's own batch, set to the post-rewrite tip it replayed).
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        self.rebuild_balances_index(&balances_tree).await?;
        self.write_chain_tip_metadata(&branch_tip)?;
        let _ = self.get_network_difficulty().await?;
        self.db.flush()?;
        balances_tree.flush()?;
        self.open_chain_meta_tree()?.flush()?;
        self.clear_chain_state_dirty()?;
        drop(index_guard);

        // Reconcile the mempool with the reorg (M14). First evict the branch's
        // now-confirmed transactions so they are not double-counted as pending or
        // re-selected into the next block template (mirrors the finalize/persist paths;
        // clear_transaction is a no-op for txs that were never in the local mempool).
        // Then return the reverted transactions the new branch did NOT re-confirm so
        // they can be re-mined instead of being silently lost — add_transaction
        // re-validates each against the new canonical state and drops any now invalid
        // (e.g. spent by the winning branch).
        {
            let mut mempool = self.mempool.write().await;
            for b in &branch {
                for tx in &b.transactions {
                    mempool.clear_transaction(tx);
                }
            }
            for tx in reverted_txs {
                let _ = mempool.add_transaction(tx);
            }
        }

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

        // Replay guard (tip extension): reject a block that re-includes a
        // transaction already confirmed at a different height. Without this a
        // confirmed, validly-signed payment could be re-mined to drain the sender.
        // The reorg path has its own fork-aware replay check.
        if self.block_has_replayed_tx(block) {
            return Err(BlockchainError::InvalidTransaction);
        }

        // Run the BOUNDED frontier integrity check periodically. This used to be
        // the full from-genesis walk — O(chain) disk reads under the state lock
        // and the caller's write guard, every ~60s of steady ingest. Once the
        // chain outgrew the walk (5s blocks, ~17k/day), nodes wedged for minutes
        // per walk (lock-watchdog chain_ok=false, 2026-07-10). The frontier
        // window covers everything that can still change (reorgs at/below the
        // trusted checkpoint are rejected outright; deeper blocks all passed full
        // admission validation on arrival), at a fixed ~sub-second cost.
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
            if !self
                .chain_sentinel
                .verify_recent_chain_integrity(self, INTEGRITY_FRONTIER_WINDOW)
                .await
            {
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

        // A block must carry at least the local verification recorded just above
        // before it is persisted. The ALPHANUMERIC_REQUIRE_QUORUM toggle was removed:
        // it demanded 3 verifiers that the normal single-node verification flow can
        // never produce, so enabling it silently halted the chain (no block ever
        // persisted). Default behaviour (toggle off) is unchanged.
        if self.chain_sentinel.get_verification_count(block) == 0 {
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

        // Evict the now-confirmed transactions from the IN-MEMORY mempool. Their
        // on-disk pending records and pending-debit reservations were already
        // cleared by process_transactions_batch, but nothing removed them from the
        // in-memory pool — so without this they would linger forever (unbounded
        // memory growth) and could be re-selected into a later block. The mempool
        // has its own lock, so this cannot deadlock against the state guard held by
        // the callers of this function.
        {
            let mut mempool = self.mempool.write().await;
            for tx in &block.transactions {
                mempool.clear_transaction(tx);
            }
        }

        // Register this block's transactions in the replay registry so any later
        // block that re-includes one is rejected as a replay, then prune entries
        // now past the freshness window so the registry stays bounded.
        let _ = self.record_confirmed_txs(block);
        let _ = self.prune_confirmed_txs(block.timestamp);

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

        // The index marker already advanced atomically with the balance content
        // inside process_transactions_batch's apply batch — and tip metadata is
        // written only after it, so a reader that can see the new tip can never
        // observe a lagging marker (the window that used to trigger stampeding
        // full rebuilds on every block). The tree is opened here only to flush.
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
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

    // Production paths now advance the marker atomically inside the same batch as
    // the balance content (process_transactions_batch / rebuild / catch-up); this
    // standalone setter remains for tests that stage stale-marker scenarios.
    #[cfg_attr(not(test), allow(dead_code))]
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
        let force_rebuild_env = std::env::var("ALPHANUMERIC_REBUILD_BALANCES")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let force = force_rebuild_requested || force_rebuild_env;

        // Fast path, no lock: index exactly at the tip and nothing forced. This is
        // the steady-state outcome for every reader (the apply paths advance the
        // marker atomically with the content), so the gate below stays uncontended
        // in normal operation and the writers' in-lock balance reads never block.
        if !force {
            if let Some(height) = Self::get_balances_height(&balances_tree)? {
                if height == self.get_latest_block_index() {
                    return Ok(());
                }
            }
        }

        // Single-flight: exactly one rebuild/catch-up runs; concurrent callers WAIT
        // here, then re-check and read the fresh result. Previously each stale-index
        // reader launched its own full O(chain) replay — once 5s blocks arrived
        // faster than a replay completed, nodes ground through back-to-back rebuilds
        // (starving block ingest via the write-preferring RwLock) until block
        // arrivals paused: the observed multi-minute wedges.
        let _index_guard = self.balances_index_gate.lock().await;

        // A writer (persist/finalize/reorg) is mid-mutation: the tree is a consistent
        // as-of-marker snapshot and the writer advances the marker atomically with
        // its content. Mutating here would race the writer's absolute balance writes.
        // Crashed-writer markers are owned by startup recovery, which re-derives the
        // tip and calls back in with force=true (never skipped).
        if !force && self.chain_state_dirty()?.is_some() {
            return Ok(());
        }

        let tip = self.get_latest_block_index();
        let current_height = Self::get_balances_height(&balances_tree)?;

        match current_height {
            // Raced: another caller brought it current while we waited on the gate.
            Some(height) if !force && height == tip => Ok(()),
            // Merely behind: close the gap in O(gap) through the SAME replay
            // function the full rebuild uses — identical values by construction.
            Some(height) if !force && height < tip => {
                self.catch_up_balances_index(&balances_tree, height, tip)
                    .await
            }
            // Forced, no marker yet, or marker ahead of the tip (chain shrank or
            // unknown state): re-derive everything from the canonical chain.
            _ => {
                self.rebuild_balances_index(&balances_tree).await?;
                balances_tree.flush()?;
                Ok(())
            }
        }
    }

    /// O(gap) catch-up for an index that is merely BEHIND the tip: applies blocks
    /// [from+1, tip] through replay_apply_block_checked — the same function the
    /// full rebuild and the reorg dry-run use — against the tree's current values,
    /// so the result is identical to a from-genesis replay by construction (raw
    /// balances are exact integer sums; the maturity overlay is comparison-only).
    /// Each block's deltas commit atomically WITH the advanced marker, so a crash
    /// can only lose whole suffixes, never tear the (content, marker) pair. Any
    /// unloadable or non-replaying block falls back to the full rebuild, which owns
    /// the loud M23 corruption alarm and re-derives from scratch.
    async fn catch_up_balances_index(
        &self,
        balances_tree: &sled::Tree,
        from: u64,
        tip: u64,
    ) -> Result<(), BlockchainError> {
        // Seed the rolling immature-coinbase window exactly as a from-genesis
        // replay would hold it entering block from+1. Seeding slightly deeper than
        // necessary is self-correcting (the replay pops stale fronts), so start at
        // the conservative (from+1)-MATURITY bound, ascending — the pop loop only
        // inspects the front, so order must match the replay's push order.
        let first = from.saturating_add(1);
        let mut recent: std::collections::VecDeque<(u32, String, i128)> =
            std::collections::VecDeque::new();
        let seed_low = first.saturating_sub(MINING_REWARD_MATURITY as u64);
        for rh in seed_low..=from {
            let Ok(block) = self.get_block(rh as u32) else {
                self.rebuild_balances_index(balances_tree).await?;
                balances_tree.flush()?;
                return Ok(());
            };
            for tx in &block.transactions {
                if tx.sender == "MINING_REWARDS" {
                    recent.push_back((block.index, tx.recipient.clone(), tx.amount_units));
                }
            }
        }

        let mut balances: HashMap<String, i128> = HashMap::new();
        for h in first..=tip {
            let Ok(block) = self.get_block(h as u32) else {
                self.rebuild_balances_index(balances_tree).await?;
                balances_tree.flush()?;
                return Ok(());
            };
            // Load current confirmed values for every address this block's replay
            // will touch (absent == 0, exactly a fresh accumulator's start). The
            // touch set mirrors replay_apply_block_checked: a coinbase touches its
            // recipient only; a regular tx touches sender and recipient.
            let mut touched: Vec<String> = Vec::new();
            for tx in &block.transactions {
                if tx.sender != "MINING_REWARDS" {
                    touched.push(tx.sender.clone());
                }
                touched.push(tx.recipient.clone());
            }
            for addr in &touched {
                if !balances.contains_key(addr.as_str()) {
                    let value = match balances_tree.get(addr.as_bytes())? {
                        Some(raw) => Self::deserialize_units_compatible(&raw)?,
                        None => 0,
                    };
                    balances.insert(addr.clone(), value);
                }
            }
            if Self::replay_apply_block_checked(
                block.index,
                &block.transactions,
                &mut balances,
                &mut recent,
            )
            .is_err()
            {
                // A persisted canonical block must replay cleanly; if it does not,
                // the marker (or the history under it) is not trustworthy here —
                // re-derive from scratch instead of guessing.
                self.rebuild_balances_index(balances_tree).await?;
                balances_tree.flush()?;
                return Ok(());
            }
            let mut batch = sled::Batch::default();
            for addr in &touched {
                if let Some(balance) = balances.get(addr.as_str()) {
                    batch.insert(addr.as_bytes(), codec::serialize(balance)?);
                }
            }
            batch.insert(BALANCES_HEIGHT_KEY, codec::serialize(&h)?);
            balances_tree.apply_batch(batch)?;
        }
        balances_tree.flush()?;
        Ok(())
    }

    async fn rebuild_balances_index(
        &self,
        balances_tree: &sled::Tree,
    ) -> Result<(), BlockchainError> {
        // Stream blocks by numeric height (O(1) block RAM) instead of loading + sorting the
        // WHOLE chain into memory — numeric order is exactly the index/solvency-replay order
        // the lexical `block_{n}` sort was reconstructing.
        let mut balances: HashMap<String, i128> = HashMap::new();
        // Rolling immature-coinbase window (M06), maintained across the whole 0..=tip replay
        // and byte-identical to branch_is_balance_valid via the shared helper. The helper
        // enforces sequential availability (like the forward apply path) AND the maturity
        // overlay above the activation height; `balances` stays RAW confirmed totals and
        // feeds the atomic diff-batch below unchanged.
        let mut recent: std::collections::VecDeque<(u32, String, i128)> =
            std::collections::VecDeque::new();
        let covered = self.highest_block_index();
        if let Some(tip) = covered {
            let mut missing = 0u32;
            let mut first_missing = 0u32;
            for h in 0..=tip {
                let Ok(block) = self.get_block(h) else {
                    // M23: blocks are never pruned, so a gap in [0, tip] is genuine on-disk
                    // corruption. Skipping it silently (as before) rebuilds WRONG balances
                    // that still look authoritative because `tip` is unchanged. Count and
                    // alarm loudly so the corruption is visible. Deliberately NOT a hard
                    // fail: one bad old block must not strand a node whose recent state is
                    // fine, and there is no pruning path that makes a gap legitimate.
                    if missing == 0 {
                        first_missing = h;
                    }
                    missing += 1;
                    continue;
                };
                Self::replay_apply_block_checked(
                    h,
                    &block.transactions,
                    &mut balances,
                    &mut recent,
                )?;
            }
            if missing > 0 {
                log::error!(
                    "rebuild_balances_index: {} of {} blocks in [0, {}] failed to load \
                     (first at height {}) and were SKIPPED -- rebuilt balances are \
                     INCOMPLETE and almost certainly WRONG. The block DB is corrupt; \
                     restore from a good snapshot or re-sync from the network.",
                    missing,
                    tip + 1,
                    tip,
                    first_missing,
                );
            }
        }

        // Atomic swap — NO clear(). One batch removes addresses that vanished from the
        // recomputed set and writes every new balance, so a concurrent lock-free reader
        // (get_confirmed_balance -> ensure_balances_index) sees all-old or all-new, never the
        // empty tree that clear() briefly exposed (which returned wrong balances and could
        // trigger a re-entrant rebuild storm). The height marker key is preserved.
        let mut batch = sled::Batch::default();
        for entry in balances_tree.iter() {
            let (key, _) = entry?;
            if key.as_ref() == BALANCES_HEIGHT_KEY {
                continue;
            }
            let vanished = match std::str::from_utf8(key.as_ref()) {
                Ok(addr) => !balances.contains_key(addr),
                Err(_) => true,
            };
            if vanished {
                batch.remove(key);
            }
        }
        for (address, balance) in &balances {
            batch.insert(address.as_bytes(), codec::serialize(balance)?);
        }
        // The marker commits in the SAME atomic batch as the recomputed content,
        // recording the tip this replay actually covered — NOT a caller-captured
        // tip. Under 5s blocks the tip can advance during a long replay; marking
        // the stale capture left the index permanently one-behind and re-armed
        // the rebuild on every subsequent read (the treadmill). Any gap that
        // opens mid-replay is closed by the next ensure via O(gap) catch-up.
        let covered_height = covered.map(u64::from).unwrap_or(0);
        batch.insert(BALANCES_HEIGHT_KEY, codec::serialize(&covered_height)?);
        balances_tree.apply_batch(batch)?;

        Ok(())
    }

    /// Coinbase-maturity overlay (M06) for the two REPLAY gates (branch_is_balance_valid
    /// and rebuild_balances_index). Applies one block to a RAW-totals `balances` map while
    /// maintaining `recent` — a rolling window of still-immature MINING_REWARDS credits —
    /// and gating each spend on `spendable = raw - immature >= debit`. Both replay gates
    /// MUST call this so their maturity logic is byte-identical: a reorg rewrites canonical
    /// slots (branch_is_balance_valid dry-run passes) BEFORE rebuild_balances_index re-applies,
    /// so any divergence between them would corrupt the chain. `balances` is never reduced by
    /// the immature amount — maturity is a comparison-time overlay only. Below the activation
    /// height the overlay is 0 and this is identical to a plain solvency replay.
    fn replay_apply_block_checked(
        block_height: u32,
        txs: &[Transaction],
        balances: &mut HashMap<String, i128>,
        recent: &mut std::collections::VecDeque<(u32, String, i128)>,
    ) -> Result<(), BlockchainError> {
        let h = block_height as u64;
        let mat = MINING_REWARD_MATURITY as u64;
        let enforce = block_height >= MATURITY_ACTIVATION_HEIGHT;
        // Drop coinbases that are now mature (buried >= MATURITY deep) at this height.
        while let Some(&(rh, _, _)) = recent.front() {
            if (rh as u64).saturating_add(mat) <= h {
                recent.pop_front();
            } else {
                break;
            }
        }
        for tx in txs {
            if tx.sender == "MINING_REWARDS" {
                *balances.entry(tx.recipient.clone()).or_insert(0) += tx.amount_units;
                // The block's own coinbase (pushed before its regular txs) is immature at
                // depth 0, so a same-block spend of the fresh reward is blocked.
                recent.push_back((block_height, tx.recipient.clone(), tx.amount_units));
                continue;
            }
            let debit = tx.total_debit_units();
            let immature = if enforce {
                recent
                    .iter()
                    .filter(|(_, r, _)| r == &tx.sender)
                    .map(|(_, _, a)| *a)
                    .sum::<i128>()
            } else {
                0
            };
            let entry = balances.entry(tx.sender.clone()).or_insert(0);
            if *entry - immature < debit {
                return Err(BlockchainError::InsufficientFunds);
            }
            *entry -= debit;
            *balances.entry(tx.recipient.clone()).or_insert(0) += tx.amount_units;
        }
        Ok(())
    }

    /// Coinbase-maturity overlay (M06) for the tip-extension and advisory gates: the total
    /// MINING_REWARDS credited to `address` that is still immature at `spend_height` (rewards
    /// from stored blocks in [spend_height-MATURITY+1, spend_height-1], plus any coinbase in
    /// `in_flight` — the block being validated, whose own coinbase is not in storage yet).
    /// Returns 0 below the activation height. Implements the SAME predicate rh+MATURITY>h as
    /// replay_apply_block_checked, so the scan path and the replay path agree for a given chain.
    /// Delegates to immature_coinbase_details so the enforced total and the displayed
    /// per-reward breakdown can never drift.
    fn immature_reward_units_scan(
        &self,
        address: &str,
        spend_height: u64,
        in_flight: &[Transaction],
    ) -> i128 {
        self.immature_coinbase_details(address, spend_height, in_flight)
            .iter()
            .map(|(_, amount_units)| *amount_units)
            .sum()
    }

    /// The M06 overlay's per-reward view: every still-immature MINING_REWARDS credit to
    /// `address` at `spend_height`, as (reward_height, amount_units) in ascending height
    /// order (in-flight coinbases, at `spend_height` itself, last). This is the single
    /// implementation of the maturity predicate — immature_reward_units_scan is its sum —
    /// so any UI built on it shows exactly the set the affordability gates enforce.
    /// Empty below the activation height.
    fn immature_coinbase_details(
        &self,
        address: &str,
        spend_height: u64,
        in_flight: &[Transaction],
    ) -> Vec<(u32, i128)> {
        if (spend_height as u32) < MATURITY_ACTIVATION_HEIGHT {
            return Vec::new();
        }
        let mat = MINING_REWARD_MATURITY as u64;
        let mut details: Vec<(u32, i128)> = Vec::new();
        let low = spend_height.saturating_sub(mat).saturating_add(1);
        for rh in low..spend_height {
            if let Ok(b) = self.get_block(rh as u32) {
                for tx in &b.transactions {
                    if tx.sender == "MINING_REWARDS" && tx.recipient == address {
                        details.push((rh as u32, tx.amount_units));
                    }
                }
            }
        }
        for tx in in_flight {
            if tx.sender == "MINING_REWARDS" && tx.recipient == address {
                details.push((spend_height as u32, tx.amount_units));
            }
        }
        details
    }

    /// Dry-run: would the chain formed by canonical blocks below `fork_start`
    /// plus `branch` keep every sender solvent at each step? Reads only; used to
    /// reject a reorg to a competing branch that double-spends or overspends
    /// BEFORE any canonical slots are rewritten (no rollback needed).
    async fn branch_is_balance_valid(
        &self,
        fork_start: u32,
        branch: &[Block],
    ) -> Result<bool, BlockchainError> {
        let mut balances: HashMap<String, i128> = HashMap::new();
        // One rolling immature-coinbase window (M06) shared across BOTH loops so it spans the
        // fork boundary; must be byte-identical to rebuild_balances_index (the authoritative
        // re-apply that runs after this dry-run passes) — both use replay_apply_block_checked.
        let mut recent: std::collections::VecDeque<(u32, String, i128)> =
            std::collections::VecDeque::new();
        // Stream canonical history below the fork by numeric height (O(1) block RAM instead of
        // loading + sorting the whole sub-chain), then the branch — numeric height order is
        // exactly the replay order.
        for h in 0..fork_start {
            let Ok(block) = self.get_block(h) else {
                continue;
            };
            if Self::replay_apply_block_checked(h, &block.transactions, &mut balances, &mut recent)
                .is_err()
            {
                return Ok(false);
            }
        }
        for block in branch {
            if Self::replay_apply_block_checked(
                block.index,
                &block.transactions,
                &mut balances,
                &mut recent,
            )
            .is_err()
            {
                return Ok(false);
            }
        }
        Ok(true)
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
            balances_index_gate: Arc::new(Mutex::new(())),
            tip_change_counter,
            tip_watch_tx,
            witness_blocked: Arc::new(PLMutex::new(HashMap::new())),
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
            // A crash mid-reorg can leave the replay registry half-written (its
            // remove/record loops run outside the atomic canonical-slot batch), so
            // rederive it from the now-consistent canonical chain before clearing the
            // marker. Otherwise a stale registry would silently let a confirmed tx be
            // replayed after recovery.
            self.rebuild_confirmed_tx_index()?;
            // The address history index has the same half-applied exposure as the
            // registry (its remove/record run outside the atomic slot batch), but it
            // is display-only: a failed rebuild must not abort startup. Fail-open —
            // a failure leaves its meta invalidated, so ensure retries next start.
            if let Err(e) = self.rebuild_address_tx_index() {
                warn!("Address history index rebuild failed during recovery: {}", e);
            }
            self.clear_chain_state_dirty()?;
        }
        // Build the address history index on first run under this feature, rebuild
        // it if the chain was rewritten while it was offline, or catch up if merely
        // behind. Cheap no-op when current. Fail-open: the account/history displays
        // degrade to "index unavailable", never a startup failure.
        if let Err(e) = self.ensure_address_tx_index() {
            warn!("Address history index unavailable (build failed): {}", e);
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

        // Mirror the persist path's replay guard on the local mining commit too:
        // reject a block that re-includes a transaction already confirmed at a
        // different height, before any balance mutation. Legitimate mined blocks draw
        // from the mempool (now evicted of confirmed txs), so this fires only on a
        // genuine replay rather than on the miner's own fresh transactions.
        if self.block_has_replayed_tx(&block) {
            return Err(BlockchainError::InvalidTransaction);
        }

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
            // M06 (defense-in-depth): don't let the local miner commit a block that spends an
            // immature reward — process_transactions_batch would reject it anyway.
            let immature =
                self.immature_reward_units_scan(&tx.sender, block.index as u64, &block.transactions);
            let available = confirmed - pending - immature;
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
        // Marker advanced atomically with the balances inside
        // process_transactions_batch's batch; tree opened only to flush below.
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        self.write_chain_tip_metadata(&block)?;
        set_finalize_stage(6);
        trace_step("balances_height");
        self.db.flush()?;
        balances_tree.flush()?;
        self.open_chain_meta_tree()?.flush()?;

        // Mirror the persist path's confirm side-effects on the LOCAL MINING commit
        // path too: register this block's transactions in the replay registry (and
        // prune stale entries), and evict them from the in-memory mempool. Without
        // this a locally-mined transaction is absent from the replay registry (so it
        // could be replayed within the freshness window) and lingers in the mempool
        // to be re-selected into the very next block template.
        //
        // Ordered BEFORE clear_chain_state_dirty (like the persist path): a crash
        // between the block commit and these derived-state writes must leave the
        // dirty marker set so startup recovery force-rebuilds the registry and the
        // address index instead of silently missing this block's entries.
        let _ = self.record_confirmed_txs(&block);
        let _ = self.prune_confirmed_txs(block.timestamp);
        {
            let mut mempool = self.mempool.write().await;
            for tx in &block.transactions {
                mempool.clear_transaction(tx);
            }
        }
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
        let Some(tip) = self.highest_block_index() else {
            return Ok(true);
        };

        // Stream one block at a time by height instead of materialising the whole
        // chain into a Vec — peak RAM is O(1) regardless of chain length. Missing
        // heights are skipped just as scan_prefix omits them, so a gap still surfaces
        // as a previous_hash mismatch against the last block that did load.
        let mut previous_block: Option<Block> = None;
        for h in 0..=tip {
            let Ok(current_block) = self.get_block(h) else {
                continue;
            };

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

        // M06 (advisory): for mempool admission (block=None) don't offer to spend an immature
        // reward at the prospective next height. The block=Some path is a local-miner check
        // already covered by gate (1) / the finalize inline check, so it stays 0 here.
        let immature = match block {
            None => {
                let h = self.get_latest_block_index() as u64 + 1;
                self.immature_reward_units_scan(&tx.sender, h, &[])
            }
            Some(_) => 0,
        };
        let available_balance = Transaction::to_units(confirmed_balance - pending_amount) - immature;
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

        // Bound transactions per block (DoS): reject an over-full block before any
        // further per-transaction work. Finalized history is small and unaffected.
        if block.transactions.len() > MAX_BLOCK_TX_COUNT {
            return Err(BlockchainError::InvalidBlockHeader);
        }

        // Verify merkle root matches transactions
        let expected_root = Blockchain::calculate_merkle_root(&block.transactions)?;
        if expected_root != block.merkle_root {
            return Err(BlockchainError::InvalidBlockHeader);
        }

        // Check the hash meets the difficulty requirement
        if !self.is_valid_hash_with_difficulty(&block.hash, block.difficulty) {
            return Err(BlockchainError::InvalidHash);
        }

        // Pin genesis: the only valid block at height 0 is the deterministic launch
        // genesis. Without this a fresh node (tip==0) could be forked onto an
        // attacker chain rooted at a forged genesis — every subsequent block would
        // link cleanly to the fake root. Pinning the root makes that impossible.
        if block.index == 0 && block.hash != Self::genesis_launch_block()?.hash {
            return Err(BlockchainError::InvalidBlockHeader);
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
            // Complete the linkage check independent of the caller: the referenced parent must
            // sit exactly one height below. get_parent_block_for can resolve an orphan at a
            // different height whose hash happens to match, so without this a structurally
            // invalid (height, parent) pair could slip through this canonical gate.
            if parent.index != block.index.saturating_sub(1) {
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
            // Self-sufficient amount gate (L35): min amount, fee >= 0, and no
            // amount+fee overflow — so the canonical gate does not depend on an
            // earlier prevalidate call having run. Every confirmed block already
            // satisfies this (all live persist paths prevalidate first), so nothing
            // in history is newly rejected.
            if !tx.has_valid_regular_amounts() {
                return Err(BlockchainError::InvalidTransactionAmount);
            }
            // Transaction freshness: a non-system transaction must be mined within
            // MAX_TX_AGE_SECS of its signed timestamp and not be dated meaningfully
            // ahead of the block. This expires stale transactions — which is what
            // keeps the replay registry bounded to a recent window — while making
            // replay of an old confirmed transaction impossible (a block re-including
            // it would fail this same check). Grandfathered for finalized history,
            // which validate_block_internal is never re-run over.
            if block.index > 0 {
                if tx.timestamp.saturating_add(MAX_TX_AGE_SECS) < block.timestamp {
                    return Err(BlockchainError::InvalidTransaction);
                }
                if tx.timestamp > block.timestamp.saturating_add(MAX_BLOCK_FUTURE_TIME) {
                    return Err(BlockchainError::InvalidTransaction);
                }
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

            // M06 (defense-in-depth): reject a candidate block that spends an immature reward.
            let immature =
                self.immature_reward_units_scan(&tx.sender, block.index as u64, &block.transactions);
            let available_balance = current_confirmed - pending_deducted - immature;
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

        // ALREADY-CONFIRMED gate (one cheap registry read): a tx that is already in
        // a canonical block must never re-enter the mempool. Without this, a
        // confirmed tx bounces back in (peer gossip echo, the periodic re-announce,
        // reorg mempool reconciliation) and poisons every block template built from
        // this mempool — the miner grinds the full nonce window and finalize rejects
        // the block via the replay guard, repeatedly, while miners without the stale
        // tx win every height (the 2026-07-09 "Transaction is invalid" mining loop).
        // Rejecting at admission kills the loop at every entry point at once, since
        // all of them funnel through here.
        if self.confirmed_tx_index(&transaction.get_tx_id()).is_some() {
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

        // Reject self-transfers at mempool admission (L06): sender == recipient is a
        // near-free block/mempool filler (it only burns the fee) and enforces the
        // long-defined SelfTransferNotAllowed intent. Kept to admission only — a
        // block-validation reject would change block validity and could reject any
        // self-transfer already in chain history, so it is not done here.
        if transaction.sender == transaction.recipient {
            return Err(BlockchainError::SelfTransferNotAllowed);
        }

        // Reject reserved-key collisions at mempool admission (L53): a real address is
        // 40 lowercase hex chars, so it can never begin with the "__" prefix used for
        // internal balances-tree markers (e.g. BALANCES_HEIGHT_KEY = "__height"). A tx
        // crediting such a string would clobber that marker when the balances index is
        // rebuilt. Admission-only, like the self-transfer guard above, so block validity
        // is unchanged (a block-validation reject could fork on any such tx already in
        // chain history).
        if transaction.sender.starts_with("__") || transaction.recipient.starts_with("__") {
            return Err(BlockchainError::InvalidTransaction);
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

        // M06 (advisory): don't admit a tx that spends an immature reward at the next height.
        let immature = self.immature_reward_units_scan(
            &transaction.sender,
            self.get_latest_block_index() as u64 + 1,
            &[],
        );
        let available_balance =
            Transaction::to_units(confirmed_balance - pending_amount) - immature;
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
        let now = Self::now_unix_secs();
        mempool
            .get_transactions_for_block()
            .into_iter()
            .filter(|tx| {
                // Never select a transaction the consensus freshness rule
                // (MAX_TX_AGE_SECS) would reject — it would only get the whole
                // mined block rejected. System transactions have no user timestamp.
                SYSTEM_ADDRESSES.contains(&tx.sender.as_str())
                    || tx.timestamp.saturating_add(MAX_TX_AGE_SECS) >= now
            })
            .collect()
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
        // Windowed estimate over the last 32 intervals. The old 2-block sample
        // broke down at a fast block time: consecutive blocks routinely share a
        // 1-second timestamp, so time_diff was 0 and the reported hashrate was a
        // hard 0 even while difficulty climbed past 550 (the "hashrate 0 but
        // difficulty rising" confusion) — and when it did fire, one noisy interval
        // swung it wildly. Sum expected work per block and divide by the span.
        const WINDOW: u32 = 32;
        let Some(tip) = self.get_last_block() else {
            return 0.0;
        };
        let start_index = tip.index.saturating_sub(WINDOW);
        let Ok(start_block) = self.get_block(start_index) else {
            return 0.0;
        };
        let span = tip.timestamp.saturating_sub(start_block.timestamp);
        if span == 0 || tip.index == start_index {
            return 0.0;
        }
        let mut expected_hashes = 0.0f64;
        for h in (start_index + 1)..=tip.index {
            if let Ok(b) = self.get_block(h) {
                let target = pow_target_from_difficulty(b.difficulty);
                expected_hashes +=
                    MAX_TARGET.to_f64().unwrap_or(0.0) / target.to_f64().unwrap_or(1.0);
            }
        }
        (expected_hashes / span as f64) / 1_000_000_000_000.0 // TH/s
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

        // Coinbase-maturity overlay (M06) for this tip-extension apply. Precomputed once per
        // block: the still-immature MINING_REWARDS credited to each address = this block's own
        // coinbase (depth 0; not yet in storage, so sourced from `transactions`) plus stored
        // canonical rewards in [confirm_height-MATURITY+1, confirm_height-1]. Subtracted from
        // spendable at the affordability compare below; the stored ledger stays RAW. The
        // current block's coinbase cancels: it is +amount in balance_changes and +amount here,
        // so it nets out of spendable — a same-block spend of the fresh reward is blocked.
        // No-op below the activation height, so all pre-activation history applies unchanged.
        let mut immature_by_addr: HashMap<String, i128> = HashMap::new();
        if (confirm_height as u32) >= MATURITY_ACTIVATION_HEIGHT {
            for tx in &transactions {
                if tx.sender == "MINING_REWARDS" {
                    *immature_by_addr.entry(tx.recipient.clone()).or_default() += tx.amount_units;
                }
            }
            let low = confirm_height
                .saturating_sub(MINING_REWARD_MATURITY as u64)
                .saturating_add(1);
            for rh in low..confirm_height {
                if let Ok(b) = self.get_block(rh as u32) {
                    for tx in &b.transactions {
                        if tx.sender == "MINING_REWARDS" {
                            *immature_by_addr.entry(tx.recipient.clone()).or_default() +=
                                tx.amount_units;
                        }
                    }
                }
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
                    let immature = immature_by_addr.get(&tx.sender).copied().unwrap_or(0);

                    // Check if sufficient funds available (raw confirmed + intra-block change,
                    // minus any still-immature coinbase — M06).
                    if current_balance + pending_change - immature < total_debit {
                        return Err(BlockchainError::InsufficientFunds);
                    }

                    *balance_changes.entry(tx.sender.clone()).or_default() -= total_debit;
                    *balance_changes.entry(tx.recipient.clone()).or_default() += tx.amount_units;
                }
            }
        }

        // Apply all changes atomically — the balance deltas AND the advanced index
        // marker land in ONE batch, so the (content, marker) pair can never tear.
        // The marker is only trustworthy if it always equals the replay height of
        // the content; the O(gap) catch-up in ensure_balances_index relies on that
        // to apply exactly the missing blocks and nothing twice. Both callers
        // (persist_validated_block_with_mode, finalize_block) are strict tip
        // extensions guarded by the state-mutation lock, so confirm_height here is
        // always the new canonical tip.
        let mut batch = sled::Batch::default();
        for (address, change) in balance_changes {
            let current = current_balances.get(&address).copied().unwrap_or(0);
            let new_balance = current + change;
            batch.insert(address.as_bytes(), codec::serialize(&new_balance)?);
        }
        batch.insert(BALANCES_HEIGHT_KEY, codec::serialize(&confirm_height)?);

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

    /// Return a copy of `block` with every non-system transaction's full ML-DSA
    /// signature restored from the retained witness store, if available. Used
    /// before posting a block to the gateway relay so relay-only nodes (which
    /// have no p2p peer to fetch witnesses from) can still verify signatures
    /// instead of receipt-trusting the tip.
    pub fn block_with_full_witnesses(&self, block: &Block) -> Block {
        let mut hydrated = block.clone();
        for tx in &mut hydrated.transactions {
            if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                continue;
            }
            let tx_id = tx.get_tx_id();
            if let Some(full) = self.get_confirmed_witness_tx(&tx_id) {
                if full.signature.is_some() {
                    tx.signature = full.signature;
                }
            }
        }
        hydrated
    }

    /// Strict gate for adopting a block ABOVE the trusted checkpoint: EVERY
    /// non-system transaction must carry a full (non-truncated) ML-DSA signature
    /// that verifies. On the unfinalized frontier there is no receipt fast-path —
    /// a missing or truncated witness means we cannot prove the block, so we
    /// decline it rather than trust it. Coinbase (system) transactions are
    /// unsigned and exempt, so a coinbase-only block passes trivially.
    pub fn block_signatures_fully_verified(&self, block: &Block) -> bool {
        for tx in &block.transactions {
            if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                continue;
            }
            let full_sig_present = tx
                .signature
                .as_ref()
                .and_then(|s| hex::decode(s).ok())
                .map(|b| b.len() > 64)
                .unwrap_or(false);
            if !full_sig_present {
                return false;
            }
            if self.verify_transaction_signature(tx).is_err() {
                return false;
            }
        }
        true
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
        Ok(self.get_wallet_balance_breakdown(address).await?.spendable)
    }

    /// get_wallet_balance with its components kept separate (see WalletBalanceBreakdown).
    /// Same cost as get_wallet_balance — one confirmed read, one pending read, one
    /// maturity-window scan — so display callers can switch to this for free.
    pub async fn get_wallet_balance_breakdown(
        &self,
        address: &str,
    ) -> Result<WalletBalanceBreakdown, BlockchainError> {
        let confirmed = self.get_confirmed_balance(address).await?;
        let pending_debit = self.get_pending_debit_for(address).await?;
        // M06 (display): exclude still-immature rewards from the spendable balance the UI/send
        // flow offers — they'd be rejected at consensus. Prospective next height, no in-flight.
        let as_of_height = self.get_latest_block_index() as u64;
        let maturing_units = self.immature_coinbase_details(address, as_of_height + 1, &[]);
        let immature: i128 = maturing_units.iter().map(|(_, amt)| *amt).sum();
        let net_units = Transaction::to_units(confirmed)
            .saturating_sub(Transaction::to_units(pending_debit))
            .saturating_sub(immature);
        Ok(WalletBalanceBreakdown {
            confirmed,
            pending_debit,
            spendable: Transaction::from_units(net_units),
            maturing: maturing_units
                .into_iter()
                .map(|(height, amt)| (height, Transaction::from_units(amt)))
                .collect(),
            as_of_height,
        })
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

/// Role bits for an address-history entry. An entry carries both bits for a
/// self-send so it is stored (and counted) once.
pub const ADDRESS_TX_FLAG_SENDER: u8 = 0b01;
pub const ADDRESS_TX_FLAG_RECIPIENT: u8 = 0b10;

/// One confirmed transaction as seen from one address's point of view, decoded
/// from ADDRESS_TX_TREE. Self-contained for display (no block load needed);
/// `height`/`position` locate the full transaction in the chain when required.
#[derive(Debug, Clone, PartialEq)]
pub struct AddressTxEntry {
    pub height: u32,
    pub position: u32,
    pub flags: u8,
    pub amount_units: i128,
    pub fee_units: i128,
    pub timestamp: u64,
    pub counterparty: String,
}

impl AddressTxEntry {
    pub fn is_sender(&self) -> bool {
        self.flags & ADDRESS_TX_FLAG_SENDER != 0
    }
    pub fn is_recipient(&self) -> bool {
        self.flags & ADDRESS_TX_FLAG_RECIPIENT != 0
    }
}

/// Whole-chain accumulation over one address's ADDRESS_TX_TREE entries.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AddressHistorySummary {
    pub tx_count: u64,
    pub sent_units: i128,
    pub received_units: i128,
    pub fees_units: i128,
    pub first_height: Option<u32>,
    pub last_height: Option<u32>,
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

    /// Full from-genesis integrity walk. UNBOUNDED — cost grows with the chain
    /// (~17k blocks/day at 5s blocks), so this must never run on the block-apply
    /// path under the chain locks: it did until v7.7.6, firing every ~60s of
    /// ingest, and once the walk outgrew the lock-watchdog probe window it wedged
    /// nodes for minutes at a time (chain_ok=false strikes, 2026-07-10). Hot-path
    /// callers use verify_recent_chain_integrity below; this stays for callers
    /// that can afford unbounded time (audits, tests).
    pub async fn verify_chain_integrity(&self, blockchain: &Blockchain) -> bool {
        self.verify_chain_integrity_from(blockchain, 0).await
    }

    /// Bounded frontier variant for the hot persist path: the SAME three per-pair
    /// invariants (hash linkage, timestamp order, parent-linked difficulty) over
    /// only the last `window` blocks — the only region that can still change.
    /// Reorgs at/below the trusted checkpoint are rejected outright, and every
    /// stored block already passed full admission validation when it landed, so
    /// re-walking deep immutable history under the write lock bought nothing but
    /// the wedge. Each pair's verdict depends ONLY on that pair (the difficulty
    /// oracle records metrics; consensus_next_difficulty is parent-linked pure
    /// math), so starting mid-chain cannot flip any checked pair's outcome — a
    /// false failure here would reject a valid block, which is why this must stay
    /// semantically identical to the full walk over its window.
    pub async fn verify_recent_chain_integrity(
        &self,
        blockchain: &Blockchain,
        window: u32,
    ) -> bool {
        let Some(tip) = blockchain.highest_block_index() else {
            return true;
        };
        self.verify_chain_integrity_from(blockchain, tip.saturating_sub(window))
            .await
    }

    async fn verify_chain_integrity_from(&self, blockchain: &Blockchain, start: u32) -> bool {
        let Some(tip) = blockchain.highest_block_index() else {
            return true;
        };

        // Stream by height instead of loading the whole chain: peak RAM is O(1) and
        // the ascending order still feeds the difficulty oracle the same sequence.
        // Missing heights are skipped as scan_prefix would omit them, so a gap still
        // surfaces as a previous_hash mismatch against the last present block.
        // The first present block at/after `start` only seeds `prev`; pair checks
        // begin with its successor — identical shape at any starting height.
        let mut difficulty_oracle = DifficultyOracle::new();
        let mut prev: Option<([u8; 32], u64, u64)> = None; // (hash, timestamp, difficulty)

        for h in start..=tip {
            let Ok(block) = blockchain.get_block(h) else {
                continue;
            };

            let Some((prev_hash, prev_timestamp, prev_difficulty)) = prev else {
                prev = Some((block.hash, block.timestamp, block.difficulty));
                continue;
            };

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

            prev = Some((block.hash, block.timestamp, block.difficulty));
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

    /// Like metadata_test_block, but with regular transactions appended after the
    /// coinbase. Signatures are irrelevant here: the balances replay
    /// (replay_apply_block_checked) applies amounts only.
    fn test_block_with_txs(
        index: u32,
        previous_hash: [u8; 32],
        miner: &str,
        reward: f64,
        transfers: &[(&str, &str, f64)],
    ) -> Block {
        let mut transactions = vec![Transaction {
            sender: "MINING_REWARDS".to_string(),
            recipient: miner.to_string(),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: Transaction::to_units(reward),
            timestamp: 1_000 + index as u64,
            signature: None,
            pub_key: None,
            sig_hash: None,
        }];
        for (sender, recipient, amount) in transfers {
            transactions.push(Transaction {
                sender: sender.to_string(),
                recipient: recipient.to_string(),
                fee_units: Transaction::to_units(NETWORK_FEE),
                amount_units: Transaction::to_units(*amount),
                timestamp: 1_000 + index as u64,
                signature: None,
                pub_key: None,
                sig_hash: None,
            });
        }
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

    /// Every (address -> units) pair in the balances tree, marker excluded.
    /// Missing keys are semantically 0, so comparisons should go through
    /// balance_units_of over a key union rather than raw map equality.
    fn dump_balances(blockchain: &Blockchain) -> std::collections::BTreeMap<String, i128> {
        let tree = blockchain.db.open_tree(BALANCES_TREE).unwrap();
        let mut out = std::collections::BTreeMap::new();
        for item in tree.iter() {
            let (k, v) = item.unwrap();
            if k.as_ref() == BALANCES_HEIGHT_KEY {
                continue;
            }
            let addr = String::from_utf8(k.to_vec()).unwrap();
            out.insert(addr, Blockchain::deserialize_units_compatible(&v).unwrap());
        }
        out
    }

    #[test]
    fn replay_registry_flags_a_reused_transaction() {
        let bc = test_blockchain();
        let payment = Transaction {
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: Transaction::to_units(1.0),
            timestamp: 5_000,
            signature: Some("aa".repeat(2400)),
            pub_key: None,
            sig_hash: None,
        };

        // Confirm the payment in a block at height 5.
        let mut b5 = metadata_test_block(5, [0u8; 32], "miner", 1.0);
        b5.transactions.push(payment.clone());
        bc.record_confirmed_txs(&b5).unwrap();

        // Re-applying the SAME block at its own height is idempotent, not a replay.
        assert!(
            !bc.block_has_replayed_tx(&b5),
            "same-height re-apply must not be flagged"
        );

        // A later block re-including the exact same payment IS a replay.
        let mut b6 = metadata_test_block(6, b5.hash, "miner", 1.0);
        b6.transactions.push(payment.clone());
        assert!(
            bc.block_has_replayed_tx(&b6),
            "a replayed transaction must be flagged"
        );

        // A distinct payment (different timestamp -> different tx_id) is fine.
        let mut fresh = payment.clone();
        fresh.timestamp = 7_000;
        let mut b7 = metadata_test_block(7, [0u8; 32], "miner", 1.0);
        b7.transactions.push(fresh);
        assert!(
            !bc.block_has_replayed_tx(&b7),
            "a fresh transaction must not be flagged"
        );

        // Reverting height 5 unregisters it, so the same payment is admissible again.
        bc.remove_confirmed_txs(&b5).unwrap();
        assert!(
            !bc.block_has_replayed_tx(&b6),
            "after revert the transaction is no longer a replay"
        );
    }

    #[test]
    fn prune_retains_post_dated_tx_until_its_own_freshness_window_closes() {
        let bc = test_blockchain();
        // A transaction post-dated to the maximum future skew: its own timestamp is
        // MAX_BLOCK_FUTURE_TIME ahead of the block that confirms it (the freshness
        // rule permits this), yet its registry entry is keyed on the block timestamp.
        let block_ts = 1_000_000u64;
        let payment = Transaction {
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: Transaction::to_units(1.0),
            timestamp: block_ts + MAX_BLOCK_FUTURE_TIME,
            signature: Some("aa".repeat(2400)),
            pub_key: None,
            sig_hash: None,
        };
        let tx_id = payment.get_tx_id();

        let mut b = metadata_test_block(5, [0u8; 32], "miner", 1.0);
        b.timestamp = block_ts;
        b.transactions.push(payment.clone());
        bc.record_confirmed_txs(&b).unwrap();
        assert!(bc.confirmed_tx_index(&tx_id).is_some(), "entry must be registered");

        // At the block-timestamp horizon the transaction can STILL be replayed — its
        // own freshness window closes MAX_BLOCK_FUTURE_TIME later — so the registry
        // entry must survive. Keying prune on the block timestamp alone would drop it
        // here and reopen the double-spend.
        bc.prune_confirmed_txs(block_ts + MAX_TX_AGE_SECS).unwrap();
        assert!(
            bc.confirmed_tx_index(&tx_id).is_some(),
            "post-dated tx must not be pruned while a block can still replay it"
        );

        // Once the transaction's own freshness window has fully closed it can never be
        // replayed again, so it is safely pruned and the registry stays bounded.
        bc.prune_confirmed_txs(block_ts + MAX_BLOCK_FUTURE_TIME + MAX_TX_AGE_SECS + 1)
            .unwrap();
        assert!(
            bc.confirmed_tx_index(&tx_id).is_none(),
            "fully-expired tx should be pruned to keep the registry bounded"
        );
    }

    #[test]
    fn pow_floor_rejects_below_minimum_difficulty_at_ingress() {
        // A non-genesis block below the network minimum difficulty makes its PoW a
        // no-op; the ingress check must reject it even though the bare mechanism
        // "passes". Genesis (index 0) is pinned by hash and exempt.
        let mut block = metadata_test_block(1, [0u8; 32], "alice", 1.0);
        block.difficulty = 0;
        block.hash = block.calculate_hash_for_block();
        assert!(block.verify_pow(), "difficulty-0 PoW is trivially valid as a mechanism");
        assert!(
            !block.verify_pow_meets_floor(),
            "the ingress floor must reject a sub-minimum-difficulty block"
        );

        let mut genesis = metadata_test_block(0, [0u8; 32], "miner", 1.0);
        genesis.difficulty = 0;
        genesis.hash = genesis.calculate_hash_for_block();
        assert!(
            genesis.verify_pow_meets_floor(),
            "genesis is exempt from the floor (pinned by hash, not PoW)"
        );
    }

    #[test]
    fn trusted_checkpoint_is_monotonic_and_seeds_once() {
        let bc = test_blockchain();
        // Unseeded reads as 0.
        assert_eq!(bc.trusted_checkpoint_height(), 0);
        // raise_trusted_checkpoint only ever moves up — finality never regresses.
        bc.raise_trusted_checkpoint(100).unwrap();
        assert_eq!(bc.trusted_checkpoint_height(), 100);
        bc.raise_trusted_checkpoint(50).unwrap();
        assert_eq!(bc.trusted_checkpoint_height(), 100);
        bc.raise_trusted_checkpoint(100).unwrap();
        assert_eq!(bc.trusted_checkpoint_height(), 100);
        // advance_checkpoint_behind trails a verified frontier by the reorg margin.
        bc.advance_checkpoint_behind(100 + CHECKPOINT_REORG_MARGIN + 5)
            .unwrap();
        assert_eq!(bc.trusted_checkpoint_height(), 105);
        // A frontier height within the margin of the checkpoint cannot lower it.
        bc.advance_checkpoint_behind(120).unwrap();
        assert_eq!(bc.trusted_checkpoint_height(), 105);
        // Seeding is a no-op once any checkpoint exists.
        bc.seed_trusted_checkpoint_if_unset().unwrap();
        assert_eq!(bc.trusted_checkpoint_height(), 105);
    }

    #[test]
    fn verification_floor_never_drops_below_witness_loss_floor() {
        let bc = test_blockchain();
        // With no checkpoint recorded, the floor still sits at the witness-loss
        // height, so a node lagging beneath the permanently-truncated 34-35
        // receipt-trusts through them instead of stalling on the frontier gate.
        assert_eq!(bc.verification_floor(), WITNESS_LOSS_FLOOR);
        // Once the checkpoint rises above the floor, the checkpoint dominates.
        bc.raise_trusted_checkpoint(WITNESS_LOSS_FLOOR + 100).unwrap();
        assert_eq!(bc.verification_floor(), WITNESS_LOSS_FLOOR + 100);
    }

    #[test]
    fn frontier_verification_exempts_coinbase_and_rejects_unwitnessed_spend() {
        let bc = test_blockchain();
        // A coinbase-only block has no user signatures to prove, so it passes the
        // frontier gate trivially.
        let coinbase = metadata_test_block(1, [0u8; 32], "alice", 50.0);
        assert!(bc.block_signatures_fully_verified(&coinbase));
        // A block carrying a user-sender spend whose witness is absent/truncated
        // must be declined ABOVE the checkpoint: it cannot be proven, so it is not
        // trusted (this is exactly the S-01 forgery vector closed on the frontier).
        let mut with_spend = metadata_test_block(2, coinbase.hash, "bob", 50.0);
        with_spend.transactions.push(Transaction {
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: Transaction::to_units(1.0),
            timestamp: 2_000,
            signature: Some("deadbeef".to_string()), // 4 bytes: a truncated receipt stub
            pub_key: None,
            sig_hash: None,
        });
        assert!(!bc.block_signatures_fully_verified(&with_spend));
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

    // (G) The witness-blocked memo: record arms the backoff + stores R's fetch
    // list, backoff suppresses re-evaluation, snapshot exposes the queue, and
    // clear (R's success signal) removes it so the next ingest re-evaluates now.
    #[test]
    fn witness_blocked_memo_backoff_snapshot_and_clear() {
        let bc = test_blockchain();
        let tip_a = [0xAAu8; 32];
        let tip_b = [0xBBu8; 32];
        let needed = vec![(36373u32, [0x11u8; 32]), (36374u32, [0x22u8; 32])];

        // Not blocked initially.
        assert!(!bc.witness_branch_backoff_active(&tip_a));
        assert!(bc.witness_blocked_snapshot().is_empty());

        // Record -> backoff active, queued for R with the exact needed blocks.
        bc.record_witness_blocked(tip_a, needed.clone());
        assert!(bc.witness_branch_backoff_active(&tip_a));
        assert!(!bc.witness_branch_backoff_active(&tip_b), "unrelated branch unaffected");
        let snap = bc.witness_blocked_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, tip_a);
        assert_eq!(snap[0].1, 1, "first defer => attempts == 1");
        assert_eq!(snap[0].2, needed);

        // Re-record bumps the attempt counter (drives R's give-up -> B).
        bc.record_witness_blocked(tip_a, needed.clone());
        assert_eq!(bc.witness_blocked_snapshot()[0].1, 2);

        // Clear (R rehydrated) -> gone, next ingest re-evaluates immediately.
        bc.clear_witness_blocked(&tip_a);
        assert!(!bc.witness_branch_backoff_active(&tip_a));
        assert!(bc.witness_blocked_snapshot().is_empty());
    }

    // M06: the shared replay gate (used by both branch_is_balance_valid and
    // rebuild_balances_index) must block spending an immature coinbase above the activation
    // height, allow it once buried MATURITY deep, block a same-block spend of the fresh reward,
    // and be a no-op below the activation height (so existing history replays unchanged).
    #[test]
    fn reward_maturity_replay_gates_immature_and_respects_activation() {
        use std::collections::VecDeque;
        let coinbase = |to: &str, amt: i128| Transaction {
            sender: "MINING_REWARDS".to_string(),
            recipient: to.to_string(),
            fee_units: 0,
            amount_units: amt,
            timestamp: 1,
            signature: None,
            pub_key: None,
            sig_hash: None,
        };
        let spend = |from: &str, to: &str, amt: i128| Transaction {
            sender: from.to_string(),
            recipient: to.to_string(),
            fee_units: 0,
            amount_units: amt,
            timestamp: 1,
            signature: Some("sig".to_string()),
            pub_key: None,
            sig_hash: None,
        };
        let a = MATURITY_ACTIVATION_HEIGHT;
        let m = MINING_REWARD_MATURITY;

        // (1) Above activation, immature: reward at `a`, spend at a+m-1 (depth m-1) -> rejected.
        {
            let (mut bal, mut recent) = (HashMap::new(), VecDeque::new());
            Blockchain::replay_apply_block_checked(a, &[coinbase("A", 1000)], &mut bal, &mut recent)
                .unwrap();
            let r = Blockchain::replay_apply_block_checked(
                a + m - 1,
                &[spend("A", "B", 500)],
                &mut bal,
                &mut recent,
            );
            assert!(r.is_err(), "reward buried only m-1 deep must not be spendable");
        }
        // (2) Above activation, mature: reward at `a`, spend at a+m (depth m) -> allowed.
        {
            let (mut bal, mut recent) = (HashMap::new(), VecDeque::new());
            Blockchain::replay_apply_block_checked(a, &[coinbase("A", 1000)], &mut bal, &mut recent)
                .unwrap();
            let r = Blockchain::replay_apply_block_checked(
                a + m,
                &[spend("A", "B", 500)],
                &mut bal,
                &mut recent,
            );
            assert!(r.is_ok(), "reward buried m deep must be spendable");
            assert_eq!(*bal.get("A").unwrap(), 500);
        }
        // (3) Same-block spend of the freshly-mined coinbase is blocked.
        {
            let (mut bal, mut recent) = (HashMap::new(), VecDeque::new());
            let r = Blockchain::replay_apply_block_checked(
                a,
                &[coinbase("A", 1000), spend("A", "B", 500)],
                &mut bal,
                &mut recent,
            );
            assert!(r.is_err(), "spending the fresh coinbase in its own block must be rejected");
        }
        // (4) Below activation: identical immediate-spend scenario is unchanged (overlay off).
        {
            let (mut bal, mut recent) = (HashMap::new(), VecDeque::new());
            let r = Blockchain::replay_apply_block_checked(
                a - 1,
                &[coinbase("A", 1000), spend("A", "B", 500)],
                &mut bal,
                &mut recent,
            );
            assert!(r.is_ok(), "below activation, an immediate reward spend must still be allowed");
            assert_eq!(*bal.get("A").unwrap(), 500);
        }
    }

    // M06: the scan overlay (tip-extension/advisory gates) and the replay overlay (reorg/rebuild
    // gates) must compute the SAME immature total for the same chain — otherwise a reorg whose
    // dry-run passes could fail the authoritative rebuild after slots are rewritten. Cross-check
    // them on a window straddling the maturity boundary.
    #[test]
    fn reward_maturity_scan_matches_replay_over_window() {
        use std::collections::VecDeque;
        let bc = test_blockchain();
        let a = MATURITY_ACTIVATION_HEIGHT;
        let m = MINING_REWARD_MATURITY;
        // Reward blocks: one just old enough to be mature at `spend_h`, one still immature.
        let spend_h = a + m; // spend height
        let mature_reward_h = spend_h - m; // exactly m deep -> mature
        let immature_reward_h = spend_h - 1; // 1 deep -> immature
        let coinbase_block = |idx: u32, amt: i128| {
            let mut b = metadata_test_block(idx, [0u8; 32], "miner", 1.0);
            // Replace the block's transactions with a single explicit coinbase to "X".
            b.transactions = vec![Transaction {
                sender: "MINING_REWARDS".to_string(),
                recipient: "X".to_string(),
                fee_units: 0,
                amount_units: amt,
                timestamp: 1,
                signature: None,
                pub_key: None,
                sig_hash: None,
            }];
            b
        };
        let mature = coinbase_block(mature_reward_h, 700);
        let immature = coinbase_block(immature_reward_h, 900);
        insert_raw_block(&bc, &mature);
        insert_raw_block(&bc, &immature);

        // Scan at spend_h: only the immature (spend_h-1) reward counts; the mature one aged out.
        let scanned = bc.immature_reward_units_scan("X", spend_h as u64, &[]);
        assert_eq!(scanned, 900, "only the reward < MATURITY deep is immature");

        // Replay the same two blocks through the replay helper and read its `recent` window.
        let (mut bal, mut recent): (HashMap<String, i128>, VecDeque<(u32, String, i128)>) =
            (HashMap::new(), VecDeque::new());
        Blockchain::replay_apply_block_checked(
            mature_reward_h,
            &mature.transactions,
            &mut bal,
            &mut recent,
        )
        .unwrap();
        Blockchain::replay_apply_block_checked(
            immature_reward_h,
            &immature.transactions,
            &mut bal,
            &mut recent,
        )
        .unwrap();
        // At spend_h the mature reward (spend_h-m) is purged when a block at spend_h is applied;
        // emulate the purge boundary: entries with rh + m <= spend_h are mature.
        let replay_immature: i128 = recent
            .iter()
            .filter(|(rh, r, _)| r == "X" && (*rh as u64) + m as u64 > spend_h as u64)
            .map(|(_, _, amt)| *amt)
            .sum();
        assert_eq!(replay_immature, scanned, "scan and replay must agree on the immature total");
    }

    /// Display breakdown (WalletBalanceBreakdown): the maturing list must be exactly the
    /// M06 overlay set — same 100-block window, same boundaries — and `spendable` must
    /// equal get_wallet_balance (which delegates to the breakdown). Pins the "credited
    /// but not yet spendable" display contract, both window edges, and the oldest reward
    /// crossing the maturity boundary exactly one block later.
    #[tokio::test]
    async fn wallet_balance_breakdown_surfaces_maturing_coinbases() {
        let bc = test_blockchain();
        let act = MATURITY_ACTIVATION_HEIGHT;
        let m = MINING_REWARD_MATURITY; // 100
        let tip = act + 10; // 1510
        // Contiguous chain 0..=tip; "M" mines four blocks around the maturity window:
        // two already mature at the tip (outside the window), one at the window's lower
        // edge, one at the tip itself.
        let m_blocks: HashMap<u32, f64> = [
            (act - 200, 2.0),   // 1300: long mature
            (tip - m + 1, 3.0), // 1411: exactly below the window (low edge is 1412)
            (tip - m + 2, 5.0), // 1412: oldest still-immature -> matures next block
            (tip, 7.0),         // 1510: fresh at the tip
        ]
        .into_iter()
        .collect();
        let mut prev = [0u8; 32];
        for h in 0..=tip {
            let (miner, amount) = match m_blocks.get(&h) {
                Some(amount) => ("M", *amount),
                None => ("other", 1.0),
            };
            let b = metadata_test_block(h, prev, miner, amount);
            prev = b.hash;
            insert_raw_block(&bc, &b);
        }
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.ensure_balances_index().await.unwrap();

        let breakdown = bc.get_wallet_balance_breakdown("M").await.unwrap();
        assert_eq!(breakdown.as_of_height, tip as u64);
        assert_eq!(
            breakdown.maturing,
            vec![(tip - m + 2, 5.0), (tip, 7.0)],
            "exactly the coinbases inside the maturity window, ascending by height"
        );
        assert_eq!(breakdown.confirmed, 17.0, "confirmed includes immature coinbases");
        assert_eq!(breakdown.spendable, 5.0, "spendable excludes the maturing portion");
        assert_eq!(
            breakdown.spendable,
            bc.get_wallet_balance("M").await.unwrap(),
            "get_wallet_balance must be exactly the breakdown's spendable"
        );

        // One more block and the 1412 reward crosses the boundary (tip reaches rh+m-1).
        let next = metadata_test_block(tip + 1, prev, "other", 1.0);
        insert_raw_block(&bc, &next);
        bc.rebuild_chain_tip_metadata().unwrap();
        let after = bc.get_wallet_balance_breakdown("M").await.unwrap();
        assert_eq!(
            after.maturing,
            vec![(tip, 7.0)],
            "oldest maturing reward must leave the set exactly one block later"
        );
        assert_eq!(after.spendable, 10.0, "the just-matured reward becomes spendable");
    }

    /// Below the M06 activation height the overlay is off: a fresh coinbase is spendable
    /// immediately and the breakdown reports nothing maturing.
    #[tokio::test]
    async fn wallet_balance_breakdown_empty_below_activation() {
        let bc = test_blockchain();
        let mut prev = [0u8; 32];
        for h in 0..=10u32 {
            let b = metadata_test_block(h, prev, if h == 10 { "M" } else { "other" }, 4.0);
            prev = b.hash;
            insert_raw_block(&bc, &b);
        }
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.ensure_balances_index().await.unwrap();
        let breakdown = bc.get_wallet_balance_breakdown("M").await.unwrap();
        assert!(breakdown.maturing.is_empty(), "overlay is a no-op below activation");
        assert_eq!(breakdown.confirmed, 4.0);
        assert_eq!(
            breakdown.spendable, 4.0,
            "fresh coinbase is spendable at once below activation"
        );
    }

    // Regression for the mining-loop reentrant deadlock (the permanent freeze when a
    // miner loses a block race). The finalize error path used to call
    // self.blockchain.read().await while STILL holding the write guard it took for
    // finalize_block; tokio's RwLock is non-reentrant + write-preferring, so that
    // second acquire can never be granted -> the task waits on itself forever. The
    // fix reads the tip through the already-held guard. This pins both behaviours.
    #[tokio::test]
    async fn mining_finalize_error_path_must_not_reacquire_blockchain_lock() {
        use std::time::Duration;
        let blockchain = Arc::new(RwLock::new(test_blockchain()));

        // FIXED pattern: read the tip through the write guard already held. Completes.
        let fixed = tokio::time::timeout(Duration::from_secs(5), async {
            let guard = blockchain.write().await;
            let _tip = guard.get_last_block(); // &self via the held guard — no reentrancy
            drop(guard);
        })
        .await;
        assert!(fixed.is_ok(), "reusing the held write guard must not deadlock");

        // OLD (removed) pattern: acquire a second guard on the same lock while the
        // write guard is held. Must never be granted -> times out (i.e. deadlocked).
        let reentrant = tokio::time::timeout(Duration::from_secs(2), async {
            let guard = blockchain.write().await;
            let _second = blockchain.read().await; // the bug this fix removes
            drop(guard);
        })
        .await;
        assert!(
            reentrant.is_err(),
            "write-guard-held + read on the same lock must deadlock (proves the removed bug)"
        );
    }

    // Exact reproduction of the user-reported freeze: a PENDING transaction in the
    // mempool (which drives tx-selection through get_confirmed_balance -> the old
    // write-lock-across-await, bug 2) PLUS a competing block that makes the loser hit
    // the finalize error path (the old reentrant self-deadlock, bug 1). Two real
    // miners race for block #1 with the same pending tx queued; both must complete.
    //   cargo test --release racing_miners_with_pending_tx -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "real ProgPoW mining at the 464 floor; run with --ignored"]
    async fn racing_miners_with_pending_tx_both_complete() {
        use crate::a9::miner::{BlockHeader, MiningManager, ProgPowTransaction};
        use std::time::Duration;

        let blockchain = Arc::new(RwLock::new(test_blockchain()));
        let genesis = Blockchain::genesis_launch_block().expect("genesis builds");
        {
            let g = blockchain.read().await;
            insert_raw_block(&g, &genesis);
        }

        // Fund a wallet and queue a real signed pending transaction — a non-empty
        // mempool is the exact trigger (empty mempool never hit the freeze).
        let wallet = Wallet::new(None).expect("wallet builds");
        {
            let g = blockchain.read().await;
            set_confirmed_balance(&g, &wallet.address, Transaction::to_units(1000.0));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let tx = signed_transfer(&wallet, "recipient_addr_for_test", 120.0, now).await;
        {
            let g = blockchain.read().await;
            g.add_transaction(tx.clone())
                .await
                .expect("pending tx should be admitted");
        }
        // Build the ProgPow tx from the MEMPOOL entry exactly like the real miner,
        // so it carries the sig_hash add_transaction computes on admission.
        let ptx = {
            let g = blockchain.read().await;
            let mtxs = g.get_mempool_transactions().await.expect("mempool loads");
            let mtx = mtxs
                .into_iter()
                .find(|t| t.sender == wallet.address)
                .expect("our pending tx is in the mempool");
            ProgPowTransaction {
                fee: mtx.fee(),
                sender: mtx.sender.clone(),
                recipient: mtx.recipient.clone(),
                amount: mtx.amount(),
                timestamp: mtx.timestamp,
                signature: mtx.signature.clone(),
                pub_key: mtx.pub_key.clone(),
                sig_hash: mtx.sig_hash.clone(),
            }
        };

        let header = || BlockHeader {
            number: 1,
            parent_hash: genesis.hash,
            timestamp: now,
            merkle_root: [0u8; 32],
            difficulty: NETWORK_MIN_DIFFICULTY,
        };
        let mgr_a = MiningManager::new(Arc::clone(&blockchain));
        let mgr_b = MiningManager::new(Arc::clone(&blockchain));
        let (ha, hb) = (header(), header());
        let (ta, tb) = (vec![ptx.clone()], vec![ptx]);

        let task_a = tokio::spawn(async move {
            let mut h = ha;
            mgr_a
                .mine_block(&mut h, &ta, 1u64 << 26, "miner_a".to_string(), 0.0)
                .await
        });
        let task_b = tokio::spawn(async move {
            let mut h = hb;
            mgr_b
                .mine_block(&mut h, &tb, 1u64 << 26, "miner_b".to_string(), 0.0)
                .await
        });

        let (ra, rb) = tokio::time::timeout(Duration::from_secs(120), async {
            tokio::try_join!(task_a, task_b)
        })
        .await
        .expect("FREEZE: a miner hung with a pending tx + a competing block (120s timeout)")
        .expect("mining tasks should not panic");

        // The reported bug was a PERMANENT hang; both miners returning within the
        // timeout above is the anti-freeze guarantee. At least the race winner must
        // have mined a block. The loser may legitimately fail to re-mine the same
        // now-confirmed tx here because this test passes a FIXED template to
        // mine_block — the real node re-reads the mempool per block, so it would
        // simply build the next template without the evicted tx.
        assert!(
            ra.is_ok() || rb.is_ok(),
            "at least one miner must mine a block; both failed: {:?} / {:?}",
            ra.err(),
            rb.err()
        );
    }

    // End-to-end proof that a miner which LOSES a block race recovers and completes
    // instead of freezing. Two real miners race for block #1 on the same chain; the
    // loser's finalize returns InvalidBlockHeader (tip already advanced) and must
    // recover onto the next height rather than deadlocking. Real ProgPoW at the 464
    // floor takes tens of seconds, so this is #[ignore]d — run it explicitly with:
    //   cargo test --release racing_miners_both_complete -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "real ProgPoW mining at the 464 floor; run with --ignored"]
    async fn racing_miners_both_complete_loser_recovers() {
        use crate::a9::miner::{BlockHeader, MiningManager, ProgPowTransaction};
        use std::time::Duration;

        let blockchain = Arc::new(RwLock::new(test_blockchain()));
        let genesis = Blockchain::genesis_launch_block().expect("genesis builds");
        {
            let g = blockchain.read().await;
            insert_raw_block(&g, &genesis);
        }

        let header = || BlockHeader {
            number: 1,
            parent_hash: genesis.hash,
            timestamp: genesis.timestamp + 5,
            merkle_root: [0u8; 32],
            difficulty: NETWORK_MIN_DIFFICULTY,
        };
        let no_txs: Vec<ProgPowTransaction> = Vec::new();

        let mgr_a = MiningManager::new(Arc::clone(&blockchain));
        let mgr_b = MiningManager::new(Arc::clone(&blockchain));
        let (ha, hb) = (header(), header());
        let (txs_a, txs_b) = (no_txs.clone(), no_txs);

        let task_a = tokio::spawn(async move {
            let mut h = ha;
            mgr_a
                .mine_block(&mut h, &txs_a, 1u64 << 26, "miner_a".to_string(), 0.0)
                .await
        });
        let task_b = tokio::spawn(async move {
            let mut h = hb;
            mgr_b
                .mine_block(&mut h, &txs_b, 1u64 << 26, "miner_b".to_string(), 0.0)
                .await
        });

        let joined = tokio::time::timeout(Duration::from_secs(240), async {
            tokio::try_join!(task_a, task_b)
        })
        .await
        .expect("neither miner may hang: the loser must recover from the lost race")
        .expect("mining tasks should not panic");

        assert!(joined.0.is_ok(), "miner A should complete: {:?}", joined.0.err());
        assert!(joined.1.is_ok(), "miner B should complete: {:?}", joined.1.err());
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
    fn convergence_gate_breaks_equal_work_ties_by_lowest_hash() {
        // Regression for the "won't catch up / 3-of-4 agreement" fork. Two miners producing a
        // same-height, floor-difficulty (equal-work) block must deterministically converge on
        // the lowest-hash tip. The beacon/relay convergence path (external_branch_wins_fork_choice)
        // must therefore adopt a same-height EQUAL-work competitor iff its tip hash is strictly
        // lower — matching try_adopt_orphan_branch — otherwise beacon-only nodes stay split from
        // the directly-P2P-meshed nodes forever. The previous strict-`>` gate returned false on
        // every tie and never reorged.
        let blockchain = test_blockchain();
        let block0 = metadata_test_block(0, [0u8; 32], "b0", 1.0);
        let block1 = metadata_test_block(1, block0.hash, "ancestor", 1.0);

        // Three same-height (2), equal-work competitors off `block1`, ordered by hash so we can
        // name lowest / middle / highest deterministically regardless of how they hash.
        let mut competitors = vec![
            metadata_test_block(2, block1.hash, "comp_a", 1.0),
            metadata_test_block(2, block1.hash, "comp_b", 1.0),
            metadata_test_block(2, block1.hash, "comp_c", 1.0),
        ];
        competitors.sort_by(|a, b| a.hash.cmp(&b.hash));
        let lowest = competitors[0].clone();
        let middle = competitors[1].clone();
        let highest = competitors[2].clone();
        assert!(lowest.hash < middle.hash && middle.hash < highest.hash);

        // Local node holds the MIDDLE-hash block at the tip (height 2).
        insert_raw_block(&blockchain, &block0);
        insert_raw_block(&blockchain, &block1);
        insert_raw_block(&blockchain, &middle);

        // Equal work, same height, strictly LOWER hash -> adopt (the fix).
        assert!(
            blockchain.external_branch_wins_fork_choice(&[lowest.clone()], 1, 2),
            "must adopt a same-height equal-work competitor with a strictly lower tip hash"
        );
        // Equal work, same height, strictly HIGHER hash -> keep ours.
        assert!(
            !blockchain.external_branch_wins_fork_choice(&[highest.clone()], 1, 2),
            "must NOT reorg to a higher-hash same-height equal-work competitor"
        );
        // Our own tip (equal hash) never 'wins' over itself -> no needless reorg/flap.
        assert!(
            !blockchain.external_branch_wins_fork_choice(&[middle.clone()], 1, 2),
            "equal hash is not strictly lower -> no reorg"
        );

        // Strictly HEAVIER (taller) branch -> adopt regardless of tip hash ordering.
        let heavier_child = metadata_test_block(3, highest.hash, "child", 1.0);
        assert!(
            blockchain.external_branch_wins_fork_choice(&[highest.clone(), heavier_child], 1, 2),
            "a strictly heavier (taller) branch must be adopted"
        );

        // Strictly LIGHTER branch -> never adopt, even with a lower tip hash. Extend the local
        // chain to height 3 so the local span [2..=3] outweighs a single height-2 competitor.
        let local3 = metadata_test_block(3, middle.hash, "local3", 1.0);
        insert_raw_block(&blockchain, &local3);
        assert!(
            !blockchain.external_branch_wins_fork_choice(&[lowest.clone()], 1, 3),
            "a strictly lighter branch must never be adopted, even with a lower tip hash"
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

    /// Valid chain builder for sentinel tests: same spacing/difficulty recipe as
    /// the passing two-block test above (constant target-time spacing pins the
    /// consensus difficulty at NETWORK_MIN_DIFFICULTY after genesis), extended to
    /// arbitrary length.
    fn build_valid_sentinel_chain(blockchain: &Blockchain, len: u32) -> Vec<Block> {
        let genesis = Blockchain::genesis_launch_block().expect("genesis should build");
        insert_raw_block(blockchain, &genesis);
        let mut blocks = vec![genesis];
        for i in 1..len {
            let prev = blocks.last().unwrap();
            let mut b = metadata_test_block(i, prev.hash, &format!("m{i}"), 1.0);
            b.timestamp = prev.timestamp + TARGET_BLOCK_TIME * 1_000;
            b.difficulty = NETWORK_MIN_DIFFICULTY;
            b.hash = b.calculate_hash_for_block();
            insert_raw_block(blockchain, &b);
            blocks.push(b);
        }
        blockchain.rebuild_chain_tip_metadata().unwrap();
        blocks
    }

    /// The frontier check must catch corruption INSIDE its window exactly like
    /// the full walk does.
    #[tokio::test]
    async fn frontier_integrity_detects_recent_corruption() {
        let bc = test_blockchain();
        let blocks = build_valid_sentinel_chain(&bc, 300);
        let sentinel = ChainSentinel::new();
        assert!(
            sentinel
                .verify_recent_chain_integrity(&bc, INTEGRITY_FRONTIER_WINDOW)
                .await
        );

        // Tamper a block near the tip: break its parent linkage.
        let mut bad = blocks[297].clone();
        bad.previous_hash = [0xEEu8; 32];
        bad.hash = bad.calculate_hash_for_block();
        insert_raw_block(&bc, &bad);

        assert!(
            !sentinel
                .verify_recent_chain_integrity(&bc, INTEGRITY_FRONTIER_WINDOW)
                .await,
            "frontier check must catch corruption inside its window"
        );
        assert!(!sentinel.verify_chain_integrity(&bc).await);
    }

    /// The frontier check is genuinely BOUNDED: corruption below the window is
    /// deliberately out of its scope (deep history is checkpoint-final and was
    /// admission-validated on arrival) — the full walk still catches it. This
    /// documents the coverage trade the hot path makes for a fixed lock-held cost.
    #[tokio::test]
    async fn frontier_integrity_is_bounded_full_walk_still_catches_deep() {
        let bc = test_blockchain();
        let blocks = build_valid_sentinel_chain(&bc, 300);
        let sentinel = ChainSentinel::new();

        // Corrupt DEEP history (height 10, far below tip-256).
        let mut bad = blocks[10].clone();
        bad.previous_hash = [0xEEu8; 32];
        bad.hash = bad.calculate_hash_for_block();
        insert_raw_block(&bc, &bad);

        assert!(
            sentinel
                .verify_recent_chain_integrity(&bc, INTEGRITY_FRONTIER_WINDOW)
                .await,
            "frontier check is windowed by design; deep corruption is the full walk's job"
        );
        assert!(
            !sentinel.verify_chain_integrity(&bc).await,
            "full walk must still catch deep corruption"
        );
    }

    /// A mid-chain start must NEVER flip a valid pair to invalid — a false
    /// integrity failure on the persist path would reject a valid block. Verify
    /// the windowed walk passes from every kind of starting offset on a chain
    /// the full walk accepts.
    #[tokio::test]
    async fn frontier_integrity_no_false_failures_at_any_start() {
        let bc = test_blockchain();
        let _ = build_valid_sentinel_chain(&bc, 300);
        let sentinel = ChainSentinel::new();
        assert!(sentinel.verify_chain_integrity(&bc).await);
        for start in [0u32, 1, 7, 100, 250, 298, 299] {
            assert!(
                sentinel.verify_chain_integrity_from(&bc, start).await,
                "false integrity failure starting at height {start}"
            );
        }
        // And through the public windowed API at several window sizes.
        for window in [0u32, 1, 5, 256, 1000] {
            assert!(
                sentinel.verify_recent_chain_integrity(&bc, window).await,
                "false integrity failure with window {window}"
            );
        }
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

    /// The O(gap) catch-up must produce exactly the values a from-genesis full
    /// rebuild produces — same replay function, same integer arithmetic — across
    /// regular transfers, multiple txs per block, and repeated same-sender spends.
    /// The sentinel key proves the CATCH-UP path ran (a full rebuild removes keys
    /// absent from its replay map; catch-up never removes).
    #[tokio::test]
    async fn balances_catch_up_matches_full_rebuild() {
        let build_chain = || -> Vec<Block> {
            let mut blocks = Vec::new();
            let mut prev = [0u8; 32];
            // Blocks 0..=3: fund alice and bob via coinbase.
            for (i, miner) in [(0u32, "alice"), (1, "bob"), (2, "alice"), (3, "carol")] {
                let b = metadata_test_block(i, prev, miner, 10.0);
                prev = b.hash;
                blocks.push(b);
            }
            // Block 4: two transfers in one block, one shared sender.
            let b4 = test_block_with_txs(
                4,
                prev,
                "miner4",
                10.0,
                &[("alice", "dave", 3.0), ("alice", "bob", 2.0)],
            );
            prev = b4.hash;
            blocks.push(b4);
            // Block 5: chained transfer of freshly received funds.
            let b5 = test_block_with_txs(5, prev, "miner5", 10.0, &[("dave", "erin", 1.0)]);
            prev = b5.hash;
            blocks.push(b5);
            // Blocks 6..=8: more coinbase + a bob spend.
            let b6 = metadata_test_block(6, prev, "bob", 10.0);
            prev = b6.hash;
            blocks.push(b6);
            let b7 = test_block_with_txs(7, prev, "miner7", 10.0, &[("bob", "frank", 7.5)]);
            prev = b7.hash;
            blocks.push(b7);
            let b8 = metadata_test_block(8, prev, "alice", 10.0);
            blocks.push(b8);
            blocks
        };

        // Instance A: index built through height 3, then blocks 4..=8 arrive raw —
        // ensure must close the gap via catch-up.
        let a = test_blockchain();
        let chain = build_chain();
        for b in &chain[..=3] {
            insert_raw_block(&a, b);
        }
        a.rebuild_chain_tip_metadata().unwrap();
        a.ensure_balances_index().await.unwrap();
        let a_tree = a.db.open_tree(BALANCES_TREE).unwrap();
        assert_eq!(Blockchain::get_balances_height(&a_tree).unwrap(), Some(3));
        // Sentinel: survives catch-up, would be removed by a full rebuild.
        a_tree
            .insert("zz_sentinel".as_bytes(), codec::serialize(&777i128).unwrap())
            .unwrap();
        for b in &chain[4..] {
            insert_raw_block(&a, b);
        }
        a.rebuild_chain_tip_metadata().unwrap();
        a.ensure_balances_index().await.unwrap();
        assert_eq!(Blockchain::get_balances_height(&a_tree).unwrap(), Some(8));
        assert_eq!(
            a_tree.get("zz_sentinel".as_bytes()).unwrap().map(|v| v.to_vec()),
            Some(codec::serialize(&777i128).unwrap()),
            "catch-up path should have run (full rebuild would remove the sentinel)"
        );

        // Instance B: identical chain, single from-genesis rebuild.
        let b_chain = test_blockchain();
        for b in &chain {
            insert_raw_block(&b_chain, b);
        }
        b_chain.rebuild_chain_tip_metadata().unwrap();
        b_chain.ensure_balances_index().await.unwrap();

        // Value identity over the union of addresses (absent == 0).
        let mut a_vals = dump_balances(&a);
        a_vals.remove("zz_sentinel");
        let b_vals = dump_balances(&b_chain);
        let keys: std::collections::BTreeSet<String> =
            a_vals.keys().chain(b_vals.keys()).cloned().collect();
        for k in keys {
            assert_eq!(
                a_vals.get(&k).copied().unwrap_or(0),
                b_vals.get(&k).copied().unwrap_or(0),
                "address {k} diverged between catch-up and full rebuild"
            );
        }
    }

    /// Catch-up starting MID-WAY through the coinbase-maturity window must seed
    /// the rolling immature set exactly as a from-genesis replay would hold it:
    /// a spend that is valid only because its funding coinbase just matured has
    /// to replay cleanly (over-seeding would false-fail it and silently fall back
    /// to the full rebuild — which the sentinel detects).
    #[tokio::test]
    async fn balances_catch_up_seeds_maturity_window() {
        let mat = MINING_REWARD_MATURITY; // 100
        let act = MATURITY_ACTIVATION_HEIGHT; // 1500
        let spend_height = act + mat + 2; // 1602: coinbase from 1500 is mature, 1503+ are not
        let build_chain = |upto: u32| -> Vec<Block> {
            let mut blocks = Vec::new();
            let mut prev = [0u8; 32];
            for i in 0..=upto {
                let block = if i == spend_height {
                    // earner raw = 102 coinbases x 10; immature = 99 x 10; spendable = 30.
                    test_block_with_txs(i, prev, "closer", 10.0, &[("earner", "shop", 5.0)])
                } else if i >= act {
                    metadata_test_block(i, prev, "earner", 10.0)
                } else {
                    metadata_test_block(i, prev, "filler", 10.0)
                };
                prev = block.hash;
                blocks.push(block);
            }
            blocks
        };

        let a = test_blockchain();
        let chain = build_chain(spend_height);
        let resume_from = (act + 50) as usize; // marker 1550: seed spans the window mid-flight
        for b in &chain[..=resume_from] {
            insert_raw_block(&a, b);
        }
        a.rebuild_chain_tip_metadata().unwrap();
        a.ensure_balances_index().await.unwrap();
        let a_tree = a.db.open_tree(BALANCES_TREE).unwrap();
        assert_eq!(
            Blockchain::get_balances_height(&a_tree).unwrap(),
            Some(resume_from as u64)
        );
        a_tree
            .insert("zz_sentinel".as_bytes(), codec::serialize(&777i128).unwrap())
            .unwrap();
        for b in &chain[resume_from + 1..] {
            insert_raw_block(&a, b);
        }
        a.rebuild_chain_tip_metadata().unwrap();
        a.ensure_balances_index().await.unwrap();
        assert_eq!(
            Blockchain::get_balances_height(&a_tree).unwrap(),
            Some(spend_height as u64)
        );
        assert!(
            a_tree.get("zz_sentinel".as_bytes()).unwrap().is_some(),
            "maturity seeding false-failed a valid mature spend (fell back to full rebuild)"
        );

        // And the values still match a from-genesis rebuild.
        let b_chain = test_blockchain();
        for b in &chain {
            insert_raw_block(&b_chain, b);
        }
        b_chain.rebuild_chain_tip_metadata().unwrap();
        b_chain.ensure_balances_index().await.unwrap();
        let expected_earner = b_chain.get_confirmed_balance("earner").await.unwrap();
        let got_earner = a.get_confirmed_balance("earner").await.unwrap();
        assert_eq!(got_earner, expected_earner);
        assert_eq!(
            a.get_confirmed_balance("shop").await.unwrap(),
            b_chain.get_confirmed_balance("shop").await.unwrap()
        );
    }

    /// While a writer's dirty marker is up, a lazy ensure must leave the index
    /// alone (consistent as-of-marker snapshot); once cleared it catches up.
    #[tokio::test]
    async fn balances_ensure_skips_while_dirty_then_catches_up() {
        let bc = test_blockchain();
        let b0 = metadata_test_block(0, [0u8; 32], "miner0", 1.0);
        let b1 = metadata_test_block(1, b0.hash, "miner1", 2.0);
        let b2 = metadata_test_block(2, b1.hash, "miner2", 3.0);
        insert_raw_block(&bc, &b0);
        insert_raw_block(&bc, &b1);
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.ensure_balances_index().await.unwrap();
        let tree = bc.db.open_tree(BALANCES_TREE).unwrap();
        assert_eq!(Blockchain::get_balances_height(&tree).unwrap(), Some(1));

        insert_raw_block(&bc, &b2);
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.mark_chain_state_dirty(2, "test_writer_in_flight").unwrap();
        bc.ensure_balances_index().await.unwrap();
        assert_eq!(
            Blockchain::get_balances_height(&tree).unwrap(),
            Some(1),
            "ensure must not mutate while the dirty marker is up"
        );

        bc.clear_chain_state_dirty().unwrap();
        bc.ensure_balances_index().await.unwrap();
        assert_eq!(Blockchain::get_balances_height(&tree).unwrap(), Some(2));
        assert_eq!(bc.get_confirmed_balance("miner2").await.unwrap(), 3.0);
    }

    /// A marker AHEAD of the tip means the content's provenance is unknown
    /// (chain shrank, foreign DB, manual surgery): ensure must fall back to the
    /// authoritative full rebuild, not trust or extend the content.
    #[tokio::test]
    async fn balances_marker_ahead_forces_full_rebuild() {
        let bc = test_blockchain();
        let b0 = metadata_test_block(0, [0u8; 32], "miner0", 1.0);
        let b1 = metadata_test_block(1, b0.hash, "miner1", 2.0);
        insert_raw_block(&bc, &b0);
        insert_raw_block(&bc, &b1);
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.ensure_balances_index().await.unwrap();

        let tree = bc.db.open_tree(BALANCES_TREE).unwrap();
        set_confirmed_balance(&bc, "miner1", Transaction::to_units(999.0));
        Blockchain::set_balances_height(&tree, 10).unwrap();

        bc.ensure_balances_index().await.unwrap();
        assert_eq!(Blockchain::get_balances_height(&tree).unwrap(), Some(1));
        assert_eq!(
            bc.get_confirmed_balance("miner1").await.unwrap(),
            2.0,
            "full rebuild must correct the poisoned balance"
        );
    }

    /// Concurrent stale-index readers must all succeed with fresh values and no
    /// deadlock: the single-flight gate lets one catch-up run while the rest wait
    /// and re-check.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn balances_concurrent_stale_reads_single_flight() {
        let bc = Arc::new(test_blockchain());
        let mut prev = [0u8; 32];
        let mut blocks = Vec::new();
        for i in 0..=30u32 {
            let b = metadata_test_block(i, prev, &format!("miner{i}"), 1.0);
            prev = b.hash;
            blocks.push(b);
        }
        for b in &blocks[..=5] {
            insert_raw_block(&bc, b);
        }
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.ensure_balances_index().await.unwrap();
        for b in &blocks[6..] {
            insert_raw_block(&bc, b);
        }
        bc.rebuild_chain_tip_metadata().unwrap();

        let mut handles = Vec::new();
        for i in 0..8u32 {
            let bc = Arc::clone(&bc);
            handles.push(tokio::spawn(async move {
                let addr = format!("miner{}", 7 + (i % 20));
                // Resolve inside the task: BlockchainError is !Send (boxed dyn
                // StdError), so it cannot cross the JoinHandle. A failure panics
                // the task, which surfaces as a JoinError below.
                bc.get_confirmed_balance(&addr)
                    .await
                    .expect("concurrent confirmed-balance read failed")
            }));
        }
        for h in handles {
            let balance = tokio::time::timeout(std::time::Duration::from_secs(30), h)
                .await
                .expect("deadlocked: concurrent reads did not complete")
                .unwrap();
            assert_eq!(balance, 1.0);
        }
        let tree = bc.db.open_tree(BALANCES_TREE).unwrap();
        assert_eq!(Blockchain::get_balances_height(&tree).unwrap(), Some(30));
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

    fn user_tx(sender: &str, recipient: &str, amount: f64, timestamp: u64) -> Transaction {
        Transaction {
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: Transaction::to_units(amount),
            timestamp,
            signature: Some("aa".repeat(2400)),
            pub_key: None,
            sig_hash: None,
        }
    }

    #[test]
    fn address_index_unavailable_before_first_build() {
        let bc = test_blockchain();
        assert!(!bc.address_index_ready());
        assert_eq!(
            bc.address_history_summary("anyone").unwrap(),
            None,
            "an unbuilt index must read as unavailable, not as zero activity"
        );
    }

    #[test]
    fn address_index_records_coinbase_transfers_and_self_sends() {
        let bc = test_blockchain();
        // Coinbase to "miner" + payment alice->bob + self-send carol->carol.
        let mut block = metadata_test_block(5, [0u8; 32], "miner", 2.0);
        block.transactions.push(user_tx("alice", "bob", 2.5, 5_000));
        block.transactions.push(user_tx("carol", "carol", 1.0, 5_001));
        bc.record_confirmed_txs(&block).unwrap();

        // The miner's coinbase receipt IS indexed (the replay registry skips
        // system txs; the address index must not — that was the "balance with
        // zero history" bug).
        let miner = bc.address_history_summary("miner").unwrap().unwrap();
        assert_eq!(miner.tx_count, 1);
        assert_eq!(miner.received_units, Transaction::to_units(2.0));
        assert_eq!(miner.sent_units, 0);
        assert_eq!(miner.fees_units, 0);
        assert_eq!(miner.first_height, Some(5));
        assert_eq!(miner.last_height, Some(5));
        let miner_txs = bc.address_recent_txs("miner", 10, None).unwrap();
        assert_eq!(miner_txs.len(), 1);
        assert_eq!(miner_txs[0].counterparty, "MINING_REWARDS");
        assert!(miner_txs[0].is_recipient() && !miner_txs[0].is_sender());

        let alice = bc.address_history_summary("alice").unwrap().unwrap();
        assert_eq!(alice.tx_count, 1);
        assert_eq!(alice.sent_units, Transaction::to_units(2.5));
        assert_eq!(alice.fees_units, Transaction::to_units(NETWORK_FEE));
        assert_eq!(alice.received_units, 0);

        let bob = bc.address_history_summary("bob").unwrap().unwrap();
        assert_eq!(bob.tx_count, 1);
        assert_eq!(bob.received_units, Transaction::to_units(2.5));
        assert_eq!(bob.sent_units, 0);

        // Self-send: ONE entry carrying both roles, counted once.
        let carol = bc.address_history_summary("carol").unwrap().unwrap();
        assert_eq!(carol.tx_count, 1);
        assert_eq!(carol.sent_units, Transaction::to_units(1.0));
        assert_eq!(carol.received_units, Transaction::to_units(1.0));

        // The system address itself is never indexed.
        let system = bc.address_history_summary("MINING_REWARDS").unwrap().unwrap();
        assert_eq!(system.tx_count, 0);

        // A prefix address must not leak entries from a longer address.
        let prefix = bc.address_history_summary("mine").unwrap().unwrap();
        assert_eq!(prefix.tx_count, 0);
    }

    #[test]
    fn address_index_reverts_with_reorged_blocks() {
        let bc = test_blockchain();
        let mut old_block = metadata_test_block(5, [0u8; 32], "miner_old", 2.0);
        old_block
            .transactions
            .push(user_tx("alice", "bob", 2.5, 5_000));
        bc.record_confirmed_txs(&old_block).unwrap();
        assert_eq!(
            bc.address_history_summary("alice").unwrap().unwrap().tx_count,
            1
        );

        // Reorg: the block is reverted and a competitor at the same height with a
        // different payment becomes canonical (mirrors try_adopt_orphan_branch's
        // remove-then-record sequence).
        bc.remove_confirmed_txs(&old_block).unwrap();
        let mut new_block = metadata_test_block(5, [1u8; 32], "miner_new", 2.0);
        new_block
            .transactions
            .push(user_tx("dave", "erin", 4.0, 5_002));
        bc.record_confirmed_txs(&new_block).unwrap();

        assert_eq!(
            bc.address_history_summary("alice").unwrap().unwrap().tx_count,
            0,
            "reverted payment must leave the sender's history"
        );
        assert_eq!(
            bc.address_history_summary("miner_old")
                .unwrap()
                .unwrap()
                .tx_count,
            0,
            "reverted coinbase must leave the old miner's history"
        );
        assert_eq!(
            bc.address_history_summary("dave").unwrap().unwrap().tx_count,
            1
        );
        assert_eq!(
            bc.address_history_summary("miner_new")
                .unwrap()
                .unwrap()
                .received_units,
            Transaction::to_units(2.0)
        );
    }

    #[test]
    fn address_index_rebuild_ensure_catchup_and_rewrite_detection() {
        let bc = test_blockchain();
        let mut prev = [0u8; 32];
        for height in 0..=4u32 {
            let block = metadata_test_block(height, prev, &format!("miner{}", height), 1.0);
            prev = block.hash;
            insert_raw_block(&bc, &block);
        }

        // First build under the feature: full rebuild from stored blocks.
        bc.rebuild_address_tx_index().unwrap();
        assert!(bc.address_index_ready());
        assert_eq!(
            bc.address_history_summary("miner3").unwrap().unwrap().tx_count,
            1
        );

        // A block committed while the index was offline (older binary) is picked
        // up by the incremental catch-up path, not a full rebuild. Real commit
        // paths maintain the tip metadata; raw test inserts must refresh it.
        let late = metadata_test_block(5, prev, "miner5", 1.0);
        insert_raw_block(&bc, &late);
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.ensure_address_tx_index().unwrap();
        assert_eq!(
            bc.address_history_summary("miner5").unwrap().unwrap().tx_count,
            1
        );

        // Ensure is idempotent: re-running must not duplicate entries.
        bc.ensure_address_tx_index().unwrap();
        assert_eq!(
            bc.address_history_summary("miner5").unwrap().unwrap().tx_count,
            1
        );

        // Chain rewritten at the indexed tip while the index was offline (hash at
        // the meta height no longer matches) => full rebuild, stale entries gone.
        let replacement = metadata_test_block(5, [9u8; 32], "usurper", 1.0);
        insert_raw_block(&bc, &replacement);
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.ensure_address_tx_index().unwrap();
        assert_eq!(
            bc.address_history_summary("miner5").unwrap().unwrap().tx_count,
            0,
            "entries from the rewritten block must not survive"
        );
        assert_eq!(
            bc.address_history_summary("usurper").unwrap().unwrap().tx_count,
            1
        );
    }

    #[test]
    fn address_recent_txs_orders_newest_first_and_honors_cutoff() {
        let bc = test_blockchain();
        for height in 1..=3u32 {
            let mut block = metadata_test_block(height, [height as u8; 32], "miner", 1.0);
            // metadata_test_block stamps timestamp 1_000 + height; the payment
            // rides the same block timestamp for the cutoff check.
            block.transactions.push(user_tx(
                "alice",
                "bob",
                height as f64,
                1_000 + height as u64,
            ));
            bc.record_confirmed_txs(&block).unwrap();
        }

        let newest_first = bc.address_recent_txs("alice", 10, None).unwrap();
        assert_eq!(
            newest_first.iter().map(|e| e.height).collect::<Vec<_>>(),
            vec![3, 2, 1]
        );

        let limited = bc.address_recent_txs("alice", 2, None).unwrap();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].height, 3);

        // A cutoff far past every entry (beyond the skew slack) returns nothing.
        let cutoff = 1_000 + 3 + 2 * MAX_BLOCK_FUTURE_TIME + 1;
        let recent = bc.address_recent_txs("alice", 10, Some(cutoff)).unwrap();
        assert!(recent.is_empty());
    }

    #[test]
    fn address_txs_page_cursors_through_full_history() {
        let bc = test_blockchain();
        // 2 entries per height for alice (a payment out and one in) across 5 blocks.
        for height in 1..=5u32 {
            let mut block = metadata_test_block(height, [height as u8; 32], "miner", 1.0);
            block
                .transactions
                .push(user_tx("alice", "bob", 1.0, 1_000 + height as u64));
            block
                .transactions
                .push(user_tx("carol", "alice", 2.0, 1_000 + height as u64));
            bc.record_confirmed_txs(&block).unwrap();
        }

        // Page through with limit 3 and reassemble; must equal the unpaged scan.
        let mut paged = Vec::new();
        let mut before = None;
        loop {
            let page = bc.address_txs_page("alice", 3, before).unwrap();
            if page.is_empty() {
                break;
            }
            before = page.last().map(|e| (e.height, e.position));
            let full_page = page.len() == 3;
            paged.extend(page);
            if !full_page {
                break;
            }
        }
        let unpaged = bc.address_recent_txs("alice", 100, None).unwrap();
        assert_eq!(paged, unpaged);
        assert_eq!(paged.len(), 10);
        // Newest-first, cursor is exclusive: no duplicates, strictly descending.
        for pair in paged.windows(2) {
            assert!(
                (pair[0].height, pair[0].position) > (pair[1].height, pair[1].position),
                "pages must be strictly descending with no duplicates"
            );
        }
        // A cursor below everything returns an empty page.
        assert!(bc.address_txs_page("alice", 3, Some((1, 0))).unwrap().is_empty());
        // Prefix addresses must not bleed into the page window.
        assert!(bc.address_txs_page("ali", 10, Some((5, 2))).unwrap().is_empty());
    }

    #[test]
    fn pow_byte_compare_matches_biguint_compare() {
        // The mining hot loop replaced `BigUint::from_bytes_be(&hash) <= target`
        // with a fixed-width byte comparison. Prove them interchangeable across
        // difficulty edge cases and structured + pseudorandom hashes, including
        // exact-equality and off-by-one boundaries around each target.
        let difficulties: [u64; 9] = [0, 1, 15, 16, 17, 464, 550, 4080, 4096];
        for difficulty in difficulties {
            let target = pow_target_from_difficulty(difficulty);
            let target_bytes = pow_target_bytes(&target);
            assert_eq!(
                BigUint::from_bytes_be(&target_bytes),
                target,
                "byte form must round-trip exactly (difficulty {})",
                difficulty
            );

            let mut candidates: Vec<[u8; 32]> = vec![[0u8; 32], [0xffu8; 32], target_bytes];
            if target > BigUint::from(0u8) {
                candidates.push(pow_target_bytes(&(target.clone() - 1u8)));
            }
            if target < *MAX_TARGET {
                candidates.push(pow_target_bytes(&(target.clone() + 1u8)));
            }
            for seed in 0u64..64 {
                candidates.push(*blake3::hash(&seed.to_le_bytes()).as_bytes());
            }

            for hash in candidates {
                let via_biguint = BigUint::from_bytes_be(&hash) <= target;
                let via_bytes = hash <= target_bytes;
                assert_eq!(
                    via_biguint, via_bytes,
                    "compare divergence at difficulty {} hash {:02x?}",
                    difficulty, hash
                );
            }
        }
    }

    #[test]
    fn readonly_balance_reads_without_rebuilding() {
        let bc = test_blockchain();
        // No balances tree entry -> 0, and crucially no index build side effects.
        assert_eq!(bc.confirmed_balance_units_readonly("nobody").unwrap(), 0);
        let balances = bc.db.open_tree(BALANCES_TREE).unwrap();
        balances
            .insert("alice".as_bytes(), codec::serialize(&123_i128).unwrap())
            .unwrap();
        assert_eq!(bc.confirmed_balance_units_readonly("alice").unwrap(), 123);
    }
}
