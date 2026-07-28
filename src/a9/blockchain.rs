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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{watch, Mutex, RwLock};

use crate::a9::codec;
use crate::a9::mempool::Mempool;
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
/// Explicit "the confirmed-tx replay registry has finished a build" marker. Needed because the
/// registry is legitimately EMPTY on a chain with no non-system transactions, which is
/// indistinguishable from "never built" if you only check the prune index for entries.
const CONFIRMED_TX_BUILT_KEY: &[u8] = b"confirmed_tx_index_built";
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
/// Cap on how many best-ranked branches the reorg engine fully validates and tries to adopt
/// in one pass. The first branch to pass every gate wins; a gate-rejected best falls through
/// to the next-best. Bounds the extra validation work when an attacker floods invalid
/// high-ranked competitors — each of which still costs a real floor-difficulty grind, and a
/// rejected best only prolongs a self-healing equal-work fork.
const MAX_REORG_ADOPT_ATTEMPTS: usize = 16;
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

// Whisper arithmetic compatibility. Regular wallet fee policy is defined separately.
pub const FEE_PERCENTAGE: f64 = 0.000563063063; // 0.0563063063%
pub const MIN_BLOCK_REWARD: f64 = 1.0;
pub const MAX_BLOCK_REWARD: f64 = 50.0;
/// Coordinated activation for the deterministic fee-accounting and block-shape
/// rules below: at the pinned activation height + 241,920 blocks after the
/// release reference, a soft-hard-fork boundary where the stricter accounting,
/// canonical shape, and weight predicate begin.
/// Active pinned value: bootstrap manifest tip (275_663 from
/// https://alphanumeric.blue/api/bootstrap/manifest on 2026-07-26) + 241,920 =
/// 517,583.
pub const FEE_SYSTEM_ACTIVATION_HEIGHT: u32 = 517_583;
pub const FEE_ACCOUNTING_RULES_VERSION: u32 = 1;
/// Aggregate low-fee compatibility envelope used by the scheduled accounting
/// baseline (500,000 atomic units = 0.005 ALPHA).
pub const LOW_FEE_COMPATIBILITY_ENVELOPE_UNITS: i128 = 500_000;
/// Deterministic full-witness-equivalent block budget. The metric deliberately
/// charges stored receipt signatures at their full wire cost, so validity is the
/// same for an incoming full block and its locally compacted representation.
pub const MAX_BLOCK_WEIGHT_BYTES: usize = 3_500_000;
/// Consensus cap on transactions per block. Without it a single block could carry
/// an unbounded number of transactions and stall the serial block-processing loop
/// (a cheap DoS). The full-witness weight limit below is the effective bound for
/// ordinary transfers (roughly 237 per five-second block today); this independent
/// count ceiling also bounds pathological tiny encodings. The mining-reward
/// transaction counts toward it.
pub const MAX_BLOCK_TX_COUNT: usize = 4096;
pub const NETWORK_FEE: f64 = 0.0005; // Operator fee from mining rewards
/// RELAY/MEMPOOL POLICY fee floor for user transactions, in 1e-8 units
/// (10_000 = 0.0001 coins). NOT consensus: block validation deliberately never
/// checks it (that would be a soft fork) — it gates only what this node admits
/// to its mempool, relays onward, and selects into its own block templates.
/// The value is the largest always-whisper-safe flat floor: a whisper's fee is
/// WHISPER_MIN_AMOUNT (0.0001) plus a strictly positive arithmetic-coded
/// component plus the percentage fee, so every legitimate whisper clears it.
/// Deterrence scope (be precise): the fee only BURNS when a tx is mined, so
/// what the floor prices is confirmed chain-bloat — every spam tx that lands
/// in a block now costs real coins. Mempool-resident spam that expires unpaid
/// is instead bounded by the per-sender caps, rate limiter and TTL.
pub const MIN_RELAY_FEE_UNITS: i128 = 10_000;
/// Reference-wallet safety ceiling for ANY fee the wallet will attach (explicit
/// --fee or the auto estimate), in 1e-8 units (1_000_000 = 0.01 coins). Wallet
/// POLICY, not consensus: it exists so neither a typo nor a manipulated fee
/// recommendation can burn a meaningful balance in one transaction. Single
/// source of truth — mgmt.rs (the --fee guard) and the fee estimator both
/// derive from this constant.
pub const WALLET_FEE_SAFETY_LIMIT_UNITS: i128 = 1_000_000;
/// Quiet-network default fee the reference wallet attaches when the mempool is
/// uncontended, expressed as a multiple of the relay floor so it tracks any
/// future floor change automatically. 2x the floor (0.0002 coins today) keeps a
/// default-wallet transaction strictly ahead of floor-paying bulk templates
/// (mining pools/exchanges submitting at exactly MIN_RELAY_FEE_UNITS) in the
/// miner's fee-descending selection, while staying far below the old
/// amount-proportional cap. Anti-spam is NOT this constant's job — the relay
/// floor and the per-block weight budget already price chain-bloat.
pub const FEE_ESTIMATE_ANCHOR_UNITS: i128 = MIN_RELAY_FEE_UNITS * 2;
/// Ceiling for the AUTOMATIC fee only — deliberately an order of magnitude
/// below WALLET_FEE_SAFETY_LIMIT_UNITS (which stays the ceiling for a fee the
/// user explicitly typed). A fee nobody chose must never be able to spend a
/// meaningful balance because the mempool happened to be contended (or was
/// deliberately stuffed) at the instant of send: 10x the anchor is more than
/// enough to outbid any honest backlog, and a user who genuinely wants to pay
/// more can always pass --fee. Also bounds the payoff of fee-pumping the
/// estimate: an attacker who fills blocks with ceiling-fee traffic moves
/// default wallets by at most this much.
pub const FEE_ESTIMATE_AUTO_CAP_UNITS: i128 = FEE_ESTIMATE_ANCHOR_UNITS * 10;
/// Serialized size allowance for ONE ordinary full-witness transfer, used by
/// the estimator to reserve next-block headroom for the caller's own
/// transaction (the miner reserves the coinbase slot the same way). Derived
/// from the fixed transaction framing plus the ML-DSA-87 witness that
/// dominates it; deliberately generous, since over-reserving only makes the
/// estimator declare congestion one transaction early.
pub const TYPICAL_FULL_WITNESS_TX_BYTES: usize = 16 * 1024;
/// Cap on the summed serialized size of the transactions selected into a block
/// template. Every transport enforces node.rs MAX_MESSAGE_SIZE (4 MiB) per
/// frame, so a bigger block is unrelayable and would strand the miner on its
/// own fork. The consensus MAX_BLOCK_TX_COUNT alone does NOT keep templates
/// under the frame: full ML-DSA-87 witnesses put a signed transfer near ~15 KB,
/// so a count-full template would serialize to tens of MB. 3.5 MiB leaves
/// headroom for the header, coinbase and codec envelope. Single source of
/// truth — the miner's packing loop and the fee estimator both use this.
pub const MAX_TEMPLATE_TX_BYTES: usize = MAX_BLOCK_WEIGHT_BYTES;
/// Safety margin the template selector (and the fee estimator, which must
/// mirror it exactly) applies on top of the consensus freshness rule: a
/// transaction within this margin of MAX_TX_AGE_SECS expiry is not templated,
/// so a block can never be rejected because its transactions aged out during
/// the nonce grind.
pub const TEMPLATE_FRESHNESS_MARGIN_SECS: u64 = 60;
pub const MINT_CLIP: f64 = 0.35; // Fee-weighted reward damping
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
// Conservative encoded-size accounting. Variable witness fields are charged
// separately below; these allowances cover framing, numeric fields and options.
const BLOCK_WEIGHT_FIXED_BYTES: usize = 512;
const TRANSACTION_WEIGHT_FIXED_BYTES: usize = 128;
lazy_static! {
    pub static ref MAX_TARGET: BigUint = BigUint::from_bytes_be(&MAX_TARGET_BYTES);
}

/// Non-consensus fee recommendation for the reference wallet and API users —
/// the output of Blockchain::fee_estimate(). Every field is advisory POLICY;
/// nothing here is validated by consensus. `recommended_units` is what the
/// reference wallet attaches when `create` is run without --fee; explicit fees
/// (mining pools, exchanges, power users) bypass the estimator entirely and are
/// bounded only by the relay floor and the wallet safety ceiling.
#[derive(Clone, Debug, PartialEq)]
pub struct FeeEstimate {
    /// The fee a default wallet/API user should attach right now.
    pub recommended_units: i128,
    /// Quiet-network default (FEE_ESTIMATE_ANCHOR_UNITS).
    pub anchor_units: i128,
    /// Relay-policy floor (MIN_RELAY_FEE_UNITS) — never recommend below.
    pub floor_units: i128,
    /// Ceiling the AUTO path clamps to (FEE_ESTIMATE_AUTO_CAP_UNITS). Lower
    /// than the explicit --fee ceiling on purpose: an automatic fee nobody
    /// typed should never be able to spend a meaningful balance.
    pub auto_cap_units: i128,
    /// The wallet's explicit-fee ceiling (WALLET_FEE_SAFETY_LIMIT_UNITS) —
    /// reported for reference; only a user-supplied --fee may reach it.
    pub explicit_cap_units: i128,
    /// True when next-block capacity cannot absorb the eligible backlog PLUS
    /// the caller's own transaction, i.e. the recommendation is priced off the
    /// marginal included fee rather than the anchor.
    pub congested: bool,
    /// Template-eligible transactions seen within the bounded scan.
    pub pending_candidates: usize,
    /// How many of those fit the modeled next block.
    pub next_block_fits: usize,
}

/// Running fee-accounting state for ONE template build.
///
/// The activated rule admits a transaction set iff
/// `reward(count, fees) - fee_units <= baseline`, and every one of those inputs
/// is an aggregate. Carrying them forward turns the per-candidate cost from
/// O(selected) into O(1): the packer no longer rebuilds a synthetic block and
/// re-folds the entire selected prefix for each candidate it considers.
///
/// `admits` is deliberately TENTATIVE — it derives the totals the set *would*
/// have and never mutates. Committing is a separate call, and there is no
/// "uncommit". That asymmetry is load-bearing: a rollback would have to subtract
/// an f64 it had previously added, and f64 addition is not exactly invertible
/// (`(fees + f) - f != fees` in general), so a push/pop design would silently
/// drift from the block-form result. Totals only ever move forward, by append,
/// in selection order — which is precisely the fold `calculate_block_reward`
/// performs, hence bit-identical results rather than merely close ones.
pub struct TemplateFeeAccounting {
    activated: bool,
    block_index: u32,
    block_timestamp: u64,
    baseline_units: i128,
    tx_count: usize,
    total_fees: f64,
    total_fee_units: i128,
}

impl TemplateFeeAccounting {
    /// Baseline is resolved once here; it depends only on (height, timestamp).
    pub fn new_at(
        blockchain: &Blockchain,
        block_index: u32,
        block_timestamp: u64,
        activation_height: u32,
    ) -> Result<Self, BlockchainError> {
        let activated = block_index >= activation_height;
        let baseline_units = if activated {
            blockchain.scheduled_baseline_units_at(block_index, block_timestamp)?
        } else {
            0
        };
        Ok(Self {
            activated,
            block_index,
            block_timestamp,
            baseline_units,
            tx_count: 0,
            total_fees: 0.0,
            total_fee_units: 0,
        })
    }

    pub fn new(
        blockchain: &Blockchain,
        block_index: u32,
        block_timestamp: u64,
    ) -> Result<Self, BlockchainError> {
        Self::new_at(
            blockchain,
            block_index,
            block_timestamp,
            FEE_SYSTEM_ACTIVATION_HEIGHT,
        )
    }

    /// Totals the set would have with `tx` appended. Mirrors the negative-fee
    /// rejection and checked accumulation of `aggregate_regular_fee_units`.
    fn totals_with(&self, tx: &Transaction) -> Result<(usize, f64, i128), BlockchainError> {
        if tx.fee_units < 0 {
            return Err(BlockchainError::InvalidTransactionAmount);
        }
        let total_fee_units = self
            .total_fee_units
            .checked_add(tx.fee_units)
            .ok_or(BlockchainError::InvalidTransactionAmount)?;
        Ok((
            self.tx_count.saturating_add(1),
            self.total_fees + tx.fee(),
            total_fee_units,
        ))
    }

    /// Would the selected set still be admissible with `tx` appended? Pure.
    pub fn admits(
        &self,
        blockchain: &Blockchain,
        tx: &Transaction,
    ) -> Result<bool, BlockchainError> {
        if !self.activated {
            return Ok(true);
        }
        let (tx_count, total_fees, total_fee_units) = self.totals_with(tx)?;
        let reward_units = Transaction::to_units(blockchain.block_reward_from_totals(
            self.block_index,
            self.block_timestamp,
            tx_count,
            total_fees,
        )?);
        let net_issuance_units = reward_units
            .checked_sub(total_fee_units)
            .ok_or(BlockchainError::InvalidTransactionAmount)?;
        Ok(net_issuance_units <= self.baseline_units)
    }

    /// Fold `tx` into the running totals. Only call after `admits` returned true.
    pub fn commit(&mut self, tx: &Transaction) -> Result<(), BlockchainError> {
        let (tx_count, total_fees, total_fee_units) = self.totals_with(tx)?;
        self.tx_count = tx_count;
        self.total_fees = total_fees;
        self.total_fee_units = total_fee_units;
        Ok(())
    }
}

impl FeeEstimate {
    /// Stable label for displays and the explorer API: what priced the
    /// recommendation.
    pub fn basis(&self) -> &'static str {
        if self.congested {
            "next-block"
        } else {
            "quiet"
        }
    }
}

/// Canonical user/miner address form used by wallets and activated block rules.
/// This validates only the textual address representation; signature validation
/// separately binds a sender address to its public key.
pub fn is_canonical_user_address(address: &str) -> bool {
    address.len() == 40
        && address
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
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
        // Exact i128 (hygiene: this path is currently unreachable, but keep it off the
        // lossy f64 round-trip like every other affordability check — 2026-07-12 audit).
        let sender_units = blockchain.get_confirmed_balance_units(&self.sender).await?;

        if !self.has_valid_regular_amounts() {
            return Err(BlockchainError::InvalidTransactionAmount);
        }

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
    /// A block repeats a non-coinbase transaction id.
    DuplicateTransaction,
    /// A block carries more than MAX_BLOCK_TX_COUNT transactions. Distinct from
    /// InvalidBlockHeader so the continuous miner never mistakes an over-full
    /// template for a lost race and re-grinds the same doomed block forever.
    BlockTransactionCountExceeded,
    /// The deterministic full-witness-equivalent block budget is exceeded.
    BlockWeightExceeded,
    /// An activated transaction field is not in its canonical wire form.
    NonCanonicalTransaction,
    /// The candidate falls outside the activated block fee-accounting range.
    FeeAccountingLimitExceeded,
    /// Mempool/relay POLICY reject: transaction fee below MIN_RELAY_FEE_UNITS.
    /// Never returned by block validation — a mined block carrying such a tx is
    /// still fully valid (see the admission guard in add_transaction).
    FeeBelowRelayFloor,
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
            BlockchainError::DuplicateTransaction => {
                write!(f, "Block repeats a non-coinbase transaction id")
            }
            BlockchainError::BlockTransactionCountExceeded => {
                write!(f, "Block exceeds the maximum transaction count")
            }
            BlockchainError::BlockWeightExceeded => {
                write!(f, "Block exceeds the maximum full-witness weight")
            }
            BlockchainError::NonCanonicalTransaction => {
                write!(f, "Transaction fields are not canonically encoded")
            }
            BlockchainError::FeeAccountingLimitExceeded => {
                write!(
                    f,
                    "Transaction fees are outside the current block accounting range"
                )
            }
            BlockchainError::FeeBelowRelayFloor => {
                write!(
                    f,
                    "Transaction fee below the relay floor (min {:.8})",
                    Transaction::from_units(MIN_RELAY_FEE_UNITS)
                )
            }
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
        // The monotonic clock is boot-relative, so `now - window` underflows in the first
        // `window` seconds after boot; the std Instant subtraction panics on underflow (and
        // panic=unwind would tear down the request task). Saturate to `now` instead — the
        // window briefly collapses to the current instant (fail-open) until the clock passes
        // the window. Value-identical for every non-underflow case.
        let cutoff = now
            .checked_sub(std::time::Duration::from_secs(window_secs))
            .unwrap_or(now);

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

        // Fast path: an existing key admits/rejects with no owned-String allocation.
        if let Some(mut times) = self.windows.get_mut(address) {
            return Self::admit_in_window(times.value_mut(), now, cutoff, self.max_requests);
        }
        // First in-window request for this key: allocate the key once. (entry may observe a value
        // another thread just inserted, so run the same window logic rather than assuming empty.)
        let mut times = self.windows.entry(address.to_string()).or_default();
        Self::admit_in_window(times.value_mut(), now, cutoff, self.max_requests)
    }

    fn admit_in_window(
        times: &mut Vec<tokio::time::Instant>,
        now: tokio::time::Instant,
        cutoff: tokio::time::Instant,
        max_requests: usize,
    ) -> bool {
        // Drop entries that have aged out of the window (the first valid index onward is kept).
        if !times.is_empty() && times[0] < cutoff {
            let first_valid = times
                .iter()
                .position(|&t| t >= cutoff)
                .unwrap_or(times.len());
            times.drain(0..first_valid);
        }

        if times.len() >= max_requests {
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
    signature_cache: Arc<PLMutex<LruCache<String, bool>>>,
    /// Last successfully-read trusted checkpoint. Guards against a transient
    /// meta-tree read error silently degrading finality to 0 (see
    /// trusted_checkpoint_height).
    last_known_checkpoint: Arc<AtomicU64>,
    /// Genesis timestamp memo (genesis is immutable): calculate_block_reward used
    /// to do a sled get + full block deserialize on EVERY call — and the template
    /// packer calls it 4x per admitted candidate.
    genesis_timestamp: Arc<std::sync::OnceLock<u64>>,
    state_mutation_lock: Arc<Mutex<()>>,
    /// Single-flight gate for the one-time pending-set transition at the
    /// coordinated fee-system height. Lock order is this gate ->
    /// state_mutation_lock; callers must invoke the public ensure method without
    /// already holding the state lock.
    pending_rules_gate: Arc<Mutex<()>>,
    /// Set only after the activated pending set, sidecars, in-memory mempool and
    /// debit/credit indexes have all been reconciled successfully.
    pending_rules_complete: Arc<AtomicBool>,
    #[cfg(test)]
    pending_rules_revalidation_runs: Arc<AtomicUsize>,
    /// Single-flight gate for balances-index maintenance (rebuild / catch-up).
    /// Concurrent get_confirmed_balance callers finding a stale index WAIT here
    /// and re-check instead of each launching their own O(chain) replay — the
    /// stampede that wedged nodes once 5s blocks outpaced the rebuild. Lock
    /// order where both are held is state_mutation_lock -> balances_index_gate
    /// (writers hold the state lock and read balances inside it); the gate is
    /// never held while acquiring the state lock.
    balances_index_gate: Arc<Mutex<()>>,
    tip_change_counter: Arc<AtomicU64>,
    /// In-memory memo of the validated chain tip, keyed by `tip_change_counter`. Every tip change
    /// bumps that counter (persist pairs write_chain_tip_metadata with notify_tip_changed; finalize
    /// and reorg notify too), so a cached entry is valid exactly while the counter is unchanged.
    /// This lets the very hot get_latest_block_index / get_last_block path skip re-reading and fully
    /// deserializing the tip block on every call; a version mismatch falls back to the validated
    /// current_chain_tip_metadata, so results are identical to the uncached path.
    chain_tip_cache: Arc<PLMutex<Option<(u64, ChainTipMetadata)>>>,
    /// In-memory memo of total confirmed supply, keyed by `tip_change_counter`. Supply changes only
    /// when a block is applied (which bumps the counter), so the opt-in /explorer/supply endpoint can
    /// reuse the last full balances-tree scan within a tip while it stays unchanged.
    supply_cache: Arc<PLMutex<Option<(u64, i128)>>>,
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
        let version = self.tip_change_counter.load(Ordering::Acquire);
        // Fast path: the memoized tip is valid while the tip-change counter is unchanged. The Option
        // is Copy, so this copies out and drops the guard immediately (no lock across the slow path).
        let cached = *self.chain_tip_cache.lock();
        if let Some((cached_version, tip)) = cached {
            if cached_version == version {
                return Some(tip.height);
            }
        }
        // Slow path: validate against storage exactly as the uncached code did, then memoize under
        // this version so the ~2K same-version reads per applied block skip the full tip-block parse.
        match self.current_chain_tip_metadata() {
            Ok(Some(tip)) => {
                *self.chain_tip_cache.lock() = Some((version, tip));
                Some(tip.height)
            }
            _ => {
                *self.chain_tip_cache.lock() = None;
                self.highest_block_index_scan()
            }
        }
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
        if block.index.saturating_add(1) < FEE_SYSTEM_ACTIVATION_HEIGHT {
            // A reorg can move the next candidate back below activation after a
            // completed transition. Clear the one-time marker so any pending
            // entries admitted on that lower branch are reconciled on recross.
            self.pending_rules_complete.store(false, Ordering::Release);
        }
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
        // Invalidate the in-memory memos the moment the persisted tip changes — before the caller's
        // fallible flushes / notify_tip_changed — so a flush error between here and the counter bump
        // can never leave a reader serving a tip staler than storage.
        *self.chain_tip_cache.lock() = None;
        *self.supply_cache.lock() = None;
        Ok(())
    }

    fn clear_chain_tip_metadata(&self) -> Result<(), BlockchainError> {
        let meta_tree = self.open_chain_meta_tree()?;
        meta_tree.remove(CHAIN_TIP_KEY)?;
        *self.chain_tip_cache.lock() = None;
        *self.supply_cache.lock() = None;
        Ok(())
    }

    fn rebuild_chain_tip_metadata(&self) -> Result<Option<ChainTipMetadata>, BlockchainError> {
        // A rebuild replaces the persisted tip; drop the in-memory memo so the next read re-validates
        // (defensive — rebuild is normally reached only through the validating read path or startup).
        *self.chain_tip_cache.lock() = None;
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

    /// Recover ALL derived state from the authoritative canonical block store after an interrupted
    /// apply (a crash, OR a live mid-apply `Err` the caller caught and continued past). The order
    /// is load-bearing:
    ///   1. `rebuild_chain_tip_metadata` FIRST — it invalidates `chain_tip_cache` and re-anchors
    ///      `CHAIN_TIP` by scanning `block_` keys. This MUST precede any `highest_block_index()`-
    ///      driven rebuild: a reorg that failed before `write_chain_tip_metadata` left the cache
    ///      holding the OLD tip with a still-valid version, so a balance/registry rebuild would
    ///      otherwise cover the wrong height range and re-poison the ledger.
    ///   2. force-rebuild the balances index from canonical `[0..=tip]`, discarding a marker that
    ///      is ahead of the tip (H4) or on the wrong branch (M1) — neither is a trustworthy gap.
    ///   3. re-derive the replay registry from the same canonical range (its remove/record loops
    ///      run outside the atomic slot batch, so a failure can leave it half-written).
    ///   4. address history index is display-only — fail open.
    ///   5. clear the dirty marker LAST, so any earlier failure leaves it set and the next apply
    ///      (or startup) retries recovery.
    ///
    /// This is the SAME body `initialize()` runs at startup, factored out so live and startup
    /// recovery cannot drift.
    async fn recover_dirty_chain_state(
        &self,
        marker: &ChainStateDirty,
    ) -> Result<(), BlockchainError> {
        warn!(
            "Recovering derived chain state after interrupted {} at block {}",
            marker.reason, marker.block_index
        );
        let _ = self.rebuild_chain_tip_metadata()?; // (1) re-anchor tip; invalidate stale cache
        self.ensure_balances_index_with_force(true).await?; // (2) full rebuild from canonical slots
        self.rebuild_confirmed_tx_index()?; // (3) re-derive replay registry
        if let Err(e) = self.rebuild_address_tx_index() {
            // (4) display-only: a failure must not abort the apply/startup
            warn!(
                "Address history index rebuild failed during recovery: {}",
                e
            );
        }
        self.clear_chain_state_dirty()?; // (5) clear LAST
        Ok(())
    }

    /// Cheap, idempotent, ~free when clean (one `CHAIN_META_TREE` get). Runs `recover_dirty_chain_state`
    /// ONLY when a prior apply left the dirty marker stuck. It MUST be called under the same
    /// serialization as the apply it precedes, and BEFORE that apply reads the tip or the balances
    /// index — so a live mid-apply failure is healed to the authoritative canonical state instead
    /// of the next apply re-applying against poisoned (marker-ahead / wrong-branch) derived state
    /// (H4 double-coinbase self-fork; M1 reorg divergence). The joint serialization
    /// (`state_mutation_lock` for tip extensions, the outer `RwLock` write guard for the external
    /// reorg) guarantees a marker seen here reflects a PRIOR failed apply, never an in-flight one.
    async fn reconcile_chain_state_if_dirty(&self) -> Result<(), BlockchainError> {
        // Resolve the `?` (which threads a !Send ControlFlow<Result<_, BlockchainError>>) to a plain
        // Option BEFORE the await, so no BlockchainError-carrying temporary is held across it — the
        // project-wide !Send rule (BlockchainError is a boxed dyn Error). `marker` is all-Send.
        let dirty = self.chain_state_dirty()?;
        if let Some(marker) = dirty {
            self.recover_dirty_chain_state(&marker).await?;
        }
        Ok(())
    }

    /// Highest block height the node treats as final. Blocks at/below it are
    /// signature-trusted (vouched for by a verified signed snapshot, or fully
    /// verified locally then aged past the reorg margin) and cannot be reorged;
    /// blocks above it — the unfinalized frontier — MUST pass full ML-DSA
    /// verification to be adopted from a peer or the relay. 0 if never seeded.
    pub fn trusted_checkpoint_height(&self) -> u32 {
        // A read error must NOT degrade to 0. Zero disables finality outright:
        // deep reorgs stop being rejected, and verification_floor() collapses so
        // the node demands full witnesses for hundreds of thousands of buried
        // blocks. Fall back to the last value we successfully read instead, and
        // say so — a LOWER checkpoint is never the safe direction to fail in.
        match self
            .open_chain_meta_tree()
            .ok()
            .and_then(|tree| tree.get(TRUSTED_CHECKPOINT_KEY).ok().flatten())
            .and_then(|raw| codec::deserialize::<u32>(&raw).ok())
        {
            Some(height) => {
                self.last_known_checkpoint.store(height as u64, Ordering::Release);
                height
            }
            None => {
                let cached = self.last_known_checkpoint.load(Ordering::Acquire) as u32;
                if cached > 0 {
                    warn!(
                        "Could not read the trusted checkpoint; holding the last known value {} rather than degrading finality to 0",
                        cached
                    );
                }
                cached
            }
        }
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
        //
        // `stale` (in-memory) and `tree_stale` (sled) OVERLAP: add_transaction writes both the
        // mempool and the pending tree, and sync_mempool_with_sled rebuilds the mempool FROM the
        // tree, so a confirmed tx is normally present in both. clear_processed_transactions
        // subtracts each tx's pending debit PER occurrence (saturating), so listing a tx twice
        // would double-subtract and wipe the reservation still held by the sender's OTHER pending
        // txs (a local over-admission bug — block validation still catches real overspends). Dedup
        // by tx_id so every debit is cleared exactly once; tree/sidecar removal is idempotent.
        let mut seen = HashSet::new();
        let all: Vec<Transaction> = stale
            .into_iter()
            .chain(tree_stale)
            .filter(|tx| seen.insert(tx.get_tx_id()))
            .collect();
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
        // No per-tree flush: in sled, Tree::flush() IS a full-database
        // pagecache flush + fsync, and every caller of this path ends its dirty
        // window with one authoritative db.flush() (persist/reorg tails). The
        // intermediate flushes multiplied whole-DB fsyncs per applied block for
        // zero extra durability.
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
        // An explicit completion marker distinguishes "registry built, but this chain simply has no
        // non-system transactions to index" (a quiet / low-tx node) from "never built". Without it,
        // keying solely on the prune index being non-empty re-derived the whole registry (O(chain))
        // on EVERY startup for a tx-free chain, since an empty index looks identical to an unbuilt
        // one. New blocks maintain the registry incrementally, so a stamped-empty registry stays
        // correct.
        let meta = self.open_chain_meta_tree()?;
        if meta.get(CONFIRMED_TX_BUILT_KEY)?.is_some() {
            return Ok(());
        }
        // Back-compat: a registry built by a pre-marker binary has a populated prune index but no
        // marker. Treat a non-empty index as already-built and just stamp the marker, so this stays
        // an O(1) check next startup rather than an O(chain) rebuild. (This also preserves the old
        // "prune index present => current prunable format" migration signal.)
        let index = self.db.open_tree(CONFIRMED_TX_TS_INDEX)?;
        if index.iter().next().is_some() {
            meta.insert(CONFIRMED_TX_BUILT_KEY, vec![1u8])?;
            meta.flush()?;
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
        if let Some(tip) = self.highest_block_index() {
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
        }
        // Stamp the completion marker unconditionally — even for a chain with no blocks or no
        // indexable txs — so ensure_confirmed_tx_index does not re-derive on every startup. New
        // blocks keep the registry current incrementally (record_confirmed_txs on commit).
        let meta = self.open_chain_meta_tree()?;
        meta.insert(CONFIRMED_TX_BUILT_KEY, vec![1u8])?;
        meta.flush()?;
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

    fn decode_address_tx_entry(
        prefix_len: usize,
        key: &[u8],
        value: &[u8],
    ) -> Option<AddressTxEntry> {
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
        // No per-tree flush (a full-DB fsync in sled): the commit sites' tail
        // db.flush() covers durability, and the boot-time catch-up loop calls this
        // once per block — the flush made a day of offline catch-up cost one
        // whole-DB fsync per height.
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
        // Supply changes only when a block is applied (which bumps tip_change_counter); reuse the
        // last full scan while the tip is unchanged instead of walking the whole balances tree per
        // request. Falls through to a fresh scan on any tip change.
        let version = self.tip_change_counter.load(Ordering::Acquire);
        if let Some((cached_version, supply)) = *self.supply_cache.lock() {
            if cached_version == version {
                return Ok(supply);
            }
        }
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
        *self.supply_cache.lock() = Some((version, total));
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
        // Same finality invariant as prune_orphans: a block at/below the trusted
        // checkpoint can never appear in an adoptable branch, so storing it only
        // buys per-ingest branch-reassembly work. Dropping it here (instead of
        // store-then-prune) also skips two tree flushes per dead block while a
        // partitioned miner floods the relay with a finalized-depth fork.
        let checkpoint = self.trusted_checkpoint_height();
        if checkpoint > 0 && block.index <= checkpoint {
            return Ok(());
        }

        // Unreachable-height guard (bound 4, H1): collect_orphan_branches_from caps branch depth at
        // ORPHAN_REORG_DEPTH and seeds only from candidates <= tip, so the highest block any
        // adoptable branch can contain is tip + ORPHAN_REORG_DEPTH - 1. A block above
        // tip + ORPHAN_REORG_DEPTH can never enter an adopted branch — the SAME bound holds on
        // un-upgraded peers, so this cannot diverge the canonical chain — and retaining it only
        // feeds an above-tip flood. Skipped pre-genesis (tip None); a far-behind node catches up
        // via height-indexed sync, not via retained far-ahead orphans. Threshold MUST track
        // collect's max_depth (both ORPHAN_REORG_DEPTH).
        if let Some(tip) = self.highest_block_index() {
            if block.index > tip.saturating_add(ORPHAN_REORG_DEPTH) {
                return Ok(());
            }
        }

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

    /// Enumerate all orphan branches rooted at `start`, bounded by `max_depth` and `max_branches`.
    /// Branches are `Vec<Arc<Block>>`: at a fork the branch-so-far is cloned per child, but with
    /// `Arc` that copies 8-byte pointers, not whole `Block` bodies (bound 2). Without this, a
    /// spine+fanout orphan DAG (`max_depth * max_branches` ~ 4.19M) deep-copied ~1.3-1.6 GB of block
    /// bodies under the lock (H1). The returned branch set/order/contents are byte-identical to the
    /// former body-clone version — every fork-choice input (`branch[0].index`,
    /// `branch_work_to_height`, tie-break hash) reads the same bytes, so adoption is unchanged.
    fn collect_orphan_branches_from(
        &self,
        start: Arc<Block>,
        max_depth: usize,
        max_branches: usize,
    ) -> Result<Vec<Vec<Arc<Block>>>, BlockchainError> {
        let mut complete: Vec<Vec<Arc<Block>>> = Vec::new();
        let mut stack: Vec<Vec<Arc<Block>>> = vec![vec![start]];

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
                let mut next_branch = branch.clone(); // Vec<Arc<Block>> clone = pointer copies only
                next_branch.push(Arc::new(child));
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

    // Generic over Borrow<Block> so it serves BOTH the external-branch fork-choice callers (which
    // hold owned `Block`s) and the orphan-reorg ranking (which now holds `Arc<Block>` for bound 2).
    fn branch_work_to_height<B: std::borrow::Borrow<Block>>(
        branch: &[B],
        max_height: u32,
    ) -> BigUint {
        branch
            .iter()
            .filter(|b| b.borrow().index <= max_height)
            .fold(BigUint::from(0u8), |acc, b| {
                acc + Self::work_units_for_difficulty(b.borrow().difficulty)
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
        // Build the storage tx vector directly (no whole-block clone whose tx vector is discarded).
        // When a sig_hash is present the truncated tx is produced straight off the borrow (one
        // allocation); only the derive-from-signature branch needs to compute the hash first.
        // Byte-identical to the prior clone-then-truncate path.
        let transactions = block
            .transactions
            .iter()
            .map(|tx| {
                if tx.sender == "MINING_REWARDS" {
                    return tx.clone();
                }

                let sig_hash = match &tx.sig_hash {
                    Some(h) => Some(h.clone()),
                    None => tx.signature.as_ref().and_then(|sig_hex| {
                        hex::decode(sig_hex)
                            .ok()
                            .map(|sig_bytes| Transaction::signature_hash_hex(&sig_bytes))
                    }),
                };

                match sig_hash {
                    Some(sig_hash) => tx.with_truncated_signature(sig_hash),
                    None => tx.clone(),
                }
            })
            .collect();

        Block {
            index: block.index,
            previous_hash: block.previous_hash,
            timestamp: block.timestamp,
            transactions,
            nonce: block.nonce,
            difficulty: block.difficulty,
            hash: block.hash,
            merkle_root: block.merkle_root,
        }
    }

    /// Adopt an externally-fetched competing branch (pulled from the gateway
    /// during a beacon-driven reorg). The blocks are staged as orphan candidates
    /// and run through the SAME fork-choice reorg as any other adoption — so the
    /// checkpoint-finality guard, balance validation, and frontier-signature gate
    /// all apply — and on success it disconnects the losing blocks, connects the
    /// heavier canonical branch, and fires notify_tip_changed. Never re-downloads.
    pub async fn adopt_external_branch(&self, blocks: Vec<Block>) -> Result<bool, BlockchainError> {
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
        map.get(tip_hash)
            .map(|e| now < e.retry_after)
            .unwrap_or(false)
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

    // NOTE: the witness_blocked memo below (G) records, per deferred branch, the exact
    // (height,hash) blocks a rehydration consumer WOULD refetch — but that consumer is not
    // shipped in this tree. An in-place relay witness-REHYDRATION recovery path (fetch the
    // full-witness body by exact (height,hash), re-run hash+PoW+S-01, install over the
    // truncated copy, then re-adopt) plus a checkpoint-relative deep-reorg bound were
    // designed and intentionally deferred: raising the reorg bound deeper than the
    // coinbase-maturity depth would let a reorg reach a MATURED coinbase, so it must not
    // land without first resolving the reorg-depth-vs-maturity question, plus a complete
    // adversarial review and soak. This tree ships only G (the defer/backoff below, which
    // stops the S-01 re-verify/log storm with zero consensus surface); a witness-wedged node
    // still recovers via the escape-hatch re-bootstrap path (converge NeedsBootstrap ->
    // marker). Do NOT add rehydration or a deeper reorg bound without that decision.

    /// Rehydrate a reverted transaction to its full-signature form from the retained
    /// witness store. Returns None when this node never held (or has since pruned) the
    /// full signature. Transactions read back from a stored block carry only a truncated
    /// (<=64-byte) signature, which can never pass the full-signature gate, so a reverted
    /// tx that cannot be rehydrated must be dropped rather than re-queued: re-added as-is
    /// it would be re-selected into every block template the miner builds and rejected at
    /// finalize, wasting a full proof-of-work grind per attempt until it ages out.
    /// Durable half of the M14 reorg re-queue: write a rehydrated reverted tx back
    /// into the pending tree (compact storage form) and the full-signature sidecar,
    /// exactly as add_transaction persists a fresh submission. Without this the
    /// re-queue lived only in the in-memory mempool — and the next
    /// sync_mempool_with_sled (any `account`/`info` command, the 45s gossip
    /// re-announce, or a restart) wiped the mempool, rebuilt it exclusively from
    /// the sled pending tree, and silently destroyed the payment. No re-validation
    /// here: the tx was consensus-valid in a mined block and
    /// rehydrate_reverted_tx restored its full witness; the periodic pending
    /// re-verification passes prune anything that has gone stale since.
    fn persist_readmitted_pending_tx(&self, full: &Transaction) -> Result<(), BlockchainError> {
        let sig_hex = full
            .signature
            .as_ref()
            .ok_or(BlockchainError::InvalidTransactionSignature)?;
        let sig_bytes =
            hex::decode(sig_hex).map_err(|_| BlockchainError::InvalidTransactionSignature)?;
        let sig_hash = Transaction::signature_hash_hex(&sig_bytes);
        let storage_tx = full.with_truncated_signature(sig_hash);
        let tx_id = full.get_tx_id();
        let full_sigs_tree = self.db.open_tree(PENDING_FULL_SIGNATURES_TREE)?;
        full_sigs_tree.insert(tx_id.as_bytes(), sig_bytes)?;
        let pending_tree = self.db.open_tree(PENDING_TRANSACTIONS_TREE)?;
        pending_tree.insert(tx_id.as_bytes(), codec::serialize(&storage_tx)?)?;
        Ok(())
    }

    fn rehydrate_reverted_tx(&self, tx: &Transaction) -> Option<Transaction> {
        let full = self.get_confirmed_witness_tx(&tx.get_tx_id())?;
        let has_full_sig = full
            .signature
            .as_deref()
            .and_then(|s| hex::decode(s).ok())
            .map(|b| b.len() > 64)
            .unwrap_or(false);
        has_full_sig.then_some(full)
    }

    async fn try_adopt_orphan_branch(&self) -> Result<bool, BlockchainError> {
        // Heal any state a PRIOR interrupted apply left dirty (a failed reorg leaves storage on the
        // new branch but balances on the old) BEFORE reading the tip or scoring branches, so
        // selection never runs against a stale tip cache / wrong-branch balances (M1). No-op when
        // clean. Runs under the outer RwLock write guard (adopt_external_branch), before
        // adopt_branch_if_valid acquires balances_index_gate, so no re-entrant gate acquisition.
        self.reconcile_chain_state_if_dirty().await?;
        let Some(tip) = self.get_last_block() else {
            return Ok(false);
        };
        let orphan_blocks = self.open_orphan_blocks_tree()?;
        // Steady-state fast path: with no orphans there is nothing to scan — and
        // this runs on EVERY applied block, previously deserializing the whole
        // pool (up to 10k full blocks) under the write lock even when empty.
        if orphan_blocks.is_empty() {
            return Ok(false);
        }
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
        //
        // INVARIANT (bound-3 neutrality): the PRIMARY key MUST stay index-descending. It forces
        // every sub-checkpoint candidate strictly after all above-checkpoint ones, which is the
        // only reason skipping sub-checkpoint candidates BEFORE collect() (H1 bound 3) leaves the
        // MAX_REORG_BRANCHES_EVALUATED-budgeted ranked set identical to the old per-branch filter.
        // Re-keying this by work/difficulty first could let a sub-checkpoint candidate consume the
        // eval budget ahead of an adoptable one and diverge an upgraded node from an un-upgraded peer.
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

        // Rank every work-eligible branch instead of committing to a single "best" before its
        // validity is known. A structurally-valid but balance-invalid same-height competitor can
        // be ground to the lowest tip hash and win the work/tie-break comparison; if that winner
        // is the ONLY branch we ever validate, its post-selection rejection (overspend / replay /
        // missing witnesses) makes us abandon the reorg and never consider the honest tie-winner,
        // prolonging the fork. Keep all eligible branches so a rejected best falls through to the
        // next-best VALID branch — the deterministic lowest-hash tie-break is then resolved over
        // ADOPTABLE branches only.
        let mut ranked: Vec<(Vec<Arc<Block>>, BigUint, BigUint, [u8; 32])> = Vec::new();
        let mut branches_evaluated: usize = 0;
        // Read the finality checkpoint once (monotonic within a pass). Every branch from a candidate
        // shares branch[0] = candidate, so a sub-checkpoint candidate yields only unadoptable
        // branches — skip the whole enumeration for it rather than filtering each branch afterward
        // (bound 3). Value-identical to the former per-branch check, applied one step earlier.
        let checkpoint = self.trusted_checkpoint_height();

        'candidate: for candidate in candidates {
            if candidate.index <= checkpoint {
                continue;
            }
            let branches = self.collect_orphan_branches_from(
                Arc::new(candidate),
                ORPHAN_REORG_DEPTH as usize,
                ORPHAN_BRANCH_SEARCH_LIMIT,
            )?;
            for branch in branches {
                if branches_evaluated >= MAX_REORG_BRANCHES_EVALUATED {
                    debug!(
                        "Reorg scan hit branch-eval budget ({} branches); ranking best found so far",
                        MAX_REORG_BRANCHES_EVALUATED
                    );
                    break 'candidate;
                }
                branches_evaluated += 1;

                let Some(branch_tip) = branch.last() else {
                    continue;
                };
                let branch_tip_hash = branch_tip.hash;
                // Checkpoint finality is now enforced one step earlier, on the candidate seed
                // (branch[0] == candidate for every branch), so no per-branch re-check is needed.
                let fork_height = branch[0].index;
                // O(1) memoised lookup; the suffix covers every fork height in range.
                let canonical_work = canonical_suffix
                    .get(&fork_height)
                    .cloned()
                    .unwrap_or_else(|| BigUint::from(0u8));
                let branch_work = Self::branch_work_to_height(&branch, branch_tip.index);

                // Only rank branches that could actually be adopted over the current tip:
                // strictly more overlap work, or an equal-work SAME-HEIGHT tip whose hash is
                // strictly lower than ours (the deterministic lowest-hash tie-break).
                if branch_work < canonical_work {
                    continue;
                }
                if branch_work == canonical_work
                    && (branch_tip.index != tip.index || branch_tip.hash >= tip.hash)
                {
                    continue;
                }

                ranked.push((branch, branch_work, canonical_work, branch_tip_hash));
            }
        }

        // Best-first: greater overlap-work delta wins; an equal delta breaks to the lower tip
        // hash (identical to the former single-best rule, now expressed as a total order).
        ranked.sort_by(
            |a, b| match Self::compare_work_delta(&a.1, &a.2, &b.1, &b.2) {
                std::cmp::Ordering::Greater => std::cmp::Ordering::Less,
                std::cmp::Ordering::Less => std::cmp::Ordering::Greater,
                std::cmp::Ordering::Equal => a.3.cmp(&b.3),
            },
        );

        // Try branches best-first and adopt the first that passes every validity gate. Bounded
        // so a flood of invalid high-ranked competitors cannot force many dry-runs.
        for (branch, _branch_work, _canonical_work, _branch_tip_hash) in
            ranked.into_iter().take(MAX_REORG_ADOPT_ATTEMPTS)
        {
            // Rehydrate the <=MAX_REORG_ADOPT_ATTEMPTS branches actually dry-run back to owned Block
            // bodies (a value copy of the same bytes) for adopt_branch_if_valid, which mutates and
            // persists them. Only these few branches ever pay the body copy — never all ~4M.
            let branch: Vec<Block> = branch.iter().map(|a| (**a).clone()).collect();
            if self.adopt_branch_if_valid(branch, &tip).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Validate one candidate branch against every reorg gate and, if it passes, apply it
    /// atomically. Returns Ok(true) when the branch is adopted and Ok(false) when a gate rejects
    /// it (the caller then tries the next-best branch); an Err is a genuine fault, some inside
    /// the mutation window where the dirty marker is left set for startup recovery. Split out of
    /// try_adopt_orphan_branch so the deterministic tie-break is resolved over ADOPTABLE branches
    /// rather than a single pre-validation pick.
    async fn adopt_branch_if_valid(
        &self,
        branch: Vec<Block>,
        tip: &Block,
    ) -> Result<bool, BlockchainError> {
        // Validate the selected branch (including parent-linked difficulty adjustment) before
        // applying. An INVALID branch is a rejected candidate — Ok(false), caller tries the
        // next-best — NOT a fault: this is the documented contract of this fn, honored by every
        // other gate below, but this first gate propagated Err out of save_block for an honest
        // block that was ALREADY persisted. One parked malformed orphan (admitted without
        // parent-linked difficulty checks by design — the parent may be missing at receipt)
        // could thereby fail every honest submission that triggered the orphan scan.
        for b in &branch {
            if let Err(e) = self
                .validate_block_internal(b, SignatureValidationMode::AllowTruncatedStored)
                .await
            {
                debug!(
                    "Reorg candidate branch rejected: block {} failed validation: {}",
                    b.index, e
                );
                return Ok(false);
            }
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
        //
        // O(reorg span) fast path: derive the fork-boundary state from the
        // balances index (marker must vouch for the exact current tip) and
        // dry-run ONLY the branch, instead of replaying the whole chain from
        // genesis. Same replay function, same inputs at the boundary, same
        // verdict — the from-genesis walk at ~42k blocks held the write lock
        // past the 10s lock-watchdog on every fork-storm race reorg
        // (2026-07-11: nodes struck chain_ok=false, fell behind, never
        // recovered). The index gate is taken HERE (not at the mutation window
        // below) so no concurrent catch-up moves the tree between the marker
        // check, the dry-run read, and the post-rewrite write-back. Lock order
        // state_mutation_lock -> balances_index_gate, same as the writers'
        // in-lock balance reads; dropped before the mempool reconcile.
        let fork_start = branch[0].index;
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        let index_guard = self.balances_index_gate.lock().await;
        let fork_state =
            self.balances_at_fork_state(&balances_tree, fork_start, tip.index, &branch)?;
        let balance_valid = match &fork_state {
            Some((fork_balances, fork_recent)) => {
                let mut balances = fork_balances.clone();
                let mut recent = fork_recent.clone();
                branch.iter().all(|block| {
                    Self::replay_apply_block_checked(
                        block.index,
                        &block.transactions,
                        &mut balances,
                        &mut recent,
                    )
                    .is_ok()
                })
            }
            // Index can't vouch for the tip (lagging marker, unloadable block):
            // the authoritative from-genesis dry-run, as before.
            None => self.branch_is_balance_valid(fork_start, &branch).await?,
        };
        if !balance_valid {
            debug!(
                "Reorg rejected: branch at height {} fails balance validation (overspend/double-spend)",
                fork_start
            );
            return Ok(false);
        }

        // Replay guard (reorg, fork-aware): a branch may legitimately re-include a
        // transaction from the range it replaces, but it must not replay one that is
        // confirmed BELOW the fork point (in the history the branch keeps). Reject a
        // branch that does — this closes replay via a crafted reorg.
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
                // Fatal, like every other write in this marker-protected window: a swallowed
                // failure would leave a reverted, not-re-confirmed tx registered and later
                // reject its legitimate re-mine as a false replay. Returning Err aborts the
                // reorg with the dirty marker still set, so recovery rebuilds the registry.
                self.remove_confirmed_txs(&old)?;
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

        // The balances-index gate is already held (acquired at the dry-run above)
        // across the whole mutation window: a lazy catch-up
        // (ensure_balances_index) must never read canonical slots mid-rewrite,
        // and the fork-boundary state computed above must stay valid until it is
        // written back below. The dirty marker (set above) makes a gate-waiter
        // skip once it gets in.

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
        // then prune anything now past the freshness window. Fatal (like the revert above):
        // a swallowed failure would leave the adopted branch's txs unregistered so a later
        // block could replay one; returning Err keeps the dirty marker set for recovery.
        for b in &branch {
            self.record_confirmed_txs(b)?;
        }
        let _ = self.prune_confirmed_txs(branch_tip.timestamp);

        // Balances after the reorg, in O(reorg span): the fork-boundary values
        // (already reverted to fork_start-1 for every touched address) commit
        // atomically WITH the marker, then the tested O(gap) catch-up replays
        // the new canonical branch from the freshly-rewritten slots. Falls back
        // to the authoritative from-genesis rebuild when the index could not
        // vouch for the old tip (fork_state None). catch_up itself falls back
        // to the full rebuild on any unloadable/non-replaying block, so every
        // failure path still converges on authoritative values.
        match fork_state {
            Some((reverted, _recent)) => {
                let mut batch = sled::Batch::default();
                for (addr, bal) in &reverted {
                    batch.insert(addr.as_bytes(), codec::serialize(bal)?);
                }
                let fork_base = (fork_start as u64).saturating_sub(1);
                batch.insert(BALANCES_HEIGHT_KEY, codec::serialize(&fork_base)?);
                balances_tree.apply_batch(batch)?;
                self.catch_up_balances_index(&balances_tree, fork_base, branch_tip.index as u64)
                    .await?;
            }
            None => {
                self.rebuild_balances_index(&balances_tree).await?;
            }
        }
        self.write_chain_tip_metadata(&branch_tip)?;
        let _ = self.get_network_difficulty().await?;
        // ONE flush closes the dirty window: Tree::flush() is the same full-DB
        // pagecache fsync as db.flush(), so the two tree flushes that followed
        // were pure repeats.
        self.db.flush()?;
        self.clear_chain_state_dirty()?;
        drop(index_guard);

        // Reconcile the mempool with the reorg (M14). First evict the branch's
        // now-confirmed transactions so they are not double-counted as pending or
        // re-selected into the next block template (mirrors the finalize/persist paths;
        // clear_transaction is a no-op for txs that were never in the local mempool).
        // Then return the reverted transactions the new branch did NOT re-confirm so
        // they can be re-mined instead of being silently lost. Stored blocks keep only
        // truncated (<=64-byte) signatures, so the copies read from get_block above can
        // never pass the full-signature gate — re-queued as-is they would poison every
        // template the miner builds until they age out. Rehydrate each to its full
        // signature from the retained witness store; drop (with a log) any whose full
        // witness this node never held or the retention window has pruned. Re-queued via
        // the Mempool method directly, never self.add_transaction — that re-takes the
        // mutation lock (held across this whole reorg) and would deadlock.
        let mut readmitted = 0usize;
        {
            let mut mempool = self.mempool.write().await;
            for b in &branch {
                for tx in &b.transactions {
                    mempool.clear_transaction(tx);
                }
            }
            for tx in reverted_txs {
                match self.rehydrate_reverted_tx(&tx) {
                    Some(full) => {
                        // DURABILITY FIRST (the other half of M14): the in-memory
                        // readmit alone did not survive the next
                        // sync_mempool_with_sled — any `account`/`info` command,
                        // the gossip re-announce, or a restart wiped the mempool
                        // and rebuilt it from the sled pending tree, where this tx
                        // no longer existed: the payment vanished without trace.
                        // Persist the pending row + full-signature sidecar; the
                        // debit/credit reservations are recomputed in one pass
                        // below.
                        if let Err(e) = self.persist_readmitted_pending_tx(&full) {
                            warn!(
                                "Reorg: could not persist re-queued tx {}: {}",
                                tx.get_tx_id(),
                                e
                            );
                        }
                        // readmit_reverted: floor-exempt — a reverted tx was
                        // consensus-valid in a mined block; the relay floor must
                        // not turn a reorg into silent loss of that payment.
                        let _ = mempool.readmit_reverted(full);
                        readmitted += 1;
                    }
                    None => {
                        debug!(
                            "Reorg: dropping reverted tx {} — full signature unavailable (never held locally or pruned)",
                            tx.get_tx_id()
                        );
                    }
                }
            }
        }
        if readmitted > 0 {
            // One pass recomputes the pending debit/credit reservations from the
            // now-complete pending tree — identical to what the next
            // sync_mempool_with_sled derives, but without waiting for one.
            if let Err(e) = self.rebuild_pending_debits_index().await {
                warn!("Reorg: pending debit index rebuild failed: {}", e);
            }
        }

        self.notify_tip_changed(&branch_tip);

        Ok(true)
    }

    fn prune_orphans(&self) -> Result<(), BlockchainError> {
        let orphan_blocks = self.open_orphan_blocks_tree()?;
        let orphan_index = self.open_orphan_index_tree()?;
        // Steady-state fast path (this runs per applied block and per stored
        // orphan): nothing to prune when both trees are empty.
        if orphan_blocks.is_empty() && orphan_index.is_empty() {
            return Ok(());
        }
        let now = Self::now_unix_secs();
        let tip = self.highest_block_index();
        let mut remove_hashes: Vec<[u8; 32]> = Vec::new();

        let mut retained: Vec<OrphanStoredBlock> = Vec::new();
        let checkpoint = self.trusted_checkpoint_height();
        for item in orphan_blocks.iter() {
            let (_, raw) = item?;
            if let Ok(entry) = codec::deserialize::<OrphanStoredBlock>(&raw) {
                let expired = now.saturating_sub(entry.received_at) > ORPHAN_TTL_SECS;
                let stale_height = tip
                    .map(|t| entry.block.index.saturating_add(ORPHAN_REORG_DEPTH) < t)
                    .unwrap_or(false);
                // Finality invariant applied to the pool: no adoptable branch may
                // fork at/below the trusted checkpoint (branch[0].index must be
                // above it), so an orphan AT or BELOW the checkpoint can never be
                // part of an adopted branch — it is dead weight that only feeds
                // branch re-assembly on every ingest. Pruning it also severs the
                // ancestry of any long dead fork (the 2026-07-11 ~770-block
                // incompatible-client branch) so it stops re-assembling at all.
                // The checkpoint never regresses, so this can never discard a
                // block a future reorg could want.
                let finalized_below = checkpoint > 0 && entry.block.index <= checkpoint;
                if expired || stale_height || finalized_below {
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
        // Heal any state a PRIOR interrupted apply left dirty BEFORE this persist reads balances
        // (process_transactions_batch below), so a marker left ahead of the tip by a failed apply
        // cannot double-credit this block's coinbase on the retry (H4). No-op when clean. Also
        // covers the promote_orphans_from_tip loop, where a mid-loop persist failure must be healed
        // before the next iteration's balance read.
        self.reconcile_chain_state_if_dirty().await?;

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
            .process_transactions_batch(&block.transactions, tx_context, block.index as u64)
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
        // now past the freshness window so the registry stays bounded. The register
        // write must be fatal: swallowing a failure here would commit the block (below)
        // with its transactions absent from the registry AND clear the dirty marker, so
        // startup recovery would never rebuild it — and the replay guard would later miss
        // a re-mine of one of these confirmed payments. Returning Err leaves the marker set
        // (and the block unstored), so recovery heals the registry from the canonical chain.
        if let Err(err) = self.record_confirmed_txs(block) {
            warn!(
                "Block {} replay-registry write failed; dirty marker remains for startup recovery: {}",
                block.index, err
            );
            return Err(err);
        }
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
        // The index just advanced at the current tip; drop the supply memo (keyed by tip version)
        // so /explorer/supply doesn't serve a pre-catch-up partial sum until the next block.
        *self.supply_cache.lock() = None;
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

        // The index was rebuilt fully current; drop the supply memo so /explorer/supply cannot keep
        // serving a pre-rebuild partial sum. Covers every catch-up fallback and the direct rebuild.
        *self.supply_cache.lock() = None;
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

    /// Exact arithmetic inverse of replay_apply_block_checked over RAW confirmed
    /// totals: coinbase -> recipient loses the reward; anything else -> sender
    /// regains the full debit (amount + fee), recipient loses the amount. The
    /// special case mirrors the apply's predicate byte-for-byte (`sender ==
    /// "MINING_REWARDS"`, NOT the wider SYSTEM_ADDRESSES set). No solvency or
    /// maturity logic on purpose: maturity is a comparison-time overlay that
    /// never changes stored values (see replay_apply_block_checked), and a
    /// revert of already-applied blocks cannot fail — the sums are additive and
    /// order-independent, so intermediate negatives in the in-memory map are
    /// fine and never reach disk (callers write one final batch).
    fn replay_revert_block(txs: &[Transaction], balances: &mut HashMap<String, i128>) {
        for tx in txs {
            if tx.sender == "MINING_REWARDS" {
                *balances.entry(tx.recipient.clone()).or_insert(0) -= tx.amount_units;
                continue;
            }
            *balances.entry(tx.sender.clone()).or_insert(0) += tx.total_debit_units();
            *balances.entry(tx.recipient.clone()).or_insert(0) -= tx.amount_units;
        }
    }

    /// The state a reorg needs at the fork boundary, derived in O(reorg span)
    /// from the balances index instead of an O(chain) from-genesis replay: RAW
    /// confirmed balances exactly as of `fork_start - 1` for every address the
    /// reverted blocks or the candidate branch touch, plus the rolling
    /// immature-coinbase window seeded exactly as a from-genesis replay would
    /// hold it entering `fork_start` (same conservative seed as
    /// catch_up_balances_index — over-seeding is self-correcting).
    ///
    /// Returns None — callers MUST fall back to the O(chain) full replay /
    /// rebuild — whenever the index cannot vouch for the exact current tip:
    /// marker != old_tip (index lagging or mid-recovery), any reverted or seed
    /// block fails to load, or fork_start is 0. When Some is returned the
    /// values are byte-equivalent to a from-genesis replay for the touched set:
    /// the marker proves the index applied exactly blocks [0, old_tip], and
    /// replay_revert_block is the exact inverse of the apply over the reverted
    /// span. Caller must hold balances_index_gate across this call AND the
    /// subsequent write-back so no concurrent catch-up moves the tree.
    fn balances_at_fork_state(
        &self,
        balances_tree: &sled::Tree,
        fork_start: u32,
        old_tip: u32,
        branch: &[Block],
    ) -> Result<
        Option<(
            HashMap<String, i128>,
            std::collections::VecDeque<(u32, String, i128)>,
        )>,
        BlockchainError,
    > {
        if fork_start == 0 || fork_start > old_tip {
            return Ok(None);
        }
        if Self::get_balances_height(balances_tree)? != Some(old_tip as u64) {
            return Ok(None);
        }

        // Touch set mirrors replay_apply_block_checked: a coinbase touches its
        // recipient only; anything else touches sender and recipient. Branch
        // addresses are included so the dry-run reads every value it needs.
        let mut touched: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut collect = |txs: &[Transaction]| {
            for tx in txs {
                if tx.sender != "MINING_REWARDS" {
                    touched.insert(tx.sender.clone());
                }
                touched.insert(tx.recipient.clone());
            }
        };
        let mut reverted_blocks: Vec<Block> =
            Vec::with_capacity((old_tip - fork_start + 1) as usize);
        for h in fork_start..=old_tip {
            let Ok(block) = self.get_block(h) else {
                return Ok(None);
            };
            collect(&block.transactions);
            reverted_blocks.push(block);
        }
        for b in branch {
            collect(&b.transactions);
        }

        let mut balances: HashMap<String, i128> = HashMap::new();
        for addr in &touched {
            let value = match balances_tree.get(addr.as_bytes())? {
                Some(raw) => Self::deserialize_units_compatible(&raw)?,
                None => 0,
            };
            balances.insert(addr.clone(), value);
        }
        for block in &reverted_blocks {
            Self::replay_revert_block(&block.transactions, &mut balances);
        }

        // Maturity window entering fork_start — blocks below the fork are
        // canonical and untouched by the reorg, so this seed is identical for
        // the old and new histories. Ascending order matches the replay's push
        // order (the pop loop only inspects the front).
        let mut recent: std::collections::VecDeque<(u32, String, i128)> =
            std::collections::VecDeque::new();
        let seed_low = fork_start.saturating_sub(MINING_REWARD_MATURITY);
        for rh in seed_low..fork_start {
            let Ok(block) = self.get_block(rh) else {
                return Ok(None);
            };
            for tx in &block.transactions {
                if tx.sender == "MINING_REWARDS" {
                    recent.push_back((block.index, tx.recipient.clone(), tx.amount_units));
                }
            }
        }

        Ok(Some((balances, recent)))
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

    /// Batched form of the M06 overlay for the local-miner affordability gates: the total
    /// still-immature MINING_REWARDS credited to each recipient at `spend_height`, computed in
    /// ONE pass over the maturity window instead of one per transaction. For any address the
    /// returned value equals `immature_reward_units_scan(address, spend_height, &[])` exactly —
    /// same window [spend_height-MATURITY+1, spend_height), same MINING_REWARDS filter, same
    /// below-activation cutoff, and the block's own (in-flight) coinbase excluded — so a
    /// per-sender lookup is byte-identical to the per-tx scan while turning a full block's
    /// O(tx x MATURITY) block reads into O(MATURITY), keeping the gates well under the miner's
    /// solve-validation timeout as blocks fill.
    fn immature_rewards_by_recipient(
        &self,
        transactions: &[Transaction],
        spend_height: u32,
    ) -> HashMap<String, i128> {
        let mut immature_by_addr: HashMap<String, i128> = HashMap::new();
        let has_regular_sender = transactions.iter().any(|tx| tx.sender != "MINING_REWARDS");
        if !has_regular_sender || spend_height < MATURITY_ACTIVATION_HEIGHT {
            return immature_by_addr;
        }
        let spend_height = spend_height as u64;
        let low = spend_height
            .saturating_sub(MINING_REWARD_MATURITY as u64)
            .saturating_add(1);
        for rh in low..spend_height {
            if let Ok(b) = self.get_block(rh as u32) {
                for tx in &b.transactions {
                    if tx.sender == "MINING_REWARDS" {
                        *immature_by_addr.entry(tx.recipient.clone()).or_default() +=
                            tx.amount_units;
                    }
                }
            }
        }
        immature_by_addr
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
            signature_cache,
            genesis_timestamp: Arc::new(std::sync::OnceLock::new()),
            last_known_checkpoint: Arc::new(AtomicU64::new(0)),
            state_mutation_lock: Arc::new(Mutex::new(())),
            pending_rules_gate: Arc::new(Mutex::new(())),
            pending_rules_complete: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            pending_rules_revalidation_runs: Arc::new(AtomicUsize::new(0)),
            balances_index_gate: Arc::new(Mutex::new(())),
            tip_change_counter,
            chain_tip_cache: Arc::new(PLMutex::new(None)),
            supply_cache: Arc::new(PLMutex::new(None)),
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
        // Validate-then-trust, don't rebuild: current_chain_tip_metadata reads the
        // persisted CHAIN_TIP, verifies it against one stored block, and only falls
        // back to the full rebuild — a complete scan_prefix("block_") that pages in
        // every block body — when the stored tip doesn't check out. The
        // unconditional rebuild here was a whole-chain scan on EVERY boot (tens of
        // seconds on a multi-GB chain); the crash-dirty path below still
        // force-rebuilds via recover_dirty_chain_state.
        let _ = self.current_chain_tip_metadata()?;

        // Get and set the network difficulty first
        self.get_network_difficulty().await?;

        // Sync mempool with sled
        let _ = self.prune_pending_transactions();
        self.sync_mempool_with_sled().await?;
        self.pending_rules_complete.store(
            self.next_block_index() >= FEE_SYSTEM_ACTIVATION_HEIGHT,
            Ordering::Release,
        );
        self.rebuild_pending_debits_index().await?;

        // Recover from an interrupted apply (a crash OR a live mid-apply Err) via the SAME path the
        // live reconcile uses (recover_dirty_chain_state), so startup and live recovery cannot
        // drift: it re-anchors the tip, force-rebuilds balances + the replay registry from the
        // canonical chain, and clears the marker last. Non-dirty startup just ensures the balances
        // index is current.
        match dirty_state.as_ref() {
            Some(marker) => self.recover_dirty_chain_state(marker).await?,
            None => self.ensure_balances_index().await?,
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

        // Heal any state a PRIOR interrupted apply left dirty before the tip-shape classification
        // below reads highest_block_index(): a stale cached tip from a failed reorg would otherwise
        // misclassify this block. No-op when clean.
        self.reconcile_chain_state_if_dirty().await?;

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

        // Heal any state a PRIOR interrupted apply left dirty before the tip-shape classification
        // below reads highest_block_index() (same reasoning as save_block). No-op when clean.
        self.reconcile_chain_state_if_dirty().await?;

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

        // THE mining self-fork fix (H4): heal any state a PRIOR interrupted apply left dirty BEFORE
        // the tip check, the balance prefetch, and process_transactions_batch below. A finalize that
        // failed after advancing the balances marker but before storing its block leaves the marker
        // ahead of the tip; without healing here the retry re-mines against the inflated balance and
        // credits the coinbase twice (base + 2*reward), self-forking the ledger. No-op when clean.
        self.reconcile_chain_state_if_dirty().await?;

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
                // Exact i128 to match the consensus writer process_transactions_batch;
                // a gate-vs-writer round-trip mismatch above ~33.55M coins would burn
                // valid mined blocks (2026-07-12 audit).
                let balance_units = self.get_confirmed_balance_units(&tx.sender).await?;
                confirmed_balances.insert(tx.sender.clone(), balance_units);
            }
        }
        set_finalize_stage(2);
        trace_step("prefetch_balances");

        // Precompute the M06 immature-reward overlay once for the whole block instead of
        // re-scanning the maturity window per transaction (equal value-for-value; see
        // immature_rewards_by_recipient). in_flight = &[] semantics preserved: the block's own
        // coinbase is excluded, matching the per-tx scan and the authoritative apply below.
        let immature_by_addr = self.immature_rewards_by_recipient(&block.transactions, block.index);

        // Second pass: Validate transactions and track effects
        for tx in &block.transactions {
            if tx.sender == "MINING_REWARDS" {
                continue; // Skip validation for mining rewards
            }

            let confirmed = confirmed_balances.get(&tx.sender).copied().unwrap_or(0);
            let pending = pending_effects.get(&tx.sender).copied().unwrap_or(0);
            // M06 (defense-in-depth): don't let the local miner commit a block that spends an
            // immature reward — process_transactions_batch would reject it anyway.
            // in_flight = &[] (NOT &block.transactions): `confirmed`/`pending` here are the
            // PRE-block balance (the block's own coinbase, MINING_REWARDS, is skipped above and
            // never credited), so the coinbase must NOT be subtracted via immature either. The
            // authoritative apply (process_transactions_batch) credits the coinbase AND counts it
            // immature so it CANCELS; passing &block.transactions here subtracted it without the
            // credit, making this gate exactly one reward R stricter than consensus and rejecting a
            // valid full-spendable self-spend — the "Insufficient funds while mining" burn
            // (2026-07-12 audit). &[] matches add_transaction and the authority exactly.
            let immature = immature_by_addr.get(&tx.sender).copied().unwrap_or(0);
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
                &block.transactions,
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
        // process_transactions_batch's batch.
        self.write_chain_tip_metadata(&block)?;
        set_finalize_stage(6);
        trace_step("balances_height");
        // ONE flush closes the dirty window (Tree::flush() == full-DB fsync; the
        // two tree flushes that followed were pure repeats).
        self.db.flush()?;

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
        // Evict the now-confirmed txs from the in-memory mempool FIRST (closes the window
        // where the miner re-selects them into the next template before a restart), then
        // register them in the replay registry.
        {
            let mut mempool = self.mempool.write().await;
            for tx in &block.transactions {
                mempool.clear_transaction(tx);
            }
        }
        // The registry write is fatal: on failure, return Err here — skipping
        // clear_chain_state_dirty below — so the dirty marker survives and startup recovery
        // force-rebuilds the registry from the canonical chain. Swallowing it would commit the
        // block with its txs unregistered AND clear the recovery signal, letting the replay
        // guard later miss a re-mine of one of these payments. (Kept out of any await scope:
        // BlockchainError is !Send.)
        if let Err(err) = self.record_confirmed_txs(&block) {
            warn!(
                "Finalized block {} replay-registry write failed; leaving dirty marker for startup recovery: {}",
                block.index, err
            );
            return Err(err);
        }
        let _ = self.prune_confirmed_txs(block.timestamp);
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
        let pending_credits_tree = self.open_pending_credits_tree()?;
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

            let current_credit = self.get_pending_credit_units(&tx.recipient).await?;
            let next_credit = current_credit.saturating_sub(tx.amount_units);
            Self::set_pending_credit_for(&pending_credits_tree, &tx.recipient, next_credit)?;
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
        pending_credits_tree.flush()?;

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

        // For regular transactions, validate balance with proper pending tracking.
        // Exact i128 on BOTH operands (confirmed and pending): f64 subtraction is lossy
        // above ~18M coins even below the round-trip onset, so keep the whole compare in
        // integer units (2026-07-12 audit).
        let confirmed_units = self.get_confirmed_balance_units(&tx.sender).await?;
        let pending_units = if block.is_none() {
            // Only check pending for new transactions, not during block validation
            self.get_pending_debit_units(&tx.sender).await?
        } else {
            0
        };

        // M06 (advisory): for mempool admission (block=None) don't offer to spend an immature
        // reward at the prospective next height. The block=Some path is a local-miner check
        // already covered by gate (1) / the finalize inline check, so it stays 0 here.
        let immature = match block {
            None => {
                let h = self.get_latest_block_index() + 1;
                self.immature_reward_units_scan(&tx.sender, h, &[])
            }
            Some(_) => 0,
        };
        let available_balance = confirmed_units - pending_units - immature;
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

        // Bind the CLAIMED sig_hash to the actual signature BEFORE consulting the cache — on every
        // call, warm or cold. sig_hash is merkle-committed, but the cache key covers only
        // (tx_id, pub_key, actual_hash), NOT the claimed sig_hash. Left after the cache, a warm
        // entry from a genuine tx would let a variant carrying the SAME signature but a FORGED
        // sig_hash skip this check: a warm node accepts a block a cold node rejects — a frontier-
        // path divergence, since block_signatures_fully_verified delegates here without its own
        // sig_hash re-derivation. Running it first closes that gap at zero real cost (a hex compare).
        if let Some(expected_hash) = &tx.sig_hash {
            if &actual_hash != expected_hash {
                return Err(BlockchainError::InvalidTransactionSignature);
            }
        }

        // Digest the pub_key into the cache key rather than embedding the full ML-DSA hex (~4-5 KB
        // per entry). SHA256 is collision-resistant, so distinct pub_keys can't share a digest: the
        // key still binds (tx_id, pub_key, actual_hash) exactly — a same-signature but
        // different-claimed-pub_key tx still misses the warm entry — at ~64 bytes instead of ~5 KB.
        // At the 50k default capacity this drops the cache from hundreds of MiB to ~10 MiB.
        let pub_key_digest = Transaction::signature_hash_hex(pub_key.as_bytes());
        let cache_key = format!("{}:{}:{}", tx.get_tx_id(), pub_key_digest, actual_hash);

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

    fn is_valid_hash_with_difficulty(&self, hash: &[u8; 32], difficulty: u64) -> bool {
        let hash_int = BigUint::from_bytes_be(hash);
        let target = pow_target_from_difficulty(difficulty);

        hash_int <= target
    }

    /// True if `transactions` repeats a non-coinbase transaction id. Coinbase (`MINING_REWARDS`)
    /// entries are exempt — single-coinbase positioning and reward correctness are enforced
    /// separately.
    fn has_duplicate_regular_tx(transactions: &[Transaction]) -> bool {
        let mut seen = HashSet::with_capacity(transactions.len());
        for tx in transactions {
            if tx.sender == "MINING_REWARDS" {
                continue;
            }
            if !seen.insert(tx.get_tx_id()) {
                return true;
            }
        }
        false
    }

    fn hex_field_has_decoded_len(value: &str, decoded_len: usize) -> bool {
        let Some(encoded_len) = decoded_len.checked_mul(2) else {
            return false;
        };
        value.len() == encoded_len
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    }

    fn full_witness_transaction_weight(tx: &Transaction) -> Result<usize, BlockchainError> {
        let mut tx_weight = TRANSACTION_WEIGHT_FIXED_BYTES
            .checked_add(tx.sender.len())
            .and_then(|value| value.checked_add(tx.recipient.len()))
            .ok_or(BlockchainError::BlockWeightExceeded)?;

        if !SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
            let signature_bytes = mldsa::SIGNATURE_BYTES
                .checked_mul(2)
                .ok_or(BlockchainError::BlockWeightExceeded)?;
            let public_key_bytes = mldsa::PUBLIC_KEY_BYTES
                .checked_mul(2)
                .ok_or(BlockchainError::BlockWeightExceeded)?;
            tx_weight = tx_weight
                .checked_add(signature_bytes)
                .and_then(|value| value.checked_add(public_key_bytes))
                .and_then(|value| value.checked_add(64))
                .ok_or(BlockchainError::BlockWeightExceeded)?;
        }
        Ok(tx_weight)
    }

    /// Deterministic block weight with every regular transaction charged as a
    /// full ML-DSA witness. Stored blocks therefore have exactly the same weight
    /// as the full blocks from which their receipt signatures were derived.
    pub fn full_witness_weight(block: &Block) -> Result<usize, BlockchainError> {
        let mut weight = BLOCK_WEIGHT_FIXED_BYTES;
        for tx in &block.transactions {
            weight = weight
                .checked_add(Self::full_witness_transaction_weight(tx)?)
                .ok_or(BlockchainError::BlockWeightExceeded)?;
        }
        Ok(weight)
    }

    fn validate_activated_transaction_shape(
        tx: &Transaction,
        sig_mode: SignatureValidationMode,
    ) -> Result<(), BlockchainError> {
        if !is_canonical_user_address(&tx.recipient) {
            return Err(BlockchainError::NonCanonicalTransaction);
        }

        if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
            if tx.signature.is_some() || tx.pub_key.is_some() || tx.sig_hash.is_some() {
                return Err(BlockchainError::NonCanonicalTransaction);
            }
            return Ok(());
        }

        if !is_canonical_user_address(&tx.sender) {
            return Err(BlockchainError::NonCanonicalTransaction);
        }

        let pub_key = tx
            .pub_key
            .as_deref()
            .ok_or(BlockchainError::NonCanonicalTransaction)?;
        if !Self::hex_field_has_decoded_len(pub_key, mldsa::PUBLIC_KEY_BYTES) {
            return Err(BlockchainError::NonCanonicalTransaction);
        }

        let sig_hash = tx
            .sig_hash
            .as_deref()
            .ok_or(BlockchainError::NonCanonicalTransaction)?;
        if !Self::hex_field_has_decoded_len(sig_hash, 32) {
            return Err(BlockchainError::NonCanonicalTransaction);
        }

        let signature = tx
            .signature
            .as_deref()
            .ok_or(BlockchainError::NonCanonicalTransaction)?;
        let is_full = Self::hex_field_has_decoded_len(signature, mldsa::SIGNATURE_BYTES);
        let is_receipt = Self::hex_field_has_decoded_len(signature, 64);
        if !is_full && !(sig_mode == SignatureValidationMode::AllowTruncatedStored && is_receipt) {
            return Err(BlockchainError::NonCanonicalTransaction);
        }
        Ok(())
    }

    fn validate_activated_block_shape(
        block: &Block,
        sig_mode: SignatureValidationMode,
    ) -> Result<(), BlockchainError> {
        for tx in &block.transactions {
            Self::validate_activated_transaction_shape(tx, sig_mode)?;
        }

        if Self::full_witness_weight(block)? > MAX_BLOCK_WEIGHT_BYTES {
            return Err(BlockchainError::BlockWeightExceeded);
        }
        Ok(())
    }

    fn validate_block_shape_rules_at(
        block: &Block,
        sig_mode: SignatureValidationMode,
        activation_height: u32,
    ) -> Result<(), BlockchainError> {
        if block.index < activation_height {
            return Ok(());
        }
        Self::validate_activated_block_shape(block, sig_mode)
    }

    fn template_regular_transaction_weight_at(
        block_index: u32,
        transaction: &Transaction,
        activation_height: u32,
    ) -> Result<Option<usize>, BlockchainError> {
        if block_index < activation_height {
            return Ok(None);
        }
        if SYSTEM_ADDRESSES.contains(&transaction.sender.as_str()) {
            return Err(BlockchainError::NonCanonicalTransaction);
        }
        Self::validate_activated_transaction_shape(
            transaction,
            SignatureValidationMode::RequireFull,
        )?;
        Self::full_witness_transaction_weight(transaction).map(Some)
    }

    /// Activated template check for one regular full-witness transaction.
    /// `None` means the activation height has not yet been reached.
    pub fn template_regular_transaction_weight(
        block_index: u32,
        transaction: &Transaction,
    ) -> Result<Option<usize>, BlockchainError> {
        Self::template_regular_transaction_weight_at(
            block_index,
            transaction,
            FEE_SYSTEM_ACTIVATION_HEIGHT,
        )
    }

    /// Fixed block plus canonical coinbase weight reserved before regular template
    /// packing begins.
    pub fn mining_template_base_weight(miner_address: &str) -> Result<usize, BlockchainError> {
        if !is_canonical_user_address(miner_address) {
            return Err(BlockchainError::NonCanonicalTransaction);
        }
        BLOCK_WEIGHT_FIXED_BYTES
            .checked_add(TRANSACTION_WEIGHT_FIXED_BYTES)
            .and_then(|value| value.checked_add("MINING_REWARDS".len()))
            .and_then(|value| value.checked_add(miner_address.len()))
            .ok_or(BlockchainError::BlockWeightExceeded)
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
        // Distinct error (not InvalidBlockHeader) so a continuous miner never mistakes
        // this for a lost race and re-grinds the same over-full template forever.
        if block.transactions.len() > MAX_BLOCK_TX_COUNT {
            return Err(BlockchainError::BlockTransactionCountExceeded);
        }

        Self::validate_block_shape_rules_at(block, sig_mode, FEE_SYSTEM_ACTIVATION_HEIGHT)?;

        // Intra-block transaction-id uniqueness: a block must not contain the same non-coinbase
        // transaction more than once. Honest block construction never produces this (the mempool
        // is keyed by tx_id and block assembly emits each entry once), so it never affects a
        // legitimately-built block. Deterministic, no lock/IO/state; enforced on every ingress
        // path (tip-extension, reorg, receipt/full sync all route through here).
        if Self::has_duplicate_regular_tx(&block.transactions) {
            return Err(BlockchainError::DuplicateTransaction);
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

        // Validate the single, first-position reward and the activated fee-accounting
        // invariant. The required coinbase remains the historical reward calculation
        // exactly; the added rule only narrows which fee combinations are admissible.
        self.validate_block_reward_rules_at(block, FEE_SYSTEM_ACTIVATION_HEIGHT)?;

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

        // Bound transactions per block (DoS + liveness): reject an over-full template
        // BEFORE finalize, with an error distinct from a lost race, so the continuous
        // miner treats it as a real fault instead of re-grinding it forever. The template
        // selector already caps at MAX_BLOCK_TX_COUNT-1, so this only fires on a block
        // built by some other path.
        if block.transactions.len() > MAX_BLOCK_TX_COUNT {
            return Err(BlockchainError::BlockTransactionCountExceeded);
        }

        Self::validate_block_shape_rules_at(
            block,
            SignatureValidationMode::RequireFull,
            FEE_SYSTEM_ACTIVATION_HEIGHT,
        )?;
        if block.index >= FEE_SYSTEM_ACTIVATION_HEIGHT {
            self.validate_block_reward_rules_at(block, FEE_SYSTEM_ACTIVATION_HEIGHT)?;
        }

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

        // Fetch all confirmed balances in one pass. Exact i128 to match the consensus
        // writer (round-trip drifts above ~33.55M coins — 2026-07-12 audit).
        for sender in unique_senders {
            let balance_units = self.get_confirmed_balance_units(sender).await?;
            confirmed_balances.insert(sender.clone(), balance_units);
        }

        // Precompute the M06 immature-reward overlay once for the whole block instead of
        // re-scanning the maturity window per transaction (equal value-for-value; see
        // immature_rewards_by_recipient). in_flight = &[] semantics preserved.
        let immature_by_addr = self.immature_rewards_by_recipient(&block.transactions, block.index);

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
            // in_flight = &[] (NOT &block.transactions), same reasoning as finalize_block: the
            // block's own coinbase is not credited into current_confirmed/pending_deducted, so
            // subtracting it via immature made this gate one reward stricter than the authoritative
            // apply (where the coinbase cancels) and burned valid self-spend solves (2026-07-12).
            let immature = immature_by_addr.get(&tx.sender).copied().unwrap_or(0);
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

        // RELAY-POLICY fee floor (anti-spam). Like the self-transfer guard below,
        // this is deliberately mempool-admission ONLY — block validation never
        // checks it, so a mined block carrying a lower-fee tx stays fully valid
        // and this can never fork the chain (enforcing it in validation would be
        // a soft fork). 0.0001 is the largest always-whisper-safe flat floor
        // (see MIN_RELAY_FEE_UNITS), so every legitimate wallet/whisper fee
        // passes. Fees only burn when mined, so this prices CONFIRMED
        // chain-bloat (each block-landing spam tx costs real coins); unmined
        // mempool spam stays bounded by the caps, rate limiter and TTL.
        if transaction.fee_units < MIN_RELAY_FEE_UNITS {
            return Err(BlockchainError::FeeBelowRelayFloor);
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

        // The activation transition owns its own gate and takes the state lock
        // internally. Run it before admission takes that lock so concurrent first
        // post-activation submissions cannot deadlock or bypass pending cleanup.
        self.ensure_pending_rules_for_next_block().await?;

        // Serialize admission with block application before deriving the candidate
        // height. This closes the activation-boundary race where validation could
        // observe the preceding height, wait for a block apply, then reserve a
        // transaction under rules that had become active in the meantime.
        let _state_guard = self.state_mutation_lock.lock().await;
        let candidate_index = self.next_block_index();
        let candidate_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if candidate_index < FEE_SYSTEM_ACTIVATION_HEIGHT {
            // `ensure_pending_rules_for_next_block` runs before this lock. A
            // reorg may have moved the tip below activation while admission was
            // waiting here; clear completion under the serialized tip view so a
            // later recross cannot skip cleanup of this pre-rule admission.
            self.pending_rules_complete.store(false, Ordering::Release);
        } else {
            // A caller may omit sig_hash because admission derives it from the
            // verified full witness. If one is supplied, however, it must already
            // be the canonical commitment rather than an alternate textual form.
            if transaction
                .sig_hash
                .as_ref()
                .is_some_and(|claimed| claimed != &sig_hash)
            {
                return Err(BlockchainError::NonCanonicalTransaction);
            }
            if !self.pending_transaction_is_admissible_at(
                candidate_index,
                candidate_timestamp,
                &mempool_tx,
                FEE_SYSTEM_ACTIVATION_HEIGHT,
            )? {
                return Err(BlockchainError::FeeAccountingLimitExceeded);
            }
        }

        // Create storage version with truncated signature + signature hash
        let storage_tx = mempool_tx.with_truncated_signature(sig_hash);
        let tx_id = storage_tx.get_tx_id();

        // The cheap early replay check avoids unnecessary ML-DSA work. Repeat it
        // under the state lock so a transaction confirmed while its signature was
        // being verified cannot be reinserted into pending state.
        if self.confirmed_tx_index(&tx_id).is_some() {
            return Err(BlockchainError::InvalidTransaction);
        }

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

        // Exact i128 on both operands, same reasoning as validate_transaction:
        // f64 confirmed/pending subtraction is lossy at large balances (2026-07-12 audit).
        let confirmed_units = self
            .get_confirmed_balance_units(&transaction.sender)
            .await?;
        let pending_units = self.get_pending_debit_units(&transaction.sender).await?;

        // M06 (advisory): don't admit a tx that spends an immature reward at the next height.
        let immature = self.immature_reward_units_scan(
            &transaction.sender,
            self.get_latest_block_index() + 1,
            &[],
        );
        let available_balance = confirmed_units - pending_units - immature;
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

    /// Zero-cost mempool emptiness probe (read guard + atomic counter).
    pub async fn mempool_is_empty(&self) -> bool {
        self.mempool.read().await.is_empty()
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

    /// Whether a mempool transaction is eligible for the miner's next block
    /// template. This is THE template-candidate predicate: the miner's packing
    /// loop and the fee estimator both call it, so the two can never drift —
    /// the estimator prices exactly the competition the miner will consider.
    /// Checks, in order: not a system/coinbase sender, not already confirmed,
    /// canonical positive amounts, at or above the relay-policy fee floor,
    /// fresh enough to survive the nonce grind (MAX_TX_AGE_SECS minus the
    /// template margin), not future-dated beyond consensus tolerance, and
    /// carrying its FULL witness (a truncated stored signature can never be
    /// templated — the mined block would fail full verification).
    pub fn is_template_candidate(&self, tx: &Transaction, now_secs: u64) -> bool {
        if tx.sender == "MINING_REWARDS" {
            return false;
        }
        if self.is_tx_confirmed(&tx.get_tx_id()) {
            return false;
        }
        if !tx.has_valid_regular_amounts() {
            return false;
        }
        if tx.fee_units < MIN_RELAY_FEE_UNITS {
            return false;
        }
        if tx.timestamp.saturating_add(MAX_TX_AGE_SECS)
            < now_secs.saturating_add(TEMPLATE_FRESHNESS_MARGIN_SECS)
        {
            return false;
        }
        if tx.timestamp > now_secs.saturating_add(MAX_BLOCK_FUTURE_TIME) {
            return false;
        }
        if let Some(sig_hex) = &tx.signature {
            if let Ok(bytes) = hex::decode(sig_hex) {
                return bytes.len() > 64;
            }
        }
        false
    }

    /// THE template-selection ordering: highest fee first, ties broken by the
    /// oldest signed timestamp. Shared by the miner's packing loop and the fee
    /// estimator (see is_template_candidate for why sharing matters). Regular
    /// transactions are near-constant size (the ML-DSA witness dominates), so
    /// exact fee order tracks fee-per-byte.
    pub fn template_candidate_order(a: &Transaction, b: &Transaction) -> std::cmp::Ordering {
        b.fee_units
            .cmp(&a.fee_units)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
    }

    /// Snapshot the raw mempool and produce the wallet/API fee recommendation.
    /// Async canonical form (CLI create path): briefly takes the INNER mempool
    /// read lock only — it never touches the outer chain RwLock, so it is safe
    /// to call while the caller already holds a chain read guard (the miner and
    /// the info command both hold one across mempool access; same lock order).
    pub async fn fee_estimate(&self) -> FeeEstimate {
        let candidates = {
            // Prune first, exactly like the miner's template path: an
            // arrival-TTL-expired transaction is competition the miner will
            // never see, and counting it would inflate the recommendation.
            let mut mempool = self.mempool.write().await;
            mempool.prune_expired();
            mempool.get_all_transactions()
        };
        self.fee_estimate_from_candidates(candidates, Self::now_unix_secs())
    }

    /// Non-blocking form for sync contexts that must never await while holding
    /// the chain read guard (explorer handlers, the info display): None when
    /// the mempool lock is momentarily contended (miner mid-template) — callers
    /// surface "busy" or say so rather than blocking. Read-only, so it cannot
    /// prune: transactions past their arrival TTL but not yet swept (bounded by
    /// the re-announce loop's prune cadence) may still count as competition,
    /// which errs toward recommending MORE, never less.
    pub fn try_fee_estimate(&self) -> Option<FeeEstimate> {
        let candidates = self.mempool.try_read().ok()?.get_all_transactions();
        Some(self.fee_estimate_from_candidates(candidates, Self::now_unix_secs()))
    }

    /// The estimator core: a pure function of the mempool snapshot and the
    /// template-selection rules. Deliberately STATELESS (no history, no EMA) so
    /// it stays deterministic, testable, and never needs retuning: every input
    /// is a constant that already governs block building, so if those evolve
    /// the estimate follows automatically.
    ///
    /// Model: replay the real path a transaction takes into a block, in the
    /// order the pipeline actually applies it.
    ///
    /// STAGE 1 — the mempool feed. Mempool::get_transactions_for_block caps its
    /// output at MAX_TRANSACTIONS_PER_BLOCK / MAX_BLOCK_SIZE over the RAW pool,
    /// BEFORE the miner filters anything. Ineligible-but-pooled transactions
    /// (sub-floor rehydrations, truncated-witness reorg readmits, stale
    /// timestamps) therefore consume real selection budget, so this walk debits
    /// them too and only skips them for INCLUSION. Modeling the two stages in
    /// the wrong order would report "quiet" while junk starves the template.
    ///
    /// STAGE 2 — the miner's packing gates: the count cap (MAX_BLOCK_TX_COUNT
    /// minus the coinbase slot), the serialized-bytes relayability cap
    /// (MAX_TEMPLATE_TX_BYTES), and post-activation the consensus weight budget
    /// (MAX_BLOCK_WEIGHT_BYTES, from the canonical coinbase base weight —
    /// identical for every canonical miner address, so a placeholder is exact).
    ///
    /// The walk is BOUNDED: it stops as soon as the feed budget is spent, so
    /// cost is O(next-block capacity), never O(mempool). That matters because
    /// this runs behind an unauthenticated endpoint and under a chain read
    /// guard — an attacker cannot turn a 50k-transaction pool into 50k
    /// serializations per request.
    ///
    /// Verdict: capacity must absorb the eligible backlog PLUS the caller's own
    /// transaction — the estimate exists to price THAT transaction in, so the
    /// walk reserves TYPICAL_FULL_WITNESS_TX_BYTES of headroom exactly like the
    /// miner reserves the coinbase slot. Room to spare means uncontended:
    /// recommend the flat anchor. Otherwise recommend one unit above the
    /// weakest INCLUDED fee (the age tiebreak favors incumbents, so merely
    /// matching it loses), clamped to FEE_ESTIMATE_AUTO_CAP_UNITS so no mempool
    /// state — organic or deliberately stuffed — can make an automatic fee
    /// spend a meaningful balance.
    ///
    /// Deliberate approximations, all erring toward recommending MORE than
    /// strictly needed (overshoot still lands next block, and the oldest-first
    /// tiebreak guarantees eventual inclusion regardless):
    ///   - affordability and fee-accounting probes are skipped (they depend on
    ///     sender balances; failures only FREE capacity);
    ///   - the feed orders by fee-per-byte while this walk orders by fee;
    ///     regular transactions are near-constant size so the orders coincide
    ///     (the miner's own selection comment makes this argument).
    fn fee_estimate_from_candidates(
        &self,
        mut candidates: Vec<Transaction>,
        now_secs: u64,
    ) -> FeeEstimate {
        // Sort BEFORE filtering: ordering is cheap (integer compares) and the
        // filter is not (a confirmed-index lookup plus a witness hex decode per
        // transaction), so the bounded walk below pays the expensive check only
        // for the transactions that actually compete for the next block.
        candidates.sort_by(Self::template_candidate_order);

        let next_height = self.next_block_index();
        let activated = next_height >= FEE_SYSTEM_ACTIVATION_HEIGHT;
        // Every canonical address is exactly 40 chars, so the coinbase base
        // weight is identical for any miner; a placeholder is exact, and the
        // error arm is unreachable (kept non-panicking on principle).
        const PLACEHOLDER_MINER: &str = "0000000000000000000000000000000000000000";
        let mut consensus_weight = if activated {
            Self::mining_template_base_weight(PLACEHOLDER_MINER).unwrap_or(0)
        } else {
            0
        };

        let feed_count_cap = crate::a9::mempool::MAX_TRANSACTIONS_PER_BLOCK;
        let feed_byte_cap = crate::a9::mempool::MAX_BLOCK_SIZE;
        let count_cap = feed_count_cap.min(MAX_BLOCK_TX_COUNT.saturating_sub(1));
        let byte_cap = feed_byte_cap.min(MAX_TEMPLATE_TX_BYTES);

        let mut feed_count = 0usize;
        let mut feed_bytes = 0usize;
        let mut template_bytes = 0usize;
        let mut included = 0usize;
        let mut eligible_seen = 0usize;
        let mut min_included_fee: Option<i128> = None;
        let mut excluded_any = false;

        for tx in &candidates {
            // STAGE 1: feed budget, spent by eligible and ineligible alike.
            // Exhausted feed budget means the pool outruns what the miner can
            // even see — congestion, and the bound that keeps this walk O(1)
            // in the size of the mempool.
            if feed_count >= feed_count_cap || feed_bytes >= feed_byte_cap {
                excluded_any = true;
                break;
            }
            let tx_bytes = match codec::serialize(tx) {
                Ok(bytes) => bytes.len(),
                Err(_) => continue, // unserializable can't ship in a block
            };
            feed_count += 1;
            feed_bytes = feed_bytes.saturating_add(tx_bytes);

            if !self.is_template_candidate(tx, now_secs) {
                continue; // consumed feed budget, can never be templated
            }
            eligible_seen += 1;

            // STAGE 2: the miner's packing gates. continue-not-break mirrors
            // the miner: an oversize transaction is skipped while smaller
            // lower-fee ones may still pack in.
            if included >= count_cap {
                excluded_any = true;
                continue;
            }
            if template_bytes.saturating_add(tx_bytes) > byte_cap {
                excluded_any = true;
                continue;
            }
            if activated {
                let tx_weight = match Self::template_regular_transaction_weight(next_height, tx) {
                    Ok(Some(weight)) => weight,
                    Ok(None) | Err(_) => continue,
                };
                let Some(next_weight) = consensus_weight.checked_add(tx_weight) else {
                    continue;
                };
                if next_weight > MAX_BLOCK_WEIGHT_BYTES {
                    excluded_any = true;
                    continue;
                }
                consensus_weight = next_weight;
            }
            template_bytes = template_bytes.saturating_add(tx_bytes);
            included += 1;
            min_included_fee = Some(min_included_fee.map_or(tx.fee_units, |m| m.min(tx.fee_units)));
        }

        // Headroom for the transaction this estimate is FOR: if the caller's
        // own transfer would not fit alongside everything above, the network is
        // contended for them even though no existing transaction was displaced.
        let caller_fits = included < count_cap
            && template_bytes.saturating_add(TYPICAL_FULL_WITNESS_TX_BYTES) <= byte_cap
            && feed_count < feed_count_cap
            && feed_bytes.saturating_add(TYPICAL_FULL_WITNESS_TX_BYTES) <= feed_byte_cap
            && (!activated
                || consensus_weight.saturating_add(TYPICAL_FULL_WITNESS_TX_BYTES)
                    <= MAX_BLOCK_WEIGHT_BYTES);

        let congested = excluded_any || !caller_fits;
        let recommended_units = if congested {
            min_included_fee
                .unwrap_or(FEE_ESTIMATE_ANCHOR_UNITS)
                .saturating_add(1)
                .max(FEE_ESTIMATE_ANCHOR_UNITS)
        } else {
            FEE_ESTIMATE_ANCHOR_UNITS
        }
        .min(FEE_ESTIMATE_AUTO_CAP_UNITS);

        FeeEstimate {
            recommended_units,
            anchor_units: FEE_ESTIMATE_ANCHOR_UNITS,
            floor_units: MIN_RELAY_FEE_UNITS,
            auto_cap_units: FEE_ESTIMATE_AUTO_CAP_UNITS,
            explicit_cap_units: WALLET_FEE_SAFETY_LIMIT_UNITS,
            congested,
            pending_candidates: eligible_seen,
            next_block_fits: included,
        }
    }

    pub async fn get_mempool_transaction_by_id(&self, tx_id: &str) -> Option<Transaction> {
        self.mempool.read().await.find_transaction_by_id(tx_id)
    }

    pub async fn add_to_mempool(&self, tx: Transaction) -> Result<(), BlockchainError> {
        self.mempool.write().await.add_transaction(tx)
    }

    fn aggregate_regular_fee_units(transactions: &[Transaction]) -> Result<i128, BlockchainError> {
        transactions
            .iter()
            .filter(|tx| tx.sender != "MINING_REWARDS")
            .try_fold(0i128, |total, tx| {
                if tx.fee_units < 0 {
                    return Err(BlockchainError::InvalidTransactionAmount);
                }
                total
                    .checked_add(tx.fee_units)
                    .ok_or(BlockchainError::InvalidTransactionAmount)
            })
    }

    /// Transaction-independent accounting baseline for this schedule point. It is
    /// the greatest net issuance among the historical empty-block reward, the
    /// zero-fee nonempty floor, and the scheduled low-fee compatibility envelope.
    /// Delegating all vectors to the unchanged reward calculation preserves every
    /// six-month and long-horizon rounding boundary while keeping normal batched
    /// low-fee traffic continuously mineable.
    /// Every vector here is a fixed synthetic shape, so the baseline depends only
    /// on (height, timestamp) and NOT on the candidate transaction set — which is
    /// what lets a template packer compute it once per template rather than once
    /// per candidate. The three probes are the same ones the block form used: an
    /// empty block (0 txs, 0 fees), a zero-fee nonempty block (1 tx, 0 fees), and
    /// the low-fee compatibility envelope (1 tx carrying the envelope fee).
    fn scheduled_baseline_units_at(
        &self,
        block_index: u32,
        block_timestamp: u64,
    ) -> Result<i128, BlockchainError> {
        if block_index == 0 {
            return Ok(Transaction::to_units(GENESIS_LAUNCH_AMOUNT));
        }
        let empty_units = Transaction::to_units(self.block_reward_from_totals(
            block_index,
            block_timestamp,
            0,
            0.0,
        )?);
        let nonempty_floor_units = Transaction::to_units(self.block_reward_from_totals(
            block_index,
            block_timestamp,
            1,
            0.0,
        )?);

        // `tx.fee()` on the envelope probe is exactly from_units(ENVELOPE_UNITS).
        let envelope_fee = Transaction::from_units(LOW_FEE_COMPATIBILITY_ENVELOPE_UNITS);
        let compatibility_reward_units = Transaction::to_units(self.block_reward_from_totals(
            block_index,
            block_timestamp,
            1,
            envelope_fee,
        )?);
        let compatibility_net_units = compatibility_reward_units
            .checked_sub(LOW_FEE_COMPATIBILITY_ENVELOPE_UNITS)
            .ok_or(BlockchainError::InvalidTransactionAmount)?;

        Ok(empty_units
            .max(nonempty_floor_units)
            .max(compatibility_net_units))
    }

    fn scheduled_fee_accounting_baseline_units(
        &self,
        block: &Block,
    ) -> Result<i128, BlockchainError> {
        self.scheduled_baseline_units_at(block.index, block.timestamp)
    }

    fn fee_accounting_is_admissible_for_block(
        &self,
        block: &Block,
        expected_reward_units: i128,
    ) -> Result<bool, BlockchainError> {
        let total_fee_units = Self::aggregate_regular_fee_units(&block.transactions)?;
        let scheduled_baseline_units = self.scheduled_fee_accounting_baseline_units(block)?;
        let net_issuance_units = expected_reward_units
            .checked_sub(total_fee_units)
            .ok_or(BlockchainError::InvalidTransactionAmount)?;
        Ok(net_issuance_units <= scheduled_baseline_units)
    }

    fn validate_block_reward_rules_at(
        &self,
        block: &Block,
        activation_height: u32,
    ) -> Result<(), BlockchainError> {
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

        let expected_reward_units = Transaction::to_units(self.calculate_block_reward(block)?);
        if reward_tx.amount_units != expected_reward_units {
            return Err(BlockchainError::InvalidTransactionAmount);
        }

        if block.index >= activation_height
            && !self.fee_accounting_is_admissible_for_block(block, expected_reward_units)?
        {
            return Err(BlockchainError::FeeAccountingLimitExceeded);
        }
        Ok(())
    }

    fn template_fee_accounting_is_admissible_at(
        &self,
        block_index: u32,
        block_timestamp: u64,
        transactions: &[Transaction],
        activation_height: u32,
    ) -> Result<bool, BlockchainError> {
        if block_index < activation_height {
            return Ok(true);
        }

        // Reward accounting depends only on system-vs-regular classification,
        // amount, fee and transaction count. Build a witness-free view instead
        // of cloning multi-kilobyte ML-DSA fields on every miner packing probe.
        let accounting_transactions = transactions
            .iter()
            .map(|tx| Transaction {
                sender: if tx.sender == "MINING_REWARDS" {
                    "MINING_REWARDS".to_string()
                } else {
                    String::new()
                },
                recipient: String::new(),
                fee_units: tx.fee_units,
                amount_units: tx.amount_units,
                timestamp: tx.timestamp,
                signature: None,
                pub_key: None,
                sig_hash: None,
            })
            .collect();
        let block = Block {
            index: block_index,
            previous_hash: [0u8; 32],
            timestamp: block_timestamp,
            transactions: accounting_transactions,
            nonce: 0,
            difficulty: 0,
            hash: [0u8; 32],
            merkle_root: [0u8; 32],
        };
        let expected_reward_units = Transaction::to_units(self.calculate_block_reward(&block)?);
        self.fee_accounting_is_admissible_for_block(&block, expected_reward_units)
    }

    /// Mempool/miner policy helper for the next candidate template. Returning
    /// `false` means the transaction set cannot be included together under the
    /// activated fee-accounting rule; callers may retain other candidates.
    pub fn template_fee_accounting_is_admissible(
        &self,
        block_index: u32,
        block_timestamp: u64,
        transactions: &[Transaction],
    ) -> Result<bool, BlockchainError> {
        self.template_fee_accounting_is_admissible_at(
            block_index,
            block_timestamp,
            transactions,
            FEE_SYSTEM_ACTIVATION_HEIGHT,
        )
    }

    /// Single-transaction form used by admission and pending-set revalidation.
    pub fn transaction_fee_accounting_is_admissible(
        &self,
        block_index: u32,
        block_timestamp: u64,
        transaction: &Transaction,
    ) -> Result<bool, BlockchainError> {
        self.template_fee_accounting_is_admissible(
            block_index,
            block_timestamp,
            std::slice::from_ref(transaction),
        )
    }

    fn pending_transaction_is_admissible_at(
        &self,
        block_index: u32,
        block_timestamp: u64,
        transaction: &Transaction,
        activation_height: u32,
    ) -> Result<bool, BlockchainError> {
        if block_index < activation_height {
            return Ok(true);
        }
        Self::validate_activated_transaction_shape(
            transaction,
            SignatureValidationMode::RequireFull,
        )?;
        self.template_fee_accounting_is_admissible_at(
            block_index,
            block_timestamp,
            std::slice::from_ref(transaction),
            activation_height,
        )
    }

    /// The transaction set enters the reward formula through EXACTLY two values:
    /// the regular transaction count and the summed regular fees. Exposing that
    /// core lets the template packer carry running totals instead of rebuilding a
    /// synthetic block and re-folding the whole selected prefix once per candidate
    /// — which made template selection O(k^2) the moment the activated rule starts
    /// running. `calculate_block_reward` derives the same two values with the same
    /// left-to-right fold and then calls straight through to here, so the two paths
    /// are bit-identical, not merely close; the equivalence is pinned by
    /// `block_reward_from_totals_matches_the_block_form`.
    pub fn block_reward_from_totals(
        &self,
        block_index: u32,
        block_timestamp: u64,
        tx_count: usize,
        total_fees: f64,
    ) -> Result<f64, BlockchainError> {
        const SECONDS_IN_SIX_MONTHS: u64 = 15_768_000; // 182.5 days
        const REDUCTION_RATE: f64 = 0.83; // 17% reduction = multiply by 0.83

        if block_index == 0 {
            return Ok(GENESIS_LAUNCH_AMOUNT);
        }

        // Calculate periods since genesis for halving. Genesis is immutable, so
        // its timestamp is memoized after the first read (this used to be a sled
        // get + full block deserialize per reward calculation, on the validation
        // hot path AND 4x per template-packer candidate).
        let genesis_ts = match self.genesis_timestamp.get() {
            Some(ts) => *ts,
            None => {
                let ts = self.get_genesis_block()?.timestamp;
                let _ = self.genesis_timestamp.set(ts);
                ts
            }
        };
        let time_since_genesis = block_timestamp.saturating_sub(genesis_ts);
        let periods = time_since_genesis / SECONDS_IN_SIX_MONTHS;

        // Apply reduction rate for each period to max reward
        let current_max = MAX_BLOCK_REWARD * REDUCTION_RATE.powi(periods as i32);

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

        // Add transaction fees to the base reward.
        //
        // Floor by min(MIN_BLOCK_REWARD, current_max) — NOT MIN_BLOCK_REWARD alone.
        // current_max decays as MAX_BLOCK_REWARD * 0.83^periods (one period = 6
        // months), and once it drops below MIN_BLOCK_REWARD (~10.5 years past
        // genesis) a fixed 1.0 floor makes this `clamp(1.0, current_max<1.0)` — a
        // clamp with min > max, which f64::clamp PANICS on. calculate_block_reward
        // runs on both the validation and mining reward paths, so that panic would
        // halt every node at once. Bounding the floor by the ceiling is exactly
        // value-identical while current_max >= MIN_BLOCK_REWARD (every block for the
        // ~10.5 years the chain will actually see) and, past the crossover, lets the
        // reward follow the diminished current_max down instead of panicking. Do not
        // revert to a fixed floor.
        let reward_floor = MIN_BLOCK_REWARD.min(current_max);
        let final_reward = Transaction::round_amount(
            (base_reward + effective_fees).clamp(reward_floor, current_max),
        );

        Ok(final_reward)
    }

    pub fn calculate_block_reward(&self, block: &Block) -> Result<f64, BlockchainError> {
        if block.index == 0 {
            return Ok(GENESIS_LAUNCH_AMOUNT);
        }

        // Single pass, excluding mining rewards. The volume this used to accumulate
        // alongside was never read by the formula.
        let (tx_count, total_fees) = block
            .transactions
            .iter()
            .filter(|tx| tx.sender != "MINING_REWARDS")
            .fold((0usize, 0.0f64), |(count, fees), tx| {
                (count + 1, fees + tx.fee())
            });

        self.block_reward_from_totals(block.index, block.timestamp, tx_count, total_fees)
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

    /// Seconds between each of the last `window` consecutive blocks, oldest
    /// first. Display-only (the `info` cadence trace): a single instantaneous
    /// "last block was Ns ago" cannot distinguish one slow block from a chain
    /// that has been slowing for minutes, which is the question an operator
    /// actually asks. Reads the same tip-anchored window as
    /// calculate_network_hashrate, so it touches no block that call does not
    /// already decode, and needs no lock of its own.
    pub fn recent_block_intervals(&self, window: u32) -> Vec<u64> {
        let Some(tip) = self.get_last_block() else {
            return Vec::new();
        };
        let start_index = tip.index.saturating_sub(window);
        let mut previous = match self.get_block(start_index) {
            Ok(block) => block.timestamp,
            Err(_) => return Vec::new(),
        };
        let mut intervals = Vec::with_capacity(window as usize);
        for height in (start_index + 1)..=tip.index {
            let Ok(block) = self.get_block(height) else {
                continue;
            };
            intervals.push(block.timestamp.saturating_sub(previous));
            previous = block.timestamp;
        }
        intervals
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
        self.sync_mempool_with_sled_at(FEE_SYSTEM_ACTIVATION_HEIGHT)
            .await
    }

    fn next_block_index(&self) -> u32 {
        u32::try_from(self.get_latest_block_index())
            .unwrap_or(u32::MAX)
            .saturating_add(1)
    }

    /// Reconcile pending state exactly once when the next candidate reaches the
    /// coordinated rules height. The separate gate makes concurrent admission,
    /// mining and startup callers share one successful pass. Completion is never
    /// published after an error; a later caller retries. If a shallow reorg moves
    /// the candidate below activation, clearing the flag makes the next crossing
    /// run the same transition again.
    ///
    /// This method acquires `state_mutation_lock` through the sync routine. It
    /// must therefore be called before, never from inside, a state mutation.
    pub async fn ensure_pending_rules_for_next_block(&self) -> Result<(), BlockchainError> {
        if self.next_block_index() < FEE_SYSTEM_ACTIVATION_HEIGHT {
            self.pending_rules_complete.store(false, Ordering::Release);
            return Ok(());
        }
        if self.pending_rules_complete.load(Ordering::Acquire) {
            return Ok(());
        }

        let _gate = self.pending_rules_gate.lock().await;
        if self.next_block_index() < FEE_SYSTEM_ACTIVATION_HEIGHT {
            self.pending_rules_complete.store(false, Ordering::Release);
            return Ok(());
        }
        if self.pending_rules_complete.load(Ordering::Acquire) {
            return Ok(());
        }

        #[cfg(test)]
        self.pending_rules_revalidation_runs
            .fetch_add(1, Ordering::AcqRel);
        self.sync_mempool_with_sled().await?;

        if self.next_block_index() >= FEE_SYSTEM_ACTIVATION_HEIGHT {
            self.pending_rules_complete.store(true, Ordering::Release);
        } else {
            self.pending_rules_complete.store(false, Ordering::Release);
        }
        Ok(())
    }

    async fn sync_mempool_with_sled_at(
        &self,
        activation_height: u32,
    ) -> Result<(), BlockchainError> {
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
        let candidate_index = u32::try_from(self.get_latest_block_index())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let candidate_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
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

            match self.pending_transaction_is_admissible_at(
                candidate_index,
                candidate_timestamp,
                &tx,
                activation_height,
            ) {
                Ok(true) => {}
                Ok(false) | Err(BlockchainError::NonCanonicalTransaction) => {
                    invalid_txs.push(key.to_vec());
                    continue;
                }
                Err(error) => return Err(error),
            }

            transactions.push(tx);
        }

        for key in invalid_txs {
            pending_tree.remove(&key)?;
            let _ = full_sigs_tree.remove(&key);
        }
        pending_tree.flush()?;
        full_sigs_tree.flush()?;

        // Reset mempool and rebuild from the durable pending set. Admission is
        // BEST-EFFORT: the in-memory caps (per-sender / pool size / bytes) are soft
        // admission-control limits, but the sled pending tree is the source of truth
        // and can legitimately exceed them across the eviction and TTL windows. A
        // fatal `?` here aborts the whole sync — and on the initialize() path the
        // whole process — the instant the durable set overflows a cap, turning a tx
        // flood into a boot-time DoS (the node then cannot start until the rows age
        // past the 7200s prune). Drop the overflow from memory and keep going;
        // get_pending_transactions reads the sled tree directly, so nothing is lost.
        *mempool = Mempool::new();
        for tx in transactions {
            let _ = mempool.add_transaction(tx);
        }
        drop(mempool);
        self.rebuild_pending_debits_index().await?;

        Ok(())
    }

    pub async fn get_pending_transactions(&self) -> Result<Vec<Transaction>, BlockchainError> {
        // Pure read, straight from the sled pending tree. This used to call
        // sync_mempool_with_sled first — taking the state_mutation_lock (the SAME
        // lock every block apply holds), re-verifying every pending signature,
        // fsyncing twice and rebuilding the whole in-memory mempool — for a
        // DISPLAY read (`account`, `info`) that then read the sled tree directly
        // anyway. During a deep sync that turned a balance query into a silent
        // multi-minute hang one layer below the caller's timeout. The periodic
        // re-verification paths (initialize, the gossip re-announce) still prune
        // stale rows; a display read must never mutate.
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

    /// Pending transactions carrying their FULL signatures — for the gossip / re-announce path,
    /// which must broadcast peer-verifiable transactions. get_pending_transactions returns the
    /// persisted sled records, which hold a TRUNCATED signature (the full signature lives in the
    /// PENDING_FULL_SIGNATURES_TREE sidecar); re-announcing those would gossip unverifiable txs that
    /// peers defer — the truncated-witness pathology. The in-memory mempool holds the full signature,
    /// so sync from sled first (which rehydrates the full signature and skips any tx whose sidecar
    /// copy is missing, rather than gossiping it truncated) and read the mempool.
    pub async fn get_pending_transactions_with_full_signatures(
        &self,
    ) -> Result<Vec<Transaction>, BlockchainError> {
        self.sync_mempool_with_sled().await?;
        self.get_mempool_transactions().await
    }

    // Temporal Provenance with Causal Linking
    // Add to handle distributions
    pub async fn process_transactions_batch(
        &self,
        transactions: &[Transaction],
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

        // First pass: Get all current balances for any address touched by this batch.
        // EXACT i128 (get_confirmed_balance_units), NOT to_units(get_confirmed_balance):
        // this is the consensus ledger writer (new_balance = current + change is written
        // back below), and the f64 round-trip drifts the stored ledger away from the
        // exact rebuild/catch-up paths above ~33.55M coins — a latent chain split
        // (2026-07-12 audit). Value-identical below that in the reachable range.
        for tx in transactions {
            if tx.sender != "MINING_REWARDS" && !current_balances.contains_key(&tx.sender) {
                let balance_units = self.get_confirmed_balance_units(&tx.sender).await?;
                current_balances.insert(tx.sender.clone(), balance_units);
            }
            if !current_balances.contains_key(&tx.recipient) {
                let balance_units = self.get_confirmed_balance_units(&tx.recipient).await?;
                current_balances.insert(tx.recipient.clone(), balance_units);
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
        // The overlay is consulted ONLY in the regular-sender branch below (the affordability check
        // reads immature_by_addr.get(&tx.sender)). A block whose senders are all MINING_REWARDS never
        // reads it, so skip its ~MINING_REWARD_MATURITY stored-block deserializes entirely. This is
        // consensus-identical: the map that would be built is never queried for such a block.
        let has_regular_sender = transactions.iter().any(|tx| tx.sender != "MINING_REWARDS");
        if has_regular_sender && (confirm_height as u32) >= MATURITY_ACTIVATION_HEIGHT {
            for tx in transactions {
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
        for tx in transactions {
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
            for tx in transactions {
                if tx.sender != "MINING_REWARDS" {
                    let tx_id = tx.get_tx_id();
                    // Retain the full witness for a bounded window (before purging the pending
                    // copy) so peers can serve it for near-tip verification during sync.
                    // Local-only: no effect on block hashes, merkle roots, or validity. Sourced
                    // from the local mempool sidecar if we gossiped the tx, else from the incoming
                    // block's OWN just-verified signature (witness_to_retain enforces full-sig +
                    // sig_hash binding + BlockValidation-only), so a tx first seen inside this
                    // block is retained instead of lost.
                    let sidecar_sig = full_sigs_tree
                        .get(tx_id.as_bytes())
                        .ok()
                        .flatten()
                        .map(|s| s.to_vec());
                    if let Some(sig) = Self::witness_to_retain(
                        tx,
                        sidecar_sig,
                        matches!(context, TransactionContext::BlockValidation),
                    ) {
                        let mut full_tx = tx.clone();
                        full_tx.signature = Some(hex::encode(&sig));
                        if let Ok(bytes) = codec::serialize(&full_tx) {
                            // Do NOT swallow these. If witness retention fails
                            // (disk full, transient sled error) the node keeps
                            // accepting blocks while quietly becoming unable to
                            // serve witnesses to peers — and a peer that cannot
                            // obtain them cannot advance its verification floor,
                            // which is exactly the multi-minute freeze the beacon
                            // escape has to rescue. That cause was invisible.
                            if let Err(e) = cw_tree.insert(tx_id.as_bytes(), bytes) {
                                warn!(
                                    "Could not retain confirmed witness for {} — peers may be unable to verify near-tip blocks from us: {}",
                                    tx_id, e
                                );
                            }
                            let mut idx_key = confirm_height.to_be_bytes().to_vec();
                            idx_key.extend_from_slice(tx_id.as_bytes());
                            if let Err(e) = cw_index.insert(idx_key, b"" as &[u8]) {
                                warn!("Could not index confirmed witness for {}: {}", tx_id, e);
                            }
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
            // No per-tree flushes here (each was a full-DB fsync in sled): this
            // runs inside the block-apply dirty window, which both persist tails
            // close with one authoritative db.flush(). Five redundant whole-DB
            // fsyncs per applied block deleted.
            self.prune_confirmed_witnesses(confirm_height)?;
        }

        Ok(())
    }

    /// Decide which full signature (if any) to retain as a servable witness for `tx`.
    /// Prefers the local mempool sidecar copy (`sidecar_sig`, present only if this node gossiped
    /// the tx); otherwise — under BlockValidation ONLY — falls back to the incoming block's own
    /// signature, which was just verified upstream. That fallback preserves a tx first seen inside
    /// a mined block (never gossiped to this node) so it can still be served to peers and
    /// rehydrated on reorg instead of dropped.
    ///
    /// GUARD (money-chain safety): only a FULL signature (>64 bytes — a truncated sig is exactly a
    /// 64-byte prefix) whose SHA-256 hash equals the tx's committed `sig_hash` is retained. sig_hash
    /// is committed into the merkle root, so the bind is exact; and ReceiptValidation (historical
    /// sync) carries TRUNCATED sigs, which must never enter the store — a served truncated witness
    /// makes peers defer honest blocks (the 2026-07-23 truncated-witness pathology). A poisoned
    /// witness cannot split the chain regardless (every consumer re-derives sig_hash in
    /// block_signatures_fully_verified and defers on mismatch); this preserves the store's
    /// invariant that it holds only full, binding witnesses.
    fn witness_to_retain(
        tx: &Transaction,
        sidecar_sig: Option<Vec<u8>>,
        is_block_validation: bool,
    ) -> Option<Vec<u8>> {
        // The sidecar only ever holds gossip-verified full signatures; the >64 check is
        // defense-in-depth against a corrupt entry, never a filter on a real one.
        if let Some(sig) = sidecar_sig {
            if sig.len() > 64 {
                return Some(sig);
            }
        }
        if is_block_validation {
            if let Some(sig) = tx.signature.as_ref().and_then(|s| hex::decode(s).ok()) {
                if sig.len() > 64
                    && tx.sig_hash.as_deref()
                        == Some(Transaction::signature_hash_hex(&sig).as_str())
                {
                    return Some(sig);
                }
            }
        }
        None
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
    /// SHAPE-ONLY companion to `block_signatures_fully_verified`: does every
    /// non-system transaction carry a FULL (non-truncated) ML-DSA signature?
    ///
    /// This is the "can anyone else verify this body" test, and it is deliberately
    /// cheap (no signature verification) because it gates the RELAY PUBLISH path,
    /// which runs per block and would otherwise re-verify already-verified bodies.
    ///
    /// Why it exists: stored blocks keep only the truncated 64-byte receipt form,
    /// and `block_with_full_witnesses` rehydrates from the confirmed-witness store
    /// — which retains just WITNESS_RETENTION_BLOCKS. Past that window rehydration
    /// silently yields a witness-SHORT body. Publishing one poisons that relay
    /// height: nodes validating at their frontier require full witnesses, cannot
    /// obtain them from any peer, and wedge until a snapshot laps the block
    /// (observed 2026-07-27: two independent nodes stuck ~85 min at block 290968).
    pub fn block_witnesses_are_complete(block: &Block) -> bool {
        block.transactions.iter().all(|tx| {
            if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                return true;
            }
            tx.signature
                .as_deref()
                .and_then(|sig| hex::decode(sig).ok())
                .map(|bytes| bytes.len() > 64)
                .unwrap_or(false)
        })
    }

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

    /// Exact confirmed balance in i128 units — the SINGLE source of truth for any
    /// affordability or consensus decision. Preserves the lazy ensure_balances_index
    /// rebuild, the 0-insert, and the slow-path scan. Consensus/affordability callers
    /// MUST use this, never `Transaction::to_units(get_confirmed_balance(...))`: that
    /// f64 round-trip is not the identity above ~33.55M coins (2^25 coins) and drifts
    /// the incrementally-maintained ledger away from the exact rebuild/catch-up path,
    /// a latent chain split on a large-balance payment (2026-07-12 audit).
    pub async fn get_confirmed_balance_units(
        &self,
        address: &str,
    ) -> Result<i128, BlockchainError> {
        let balances_tree = self.db.open_tree(BALANCES_TREE)?;
        // The auto-rebuild flag is fixed for the process lifetime; read the env once and cache it
        // instead of taking the process-wide env lock + allocating a String on every balance read.
        fn balances_auto_rebuild_enabled() -> bool {
            static FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
            *FLAG.get_or_init(|| {
                std::env::var("ALPHANUMERIC_BALANCES_AUTO_REBUILD")
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true)
            })
        }
        let auto_rebuild = balances_auto_rebuild_enabled();

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
            return Ok(balance_units);
        }
        if auto_rebuild && index_height >= self.get_latest_block_index() {
            // Index is current and the address has no entry, so its confirmed balance is 0.
            // Do NOT persist a 0-entry here: this is the read path (explorer / RPC balance
            // queries for arbitrary addresses), and writing on read grows the balances tree
            // without bound (sled never reclaims freed keys). Every later read of this address
            // hits this same branch and returns 0 without a slow-path recompute; the consensus
            // writer persists real entries for every address a block actually touches.
            return Ok(0);
        }
        // Slow path: calculate from blocks.
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

        Ok(balance_units)
    }

    /// Confirmed balance as f64 — DISPLAY ONLY. A thin wrapper over the exact
    /// get_confirmed_balance_units for UI/reporting; never route an affordability
    /// or consensus check through this (the f64 is lossy above ~33.55M coins).
    pub async fn get_confirmed_balance(&self, address: &str) -> Result<f64, BlockchainError> {
        Ok(Transaction::from_units(
            self.get_confirmed_balance_units(address).await?,
        ))
    }

    // Public method that shows spendable balance to users
    pub async fn get_wallet_balance(&self, address: &str) -> Result<f64, BlockchainError> {
        Ok(self.get_wallet_balance_breakdown(address).await?.spendable)
    }

    async fn wallet_balance_components_units(
        &self,
        address: &str,
    ) -> Result<(i128, i128, Vec<(u32, i128)>, u64), BlockchainError> {
        let confirmed_units = self.get_confirmed_balance_units(address).await?;
        let pending_debit_units = self.get_pending_debit_units(address).await?;
        let as_of_height = self.get_latest_block_index();
        let maturing_units =
            self.immature_coinbase_details(address, as_of_height.saturating_add(1), &[]);
        Ok((
            confirmed_units,
            pending_debit_units,
            maturing_units,
            as_of_height,
        ))
    }

    /// Exact spendable balance for transaction construction and affordability
    /// checks: confirmed minus pending debits minus immature mining rewards.
    pub async fn get_spendable_balance_units(
        &self,
        address: &str,
    ) -> Result<i128, BlockchainError> {
        let (confirmed, pending_debit, maturing, _) =
            self.wallet_balance_components_units(address).await?;
        let immature = maturing.iter().try_fold(0i128, |total, (_, amount)| {
            total
                .checked_add(*amount)
                .ok_or(BlockchainError::InvalidTransactionAmount)
        })?;
        confirmed
            .checked_sub(pending_debit)
            .and_then(|value| value.checked_sub(immature))
            .ok_or(BlockchainError::InvalidTransactionAmount)
    }

    /// get_wallet_balance with its components kept separate (see WalletBalanceBreakdown).
    /// Same cost as get_wallet_balance — one confirmed read, one pending read, one
    /// maturity-window scan — so display callers can switch to this for free.
    pub async fn get_wallet_balance_breakdown(
        &self,
        address: &str,
    ) -> Result<WalletBalanceBreakdown, BlockchainError> {
        let (confirmed_units, pending_debit_units, maturing_units, as_of_height) =
            self.wallet_balance_components_units(address).await?;
        let immature_units = maturing_units
            .iter()
            .try_fold(0i128, |total, (_, amount)| {
                total
                    .checked_add(*amount)
                    .ok_or(BlockchainError::InvalidTransactionAmount)
            })?;
        let spendable_units = confirmed_units
            .checked_sub(pending_debit_units)
            .and_then(|value| value.checked_sub(immature_units))
            .ok_or(BlockchainError::InvalidTransactionAmount)?;
        Ok(WalletBalanceBreakdown {
            confirmed: Transaction::from_units(confirmed_units),
            pending_debit: Transaction::from_units(pending_debit_units),
            spendable: Transaction::from_units(spendable_units),
            maturing: maturing_units
                .into_iter()
                .map(|(height, amt)| (height, Transaction::from_units(amt)))
                .collect(),
            as_of_height,
        })
    }

    // (removed 2026-07-12) update_wallet_balance: a dead pub f64 ledger writer with
    // zero callers that bypassed the BALANCES_HEIGHT_KEY marker and seeded from
    // to_units(f64) — exactly the round-trip drift this audit is eliminating. Deleted
    // so it can't reintroduce the bug class. Ledger writes go through
    // process_transactions_batch / rebuild / catch-up only.

    pub fn calculate_merkle_root(
        transactions: &[Transaction],
    ) -> Result<[u8; 32], BlockchainError> {
        if transactions.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(b"empty_transactions_hash");
            return Ok(hasher.finalize().into());
        }

        let leaves = transactions
            .iter()
            .map(Self::calculate_merkle_leaf_hash)
            .collect::<Result<Vec<_>, BlockchainError>>()?;
        Self::calculate_merkle_root_from_leaf_hashes(&leaves)
    }

    /// Hash one transaction exactly as the consensus Merkle tree does.
    ///
    /// Compact block transport uses this full 32-byte digest as its transaction
    /// identifier. Keeping the normalization in the ledger module prevents the
    /// transport from drifting away from the consensus commitment: public key,
    /// signature hash, and the stored 64-byte signature prefix are all bound,
    /// unlike the display-oriented transaction id.
    pub fn calculate_merkle_leaf_hash(tx: &Transaction) -> Result<[u8; 32], BlockchainError> {
        // Consensus merkle leaves must be stable across:
        // - in-memory full-signature transactions (used for admission verification)
        // - on-disk truncated-signature blocks (used for storage efficiency)
        //
        // Normalize to the stored (truncated-signature, sig_hash-bound) form.
        // Derive sig_hash only when absent and the signature decodes to non-empty
        // bytes. This is byte-identical to the historical calculate_merkle_root
        // input and is therefore a refactor, not a consensus change.
        let tx_for_merkle = if tx.sender == "MINING_REWARDS" {
            tx.clone()
        } else {
            let sig_hash = match &tx.sig_hash {
                Some(h) => Some(h.clone()),
                None => tx.signature.as_ref().and_then(|sig_hex| {
                    hex::decode(sig_hex).ok().and_then(|sig_bytes| {
                        if sig_bytes.is_empty() {
                            None
                        } else {
                            Some(Transaction::signature_hash_hex(&sig_bytes))
                        }
                    })
                }),
            };

            match sig_hash {
                Some(sig_hash) => tx.with_truncated_signature(sig_hash),
                None => tx.clone(),
            }
        };

        let tx_bytes = codec::serialize(&tx_for_merkle)
            .map_err(|e| BlockchainError::SerializationError(Box::new(e)))?;
        let mut hasher = Sha256::new();
        hasher.update(&tx_bytes);
        Ok(hasher.finalize().into())
    }

    /// Build the consensus Merkle root from already-normalized leaf hashes.
    ///
    /// This intentionally preserves the chain's existing tree rules, including
    /// duplicating a lone leaf and carrying an odd final leaf through a level by
    /// hashing it once. Compact block receivers use it to validate the ordered
    /// commitment before requesting any transaction bodies.
    pub fn calculate_merkle_root_from_leaf_hashes(
        leaves: &[[u8; 32]],
    ) -> Result<[u8; 32], BlockchainError> {
        if leaves.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(b"empty_transactions_hash");
            return Ok(hasher.finalize().into());
        }

        let mut current_level = leaves.to_vec();

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

    // Fee-accounting probes: a regular (non-coinbase) transaction carrying `fee`.
    fn fee_tx(fee: f64, ts: u64) -> Transaction {
        Transaction {
            sender: "a".repeat(40),
            recipient: "b".repeat(40),
            fee_units: Transaction::to_units(fee),
            amount_units: MIN_TRANSACTION_AMOUNT_UNITS,
            timestamp: ts,
            signature: None,
            pub_key: None,
            sig_hash: None,
        }
    }

    // The template packer carries running (count, fees) instead of re-folding the
    // selected prefix per candidate. That is only safe if the aggregate form is
    // EXACTLY the block form — f64 addition is neither associative nor invertible,
    // so "close enough" would silently drift the reward, and the reward is consensus.
    // Compared on raw bits, not with an epsilon.
    #[test]
    fn block_reward_from_totals_matches_the_block_form() {
        let bc = test_blockchain();
        let genesis_ts = 1_700_000_000u64;
        let _ = bc.genesis_timestamp.set(genesis_ts);

        let fee_sets: Vec<Vec<f64>> = vec![
            vec![],
            vec![0.0],
            vec![0.0001],
            vec![0.0002; 7],
            vec![0.0001, 0.0005, 0.00123, 0.07, 0.3],
            vec![0.005; 200],
            vec![0.056_306_306_3; 13],
            // Straddles fee_factor saturation and the admissible-band edge.
            vec![0.726_392],
            vec![1.0, 2.5, 0.75],
            vec![0.0001; 4095],
        ];
        // Pre-activation, activation edge, post-activation; and reward periods
        // 0 / 1 / 3 so the halving branch is exercised too.
        let heights = [1u32, FEE_SYSTEM_ACTIVATION_HEIGHT - 1, FEE_SYSTEM_ACTIVATION_HEIGHT, 900_000];
        let stamps = [
            genesis_ts,
            genesis_ts + 15_768_000,
            genesis_ts + 3 * 15_768_000,
        ];

        let mut compared = 0usize;
        for fees in &fee_sets {
            for &height in &heights {
                for &ts in &stamps {
                    let txs: Vec<Transaction> = fees.iter().map(|f| fee_tx(*f, ts)).collect();
                    let block = Block {
                        index: height,
                        previous_hash: [0u8; 32],
                        timestamp: ts,
                        transactions: txs.clone(),
                        nonce: 0,
                        difficulty: 0,
                        hash: [0u8; 32],
                        merkle_root: [0u8; 32],
                    };
                    let via_block = bc.calculate_block_reward(&block).unwrap();

                    // Appended in selection order, exactly as the packer accumulates.
                    let mut tx_count = 0usize;
                    let mut total_fees = 0.0f64;
                    for tx in &txs {
                        tx_count += 1;
                        total_fees += tx.fee();
                    }
                    let via_totals = bc
                        .block_reward_from_totals(height, ts, tx_count, total_fees)
                        .unwrap();

                    assert_eq!(
                        via_block.to_bits(),
                        via_totals.to_bits(),
                        "reward diverged at height {} ts {} with {} txs: {} vs {}",
                        height,
                        ts,
                        txs.len(),
                        via_block,
                        via_totals
                    );
                    compared += 1;
                }
            }
        }
        assert_eq!(compared, 120, "every shape/height/period combination must be compared");
    }

    // The packer's running accountant must admit and reject EXACTLY the set the
    // whole-prefix block form did, including at the boundary where net issuance
    // crosses the baseline.
    #[test]
    fn template_fee_accounting_admits_exactly_what_the_block_form_admits() {
        let bc = test_blockchain();
        let genesis_ts = 1_700_000_000u64;
        let _ = bc.genesis_timestamp.set(genesis_ts);
        let height = FEE_SYSTEM_ACTIVATION_HEIGHT;
        let ts = genesis_ts + 1_000;

        // A rising fee ladder: the running total walks up to the admissible ceiling
        // and past it, so both verdicts are exercised.
        let candidates: Vec<Transaction> = (0..400)
            .map(|i| fee_tx(0.002 + (i as f64) * 0.000_01, ts))
            .collect();

        let mut accounting =
            TemplateFeeAccounting::new_at(&bc, height, ts, FEE_SYSTEM_ACTIVATION_HEIGHT).unwrap();
        let mut prefix: Vec<Transaction> = Vec::new();
        let (mut admitted, mut rejected) = (0usize, 0usize);

        for (idx, tx) in candidates.iter().enumerate() {
            // Reference: the block form over the whole prefix, push/pop as before.
            prefix.push(tx.clone());
            let reference = bc
                .template_fee_accounting_is_admissible_at(
                    height,
                    ts,
                    &prefix,
                    FEE_SYSTEM_ACTIVATION_HEIGHT,
                )
                .unwrap();
            let running = accounting.admits(&bc, tx).unwrap();

            assert_eq!(
                reference, running,
                "verdict diverged at candidate {} (fee {})",
                idx,
                tx.fee()
            );

            if running {
                accounting.commit(tx).unwrap();
                admitted += 1;
            } else {
                prefix.pop();
                rejected += 1;
            }
        }

        assert!(
            admitted > 0 && rejected > 0,
            "ladder must exercise BOTH outcomes, got {} admitted / {} rejected",
            admitted,
            rejected
        );
    }

    // Below activation the rule is dormant, so the accountant must admit anything
    // — including a set the activated rule would refuse.
    #[test]
    fn template_fee_accounting_is_inert_below_activation() {
        let bc = test_blockchain();
        let genesis_ts = 1_700_000_000u64;
        let _ = bc.genesis_timestamp.set(genesis_ts);
        let ts = genesis_ts + 1_000;
        let height = FEE_SYSTEM_ACTIVATION_HEIGHT - 1;

        let mut accounting =
            TemplateFeeAccounting::new_at(&bc, height, ts, FEE_SYSTEM_ACTIVATION_HEIGHT).unwrap();
        // Far above the activated ceiling.
        let fat = fee_tx(5.0, ts);
        for _ in 0..8 {
            assert!(accounting.admits(&bc, &fat).unwrap());
            accounting.commit(&fat).unwrap();
        }
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

    // A tx FIRST SEEN inside a mined block (no local mempool sidecar copy) whose own signature is
    // full and binds to its committed sig_hash must be retained from THAT signature under
    // BlockValidation — the fix for the first-seen-in-block witness loss (serve-fail + reorg-drop).
    #[test]
    fn witness_to_retain_persists_first_seen_in_block_full_hash_bound_sig() {
        let mut tx = user_tx("alice", "bob", 1.0, 100);
        let full_sig = vec![7u8; 200]; // >64 bytes = a full (non-truncated) signature
        tx.signature = Some(hex::encode(&full_sig));
        tx.sig_hash = Some(Transaction::signature_hash_hex(&full_sig));
        // No sidecar (never gossiped to this node), BlockValidation context.
        assert_eq!(
            Blockchain::witness_to_retain(&tx, None, true),
            Some(full_sig),
            "full, hash-bound block signature must be retained when the sidecar is empty"
        );
    }

    // GUARD: the store must never accept a truncated sig, a hash-mismatched sig, or ANY block
    // signature under ReceiptValidation (historical sync carries TRUNCATED sigs). A truncated
    // witness later served to a peer would make it defer honest blocks (the 2026-07-23 pathology).
    #[test]
    fn witness_to_retain_rejects_truncated_mismatch_and_receipt_context() {
        let mut tx = user_tx("alice", "bob", 1.0, 100);
        let full_sig = vec![7u8; 200];
        tx.signature = Some(hex::encode(&full_sig));
        tx.sig_hash = Some(Transaction::signature_hash_hex(&full_sig));

        // ReceiptValidation (is_block_validation = false): never retain from tx.signature.
        assert_eq!(
            Blockchain::witness_to_retain(&tx, None, false),
            None,
            "ReceiptValidation must not retain a block signature (may be truncated)"
        );

        // Truncated signature (<= 64 bytes) under BlockValidation: rejected even if self-consistent.
        let trunc = vec![9u8; 64];
        tx.signature = Some(hex::encode(&trunc));
        tx.sig_hash = Some(Transaction::signature_hash_hex(&trunc));
        assert_eq!(
            Blockchain::witness_to_retain(&tx, None, true),
            None,
            "a truncated (<=64B) signature must never be retained"
        );

        // Full signature but sig_hash does NOT bind: rejected.
        tx.signature = Some(hex::encode(&full_sig));
        tx.sig_hash = Some("deadbeef".to_string());
        assert_eq!(
            Blockchain::witness_to_retain(&tx, None, true),
            None,
            "a full signature whose hash does not match sig_hash must be rejected"
        );

        // Full signature but NO committed sig_hash (Transaction::new default): rejected — an
        // unbound sig cannot be proven to belong to this tx, so it is intentionally not retained.
        tx.signature = Some(hex::encode(&full_sig));
        tx.sig_hash = None;
        assert_eq!(
            Blockchain::witness_to_retain(&tx, None, true),
            None,
            "a full signature with no committed sig_hash must not be retained"
        );

        // A present full sidecar witness is retained regardless of context (existing behavior).
        assert_eq!(
            Blockchain::witness_to_retain(&tx, Some(full_sig.clone()), false),
            Some(full_sig),
            "a present full sidecar witness is retained regardless of context"
        );
    }

    // END-TO-END through process_transactions_batch: exercises the WIRING (sidecar read, context
    // flag, serialize + index-key round-trip) that the helper unit tests skip. A tx first seen
    // inside a mined block (empty sidecar) becomes serve-able after a BlockValidation apply; the
    // same tx under ReceiptValidation retains nothing (the block fallback is BlockValidation-gated).
    #[tokio::test]
    async fn process_batch_retains_first_seen_in_block_witness() {
        let ts = 1_700_000_000u64;
        let wallet = Wallet::new(None).expect("wallet builds");

        // An incoming block's tx: fully signed AND carrying its committed sig_hash, never gossiped
        // to this node (so PENDING_FULL_SIGNATURES_TREE has no copy).
        let mut tx = signed_transfer(&wallet, "recipient_addr_for_test", 10.0, ts).await;
        let sig_bytes = hex::decode(tx.signature.as_ref().unwrap()).unwrap();
        tx.sig_hash = Some(Transaction::signature_hash_hex(&sig_bytes));
        let tx_id = tx.get_tx_id();

        let fund = |bc: &Blockchain| {
            bc.db
                .open_tree(BALANCES_TREE)
                .unwrap()
                .insert(
                    wallet.address.as_bytes(),
                    codec::serialize(&Transaction::to_units(1000.0)).unwrap(),
                )
                .unwrap();
        };

        // BlockValidation apply on a fresh, funded chain retains the just-verified witness.
        let bc = test_blockchain();
        fund(&bc);
        assert!(
            bc.verify_transaction_signature(&tx).is_ok(),
            "the incoming block tx must verify"
        );
        assert!(
            bc.db
                .open_tree(PENDING_FULL_SIGNATURES_TREE)
                .unwrap()
                .get(tx_id.as_bytes())
                .unwrap()
                .is_none(),
            "precondition: tx was NOT gossiped (empty sidecar)"
        );
        bc.process_transactions_batch(
            std::slice::from_ref(&tx),
            TransactionContext::BlockValidation,
            1,
        )
        .await
        .expect("BlockValidation batch applies");

        let served = bc
            .get_confirmed_witness_tx(&tx_id)
            .expect("a first-seen-in-block witness must be retained and serve-able");
        let served_sig = hex::decode(served.signature.as_ref().unwrap()).unwrap();
        assert!(
            served_sig.len() > 64,
            "served witness must be the FULL signature"
        );
        assert_eq!(
            served_sig, sig_bytes,
            "served witness is the exact verified signature"
        );

        // Negative: the SAME tx under ReceiptValidation must retain nothing.
        let bc2 = test_blockchain();
        fund(&bc2);
        bc2.process_transactions_batch(
            std::slice::from_ref(&tx),
            TransactionContext::ReceiptValidation,
            1,
        )
        .await
        .expect("ReceiptValidation batch applies");
        assert!(
            bc2.get_confirmed_witness_tx(&tx_id).is_none(),
            "ReceiptValidation must not retain via the block fallback"
        );
    }

    // A transaction reverted by a reorg must be re-queued with its FULL signature
    // (pulled from the witness store, keyed on the signature-independent tx id), and
    // dropped entirely when no full witness is available — a truncated copy could
    // never be mined and would only poison the block template until it ages out.
    #[test]
    fn beacon_can_unfreeze_a_node_whose_own_checkpoint_cannot_advance() {
        // The frozen-tip deadlock: verification_floor() comes from the node's OWN
        // trusted checkpoint, which only advances when it APPLIES a block. A node
        // that cannot apply block H+1 (unobtainable witnesses) therefore keeps H+1
        // above its floor forever, so it keeps demanding full witnesses for it
        // forever — even once the network has buried it. Live: 80 minutes frozen.
        //
        // The escape is advancing the checkpoint from the SIGNED BEACON. This pins
        // the two properties that make that safe and effective.
        // Mirrors Node::routes_via_witness (private to node.rs): a block AT or
        // ABOVE floor+1 is on the unfinalized frontier and needs full witnesses.
        let needs_full_witness = |h: u32, floor: u32| h >= floor.saturating_add(1);
        let (bc, _genesis) = fee_accounting_test_chain();
        let stuck_tip = 292_952u32;
        let blocked = stuck_tip + 1;

        // While the network has NOT yet buried the blocked block by the reorg
        // margin, the beacon must NOT be able to receipt-trust it — finality is
        // never brought nearer the tip than CHECKPOINT_REORG_MARGIN.
        let too_soon = blocked + CHECKPOINT_REORG_MARGIN - 1;
        bc.advance_checkpoint_behind(too_soon).unwrap();
        assert!(
            needs_full_witness(blocked, bc.verification_floor()),
            "a block the network has not yet buried must still require full witnesses"
        );

        // Once the beacon is a full margin past it, the floor covers it and the
        // block routes via the receipt path — the node can move again.
        let buried = blocked + CHECKPOINT_REORG_MARGIN;
        bc.advance_checkpoint_behind(buried).unwrap();
        assert!(
            !needs_full_witness(blocked, bc.verification_floor()),
            "once the beacon has buried the block by the reorg margin it must be receipt-trustable"
        );

        // Monotonic: a lower/stale beacon can never walk finality backwards.
        let floor_before = bc.verification_floor();
        bc.advance_checkpoint_behind(buried - 100).unwrap();
        assert_eq!(
            bc.verification_floor(),
            floor_before,
            "checkpoint advancement must be monotonic — finality can never regress"
        );
    }

    #[test]
    fn witness_completeness_gates_the_relay_publish_shape() {
        // The relay-publish poison guard: a body is publishable only when EVERY
        // non-system tx carries a full (>64-byte) ML-DSA signature. A truncated
        // receipt-form signature — what a stored block keeps once the confirmed-
        // witness store has pruned past WITNESS_RETENTION_BLOCKS — must fail, or
        // publishing it wedges every node that later validates that height at its
        // own frontier (live incident 2026-07-27, block 290968).
        let coinbase = Transaction {
            sender: "MINING_REWARDS".to_string(),
            recipient: "11".repeat(20),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: Transaction::to_units(10.0),
            timestamp: 1_700_000_000,
            signature: None,
            pub_key: None,
            sig_hash: None,
        };
        let mut regular = Transaction {
            sender: "a".repeat(40),
            recipient: "b".repeat(40),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: Transaction::to_units(1.0),
            timestamp: 1_700_000_000,
            signature: Some(hex::encode(vec![7u8; mldsa::SIGNATURE_BYTES])),
            pub_key: Some("bb".repeat(mldsa::PUBLIC_KEY_BYTES)),
            sig_hash: Some("cc".repeat(32)),
        };
        let mk = |txs: Vec<Transaction>| Block {
            index: 100,
            previous_hash: [0u8; 32],
            timestamp: 1_700_000_000,
            transactions: txs,
            nonce: 0,
            difficulty: 0,
            hash: [0u8; 32],
            merkle_root: [0u8; 32],
        };

        // Coinbase-only: trivially complete (system txs are unsigned by design).
        assert!(Blockchain::block_witnesses_are_complete(&mk(vec![
            coinbase.clone()
        ])));
        // Full witness present: publishable.
        assert!(Blockchain::block_witnesses_are_complete(&mk(vec![
            coinbase.clone(),
            regular.clone()
        ])));

        // Truncated (64-byte receipt) signature: NOT publishable — this is the
        // exact shape that poisoned the relay.
        regular.signature = Some(hex::encode(vec![7u8; 64]));
        assert!(!Blockchain::block_witnesses_are_complete(&mk(vec![
            coinbase.clone(),
            regular.clone()
        ])));

        // Missing signature entirely: also not publishable.
        regular.signature = None;
        assert!(!Blockchain::block_witnesses_are_complete(&mk(vec![
            coinbase.clone(),
            regular.clone()
        ])));

        // One good tx does not excuse one short tx (block 290968's exact shape:
        // a full witness alongside truncated ones).
        let mut good = regular.clone();
        good.signature = Some(hex::encode(vec![9u8; mldsa::SIGNATURE_BYTES]));
        let mut short = regular.clone();
        short.signature = Some(hex::encode(vec![9u8; 64]));
        assert!(!Blockchain::block_witnesses_are_complete(&mk(vec![
            coinbase, good, short
        ])));
    }

    #[test]
    fn reorg_readmit_persists_row_that_survives_a_mempool_rebuild() {
        let bc = test_blockchain();
        let full = Transaction {
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: Transaction::to_units(2.0),
            timestamp: 1_234,
            signature: Some(hex::encode(vec![7u8; 128])), // full (>64B) signature
            pub_key: None,
            sig_hash: None,
        };

        bc.persist_readmitted_pending_tx(&full).unwrap();

        // The pending row exists (this is what sync_mempool_with_sled rebuilds
        // from — before the fix the re-queue lived only in memory and the next
        // rebuild silently destroyed the payment) and stores the COMPACT form.
        let pending = bc.db.open_tree(PENDING_TRANSACTIONS_TREE).unwrap();
        let row = pending
            .get(full.get_tx_id().as_bytes())
            .unwrap()
            .expect("pending row must survive a mempool rebuild");
        let stored = deserialize_transaction(&row).expect("storage form decodes");
        let stored_sig = hex::decode(stored.signature.unwrap()).unwrap();
        assert!(
            stored_sig.len() <= 64,
            "pending row stores the truncated storage form"
        );
        assert!(stored.sig_hash.is_some(), "storage form carries sig_hash");

        // The sidecar keeps the FULL signature so the mempool rebuild can
        // rehydrate a gossip-able tx.
        let sidecar = bc.db.open_tree(PENDING_FULL_SIGNATURES_TREE).unwrap();
        let sig = sidecar
            .get(full.get_tx_id().as_bytes())
            .unwrap()
            .expect("full-signature sidecar row present");
        assert!(sig.len() > 64, "sidecar keeps the full signature");
    }

    #[test]
    fn rehydrate_reverted_tx_restores_full_signature_or_drops() {
        let bc = test_blockchain();
        let cw_tree = bc.db.open_tree(CONFIRMED_WITNESSES_TREE).unwrap();

        // A reverted tx as read back from a stored block: identifying fields intact,
        // but only a truncated signature survived storage.
        let reverted = Transaction {
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: Transaction::to_units(2.0),
            timestamp: 1_234,
            signature: Some(hex::encode(vec![0u8; 32])),
            pub_key: None,
            sig_hash: None,
        };

        // No witness retained: nothing to rehydrate, so it is dropped.
        assert!(bc.rehydrate_reverted_tx(&reverted).is_none());

        // Retain the full-signature witness under the same (signature-independent) id.
        let mut full = reverted.clone();
        full.signature = Some(hex::encode(vec![7u8; 128]));
        cw_tree
            .insert(
                reverted.get_tx_id().as_bytes(),
                codec::serialize(&full).unwrap(),
            )
            .unwrap();
        let got = bc
            .rehydrate_reverted_tx(&reverted)
            .expect("full witness present");
        let sig = hex::decode(got.signature.unwrap()).unwrap();
        assert!(
            sig.len() > 64,
            "rehydrated tx must carry the full signature"
        );

        // A witness whose own signature is truncated is treated as absent (it could
        // not pass the full-signature gate either).
        let mut truncated_witness = reverted.clone();
        truncated_witness.signature = Some(hex::encode(vec![9u8; 40]));
        cw_tree
            .insert(
                reverted.get_tx_id().as_bytes(),
                codec::serialize(&truncated_witness).unwrap(),
            )
            .unwrap();
        assert!(bc.rehydrate_reverted_tx(&reverted).is_none());
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
        assert!(
            bc.confirmed_tx_index(&tx_id).is_some(),
            "entry must be registered"
        );

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
        assert!(
            block.verify_pow(),
            "difficulty-0 PoW is trivially valid as a mechanism"
        );
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
        bc.raise_trusted_checkpoint(WITNESS_LOSS_FLOOR + 100)
            .unwrap();
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

    /// Balance round-trip identity: to_units(from_units(u)) == u for every u the chain
    /// can reach (through 2^51 units). This is WHY routing the consensus writer + gates
    /// from to_units(get_confirmed_balance(..)) to the exact get_confirmed_balance_units
    /// is value-identical in the reachable range — no fork. The first value where the
    /// round-trip drifts is 3_355_443_200_000_019 units (2^25 coins + 19, ~33.55M coins),
    /// far above any balance the current chain could hold; the exact path is what keeps
    /// an incrementally-maintained ledger equal to a from-genesis rebuild past that point.
    #[test]
    fn balance_roundtrip_is_identity_through_the_reachable_range() {
        // ~2^51 units = 2_251_799_813_685_248 (~22.5M coins) is the top of the verified
        // identity range and already well beyond any reachable single-address balance.
        for u in [
            0i128,
            1,
            100_000_000,           // 1 coin
            2_250_000_000_000_000, // ~22.5M coins
            1i128 << 50,
            1i128 << 51,
        ] {
            assert_eq!(
                Transaction::to_units(Transaction::from_units(u)),
                u,
                "round-trip must be the identity at {u} units (reachable range)"
            );
        }
        // Documented onset: the first unit value where the old f64 round-trip drifts.
        const ROUNDTRIP_ONSET: i128 = 3_355_443_200_000_019;
        assert_ne!(
            Transaction::to_units(Transaction::from_units(ROUNDTRIP_ONSET)),
            ROUNDTRIP_ONSET,
            "onset: to_units(from_units) is expected to drift at {ROUNDTRIP_ONSET} units"
        );
    }

    /// get_confirmed_balance_units returns the stored i128 EXACTLY at a balance where the
    /// f64 get_confirmed_balance drifts — proving the consensus writer/gates (now routed
    /// to the units getter) stay equal to the exact rebuild/catch-up ledger past the
    /// round-trip onset, while the old to_units(get_confirmed_balance(..)) would not.
    #[tokio::test]
    async fn confirmed_balance_units_is_exact_where_f64_drifts() {
        let bc = test_blockchain();
        // Empty chain: tip 0, index height 0, so no lazy rebuild fires and the seeded
        // value is read straight back.
        let tree = bc.db.open_tree(BALANCES_TREE).unwrap();
        const DRIFTY: i128 = 3_355_443_200_000_019; // first value the f64 round-trip drifts
        tree.insert("whale".as_bytes(), codec::serialize(&DRIFTY).unwrap())
            .unwrap();

        // Exact getter: byte-for-byte the stored value.
        assert_eq!(
            bc.get_confirmed_balance_units("whale").await.unwrap(),
            DRIFTY
        );

        // The f64 path round-trips and drifts — exactly why consensus reads the units getter.
        let via_f64 = Transaction::to_units(bc.get_confirmed_balance("whale").await.unwrap());
        assert_ne!(
            via_f64, DRIFTY,
            "the f64 round-trip drifts at this balance; consensus must use the units getter"
        );

        // A reachable-range balance is identical either way (value-identical, no fork).
        tree.insert(
            "small".as_bytes(),
            codec::serialize(&2_250_000_000_000_000i128).unwrap(),
        )
        .unwrap();
        assert_eq!(
            bc.get_confirmed_balance_units("small").await.unwrap(),
            Transaction::to_units(bc.get_confirmed_balance("small").await.unwrap()),
            "below the onset the exact getter and the f64 round-trip must agree"
        );
    }

    /// A confirmed-balance read for an absent address on a current-index chain returns 0
    /// WITHOUT persisting a phantom 0-entry. The old read-path write grew the balances tree
    /// without bound (one key per explorer/RPC query of an arbitrary address; sled never
    /// reclaims), while the returned value — and total supply — are unchanged.
    #[tokio::test]
    async fn confirmed_balance_read_does_not_persist_phantom_zero_entries() {
        let bc = test_blockchain();
        let tree = bc.db.open_tree(BALANCES_TREE).unwrap();

        // Empty chain: index height 0 >= tip 0, so absent addresses take the current-index
        // no-entry branch. Each reads back 0 and must leave the tree untouched.
        for addr in ["nobody_1", "nobody_2", "nobody_3"] {
            assert_eq!(bc.get_confirmed_balance_units(addr).await.unwrap(), 0);
            assert!(
                tree.get(addr.as_bytes()).unwrap().is_none(),
                "reading an absent balance must not persist a 0-entry for {addr}"
            );
        }
        // Reading is idempotent (still 0, still no entry) and real entries read back exactly.
        assert_eq!(bc.get_confirmed_balance_units("nobody_1").await.unwrap(), 0);
        assert!(tree.get("nobody_1".as_bytes()).unwrap().is_none());
        tree.insert("funded".as_bytes(), codec::serialize(&12_345i128).unwrap())
            .unwrap();
        assert_eq!(
            bc.get_confirmed_balance_units("funded").await.unwrap(),
            12_345
        );
    }

    /// The mining affordability gates (validate_new_block / finalize_block) must pass
    /// in_flight = &[] to the maturity scan, NOT &block.transactions. The block's own
    /// coinbase is never credited into the pre-block `confirmed`, so counting it in
    /// `immature` subtracts an uncredited reward and makes the gate exactly one block
    /// reward stricter than the authoritative apply (process_transactions_batch, where
    /// the coinbase cancels: +R in balance, +R in immature) — the "Insufficient funds
    /// while mining" self-spend burn (2026-07-12 audit). This pins the crux: the
    /// in-flight coinbase inflates the immature total by exactly its amount, which is
    /// what the gates must NOT subtract (matching add_transaction and the authority).
    #[test]
    fn mining_gate_maturity_scan_must_exclude_the_blocks_own_coinbase() {
        let bc = test_blockchain();
        // Past the activation height, so the maturity overlay is enforced.
        let spend_height = MATURITY_ACTIVATION_HEIGHT as u64 + 200;
        let reward = Transaction::to_units(10.0);
        let own_coinbase = Transaction {
            sender: "MINING_REWARDS".to_string(),
            recipient: "W".to_string(),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: reward,
            timestamp: 1_000,
            signature: None,
            pub_key: None,
            sig_hash: None,
        };
        // Fresh chain: no stored coinbase in the maturity window, so stored immature = 0.
        let without_inflight = bc.immature_reward_units_scan("W", spend_height, &[]);
        let with_inflight =
            bc.immature_reward_units_scan("W", spend_height, std::slice::from_ref(&own_coinbase));
        assert_eq!(
            without_inflight, 0,
            "no stored immature coinbase for W on a fresh chain"
        );
        assert_eq!(
            with_inflight - without_inflight,
            reward,
            "the block's own coinbase inflates immature by exactly R; the gates now pass &[] so \
             they never subtract that uncredited R (matching add_transaction + the authority)"
        );
        // Below the activation height the overlay is inert regardless of in_flight.
        assert_eq!(
            bc.immature_reward_units_scan("W", 100, std::slice::from_ref(&own_coinbase)),
            0
        );
    }

    /// The hoisted precompute the local-miner gates now use (immature_rewards_by_recipient)
    /// must return, for EVERY address, the byte-identical i128 that the per-transaction
    /// immature_reward_units_scan(addr, height, &[]) returned — the gates' accept/reject
    /// verdict depends on that equivalence. Also pins the crux that the map excludes the
    /// block's own (in-flight) coinbase, exactly matching the &[] the gates pass.
    #[test]
    fn immature_rewards_by_recipient_matches_per_tx_scan() {
        let bc = test_blockchain();
        let mat = MINING_REWARD_MATURITY as u64;
        let spend_height = MATURITY_ACTIVATION_HEIGHT as u64 + 200; // past activation
        let window_low = spend_height - mat + 1;

        // Two stored coinbases to alice and one to bob INSIDE the window
        // [spend_height-MAT+1, spend_height); one to carol BELOW it (must not count).
        for (h, miner) in [
            (window_low, "alice"),
            (window_low + 30, "bob"),
            (spend_height - 2, "alice"),
            (window_low - 5, "carol"),
        ] {
            insert_raw_block(&bc, &metadata_test_block(h as u32, [0u8; 32], miner, 10.0));
        }

        // Block being validated at spend_height: its OWN coinbase to alice, then regular spends.
        let mut txs = vec![Transaction {
            sender: "MINING_REWARDS".to_string(),
            recipient: "alice".to_string(),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: Transaction::to_units(10.0),
            timestamp: 1_000,
            signature: None,
            pub_key: None,
            sig_hash: None,
        }];
        for s in ["alice", "bob", "carol", "dave"] {
            txs.push(Transaction {
                sender: s.to_string(),
                recipient: "zzz".to_string(),
                fee_units: Transaction::to_units(NETWORK_FEE),
                amount_units: Transaction::to_units(1.0),
                timestamp: 1_000,
                signature: Some(hex::encode(vec![1u8; 128])),
                pub_key: None,
                sig_hash: None,
            });
        }

        // Value-for-value equivalence with the per-tx &[] scan, for every address touched.
        let map = bc.immature_rewards_by_recipient(&txs, spend_height as u32);
        for s in ["alice", "bob", "carol", "dave", "MINING_REWARDS", "zzz"] {
            assert_eq!(
                map.get(s).copied().unwrap_or(0),
                bc.immature_reward_units_scan(s, spend_height, &[]),
                "map must equal the per-tx &[] scan for {s}"
            );
        }

        // Crux: the map counts only in-window stored rewards and EXCLUDES the in-flight coinbase.
        assert_eq!(
            map.get("alice").copied().unwrap_or(0),
            Transaction::to_units(20.0),
            "alice has two in-window stored rewards; the block's own coinbase is not counted"
        );
        assert!(
            bc.immature_reward_units_scan("alice", spend_height, &txs)
                > map.get("alice").copied().unwrap_or(0),
            "the in-flight coinbase inflates immature — the gates must use the &[] map"
        );
        assert_eq!(
            map.get("carol").copied().unwrap_or(0),
            0,
            "carol's only reward is below the maturity window"
        );

        // Below the activation height the overlay is inert (empty map, scan 0), and at the
        // exact boundary it engages — both must still agree with the scan.
        let below = bc.immature_rewards_by_recipient(&txs, MATURITY_ACTIVATION_HEIGHT - 1);
        assert!(
            below.is_empty(),
            "overlay is empty below the activation height"
        );
        for s in ["alice", "bob"] {
            assert_eq!(
                below.get(s).copied().unwrap_or(0),
                bc.immature_reward_units_scan(s, (MATURITY_ACTIVATION_HEIGHT - 1) as u64, &[]),
                "below activation both the map and the scan must be 0 for {s}"
            );
        }
    }

    /// The block reward is well-formed across the ENTIRE emission timeline,
    /// including the long-horizon regime where the decaying current_max
    /// (MAX_BLOCK_REWARD * 0.83^periods) falls below MIN_BLOCK_REWARD. The reward
    /// floor is bounded by the ceiling, so no period produces a `clamp(min > max)`
    /// (which f64::clamp would panic on, on both the validation and mining reward
    /// paths). This pins two things at once: (a) VALUE IDENTITY in the reachable
    /// range — for every period where current_max >= MIN_BLOCK_REWARD the reward is
    /// exactly what a fixed-1.0 floor produced, so the bound is not a consensus
    /// change for any block the chain will see for ~10.5 years; (b) past the
    /// crossover the reward tracks current_max and never panics.
    #[test]
    fn block_reward_well_formed_across_full_emission_timeline() {
        const SECONDS_IN_SIX_MONTHS: u64 = 15_768_000;
        let bc = test_blockchain();
        let genesis = metadata_test_block(0, [0u8; 32], "genesis", 50.0);
        let g_ts = genesis.timestamp;
        insert_raw_block(&bc, &genesis);

        // metadata_test_block carries only the MINING_REWARDS coinbase, which the
        // reward fold filters out -> tx_count 0 -> empty-block base = current_max*0.2.
        for periods in [0u32, 1, 5, 12, 13, 20, 21, 22, 30, 60] {
            let current_max = MAX_BLOCK_REWARD * 0.83f64.powi(periods as i32);
            let mut b = metadata_test_block(1, genesis.hash, "miner", 1.0);
            b.timestamp = g_ts + periods as u64 * SECONDS_IN_SIX_MONTHS;
            let got = bc
                .calculate_block_reward(&b)
                .expect("reward must compute (no panic) at every period");
            assert!(
                got.is_finite() && got >= 0.0,
                "period {periods}: reward {got} not finite/non-negative"
            );

            // Independent expected value using the ORIGINAL fixed-1.0 floor in the
            // reachable range: proves the ceiling-bounded floor changed nothing while
            // current_max >= 1.0. Past the crossover the original panicked, so there
            // the only requirement is "== current_max, no panic".
            let base = current_max * 0.2; // empty-block base
            if current_max >= MIN_BLOCK_REWARD {
                let expected = Transaction::round_amount(base.clamp(MIN_BLOCK_REWARD, current_max));
                assert!(
                    (got - expected).abs() < 1e-9,
                    "period {periods}: reward {got} != fixed-floor expected {expected} \
                     (current_max={current_max}) — the bound must be value-identical in range"
                );
            } else {
                let expected = Transaction::round_amount(current_max);
                assert!(
                    (got - expected).abs() < 1e-9,
                    "period {periods}: reward {got} != current_max {expected} past crossover"
                );
            }
        }
    }

    fn fee_accounting_test_chain() -> (Blockchain, Block) {
        let bc = test_blockchain();
        let genesis = Blockchain::genesis_launch_block().expect("launch genesis");
        insert_raw_block(&bc, &genesis);
        (bc, genesis)
    }

    /// A template-eligible user transaction for estimator tests. sig_bytes
    /// controls the decoded signature length (must exceed 64 to count as a
    /// full witness) and, through the hex string, the serialized size — which
    /// is how the byte-budget congestion tests steer capacity with few txs.
    fn estimator_tx(fee_units: i128, timestamp: u64, sig_bytes: usize) -> Transaction {
        Transaction {
            sender: "11".repeat(20),
            recipient: "22".repeat(20),
            amount_units: 100_000_000,
            fee_units,
            timestamp,
            signature: Some("ab".repeat(sig_bytes)),
            pub_key: None,
            sig_hash: None,
        }
    }

    const ESTIMATOR_NOW: u64 = 2_000_000_000;

    #[test]
    fn fee_estimate_quiet_mempool_recommends_the_anchor() {
        let bc = test_blockchain();

        // Anchor invariants the wallet relies on: strictly above the relay
        // floor, under the AUTO ceiling, which is itself well under the
        // explicit --fee ceiling (an automatic fee must never reach it).
        assert_eq!(FEE_ESTIMATE_ANCHOR_UNITS, MIN_RELAY_FEE_UNITS * 2);
        assert!(FEE_ESTIMATE_ANCHOR_UNITS < FEE_ESTIMATE_AUTO_CAP_UNITS);
        assert!(FEE_ESTIMATE_AUTO_CAP_UNITS < WALLET_FEE_SAFETY_LIMIT_UNITS);

        let empty = bc.fee_estimate_from_candidates(Vec::new(), ESTIMATOR_NOW);
        assert_eq!(empty.recommended_units, FEE_ESTIMATE_ANCHOR_UNITS);
        assert!(!empty.congested);
        assert_eq!(empty.pending_candidates, 0);
        assert_eq!(empty.next_block_fits, 0);
        assert_eq!(empty.basis(), "quiet");

        // A lightly loaded mempool that fully fits the next block still prices
        // at the anchor — fees only rise when inclusion is actually contended.
        let light = bc.fee_estimate_from_candidates(
            vec![
                estimator_tx(MIN_RELAY_FEE_UNITS, ESTIMATOR_NOW - 10, 65),
                estimator_tx(30_000, ESTIMATOR_NOW - 5, 65),
                estimator_tx(500_000, ESTIMATOR_NOW - 1, 65),
            ],
            ESTIMATOR_NOW,
        );
        assert_eq!(light.recommended_units, FEE_ESTIMATE_ANCHOR_UNITS);
        assert!(!light.congested);
        assert_eq!(light.pending_candidates, 3);
        assert_eq!(light.next_block_fits, 3);
    }

    #[test]
    fn fee_estimate_prices_one_unit_over_the_marginal_fee_under_congestion() {
        let bc = test_blockchain();
        // Three ~480 KB transactions against the mempool feed's 1 MB byte
        // budget (the binding constraint pre-activation): the two highest fees
        // fit, the third is excluded, so the recommendation must beat the
        // weakest INCLUDED fee by exactly one unit (the oldest-first tiebreak
        // means merely matching it loses).
        let sig_bytes = 240_000;
        let estimate = bc.fee_estimate_from_candidates(
            vec![
                estimator_tx(50_000, ESTIMATOR_NOW - 30, sig_bytes),
                estimator_tx(40_000, ESTIMATOR_NOW - 20, sig_bytes),
                estimator_tx(30_000, ESTIMATOR_NOW - 10, sig_bytes),
            ],
            ESTIMATOR_NOW,
        );
        assert!(estimate.congested);
        assert_eq!(estimate.next_block_fits, 2);
        assert_eq!(estimate.pending_candidates, 3);
        assert_eq!(estimate.recommended_units, 40_001);
        assert_eq!(estimate.basis(), "next-block");
    }

    #[test]
    fn fee_estimate_is_clamped_to_the_automatic_ceiling() {
        let bc = test_blockchain();
        // A mempool stuffed with maximum-fee transactions must not drag the
        // AUTOMATIC fee up with it: marginal+1 far exceeds the auto cap, so the
        // clamp binds. This is the bound that keeps a hostile (or merely rich)
        // mempool from spending a default user's balance, and it caps the payoff
        // of deliberately fee-pumping the estimator.
        let sig_bytes = 240_000;
        let estimate = bc.fee_estimate_from_candidates(
            vec![
                estimator_tx(WALLET_FEE_SAFETY_LIMIT_UNITS, ESTIMATOR_NOW - 30, sig_bytes),
                estimator_tx(WALLET_FEE_SAFETY_LIMIT_UNITS, ESTIMATOR_NOW - 20, sig_bytes),
                estimator_tx(WALLET_FEE_SAFETY_LIMIT_UNITS, ESTIMATOR_NOW - 10, sig_bytes),
            ],
            ESTIMATOR_NOW,
        );
        assert!(estimate.congested);
        assert_eq!(estimate.recommended_units, FEE_ESTIMATE_AUTO_CAP_UNITS);
        assert!(estimate.recommended_units < WALLET_FEE_SAFETY_LIMIT_UNITS);
    }

    #[test]
    fn fee_estimate_reserves_headroom_for_the_callers_own_transaction() {
        let bc = test_blockchain();
        // Every existing transaction fits, so nothing is displaced — but the
        // remaining byte budget cannot hold one more ordinary transfer. The
        // estimate exists to price THAT transfer, so this must read congested
        // (the pre-fix code called it quiet and recommended the anchor, which
        // would have been outbid by every incumbent).
        // Two ~494 KB transactions leave under TYPICAL_FULL_WITNESS_TX_BYTES of
        // the 1 MB feed budget free.
        let sig_bytes = 247_000;
        let estimate = bc.fee_estimate_from_candidates(
            vec![
                estimator_tx(60_000, ESTIMATOR_NOW - 30, sig_bytes),
                estimator_tx(50_000, ESTIMATOR_NOW - 20, sig_bytes),
            ],
            ESTIMATOR_NOW,
        );
        assert_eq!(estimate.next_block_fits, 2, "both incumbents fit");
        assert!(
            estimate.congested,
            "no room left for the caller's own transaction"
        );
        assert_eq!(estimate.recommended_units, 50_001);
    }

    #[test]
    fn fee_estimate_charges_ineligible_transactions_against_the_feed_budget() {
        let bc = test_blockchain();
        // Ineligible transactions still consume the mempool feed's selection
        // budget (the feed caps the RAW pool before the miner filters), so a
        // pool clogged with junk is congestion even though little is minable.
        // Truncated-witness readmits are the real-world shape: high fee, tiny,
        // never templatable.
        let junk_sig = 64; // stored/truncated witness -> not a template candidate
        let mut candidates = vec![estimator_tx(80_000, ESTIMATOR_NOW - 60, 245_000)];
        for i in 0..40 {
            candidates.push(estimator_tx(90_000, ESTIMATOR_NOW - 50 + i, junk_sig));
        }
        candidates.push(estimator_tx(70_000, ESTIMATOR_NOW - 5, 245_000));

        let estimate = bc.fee_estimate_from_candidates(candidates, ESTIMATOR_NOW);
        assert_eq!(
            estimate.pending_candidates, 2,
            "only the two full-witness transfers are template-eligible"
        );
        assert!(
            estimate.congested,
            "junk consuming feed budget is real congestion"
        );
    }

    #[test]
    fn fee_estimate_walk_is_bounded_by_next_block_capacity() {
        let bc = test_blockchain();
        // A large pool must not cost O(mempool): the walk stops once the feed
        // budget is spent. With ~480 KB transactions the 1 MB feed byte cap is
        // reached after 3, so the remaining thousands are never serialized —
        // this is what keeps the unauthenticated estimate endpoint cheap.
        let sig_bytes = 240_000;
        let candidates: Vec<Transaction> = (0..4_000)
            .map(|i| estimator_tx(50_000 + i as i128, ESTIMATOR_NOW - 100, sig_bytes))
            .collect();
        let estimate = bc.fee_estimate_from_candidates(candidates, ESTIMATOR_NOW);
        assert!(estimate.congested);
        assert!(
            estimate.pending_candidates <= 8,
            "scan stopped at feed capacity, saw {} candidates",
            estimate.pending_candidates
        );
    }

    #[test]
    fn template_candidate_predicate_matches_selection_rules() {
        let bc = test_blockchain();
        let good = estimator_tx(MIN_RELAY_FEE_UNITS, ESTIMATOR_NOW - 10, 65);
        assert!(bc.is_template_candidate(&good, ESTIMATOR_NOW));

        let mut coinbase = good.clone();
        coinbase.sender = "MINING_REWARDS".to_string();
        assert!(!bc.is_template_candidate(&coinbase, ESTIMATOR_NOW));

        let mut below_floor = good.clone();
        below_floor.fee_units = MIN_RELAY_FEE_UNITS - 1;
        assert!(!bc.is_template_candidate(&below_floor, ESTIMATOR_NOW));

        let mut stale = good.clone();
        stale.timestamp = ESTIMATOR_NOW
            .saturating_sub(MAX_TX_AGE_SECS)
            .saturating_sub(TEMPLATE_FRESHNESS_MARGIN_SECS);
        assert!(!bc.is_template_candidate(&stale, ESTIMATOR_NOW));

        let mut future = good.clone();
        future.timestamp = ESTIMATOR_NOW + MAX_BLOCK_FUTURE_TIME + 1;
        assert!(!bc.is_template_candidate(&future, ESTIMATOR_NOW));

        let mut truncated = good.clone();
        truncated.signature = Some("ab".repeat(64)); // stored form, not a full witness
        assert!(!bc.is_template_candidate(&truncated, ESTIMATOR_NOW));

        let mut unsigned = good.clone();
        unsigned.signature = None;
        assert!(!bc.is_template_candidate(&unsigned, ESTIMATOR_NOW));
    }

    #[test]
    fn template_candidate_order_is_fee_desc_then_oldest_first() {
        let high = estimator_tx(50_000, 100, 65);
        let low = estimator_tx(20_000, 50, 65);
        let low_newer = estimator_tx(20_000, 60, 65);

        assert_eq!(
            Blockchain::template_candidate_order(&high, &low),
            std::cmp::Ordering::Less,
            "higher fee sorts first"
        );
        assert_eq!(
            Blockchain::template_candidate_order(&low, &low_newer),
            std::cmp::Ordering::Less,
            "equal fees break ties oldest-first"
        );
    }

    fn fee_accounting_test_block(
        bc: &Blockchain,
        index: u32,
        timestamp: u64,
        fee_units: &[i128],
    ) -> Block {
        let mut transactions = vec![Transaction {
            sender: "MINING_REWARDS".to_string(),
            recipient: "11".repeat(20),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: 0,
            timestamp,
            signature: None,
            pub_key: None,
            sig_hash: None,
        }];
        for (position, fee_units) in fee_units.iter().copied().enumerate() {
            transactions.push(Transaction {
                sender: format!("{:040x}", position + 2),
                recipient: "22".repeat(20),
                fee_units,
                amount_units: Transaction::to_units(1.0),
                timestamp: timestamp.saturating_sub(position as u64),
                signature: None,
                pub_key: None,
                sig_hash: None,
            });
        }

        let mut block = Block {
            index,
            previous_hash: [0u8; 32],
            timestamp,
            transactions,
            nonce: 0,
            difficulty: 0,
            hash: [0u8; 32],
            merkle_root: [0u8; 32],
        };
        let expected = bc
            .calculate_block_reward(&block)
            .expect("historical reward calculation");
        block.transactions[0].amount_units = Transaction::to_units(expected);
        block
    }

    fn add_canonical_test_witnesses(block: &mut Block, receipt: bool) {
        let signature_bytes = if receipt { 64 } else { mldsa::SIGNATURE_BYTES };
        for tx in block
            .transactions
            .iter_mut()
            .filter(|tx| tx.sender != "MINING_REWARDS")
        {
            tx.signature = Some("aa".repeat(signature_bytes));
            tx.pub_key = Some("bb".repeat(mldsa::PUBLIC_KEY_BYTES));
            tx.sig_hash = Some("cc".repeat(32));
        }
    }

    #[test]
    fn fee_accounting_activation_preserves_historical_reward_vectors() {
        let (bc, genesis) = fee_accounting_test_chain();
        let vectors = [
            (Vec::new(), 10.0),
            (vec![Transaction::to_units(0.0005)], 1.006695),
            (vec![Transaction::to_units(0.005)], 1.06695),
            (vec![Transaction::to_units(0.71677928)], 10.59767456),
        ];

        for (fees, expected) in vectors {
            let block = fee_accounting_test_block(&bc, 99, genesis.timestamp, fees.as_slice());
            assert_eq!(
                bc.calculate_block_reward(&block).unwrap(),
                expected,
                "the historical reward vector must remain byte-for-byte unchanged"
            );
            bc.validate_block_reward_rules_at(&block, 100)
                .expect("all exact historical coinbases remain valid before activation");
        }
    }

    #[test]
    fn fee_accounting_accepts_compatibility_vectors() {
        const SIX_MONTHS: u64 = 15_768_000;
        let (bc, genesis) = fee_accounting_test_chain();

        let current_period_fee_vector = fee_accounting_test_block(
            &bc,
            100,
            genesis.timestamp,
            &[Transaction::to_units(0.71677928)],
        );
        bc.validate_block_reward_rules_at(&current_period_fee_vector, 100)
            .expect("current-period compatibility vector remains admissible");

        let pool_fees = vec![Transaction::to_units(0.0005); 10];
        for (index, timestamp) in [
            (100, genesis.timestamp),
            (101, genesis.timestamp + SIX_MONTHS),
        ] {
            let pool = fee_accounting_test_block(&bc, index, timestamp, &pool_fees);
            bc.validate_block_reward_rules_at(&pool, 100)
                .expect("ten existing pool payouts remain admissible");
        }
    }

    #[test]
    fn activated_fee_accounting_is_a_strict_subset_of_the_prior_reward_rule() {
        let (bc, genesis) = fee_accounting_test_chain();
        let admissible = fee_accounting_test_block(
            &bc,
            100,
            genesis.timestamp,
            &[Transaction::to_units(0.0005)],
        );
        let prior_reward_units =
            Transaction::to_units(bc.calculate_block_reward(&admissible).unwrap());
        assert_eq!(
            admissible.transactions[0].amount_units, prior_reward_units,
            "an admissible activated template keeps the exact prior coinbase"
        );
        bc.validate_block_reward_rules_at(&admissible, 101)
            .expect("the prior-height predicate accepts the admissible template");
        bc.validate_block_reward_rules_at(&admissible, 100)
            .expect("the activated predicate accepts the same exact template");

        let excluded =
            fee_accounting_test_block(&bc, 100, genesis.timestamp, &[Transaction::to_units(1.0)]);
        assert_eq!(
            excluded.transactions[0].amount_units,
            Transaction::to_units(bc.calculate_block_reward(&excluded).unwrap())
        );
        bc.validate_block_reward_rules_at(&excluded, 101)
            .expect("the prior-height predicate accepts its exact historical reward");
        assert!(matches!(
            bc.validate_block_reward_rules_at(&excluded, 100),
            Err(BlockchainError::FeeAccountingLimitExceeded)
        ));
    }

    #[test]
    fn current_schedule_high_reward_region_is_bounded_by_net_issuance() {
        let (bc, genesis) = fee_accounting_test_chain();

        for (fee, expected_reward) in [(3.0, 41.17), (3.84615385, 50.0)] {
            let candidate = fee_accounting_test_block(
                &bc,
                100,
                genesis.timestamp,
                &[Transaction::to_units(fee)],
            );
            let reward_units = candidate.transactions[0].amount_units;
            let fee_units =
                Blockchain::aggregate_regular_fee_units(&candidate.transactions).unwrap();
            let baseline = bc
                .scheduled_fee_accounting_baseline_units(&candidate)
                .unwrap();

            assert_eq!(reward_units, Transaction::to_units(expected_reward));
            assert_eq!(baseline, Transaction::to_units(10.0));
            assert!(
                reward_units - fee_units > baseline,
                "the high-reward vector must exceed the scheduled net-issuance baseline"
            );
            assert!(matches!(
                bc.validate_block_reward_rules_at(&candidate, 100),
                Err(BlockchainError::FeeAccountingLimitExceeded)
            ));
        }

        let one_atom_over = fee_accounting_test_block(
            &bc,
            100,
            genesis.timestamp,
            &[Transaction::to_units(39.99999999)],
        );
        assert_eq!(
            one_atom_over.transactions[0].amount_units,
            Transaction::to_units(MAX_BLOCK_REWARD)
        );
        assert!(matches!(
            bc.validate_block_reward_rules_at(&one_atom_over, 100),
            Err(BlockchainError::FeeAccountingLimitExceeded)
        ));

        let fee_funded =
            fee_accounting_test_block(&bc, 100, genesis.timestamp, &[Transaction::to_units(40.0)]);
        assert_eq!(
            fee_funded.transactions[0].amount_units,
            Transaction::to_units(MAX_BLOCK_REWARD),
            "the historical reward calculation remains exactly capped at 50"
        );
        let fee_units = Blockchain::aggregate_regular_fee_units(&fee_funded.transactions).unwrap();
        let baseline = bc
            .scheduled_fee_accounting_baseline_units(&fee_funded)
            .unwrap();
        assert_eq!(
            fee_funded.transactions[0].amount_units - fee_units,
            baseline,
            "a capped reward is admissible only when fees fund everything above baseline issuance"
        );
        bc.validate_block_reward_rules_at(&fee_funded, 100)
            .expect("a fee-funded reward at the exact net-issuance boundary must remain valid");
    }

    #[test]
    fn fee_accounting_rejects_only_over_bound_templates_and_keeps_exact_coinbase() {
        let (bc, genesis) = fee_accounting_test_chain();
        let over_bound =
            fee_accounting_test_block(&bc, 100, genesis.timestamp, &[Transaction::to_units(1.0)]);
        assert!(matches!(
            bc.validate_block_reward_rules_at(&over_bound, 100),
            Err(BlockchainError::FeeAccountingLimitExceeded)
        ));

        let mut lower_coinbase = fee_accounting_test_block(
            &bc,
            100,
            genesis.timestamp,
            &[Transaction::to_units(0.0005)],
        );
        lower_coinbase.transactions[0].amount_units -= 1;
        assert!(matches!(
            bc.validate_block_reward_rules_at(&lower_coinbase, 100),
            Err(BlockchainError::InvalidTransactionAmount)
        ));

        let mut higher_coinbase = lower_coinbase.clone();
        higher_coinbase.transactions[0].amount_units += 2;
        assert!(matches!(
            bc.validate_block_reward_rules_at(&higher_coinbase, 100),
            Err(BlockchainError::InvalidTransactionAmount)
        ));
    }

    #[test]
    fn fee_accounting_template_helper_tracks_aggregate_and_checked_arithmetic() {
        let (bc, genesis) = fee_accounting_test_chain();
        let individual =
            fee_accounting_test_block(&bc, 100, genesis.timestamp, &[Transaction::to_units(0.4)]);
        let first = individual.transactions[1].clone();
        assert!(
            bc.template_fee_accounting_is_admissible_at(
                100,
                genesis.timestamp,
                std::slice::from_ref(&first),
                100,
            )
            .unwrap(),
            "each individual transaction fits"
        );
        assert!(
            !bc.template_fee_accounting_is_admissible_at(
                100,
                genesis.timestamp,
                &[first.clone(), first.clone()],
                100,
            )
            .unwrap(),
            "the miner must account for the aggregate template"
        );
        assert!(
            bc.template_fee_accounting_is_admissible_at(
                99,
                genesis.timestamp,
                &[first.clone(), first],
                100,
            )
            .unwrap(),
            "the helper is inert before activation"
        );

        let mut overflow = individual.transactions[1].clone();
        overflow.fee_units = i128::MAX;
        assert!(matches!(
            bc.template_fee_accounting_is_admissible_at(
                100,
                genesis.timestamp,
                &[overflow.clone(), overflow],
                100,
            ),
            Err(BlockchainError::InvalidTransactionAmount)
        ));
    }

    #[test]
    fn fee_accounting_keeps_bounded_transfer_fees_mineable_across_the_full_schedule() {
        const SIX_MONTHS: u64 = 15_768_000;
        let (bc, genesis) = fee_accounting_test_chain();
        let mut saw_floor_regime = false;
        let mut saw_below_floor_ceiling = false;

        for period in 0u64..=60 {
            let timestamp = genesis
                .timestamp
                .saturating_add(period.saturating_mul(SIX_MONTHS));
            for fee in [0.0001, 0.0005] {
                let block =
                    fee_accounting_test_block(&bc, 100, timestamp, &[Transaction::to_units(fee)]);
                bc.validate_block_reward_rules_at(&block, 100)
                    .unwrap_or_else(|error| {
                        panic!("period {period}, fee {fee:.4} must remain mineable: {error}")
                    });
            }
            for fees in [
                vec![Transaction::to_units(0.0005); 10],
                vec![Transaction::to_units(0.001); 5],
                vec![Transaction::to_units(0.0001); 50],
            ] {
                let block = fee_accounting_test_block(&bc, 100, timestamp, &fees);
                bc.validate_block_reward_rules_at(&block, 100)
                    .unwrap_or_else(|error| {
                        panic!(
                            "period {period}, aggregate low-fee compatibility template failed: {error}"
                        )
                    });
            }

            let reference = fee_accounting_test_block(&bc, 100, timestamp, &[]);
            let baseline = bc
                .scheduled_fee_accounting_baseline_units(&reference)
                .unwrap();
            if period == 13 {
                assert!(
                    baseline >= Transaction::to_units(MIN_BLOCK_REWARD)
                        && baseline < Transaction::to_units(1.1),
                    "the scheduled floor plus low-fee compatibility envelope remains bounded"
                );
                saw_floor_regime = true;
            }
            if period == 22 {
                assert!(
                    baseline < Transaction::to_units(MIN_BLOCK_REWARD),
                    "the baseline follows the ceiling once it falls below the fixed floor"
                );
                saw_below_floor_ceiling = true;
            }
        }

        assert!(saw_floor_regime && saw_below_floor_ceiling);
    }

    #[test]
    fn activation_keeps_realistically_full_blocks_mineable_and_bounds_capacity() {
        // The other activation tests use tiny aggregates (<=50 txs, <=0.005 total
        // fees). The case that would actually bite a live network — a block filled
        // with ORDINARY transactions at the fee the wallet really recommends — was
        // untested. The activated rule caps NET issuance (reward - fees) at the
        // scheduled baseline, and because the coinbase is pinned to an exact value
        // a miner cannot voluntarily take less: past the bound the only legal move
        // is to include FEWER transactions. So per-block capacity is bounded by
        // aggregate FEES, not by tx count or bytes. This test pins both halves:
        // a full mempool feed at the anchor fee stays mineable today, and the
        // capacity bound is where we think it is.
        let (bc, genesis) = fee_accounting_test_chain();

        // A full 2000-tx mempool feed at the anchor fee (what the estimator
        // recommends on a quiet network) must remain mineable.
        let full_feed = vec![FEE_ESTIMATE_ANCHOR_UNITS; 2_000];
        let block = fee_accounting_test_block(&bc, 100, genesis.timestamp, &full_feed);
        bc.validate_block_reward_rules_at(&block, 100)
            .expect("a full 2000-tx feed at the anchor fee must stay mineable after activation");

        // Capacity bound: find the largest admissible anchor-fee tx count by
        // bisection, so a formula change that silently moves it fails here.
        let admits = |count: usize| -> bool {
            let fees = vec![FEE_ESTIMATE_ANCHOR_UNITS; count];
            let candidate = fee_accounting_test_block(&bc, 100, genesis.timestamp, &fees);
            bc.validate_block_reward_rules_at(&candidate, 100).is_ok()
        };
        let (mut lo, mut hi) = (0usize, MAX_BLOCK_TX_COUNT);
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            if admits(mid) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        assert!(
            lo >= 2_000,
            "anchor-fee capacity ({lo}) must cover a full mempool feed"
        );
        assert!(
            lo < MAX_BLOCK_TX_COUNT,
            "capacity ({lo}) is expected to bind below the hard tx cap at this schedule point"
        );

        // The bound is on AGGREGATE fees, so a higher per-tx fee reaches it with
        // proportionally fewer transactions — this is the number that shrinks as
        // the emission schedule decays, and the reason an un-upgraded miner can
        // only ever produce a rejected block when a block carries real fee volume.
        let ten_x = FEE_ESTIMATE_ANCHOR_UNITS * 10;
        let over = vec![ten_x; (lo / 10) + 2];
        let over_block = fee_accounting_test_block(&bc, 100, genesis.timestamp, &over);
        assert!(
            matches!(
                bc.validate_block_reward_rules_at(&over_block, 100),
                Err(BlockchainError::FeeAccountingLimitExceeded)
            ),
            "aggregate fees past the bound must be rejected regardless of tx count"
        );
    }

    #[test]
    fn activation_shape_rules_accept_transactions_built_by_pre_activation_clients() {
        // Compatibility guard for the flag day: the activated shape rules demand
        // pub_key + sig_hash + a full signature on every regular tx, and NO
        // signature fields on the system coinbase. Pre-activation clients already
        // build exactly this (admission sets sig_hash and requires pub_key;
        // Transaction::new leaves the coinbase's fields None), so their
        // transactions and templates stay valid across the boundary. If a future
        // change ever makes the shape stricter than what shipped clients emit,
        // this test fails instead of the live network splitting.
        let coinbase = Transaction::new(
            "MINING_REWARDS".to_string(),
            "11".repeat(20),
            0.0,
            NETWORK_FEE,
            1_700_000_000,
            None,
        );
        Blockchain::validate_activated_transaction_shape(
            &coinbase,
            SignatureValidationMode::RequireFull,
        )
        .expect("a pre-activation client's coinbase shape must stay valid");

        let mut regular = Transaction::new(
            "a".repeat(40),
            "b".repeat(40),
            1.0,
            NETWORK_FEE,
            1_700_000_000,
            Some("aa".repeat(mldsa::SIGNATURE_BYTES)),
        );
        regular.pub_key = Some("bb".repeat(mldsa::PUBLIC_KEY_BYTES));
        regular.sig_hash = Some("cc".repeat(32));
        Blockchain::validate_activated_transaction_shape(
            &regular,
            SignatureValidationMode::RequireFull,
        )
        .expect("a pre-activation client's signed transfer must stay valid");
    }

    #[test]
    fn fee_accounting_envelope_boundary_is_atomic_in_the_rising_regime() {
        const SIX_MONTHS: u64 = 15_768_000;
        let (bc, genesis) = fee_accounting_test_chain();
        let period_twelve_timestamp = genesis.timestamp + 12 * SIX_MONTHS;
        let period_twelve_boundary_units = Transaction::to_units(0.00674327);
        let period_twelve_boundary = fee_accounting_test_block(
            &bc,
            100,
            period_twelve_timestamp,
            &[period_twelve_boundary_units],
        );
        bc.validate_block_reward_rules_at(&period_twelve_boundary, 100)
            .expect("the pre-floor schedule boundary is inclusive");
        let period_twelve_above = fee_accounting_test_block(
            &bc,
            100,
            period_twelve_timestamp,
            &[period_twelve_boundary_units + 1],
        );
        assert!(matches!(
            bc.validate_block_reward_rules_at(&period_twelve_above, 100),
            Err(BlockchainError::FeeAccountingLimitExceeded)
        ));

        let timestamp = genesis.timestamp + 13 * SIX_MONTHS;
        let at_envelope =
            fee_accounting_test_block(&bc, 100, timestamp, &[LOW_FEE_COMPATIBILITY_ENVELOPE_UNITS]);
        bc.validate_block_reward_rules_at(&at_envelope, 100)
            .expect("the scheduled compatibility envelope is inclusive");

        let above_envelope = fee_accounting_test_block(
            &bc,
            100,
            timestamp,
            &[LOW_FEE_COMPATIBILITY_ENVELOPE_UNITS + 1],
        );
        assert!(matches!(
            bc.validate_block_reward_rules_at(&above_envelope, 100),
            Err(BlockchainError::FeeAccountingLimitExceeded)
        ));
    }

    #[test]
    fn fee_accounting_acceptance_matches_the_net_issuance_invariant() {
        const SIX_MONTHS: u64 = 15_768_000;
        let (bc, genesis) = fee_accounting_test_chain();
        let fees = [
            0.0001, 0.0005, 0.01, 0.10, 0.25, 0.50, 0.75, 1.0, 2.0, 3.0, 5.0, 10.0, 25.0, 50.0,
        ];
        let mut saw_excluded_region = false;

        for period in 0u64..=30 {
            let timestamp = genesis.timestamp + period * SIX_MONTHS;
            for fee in fees {
                let block =
                    fee_accounting_test_block(&bc, 100, timestamp, &[Transaction::to_units(fee)]);
                let reward_units = block.transactions[0].amount_units;
                let fee_units = Blockchain::aggregate_regular_fee_units(&block.transactions)
                    .expect("sample fees sum exactly");
                let baseline = bc
                    .scheduled_fee_accounting_baseline_units(&block)
                    .expect("scheduled baseline");
                let should_accept = reward_units.checked_sub(fee_units).unwrap() <= baseline;
                let result = bc.validate_block_reward_rules_at(&block, 100);

                if should_accept {
                    result.unwrap_or_else(|error| {
                        panic!(
                            "period {period}, fee {fee}: invariant-compliant block rejected: {error}"
                        )
                    });
                } else {
                    saw_excluded_region = true;
                    assert!(matches!(
                        result,
                        Err(BlockchainError::FeeAccountingLimitExceeded)
                    ));
                }
            }
        }

        assert!(
            saw_excluded_region,
            "the sampled schedule must exercise the narrowed accounting region"
        );
    }

    #[test]
    fn activated_shape_rules_are_canonical_bounded_and_storage_invariant() {
        let (bc, genesis) = fee_accounting_test_chain();
        let pool_fees = vec![Transaction::to_units(0.0005); 10];
        let mut full = fee_accounting_test_block(&bc, 100, genesis.timestamp, pool_fees.as_slice());
        add_canonical_test_witnesses(&mut full, false);

        Blockchain::validate_block_shape_rules_at(&full, SignatureValidationMode::RequireFull, 100)
            .expect("current ten-payout pool shape remains valid");
        let full_weight = Blockchain::full_witness_weight(&full).unwrap();
        assert!(
            codec::serialize(&full).unwrap().len() <= full_weight,
            "the deterministic weight must conservatively cover the full encoded block"
        );
        let packed_weight = full.transactions[1..]
            .iter()
            .try_fold(
                Blockchain::mining_template_base_weight(&full.transactions[0].recipient).unwrap(),
                |weight, tx| {
                    let tx_weight =
                        Blockchain::template_regular_transaction_weight_at(100, tx, 100)
                            .unwrap()
                            .unwrap();
                    weight.checked_add(tx_weight)
                },
            )
            .unwrap();
        assert_eq!(
            packed_weight, full_weight,
            "incremental miner accounting and canonical block accounting must agree"
        );
        assert!(
            full_weight < MAX_BLOCK_WEIGHT_BYTES / 10,
            "current pool batches retain ample weight headroom"
        );

        let mut receipt = full.clone();
        add_canonical_test_witnesses(&mut receipt, true);
        assert_eq!(
            Blockchain::full_witness_weight(&receipt).unwrap(),
            full_weight,
            "stored receipt form and incoming full form have identical weight"
        );
        Blockchain::validate_block_shape_rules_at(
            &receipt,
            SignatureValidationMode::AllowTruncatedStored,
            100,
        )
        .expect("exact stored receipt signatures are valid");
        assert!(matches!(
            Blockchain::validate_block_shape_rules_at(
                &receipt,
                SignatureValidationMode::RequireFull,
                100,
            ),
            Err(BlockchainError::NonCanonicalTransaction)
        ));

        let mut malformed = full.clone();
        malformed.transactions[1].recipient = "NOT_AN_ADDRESS".to_string();
        assert_eq!(
            Blockchain::template_regular_transaction_weight_at(
                99,
                &malformed.transactions[1],
                100,
            )
            .unwrap(),
            None,
            "pre-activation pending entries retain their historical template treatment"
        );
        assert!(matches!(
            Blockchain::template_regular_transaction_weight_at(
                100,
                &malformed.transactions[1],
                100,
            ),
            Err(BlockchainError::NonCanonicalTransaction)
        ));
        Blockchain::validate_block_shape_rules_at(
            &malformed,
            SignatureValidationMode::RequireFull,
            101,
        )
        .expect("shape restrictions are inert before activation");
        assert!(matches!(
            Blockchain::validate_block_shape_rules_at(
                &malformed,
                SignatureValidationMode::RequireFull,
                100,
            ),
            Err(BlockchainError::NonCanonicalTransaction)
        ));

        let mut uppercase_witness = full.clone();
        uppercase_witness.transactions[1].pub_key = Some("AB".repeat(mldsa::PUBLIC_KEY_BYTES));
        assert!(matches!(
            Blockchain::validate_block_shape_rules_at(
                &uppercase_witness,
                SignatureValidationMode::RequireFull,
                100,
            ),
            Err(BlockchainError::NonCanonicalTransaction)
        ));

        let heavy_fees = vec![Transaction::to_units(0.0005); 238];
        let mut heavy =
            fee_accounting_test_block(&bc, 100, genesis.timestamp, heavy_fees.as_slice());
        add_canonical_test_witnesses(&mut heavy, false);
        assert!(Blockchain::full_witness_weight(&heavy).unwrap() > MAX_BLOCK_WEIGHT_BYTES);
        assert!(matches!(
            Blockchain::validate_block_shape_rules_at(
                &heavy,
                SignatureValidationMode::RequireFull,
                100,
            ),
            Err(BlockchainError::BlockWeightExceeded)
        ));
    }

    #[test]
    fn canonical_user_address_is_exact_lowercase_hex() {
        assert!(is_canonical_user_address(&"01ab".repeat(10)));
        assert!(!is_canonical_user_address(&"01AB".repeat(10)));
        assert!(!is_canonical_user_address(&"0".repeat(39)));
        assert!(!is_canonical_user_address(&"g".repeat(40)));
        assert!(!is_canonical_user_address("MINING_REWARDS"));
    }

    #[tokio::test]
    async fn spendable_units_accessor_never_round_trips_through_f64() {
        let bc = test_blockchain();
        let address = "12".repeat(20);
        let confirmed_units = 4_567_890_123_456_789i128;
        let pending_units = 123_456_789i128;
        set_confirmed_balance(&bc, &address, confirmed_units);
        let pending_tree = bc.open_pending_debits_tree().unwrap();
        Blockchain::set_pending_debit_for(&pending_tree, &address, pending_units).unwrap();

        assert_eq!(
            bc.get_spendable_balance_units(&address).await.unwrap(),
            confirmed_units - pending_units
        );
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
    fn merkle_leaf_helper_preserves_normalized_consensus_encoding() {
        let signature = vec![0xabu8; 4_627];
        let mut tx = Transaction {
            sender: "11".repeat(20),
            recipient: "22".repeat(20),
            fee_units: Transaction::to_units(0.0005),
            amount_units: Transaction::to_units(3.0),
            timestamp: 123,
            signature: Some(hex::encode(&signature)),
            pub_key: Some(hex::encode(vec![0xcdu8; 2_592])),
            sig_hash: None,
        };

        // Reproduce the historical calculate_merkle_root leaf input directly:
        // derive sig_hash from the full signature, truncate to 64 bytes, serialize,
        // then SHA-256. The new helper must remain byte-identical.
        let sig_hash = Transaction::signature_hash_hex(&signature);
        let normalized = tx.with_truncated_signature(sig_hash.clone());
        let bytes = codec::serialize(&normalized).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let historical_leaf: [u8; 32] = hasher.finalize().into();

        assert_eq!(
            Blockchain::calculate_merkle_leaf_hash(&tx).unwrap(),
            historical_leaf
        );

        // Full and stored/truncated forms commit to the same leaf.
        tx.sig_hash = Some(sig_hash);
        assert_eq!(
            Blockchain::calculate_merkle_leaf_hash(&tx).unwrap(),
            Blockchain::calculate_merkle_leaf_hash(&normalized).unwrap()
        );
    }

    #[test]
    fn merkle_root_from_leaf_hashes_matches_transaction_path_for_all_shapes() {
        let txs = vec![
            user_tx("alice", "bob", 1.0, 1),
            user_tx("carol", "dave", 2.0, 2),
            user_tx("erin", "frank", 3.0, 3),
            user_tx("grace", "heidi", 4.0, 4),
            user_tx("ivan", "judy", 5.0, 5),
        ];
        for count in 0..=txs.len() {
            let slice = &txs[..count];
            let leaves = slice
                .iter()
                .map(Blockchain::calculate_merkle_leaf_hash)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(
                Blockchain::calculate_merkle_root(slice).unwrap(),
                Blockchain::calculate_merkle_root_from_leaf_hashes(&leaves).unwrap(),
                "root mismatch at transaction count {}",
                count
            );
        }
    }

    // ===== intra-block transaction-uniqueness rule =====

    // The predicate flags a repeated non-coinbase tx_id and exempts coinbase entries.
    #[test]
    fn has_duplicate_regular_tx_detects_dups_and_exempts_coinbase() {
        let a = user_tx("alice", "bob", 1.0, 100);
        let b = user_tx("alice", "carol", 2.0, 200);

        assert!(!Blockchain::has_duplicate_regular_tx(&[
            a.clone(),
            b.clone()
        ]));
        assert!(Blockchain::has_duplicate_regular_tx(&[
            a.clone(),
            a.clone()
        ]));

        // Two entries with the same id but different signature bytes are still a duplicate.
        let mut a_resigned = a.clone();
        a_resigned.signature = Some("bb".repeat(2400));
        assert_eq!(a.get_tx_id(), a_resigned.get_tx_id());
        assert!(Blockchain::has_duplicate_regular_tx(&[
            a.clone(),
            a_resigned
        ]));

        // Coinbase (MINING_REWARDS) entries are exempt even when identical.
        let coinbase = Transaction {
            sender: "MINING_REWARDS".to_string(),
            recipient: "miner".to_string(),
            fee_units: 0,
            amount_units: Transaction::to_units(50.0),
            timestamp: 1,
            signature: None,
            pub_key: None,
            sig_hash: None,
        };
        assert!(!Blockchain::has_duplicate_regular_tx(&[
            coinbase.clone(),
            coinbase.clone(),
            a
        ]));
    }

    // End-to-end: validate_block rejects a duplicate-tx block at any height (the rule is
    // ALWAYS-ON). Asserting the specific DuplicateTransaction variant makes this isolating: the C1
    // check runs before the merkle/difficulty/parent gates, so it is the FIRST to fire; if the
    // enforcement call were removed the block would be rejected by a later gate with a DIFFERENT
    // variant and this assertion would fail (confirmed separately via mutation testing).
    #[tokio::test]
    async fn validate_block_rejects_duplicate_tx() {
        let bc = test_blockchain();
        let tx = user_tx("alice", "bob", 1.0, 1234);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // A duplicate-tx block at an ordinary height is rejected as DuplicateTransaction.
        let dup = vec![tx.clone(), tx.clone()];
        assert!(Blockchain::has_duplicate_regular_tx(&dup));
        let merkle_root = Blockchain::calculate_merkle_root(&dup).unwrap();
        let mut block = Block {
            index: 7,
            previous_hash: [0u8; 32],
            timestamp: now,
            transactions: dup,
            nonce: 0,
            difficulty: 0,
            hash: [0u8; 32],
            merkle_root,
        };
        block.hash = block.calculate_hash_for_block();
        assert!(
            block.validate_header().is_ok(),
            "crafted block header should be valid"
        );
        assert!(
            matches!(
                bc.validate_block(&block).await,
                Err(BlockchainError::DuplicateTransaction)
            ),
            "a duplicate-tx block must be rejected as DuplicateTransaction"
        );

        // Control: an honest (distinct-tx) block at the SAME height is NOT flagged as a duplicate —
        // it fails later (parent linkage), never with DuplicateTransaction. Proves the rule fires
        // only on duplicates, not as a blanket rejection.
        let honest = vec![tx.clone(), user_tx("alice", "carol", 2.0, 5678)];
        let mut honest_block = block.clone();
        honest_block.merkle_root = Blockchain::calculate_merkle_root(&honest).unwrap();
        honest_block.transactions = honest;
        honest_block.hash = honest_block.calculate_hash_for_block();
        assert!(
            !matches!(
                bc.validate_block(&honest_block).await,
                Err(BlockchainError::DuplicateTransaction)
            ),
            "an honest (non-duplicate) block must NOT be rejected as DuplicateTransaction"
        );
    }

    // Invariant behind verified-only witness caching: get_tx_id() covers sender:recipient:amount:
    // fee:timestamp and excludes the signature/pub_key, so two transactions can share a tx_id while
    // only one carries the sender's real signature. Verification keys on the signature/address
    // binding, not on the id — so a witness that matches an id but not that binding fails to verify,
    // and is therefore never cached. This pins that: matching id, non-matching binding -> rejected.
    #[tokio::test]
    async fn witness_matching_id_but_wrong_binding_fails_verification() {
        let bc = test_blockchain();
        let wallet = Wallet::new(None).expect("wallet builds");
        let other = Wallet::new(None).expect("second wallet builds");
        let ts = 1_700_000_000u64;

        let genuine = signed_transfer(&wallet, "recipient_addr_for_test", 10.0, ts).await;
        assert!(
            bc.verify_transaction_signature(&genuine).is_ok(),
            "a correctly-signed witness must verify — honest blocks are unaffected"
        );

        // Same id-defining fields, but the key/signature binding is not the sender's.
        let mut mismatched = genuine.clone();
        mismatched.pub_key = other.get_public_key_hex().await;
        mismatched.sig_hash = None;

        assert_eq!(
            mismatched.get_tx_id(),
            genuine.get_tx_id(),
            "same tx_id — it excludes the signature/pub_key"
        );
        assert!(
            bc.verify_transaction_signature(&mismatched).is_err(),
            "matching id but not the sender's binding must fail verification, so it is never cached"
        );
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
        assert!(
            !bc.witness_branch_backoff_active(&tip_b),
            "unrelated branch unaffected"
        );
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
            Blockchain::replay_apply_block_checked(
                a,
                &[coinbase("A", 1000)],
                &mut bal,
                &mut recent,
            )
            .unwrap();
            let r = Blockchain::replay_apply_block_checked(
                a + m - 1,
                &[spend("A", "B", 500)],
                &mut bal,
                &mut recent,
            );
            assert!(
                r.is_err(),
                "reward buried only m-1 deep must not be spendable"
            );
        }
        // (2) Above activation, mature: reward at `a`, spend at a+m (depth m) -> allowed.
        {
            let (mut bal, mut recent) = (HashMap::new(), VecDeque::new());
            Blockchain::replay_apply_block_checked(
                a,
                &[coinbase("A", 1000)],
                &mut bal,
                &mut recent,
            )
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
            assert!(
                r.is_err(),
                "spending the fresh coinbase in its own block must be rejected"
            );
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
            assert!(
                r.is_ok(),
                "below activation, an immediate reward spend must still be allowed"
            );
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
        assert_eq!(
            replay_immature, scanned,
            "scan and replay must agree on the immature total"
        );
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
        assert_eq!(
            breakdown.confirmed, 17.0,
            "confirmed includes immature coinbases"
        );
        assert_eq!(
            breakdown.spendable, 5.0,
            "spendable excludes the maturing portion"
        );
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
        assert_eq!(
            after.spendable, 10.0,
            "the just-matured reward becomes spendable"
        );
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
        assert!(
            breakdown.maturing.is_empty(),
            "overlay is a no-op below activation"
        );
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
        assert!(
            fixed.is_ok(),
            "reusing the held write guard must not deadlock"
        );

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
                .mine_block(
                    &mut h,
                    &ta,
                    1u64 << 26,
                    "miner_a".to_string(),
                    false,
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                )
                .await
        });
        let task_b = tokio::spawn(async move {
            let mut h = hb;
            mgr_b
                .mine_block(
                    &mut h,
                    &tb,
                    1u64 << 26,
                    "miner_b".to_string(),
                    false,
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                )
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
        // have mined a block. (mine_block now selects from the LIVE mempool on
        // every template rebuild — the tx snapshot argument is ignored — so the
        // tx reaches the template via add_transaction above, and the loser drops
        // the now-confirmed tx on its next rebuild instead of re-mining it.)
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
                .mine_block(
                    &mut h,
                    &txs_a,
                    1u64 << 26,
                    "miner_a".to_string(),
                    false,
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                )
                .await
        });
        let task_b = tokio::spawn(async move {
            let mut h = hb;
            mgr_b
                .mine_block(
                    &mut h,
                    &txs_b,
                    1u64 << 26,
                    "miner_b".to_string(),
                    false,
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                )
                .await
        });

        let joined = tokio::time::timeout(Duration::from_secs(240), async {
            tokio::try_join!(task_a, task_b)
        })
        .await
        .expect("neither miner may hang: the loser must recover from the lost race")
        .expect("mining tasks should not panic");

        assert!(
            joined.0.is_ok(),
            "miner A should complete: {:?}",
            joined.0.err()
        );
        assert!(
            joined.1.is_ok(),
            "miner B should complete: {:?}",
            joined.1.err()
        );
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

    // P0 regression: a WARM signature_cache must not let a tx skip its sig_hash bind. sig_hash is
    // merkle-committed, so a variant carrying the same signature but a forged sig_hash would
    // otherwise be accepted by a warm node and rejected by a cold one (frontier-path divergence).
    #[tokio::test]
    async fn warm_signature_cache_does_not_skip_sig_hash_bind() {
        let bc = test_blockchain();
        let wallet = Wallet::new(None).expect("wallet builds");
        let ts = 1_700_000_000u64;

        // Genuine tx with a correct (bound) sig_hash — verifying it WARMS the cache.
        let mut genuine = signed_transfer(&wallet, "recipient_addr_for_test", 10.0, ts).await;
        let sig_bytes = hex::decode(genuine.signature.as_ref().unwrap()).unwrap();
        genuine.sig_hash = Some(Transaction::signature_hash_hex(&sig_bytes));
        assert!(
            bc.verify_transaction_signature(&genuine).is_ok(),
            "the genuine tx must verify and warm the cache"
        );

        // Variant: identical core fields + pub_key + signature (so same tx_id + actual_hash ->
        // COLLIDES with the warmed cache key) but a FORGED, merkle-committed sig_hash.
        let mut forged = genuine.clone();
        forged.sig_hash = Some("deadbeef".repeat(8)); // 64 hex chars, != SHA256(signature)

        // PIN the warm-path precondition so the test can't silently rot: get_tx_id excludes
        // sig_hash, so genuine and forged must share a tx_id, AND the genuine verify must have
        // actually warmed the cache under the current key (forged looks up that same key). If a
        // future cache-key redesign moves forged to the COLD path, these asserts fire loudly
        // instead of the test passing while no longer exercising the warm-skip scenario.
        assert_eq!(
            genuine.get_tx_id(),
            forged.get_tx_id(),
            "genuine and forged must collide on tx_id to exercise the warm path"
        );
        let warmed_key = format!(
            "{}:{}:{}",
            genuine.get_tx_id(),
            Transaction::signature_hash_hex(genuine.pub_key.as_ref().unwrap().as_bytes()),
            Transaction::signature_hash_hex(&sig_bytes)
        );
        assert!(
            bc.signature_cache.lock().get(&warmed_key).is_some(),
            "the genuine verify must have warmed the cache under the key forged collides with"
        );

        // THE POINT: forged sig_hash rejected even though the cache is warm for the genuine tx.
        assert!(
            bc.verify_transaction_signature(&forged).is_err(),
            "a forged sig_hash must be rejected even when the cache is warm for the genuine tx"
        );

        // Happy-path guard: the reorder must NOT false-reject a legit tx on a WARM cache.
        assert!(
            bc.verify_transaction_signature(&genuine).is_ok(),
            "the genuine tx must still verify from a warm cache after the reorder"
        );

        // A tx with NO claimed sig_hash must still verify (the new `if let Some` guard skips None).
        let mut no_hash = signed_transfer(&wallet, "recipient_addr_for_test", 11.0, ts).await;
        no_hash.sig_hash = None;
        assert!(
            bc.verify_transaction_signature(&no_hash).is_ok(),
            "a tx without a claimed sig_hash must still verify"
        );
    }

    // Consensus property behind the miner's parent-timestamp clamp (miner::candidate_timestamp):
    // a child clamped UP to a future-dated parent is valid under the UNCHANGED rules, so old and
    // new binaries agree on it. Proves (a) the validator's difficulty (adjust_dynamic_difficulty)
    // equals the miner's (consensus_next_difficulty) for the clamped delta=0 — they must, since the
    // former delegates to the latter — and (b) validate_parent_timestamp accepts child==parent but
    // still rejects the pre-clamp child<parent (the wasted-grind bug the clamp removes).
    #[test]
    fn clamped_child_is_consensus_valid_against_future_dated_parent() {
        for parent_diff in [NETWORK_MIN_DIFFICULTY, 500, 10_000, MAX_NETWORK_DIFFICULTY] {
            assert_eq!(
                Block::adjust_dynamic_difficulty(
                    parent_diff,
                    0, // clamped delta: now < parent -> timestamp == parent -> diff input 0
                    9,
                    &mut DifficultyOracle::new(),
                    1_000_000,
                ),
                Block::consensus_next_difficulty(parent_diff, 0, 9),
                "validator and miner difficulty must agree for the clamped delta=0"
            );
        }

        let mut parent = metadata_test_block(5, [0u8; 32], "miner", 1.0);
        parent.timestamp = 2_000_000; // future-dated but valid parent
        let mut child = metadata_test_block(6, parent.hash, "miner", 1.0);

        // Clamped child (== parent): the exact block a behind-clock miner now produces — accepted.
        child.timestamp = parent.timestamp;
        assert!(
            Blockchain::validate_parent_timestamp(&child, &parent).is_ok(),
            "a child clamped to == its parent must be accepted (equal timestamps are valid)"
        );
        // Pre-clamp child (< parent): still rejected — this is the wasted-grind the clamp avoids.
        child.timestamp = parent.timestamp - 1;
        assert!(
            Blockchain::validate_parent_timestamp(&child, &parent).is_err(),
            "a child below its parent must be rejected (why the miner clamps)"
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
            .collect_orphan_branches_from(std::sync::Arc::new(start), 8, ORPHAN_BRANCH_SEARCH_LIMIT)
            .unwrap();

        assert!(branches.iter().any(|branch| branch.len() == 2));
        assert!(branches.iter().any(|branch| branch.len() == 3));
    }

    // Bound 4 (H1): store_orphan_block admits an orphan up to tip + ORPHAN_REORG_DEPTH (the highest
    // index any adoptable branch can reach) but rejects one above it — a provably-unreachable
    // height that un-upgraded peers bound identically, so this cannot diverge the canonical chain.
    #[tokio::test]
    async fn above_tip_orphan_admission_boundary() {
        let bc = test_blockchain();
        let b0 = metadata_test_block(0, [0u8; 32], "m0", 1.0);
        let b1 = metadata_test_block(1, b0.hash, "m1", 1.0);
        let b2 = metadata_test_block(2, b1.hash, "m2", 1.0);
        for b in [&b0, &b1, &b2] {
            insert_raw_block(&bc, b);
        }
        bc.rebuild_chain_tip_metadata().unwrap();
        assert_eq!(bc.highest_block_index(), Some(2));
        let tip = 2u32;

        let at_bound = metadata_test_block(tip + ORPHAN_REORG_DEPTH, [7u8; 32], "at", 1.0);
        let above = metadata_test_block(tip + ORPHAN_REORG_DEPTH + 1, [8u8; 32], "above", 1.0);
        bc.store_orphan_block(&at_bound).unwrap();
        bc.store_orphan_block(&above).unwrap();

        let orphans = bc.open_orphan_blocks_tree().unwrap();
        assert!(
            orphans
                .get(Blockchain::orphan_hash_key(&at_bound.hash).as_bytes())
                .unwrap()
                .is_some(),
            "orphan at exactly tip + ORPHAN_REORG_DEPTH is admitted (still reachable)"
        );
        assert!(
            orphans
                .get(Blockchain::orphan_hash_key(&above.hash).as_bytes())
                .unwrap()
                .is_none(),
            "orphan above tip + ORPHAN_REORG_DEPTH is rejected (provably unreachable)"
        );

        // A below-tip orphan is a legitimate reorg competitor and must still be admitted — the
        // guard only rejects FAR-above-tip blocks, never same-height/below forks.
        let below = metadata_test_block(1, [9u8; 32], "below", 1.0);
        bc.store_orphan_block(&below).unwrap();
        assert!(
            orphans
                .get(Blockchain::orphan_hash_key(&below.hash).as_bytes())
                .unwrap()
                .is_some(),
            "a below-tip orphan (a valid reorg competitor) is still admitted"
        );
    }

    // Bound 2 (H1): the Arc<Block> enumeration must return the SAME branch set as the former
    // body-clone version — no branch dropped by the memory-representation change. A fanout of N
    // children yields exactly N branches; a grandchild extends one of them.
    #[tokio::test]
    async fn orphan_enumeration_preserves_all_branches_under_fanout() {
        let bc = test_blockchain();
        let root = metadata_test_block(1, [0u8; 32], "root", 1.0);
        let mut kids = Vec::new();
        for i in 0..5u32 {
            let k = metadata_test_block(2, root.hash, &format!("k{}", i), 1.0);
            bc.store_orphan_block(&k).unwrap();
            kids.push(k);
        }
        // One child also has a grandchild — a length-3 branch.
        let gc = metadata_test_block(3, kids[0].hash, "gc", 1.0);
        bc.store_orphan_block(&gc).unwrap();

        let branches = bc
            .collect_orphan_branches_from(
                std::sync::Arc::new(root),
                ORPHAN_REORG_DEPTH as usize,
                ORPHAN_BRANCH_SEARCH_LIMIT,
            )
            .unwrap();

        assert_eq!(
            branches.len(),
            5,
            "every fanout child yields a branch (none dropped)"
        );
        assert_eq!(
            branches.iter().filter(|b| b.len() == 3).count(),
            1,
            "exactly the grandchild branch reaches length 3"
        );
        assert_eq!(branches.iter().filter(|b| b.len() == 2).count(), 4);
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

    // #5: a confirmed tx lives in BOTH the in-memory mempool and the sled pending tree
    // (add_transaction writes both), so drop_confirmed_mempool_txs' stale+tree_stale union lists it
    // twice. clear_processed_transactions subtracts the pending debit per occurrence, so without the
    // tx_id dedup the double-subtract saturates the sender's reservation to 0 and wipes the debit
    // still held by their OTHER pending tx. This asserts the surviving reservation.
    #[tokio::test]
    async fn drop_confirmed_dedups_debit_across_memory_and_sled() {
        let bc = test_blockchain();
        let wallet = Wallet::new(None).expect("test wallet should build");
        // Asymmetric amounts (delta_a < delta_b) so the pre-fix double-subtract lands on a specific
        // non-saturated value (delta_b - delta_a), not merely the saturating floor of 0 — the debit
        // assertion then pins "cleared exactly once" precisely.
        let tx_a = signed_transfer(&wallet, "bob", 1.0, 20_001).await;
        let tx_b = signed_transfer(&wallet, "carol", 2.0, 20_002).await;
        let delta_a = tx_a.total_debit_units();
        let delta_b = tx_b.total_debit_units();

        // Fund both so both admit; pending_debit becomes delta_a + delta_b.
        set_confirmed_balance(&bc, &wallet.address, delta_a + delta_b);
        bc.add_transaction(tx_a.clone())
            .await
            .expect("tx_a admitted");
        bc.add_transaction(tx_b.clone())
            .await
            .expect("tx_b admitted");
        assert_eq!(
            bc.get_pending_debit_units(&wallet.address).await.unwrap(),
            delta_a + delta_b,
            "both pending txs reserve their debit"
        );

        // Mark ONLY tx_a confirmed (it is in both the mempool and the sled tree); tx_b stays pending.
        let confirmed = bc.open_confirmed_tx_tree().expect("confirmed tx tree");
        confirmed
            .insert(tx_a.get_tx_id().as_bytes(), 0u32.to_le_bytes().to_vec())
            .expect("mark tx_a confirmed");

        let dropped = bc.drop_confirmed_mempool_txs().await;
        assert_eq!(
            dropped, 1,
            "exactly one DISTINCT confirmed tx is dropped (the union is deduped, not double-counted)"
        );

        // tx_b's reservation must survive. Without the dedup tx_a's debit is subtracted twice, so
        // pending_debit reads (delta_a + delta_b) - 2*delta_a = delta_b - delta_a (< delta_b) instead.
        assert_eq!(
            bc.get_pending_debit_units(&wallet.address).await.unwrap(),
            delta_b,
            "only tx_a's debit is cleared; tx_b's reservation is preserved"
        );
    }

    // #11: clear_processed_transactions also removes pending credit reservations, preventing
    // already-spent income entries from remaining available after a tx is confirmed.
    #[tokio::test]
    async fn clear_processed_transactions_clears_pending_credits() {
        let bc = test_blockchain();
        let sender = Wallet::new(None).expect("sender wallet should build");
        let recipient = Wallet::new(None).expect("recipient wallet should build");

        let tx = signed_transfer(&sender, &recipient.address, 1.75, 10_000).await;
        set_confirmed_balance(&bc, &sender.address, tx.total_debit_units());
        bc.add_transaction(tx.clone()).await.expect("tx admitted");

        assert_eq!(
            bc.get_pending_debit_units(&sender.address)
                .await
                .expect("pending debit should read"),
            tx.total_debit_units()
        );
        assert_eq!(
            bc.get_pending_credit_units(&recipient.address)
                .await
                .expect("pending credit should read"),
            tx.amount_units
        );

        bc.clear_processed_transactions(std::slice::from_ref(&tx))
            .await
            .expect("confirmed tx should clear pending reservations");

        assert_eq!(
            bc.get_pending_debit_units(&sender.address)
                .await
                .expect("pending debit should clear"),
            0
        );
        assert_eq!(
            bc.get_pending_credit_units(&recipient.address)
                .await
                .expect("pending credit should clear"),
            0
        );
    }

    // #10: the re-announce accessor must return FULL-signature txs. The persisted pending record
    // carries a truncated signature (the full one is in the sidecar); gossiping the truncated form
    // makes peers defer the tx (the truncated-witness pathology).
    #[tokio::test]
    async fn reannounce_accessor_returns_full_signatures() {
        let bc = test_blockchain();
        let wallet = Wallet::new(None).expect("test wallet should build");
        // A fresh timestamp: sync_mempool_with_sled prunes pending rows older than the TTL.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let tx = signed_transfer(&wallet, "bob", 1.0, now).await;
        let full_sig_len = hex::decode(tx.signature.as_ref().unwrap()).unwrap().len();
        assert!(
            full_sig_len > 64,
            "the created tx carries a full ML-DSA signature"
        );
        set_confirmed_balance(&bc, &wallet.address, tx.total_debit_units());
        bc.add_transaction(tx.clone()).await.expect("tx admitted");

        // get_pending_transactions reads the SLED record -> TRUNCATED signature.
        let sled_pending = bc.get_pending_transactions().await.unwrap();
        assert_eq!(sled_pending.len(), 1);
        let sled_sig = hex::decode(sled_pending[0].signature.as_ref().unwrap()).unwrap();
        assert!(
            sled_sig.len() <= 64,
            "sled pending record carries a truncated signature"
        );

        // The re-announce accessor rehydrates the FULL signature from the sidecar.
        let full_pending = bc
            .get_pending_transactions_with_full_signatures()
            .await
            .unwrap();
        assert_eq!(full_pending.len(), 1);
        assert_eq!(full_pending[0].get_tx_id(), sled_pending[0].get_tx_id());
        let full_sig = hex::decode(full_pending[0].signature.as_ref().unwrap()).unwrap();
        assert_eq!(
            full_sig.len(),
            full_sig_len,
            "re-announce accessor must carry the FULL signature, not the truncated one"
        );
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

    // #8: on a chain with no NON-system transactions the confirmed-tx replay registry is
    // legitimately empty, which pre-fix was indistinguishable from "never built" — so
    // ensure_confirmed_tx_index re-derived the whole chain (O(chain)) on every startup. The
    // completion marker must be stamped anyway, and a second ensure must short-circuit.
    #[test]
    fn ensure_confirmed_tx_index_marks_built_on_tx_free_chain() {
        let bc = test_blockchain();
        // Coinbase-only (MINING_REWARDS = system) block -> no indexable txs -> empty prune index.
        let b0 = metadata_test_block(0, [0u8; 32], "miner", 1.0);
        insert_raw_block(&bc, &b0);

        // First ensure builds (empty) and stamps the completion marker.
        bc.ensure_confirmed_tx_index().expect("ensure builds");
        let meta = bc.open_chain_meta_tree().expect("meta tree");
        assert!(
            meta.get(CONFIRMED_TX_BUILT_KEY).unwrap().is_some(),
            "completion marker is stamped even with no indexable txs"
        );
        let index = bc.db.open_tree(CONFIRMED_TX_TS_INDEX).unwrap();
        assert!(
            index.iter().next().is_none(),
            "no non-system txs -> the prune index is legitimately empty"
        );

        // Prove the marker short-circuits: seed a sentinel into the confirmed-tx TREE (index still
        // empty) and call ensure again. A rebuild would clear it — that O(chain) re-derive on every
        // startup is exactly what this fix removes.
        let tree = bc.open_confirmed_tx_tree().unwrap();
        tree.insert(b"sentinel_txid", vec![0u8; 4]).unwrap();
        bc.ensure_confirmed_tx_index()
            .expect("ensure short-circuits");
        assert!(
            tree.get(b"sentinel_txid").unwrap().is_some(),
            "marker short-circuits ensure; the registry is not re-derived (pre-fix would clear it)"
        );
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

    // T1 (H4): live reconcile discards a marker-AHEAD poison — the state a finalize leaves when it
    // advances the balances marker + credits the coinbase but then fails before storing its block —
    // crediting the coinbase EXACTLY once. This is the core no-double-coinbase / no-self-fork check.
    #[tokio::test]
    async fn reconcile_heals_marker_ahead_poison_no_double_coinbase() {
        let bc = test_blockchain();
        let block0 = metadata_test_block(0, [0u8; 32], "miner0", 5.0);
        let block1 = metadata_test_block(1, block0.hash, "minerx", 5.0);
        insert_raw_block(&bc, &block0);
        insert_raw_block(&bc, &block1);
        bc.write_chain_tip_metadata(&block1).unwrap();
        bc.ensure_balances_index().await.unwrap();
        assert_eq!(bc.get_confirmed_balance("minerx").await.unwrap(), 5.0);

        // Stage the poison of a half-committed finalize of a phantom block 2: advance the marker to
        // 2 and credit minerx a SECOND coinbase (as process_transactions_batch would), but never
        // store block 2 (tip stays 1). Mark dirty, exactly as the failed finalize would have.
        let balances = bc.db.open_tree(BALANCES_TREE).unwrap();
        balances
            .insert(
                "minerx".as_bytes(),
                codec::serialize(&Transaction::to_units(10.0)).unwrap(),
            )
            .unwrap();
        Blockchain::set_balances_height(&balances, 2).unwrap();
        bc.mark_chain_state_dirty(2, "finalize_block").unwrap();

        bc.reconcile_chain_state_if_dirty().await.unwrap();

        assert_eq!(bc.chain_state_dirty().unwrap(), None, "marker cleared");
        let balances = bc.db.open_tree(BALANCES_TREE).unwrap();
        assert_eq!(
            Blockchain::get_balances_height(&balances).unwrap(),
            Some(1),
            "marker re-anchored to the true tip"
        );
        assert_eq!(bc.get_latest_block_index(), 1, "tip unchanged");
        assert_eq!(
            bc.get_confirmed_balance("minerx").await.unwrap(),
            5.0,
            "phantom second coinbase erased; credited exactly once"
        );
    }

    // T2 (M1, DECISIVE): recovery must re-anchor the tip (rebuild_chain_tip_metadata FIRST) before
    // rebuilding balances. A reorg that failed after rewriting canonical slots to a TALLER branch B
    // (but before write_chain_tip_metadata) leaves chain_tip_cache holding the OLD height; without
    // the tip re-anchor the balance rebuild would cover [0..=old_tip] and miss B's top block. This
    // test fails if rebuild_chain_tip_metadata is ever dropped from recover_dirty_chain_state.
    #[tokio::test]
    async fn reconcile_reanchors_tip_before_rebuilding_balances_after_failed_reorg() {
        let bc = test_blockchain();
        // Chain A: 0..=3.
        let a0 = metadata_test_block(0, [0u8; 32], "m0", 5.0);
        let a1 = metadata_test_block(1, a0.hash, "m1", 5.0);
        let a2 = metadata_test_block(2, a1.hash, "m2a", 5.0);
        let a3 = metadata_test_block(3, a2.hash, "m3a", 5.0);
        for b in [&a0, &a1, &a2, &a3] {
            insert_raw_block(&bc, b);
        }
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.ensure_balances_index().await.unwrap();
        // Populate chain_tip_cache at height 3 — the stale value recovery must invalidate.
        assert_eq!(bc.highest_block_index(), Some(3));

        // Simulate a reorg to a TALLER branch B forking at 2 that FAILED after the slot rewrite:
        // overwrite block_2/block_3 and add block_4 on B (insert_raw_block does NOT invalidate the
        // cache); balances + marker still reflect A (marker=3). Mark dirty as the failed reorg would.
        let b2 = metadata_test_block(2, a1.hash, "m2b", 5.0);
        let b3 = metadata_test_block(3, b2.hash, "m3b", 5.0);
        let b4 = metadata_test_block(4, b3.hash, "m4b", 5.0);
        for b in [&b2, &b3, &b4] {
            insert_raw_block(&bc, b);
        }
        bc.mark_chain_state_dirty(2, "orphan_branch_reorg").unwrap();

        bc.reconcile_chain_state_if_dirty().await.unwrap();

        assert_eq!(bc.chain_state_dirty().unwrap(), None);
        assert_eq!(
            bc.get_latest_block_index(),
            4,
            "tip re-anchored to the taller branch B"
        );
        let balances = bc.db.open_tree(BALANCES_TREE).unwrap();
        assert_eq!(Blockchain::get_balances_height(&balances).unwrap(), Some(4));
        assert_eq!(
            bc.get_confirmed_balance("m4b").await.unwrap(),
            5.0,
            "B4's coinbase is credited (tip was re-anchored past the stale height 3)"
        );
        assert_eq!(
            bc.get_confirmed_balance("m3a").await.unwrap(),
            0.0,
            "A3's reverted coinbase is gone (block_3 was overwritten by B3)"
        );
    }

    // T5: live reconcile produces the SAME state as a full initialize() over the same staged-dirty
    // DB — the property that lets startup and live recovery share one code path.
    #[tokio::test]
    async fn live_reconcile_matches_initialize_recovery() {
        let stage = |bc: &Blockchain| {
            let b0 = metadata_test_block(0, [0u8; 32], "m0", 5.0);
            let b1 = metadata_test_block(1, b0.hash, "m1", 5.0);
            insert_raw_block(bc, &b0);
            insert_raw_block(bc, &b1);
            bc.write_chain_tip_metadata(&b1).unwrap();
            let balances = bc.db.open_tree(BALANCES_TREE).unwrap();
            // marker-ahead poison identical to T1.
            balances
                .insert(
                    "m1".as_bytes(),
                    codec::serialize(&Transaction::to_units(10.0)).unwrap(),
                )
                .unwrap();
            Blockchain::set_balances_height(&balances, 2).unwrap();
            bc.mark_chain_state_dirty(2, "finalize_block").unwrap();
        };

        let live = test_blockchain();
        stage(&live);
        live.reconcile_chain_state_if_dirty().await.unwrap();

        let boot = test_blockchain();
        stage(&boot);
        boot.initialize().await.unwrap();

        assert_eq!(dump_balances(&live), dump_balances(&boot), "same balances");
        assert_eq!(live.get_latest_block_index(), boot.get_latest_block_index());
        assert_eq!(live.chain_state_dirty().unwrap(), None);
        assert_eq!(boot.chain_state_dirty().unwrap(), None);
    }

    // T6: reconcile on an already-consistent DB is a no-op — no marker, balances unchanged, and
    // running it twice back-to-back changes nothing (idempotent).
    #[tokio::test]
    async fn reconcile_is_noop_when_clean() {
        let bc = test_blockchain();
        let b0 = metadata_test_block(0, [0u8; 32], "m0", 5.0);
        let b1 = metadata_test_block(1, b0.hash, "m1", 5.0);
        insert_raw_block(&bc, &b0);
        insert_raw_block(&bc, &b1);
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.ensure_balances_index().await.unwrap();

        assert_eq!(bc.chain_state_dirty().unwrap(), None, "clean to start");
        let before = dump_balances(&bc);
        bc.reconcile_chain_state_if_dirty().await.unwrap();
        bc.reconcile_chain_state_if_dirty().await.unwrap();
        assert_eq!(
            dump_balances(&bc),
            before,
            "clean reconcile changes nothing"
        );
        assert_eq!(bc.chain_state_dirty().unwrap(), None);
        // The healthy invariant: marker never ahead of the tip once clean.
        let balances = bc.db.open_tree(BALANCES_TREE).unwrap();
        assert!(
            Blockchain::get_balances_height(&balances)
                .unwrap()
                .unwrap_or(0)
                <= bc.get_latest_block_index()
        );
    }

    // WIRING (H4): finalize_block must run its reconcile BEFORE the tip check / balance prefetch /
    // apply. Unlike the isolated T1/T5 tests, this drives the REAL entry point, so it FAILS if
    // finalize's reconcile insert is ever deleted (the marker would stay Some(2)). finalize may
    // reject the diff-0 retry block AFTER reconciling — that failure is intentionally ignored; the
    // assertion is on the reconcile's effect.
    #[tokio::test]
    async fn finalize_reconciles_marker_ahead_poison_before_apply() {
        let bc = test_blockchain();
        let block0 = metadata_test_block(0, [0u8; 32], "miner0", 5.0);
        let block1 = metadata_test_block(1, block0.hash, "minerx", 5.0);
        insert_raw_block(&bc, &block0);
        insert_raw_block(&bc, &block1);
        bc.write_chain_tip_metadata(&block1).unwrap();
        bc.ensure_balances_index().await.unwrap();

        // The H4 poison a failed finalize leaves: marker ahead + coinbase double-credited, unstored.
        let balances = bc.db.open_tree(BALANCES_TREE).unwrap();
        balances
            .insert(
                "minerx".as_bytes(),
                codec::serialize(&Transaction::to_units(10.0)).unwrap(),
            )
            .unwrap();
        Blockchain::set_balances_height(&balances, 2).unwrap();
        bc.mark_chain_state_dirty(2, "finalize_block").unwrap();

        // Drive the real entry point; its reconcile must heal before it touches balances.
        let retry = metadata_test_block(2, block1.hash, "minery", 5.0);
        let _ = bc.finalize_block(retry, "minery".to_string()).await;

        assert_eq!(
            bc.chain_state_dirty().unwrap(),
            None,
            "finalize healed the marker"
        );
        assert_eq!(
            bc.get_confirmed_balance("minerx").await.unwrap(),
            5.0,
            "phantom second coinbase erased by finalize's reconcile — credited once"
        );
    }

    // WIRING (M1): try_adopt_orphan_branch must run its reconcile BEFORE it reads the tip / scores
    // branches. Drives the real reorg entry point, so it FAILS if try_adopt's reconcile insert is
    // deleted (the tip would stay at the stale cached height 1). The orphan pool is empty, so the
    // adoption itself is a no-op; the assertion is on the reconcile re-anchoring the tip.
    #[tokio::test]
    async fn try_adopt_reconciles_before_branch_selection() {
        let bc = test_blockchain();
        let a0 = metadata_test_block(0, [0u8; 32], "m0", 5.0);
        let a1 = metadata_test_block(1, a0.hash, "m1", 5.0);
        insert_raw_block(&bc, &a0);
        insert_raw_block(&bc, &a1);
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.ensure_balances_index().await.unwrap();
        assert_eq!(bc.highest_block_index(), Some(1)); // populate the stale cache

        // A failed reorg left a TALLER branch B's slots written but balances/marker on old chain A.
        let b1 = metadata_test_block(1, a0.hash, "m1b", 5.0);
        let b2 = metadata_test_block(2, b1.hash, "m2b", 5.0);
        insert_raw_block(&bc, &b1);
        insert_raw_block(&bc, &b2);
        bc.mark_chain_state_dirty(1, "orphan_branch_reorg").unwrap();

        let _ = bc.try_adopt_orphan_branch().await;

        assert_eq!(
            bc.chain_state_dirty().unwrap(),
            None,
            "try_adopt healed the marker"
        );
        assert_eq!(
            bc.get_latest_block_index(),
            2,
            "try_adopt's reconcile re-anchored the tip to the taller branch before selection"
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
            .insert(
                "zz_sentinel".as_bytes(),
                codec::serialize(&777i128).unwrap(),
            )
            .unwrap();
        for b in &chain[4..] {
            insert_raw_block(&a, b);
        }
        a.rebuild_chain_tip_metadata().unwrap();
        a.ensure_balances_index().await.unwrap();
        assert_eq!(Blockchain::get_balances_height(&a_tree).unwrap(), Some(8));
        assert_eq!(
            a_tree
                .get("zz_sentinel".as_bytes())
                .unwrap()
                .map(|v| v.to_vec()),
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

    /// replay_revert_block must be the exact arithmetic inverse of
    /// replay_apply_block_checked over raw totals: applying a set of blocks and
    /// then reverting them (in any order) returns every touched address to its
    /// starting value.
    #[test]
    fn replay_revert_is_exact_inverse_of_apply() {
        let mut prev = [0u8; 32];
        let mut blocks = Vec::new();
        for (i, miner) in [(0u32, "alice"), (1, "bob")] {
            let b = metadata_test_block(i, prev, miner, 10.0);
            prev = b.hash;
            blocks.push(b);
        }
        let b2 = test_block_with_txs(2, prev, "carol", 10.0, &[("alice", "dave", 3.0)]);
        prev = b2.hash;
        blocks.push(b2);
        let b3 = test_block_with_txs(
            3,
            prev,
            "alice",
            10.0,
            &[("dave", "erin", 1.0), ("bob", "alice", 2.5)],
        );
        blocks.push(b3);

        let mut balances: HashMap<String, i128> = HashMap::new();
        let mut recent: std::collections::VecDeque<(u32, String, i128)> =
            std::collections::VecDeque::new();
        for b in &blocks {
            Blockchain::replay_apply_block_checked(
                b.index,
                &b.transactions,
                &mut balances,
                &mut recent,
            )
            .unwrap();
        }
        // Revert in forward order on purpose: the inverse must be
        // order-independent (additive sums), not just LIFO-correct.
        for b in &blocks {
            Blockchain::replay_revert_block(&b.transactions, &mut balances);
        }
        for (addr, v) in &balances {
            assert_eq!(
                *v, 0,
                "address {addr} did not return to its pre-apply value"
            );
        }
    }

    /// The O(reorg span) fast path (balances_at_fork_state -> revert write-back
    /// -> catch_up over the new branch) must land the SAME values as a fresh
    /// from-genesis build of the post-reorg chain. Mirrors
    /// try_adopt_orphan_branch's exact sequence at the storage level. The
    /// sentinel proves no full rebuild ran (a rebuild removes unknown keys;
    /// the incremental path never removes).
    #[tokio::test]
    async fn reorg_incremental_balances_match_full_rebuild() {
        // Old canonical chain 0..=6; fork at 4. dave/erin exist ONLY on the
        // reverted span (their values must return to zero), alice is funded
        // pre-fork and spends on both sides.
        let mut prev = [0u8; 32];
        let mut base = Vec::new();
        for (i, miner) in [(0u32, "alice"), (1, "bob"), (2, "alice"), (3, "carol")] {
            let b = metadata_test_block(i, prev, miner, 10.0);
            prev = b.hash;
            base.push(b);
        }
        let fork_prev = prev;
        let old4 = test_block_with_txs(4, prev, "miner4", 10.0, &[("alice", "dave", 3.0)]);
        prev = old4.hash;
        let old5 = test_block_with_txs(5, prev, "miner5", 10.0, &[("dave", "erin", 1.0)]);
        prev = old5.hash;
        let old6 = metadata_test_block(6, prev, "bob", 10.0);
        let old_branch = vec![old4, old5, old6];

        let mut prev = fork_prev;
        let new4 = test_block_with_txs(4, prev, "nb4", 10.0, &[("alice", "bob", 2.0)]);
        prev = new4.hash;
        let new5 = metadata_test_block(5, prev, "nb5", 10.0);
        prev = new5.hash;
        let new6 = test_block_with_txs(6, prev, "nb6", 10.0, &[("bob", "grace", 5.0)]);
        prev = new6.hash;
        let new7 = metadata_test_block(7, prev, "nb7", 10.0);
        let new_branch = vec![new4, new5, new6, new7];

        // Instance A: old chain indexed at its tip, then the try_adopt sequence.
        let a = test_blockchain();
        for b in base.iter().chain(old_branch.iter()) {
            insert_raw_block(&a, b);
        }
        a.rebuild_chain_tip_metadata().unwrap();
        a.ensure_balances_index().await.unwrap();
        let a_tree = a.db.open_tree(BALANCES_TREE).unwrap();
        assert_eq!(Blockchain::get_balances_height(&a_tree).unwrap(), Some(6));
        a_tree
            .insert(
                "zz_sentinel".as_bytes(),
                codec::serialize(&777i128).unwrap(),
            )
            .unwrap();

        let fork_state = a
            .balances_at_fork_state(&a_tree, 4, 6, &new_branch)
            .unwrap()
            .expect("marker vouches for the tip — fast path must engage");
        // Dry-run the branch from the fork state (the balance_valid check).
        {
            let (mut balances, mut recent) = fork_state.clone();
            for b in &new_branch {
                Blockchain::replay_apply_block_checked(
                    b.index,
                    &b.transactions,
                    &mut balances,
                    &mut recent,
                )
                .expect("valid branch must dry-run cleanly from the fork state");
            }
        }
        // Slot rewrite, then the atomic revert write-back + marker, then catch-up
        // over the new branch — exactly try_adopt_orphan_branch's update.
        for b in &new_branch {
            insert_raw_block(&a, b);
        }
        a.rebuild_chain_tip_metadata().unwrap();
        let (reverted, _) = fork_state;
        let mut batch = sled::Batch::default();
        for (addr, bal) in &reverted {
            batch.insert(addr.as_bytes(), codec::serialize(bal).unwrap());
        }
        batch.insert(BALANCES_HEIGHT_KEY, codec::serialize(&3u64).unwrap());
        a_tree.apply_batch(batch).unwrap();
        a.catch_up_balances_index(&a_tree, 3, 7).await.unwrap();
        assert_eq!(Blockchain::get_balances_height(&a_tree).unwrap(), Some(7));
        assert!(
            a_tree.get("zz_sentinel".as_bytes()).unwrap().is_some(),
            "incremental path must have run (a full rebuild removes the sentinel)"
        );

        // Instance B: the post-reorg chain built fresh from genesis.
        let b_chain = test_blockchain();
        for b in base.iter().chain(new_branch.iter()) {
            insert_raw_block(&b_chain, b);
        }
        b_chain.rebuild_chain_tip_metadata().unwrap();
        b_chain.ensure_balances_index().await.unwrap();

        // Value identity over the union of addresses (absent == 0): reverted-
        // span-only addresses (dave, erin, miner4, miner5) may remain as
        // explicit zeros on the incremental side, matching catch-up semantics.
        let mut a_vals = dump_balances(&a);
        a_vals.remove("zz_sentinel");
        let b_vals = dump_balances(&b_chain);
        let keys: std::collections::BTreeSet<String> =
            a_vals.keys().chain(b_vals.keys()).cloned().collect();
        for k in keys {
            assert_eq!(
                a_vals.get(&k).copied().unwrap_or(0),
                b_vals.get(&k).copied().unwrap_or(0),
                "address {k} diverged between incremental reorg and full rebuild"
            );
        }
        for gone in ["dave", "erin", "miner4", "miner5"] {
            assert_eq!(
                a_vals.get(gone).copied().unwrap_or(0),
                0,
                "reverted-branch-only address {gone} must return to zero"
            );
        }
    }

    /// A lagging marker must disable the fast path (balances_at_fork_state ->
    /// None) so the reorg falls back to the authoritative full rebuild instead
    /// of reverting blocks the index never applied.
    #[tokio::test]
    async fn reorg_fast_path_requires_marker_at_tip() {
        let mut prev = [0u8; 32];
        let mut chain = Vec::new();
        for i in 0..=5u32 {
            let b = metadata_test_block(i, prev, &format!("m{i}"), 10.0);
            prev = b.hash;
            chain.push(b);
        }
        let bc = test_blockchain();
        for b in &chain {
            insert_raw_block(&bc, b);
        }
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.ensure_balances_index().await.unwrap();
        let tree = bc.db.open_tree(BALANCES_TREE).unwrap();
        assert_eq!(Blockchain::get_balances_height(&tree).unwrap(), Some(5));

        // Marker at tip: fast path engages.
        assert!(bc
            .balances_at_fork_state(&tree, 4, 5, &[])
            .unwrap()
            .is_some());
        // Lagging marker: fast path must refuse.
        Blockchain::set_balances_height(&tree, 4).unwrap();
        assert!(bc
            .balances_at_fork_state(&tree, 4, 5, &[])
            .unwrap()
            .is_none());
        // Genesis fork or inverted span: refuse.
        Blockchain::set_balances_height(&tree, 5).unwrap();
        assert!(bc
            .balances_at_fork_state(&tree, 0, 5, &[])
            .unwrap()
            .is_none());
        assert!(bc
            .balances_at_fork_state(&tree, 6, 5, &[])
            .unwrap()
            .is_none());
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
            .insert(
                "zz_sentinel".as_bytes(),
                codec::serialize(&777i128).unwrap(),
            )
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
        bc.mark_chain_state_dirty(2, "test_writer_in_flight")
            .unwrap();
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

    // H3 regression: an over-full block (more than MAX_BLOCK_TX_COUNT transactions) must be
    // rejected with a DISTINCT error, never one that stringifies like a lost race. Otherwise
    // the continuous miner mistakes the finalize rejection for "another miner's block won",
    // resets its error counter, and re-grinds the same doomed over-full template forever —
    // halting block production network-wide whenever the mempool exceeds the cap.
    #[tokio::test]
    async fn validate_new_block_rejects_over_full_template_with_distinct_error() {
        let bc = test_blockchain();
        let coinbase = Transaction {
            sender: "MINING_REWARDS".to_string(),
            recipient: "miner0".to_string(),
            fee_units: Transaction::to_units(NETWORK_FEE),
            amount_units: Transaction::to_units(1.0),
            timestamp: 1_000,
            signature: None,
            pub_key: None,
            sig_hash: None,
        };
        // 1 coinbase + MAX_BLOCK_TX_COUNT regular = MAX_BLOCK_TX_COUNT + 1 (over the cap).
        let mut transactions = vec![coinbase];
        for i in 0..MAX_BLOCK_TX_COUNT {
            transactions.push(Transaction {
                sender: format!("s{}", i),
                recipient: "r".to_string(),
                fee_units: Transaction::to_units(NETWORK_FEE),
                amount_units: Transaction::to_units(1.0),
                timestamp: 1_000,
                signature: None,
                pub_key: None,
                sig_hash: None,
            });
        }
        assert!(transactions.len() > MAX_BLOCK_TX_COUNT);

        let merkle_root =
            Blockchain::calculate_merkle_root(&transactions).expect("merkle root should build");
        let mut block = Block {
            index: 1,
            previous_hash: [1u8; 32],
            timestamp: 1_000,
            transactions,
            nonce: 0,
            difficulty: 0,
            hash: [0u8; 32],
            merkle_root,
        };
        block.hash = block.calculate_hash_for_block();

        let err = bc
            .validate_new_block(&block)
            .await
            .expect_err("over-full block must be rejected");
        assert!(matches!(
            err,
            BlockchainError::BlockTransactionCountExceeded
        ));
        // The classification guard: this must never read as a lost race.
        assert!(!err.to_string().contains("Block header is invalid"));
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

    #[tokio::test]
    async fn relay_floor_rejects_below_floor_fee_at_admission() {
        let blockchain = test_blockchain();
        let wallet = Wallet::new(None).expect("test wallet should build");
        set_confirmed_balance(&blockchain, &wallet.address, Transaction::to_units(10.0));

        // amount 0.01 -> percentage fee 0.00000563 (563 units), under the 10_000-unit floor.
        let low = signed_transfer(&wallet, "bob", 0.01, 10_000).await;
        assert!(low.fee_units < MIN_RELAY_FEE_UNITS);
        let err = blockchain
            .add_transaction(low)
            .await
            .expect_err("below-floor fee must be rejected at admission");
        assert!(matches!(err, BlockchainError::FeeBelowRelayFloor));

        // amount 1.0 -> percentage fee 0.000563 (56_306 units) clears the floor.
        let ok = signed_transfer(&wallet, "bob", 1.0, 10_001).await;
        assert!(ok.fee_units >= MIN_RELAY_FEE_UNITS);
        blockchain
            .add_transaction(ok)
            .await
            .expect("above-floor fee must be admitted");
    }

    #[tokio::test]
    async fn pending_revalidation_evicts_newly_inadmissible_fee_and_releases_balance() {
        let (bc, _) = fee_accounting_test_chain();
        let wallet = Wallet::new(None).expect("test wallet should build");
        set_confirmed_balance(&bc, &wallet.address, Transaction::to_units(3.0));

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let recipient = "22".repeat(20);
        let mut tx = Transaction::new(
            wallet.address.clone(),
            recipient.clone(),
            1.0,
            1.0,
            timestamp,
            None,
        );
        tx.signature = wallet.sign_transaction(&tx.get_message()).await;
        tx.pub_key = wallet.get_public_key_hex().await;
        let tx_id = tx.get_tx_id();

        // Force the revalidation path via a low activation floor.
        bc.add_transaction(tx)
            .await
            .expect("pre-activation pending transaction should stage");
        assert_eq!(
            bc.get_pending_debit_units(&wallet.address).await.unwrap(),
            Transaction::to_units(2.0)
        );
        assert_eq!(
            bc.get_pending_credit_units(&recipient).await.unwrap(),
            Transaction::to_units(1.0)
        );

        bc.sync_mempool_with_sled_at(1)
            .await
            .expect("activated pending revalidation should complete");

        let pending_tree = bc.db.open_tree(PENDING_TRANSACTIONS_TREE).unwrap();
        let full_sigs_tree = bc.db.open_tree(PENDING_FULL_SIGNATURES_TREE).unwrap();
        assert!(pending_tree.get(tx_id.as_bytes()).unwrap().is_none());
        assert!(full_sigs_tree.get(tx_id.as_bytes()).unwrap().is_none());
        assert_eq!(
            bc.get_pending_debit_units(&wallet.address).await.unwrap(),
            0,
            "rebuilding pending indexes releases the sender's reserved balance"
        );
        assert_eq!(
            bc.get_pending_credit_units(&recipient).await.unwrap(),
            0,
            "rebuilding pending indexes releases the recipient's pending credit"
        );
        assert!(bc.get_mempool_transaction_by_id(&tx_id).await.is_none());
    }

    #[tokio::test]
    async fn activation_pending_revalidation_is_single_flight_and_releases_both_indexes() {
        let (bc, _) = fee_accounting_test_chain();
        let bc = Arc::new(bc);
        let wallet = Wallet::new(None).expect("test wallet should build");
        let recipient = "22".repeat(20);
        set_confirmed_balance(&bc, &wallet.address, Transaction::to_units(3.0));

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut tx = Transaction::new(
            wallet.address.clone(),
            recipient.clone(),
            1.0,
            1.0,
            timestamp,
            None,
        );
        tx.signature = wallet.sign_transaction(&tx.get_message()).await;
        tx.pub_key = wallet.get_public_key_hex().await;
        let tx_id = tx.get_tx_id();
        bc.add_transaction(tx)
            .await
            .expect("pre-activation pending transaction should stage");
        assert_eq!(
            bc.get_pending_debit_units(&wallet.address).await.unwrap(),
            Transaction::to_units(2.0)
        );
        assert_eq!(
            bc.get_pending_credit_units(&recipient).await.unwrap(),
            Transaction::to_units(1.0)
        );

        let activation_parent = metadata_test_block(
            FEE_SYSTEM_ACTIVATION_HEIGHT.saturating_sub(1),
            [0u8; 32],
            &"11".repeat(20),
            1.0,
        );
        insert_raw_block(&bc, &activation_parent);
        bc.write_chain_tip_metadata(&activation_parent)
            .expect("activation-boundary tip metadata should write");

        let calls = (0..16).map(|_| {
            let bc = Arc::clone(&bc);
            async move { bc.ensure_pending_rules_for_next_block().await }
        });
        for result in futures::future::join_all(calls).await {
            result.expect("all concurrent transition callers should share a successful pass");
        }
        assert_eq!(
            bc.pending_rules_revalidation_runs.load(Ordering::Acquire),
            1,
            "the activation transition must be single-flight"
        );
        bc.ensure_pending_rules_for_next_block()
            .await
            .expect("a completed transition should be an idempotent no-op");
        assert_eq!(
            bc.pending_rules_revalidation_runs.load(Ordering::Acquire),
            1,
            "completion must suppress repeat full pending scans"
        );

        assert!(bc
            .db
            .open_tree(PENDING_TRANSACTIONS_TREE)
            .unwrap()
            .get(tx_id.as_bytes())
            .unwrap()
            .is_none());
        assert!(bc
            .db
            .open_tree(PENDING_FULL_SIGNATURES_TREE)
            .unwrap()
            .get(tx_id.as_bytes())
            .unwrap()
            .is_none());
        assert!(bc.get_mempool_transaction_by_id(&tx_id).await.is_none());
        assert_eq!(
            bc.get_pending_debit_units(&wallet.address).await.unwrap(),
            0
        );
        assert_eq!(bc.get_pending_credit_units(&recipient).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn activation_pending_revalidation_rearms_after_a_lower_tip() {
        let (bc, genesis) = fee_accounting_test_chain();
        let activation_parent = metadata_test_block(
            FEE_SYSTEM_ACTIVATION_HEIGHT.saturating_sub(1),
            [0u8; 32],
            &"11".repeat(20),
            1.0,
        );
        insert_raw_block(&bc, &activation_parent);
        bc.write_chain_tip_metadata(&activation_parent).unwrap();
        bc.ensure_pending_rules_for_next_block()
            .await
            .expect("first activation crossing should complete");
        assert!(bc.pending_rules_complete.load(Ordering::Acquire));
        assert_eq!(
            bc.pending_rules_revalidation_runs.load(Ordering::Acquire),
            1
        );

        bc.write_chain_tip_metadata(&genesis).unwrap();
        bc.notify_tip_changed(&genesis);
        assert!(
            !bc.pending_rules_complete.load(Ordering::Acquire),
            "a canonical tip whose next block is pre-activation must rearm cleanup"
        );

        let wallet = Wallet::new(None).expect("test wallet should build");
        let recipient = "22".repeat(20);
        set_confirmed_balance(&bc, &wallet.address, Transaction::to_units(3.0));
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut tx = Transaction::new(
            wallet.address.clone(),
            recipient.clone(),
            1.0,
            1.0,
            timestamp,
            None,
        );
        tx.signature = wallet.sign_transaction(&tx.get_message()).await;
        tx.pub_key = wallet.get_public_key_hex().await;
        let tx_id = tx.get_tx_id();
        bc.add_transaction(tx)
            .await
            .expect("the lower branch should retain pre-activation admission behavior");

        bc.write_chain_tip_metadata(&activation_parent).unwrap();
        bc.ensure_pending_rules_for_next_block()
            .await
            .expect("recrossing activation should reconcile again");
        assert_eq!(
            bc.pending_rules_revalidation_runs.load(Ordering::Acquire),
            2
        );
        assert!(bc
            .db
            .open_tree(PENDING_TRANSACTIONS_TREE)
            .unwrap()
            .get(tx_id.as_bytes())
            .unwrap()
            .is_none());
        assert_eq!(
            bc.get_pending_debit_units(&wallet.address).await.unwrap(),
            0
        );
        assert_eq!(bc.get_pending_credit_units(&recipient).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn activation_revalidation_evicts_noncanonical_pending_shape() {
        let (bc, _) = fee_accounting_test_chain();
        let wallet = Wallet::new(None).expect("test wallet should build");
        set_confirmed_balance(&bc, &wallet.address, Transaction::to_units(3.0));

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut tx = Transaction::new(
            wallet.address.clone(),
            "pre_activation_recipient".to_string(),
            1.0,
            NETWORK_FEE,
            timestamp,
            None,
        );
        tx.signature = wallet.sign_transaction(&tx.get_message()).await;
        tx.pub_key = wallet.get_public_key_hex().await;
        let tx_id = tx.get_tx_id();

        bc.add_transaction(tx)
            .await
            .expect("pre-activation pending shape should stage");
        bc.sync_mempool_with_sled_at(1)
            .await
            .expect("activation revalidation should complete");

        assert!(bc
            .db
            .open_tree(PENDING_TRANSACTIONS_TREE)
            .unwrap()
            .get(tx_id.as_bytes())
            .unwrap()
            .is_none());
        assert_eq!(
            bc.get_pending_debit_units(&wallet.address).await.unwrap(),
            0
        );
        assert!(bc.get_mempool_transaction_by_id(&tx_id).await.is_none());
    }

    #[tokio::test]
    async fn activated_admission_rejects_noncanonical_witness_text_without_reserving_balance() {
        let (bc, _) = fee_accounting_test_chain();
        let activation_parent = metadata_test_block(
            FEE_SYSTEM_ACTIVATION_HEIGHT.saturating_sub(1),
            [0u8; 32],
            &"11".repeat(20),
            1.0,
        );
        insert_raw_block(&bc, &activation_parent);
        bc.write_chain_tip_metadata(&activation_parent)
            .expect("activation-boundary tip metadata should write");
        assert_eq!(
            bc.get_latest_block_index(),
            u64::from(FEE_SYSTEM_ACTIVATION_HEIGHT.saturating_sub(1))
        );

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut candidates = Vec::new();
        for variant in 0..3u64 {
            let wallet = Wallet::new(None).expect("test wallet should build");
            set_confirmed_balance(&bc, &wallet.address, Transaction::to_units(3.0));
            let mut tx = signed_transfer(&wallet, &"22".repeat(20), 1.0, timestamp + variant).await;
            let signature_bytes =
                hex::decode(tx.signature.as_deref().expect("signed transfer")).unwrap();
            tx.sig_hash = Some(Transaction::signature_hash_hex(&signature_bytes));
            match variant {
                0 => {
                    tx.signature = tx.signature.map(|value| value.to_ascii_uppercase());
                }
                1 => {
                    tx.pub_key = tx.pub_key.map(|value| value.to_ascii_uppercase());
                }
                2 => {
                    tx.sig_hash = tx.sig_hash.map(|value| value.to_ascii_uppercase());
                }
                _ => unreachable!(),
            }
            candidates.push((wallet.address.clone(), tx));
        }

        let pending_tree = bc.db.open_tree(PENDING_TRANSACTIONS_TREE).unwrap();
        let full_sigs_tree = bc.db.open_tree(PENDING_FULL_SIGNATURES_TREE).unwrap();
        for (sender, tx) in candidates {
            let tx_id = tx.get_tx_id();
            let error = bc
                .add_transaction(tx)
                .await
                .expect_err("noncanonical witness text must not enter pending state");
            assert!(matches!(error, BlockchainError::NonCanonicalTransaction));
            assert_eq!(
                bc.get_pending_debit_units(&sender).await.unwrap(),
                0,
                "rejected admission must not reserve the sender's balance"
            );
            assert!(pending_tree.get(tx_id.as_bytes()).unwrap().is_none());
            assert!(full_sigs_tree.get(tx_id.as_bytes()).unwrap().is_none());
            assert!(bc.get_mempool_transaction_by_id(&tx_id).await.is_none());
        }
    }

    #[test]
    fn transaction_admission_future_remains_send() {
        fn assert_send<T: Send>(_: T) {}

        let bc = test_blockchain();
        let tx = user_tx(&"11".repeat(20), &"22".repeat(20), 1.0, 1);
        assert_send(bc.add_transaction(tx));
    }

    // ANTI-SOFT-FORK REGRESSION: the relay fee floor is mempool POLICY only. A
    // mined block carrying a below-floor (even zero) fee tx must never be
    // rejected for its fee — enforcing the floor in block validation would be a
    // soft fork against non-upgraded miners. If this test ever fails with
    // FeeBelowRelayFloor, the floor has leaked into consensus: revert that leak.
    #[tokio::test]
    async fn block_with_below_floor_fee_tx_is_not_rejected_for_its_fee() {
        let bc = test_blockchain();
        let mut zero_fee = user_tx("alice", "bob", 1.0, 1234);
        zero_fee.fee_units = 0;
        let txs = vec![zero_fee];
        let merkle_root = Blockchain::calculate_merkle_root(&txs).unwrap();
        let mut block = Block {
            index: 7,
            previous_hash: [0u8; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            transactions: txs,
            nonce: 0,
            difficulty: 0,
            hash: [0u8; 32],
            merkle_root,
        };
        block.hash = block.calculate_hash_for_block();

        // The block may fail for OTHER reasons (no coinbase, dummy signature,
        // parent linkage) — what it must never fail with is the fee floor.
        let res = bc.validate_block(&block).await;
        assert!(
            !matches!(res, Err(BlockchainError::FeeBelowRelayFloor)),
            "validate_block must never enforce the relay fee floor (soft fork), got {:?}",
            res
        );
        let res_new = bc.validate_new_block(&block).await;
        assert!(
            !matches!(res_new, Err(BlockchainError::FeeBelowRelayFloor)),
            "validate_new_block must never enforce the relay fee floor (soft fork), got {:?}",
            res_new
        );
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
        block
            .transactions
            .push(user_tx("carol", "carol", 1.0, 5_001));
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
        let system = bc
            .address_history_summary("MINING_REWARDS")
            .unwrap()
            .unwrap();
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
            bc.address_history_summary("alice")
                .unwrap()
                .unwrap()
                .tx_count,
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
            bc.address_history_summary("alice")
                .unwrap()
                .unwrap()
                .tx_count,
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
            bc.address_history_summary("dave")
                .unwrap()
                .unwrap()
                .tx_count,
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
            bc.address_history_summary("miner3")
                .unwrap()
                .unwrap()
                .tx_count,
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
            bc.address_history_summary("miner5")
                .unwrap()
                .unwrap()
                .tx_count,
            1
        );

        // Ensure is idempotent: re-running must not duplicate entries.
        bc.ensure_address_tx_index().unwrap();
        assert_eq!(
            bc.address_history_summary("miner5")
                .unwrap()
                .unwrap()
                .tx_count,
            1
        );

        // Chain rewritten at the indexed tip while the index was offline (hash at
        // the meta height no longer matches) => full rebuild, stale entries gone.
        let replacement = metadata_test_block(5, [9u8; 32], "usurper", 1.0);
        insert_raw_block(&bc, &replacement);
        bc.rebuild_chain_tip_metadata().unwrap();
        bc.ensure_address_tx_index().unwrap();
        assert_eq!(
            bc.address_history_summary("miner5")
                .unwrap()
                .unwrap()
                .tx_count,
            0,
            "entries from the rewritten block must not survive"
        );
        assert_eq!(
            bc.address_history_summary("usurper")
                .unwrap()
                .unwrap()
                .tx_count,
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
        assert!(bc
            .address_txs_page("alice", 3, Some((1, 0)))
            .unwrap()
            .is_empty());
        // Prefix addresses must not bleed into the page window.
        assert!(bc
            .address_txs_page("ali", 10, Some((5, 2)))
            .unwrap()
            .is_empty());
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
