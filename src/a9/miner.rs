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
    BlockchainError, MAX_BLOCK_FUTURE_TIME, MAX_BLOCK_TX_COUNT, MAX_TX_AGE_SECS,
    MIN_RELAY_FEE_UNITS, NETWORK_FEE,
};
use crate::a9::blockchain::{Block, Blockchain, Transaction};
use crate::a9::codec;

/// Cap on the summed serialized size of the transactions selected into a block
/// template. Every transport enforces node.rs MAX_MESSAGE_SIZE (4 MiB) per
/// frame, so a bigger block is unrelayable and would strand this miner on its
/// own fork. The consensus MAX_BLOCK_TX_COUNT alone does NOT keep templates
/// under the frame: full ML-DSA-87 witnesses put a signed transfer near ~15 KB,
/// so a count-full template would serialize to tens of MB. 3.5 MiB leaves
/// headroom for the header, coinbase and codec envelope.
const MAX_TEMPLATE_TX_BYTES: usize = 3_500_000;

// Constants for ProgPOW
const PROGPOW_LANES: usize = 16;
const PROGPOW_REGS: usize = 32;
// {wide_msg}: indicatif never truncates a plain {msg}, so a long status line
// WRAPS and the single moving bar becomes a flickering two-row block on an
// 80-col terminal; wide_msg clips the message to the remaining row instead.
const MINING_PROGRESS_TEMPLATE: &str = "{prefix} {bar:37.cyan/blue} {pos:>7}/{len:7} {wide_msg}";
const MINING_SUCCESS_TEMPLATE: &str = "{prefix} {bar:36.cyan/blue}> {pos:>7}/{len:7} {wide_msg}";
/// GPU mode drives the same ===== bar, but as PERCENT of one expected block of
/// work at the live difficulty (len 100; gpu_miner.rs drives the position) —
/// unit-free, so it moves at any difficulty (a GH-scaled length collapsed to
/// zero usable ticks at the 464 floor). The spinner keeps visible motion
/// between the bar's coarse increments. The message is ordered
/// most-important-first (rate, ETA) so an 80-col clip still shows what matters.
#[cfg(feature = "gpu_miner")]
const GPU_MINING_PROGRESS_TEMPLATE: &str =
    "{prefix} {spinner:.cyan} {bar:37.cyan/blue} {pos:>3}% {wide_msg}";
/// Success frame in GPU scale — keeps the percent grammar on the final frame
/// instead of flipping to the CPU template's pos/len columns.
#[cfg(feature = "gpu_miner")]
const GPU_MINING_SUCCESS_TEMPLATE: &str =
    "{prefix} {bar:37.cyan/blue}> {pos:>3}% {wide_msg}";
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

#[derive(Error, Debug)]
pub enum MiningError {
    #[error("Mining failed: {0}")]
    MiningFailed(String),
    #[error("Blockchain error: {0}")]
    BlockchainError(String),
    #[error("Invalid hash format")]
    InvalidHashFormat,
    #[error("Exceeded max nonce limit")]
    MaxNonceExceeded,
    #[error("Mining stopped by user")]
    Stopped,
}

impl From<Box<dyn std::error::Error>> for MiningError {
    fn from(error: Box<dyn std::error::Error>) -> Self {
        MiningError::MiningFailed(error.to_string())
    }
}

/// Aborts a spawned task when dropped — ties the GPU display task's lifetime
/// to mine_block's many exit paths without threading an abort through each.
#[cfg(feature = "gpu_miner")]
struct AbortOnDrop(tokio::task::JoinHandle<()>);
#[cfg(feature = "gpu_miner")]
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Random nonce-window base for one mining attempt (splitmix64 of the clock +
/// pid). NOT crypto — it only de-correlates the search windows of same-wallet
/// rigs: the reward tx is deterministic with a whole-second timestamp, so two
/// rigs on one wallet routinely build IDENTICAL merkle roots in the same
/// second, and with every searcher anchored at nonce 0 they then scan
/// near-100% overlapping (timestamp, nonce) space — half their combined
/// hashrate thrown away. Random ~2^34-nonce windows in a 2^64 space collide
/// with probability ~6e-9 per attempt. Masked to 2^62 so the CPU path's
/// saturating/checked range math never nears the u64 ceiling.
pub(crate) fn attempt_nonce_base() -> u64 {
    let mut x = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        ^ ((std::process::id() as u64) << 32);
    // splitmix64 finalizer
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (x ^ (x >> 31)) & ((1u64 << 62) - 1)
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
        #[cfg_attr(not(feature = "gpu_miner"), allow(unused_variables))] use_gpu: bool,
        stop: Arc<AtomicBool>,
    ) -> Result<(u64, String, Block), MiningError> {
        // The command-time snapshot is no longer mined from — the template
        // rebuild below selects from the LIVE mempool every pass, so txs that
        // confirm mid-grind leave the template and new arrivals enter it.
        let _ = transactions;

        let found = Arc::new(AtomicBool::new(false));
        let abort_for_tip_change = Arc::new(AtomicBool::new(false));
        let result_nonce = Arc::new(AtomicU64::new(0));
        let result_timestamp = Arc::new(AtomicU64::new(0));
        let result_difficulty = Arc::new(AtomicU64::new(0));
        let hash_result = Arc::new(Mutex::new(Vec::with_capacity(32)));

        if max_nonce == 0 {
            return Err(MiningError::MaxNonceExceeded);
        }

        // Reserve headroom for the async runtime by default. Header PoW is
        // embarrassingly parallel, so grabbing every core maximizes raw hashrate,
        // but the SAME process must also fetch the tip beacon, ingest blocks, and
        // converge to the tip, and the in-grind tip-change abort can only fire once
        // that async catch-up advances the local tip. Pinning all cores to BLAKE3
        // starved that path, so the CPU scan sat on a stale template while the
        // network moved on. (The GPU path offloads hashing to the device and keeps
        // cores free on its own — this default is what matters for the CPU fallback
        // and for a rig that demotes to CPU when its GPU dies mid-session.) Leaving
        // two cores free keeps catch-up responsive; big rigs lose <1%. Operators
        // who want a specific count set ALPHANUMERIC_MINE_THREADS (still honored
        // verbatim, clamped 1..=1024).
        let num_threads = std::env::var("ALPHANUMERIC_MINE_THREADS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map(|n| n.clamp(1, 1024))
            .unwrap_or_else(|| num_cpus::get().saturating_sub(2).max(1))
            .max(1);
        let nonces_per_thread = max_nonce.div_ceil(num_threads as u64);

        // Resolve the GPU ONCE per mine command, out loud, BEFORE the progress
        // bar exists (its 100ms steady tick would garble any plain println
        // racing it — the exact bug this rework removes). The default log
        // filter is Error-only, so the old log-only init path left `--gpu`
        // totally silent about WHICH adapter it picked — or that init/self-check
        // failed and it was about to pick none. Worse, a failed GPU used to make
        // the loop below `continue` forever: rebuilding templates at full speed,
        // hashing nothing, telling nobody. Now a dead GPU says so and falls back
        // to the CPU scan, which is what the fallback always claimed to do.
        // `mut`: a GPU that dies MID-session (driver reset/TDR) demotes too.
        #[cfg(feature = "gpu_miner")]
        let mut gpu_active = if use_gpu {
            // First call initializes wgpu — ~100-200ms of pollster::block_on —
            // so it runs on the blocking pool, not the async thread (mine_block
            // can be polled inside the client's LocalSet; see the spawn_blocking
            // note on the dispatch below).
            let status = tokio::task::spawn_blocking(crate::a9::gpu_miner::gpu_status)
                .await
                .unwrap_or_else(|_| Err("GPU init/re-check thread failed".to_string()));
            match status {
                Ok(adapter) => {
                    println!("  GPU: {adapter} — BLAKE3 kernel self-check passed");
                    // Clear any leftover rate/difficulty from a prior command so
                    // the first display frames don't show stale readings.
                    crate::a9::gpu_miner::reset_display_state();
                    true
                }
                Err(reason) => {
                    println!("  GPU unavailable: {reason}");
                    println!("  Falling back to CPU mining so this command still mines.");
                    false
                }
            }
        } else {
            false
        };
        // Cumulative expected-blocks of work this mine command, micro-units
        // (each dispatch adds per_dispatch/expected at THAT dispatch's
        // difficulty — monotonic through both tip churn and difficulty-band
        // flapping). The tip advances every ~5s network-wide, so any
        // per-height meter would reset before it moved.
        #[cfg(feature = "gpu_miner")]
        let gpu_session_progress_micro = Arc::new(AtomicU64::new(0));

        let progress_bar = Arc::new(Mutex::new(ProgressBar::new(max_nonce)));
        {
            if let Ok(pb) = progress_bar.lock() {
                let style = ProgressStyle::with_template(MINING_PROGRESS_TEMPLATE)
                    .map_err(|e| MiningError::MiningFailed(format!("Progress style error: {}", e)))?
                    .progress_chars("=  ");
                pb.set_style(style);
                pb.set_prefix(format!("Block #{}", header.number));
                pb.enable_steady_tick(Duration::from_millis(100));
                #[cfg(feature = "gpu_miner")]
                if gpu_active {
                    // GPU scale: the bar is percent-of-one-expected-block (len
                    // 100, position set by gpu_mine_attempt), difficulty-
                    // independent — a GH-unit length truncated to 0 usable
                    // ticks at the 464-difficulty floor (2^29 ≈ 0.54 GH).
                    if let Ok(style) = ProgressStyle::with_template(GPU_MINING_PROGRESS_TEMPLATE) {
                        pb.set_style(style.progress_chars("=  "));
                    }
                    pb.set_length(100);
                    pb.set_message("warming up GPU search...");
                }
            } else {
                return Err(MiningError::MiningFailed(
                    "Progress bar lock poisoned".to_string(),
                ));
            }
        }

        // GPU display task: the ONLY painter of GPU search progress. The GPU
        // submit thread writes atomics and never touches the console — indicatif
        // draws on the calling thread, and Windows console writes can stall
        // 100ms+, which idled the GPU behind console I/O (Task Manager showed
        // 40-70% oscillating utilization; every ms between dispatches is paid
        // at the ~5s tip cadence). A console stall now costs this task's next
        // repaint, never a dispatch. Aborted on every mine_block exit by the
        // drop guard, and on mid-session CPU demotion below.
        #[cfg(feature = "gpu_miner")]
        let mut _gpu_display_guard: Option<AbortOnDrop> = if gpu_active {
            let pb = match progress_bar.lock() {
                Ok(pb) => pb.clone(),
                Err(_) => {
                    return Err(MiningError::MiningFailed(
                        "Progress bar lock poisoned".to_string(),
                    ))
                }
            };
            let progress_micro = Arc::clone(&gpu_session_progress_micro);
            Some(AbortOnDrop(tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(1));
                loop {
                    ticker.tick().await;
                    let (ghs, difficulty) = crate::a9::gpu_miner::gpu_display_snapshot();
                    if ghs <= 0.0 || difficulty == 0 {
                        continue; // first dispatch hasn't landed yet
                    }
                    let sweeps =
                        progress_micro.load(Ordering::Relaxed) as f64 / 1e6;
                    pb.set_position(((sweeps.fract() * 100.0) as u64).min(99));
                    let eta = crate::a9::gpu_miner::format_eta(
                        crate::a9::gpu_miner::expected_block_seconds(difficulty, ghs),
                    );
                    // Most-important-first: {wide_msg} clips the tail at 80
                    // cols, so rate and ETA must survive; the multiplier is
                    // the "how unlucky is this block" meter past 1x.
                    let due = if sweeps >= 1.0 {
                        format!(" · {:.1}x expected work", sweeps)
                    } else {
                        String::new()
                    };
                    pb.set_message(format!(
                        "{:.2} GH/s · block in {} · diff {}{}",
                        ghs, eta, difficulty, due
                    ));
                }
            })))
        } else {
            None
        };

        let mut current_nonce: u64 = attempt_nonce_base();
        // Progress-bar refresh cadence per thread. try_lock keeps losers from
        // blocking, but with hundreds of threads even the attempts are traffic —
        // 8192 still repaints many times a second while staying off the hot path.
        let update_interval = 8192;
        let tip_change_counter = {
            let blockchain_guard = self.blockchain.read().await;
            blockchain_guard.tip_change_counter_handle()
        };

        'mining: loop {
            // User pressed Enter (continuous mode): bail before building the
            // next template. The GPU/CPU search loops below also observe `stop`
            // mid-grind, so a stop during a long solo grind returns promptly
            // rather than waiting out the whole attempt.
            if stop.load(Ordering::SeqCst) {
                if let Ok(pb) = progress_bar.lock() {
                    pb.finish_and_clear();
                }
                return Err(MiningError::Stopped);
            }
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

            // `!=`, not `>`: a reorg can LOWER the tip, and this check is the
            // only retarget point in GPU mode — with `>` the header kept its
            // stale-high index while previous_hash tracked the real (lower)
            // tip, so every subsequent solve was doomed at finalize until the
            // chain grew back past the stale number.
            if current_height != header.number {
                header.number = current_height;
                if let Ok(pb) = progress_bar.lock() {
                    pb.set_prefix(format!("Block #{}", header.number));
                    pb.set_message("New network tip detected; rebuilding block template...");
                }
                current_nonce = attempt_nonce_base();
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
                // LIVE mempool, not the command-time snapshot: mine_block runs
                // for hours, and against a static snapshot (a) a tx another
                // miner confirmed mid-grind stays in our template and burns the
                // whole solve at finalize's replay guard, and (b) txs that
                // arrived after the command never enter the template at all —
                // no fees, and their confirmation waits on other miners.
                // Source = get_transactions_for_block (prunes expired, applies
                // the MAX_TX_AGE_SECS freshness gate) + the handle_mine_command
                // gates + the consensus bounds the block itself will be checked
                // against: age with a margin (the block is stamped up to an
                // attempt later than this filter runs — a tx within seconds of
                // expiry would pass here and burn the solve at finalize) and
                // the future-dating bound (a sender's skewed clock would
                // otherwise poison every rebuilt template).
                // TIP-CHANGE HOT PATH: this rebuild runs on every ~5s network
                // tip change, and every ms here is a ms the GPU is not hashing
                // the new block. When the pool is EMPTY (the common state) an
                // atomic-counter probe is the ONLY mempool work — the sweep,
                // selection lock, and filters below never run, and the rebuild
                // is back to sub-ms. There is nothing to go stale in an empty
                // template, so the correctness gates below are vacuous anyway.
                let live_transactions: Vec<Transaction> = if blockchain_lock
                    .mempool_is_empty()
                    .await
                {
                    Vec::new()
                } else {
                let _ = blockchain_lock.drop_confirmed_mempool_txs().await;
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                const TEMPLATE_FRESHNESS_MARGIN_SECS: u64 = 60;
                blockchain_lock
                    .get_transactions_for_block()
                    .await
                    .into_iter()
                    .filter(|tx| {
                        if tx.sender == "MINING_REWARDS" {
                            return false;
                        }
                        if blockchain_lock.is_tx_confirmed(&tx.get_tx_id()) {
                            return false;
                        }
                        if !tx.has_valid_regular_amounts() {
                            return false;
                        }
                        // Relay-policy floor, belt to the mempool's suspender:
                        // never template a below-floor tx that slipped in via
                        // startup rehydration or a reorg readmit.
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
                    })
                    .collect()
                };

                // Reserve one slot for the coinbase so the finalized block never exceeds
                // the consensus per-block transaction cap. Without this bound, a mempool
                // larger than the cap made every template over-full: the nonce grind
                // completed, finalize rejected the block, and — the rejection being
                // indistinguishable from a lost race — the continuous loop reset its error
                // counter and re-ground the same doomed template forever, stalling block
                // production across the whole network until the backlog drained.
                let regular_cap = MAX_BLOCK_TX_COUNT.saturating_sub(1);

                // Order candidates highest-fee first, then oldest first, so that when the
                // live mempool exceeds the cap we keep the most valuable / longest-waiting
                // transactions rather than an arbitrary subset. Regular transactions are
                // near-constant size (the ML-DSA signature dominates), so exact fee order
                // tracks fee-per-byte.
                let mut ordered: Vec<&Transaction> = live_transactions.iter().collect();
                ordered.sort_by(|a, b| {
                    b.fee_units
                        .cmp(&a.fee_units)
                        .then_with(|| a.timestamp.cmp(&b.timestamp))
                });

                let mut selected_regular =
                    Vec::with_capacity(regular_cap.min(live_transactions.len()));
                let mut sender_debits: HashMap<String, i128> = HashMap::new();
                // One confirmed-balance read PER UNIQUE SENDER, not per candidate.
                // The chain read lock is held across this loop, so a sender's
                // confirmed balance cannot change mid-selection — the per-candidate
                // re-await only serialized an O(candidates) chain of redundant index
                // reads on the tip-change hot path, with the GPU idle for all of it.
                // Worst case was exactly the dust-storm shape (thousands of txs from
                // a handful of senders). Intra-template spending is still tracked
                // exactly by `sender_debits`; selection order and outcomes are
                // byte-identical to the per-candidate version.
                let mut confirmed_cache: HashMap<String, i128> = HashMap::new();
                let mut template_bytes: usize = 0;

                for transaction in ordered {
                    if selected_regular.len() >= regular_cap {
                        break;
                    }
                    // Exact i128: tx selection must agree with the consensus writer's
                    // affordability so it doesn't select a tx that finalize then rejects
                    // (the f64 round-trip drifts above ~33.55M coins — 2026-07-12 audit).
                    let confirmed_units = match confirmed_cache.get(&transaction.sender) {
                        Some(units) => *units,
                        None => {
                            let units = blockchain_lock
                                .get_confirmed_balance_units(&transaction.sender)
                                .await?;
                            confirmed_cache.insert(transaction.sender.clone(), units);
                            units
                        }
                    };
                    let already_selected = sender_debits
                        .get(&transaction.sender)
                        .copied()
                        .unwrap_or_default();
                    let required_units = transaction.total_debit_units();

                    if confirmed_units.saturating_sub(already_selected) >= required_units {
                        // Relayability cap (MAX_TEMPLATE_TX_BYTES): continue, not
                        // break — fee-desc order still packs any smaller txs that
                        // fit under the remaining budget.
                        let tx_bytes = match codec::serialize(transaction) {
                            Ok(bytes) => bytes.len(),
                            Err(_) => continue, // unserializable can't ship in a block
                        };
                        if template_bytes.saturating_add(tx_bytes) > MAX_TEMPLATE_TX_BYTES {
                            continue;
                        }
                        template_bytes += tx_bytes;
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

            // GPU FAST PATH (feature gpu_miner + runtime `mine --gpu`). Propose a
            // winning nonce on the GPU; on success set the SAME result atomics the
            // CPU search would, so the finalization below builds and re-verifies the
            // block through the identical consensus path. The GPU only supplies a
            // nonce — a wrong hash is caught by the normal block verify (fail-closed).
            // The CPU rayon search below then no-ops (its threads see `found`).
            #[cfg(feature = "gpu_miner")]
            if gpu_active {
                // spawn_blocking: gpu_mine_attempt blocks synchronously on GPU
                // readbacks for up to the whole budget. Running it inline on a
                // tokio worker starved the very tasks that advance the tip
                // (beacon-watch, converge) on low-core boxes — the miner was
                // slowing down its own view of the network. NOT block_in_place:
                // the interactive client polls its command loop inside
                // LocalSet::run_until (main.rs), whose poll forbids
                // block_in_place — it panics with "can call blocking only when
                // running on the multi-threaded runtime" and kills the whole
                // client on the first `mine --gpu` (2026-07-11 audit finding,
                // verified against tokio 1.52.3). spawn_blocking runs on the
                // blocking pool from any context. The 20s budget (was 5s) is
                // safe now that the adaptive ~250ms dispatches end the attempt
                // within a fraction of a block of any tip change: the budget's
                // only remaining job is refreshing the tx selection.
                let gpu_number = header.number;
                let gpu_prev = previous_block_hash;
                let gpu_merkle = merkle_root;
                let gpu_counter = Arc::clone(&tip_change_counter);
                let gpu_progress = Arc::clone(&gpu_session_progress_micro);
                let gpu_stop = Arc::clone(&stop);
                let gpu_hit = match tokio::task::spawn_blocking(move || {
                    crate::a9::gpu_miner::gpu_mine_attempt(
                        gpu_number,
                        &gpu_prev,
                        &gpu_merkle,
                        previous_difficulty,
                        previous_block_timestamp,
                        std::time::Duration::from_secs(20),
                        &gpu_counter,
                        template_tip_version,
                        &gpu_progress,
                        &gpu_stop,
                    )
                })
                .await
                {
                    Ok(hit) => hit,
                    Err(join_err) => {
                        // The GPU thread PANICKED — a mid-session device loss
                        // (driver reset/TDR, eGPU unplug). Without demotion this
                        // would re-panic every attempt forever, mining nothing:
                        // the same wedge the startup check closes, one step
                        // later. Demote to the CPU scan for the rest of the
                        // command; a restart re-probes the GPU.
                        _gpu_display_guard = None; // stop the GPU display task
                        if let Ok(pb) = progress_bar.lock() {
                            pb.println(format!(
                                "  GPU search failed mid-session ({join_err}); falling back to CPU mining."
                            ));
                            if let Ok(style) =
                                ProgressStyle::with_template(MINING_PROGRESS_TEMPLATE)
                            {
                                pb.set_style(style.progress_chars("=  "));
                            }
                            pb.set_length(max_nonce);
                            pb.set_position(0);
                        }
                        gpu_active = false;
                        None
                    }
                };
                if let Some((n, ts, diff, hash)) = gpu_hit {
                    if !found.swap(true, Ordering::Release) {
                        result_nonce.store(n, Ordering::Release);
                        result_timestamp.store(ts, Ordering::Release);
                        result_difficulty.store(diff, Ordering::Release);
                        if let Ok(mut g) = hash_result.lock() {
                            *g = hash.to_vec();
                        }
                    }
                }
                // User pressed Enter mid-grind: gpu_mine_attempt observes `stop`
                // between dispatches and returns promptly; end the command here
                // instead of looping into another attempt. But if this very
                // dispatch found a block, honor the solve first (fall through to
                // finalize) — throwing away a real block because Enter landed in
                // the same 140ms window would waste a genuine reward.
                if stop.load(Ordering::SeqCst) && !found.load(Ordering::Acquire) {
                    if let Ok(pb) = progress_bar.lock() {
                        pb.finish_and_clear();
                    }
                    return Err(MiningError::Stopped);
                }
                // GPU is the whole search when active: if it found a block, fall
                // through to finalization (found=true, the CPU rayon below no-ops);
                // if not (budget hit / tip moved), skip the pointless CPU scan and
                // loop to a fresh GPU attempt against the current tip. Running the
                // CPU window here was ~half the wasted duty cycle that stopped the
                // GPU from winning blocks. If the GPU just DIED (gpu_active
                // demoted above), fall through to the CPU scan instead.
                if !found.load(Ordering::Acquire) && gpu_active {
                    continue;
                }
            }

            let mining_result: Result<(), MiningError> = {
                // Run the CPU-fallback grind on the blocking pool, NOT the caller's
                // thread. This path runs when `mine` has no GPU, or when the GPU
                // died mid-session and demoted to CPU. The GPU fast path above
                // already offloads via spawn_blocking, but the CPU scan ran the
                // rayon join inline: on an interactive node the REPL + node monitor
                // share a single-threaded LocalSet, so the synchronous join parked
                // that thread for the whole pass while all cores hashed BLAKE3 —
                // starving the beacon-watch/converge catch-up that advances the
                // local tip, so the in-grind tip-change abort never fired and the
                // scan sat on a stale template. spawn_blocking hands the grind to a
                // blocking thread and yields the caller so convergence keeps running.
                // Each `let` below shadows an Arc/handle and is MOVED into the task;
                // the originals (including the result clones the GPU path and the
                // finalize below also use) stay valid and are read after the join.
                // JoinError (task panic) -> mining failure, not a silent stall.
                let found = Arc::clone(&found);
                let result_nonce = Arc::clone(&result_nonce);
                let result_timestamp = Arc::clone(&result_timestamp);
                let result_difficulty = Arc::clone(&result_difficulty);
                let hash_result = Arc::clone(&hash_result);
                let abort_for_tip_change_check = Arc::clone(&abort_for_tip_change_check);
                let tip_change_counter_check = Arc::clone(&tip_change_counter_check);
                let blockchain_for_tip_checks = Arc::clone(&blockchain_for_tip_checks);
                let progress_bar = Arc::clone(&progress_bar);
                let stop_for_cpu = Arc::clone(&stop);
                let header = header.clone();
                match tokio::task::spawn_blocking(move || {
                    (0..num_threads as u64)
                        .into_par_iter()
                        .try_for_each(|thread_id| -> Result<(), MiningError> {
                            let mut local_header = header.clone();
                            local_header.merkle_root = merkle_root;
                            let range_end = current_nonce.saturating_add(max_nonce);
                            let start_nonce = current_nonce
                                .saturating_add(thread_id.saturating_mul(nonces_per_thread));
                            if start_nonce >= range_end {
                                return Ok(());
                            }
                            let end_nonce =
                                start_nonce.saturating_add(nonces_per_thread).min(range_end);
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
                                    || stop_for_cpu.load(Ordering::Relaxed)
                                {
                                    return Ok(());
                                }

                                // Don't create full Block - just calculate hash directly
                                // We only need the full block when we find a valid nonce
                                // Clamped to the parent's timestamp: a local clock behind
                                // the parent would stamp a block that fails parent-
                                // timestamp validation — discovered only AFTER the grind,
                                // burning the whole solve.
                                let timestamp = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs()
                                    .max(previous_block_timestamp);
                                if timestamp != cached_timestamp {
                                    cached_timestamp = timestamp;
                                    cached_difficulty = Block::consensus_next_difficulty(
                                        previous_difficulty,
                                        timestamp.saturating_sub(previous_block_timestamp),
                                        local_header.number,
                                    );
                                    cached_target_bytes = pow_target_bytes(
                                        &pow_target_from_difficulty(cached_difficulty),
                                    );
                                }
                                let hash = {
                                    let mut header_data = [0u8; 92];
                                    let mut offset = 0;

                                    header_data[offset..offset + 4]
                                        .copy_from_slice(&local_header.number.to_le_bytes());
                                    offset += 4;

                                    header_data[offset..offset + 32]
                                        .copy_from_slice(&previous_block_hash);
                                    offset += 32;

                                    header_data[offset..offset + 8]
                                        .copy_from_slice(&timestamp.to_le_bytes());
                                    offset += 8;

                                    header_data[offset..offset + 8]
                                        .copy_from_slice(&nonce.to_le_bytes());
                                    offset += 8;

                                    header_data[offset..offset + 8]
                                        .copy_from_slice(&cached_difficulty.to_le_bytes());
                                    offset += 8;

                                    header_data[offset..offset + 32]
                                        .copy_from_slice(&merkle_root);

                                    *blake3::hash(&header_data).as_bytes()
                                };

                                if hash <= cached_target_bytes {
                                    if !found.swap(true, Ordering::Relaxed) {
                                        result_nonce.store(nonce, Ordering::Release);
                                        result_timestamp.store(timestamp, Ordering::Release);
                                        result_difficulty
                                            .store(cached_difficulty, Ordering::Release);
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
                                        abort_for_tip_change_check
                                            .store(true, Ordering::Release);
                                        return Ok(());
                                    }
                                }

                                if nonce % DB_TIP_CONFIRM_INTERVAL == 0 {
                                    if let Ok(blockchain) = blockchain_for_tip_checks.try_read()
                                    {
                                        if let Some(tip) = blockchain.get_last_block() {
                                            if tip.index != expected_parent_index
                                                || tip.hash != previous_block_hash
                                            {
                                                abort_for_tip_change_check
                                                    .store(true, Ordering::Release);
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

                                    // Avoid blocking inside rayon threads; height changes
                                    // will be picked up on the next outer loop iteration.
                                }
                            }
                            Ok(())
                        })
                })
                .await
                {
                    Ok(inner) => inner,
                    Err(join_err) => Err(MiningError::MiningFailed(format!(
                        "mining task failed to join: {}",
                        join_err
                    ))),
                }
            };

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
                current_nonce = attempt_nonce_base();
                if let Ok(pb) = progress_bar.lock() {
                    pb.reset();
                    pb.set_prefix(format!("Block #{}", header.number));
                    pb.set_message("New network tip detected; mining next block...");
                }
                continue;
            }

            if found.load(Ordering::Relaxed) {
                // Stop the GPU display task NOW, before finalization: it and the
                // finalize painter share the bar, and letting both write it
                // would reintroduce the two-painters flicker this rework removed.
                #[cfg(feature = "gpu_miner")]
                {
                    _gpu_display_guard = None;
                }
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
                                        // Keep the bar's own unit grammar on the
                                        // final frame: percent for the GPU scale
                                        // (len 100), pos/len nonces for the CPU.
                                        #[cfg(feature = "gpu_miner")]
                                        let success_template = if gpu_active {
                                            GPU_MINING_SUCCESS_TEMPLATE
                                        } else {
                                            MINING_SUCCESS_TEMPLATE
                                        };
                                        #[cfg(not(feature = "gpu_miner"))]
                                        let success_template = MINING_SUCCESS_TEMPLATE;
                                        if let Ok(style) =
                                            ProgressStyle::with_template(success_template)
                                        {
                                            pb.set_style(style.progress_chars("=  "));
                                        }
                                        // length-relative: the GPU bar is
                                        // percent-scaled (len 100), the CPU bar
                                        // nonce-scaled (len max_nonce) — either
                                        // way "full" is the bar's own length.
                                        pb.set_position(pb.length().unwrap_or(max_nonce));
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
                                            current_nonce = attempt_nonce_base();
                                            if let Ok(pb) = progress_bar.lock() {
                                                // GPU percent bar (len 100) is
                                                // session-cumulative — a reset
                                                // here would flash it to 0% and
                                                // snap back on the next report,
                                                // a backward glitch right as the
                                                // user is told they lost a race.
                                                if pb.length() != Some(100) {
                                                    pb.reset();
                                                }
                                                pb.set_prefix(format!("Block #{}", header.number));
                                                pb.set_message(
                                                    "Lost the race for this height — retargeting the new tip...",
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
        use_gpu: bool,
        stop: Arc<AtomicBool>,
    ) -> Result<(u64, String, Block), MiningError> {
        self.manager
            .mine_block(
                header,
                transactions,
                max_nonce,
                miner_address,
                use_gpu,
                stop,
            )
            .await
            // Preserve Stopped so the caller can distinguish a user stop from a
            // real fault; flatten everything else to a message as before.
            .map_err(|e| match e {
                MiningError::Stopped => MiningError::Stopped,
                other => MiningError::MiningFailed(other.to_string()),
            })
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
