//! Durable operator-side payment idempotency and uniqueness ledger.
//!
//! This is purely operator/wallet-side state. It changes NO transaction field, signed message,
//! transaction ID, codec, Merkle calculation, block, consensus rule, network message, or chain
//! database format. It never appears on the wire or in the chain sled database.
//!
//! The chain's transaction identity is the tuple `(sender, recipient, amount, fee, timestamp)`,
//! which is simultaneously the signed message and the replay key. Two payments that a caller
//! *intends* to be distinct but that share the first four fields collide into ONE on-chain
//! transaction if they also share the second — the later one silently merges into the earlier and
//! is never paid. This ledger:
//!
//! * allocates a distinct timestamp per genuinely-new payment for a `(sender, recipient, amount,
//!   fee)` tuple, so two intended-distinct payments can never be signed as the same transaction in
//!   the same second;
//! * maps an operator idempotency key (a pool/exchange withdrawal identifier) to exactly one
//!   transaction and its last known outcome, so a true retry returns the original payment instead
//!   of creating a second one, and reusing a key for a different payment is refused rather than
//!   double-paid;
//! * persists every reservation durably *before* the signed transaction is exposed, so a crash
//!   between signing and broadcast still recognizes the operation on restart.
//!
//! Because the fee is part of the identity tuple, re-signing the "same" payment at a higher fee is
//! a genuinely different transaction that can also confirm. The ledger therefore treats a fee bump
//! as a new payment and, at the integration layer, only permits it after the original is definitively
//! rejected or can no longer be valid — it is never presented as replace-by-fee.
//!
//! Persistence is an append-only JSON-lines log with atomic full-file compaction, mirroring the
//! temp-write + fsync + rename + parent-dir-fsync discipline of the wallet key file. I/O is
//! synchronous; async callers invoke mutating methods through `tokio::task::spawn_blocking`, which
//! is also the correct way to keep an fsync off the async executor.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

/// Default ledger filename, alongside the wallet key file in the working directory. One shared
/// instance backs both the local signing path and the node's protected submission endpoints.
pub const DEFAULT_LEDGER_FILENAME: &str = "wallet-ledger.log";
/// Chain freshness window (`MAX_TX_AGE_SECS`). A payment whose timestamp plus this margin is in the
/// past can never be mined again, so its ledger entry is safe to expire and a new payment for the
/// same tuple can reuse the current second. Kept as a construction parameter so the module has no
/// dependency on consensus constants; the node passes the real value.
pub const DEFAULT_TX_AGE_LIMIT_SECS: u64 = 21_600;
/// Ceiling on how far a collision-avoiding timestamp may be pushed past wall-clock. Mirrors the
/// consensus future-dating limit so an allocated timestamp is never rejected as future-dated.
pub const DEFAULT_FUTURE_ALLOCATION_MARGIN_SECS: u64 = 300;
/// Terminal entries older than this are pruned. Generous so an exchange can still reconcile a
/// withdrawal long after it confirmed, while keeping the live set bounded.
pub const DEFAULT_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
/// Hard ceiling on retained entries regardless of age, so an abusive or runaway caller cannot grow
/// the ledger without bound. Oldest terminal entries are dropped first.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;
/// Compact the append log once it grows past this many bytes, collapsing superseded records.
pub const DEFAULT_COMPACTION_THRESHOLD_BYTES: u64 = 4 * 1024 * 1024;

/// Serialize `i128` as a JSON string. Two reasons: serde's internally-tagged-enum `Content` buffer
/// (used when decoding the tagged `LogRecord`) cannot hold `i128`, and a JSON number cannot safely
/// carry the full `i128` range anyway. A decimal string is exact and buffer-safe.
mod i128_str {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &i128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i128, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse::<i128>().map_err(serde::de::Error::custom)
    }
}

/// The collision key: a chain transaction identity with the timestamp removed. Two payments that
/// share this must differ in timestamp or they are the same on-chain transaction.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PaymentTuple {
    pub sender: String,
    pub recipient: String,
    #[serde(with = "i128_str")]
    pub amount_units: i128,
    #[serde(with = "i128_str")]
    pub fee_units: i128,
}

impl PaymentTuple {
    pub fn new(sender: String, recipient: String, amount_units: i128, fee_units: i128) -> Self {
        Self {
            sender,
            recipient,
            amount_units,
            fee_units,
        }
    }
}

/// Explicit, operator-visible lifecycle state of a recorded operation. Independent of consensus:
/// it records what the operator's own submissions observed, not a chain verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EntryState {
    /// Admitted to a mempool (or awaiting first submission) and not yet known-terminal.
    Pending,
    /// Observed confirmed at the given height.
    Confirmed { height: u32 },
    /// Definitively rejected for a reason that is a pure function of the transaction bytes.
    Rejected { reason: String },
    /// The original transaction can no longer be valid under the freshness window.
    Expired,
}

impl EntryState {
    /// A terminal state can be pruned once old enough; a pending one is always retained.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, EntryState::Pending)
    }
}

/// One durably recorded intended payment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Primary key: the operator idempotency key when supplied, else the transaction id.
    pub key: String,
    /// Present only when the caller supplied an explicit operator idempotency key.
    pub idempotency_key: Option<String>,
    pub tuple: PaymentTuple,
    pub timestamp: u64,
    pub tx_id: String,
    /// Opaque signed-transaction blob the caller can rebroadcast verbatim. The ledger never parses
    /// it. `None` for an already-signed transaction submitted through the node API, where the
    /// operator retains the signed bytes.
    pub signed_tx: Option<String>,
    pub state: EntryState,
    pub created_at: u64,
    pub updated_at: u64,
}

/// One append-log line. Applied in order on load; later records supersede earlier ones by key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum LogRecord {
    Upsert {
        entry: LedgerEntry,
    },
    State {
        tx_id: String,
        state: EntryState,
        updated_at: u64,
    },
}

/// Result of allocating a collision-free timestamp for a genuinely new payment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllocateError {
    /// Too many intended-distinct payments share one `(sender, recipient, amount, fee)` tuple in a
    /// single freshness window; a distinct valid timestamp can no longer be scheduled. The caller
    /// must differentiate the payment (change the amount or fee) instead.
    ExhaustedTimestamps,
}

/// Outcome of checking an operator idempotency key + transaction against the durable ledger. This
/// is the full four-case idempotency contract that lets the node protect an exchange that supplies
/// a distinct withdrawal id per business operation:
///
/// | submission                              | outcome     |
/// |-----------------------------------------|-------------|
/// | new key, transaction never seen         | `New`       |
/// | same key, same transaction              | `Duplicate` |
/// | same key, different transaction         | `Conflict`  |
/// | new key, transaction already seen       | `Collision` |
///
/// The last case is the one nothing else can catch: two byte-identical transactions carrying two
/// *different* withdrawal ids are two distinct payments that collided on `sender:recipient:amount:
/// fee:timestamp`. Without the two ids the node cannot tell them from one transaction submitted
/// twice — which is exactly why the id has to come from the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmissionCheck {
    /// Neither the key nor the transaction has been seen; admit it, then `record`.
    New,
    /// This exact (key, transaction) pair is already recorded — an idempotent retry. Return the
    /// stored result rather than admitting again.
    Duplicate(LedgerEntry),
    /// The key is already bound to a DIFFERENT transaction (an attempted re-sign or duplicate under
    /// one withdrawal id). Reject and return the original so it cannot become a second payment.
    Conflict(LedgerEntry),
    /// The transaction is already recorded under a DIFFERENT key: two distinct withdrawals produced
    /// byte-identical transactions and collided. Reject so the caller re-signs the second one with a
    /// new timestamp. Carries the original owning entry.
    Collision(LedgerEntry),
}

#[derive(Clone, Debug)]
pub struct LedgerConfig {
    pub tx_age_limit_secs: u64,
    pub future_allocation_margin_secs: u64,
    pub retention_secs: u64,
    pub max_entries: usize,
    pub compaction_threshold_bytes: u64,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            tx_age_limit_secs: DEFAULT_TX_AGE_LIMIT_SECS,
            future_allocation_margin_secs: DEFAULT_FUTURE_ALLOCATION_MARGIN_SECS,
            retention_secs: DEFAULT_RETENTION_SECS,
            max_entries: DEFAULT_MAX_ENTRIES,
            compaction_threshold_bytes: DEFAULT_COMPACTION_THRESHOLD_BYTES,
        }
    }
}

#[derive(Debug)]
struct Inner {
    path: PathBuf,
    config: LedgerConfig,
    /// Live entries keyed by their primary key (idempotency key or tx id).
    entries: HashMap<String, LedgerEntry>,
    /// tx_id -> primary key, so a state update by transaction id finds its entry.
    tx_index: HashMap<String, String>,
    /// Highest timestamp allocated per collision tuple, for distinct-timestamp scheduling.
    tuple_last_ts: HashMap<PaymentTuple, u64>,
    /// Bytes appended to the log since the last compaction, to trigger compaction by size.
    log_len_bytes: u64,
}

/// Durable operator-side idempotency ledger. Cheap to clone the handle via `Arc`.
#[derive(Debug)]
pub struct WalletLedger {
    inner: Mutex<Inner>,
}

impl WalletLedger {
    /// Open (and replay) the ledger at `path`, creating it lazily on first write. A torn final log
    /// line from an interrupted append is discarded; an unreadable line before the end stops replay
    /// so recovery never silently drops committed middle records without evidence in the log.
    pub fn open(path: impl Into<PathBuf>, config: LedgerConfig) -> io::Result<Self> {
        let path = path.into();
        let mut inner = Inner {
            path,
            config,
            entries: HashMap::new(),
            tx_index: HashMap::new(),
            tuple_last_ts: HashMap::new(),
            log_len_bytes: 0,
        };
        inner.load()?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Allocate a collision-free timestamp for a genuinely new payment with `tuple`. Reserved in
    /// memory immediately under the lock so two concurrent allocations for the same tuple never
    /// return the same value; durability comes from `record`, which the caller must call before
    /// exposing or broadcasting the signed transaction.
    pub fn allocate_timestamp(&self, tuple: &PaymentTuple, now: u64) -> Result<u64, AllocateError> {
        let mut inner = self.inner.lock();
        let candidate = match inner.tuple_last_ts.get(tuple) {
            Some(last) => now.max(last.saturating_add(1)),
            None => now,
        };
        if candidate > now.saturating_add(inner.config.future_allocation_margin_secs) {
            return Err(AllocateError::ExhaustedTimestamps);
        }
        inner.tuple_last_ts.insert(tuple.clone(), candidate);
        Ok(candidate)
    }

    /// Evaluate the full four-case idempotency contract for an already-signed transaction submitted
    /// under `idempotency_key` (see [`SubmissionCheck`]). Refreshes expiry first so a stale pending
    /// entry is reported honestly. This does not mutate the ledger — the caller admits on `New` and
    /// then `record`s.
    pub fn check_submission(
        &self,
        idempotency_key: &str,
        tx_id: &str,
        now: u64,
    ) -> SubmissionCheck {
        let mut inner = self.inner.lock();
        inner.refresh_expiry(now);
        if let Some(entry) = inner.entries.get(idempotency_key) {
            return if entry.tx_id == tx_id {
                SubmissionCheck::Duplicate(entry.clone())
            } else {
                SubmissionCheck::Conflict(entry.clone())
            };
        }
        // The key is unseen. If this exact transaction is already owned by a DIFFERENT key, two
        // distinct withdrawals produced identical bytes and collided.
        if let Some(owner_key) = inner.tx_index.get(tx_id) {
            let owner_key = owner_key.clone();
            if owner_key != idempotency_key {
                if let Some(owner) = inner.entries.get(&owner_key) {
                    return SubmissionCheck::Collision(owner.clone());
                }
            }
        }
        SubmissionCheck::New
    }

    /// Durably record a reservation before the signed transaction is exposed. The primary key is
    /// the idempotency key when present, otherwise the transaction id (which is unique per payment).
    /// Re-recording the same key overwrites only when the transaction id matches, so a caller cannot
    /// silently repoint a key at a different payment; a mismatch is an error the caller surfaces.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        idempotency_key: Option<String>,
        tuple: PaymentTuple,
        timestamp: u64,
        tx_id: String,
        signed_tx: Option<String>,
        now: u64,
    ) -> io::Result<LedgerEntry> {
        let mut inner = self.inner.lock();
        let key = idempotency_key.clone().unwrap_or_else(|| tx_id.clone());
        if let Some(existing) = inner.entries.get(&key) {
            if existing.tx_id != tx_id {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "idempotency key already bound to a different transaction",
                ));
            }
            // Idempotent re-record of the same payment: return the durable original unchanged.
            return Ok(existing.clone());
        }
        // The key is new. Refuse to bind a transaction already owned by a different key: that is the
        // collision case, and recording it would silently overwrite the first owner. `record` fails
        // closed here even though `check_submission` should have already rejected it upstream.
        if let Some(owner_key) = inner.tx_index.get(&tx_id) {
            if owner_key != &key {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "transaction already recorded under a different idempotency key (collision)",
                ));
            }
        }
        let entry = LedgerEntry {
            key: key.clone(),
            idempotency_key,
            tuple: tuple.clone(),
            timestamp,
            tx_id: tx_id.clone(),
            signed_tx,
            state: EntryState::Pending,
            created_at: now,
            updated_at: now,
        };
        inner.append(&LogRecord::Upsert {
            entry: entry.clone(),
        })?;
        inner.index_entry(entry.clone());
        inner.maybe_compact()?;
        Ok(entry)
    }

    /// Update the recorded state of a transaction after observing an admission or confirmation
    /// outcome. Silently succeeds if the transaction is unknown (nothing to update).
    pub fn update_state(&self, tx_id: &str, state: EntryState, now: u64) -> io::Result<()> {
        let mut inner = self.inner.lock();
        let Some(key) = inner.tx_index.get(tx_id).cloned() else {
            return Ok(());
        };
        inner.append(&LogRecord::State {
            tx_id: tx_id.to_string(),
            state: state.clone(),
            updated_at: now,
        })?;
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.state = state;
            entry.updated_at = now;
        }
        inner.maybe_compact()?;
        Ok(())
    }

    /// Look up an entry by its operator idempotency key, refreshing expiry first.
    pub fn find_by_key(&self, idempotency_key: &str, now: u64) -> Option<LedgerEntry> {
        let mut inner = self.inner.lock();
        inner.refresh_expiry(now);
        inner.entries.get(idempotency_key).cloned()
    }

    /// Look up an entry by transaction id, refreshing expiry first.
    pub fn find_by_tx_id(&self, tx_id: &str, now: u64) -> Option<LedgerEntry> {
        let mut inner = self.inner.lock();
        inner.refresh_expiry(now);
        let key = inner.tx_index.get(tx_id).cloned()?;
        inner.entries.get(&key).cloned()
    }

    /// Prune terminal entries past the retention window or over the count cap, then compact.
    pub fn prune(&self, now: u64) -> io::Result<usize> {
        let mut inner = self.inner.lock();
        inner.refresh_expiry(now);
        let removed = inner.prune(now);
        if removed > 0 {
            inner.compact()?;
        }
        Ok(removed)
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner.lock().entries.len()
    }
}

impl Inner {
    fn load(&mut self) -> io::Result<()> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let reader = io::BufReader::new(file);
        let mut pending: Vec<LogRecord> = Vec::new();
        let mut total_bytes: u64 = 0;
        let mut lines = reader.lines().peekable();
        while let Some(line) = lines.next() {
            let line = line?;
            total_bytes = total_bytes.saturating_add(line.len() as u64 + 1);
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<LogRecord>(&line) {
                Ok(record) => pending.push(record),
                Err(_) if lines.peek().is_none() => {
                    // Only the final line may be a torn interrupted append; drop it and stop.
                    log::warn!("wallet ledger: discarding torn final log record");
                    break;
                }
                Err(e) => {
                    // A corrupt record before the end is not a clean interruption. Keep everything
                    // decoded so far and refuse to silently reinterpret the remainder.
                    log::error!("wallet ledger: stopping replay at unreadable record: {e}");
                    break;
                }
            }
        }
        for record in pending {
            self.apply(record);
        }
        self.log_len_bytes = total_bytes;
        Ok(())
    }

    fn apply(&mut self, record: LogRecord) {
        match record {
            LogRecord::Upsert { entry } => self.index_entry(entry),
            LogRecord::State {
                tx_id,
                state,
                updated_at,
            } => {
                if let Some(key) = self.tx_index.get(&tx_id).cloned() {
                    if let Some(entry) = self.entries.get_mut(&key) {
                        entry.state = state;
                        entry.updated_at = updated_at;
                    }
                }
            }
        }
    }

    fn index_entry(&mut self, entry: LedgerEntry) {
        let last = self
            .tuple_last_ts
            .get(&entry.tuple)
            .copied()
            .unwrap_or(0)
            .max(entry.timestamp);
        self.tuple_last_ts.insert(entry.tuple.clone(), last);
        // First-writer-wins: the transaction's owning key is the one that recorded it first. Never
        // overwrite it, or the collision signal (a repeat transaction under a new key) is lost.
        self.tx_index
            .entry(entry.tx_id.clone())
            .or_insert_with(|| entry.key.clone());
        self.entries.insert(entry.key.clone(), entry);
    }

    /// Transition still-pending entries whose transaction can no longer be valid to `Expired`. In
    /// memory only — the durable record is refreshed lazily by the next compaction, and expiry is
    /// re-derivable from the immutable timestamp on any reload, so it never needs its own log write.
    fn refresh_expiry(&mut self, now: u64) {
        let horizon = self.config.tx_age_limit_secs;
        for entry in self.entries.values_mut() {
            if matches!(entry.state, EntryState::Pending)
                && entry.timestamp.saturating_add(horizon) < now
            {
                entry.state = EntryState::Expired;
                entry.updated_at = now;
            }
        }
    }

    fn prune(&mut self, now: u64) -> usize {
        let retention = self.config.retention_secs;
        let before = self.entries.len();

        // Drop terminal entries past the retention window.
        let expired_keys: Vec<String> = self
            .entries
            .values()
            .filter(|e| e.state.is_terminal() && e.updated_at.saturating_add(retention) < now)
            .map(|e| e.key.clone())
            .collect();
        for key in expired_keys {
            self.remove_entry(&key);
        }

        // Enforce the hard count cap by dropping oldest terminal entries first; never evict a
        // pending entry, which still needs its idempotency guarantee.
        if self.entries.len() > self.config.max_entries {
            let mut terminal: Vec<(u64, String)> = self
                .entries
                .values()
                .filter(|e| e.state.is_terminal())
                .map(|e| (e.updated_at, e.key.clone()))
                .collect();
            terminal.sort_by_key(|(updated, _)| *updated);
            let overflow = self.entries.len() - self.config.max_entries;
            for (_, key) in terminal.into_iter().take(overflow) {
                self.remove_entry(&key);
            }
        }
        before - self.entries.len()
    }

    fn remove_entry(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            self.tx_index.remove(&entry.tx_id);
            // Keep tuple_last_ts: forgetting the last allocated timestamp for a tuple could let a
            // later same-tuple payment reuse a just-freed timestamp. It is bounded by distinct
            // live tuples and re-derived from surviving entries on reload.
        }
    }

    fn append(&mut self, record: &LogRecord) -> io::Result<()> {
        let mut line = serde_json::to_vec(record)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        line.push(b'\n');
        let mut file = open_append(&self.path)?;
        file.write_all(&line)?;
        file.flush()?;
        file.sync_all()?;
        self.log_len_bytes = self.log_len_bytes.saturating_add(line.len() as u64);
        Ok(())
    }

    fn maybe_compact(&mut self) -> io::Result<()> {
        if self.log_len_bytes > self.config.compaction_threshold_bytes {
            self.compact()?;
        }
        Ok(())
    }

    /// Rewrite the log as exactly one `Upsert` per live entry, atomically. Collapses superseded
    /// records and applies in-memory expiry transitions to the durable form.
    fn compact(&mut self) -> io::Result<()> {
        let mut buf = Vec::new();
        for entry in self.entries.values() {
            let mut line = serde_json::to_vec(&LogRecord::Upsert {
                entry: entry.clone(),
            })
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            line.push(b'\n');
            buf.extend_from_slice(&line);
        }
        atomic_write(&self.path, &buf)?;
        self.log_len_bytes = buf.len() as u64;
        Ok(())
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Atomic full-file replace: write a temp file, fsync it, rename over the target, then fsync the
/// parent directory so the rename itself survives power loss.
fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(data)?;
        file.flush()?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        if let Ok(dir) = File::open(&parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(amount: i128, fee: i128) -> PaymentTuple {
        PaymentTuple::new("alice".into(), "bob".into(), amount, fee)
    }

    fn ledger(path: &Path) -> WalletLedger {
        WalletLedger::open(path, LedgerConfig::default()).unwrap()
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        // Distinct per test process and name; tests never share a file.
        path.push(format!(
            "a9-wallet-ledger-{}-{}.log",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    // Regression guard: the tagged `LogRecord` decodes its content through serde's `Content`
    // buffer, which cannot hold `i128`. The `PaymentTuple` units must round-trip (as strings) or
    // every reload silently loses records — the failure mode this test was written against.
    #[test]
    fn logrecord_with_i128_tuple_roundtrips_through_json() {
        let entry = LedgerEntry {
            key: "k".into(),
            idempotency_key: Some("k".into()),
            tuple: tuple(500, 10_000),
            timestamp: 2_000,
            tx_id: "tx".into(),
            signed_tx: Some("BYTES".into()),
            state: EntryState::Pending,
            created_at: 2_000,
            updated_at: 2_000,
        };
        let record = LogRecord::Upsert { entry };
        let json = serde_json::to_string(&record).expect("serialize");
        let back: LogRecord = serde_json::from_str(&json).expect("deserialize");
        match back {
            LogRecord::Upsert { entry } => assert_eq!(entry.tx_id, "tx"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn distinct_same_tuple_payments_never_share_a_timestamp_in_one_second() {
        let path = temp_path("collision");
        let ledger = ledger(&path);
        let t = tuple(100, 10_000);

        // Three genuinely-new payments for the same (sender, recipient, amount, fee) at the same
        // wall-clock second must each get a distinct, strictly increasing timestamp.
        let a = ledger.allocate_timestamp(&t, 1_000).unwrap();
        let b = ledger.allocate_timestamp(&t, 1_000).unwrap();
        let c = ledger.allocate_timestamp(&t, 1_000).unwrap();
        assert_eq!((a, b, c), (1_000, 1_001, 1_002));

        // A different tuple is independent.
        let other = ledger
            .allocate_timestamp(&tuple(200, 10_000), 1_000)
            .unwrap();
        assert_eq!(other, 1_000);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn allocation_refuses_to_future_date_past_the_margin() {
        let path = temp_path("exhaust");
        let config = LedgerConfig {
            future_allocation_margin_secs: 2,
            ..Default::default()
        };
        let ledger = WalletLedger::open(&path, config).unwrap();
        let t = tuple(1, 10_000);
        assert_eq!(ledger.allocate_timestamp(&t, 100).unwrap(), 100);
        assert_eq!(ledger.allocate_timestamp(&t, 100).unwrap(), 101);
        assert_eq!(ledger.allocate_timestamp(&t, 100).unwrap(), 102);
        // 103 would exceed now (100) + margin (2); refuse rather than emit a future-dated timestamp.
        assert_eq!(
            ledger.allocate_timestamp(&t, 100),
            Err(AllocateError::ExhaustedTimestamps)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn submission_check_covers_all_four_idempotency_cases() {
        let path = temp_path("idem");
        let ledger = ledger(&path);
        let t = tuple(500, 10_000);
        let tx_a = "alice:bob:0.00000500:0.00010000:2000".to_string();
        let recorded = ledger
            .record(
                Some("withdrawal-A".into()),
                t.clone(),
                2_000,
                tx_a.clone(),
                Some("SIGNED_BYTES".into()),
                2_000,
            )
            .unwrap();

        // Case 1 — New: an unseen key with an unseen transaction.
        assert_eq!(
            ledger.check_submission(
                "withdrawal-B",
                "alice:bob:0.00000500:0.00010000:2001",
                2_005
            ),
            SubmissionCheck::New
        );
        // Case 2 — Duplicate: same key, same transaction (a safe retry of the same withdrawal).
        assert_eq!(
            ledger.check_submission("withdrawal-A", &tx_a, 2_005),
            SubmissionCheck::Duplicate(recorded.clone())
        );
        // Case 3 — Conflict: same key bound to a DIFFERENT transaction (attempted re-sign).
        match ledger.check_submission(
            "withdrawal-A",
            "alice:bob:0.00000500:0.00010000:2099",
            2_005,
        ) {
            SubmissionCheck::Conflict(original) => assert_eq!(original.tx_id, tx_a),
            other => panic!("expected conflict, got {other:?}"),
        }
        // Case 4 — Collision: a NEW key carrying the SAME transaction bytes as an existing key. Two
        // distinct withdrawals produced identical transactions — the case nothing else can detect,
        // and the bug the first-writer tx-index exists to catch.
        match ledger.check_submission("withdrawal-B", &tx_a, 2_005) {
            SubmissionCheck::Collision(owner) => {
                assert_eq!(owner.tx_id, tx_a);
                assert_eq!(owner.idempotency_key.as_deref(), Some("withdrawal-A"));
            }
            other => panic!("expected collision, got {other:?}"),
        }

        // The durable boundary fails closed on both dangerous cases too, not just the read check.
        assert_eq!(
            ledger
                .record(
                    Some("withdrawal-A".into()),
                    t.clone(),
                    2_099,
                    "alice:bob:0.00000500:0.00010000:2099".into(),
                    None,
                    2_006,
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists,
            "same key, different tx must be refused at record time"
        );
        assert_eq!(
            ledger
                .record(
                    Some("withdrawal-B".into()),
                    t,
                    2_000,
                    tx_a.clone(),
                    None,
                    2_006
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists,
            "new key, existing tx (collision) must be refused at record time"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn state_survives_restart_and_expiry_is_rederived() {
        let path = temp_path("restart");
        let tx_id = "alice:bob:0.00000500:0.00010000:3000".to_string();
        {
            let ledger = ledger(&path);
            ledger
                .record(
                    Some("w-1".into()),
                    tuple(500, 10_000),
                    3_000,
                    tx_id.clone(),
                    Some("BYTES".into()),
                    3_000,
                )
                .unwrap();
            ledger
                .update_state(&tx_id, EntryState::Confirmed { height: 12 }, 3_100)
                .unwrap();
        }
        // Reopen from the on-disk log only.
        let reopened = ledger(&path);
        let entry = reopened.find_by_key("w-1", 3_200).unwrap();
        assert_eq!(entry.state, EntryState::Confirmed { height: 12 });
        assert_eq!(entry.signed_tx.as_deref(), Some("BYTES"));

        // A pending entry whose freshness window has elapsed reads back as Expired without any
        // extra durable write, purely from its immutable timestamp.
        reopened
            .record(
                Some("w-2".into()),
                tuple(600, 10_000),
                3_000,
                "alice:bob:0.00000600:0.00010000:3000".into(),
                None,
                3_000,
            )
            .unwrap();
        let expired = reopened
            .find_by_key("w-2", 3_000 + DEFAULT_TX_AGE_LIMIT_SECS + 1)
            .unwrap();
        assert_eq!(expired.state, EntryState::Expired);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_torn_final_append_is_discarded_and_earlier_records_survive() {
        let path = temp_path("torn");
        {
            let ledger = ledger(&path);
            ledger
                .record(
                    Some("good".into()),
                    tuple(1, 10_000),
                    4_000,
                    "alice:bob:0.00000001:0.00010000:4000".into(),
                    None,
                    4_000,
                )
                .unwrap();
        }
        // Simulate a crash mid-append: a partial JSON line with no newline at the end of the log.
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(b"{\"op\":\"upsert\",\"entry\":{\"key\":\"trunc")
                .unwrap();
            file.sync_all().unwrap();
        }
        let reopened = ledger(&path);
        assert!(reopened.find_by_key("good", 4_100).is_some());
        assert_eq!(reopened.entry_count(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn compaction_collapses_superseded_records_and_preserves_state() {
        let path = temp_path("compact");
        // Force compaction on the first state update.
        let config = LedgerConfig {
            compaction_threshold_bytes: 1,
            ..Default::default()
        };
        let ledger = WalletLedger::open(&path, config).unwrap();
        let tx_id = "alice:bob:0.00000700:0.00010000:5000".to_string();
        ledger
            .record(
                Some("c-1".into()),
                tuple(700, 10_000),
                5_000,
                tx_id.clone(),
                None,
                5_000,
            )
            .unwrap();
        ledger
            .update_state(&tx_id, EntryState::Confirmed { height: 7 }, 5_050)
            .unwrap();
        // After compaction the log holds exactly one collapsed record (the confirmed upsert), not
        // the original pending upsert plus an appended state record.
        let lines = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .count();
        assert_eq!(
            lines, 1,
            "compaction must collapse the append trail to one record"
        );

        let reopened = ledger_from(&path, 1);
        assert_eq!(
            reopened.find_by_key("c-1", 5_100).unwrap().state,
            EntryState::Confirmed { height: 7 }
        );
        assert_eq!(reopened.entry_count(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn prune_drops_old_terminal_entries_but_keeps_pending() {
        let path = temp_path("prune");
        let config = LedgerConfig {
            retention_secs: 100,
            ..Default::default()
        };
        let ledger = WalletLedger::open(&path, config).unwrap();

        let confirmed_tx = "alice:bob:0.00000001:0.00010000:6000".to_string();
        ledger
            .record(
                Some("old".into()),
                tuple(1, 10_000),
                6_000,
                confirmed_tx.clone(),
                None,
                6_000,
            )
            .unwrap();
        ledger
            .update_state(&confirmed_tx, EntryState::Confirmed { height: 1 }, 6_000)
            .unwrap();
        ledger
            .record(
                Some("live".into()),
                tuple(2, 10_000),
                9_000,
                "alice:bob:0.00000002:0.00010000:9000".into(),
                None,
                9_000,
            )
            .unwrap();

        // Well past the confirmed entry's retention window, but the pending one is always kept.
        let removed = ledger.prune(6_000 + 1_000).unwrap();
        assert_eq!(removed, 1);
        assert!(ledger.find_by_key("old", 7_100).is_none());
        assert!(ledger.find_by_key("live", 7_100).is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrent_allocation_for_one_tuple_yields_all_distinct_timestamps() {
        use std::sync::Arc;
        let path = temp_path("concurrent");
        let ledger = Arc::new(ledger(&path));
        const THREADS: usize = 16;
        let barrier = Arc::new(std::sync::Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let ledger = Arc::clone(&ledger);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    ledger.allocate_timestamp(&tuple(1, 10_000), 8_000).unwrap()
                })
            })
            .collect();
        let mut stamps: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        stamps.sort_unstable();
        stamps.dedup();
        assert_eq!(stamps.len(), THREADS, "every allocation must be unique");
        let _ = std::fs::remove_file(&path);
    }

    fn ledger_from(path: &Path, compaction_threshold_bytes: u64) -> WalletLedger {
        let config = LedgerConfig {
            compaction_threshold_bytes,
            ..Default::default()
        };
        WalletLedger::open(path, config).unwrap()
    }
}
