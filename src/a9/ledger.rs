//! Durable operator-side payment idempotency and uniqueness ledger.
//!
//! This is purely operator/wallet-side state. It changes NO transaction field, signed message,
//! transaction ID, codec, Merkle calculation, block, consensus rule, network message, or chain
//! database format. It never appears on the wire or in the chain database.
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
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
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
/// Hard ceiling on the serialized live snapshot. API entries omit the caller-owned signed body;
/// local entries retain it for recovery, so a count-only cap would still permit multi-gigabyte
/// compactions with ML-DSA witnesses.
pub const DEFAULT_MAX_LIVE_BYTES: usize = 256 * 1024 * 1024;
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
    /// Durably reserved before the first admission attempt. A retry of this exact operation may
    /// safely attempt canonical admission; no different transaction may reuse the key.
    Reserved,
    /// Admitted to a mempool and not yet known-terminal.
    Pending,
    /// Observed confirmed at the given height.
    Confirmed { height: u32 },
    /// Definitively rejected for a reason that is a pure function of the transaction bytes.
    Rejected { reason: String },
    /// The original transaction can no longer be valid under the freshness window.
    Expired,
    /// The transaction was already pending or confirmed before this node could attribute it to the
    /// supplied key. It may be the caller's earlier submission or a distinct colliding withdrawal;
    /// the node must never guess which.
    AmbiguousExisting,
}

impl EntryState {
    /// A terminal state can be pruned once old enough. Reserved, pending, and ambiguous entries are
    /// retained: none is safe to forget while the payment may still be live or unattributed.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            EntryState::Confirmed { .. } | EntryState::Rejected { .. } | EntryState::Expired
        )
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
    Delete {
        key: String,
        tx_id: String,
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
    /// Neither the key nor the transaction has been seen; durably `record` it, then admit it.
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
    pub max_live_bytes: usize,
    pub compaction_threshold_bytes: u64,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            tx_age_limit_secs: DEFAULT_TX_AGE_LIMIT_SECS,
            future_allocation_margin_secs: DEFAULT_FUTURE_ALLOCATION_MARGIN_SECS,
            retention_secs: DEFAULT_RETENTION_SECS,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_live_bytes: DEFAULT_MAX_LIVE_BYTES,
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
    /// Conservative count of uncompacted log bytes. Reset to zero after a successful compaction;
    /// initialized to the on-disk length after restart so a large append trail compacts once on the
    /// next mutation instead of compacting after every write forever.
    uncompacted_bytes: u64,
    /// Cached serialized `Upsert` snapshot bytes for live entries, including newlines. Lifecycle
    /// transitions can change an entry's encoded size, so write paths recompute this value before
    /// enforcing the hard byte ceiling.
    live_bytes: usize,
    /// Separate process lock. Locking the data file itself prevents atomic replacement on Windows.
    _lock_file: File,
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
        let lock_path = lock_path_for(&path);
        let lock_file = open_lock_file(&lock_path)?;
        fs2::FileExt::try_lock_exclusive(&lock_file).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "wallet ledger is already open by another process ({}): {error}",
                    lock_path.display()
                ),
            )
        })?;
        let mut inner = Inner {
            path,
            config,
            entries: HashMap::new(),
            tx_index: HashMap::new(),
            tuple_last_ts: HashMap::new(),
            uncompacted_bytes: 0,
            live_bytes: 0,
            _lock_file: lock_file,
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
    /// entry is reported honestly. This does not durably mutate the ledger — the caller must
    /// `record` the reservation on `New` before attempting canonical admission.
    pub fn check_submission(
        &self,
        idempotency_key: &str,
        tx_id: &str,
        now: u64,
    ) -> SubmissionCheck {
        let mut inner = self.inner.lock();
        inner.refresh_expiry(now);
        let key = primary_key(Some(idempotency_key), tx_id);
        if let Some(entry) = inner.entries.get(&key) {
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
            if owner_key != key {
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
        let key = primary_key(idempotency_key.as_deref(), &tx_id);
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
        inner.refresh_expiry(now);
        inner.recalculate_live_bytes()?;
        // Enforce the advertised hard cap on the write path. Prefer dropping the oldest terminal
        // entries, but never evict an operation that can still pay.
        let new_entry = LedgerEntry {
            key: key.clone(),
            idempotency_key,
            tuple: tuple.clone(),
            timestamp,
            tx_id: tx_id.clone(),
            signed_tx,
            state: EntryState::Reserved,
            created_at: now,
            updated_at: now,
        };
        let new_entry_bytes = encoded_upsert_len(&new_entry)?;
        if new_entry_bytes > inner.config.max_live_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "one wallet-ledger entry exceeds the live-byte ceiling",
            ));
        }
        let target_entries = inner.config.max_entries.saturating_sub(1);
        let target_bytes = inner.config.max_live_bytes.saturating_sub(new_entry_bytes);
        inner.prune_durable(now, target_entries, target_bytes)?;
        if inner.entries.len() >= inner.config.max_entries {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "wallet ledger capacity exhausted by non-terminal payments",
            ));
        }
        if inner.live_bytes > target_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "wallet ledger live-byte capacity exhausted by non-terminal payments",
            ));
        }
        let entry = new_entry;
        inner.append(&LogRecord::Upsert {
            entry: entry.clone(),
        })?;
        inner.index_entry(entry.clone())?;
        inner.maybe_compact_best_effort();
        Ok(entry)
    }

    /// Remove a never-admitted reservation after canonical admission definitively failed. The
    /// `(key, tx_id)` pair must still own the entry, so this cannot delete a later replacement.
    pub fn release_reservation(&self, idempotency_key: &str, tx_id: &str) -> io::Result<bool> {
        let mut inner = self.inner.lock();
        let key = primary_key(Some(idempotency_key), tx_id);
        inner.release_reservation(&key, tx_id)
    }

    /// Remove a locally-created signed reservation that the operator explicitly cancelled before
    /// admission. This is intentionally separate from API-key release so the namespaces cannot
    /// alias even when a caller chooses a transaction-looking key.
    pub fn release_local_reservation(&self, tx_id: &str) -> io::Result<bool> {
        let mut inner = self.inner.lock();
        let key = primary_key(None, tx_id);
        inner.release_reservation(&key, tx_id)
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
        inner.maybe_compact_best_effort();
        Ok(())
    }

    /// Look up an entry by its operator idempotency key, refreshing expiry first.
    pub fn find_by_key(&self, idempotency_key: &str, now: u64) -> Option<LedgerEntry> {
        let mut inner = self.inner.lock();
        inner.refresh_expiry(now);
        inner
            .entries
            .get(&primary_key(Some(idempotency_key), ""))
            .cloned()
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
        inner.recalculate_live_bytes()?;
        let target = inner.config.max_entries;
        let target_bytes = inner.config.max_live_bytes;
        inner.prune_durable(now, target, target_bytes)
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner.lock().entries.len()
    }

    #[cfg(test)]
    pub(crate) fn set_data_path_for_test(&self, path: PathBuf) {
        self.inner.lock().path = path;
    }
}

impl Inner {
    fn release_reservation(&mut self, key: &str, tx_id: &str) -> io::Result<bool> {
        let Some(entry) = self.entries.get(key) else {
            return Ok(false);
        };
        if entry.tx_id != tx_id || !matches!(entry.state, EntryState::Reserved) {
            return Ok(false);
        }
        self.append(&LogRecord::Delete {
            key: key.to_string(),
            tx_id: tx_id.to_string(),
        })?;
        self.remove_entry(key);
        self.maybe_compact_best_effort();
        Ok(true)
    }
    fn load(&mut self) -> io::Result<()> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => {
                // Upgrade ledgers created by older releases to the same operator-only mode used
                // for new files. Withdrawal identifiers are operationally sensitive even though
                // the signed transactions themselves are public.
                set_restrictive_permissions(&self.path)?;
                bytes
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut offset = 0usize;
        while offset < bytes.len() {
            if let Some(relative_end) = bytes[offset..].iter().position(|byte| *byte == b'\n') {
                let end = offset + relative_end;
                let line = &bytes[offset..end];
                offset = end + 1;
                if line.is_empty() {
                    continue;
                }
                let record = serde_json::from_slice::<LogRecord>(line).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("corrupt complete wallet-ledger record: {error}"),
                    )
                })?;
                self.apply(record)?;
                continue;
            }

            // A final record without a newline is either complete (the crash landed between the
            // JSON and newline writes) or torn. Accept and repair a complete record; truncate only
            // an invalid unterminated tail. A malformed newline-terminated final record above is
            // corruption and fails open(), never masquerading as a recoverable tear.
            let tail = &bytes[offset..];
            if !tail.is_empty() {
                match serde_json::from_slice::<LogRecord>(tail) {
                    Ok(record) => {
                        self.apply(record)?;
                        let mut file = OpenOptions::new().append(true).open(&self.path)?;
                        file.write_all(b"\n")?;
                        file.sync_all()?;
                        offset = bytes.len().saturating_add(1);
                    }
                    Err(_) => {
                        log::warn!("wallet ledger: repairing torn final log record");
                        let file = OpenOptions::new().write(true).open(&self.path)?;
                        file.set_len(offset as u64)?;
                        file.sync_all()?;
                    }
                }
            }
            break;
        }
        self.uncompacted_bytes = offset as u64;
        self.recalculate_live_bytes()?;
        Ok(())
    }

    fn apply(&mut self, record: LogRecord) -> io::Result<()> {
        match record {
            LogRecord::Upsert { mut entry } => {
                // Normalize records written by the initial release, which used un-namespaced map
                // keys. Namespaces prevent a caller-chosen idempotency key from aliasing a local
                // transaction-id key.
                entry.key = primary_key(entry.idempotency_key.as_deref(), &entry.tx_id);
                if self
                    .entries
                    .get(&entry.key)
                    .is_some_and(|existing| existing.tx_id != entry.tx_id)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "wallet ledger key is bound to multiple transactions",
                    ));
                }
                if self
                    .tx_index
                    .get(&entry.tx_id)
                    .is_some_and(|owner| owner != &entry.key)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "wallet ledger transaction is bound to multiple keys",
                    ));
                }
                self.index_entry(entry)?;
            }
            LogRecord::State {
                tx_id,
                state,
                updated_at,
            } => {
                let key = self.tx_index.get(&tx_id).cloned().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "wallet ledger state record references an unknown transaction",
                    )
                })?;
                let entry = self.entries.get_mut(&key).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "wallet ledger transaction index references an unknown entry",
                    )
                })?;
                entry.state = state;
                entry.updated_at = updated_at;
            }
            LogRecord::Delete { key, tx_id } => {
                let key = if key.starts_with("idempotency:") || key.starts_with("transaction:") {
                    key
                } else if self
                    .entries
                    .get(&key)
                    .and_then(|entry| entry.idempotency_key.as_ref())
                    .is_some()
                {
                    format!("idempotency:{key}")
                } else {
                    format!("transaction:{key}")
                };
                if self
                    .entries
                    .get(&key)
                    .is_some_and(|entry| entry.tx_id == tx_id)
                {
                    self.remove_entry(&key);
                }
            }
        }
        Ok(())
    }

    fn index_entry(&mut self, entry: LedgerEntry) -> io::Result<()> {
        let last = self
            .tuple_last_ts
            .get(&entry.tuple)
            .copied()
            .unwrap_or(0)
            .max(entry.timestamp);
        self.tuple_last_ts.insert(entry.tuple.clone(), last);
        // First-writer-wins: the transaction's owning key is the one that recorded it first. Never
        // overwrite it, or the collision signal (a repeat transaction under a new key) is lost.
        let encoded_len = encoded_upsert_len(&entry)?;
        if let Some(previous) = self.entries.get(&entry.key) {
            self.live_bytes = self
                .live_bytes
                .saturating_sub(encoded_upsert_len(previous)?);
        }
        self.tx_index.insert(entry.tx_id.clone(), entry.key.clone());
        self.entries.insert(entry.key.clone(), entry);
        self.live_bytes = self.live_bytes.saturating_add(encoded_len);
        Ok(())
    }

    fn recalculate_live_bytes(&mut self) -> io::Result<()> {
        self.live_bytes = self.entries.values().try_fold(0usize, |total, entry| {
            encoded_upsert_len(entry).map(|encoded_len| total.saturating_add(encoded_len))
        })?;
        Ok(())
    }

    /// Transition still-pending entries whose transaction can no longer be valid to `Expired`. In
    /// memory only — the durable record is refreshed lazily by the next compaction, and expiry is
    /// re-derivable from the immutable timestamp on any reload, so it never needs its own log write.
    fn refresh_expiry(&mut self, now: u64) {
        let horizon = self.config.tx_age_limit_secs;
        for entry in self.entries.values_mut() {
            if matches!(entry.state, EntryState::Reserved | EntryState::Pending)
                && entry.timestamp.saturating_add(horizon) < now
            {
                entry.state = EntryState::Expired;
                entry.updated_at = now;
            }
        }
    }

    fn prune_keys(
        &self,
        now: u64,
        target_max_entries: usize,
        target_max_bytes: usize,
    ) -> io::Result<HashSet<String>> {
        let retention = self.config.retention_secs;
        let mut removed: HashSet<String> = self
            .entries
            .values()
            .filter(|e| e.state.is_terminal() && e.updated_at.saturating_add(retention) < now)
            .map(|e| e.key.clone())
            .collect();

        let remaining = self.entries.len().saturating_sub(removed.len());
        if remaining > target_max_entries {
            let mut terminal: Vec<(u64, String)> = self
                .entries
                .values()
                .filter(|e| e.state.is_terminal() && !removed.contains(&e.key))
                .map(|e| (e.updated_at, e.key.clone()))
                .collect();
            terminal.sort_by_key(|(updated, _)| *updated);
            let overflow = remaining - target_max_entries;
            for (_, key) in terminal.into_iter().take(overflow) {
                removed.insert(key);
            }
        }

        let mut remaining_bytes = self.live_bytes;
        for key in &removed {
            if let Some(entry) = self.entries.get(key) {
                remaining_bytes = remaining_bytes.saturating_sub(encoded_upsert_len(entry)?);
            }
        }
        if remaining_bytes > target_max_bytes {
            let mut terminal: Vec<(u64, String)> = self
                .entries
                .values()
                .filter(|entry| entry.state.is_terminal() && !removed.contains(&entry.key))
                .map(|entry| (entry.updated_at, entry.key.clone()))
                .collect();
            terminal.sort_by_key(|(updated, _)| *updated);
            for (_, key) in terminal {
                if remaining_bytes <= target_max_bytes {
                    break;
                }
                if let Some(entry) = self.entries.get(&key) {
                    remaining_bytes = remaining_bytes.saturating_sub(encoded_upsert_len(entry)?);
                    removed.insert(key);
                }
            }
        }
        Ok(removed)
    }

    fn prune_durable(
        &mut self,
        now: u64,
        target_max_entries: usize,
        target_max_bytes: usize,
    ) -> io::Result<usize> {
        let removed = self.prune_keys(now, target_max_entries, target_max_bytes)?;
        if removed.is_empty() {
            return Ok(0);
        }
        // Persist each deletion before applying it in memory. Rewriting a snapshot that excludes
        // all victims first would create disk/memory disagreement if rename succeeded but the
        // parent-directory fsync reported failure. Partial pruning is harmless and replayable;
        // admitting a new payment waits until the entire requested capacity operation succeeds.
        let mut removed = removed.into_iter().collect::<Vec<_>>();
        removed.sort_unstable();
        let mut count = 0usize;
        for key in removed {
            let Some(entry) = self.entries.get(&key) else {
                continue;
            };
            let tx_id = entry.tx_id.clone();
            self.append(&LogRecord::Delete {
                key: key.clone(),
                tx_id,
            })?;
            self.remove_entry(&key);
            count = count.saturating_add(1);
        }
        self.tuple_last_ts.retain(|_, timestamp| *timestamp >= now);
        self.maybe_compact_best_effort();
        Ok(count)
    }

    fn remove_entry(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            if let Ok(encoded_len) = encoded_upsert_len(&entry) {
                self.live_bytes = self.live_bytes.saturating_sub(encoded_len);
            }
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
        let file_existed = match std::fs::metadata(&self.path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let mut file = open_append(&self.path)?;
        file.write_all(&line)?;
        file.flush()?;
        file.sync_all()?;
        // fsyncing a newly-created file does not by itself make its directory entry durable. The
        // first reservation must survive power loss before a caller is ever told it was accepted.
        if !file_existed {
            sync_parent_directory(&self.path)?;
        }
        self.uncompacted_bytes = self.uncompacted_bytes.saturating_add(line.len() as u64);
        Ok(())
    }

    fn maybe_compact_best_effort(&mut self) {
        if self.uncompacted_bytes > self.config.compaction_threshold_bytes {
            if let Err(error) = self.compact() {
                // The append/state transition is already fsynced and authoritative. Returning an
                // error now would falsely tell a caller the operation failed and could induce a
                // second payment. Compaction is maintenance; surface it loudly without lying about
                // the committed mutation.
                log::error!("wallet ledger compaction failed after committed append: {error}");
            }
        }
    }

    /// Rewrite the log as exactly one `Upsert` per live entry, atomically. Collapses superseded
    /// records and applies in-memory expiry transitions to the durable form.
    fn compact(&mut self) -> io::Result<()> {
        let path = self.path.clone();
        atomic_replace(&path, |file| {
            for entry in self.entries.values() {
                serde_json::to_writer(
                    &mut *file,
                    &LogRecord::Upsert {
                        entry: entry.clone(),
                    },
                )
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                file.write_all(b"\n")?;
            }
            Ok(())
        })?;
        self.uncompacted_bytes = 0;
        Ok(())
    }
}

fn primary_key(idempotency_key: Option<&str>, tx_id: &str) -> String {
    match idempotency_key {
        Some(key) => format!("idempotency:{key}"),
        None => format!("transaction:{tx_id}"),
    }
}

fn encoded_upsert_len(entry: &LedgerEntry) -> io::Result<usize> {
    serde_json::to_vec(&LogRecord::Upsert {
        entry: entry.clone(),
    })
    .map(|encoded| encoded.len().saturating_add(1))
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn lock_path_for(path: &Path) -> PathBuf {
    let mut path = path.as_os_str().to_os_string();
    path.push(".lock");
    PathBuf::from(path)
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    set_restrictive_permissions(path)?;
    Ok(file)
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    set_restrictive_permissions(path)?;
    Ok(file)
}

fn set_restrictive_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    // Windows: NTFS ACLs are not applied here (same as the wallet key helper);
    // the parameter is only consumed on unix, so name the fact for the linter.
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        File::open(parent)?.sync_all()?;
    }
    // Windows has no directory fsync; the rename is already durable enough there.
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Atomic full-file replace: stream a temp file, fsync it, rename over the target, then fsync the
/// parent directory so the rename itself survives power loss. Streaming avoids allocating a second
/// in-memory copy of the bounded-but-potentially-large live ledger.
fn atomic_replace<F>(path: &Path, write_contents: F) -> io::Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
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
        set_restrictive_permissions(&tmp)?;
        write_contents(&mut file)?;
        file.flush()?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    sync_parent_directory(path)?;
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
        let _ = std::fs::remove_file(lock_path_for(&path));
        path
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(lock_path_for(path));
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
        // The repair must truncate the bad tail, not merely ignore it in memory. A later append and
        // second restart must therefore preserve both valid records.
        reopened
            .record(
                Some("after-repair".into()),
                tuple(2, 10_000),
                4_001,
                "alice:bob:0.00000002:0.00010000:4001".into(),
                None,
                4_001,
            )
            .unwrap();
        drop(reopened);
        let second_restart = ledger(&path);
        assert!(second_restart.find_by_key("good", 4_100).is_some());
        assert!(second_restart.find_by_key("after-repair", 4_100).is_some());
        drop(second_restart);
        cleanup(&path);
    }

    #[test]
    fn complete_corrupt_record_fails_closed_including_at_end_of_file() {
        let path = temp_path("complete-corrupt");
        std::fs::write(&path, b"{not-json}\n").unwrap();
        let error = WalletLedger::open(&path, LedgerConfig::default()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        cleanup(&path);
    }

    #[test]
    fn a_complete_final_record_without_newline_is_accepted_and_repaired() {
        let path = temp_path("complete-no-newline");
        let entry = LedgerEntry {
            key: "legacy-key".into(),
            idempotency_key: Some("complete-key".into()),
            tuple: tuple(1, 10_000),
            timestamp: 4_000,
            tx_id: "complete-tx".into(),
            signed_tx: None,
            state: EntryState::Pending,
            created_at: 4_000,
            updated_at: 4_000,
        };
        std::fs::write(
            &path,
            serde_json::to_vec(&LogRecord::Upsert { entry }).unwrap(),
        )
        .unwrap();
        let opened = ledger(&path);
        assert!(opened.find_by_key("complete-key", 4_001).is_some());
        assert!(std::fs::read(&path).unwrap().ends_with(b"\n"));
        drop(opened);
        cleanup(&path);
    }

    #[test]
    fn a_second_process_handle_cannot_open_the_same_ledger() {
        let path = temp_path("exclusive-lock");
        let first = ledger(&path);
        let error = WalletLedger::open(&path, LedgerConfig::default()).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Other
        ));
        drop(first);
        assert!(WalletLedger::open(&path, LedgerConfig::default()).is_ok());
        cleanup(&path);
    }

    #[test]
    fn idempotency_and_local_transaction_keys_have_disjoint_namespaces() {
        let path = temp_path("key-namespace");
        let ledger = ledger(&path);
        let local_tx_id = "caller-controlled-looking-key";
        ledger
            .record(None, tuple(1, 10_000), 10, local_tx_id.into(), None, 10)
            .unwrap();
        ledger
            .record(
                Some(local_tx_id.into()),
                tuple(2, 10_000),
                11,
                "different-tx".into(),
                None,
                11,
            )
            .unwrap();
        assert_eq!(ledger.entry_count(), 2);
        cleanup(&path);
    }

    #[test]
    fn write_path_enforces_the_hard_entry_cap_without_evicting_live_operations() {
        let path = temp_path("entry-cap");
        let config = LedgerConfig {
            max_entries: 2,
            ..Default::default()
        };
        let ledger = WalletLedger::open(&path, config).unwrap();
        for index in 0..2 {
            ledger
                .record(
                    Some(format!("key-{index}")),
                    tuple(index, 10_000),
                    100 + index as u64,
                    format!("tx-{index}"),
                    None,
                    100,
                )
                .unwrap();
        }
        let error = ledger
            .record(
                Some("key-overflow".into()),
                tuple(9, 10_000),
                109,
                "tx-overflow".into(),
                None,
                100,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        assert_eq!(ledger.entry_count(), 2);
        cleanup(&path);
    }

    #[test]
    fn write_path_enforces_the_live_byte_cap_and_evicts_only_terminal_entries() {
        let path = temp_path("byte-cap");
        let first_key = "idempotency:first".to_string();
        let second_key = "idempotency:second".to_string();
        let first_tx = "tx-first".to_string();
        let second_tx = "tx-second".to_string();
        let first = LedgerEntry {
            key: first_key,
            idempotency_key: Some("first".into()),
            tuple: tuple(1, 10_000),
            timestamp: 100,
            tx_id: first_tx.clone(),
            signed_tx: Some("x".repeat(512)),
            state: EntryState::Reserved,
            created_at: 100,
            updated_at: 100,
        };
        let second = LedgerEntry {
            key: second_key,
            idempotency_key: Some("second".into()),
            tuple: tuple(2, 10_000),
            timestamp: 101,
            tx_id: second_tx.clone(),
            signed_tx: Some("y".repeat(512)),
            state: EntryState::Reserved,
            created_at: 101,
            updated_at: 101,
        };
        let max_live_bytes = encoded_upsert_len(&first)
            .unwrap()
            .max(encoded_upsert_len(&second).unwrap());
        let config = LedgerConfig {
            // Either entry fits alone; the pair cannot fit together.
            max_live_bytes,
            ..Default::default()
        };
        let ledger = WalletLedger::open(&path, config).unwrap();
        ledger
            .record(
                Some("first".into()),
                first.tuple.clone(),
                first.timestamp,
                first_tx.clone(),
                first.signed_tx.clone(),
                first.created_at,
            )
            .unwrap();

        // A live reservation is never evicted just to make capacity.
        let full = ledger
            .record(
                Some("second".into()),
                second.tuple.clone(),
                second.timestamp,
                second_tx.clone(),
                second.signed_tx.clone(),
                second.created_at,
            )
            .unwrap_err();
        assert_eq!(full.kind(), io::ErrorKind::StorageFull);
        assert!(ledger.find_by_key("first", 101).is_some());

        // Once terminal, the oldest entry may be durably pruned and the new reservation admitted.
        ledger
            .update_state(&first_tx, EntryState::Confirmed { height: 1 }, 101)
            .unwrap();
        ledger
            .record(
                Some("second".into()),
                second.tuple,
                second.timestamp,
                second_tx,
                second.signed_tx,
                second.created_at,
            )
            .unwrap();
        assert!(ledger.find_by_key("first", 101).is_none());
        assert!(ledger.find_by_key("second", 101).is_some());
        drop(ledger);

        let reopened = WalletLedger::open(
            &path,
            LedgerConfig {
                max_live_bytes,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(reopened.find_by_key("first", 101).is_none());
        assert!(reopened.find_by_key("second", 101).is_some());
        drop(reopened);
        cleanup(&path);
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

        drop(ledger);
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
                6_001,
                "alice:bob:0.00000002:0.00010000:6001".into(),
                None,
                6_001,
            )
            .unwrap();
        let ambiguous_tx = "alice:bob:0.00000003:0.00010000:6002".to_string();
        ledger
            .record(
                Some("ambiguous".into()),
                tuple(3, 10_000),
                6_002,
                ambiguous_tx.clone(),
                None,
                6_002,
            )
            .unwrap();
        ledger
            .update_state(&ambiguous_tx, EntryState::AmbiguousExisting, 6_002)
            .unwrap();

        // Well past the confirmed entry's retention window, but live and ambiguous operations are
        // always kept because either may still represent a payment.
        let removed = ledger.prune(6_000 + 1_000).unwrap();
        assert_eq!(removed, 1);
        assert!(ledger.find_by_key("old", 7_100).is_none());
        assert!(ledger.find_by_key("live", 7_100).is_some());
        assert!(ledger.find_by_key("ambiguous", 7_100).is_some());
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
