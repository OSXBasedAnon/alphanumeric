//! The chain's storage engine boundary: a thin, semantics-preserving wrapper
//! over redb that mirrors the exact sled surface the node was built on, so the
//! engine swap is mechanical at call sites and every durability property is
//! decided in ONE place.
//!
//! Semantics contract (mirrors the node's sled discipline):
//! - Mutations (`insert`/`remove`/`apply_batch`) commit with `Durability::None`:
//!   immediately visible to readers, made crash-durable by the NEXT durable
//!   commit — exactly sled's write-then-`flush()` model, so the dirty-marker
//!   protocol's ordering guarantees carry over unchanged.
//! - `flush()` (on the store or any tree) is one empty `Durability::Immediate`
//!   commit: everything committed before it becomes durable. A tree flush is a
//!   full-store fsync, as it was in sled's single shared log.
//! - `apply_batch` is one transaction: all-or-nothing under crash, the property
//!   the balances-plus-marker write depends on.
//! - Writers are serialized through one mutex (redb is single-writer; the lock
//!   makes contention explicit and fair instead of implicit inside redb).

use parking_lot::Mutex;
use redb::{
    Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    TableHandle,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "store: {}", self.0)
    }
}
impl std::error::Error for StoreError {}

macro_rules! from_err {
    ($($t:ty),+) => {$(
        impl From<$t> for StoreError {
            fn from(e: $t) -> Self {
                StoreError(e.to_string())
            }
        }
    )+};
}
from_err!(
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError,
    redb::SetDurabilityError,
    std::io::Error
);

pub type Result<T> = std::result::Result<T, StoreError>;
pub type KvPair = (Vec<u8>, Vec<u8>);

/// Physical-vs-logical space accounting (see `Store::space_stats`).
#[derive(Clone, Copy, Debug)]
pub struct SpaceStats {
    pub file_bytes: u64,
    pub stored_bytes: u64,
    pub fragmented_bytes: u64,
}

/// Table definitions require `&'static str` names; the chain's tree names are a
/// small fixed set, so leak-once interning is bounded and permanent by design.
fn interned(name: &str) -> &'static str {
    static NAMES: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let names = NAMES.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = names.lock();
    if let Some(existing) = guard.get(name) {
        existing
    } else {
        let leaked: &'static str = Box::leak(name.to_owned().into_boxed_str());
        guard.insert(leaked);
        leaked
    }
}

/// Exclusive-end bound for a prefix scan: the prefix with its last non-0xff
/// byte incremented (shorter tail truncated). All-0xff prefixes are unbounded.
fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xff {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

/// Table name for the default tree — the namespace sled's `Db` deref exposed.
/// Fresh redb stores are ours to name; the converter maps sled's default tree
/// here.
pub const DEFAULT_TREE: &str = "__default__";

struct Inner {
    db: redb::Database,
    path: PathBuf,
    write_lock: Mutex<()>,
    temporary: bool,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if self.temporary {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
    default_tree: OnceLock<Box<Tree>>,
}

/// sled's `Db` dereferenced to its default tree, and the node leans on that
/// (`self.db.get("block_…")`). Preserving the deref keeps those call sites
/// byte-identical across the engine swap. Boxed to break the Store↔Tree type
/// cycle; pre-populated by every constructor so the deref is infallible.
impl std::ops::Deref for Store {
    type Target = Tree;
    fn deref(&self) -> &Tree {
        // Infallible by construction (per the lib.rs lint contract): every
        // constructor populates `default_tree` before the Store is handed out,
        // surfacing any failure there as a Result.
        #[allow(clippy::expect_used)]
        self.default_tree
            .get()
            .expect("default tree pre-populated by every Store constructor")
    }
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.inner.path)
            .finish()
    }
}

/// Errors that must route the caller into the corruption-recovery ladder
/// (quarantine + re-bootstrap) carry this marker prefix. Classification happens
/// HERE, from redb's error variants — never by string-matching engine internals
/// at call sites (review finding F1: redb reports a clobbered magic number as
/// Io(InvalidData), which a bare "Corrupt" substring match missed).
pub const CORRUPTION_MARKER: &str = "CORRUPTION:";

impl StoreError {
    pub fn is_corruption(&self) -> bool {
        self.0.starts_with(CORRUPTION_MARKER)
    }
}

fn classify_open_error(e: redb::DatabaseError, pre_existing: bool) -> StoreError {
    let corrupt = match &e {
        redb::DatabaseError::Storage(redb::StorageError::Corrupted(_)) => true,
        // On a PRE-EXISTING file, an InvalidData at open is a damaged header /
        // magic number, not an environmental I/O problem.
        redb::DatabaseError::Storage(redb::StorageError::Io(io)) => {
            pre_existing && io.kind() == std::io::ErrorKind::InvalidData
        }
        _ => false,
    };
    if corrupt {
        StoreError(format!("{CORRUPTION_MARKER} {e}"))
    } else {
        StoreError(e.to_string())
    }
}

impl Store {
    pub fn open(path: impl AsRef<Path>, cache_bytes: usize) -> Result<Store> {
        let path = path.as_ref().to_path_buf();
        // Gross-truncation guard (review F1): a pre-existing non-empty file
        // shorter than redb's header region trips an assert INSIDE the engine
        // (an uncatchable panic) before any error can be returned. Classify it
        // as corruption here so the recovery ladder gets its chance.
        let pre_existing_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if pre_existing_len > 0 && pre_existing_len < 4096 {
            return Err(StoreError(format!(
                "{CORRUPTION_MARKER} store file {} is truncated ({} bytes — smaller than \
                 the engine header region)",
                path.display(),
                pre_existing_len
            )));
        }
        let db = redb::Builder::new()
            .set_cache_size(cache_bytes)
            .create(&path)
            .map_err(|e| classify_open_error(e, pre_existing_len > 0))?;
        let store = Store {
            inner: Arc::new(Inner {
                db,
                path,
                write_lock: Mutex::new(()),
                temporary: false,
            }),
            default_tree: OnceLock::new(),
        };
        let default = store.open_tree(DEFAULT_TREE)?;
        let _ = store.default_tree.set(Box::new(default));
        Ok(store)
    }

    /// A throwaway store in the OS temp dir, deleted when the last handle
    /// drops. Test-support parity with sled's `temporary(true)`.
    pub fn temporary() -> Result<Store> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "a9store-{}-{}.redb",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        let db = redb::Builder::new()
            .set_cache_size(64 * 1024 * 1024)
            .create(&path)?;
        let store = Store {
            inner: Arc::new(Inner {
                db,
                path,
                write_lock: Mutex::new(()),
                temporary: true,
            }),
            default_tree: OnceLock::new(),
        };
        let default = store.open_tree(DEFAULT_TREE)?;
        let _ = store.default_tree.set(Box::new(default));
        Ok(store)
    }

    pub fn open_tree(&self, name: impl AsRef<[u8]>) -> Result<Tree> {
        let name = String::from_utf8_lossy(name.as_ref()).into_owned();
        let def_name = interned(&name);
        // Create the table eagerly so `tree_names`/readers see it immediately,
        // matching sled's open_tree side effect.
        {
            let _guard = self.inner.write_lock.lock();
            let mut txn = self.inner.db.begin_write()?;
            txn.set_durability(Durability::None)?;
            {
                let def = TableDefinition::<&[u8], &[u8]>::new(def_name);
                txn.open_table(def)?;
            }
            txn.commit()?;
        }
        Ok(Tree {
            store: self.clone(),
            def_name,
        })
    }

    pub fn tree_names(&self) -> Result<Vec<Vec<u8>>> {
        let txn = self.inner.db.begin_read()?;
        let mut names: Vec<Vec<u8>> = txn
            .list_tables()?
            .map(|h| h.name().as_bytes().to_vec())
            .collect();
        names.sort();
        Ok(names)
    }

    /// One durable commit covering every previously committed write, in the
    /// CONSERVATIVE configuration a public value-bearing chain should run:
    /// two-phase commit (torn-write protection on non-atomic media — one extra
    /// fsync, paid only here, never on the hot mutation path) and quick_repair
    /// (persists allocator state so an unclean open after this point recovers
    /// in O(1) instead of walking the whole file's checksums — the difference
    /// between milliseconds and minutes at multi-GB scale).
    pub fn flush(&self) -> Result<()> {
        let _guard = self.inner.write_lock.lock();
        let mut txn = self.inner.db.begin_write()?;
        txn.set_durability(Durability::Immediate)?;
        txn.set_two_phase_commit(true);
        txn.set_quick_repair(true);
        txn.commit()?;
        Ok(())
    }

    pub fn size_on_disk(&self) -> Result<u64> {
        Ok(std::fs::metadata(&self.inner.path)?.len())
    }

    /// Space accounting for the amplification telemetry (review F2): the
    /// physical file size against the engine's own logical accounting, plus the
    /// freed-but-unreleased byte count — redb's actual amplification mode
    /// (the file only shrinks on clean close).
    pub fn space_stats(&self) -> Result<SpaceStats> {
        let file_bytes = std::fs::metadata(&self.inner.path)?.len();
        let _guard = self.inner.write_lock.lock();
        let txn = self.inner.db.begin_write()?;
        let stats = txn.stats()?;
        let out = SpaceStats {
            file_bytes,
            stored_bytes: stats.stored_bytes() + stats.metadata_bytes(),
            fragmented_bytes: stats.fragmented_bytes(),
        };
        txn.abort()?;
        Ok(out)
    }

    /// Consistent point-in-time copy of the database file for snapshot
    /// publishing: hold the writer lock (no transaction can begin), seal
    /// everything with one durable two-phase commit, then copy the file while
    /// writers are still paused. Readers are unaffected (reads never mutate
    /// the file). On APFS the copy is a clonefile — effectively instant — so
    /// the writer pause is milliseconds regardless of database size.
    pub fn snapshot_file_to(&self, dest: &Path) -> Result<()> {
        let _guard = self.inner.write_lock.lock();
        let mut txn = self.inner.db.begin_write()?;
        txn.set_durability(Durability::Immediate)?;
        txn.set_two_phase_commit(true);
        txn.set_quick_repair(true);
        txn.commit()?;
        std::fs::copy(&self.inner.path, dest)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }
}

/// A batch of writes applied in one all-or-nothing transaction. Drop-in for
/// `sled::Batch`.
#[derive(Default, Clone)]
pub struct Batch {
    ops: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl Batch {
    pub fn insert(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        self.ops
            .push((key.as_ref().to_vec(), Some(value.as_ref().to_vec())));
    }
    pub fn remove(&mut self, key: impl AsRef<[u8]>) {
        self.ops.push((key.as_ref().to_vec(), None));
    }
    pub fn len(&self) -> usize {
        self.ops.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

#[derive(Clone)]
pub struct Tree {
    store: Store,
    def_name: &'static str,
}

impl Tree {
    fn def(&self) -> TableDefinition<'static, &'static [u8], &'static [u8]> {
        TableDefinition::new(self.def_name)
    }

    pub fn name(&self) -> &str {
        self.def_name
    }

    pub fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        let txn = self.store.inner.db.begin_read()?;
        let table = match txn.open_table(self.def()) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(table.get(key.as_ref())?.map(|g| g.value().to_vec()))
    }

    pub fn contains_key(&self, key: impl AsRef<[u8]>) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    /// Insert, returning the previous value (sled parity).
    pub fn insert(
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<Option<Vec<u8>>> {
        let _guard = self.store.inner.write_lock.lock();
        let mut txn = self.store.inner.db.begin_write()?;
        txn.set_durability(Durability::None)?;
        let mut table = txn.open_table(self.def())?;
        let guard = table.insert(key.as_ref(), value.as_ref())?;
        let prev = guard.map(|g| g.value().to_vec());
        drop(table);
        txn.commit()?;
        Ok(prev)
    }

    /// Remove, returning the previous value (sled parity).
    pub fn remove(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        let _guard = self.store.inner.write_lock.lock();
        let mut txn = self.store.inner.db.begin_write()?;
        txn.set_durability(Durability::None)?;
        let mut table = txn.open_table(self.def())?;
        let guard = table.remove(key.as_ref())?;
        let prev = guard.map(|g| g.value().to_vec());
        drop(table);
        txn.commit()?;
        Ok(prev)
    }

    /// All operations land in one transaction: all-or-nothing under crash.
    pub fn apply_batch(&self, batch: Batch) -> Result<()> {
        let _guard = self.store.inner.write_lock.lock();
        let mut txn = self.store.inner.db.begin_write()?;
        txn.set_durability(Durability::None)?;
        {
            let mut table = txn.open_table(self.def())?;
            for (key, value) in &batch.ops {
                match value {
                    Some(v) => {
                        table.insert(key.as_slice(), v.as_slice())?;
                    }
                    None => {
                        table.remove(key.as_slice())?;
                    }
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Full-store durable commit; identical cost/semantics to `Store::flush`
    /// (in sled, a tree flush was a full-DB fsync — preserved knowingly).
    pub fn flush(&self) -> Result<()> {
        self.store.flush()
    }

    pub fn len(&self) -> Result<u64> {
        let txn = self.store.inner.db.begin_read()?;
        match txn.open_table(self.def()) {
            Ok(t) => Ok(t.len()?),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    pub fn first(&self) -> Result<Option<KvPair>> {
        let txn = self.store.inner.db.begin_read()?;
        match txn.open_table(self.def()) {
            Ok(t) => Ok(t
                .first()?
                .map(|(k, v)| (k.value().to_vec(), v.value().to_vec()))),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn last(&self) -> Result<Option<KvPair>> {
        let txn = self.store.inner.db.begin_read()?;
        match txn.open_table(self.def()) {
            Ok(t) => Ok(t
                .last()?
                .map(|(k, v)| (k.value().to_vec(), v.value().to_vec()))),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Lazy, chunked prefix scan with sled's iterator shape
    /// (`Iterator<Item = Result<(key, value)>>`), so existing call sites —
    /// including `.flatten()` loops — carry over unchanged. Each page reads
    /// through a fresh snapshot (weakly consistent across pages, exactly as a
    /// long-lived sled iterator was against concurrent writers), and memory
    /// stays bounded by the page size regardless of tree size.
    pub fn scan_prefix(&self, prefix: impl AsRef<[u8]>) -> LazyScan {
        let prefix = prefix.as_ref().to_vec();
        let end = prefix_end(&prefix);
        LazyScan::new(self.clone(), prefix, end)
    }

    /// Lazy full-table scan, key-ascending, sled iterator shape.
    pub fn iter(&self) -> LazyScan {
        LazyScan::new(self.clone(), Vec::new(), None)
    }

    /// Lazy range scan with sled's `range(..)` shape. Bounds map to the
    /// byte-order successor where needed (`x ∥ 0x00` is the immediate
    /// successor of `x`).
    pub fn range<R: std::ops::RangeBounds<Vec<u8>>>(&self, bounds: R) -> LazyScan {
        use std::ops::Bound;
        let start = match bounds.start_bound() {
            Bound::Included(s) => s.clone(),
            Bound::Excluded(s) => {
                let mut succ = s.clone();
                succ.push(0);
                succ
            }
            Bound::Unbounded => Vec::new(),
        };
        let end = match bounds.end_bound() {
            Bound::Included(e) => {
                let mut succ = e.clone();
                succ.push(0);
                Some(succ)
            }
            Bound::Excluded(e) => Some(e.clone()),
            Bound::Unbounded => None,
        };
        LazyScan::new(self.clone(), start, end)
    }

    /// Delete every entry (sled `Tree::clear` parity): one transaction that
    /// drops and recreates the table.
    pub fn clear(&self) -> Result<()> {
        let _guard = self.store.inner.write_lock.lock();
        let mut txn = self.store.inner.db.begin_write()?;
        txn.set_durability(Durability::None)?;
        txn.delete_table(self.def())?;
        txn.open_table(self.def())?;
        txn.commit()?;
        Ok(())
    }

    /// One page of `start..end` (end exclusive; `None` = open), at most `limit`
    /// entries. The lazy scans build on this.
    fn range_page(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KvPair>> {
        let txn = self.store.inner.db.begin_read()?;
        let table = match txn.open_table(self.def()) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let iter: Box<dyn Iterator<Item = _>> = match end {
            Some(end) => Box::new(table.range(start..end)?),
            None => Box::new(table.range(start..)?),
        };
        // Byte budget (review F3): pages stop at the entry limit OR this many
        // accumulated bytes, whichever first — a run of max-size block values
        // must never turn one page into a multi-GiB buffer. Resume logic
        // already handles short pages.
        const PAGE_BYTE_BUDGET: usize = 16 * 1024 * 1024;
        let mut out = Vec::with_capacity(limit.min(1024));
        let mut bytes = 0usize;
        for entry in iter.take(limit) {
            let (k, v) = entry?;
            bytes += k.value().len() + v.value().len();
            out.push((k.value().to_vec(), v.value().to_vec()));
            if bytes >= PAGE_BYTE_BUDGET {
                break;
            }
        }
        Ok(out)
    }

    /// One DESCENDING page from the top of `start..end`, at most `limit`
    /// entries, using the double-ended range iterator inside one snapshot.
    fn range_page_rev(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<KvPair>> {
        let txn = self.store.inner.db.begin_read()?;
        let table = match txn.open_table(self.def()) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let iter: Box<dyn DoubleEndedIterator<Item = _>> = match end {
            Some(end) => Box::new(table.range(start..end)?),
            None => Box::new(table.range(start..)?),
        };
        const PAGE_BYTE_BUDGET: usize = 16 * 1024 * 1024;
        let mut out = Vec::with_capacity(limit.min(1024));
        let mut bytes = 0usize;
        for entry in iter.rev().take(limit) {
            let (k, v) = entry?;
            bytes += k.value().len() + v.value().len();
            out.push((k.value().to_vec(), v.value().to_vec()));
            if bytes >= PAGE_BYTE_BUDGET {
                break;
            }
        }
        Ok(out)
    }

    /// Streaming prefix scan: the callback returns `false` to stop early. The
    /// read transaction stays open only for the duration of the walk.
    pub fn for_each_prefix(
        &self,
        prefix: impl AsRef<[u8]>,
        mut f: impl FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<()> {
        let prefix = prefix.as_ref();
        let txn = self.store.inner.db.begin_read()?;
        let table = match txn.open_table(self.def()) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let iter: Box<dyn Iterator<Item = _>> = match prefix_end(prefix) {
            Some(end) => Box::new(table.range(prefix..end.as_slice())?),
            None => Box::new(table.range(prefix..)?),
        };
        for entry in iter {
            let (k, v) = entry?;
            if !f(k.value(), v.value()) {
                break;
            }
        }
        Ok(())
    }

    /// Streaming full-table walk, key-ascending; callback returns `false` to
    /// stop. The way large trees (blocks) are iterated without materializing.
    pub fn for_each(&self, mut f: impl FnMut(&[u8], &[u8]) -> bool) -> Result<()> {
        let txn = self.store.inner.db.begin_read()?;
        let table = match txn.open_table(self.def()) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        for entry in table.iter()? {
            let (k, v) = entry?;
            if !f(k.value(), v.value()) {
                break;
            }
        }
        Ok(())
    }

    /// Atomic read-modify-write on one key (sled `update_and_fetch` parity):
    /// the closure sees the current value and returns the new one (`None`
    /// deletes). Runs inside a single write transaction under the global write
    /// lock, so concurrent writers cannot interleave. Returns the NEW value.
    pub fn update_and_fetch(
        &self,
        key: impl AsRef<[u8]>,
        mut f: impl FnMut(Option<&[u8]>) -> Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>> {
        let key = key.as_ref();
        let _guard = self.store.inner.write_lock.lock();
        let mut txn = self.store.inner.db.begin_write()?;
        txn.set_durability(Durability::None)?;
        let mut table = txn.open_table(self.def())?;
        let current = table.get(key)?.map(|g| g.value().to_vec());
        let next = f(current.as_deref());
        match &next {
            Some(v) => {
                table.insert(key, v.as_slice())?;
            }
            None => {
                table.remove(key)?;
            }
        }
        drop(table);
        txn.commit()?;
        Ok(next)
    }
}

/// Chunked lazy scan over a tree: pages of `PAGE` entries fetched through
/// fresh read snapshots, resuming after the last-seen key (its immediate
/// bytewise successor is `key ∥ 0x00`). Emits at most one terminal error.
pub struct LazyScan {
    tree: Option<Tree>,
    next_start: Vec<u8>,
    end: Option<Vec<u8>>,
    buf: std::collections::VecDeque<KvPair>,
}

impl LazyScan {
    const PAGE: usize = 1024;

    fn new(tree: Tree, start: Vec<u8>, end: Option<Vec<u8>>) -> Self {
        LazyScan {
            tree: Some(tree),
            next_start: start,
            end,
            buf: std::collections::VecDeque::new(),
        }
    }
}

impl Iterator for LazyScan {
    type Item = Result<KvPair>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(pair) = self.buf.pop_front() {
            return Some(Ok(pair));
        }
        let tree = self.tree.as_ref()?;
        match tree.range_page(&self.next_start, self.end.as_deref(), Self::PAGE) {
            Ok(page) => {
                if page.is_empty() {
                    self.tree = None;
                    return None;
                }
                if let Some((last_key, _)) = page.last() {
                    let mut succ = last_key.clone();
                    succ.push(0);
                    self.next_start = succ;
                }
                self.buf = page.into();
                self.buf.pop_front().map(Ok)
            }
            Err(e) => {
                self.tree = None;
                Some(Err(e))
            }
        }
    }
}

impl LazyScan {
    /// Descending-order variant (sled's `.rev()` shape). Inherent method, so
    /// call sites written as `tree.scan_prefix(p).rev()` resolve here instead
    /// of the `Iterator::rev` adapter (which `LazyScan` cannot support lazily).
    pub fn rev(self) -> LazyScanRev {
        LazyScanRev {
            tree: self.tree,
            start: self.next_start,
            next_end: self.end,
            buf: std::collections::VecDeque::new(),
        }
    }
}

/// Backward chunked scan: pages are taken from the top of the remaining
/// `start..end` window via the (transaction-local) double-ended range
/// iterator, and the window's end moves down to the smallest key seen.
pub struct LazyScanRev {
    tree: Option<Tree>,
    start: Vec<u8>,
    /// Exclusive end of the remaining window; `None` = unbounded high.
    next_end: Option<Vec<u8>>,
    buf: std::collections::VecDeque<KvPair>,
}

impl Iterator for LazyScanRev {
    type Item = Result<KvPair>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(pair) = self.buf.pop_front() {
            return Some(Ok(pair));
        }
        let tree = self.tree.as_ref()?;
        match tree.range_page_rev(&self.start, self.next_end.as_deref(), LazyScan::PAGE) {
            Ok(page) => {
                if page.is_empty() {
                    self.tree = None;
                    return None;
                }
                // Page is in DESCENDING order; its last element is the
                // smallest key seen, which becomes the new exclusive end.
                if let Some((smallest, _)) = page.last() {
                    self.next_end = Some(smallest.clone());
                }
                self.buf = page.into();
                self.buf.pop_front().map(Ok)
            }
            Err(e) => {
                self.tree = None;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_returns_previous_values() {
        let store = Store::temporary().unwrap();
        let tree = store.open_tree("t").unwrap();
        assert_eq!(tree.insert(b"k", b"v1").unwrap(), None);
        assert_eq!(tree.insert(b"k", b"v2").unwrap(), Some(b"v1".to_vec()));
        assert_eq!(tree.get(b"k").unwrap(), Some(b"v2".to_vec()));
        assert_eq!(tree.remove(b"k").unwrap(), Some(b"v2".to_vec()));
        assert_eq!(tree.get(b"k").unwrap(), None);
        assert_eq!(tree.remove(b"k").unwrap(), None);
    }

    #[test]
    fn batch_applies_all_operations_atomically_visible() {
        let store = Store::temporary().unwrap();
        let tree = store.open_tree("t").unwrap();
        tree.insert(b"stale", b"x").unwrap();
        let mut batch = Batch::default();
        batch.insert(b"a", b"1");
        batch.insert(b"b", b"2");
        batch.remove(b"stale");
        tree.apply_batch(batch).unwrap();
        assert_eq!(tree.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(tree.get(b"b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(tree.get(b"stale").unwrap(), None);
        assert_eq!(tree.len().unwrap(), 2);
    }

    #[test]
    fn prefix_scan_hits_exactly_the_prefix_in_order() {
        let store = Store::temporary().unwrap();
        let tree = store.open_tree("t").unwrap();
        for key in ["block_1", "block_2", "block_20", "blocj_9", "blocl_0"] {
            tree.insert(key.as_bytes(), b"v").unwrap();
        }
        let hits: Vec<Vec<u8>> = tree
            .scan_prefix(b"block_")
            .map(|r| r.unwrap())
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            hits,
            vec![
                b"block_1".to_vec(),
                b"block_2".to_vec(),
                b"block_20".to_vec()
            ]
        );

        // All-0xff prefix: unbounded high end must not panic or miss.
        tree.insert([0xff, 0xff, 0x01], b"v").unwrap();
        let ff: Vec<_> = tree.scan_prefix([0xff, 0xff]).flatten().collect();
        assert_eq!(ff.len(), 1);
    }

    #[test]
    fn early_stop_and_full_walk() {
        let store = Store::temporary().unwrap();
        let tree = store.open_tree("t").unwrap();
        for i in 0..10u8 {
            tree.insert([i], [i]).unwrap();
        }
        let mut seen = 0;
        tree.for_each(|_, _| {
            seen += 1;
            seen < 3
        })
        .unwrap();
        assert_eq!(seen, 3, "callback false stops the walk");
        assert_eq!(tree.first().unwrap().unwrap().0, vec![0]);
        assert_eq!(tree.last().unwrap().unwrap().0, vec![9]);
    }

    #[test]
    fn durable_after_flush_and_reopen() {
        let path = std::env::temp_dir().join(format!(
            "a9store-reopen-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        {
            let store = Store::open(&path, 8 * 1024 * 1024).unwrap();
            let tree = store.open_tree("t").unwrap();
            tree.insert(b"k", b"v").unwrap();
            store.flush().unwrap();
        }
        {
            let store = Store::open(&path, 8 * 1024 * 1024).unwrap();
            let tree = store.open_tree("t").unwrap();
            assert_eq!(tree.get(b"k").unwrap(), Some(b"v".to_vec()));
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tree_names_lists_created_tables() {
        let store = Store::temporary().unwrap();
        store.open_tree("alpha").unwrap();
        store.open_tree("beta").unwrap();
        let names = store.tree_names().unwrap();
        assert!(names.contains(&b"alpha".to_vec()));
        assert!(names.contains(&b"beta".to_vec()));
    }

    #[test]
    fn truncated_store_file_classifies_as_corruption() {
        let path = std::env::temp_dir().join(format!("a9store-trunc-{}.redb", std::process::id()));
        std::fs::write(&path, b"redb!but-way-too-short").unwrap();
        let err = Store::open(&path, 8 * 1024 * 1024).unwrap_err();
        assert!(
            err.is_corruption(),
            "gross truncation must route to the recovery ladder: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    // The resume-key semantics under scan-while-mutating: deleting entries
    // behind AND ahead of the cursor must never skip or double-visit a
    // surviving key (the witness-prune pattern).
    #[test]
    fn lazy_scan_survives_deletions_during_the_walk() {
        let store = Store::temporary().unwrap();
        let tree = store.open_tree("t").unwrap();
        for i in 0..3000u32 {
            tree.insert(i.to_be_bytes(), b"v").unwrap();
        }
        let mut seen = Vec::new();
        for (n, item) in tree.iter().enumerate() {
            let (k, _) = item.unwrap();
            seen.push(u32::from_be_bytes(k[..4].try_into().unwrap()));
            if n == 1500 {
                // Behind the cursor and ahead of it, spanning page boundaries.
                for d in [0u32, 1, 2, 2000, 2001, 2002] {
                    tree.remove(d.to_be_bytes()).unwrap();
                }
            }
        }
        // No duplicates ever.
        let unique: std::collections::HashSet<_> = seen.iter().collect();
        assert_eq!(unique.len(), seen.len(), "no key visited twice");
        // Every key that was NEVER deleted must have been visited.
        let deleted: std::collections::HashSet<u32> = [0, 1, 2, 2000, 2001, 2002].into();
        for i in 0..3000u32 {
            if !deleted.contains(&i) {
                assert!(seen.contains(&i), "surviving key {i} skipped");
            }
        }
    }

    #[test]
    fn update_and_fetch_is_atomic_across_threads() {
        let store = Store::temporary().unwrap();
        let tree = store.open_tree("t").unwrap();
        tree.insert(b"n", 0u64.to_le_bytes()).unwrap();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let tree = tree.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    tree.update_and_fetch(b"n", |old| {
                        let cur = old
                            .map(|v| u64::from_le_bytes(v[..8].try_into().unwrap()))
                            .unwrap_or(0);
                        Some((cur + 1).to_le_bytes().to_vec())
                    })
                    .unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let v = tree.get(b"n").unwrap().unwrap();
        assert_eq!(
            u64::from_le_bytes(v[..8].try_into().unwrap()),
            400,
            "8 threads x 50 read-modify-writes lost none"
        );
    }

    // A garbage (non-truncated) store file must classify as corruption so the
    // launch recovery ladder engages — this is the clobbered-magic-number
    // class the review flagged (F1), distinct from the pre-open truncation
    // guard.
    #[test]
    fn garbage_store_file_classifies_as_corruption() {
        let path =
            std::env::temp_dir().join(format!("a9store-garbage-{}.redb", std::process::id()));
        let junk: Vec<u8> = (0..16_384u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, junk).unwrap();
        let err = Store::open(&path, 8 * 1024 * 1024).unwrap_err();
        assert!(
            err.is_corruption(),
            "a clobbered store must route to the recovery ladder: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    // The snapshot copy is a sealed point-in-time state: later writes to the
    // source must never appear in it, and it must open cleanly on its own.
    #[test]
    fn snapshot_file_is_a_sealed_point_in_time_copy() {
        let store = Store::temporary().unwrap();
        let tree = store.open_tree("t").unwrap();
        tree.insert(b"before", b"1").unwrap();
        let dest = std::env::temp_dir().join(format!("a9store-snap-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&dest);
        store.snapshot_file_to(&dest).unwrap();
        tree.insert(b"after", b"2").unwrap();
        store.flush().unwrap();

        let copy = Store::open(&dest, 8 * 1024 * 1024).unwrap();
        let copy_tree = copy.open_tree("t").unwrap();
        assert_eq!(copy_tree.get(b"before").unwrap(), Some(b"1".to_vec()));
        assert_eq!(
            copy_tree.get(b"after").unwrap(),
            None,
            "post-snapshot writes must not leak into the sealed copy"
        );
        assert_eq!(tree.get(b"after").unwrap(), Some(b"2".to_vec()));
        drop(copy);
        let _ = std::fs::remove_file(&dest);
    }

    // The sled-parity Deref: Store IS its default tree for reads and writes,
    // and the default tree is visible in the listing under its own name.
    #[test]
    fn store_derefs_to_a_real_default_tree() {
        let store = Store::temporary().unwrap();
        store.insert(b"k", b"v").unwrap();
        assert_eq!(store.get(b"k").unwrap(), Some(b"v".to_vec()));
        let names = store.tree_names().unwrap();
        assert!(names.contains(&DEFAULT_TREE.as_bytes().to_vec()));
    }

    #[test]
    fn temporary_store_removes_its_file() {
        let path;
        {
            let store = Store::temporary().unwrap();
            path = store.path().to_path_buf();
            assert!(path.exists());
        }
        assert!(!path.exists(), "temp store file removed on drop");
    }
}
