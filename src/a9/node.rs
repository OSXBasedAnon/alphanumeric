use arrayref::array_ref;
use axum::{
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use dashmap::{mapref::entry::Entry, DashMap};
use futures_util::future::join_all;
use igd_next::{search_gateway, PortMappingProtocol};
use ipnet::{Ipv4Net, Ipv6Net};
use libp2p_core::{Multiaddr, PeerId};
use libp2p_identity as identity;
use libp2p_kad::{
    store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig, Event as KademliaEvent,
    QueryResult,
};
use libp2p_noise as noise;
use libp2p_swarm::{NetworkBehaviour, Swarm};
use libp2p_yamux as yamux;
use log::{debug, error, info, warn};
use lru::LruCache;
use parking_lot::Mutex as PLMutex;
use rand::{seq::SliceRandom, thread_rng, Rng};
use reqwest::Client;
use ring::{
    agreement,
    rand::SecureRandom,
    signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sled::Db;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    convert::TryInto,
    hash::{Hash, Hasher},
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{broadcast, mpsc, oneshot, Mutex, RwLock, Semaphore},
    time::{interval, sleep, timeout, MissedTickBehavior},
};

use crate::a9::blockchain::{
    Block, Blockchain, BlockchainError, RateLimiter, Transaction, FEE_SYSTEM_ACTIVATION_HEIGHT,
    MAX_BLOCK_TX_COUNT, MAX_BLOCK_WEIGHT_BYTES, MIN_RELAY_FEE_UNITS, SYSTEM_ADDRESSES,
};
use crate::a9::bpos::{BlockHeaderInfo, HeaderSentinel, NetworkHealth};
use crate::a9::codec;
use crate::a9::mldsa;
use crate::a9::velocity::{Shred, ShredRequest, ShredRequestType, VelocityError, VelocityManager};

//----------------------------------------------------------------------
// Constants
//----------------------------------------------------------------------

// Network parameters
pub const DEFAULT_PORT: u16 = 7177;
/// Marker error for a relay block POST rejected by the gateway's per-IP rate limit.
/// Callers match on this to BACK OFF instead of backfilling (which amplifies the storm).
const RELAY_POST_RATE_LIMITED: &str = "Block relay post rate-limited";
/// Marker error for a relay block POST that failed everywhere for TRANSIENT reasons
/// only: transport errors, client timeouts, 408, or 5xx. Distinct from the rate-limit
/// marker because the right response differs — a 429 means the per-IP window is CLOSED
/// and a retry must wait for it to roll over, while a transient blip deserves one
/// prompt second attempt. Permanent 4xx verdicts (schema, auth, size) map to NEITHER
/// marker: the identical request would meet the identical answer, so retrying it is
/// pure amplification.
const RELAY_POST_TRANSIENT: &str = "Block relay post transiently unavailable";
/// Single-flight latch for the detached post-mine relay backfill (process-wide: one
/// node per process in practice). Overlapping runs re-post the same recent window and
/// only burn POST budget — the newest run supersedes the older one's purpose.
static RELAY_BACKFILL_INFLIGHT: AtomicBool = AtomicBool::new(false);
// Maintained TCP peer floor. 5, not 3: at degree 3 the loss of two neighbors
// during a gateway outage partitions the node from gap-recovery (mesh gossip
// has no range-fetch), and every acquisition trigger gates on this floor — it
// is the de-facto degree. Roster poverty is self-limiting: discovery's
// exponential backoff (60s→900s) engages whenever the network cannot supply
// this many, so raising the floor cannot create a dial-churn loop.
const MIN_PEERS: usize = 5;
const MAX_PEERS_PER_SUBNET: usize = 3;
// Max span a single GetBlocks request may ask for (and the client's batch size, kept in
// lockstep). Bounds the per-request disk reads on the event loop and the reply size. 256 =
// 4x the 64-aligned convergence window, so it never throttles catch-up.
pub const MAX_GETBLOCKS_SPAN: u32 = 256;
// Max connected peers a single sync_full_history_from_peer call will probe for a fresh
// height before giving up. Each probe is bounded by the message timeouts (5s connect /
// 30s response worst case against a half-open post-sleep socket), so this also bounds
// the call's worst-case candidate-selection time.
const FULL_SYNC_MAX_CANDIDATES: usize = 8;
const SUBNET_MASK_IPV4: u8 = 24; // /24 subnet
                                 // Group IPv6 peers by /48, NOT /64: a single rented /48 contains 65,536 /64s, so a /64
                                 // grouping let one attacker present that many distinct "subnets" and completely bypass the
                                 // MAX_PEERS_PER_SUBNET anti-eclipse cap. /48 is the typical site allocation, so all of an
                                 // attacker's addresses within one rental collapse to one group and the cap bites.
const SUBNET_MASK_IPV6: u8 = 48; // /48 subnet

// Timeouts and intervals
// Inbound idle read timeout. Peers ping every PING_INTERVAL (30s), so a live peer resets this
// well within the window; 90s tolerates 3 missed pings before evicting an idle connection so it
// can't hold a slot for minutes (was 300s).
const PEER_TIMEOUT: u64 = 90; // seconds
const MAINTENANCE_INTERVAL: u64 = 60; // 1 minute
const VERSION_CHECK_INTERVAL_SECS: u64 = 1800; // 30 min: notice-only client-version check
const DEFAULT_ANNOUNCE_INTERVAL_SECS: u64 = 300;
const DEFAULT_HEADER_SNAPSHOT_INTERVAL_SECS: u64 = 30;
// Upper bound on wall-clock time spent resolving a single block's transaction witnesses.
// Honest blocks resolve theirs locally — near-tip gossip leaves them in the mempool and relay
// sync ships them inline — so this is only approached when witnesses have to be fetched one by
// one from a slow-responding peer. Reaching it defers the block (re-verified later, never
// negative-cached) rather than letting resolution run for an unbounded stretch.
const WITNESS_RESOLVE_DEADLINE: Duration = Duration::from_secs(30);
const WITNESS_RESOLVE_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
/// Ceiling on a beacon-committed catch-up span, in blocks and in buffered bytes.
/// The span is held in memory until the whole chain is proven against the signed
/// beacon (that proof is what makes it safe), so it must be bounded. A gap past
/// either bound falls through to the snapshot bootstrap, which is the cheaper
/// recovery at that depth anyway. 8192 blocks is ~11 hours of chain at the 5s
/// target, so an overnight-idle client heals in place.
const COMMITTED_SPAN_MAX_BLOCKS: u32 = 8192;
const COMMITTED_SPAN_MAX_BYTES: usize = 64 * 1024 * 1024;
/// How often a client polls the tiny edge-cached tip beacon. Cache HITS cost the
/// origin/Redis nothing, so this stays O(1) in client count; a version change is
/// the ONLY thing that triggers a block fetch, so there is no redundant pulling.
// 3s (was 2s): with ~10s+ block intervals the extra second of worst-case discovery
// latency is invisible, but it cuts every client's edge-request volume against the
// gateway by a third (43k -> 29k requests/day per node) — the fleet is the dominant
// consumer of the Vercel edge budget.
const BEACON_POLL_INTERVAL_SECS: u64 = 3;
/// Window over which beacon-height observations count toward the mine-prep stale-tip
/// high-water. Must comfortably exceed the worst observed CDN staleness of the beacon
/// (~29s) so a transient stale-low read can never become the window max (ghost-block
/// safety), while still letting a genuine canonical regression age the old stuck-high
/// value out. 10 min gives >20x margin; post-regression recovery is bounded by this
/// window plus the gateway's beacon TTL (~5 min), i.e. ~15 min, versus FOREVER before.
const BEACON_HIGH_WATER_WINDOW_SECS: u64 = 600;

/// The canonical tip as advertised by the signed beacon (height, hash, version).
#[derive(Clone, Copy, Debug)]
struct TipBeaconInfo {
    height: u32,
    hash: [u8; 32],
    version: u64,
}

/// The gateway's relay-head hint: newest ACCEPTED block POST. A freshness/wake
/// signal only — never a consensus input (see fetch_relay_head).
struct RelayHeadInfo {
    height: u32,
    hash: [u8; 32],
}

/// Outcome of a single always-converge attempt toward the signed beacon tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Converge {
    /// Local now holds the beacon tip block (in sync).
    Converged,
    /// Local is at or ahead of this beacon on an equal-or-heavier chain — a terminal
    /// SUCCESS, never a concede: the node may mine to compete for the next block.
    AtTipAhead,
    /// Made forward progress but not yet at the beacon tip (caller retries).
    Progressed,
    /// Local diverges from canonical below the finality floor — only a full bootstrap
    /// can fix it. Reserved for a contiguously-proven deep divergence.
    NeedsBootstrap,
    /// The relay/beacon could not be read coherently right now (gap / empty / error).
    /// Transient — retry next tick; NEVER escalates to bootstrap/exit.
    BeaconStale,
    /// The target's branch FAILED validation (bad tx / PoW / linkage) — e.g. a fork
    /// mined by an incompatible client. Terminal for THIS target (its descendants
    /// are equally invalid), but says nothing about other branches: callers skip
    /// the branch (deadness propagates through its ancestry) and try the next one.
    BranchInvalid,
}

/// Result of the prev-hash-linked common-ancestor search.
enum Ancestor {
    /// Highest height where the LOCAL chain equals the CANONICAL chain the beacon
    /// points to (the fork point), plus the canonical block bodies from that height
    /// up to the beacon tip (ascending, contiguous) so the caller reuses them.
    Found(u32, Vec<Block>),
    /// A fully-linked canonical chain from the beacon tip down to the finality floor
    /// matched the local chain nowhere — genuine deep divergence -> bootstrap.
    NoneBelowFloor,
    /// A gap/broken link deeper than a convergent reorg could ever reach (below
    /// beacon.height - CHECKPOINT_REORG_MARGIN) — e.g. the needed history has aged out of
    /// the relay's ~1h window. Incremental convergence is impossible; only a fresh
    /// snapshot recovers it -> bootstrap.
    NeedsBootstrap,
    /// The relay could not supply a contiguous, prev-linked canonical chain right now but
    /// the gap is still WITHIN reorg reach (missing body / empty-200 window / fetch error
    /// near the tip) -> transient, retry (never bootstrap).
    Transient,
}

/// Outcome of an exact (height,hash) relay fetch. Distinguishing a TRANSIENT
/// failure (unreachable base / 429 / 5xx / 404-not-posted-yet / decode error)
/// from a DEFINITIVE miss (a reachable base cleanly served a response that lacks
/// or mismatches the asked block) is load-bearing: the ancestor walk must RETRY a
/// transient blip on the soft tier rather than escalate it to NeedsBootstrap and
/// sideline the live lineage for 300s. The windowed fetch path already makes this
/// split (Err -> Ancestor::Transient, 2ff72d8); the exact-fetch path bypassed it
/// by collapsing every failure to None (2026-07-12 audit).
enum ExactFetch {
    Found(Block),
    Missing,
    Transient,
}
const DEFAULT_STATS_SNAPSHOT_INTERVAL_SECS: u64 = 300;
const DISCOVERY_HTTP_TIMEOUT_MS: u64 = 3000;
const DISCOVERY_BACKOFF_BASE_SECS: u64 = 60;
const DISCOVERY_BACKOFF_MAX_SECS: u64 = 900;
const DEFAULT_DISCOVERY_BASE: &str = "https://alphanumeric.blue";
// DNS seeds are optional fallback only. Primary discovery should come from alphanumeric.blue.
// NOTE: this must be a hostname the project actually controls. The old defaults
// (seed*.alphanumeric.network, a9seed.mynode.network) were NXDOMAIN/domain-parked —
// i.e. zero functional seeds — verified 2026-07-10. alphanumeric.blue's DNS outlives
// the gateway app, so a plain A record here keeps first-contact working through a
// gateway outage once the operator points it at a public node.
const DEFAULT_DNS_SEEDS: &[&str] = &["seed.alphanumeric.blue:7177"];
/// Retry cadence for a FAILED discovery announce. A successful announce still
/// re-arms on the full announce interval; this only bounds how long a node stays
/// invisible after the gateway comes back from an outage (2026-07-10 incident:
/// the roster read as empty for minutes because failed announces silenced the
/// loop for the whole 300s interval). Network errors (gateway unreachable) retry
/// at this flat cadence — the gateway isn't serving anything, so recovery speed
/// wins. HTTP rejections (gateway UP and saying 429/4xx) back off exponentially
/// toward the full interval instead: those responses are real gateway work, and
/// a fleet retrying rejections at 10x forever is the 2026-07-08 storm shape.
const ANNOUNCE_RETRY_SECS: u64 = 30;
/// Cap on PEX-learned addresses kept in memory for the persisted peer cache.
const PEX_ADDR_BOOK_CAP: usize = 256;
/// PEX book entries older than this are dropped (dead/rotated addresses must not
/// haunt the persisted cache forever); re-learning an address refreshes it.
const PEX_ADDR_TTL_SECS: u64 = 86_400;
/// Max addresses accepted from a single GetPeers response per tick — bounds how
/// much of the book one (possibly malicious) peer can claim at a time.
const PEX_MAX_ADDRS_PER_RESPONSE: usize = 32;
/// Outer bound on a single PEX GetPeers exchange. send_message_with_response can
/// legitimately take 30s x 2 attempts; the cache-saver tick must never serialize
/// behind half-dead peers for minutes (its period is 120s).
const PEX_REQUEST_TIMEOUT_SECS: u64 = 5;
/// Consecutive zero-progress converge calls (while > CHECKPOINT_REORG_MARGIN
/// behind a fresh beacon) before escalating to NeedsBootstrap. Converge callers
/// run at 3-20s cadences, so this trips in roughly 0.5-3.5 minutes of proven
/// non-convergence — fast enough to unstick a wedged client, slow enough that a
/// transient relay hiccup (which heals within a call or two) never trips it.
const CONVERGE_STALL_ESCALATE_CALLS: u32 = 10;
/// Minimum wall-clock spacing between converge-stall increments. converge_to_relay_tip evaluates up
/// to MAX_TIP_CANDIDATES candidates within a single ~3-20s pass with an unchanged tip; without this
/// gate every candidate would bump the counter, tripping escalation in ~2 passes instead of the
/// intended ~0.5-3.5 minutes. Set just under the fastest caller cadence so distinct passes each
/// count once while a within-pass candidate burst counts once.
const CONVERGE_STALL_MIN_INTERVAL_MS: u64 = 2_500;

// ===== Chain re-bootstrap coordination (single source; main.rs boot logic and
// the runtime paths in this module both use these) =====

/// Floor between marker-forced re-bootstraps. On a shattered network the
/// diverge->exit->restore cycle would otherwise loop a 13MB snapshot download
/// every ~minute; within the cooldown the node stays up and keeps retrying
/// converge instead. Stamped into the FRESH db dir right after a marker-forced
/// restore, so (like the marker) it travels with the chain it describes.
pub const REBOOTSTRAP_COOLDOWN_SECS: u64 = 1800;

/// Shorter cooldown for HARD divergence verdicts (diverged below the finality
/// window, hash-verified against the signed beacon/manifest). The 1800s generic
/// cooldown exists to stop heuristic stall detectors from thrashing snapshot
/// downloads — but suppressing a PROVEN below-finality divergence leaves a node
/// that KNOWS it is stranded sitting stale for half an hour doing nothing
/// (observed live 2026-07-11: "--sync: re-bootstrap is required" + no marker
/// written + boot false-passing = fully stale until a human forced it). Bounded
/// worst case with 300s: one snapshot download per 5 minutes on a genuinely
/// shattered network — the price of never being silently stale.
pub const REBOOTSTRAP_HARD_COOLDOWN_SECS: u64 = 300;

/// Marker meaning "the runtime PROVED this chain cannot converge — re-bootstrap
/// at next boot regardless of what the (possibly stale) manifest comparison
/// says." Lives INSIDE the sled directory so removing the chain removes it, and
/// proven convergence deletes it.
pub fn force_rebootstrap_marker_path(db_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(db_dir).join("force_rebootstrap")
}

/// Cooldown stamp file (mtime is the clock) — see REBOOTSTRAP_COOLDOWN_SECS.
pub fn rebootstrap_cooldown_path(db_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(db_dir).join("rebootstrap_cooldown")
}

/// True while a marker-forced re-bootstrap happened less than the cooldown ago.
pub fn rebootstrap_cooldown_active(db_dir: &str) -> bool {
    rebootstrap_cooldown_within(db_dir, REBOOTSTRAP_COOLDOWN_SECS)
}

/// Hard-verdict variant: same stamp file, the shorter window. Used when the
/// divergence is PROVEN (below-finality hash mismatch vs the signed canonical),
/// where waiting out the generic cooldown means being knowingly stale.
pub fn rebootstrap_hard_cooldown_active(db_dir: &str) -> bool {
    rebootstrap_cooldown_within(db_dir, REBOOTSTRAP_HARD_COOLDOWN_SECS)
}

fn rebootstrap_cooldown_within(db_dir: &str, window_secs: u64) -> bool {
    std::fs::metadata(rebootstrap_cooldown_path(db_dir))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|elapsed| elapsed.as_secs() < window_secs)
        .unwrap_or(false)
}
const MAX_INBOUND_ATTEMPTS_PER_IP: u32 = 5;
const INBOUND_ATTEMPT_WINDOW: u64 = 60; // seconds
const INBOUND_ATTEMPT_MAX_KEYS: usize = 10_000;
const PEER_FAILURE_MAX_KEYS: usize = 10_000;

// Protocol
const NETWORK_VERSION: u32 = 3;

// Resource limits
const MAX_PARALLEL_VALIDATIONS: usize = 200;
// Concurrent outbound witness fetches, pooled separately from validation permits so a slow-
// responding peer can only ever contend with other fetches — never with block validation itself.
const MAX_PARALLEL_WITNESS_FETCHES: usize = 200;
const EVENT_QUEUE_CAPACITY: usize = 1000;
const EVENT_QUEUE_WARN_THRESHOLD: usize = 800;
const EVENT_BROADCAST_CAPACITY: usize = 1000;
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4MB hard cap per frame
const OUTBOUND_POOL_IDLE_SECS: u64 = 90;
const OUTBOUND_POOL_MAX_FACTOR: usize = 2;
// Per-peer outbound circuit breaker. Loosened 2026-07-11 (was 3 / 30s): under a
// fork-storm send burst, 3 consecutive timeouts tripped the breaker on many peers
// at once for a full 30s, and a node whose peers were all open could not broadcast
// its own freshly-mined block — so it orphaned (rplant's report). 6 consecutive
// failures before declaring a peer dead tolerates transient bursts; a 15s (not 30s)
// open window retries a momentarily-congested peer sooner. Still bounds hammering a
// genuinely dead peer. Per-peer and success-resetting, so this only widens the
// transient-tolerance, it does not remove the protection.
const OUTBOUND_CIRCUIT_FAILURE_THRESHOLD: u32 = 6;
const OUTBOUND_CIRCUIT_OPEN_SECS: u64 = 15;
const BLOOM_FILTER_SIZE: usize = 100_000;
const BLOOM_FILTER_FPR: f64 = 0.01;
const VALIDATION_CACHE_TTL_SECS: u64 = 3600;
const VALIDATION_CACHE_MAX_ENTRIES: usize = 50_000;
/// Level the validation cache is pruned back to once it crosses its ceiling. The gap is what
/// makes eviction amortised: pruning to the ceiling itself meant every insert past saturation
/// paid a full scan, clone and ordering pass to reclaim a single entry.
const VALIDATION_CACHE_TRIM_TARGET: usize = VALIDATION_CACHE_MAX_ENTRIES * 9 / 10;
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
/// Capability marker carried in the existing Ping/Pong `node_id` field. Older
/// peers already ignore that field after the authenticated handshake, so this
/// negotiates compact transport without changing NETWORK_VERSION or the signed
/// handshake schema. New message variants are sent only after observing it.
const COMPACT_BLOCK_V1_CAPABILITY_SUFFIX: &str = "|a9-compact-block-v1";
/// Release safety gate for the TCP compact extension.
///
/// The TCP reader processes one frame at a time, while compact reconstruction
/// may require bounded pull/proxy requests.  Until that path has a receiver ACK
/// and an independently framed fallback that cannot sit behind reconstruction,
/// TCP compact is deliberately dormant: no capability is advertised or
/// observed, no compact message is transmitted or processed, and no body/full
/// response is served.  Traditional unchanged full-block TCP relay remains the
/// reliability path.  WebRTC's local-only compact hint plus ordered full-frame
/// fallback is separate and does not consult this gate.
const TCP_COMPACT_V1_ENABLED: bool = false;
/// Keep a transaction-body response comfortably below the 4 MiB frame ceiling
/// even when every entry carries a full ML-DSA witness.
const COMPACT_TX_BATCH_MAX: usize = 64;
const COMPACT_SOURCE_MAX: usize = 8;
const COMPACT_PROXY_HOPS_MAX: u8 = 1;
const COMPACT_PENDING_CACHE_ENTRIES: usize = 32;
const COMPACT_FULL_BLOCK_CACHE_ENTRIES: usize = 32;
const COMPACT_TX_INDEX_ENTRIES: usize = 50_000;
const COMPACT_RECONSTRUCTION_CONCURRENCY: usize = 4;
const COMPACT_FORK_FALLBACK_CONCURRENCY: usize = 2;
const COMPACT_FORK_FALLBACK_DEADLINE: Duration = Duration::from_secs(15);
const COMPACT_RESPONSE_MAX_BYTES: usize = 1024 * 1024;
const COMPACT_TRANSACTION_MAX_ENCODED_BYTES: usize = 1024 * 1024;
/// The largest valid 4,096-transaction announcement is only about 150 KiB.
/// Leave ample codec/headroom while preventing an announcement itself from
/// consuming the full block-frame allowance.
const COMPACT_ANNOUNCEMENT_MAX_BYTES: usize = 512 * 1024;
const COMPACT_SAFE_ASSEMBLED_BYTES: usize = MAX_MESSAGE_SIZE - 64 * 1024;
const COMPACT_PENDING_CACHE_BYTE_BUDGET: usize = 24 * 1024 * 1024;
const COMPACT_FULL_CACHE_BYTE_BUDGET: usize = 40 * 1024 * 1024;
const COMPACT_GLOBAL_CACHE_BYTE_BUDGET: usize =
    COMPACT_PENDING_CACHE_BYTE_BUDGET + COMPACT_FULL_CACHE_BYTE_BUDGET;
const MESH_COMPACT_V1_MAGIC: [u8; 8] = *b"A9CMPCT\0";
const MESH_COMPACT_V1_VERSION: u8 = 1;
/// Fresh coinbases are small. Keeping this transport-only ceiling well above
/// their canonical encoding prevents a malformed full-frame coinbase from
/// defeating the purpose of the compact announcement. Construction falls back
/// to the traditional full-block path if this limit is ever exceeded.
const COMPACT_COINBASE_MAX_ENCODED_BYTES: usize = 16 * 1024;
const COMPACT_CAPABILITY_TTL: Duration = Duration::from_secs(15 * 60);
const COMPACT_RESOLVE_DEADLINE: Duration = Duration::from_secs(30);
/// Covers compact body resolution, the normal witness-resolution deadline, and
/// validation headroom. A stale claim can be replaced atomically after this.
const COMPACT_INFLIGHT_TTL: Duration = Duration::from_secs(70);

// STUN servers for NAT traversal
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun.stunprotocol.org:3478",
];

//----------------------------------------------------------------------
// Error Handling
//----------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum NodeError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Blockchain error: {0}")]
    Blockchain(String),

    #[error("Database error: {0}")]
    Database(#[from] sled::Error),

    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Consensus failure: {0}")]
    ConsensusFailure(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid address format: {0}")]
    InvalidAddressFormat(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Velocity error: {0}")]
    Velocity(String),

    #[error("Retryable: {0}")]
    Retryable(String),
}

// Implement Clone manually
impl Clone for NodeError {
    fn clone(&self) -> Self {
        match self {
            Self::Network(s) => Self::Network(s.clone()),
            Self::Blockchain(_) => Self::Network("Blockchain error".to_string()),
            Self::Database(_) => Self::Network("Database error".to_string()),
            Self::InvalidBlock(s) => Self::InvalidBlock(s.clone()),
            Self::InvalidTransaction(s) => Self::InvalidTransaction(s.clone()),
            Self::ConsensusFailure(s) => Self::ConsensusFailure(s.clone()),
            Self::InvalidAddress(s) => Self::InvalidAddress(s.clone()),
            Self::InvalidAddressFormat(s) => Self::InvalidAddressFormat(s.clone()),
            Self::Timeout(s) => Self::Timeout(s.clone()),
            Self::Io(_) => Self::Network("I/O error".to_string()),
            Self::Serialization(s) => Self::Serialization(s.clone()),
            Self::RateLimit(s) => Self::RateLimit(s.clone()),
            Self::Velocity(_) => Self::Network("Velocity error".to_string()),
            Self::Retryable(s) => Self::Retryable(s.clone()),
        }
    }
}

// Implement std::io::Error conversion to avoid Clone issues
impl From<std::io::Error> for NodeError {
    fn from(err: std::io::Error) -> Self {
        NodeError::Io(err.to_string())
    }
}

// Fix VelocityError conversion
impl From<VelocityError> for NodeError {
    fn from(err: VelocityError) -> Self {
        NodeError::Velocity(err.to_string())
    }
}

impl From<BlockchainError> for NodeError {
    fn from(err: BlockchainError) -> Self {
        NodeError::Blockchain(err.to_string())
    }
}

impl From<codec::CodecError> for NodeError {
    fn from(err: codec::CodecError) -> Self {
        NodeError::Serialization(format!("Codec error: {}", err))
    }
}

impl From<tokio::time::error::Elapsed> for NodeError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        NodeError::Timeout("Operation timed out".to_string())
    }
}

impl From<tokio::sync::AcquireError> for NodeError {
    fn from(err: tokio::sync::AcquireError) -> Self {
        NodeError::Network(format!("Lock acquisition error: {}", err))
    }
}

impl From<String> for NodeError {
    fn from(err: String) -> Self {
        NodeError::Network(err)
    }
}

//----------------------------------------------------------------------
// Helper Structures
//----------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubnetGroup {
    data: [u8; 16], // Store up to 128 bits for IPv6 or 32 bits for IPv4
    len: u8,        // Store the prefix length (0-128)
}

impl SubnetGroup {
    /// Group `ip` into its diversity bucket.
    ///
    /// An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is folded to real IPv4 FIRST, so it is
    /// capped as an IPv4 /24 rather than counted as a distinct IPv6 group — otherwise an
    /// attacker reaching a dual-stack listener could vary the mapped form freely and walk
    /// straight past the subnet-diversity cap. The fold lives here, in the one function every
    /// caller goes through, because it used to live in PeerInfo::new alone and the two
    /// handshake sites that build a PeerInfo literal bypassed it.
    fn from_ip(ip: IpAddr, mask_v4: u8, mask_v6: u8) -> Self {
        let ip = match ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        match ip {
            IpAddr::V4(ipv4) => {
                let mut data = [0u8; 16];
                data[0..4].copy_from_slice(&ipv4.octets());

                // Apply subnet mask
                let mask = mask_v4;
                let full_bytes = (mask / 8) as usize;
                let remainder_bits = mask % 8;

                if full_bytes < 4 && remainder_bits > 0 {
                    let mask_byte = 0xff_u8 << (8 - remainder_bits);
                    data[full_bytes] &= mask_byte;
                }

                let zero_start = if remainder_bits == 0 {
                    full_bytes
                } else {
                    full_bytes + 1
                };
                for byte in data.iter_mut().take(4).skip(zero_start) {
                    *byte = 0;
                }

                Self { data, len: mask }
            }
            IpAddr::V6(ipv6) => {
                let mut data = [0u8; 16];
                data.copy_from_slice(&ipv6.octets());

                // Apply subnet mask
                let mask = mask_v6;
                let full_bytes = (mask / 8) as usize;
                let remainder_bits = mask % 8;

                if full_bytes < 16 && remainder_bits > 0 {
                    let mask_byte = 0xff_u8 << (8 - remainder_bits);
                    data[full_bytes] &= mask_byte;
                }

                let zero_start = if remainder_bits == 0 {
                    full_bytes
                } else {
                    full_bytes + 1
                };
                for byte in data.iter_mut().skip(zero_start) {
                    *byte = 0;
                }

                Self { data, len: mask }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: SocketAddr,
    pub version: u32,
    pub last_seen: u64,
    pub blocks: u32,
    pub latency: u64,
    pub subnet_group: SubnetGroup,
}

impl PeerInfo {
    pub fn new(addr: SocketAddr) -> Self {
        // Normalization and mask selection both live in SubnetGroup::from_ip.
        let subnet_group = SubnetGroup::from_ip(addr.ip(), SUBNET_MASK_IPV4, SUBNET_MASK_IPV6);

        Self {
            address: addr,
            version: NETWORK_VERSION,
            last_seen: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            blocks: 0,
            latency: 0,
            subnet_group,
        }
    }

    // Added method to get subnet from IP
    pub fn get_subnet(&self, ip: IpAddr) -> Option<SubnetGroup> {
        Some(SubnetGroup::from_ip(ip, SUBNET_MASK_IPV4, SUBNET_MASK_IPV6))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub version: u32,
    pub timestamp: u64,
    pub nonce: [u8; 32],
    pub public_key: Vec<u8>,
    pub node_id: String,
    pub network_id: [u8; 32],
    pub listen_port: u16,
    pub blockchain_height: u32,
    pub signature: Vec<u8>,
}

/// A transport-only compact block announcement.
///
/// `transaction_hashes` contains the ordered, full 32-byte hashes of the exact
/// normalized transaction encodings used by the consensus Merkle tree. The full
/// coinbase is included because it is block-specific; regular transactions are
/// reconstructed from the verified mempool/witness cache or requested in bounded
/// batches from the announcing peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactBlockV1 {
    pub index: u32,
    pub previous_hash: [u8; 32],
    pub timestamp: u64,
    pub nonce: u64,
    pub difficulty: u64,
    pub hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub coinbase: Transaction,
    pub transaction_hashes: Vec<[u8; 32]>,
}

impl CompactBlockV1 {
    fn from_block(block: &Block) -> Result<Self, NodeError> {
        // Compact is only an optimization for blocks whose unchanged full body
        // can be reconstructed and carried by this transport.  Never announce a
        // block that downstream peers could not recover after a cache miss.
        if !Node::compact_block_transport_ok(block) {
            return Err(NodeError::InvalidBlock(
                "compact block source is not transport eligible".into(),
            ));
        }
        let coinbase = block
            .transactions
            .first()
            .filter(|tx| tx.sender == "MINING_REWARDS")
            .cloned()
            .ok_or_else(|| {
                NodeError::InvalidBlock("compact block source has no leading coinbase".into())
            })?;
        if !Self::coinbase_transport_size_ok(&coinbase) {
            return Err(NodeError::InvalidBlock(
                "compact block coinbase exceeds transport limit".into(),
            ));
        }
        let transaction_hashes = block
            .transactions
            .iter()
            .map(Blockchain::calculate_merkle_leaf_hash)
            .collect::<Result<Vec<_>, _>>()?;

        let compact = Self {
            index: block.index,
            previous_hash: block.previous_hash,
            timestamp: block.timestamp,
            nonce: block.nonce,
            difficulty: block.difficulty,
            hash: block.hash,
            merkle_root: block.merkle_root,
            coinbase,
            transaction_hashes,
        };
        if codec::serialize(&compact)?.len() > COMPACT_ANNOUNCEMENT_MAX_BYTES {
            return Err(NodeError::InvalidBlock(
                "compact block announcement exceeds transport limit".into(),
            ));
        }
        Ok(compact)
    }

    fn coinbase_transport_size_ok(coinbase: &Transaction) -> bool {
        codec::serialize(coinbase)
            .map(|encoded| encoded.len() <= COMPACT_COINBASE_MAX_ENCODED_BYTES)
            .unwrap_or(false)
    }

    fn encode_mesh_envelope(&self) -> Result<Vec<u8>, NodeError> {
        let payload = codec::serialize(self)?;
        let capacity = MESH_COMPACT_V1_MAGIC
            .len()
            .checked_add(1)
            .and_then(|value| value.checked_add(payload.len()))
            .ok_or_else(|| NodeError::Serialization("compact mesh envelope overflow".into()))?;
        if capacity > COMPACT_ANNOUNCEMENT_MAX_BYTES {
            return Err(NodeError::InvalidBlock(
                "compact mesh envelope exceeds transport limit".into(),
            ));
        }
        let mut envelope = Vec::with_capacity(capacity);
        envelope.extend_from_slice(&MESH_COMPACT_V1_MAGIC);
        envelope.push(MESH_COMPACT_V1_VERSION);
        envelope.extend_from_slice(&payload);
        Ok(envelope)
    }

    fn decode_mesh_envelope(raw: &[u8]) -> Option<Self> {
        let header_len = MESH_COMPACT_V1_MAGIC.len().checked_add(1)?;
        if raw.len() <= header_len
            || raw.len() > COMPACT_ANNOUNCEMENT_MAX_BYTES
            || raw.get(..MESH_COMPACT_V1_MAGIC.len())? != MESH_COMPACT_V1_MAGIC
            || *raw.get(MESH_COMPACT_V1_MAGIC.len())? != MESH_COMPACT_V1_VERSION
        {
            return None;
        }
        codec::deserialize(raw.get(header_len..)?).ok()
    }

    fn header_block(&self) -> Block {
        Block {
            index: self.index,
            previous_hash: self.previous_hash,
            timestamp: self.timestamp,
            transactions: Vec::new(),
            nonce: self.nonce,
            difficulty: self.difficulty,
            hash: self.hash,
            merkle_root: self.merkle_root,
        }
    }

    fn validate_commitment(&self) -> bool {
        if self.transaction_hashes.is_empty()
            || self.transaction_hashes.len() > MAX_BLOCK_TX_COUNT
            || self.coinbase.sender != "MINING_REWARDS"
            || !Self::coinbase_transport_size_ok(&self.coinbase)
        {
            return false;
        }

        let coinbase_hash = match Blockchain::calculate_merkle_leaf_hash(&self.coinbase) {
            Ok(hash) => hash,
            Err(_) => return false,
        };
        if self.transaction_hashes[0] != coinbase_hash {
            return false;
        }

        let committed_root =
            match Blockchain::calculate_merkle_root_from_leaf_hashes(&self.transaction_hashes) {
                Ok(root) => root,
                Err(_) => return false,
            };
        if committed_root != self.merkle_root {
            return false;
        }

        let header = self.header_block();
        header.validate_header().is_ok() && header.verify_pow_meets_floor()
    }

    fn reconstruct(&self, transactions: Vec<Transaction>) -> Result<Block, NodeError> {
        if transactions.len() != self.transaction_hashes.len() {
            return Err(NodeError::InvalidBlock(
                "compact block transaction count mismatch".into(),
            ));
        }
        for (tx, expected) in transactions.iter().zip(&self.transaction_hashes) {
            let actual = Blockchain::calculate_merkle_leaf_hash(tx)?;
            if &actual != expected {
                return Err(NodeError::InvalidBlock(
                    "compact block transaction commitment mismatch".into(),
                ));
            }
        }

        let block = Block {
            index: self.index,
            previous_hash: self.previous_hash,
            timestamp: self.timestamp,
            transactions,
            nonce: self.nonce,
            difficulty: self.difficulty,
            hash: self.hash,
            merkle_root: self.merkle_root,
        };
        if block.calculate_hash_for_block() != block.hash {
            return Err(NodeError::InvalidBlock(
                "compact block reconstructed header mismatch".into(),
            ));
        }
        Ok(block)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IndexedCompactTransactionV1 {
    pub index: u16,
    pub transaction: Transaction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Version {
        version: u32,
        blockchain_height: u32,
        node_id: String,
    },
    Block(Block),
    Transaction(Transaction),
    TxRequest {
        tx_id: String,
    },
    TxResponse {
        tx_id: String,
        tx: Option<Transaction>,
    },
    GetBlocks {
        start: u32,
        end: u32,
    },
    GetHeaders {
        start_height: u32,
        end_height: u32,
    },
    AlertMessage(String),
    HeaderVerification {
        header: BlockHeaderInfo,
        node_id: String,
        signature: Vec<u8>,
    },
    HeaderSync {
        headers: Vec<BlockHeaderInfo>,
        node_id: String,
        signature: Vec<u8>,
    },
    MldsaKeyRegistration {
        node_id: String,
        mldsa_public_key: Vec<u8>,
        ed25519_signature: Vec<u8>,
    },
    Challenge(Vec<u8>),
    ChallengeResponse {
        signature: Vec<u8>,
        node_id: String,
    },
    Shred(Shred),
    ShredRequest(ShredRequestType),
    ShredResponse {
        block_hash: [u8; 32],
        shreds: Vec<Shred>,
    },
    Blocks(Vec<Block>),
    GetPeers,
    Peers(Vec<SocketAddr>),
    GetBlockHeight,
    BlockHeight(u32),
    WalletInfo {
        address: String,
        public_key_hex: String,
        signature: Vec<u8>,
    },
    GetWalletInfo {
        address: String,
    },
    WalletInfoResponse {
        address: String,
        exists: bool,
        public_key_hex: Option<String>,
    },
    Ping {
        timestamp: u64,
        node_id: String,
    },
    Pong {
        timestamp: u64,
        node_id: String,
    },
    RawData(Vec<u8>),
    // APPEND transport extensions so existing NetworkMessage variant indexes stay
    // byte-for-byte stable. These are sent only to capability-negotiated peers.
    CompactBlockV1(CompactBlockV1),
    GetCompactTransactionsV1 {
        block_hash: [u8; 32],
        indexes: Vec<u16>,
        proxy_hops: u8,
    },
    CompactTransactionsV1 {
        block_hash: [u8; 32],
        transactions: Vec<IndexedCompactTransactionV1>,
    },
    GetCompactBlockV1 {
        block_hash: [u8; 32],
        proxy_hops: u8,
    },
    CompactBlockResponseV1 {
        block_hash: [u8; 32],
        block: Option<Block>,
    },
}

#[derive(Debug)]
pub enum NetworkEvent {
    NewTransaction(Transaction),
    NewBlock(Block),
    PeerJoin(SocketAddr),
    PeerLeave(SocketAddr),
    ChainRequest {
        start: u32,
        end: u32,
        requester: SocketAddr,
        response_channel: Arc<tokio::sync::Mutex<Option<oneshot::Sender<Vec<Block>>>>>,
    },
    ChainResponse {
        blocks: Vec<Block>,
        sender: SocketAddr,
    },
}

// For use with clone(), as ChainRequest has a oneshot channel
impl Clone for NetworkEvent {
    fn clone(&self) -> Self {
        match self {
            NetworkEvent::NewTransaction(tx) => NetworkEvent::NewTransaction(tx.clone()),
            NetworkEvent::NewBlock(block) => NetworkEvent::NewBlock(block.clone()),
            NetworkEvent::PeerJoin(addr) => NetworkEvent::PeerJoin(*addr),
            NetworkEvent::PeerLeave(addr) => NetworkEvent::PeerLeave(*addr),
            NetworkEvent::ChainResponse { blocks, sender } => NetworkEvent::ChainResponse {
                blocks: blocks.clone(),
                sender: *sender,
            },
            NetworkEvent::ChainRequest {
                start,
                end,
                requester,
                response_channel,
            } => NetworkEvent::ChainRequest {
                start: *start,
                end: *end,
                requester: *requester,
                response_channel: response_channel.clone(),
            },
        }
    }
}

//----------------------------------------------------------------------
// Bloom Filter for Message Deduplication
//----------------------------------------------------------------------

#[derive(Debug)]
pub struct NetworkBloom {
    bits: Vec<AtomicBool>,
    num_hashes: usize,
    size: usize,
    max_items_before_reset: usize,
    items_count: AtomicUsize,
    // Per-process random seed mixed into every hash. Without it the ~1% false-positive
    // pattern is identical on every node (DefaultHasher has fixed keys), so an item that
    // false-positives at one node's dedup gate false-positives at all of them — silently
    // dropping the same never-seen block or tx network-wide. A random seed decorrelates it.
    seed: u64,
}

impl NetworkBloom {
    pub fn new(size: usize, fpr: f64) -> Self {
        let size = size.max(8);
        let max_items_before_reset = Self::optimal_item_capacity(size, fpr);
        let num_hashes = Self::optimal_num_hashes(size, max_items_before_reset);
        let bits = (0..size).map(|_| AtomicBool::new(false)).collect();

        Self {
            bits,
            num_hashes,
            size,
            max_items_before_reset,
            items_count: AtomicUsize::new(0),
            seed: Self::random_seed(),
        }
    }

    pub fn insert(&self, item: &[u8]) -> bool {
        self.rotate_if_needed();

        let mut was_new = false;

        for i in 0..self.num_hashes {
            let hash = self.hash(item, i);
            let idx = hash as usize % self.bits.len();

            let old = self.bits[idx].swap(true, Ordering::Relaxed);
            was_new |= !old;
        }

        if was_new {
            self.items_count.fetch_add(1, Ordering::Relaxed);
        }

        was_new
    }

    pub fn check(&self, item: &[u8]) -> bool {
        (0..self.num_hashes).all(|i| {
            let hash = self.hash(item, i);
            let idx = hash as usize % self.bits.len();
            self.bits[idx].load(Ordering::Relaxed)
        })
    }

    pub fn clear(&self) {
        for bit in &self.bits {
            bit.store(false, Ordering::Relaxed);
        }
        self.items_count.store(0, Ordering::Relaxed);
    }

    fn rotate_if_needed(&self) {
        if self.items_count.load(Ordering::Relaxed) >= self.max_items_before_reset {
            self.clear();
        }
    }

    fn optimal_item_capacity(size: usize, fpr: f64) -> usize {
        let fpr = if fpr.is_finite() {
            fpr.clamp(1e-9, 0.5)
        } else {
            0.01
        };
        let capacity = -((size as f64) * std::f64::consts::LN_2.powi(2)) / fpr.ln();
        capacity.floor().max(1.0) as usize
    }

    fn optimal_num_hashes(size: usize, expected_items: usize) -> usize {
        let expected_items = expected_items.max(1);
        (((size as f64 / expected_items as f64) * std::f64::consts::LN_2).round() as usize).max(1)
    }

    fn hash(&self, data: &[u8], round: usize) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.seed.hash(&mut hasher);
        round.hash(&mut hasher);
        data.hash(&mut hasher);
        hasher.finish()
    }

    fn random_seed() -> u64 {
        // RandomState is seeded from the OS RNG on each construction; hashing nothing yields a
        // per-process-random u64 with no extra dependency.
        use std::hash::BuildHasher;
        std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish()
    }

    pub fn load_factor(&self) -> f64 {
        let set_bits = self
            .bits
            .iter()
            .filter(|bit| bit.load(Ordering::Relaxed))
            .count();

        set_bits as f64 / self.size as f64
    }

    pub fn item_count(&self) -> usize {
        self.items_count.load(Ordering::Relaxed)
    }
}

impl Clone for NetworkBloom {
    fn clone(&self) -> Self {
        let bits = self
            .bits
            .iter()
            .map(|bit| AtomicBool::new(bit.load(Ordering::Relaxed)))
            .collect();

        Self {
            bits,
            num_hashes: self.num_hashes,
            size: self.size,
            max_items_before_reset: self.max_items_before_reset,
            items_count: AtomicUsize::new(self.items_count.load(Ordering::Relaxed)),
            // Keep the same seed: the copied bits only mean anything under the seed that set them.
            seed: self.seed,
        }
    }
}

//----------------------------------------------------------------------
// Validation Pool
//----------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ValidationPool {
    available: Arc<Semaphore>,
    // Network-bound witness fetches draw from this SEPARATE pool, so a peer that answers slowly can
    // never occupy a validation permit. Only blocks that must fetch a missing witness contend here;
    // locally-resolvable blocks never touch it.
    fetch: Arc<Semaphore>,
    timeout: Duration,
}

impl ValidationPool {
    pub fn new() -> Self {
        Self {
            available: Arc::new(Semaphore::new(MAX_PARALLEL_VALIDATIONS)),
            fetch: Arc::new(Semaphore::new(MAX_PARALLEL_WITNESS_FETCHES)),
            timeout: Duration::from_secs(30),
        }
    }

    // One slot for a single outbound witness fetch. Non-blocking: if the fetch pool is saturated the
    // caller treats the witness as unresolved and defers the block (it re-verifies later) rather than
    // queueing behind slow peers.
    fn acquire_fetch_slot(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.fetch.clone().try_acquire_owned().ok()
    }

    async fn acquire_validation_permit(&self) -> Result<ValidationPermit<'_>, NodeError> {
        match timeout(self.timeout, self.available.acquire()).await {
            Ok(Ok(permit)) => Ok(ValidationPermit { _permit: permit }),
            Ok(Err(e)) => Err(NodeError::Network(format!(
                "Failed to acquire permit: {}",
                e
            ))),
            Err(_) => Err(NodeError::Timeout("Validation timeout".to_string())),
        }
    }
}

impl Default for ValidationPool {
    fn default() -> Self {
        Self::new()
    }
}

// RAII holder for a validation permit: keeps the semaphore permit alive until dropped
// (the permit releases itself on drop).
struct ValidationPermit<'a> {
    _permit: tokio::sync::SemaphorePermit<'a>,
}

//----------------------------------------------------------------------
// P2P Swarm (libp2p integration)
//----------------------------------------------------------------------

#[derive(NetworkBehaviour)]
#[behaviour(
    to_swarm = "HybridBehaviourEvent",
    prelude = "libp2p_swarm::derive_prelude"
)]
pub struct HybridBehaviour {
    kademlia: Kademlia<MemoryStore>,
}

#[derive(Debug)]
pub enum HybridBehaviourEvent {
    Kademlia(KademliaEvent),
}

impl From<KademliaEvent> for HybridBehaviourEvent {
    fn from(event: KademliaEvent) -> Self {
        HybridBehaviourEvent::Kademlia(event)
    }
}

impl std::fmt::Debug for HybridBehaviour {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridBehaviour")
            .field("kademlia", &"Kademlia<MemoryStore>")
            .finish()
    }
}

pub struct HybridSwarm(Swarm<HybridBehaviour>);

impl Deref for HybridSwarm {
    type Target = Swarm<HybridBehaviour>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for HybridSwarm {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::fmt::Debug for HybridSwarm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridSwarm")
    }
}

//----------------------------------------------------------------------
// TcpNatConfig
//----------------------------------------------------------------------

#[derive(Clone)]
pub struct TcpNatConfig {
    pub external_port: u16,
    pub supports_upnp: bool,
    pub supports_nat_pmp: bool,
    pub connect_timeout: Duration,
    pub mapping_lifetime: Duration,
    pub max_retries: u32,
}

//----------------------------------------------------------------------
// Node Implementation
//----------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct NodeRuntimeConfig {
    pub bind_addr: Option<SocketAddr>,
    pub velocity_enabled: bool,
    pub max_peers: usize,
    pub max_connections: usize,
    pub seed_nodes: Vec<String>,
    /// Resolved chain-DB path; the peer cache lives NEXT TO it (same parent dir)
    /// so the address book survives reboots. None falls back to the OS temp dir
    /// (the old default, which OS cleaners wipe — exactly when it matters).
    pub data_dir: Option<String>,
}

/// Byte budget for the transaction-witness memoization cache. The cache is also count-bounded
/// (witness_cache_capacity), but every witness Transaction carries a full ML-DSA signature and public
/// key (~14 KB each), so the count cap alone permits hundreds of MB resident. Bound the bytes directly
/// so a busy chain — or a witness larger than today's — cannot bloat memory past this budget.
const WITNESS_CACHE_BYTE_BUDGET: usize = 64 * 1024 * 1024; // 64 MiB

/// An LruCache of resolved tx witnesses that also enforces a byte budget: on insert it evicts the
/// least-recently-used entries until the tracked resident size is within budget (never the entry just
/// inserted). The count cap still applies — whichever bound binds first wins.
#[derive(Debug)]
struct WitnessCache {
    // Held UNBOUNDED so that every eviction goes through `put` below (which keeps the byte counter in
    // sync). If the inner LruCache enforced the count cap itself, its internal eviction on a full
    // insert would drop an entry WITHOUT decrementing `bytes`, leaking the counter (and eventually
    // wedging the cache) whenever the count cap binds before the byte budget.
    cache: LruCache<String, Transaction>,
    bytes: usize,
    byte_budget: usize,
    count_cap: usize,
}

impl WitnessCache {
    fn new(count_cap: NonZeroUsize, byte_budget: usize) -> Self {
        Self {
            cache: LruCache::unbounded(),
            bytes: 0,
            byte_budget,
            count_cap: count_cap.get(),
        }
    }

    /// Approximate resident footprint of a cached witness — dominated by the ML-DSA signature and
    /// public-key hex strings. Byte-exactness is unnecessary; this only paces eviction.
    fn entry_bytes(tx: &Transaction) -> usize {
        tx.signature.as_ref().map_or(0, |s| s.len())
            + tx.pub_key.as_ref().map_or(0, |s| s.len())
            + tx.sig_hash.as_ref().map_or(0, |s| s.len())
            + tx.sender.len()
            + tx.recipient.len()
            // Slack for what the field sum omits: the String KEY (the tx_id), the LinkedHashMap node,
            // the Transaction's fixed fields, and String capacity overhead. Deliberately generous so
            // the budget errs toward LESS resident memory, not more. Dominated by sig+pub_key anyway.
            + 256
    }

    fn put(&mut self, tx_id: String, tx: Transaction) {
        let added = Self::entry_bytes(&tx);
        if let Some(old) = self.cache.put(tx_id, tx) {
            self.bytes = self.bytes.saturating_sub(Self::entry_bytes(&old));
        }
        self.bytes = self.bytes.saturating_add(added);
        // Evict LRU until within BOTH the byte budget and the count cap. The just-inserted key is the
        // MRU, so pop_lru targets older entries; the len() > 1 guard makes it impossible to evict the
        // entry just inserted even if it alone exceeds the budget.
        while (self.bytes > self.byte_budget || self.cache.len() > self.count_cap)
            && self.cache.len() > 1
        {
            match self.cache.pop_lru() {
                Some((_, evicted)) => {
                    self.bytes = self.bytes.saturating_sub(Self::entry_bytes(&evicted));
                }
                None => break,
            }
        }
    }

    fn get(&mut self, tx_id: &str) -> Option<&Transaction> {
        self.cache.get(tx_id)
    }

    fn pop(&mut self, tx_id: &str) -> Option<Transaction> {
        let removed = self.cache.pop(tx_id);
        if let Some(ref tx) = removed {
            self.bytes = self.bytes.saturating_sub(Self::entry_bytes(tx));
        }
        removed
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    // Core components
    pub db: Arc<Db>,
    pub blockchain: Arc<RwLock<Blockchain>>,
    pub bind_addr: SocketAddr,
    pub listener: Option<Arc<TcpListener>>,
    pub node_id: String,
    pub start_time: u64,

    // Network state
    pub peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    max_peers: usize,
    max_connections: usize,
    pub network_health: Arc<RwLock<NetworkHealth>>,
    network_bloom: Arc<NetworkBloom>,
    peer_failures: Arc<RwLock<HashMap<SocketAddr, u32>>>,
    peer_secrets: Arc<RwLock<HashMap<SocketAddr, Vec<u8>>>>,
    outbound_connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<OutboundConnection>>>>>,
    outbound_circuit_breakers: Arc<RwLock<HashMap<SocketAddr, OutboundCircuitState>>>,
    pub rate_limiter: Arc<RateLimiter>,
    http_client: Client,
    discovery_state: Arc<Mutex<DiscoveryState>>,
    // Single-flight flag for discover_network_nodes. Kept in an AtomicBool (not
    // inside the async-Mutex DiscoveryState) so an RAII guard can clear it in a
    // sync Drop on any exit — return, error, panic, or task cancellation — instead
    // of a straight-line reset that unwinding skips (which wedged discovery off).
    discovery_in_progress: Arc<AtomicBool>,
    public_relay_tip: Arc<RwLock<Option<RelayTipState>>>,
    // Relay tip candidates that recently FAILED to converge (ancestry unfetchable —
    // e.g. a gap-broken abandoned fork whose owner's POSTs were rate-limited away).
    // converge_to_relay_tip memoizes them so the 1s publisher tick moves on to the
    // next-best live branch instead of re-walking the same dead fork forever (the
    // 2026-07-08 frozen-beacon incident: a dead max-height fork at 1240 pinned the
    // publisher at 1209 while live miners advanced).
    // Value = (when memoized, hard). `hard` marks a VALIDATION failure (invalid
    // branch): hard deadness propagates to descendants via the ancestry check, so a
    // growing invalid fork costs one validation total, not one per posted block.
    // Soft entries (transient walk/gap failures) time out but never propagate —
    // a momentary relay gap must not poison the live chain's fresh tips.
    #[allow(clippy::type_complexity)] // (height, hash) -> (retry instant, permanently rejected).
    relay_dead_targets: Arc<PLMutex<LruCache<(u32, [u8; 32]), (Instant, bool)>>>,
    // Relay-once bookkeeping for the early (pre-full-validation) block relay. DISJOINT from
    // network_bloom by construction, so early-relay accounting never touches the acceptance dedup
    // path: a block forwarded early is recorded here, never in the shared bloom, so it can never
    // suppress a later witness-bearing delivery that the node must still fully validate and accept.
    early_relay_seen: Arc<PLMutex<LruCache<[u8; 32], ()>>>,
    /// Per-block set of peers that successfully received the compact announcement.
    /// Failed or never-selected peers remain eligible on a later relay pass; this
    /// bookkeeping is independent from full-block relay and acceptance dedup.
    compact_relay_delivered: Arc<PLMutex<LruCache<[u8; 32], HashSet<SocketAddr>>>>,
    /// Peers that advertised CompactBlockV1 over the backward-compatible ping/pong
    /// capability marker. Entries expire unless refreshed by health pings.
    compact_capable_peers: Arc<DashMap<SocketAddr, Instant>>,
    /// Bounds duplicate concurrent reconstruction work without poisoning the
    /// definitive block dedup bloom on a transient missing-body failure.
    compact_inflight: Arc<DashMap<[u8; 32], CompactInflight>>,
    /// Caps all simultaneous compact reconstruction/validation work. Excess
    /// announcements retain their source metadata and await the normal full
    /// transport instead of queueing unbounded allocations.
    compact_reconstruction_slots: Arc<Semaphore>,
    /// Separate, low-concurrency lane for retrieving the unchanged full body of
    /// a same-height/next-height competitor. It preserves ordinary fork delivery
    /// without allowing off-tip announcements to occupy reconstruction slots.
    compact_fork_fallback_slots: Arc<Semaphore>,
    /// Recent compact announcements and exact-hash-matched transaction bodies,
    /// retained so a cut-through relay can serve or proxy downstream batch requests.
    compact_pending: Arc<PLMutex<CompactPendingCache>>,
    /// Recent full bodies, bounded independently. Used for missing-body replies and
    /// explicit fallback; gateway and canonical storage remain unchanged.
    compact_full_blocks: Arc<PLMutex<CompactFullBlockCache>>,
    /// Exact normalized Merkle leaf -> verified witness-cache key. This small index
    /// reuses the existing bounded full-witness cache instead of duplicating ML-DSA
    /// transaction bodies.
    compact_tx_index: Arc<PLMutex<LruCache<[u8; 32], String>>>,
    last_public_announce_at: Arc<AtomicU64>,
    /// Last announce ATTEMPT (success or failure) — throttles failure retries to
    /// ANNOUNCE_RETRY_SECS without silencing the loop for the full interval.
    last_public_announce_attempt_at: Arc<AtomicU64>,
    /// Consecutive HTTP-REJECTED announces (gateway up, non-2xx). Drives the
    /// exponential retry backoff; reset on success. Pure network errors don't
    /// count — see ANNOUNCE_RETRY_SECS.
    announce_reject_streak: Arc<AtomicU64>,
    /// STUN-discovered external IP + unix time discovered (TTL-cached so outage
    /// retries don't re-query third-party STUN servers every 30s).
    cached_external_ip: Arc<RwLock<Option<(IpAddr, u64)>>>,
    /// Tip observed at the previous converge_to_canonical call (stall watchdog).
    converge_stall_tip: Arc<AtomicU64>,
    /// Unix-millis of the last counted converge-stall increment; gates increments to at most one per
    /// CONVERGE_STALL_MIN_INTERVAL_MS so a per-pass candidate burst counts once (see that const).
    converge_stall_last_ms: Arc<AtomicU64>,
    /// Consecutive zero-progress converge calls while > reorg-margin behind a
    /// fresh beacon; escalates to NeedsBootstrap at CONVERGE_STALL_ESCALATE_CALLS.
    converge_stall_cycles: Arc<AtomicU64>,
    /// True while a bulk peer delta-sync (sync_full_history_from_peer) is streaming.
    /// The idle reconcile loop, the beacon-watch loop and mine-prep can all decide to
    /// heal the same far-behind chain at once (they all fire together on a
    /// wake-from-sleep); overlapping calls return immediately instead of
    /// double-streaming the same span. See sync_full_history_from_peer_bounded.
    full_sync_in_flight: Arc<AtomicBool>,
    /// ~1s TTL memo of the last successfully fetched signed tip beacon
    /// (fetch_tip_beacon): dedups same-second fetch bursts across the many
    /// beacon consumers without changing any staleness guarantee.
    beacon_memo: Arc<PLMutex<Option<(Instant, TipBeaconInfo)>>>,
    /// Rolling window of recent (observed-at, height) beacon reads that positively
    /// matched our network. The mine-prep stale-tip guard consults the MAX height in
    /// the window as "the freshest network height we can trust." A ROLLING max (not a
    /// forever-monotonic one) is deliberate: a forever high-water pinned every miner
    /// into refusing to mine after a genuine canonical REGRESSION (publisher
    /// re-bootstrap onto a lower true chain, or a heavier-but-shorter reorg) with no
    /// exit but a process restart (2026-07-12 audit). A rolling max still catches a
    /// momentary stale CDN read (fresh reads every ~5s keep re-raising it, so one
    /// stale-low copy can never be the window max), but lets a stuck-high value age
    /// out after a real regression. Uses NO timestamp from the beacon body (miner-set
    /// block_time is forgeable +300s) — only the local observation time.
    beacon_high_water: Arc<PLMutex<std::collections::VecDeque<(Instant, u32)>>>,
    /// Forever-monotonic max of every network_id-matched beacon height ever seen.
    /// Used ONLY by the beacon-UNREACHABLE fail-open bound: during a total beacon
    /// outage there are no fresh reads, so the rolling window would age out to 0 and
    /// let a genuinely far-behind node fail-open into mining orphans hundreds below
    /// the network (the 2026-07-11 far-behind incident). Aging out is only safe when
    /// fresh LOW reads confirm a regression — which the reachable +2 ghost arms have
    /// (they use the rolling window) but the unreachable arm does not. So this monotonic
    /// value stays for the outage case; the rolling window handles reachable recovery.
    last_seen_beacon_height: Arc<AtomicU64>,
    /// Resolved chain-DB directory (same value main.rs boots with) — lets runtime
    /// paths schedule a force-re-bootstrap marker. None in tests/embedded uses.
    chain_data_dir: Option<Arc<str>>,
    /// PEX-learned dialable addresses -> unix time last learned (bounded by
    /// PEX_ADDR_BOOK_CAP, aged out after PEX_ADDR_TTL_SECS), merged into the
    /// persisted peer cache so the address book outgrows our own connections.
    pex_addr_book: Arc<RwLock<HashMap<SocketAddr, u64>>>,
    last_header_snapshot_at: Arc<AtomicU64>,
    last_header_snapshot_height: Arc<AtomicU64>,
    last_stats_snapshot_at: Arc<AtomicU64>,
    p2p_swarm: Arc<Mutex<Option<HybridSwarm>>>,
    pub peer_id: String,
    inbound_attempts: Arc<RwLock<HashMap<IpAddr, (u32, u64)>>>,
    peer_cache_path: Arc<String>,
    configured_seed_nodes: Arc<Vec<String>>,

    // Consensus state
    tx_witness_cache: Arc<PLMutex<WitnessCache>>,
    pub validation_pool: Arc<ValidationPool>,
    validation_cache: Arc<DashMap<String, ValidationCacheEntry>>,
    // Peers we recently sent a GetBlocks request to. Inbound block responses are
    // correlated against this set: a `ChainResponse` from a peer we did not
    // solicit is untrusted and never applied to canonical state.
    solicited_block_peers: Arc<DashMap<SocketAddr, Instant>>,
    tx: broadcast::Sender<NetworkEvent>,

    // Feature components
    pub header_sentinel: Option<Arc<HeaderSentinel>>,
    pub velocity_manager: Option<Arc<VelocityManager>>,

    // Security
    network_id: [u8; 32],
    handshake_public_key: Vec<u8>,
    handshake_key_bytes: Arc<Vec<u8>>,

    // WebRTC mesh (feature `webrtc_mesh`): direct P2P DataChannels to NAT'd peers, signaled by the
    // gateway. Set once the mesh spawns; block/tx gossip is flooded here in parallel to TCP.
    #[cfg(feature = "webrtc_mesh")]
    webrtc_mesh: Arc<RwLock<Option<Arc<crate::a9::webrtc::WebRtcMesh>>>>,

    // Filesystem
    // RAII identity-lock guard (see IdentityLock): the lock file is removed only when the LAST
    // Node clone drops (process teardown), NOT on every clone drop. Held purely for its Drop —
    // never read directly, hence allow(dead_code).
    #[allow(dead_code)]
    identity_lock: Arc<IdentityLock>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum ScanNetwork {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

#[derive(Debug, Clone)]
struct ScanRange {
    network: ScanNetwork,
    priority: u8,
}

#[derive(Debug, Clone)]
struct ValidationCacheEntry {
    pub valid: bool,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone)]
struct PendingCompactBlock {
    announcement: CompactBlockV1,
    sources: Vec<SocketAddr>,
    /// Bodies whose exact normalized leaf hash was checked against the ordered
    /// announcement. They are not considered signature-verified until the normal
    /// block validation pipeline succeeds.
    transactions: HashMap<u16, Transaction>,
    transaction_sizes: HashMap<u16, usize>,
    assembled_bytes: usize,
    cache_bytes: usize,
}

#[derive(Debug, Clone)]
struct PendingCompactRoute {
    announcement: CompactBlockV1,
    sources: Vec<SocketAddr>,
}

#[derive(Debug, Clone)]
struct CompactInflight {
    started: Instant,
    sources: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompactIngressRoute {
    ReconstructLocalTip,
    FetchFullCompetitor,
    DeferToChainSync,
}

#[derive(Debug)]
struct CompactPendingCache {
    entries: LruCache<[u8; 32], PendingCompactBlock>,
    bytes: usize,
}

#[derive(Debug)]
struct CompactFullBlockEntry {
    block: Arc<Block>,
    encoded_bytes: usize,
}

#[derive(Debug)]
struct CompactFullBlockCache {
    entries: LruCache<[u8; 32], CompactFullBlockEntry>,
    bytes: usize,
}

impl CompactPendingCache {
    fn insert(&mut self, block_hash: [u8; 32], entry: PendingCompactBlock) -> bool {
        if entry.cache_bytes > COMPACT_SAFE_ASSEMBLED_BYTES
            || entry.cache_bytes > COMPACT_PENDING_CACHE_BYTE_BUDGET
        {
            return false;
        }

        if let Some(previous) = self.entries.pop(&block_hash) {
            self.bytes = self.bytes.saturating_sub(previous.cache_bytes);
        }
        while self.bytes.saturating_add(entry.cache_bytes) > COMPACT_PENDING_CACHE_BYTE_BUDGET {
            let Some((_, evicted)) = self.entries.pop_lru() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(evicted.cache_bytes);
        }
        if self.bytes.saturating_add(entry.cache_bytes) > COMPACT_PENDING_CACHE_BYTE_BUDGET {
            return false;
        }

        self.bytes = self.bytes.saturating_add(entry.cache_bytes);
        if let Some((_, evicted)) = self.entries.push(block_hash, entry) {
            self.bytes = self.bytes.saturating_sub(evicted.cache_bytes);
        }
        true
    }

    fn remove(&mut self, block_hash: &[u8; 32]) -> Option<PendingCompactBlock> {
        let removed = self.entries.pop(block_hash);
        if let Some(ref entry) = removed {
            self.bytes = self.bytes.saturating_sub(entry.cache_bytes);
        }
        removed
    }
}

impl CompactFullBlockCache {
    fn insert(&mut self, block_hash: [u8; 32], entry: CompactFullBlockEntry) -> bool {
        if entry.encoded_bytes > COMPACT_SAFE_ASSEMBLED_BYTES
            || entry.encoded_bytes > COMPACT_FULL_CACHE_BYTE_BUDGET
        {
            return false;
        }

        if let Some(previous) = self.entries.pop(&block_hash) {
            self.bytes = self.bytes.saturating_sub(previous.encoded_bytes);
        }
        while self.bytes.saturating_add(entry.encoded_bytes) > COMPACT_FULL_CACHE_BYTE_BUDGET {
            let Some((_, evicted)) = self.entries.pop_lru() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(evicted.encoded_bytes);
        }
        if self.bytes.saturating_add(entry.encoded_bytes) > COMPACT_FULL_CACHE_BYTE_BUDGET {
            return false;
        }

        self.bytes = self.bytes.saturating_add(entry.encoded_bytes);
        if let Some((_, evicted)) = self.entries.push(block_hash, entry) {
            self.bytes = self.bytes.saturating_sub(evicted.encoded_bytes);
        }
        true
    }
}

/// Spawn a load-bearing background loop under a supervisor. A panic in a plain
/// `tokio::spawn` unwinds into a JoinError nobody reads: the loop dies SILENTLY
/// and the node keeps running visibly "up" with the subsystem gone (no sync, no
/// maintenance, no watchdog — depending on which loop died). The supervisor
/// makes the panic loud and re-arms the loop with exponential backoff (2s..32s).
/// A body that returns cleanly is an intentional exit (shutdown) — not restarted.
pub fn spawn_supervised<F, Fut>(name: &'static str, mut body: F)
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut restarts: u32 = 0;
        loop {
            match tokio::spawn(body()).await {
                Ok(()) => return,
                Err(e) if e.is_panic() => {
                    restarts = restarts.saturating_add(1);
                    let wait = Duration::from_secs(2u64.saturating_pow(restarts.min(5)));
                    error!(
                        "Background task '{}' PANICKED (restart #{}); re-arming in {:?}",
                        name, restarts, wait
                    );
                    eprintln!(
                        "BUG: background task '{}' panicked and was restarted (#{}). The node keeps running — please report this.",
                        name, restarts
                    );
                    sleep(wait).await;
                }
                // Cancelled (runtime shutdown/abort): nothing to re-arm.
                Err(_) => return,
            }
        }
    });
}

/// Panic-VISIBILITY wrapper for background tasks that cannot be restarted
/// (they own a non-recreatable resource, e.g. the TCP listener): the task stays
/// down after a panic, but the operator is told instead of the node silently
/// degrading.
pub fn spawn_logged<Fut>(name: &'static str, fut: Fut)
where
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(e) = tokio::spawn(fut).await {
            if e.is_panic() {
                error!(
                    "Background task '{}' PANICKED and is DOWN until the node restarts",
                    name
                );
                eprintln!(
                    "BUG: background task '{}' panicked and is no longer running — restart the node and please report this.",
                    name
                );
            }
        }
    });
}

#[derive(Debug)]
struct OutboundConnection {
    stream: TcpStream,
    shared_secret: Vec<u8>,
    last_used: Instant,
    /// Wall-clock twin of `last_used`. `Instant` does not advance across an OS
    /// suspend (macOS/Linux), so after a sleep the idle sweep saw only the
    /// pre-sleep age and kept every half-open socket alive; the wall clock
    /// jumps across the gap and lets the sweep catch them.
    last_used_wall: SystemTime,
    /// True from just before a request frame is written until its response is
    /// fully read. A request/response exchange that was CANCELLED in between
    /// (caller-side timeout dropping the future) leaves an unconsumed response
    /// in the socket; the next exchange would read that stale frame and return
    /// the wrong message forever after ("unexpected response type"). The next
    /// holder that observes `exchange_armed == true` must discard the
    /// connection instead of using it.
    exchange_armed: bool,
}

#[derive(Debug, Clone, Default)]
struct OutboundCircuitState {
    consecutive_failures: u32,
    open_until: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct PortMappingResult {
    upnp: bool,
    nat_pmp: bool,
    external_port: Option<u16>,
}

#[derive(Clone)]
struct StatsState {
    blockchain: Arc<RwLock<Blockchain>>,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    start_time: u64,
    network_id: [u8; 32],
    // Coarse per-process token bucket so an unauthenticated flood of /stats (when
    // ALPHANUMERIC_STATS_BIND is a public interface) can't hammer the blockchain read lock.
    read_bucket: Arc<PLMutex<(Instant, f64)>>,
}

/// State for the opt-in explorer API (see start_explorer_server).
#[derive(Clone)]
struct ExplorerState {
    blockchain: Arc<RwLock<Blockchain>>,
    node: Node,
    start_time: u64,
    network_id: [u8; 32],
    // Coarse per-process token bucket for the write endpoint (submit-tx). The
    // per-sender mempool rate limit is the real guard; this only blunts a flood
    // of junk that would fail validation, keeping it off the mempool lock.
    submit_bucket: Arc<PLMutex<(Instant, f64)>>,
    // Coarse per-process token bucket for the O(chain) explorer READ endpoints (address summary,
    // supply): a node-side flood guard for the opt-in explorer, independent of any upstream proxy.
    read_bucket: Arc<PLMutex<(Instant, f64)>>,
}

#[derive(Debug, Deserialize)]
struct ExplorerAddressQuery {
    limit: Option<usize>,
    before_height: Option<u32>,
    before_pos: Option<u32>,
}

/// Query for `GET /explorer/tx?id=<tx_id>`. The tx id is a composite
/// colon-delimited string (`get_tx_id`), not URL-path-friendly, so it is passed
/// as a query parameter rather than a path segment.
#[derive(Debug, Deserialize)]
struct ExplorerTxIdQuery {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiscoveryResponse {
    ok: bool,
    peers: Vec<DiscoveryPeer>,
}

#[derive(Debug, Deserialize)]
struct DiscoveryPeer {
    ip: String,
    port: u16,
    node_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BlockRelayResponse {
    ok: bool,
    blocks: Option<Vec<BlockRelayRecord>>,
}

#[derive(Debug, Deserialize)]
struct BlockRelayRecord {
    block: Value,
}

#[derive(Debug)]
struct DiscoveryState {
    failures: u32,
    next_attempt: Instant,
}

#[derive(Debug, Clone, Copy)]
struct RelayTipState {
    height: u32,
    hash: [u8; 32],
}

impl DiscoveryState {
    fn new() -> Self {
        Self {
            failures: 0,
            next_attempt: Instant::now(),
        }
    }
}

impl Node {
    //----------------------------------------------------------------------
    // Initialization
    //----------------------------------------------------------------------

    pub async fn new(
        db: Arc<Db>,
        blockchain: Arc<RwLock<Blockchain>>,
        handshake_key_bytes: Vec<u8>,
        runtime_config: NodeRuntimeConfig,
    ) -> Result<Self, NodeError> {
        let NodeRuntimeConfig {
            bind_addr,
            velocity_enabled,
            max_peers,
            max_connections,
            seed_nodes: configured_seed_nodes,
            data_dir,
        } = runtime_config;
        let (tx, _) = broadcast::channel(EVENT_BROADCAST_CAPACITY);
        let keypair = Ed25519KeyPair::from_pkcs8(&handshake_key_bytes)
            .map_err(|_| NodeError::Network("Invalid handshake key bytes".into()))?;
        let p2p_key = identity::Keypair::generate_ed25519();

        let witness_cache_capacity = Self::witness_cache_capacity();
        let peer_id = PeerId::from(p2p_key.public()).to_string();
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
        let http_client = Client::builder()
            .timeout(Duration::from_millis(DISCOVERY_HTTP_TIMEOUT_MS))
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| NodeError::Network(format!("HTTP client error: {}", e)))?;
        let chain_data_dir: Option<Arc<str>> = data_dir
            .as_deref()
            .filter(|d| !d.trim().is_empty())
            .map(Arc::from);
        let peer_cache_path = Self::resolve_peer_cache_path(data_dir.as_deref());
        debug_assert_eq!(
            COMPACT_GLOBAL_CACHE_BYTE_BUDGET,
            COMPACT_PENDING_CACHE_BYTE_BUDGET + COMPACT_FULL_CACHE_BYTE_BUDGET
        );

        // Initialize socket and listener
        let (bind_addr, listener) = Self::initialize_listener(bind_addr)?;

        // Create lock file path
        let lock_dir = std::env::temp_dir().join("node_locks");
        std::fs::create_dir_all(&lock_dir)
            .map_err(|e| NodeError::Network(format!("Failed to create lock directory: {}", e)))?;

        let lock_path = lock_dir.join(format!(
            "{}.lock",
            hex::encode(keypair.public_key().as_ref())
        ));

        // Check for existing lock
        if lock_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&lock_path) {
                if let Ok(_pid) = content.parse::<u32>() {
                    #[cfg(unix)]
                    {
                        use nix::sys::signal;
                        use nix::unistd::Pid;
                        if signal::kill(Pid::from_raw(_pid as i32), None).is_ok() {
                            return Err(NodeError::Network(
                                "Wallet already in use. Please close other instances first."
                                    .to_string(),
                            ));
                        }
                    }
                    #[cfg(windows)]
                    {
                        // Windows-specific process check
                        let _ = std::fs::remove_file(&lock_path);
                    }
                }
            }
            // Reclaim a STALE lock so create_new below succeeds. A LIVE owner already returned
            // "Wallet already in use" above, so anything remaining here belongs to a dead PID
            // (or is unreadable/garbage) left by a crashed instance. Without this a stale lock
            // makes create_new fail and bricks restart — now reachable because IdentityLock no
            // longer deletes the lock mid-run on a clone drop. create_new(true) stays the atomic
            // arbiter if two processes reclaim at once.
            let _ = std::fs::remove_file(&lock_path);
        }

        // Create new lock file
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|e| NodeError::Network(format!("Failed to create lock file: {}", e)))?;

        // Write PID
        file.write_all(std::process::id().to_string().as_bytes())
            .map_err(|e| NodeError::Network(format!("Failed to write PID to lock file: {}", e)))?;

        // Generate network ID from blockchain genesis hash
        let network_id = blockchain
            .read()
            .await
            .get_block(0)
            .map(|b| b.hash)
            .unwrap_or_default();

        if velocity_enabled {
            warn!(
                "Velocity propagation is disabled: shred transport must be moved onto the authenticated peer channel before use"
            );
        }
        let velocity_manager = None;

        Ok(Self {
            db,
            peers: Arc::new(RwLock::new(HashMap::new())),
            max_peers: max_peers.max(MIN_PEERS),
            max_connections: max_connections.max(10),
            blockchain,
            network_health: Arc::new(RwLock::new(NetworkHealth::new())),
            node_id: hex::encode(keypair.public_key().as_ref()),
            tx,
            start_time,
            validation_pool: Arc::new(ValidationPool::new()),
            validation_cache: Arc::new(DashMap::with_capacity(10000)),
            solicited_block_peers: Arc::new(DashMap::new()),
            tx_witness_cache: Arc::new(PLMutex::new(WitnessCache::new(
                witness_cache_capacity,
                WITNESS_CACHE_BYTE_BUDGET,
            ))),
            relay_dead_targets: Arc::new(PLMutex::new(LruCache::new(
                // Must comfortably exceed the number of distinct dead tips a post-storm
                // relay window can hold, or eviction re-admits chewed-through dead
                // candidates and starves the live tip out of the per-tick budget.
                std::num::NonZeroUsize::new(512).expect("nonzero"),
            ))),
            network_bloom: Arc::new(NetworkBloom::new(BLOOM_FILTER_SIZE, BLOOM_FILTER_FPR)),
            // Bounded relay-once set for the early relay path (see field comment). Same 8192 cap
            // as the mesh seen-set; a block hash is a fixed 32 bytes so this is ~small.
            early_relay_seen: Arc::new(PLMutex::new(LruCache::new(
                NonZeroUsize::new(8192).expect("nonzero"),
            ))),
            compact_relay_delivered: Arc::new(PLMutex::new(LruCache::new(
                NonZeroUsize::new(8192).expect("nonzero"),
            ))),
            compact_capable_peers: Arc::new(DashMap::new()),
            compact_inflight: Arc::new(DashMap::new()),
            compact_reconstruction_slots: Arc::new(Semaphore::new(
                COMPACT_RECONSTRUCTION_CONCURRENCY,
            )),
            compact_fork_fallback_slots: Arc::new(Semaphore::new(
                COMPACT_FORK_FALLBACK_CONCURRENCY,
            )),
            compact_pending: Arc::new(PLMutex::new(CompactPendingCache {
                entries: LruCache::new(
                    NonZeroUsize::new(COMPACT_PENDING_CACHE_ENTRIES).expect("nonzero"),
                ),
                bytes: 0,
            })),
            compact_full_blocks: Arc::new(PLMutex::new(CompactFullBlockCache {
                entries: LruCache::new(
                    NonZeroUsize::new(COMPACT_FULL_BLOCK_CACHE_ENTRIES).expect("nonzero"),
                ),
                bytes: 0,
            })),
            compact_tx_index: Arc::new(PLMutex::new(LruCache::new(
                NonZeroUsize::new(COMPACT_TX_INDEX_ENTRIES).expect("nonzero"),
            ))),
            rate_limiter: Arc::new(RateLimiter::new(60, 100)),
            bind_addr,
            listener,
            p2p_swarm: Arc::new(Mutex::new(None)),
            http_client,
            discovery_state: Arc::new(Mutex::new(DiscoveryState::new())),
            discovery_in_progress: Arc::new(AtomicBool::new(false)),
            public_relay_tip: Arc::new(RwLock::new(None)),
            last_public_announce_at: Arc::new(AtomicU64::new(0)),
            last_public_announce_attempt_at: Arc::new(AtomicU64::new(0)),
            announce_reject_streak: Arc::new(AtomicU64::new(0)),
            cached_external_ip: Arc::new(RwLock::new(None)),
            converge_stall_tip: Arc::new(AtomicU64::new(0)),
            converge_stall_last_ms: Arc::new(AtomicU64::new(0)),
            converge_stall_cycles: Arc::new(AtomicU64::new(0)),
            full_sync_in_flight: Arc::new(AtomicBool::new(false)),
            beacon_memo: Arc::new(PLMutex::new(None)),
            beacon_high_water: Arc::new(PLMutex::new(std::collections::VecDeque::new())),
            last_seen_beacon_height: Arc::new(AtomicU64::new(0)),
            chain_data_dir,
            pex_addr_book: Arc::new(RwLock::new(HashMap::new())),
            last_header_snapshot_at: Arc::new(AtomicU64::new(0)),
            last_header_snapshot_height: Arc::new(AtomicU64::new(0)),
            last_stats_snapshot_at: Arc::new(AtomicU64::new(0)),
            peer_id,
            peer_failures: Arc::new(RwLock::new(HashMap::new())),
            header_sentinel: Some(Arc::new(HeaderSentinel::new())),
            identity_lock: Arc::new(IdentityLock {
                path: lock_path.to_string_lossy().into_owned(),
            }),
            velocity_manager,
            network_id,
            peer_secrets: Arc::new(RwLock::new(HashMap::new())),
            outbound_connections: Arc::new(RwLock::new(HashMap::new())),
            outbound_circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
            handshake_public_key: keypair.public_key().as_ref().to_vec(),
            handshake_key_bytes: Arc::new(handshake_key_bytes),
            #[cfg(feature = "webrtc_mesh")]
            webrtc_mesh: Arc::new(RwLock::new(None)),
            inbound_attempts: Arc::new(RwLock::new(HashMap::new())),
            peer_cache_path: Arc::new(peer_cache_path),
            configured_seed_nodes: Arc::new(configured_seed_nodes),
        })
    }

    fn initialize_listener(
        bind_addr: Option<SocketAddr>,
    ) -> Result<(SocketAddr, Option<Arc<TcpListener>>), NodeError> {
        match bind_addr {
            Some(addr) => {
                info!("Using provided bind address: {}", addr);
                // Match the socket domain to the bind address family. An IPv4-domain socket
                // cannot bind an explicit IPv6 SocketAddr (address-family error), so the node
                // failed to start on an IPv6 bind. IPv4 behavior is unchanged.
                let domain = if addr.is_ipv6() {
                    Domain::IPV6
                } else {
                    Domain::IPV4
                };
                let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
                socket.set_reuse_address(true)?;
                socket.set_nodelay(true)?;

                info!("Attempting to bind to address: {}", addr);
                socket.bind(&addr.into())?;
                socket.listen(1024)?;
                // Tokio's TcpListener::from_std requires a non-blocking socket;
                // a blocking one stalls a worker thread inside accept() and
                // strands every accepted connection's handler task.
                socket.set_nonblocking(true)?;

                let std_listener = socket.into();
                let listener = TcpListener::from_std(std_listener)?;
                Ok((addr, Some(Arc::new(listener))))
            }
            None => {
                // First try binding to all interfaces with default port
                if let Ok((addr, listener)) = Self::try_bind_default_port() {
                    return Ok((addr, Some(Arc::new(listener))));
                }

                // If that fails, try a random port
                let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                socket.set_reuse_address(true)?;
                socket.set_nodelay(true)?;

                let alt_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
                socket.bind(&alt_addr.into())?;
                socket.listen(1024)?;
                socket.set_nonblocking(true)?;

                let std_listener = socket.into();
                let listener = TcpListener::from_std(std_listener)?;
                let addr = listener.local_addr()?;
                info!("Bound to alternative port on all interfaces: {}", addr);
                Ok((addr, Some(Arc::new(listener))))
            }
        }
    }

    fn try_bind_default_port() -> Result<(SocketAddr, TcpListener), NodeError> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        socket.set_nodelay(true)?;

        // Bind to all interfaces (0.0.0.0) with default port
        let primary_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), DEFAULT_PORT);
        info!("Attempting to bind to all interfaces: {}", primary_addr);

        socket.bind(&primary_addr.into())?;
        socket.listen(1024)?;
        socket.set_nonblocking(true)?;
        let std_listener = socket.into();
        let listener = TcpListener::from_std(std_listener)?;
        let addr = listener.local_addr()?;
        info!("Listener active on all interfaces: {}", addr);

        Ok((addr, listener))
    }

    pub fn id(&self) -> &str {
        &self.node_id
    }

    // Get public key implementation
    pub fn get_public_key(&self) -> String {
        self.node_id.clone()
    }

    pub fn header_sentinel(&self) -> Option<Arc<HeaderSentinel>> {
        self.header_sentinel.clone()
    }

    fn handshake_payload(message: &HandshakeMessage) -> Result<Vec<u8>, NodeError> {
        let mut msg = message.clone();
        msg.signature = Vec::new();
        Ok(codec::serialize(&msg)?)
    }

    fn sign_handshake(&self, message: &HandshakeMessage) -> Result<Vec<u8>, NodeError> {
        let keypair = Ed25519KeyPair::from_pkcs8(&self.handshake_key_bytes)
            .map_err(|_| NodeError::Network("Invalid handshake key bytes".into()))?;
        let payload = Self::handshake_payload(message)?;
        Ok(keypair.sign(&payload).as_ref().to_vec())
    }

    fn sign_with_handshake_key(&self, payload: &[u8]) -> Result<Vec<u8>, NodeError> {
        let keypair = Ed25519KeyPair::from_pkcs8(&self.handshake_key_bytes)
            .map_err(|_| NodeError::Network("Invalid handshake key bytes".into()))?;
        Ok(keypair.sign(payload).as_ref().to_vec())
    }

    fn build_mldsa_registration_message(&self) -> Result<Option<NetworkMessage>, NodeError> {
        let Some(sentinel) = &self.header_sentinel else {
            return Ok(None);
        };

        let mldsa_public_key = sentinel.local_mldsa_public_key();
        if mldsa_public_key.is_empty() {
            return Ok(None);
        }

        let payload =
            crate::a9::bpos::build_mldsa_binding_payload(&self.node_id, &mldsa_public_key);
        let ed25519_signature = self.sign_with_handshake_key(&payload)?;

        Ok(Some(NetworkMessage::MldsaKeyRegistration {
            node_id: self.node_id.clone(),
            mldsa_public_key,
            ed25519_signature,
        }))
    }

    pub async fn advertise_mldsa_key(&self, addr: SocketAddr) -> Result<(), NodeError> {
        if let Some(message) = self.build_mldsa_registration_message()? {
            self.send_message(addr, &message).await?;
        }
        Ok(())
    }

    fn verify_handshake(&self, message: &HandshakeMessage) -> Result<(), NodeError> {
        const MAX_HANDSHAKE_SKEW_SECS: u64 = 300;
        if message.public_key.len() != 32 || message.signature.len() != 64 {
            return Err(NodeError::Network(
                "Invalid handshake key/signature length".into(),
            ));
        }
        if message.listen_port == 0 {
            return Err(NodeError::Network("Invalid handshake listen port".into()));
        }
        if message.public_key == self.handshake_public_key {
            return Err(NodeError::Network("Self-handshake rejected".into()));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let skew = now.abs_diff(message.timestamp);
        if skew > MAX_HANDSHAKE_SKEW_SECS {
            return Err(NodeError::Network(
                "Handshake timestamp outside allowed skew".into(),
            ));
        }
        // Bind the advertised node_id to the signed public key: a peer must not present an
        // identity string that doesn't correspond to the key it proves possession of below.
        if message.node_id != hex::encode(&message.public_key) {
            return Err(NodeError::Network(
                "Handshake node_id not bound to public key".into(),
            ));
        }
        let payload = Self::handshake_payload(message)?;
        let public_key = UnparsedPublicKey::new(&ED25519, &message.public_key);
        public_key
            .verify(&payload, &message.signature)
            .map_err(|_| NodeError::Network("Invalid handshake signature".into()))
    }

    fn peer_listen_addr(
        socket_addr: SocketAddr,
        listen_port: u16,
    ) -> Result<SocketAddr, NodeError> {
        if listen_port == 0 {
            return Err(NodeError::Network("Invalid peer listen port".into()));
        }
        Ok(SocketAddr::new(socket_addr.ip(), listen_port))
    }

    fn canonicalize_json(value: &Value) -> Value {
        match value {
            Value::Array(items) => {
                Value::Array(items.iter().map(Self::canonicalize_json).collect())
            }
            Value::Object(map) => {
                let mut keys: Vec<_> = map.keys().cloned().collect();
                keys.sort();
                let mut new_map = serde_json::Map::new();
                for key in keys {
                    if let Some(v) = map.get(&key) {
                        new_map.insert(key, Self::canonicalize_json(v));
                    }
                }
                Value::Object(new_map)
            }
            _ => value.clone(),
        }
    }

    fn canonical_json_string(value: &Value) -> Result<String, NodeError> {
        let canonical = Self::canonicalize_json(value);
        serde_json::to_string(&canonical)
            .map_err(|e| NodeError::Serialization(format!("JSON canonicalization error: {}", e)))
    }

    fn env_flag_enabled(name: &str) -> bool {
        std::env::var(name)
            .map(|value| {
                let value = value.trim();
                !value.is_empty()
                    && !matches!(
                        value.to_ascii_lowercase().as_str(),
                        "0" | "false" | "no" | "off"
                    )
            })
            .unwrap_or(false)
    }

    fn public_discovery_publish_enabled() -> bool {
        !Self::env_flag_enabled("ALPHANUMERIC_DISABLE_PUBLIC_DISCOVERY")
    }

    fn public_announce_enabled() -> bool {
        Self::public_discovery_publish_enabled()
            && !Self::env_flag_enabled("ALPHANUMERIC_DISABLE_PUBLIC_ANNOUNCE")
    }

    fn public_header_snapshots_enabled() -> bool {
        Self::public_discovery_publish_enabled()
            && Self::env_flag_enabled("ALPHANUMERIC_ENABLE_HEADER_SNAPSHOTS")
    }

    fn public_stats_snapshots_enabled() -> bool {
        Self::public_discovery_publish_enabled()
            && Self::env_flag_enabled("ALPHANUMERIC_ENABLE_STATS_SNAPSHOTS")
    }

    fn block_relay_publish_enabled() -> bool {
        // Unconditional. Posting mined and tip blocks to the gateway relay is the
        // network's propagation path — without it a miner's block never leaves the
        // machine and the node "mines into the void". On a live production network
        // there is no reason to opt out, so it is not a toggle.
        true
    }

    fn block_relay_sync_enabled() -> bool {
        // Unconditional. Pulling blocks from the gateway relay is how any node —
        // including one behind NAT with no direct peers — learns the network tip
        // and stays in sync. Core behaviour, never a toggle.
        true
    }

    fn kademlia_fallback_enabled() -> bool {
        std::env::var("ALPHANUMERIC_DISCOVERY_ENABLE_KAD_FALLBACK")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn private_discovery_peers_allowed() -> bool {
        Self::env_flag_enabled("ALPHANUMERIC_ALLOW_PRIVATE_PEERS")
    }

    fn stats_server_explicitly_enabled() -> bool {
        // Honour the whole falsy set (0/false/no/off), not just the literal
        // "false": ALPHANUMERIC_STATS_ENABLED=0 used to ENABLE this, which is
        // the opposite of what an operator typing 0 intends.
        Self::env_flag_enabled("ALPHANUMERIC_STATS_ENABLED")
    }

    fn upnp_explicitly_enabled() -> bool {
        // Honour the whole falsy set (0/false/no/off), not just the literal
        // "false": ALPHANUMERIC_ENABLE_UPNP=0 used to ENABLE this, which is
        // the opposite of what an operator typing 0 intends.
        Self::env_flag_enabled("ALPHANUMERIC_ENABLE_UPNP")
    }

    fn is_expected_startup_sync_gap(error: &NodeError) -> bool {
        match error {
            NodeError::Network(message) => {
                message.contains("No peers available")
                    || message.contains("No peers reported their height")
                    || message.contains("No suitable peers for sync")
                    || message.contains("Block relay sync disabled")
            }
            _ => false,
        }
    }

    fn parse_seed_list(value: &str) -> Vec<String> {
        value
            .split(',')
            .filter_map(|s| {
                let t = s.trim();
                (!t.is_empty()).then(|| t.to_owned())
            })
            .collect()
    }

    fn configured_seed_nodes(&self) -> &[String] {
        self.configured_seed_nodes.as_slice()
    }

    fn dns_seeds() -> Vec<String> {
        if let Ok(seeds) = std::env::var("ALPHANUMERIC_DNS_SEEDS") {
            let parsed = Self::parse_seed_list(&seeds);
            if !parsed.is_empty() {
                return parsed;
            }
        }

        DEFAULT_DNS_SEEDS.iter().map(|s| s.to_string()).collect()
    }

    fn discovery_bases() -> Vec<String> {
        let bases = std::env::var("ALPHANUMERIC_DISCOVERY_BASES")
            .ok()
            .map(|v| {
                v.split(',')
                    .filter_map(|s| {
                        let t = s.trim();
                        (!t.is_empty()).then(|| t.to_owned())
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if !bases.is_empty() {
            return bases;
        }

        vec![std::env::var("ALPHANUMERIC_DISCOVERY_BASE")
            .unwrap_or_else(|_| DEFAULT_DISCOVERY_BASE.to_string())]
    }

    /// Parse a dotted version ("7.5.0", tolerating a leading `v` and any pre-release suffix)
    /// into a comparable (major, minor, patch) tuple; missing/garbage components read as 0.
    fn parse_semver(v: &str) -> (u64, u64, u64) {
        let mut it = v.trim().trim_start_matches('v').split('.').map(|p| {
            p.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse::<u64>()
                .unwrap_or(0)
        });
        (
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
        )
    }

    fn version_is_older(local: &str, remote: &str) -> bool {
        Self::parse_semver(local) < Self::parse_semver(remote)
    }

    /// Notice-only client-version check. Asks the gateway which node version is recommended and,
    /// if this build is older, logs a one-line update notice. The node keeps running and NOTHING
    /// auto-updates — this is purely informational so an operator on a stale binary (e.g. one that
    /// predates a convergence fix) learns to update. Best-effort: any network/parse error is
    /// swallowed so it never disrupts the node.
    async fn check_client_version_and_warn(&self) {
        let local = env!("CARGO_PKG_VERSION");
        for base in Self::discovery_bases() {
            let url = format!("{}/api/client-release", base);
            let res = match self.http_client.get(&url).send().await {
                Ok(r) if r.status().is_success() => r,
                _ => continue,
            };
            let body: Value = match res.json().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(recommended) = body.get("recommended_version").and_then(|v| v.as_str()) else {
                return; // gateway answered but advertises no version -> nothing to compare
            };
            if Self::version_is_older(local, recommended) {
                let hint = body
                    .get("download_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("https://alphanumeric.blue");
                warn!(
                    "Node update available: {} (you are running {}). Update recommended — {}. \
                     Your node keeps running; this is a notice only.",
                    recommended, local, hint
                );
            }
            return; // first reachable gateway answered
        }
    }

    /// Poll the gateway's mesh kill switch. Returns false ONLY if the gateway explicitly advertises
    /// `mesh_enabled: false`; any error, timeout, or missing field returns true (fail-safe — a
    /// transient blip must never disable the mesh network-wide).
    #[cfg(feature = "webrtc_mesh")]
    async fn fetch_mesh_enabled(&self) -> bool {
        for base in Self::discovery_bases() {
            let url = format!("{}/api/client-release", base);
            let res = match self.http_client.get(&url).send().await {
                Ok(r) if r.status().is_success() => r,
                _ => continue,
            };
            let body: Value = match res.json().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            return body.get("mesh_enabled").and_then(|v| v.as_bool()) != Some(false);
        }
        true // no gateway answered -> stay enabled
    }

    fn discovery_peers_urls() -> Vec<String> {
        if let Ok(url) = std::env::var("ALPHANUMERIC_DISCOVERY_URL") {
            return vec![url];
        }
        Self::discovery_bases()
            .into_iter()
            .map(|base| format!("{}/api/peers", base))
            .collect()
    }

    fn discovery_announce_urls() -> Vec<String> {
        if let Ok(url) = std::env::var("ALPHANUMERIC_ANNOUNCE_URL") {
            return vec![url];
        }
        Self::discovery_bases()
            .into_iter()
            .map(|base| format!("{}/api/announce", base))
            .collect()
    }

    fn discovery_headers_urls() -> Vec<String> {
        if let Ok(url) = std::env::var("ALPHANUMERIC_HEADERS_URL") {
            return vec![url];
        }
        Self::discovery_bases()
            .into_iter()
            .map(|base| format!("{}/api/headers", base))
            .collect()
    }

    fn discovery_blocks_urls() -> Vec<String> {
        if let Ok(url) = std::env::var("ALPHANUMERIC_BLOCKS_URL") {
            return vec![url];
        }
        Self::discovery_bases()
            .into_iter()
            .map(|base| format!("{}/api/blocks", base))
            .collect()
    }

    fn relay_backfill_limit() -> u32 {
        // 32 (was 4, cap 12): after each mined/accepted block a node re-posts its
        // recent tail to the relay. At 4-deep, a fork storm that drops posts (old
        // 90/min limit) left the winning chain as Swiss cheese on the relay — ~70
        // missing heights across 2200-2483 on 2026-07-08 — which no node could
        // reorg across, stranding the majority on a losing fork. A deeper tail means
        // every active miner continuously heals recent holes on the shared relay, so
        // a scattered chain reconverges instead of fragmenting. The WASM PoW gate +
        // 300/min per-IP limit keep this from being a write-amplification problem
        // (re-posts of already-stored blocks are cheap SET NX no-ops).
        std::env::var("ALPHANUMERIC_RELAY_BACKFILL_LIMIT")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(32)
            .min(64)
    }

    fn env_interval_secs(name: &str, default_secs: u64, min_secs: u64, max_secs: u64) -> u64 {
        std::env::var(name)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(default_secs)
            .clamp(min_secs, max_secs)
    }

    fn announce_interval_secs() -> u64 {
        Self::env_interval_secs(
            "ALPHANUMERIC_ANNOUNCE_INTERVAL_SECS",
            DEFAULT_ANNOUNCE_INTERVAL_SECS,
            60,
            3600,
        )
    }

    fn header_snapshot_interval_secs() -> u64 {
        Self::env_interval_secs(
            "ALPHANUMERIC_HEADER_SNAPSHOT_INTERVAL_SECS",
            DEFAULT_HEADER_SNAPSHOT_INTERVAL_SECS,
            15,
            3600,
        )
    }

    fn stats_snapshot_interval_secs() -> u64 {
        Self::env_interval_secs(
            "ALPHANUMERIC_STATS_SNAPSHOT_INTERVAL_SECS",
            DEFAULT_STATS_SNAPSHOT_INTERVAL_SECS,
            60,
            3600,
        )
    }

    fn should_publish_now(last_publish: &AtomicU64, interval_secs: u64, now: u64) -> bool {
        let previous = last_publish.load(Ordering::Acquire);
        if previous > 0 && now.saturating_sub(previous) < interval_secs {
            return false;
        }

        last_publish
            .compare_exchange(previous, now, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn relay_sync_backfill_depth() -> u32 {
        // Default 64 (= CHECKPOINT_REORG_MARGIN, 2026-07-11): the forward relay
        // drain re-examines the finality-margin window below its tip, so a fork
        // within the reorgable range self-heals on the forward path too, not only
        // via converge's backward ancestor walk. Was 0 (pure forward-from-tip+1),
        // which left a behind-but-on-canonical node unable to reconcile any shallow
        // divergence — rplant's report, 2026-07-11. Only runs on behind-node
        // catch-up paths, and one extra 64-block batch per call, so relay-GET load
        // is bounded. (The witness-truncated case is handled by relay rehydration,
        // not by re-pulling — see the S-01 path; this default only helps the
        // on-canonical-but-behind case.)
        std::env::var("ALPHANUMERIC_RELAY_SYNC_BACKFILL_DEPTH")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(crate::a9::blockchain::CHECKPOINT_REORG_MARGIN)
            .min(256)
    }

    fn relay_sync_max_rounds() -> usize {
        std::env::var("ALPHANUMERIC_RELAY_SYNC_MAX_ROUNDS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4)
            .clamp(1, 24)
    }

    async fn mark_block_relayed(&self, block: &Block) {
        self.mark_block_relayed_key(block.index, block.hash).await;
    }

    /// Key-only variant: the relay tip marker never needs the block body, so bulk
    /// callers can pass (index, hash) instead of cloning whole blocks.
    async fn mark_block_relayed_key(&self, index: u32, hash: [u8; 32]) {
        let mut public_tip = self.public_relay_tip.write().await;
        let should_update = public_tip
            .map(|tip| index > tip.height || (index == tip.height && hash == tip.hash))
            .unwrap_or(true);
        if should_update {
            *public_tip = Some(RelayTipState {
                height: index,
                hash,
            });
        }
    }

    async fn public_advertisable_tip(&self) -> Option<Block> {
        let relay_tip = *self.public_relay_tip.read().await;
        let blockchain = self.blockchain.read().await;

        let Some(relay_tip) = relay_tip else {
            return blockchain.get_last_block();
        };

        match blockchain.get_block(relay_tip.height) {
            Ok(block) if block.hash == relay_tip.hash => Some(block),
            Ok(_) => {
                warn!(
                    "Relay-confirmed tip #{} no longer matches local canonical block; using local tip for discovery announce",
                    relay_tip.height
                );
                blockchain.get_last_block()
            }
            Err(e) => {
                warn!(
                    "Relay-confirmed tip #{} is not available locally: {}; using local tip for discovery announce",
                    relay_tip.height, e
                );
                blockchain.get_last_block()
            }
        }
    }

    async fn ensure_public_tip_relayed(&self) -> Result<(), NodeError> {
        let tip = {
            let blockchain = self.blockchain.read().await;
            blockchain
                .get_last_block()
                .ok_or_else(|| NodeError::Blockchain("No local chain tip found".to_string()))?
        };

        let already_relayed = self
            .public_relay_tip
            .read()
            .await
            .map(|public_tip| public_tip.height == tip.index && public_tip.hash == tip.hash)
            .unwrap_or(false);
        if already_relayed {
            return Ok(());
        }

        self.post_block_relay(&tip).await?;
        self.post_recent_blocks_to_relay(Self::relay_backfill_limit())
            .await;
        Ok(())
    }

    async fn get_external_ip(&self) -> Option<IpAddr> {
        // Prefer a concrete bind address if available
        let ip = self.bind_addr.ip();
        if !ip.is_unspecified() && !ip.is_loopback() {
            return Some(ip);
        }

        // TTL cache: the announce retry path can call this every 30s during a
        // gateway outage — don't re-walk third-party STUN servers each time. The
        // TTL matches the healthy announce interval, so steady-state freshness is
        // unchanged (one STUN exchange per announce interval at most).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        {
            let cached = self.cached_external_ip.read().await;
            if let Some((ip, at)) = *cached {
                if now.saturating_sub(at) < Self::announce_interval_secs() {
                    return Some(ip);
                }
            }
        }

        if let Ok((Some(ip), _v6)) = self.discover_external_addresses(STUN_SERVERS).await {
            *self.cached_external_ip.write().await = Some((ip, now));
            return Some(ip);
        }

        None
    }

    /// Fold an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its real IPv4 form so the IPv4
    /// filters apply to it; Rust std does not auto-fold these. Mirrors PeerInfo::new. Without it
    /// an attacker-supplied ::ffff:<internal-ipv4> slips past the IPv6 arm of the address filters
    /// as "public/dialable" (SSRF / internal-host dialing). Non-mapped addresses pass through.
    fn canonical_ip(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        }
    }

    fn is_private_ip(addr: &IpAddr) -> bool {
        match Self::canonical_ip(*addr) {
            IpAddr::V4(ip) => {
                ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()
            }
            IpAddr::V6(ip) => ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local(),
        }
    }

    fn is_dialable_discovery_addr(addr: &SocketAddr, allow_private: bool) -> bool {
        if addr.port() == 0 {
            return false;
        }

        // Fold an IPv4-mapped IPv6 address to IPv4 so the IPv4 filters below apply to it (std does
        // not auto-fold); otherwise ::ffff:<internal-ipv4> would slip past the IPv6 arm as dialable.
        let ip = Self::canonical_ip(addr.ip());

        if allow_private {
            return !ip.is_unspecified();
        }

        match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                let is_shared_cgnat = octets[0] == 100 && (64..=127).contains(&octets[1]);
                let is_benchmark = octets[0] == 198 && (18..=19).contains(&octets[1]);
                let is_protocol_assignment = octets[0] == 192 && octets[1] == 0 && octets[2] == 0;
                !(ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_unspecified()
                    || ip.is_broadcast()
                    || ip.is_multicast()
                    || ip.is_documentation()
                    || is_shared_cgnat
                    || is_benchmark
                    || is_protocol_assignment
                    || octets[0] >= 240)
            }
            IpAddr::V6(ip) => {
                let segments = ip.segments();
                let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
                let is_unicast_link_local = (segments[0] & 0xffc0) == 0xfe80;
                !(ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_unique_local()
                    || ip.is_multicast()
                    || is_documentation
                    || is_unicast_link_local)
            }
        }
    }

    fn filter_dialable_discovery_candidates<I>(
        addrs: I,
        bind_addr: SocketAddr,
        current_peers: &HashSet<SocketAddr>,
        allow_private: bool,
    ) -> Vec<SocketAddr>
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        let mut seen_addrs = HashSet::new();
        addrs
            .into_iter()
            .filter(|addr| {
                *addr != bind_addr
                    && !current_peers.contains(addr)
                    && Self::is_dialable_discovery_addr(addr, allow_private)
                    && seen_addrs.insert(*addr)
            })
            .collect()
    }

    async fn fetch_discovery_peers(&self) -> Result<Vec<SocketAddr>, NodeError> {
        let mut all_addrs = Vec::new();
        let mut seen_addrs = HashSet::new();
        let mut any_ok = false;
        let allow_private = Self::private_discovery_peers_allowed();
        let peer_limit = self.max_peers.saturating_mul(4).max(32);

        for url in Self::discovery_peers_urls() {
            let res = self.http_client.get(url).send().await;
            let res = match res {
                Ok(r) => r,
                Err(_) => continue,
            };

            if !res.status().is_success() {
                continue;
            }

            let body = res.json::<DiscoveryResponse>().await;
            let body = match body {
                Ok(b) => b,
                Err(_) => continue,
            };

            if !body.ok {
                continue;
            }

            any_ok = true;
            for peer in body.peers {
                if peer.node_id.as_deref() == Some(self.node_id.as_str()) {
                    continue;
                }

                if let Ok(ip) = peer.ip.parse::<IpAddr>() {
                    let addr = SocketAddr::new(ip, peer.port);
                    if addr == self.bind_addr {
                        continue;
                    }
                    if !Self::is_dialable_discovery_addr(&addr, allow_private) {
                        debug!("Ignoring non-routable discovery peer {}", addr);
                        continue;
                    }
                    if !seen_addrs.insert(addr) {
                        continue;
                    }
                    all_addrs.push(addr);
                    if all_addrs.len() >= peer_limit {
                        break;
                    }
                }
            }
            if all_addrs.len() >= peer_limit {
                break;
            }
        }

        if !any_ok {
            return Err(NodeError::Network("Discovery fetch failed".into()));
        }

        Ok(all_addrs)
    }

    async fn connect_discovery_peers(&self, limit: usize) -> Result<(), NodeError> {
        let mut addrs = match self.fetch_discovery_peers().await {
            Ok(addrs) => addrs,
            Err(fetch_err) => {
                let mut fallback_addrs: Vec<SocketAddr> = self.load_peer_cache();
                for seed in self.configured_seed_nodes() {
                    match tokio::net::lookup_host(seed.as_str()).await {
                        Ok(addrs) => fallback_addrs.extend(addrs),
                        Err(e) => debug!("Seed node lookup failed for {}: {}", seed, e),
                    }
                }

                if fallback_addrs.is_empty() {
                    return Err(fetch_err);
                }
                fallback_addrs
            }
        };
        let allow_private = Self::private_discovery_peers_allowed();
        let current_peers: HashSet<SocketAddr> = self.peers.read().await.keys().copied().collect();
        addrs = Self::filter_dialable_discovery_candidates(
            addrs,
            self.bind_addr,
            &current_peers,
            allow_private,
        );
        if addrs.is_empty() {
            return Err(NodeError::Network("No dialable discovery peers".into()));
        }
        addrs.shuffle(&mut thread_rng());

        let attempts: Vec<_> = addrs
            .into_iter()
            .take(limit)
            .map(|addr| async move {
                matches!(
                    timeout(Duration::from_secs(5), self.verify_peer(addr)).await,
                    Ok(Ok(_))
                )
            })
            .collect();

        let connected = match timeout(Duration::from_secs(6), join_all(attempts)).await {
            Ok(results) => results.into_iter().filter(|ok| *ok).count(),
            Err(_) => {
                debug!("Discovery peer connect timed out");
                0
            }
        };

        if connected > 0 {
            info!("Connected to {} peer(s) via discovery/bootstrap", connected);
        }

        Ok(())
    }

    /// Peer-cache location: env override first, else INSIDE the chain-DB directory
    /// so the address book survives reboots, else the legacy OS temp-dir default.
    /// Inside the DB dir (not its parent) because that directory is guaranteed
    /// writable — sled writes there continuously — while the parent can be
    /// read-only (system-wide installs); sled ignores foreign files in its dir.
    /// The temp dir was the original home and is wiped by OS cleaners on reboot —
    /// i.e. the cache vanished exactly in the scenario it exists for (restarting
    /// during a gateway outage).
    fn resolve_peer_cache_path(data_dir: Option<&str>) -> String {
        if let Ok(path) = std::env::var("ALPHANUMERIC_PEER_CACHE_PATH") {
            if !path.trim().is_empty() {
                return path;
            }
        }
        if let Some(dir) = data_dir {
            if !dir.trim().is_empty() {
                return std::path::Path::new(dir)
                    .join("alphanumeric_peers.json")
                    .to_string_lossy()
                    .into_owned();
            }
        }
        std::env::temp_dir()
            .join("alphanumeric_peers.json")
            .to_string_lossy()
            .into_owned()
    }

    fn load_peer_cache(&self) -> Vec<SocketAddr> {
        let path = &*self.peer_cache_path;
        // Legacy fallback: pre-v7.7.7 the cache lived in the OS temp dir. Read it
        // once when the new location is empty so upgrades keep their address book;
        // saves only ever go to the new path.
        let data = std::fs::read_to_string(path).or_else(|_| {
            std::fs::read_to_string(std::env::temp_dir().join("alphanumeric_peers.json"))
        });
        if data.is_err() {
            return Vec::new();
        }
        let data = data.unwrap_or_default();
        let list: Vec<String> = serde_json::from_str(&data).unwrap_or_default();
        list.into_iter()
            .filter_map(|s| s.parse::<SocketAddr>().ok())
            .collect()
    }

    fn save_peer_cache(&self, peers: &[SocketAddr]) -> Result<(), NodeError> {
        let path = &*self.peer_cache_path;
        let tmp_path = format!("{}.tmp", path);
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| NodeError::Io(format!("Peer cache mkdir error: {}", e)))?;
            }
        }
        let list: Vec<String> = peers.iter().map(|p| p.to_string()).collect();
        let data = serde_json::to_string(&list)
            .map_err(|e| NodeError::Serialization(format!("Peer cache error: {}", e)))?;
        std::fs::write(&tmp_path, data)
            .map_err(|e| NodeError::Io(format!("Peer cache write error: {}", e)))?;
        std::fs::rename(&tmp_path, path)
            .map_err(|e| NodeError::Io(format!("Peer cache rename error: {}", e)))?;
        Ok(())
    }

    fn score_peer_for_cache(peer: &PeerInfo, now: u64) -> f64 {
        let age = now.saturating_sub(peer.last_seen) as f64;
        let latency = peer.latency as f64;
        let height = peer.blocks as f64;
        // Higher is better
        height * 0.002 - age * 0.02 - latency * 0.005
    }

    fn response_body_snippet(body: &str) -> String {
        let trimmed = body.trim();
        const MAX_CHARS: usize = 240;
        let mut chars = trimmed.chars();
        let snippet: String = chars.by_ref().take(MAX_CHARS).collect();
        if chars.next().is_some() {
            format!("{}...", snippet)
        } else {
            snippet
        }
    }

    async fn announce_to_discovery(&self) -> Result<(), NodeError> {
        if !Self::public_announce_enabled() {
            debug!("Skipping public discovery announce because it is disabled by environment");
            return Ok(());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Success-then-attempt gate. The old should_publish_now marked the interval
        // on ATTEMPT, so one failed announce during a gateway outage silenced this
        // node for the whole interval — after recovery the roster read as empty for
        // minutes (2026-07-10 incident). Now: a SUCCESS re-arms the full interval;
        // a network failure only re-arms ANNOUNCE_RETRY_SECS (fast recovery), and
        // HTTP rejections back off exponentially toward the interval (a rejecting
        // gateway is doing real work per retry — don't 10x it forever).
        let interval = Self::announce_interval_secs();
        let retry = Self::announce_retry_secs_for_streak(
            self.announce_reject_streak.load(Ordering::Acquire),
            interval,
        );
        let last_attempt = self.last_public_announce_attempt_at.load(Ordering::Acquire);
        if !Self::announce_gate(
            now,
            self.last_public_announce_at.load(Ordering::Acquire),
            last_attempt,
            interval,
            retry,
        ) {
            return Ok(());
        }
        // CAS against the SAME value the gate evaluated: a concurrent caller then
        // fails either the gate (fresh marker is recent) or this exchange (stale
        // expected value), so exactly one attempt claims the window. Re-loading
        // the marker here would let two callers interleave past both checks.
        if self
            .last_public_announce_attempt_at
            .compare_exchange(last_attempt, now, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }

        // Tip check FIRST: a syncing/tip-less node exits here without burning a
        // STUN exchange per retry (get_external_ip walks up to 4 third-party
        // servers at 3s each when STUN is degraded).
        let Some(public_tip) = self.public_advertisable_tip().await else {
            return Ok(());
        };
        let height = public_tip.index;

        let ip = if let Ok(public_ip) = std::env::var("ALPHANUMERIC_PUBLIC_IP") {
            if !public_ip.trim().is_empty() {
                Some(public_ip.trim().to_string())
            } else {
                None
            }
        } else {
            self.get_external_ip()
                .await
                .filter(|addr| !Self::is_private_ip(addr))
                .map(|addr| addr.to_string())
        };
        let network_id = hex::encode(self.network_id);

        let stats_enabled = std::env::var("ALPHANUMERIC_STATS_ENABLED")
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let stats_bind_ip =
            std::env::var("ALPHANUMERIC_STATS_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let stats_bind_public = stats_bind_ip
            .parse::<IpAddr>()
            .map(|ip| ip.is_unspecified() || !ip.is_loopback())
            .unwrap_or(false);
        let stats_port: Option<u16> = if stats_enabled {
            std::env::var("ALPHANUMERIC_STATS_PORT")
                .ok()
                .and_then(|p| p.parse::<u16>().ok())
                .or(Some(8787))
                .filter(|_| stats_bind_public)
        } else {
            None
        };

        let mut message = serde_json::Map::new();
        message.insert("ip".to_string(), json!(ip.clone().unwrap_or_default()));
        message.insert("port".to_string(), json!(self.bind_addr.port()));
        message.insert("node_id".to_string(), json!(&self.node_id));
        message.insert("public_key".to_string(), json!(&self.node_id));
        message.insert("network_id".to_string(), json!(&network_id));
        message.insert(
            "version".to_string(),
            json!(format!("rust-{}", NETWORK_VERSION)),
        );
        message.insert("height".to_string(), json!(height));
        message.insert("last_seen".to_string(), json!(now));
        message.insert("latency_ms".to_string(), json!(0));
        if let Some(port) = stats_port {
            message.insert("stats_port".to_string(), json!(port));
        }
        let message = serde_json::Value::Object(message);

        let canonical = Self::canonical_json_string(&message)?;
        let keypair = Ed25519KeyPair::from_pkcs8(&self.handshake_key_bytes)
            .map_err(|_| NodeError::Network("Invalid handshake key bytes".into()))?;
        let signature = keypair.sign(canonical.as_bytes());

        let mut payload = serde_json::Map::new();
        payload.insert("ip".to_string(), json!(ip.unwrap_or_default()));
        payload.insert("port".to_string(), json!(self.bind_addr.port()));
        payload.insert("node_id".to_string(), json!(&self.node_id));
        payload.insert("public_key".to_string(), json!(&self.node_id));
        payload.insert("network_id".to_string(), json!(network_id));
        payload.insert(
            "version".to_string(),
            json!(format!("rust-{}", NETWORK_VERSION)),
        );
        payload.insert("height".to_string(), json!(height));
        payload.insert("last_seen".to_string(), json!(now));
        payload.insert("latency_ms".to_string(), json!(0));
        if let Some(port) = stats_port {
            payload.insert("stats_port".to_string(), json!(port));
        }
        // Unsigned advisory telemetry: the node's release version (CARGO_PKG_VERSION),
        // so the gateway can show the network's per-release spread. Deliberately NOT in
        // the signed `message` above — the gateway verifies over a fixed field list, so
        // this extra field never affects signature verification, and it is NEVER the
        // wire `version` field (that is the load-bearing NETWORK_VERSION handshake gate,
        // node.rs ~8171). Self-reported and unsigned, which is fine for a version count.
        payload.insert(
            "release_version".to_string(),
            json!(env!("CARGO_PKG_VERSION")),
        );
        payload.insert(
            "signature".to_string(),
            json!(hex::encode(signature.as_ref())),
        );
        let payload = serde_json::Value::Object(payload);

        let mut any_ok = false;
        let mut any_rejection = false;
        for url in Self::discovery_announce_urls() {
            let res = self.http_client.post(url).json(&payload).send().await;
            match res {
                Ok(res) if res.status().is_success() => any_ok = true,
                Ok(res) => {
                    // The gateway is UP and rejecting (429/4xx/5xx) — this drives
                    // the exponential backoff, unlike a pure network error.
                    any_rejection = true;
                    let status = res.status();
                    let body = res.text().await.unwrap_or_default();
                    debug!(
                        "Discovery announce failed: {} {}",
                        status,
                        Self::response_body_snippet(&body)
                    );
                }
                Err(e) => debug!("Discovery announce error: {}", e),
            }
        }

        if any_ok {
            // Only a SUCCESS re-arms the full announce interval (see gate above).
            self.last_public_announce_at.store(now, Ordering::Release);
            self.announce_reject_streak.store(0, Ordering::Release);
        } else if any_rejection {
            self.announce_reject_streak.fetch_add(1, Ordering::AcqRel);
            debug!("Discovery announce rejected on all endpoints");
        } else {
            // Gateway unreachable: keep the flat fast retry (streak untouched) so
            // the node re-registers within ~ANNOUNCE_RETRY_SECS of recovery.
            debug!("Discovery announce failed on all endpoints");
        }

        Ok(())
    }

    /// Schedule an unconditional re-bootstrap at the next boot by dropping the
    /// force-rebootstrap marker (the same file the runtime divergence exit and
    /// the boot-time reconcile use). Respects the bootstrap-cycle cooldown.
    /// Returns whether the marker was actually written — callers use this to
    /// give the operator honest advice ("restart to re-sync" is only true when
    /// the marker exists).
    pub fn schedule_force_rebootstrap(&self, reason: &str) -> bool {
        self.schedule_force_rebootstrap_bounded(reason, false)
    }

    /// Hard-verdict variant: a PROVEN below-finality divergence uses the short
    /// cooldown so a node that knows it is stranded is never suppressed into
    /// staying stale for the full generic window.
    pub fn schedule_force_rebootstrap_hard(&self, reason: &str) -> bool {
        self.schedule_force_rebootstrap_bounded(reason, true)
    }

    fn schedule_force_rebootstrap_bounded(&self, reason: &str, hard: bool) -> bool {
        let Some(dir) = self.chain_data_dir.as_deref() else {
            return false;
        };
        let suppressed = if hard {
            rebootstrap_hard_cooldown_active(dir)
        } else {
            rebootstrap_cooldown_active(dir)
        };
        if suppressed {
            return false;
        }
        let marker = force_rebootstrap_marker_path(dir);
        // Durable write (fsync): this marker is control state that decides whether
        // the NEXT boot re-bootstraps — it exists precisely to break crash loops,
        // so it must survive the power cut / kernel panic that may follow.
        let write_result = std::fs::write(&marker, format!("{}\n", reason)).and_then(|()| {
            std::fs::OpenOptions::new()
                .read(true)
                .open(&marker)
                .and_then(|f| f.sync_all())
        });
        match write_result {
            Ok(()) => {
                warn!(
                    "Force re-bootstrap scheduled ({}): {}",
                    reason,
                    marker.display()
                );
                true
            }
            Err(e) => {
                warn!(
                    "Could not write re-bootstrap marker {}: {}",
                    marker.display(),
                    e
                );
                false
            }
        }
    }

    /// Ghost-block guard: refuse to mine the local tip when the freshest trusted
    /// network height (`known_tip`) is more than a same/next-height race ahead of our
    /// local tip — even if the latest single beacon read came back stale (== local)
    /// and converge reported "at the tip". The reachable-beacon arms pass the ROLLING
    /// high-water here (max over the last window of reads) so a genuine regression
    /// clears the guard once the old height ages out; the beacon-unreachable fail-open
    /// arm passes the forever-monotonic high-water instead (no fresh read to confirm a
    /// regression). Fires only when behind (known_tip > local); a node at or ahead of
    /// the tip always mines. The +2 tolerance matches the BeaconStale racing distance.
    fn stale_tip_mine_refused(local_tip: u32, known_tip: u32) -> bool {
        known_tip > local_tip.saturating_add(2)
    }

    /// Record a network_id-matched beacon height observation into the rolling
    /// high-water window (prunes entries older than BEACON_HIGH_WATER_WINDOW_SECS).
    fn record_beacon_observation(&self, height: u32) {
        let now = Instant::now();
        let mut obs = self.beacon_high_water.lock();
        obs.push_back((now, height));
        while let Some(&(t, _)) = obs.front() {
            if now.duration_since(t).as_secs() > BEACON_HIGH_WATER_WINDOW_SECS {
                obs.pop_front();
            } else {
                break;
            }
        }
        // Length backstop (reads are ~1 per 3s, so ~200 fit the window; cap far above
        // that so a burst can't grow it unboundedly).
        while obs.len() > 4096 {
            obs.pop_front();
        }
    }

    /// The freshest network height we can currently trust: the MAX beacon height
    /// observed within the rolling window. A single stale-low read can never be the
    /// max while fresh reads are present; a genuinely regressed chain ages the old
    /// stuck-high value out. 0 if nothing observed yet (fail-open — same as the old
    /// AtomicU64::new(0) start, so a fresh node isn't pinned).
    pub fn beacon_high_water_height(&self) -> u32 {
        let now = Instant::now();
        let mut obs = self.beacon_high_water.lock();
        while let Some(&(t, _)) = obs.front() {
            if now.duration_since(t).as_secs() > BEACON_HIGH_WATER_WINDOW_SECS {
                obs.pop_front();
            } else {
                break;
            }
        }
        Self::window_high_water(&obs, now, BEACON_HIGH_WATER_WINDOW_SECS)
    }

    /// Pure max-height-in-window (does not depend on prior pruning): the highest
    /// beacon height observed no more than `window_secs` ago. This is what makes the
    /// guard ghost-safe AND regression-recoverable: a stale-low read is never the max
    /// while any fresher-higher read is still inside the window, yet a stuck-high value
    /// drops out once it ages past the window.
    fn window_high_water(
        obs: &std::collections::VecDeque<(Instant, u32)>,
        now: Instant,
        window_secs: u64,
    ) -> u32 {
        obs.iter()
            .filter(|(t, _)| now.duration_since(*t).as_secs() <= window_secs)
            .map(|(_, h)| *h)
            .max()
            .unwrap_or(0)
    }

    /// Pure verdict for the converge stall watchdog: (new_cycle_count, escalate).
    /// A call counts toward the stall only when the node is beyond the reorg
    /// margin behind a fresh beacon AND its tip did not move since the previous
    /// call; any progress (or a small gap) resets. Kept pure so the escalation
    /// semantics are testable.
    fn converge_stall_verdict(last_tip: u32, tip: u32, gap: u32, cycles: u64) -> (u64, bool) {
        if gap <= crate::a9::blockchain::CHECKPOINT_REORG_MARGIN || tip != last_tip {
            return (0, false);
        }
        let cycles = cycles.saturating_add(1);
        (cycles, cycles >= CONVERGE_STALL_ESCALATE_CALLS as u64)
    }

    /// Pure gate for announce_to_discovery: allow when the last SUCCESS is older
    /// than `interval` AND the last ATTEMPT is older than `retry`. Zero means
    /// "never". Kept as a pure function so the two-marker semantics are testable.
    fn announce_gate(
        now: u64,
        last_success: u64,
        last_attempt: u64,
        interval: u64,
        retry: u64,
    ) -> bool {
        if last_success > 0 && now.saturating_sub(last_success) < interval {
            return false;
        }
        if last_attempt > 0 && now.saturating_sub(last_attempt) < retry {
            return false;
        }
        true
    }

    /// Retry cadence as a function of the consecutive-rejection streak: flat
    /// ANNOUNCE_RETRY_SECS while the gateway is merely unreachable (streak 0),
    /// doubling per consecutive HTTP rejection, capped at the full interval —
    /// i.e. a persistently-rejecting gateway sees at most the pre-existing
    /// 1-per-interval announce volume, while outage recovery stays fast.
    fn announce_retry_secs_for_streak(streak: u64, interval: u64) -> u64 {
        ANNOUNCE_RETRY_SECS
            .saturating_mul(1u64 << streak.min(4))
            .min(interval.max(ANNOUNCE_RETRY_SECS))
    }

    async fn post_header_snapshot(&self) -> Result<(), NodeError> {
        if !Self::public_header_snapshots_enabled() {
            debug!("Skipping public header snapshot because it is disabled by environment");
            return Ok(());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // HEIGHT-DELTA BYPASS of the wall-clock interval: under heavy racing the
        // chain mints every ~5-6s, so a 30s cadence left the site's VERIFIED height
        // 30-50 blocks behind LATEST — stale exactly when activity (and operator
        // attention) peaks. If the tip has advanced >= 8 blocks since the last
        // snapshot, post now; a 5s burst floor still bounds the POST rate during
        // storms, and a quiet chain keeps the old 30s cadence untouched.
        let tip_now = { self.blockchain.read().await.get_latest_block_index() };
        let last_h = self.last_header_snapshot_height.load(Ordering::Acquire);
        let last_at = self.last_header_snapshot_at.load(Ordering::Acquire);
        // Burst floor 7s: the gateway allows 10 header POSTs/min per IP, so the
        // floor must keep worst-case bursts under that (60/7 ≈ 8.5/min). At 5s it
        // permitted 12/min and every overflow post 429'd — and worse, the failed
        // posts still advanced the height marker (stored pre-POST at the time), so
        // the trigger skipped ahead without the snapshot ever landing and VERIFIED
        // drifted 38+ behind during the very bursts this exists to cover.
        let delta_due = tip_now.saturating_sub(last_h) >= 8 && now.saturating_sub(last_at) >= 7;
        if delta_due {
            // Claim the burst window atomically. A bare store let two concurrent callers
            // (the 5s periodic loop and the post-mine path) both observe delta_due and both
            // POST, defeating the 7s floor. compare_exchange lets only the caller that swaps
            // last_at from the value it observed proceed; the loser bails.
            if self
                .last_header_snapshot_at
                .compare_exchange(last_at, now, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Ok(());
            }
        } else if !Self::should_publish_now(
            &self.last_header_snapshot_at,
            Self::header_snapshot_interval_secs(),
            now,
        ) {
            return Ok(());
        }

        let Some(last_block) = self.public_advertisable_tip().await else {
            return Ok(());
        };
        let height = last_block.index;
        let difficulty = last_block.difficulty;

        // Widened to 64 so a client resolving a fork can always walk back to the
        // common ancestor within the signed header window (the gateway accepts up
        // to 256), instead of falling back to a full re-download.
        let start = height.saturating_sub(64);
        let mut headers = Vec::new();
        {
            let blockchain = self.blockchain.read().await;
            for h in start..=height {
                if let Ok(block) = blockchain.get_block(h) {
                    headers.push(json!({
                        "height": block.index,
                        "hash": hex::encode(block.hash),
                        "prev_hash": hex::encode(block.previous_hash),
                        "timestamp": block.timestamp
                    }));
                }
            }
        }

        if headers.is_empty() {
            // Fallback to last block if indexed fetch failed
            headers.push(json!({
                "height": last_block.index,
                "hash": hex::encode(last_block.hash),
                "prev_hash": hex::encode(last_block.previous_hash),
                "timestamp": last_block.timestamp
            }));
        }

        let last_block_time = headers
            .last()
            .and_then(|h| h.get("timestamp"))
            .and_then(|v| v.as_u64())
            .unwrap_or(last_block.timestamp);

        // hashrate_ths is deliberately omitted: it is an f64, and Rust (ryu) and
        // the gateway's JS canonical JSON stringify floats differently, so any
        // float in the signed message makes signature verification fail
        // server-side. The gateway treats it as optional and gets hashrate from
        // the stats push instead.
        let message = json!({
            "height": height,
            "network_id": hex::encode(self.network_id),
            "last_block_time": last_block_time,
            "difficulty": difficulty,
            "headers": headers,
            "node_id": &self.node_id,
            "public_key": &self.node_id
        });

        let canonical = Self::canonical_json_string(&message)?;
        let keypair = Ed25519KeyPair::from_pkcs8(&self.handshake_key_bytes)
            .map_err(|_| NodeError::Network("Invalid handshake key bytes".into()))?;
        let signature = keypair.sign(canonical.as_bytes());

        let payload = json!({
            "height": height,
            "network_id": hex::encode(self.network_id),
            "last_block_time": last_block_time,
            "difficulty": difficulty,
            "headers": message["headers"],
            "node_id": &self.node_id,
            "public_key": &self.node_id,
            "signature": hex::encode(signature.as_ref())
        });

        let mut any_ok = false;
        for url in Self::discovery_headers_urls() {
            let res = self.http_client.post(url).json(&payload).send().await;
            match res {
                Ok(res) if res.status().is_success() => any_ok = true,
                Ok(res) => {
                    let status = res.status();
                    let body = res.text().await.unwrap_or_default();
                    warn!(
                        "Header snapshot post failed: {} {}",
                        status,
                        Self::response_body_snippet(&body)
                    );
                }
                Err(e) => warn!("Header snapshot error: {}", e),
            }
        }

        if !any_ok {
            warn!("Header snapshot post failed on all endpoints");
            return Ok(());
        }
        // Mark the posted height ONLY on success: a rejected post (429 during a
        // burst, transient network error) must leave the delta trigger armed so the
        // next window retries, instead of "skipping ahead" past a snapshot that
        // never landed.
        self.last_header_snapshot_height
            .store(height as u64, Ordering::Release);

        Ok(())
    }

    fn discovery_tip_urls() -> Vec<String> {
        Self::discovery_bases()
            .into_iter()
            .map(|base| format!("{}/api/tip", base))
            .collect()
    }

    /// Publish the tiny signed tip beacon — the per-block liveness signal every
    /// client polls from the CDN edge. Called event-driven on each tip change, so
    /// it is per-block fresh (unlike the heavy, throttled header snapshot) while
    /// being one small signed SET. Publisher only.
    async fn post_tip_beacon(&self) -> Result<(), NodeError> {
        if !Self::public_header_snapshots_enabled() {
            return Ok(());
        }
        let (height, hash, prev_hash, block_time, difficulty, version) = {
            let blockchain = self.blockchain.read().await;
            let Some(tip) = blockchain.get_last_block() else {
                return Ok(());
            };
            (
                tip.index,
                hex::encode(tip.hash),
                hex::encode(tip.previous_hash),
                tip.timestamp,
                tip.difficulty,
                blockchain.tip_change_version(),
            )
        };

        // No floats in the signed message (ryu vs JS stringify diverge); all
        // fields are ints/hex strings, matching the /api/tip canonicalization.
        let message = json!({
            "network_id": hex::encode(self.network_id),
            "height": height,
            "hash": hash,
            "prev_hash": prev_hash,
            "block_time": block_time,
            "difficulty": difficulty,
            "version": version,
            "node_id": &self.node_id,
            "public_key": &self.node_id,
        });
        let canonical = Self::canonical_json_string(&message)?;
        let keypair = Ed25519KeyPair::from_pkcs8(&self.handshake_key_bytes)
            .map_err(|_| NodeError::Network("Invalid handshake key bytes".into()))?;
        let signature = keypair.sign(canonical.as_bytes());

        let payload = json!({
            "network_id": hex::encode(self.network_id),
            "height": height,
            "hash": hash,
            "prev_hash": prev_hash,
            "block_time": block_time,
            "difficulty": difficulty,
            "version": version,
            "node_id": &self.node_id,
            "public_key": &self.node_id,
            "signature": hex::encode(signature.as_ref()),
        });

        for url in Self::discovery_tip_urls() {
            if let Err(e) = self.http_client.post(url).json(&payload).send().await {
                debug!("Tip beacon post error: {}", e);
            }
        }
        Ok(())
    }

    /// Read the tiny signed tip beacon (the live liveness signal). Served from the
    /// CDN edge, so this poll is essentially free at the origin. The beacon only
    /// tells us WHERE the tip is; the blocks it points to are still independently
    /// validated (PoW + linkage + signatures) on apply, so a poisoned beacon can
    /// at worst cause a wasted fetch, never a bad adoption.
    async fn fetch_tip_beacon(&self) -> Option<TipBeaconInfo> {
        // ~1s TTL memo: bursts of callers (mine-prep rounds, the absorb wait, the
        // beacon-watch tick, converge STEP-4) each re-fetched the same edge-cached
        // beacon within the same second — the absorb loop alone issued up to 40
        // GETs per mined block. One fetch per second per process is plenty; the
        // TTL sits far under the 5s block time, so every staleness guard
        // (ghost-block, high-water) sees the same freshness it did before.
        // Failures are NOT memoized — the unreachable path keeps retrying live.
        const BEACON_MEMO_TTL: Duration = Duration::from_millis(1000);
        if let Some((at, memo)) = *self.beacon_memo.lock() {
            if at.elapsed() < BEACON_MEMO_TTL {
                return Some(memo);
            }
        }
        for url in Self::discovery_tip_urls() {
            let Ok(res) = self.http_client.get(&url).send().await else {
                continue;
            };
            if !res.status().is_success() {
                continue;
            }
            let Ok(body) = res.json::<serde_json::Value>().await else {
                continue;
            };
            if !body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                continue;
            }
            // Reject a beacon for a different network outright: it must never drive
            // convergence/bootstrap decisions on this chain. (Consensus safety still
            // comes from independent block validation on apply; this is a cheap guard
            // so a cross-network beacon can't even trigger a fetch or an exit path.)
            let network_id_match = body
                .get("network_id")
                .and_then(|v| v.as_str())
                .map(|nid| nid.eq_ignore_ascii_case(&hex::encode(self.network_id)));
            // Absent network_id: don't hard-fail (older gateway).
            if network_id_match == Some(false) {
                continue;
            }
            let Some(height) = body.get("height").and_then(|v| v.as_u64()) else {
                continue;
            };
            let version = body.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
            let parse_hash = |field: &str| -> Option<[u8; 32]> {
                body.get(field)
                    .and_then(|v| v.as_str())
                    .and_then(|s| hex::decode(s).ok())
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
            };
            let Some(hash) = parse_hash("hash") else {
                continue;
            };
            // Remember the freshest beacon we ever saw: the mine-prep fail-open
            // consults this when the beacon is momentarily unreachable, so known
            // staleness can't be laundered into "mine the local tip anyway".
            // Only a beacon that POSITIVELY identified our network is recorded: a
            // cross-network or malformed read (no network_id) must not move the
            // high-water. Recorded into the ROLLING window (not a forever-monotonic
            // max) so a genuine canonical regression can eventually clear the guard
            // (2026-07-12 audit) instead of pinning every miner into a permanent
            // refuse-to-mine until restart.
            if network_id_match == Some(true) {
                self.record_beacon_observation(height as u32);
                // Also feed the forever-monotonic high-water used by the unreachable
                // fail-open bound (see field doc): it must NOT age out, or a total
                // beacon outage would drop a far-behind node into orphan mining.
                self.last_seen_beacon_height
                    .fetch_max(height, Ordering::AcqRel);
            }
            let info = TipBeaconInfo {
                height: height as u32,
                hash,
                version,
            };
            *self.beacon_memo.lock() = Some((Instant::now(), info));
            return Some(info);
        }
        None
    }

    /// Current signed network beacon height, if reachable. Public accessor for
    /// pacing decisions (e.g. continuous mining waits for the network to absorb a
    /// mined block before starting the next). Read-only; one edge-cached HTTP GET.
    pub async fn network_beacon_height(&self) -> Option<u32> {
        self.fetch_tip_beacon().await.map(|b| b.height)
    }

    /// Current signed beacon tip as `(height, hex hash)`, or None if the beacon
    /// is unreachable. Read-only sibling of `network_beacon_height` for callers
    /// that also need the tip HASH — e.g. the idle reconcile loop's fork check,
    /// which compares the local block at the beacon height against this hash to
    /// catch an out-extended (taller-but-losing) fork. Mining never calls this;
    /// it is behaviour-neutral for the mining path.
    pub async fn network_beacon_tip(&self) -> Option<(u32, String)> {
        self.fetch_tip_beacon()
            .await
            .map(|b| (b.height, hex::encode(b.hash)))
    }

    /// Highest network beacon height OBSERVED by the background reconcile loops
    /// (a free read of the last-seen high-water — NO network fetch), or None if
    /// none seen yet. Powers the explorer `/status` freshness signal so a
    /// consumer (exchange deposit-crediting, a wallet) can gate on how far
    /// behind the serving node is without doing its own beacon fetch.
    pub fn observed_beacon_height(&self) -> Option<u32> {
        match self.last_seen_beacon_height.load(Ordering::Acquire) {
            0 => None,
            h => Some(h as u32),
        }
    }

    /// Find the highest height at which the LOCAL chain agrees with the CANONICAL
    /// chain the beacon points to — the fork point from which we adopt canonical
    /// forward.
    ///
    /// CRITICAL (this is the algorithm that actually breaks the monopoly): the
    /// canonical chain is reconstructed by following `previous_hash` DOWNWARD from
    /// `beacon.hash`, NOT by a height->hash map. A stuck miner posts its own fork
    /// blocks to the relay too, so `/api/blocks` returns BOTH sides of a fork at a
    /// shared height; a height->hash map picks arbitrarily and can select the LOCAL
    /// fork's block, yielding a false-HIGH ancestor — after which the adopt fetch
    /// misses the true canonical block and the node stays stuck exactly as before.
    /// The prev-hash walk can only ever UNDER-estimate the ancestor, which is safe
    /// (the reorg engine re-derives the true root from the first differing height).
    ///
    /// Windows are 64-ALIGNED so every node issues identical relay ranges and the
    /// CDN/gateway cache coalesces the reorg scan to one origin read per window.
    /// Bounded, floored at `verification_floor()`; any relay gap/empty/break returns
    /// `Transient` (retry) rather than a spurious deep-divergence verdict.
    /// `by_hash` is the caller-owned canonical-body cache, keyed by block hash.
    /// converge_to_canonical passes ONE cache across all its rounds against the
    /// same fixed beacon: without it, every round after a chunked adoption
    /// re-fetched the identical windows from the beacon down (a quadratic
    /// re-walk — ~72 GETs to converge a 1024 gap instead of ~17). Hash-keyed
    /// entries cannot go stale (blocks are immutable and the walk follows
    /// prev-hash links), and every adopted block still passes the sig gate +
    /// engine validation — the cache only saves re-downloading bodies.
    async fn find_common_ancestor(
        &self,
        beacon: &TipBeaconInfo,
        floor: u32,
        by_hash: &mut std::collections::HashMap<[u8; 32], Block>,
    ) -> Ancestor {
        const WIN: u32 = 64;
        let mut canon_desc: Vec<Block> = Vec::new(); // canonical bodies, tip -> ancestor
        let mut expected_hash = beacon.hash;
        let mut expected_height = beacon.height;
        let max_rounds = (beacon.height.saturating_sub(floor) / WIN) + 2;
        // A gap/broken link at a height deeper than a convergent reorg could reach
        // (below beacon - margin) is not transient — the needed history is gone (aged out
        // of the ~1h relay) and only a fresh snapshot recovers it. A gap WITHIN reorg
        // reach near the tip is genuinely transient and must retry, never bootstrap.
        let reorg_floor = beacon
            .height
            .saturating_sub(crate::a9::blockchain::CHECKPOINT_REORG_MARGIN);
        let gap_verdict = |needed: u32| -> Ancestor {
            if needed < reorg_floor {
                Ancestor::NeedsBootstrap
            } else {
                Ancestor::Transient
            }
        };

        for _ in 0..max_rounds {
            // Fetch the 64-aligned window containing the height we need next —
            // unless the caller's cross-round cache already holds the body the
            // walk needs (warm after a prior round's fetches). On a cache hit
            // the walk below consumes cached bodies directly and the exact-fetch
            // fallback covers any individual miss, so skipping the window fetch
            // can never manufacture a gap verdict.
            let win_base = expected_height - (expected_height % WIN);
            if !by_hash.contains_key(&expected_hash) {
                let win_end = win_base + WIN - 1;
                match self.fetch_relay_blocks(win_base, win_end).await {
                    Ok(v) if !v.is_empty() => {
                        for b in v {
                            by_hash.entry(b.hash).or_insert(b);
                        }
                    }
                    // Empty-but-200 in a below-tip window IS a genuine gap: depth decides —
                    // within reorg reach retry (Transient), deeper the history is gone and only
                    // a snapshot recovers it (NeedsBootstrap).
                    Ok(_) => return gap_verdict(expected_height),
                    // A network ERROR (429 rate-limit, timeout, 5xx) tells us NOTHING about
                    // whether the history exists — it's a transient relay hiccup. Treat it as
                    // Transient and retry; never self-bootstrap or freeze the applied tip on it.
                    // (audit finding #6: a pool's own /api/blocks GETs getting rate-limited
                    // under sustained load was misclassified as a chain gap → BeaconStale freeze
                    // / needless NeedsBootstrap restart.)
                    Err(_) => return Ancestor::Transient,
                }
            }

            // Walk the prev-hash chain down through the bodies we now hold.
            loop {
                let cb = match by_hash.get(&expected_hash).cloned() {
                    Some(cb) => cb,
                    None => {
                        // The windowed fetch is fork-capped + limited, so under heavy
                        // forking it can omit the EXACT parent this walk needs even
                        // though the block exists on the relay — which stranded nodes
                        // on losing forks (2026-07-08). Before declaring a gap, ask for
                        // the exact block by (height, hash); it can never be hidden by
                        // fork density. Only a genuine miss falls through to gap_verdict.
                        match self
                            .fetch_relay_block_exact(expected_height, expected_hash)
                            .await
                        {
                            ExactFetch::Found(b) => {
                                by_hash.entry(b.hash).or_insert(b.clone());
                                b
                            }
                            // A transient blip (429/timeout/unreachable) on the exact
                            // fetch must retry on the soft tier, NOT sideline the live
                            // lineage for 300s via NeedsBootstrap (2026-07-12 audit).
                            ExactFetch::Transient => return Ancestor::Transient,
                            ExactFetch::Missing => return gap_verdict(expected_height),
                        }
                    }
                };
                let h = cb.index;
                canon_desc.push(cb.clone());
                let local_hash = self
                    .blockchain
                    .read()
                    .await
                    .get_block(h)
                    .ok()
                    .map(|lb| lb.hash);
                if local_hash == Some(cb.hash) {
                    canon_desc.reverse(); // ascending [ancestor ..= beacon.height]
                    return Ancestor::Found(h, canon_desc);
                }
                if h <= floor {
                    // Linked canonical contiguously to the floor with no local match.
                    return Ancestor::NoneBelowFloor;
                }
                expected_hash = cb.previous_hash;
                expected_height = h - 1;
                if expected_height < win_base {
                    break; // descend to the next lower window
                }
            }
        }
        gap_verdict(expected_height)
    }

    /// The single always-converge operation. From ANY local state — behind, forked at
    /// the tip, forked and behind, same-height fork, or already ahead — drive the local
    /// chain to the signed-beacon canonical tip. Idempotent when already synced,
    /// bounded in rounds and reorg depth, and it NEVER concedes: a node legitimately at
    /// or ahead of the beacon returns `AtTipAhead` so it can mine and compete.
    ///
    /// Consensus safety is unchanged — every adoption still routes through the reorg
    /// engine's work/checkpoint/S-01/replay guards; this only chooses WHICH canonical
    /// blocks to stage. Adopted (canonical) blocks are NEVER re-published to the relay
    /// (that would echo-storm the gateway and self-rate-limit the very catch-up it does).
    async fn converge_to_canonical(&self, beacon: &TipBeaconInfo) -> Converge {
        const MAX_ROUNDS: u32 = 6;
        // Per-round adoption cap: large enough to catch up fast (6 rounds x 128 =
        // 768 blocks per converge call), small enough that one engine adoption
        // always finishes inside the caller's round timeout. See the chunked-
        // adoption comment below.
        const CONVERGE_CHUNK: u32 = 128;
        let entry_tip = self.blockchain.read().await.get_latest_block_index() as u32;
        // PROGRESS-BASED stall escalation (2026-07-11). Classification-based
        // escalation missed a real stuck state observed live within the hour of
        // widening the boot stream window: a fork-storm relay develops per-height
        // slot holes, the exact ancestor walk keeps failing (Ancestor::Transient
        // -> BeaconStale — which never strikes the divergence watchdog), and the
        // node sits far behind a FRESH beacon making zero progress: not diverged,
        // not streamable, never escalated. The verdict here is purely about
        // progress: CONVERGE_STALL_ESCALATE_CALLS consecutive converge calls with
        // the gap beyond the reorg margin and a non-advancing tip = cannot
        // converge, whatever each call's classification was. NeedsBootstrap then
        // rides the existing 2-strike -> marker -> re-bootstrap machinery.
        {
            let gap = beacon.height.saturating_sub(entry_tip);
            let last_tip = self
                .converge_stall_tip
                .swap(entry_tip as u64, Ordering::AcqRel) as u32;
            let prev_cycles = self.converge_stall_cycles.load(Ordering::Acquire);
            let cycles = Self::converge_stall_verdict(last_tip, entry_tip, gap, prev_cycles).0;

            if cycles == 0 {
                // Progress (tip advanced) or a within-margin gap: reset immediately, always.
                self.converge_stall_cycles.store(0, Ordering::Release);
            } else {
                // Zero-progress stall. Throttle COUNTING to at most once per
                // CONVERGE_STALL_MIN_INTERVAL_MS so a candidate burst within one converge_to_relay_tip
                // pass counts once (not once per candidate), restoring the intended ~0.5-3.5 minute
                // horizon. Escalation itself is NEVER throttled: once the persisted counter reaches
                // the threshold, every stalled call must return NeedsBootstrap, or a gated candidate
                // in an aggregating pass would starve the caller's 2-strike re-bootstrap machinery.
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let last_ms = self.converge_stall_last_ms.load(Ordering::Acquire);
                // saturating_sub reads a backward wall-clock step as 0 elapsed; treat now < last as
                // "interval elapsed" so a clock regression can never stall this watchdog.
                let interval_elapsed =
                    now_ms < last_ms || now_ms - last_ms >= CONVERGE_STALL_MIN_INTERVAL_MS;
                let effective = if interval_elapsed {
                    self.converge_stall_last_ms.store(now_ms, Ordering::Release);
                    self.converge_stall_cycles.store(cycles, Ordering::Release);
                    cycles
                } else {
                    // Within the cadence window: do not count this candidate, but read the persisted
                    // counter so an already-reached threshold still escalates.
                    self.converge_stall_cycles.load(Ordering::Acquire)
                };
                if effective >= CONVERGE_STALL_ESCALATE_CALLS as u64 {
                    warn!(
                        "Converge made no progress for {} consecutive ticks at tip {} with beacon {} ({} behind); escalating to re-bootstrap",
                        effective, entry_tip, beacon.height, gap
                    );
                    return Converge::NeedsBootstrap;
                }
            }
        }
        // Canonical-body cache shared across THIS call's rounds (one fixed
        // beacon): after a chunked adoption the next round's ancestor walk
        // re-reads the same bodies from here instead of re-fetching the whole
        // beacon-to-tip span from the relay (the quadratic re-walk).
        let mut walk_cache: std::collections::HashMap<[u8; 32], Block> =
            std::collections::HashMap::new();
        for _ in 0..MAX_ROUNDS {
            let (tip, at_beacon) = {
                let bc = self.blockchain.read().await;
                let t = bc.get_latest_block_index() as u32;
                let at = matches!(bc.get_block(beacon.height), Ok(b) if b.hash == beacon.hash);
                (t, at)
            };
            if at_beacon {
                return Converge::Converged; // holds the beacon tip (or is ahead of it on-chain)
            }

            let floor = self.blockchain.read().await.verification_floor();
            let (ancestor, canon) = match self
                .find_common_ancestor(beacon, floor, &mut walk_cache)
                .await
            {
                Ancestor::Found(a, canon) => (a, canon),
                Ancestor::NoneBelowFloor | Ancestor::NeedsBootstrap => {
                    return Converge::NeedsBootstrap
                }
                Ancestor::Transient => return Converge::BeaconStale,
            };

            let before = tip;
            if ancestor >= tip {
                // Same chain, strictly behind (ancestor == tip). v7.6.5 FIX (2026-07-08
                // night): this used to forward-stream via windowed relay fetches ONLY —
                // but the windowed list is fork-capped ("2 oldest + 1 newest" per
                // height), and in a reorg-overtake zone the canonical block at a height
                // is often a LATER post that holds neither slot, so the stream saw the
                // canonical child only in the brief moment it was "newest". Catch-up was
                // therefore pinned to ~mint speed (or fully stuck), and a node that fell
                // behind could NEVER close the gap — the network-wide "everyone at a
                // different height" complaint. find_common_ancestor already walked the
                // exact canonical bodies down to our tip (exact-by-(height,hash) fetches
                // that fork density cannot hide), so ADOPT that branch directly — a pure
                // append (rewrite depth 0) through the same fully-validated engine path
                // the reorg case uses. The windowed stream remains only as a fallback
                // for the no-new-bodies edge (beacon exactly at our tip).
                // Same bound as the divergent path: a very long append may not hold the
                // write lock for an unbounded validation — a node THAT far behind
                // re-bootstraps from the snapshot instead.
                if beacon.height.saturating_sub(tip) > crate::a9::blockchain::ORPHAN_REORG_DEPTH {
                    return Converge::NeedsBootstrap;
                }
                // CHUNKED ADOPTION (v7.6.5): adopt at most CONVERGE_CHUNK blocks per
                // round. A 180-block branch validated atomically under the write lock
                // outlived the caller's per-round timeout, the cancelled adoption
                // applied NOTHING, and every retry restarted from scratch — a node a
                // few hours behind could provably never converge (2026-07-08 night).
                // A capped chunk always finishes inside the round budget; the loop
                // re-runs and RESUMES from the new tip, so progress is monotonic.
                let branch: Vec<Block> = canon
                    .into_iter()
                    .filter(|b| b.index > tip && b.index <= tip.saturating_add(CONVERGE_CHUNK))
                    .collect();
                if branch.is_empty() {
                    let _ = self.sync_with_block_relay(tip).await;
                } else {
                    // Apply the walked bodies through the SAME per-block ingest the relay
                    // stream uses (frontier sig gate -> save_receipt_verified_block ->
                    // checkpoint trail). This path used to call adopt_external_branch,
                    // which routes through try_adopt_orphan_branch — and that filter
                    // DISCARDS every block above the current tip (`b.index > tip.index
                    // -> continue`), so a pure forward APPEND always came back Ok(false),
                    // the `Ok(_)` arm swallowed it, and the round reported Progressed
                    // having applied NOTHING: the publisher pinned at 2800 re-walking the
                    // same branch every tick while the site froze (2026-07-09). The
                    // orphan machinery is for reorgs (branch roots at/below tip) and
                    // still handles the divergent path below.
                    // Floor hoisted out of the loop: it cannot move mid-append (and a
                    // stale-low floor only ever demands MORE verification, never
                    // less). The per-block re-read plus a second guard acquisition
                    // was 2 RwLock hits per block on a lock contended by ingest.
                    let floor = self.blockchain.read().await.verification_floor();
                    // RECEIPT-TRUST CEILING. A block may skip the ML-DSA witness
                    // re-check only when something we already trust vouches for it:
                    //
                    //  * at/below `floor` — our own finalized history (snapshot- or
                    //    self-verified); the pre-existing rule, unchanged; or
                    //  * at/below beacon.height - CHECKPOINT_REORG_MARGIN — buried
                    //    history vouched for by the SIGNED BEACON.
                    //
                    // The second clause is only sound because every block in `branch`
                    // came from find_common_ancestor, which walks DOWN from beacon.hash
                    // taking each block's previous_hash as the hash the next one must
                    // have, and admits a body only if it self-hashes and carries floor
                    // PoW. Burial is therefore PROVEN per block against a signed hash,
                    // never inferred from a height — a height alone vouches for no
                    // particular body. The frontier (within the reorg margin of the
                    // beacon) still demands full witnesses, preserving S-01.
                    let receipt_trust_ceiling = floor.max(
                        beacon
                            .height
                            .saturating_sub(crate::a9::blockchain::CHECKPOINT_REORG_MARGIN),
                    );
                    // One dirty window per adopted chunk (≤CONVERGE_CHUNK):
                    // amortizes the per-block fsyncs. The loop's early exits
                    // are collected into `early` and returned only AFTER the
                    // window commits, so no exit path leaves it open.
                    let batch = {
                        let bc = self.blockchain.read().await;
                        bc.begin_receipt_batch()
                            .await
                            .map_err(|e| {
                                warn!(
                                    "converge: apply window unavailable, using per-block durability: {}",
                                    e
                                )
                            })
                            .ok()
                    };
                    let mut early: Option<Converge> = None;
                    for block in branch {
                        if block.index > receipt_trust_ceiling
                            && !self
                                .blockchain
                                .read()
                                .await
                                .block_signatures_fully_verified(&block)
                        {
                            warn!(
                                "Rejected forward block {} (> receipt-trust ceiling {}): signatures not fully verifiable",
                                block.index, receipt_trust_ceiling
                            );
                            early = Some(Converge::BranchInvalid);
                            break;
                        }
                        let saved = {
                            let bc = self.blockchain.write().await;
                            let before = bc.get_latest_block_index() as u32;
                            // String-ify immediately: BlockchainError is !Send and this
                            // value is held across the checkpoint await below.
                            let result = bc
                                .save_receipt_verified_block(&block)
                                .await
                                .map_err(|e| e.to_string());
                            let after = bc.get_latest_block_index() as u32;
                            (result, before, after)
                        };
                        match saved {
                            (Ok(()), before, after) => {
                                // Only trail the finality checkpoint when the save actually
                                // extended the canonical tip, matching the relay-tip sibling.
                                // save_receipt_verified_block also returns Ok(()) for an
                                // idempotent duplicate or a parked side block, and advancing
                                // finality behind a block that did not move the tip is unsafe.
                                if after > before && block.index > floor {
                                    let _ = self
                                        .blockchain
                                        .read()
                                        .await
                                        .advance_checkpoint_behind(block.index);
                                }
                            }
                            (Err(e), _, _) => {
                                debug!(
                                    "Rejected forward block {} toward {}@{}: {}",
                                    block.index,
                                    beacon.height,
                                    hex::encode(beacon.hash),
                                    e
                                );
                                // Storage/serialization trouble is TRANSIENT — report it
                                // as a stale view so the caller retries soon. BranchInvalid
                                // here gets memoized lineage-dead and PROPAGATES to every
                                // child, so one sled hiccup mid-append would sideline our
                                // own live lineage for the whole 300s cooldown.
                                early = Some(
                                    if e.contains("Database error") || e.contains("Serialization")
                                    {
                                        Converge::BeaconStale
                                    } else {
                                        Converge::BranchInvalid
                                    },
                                );
                                break;
                            }
                        }
                    }
                    if let Some(batch) = batch {
                        if let Err(e) = {
                            let bc = self.blockchain.read().await;
                            bc.commit_receipt_batch(batch).await
                        } {
                            warn!(
                                "converge: apply window commit failed; dirty marker left for recovery: {}",
                                e
                            );
                        }
                    }
                    if let Some(outcome) = early {
                        return outcome;
                    }
                }
            } else {
                // Divergent: our tip forks from canonical at `ancestor` < tip.
                let d = ancestor + 1;
                // Reuse the bodies find_common_ancestor already fetched: [d ..= beacon],
                // capped per round (chunked adoption — see the append path) so one
                // engine call always finishes inside the caller's round timeout. The
                // rewrite segment (<= CHECKPOINT_REORG_MARGIN = 64) always fits.
                let branch: Vec<Block> = canon
                    .into_iter()
                    .filter(|b| b.index >= d && b.index <= ancestor.saturating_add(CONVERGE_CHUNK))
                    .collect();
                if branch.is_empty() {
                    return Converge::BeaconStale;
                }
                // FORK-CHOICE GATE, BEFORE the finality/depth guards. Proceed toward the
                // canonical branch when it is strictly HEAVIER, OR when it is an EQUAL-work
                // SAME-HEIGHT fork whose tip hash is strictly lower (the deterministic
                // lowest-hash tie-break the reorg engine applies). The equal-work tie MUST be
                // honoured here: without it, two miners producing a same-height block leave
                // beacon/relay-only nodes stuck on their own higher-hash block forever (they
                // never route the competitor through the engine), splitting them from the
                // directly-P2P-meshed nodes that do — the "won't catch up" fork.
                //
                // Everything else returns AtTipAhead (keep mining, reset strikes), never
                // bootstrap: a strictly-LIGHTER or taller-but-lighter fork (which
                // converge_to_relay_tip can nominate by max height) must not reach the depth
                // guards below, or a repeated NeedsBootstrap would drive the publisher's
                // 2-strike exit(0) and freeze the beacon for the whole network.
                let wins = {
                    let bc = self.blockchain.read().await;
                    bc.external_branch_wins_fork_choice(&branch, ancestor, tip)
                };
                if !wins {
                    return Converge::AtTipAhead;
                }
                let checkpoint = self.blockchain.read().await.trusted_checkpoint_height();
                if d <= checkpoint {
                    return Converge::NeedsBootstrap; // may not rewrite finalized history
                }
                // Finality bound: cap the local REWRITE depth (blocks we rewind), which
                // is `tip - ancestor` — NOT `beacon.height - ancestor`. The forward part
                // of the branch (tip..=beacon) is a pure APPEND, not a rewrite, so it is
                // not finality-limited; capping the whole span wrongly refused a shallow
                // fork that happens to sit far behind a tall winning chain (e.g. a node
                // ~1h behind), wedging it into NeedsBootstrap when a normal reorg + append
                // would have converged it.
                if tip.saturating_sub(ancestor) > crate::a9::blockchain::CHECKPOINT_REORG_MARGIN {
                    return Converge::NeedsBootstrap;
                }
                // Separately bound the total branch we validate under the write lock, so
                // a very long append can't hold it for an unbounded time.
                if beacon.height.saturating_sub(ancestor)
                    > crate::a9::blockchain::ORPHAN_REORG_DEPTH
                {
                    return Converge::NeedsBootstrap;
                }
                let adopted = match self
                    .blockchain
                    .write()
                    .await
                    .adopt_external_branch(branch)
                    .await
                {
                    Ok(adopted) => adopted,
                    Err(e) => {
                        // The branch FAILED validation (bad tx, PoW, linkage…). This is
                        // NOT "we hold a heavier chain" — conflating the two returned a
                        // fake AtTipAhead success that short-circuited the publisher's
                        // candidate iteration: an INVALID fork posted by an incompatible
                        // client (relay height 1388, "Transaction is invalid") pinned the
                        // beacon at 1261 while a perfectly valid forward extension sat
                        // one candidate further down the list. Report the target as
                        // stale so the caller memoizes it dead and tries the next branch.
                        debug!(
                            "Rejected candidate branch toward {}@{}: {}",
                            beacon.height,
                            hex::encode(beacon.hash),
                            e
                        );
                        return Converge::BranchInvalid;
                    }
                };
                if !adopted {
                    // The engine declined because our branch's work is >= canonical
                    // (we hold an equal-or-heavier chain, including the equal-work
                    // lower-local-hash tie). That is a terminal SUCCESS for mining,
                    // not a concede — extend our chain and let PoW settle it.
                    return Converge::AtTipAhead;
                }
                info!(
                    "Converged onto canonical branch via reorg (fork@{} -> beacon {})",
                    ancestor, beacon.height
                );
                // Deliberately DO NOT publish_local_tip here: these are canonical
                // blocks we adopted, not blocks we mined. Re-POSTing them echoes the
                // relay and can trip the per-IP rate limit into non-convergence.
            }

            let after = self.blockchain.read().await.get_latest_block_index() as u32;
            if after == before {
                break; // no progress this round -> stop (avoid spin)
            }
        }

        let (synced, final_tip) = {
            let bc = self.blockchain.read().await;
            (
                matches!(bc.get_block(beacon.height), Ok(b) if b.hash == beacon.hash),
                bc.get_latest_block_index() as u32,
            )
        };
        if synced {
            Converge::Converged
        } else if final_tip > entry_tip {
            Converge::Progressed
        } else {
            // ZERO blocks were applied across every round. Reporting Progressed here
            // let a broken apply path masquerade as success: the publisher's candidate
            // iterator treats Progressed as a terminal win for the tick (it returns
            // immediately, skipping other candidates AND the forward-drain fallback),
            // so the same no-op "progress" repeated every tick forever — the frozen-
            // at-2800 site stall. No progress = a stale/gapped view of this branch:
            // report it as such so callers try other branches and fallbacks.
            Converge::BeaconStale
        }
    }

    /// Fetch the signed beacon and converge to it. Callable from `main.rs` (the `--sync`
    /// command, launch, and the runtime reconcile loop). Beacon unreachable -> fail-open
    /// as `BeaconStale` (never a hard stop).
    pub async fn sync_to_beacon(&self) -> Converge {
        match self.fetch_tip_beacon().await {
            Some(beacon) => self.converge_to_canonical(&beacon).await,
            None => Converge::BeaconStale,
        }
    }

    /// PUBLISHER-side sync: converge to the HEAVIEST chain the relay holds, reorging off
    /// a losing fork if necessary.
    ///
    /// The publisher is the SOURCE of the beacon, so it cannot follow it — it must decide
    /// canonical from the blocks miners actually posted. A plain forward relay pull can
    /// latch the publisher onto a losing fork (e.g. two miners post competing blocks at the
    /// same height and it ingests the wrong one first) and then get STUCK: the heavier
    /// chain's newer blocks don't chain onto the fork it holds, and a forward pull never
    /// re-fetches the lower blocks needed to reorg. So instead we take the relay's
    /// highest block as the target and run the same fork-aware converge — which finds the
    /// real common ancestor, fetches the competing branch, and hands it to the engine's
    /// WORK-based fork choice (so we only ever switch to a genuinely heavier chain, never a
    /// merely "taller" low-work one). The reorg depth is bounded exactly as for clients.
    async fn converge_to_relay_tip(&self) -> Converge {
        let (local_tip, local_hash) = {
            let bc = self.blockchain.read().await;
            (
                bc.get_latest_block_index() as u32,
                bc.get_last_block().map(|b| b.hash),
            )
        };

        // Caught-up FAST PATH (runs ~every 1s on the publisher). Cheapest first: the
        // gateway-maintained relay-head hint ({height,hash} of the newest ACCEPTED
        // block POST, refreshed/purged on every write). One CDN-fresh read replaces a
        // block-range scan whose non-empty response gets edge/instance cached for
        // 5-30s — the measured 5-25s ingest lag that widened every mining race. The
        // head is a HINT about when to look, never a source of truth: adoption below
        // still routes through the full validation/work-choice engine, so a wrong head
        // can only delay or waste a look. If the endpoint is missing or unreachable
        // (older gateway, transient error), fall back to the original tip-adjacent
        // range probe, byte-for-byte today's behavior.
        match self.fetch_relay_head().await {
            Some(head) => {
                let caught_up = head.height < local_tip
                    || (head.height == local_tip && Some(head.hash) == local_hash);
                if caught_up {
                    return Converge::Converged;
                }
                // Something new or foreign at/above our tip: pay for the wide scan.
            }
            None => {
                match self
                    .fetch_relay_blocks(local_tip, local_tip.saturating_add(1))
                    .await
                {
                    Ok(probe) => {
                        let has_forward = probe.iter().any(|b| b.index > local_tip);
                        let foreign_at_tip = probe
                            .iter()
                            .any(|b| b.index == local_tip && Some(b.hash) != local_hash);
                        if !has_forward && !foreign_at_tip {
                            return Converge::Converged;
                        }
                    }
                    Err(_) => return Converge::BeaconStale,
                }
            }
        }

        // Not caught up: find the relay's heaviest LIVE tip and converge to it.
        let from = local_tip.saturating_sub(8);
        let to = local_tip.saturating_add(256);
        let blocks = match self.fetch_relay_blocks(from, to).await {
            Ok(b) if !b.is_empty() => b,
            _ => return Converge::BeaconStale,
        };

        // Candidate tips, best-first: height DESC then LOWEST hash (the engine's
        // work-tie lexical rule, so selection can't oscillate between competing tips
        // on successive ticks). We iterate candidates instead of pinning the single
        // max-height block: the relay holds first-seen blocks from EVERY fork, and an
        // abandoned fork with a relay gap in its ancestry (its owner's POSTs were
        // rate-limited away during a race storm) is UNCONVERGEABLE-BY-DESIGN — walking
        // only that one target froze the beacon for the whole network at height 1209
        // on 2026-07-08 while live miners advanced 24+ blocks. Dead candidates are
        // memoized (relay_dead_targets) with an expiry so each 1s tick moves straight
        // to the next live branch instead of re-walking the broken one.
        // 8 (was 4): a dead far-ahead fork keeps MINTING fresh tips, and each new tip
        // is a brand-new candidate the memo has never seen — at 4, those burned the
        // whole per-tick budget and the LIVE lineage never got tried (2026-07-08
        // night crawl). 8 leaves room for the live branch behind a noisy dead one.
        const MAX_TIP_CANDIDATES: usize = 8;
        const DEAD_TARGET_RETRY_SECS: u64 = 300;
        // Soft (non-lineage) verdicts get a SHORT block: a single per-candidate
        // timeout or transient relay gap on a LIVE branch must not sideline it for
        // the full 300s window — during racing that is 30-60 blocks of beacon lag
        // self-inflicted by one hiccup. Only lineage-dead verdicts (validation
        // failure / fork point below finality) deserve the long cooldown.
        const SOFT_TARGET_RETRY_SECS: u64 = 15;
        // TRUE TIPS ONLY: a block some other wire block names as its parent is not a
        // tip — converging to its tip covers it. Without this filter, an abandoned
        // fork contributes EVERY one of its blocks as a candidate (a post-storm relay
        // held a ~120-block dead fork), and the per-tick candidate budget could burn
        // entirely on dead mid-fork blocks before ever reaching the live chain's
        // fresh tip.
        let parent_hashes: HashSet<[u8; 32]> = blocks.iter().map(|b| b.previous_hash).collect();
        let mut candidates: Vec<(u32, [u8; 32])> = blocks
            .iter()
            .filter(|b| b.index >= local_tip && !parent_hashes.contains(&b.hash))
            .map(|b| (b.index, b.hash))
            .collect();
        candidates.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        candidates.dedup();

        // Deadness PROPAGATES through ancestry: an incompatible client keeps
        // EXTENDING its invalid fork, so every block it posts is a brand-new
        // candidate tip that a plain (height,hash) memo has never seen — each one
        // would cost a full ancestry walk plus a failed branch validation under the
        // chain write lock. If a candidate's parent chain (within this window)
        // passes through a memoized dead block, the candidate inherits the verdict
        // for free and is memoized itself.
        let wire_by_hash: HashMap<[u8; 32], (u32, [u8; 32])> = blocks
            .iter()
            .map(|b| (b.hash, (b.index, b.previous_hash)))
            .collect();
        let ancestry_dead = |start: [u8; 32],
                             dead: &mut LruCache<(u32, [u8; 32]), (Instant, bool)>|
         -> bool {
            let mut cursor = start;
            for _ in 0..1024 {
                let Some(&(h, prev)) = wire_by_hash.get(&cursor) else {
                    return false;
                };
                if let Some(&(when, lineage_dead)) = dead.peek(&(h, cursor)) {
                    // LINEAGE deadness propagates: BranchInvalid (fails validation) and
                    // NeedsBootstrap (fork point below the finality window) are properties
                    // of the whole branch — every child shares the ancestor/validity — so
                    // a stranded old-version miner minting a fresh tip every few seconds
                    // costs ONE lookup here instead of a full multi-window ancestry walk.
                    // Without NeedsBootstrap propagation those walks burned the entire
                    // candidate budget every tick and the beacon froze for minutes while
                    // OUR OWN lineage's fresh tips waited in line (2026-07-09 stall).
                    // Transient gap verdicts (BeaconStale) stay non-propagating.
                    if lineage_dead && when.elapsed() < Duration::from_secs(DEAD_TARGET_RETRY_SECS)
                    {
                        return true;
                    }
                }
                cursor = prev;
            }
            false
        };

        // DEEPEST-REACHABLE-TIP PRIORITY. When the winning branch has holes higher up
        // (posts dropped during a fork storm), the max-height tip is unwalkable, but
        // the branch is contiguous from our fork point up to the FIRST hole. Targeting
        // the highest block just below that first gap lets the publisher reorg onto the
        // winning branch and advance to the gap in one step, instead of the candidate
        // budget burning on unreachable high tips (2026-07-08: stranded at 2199 on a
        // dead fork while a reorg to ~2272 was available). This is a HINT prepended to
        // the candidate list; it still routes through the same validated converge.
        {
            let present: std::collections::HashSet<u32> = blocks.iter().map(|b| b.index).collect();
            let max_h = blocks.iter().map(|b| b.index).max().unwrap_or(local_tip);
            let mut first_gap = None;
            let mut h = local_tip.saturating_add(1);
            while h <= max_h {
                if !present.contains(&h) {
                    first_gap = Some(h);
                    break;
                }
                h += 1;
            }
            let reachable_top = first_gap.map(|g| g.saturating_sub(1)).unwrap_or(max_h);
            if reachable_top > local_tip {
                // EVERY fork at the reachable-top height, hash-ascending (was: lowest
                // hash only). Under same-height racing the lowest-hash block is often
                // a dead fork; once it failed and was memoized, the LIVE fork at the
                // same height never got hinted and the publisher fell back to burning
                // candidates on unreachable high tips (2026-07-08 night crawl).
                let mut tops: Vec<(u32, [u8; 32])> = blocks
                    .iter()
                    .filter(|b| b.index == reachable_top)
                    .map(|b| (b.index, b.hash))
                    .collect();
                tops.sort_by(|a, b| a.1.cmp(&b.1));
                for key in tops.into_iter().rev() {
                    candidates.retain(|c| *c != key);
                    candidates.insert(0, key);
                }
            }
        }

        // OWN-LINEAGE EXTENSION FIRST. The height-presence hint above LIES under
        // multi-lineage forks: a stranded miner cohort fills EVERY height of the scan
        // window with its own (unadoptable) blocks, so `first_gap` is never found and
        // the hint crowns THEIR far-ahead tip — while the block that actually extends
        // the canonical chain (a live miner's fresh POST that chains onto our tip)
        // waits behind 8 doomed candidates and the beacon freezes (2026-07-09 stall).
        // Walk the child links FROM OUR OWN TIP HASH through the fetched window; the
        // deepest descendants of the block we hold are the one set of candidates that
        // can extend the beacon without any reorg at all, so they are tried first.
        // Pure prioritization: same validated converge path decides, and a heavier
        // adoptable fork still wins the engine's work-choice when its turn comes.
        if let Some(local_hash) = local_hash {
            let mut children: HashMap<[u8; 32], Vec<(u32, [u8; 32])>> = HashMap::new();
            for b in &blocks {
                children
                    .entry(b.previous_hash)
                    .or_default()
                    .push((b.index, b.hash));
            }
            let mut frontier = vec![local_hash];
            let mut deepest: Vec<(u32, [u8; 32])> = Vec::new();
            for _ in 0..512 {
                let mut next = Vec::new();
                for h in &frontier {
                    if let Some(kids) = children.get(h) {
                        for &(kh, khash) in kids {
                            next.push((kh, khash));
                        }
                    }
                }
                if next.is_empty() {
                    break;
                }
                deepest = next.clone();
                frontier = next.into_iter().map(|(_, h)| h).collect();
            }
            deepest.sort_by(|a, b| a.1.cmp(&b.1));
            for key in deepest.into_iter().rev() {
                candidates.retain(|c| *c != key);
                candidates.insert(0, key);
            }
        }

        let mut last = Converge::BeaconStale;
        let mut tried = 0usize;
        let mut all_needs_bootstrap = true;
        // Hard wall-clock budget for the WHOLE candidate pass. A single candidate's
        // converge can fan out into many relay window walks; before this bound, a
        // handful of deep foreign lineages made one "1s tick" take minutes — which WAS
        // the site's LAST-BLOCK-6m-ago stall, no lock wedge required. Cancelling is
        // state-safe (branch adoption is atomic; partial walk state is re-derived) and
        // the forward-drain fallback below still runs, so a budget hit degrades into
        // "advance what chains, try the rest next tick" instead of a frozen beacon.
        const CANDIDATE_PASS_BUDGET: Duration = Duration::from_secs(20);
        const PER_CANDIDATE_TIMEOUT: Duration = Duration::from_secs(12);
        let pass_start = Instant::now();
        for (height, hash) in candidates {
            if tried >= MAX_TIP_CANDIDATES || pass_start.elapsed() >= CANDIDATE_PASS_BUDGET {
                break;
            }
            if height == local_tip && Some(hash) == local_hash {
                // Our own tip: nothing above us that converged — we are as caught up
                // as the relay allows this tick.
                return if tried == 0 {
                    Converge::Converged
                } else {
                    last
                };
            }
            {
                let mut dead = self.relay_dead_targets.lock();
                if let Some(&(when, lineage_dead)) = dead.get(&(height, hash)) {
                    let retry_secs = if lineage_dead {
                        DEAD_TARGET_RETRY_SECS
                    } else {
                        SOFT_TARGET_RETRY_SECS
                    };
                    if when.elapsed() < Duration::from_secs(retry_secs) {
                        continue;
                    }
                    dead.pop(&(height, hash));
                }
                if ancestry_dead(hash, &mut dead) {
                    // Inherit HARD deadness: this tip extends an invalid branch.
                    dead.put((height, hash), (Instant::now(), true));
                    continue;
                }
            }
            tried += 1;
            let target = TipBeaconInfo {
                height,
                hash,
                version: 0,
            };
            let outcome =
                match timeout(PER_CANDIDATE_TIMEOUT, self.converge_to_canonical(&target)).await {
                    Ok(outcome) => outcome,
                    // Ran out its slice (deep walk / slow relay): treat as a transient gap.
                    // Soft-memoized below so the next tick tries a DIFFERENT branch first
                    // instead of re-sinking the budget into the same slow walk.
                    Err(_) => Converge::BeaconStale,
                };
            match outcome {
                done @ (Converge::Converged | Converge::AtTipAhead | Converge::Progressed) => {
                    return done;
                }
                failed @ (Converge::BeaconStale
                | Converge::NeedsBootstrap
                | Converge::BranchInvalid) => {
                    if !matches!(failed, Converge::NeedsBootstrap) {
                        all_needs_bootstrap = false;
                    }
                    // Lineage-dead (propagates to children via ancestry_dead): a branch
                    // that fails validation OR whose fork point is below the finality
                    // window damns every future tip minted on it. Gap verdicts stay soft.
                    let lineage_dead =
                        matches!(failed, Converge::BranchInvalid | Converge::NeedsBootstrap);
                    self.relay_dead_targets
                        .lock()
                        .put((height, hash), (Instant::now(), lineage_dead));
                    debug!(
                        "Relay tip candidate {}@{} unconvergeable ({:?}); trying next branch",
                        height,
                        hex::encode(hash),
                        failed
                    );
                    last = failed;
                }
            }
        }
        // FORWARD-DRAIN FALLBACK. Every tip candidate failed to converge — which,
        // with a genuine relay hole somewhere above us (a block that was never
        // successfully posted), means NO tip's prev-hash ancestry is walkable back
        // to our tip. But the relay is still CONTIGUOUS from our tip up to that first
        // hole, and those blocks chain cleanly onto what we hold. Greedily apply that
        // hole-free prefix so the publisher (and the beacon, and every bootstrapping
        // node) advances to the hole instead of freezing far below it while miners
        // race ahead peer-to-peer (the 2026-07-08 evening stall: frozen at 2198 with
        // the relay head at 2434 over a hole at 2246). sync_with_block_relay applies
        // strictly-chaining blocks from local_tip forward and stops at the first gap;
        // it re-runs every tick, so as the hole is later backfilled the drain resumes.
        // Runs even when tried == 0: once the dead-target memo has absorbed every
        // foreign tip, a tick can skip ALL candidates — but a fresh block that chains
        // onto our tip must still be applied or the beacon freezes with a warm memo
        // (the drain is cheap: one windowed fetch, applies only strictly-chaining
        // blocks, stops at the first gap).
        if !matches!(last, Converge::Converged | Converge::AtTipAhead) {
            let before = {
                let bc = self.blockchain.read().await;
                bc.get_latest_block_index() as u32
            };
            let _ = self.sync_with_block_relay(before).await;
            let after = {
                let bc = self.blockchain.read().await;
                bc.get_latest_block_index() as u32
            };
            if after > before {
                info!(
                    "Publisher forward-drained relay prefix {} -> {} (stopped at a relay gap)",
                    before, after
                );
                return Converge::Progressed;
            }
        }

        // Escalation semantics (M2, publisher exit->re-bootstrap) are preserved but
        // STRICTER: only report NeedsBootstrap when every tried candidate needed it
        // (genuine deep divergence). A mix that includes a mere relay gap reports
        // BeaconStale (retry) so one broken fork can never drive the 2-strike exit.
        if tried > 0 && all_needs_bootstrap && matches!(last, Converge::NeedsBootstrap) {
            return Converge::NeedsBootstrap;
        }
        if matches!(last, Converge::NeedsBootstrap | Converge::BranchInvalid) {
            // Normalize for the caller: retry next tick. BranchInvalid is terminal
            // only for the tried branch (memoized above), not for the network.
            return Converge::BeaconStale;
        }
        last
    }

    /// Fetch ONE relay block by exact (height, hash) via GET /api/block. Used by the
    /// ancestor/reorg walk when the fork-capped windowed list omits the specific
    /// parent it needs. Returns Transient on any unreachable/rate-limited/decode
    /// failure (walk retries on the soft tier); Missing only when a reachable base
    /// cleanly answers WITHOUT the asked block (walk treats that as a real gap).
    /// Blocks are immutable so this is edge-cached.
    async fn fetch_relay_block_exact(&self, height: u32, hash: [u8; 32]) -> ExactFetch {
        let network_id = hex::encode(self.network_id);
        // A definitive negative requires at least one base to answer cleanly (2xx,
        // decodable) yet without the block. Send errors, non-2xx (429/5xx, and 404
        // = "not posted yet", which the gateway itself never caches, e51c878) and
        // decode errors are transient and must never be laundered into a gap.
        let mut definitive_miss = false;
        for base in Self::discovery_bases() {
            let url = format!(
                "{}/api/block?network_id={}&height={}&hash={}",
                base,
                network_id,
                height,
                hex::encode(hash)
            );
            let res = match self.http_client.get(&url).send().await {
                Ok(r) => r,
                Err(_) => continue, // transient: base unreachable
            };
            if !res.status().is_success() {
                continue; // transient: 429 / 5xx / 404-not-posted-yet
            }
            let body = match res.json::<serde_json::Value>().await {
                Ok(b) => b,
                Err(_) => continue, // transient: body decode failure
            };
            // From here the base is reachable and answered cleanly; any negative is definitive.
            if !body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                definitive_miss = true;
                continue;
            }
            let Some(record) = body.get("block") else {
                definitive_miss = true;
                continue;
            };
            // The relay wraps the node Block in an ENVELOPE record ({height, hash,
            // node_id, ..., block: <Block>}) — the same shape as /api/blocks entries.
            // This used to parse the envelope itself as a Block, which always failed
            // (silently), so the exact-lookup fallback below the fork-capped window
            // NEVER worked: every fork-loser walked into a phantom gap, reported
            // BeaconStale forever, and kept mining its own stale tip (2026-07-09
            // rotating-stall incident). Unwrap the inner Block like the windowed path.
            let Some(block_val) = record.get("block") else {
                debug!(
                    "exact-block fetch #{}: response record missing inner block field",
                    height
                );
                definitive_miss = true;
                continue;
            };
            if let Ok(block) = serde_json::from_value::<Block>(block_val.clone()) {
                // Trust nothing: the block must match the exact (height, hash) asked
                // for and carry valid PoW. Everything else is still enforced on adopt.
                if block.index == height
                    && block.hash == hash
                    && block.calculate_hash_for_block() == hash
                    && block.verify_pow_meets_floor()
                {
                    return ExactFetch::Found(block);
                }
                debug!(
                    "exact-block fetch #{}: parsed block failed (height/hash/pow) check",
                    height
                );
                definitive_miss = true;
            } else {
                debug!(
                    "exact-block fetch #{}: inner block failed to deserialize",
                    height
                );
                definitive_miss = true;
            }
        }
        if definitive_miss {
            ExactFetch::Missing
        } else {
            ExactFetch::Transient
        }
    }

    /// Fetch the gateway's relay-head hint: the {height, hash} of the newest block
    /// POST the relay ACCEPTED. Served purge-on-write from the CDN so it is fresh
    /// within ~1s of a block landing. Returns None when the endpoint is missing
    /// (older gateway), unreachable, or answers for a different network — callers
    /// treat None as "use the legacy probe", never as an error.
    async fn fetch_relay_head(&self) -> Option<RelayHeadInfo> {
        for base in Self::discovery_bases() {
            let url = format!("{}/api/blocks/head", base);
            let Ok(res) = self.http_client.get(&url).send().await else {
                continue;
            };
            if !res.status().is_success() {
                continue;
            }
            let Ok(body) = res.json::<serde_json::Value>().await else {
                continue;
            };
            if !body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                continue;
            }
            let same_network = body
                .get("network_id")
                .and_then(|v| v.as_str())
                .map(|nid| nid.eq_ignore_ascii_case(&hex::encode(self.network_id)))
                .unwrap_or(false);
            if !same_network {
                continue;
            }
            let Some(height) = body.get("height").and_then(|v| v.as_u64()) else {
                continue;
            };
            let hash = body
                .get("hash")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok())?;
            return Some(RelayHeadInfo {
                height: height as u32,
                hash,
            });
        }
        None
    }

    async fn post_stats_snapshot(&self) -> Result<(), NodeError> {
        if !Self::public_stats_snapshots_enabled() {
            debug!("Skipping public stats snapshot because it is disabled by environment");
            return Ok(());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if !Self::should_publish_now(
            &self.last_stats_snapshot_at,
            Self::stats_snapshot_interval_secs(),
            now,
        ) {
            return Ok(());
        }

        let Some(public_tip) = self.public_advertisable_tip().await else {
            return Ok(());
        };
        let height = public_tip.index;
        let last_block_time = public_tip.timestamp;
        let difficulty = public_tip.difficulty;

        let hashrate_ths = {
            let blockchain = self.blockchain.read().await;
            blockchain.calculate_network_hashrate().await
        };
        let hashrate_ths_str = format!("{:.6}", hashrate_ths);
        let network_id = hex::encode(self.network_id);

        let peers = self.peers.read().await.len() as u32;
        let uptime_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.start_time);

        let message = json!({
            "node_id": &self.node_id,
            "public_key": &self.node_id,
            "network_id": &network_id,
            "height": height,
            "difficulty": difficulty,
            "hashrate_ths": hashrate_ths_str,
            "last_block_time": last_block_time,
            "peers": peers,
            "version": format!("rust-{}", NETWORK_VERSION),
            "uptime_secs": uptime_secs
        });

        let canonical = Self::canonical_json_string(&message)?;
        let keypair = Ed25519KeyPair::from_pkcs8(&self.handshake_key_bytes)
            .map_err(|_| NodeError::Network("Invalid handshake key bytes".into()))?;
        let signature = keypair.sign(canonical.as_bytes());

        let payload = json!({
            "node_id": &self.node_id,
            "public_key": &self.node_id,
            "network_id": &network_id,
            "height": height,
            "difficulty": difficulty,
            "hashrate_ths": hashrate_ths_str,
            "last_block_time": last_block_time,
            "peers": peers,
            "version": format!("rust-{}", NETWORK_VERSION),
            "uptime_secs": uptime_secs,
            "signature": hex::encode(signature.as_ref())
        });

        let mut any_ok = false;
        for base in Self::discovery_bases() {
            let url = format!("{}/api/stats", base);
            let res = self.http_client.post(url).json(&payload).send().await;
            match res {
                Ok(res) if res.status().is_success() => any_ok = true,
                Ok(res) => {
                    let status = res.status();
                    let body = res.text().await.unwrap_or_default();
                    warn!(
                        "Stats snapshot post failed: {} {}",
                        status,
                        Self::response_body_snippet(&body)
                    );
                }
                Err(e) => warn!("Stats snapshot error: {}", e),
            }
        }

        if !any_ok {
            warn!("Stats snapshot post failed on all endpoints");
        }

        Ok(())
    }

    async fn post_block_relay(&self, block: &Block) -> Result<(), NodeError> {
        if !Self::block_relay_publish_enabled() {
            debug!("Skipping public block relay because it is disabled by environment");
            return Ok(());
        }

        // Rehydrate full ML-DSA witnesses so relay-only nodes can verify
        // signatures instead of receipt-trusting the tip. This changes only the
        // (unhashed) signature bytes; the header, hash and merkle_root are
        // unchanged, so PoW and the POST signature remain valid.
        let hydrated = self
            .blockchain
            .read()
            .await
            .block_with_full_witnesses(block);

        // POISON GUARD (2026-07-27). Rehydration is best-effort: it pulls each full
        // signature from the confirmed-witness store, which only retains
        // WITNESS_RETENTION_BLOCKS. Past that window — or for a body this node
        // never held witnesses for — it silently returns a witness-SHORT block, and
        // publishing that POISONS the height: the relay is first-write-wins, so
        // every node that later has to validate that block at its own frontier
        // requires full witnesses, cannot get them from any peer, and WEDGES until
        // a snapshot laps it. Measured live: two independent nodes (one on the
        // previous release, ruling out a build regression) sat stuck ~85 minutes at
        // block 290968, whose relay record carried 2 truncated signatures.
        //
        // A GAP is strictly better than poison: the snapshot and P2P GetBlocks both
        // serve that history, the 32-block backfill re-posts continuously, and the
        // gateway's witness-upgrade path repairs a short slot the moment ANY node
        // that does hold the witnesses posts the same block. Skipping here is what
        // lets that repair win instead of a truncated body squatting the slot.
        if !Blockchain::block_witnesses_are_complete(&hydrated) {
            warn!(
                "Not publishing block {} to the relay: {} transaction witness(es) could not be rehydrated (older than the {}-block retention window). Leaving the slot for a node that holds them — a gap is recoverable, a witness-short record wedges fresh nodes.",
                block.index,
                // Count the witnesses that actually FAILED, not every non-system tx.
                // Reporting the whole set made a 2-tx retention edge look like total
                // witness-store loss to whoever read the log.
                hydrated
                    .transactions
                    .iter()
                    .filter(|tx| {
                        !SYSTEM_ADDRESSES.contains(&tx.sender.as_str())
                            && tx
                                .signature
                                .as_deref()
                                .and_then(|s| hex::decode(s).ok())
                                .map(|b| b.len() <= 64)
                                .unwrap_or(true)
                    })
                    .count(),
                crate::a9::blockchain::WITNESS_RETENTION_BLOCKS
            );
            return Ok(());
        }
        let block_value = serde_json::to_value(&hydrated)
            .map_err(|e| NodeError::Serialization(format!("Block relay JSON error: {}", e)))?;
        let network_id = hex::encode(self.network_id);
        let hash = hex::encode(block.hash);
        let previous_hash = hex::encode(block.previous_hash);
        let message = json!({
            "network_id": network_id,
            "height": block.index,
            "hash": hash,
            "previous_hash": previous_hash,
            "timestamp": block.timestamp,
            "difficulty": block.difficulty,
            "node_id": &self.node_id,
            "public_key": &self.node_id
        });

        let canonical = Self::canonical_json_string(&message)?;
        let signature = self.sign_with_handshake_key(canonical.as_bytes())?;
        let mut payload = message.clone();
        if let Value::Object(map) = &mut payload {
            map.insert("block".to_string(), block_value);
            map.insert(
                "signature".to_string(),
                json!(hex::encode(signature.as_slice())),
            );
        }

        let mut any_ok = false;
        let mut rate_limited = false;
        let mut transient = false;
        for url in Self::discovery_blocks_urls() {
            let res = self.http_client.post(url).json(&payload).send().await;
            match res {
                Ok(res) if res.status().is_success() => any_ok = true,
                Ok(res) => {
                    let status = res.status();
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        rate_limited = true;
                    } else if Self::relay_post_status_is_transient(status) {
                        transient = true;
                    }
                    let body = res.text().await.unwrap_or_default();
                    warn!(
                        "Block relay post failed: {} {}",
                        status,
                        Self::response_body_snippet(&body)
                    );
                }
                Err(e) => {
                    // Connect/TLS/timeout errors never reached a relay verdict;
                    // they are transient by construction.
                    transient = true;
                    warn!("Block relay post error: {}", e);
                }
            }
        }

        if !any_ok {
            warn!("Block relay post failed on all endpoints");
            // Distinguish rate-limiting so callers can BACK OFF instead of amplifying:
            // the old uniform error made publish_block answer every failed POST with a
            // 32-block backfill — under a 429 that backfill is 32 MORE posts into the
            // same closed window, which is how one burst snowballed into 2,409 failed
            // posts during the 2026-07-08 recovery storms.
            return Self::fold_relay_post_outcomes(any_ok, rate_limited, transient);
        }

        self.mark_block_relayed(block).await;
        Ok(())
    }

    /// One-retry worthiness of a failed relay POST status. 429 is deliberately NOT
    /// here — rate limiting has its own marker and a longer backoff. 408 and every
    /// 5xx are momentary server/edge conditions worth one more attempt; the
    /// remaining 4xx are the relay's permanent verdict on this exact request.
    fn relay_post_status_is_transient(status: reqwest::StatusCode) -> bool {
        status == reqwest::StatusCode::REQUEST_TIMEOUT || status.is_server_error()
    }

    /// Fold one relay POST round (across every configured endpoint) into the
    /// documented error contract. Rate limiting outranks transient: a 429 anywhere
    /// means the per-IP window is closed, and retrying before it rolls over is fuel
    /// on the fire regardless of what the other endpoints answered.
    fn fold_relay_post_outcomes(
        any_ok: bool,
        rate_limited: bool,
        transient: bool,
    ) -> Result<(), NodeError> {
        if any_ok {
            return Ok(());
        }
        if rate_limited {
            return Err(NodeError::Network(RELAY_POST_RATE_LIMITED.into()));
        }
        if transient {
            return Err(NodeError::Network(RELAY_POST_TRANSIENT.into()));
        }
        Err(NodeError::Network(
            "Block relay post failed on all endpoints".into(),
        ))
    }

    /// Whether — and after how long — a failed fresh-block relay POST gets its ONE
    /// detached retry. A fresh block is the post that matters most for propagation
    /// (relay-dependent nodes fork against it until it lands), and before this the
    /// non-429 failure path had NO second attempt: the next heal was the periodic
    /// relay-tip refresh, up to an announce interval (~300s) away — observed on a
    /// TCP-less client as falling multiple blocks behind and catching up in
    /// multi-height jumps. Rate-limited waits out the per-IP window; a transient
    /// blip gets a prompt second try (the client timeout is 3s, so the blip has had
    /// that long to clear). Permanent rejections return None: the same request
    /// would meet the same verdict. ONE retry only, decided here and consulted
    /// nowhere else — the retry's own failure is terminal until the periodic heal,
    /// which is what keeps a hard relay outage from turning every mined block into
    /// a post storm (the 2026-07-08 lesson).
    fn relay_post_retry_delay(error: &NodeError) -> Option<Duration> {
        let text = error.to_string();
        if text.contains(RELAY_POST_RATE_LIMITED) {
            return Some(Duration::from_secs(10));
        }
        if text.contains(RELAY_POST_TRANSIENT) {
            return Some(Duration::from_secs(3));
        }
        None
    }

    async fn post_recent_blocks_to_relay(&self, limit: u32) {
        if limit == 0 || !Self::block_relay_publish_enabled() {
            return;
        }
        // Never re-post deeper than the witness retention window. Beyond it the
        // confirmed-witness store has been pruned, so every one of those bodies
        // rehydrates SHORT — the publish path now declines them anyway (see the
        // poison guard in post_block_relay), and walking them is pure work plus
        // per-block warn spam. This matters because the startup "deep relay heal"
        // defaults to 512 and is configured to 1024 on the publisher, i.e. 2-4x
        // the retention window: before this clamp, the majority of that sweep
        // could only ever have produced unverifiable records.
        let limit = limit.min(crate::a9::blockchain::WITNESS_RETENTION_BLOCKS as u32);

        let blocks = {
            let blockchain = self.blockchain.read().await;
            let Some(tip) = blockchain.get_last_block() else {
                return;
            };
            let start = tip.index.saturating_sub(limit.saturating_sub(1));
            let mut blocks = Vec::new();
            for height in start..=tip.index {
                match blockchain.get_block(height) {
                    Ok(block) => blocks.push(block),
                    Err(e) => debug!("Recent relay block {} unavailable: {}", height, e),
                }
            }
            blocks
        };

        let mut consecutive_failures: u32 = 0;
        for block in blocks {
            match self.post_block_relay(&block).await {
                Ok(()) => consecutive_failures = 0,
                Err(e) => {
                    // A rate-limited POST means the per-IP window is CLOSED: every further
                    // post in this run is guaranteed fuel on the fire (this loop runs after
                    // EVERY mined block at backfill=32, and at startup with deep-heal depths
                    // of 512-1024 — the 2,409-failure storms of 2026-07-08). Abort the run;
                    // the next mined block / heal tick retries against a fresh window.
                    if e.to_string().contains(RELAY_POST_RATE_LIMITED) {
                        warn!(
                            "Relay backfill rate-limited at #{}; aborting this backfill run",
                            block.index
                        );
                        return;
                    }
                    debug!("Recent block relay failed for #{}: {}", block.index, e);
                    // Other failures used to only 429-abort, so a relay rejecting for
                    // any OTHER reason (403 edge/WAF misconfig, 5xx outage) let the run
                    // walk every remaining block — observed live 2026-07-10: a 403ing
                    // edge turned the 512-block boot heal into 514 rejected POSTs.
                    // Three consecutive failures is a state, not a blip; abort and let
                    // the next tick retry against (hopefully) a healed relay. A single
                    // bad block or transient hiccup doesn't trip this (counter resets
                    // on success), so deep heals still make progress past stragglers.
                    consecutive_failures += 1;
                    if consecutive_failures >= 3 {
                        warn!(
                            "Relay backfill failing repeatedly (last: #{}); aborting this backfill run",
                            block.index
                        );
                        return;
                    }
                }
            }
            // Pace the burst: ~10 posts/s keeps even a 1024-deep heal well under the
            // gateway's per-IP POST budget, leaving headroom for the fresh mined-block
            // posts that actually advance the network.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn fetch_relay_blocks(&self, start: u32, end: u32) -> Result<Vec<Block>, NodeError> {
        if !Self::block_relay_sync_enabled() {
            return Err(NodeError::Network("Block relay sync disabled".into()));
        }
        if end < start {
            return Ok(Vec::new());
        }

        let network_id = hex::encode(self.network_id);
        let limit = end
            .saturating_sub(start)
            .saturating_add(1)
            .saturating_mul(4)
            .clamp(1, 200);
        // Caps against a HOSTILE relay that paginates forever with distinct floor-difficulty
        // blocks (the seen_pages dedup only breaks on an exact page REPEAT). Honest callers
        // request <=64-height windows (<=2 pages at limit 200), so these never bite legit sync.
        const MAX_RELAY_PAGES: u32 = 16;
        const MAX_RELAY_BLOCKS: usize = 4096;
        let mut all_blocks = Vec::new();
        let mut any_ok = false;
        let mut seen_blocks: HashSet<(u32, [u8; 32])> = HashSet::new();

        for base_url in Self::discovery_blocks_urls() {
            let mut offset: u32 = 0;
            let mut pages: u32 = 0;
            let mut seen_pages: HashSet<Vec<(u32, [u8; 32])>> = HashSet::new();
            loop {
                let url = format!(
                    "{}?network_id={}&start={}&end={}&limit={}&offset={}",
                    base_url, network_id, start, end, limit, offset
                );
                debug!("relay GET {}", url);
                let res = self.http_client.get(url).send().await;
                let res = match res {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("Block relay fetch error: {}", e);
                        break;
                    }
                };

                if !res.status().is_success() {
                    let status = res.status();
                    let body = res.text().await.unwrap_or_default();
                    debug!(
                        "Block relay fetch failed: {} {}",
                        status,
                        Self::response_body_snippet(&body)
                    );
                    break;
                }

                let body = match res.json::<BlockRelayResponse>().await {
                    Ok(body) => body,
                    Err(e) => {
                        debug!("Block relay response parse failed: {}", e);
                        break;
                    }
                };

                if !body.ok {
                    break;
                }
                any_ok = true;

                let records = body.blocks.unwrap_or_default();
                let record_count = records.len() as u32;
                debug!("relay response ok={} records={}", body.ok, record_count);
                let mut page_keys = Vec::with_capacity(records.len());
                for record in records {
                    match serde_json::from_value::<Block>(record.block) {
                        Ok(block) => {
                            let range_ok = block.index >= start && block.index <= end;
                            let hash_ok = block.calculate_hash_for_block() == block.hash;
                            let pow_ok = block.verify_pow_meets_floor();
                            debug!(
                                "relay fetch block #{}: range_ok={} hash_ok={} pow_ok={}",
                                block.index, range_ok, hash_ok, pow_ok
                            );
                            page_keys.push((block.index, block.hash));
                            if range_ok
                                && hash_ok
                                && pow_ok
                                && seen_blocks.insert((block.index, block.hash))
                            {
                                all_blocks.push(block);
                            }
                        }
                        Err(e) => debug!("Relayed block decode failed: {}", e),
                    }
                }

                if !seen_pages.insert(page_keys) {
                    break;
                }
                if record_count < limit {
                    break;
                }
                offset = offset.saturating_add(record_count);
                pages = pages.saturating_add(1);
                if pages >= MAX_RELAY_PAGES || all_blocks.len() >= MAX_RELAY_BLOCKS {
                    break;
                }
            }
        }

        if !any_ok {
            return Err(NodeError::Network("Block relay fetch failed".into()));
        }

        all_blocks.sort_by(|a, b| {
            a.index
                .cmp(&b.index)
                .then_with(|| a.timestamp.cmp(&b.timestamp))
                .then_with(|| a.hash.cmp(&b.hash))
        });
        all_blocks.dedup_by(|a, b| a.index == b.index && a.hash == b.hash);
        Ok(all_blocks)
    }

    async fn sync_with_block_relay(&self, current_height: u32) -> Result<usize, NodeError> {
        if !Self::block_relay_sync_enabled() {
            return Err(NodeError::Network("Block relay sync disabled".into()));
        }

        const RELAY_BATCH_SIZE: u32 = 64;

        let backfill_depth = Self::relay_sync_backfill_depth();
        let max_rounds = Self::relay_sync_max_rounds();
        let mut cursor = if backfill_depth > 0 {
            current_height.saturating_sub(backfill_depth)
        } else {
            current_height.saturating_add(1)
        };
        let mut total_saved = 0usize;
        let mut accepted_any = false;

        for _ in 0..max_rounds {
            // 64-align the window (same grid as the ancestor walk): aligned ranges
            // mean every node issues IDENTICAL relay URLs and the CDN coalesces N
            // nodes' scans into one origin read per window; per-node unaligned
            // starts defeated the cache entirely. Blocks below our tip inside the
            // widened window are already-stored no-ops.
            let start = cursor - (cursor % RELAY_BATCH_SIZE);
            let end = start.saturating_add(RELAY_BATCH_SIZE.saturating_sub(1));
            let blocks = self.fetch_relay_blocks(start, end).await?;
            if blocks.is_empty() {
                if start <= current_height {
                    cursor = end.saturating_add(1);
                    continue;
                }
                break;
            }

            let before_batch = {
                let blockchain = self.blockchain.read().await;
                blockchain.get_latest_block_index() as u32
            };
            let mut relay_confirmed_blocks = Vec::new();

            // LINEAGE-SURVIVING ORDER (v7.6.5, 2026-07-08 night): under same-height
            // racing every height holds several forks and the engine appends whichever
            // chaining block it meets FIRST — appending a CHILDLESS dead fork strands
            // the drain one block later ("stopped at a relay gap" on a fully
            // contiguous relay; the publisher crawled at ~2 blocks per 10 minutes
            // while five miners raced). Per height, try the blocks some LATER wire
            // block builds on first: a child-witnessed block provably has a
            // continuation, so the drain stays on a lineage that survives.
            let child_witnessed: std::collections::HashSet<[u8; 32]> =
                blocks.iter().map(|b| b.previous_hash).collect();
            let mut blocks = blocks;
            blocks.sort_by(|a, b| {
                a.index
                    .cmp(&b.index)
                    .then_with(|| {
                        child_witnessed
                            .contains(&b.hash)
                            .cmp(&child_witnessed.contains(&a.hash))
                    })
                    .then_with(|| a.hash.cmp(&b.hash))
            });

            // One dirty window per relay round (≤64 blocks): amortizes the
            // per-block fsyncs. Non-fatal if unavailable.
            let batch = {
                let bc = self.blockchain.read().await;
                bc.begin_receipt_batch()
                    .await
                    .map_err(|e| {
                        warn!(
                            "relay sync: apply window unavailable, using per-block durability: {}",
                            e
                        )
                    })
                    .ok()
            };
            for block in blocks {
                // Checkpoint-anchored verification (S-01). Blocks ABOVE the trusted
                // checkpoint are the unfinalized frontier: a relay-only node cannot
                // receipt-trust the tip, so they MUST carry full, valid ML-DSA
                // witnesses — post_block_relay rehydrates them from the miner — or we
                // decline them. Blocks at/below the checkpoint were vouched for by a
                // verified signed snapshot and are receipt-trusted, which is what lets
                // catch-up over witness-pruned history proceed.
                // Snapshot the floor per block WITHOUT a second guard acquisition
                // (it can advance mid-batch via the checkpoint trail below; a
                // stale-low read only demands MORE verification, never less).
                let (floor, sigs_ok) = {
                    let bc = self.blockchain.read().await;
                    let floor = bc.verification_floor();
                    let sigs_ok = block.index <= floor
                        || bc.block_signatures_fully_verified(&block);
                    (floor, sigs_ok)
                };
                if !sigs_ok {
                    warn!(
                        "Rejected relayed frontier block {} (> floor {}): signatures not fully verifiable",
                        block.index, floor
                    );
                    continue;
                }
                let save_result = {
                    let blockchain = self.blockchain.write().await;
                    let before = blockchain.get_latest_block_index() as u32;
                    // Reduce the error to a String immediately: BlockchainError is
                    // !Send, and this tuple is held across the checkpoint-advance
                    // await below, which would make the spawned sync future !Send.
                    let result = blockchain
                        .save_receipt_verified_block(&block)
                        .await
                        .map_err(|e| e.to_string());
                    let after = blockchain.get_latest_block_index() as u32;
                    (result, before, after)
                };

                match save_result {
                    (Ok(()), before, after) => {
                        // The relay marker only needs (index, hash) — cloning the
                        // whole block (every tx + signature) here was pure waste.
                        relay_confirmed_blocks.push((block.index, block.hash));
                        accepted_any = true;
                        if after > before {
                            total_saved += after.saturating_sub(before) as usize;
                            if block.index > floor {
                                // Frontier block passed full verification above; trail
                                // the checkpoint behind it so finality advances and the
                                // verified window stays bounded.
                                let _ = self
                                    .blockchain
                                    .read()
                                    .await
                                    .advance_checkpoint_behind(block.index);
                            }
                        }
                    }
                    (Err(e), _, _) => warn!("Failed to save relayed block {}: {}", block.index, e),
                }
            }
            if let Some(batch) = batch {
                if let Err(e) = {
                    let bc = self.blockchain.read().await;
                    bc.commit_receipt_batch(batch).await
                } {
                    warn!(
                        "relay sync: apply window commit failed; dirty marker left for recovery: {}",
                        e
                    );
                }
            }

            let after_batch = {
                let blockchain = self.blockchain.read().await;
                blockchain.get_latest_block_index() as u32
            };
            for (index, hash) in relay_confirmed_blocks {
                self.mark_block_relayed_key(index, hash).await;
            }
            if after_batch > end {
                cursor = after_batch.saturating_add(1);
            } else {
                cursor = end.saturating_add(1);
            }

            if after_batch == before_batch && start > current_height {
                break;
            }
        }

        if total_saved > 0 {
            info!(
                "Blockchain synchronized from block relay: added {} blocks to height {}",
                total_saved,
                {
                    let blockchain = self.blockchain.read().await;
                    blockchain.get_latest_block_index()
                }
            );
            self.publish_discovery_state("Post-relay-sync").await;
            Ok(total_saved)
        } else if accepted_any {
            Ok(0)
        } else {
            Err(NodeError::Network("No relayed blocks available".into()))
        }
    }

    async fn publish_discovery_state(&self, context: &str) {
        if let Err(e) = self.announce_to_discovery().await {
            debug!("{} discovery announce failed: {}", context, e);
        }
        if let Err(e) = self.post_header_snapshot().await {
            warn!("{} header snapshot failed: {}", context, e);
        }
        if let Err(e) = self.post_stats_snapshot().await {
            warn!("{} stats snapshot failed: {}", context, e);
        }
    }

    /// Fire-and-forget peer discovery for a mine command. Runs the same
    /// peers-empty probe + bounded discovery prepare_local_mining used to do
    /// INLINE — where its NAT'd dials burned up to ~3s before convergence even
    /// started. Convergence uses the relay, not p2p peers (and the post-mine
    /// flood runs its own discovery when the table is empty), so nothing waits
    /// on this. The peers-lock read stays time-boxed: a wedged peers lock
    /// elsewhere must degrade this into "skip discovery", never into a hang.
    pub fn spawn_prep_discovery(self: Arc<Self>) {
        tokio::spawn(async move {
            let peers_empty = match timeout(Duration::from_secs(2), async {
                self.peers.read().await.is_empty()
            })
            .await
            {
                Ok(empty) => empty,
                Err(_) => {
                    debug!("prep-discovery: peers lock busy; skipping");
                    false
                }
            };
            if peers_empty {
                let _ = timeout(Duration::from_secs(3), self.connect_discovery_peers(8)).await;
            }
        });
    }

    pub async fn prepare_local_mining(&self, max_wait: Duration) -> Result<(), NodeError> {
        debug!("mine-prep: enter");
        // Peer discovery is NOT done inline here anymore — the mine command
        // spawns spawn_prep_discovery once in the background instead, so the
        // whole max_wait budget goes to convergence.

        // ALWAYS CONVERGE, THEN COMPETE — never pause-and-concede.
        //
        // When behind or forked, actively converge to the signed-beacon canonical tip
        // and THEN mine on that fresh tip to compete for the next block. This is the
        // fix for the monopoly failure: a node that is behind used to just refuse to
        // mine ("mining paused until the node syncs") and sit it out, so whoever was
        // ahead kept winning and nobody could catch up. Now "behind" means "actively
        // syncing then racing", from ANY state (behind, forked-at-tip, forked-and-
        // behind). The loop re-fetches the beacon each round so a block that lands
        // mid-prep is adopted and we re-target onto it before mining.
        //
        // BACKOFF POLICY: the doubling backoff applies ONLY to rounds that made no
        // forward progress (tip unchanged) — that is genuine relay distress, and
        // backing off is what keeps a run of failing rounds from hammering the
        // relay into the very non-convergence it is meant to cure. A round that
        // ADVANCED the tip resets the backoff to the floor instead: adopted blocks
        // are never re-POSTed and the window GETs are 64-aligned/CDN-coalesced, so
        // productive rounds cost the relay nothing extra — while doubling on
        // progress was punishing success with growing sleeps that let the live
        // tip (one block ~2s) outrun the catch-up. Keyed off the ACTUAL tip delta,
        // not the returned verdict: a mid-call transient can report BeaconStale
        // even after earlier rounds applied blocks.
        let deadline = Instant::now() + max_wait;
        let mut backoff = Duration::from_millis(500);
        let mut last_round_tip = self.blockchain.read().await.get_latest_block_index() as u32;
        loop {
            debug!("mine-prep: fetching beacon");
            let Some(beacon) = self.fetch_tip_beacon().await else {
                // Beacon genuinely unreachable => FAIL OPEN and mine on the local tip —
                // but ONLY within racing distance of the last beacon we DID see.
                // Staleness we already know about doesn't stop being true because the
                // beacon blinked: a far-behind node failing open here mined
                // guaranteed-orphan blocks hundreds below the network (2026-07-11).
                // Near the tip, producing on our best-known chain still beats conceding;
                // the reorg engine resolves any fork when connectivity returns.
                let local_tip = self.blockchain.read().await.get_latest_block_index() as u32;
                // Beacon UNREACHABLE: use the FOREVER-MONOTONIC high-water, not the
                // rolling window. With no fresh read to confirm a regression, the
                // rolling window would age out to 0 during a >10min outage and let a
                // far-behind node fail-open into mining orphans (2026-07-12 review).
                let last_seen = self.last_seen_beacon_height.load(Ordering::Acquire) as u32;
                if last_seen
                    > local_tip.saturating_add(crate::a9::blockchain::CHECKPOINT_REORG_MARGIN)
                {
                    return Err(NodeError::Retryable(format!(
                        "tip beacon unreachable and the last known network tip {} is {} blocks ahead of local {}; refusing to mine a stale chain",
                        last_seen,
                        last_seen.saturating_sub(local_tip),
                        local_tip
                    )));
                }
                warn!("Tip beacon unreachable; mining on local tip (fail-open)");
                return Ok(());
            };
            debug!(
                "mine-prep: beacon h{} v{}; converge round",
                beacon.height, beacon.version
            );
            // Backstop timeout per round: the deadline is only checked BETWEEN rounds,
            // and one converge round can fan out into many relay window fetches (each
            // individually HTTP-bounded but unbounded in count on a deeply forked
            // relay) — the rare "mine hangs for a minute with zero output" stall.
            // Cancelling here is state-safe: adoption is atomic (apply_batch) and any
            // partially staged sync work is re-derived on the next round.
            // The per-round cap also respects the CALLER's remaining budget (floored
            // at 2s so a round can still do useful work): a flat 20s here let one
            // last round overshoot max_wait by ~2x — the caller's declared budget
            // was soft. Bounded worst case is now budget + ~5s, not budget + ~23s.
            let round_cap = deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_secs(2))
                .min(Duration::from_secs(20));
            let round = match timeout(round_cap, self.converge_to_canonical(&beacon)).await {
                Ok(outcome) => outcome,
                Err(_) => {
                    warn!("Converge round timed out; retrying against a fresh beacon");
                    Converge::BeaconStale
                }
            };
            match round {
                // At the canonical tip, or holding an equal/heavier chain: go COMPETE.
                Converge::Converged | Converge::AtTipAhead => {
                    // GHOST-BLOCK GUARD (2026-07-11): converge reports Converged when the
                    // local chain holds the block at the beacon height it fetched — but a
                    // single beacon read can come back STALE (equal to our own tip) while
                    // the network has already moved on, and when the relay can't serve the
                    // gap the node then mines its stale tip + 1: a guaranteed orphan, with
                    // the operator watching "Block #N" tick up on a chain that's already
                    // behind (observed live: node at 41370 mining #41371 while the network
                    // was at 41395). Cross-check the freshest network height we have EVER
                    // seen (monotonic high-water of every beacon read, node.rs fetch_max):
                    // if we KNOW the network reached a height meaningfully above ours, we
                    // are behind no matter what this one fetch said — refuse and retry
                    // rather than mint a ghost block. Same +2 racing tolerance the
                    // BeaconStale arm uses (a genuine same/next-height race still mines).
                    // Retryable (not a hard error): the caller re-invokes and we mine the
                    // instant we legitimately reach the tip. Refusing is the safe failure —
                    // worse case a miner idles briefly; the alternative is orphan spam.
                    let local_tip = self.blockchain.read().await.get_latest_block_index() as u32;
                    let known_tip = self.beacon_high_water_height();
                    if Self::stale_tip_mine_refused(local_tip, known_tip) {
                        return Err(NodeError::Retryable(format!(
                            "network has reached {} but we are at {} ({} behind) and cannot fetch the gap yet; not mining a stale tip",
                            known_tip,
                            local_tip,
                            known_tip.saturating_sub(local_tip)
                        )));
                    }
                    return Ok(());
                }
                // Diverged below the finality window — or (far more common) simply fallen
                // further behind than the converge engine's bounded forward append can
                // cross (> ORPHAN_REORG_DEPTH ≈ 1.4h of blocks: any machine that slept
                // through an evening). Incremental convergence cannot fix either, but a
                // RESTART is no longer the first answer: try the same bulk peer delta-sync
                // the idle reconcile loop uses (signed-beacon-anchored, tip-probed, every
                // block through normal ingest validation; includes a discovery kick for
                // the wake-from-sleep dead-socket case). A genuine fork cannot pass the
                // sync's ingest/linkage checks, so it falls through unhealed. Only when no
                // reachable peer could serve the missing span do we schedule the snapshot
                // re-bootstrap and stop — and then the "restart" advice is true
                // (2026-07-11: prep told a wedged operator to restart while the boot
                // check kept streaming-skipping — a perfect advice loop; that fix stays).
                Converge::NeedsBootstrap => {
                    let tip_before =
                        self.blockchain.read().await.get_latest_block_index() as u32;
                    // Slice the sync to the caller's budget, floored at 10s so a
                    // nearly-expired budget still gets one usable probe+stream window
                    // (bounded overshoot, same spirit as the round cap's 2s floor).
                    let slice = deadline.max(Instant::now() + Duration::from_secs(10));
                    let healed = self
                        .sync_full_history_from_peer_bounded(true, Some(slice))
                        .await;
                    let tip_after =
                        self.blockchain.read().await.get_latest_block_index() as u32;
                    match healed {
                        Converge::Converged | Converge::AtTipAhead => {
                            // Same ghost-block guard as the Converged arm: one stale
                            // beacon read must not let us mine below the freshest
                            // height the network is known to have reached.
                            let known_tip = self.beacon_high_water_height();
                            if Self::stale_tip_mine_refused(tip_after, known_tip) {
                                return Err(NodeError::Retryable(format!(
                                    "caught up to {} via a peer but the network has reached {}; not mining a stale tip",
                                    tip_after, known_tip
                                )));
                            }
                            info!(
                                "mine-prep: healed a {}-block deficit in place via peer delta-sync",
                                tip_after.saturating_sub(tip_before)
                            );
                            return Ok(());
                        }
                        // Real forward progress (slice expired mid-stream / peer went
                        // away mid-span): resume from the advanced tip, don't stop.
                        _ if tip_after > tip_before => {
                            if Instant::now() >= deadline {
                                return Err(NodeError::Retryable(format!(
                                    "recovered {} blocks from a peer and still catching up; retry",
                                    tip_after.saturating_sub(tip_before)
                                )));
                            }
                            backoff = Duration::from_millis(500);
                            last_round_tip = tip_after;
                        }
                        // Another loop's delta-sync already owns the stream
                        // (single-flight guard): the tip is being advanced for us —
                        // wait it out instead of hard-stopping.
                        Converge::Progressed => {
                            if Instant::now() >= deadline {
                                return Err(NodeError::Retryable(
                                    "a background peer sync is closing the gap; retry shortly".into(),
                                ));
                            }
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(5));
                            last_round_tip =
                                self.blockchain.read().await.get_latest_block_index() as u32;
                        }
                        // No peer could serve the span (none reachable, none passing
                        // the tip probe — includes the genuine-fork case, whose blocks
                        // cannot link onto our branch). Within budget keep retrying:
                        // prep-discovery / the wake recovery may land fresh peers any
                        // moment. At budget end the snapshot re-bootstrap is genuinely
                        // the only cure left.
                        _ => {
                            if Instant::now() < deadline {
                                tokio::time::sleep(backoff).await;
                                backoff = (backoff * 2).min(Duration::from_secs(5));
                                continue;
                            }
                            // BEHIND is not DIVERGED. A node that is simply far behind
                            // — the client someone reopens after hours away — reaches
                            // here whenever the gap cannot be closed inside one prep
                            // budget, e.g. peers have not finished connecting yet at
                            // startup. Reporting that as ConsensusFailure was wrong
                            // twice over: it HARD-STOPPED mining ("cannot mine right
                            // now") instead of waiting, and it dropped a
                            // force-rebootstrap marker that threw away a perfectly good
                            // local chain on the next launch. Retryable instead: the
                            // caller keeps waiting, the background converge/delta-sync
                            // keep pulling us forward, and mining starts by itself the
                            // moment we arrive. Only a SMALL-gap NeedsBootstrap is a
                            // genuine divergence worth the marker and the hard stop.
                            let local_tip =
                                self.blockchain.read().await.get_latest_block_index() as u32;
                            let behind = beacon.height.saturating_sub(local_tip);
                            if behind > crate::a9::blockchain::CHECKPOINT_REORG_MARGIN {
                                return Err(NodeError::Retryable(format!(
                                    "still catching up — {} blocks behind ({} of {}); mining starts automatically once the chain is current",
                                    behind, local_tip, beacon.height
                                )));
                            }
                            let scheduled = self.schedule_force_rebootstrap_hard(
                                "mine-prep: diverged below finality and no peer could serve the gap",
                            );
                            return Err(NodeError::ConsensusFailure(if scheduled {
                                "chain diverged below the finality window and no reachable peer could serve the missing history; a re-bootstrap is scheduled — restart this node to re-sync onto the canonical chain".into()
                            } else {
                                "chain diverged below the finality window; a re-bootstrap ran recently — the node keeps retrying in the background".into()
                            }));
                        }
                    }
                }
                // Made forward progress but not fully caught up: keep trying with backoff;
                // after the deadline hand back Retryable so the caller re-invokes (the
                // background loops keep pulling us forward between attempts).
                Converge::Progressed => {
                    if Instant::now() >= deadline {
                        return Err(NodeError::Retryable(
                            "still converging to the canonical tip; retry".into(),
                        ));
                    }
                    // Attribute progress to the ROUND, not the sleep: read the
                    // tip BEFORE sleeping (background/mesh ingest advancing the
                    // tip DURING the sleep must not launder a failing round into
                    // "productive" and pin the backoff at the floor against a
                    // distressed relay), decide the next backoff, sleep it, then
                    // re-baseline AFTER the sleep so sleep-time background
                    // progress isn't credited to the next round either.
                    let tip_after_round =
                        self.blockchain.read().await.get_latest_block_index() as u32;
                    backoff = if tip_after_round > last_round_tip {
                        Duration::from_millis(500)
                    } else {
                        (backoff * 2).min(Duration::from_secs(5))
                    };
                    tokio::time::sleep(backoff).await;
                    last_round_tip = self.blockchain.read().await.get_latest_block_index() as u32;
                }
                // Transient relay gap. A DEEP gap (history aged out) already escalated to
                // NeedsBootstrap above (M3), so this is a near-the-tip hiccup: after the
                // deadline, FAIL OPEN and mine on our local tip rather than sit out. We
                // are near the tip, so the local tip is almost certainly current; a losing
                // local block is reorged away by the normal path. This upholds the
                // "never dead-pause" contract even when the relay momentarily can't answer.
                //
                // EXCEPT when the signed beacon is far above us (v7.6.5, 2026-07-08): a
                // node stranded across a deep reorg kept "failing open" here and silently
                // mined orphans forever while printing normal mining output — the operator
                // had no idea their blocks were worthless. Beyond a stream window of
                // deficit, mining the local tip is never useful work: stop with an
                // explicit "restart to re-sync" instead (boot-time reconcile then pulls
                // the node onto the canonical chain).
                Converge::BeaconStale => {
                    if Instant::now() >= deadline {
                        let local_tip = {
                            let bc = self.blockchain.read().await;
                            bc.get_latest_block_index() as u32
                        };
                        if beacon.height > local_tip.saturating_add(64) {
                            // Before conceding to a restart, try the bulk peer
                            // delta-sync once (same heal as the NeedsBootstrap arm):
                            // a Transient-ancestor stall with a big gap usually means
                            // relay holes, and exact GetBlocks spans from a
                            // full-history peer bypass the relay entirely.
                            let slice = Instant::now() + Duration::from_secs(10);
                            let healed = self
                                .sync_full_history_from_peer_bounded(true, Some(slice))
                                .await;
                            let tip_now =
                                self.blockchain.read().await.get_latest_block_index() as u32;
                            match healed {
                                Converge::Converged | Converge::AtTipAhead => {
                                    let known_tip = self.beacon_high_water_height();
                                    if Self::stale_tip_mine_refused(tip_now, known_tip) {
                                        return Err(NodeError::Retryable(format!(
                                            "caught up to {} via a peer but the network has reached {}; not mining a stale tip",
                                            tip_now, known_tip
                                        )));
                                    }
                                    info!("mine-prep: healed a relay-hole deficit in place via peer delta-sync");
                                    return Ok(());
                                }
                                // Progress (ours, partial) or an in-flight background
                                // sync: the gap is being closed — report Retryable so
                                // the caller re-invokes instead of a restart hard-stop.
                                Converge::Progressed => {
                                    return Err(NodeError::Retryable(format!(
                                        "network tip {} is {} blocks ahead; a peer sync is closing the gap — retry",
                                        beacon.height,
                                        beacon.height.saturating_sub(tip_now)
                                    )));
                                }
                                _ if tip_now > local_tip => {
                                    return Err(NodeError::Retryable(format!(
                                        "recovered {} blocks from a peer and still catching up; retry",
                                        tip_now.saturating_sub(local_tip)
                                    )));
                                }
                                _ => {}
                            }
                            // Same advice-loop fix as the NeedsBootstrap arm: schedule
                            // the re-bootstrap so restarting actually performs it.
                            let scheduled = self.schedule_force_rebootstrap(
                                "mine-prep: behind the beacon and not converging",
                            );
                            return Err(NodeError::ConsensusFailure(format!(
                                "local chain is {} blocks behind the network tip ({} vs {}) and cannot converge incrementally; {}",
                                beacon.height.saturating_sub(local_tip),
                                local_tip,
                                beacon.height,
                                if scheduled {
                                    "a re-bootstrap is scheduled — restart this node to re-sync onto the canonical chain"
                                } else {
                                    "a re-bootstrap ran recently — the node keeps retrying in the background"
                                }
                            )));
                        }
                        // Fail-open is only competitive when we are within RACING
                        // distance of the beacon (a live same/next-height race). At a
                        // larger — but still reachable — deficit, mining the local tip
                        // is guaranteed waste and silently forks the miner off (the
                        // 2026-07-09 rotating stall: nodes 4-12 behind kept "failing
                        // open" and mining orphans for 20+ minutes while printing
                        // normal mining output). Report Retryable instead: the caller
                        // retries/backs off and the background reconcile keeps pulling
                        // us forward; we mine the moment converge actually lands.
                        if beacon.height > local_tip.saturating_add(2) {
                            return Err(NodeError::Retryable(format!(
                                "network tip {} is {} blocks ahead and the relay gap has not healed yet; not mining a stale tip",
                                beacon.height,
                                beacon.height.saturating_sub(local_tip)
                            )));
                        }
                        warn!("Relay gap while preparing to mine; mining on local tip (fail-open)");
                        return Ok(());
                    }
                    // Same round-attribution discipline as the Progressed arm
                    // (see that comment): decide from a pre-sleep read, sleep,
                    // re-baseline post-sleep.
                    let tip_after_round =
                        self.blockchain.read().await.get_latest_block_index() as u32;
                    backoff = if tip_after_round > last_round_tip {
                        Duration::from_millis(500)
                    } else {
                        (backoff * 2).min(Duration::from_secs(5))
                    };
                    tokio::time::sleep(backoff).await;
                    last_round_tip = self.blockchain.read().await.get_latest_block_index() as u32;
                }
                // The canonical branch we were pointed at failed validation locally.
                // Terminal for that branch, not for us: mine on our local tip and let
                // PoW settle it (same fail-open posture as a relay gap, immediately —
                // retrying the same invalid branch cannot succeed).
                //
                // EXCEPT when we know the network is meaningfully above us — the same
                // stale-tip guard as the Converged/AtTipAhead arm (the ea030a1 ghost
                // guard missed this arm). "That candidate is invalid" says nothing
                // about OUR height; a wedged node that kept failing candidates here
                // fail-opened and mined its own branch ~900 blocks past canonical on
                // the live network (2026-07-11), poisoning the relay head for everyone.
                Converge::BranchInvalid => {
                    let local_tip = self.blockchain.read().await.get_latest_block_index() as u32;
                    let known_tip = self.beacon_high_water_height();
                    if Self::stale_tip_mine_refused(local_tip, known_tip) {
                        return Err(NodeError::Retryable(format!(
                            "canonical candidate failed validation while the network is at {} and we are at {} ({} behind); not mining a stale tip",
                            known_tip,
                            local_tip,
                            known_tip.saturating_sub(local_tip)
                        )));
                    }
                    warn!("Canonical candidate branch failed validation; mining on local tip (fail-open)");
                    return Ok(());
                }
            }
        }
    }

    pub async fn publish_local_tip(&self) -> Result<(), NodeError> {
        if self.peers.read().await.is_empty() {
            if let Err(e) = self.connect_discovery_peers(8).await {
                debug!("Local tip discovery deferred: {}", e);
            }
        }

        let tip = {
            let blockchain = self.blockchain.read().await;
            blockchain
                .get_last_block()
                .ok_or_else(|| NodeError::Blockchain("No local chain tip found".to_string()))?
        };

        self.publish_block(tip, "Local tip").await
    }

    /// DETACHED + SINGLE-FLIGHT ascending relay backfill. Detached because the run
    /// is paced (~10 posts/s inside post_recent_blocks_to_relay) — awaited it would
    /// add ~3s to every mined block's publish path, and one run per mined block at
    /// 32 posts each was the biggest contributor to the per-IP POST budget (the
    /// 2026-07-08 429 storms). Single-flight because overlapping runs re-post the
    /// same recent window and only burn budget. Called after a successful fresh
    /// block post — first try or its one retry — so the recent-window re-post
    /// always trails a block the relay just accepted.
    fn spawn_relay_backfill(&self) {
        if RELAY_BACKFILL_INFLIGHT.swap(true, Ordering::SeqCst) {
            return;
        }
        let node = self.clone();
        tokio::spawn(async move {
            // Reset the single-flight flag via a destructor so a panic (or cancellation)
            // inside post_recent_blocks_to_relay cannot wedge it `true` forever and
            // permanently disable all future relay backfill for the process.
            struct BackfillGuard;
            impl Drop for BackfillGuard {
                fn drop(&mut self) {
                    RELAY_BACKFILL_INFLIGHT.store(false, Ordering::SeqCst);
                }
            }
            let _guard = BackfillGuard;
            node.post_recent_blocks_to_relay(Node::relay_backfill_limit())
                .await;
        });
    }

    pub async fn publish_block(&self, block: Block, context: &str) -> Result<(), NodeError> {
        let post_mine = context == "Post-mine";

        let block_hash = block.calculate_hash_for_block();
        let _ = self.network_bloom.insert(&block_hash);

        // Flood the mined block over the WebRTC mesh FIRST — before the gateway relay POST and the
        // peer discovery below — so mesh-connected miners get it on the fastest direct path without
        // waiting on the HTTP round-trip or discovery. mesh_gossip_block is fire-and-forget (it
        // spawns the actual sends), so this does not delay the relay POST. The peered broadcast
        // below passes gossip_mesh=false, so the block is mesh-gossiped exactly once.
        #[cfg(feature = "webrtc_mesh")]
        self.mesh_gossip_block(&block).await;

        // Start the gateway relay and already-connected direct peers together.
        // They are independent transports; serializing them made the direct path
        // inherit the full HTTP upload latency, precisely when a witness-heavy
        // block benefits most from the compact announcement. Peer discovery is
        // still deferred until afterward so a peerless node never delays its
        // authoritative NAT-friendly relay POST.
        let initial_peers = {
            let peers = self.peers.read().await;
            self.select_broadcast_peers(&peers, peers.len().min(16))
        };
        let initial_block = Arc::new(block.clone());
        let relay_fut = self.post_block_relay(&block);
        let direct_fut = async {
            if initial_peers.is_empty() {
                Ok(0)
            } else {
                self.broadcast_block(initial_block, None, initial_peers.clone(), false)
                    .await
            }
        };
        let (relay_result, mut direct_result) = tokio::join!(relay_fut, direct_fut);

        if let Err(e) = relay_result {
            warn!("{} block relay failed: {}", context, e);
            // A failed FRESH block is the one post that matters most for propagation
            // (relay-dependent nodes fork against it until it lands). Retryable
            // failures — a rolled-over per-IP window or a transient blip — get ONE
            // detached second attempt; relay_post_retry_delay documents the ladder
            // and returns None for permanent rejections. If the retry also fails,
            // the periodic relay-tip heal covers it. One shot only — looping here
            // would recreate the amplification this path just stopped doing.
            if let Some(delay) = Self::relay_post_retry_delay(&e) {
                let node = self.clone();
                let retry_block = block.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    match node.post_block_relay(&retry_block).await {
                        Ok(()) => {
                            // The recovered fresh block re-opens the same gap-heal
                            // window a first-try success gets: the ascending
                            // backfill posts parents before children, so any hole
                            // behind this block heals in the same pass.
                            node.spawn_relay_backfill();
                        }
                        Err(e) => warn!(
                            "Block #{} relay retry also failed: {}",
                            retry_block.index, e
                        ),
                    }
                });
            }
        } else {
            self.spawn_relay_backfill();
        }

        // If there were no already-connected peers, discovery gets one best-effort
        // second chance only after the relay POST has completed.
        if initial_peers.is_empty() {
            if let Err(e) = self.connect_discovery_peers(8).await {
                if post_mine {
                    warn!("{} discovery failed: {}", context, e);
                } else {
                    debug!("{} discovery deferred: {}", context, e);
                }
            }

            let discovered_peers = {
                let peers = self.peers.read().await;
                self.select_broadcast_peers(&peers, peers.len().min(16))
            };
            if !discovered_peers.is_empty() {
                direct_result = self
                    .broadcast_block(Arc::new(block.clone()), None, discovered_peers, false)
                    .await;
            }
        }

        match direct_result {
            Ok(0) => {
                // No TCP peers. The mined block was already flooded over the mesh at the top of
                // this function (the fastest path for a peerless NAT miner), so there is nothing
                // to do here but note the missing TCP fan-out.
                if post_mine {
                    warn!(
                        "Mined block saved locally, but no peers were available for block broadcast"
                    );
                } else {
                    debug!(
                        "{} publish deferred: no peers available for broadcast",
                        context
                    );
                }
            }
            Ok(delivered) => {
                if post_mine {
                    info!(
                        "Published mined block #{} to {} peer(s)",
                        block.index, delivered
                    );
                } else {
                    debug!(
                        "{} published block #{} to {} peer(s)",
                        context, block.index, delivered
                    );
                }
            }
            Err(e) => {
                if post_mine {
                    warn!(
                        "Mined block broadcast failed for every selected peer: {}",
                        e
                    );
                } else {
                    debug!("{} broadcast failed for selected peers: {}", context, e);
                }
            }
        }

        self.publish_discovery_state(context).await;

        Ok(())
    }

    async fn stats_handler(State(state): State<StatsState>) -> (StatusCode, Json<Value>) {
        if !Self::allow_read_bucket(&state.read_bucket) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "rate_limited" })),
            );
        }

        // ONE timed read guard: a consistent snapshot (the four fields used to be read under
        // four separate acquisitions, so under a heavy writer they could be torn across
        // instants), and fail-fast with 503 instead of hanging. get_tip_difficulty and
        // calculate_network_hashrate are &self on the guard and never re-lock the outer
        // RwLock, so holding one read across all fields is deadlock-free.
        let Ok(blockchain) = timeout(Duration::from_secs(3), state.blockchain.read()).await else {
            return Self::explorer_busy();
        };
        let height = blockchain.get_latest_block_index() as u32;
        let last_block_time = blockchain
            .get_last_block()
            .map(|b| b.timestamp)
            .unwrap_or(0);
        let difficulty = blockchain.get_tip_difficulty().await;
        let hashrate_ths = blockchain.calculate_network_hashrate().await;
        drop(blockchain);

        let peers = state.peers.read().await.len();
        let uptime_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(state.start_time);

        (
            StatusCode::OK,
            Json(json!({
                "network_id": hex::encode(state.network_id),
                "height": height,
                "difficulty": difficulty,
                "hashrate_ths": hashrate_ths,
                "last_block_time": last_block_time,
                "peers": peers,
                "version": format!("rust-{}", NETWORK_VERSION),
                "uptime_secs": uptime_secs,
            })),
        )
    }

    async fn health_handler() -> Json<Value> {
        Json(json!({
            "ok": true,
            "time": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }))
    }

    async fn start_stats_server(&self) -> Result<(), NodeError> {
        let bind_ip =
            std::env::var("ALPHANUMERIC_STATS_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = std::env::var("ALPHANUMERIC_STATS_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(8787);

        let addr: SocketAddr = format!("{}:{}", bind_ip, port)
            .parse()
            .map_err(|e| NodeError::Network(format!("Stats bind error: {}", e)))?;

        let state = StatsState {
            blockchain: Arc::clone(&self.blockchain),
            peers: Arc::clone(&self.peers),
            start_time: self.start_time,
            network_id: self.network_id,
            read_bucket: Arc::new(PLMutex::new((Instant::now(), 30.0))),
        };

        let app = Router::new()
            .route("/stats", get(Self::stats_handler))
            .route("/health", get(Self::health_handler))
            .with_state(state);

        let listener = match std::net::TcpListener::bind(addr) {
            Ok(l) => l,
            Err(e) => {
                if Self::stats_server_explicitly_enabled() {
                    warn!("Stats API disabled: failed to bind {} ({})", addr, e);
                } else {
                    debug!("Stats API disabled: failed to bind {} ({})", addr, e);
                }
                return Ok(());
            }
        };
        if let Err(e) = listener.set_nonblocking(true) {
            if Self::stats_server_explicitly_enabled() {
                warn!(
                    "Stats API disabled: failed to set nonblocking listener ({})",
                    e
                );
            } else {
                debug!(
                    "Stats API disabled: failed to set nonblocking listener ({})",
                    e
                );
            }
            return Ok(());
        }

        tokio::spawn(async move {
            match axum::Server::from_tcp(listener) {
                Ok(server) => {
                    if let Err(e) = server.serve(app.into_make_service()).await {
                        error!("Stats server error: {}", e);
                    }
                }
                Err(e) => {
                    error!("Stats server setup error: {}", e);
                }
            }
        });

        info!("Stats API listening on {}", addr);
        Ok(())
    }

    //----------------------------------------------------------------------
    // Explorer API (opt-in, read-only)
    //----------------------------------------------------------------------
    //
    // A localhost JSON surface for SELF-HOSTED explorers/integrations: run your
    // own node, point your website at it. Design rules, in order:
    //   1. OFF by default — unset env var means no task, no socket, zero cost.
    //   2. Read-only — no handler may ever write (no ensure/rebuild side
    //      effects), so anonymous GETs cannot amplify into DB work.
    //   3. Bounded — every read is cursor-paged or single-block, and chain-lock
    //      acquisition is time-boxed (503 "chain busy" instead of queueing
    //      handlers behind a busy write lock).
    //   4. Never held across await — lock guards live in sync scopes only.
    // The node serves data, not a website: JSON only, loopback bind unless the
    // operator explicitly chooses otherwise (their reverse proxy is the public
    // face, handling TLS/caching/rate limits).

    fn explorer_err(status: StatusCode, message: &str) -> (StatusCode, Json<Value>) {
        (status, Json(json!({ "error": message })))
    }

    fn explorer_busy() -> (StatusCode, Json<Value>) {
        Self::explorer_err(StatusCode::SERVICE_UNAVAILABLE, "chain busy, retry shortly")
    }

    /// Addresses are hex strings (or the MINING_REWARDS literal); reject anything
    /// else before it reaches a tree scan.
    fn explorer_valid_address(address: &str) -> bool {
        !address.is_empty()
            && address.len() <= 128
            && address
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    fn explorer_tx_json(tx: &Transaction, position: usize) -> Value {
        json!({
            "position": position,
            "from": tx.sender,
            "to": tx.recipient,
            "coinbase": SYSTEM_ADDRESSES.contains(&tx.sender.as_str()),
            "amount": Transaction::from_units(tx.amount_units),
            "amount_units": tx.amount_units.to_string(),
            "fee": Transaction::from_units(tx.fee_units),
            "fee_units": tx.fee_units.to_string(),
            "timestamp": tx.timestamp,
        })
    }

    fn explorer_block_json(block: &Block, tip_height: u32, finalized_height: u32) -> Value {
        json!({
            "height": block.index,
            "hash": hex::encode(block.hash),
            "previous_hash": hex::encode(block.previous_hash),
            "merkle_root": hex::encode(block.merkle_root),
            "timestamp": block.timestamp,
            "difficulty": block.difficulty,
            "nonce": block.nonce,
            "confirmations": tip_height.saturating_sub(block.index) as u64 + 1,
            "transaction_count": block.transactions.len(),
            // Irreversible once buried at/below the finality checkpoint — matches the tx/status
            // finality contract exchanges rely on. (EX-P3a)
            "final": block.index <= finalized_height,
            "transactions": block
                .transactions
                .iter()
                .enumerate()
                .map(|(position, tx)| Self::explorer_tx_json(tx, position))
                .collect::<Vec<_>>(),
        })
    }

    fn explorer_entry_json(entry: &crate::a9::blockchain::AddressTxEntry) -> Value {
        let direction = match (entry.is_sender(), entry.is_recipient()) {
            (true, true) => "self",
            (true, false) => "out",
            _ => "in",
        };
        json!({
            "height": entry.height,
            "position": entry.position,
            "direction": direction,
            "counterparty": entry.counterparty,
            "amount": Transaction::from_units(entry.amount_units),
            "amount_units": entry.amount_units.to_string(),
            "fee": Transaction::from_units(entry.fee_units),
            "fee_units": entry.fee_units.to_string(),
            "timestamp": entry.timestamp,
        })
    }

    async fn explorer_index_handler() -> Json<Value> {
        Json(json!({
            "service": "alphanumeric explorer api",
            "endpoints": [
                "/explorer/status",
                "/explorer/tip",
                "/explorer/block/{height}",
                "/explorer/tx/{height}/{position}",
                "/explorer/tx?id={tx_id}  (status of a tx by id: confirmed/pending/not_found)",
                "/explorer/address/{address}?limit=&before_height=&before_pos=",
                "/explorer/supply",
                "/explorer/fee-estimate  (advisory next-block fee recommendation)",
                "POST /explorer/submit-tx  (body: signed transaction JSON)",
            ],
        }))
    }

    async fn explorer_status_handler(
        State(state): State<ExplorerState>,
    ) -> (StatusCode, Json<Value>) {
        let Ok(chain) = timeout(Duration::from_secs(3), state.blockchain.read()).await else {
            return Self::explorer_busy();
        };
        let payload = {
            let tip = chain.get_last_block();
            let index_meta = chain.address_index_meta();
            let local_height = tip.as_ref().map(|b| b.index);
            // FRESHNESS SIGNAL: a resilient service node stays UP and serves while
            // it is a bit behind (rather than self-terminating), so a consumer
            // must be able to tell HOW far behind before trusting a read for e.g.
            // deposit crediting. network_height is the highest signed beacon the
            // node has observed (free cached read); blocks_behind is the delta.
            // Both null until the first beacon is seen. Data served is always a
            // valid canonical prefix — this only says how fresh it is.
            let network_height = state.node.observed_beacon_height();
            let blocks_behind = match (local_height, network_height) {
                (Some(l), Some(n)) => Some(n.saturating_sub(l)),
                _ => None,
            };
            // FINALITY SIGNAL (for exchanges): the highest height THIS node treats as
            // irreversible — reorgs at/below it are rejected outright; monotonic. Trails the
            // tip by finality_margin and advances on observed signed beacons AND on locally
            // verified frontier blocks, so it reflects THIS node's view: an eclipsed / minority-
            // partitioned node can advance it on a minority chain and thus report final:true for
            // a tx the majority later reorgs. Consumers must gate on freshness (network_height
            // present, blocks_behind small). 0 means not yet seeded. See EXPLORER_API.md.
            let finalized_height = chain.trusted_checkpoint_height();
            json!({
                "ok": true,
                "version": env!("CARGO_PKG_VERSION"),
                "network_id": hex::encode(state.network_id),
                "height": local_height,
                "tip_hash": tip.as_ref().map(|b| hex::encode(b.hash)),
                "network_height": network_height,
                "blocks_behind": blocks_behind,
                "index_height": index_meta.map(|(height, _)| height),
                "index_ready": index_meta.is_some(),
                "finalized_height": finalized_height,
                "finality_margin": crate::a9::blockchain::CHECKPOINT_REORG_MARGIN,
                "uptime_secs": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_sub(state.start_time),
            })
        };
        (StatusCode::OK, Json(payload))
    }

    async fn explorer_tip_handler(State(state): State<ExplorerState>) -> (StatusCode, Json<Value>) {
        let Ok(chain) = timeout(Duration::from_secs(3), state.blockchain.read()).await else {
            return Self::explorer_busy();
        };
        match chain.get_last_block() {
            Some(block) => {
                let tip_height = block.index;
                let finalized_height = chain.trusted_checkpoint_height();
                (
                    StatusCode::OK,
                    Json(Self::explorer_block_json(
                        &block,
                        tip_height,
                        finalized_height,
                    )),
                )
            }
            None => Self::explorer_err(StatusCode::NOT_FOUND, "chain is empty"),
        }
    }

    async fn explorer_block_handler(
        State(state): State<ExplorerState>,
        AxumPath(height): AxumPath<u32>,
    ) -> (StatusCode, Json<Value>) {
        let Ok(chain) = timeout(Duration::from_secs(3), state.blockchain.read()).await else {
            return Self::explorer_busy();
        };
        let tip_height = chain.get_latest_block_index() as u32;
        let finalized_height = chain.trusted_checkpoint_height();
        match chain.get_block(height) {
            Ok(block) => (
                StatusCode::OK,
                Json(Self::explorer_block_json(
                    &block,
                    tip_height,
                    finalized_height,
                )),
            ),
            Err(_) => Self::explorer_err(StatusCode::NOT_FOUND, "block not found"),
        }
    }

    async fn explorer_tx_handler(
        State(state): State<ExplorerState>,
        AxumPath((height, position)): AxumPath<(u32, u32)>,
    ) -> (StatusCode, Json<Value>) {
        let Ok(chain) = timeout(Duration::from_secs(3), state.blockchain.read()).await else {
            return Self::explorer_busy();
        };
        let tip_height = chain.get_latest_block_index() as u32;
        let Ok(block) = chain.get_block(height) else {
            return Self::explorer_err(StatusCode::NOT_FOUND, "block not found");
        };
        let Some(tx) = block.transactions.get(position as usize) else {
            return Self::explorer_err(StatusCode::NOT_FOUND, "transaction not found");
        };
        let finalized_height = chain.trusted_checkpoint_height();
        let mut payload = Self::explorer_tx_json(tx, position as usize);
        if let Some(object) = payload.as_object_mut() {
            object.insert("height".into(), json!(height));
            object.insert("block_hash".into(), json!(hex::encode(block.hash)));
            object.insert(
                "confirmations".into(),
                json!(tip_height.saturating_sub(height) as u64 + 1),
            );
            // Irreversible once buried at/below the finality checkpoint.
            object.insert("final".into(), json!(height <= finalized_height));
        }
        (StatusCode::OK, Json(payload))
    }

    /// `GET /explorer/tx?id=<tx_id>` — look up a transaction by its id (the value
    /// `submit-tx` returns) and report its status. This is the endpoint a web3
    /// site polls to follow a transaction it just broadcast to confirmation,
    /// without having to know the (height, position) locator up front.
    ///
    /// Returns 200 with `status: "confirmed"` (plus height, position, block_hash,
    /// confirmations, and the tx body) once it is in a block; 200 with
    /// `status: "pending"` while it sits in the mempool; and 404 `not_found` if it
    /// is unknown, was dropped, or is older than the confirmed-tx retention
    /// window (for deep history, look it up by (height, position) or via
    /// `/explorer/address`). This tracks USER-submitted transactions; coinbase /
    /// system rewards are not in the tx-id registry and read as not_found here.
    /// Read-only (confirmed-tx registry + block reads + mempool lookup) — no
    /// consensus, mining, or write surface. `status` is present on every
    /// response; `ok` is true on 200 and false on the 404.
    async fn explorer_tx_by_id_handler(
        State(state): State<ExplorerState>,
        Query(query): Query<ExplorerTxIdQuery>,
    ) -> (StatusCode, Json<Value>) {
        // Bound the id: a real get_tx_id is well under 512 chars
        // (two 40-hex addresses + amounts + a timestamp). Reject empty/oversized
        // before any tree scan.
        let tx_id = match query.id {
            Some(id) if !id.is_empty() && id.len() <= 512 => id,
            _ => {
                return Self::explorer_err(
                    StatusCode::BAD_REQUEST,
                    "missing or invalid `id` query parameter",
                )
            }
        };
        let Ok(chain) = timeout(Duration::from_secs(3), state.blockchain.read()).await else {
            return Self::explorer_busy();
        };

        // Confirmed: the recent-confirmed registry maps tx_id -> height. Locate
        // the body + position by scanning that block's transactions (unique tx_id
        // within a block is guaranteed by the replay guard).
        if let Some(height) = chain.confirmed_tx_height(&tx_id) {
            let tip_height = chain.get_latest_block_index() as u32;
            if let Ok(block) = chain.get_block(height) {
                if let Some(position) = block
                    .transactions
                    .iter()
                    .position(|t| t.get_tx_id() == tx_id)
                {
                    let finalized_height = chain.trusted_checkpoint_height();
                    let mut payload =
                        Self::explorer_tx_json(&block.transactions[position], position);
                    if let Some(object) = payload.as_object_mut() {
                        object.insert("ok".into(), json!(true));
                        object.insert("tx_id".into(), json!(tx_id));
                        object.insert("status".into(), json!("confirmed"));
                        object.insert("height".into(), json!(height));
                        object.insert("block_hash".into(), json!(hex::encode(block.hash)));
                        object.insert(
                            "confirmations".into(),
                            json!(tip_height.saturating_sub(height) as u64 + 1),
                        );
                        // Irreversible once buried at/below the finality checkpoint. An
                        // exchange should credit a deposit only when this is true (or, if it
                        // prefers a fixed depth, at finality_margin confirmations).
                        object.insert("final".into(), json!(height <= finalized_height));
                    }
                    return (StatusCode::OK, Json(payload));
                }
            }
            // Registry says confirmed but the body could not be located (a rare
            // index/block skew): still report confirmed with the height we hold.
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true, "status": "confirmed", "tx_id": tx_id, "height": height,
                    "final": height <= chain.trusted_checkpoint_height(),
                })),
            );
        }

        // Pending: still in the mempool, not yet in a block.
        if let Some(tx) = chain.get_mempool_transaction_by_id(&tx_id).await {
            let mut payload = Self::explorer_tx_json(&tx, 0);
            if let Some(object) = payload.as_object_mut() {
                // position is meaningless before the tx is placed in a block.
                object.remove("position");
                object.insert("ok".into(), json!(true));
                object.insert("tx_id".into(), json!(tx_id));
                object.insert("status".into(), json!("pending"));
            }
            return (StatusCode::OK, Json(payload));
        }

        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "status": "not_found",
                "tx_id": tx_id,
                "hint": "unknown, dropped, or older than the recent-confirmed window; for deep history look it up by (height, position) or via /explorer/address",
            })),
        )
    }

    // Consume one token from the coarse explorer read bucket (refill 10/s, cap 30). Returns false
    // when exhausted, so an unauthenticated flood is answered 429 before any O(chain) scan runs.
    /// Coarse per-process token bucket (refill 10/s, cap 30) shared by the opt-in explorer
    /// READ endpoints and the /stats endpoint.
    fn allow_read_bucket(bucket: &Arc<PLMutex<(Instant, f64)>>) -> bool {
        let mut b = bucket.lock();
        let now = Instant::now();
        b.1 = (b.1 + now.duration_since(b.0).as_secs_f64() * 10.0).min(30.0);
        b.0 = now;
        if b.1 < 1.0 {
            return false;
        }
        b.1 -= 1.0;
        true
    }

    fn allow_explorer_read(state: &ExplorerState) -> bool {
        Self::allow_read_bucket(&state.read_bucket)
    }

    async fn explorer_address_handler(
        State(state): State<ExplorerState>,
        AxumPath(address): AxumPath<String>,
        Query(query): Query<ExplorerAddressQuery>,
    ) -> (StatusCode, Json<Value>) {
        if !Self::allow_explorer_read(&state) {
            return Self::explorer_err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        }
        if !Self::explorer_valid_address(&address) {
            return Self::explorer_err(StatusCode::BAD_REQUEST, "invalid address");
        }
        let limit = query.limit.unwrap_or(50).clamp(1, 200);
        let before = match (query.before_height, query.before_pos) {
            (Some(height), Some(position)) => Some((height, position)),
            (None, None) => None,
            _ => {
                return Self::explorer_err(
                    StatusCode::BAD_REQUEST,
                    "before_height and before_pos must be passed together",
                )
            }
        };
        let Ok(chain) = timeout(Duration::from_secs(3), state.blockchain.read()).await else {
            return Self::explorer_busy();
        };
        let payload = {
            let balance_units = chain
                .confirmed_balance_units_readonly(&address)
                .unwrap_or(0);
            let index_meta = chain.address_index_meta();
            let summary = chain.address_history_summary(&address).unwrap_or(None);
            let entries = chain
                .address_txs_page(&address, limit, before)
                .unwrap_or_default();
            let next = if entries.len() == limit {
                entries.last().map(
                    |entry| json!({ "before_height": entry.height, "before_pos": entry.position }),
                )
            } else {
                None
            };
            json!({
                "address": address,
                "balance": Transaction::from_units(balance_units),
                "balance_units": balance_units.to_string(),
                "index_ready": index_meta.is_some(),
                "index_height": index_meta.map(|(height, _)| height),
                "summary": summary.map(|s| json!({
                    "transactions": s.tx_count,
                    "sent": Transaction::from_units(s.sent_units),
                    "sent_units": s.sent_units.to_string(),
                    "received": Transaction::from_units(s.received_units),
                    "received_units": s.received_units.to_string(),
                    "fees": Transaction::from_units(s.fees_units),
                    "fees_units": s.fees_units.to_string(),
                    "first_height": s.first_height,
                    "last_height": s.last_height,
                })),
                "transactions": entries
                    .iter()
                    .map(Self::explorer_entry_json)
                    .collect::<Vec<_>>(),
                "next": next,
            })
        };
        (StatusCode::OK, Json(payload))
    }

    async fn explorer_supply_handler(
        State(state): State<ExplorerState>,
    ) -> (StatusCode, Json<Value>) {
        if !Self::allow_explorer_read(&state) {
            return Self::explorer_err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        }
        let Ok(chain) = timeout(Duration::from_secs(3), state.blockchain.read()).await else {
            return Self::explorer_busy();
        };
        let payload = {
            let supply_units = chain.total_confirmed_supply_units().unwrap_or(0);
            json!({
                "height": chain.get_latest_block_index() as u32,
                "supply": Transaction::from_units(supply_units),
                "supply_units": supply_units.to_string(),
            })
        };
        (StatusCode::OK, Json(payload))
    }

    /// Advisory fee recommendation for external integrators (web wallets,
    /// exchanges building their own signing flows) — the same estimate the
    /// reference wallet's `create` uses when --fee is absent. Pure POLICY, no
    /// consensus surface: callers may attach any fee at or above the relay
    /// floor; this endpoint just prices next-block inclusion off this node's
    /// live mempool. try_fee_estimate is sync, so the chain guard is never held
    /// across an await (the explorer design rule); a momentarily contended
    /// mempool surfaces the standard 503 busy.
    async fn explorer_fee_estimate_handler(
        State(state): State<ExplorerState>,
    ) -> (StatusCode, Json<Value>) {
        if !Self::allow_explorer_read(&state) {
            return Self::explorer_err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        }
        let Ok(chain) = timeout(Duration::from_secs(3), state.blockchain.read()).await else {
            return Self::explorer_busy();
        };
        let payload = {
            let Some(estimate) = chain.try_fee_estimate() else {
                return Self::explorer_busy();
            };
            json!({
                "recommended_fee": Transaction::from_units(estimate.recommended_units),
                "recommended_fee_units": estimate.recommended_units.to_string(),
                "anchor_fee": Transaction::from_units(estimate.anchor_units),
                "anchor_fee_units": estimate.anchor_units.to_string(),
                "floor_fee": Transaction::from_units(estimate.floor_units),
                "floor_fee_units": estimate.floor_units.to_string(),
                "auto_cap_fee": Transaction::from_units(estimate.auto_cap_units),
                "auto_cap_fee_units": estimate.auto_cap_units.to_string(),
                "explicit_cap_fee": Transaction::from_units(estimate.explicit_cap_units),
                "explicit_cap_fee_units": estimate.explicit_cap_units.to_string(),
                "congested": estimate.congested,
                "pending_candidates": estimate.pending_candidates,
                "next_block_fits": estimate.next_block_fits,
                "basis": estimate.basis(),
            })
        };
        (StatusCode::OK, Json(payload))
    }

    /// Submit a signed transaction to the network (opt-in explorer API write path).
    /// This is the endpoint web wallets / exchanges POST a signed tx to. It changes
    /// NO consensus surface: the tx goes through the SAME add_transaction validation
    /// the CLI `create` uses (signature, balance, replay guard, already-confirmed
    /// gate), and on acceptance is announced via the SAME gossip path. A node only
    /// serves this when its operator sets ALPHANUMERIC_EXPLORER_API — the publisher
    /// and ordinary clients never do, so existing infra is untouched.
    async fn explorer_submit_tx_handler(
        State(state): State<ExplorerState>,
        Json(tx): Json<Transaction>,
    ) -> (StatusCode, Json<Value>) {
        // Coarse token bucket (refill 5/s, cap 20): a cheap flood guard so junk
        // that would fail validation can't hammer the mempool write lock. The real
        // rule is the per-sender rate limit inside add_transaction.
        {
            let mut b = state.submit_bucket.lock();
            let now = Instant::now();
            b.1 = (b.1 + now.duration_since(b.0).as_secs_f64() * 5.0).min(20.0);
            b.0 = now;
            if b.1 < 1.0 {
                return Self::explorer_err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
            }
            b.1 -= 1.0;
        }
        if tx.sender.is_empty() || tx.recipient.is_empty() {
            return Self::explorer_err(StatusCode::BAD_REQUEST, "missing sender or recipient");
        }
        // Transaction identity is (sender, recipient, amount, fee, timestamp). The
        // atomic admission outcome below distinguishes a new insertion from a resend
        // under the same lock as canonical and durable-pending state.
        let tx_id = tx.get_tx_id();
        // Validate + admit through the canonical path. M2: a READ lock suffices --
        // add_transaction is &self and serializes its balance-check + mempool mutation on
        // state_mutation_lock (the same lock save_block/finalize_block take, same order),
        // so a write lock added no exclusion, it only held the exclusive blockchain lock
        // across the CPU-heavy ML-DSA verify. Read lets admissions verify concurrently and
        // stops starving readers/mining during a tx burst.
        //
        // The outcome is rendered to a String here rather than carried as-is:
        // BlockchainError is not Send, and the already-confirmed arm below awaits, so
        // keeping the error in scope past this point would sink the handler's Send bound.
        let submit = {
            let Ok(chain) = timeout(Duration::from_secs(3), state.blockchain.read()).await else {
                return Self::explorer_busy();
            };
            chain
                .admit_transaction(tx.clone())
                .await
                .map_err(|e| e.to_string())
        };
        match submit {
            Ok(crate::a9::blockchain::TransactionAdmissionOutcome::Inserted) => {
                // Announce now (mesh + peers) instead of waiting for the periodic
                // re-gossip, so a withdrawal propagates immediately. The detached
                // gossip task also seeds the compact leaf index from the canonical
                // admitted mempool entry; keeping that work out of this handler
                // preserves Axum's Send future requirement.
                let node = state.node.clone();
                let announce = tx.clone();
                tokio::spawn(async move { node.gossip_transaction(&announce).await });
                (
                    StatusCode::OK,
                    Json(json!({ "ok": true, "status": "accepted", "tx_id": tx.get_tx_id() })),
                )
            }
            Ok(crate::a9::blockchain::TransactionAdmissionOutcome::AlreadyPending) => (
                StatusCode::OK,
                Json(json!({
                    "ok": true, "status": "already_pending", "tx_id": tx_id,
                    "hint": "identical transaction already pending; a distinct payment must differ in timestamp, amount, or fee"
                })),
            ),
            Ok(crate::a9::blockchain::TransactionAdmissionOutcome::AlreadyConfirmed(height)) => {
                let finalized_height = match timeout(Duration::from_secs(3), state.blockchain.read()).await {
                    Ok(chain) => chain.trusted_checkpoint_height(),
                    Err(_) => return Self::explorer_busy(),
                };
                (
                    StatusCode::OK,
                    Json(json!({
                        "ok": true, "status": "already_confirmed", "tx_id": tx_id,
                        "height": height, "final": height <= finalized_height
                    })),
                )
            }
            Err(e) => Self::explorer_err(
                StatusCode::BAD_REQUEST,
                &format!("transaction rejected: {}", e),
            ),
        }
    }

    /// Start the explorer API iff ALPHANUMERIC_EXPLORER_API is set. Accepts
    /// `host:port` or a bare port (bound to 127.0.0.1). Loopback is the intended
    /// deployment; binding wider is allowed but warned — the operator's reverse
    /// proxy, not the node, should face the internet.
    async fn start_explorer_server(&self) -> Result<(), NodeError> {
        let Ok(raw) = std::env::var("ALPHANUMERIC_EXPLORER_API") else {
            return Ok(());
        };
        let raw = raw.trim().to_string();
        if raw.is_empty() || raw.eq_ignore_ascii_case("false") || raw.eq_ignore_ascii_case("off") {
            return Ok(());
        }
        let addr: SocketAddr = if let Ok(port) = raw.parse::<u16>() {
            SocketAddr::from(([127, 0, 0, 1], port))
        } else {
            raw.parse().map_err(|e| {
                NodeError::Network(format!("ALPHANUMERIC_EXPLORER_API bind address: {}", e))
            })?
        };
        if !addr.ip().is_loopback() {
            warn!(
                "Explorer API binding non-loopback {} — it serves unauthenticated chain data; keep it behind a reverse proxy",
                addr
            );
        }

        let state = ExplorerState {
            blockchain: Arc::clone(&self.blockchain),
            node: self.clone(),
            start_time: self.start_time,
            network_id: self.network_id,
            submit_bucket: Arc::new(PLMutex::new((Instant::now(), 20.0))),
            read_bucket: Arc::new(PLMutex::new((Instant::now(), 30.0))),
        };

        let app = Router::new()
            .route("/", get(Self::explorer_index_handler))
            .route("/explorer", get(Self::explorer_index_handler))
            .route("/explorer/status", get(Self::explorer_status_handler))
            .route("/explorer/tip", get(Self::explorer_tip_handler))
            .route("/explorer/block/:height", get(Self::explorer_block_handler))
            .route("/explorer/tx", get(Self::explorer_tx_by_id_handler))
            .route(
                "/explorer/tx/:height/:position",
                get(Self::explorer_tx_handler),
            )
            .route(
                "/explorer/address/:address",
                get(Self::explorer_address_handler),
            )
            .route("/explorer/supply", get(Self::explorer_supply_handler))
            .route(
                "/explorer/fee-estimate",
                get(Self::explorer_fee_estimate_handler),
            )
            .route(
                "/explorer/submit-tx",
                axum::routing::post(Self::explorer_submit_tx_handler),
            )
            .with_state(state);

        let listener = std::net::TcpListener::bind(addr).map_err(|e| {
            NodeError::Network(format!("Explorer API failed to bind {}: {}", addr, e))
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|e| NodeError::Network(format!("Explorer API nonblocking listener: {}", e)))?;

        tokio::spawn(async move {
            match axum::Server::from_tcp(listener) {
                Ok(server) => {
                    if let Err(e) = server.serve(app.into_make_service()).await {
                        error!("Explorer API server error: {}", e);
                    }
                }
                Err(e) => {
                    error!("Explorer API setup error: {}", e);
                }
            }
        });

        info!("Explorer API listening on {}", addr);
        Ok(())
    }

    //----------------------------------------------------------------------
    // Network Discovery
    //----------------------------------------------------------------------

    // Make this a regular associated function instead of static fn
    pub fn get_bind_address() -> Result<IpAddr, NodeError> {
        // Try to get local interfaces
        if let Ok(interfaces) = if_addrs::get_if_addrs() {
            // First try to find a non-loopback IPv4 address
            if let Some(interface) = interfaces.iter().find(|interface| {
                !interface.addr.ip().is_loopback() && interface.addr.ip().is_ipv4()
            }) {
                return Ok(interface.addr.ip());
            }

            // Fallback to any IPv4 address including loopback
            if let Some(interface) = interfaces
                .iter()
                .find(|interface| interface.addr.ip().is_ipv4())
            {
                return Ok(interface.addr.ip());
            }
        }

        // Ultimate fallback to localhost
        Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    pub async fn discover_network_nodes(&self) -> Result<(), NodeError> {
        let before_count = self.peers.read().await.len();

        {
            let state = self.discovery_state.lock().await;
            let now = Instant::now();

            if before_count < MIN_PEERS && now < state.next_attempt {
                debug!(
                    "Discovery skipped: backoff active for {:?}",
                    state.next_attempt.saturating_duration_since(now)
                );
                return Ok(());
            }
        }

        // Claim the single-flight slot atomically. If another cycle already holds it,
        // skip. The RAII guard below clears the flag on EVERY exit path (return, `?`,
        // panic, cancellation) so an unwinding discovery can no longer wedge it true
        // and permanently disable peer discovery.
        if self
            .discovery_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            debug!("Discovery skipped: another discovery cycle is already running");
            return Ok(());
        }
        struct InProgressGuard(Arc<AtomicBool>);
        impl Drop for InProgressGuard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _in_progress = InProgressGuard(Arc::clone(&self.discovery_in_progress));

        info!("Starting network discovery");
        let result = self.discover_network_nodes_with_retry(0).await;
        let after_count = self.peers.read().await.len();
        let improved = after_count > before_count || after_count >= MIN_PEERS;

        {
            let mut state = self.discovery_state.lock().await;

            if after_count >= MIN_PEERS || (result.is_ok() && improved) {
                state.failures = 0;
                state.next_attempt = Instant::now();
            } else if after_count < MIN_PEERS {
                state.failures = state.failures.saturating_add(1);
                let backoff_secs = Self::discovery_backoff_secs(state.failures);
                state.next_attempt = Instant::now() + Duration::from_secs(backoff_secs);
                debug!(
                    "Discovery backoff set to {}s after {} low-peer cycle(s)",
                    backoff_secs, state.failures
                );
            }
        }

        result
    }

    fn discovery_backoff_secs(failures: u32) -> u64 {
        let exponent = failures.saturating_sub(1).min(4);
        DISCOVERY_BACKOFF_BASE_SECS
            .saturating_mul(1_u64 << exponent)
            .min(DISCOVERY_BACKOFF_MAX_SECS)
    }

    // Separate implementation for recursive calls with retry counter
    async fn discover_network_nodes_with_retry(&self, retry_count: u32) -> Result<(), NodeError> {
        const MAX_DISCOVERY_RETRIES: u32 = 1;
        const MAX_TARGET_PEERS: usize = 12;
        // Kept in step with MIN_PEERS: below this, discovery enriches its
        // candidate set from the persisted address book and configured seeds,
        // so a node at 3-4 peers actually finds the dials to reach the floor.
        const MIN_TARGET_PEERS: usize = MIN_PEERS;
        const VERIFY_BATCH_SIZE: usize = 8;
        const VERIFY_CONCURRENCY: usize = 3;

        let gateway_only = std::env::var("ALPHANUMERIC_DISCOVERY_GATEWAY_ONLY")
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let enable_dns_fallback = std::env::var("ALPHANUMERIC_DISCOVERY_ENABLE_DNS_FALLBACK")
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let enable_kad_fallback = Self::kademlia_fallback_enabled();
        let enable_aggressive_discovery = std::env::var("ALPHANUMERIC_ENABLE_AGGRESSIVE_DISCOVERY")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let mut discovered_addrs = HashSet::new();
        let mut verified_peers = Vec::new();

        let current_peers: HashSet<SocketAddr> = {
            let peers = self.peers.read().await;
            peers.keys().copied().collect()
        };

        let needs_more_peers = current_peers.len() < MIN_TARGET_PEERS;
        let configured_seed_nodes = self.configured_seed_nodes();

        if needs_more_peers {
            discovered_addrs.extend(self.load_peer_cache());
            for seed in configured_seed_nodes {
                match tokio::net::lookup_host(seed.as_str()).await {
                    Ok(addrs) => discovered_addrs.extend(addrs),
                    Err(e) => debug!("Seed node lookup failed for {}: {}", seed, e),
                }
            }
        }

        // Priority 1: alphanumeric.blue discovery service
        let mut gateway_ok = false;
        match self.fetch_discovery_peers().await {
            Ok(peer_addrs) => {
                gateway_ok = true;
                discovered_addrs.extend(peer_addrs);
                debug!(
                    "Discovery gateway provided {} candidate peers",
                    discovered_addrs.len()
                );
            }
            Err(e) => {
                debug!("Discovery gateway unavailable: {}", e);
            }
        }

        // Fallbacks are only used when gateway is unavailable, or explicitly allowed.
        let allow_fallback =
            !gateway_ok || !gateway_only || (needs_more_peers && discovered_addrs.is_empty());
        if allow_fallback {
            if !current_peers.is_empty() {
                if let Ok(peer_addrs) = self.discover_from_existing_peers().await {
                    discovered_addrs.extend(peer_addrs);
                }
            }

            if enable_dns_fallback {
                for seed in Self::dns_seeds() {
                    match tokio::net::lookup_host(seed.as_str()).await {
                        Ok(addrs) => discovered_addrs.extend(addrs),
                        Err(e) => debug!("DNS lookup failed for {}: {}", seed, e),
                    }
                }
            }

            if enable_kad_fallback {
                if let Ok(kad_addrs) = self.discover_from_kademlia().await {
                    discovered_addrs.extend(kad_addrs);
                }
            }
        }

        // Heavy scan mode is restricted to debug builds to keep release behavior conservative.
        if cfg!(debug_assertions) && enable_aggressive_discovery && needs_more_peers && !gateway_ok
        {
            if let Ok(local_addrs) = self.discover_local_network().await {
                discovered_addrs.extend(local_addrs);
            }

            if let Ok((Some(v4), v6)) = self.discover_external_addresses(STUN_SERVERS).await {
                if let Ok(ranges) = self.build_scan_ranges(v4, v6).await {
                    for range in ranges.iter().take(3) {
                        if range.priority <= 3 {
                            if let Ok(range_addrs) =
                                tokio::time::timeout(Duration::from_secs(8), self.scan_range(range))
                                    .await
                                    .unwrap_or_else(|_| Ok(HashSet::new()))
                            {
                                discovered_addrs.extend(range_addrs);
                            }
                        }
                    }
                }
            }
        }

        let mut new_addrs = Self::filter_dialable_discovery_candidates(
            discovered_addrs,
            self.bind_addr,
            &current_peers,
            Self::private_discovery_peers_allowed(),
        );

        if new_addrs.is_empty() {
            info!("No new peers discovered");
            if needs_more_peers && retry_count < MAX_DISCOVERY_RETRIES {
                let backoff_ms = 300_u64.saturating_mul(1_u64 << retry_count.min(4));
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                return Box::pin(self.discover_network_nodes_with_retry(retry_count + 1)).await;
            }
            return Ok(());
        }

        new_addrs.shuffle(&mut thread_rng());
        new_addrs.truncate(MAX_TARGET_PEERS);

        let connection_limiter = Arc::new(Semaphore::new(VERIFY_CONCURRENCY));
        for batch in new_addrs.chunks(VERIFY_BATCH_SIZE) {
            if verified_peers.len() >= MAX_TARGET_PEERS {
                break;
            }

            let verification_tasks: Vec<_> = batch
                .iter()
                .copied()
                .map(|addr| {
                    let permit = connection_limiter.clone().acquire_owned();
                    let node = self.clone();
                    tokio::spawn(async move {
                        let _permit = match permit.await {
                            Ok(permit) => permit,
                            Err(_) => return None,
                        };
                        match tokio::time::timeout(Duration::from_secs(4), node.verify_peer(addr))
                            .await
                        {
                            Ok(Ok(_)) => Some(addr),
                            Ok(Err(e)) => {
                                debug!("Failed to verify peer {}: {}", addr, e);
                                None
                            }
                            Err(_) => {
                                debug!("Verification timed out for {}", addr);
                                None
                            }
                        }
                    })
                })
                .collect();

            for result in futures::future::join_all(verification_tasks).await {
                if let Ok(Some(addr)) = result {
                    verified_peers.push(addr);
                    if verified_peers.len() >= MAX_TARGET_PEERS {
                        break;
                    }
                }
            }
        }

        info!(
            "Discovery cycle complete: verified {} new peer(s), gateway_ok={}, fallback_used={}",
            verified_peers.len(),
            gateway_ok,
            allow_fallback
        );

        if let Err(e) = self.rebalance_peer_subnets().await {
            warn!("Failed to rebalance peer subnets: {}", e);
        }

        Ok(())
    }

    async fn discover_from_kademlia(&self) -> Result<HashSet<SocketAddr>, NodeError> {
        let mut discovered = HashSet::new();

        // Check-and-RELEASE: confirm the swarm exists, then drop the guard. handle_p2p_events
        // below re-locks p2p_swarm itself, so holding the guard across that call was a
        // reentrant tokio-Mutex deadlock (the guard is not re-entrant).
        if self.p2p_swarm.lock().await.is_none() {
            return Ok(discovered);
        }

        // Pump events WITHOUT holding the swarm lock.
        if self.handle_p2p_events().await.is_ok() {
            // Re-acquire only to snapshot the connected peer ids, then DROP the guard before
            // any awaited per-peer work (never hold the swarm lock across an await).
            let peer_ids: Vec<PeerId> = {
                let swarm_guard = self.p2p_swarm.lock().await;
                match &*swarm_guard {
                    Some(swarm) => swarm.0.connected_peers().cloned().collect(),
                    None => Vec::new(),
                }
            };
            for peer_id in peer_ids {
                if let Ok(addrs) = self.get_peer_addresses_from_connections(&peer_id).await {
                    for addr in addrs {
                        discovered.insert(addr);
                    }
                }
            }
        }

        Ok(discovered)
    }

    // Helper function to safely get peer addresses
    async fn get_peer_addresses_from_connections(
        &self,
        _peer_id: &PeerId,
    ) -> Result<Vec<SocketAddr>, NodeError> {
        // Simple implementation that doesn't depend on addresses_of_peer
        let mut result = Vec::new();

        // If we have existing connections in peers map, use those
        let peers = self.peers.read().await;
        for (addr, _) in peers.iter() {
            result.push(*addr);
        }

        Ok(result)
    }

    async fn build_scan_ranges(
        &self,
        v4_addr: IpAddr,
        v6_addr: Option<IpAddr>,
    ) -> Result<Vec<ScanRange>, NodeError> {
        let mut ranges = Vec::new();

        // Add common IPv4 ranges
        for &(range, priority) in &[
            // Cloud providers
            ("3.0.0.0/8", 2),   // AWS
            ("35.0.0.0/8", 2),  // GCP
            ("52.0.0.0/8", 2),  // AWS
            ("104.0.0.0/8", 2), // Cloud
            // ISP ranges
            ("24.0.0.0/8", 4), // Comcast
            ("71.0.0.0/8", 4), // AT&T
            ("73.0.0.0/8", 4), // Verizon
            // Private networks
            ("192.168.0.0/16", 5), // Local
            ("10.0.0.0/8", 5),     // Private
        ] {
            if let Ok(net) = range.parse::<Ipv4Net>() {
                ranges.push(ScanRange {
                    network: ScanNetwork::V4(net),
                    priority,
                });
            }
        }

        // Add IPv4 subnet from current address
        if let IpAddr::V4(ipv4) = v4_addr {
            let octets = ipv4.octets();
            let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);

            if let Ok(net) = subnet.parse::<Ipv4Net>() {
                ranges.push(ScanRange {
                    network: ScanNetwork::V4(net),
                    priority: 1, // Highest priority
                });

                // Also add adjacent subnets
                for i in -2i32..=2i32 {
                    if i == 0 {
                        continue;
                    }
                    let base = (octets[2] as i32 + i) as u8;
                    let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], base);

                    if let Ok(net) = subnet.parse::<Ipv4Net>() {
                        ranges.push(ScanRange {
                            network: ScanNetwork::V4(net),
                            priority: 2,
                        });
                    }
                }
            }
        }

        // Add IPv6 ranges if available
        if let Some(IpAddr::V6(ipv6)) = v6_addr {
            let segments = ipv6.segments();
            let prefix = segments[..4].to_vec();

            let subnet = format!(
                "{}:{}:{}:{:x}::/64",
                prefix[0], prefix[1], prefix[2], prefix[3]
            );

            if let Ok(net) = subnet.parse::<Ipv6Net>() {
                ranges.push(ScanRange {
                    network: ScanNetwork::V6(net),
                    priority: 3,
                });
            }
        }

        // Sort ranges by priority
        ranges.sort_by_key(|range| range.priority);

        Ok(ranges)
    }

    async fn scan_range(&self, range: &ScanRange) -> Result<HashSet<SocketAddr>, NodeError> {
        let mut discovered = HashSet::new();

        // Get addresses to scan based on network type
        let addrs = match &range.network {
            ScanNetwork::V4(net) => {
                let mut addrs = Vec::new();
                // Generate up to 256 addresses from the subnet
                for host in net.hosts().take(256) {
                    addrs.push(SocketAddr::new(IpAddr::V4(host), DEFAULT_PORT));
                }
                addrs
            }
            ScanNetwork::V6(net) => {
                let mut addrs = Vec::new();
                let mut rng = thread_rng();

                // For IPv6, generate 50 random addresses in the subnet
                for _ in 0..50 {
                    let mut segments = [0u16; 8];

                    // Copy prefix
                    let prefix_len = (net.prefix_len() / 16) as usize;
                    let prefix = net.addr().segments();
                    segments[..prefix_len].copy_from_slice(&prefix[..prefix_len]);

                    // Randomize host part
                    for segment in segments.iter_mut().skip(prefix_len) {
                        *segment = rng.gen();
                    }

                    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(segments)), DEFAULT_PORT);
                    addrs.push(addr);
                }
                addrs
            }
        };

        // Concurrently scan addresses
        let semaphore = Arc::new(Semaphore::new(50)); // Max 50 concurrent scans
        let node = self.clone();

        let scan_tasks: Vec<_> = addrs
            .into_iter()
            .map(|addr| {
                let permit = semaphore.clone().acquire_owned();
                let node = node.clone();

                tokio::spawn(async move {
                    let _permit = permit.await.ok()?;

                    if addr == node.bind_addr {
                        return None;
                    }

                    // Quick TCP check
                    match timeout(Duration::from_millis(200), TcpStream::connect(addr)).await {
                        Ok(Ok(_)) => Some(addr),
                        _ => None,
                    }
                })
            })
            .collect();

        // Gather results
        for result in join_all(scan_tasks).await {
            if let Ok(Some(addr)) = result {
                discovered.insert(addr);
            }
        }

        Ok(discovered)
    }

    async fn discover_local_network(&self) -> Result<HashSet<SocketAddr>, NodeError> {
        let mut discovered = HashSet::new();
        let port = self.bind_addr.port();

        // Scan common local subnets
        for &subnet in &["192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/24"] {
            if let Ok(net) = subnet.parse::<Ipv4Net>() {
                // Fast port scan using socket2
                for host in net.hosts().take(255) {
                    let addr = SocketAddr::new(IpAddr::V4(host), port);

                    if addr != self.bind_addr {
                        // Create non-blocking socket for faster scanning
                        let socket =
                            match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
                                Ok(socket) => socket,
                                Err(_) => continue,
                            };

                        if socket.set_nonblocking(true).is_err() {
                            continue;
                        }

                        // Try to connect without blocking
                        match socket.connect(&addr.into()) {
                            Ok(_) => {
                                discovered.insert(addr);
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    // This might be a valid peer - check with a full TCP connection.
                                    // Bound the probe: an untimed connect to a filtered/black-hole
                                    // host hangs for the OS SYN-retry default (tens of seconds), and
                                    // this scan walks hundreds of addresses sequentially.
                                    if timeout(Duration::from_millis(300), TcpStream::connect(addr))
                                        .await
                                        .map(|r| r.is_ok())
                                        .unwrap_or(false)
                                    {
                                        discovered.insert(addr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(discovered)
    }

    async fn discover_from_existing_peers(&self) -> Result<HashSet<SocketAddr>, NodeError> {
        let mut discovered = HashSet::new();
        // THE 2026-07-08 NETWORK-WIDE WEDGE: this used to hold the peers READ guard
        // across the whole join_all network fan-out. One unresponsive peer (dead NAT
        // socket) kept the guard alive indefinitely; tokio's fair RwLock then parked
        // the first queued WRITER and, behind it, EVERY later reader — mine-prep's
        // first await, info's network section, the publisher's converge — freezing
        // the node (and the beacon, when it was the publisher) until restart.
        // Snapshot the addresses under a short guard, drop it, THEN query, and bound
        // every query so the fan-out itself always terminates.
        let addrs: Vec<SocketAddr> = {
            let peers = self.peers.read().await;
            peers.keys().copied().collect()
        };

        // Bounded concurrency, same as every other fan-out in this file (the
        // broadcasts cap at 10): uncapped, this opened one encrypted session per
        // table entry simultaneously.
        let semaphore = Arc::new(Semaphore::new(10));
        let futures: Vec<_> = addrs
            .into_iter()
            .map(|addr| {
                let semaphore = Arc::clone(&semaphore);
                async move {
                    let _permit = semaphore.acquire_owned().await.ok()?;
                    timeout(Duration::from_secs(5), self.request_peer_list(addr))
                        .await
                        .ok()
                        .and_then(|inner| inner.ok())
                }
            })
            .collect();
        for peer_list in join_all(futures).await.into_iter().flatten() {
            discovered.extend(peer_list);
        }

        Ok(discovered)
    }

    async fn discover_external_addresses(
        &self,
        stun_servers: &[&str],
    ) -> Result<(Option<IpAddr>, Option<IpAddr>), NodeError> {
        let mut v4_addr = None;
        let mut v6_addr = None;

        for &server in stun_servers {
            match self.perform_stun_request(server).await {
                Ok(IpAddr::V4(ip)) => v4_addr = Some(IpAddr::V4(ip)),
                Ok(IpAddr::V6(ip)) => v6_addr = Some(IpAddr::V6(ip)),
                Err(_) => continue,
            }

            // Break once we have both addresses or at least one
            if v4_addr.is_some() || v6_addr.is_some() {
                break;
            }
        }

        Ok((v4_addr, v6_addr))
    }

    async fn perform_stun_request(&self, server: &str) -> Result<IpAddr, NodeError> {
        const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

        // Create UDP socket for STUN
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let mut transaction_id = [0u8; 12];
        thread_rng().fill(&mut transaction_id);

        // Create STUN request
        let mut msg = vec![
            0x00,
            0x01, // Message Type: Binding Request
            0x00,
            0x00, // Message Length
            // Magic Cookie
            (STUN_MAGIC_COOKIE >> 24) as u8,
            (STUN_MAGIC_COOKIE >> 16) as u8,
            (STUN_MAGIC_COOKIE >> 8) as u8,
            STUN_MAGIC_COOKIE as u8,
        ];
        msg.extend_from_slice(&transaction_id);

        // Send request with timeout
        socket.send_to(&msg, server).await?;

        // Receive response with timeout
        let mut buf = [0u8; 512];
        let (size, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await??;

        // Parse STUN response, binding it to the request's transaction id.
        Self::parse_stun_response(&buf[..size], &transaction_id)
    }

    fn parse_stun_response(data: &[u8], expected_txid: &[u8; 12]) -> Result<IpAddr, NodeError> {
        // RFC 5389 header: type(2) + length(2) + magic cookie(4) + transaction id(12).
        if data.len() < 20 {
            return Err(NodeError::Network("Invalid STUN response".into()));
        }

        // Reject spoofed / unsolicited responses: an off-path attacker source-spoofing
        // the STUN server (or a hostile server) could otherwise feed us a forged public
        // address. The magic cookie and the 96-bit transaction id must match the request.
        if data[4..8] != STUN_MAGIC_COOKIE.to_be_bytes() || &data[8..20] != expected_txid {
            return Err(NodeError::Network(
                "STUN response cookie / transaction id mismatch".into(),
            ));
        }

        let mut pos = 20;
        while pos + 4 <= data.len() {
            let attr_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
            let attr_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);

            if attr_type == 0x0020 || attr_type == 0x8020 {
                // XOR-MAPPED-ADDRESS for IPv4 is exactly 8 bytes: family(1) +
                // reserved(1) + port(2) + address(4). Require that exact length AND that
                // the 4 address bytes are in bounds before indexing. The old
                // `pos + 8 + attr_len` guard passed for attr_len == 0 and then read
                // data[pos + 8 ..= pos + 11] out of bounds — a remote panic (DoS).
                if attr_len == 8 && pos + 12 <= data.len() {
                    let ip_family = data[pos + 5];
                    if ip_family == 0x01 {
                        // IPv4
                        let xor_ip = ((data[pos + 8] as u32) << 24)
                            | ((data[pos + 9] as u32) << 16)
                            | ((data[pos + 10] as u32) << 8)
                            | (data[pos + 11] as u32);
                        let ip = xor_ip ^ STUN_MAGIC_COOKIE;

                        let ip_addr = Ipv4Addr::from((ip).to_be_bytes());
                        return Ok(IpAddr::V4(ip_addr));
                    } else if ip_family == 0x02 { // IPv6
                         // Implement IPv6 if needed
                    }
                }
            }

            pos += 4 + attr_len;
        }

        Err(NodeError::Network(
            "No valid IP found in STUN response".into(),
        ))
    }

    //----------------------------------------------------------------------
    // NAT Traversal
    //----------------------------------------------------------------------

    pub async fn initialize_tcp_nat_traversal(&self) -> Result<TcpNatConfig, NodeError> {
        // Setup port mapping
        let mapping = self.setup_port_mapping(self.bind_addr.port()).await?;

        // Create simplified config
        let config = TcpNatConfig {
            external_port: mapping.external_port.unwrap_or(self.bind_addr.port()),
            supports_upnp: mapping.upnp,
            supports_nat_pmp: mapping.nat_pmp,
            connect_timeout: Duration::from_secs(5),
            mapping_lifetime: Duration::from_secs(3600),
            max_retries: 3,
        };

        Ok(config)
    }

    pub async fn tcp_hole_punch(
        &self,
        addr: SocketAddr,
        config: &TcpNatConfig,
    ) -> Result<(), NodeError> {
        let mut retries = 0u64;
        while retries < config.max_retries as u64 {
            if timeout(config.connect_timeout, TcpStream::connect(addr))
                .await
                .is_ok()
            {
                return Ok(());
            }

            retries += 1;
            sleep(Duration::from_millis(100 * retries)).await;
        }

        Err(NodeError::Network("TCP hole punching failed".into()))
    }

    async fn setup_port_mapping(&self, port: u16) -> Result<PortMappingResult, NodeError> {
        // Configure the TCP socket for hole punching
        let socket = self
            .configure_tcp_socket(TcpStream::connect(format!("0.0.0.0:{}", port)).await?)
            .await?;

        // Set socket options
        let sock = Socket::from(socket.into_std()?);
        sock.set_reuse_address(true)?;

        // Set non-blocking to allow concurrent connections
        sock.set_nonblocking(true)?;

        // Configure keepalive
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(15));

        sock.set_tcp_keepalive(&keepalive)?;

        let enable_upnp = std::env::var("ALPHANUMERIC_ENABLE_UPNP")
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);

        let mut upnp_ok = false;
        let mut external_port = None;

        if enable_upnp {
            let bind_ip = match self.bind_addr.ip() {
                IpAddr::V4(ip) if ip != Ipv4Addr::UNSPECIFIED => IpAddr::V4(ip),
                IpAddr::V6(ip) if !ip.is_unspecified() => IpAddr::V6(ip),
                _ => Node::get_bind_address().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            };

            let mapping_res = tokio::task::spawn_blocking(move || {
                let gateway = search_gateway(Default::default())
                    .map_err(|e| NodeError::Network(format!("UPnP search error: {}", e)))?;
                let socket = SocketAddr::new(bind_ip, port);
                gateway
                    .add_port(
                        PortMappingProtocol::TCP,
                        port,
                        socket,
                        3600,
                        "alphanumeric node",
                    )
                    .map_err(|e| NodeError::Network(format!("UPnP add port error: {}", e)))?;
                Ok::<(), NodeError>(())
            })
            .await;

            match mapping_res {
                Ok(Ok(_)) => {
                    upnp_ok = true;
                    external_port = Some(port);
                }
                Ok(Err(e)) => {
                    if Self::upnp_explicitly_enabled() {
                        warn!("UPnP port mapping failed: {}", e);
                    } else {
                        debug!("UPnP port mapping failed: {}", e);
                    }
                }
                Err(e) => {
                    if Self::upnp_explicitly_enabled() {
                        warn!("UPnP mapping task failed: {}", e);
                    } else {
                        debug!("UPnP mapping task failed: {}", e);
                    }
                }
            }
        }

        Ok(PortMappingResult {
            upnp: upnp_ok,
            nat_pmp: false,
            external_port,
        })
    }

    async fn configure_tcp_socket(&self, socket: TcpStream) -> Result<TcpStream, NodeError> {
        // Set TCP socket options for better P2P connectivity
        socket.set_nodelay(true)?;

        // Get socket to configure using socket2
        let std_socket = socket.into_std()?;
        let socket2_socket = Socket::from(std_socket);

        // Set additional socket options
        socket2_socket.set_keepalive(true)?;
        socket2_socket.set_nonblocking(true)?;

        // Convert back to TcpStream
        Ok(TcpStream::from_std(socket2_socket.into())?)
    }

    //----------------------------------------------------------------------
    // Main P2P Messaging Logic
    //----------------------------------------------------------------------

    pub async fn start(&self) -> Result<(), NodeError> {
        info!("Starting node on {}", self.bind_addr);

        // Public full-history node (role flag): a reachable node serves genesis..tip to peers
        // over GetBlocks, so fresh nodes can bootstrap from it instead of only the gateway
        // snapshot. Serving already works unconditionally; this only logs the role and warns
        // if the bind address isn't publicly reachable (so operators publish a routable one).
        if Self::public_full_history_node_enabled() {
            info!("Public full-history node: serving GetBlocks [0..tip] to peers");
            if self.bind_addr.ip().is_loopback() || self.bind_addr.ip().is_unspecified() {
                warn!(
                    "Public full-history node bound to {} — not publicly reachable. Publish a routable address via ALPHANUMERIC_PUBLIC_IP / ALPHANUMERIC_BIND_IP / ALPHANUMERIC_PORT (or a cloudflared/tailscale tunnel) so fresh nodes can reach you.",
                    self.bind_addr
                );
            }
        }

        if Self::kademlia_fallback_enabled() {
            self.initialize_p2p().await?;
        } else {
            debug!("Kademlia discovery fallback disabled; skipping libp2p swarm startup");
        }

        // Start stats API (optional)
        if std::env::var("ALPHANUMERIC_STATS_ENABLED")
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true)
        {
            if let Err(e) = self.start_stats_server().await {
                if Self::stats_server_explicitly_enabled() {
                    warn!("Stats server failed to start: {}", e);
                } else {
                    debug!("Stats server failed to start: {}", e);
                }
            }
        }

        // Explorer API (opt-in): read-only JSON for self-hosted explorers and
        // integrations. Zero cost when ALPHANUMERIC_EXPLORER_API is unset — no
        // task, no socket. A failure here is loud (the operator asked for it)
        // but never blocks the node from starting.
        if let Err(e) = self.start_explorer_server().await {
            warn!("Explorer API failed to start: {}", e);
        }

        // Keep libp2p swarm events flowing only when a swarm was initialized.
        if self.p2p_swarm.lock().await.is_some() {
            let p2p_node = self.clone();
            spawn_supervised("p2p-event-pump", move || {
                let p2p_node = p2p_node.clone();
                async move {
                    loop {
                        if let Err(e) = p2p_node.handle_p2p_events().await {
                            warn!("P2P event pump cycle failed: {}", e);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        } else {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                }
            });
        }

        // Create message processing channel. The receiver lives behind an
        // Arc<Mutex<..>> so the supervised pump below can be restarted after a
        // panic without losing the channel — a future-owned receiver dies with
        // the panicked task, closing the queue for every connection forever.
        let (msg_tx, msg_rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        let msg_rx = Arc::new(Mutex::new(msg_rx));
        let node = self.clone();

        // Start connection handler for incoming connections
        if let Some(listener) = &self.listener {
            let listener_clone = Arc::clone(listener);
            let node_clone = node.clone();
            let msg_tx_clone = msg_tx.clone();

            // spawn_logged (not supervised): the loop owns the bound listener, which
            // a restart cannot recreate — but a panic here must at least be LOUD,
            // since it means the node silently stops accepting connections.
            spawn_logged("tcp-accept", async move {
                info!("Starting connection handler on {}", node_clone.bind_addr);

                // Connection limiter to prevent DOS
                let connection_limiter = Arc::new(Semaphore::new(node_clone.max_connections));

                loop {
                    // Acquire a connection slot before accepting another socket.
                    match connection_limiter.clone().acquire_owned().await {
                        Ok(permit) => {
                            match listener_clone.accept().await {
                                Ok((stream, addr)) => {
                                    info!("New incoming connection from {}", addr);

                                    // Configure TCP socket. Best-effort: NODELAY is a
                                    // latency nicety — dropping an otherwise-usable
                                    // connection over it was needlessly unforgiving.
                                    if let Err(e) = stream.set_nodelay(true) {
                                        warn!("Failed to set TCP_NODELAY for {}: {}", addr, e);
                                    }

                                    // Handle connection in a separate task
                                    let node = node_clone.clone();
                                    let tx = msg_tx_clone.clone();
                                    let permit_owned = permit;

                                    tokio::spawn(async move {
                                        let _permit = permit_owned;
                                        match node.handle_connection(stream, addr, tx).await {
                                            Ok(_) => {
                                                info!("Connection handler completed successfully for {}", addr);
                                            }
                                            Err(e) => {
                                                warn!("Connection error from {}: {}", addr, e);
                                                node.record_peer_failure(addr).await;
                                            }
                                        }

                                        // Permit is automatically dropped here
                                    });
                                }
                                Err(e) => {
                                    error!("Accept error: {}", e);
                                    drop(permit);
                                    sleep(Duration::from_secs(1)).await;
                                }
                            }
                        }
                        Err(e) => {
                            // acquire_owned errors only when the semaphore is CLOSED —
                            // unreachable for this locally-owned limiter, but if it ever
                            // happens the listener can never accept again: die loudly
                            // (spawn_logged reports it) instead of spinning a warn loop
                            // at 5Hz forever.
                            error!("Connection limiter closed (accept loop exiting): {}", e);
                            return;
                        }
                    }
                }
            });
        } else {
            info!("No listener configured - node will not accept incoming connections");
        }

        // Start network maintenance in the background. Supervised: if this loop
        // dies, dead peers are never evicted and the runtime maps grow unbounded.
        let node_clone = node.clone();
        spawn_supervised("network-maintenance", move || {
            let node_clone = node_clone.clone();
            async move {
                let mut maintenance_interval = interval(Duration::from_secs(MAINTENANCE_INTERVAL));
                maintenance_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

                loop {
                    maintenance_interval.tick().await;

                    if let Err(e) = node_clone.maintain_peer_connections().await {
                        warn!("Peer maintenance error: {}", e);
                    }
                    node_clone.cleanup_outbound_connections().await;
                    node_clone.prune_runtime_maps().await;
                    node_clone.prune_validation_cache();
                }
            }
        });

        // Initial discovery boost via serverless gateway
        let node_clone = node.clone();
        tokio::spawn(async move {
            sleep(Duration::from_secs(3)).await;
            if let Err(e) = node_clone.connect_discovery_peers(8).await {
                debug!("Discovery connect deferred: {}", e);
            }
        });

        // Periodic announce to discovery service. The loop ticks FAST
        // (ANNOUNCE_RETRY_SECS) and lets announce_to_discovery's internal gate own
        // the cadence — full interval after a success, retry cadence after a
        // failure — same pattern as the header-snapshot loop. Ticking at the slow
        // interval meant one failed announce (gateway blip) left this node off the
        // roster until the NEXT 300s tick. The relay tip refresh is NOT retried
        // fast: it keeps its original interval via the tick counter (post storms
        // are the known failure mode there, 2026-07-08).
        let node_clone = node.clone();
        spawn_logged("discovery-announce", async move {
            let relay_every = (Self::announce_interval_secs() / ANNOUNCE_RETRY_SECS.max(1)).max(1);
            let mut tick: u64 = 0;
            let mut announce_interval = interval(Duration::from_secs(ANNOUNCE_RETRY_SECS));
            announce_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                announce_interval.tick().await;
                // `is_multiple_of` requires a newer compiler than the crate's Rust 1.70 MSRV.
                #[allow(clippy::manual_is_multiple_of)]
                if tick % relay_every == 0 {
                    if let Err(e) = node_clone.ensure_public_tip_relayed().await {
                        debug!("Public relay tip refresh failed: {}", e);
                    }
                }
                tick = tick.wrapping_add(1);
                if let Err(e) = node_clone.announce_to_discovery().await {
                    debug!("Announce error: {}", e);
                }
            }
        });

        // Periodic header snapshot submissions. The loop ticks FAST (5s) and lets
        // post_header_snapshot's internal gating decide: normally the 30s wall-clock
        // interval, but during racing the >=8-block delta trigger fires early so the
        // site's VERIFIED height stays within ~8 blocks of LATEST instead of drifting
        // 30-50 behind at a 5s block time. Ticking at the old 30s starved the delta
        // check of chances to run — the gate must own the cadence, not the timer.
        if Self::public_header_snapshots_enabled() {
            let node_clone = node.clone();
            spawn_supervised("header-snapshots", move || {
                let node_clone = node_clone.clone();
                async move {
                    let mut header_interval = interval(Duration::from_secs(5));
                    header_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    loop {
                        header_interval.tick().await;
                        if let Err(e) = node_clone.post_header_snapshot().await {
                            debug!("Header snapshot error: {}", e);
                        }
                    }
                }
            });
        }

        // Event-driven tip beacon: the publisher pushes the tiny signed beacon on
        // EVERY tip change (append or reorg) by subscribing to the in-process
        // ChainTipSignal — no timer, per-block fresh — so a new block is visible
        // to every client within one edge-cached beacon poll.
        if Self::public_header_snapshots_enabled() {
            // Supervised: this loop IS the network's beacon — if it dies on the
            // publisher, the signed tip freezes for every client until a restart.
            let node_clone = node.clone();
            spawn_supervised("tip-beacon", move || {
                let node_clone = node_clone.clone();
                async move {
                    let mut rx = { node_clone.blockchain.read().await.subscribe_tip_changes() };
                    // Heartbeat so the beacon never expires during idle (no mining): it
                    // is re-posted on every tip change AND at least this often, keeping
                    // the network's live tip visible to anyone who opens their client.
                    let mut heartbeat = interval(Duration::from_secs(60));
                    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    if let Err(e) = node_clone.post_tip_beacon().await {
                        debug!("Initial tip beacon post: {}", e);
                    }
                    loop {
                        tokio::select! {
                            changed = rx.changed() => {
                                if changed.is_err() {
                                    return;
                                }
                            }
                            _ = heartbeat.tick() => {}
                        }
                        if let Err(e) = node_clone.post_tip_beacon().await {
                            debug!("Tip beacon post: {}", e);
                        }
                    }
                }
            });
        }

        // Periodic stats snapshot submissions (push)
        if Self::public_stats_snapshots_enabled() {
            let node_clone = node.clone();
            spawn_supervised("stats-snapshots", move || {
                let node_clone = node_clone.clone();
                async move {
                    let mut stats_interval =
                        interval(Duration::from_secs(Self::stats_snapshot_interval_secs()));
                    stats_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    loop {
                        stats_interval.tick().await;
                        if let Err(e) = node_clone.post_stats_snapshot().await {
                            debug!("Stats snapshot error: {}", e);
                        }
                    }
                }
            });
        }

        // Notice-only client-version check (all nodes). The first interval tick fires
        // immediately, giving a startup check, then repeats every VERSION_CHECK_INTERVAL_SECS.
        // Notice only — never auto-updates.
        {
            let node_clone = node.clone();
            spawn_supervised("version-check", move || {
                let node_clone = node_clone.clone();
                async move {
                    let mut version_check =
                        interval(Duration::from_secs(VERSION_CHECK_INTERVAL_SECS));
                    version_check.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    loop {
                        version_check.tick().await;
                        node_clone.check_client_version_and_warn().await;
                    }
                }
            });
        }

        // Periodic peer cache persistence + PEX address-book refresh. PEX runs in
        // normal operation (not just the gateway-down fallback): GetPeers is a
        // read-only request to ≤2 live peers per 120s tick — no dialing, no
        // topology change — and it fattens the persisted address book beyond our
        // own connections, which is what a node restarts on during a gateway
        // outage. Live peers keep priority in the 200-slot file; PEX entries fill
        // the remainder.
        let node_clone = node.clone();
        spawn_logged("peer-cache-pex", async move {
            let mut cache_interval = interval(Duration::from_secs(120));
            cache_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let mut save_failure_logged = false;
            loop {
                cache_interval.tick().await;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                // Age out stale PEX entries FIRST so the book can never freeze at
                // the cap holding dead/rotated addresses forever.
                {
                    let mut book = node_clone.pex_addr_book.write().await;
                    book.retain(|_, learned| now.saturating_sub(*learned) < PEX_ADDR_TTL_SECS);
                }
                let pex_targets: Vec<SocketAddr> = {
                    let peers = node_clone.peers.read().await;
                    peers.keys().copied().take(2).collect()
                };
                if !pex_targets.is_empty() {
                    let allow_private = Self::private_discovery_peers_allowed();
                    for target in pex_targets {
                        // Outer timeout: send_message_with_response can take 30s x 2
                        // attempts; this tick runs every 120s and must not serialize
                        // behind half-dead peers.
                        let Ok(Ok(list)) = tokio::time::timeout(
                            Duration::from_secs(PEX_REQUEST_TIMEOUT_SECS),
                            node_clone.request_peer_list(target),
                        )
                        .await
                        else {
                            continue;
                        };
                        let mut book = node_clone.pex_addr_book.write().await;
                        let mut inserted = 0usize;
                        for addr in list {
                            if inserted >= PEX_MAX_ADDRS_PER_RESPONSE {
                                break;
                            }
                            if addr == node_clone.bind_addr
                                || !Self::is_dialable_discovery_addr(&addr, allow_private)
                            {
                                continue;
                            }
                            // At cap, evict the oldest entry — the book rolls
                            // instead of freezing.
                            if !book.contains_key(&addr) && book.len() >= PEX_ADDR_BOOK_CAP {
                                if let Some(oldest) = book
                                    .iter()
                                    .min_by_key(|(_, learned)| **learned)
                                    .map(|(a, _)| *a)
                                {
                                    book.remove(&oldest);
                                }
                            }
                            book.insert(addr, now);
                            inserted += 1;
                        }
                    }
                }
                let mut peers: Vec<SocketAddr> = {
                    let peers = node_clone.peers.read().await;
                    let mut scored: Vec<(SocketAddr, f64)> = peers
                        .iter()
                        .map(|(addr, info)| (*addr, Self::score_peer_for_cache(info, now)))
                        .filter(|(_, score)| *score >= -5.0)
                        .collect();
                    scored
                        .sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                    scored.into_iter().take(200).map(|(addr, _)| addr).collect()
                };
                {
                    let book = node_clone.pex_addr_book.read().await;
                    for addr in book.keys() {
                        if peers.len() >= 200 {
                            break;
                        }
                        if !peers.contains(addr) {
                            peers.push(*addr);
                        }
                    }
                }
                match node_clone.save_peer_cache(&peers) {
                    Ok(()) => save_failure_logged = false,
                    Err(e) => {
                        // warn ONCE per failure streak — a broken cache silently
                        // no-ops the reboot-resilience fix, but a warn every 120s
                        // would be log spam.
                        if !save_failure_logged {
                            warn!("Peer cache save failing (address book will not survive restarts): {}", e);
                            save_failure_logged = true;
                        } else {
                            debug!("Peer cache save error: {}", e);
                        }
                    }
                }
            }
        });

        // Periodic backpressure metrics
        let metrics_node = node.clone();
        let metrics_tx = msg_tx.clone();
        tokio::spawn(async move {
            let mut metrics_interval = interval(Duration::from_secs(15));
            metrics_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                metrics_interval.tick().await;
                let remaining = metrics_tx.capacity();
                let in_flight = EVENT_QUEUE_CAPACITY.saturating_sub(remaining);
                let broadcast_len = metrics_node.tx.len();
                let receivers = metrics_node.tx.receiver_count();
                let peer_count = metrics_node.peers.read().await.len();

                if in_flight >= EVENT_QUEUE_WARN_THRESHOLD
                    || broadcast_len >= (EVENT_BROADCAST_CAPACITY * 8 / 10)
                {
                    warn!(
                        "Backpressure: event_queue={} broadcast_backlog={} peers={} receivers={}",
                        in_flight, broadcast_len, peer_count, receivers
                    );
                } else {
                    debug!(
                        "Backpressure: event_queue={} broadcast_backlog={} peers={} receivers={}",
                        in_flight, broadcast_len, peer_count, receivers
                    );
                }
            }
        });

        // Message processing loop — the SOLE consumer of the network event queue.
        // Supervised: this pump calls the whole message-handling surface, and an
        // unsupervised panic here silently backed the bounded queue up to capacity,
        // parking every connection task on its send — and with it the accept-loop
        // permits: the "node stops accepting connections" cascade.
        let node_clone = node.clone();
        let pump_rx = Arc::clone(&msg_rx);
        spawn_supervised("network-event-pump", move || {
            let node = node_clone.clone();
            let rx = Arc::clone(&pump_rx);
            async move {
                loop {
                    // Scope the lock to the recv itself: the handler must run
                    // unlocked so a restarted pump can always re-acquire.
                    let msg = { rx.lock().await.recv().await };
                    match msg {
                        Some(msg) => {
                            if let Err(e) = node.handle_network_event(msg).await {
                                error!("Error handling network event: {}", e);
                            }
                        }
                        // Channel closed (shutdown): clean exit, not restarted.
                        None => return,
                    }
                }
            }
        });

        // ONE-TIME DEEP RELAY HEAL. Normal per-block backfill only re-posts the last
        // ~32 blocks, so a hole deeper than that in the relay's history (blocks that
        // were dropped when they were first mined, e.g. under a rate-limit storm) is
        // NEVER refilled and permanently blocks the ancestor/reorg walk that lets a
        // node converge to the heaviest chain — the 2026-07-08 stall, where the
        // winning chain was un-walkable across ~70 missing middle heights. On startup
        // every node re-posts a DEEP window of its own history to the relay; a node
        // holding the heaviest chain thereby floods it back onto the shared relay so
        // ALL nodes can walk and converge to it (pure work-based resolution, no
        // authority fork). Cheap: re-posting an already-stored block is a SET NX
        // no-op gated by the WASM PoW check, and it runs once. Depth is generous by
        // default and env-tunable for a big recovery.
        let heal_node = node.clone();
        tokio::spawn(async move {
            sleep(Duration::from_secs(8)).await;
            let depth = std::env::var("ALPHANUMERIC_RELAY_DEEP_REPOST")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(512)
                .min(4096);
            if depth > 0 {
                info!(
                    "Deep relay heal: re-posting last {} blocks to refill any gaps",
                    depth
                );
                heal_node.post_recent_blocks_to_relay(depth).await;
            }
        });

        // Start block sync if needed after startup
        let node_clone = node.clone();
        tokio::spawn(async move {
            sleep(Duration::from_secs(5)).await; // Small delay to let connections establish
            if let Err(e) = node_clone.sync_with_network().await {
                if Node::is_expected_startup_sync_gap(&e) {
                    debug!("Initial sync deferred: {}", e);
                } else {
                    warn!("Initial sync failed: {}", e);
                }
            }
            if let Err(e) = node_clone.publish_local_tip().await {
                warn!("Initial post-sync publish failed: {}", e);
            }
        });

        // Periodic pending-tx re-announce. gossip_transaction fires ONCE at create
        // time — a tx submitted while this node had no mesh links or peers (a NAT'd
        // client right after boot, mid mesh churn) reached nobody and would otherwise
        // sit local-only until the sender mined it themselves, resurrecting the
        // pre-v7.6.8 behavior through a timing hole. Re-announcing is cheap and
        // idempotent: receivers dedup via their network bloom, duplicate mempool adds
        // are rejected, and the mesh send is a no-op with no links up.
        let regossip_node = node.clone();
        spawn_logged("pending-regossip", async move {
            let mut regossip_interval = interval(Duration::from_secs(45));
            regossip_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            regossip_interval.tick().await; // consume the immediate first tick
            loop {
                regossip_interval.tick().await;
                let pending = {
                    let bc = regossip_node.blockchain.read().await;
                    // Never re-announce a tx that already confirmed: re-gossiping one
                    // refills every peer's mempool with a replay-guard poison pill
                    // (each peer then wastes a full solve per mined block until their
                    // mempool cleans up). Evict instead — this loop is exactly where
                    // stale entries would otherwise get a megaphone.
                    let _ = bc.drop_confirmed_mempool_txs().await;
                    // Re-announce the FULL-signature form: the persisted pending records carry a
                    // truncated signature, and gossiping those makes peers defer the tx (they can't
                    // verify it) — the truncated-witness pathology. This accessor reads the mempool's
                    // full-signature copy (skipping any tx whose full signature is unavailable).
                    bc.get_pending_transactions_with_full_signatures()
                        .await
                        .unwrap_or_default()
                };
                // Small cap: the mempool is tiny on this network, and a pathological
                // backlog must not turn this loop into its own gossip storm.
                for tx in pending.into_iter().take(8) {
                    regossip_node.gossip_transaction(&tx).await;
                }
            }
        });

        // (The old standalone 20s "catch-up safety net" loop was deleted: the
        // beacon-watch loop below already runs the identical converge on its safety
        // tick — now every 20s for clients, matching what the deleted loop did — and
        // the runtime reconcile loop in main.rs is the third, escalation-owning
        // copy. Three loops fetching the same beacon to run the same converge was
        // pure duplicate chatter: ~3 gateway GETs/min and one redundant converge
        // pass, at zero staleness cost.)

        // LIVE beacon-watch sync. Poll the tiny edge-cached tip beacon every ~2s;
        // a cache HIT costs the origin/Redis nothing, so this stays O(1) at any
        // client count. Only when the beacon's VERSION moves do we fetch the delta
        // blocks and apply them — so there is no redundant pulling when nothing
        // changed. Applying a block fires the in-process ChainTipSignal, which
        // drives mining-on-tip and wallet notifications for free. A slow full pull
        // is kept as a safety net in case a beacon post was missed.
        {
            let node_clone = node.clone();
            // The publisher INGESTS blocks that miners POST to the relay — nothing
            // pushes those to it (miners are NAT'd) — so it pulls the relay on a
            // FAST timer (~1s) and republishes the beacon that fans out to every
            // client, keeping propagation under the block time so miners converge
            // instead of forking. A plain client is driven by the beacon and only
            // does a rare safety pull, so it never blind-polls the relay.
            let is_publisher = Self::public_header_snapshots_enabled();
            let tick_secs = if is_publisher {
                1
            } else {
                BEACON_POLL_INTERVAL_SECS
            };
            // 20 for clients (was 30): this safety tick absorbed the deleted
            // standalone 20s catch-up loop — same converge cadence, one fewer
            // beacon fetch and converge pass per cycle.
            let safety_secs = if is_publisher { 1 } else { 20 };
            // SUPERVISED, not merely logged: this loop owns the frozen-tip escape
            // (the only way out of the verification-floor deadlock), so if it dies
            // the node keeps reporting healthy — locks fine, heartbeat ticking —
            // while never syncing again. It captures only a node handle and
            // loop-local state, so restarting it is safe.
            spawn_supervised("beacon-watch", move || {
                let node_clone = node_clone.clone();
                async move {
                let mut ticker = interval(Duration::from_secs(tick_secs));
                // Wake-from-sleep: where Instant advances across an OS suspend (Windows),
                // the default Burst behavior replays every slept-through tick back-to-back
                // — hours of beacon polls and converge calls fired in seconds. One
                // immediate tick, then the normal cadence.
                ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
                let mut last_version: u64 = u64::MAX;
                let mut ticks_since_full: u64 = 0;
                let mut publisher_bootstrap_strikes: u32 = 0;
                let mut publisher_relay_gap_strikes: u32 = 0;
                let mut tick_no: u64 = 0;
                let safety_ticks = (safety_secs / tick_secs).max(1);
                loop {
                    ticker.tick().await;
                    tick_no += 1;

                    // Publisher idle throttle: when the local tip hasn't moved in over
                    // 2 minutes nobody is mining — probing the relay every second is
                    // ~86k edge requests/day of pure idle burn. Probe every 5th tick
                    // instead; the first block after an idle stretch is noticed within
                    // <=5s, which is fine when blocks were minutes apart anyway. Full
                    // 1s cadence resumes automatically once blocks flow again.
                    if is_publisher {
                        let tip_age = {
                            let bc = node_clone.blockchain.read().await;
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            bc.get_last_block()
                                .map(|b| now.saturating_sub(b.timestamp))
                                .unwrap_or(0)
                        };
                        // `is_multiple_of` requires a newer compiler than the crate's Rust 1.70 MSRV.
                        #[allow(clippy::manual_is_multiple_of)]
                        if tip_age > 120 && tick_no % 5 != 0 {
                            continue;
                        }
                    }

                    // The publisher is the SOURCE of the beacon: fetching its own
                    // beacon back through the CDN every second was another ~86k wasted
                    // edge requests/day. Only clients follow the beacon.
                    let beacon = if is_publisher {
                        None
                    } else {
                        node_clone.fetch_tip_beacon().await
                    };
                    let beacon_changed = beacon.map(|b| b.version != last_version).unwrap_or(false);

                    ticks_since_full += 1;
                    let safety_due = ticks_since_full >= safety_ticks;
                    if !beacon_changed && !safety_due {
                        continue; // nothing new — no fetch, no origin/Redis touch
                    }
                    ticks_since_full = 0;
                    if let Some(b) = beacon {
                        last_version = b.version;
                    }

                    // The PUBLISHER and a CLIENT have opposite relationships to the
                    // beacon, so they sync differently:
                    //
                    // * Publisher: it is the SOURCE of the beacon. Miners POST their
                    //   blocks to the relay, which therefore runs AHEAD of the
                    //   publisher's tip; the publisher must INGEST those blocks (a
                    //   forward relay pull), which advances its tip and — via the tip
                    //   signal — posts the fresh beacon that fans out to everyone.
                    //   converge_to_canonical(own_beacon) would be a no-op (it already
                    //   holds its own beacon), so it must pull the relay directly. No
                    //   extra publish: the ingested blocks are already on the relay.
                    //
                    // * Client: it FOLLOWS the beacon. converge_to_canonical drives it
                    //   to the authoritative tip from any state — forward-stream when
                    //   behind, reorg when forked — and never re-publishes the canonical
                    //   blocks it adopts (that would echo-storm the relay).
                    if is_publisher {
                        // Publisher: converge to the HEAVIEST chain the relay holds
                        // (fork-aware). This ingests miner blocks forward AND reorgs off a
                        // losing fork the publisher may have latched onto during a race —
                        // so it can never get stuck on a dead branch while miners extend a
                        // heavier one (which would freeze the beacon for the whole network).
                        //
                        // P2P GAP-FILL FALLBACK: at high block rates the relay can develop
                        // ancestry HOLES (posts dropped by rate limits / lost requests), and
                        // then NO relay candidate is walkable — converge keeps returning
                        // BeaconStale while miners (who share blocks peer-to-peer) sprint
                        // ahead and the beacon crawls (2026-07-08 evening stall). The miners
                        // ARE our peers, so after repeated walk failures with the relay head
                        // visibly ahead, pull the missing span directly over p2p GetBlocks
                        // (fully validated, existing path) and let converge resume.
                        let outcome = node_clone.converge_to_relay_tip().await;
                        if matches!(outcome, Converge::BeaconStale) {
                            publisher_relay_gap_strikes += 1;
                        } else {
                            publisher_relay_gap_strikes = 0;
                        }
                        if publisher_relay_gap_strikes >= 10 {
                            publisher_relay_gap_strikes = 0;
                            let behind = match node_clone.fetch_relay_head().await {
                                Some(head) => {
                                    let local = {
                                        let bc = node_clone.blockchain.read().await;
                                        bc.get_latest_block_index() as u32
                                    };
                                    head.height > local.saturating_add(2)
                                }
                                None => false,
                            };
                            if behind {
                                warn!("Publisher: relay ancestry unwalkable while behind; pulling gap from p2p peers");
                                if let Err(e) = node_clone.sync_with_network().await {
                                    debug!("p2p gap-fill sync failed: {}", e);
                                }
                            }
                        }
                        match outcome {
                            Converge::Converged | Converge::AtTipAhead | Converge::Progressed => {
                                publisher_bootstrap_strikes = 0;
                            }
                            // Transient — don't count toward a restart.
                            Converge::BeaconStale => {}
                            // A candidate branch failed validation (incompatible-client
                            // fork). It is memoized dead inside converge_to_relay_tip;
                            // never a strike — the live branch gets tried next tick.
                            Converge::BranchInvalid => {}
                            // Genuine deep divergence the publisher cannot converge
                            // incrementally (>64-block local rewrite, or needed history
                            // aged out of the relay). Left unhandled this FREEZES the beacon
                            // for the whole network. converge_to_relay_tip targets the
                            // relay's heaviest tip, so NeedsBootstrap here already implies
                            // "a heavier chain exists that we can't reach forward" — after 2
                            // consecutive such ticks, restart into a fresh bootstrap from
                            // that chain (launchd respawns us; the imported snapshot carries
                            // tip-64 as the trusted checkpoint, so finality is preserved). A
                            // single blip never triggers it.
                            Converge::NeedsBootstrap => {
                                publisher_bootstrap_strikes += 1;
                                warn!(
                                    "Publisher: relay chain diverged below the reorg window (strike {}/2); will re-bootstrap on 2",
                                    publisher_bootstrap_strikes
                                );
                                if publisher_bootstrap_strikes >= 2 {
                                    // TIER 2 (gateway-independent): before restarting to
                                    // re-bootstrap from the gateway snapshot, try to
                                    // reconstruct the canonical chain directly from a seed
                                    // peer over GetBlocks (same validation, beacon-anchored).
                                    // No-op if no seed is configured -> falls through to the
                                    // original restart, so behaviour is unchanged there.
                                    match node_clone.sync_full_history_from_peer(false).await {
                                        Converge::Converged
                                        | Converge::AtTipAhead
                                        | Converge::Progressed => {
                                            publisher_bootstrap_strikes = 0;
                                            info!("Publisher: recovered via peer full-history sync; not restarting");
                                        }
                                        _ => {
                                            warn!("Publisher: restarting to re-bootstrap onto the canonical chain");
                                            // Persist a hard force-rebootstrap marker BEFORE exiting (M10):
                                            // otherwise the restart's boot reconcile trusts our own stale
                                            // manifest, skips the re-bootstrap, re-diverges, and respawns
                                            // in a loop with the beacon frozen network-wide. Cooldown-guarded.
                                            let _ = node_clone.schedule_force_rebootstrap_hard(
                                                "publisher: relay chain diverged below reorg window",
                                            );
                                            // Nonzero exit so systemd Restart=on-failure / launchd actually
                                            // respawns us (M9) — exit(0) reads as a clean stop and strands the node.
                                            std::process::exit(3);
                                        }
                                    }
                                }
                            }
                        }
                    } else if let Some(b) = beacon {
                        // FROZEN-TIP CURE. A node that cannot apply block H+1 — its
                        // witnesses are unobtainable because the body it received is
                        // witness-short — used to deadlock: H+1 stays above the node's
                        // own verification floor forever, so it demands full witnesses
                        // forever, even once the network has buried it by hundreds of
                        // blocks. Observed live: the explorer frozen for 80 minutes.
                        //
                        // The cure lives in converge_to_canonical, which receipt-trusts
                        // a block only once that block is transitively committed by the
                        // signed beacon (walked hash-by-hash down from beacon.hash) AND
                        // buried a full reorg margin below it. Burial is proven per
                        // block, against a hash — never inferred from the beacon HEIGHT.
                        // Recovery is also PROMPT: it needs no stall timer, because
                        // what makes it safe is the pinning, not the waiting.
                        //
                        // Nothing here advances the checkpoint. Finality trails history
                        // this node has actually applied; a height alone never moves it
                        // (see raise_trusted_checkpoint's tip clamp).
                        match node_clone.converge_to_canonical(&b).await {
                            Converge::Converged | Converge::AtTipAhead => {}
                            Converge::Progressed => {
                                debug!("Live sync: progressed toward beacon {}", b.height);
                            }
                            Converge::NeedsBootstrap => {
                                warn!(
                                    "Divergence below finality window at beacon {}; trying peer full-history sync",
                                    b.height
                                );
                                // TIER 2: reconstruct the canonical chain from a seed peer —
                                // or any CONNECTED peer (a seedless client, the common case,
                                // previously made this a no-op and fell straight through to
                                // "gateway bootstrap required"). Safety is source-independent:
                                // the sync's STEP-2 signed-beacon tip probe and per-block
                                // ingest validation gate every peer, and the single-flight
                                // guard keeps this from overlapping the idle-loop heal.
                                match node_clone.sync_full_history_from_peer(true).await {
                                    Converge::Converged
                                    | Converge::AtTipAhead
                                    | Converge::Progressed => {
                                        info!("Client: recovered canonical chain via peer full-history sync");
                                    }
                                    _ => {
                                        warn!("Client: peer full-sync unavailable; gateway bootstrap required");
                                    }
                                }
                            }
                            Converge::BeaconStale => {}
                            // The signed beacon pointed at a branch our engine rejects
                            // (should not happen with an honest publisher; possible
                            // transiently around its own reorg). Wait for the next
                            // beacon rather than escalate.
                            Converge::BranchInvalid => {
                                debug!(
                                    "Beacon branch failed local validation; awaiting next beacon"
                                );
                            }
                        }
                    }
                }
                }
            });
        }

        // Bring up the WebRTC mesh (opt-in via ALPHANUMERIC_WEBRTC_MESH): direct P2P DataChannels to
        // NAT'd peers, signaled through the gateway, so blocks gossip node-to-node instead of only
        // through the bounded gateway relay. No-op unless the feature is compiled AND the flag is set.
        #[cfg(feature = "webrtc_mesh")]
        self.spawn_webrtc_mesh();

        // LOCK WATCHDOG. Two distinct forever-wedges shipped in this codebase before
        // being found (peers guard held across a join_all fan-out; an as-yet-unlocated
        // blockchain-lock holder on 2026-07-08 that froze the publisher hourly). Each
        // froze mining/status/beacon until a manual restart. The watchdog probes both
        // core locks once a minute; two consecutive failed probes mean the node is
        // wedged beyond recovery, so a HEADLESS node (publisher — launchd/systemd
        // respawns it) exits to self-heal, capping any future wedge at ~3 minutes.
        // Interactive clients only log loudly (killing a console with a typing user
        // is worse than a degraded session). The probe log says WHICH lock wedged —
        // the breadcrumb for root-causing any holder we haven't found yet.
        {
            let wd = self.clone();
            let headless = std::env::var("ALPHANUMERIC_HEADLESS")
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false);
            // Supervised: the watchdog is the self-heal mechanism — its own silent
            // death would remove the safety net without anyone noticing.
            spawn_supervised("lock-watchdog", move || {
                let wd = wd.clone();
                async move {
                    let mut strikes: u32 = 0;
                    // Taken ONCE, before anything can wedge: an Arc to the chain's liveness
                    // counter, readable without the lock this task exists to judge.
                    let progress = wd.blockchain.read().await.chain_progress_handle();
                    let mut last_progress = progress.load(std::sync::atomic::Ordering::Relaxed);
                    loop {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        let chain_ok = timeout(Duration::from_secs(10), wd.blockchain.read())
                            .await
                            .is_ok();
                        let peers_ok = timeout(Duration::from_secs(10), wd.peers.read())
                            .await
                            .is_ok();

                        // A failed probe does NOT mean wedged. tokio's RwLock is
                        // write-preferring, so any long legitimate write — a balance rebuild,
                        // a catch-up, a dirty-state recovery, a bootstrap import — starves
                        // this read exactly the way a deadlock would. The two are only
                        // distinguishable by whether work is still getting done, so ask that
                        // instead: if the chain advanced since the last probe, the lock is
                        // demonstrably being taken and released and nothing is wedged.
                        //
                        // This can only ever SUPPRESS a strike, never invent one — a wedged
                        // chain cannot advance the counter, so a real wedge still strikes on
                        // schedule. Before this, a node doing its first big catch-up logged a
                        // wedge it did not have, which is worse than useless: it teaches the
                        // operator to ignore the one message that matters.
                        let seen = progress.load(std::sync::atomic::Ordering::Relaxed);
                        let chain_progressing = seen != last_progress;
                        last_progress = seen;

                        if !Self::watchdog_strikes(chain_ok, chain_progressing, peers_ok) {
                            strikes = 0;
                            continue;
                        }
                        strikes += 1;
                        error!(
                            "lock watchdog: core lock wedged (chain_ok={}, peers_ok={}) strike {}",
                            chain_ok, peers_ok, strikes
                        );
                        if strikes >= 2 {
                            if headless {
                                error!("lock watchdog: restarting to self-heal (supervisor respawns)");
                                // Nonzero so Restart=on-failure supervisors actually respawn (M9).
                                std::process::exit(3);
                            } else if strikes == 2 {
                                // Print the operator hint ONCE; keep counting quietly after
                                // (an interactive session is never killed under the user).
                                println!(
                                    "A background task has stalled (watchdog: chain_ok={}, peers_ok={}). Mining/commands may degrade — restart the client when convenient.",
                                    chain_ok, peers_ok
                                );
                            }
                        }
                    }
                }
            });
        }

        // OFF-RUNTIME WHOLE-RUNTIME-PIN WATCHDOG (M11). The lock watchdog above is itself a
        // tokio task, so if EVERY runtime worker is pinned at once (blocking I/O slipped onto
        // the async workers — the 2026-07-16 6h publisher park class), it cannot run and cannot
        // self-heal. This guard lives on a dedicated OS thread that never touches the runtime:
        // a lightweight in-runtime task bumps a heartbeat every 15s; the OS thread checks it and,
        // if it stays stale for >120s on a HEADLESS node, exits nonzero so the supervisor
        // respawns. Interactive sessions are never killed. Complementary to the lock probe above,
        // which still names WHICH single lock wedged.
        {
            let headless = std::env::var("ALPHANUMERIC_HEADLESS")
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false);
            let heartbeat = Arc::new(AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            ));
            // In-runtime bumper: advances the heartbeat whenever ANY worker is free to
            // run it. Supervised — an INVERTED failure mode lives here: if the bumper
            // silently dies, the heartbeat goes stale and the off-runtime checker
            // kills a perfectly healthy headless node every ~150s.
            {
                let hb = Arc::clone(&heartbeat);
                spawn_supervised("runtime-heartbeat", move || {
                    let hb = Arc::clone(&hb);
                    async move {
                        loop {
                            tokio::time::sleep(Duration::from_secs(15)).await;
                            let secs = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            hb.store(secs, Ordering::Relaxed);
                        }
                    }
                });
            }
            // Off-runtime checker: a plain OS thread, so it stays able to act even when every
            // tokio worker is blocked. eprintln! (not the log stack) keeps it working under a pin.
            let hb = Arc::clone(&heartbeat);
            let spawned = std::thread::Builder::new()
                .name("runtime-watchdog".into())
                .spawn(move || {
                    let mut stale_strikes: u32 = 0;
                    loop {
                        std::thread::sleep(Duration::from_secs(30));
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let stale = now.saturating_sub(hb.load(Ordering::Relaxed));
                        if stale <= 120 {
                            stale_strikes = 0;
                            continue;
                        }
                        stale_strikes += 1;
                        eprintln!(
                            "runtime watchdog: heartbeat stale {}s (strike {}) — async runtime may be fully pinned",
                            stale, stale_strikes
                        );
                        if stale_strikes >= 2 && headless {
                            eprintln!("runtime watchdog: restarting to self-heal (supervisor respawns)");
                            std::process::exit(3);
                        }
                    }
                });
            // Builder::spawn fails exactly under the resource exhaustion this
            // last-resort guard exists for (EAGAIN / thread limits) — say so
            // instead of silently running unguarded.
            if let Err(e) = spawned {
                eprintln!(
                    "runtime watchdog thread failed to start: {} — whole-runtime-pin self-heal is DISABLED for this session",
                    e
                );
            }
        }

        info!("Node startup complete - ready to accept connections");
        Ok(())
    }

    async fn initialize_p2p(&self) -> Result<(), NodeError> {
        use libp2p_core::transport::Transport;
        use libp2p_core::upgrade;
        use std::time::Duration;

        // Generate new identity key
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        info!("Generated peer ID: {}", local_peer_id);

        // Setup transport with current libp2p TCP+Noise APIs.
        let noise_config = noise::Config::new(&local_key)
            .map_err(|e| NodeError::Network(format!("Noise config failed: {}", e)))?;

        let transport =
            libp2p_tcp::tokio::Transport::new(libp2p_tcp::Config::default().nodelay(true))
                .upgrade(upgrade::Version::V1)
                .authenticate(noise_config)
                .multiplex(yamux::Config::default())
                .timeout(Duration::from_secs(20))
                .boxed();

        // Configure Kademlia DHT
        let mut cfg = KademliaConfig::default();
        if let Some(parallelism) = NonZeroUsize::new(32) {
            cfg.set_parallelism(parallelism);
        }
        cfg.set_query_timeout(Duration::from_secs(60));
        let store = MemoryStore::new(local_peer_id);
        let kademlia = Kademlia::with_config(local_peer_id, store, cfg);

        //==============================================================================
        // BOOTSTRAP NODE CONFIGURATION
        //==============================================================================
        // To connect to existing network nodes, uncomment the section below and add
        // bootstrap node addresses in 'ip:port' or 'domain:port' format.
        //------------------------------------------------------------------------------

        /* UNCOMMENT THIS SECTION TO ENABLE BOOTSTRAP NODES
        // Add bootstrap nodes - customize with your node addresses
        let bootstrap_addrs = vec![
            // Example formats - replace with actual node addresses:
            "192.168.1.100:7177",       // IP address format
            "node1.example.com:7177",   // Domain name format
        ];

        // Create a dummy peer ID to use for bootstrap nodes
        // In a real network, you'd discover the actual peer IDs dynamically
        let dummy_keypair = identity::Keypair::generate_ed25519();
        let bootstrap_peer_id = PeerId::from(dummy_keypair.public());

        for addr_str in bootstrap_addrs {
            // Parse address string (ip:port or domain:port format)
            let parts: Vec<&str> = addr_str.split(':').collect();
            if parts.len() == 2 {
                let host = parts[0];
                if let Ok(port) = parts[1].parse::<u16>() {
                    // Try to parse as IP address first
                    let multi_addr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                        match ip {
                            std::net::IpAddr::V4(ipv4) => format!("/ip4/{}/tcp/{}", ipv4, port),
                            std::net::IpAddr::V6(ipv6) => format!("/ip6/{}/tcp/{}", ipv6, port),
                        }
                    } else {
                        // Assume it's a domain name
                        format!("/dns/{}/tcp/{}", host, port)
                    };

                    // Parse as Multiaddr
                    if let Ok(addr) = multi_addr.parse() {
                        info!("Adding bootstrap address: {}", addr);
                        // Use add_address method which requires a peer ID
                        kademlia.add_address(&bootstrap_peer_id, addr);
                    } else {
                        warn!("Failed to parse bootstrap address: {}", addr_str);
                    }
                } else {
                    warn!("Invalid port in bootstrap address: {}", addr_str);
                }
            } else {
                warn!("Invalid bootstrap address format (should be host:port): {}", addr_str);
            }
        }

        // Start the bootstrap process to connect to the network
        match kademlia.bootstrap() {
            Ok(_) => info!("Started Kademlia bootstrap process"),
            Err(e) => warn!("Failed to start bootstrap process: {}", e),
        }
        // END OF BOOTSTRAP SECTION */

        // Initialize behavior and swarm with the Tokio executor.
        let behaviour = HybridBehaviour { kademlia };
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p_swarm::Config::with_tokio_executor(),
        );

        // Transport is explicitly TCP, so always listen on a TCP multiaddr.
        let listen_addr = "/ip4/0.0.0.0/tcp/0";

        if let Ok(addr) = listen_addr.parse() {
            match swarm.listen_on(addr) {
                Ok(id) => {
                    info!("P2P listening started successfully (id: {:?})", id);
                    info!("P2P listening started on TCP transport");
                }
                Err(e) => return Err(NodeError::Network(format!("Failed to listen: {}", e))),
            }
        }

        // Store swarm
        *self.p2p_swarm.lock().await = Some(HybridSwarm(swarm));

        Ok(())
    }

    async fn handle_p2p_events(&self) -> Result<(), NodeError> {
        // Use explicit import to avoid ambiguity
        use futures_util::StreamExt;
        use libp2p_swarm::SwarmEvent;

        let mut swarm_guard = self.p2p_swarm.lock().await;
        // Operate on the swarm IN PLACE (as_mut), never take() it out: the old
        // take → loop → put-back left the slot None forever if this future was
        // cancelled (or panicked) at any await point in between — the pump then
        // failed every second with "Swarm not initialized" and Kademlia discovery
        // silently died. With as_mut there is nothing to put back.
        let swarm = swarm_guard
            .as_mut()
            .ok_or_else(|| NodeError::Network("Swarm not initialized".to_string()))?;

        let event_count_limit = 200;

        for _ in 0..event_count_limit {
            match tokio::time::timeout(Duration::from_millis(100), swarm.select_next_some()).await {
                Ok(SwarmEvent::Behaviour(HybridBehaviourEvent::Kademlia(
                    KademliaEvent::OutboundQueryProgressed {
                        result: QueryResult::GetClosestPeers(Ok(closest_peers)),
                        ..
                    },
                ))) => {
                    // Process closest peers
                    debug!("Found {} closest peers", closest_peers.peers.len());
                }
                Ok(SwarmEvent::NewListenAddr { address, .. }) => {
                    info!("P2P listening on {:?}", address);
                }
                Ok(_) => {}
                Err(_) => {
                    break;
                }
            }
        }

        Ok(())
    }

    // Maintain connections to peers
    async fn maintain_peer_connections(&self) -> Result<(), NodeError> {
        const PING_INTERVAL_SECS: u64 = 30;
        const MAX_PING_LATENCY: u64 = 500; // ms
        const PEER_TIMEOUT_SECS: u64 = 180; // 3 minutes
        const MAX_FAILURES: u32 = 3;
        const HEALTH_CHECK_BATCH: usize = 5; // Check 5 peers per maintenance cycle

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // IMPROVEMENT: Track peer metrics for better connection management
        let mut active_peers = 0;
        let mut _inactive_peers = 0;
        let mut _high_latency_peers = 0;
        let mut peers_to_check = Vec::new();
        let mut peers_to_remove = Vec::new();

        // Identify peers that need health checks
        {
            let peers = self.peers.read().await;

            // Gather peer info first
            let peer_info: Vec<(SocketAddr, u64, u64)> = peers
                .iter()
                .map(|(addr, info)| (*addr, info.last_seen, info.latency))
                .collect();

            // Now analyze without holding the lock
            for (addr, last_seen, latency) in peer_info {
                let inactive_time = now.saturating_sub(last_seen);

                if inactive_time > PEER_TIMEOUT_SECS {
                    _inactive_peers += 1;
                    peers_to_remove.push(addr);
                } else if inactive_time > PING_INTERVAL_SECS {
                    // Needs a health check
                    peers_to_check.push(addr);
                } else {
                    active_peers += 1;

                    // Track latency
                    if latency > MAX_PING_LATENCY {
                        _high_latency_peers += 1;
                    }
                }
            }
        }

        // Find the least recently seen peers to check first
        let peer_last_seen = {
            let peers_guard = self.peers.read().await;
            let mut result = Vec::with_capacity(peers_to_check.len());

            for &addr in &peers_to_check {
                if let Some(info) = peers_guard.get(&addr) {
                    let time_since_seen = now.saturating_sub(info.last_seen);
                    result.push((addr, time_since_seen));
                }
            }

            result
        };

        // Sort by time since last seen (outside of the peers guard)
        let mut sorted_peers = peer_last_seen;
        sorted_peers.sort_by_key(|&(_, time)| std::cmp::Reverse(time));

        // Update peers_to_check with sorted order
        peers_to_check = sorted_peers.into_iter().map(|(addr, _)| addr).collect();

        // IMPROVEMENT: Perform health checks in batches
        let health_check_batch = peers_to_check
            .into_iter()
            .take(HEALTH_CHECK_BATCH)
            .collect::<Vec<_>>();

        if !health_check_batch.is_empty() {
            // Check peer health in parallel with rate limiting
            let max_concurrent_checks = health_check_batch.len().min(5);
            let semaphore = Arc::new(Semaphore::new(max_concurrent_checks));

            let health_check_futures: Vec<_> = health_check_batch
                .into_iter()
                .map(|addr| {
                    let permit = semaphore.clone().acquire_owned();
                    let node = self.clone();

                    tokio::spawn(async move {
                        let _permit = match permit.await {
                            Ok(permit) => permit,
                            Err(_) => return (addr, false),
                        };
                        let result = node.check_peer_health_internal(addr).await;
                        (addr, result.is_ok())
                    })
                })
                .collect();

            // Process health check results
            for result in futures::future::join_all(health_check_futures).await {
                match result {
                    Ok((addr, true)) => {
                        // Peer is healthy, update last_seen
                        let mut peers = self.peers.write().await;
                        if let Some(info) = peers.get_mut(&addr) {
                            info.last_seen = now;
                        }
                        drop(peers);

                        // Reset failure counter
                        self.reset_peer_failures(addr).await;
                    }
                    Ok((addr, false)) => {
                        // Peer is unhealthy, record failure
                        self.record_peer_failure(addr).await;

                        // Check if peer has failed too many times
                        let failures = self.peer_failures.read().await;
                        if failures.get(&addr).copied().unwrap_or(0) >= MAX_FAILURES {
                            peers_to_remove.push(addr);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        // IMPROVEMENT: Apply updates to peer state all at once
        if !peers_to_remove.is_empty() {
            let remove_list = peers_to_remove.clone();
            {
                let mut peers = self.peers.write().await;
                for addr in &remove_list {
                    peers.remove(addr);
                }
            }
            {
                let mut peer_secrets = self.peer_secrets.write().await;
                for addr in &remove_list {
                    peer_secrets.remove(addr);
                }
            }
            {
                let mut pool = self.outbound_connections.write().await;
                for addr in &remove_list {
                    pool.remove(addr);
                }
            }
            {
                let mut breakers = self.outbound_circuit_breakers.write().await;
                for addr in &remove_list {
                    breakers.remove(addr);
                }
            }
        }

        // IMPROVEMENT: Initiate discovery if we need more peers
        let current_peer_count = self.peers.read().await.len();
        if current_peer_count < MIN_PEERS {
            debug!(
                "Low peer count ({}), initiating discovery",
                current_peer_count
            );

            // Spawn discovery as a separate task to avoid blocking maintenance
            tokio::spawn({
                let node = self.clone();
                async move {
                    if let Err(e) = node.discover_network_nodes().await {
                        debug!("Peer discovery during maintenance deferred: {}", e);
                    }
                }
            });
        }

        // IMPROVEMENT: Rebalance subnet distribution periodically
        // Only do this if we have enough peers to be selective
        if current_peer_count >= MIN_PEERS + 2 {
            if let Err(e) = self.rebalance_peer_subnets().await {
                warn!("Subnet rebalancing failed: {}", e);
            }
        }

        // Update network health metrics. LOCK ORDER: read peers BEFORE taking the
        // health write lock — holding health.write across a peers.read await chained
        // a wedged peers lock into a wedged health lock (info's network section).
        let average_response_time = {
            let peers = self.peers.read().await;
            // Average only peers actually TIMED. Dividing by every peer counted the
            // roster entries that were never measured as 0ms, so a few real samples
            // among ~30 peers floored to 0 and `info` reported "not sampled" while
            // responses were in fact being measured. 0 now genuinely means "nothing
            // sampled yet" rather than "sampled, then diluted away".
            let (total, measured) = peers
                .values()
                .filter(|p| p.latency > 0)
                .fold((0u64, 0u64), |(sum, n), p| {
                    (sum.saturating_add(p.latency), n + 1)
                });
            if measured == 0 {
                0
            } else {
                total / measured
            }
        };
        {
            let mut network_health = self.network_health.write().await;
            network_health.active_nodes = active_peers;
            network_health.average_response_time = average_response_time;
        }

        Ok(())
    }

    // Helper method - improved subnet rebalancing
    async fn rebalance_peer_subnets(&self) -> Result<(), NodeError> {
        // Get current time at the beginning
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Get current peers
        let peers = self.peers.read().await;

        // Count peers per subnet
        let mut subnet_counts = HashMap::new();
        for (_, info) in peers.iter() {
            *subnet_counts.entry(info.subnet_group).or_insert(0) += 1;
        }

        // Find overrepresented subnets
        let max_per_subnet = (self.max_peers / 8).max(MAX_PEERS_PER_SUBNET);
        let mut removals = Vec::new();

        for (subnet, count) in subnet_counts.iter() {
            if *count > max_per_subnet {
                // Get all peers in this subnet
                let subnet_peers: Vec<_> = peers
                    .iter()
                    .filter(|(_, info)| &info.subnet_group == subnet)
                    .collect();

                // Get all the rating data first
                let mut peer_ratings = Vec::with_capacity(subnet_peers.len());

                for (addr, info) in subnet_peers {
                    // Calculate a quality score
                    // Lower is better: latency (ms) - blocks (importance) + age (seconds)
                    let score = info.latency as i64 - (info.blocks as i64)
                        + (now.saturating_sub(info.last_seen) as i64) / 60;

                    // Fixed: Don't double-dereference the address
                    peer_ratings.push((*addr, score));
                }

                // Sort by score (lower is better)
                peer_ratings.sort_by_key(|&(_, score)| score);

                // Keep the best max_per_subnet, remove the rest
                let _excess_count = count - max_per_subnet;
                let peers_to_remove = peer_ratings.len().saturating_sub(max_per_subnet);

                for i in (peer_ratings.len() - peers_to_remove)..peer_ratings.len() {
                    if i < peer_ratings.len() {
                        removals.push(peer_ratings[i].0);
                    }
                }
            }
        }

        // Drop read lock before acquiring write lock
        drop(peers);

        // Remove excess peers
        if !removals.is_empty() {
            {
                let mut peers = self.peers.write().await;
                for addr in &removals {
                    peers.remove(addr);
                }
            }
            {
                let mut peer_secrets = self.peer_secrets.write().await;
                for addr in &removals {
                    peer_secrets.remove(addr);
                }
            }
            {
                let mut pool = self.outbound_connections.write().await;
                for addr in &removals {
                    pool.remove(addr);
                }
            }
            {
                let mut breakers = self.outbound_circuit_breakers.write().await;
                for addr in &removals {
                    breakers.remove(addr);
                }
            }
        }

        Ok(())
    }

    // Request peer height for sync checking
    pub async fn request_peer_height(&self, addr: SocketAddr) -> Result<u32, NodeError> {
        let message = NetworkMessage::GetBlockHeight;

        match self.send_message_with_response(addr, &message).await {
            Ok(NetworkMessage::BlockHeight(height)) => {
                debug!("request_peer_height({}): BlockHeight={}", addr, height);
                Ok(height)
            }
            Ok(_) => {
                debug!("request_peer_height({}): unexpected response type", addr);
                Err(NodeError::Network("Invalid response type".into()))
            }
            Err(e) => {
                debug!("request_peer_height({}): ERR {}", addr, e);
                Err(e)
            }
        }
    }

    // Make peer list request helper
    /// Ask one peer for its peer list.
    ///
    /// The reply is truncated to the same budget `fetch_discovery_peers` applies to the
    /// gateway's list. The inversion it removes is stark: the TRUSTED source was capped and
    /// the untrusted one was not. MAX_MESSAGE_SIZE bounds any single reply before it is
    /// decoded, but the caller fans out across every peer and concatenates the results, so
    /// without a per-reply bound the retained total scales with peer count — one cooperating
    /// set of peers could make discovery allocate far past anything discovery can use.
    ///
    /// Truncation is not a fidelity loss: the caller only needs candidates to dial, and it
    /// already has far more than it can hold connections for.
    async fn request_peer_list(&self, addr: SocketAddr) -> Result<Vec<SocketAddr>, NodeError> {
        let message = NetworkMessage::GetPeers;

        match self.send_message_with_response(addr, &message).await {
            Ok(NetworkMessage::Peers(mut peers)) => {
                peers.truncate(self.max_peers.saturating_mul(4).max(32));
                Ok(peers)
            }
            Ok(_) => Err(NodeError::Network("Invalid response type".into())),
            Err(e) => Err(e),
        }
    }

    fn capability_node_id(&self) -> String {
        Self::tcp_capability_node_id(&self.node_id)
    }

    fn tcp_capability_node_id(base_node_id: &str) -> String {
        if TCP_COMPACT_V1_ENABLED {
            format!("{}{}", base_node_id, COMPACT_BLOCK_V1_CAPABILITY_SUFFIX)
        } else {
            base_node_id.to_string()
        }
    }

    fn observe_compact_capability(&self, addr: SocketAddr, advertised_node_id: &str) {
        if !TCP_COMPACT_V1_ENABLED {
            return;
        }
        if !Self::advertises_compact_v1(advertised_node_id) {
            return;
        }
        self.compact_capable_peers.insert(addr, Instant::now());
    }

    fn advertises_compact_v1(advertised_node_id: &str) -> bool {
        if !TCP_COMPACT_V1_ENABLED {
            return false;
        }
        Self::compact_v1_marker_well_formed(advertised_node_id)
    }

    fn compact_v1_marker_well_formed(advertised_node_id: &str) -> bool {
        let Some(base_id) = advertised_node_id.strip_suffix(COMPACT_BLOCK_V1_CAPABILITY_SUFFIX)
        else {
            return false;
        };
        // The authenticated session prevents off-path capability injection.
        // Require the established 32-byte node-id shape as well so an arbitrary
        // ping payload cannot accidentally enable an extension.
        base_id.len() == 64
            && hex::decode(base_id)
                .map(|bytes| bytes.len() == 32)
                .unwrap_or(false)
    }

    fn tcp_compact_peer_eligible(advertised_fresh: bool) -> bool {
        TCP_COMPACT_V1_ENABLED && advertised_fresh
    }

    fn peer_supports_compact_v1(&self, addr: SocketAddr) -> bool {
        let fresh = self
            .compact_capable_peers
            .get(&addr)
            .map(|seen| seen.elapsed() < COMPACT_CAPABILITY_TTL)
            .unwrap_or(false);
        if Self::tcp_compact_peer_eligible(fresh) {
            true
        } else {
            if self.compact_capable_peers.contains_key(&addr) {
                self.compact_capable_peers.remove(&addr);
            }
            false
        }
    }

    // Peer health check implementation
    async fn check_peer_health_internal(&self, addr: SocketAddr) -> Result<(), NodeError> {
        // Simple ping-pong health check
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let ping = NetworkMessage::Ping {
            timestamp: now,
            node_id: self.capability_node_id(),
        };

        // Send ping with timeout and expect pong
        let response = self.send_message_with_response(addr, &ping).await?;

        match response {
            NetworkMessage::Pong { timestamp, node_id } => {
                self.observe_compact_capability(addr, &node_id);
                if now.abs_diff(timestamp) <= 5 {
                    Ok(())
                } else {
                    Err(NodeError::Network("Invalid timestamp in pong".into()))
                }
            }
            _ => Err(NodeError::Network(
                "Expected pong, got different message".into(),
            )),
        }
    }

    // Record peer failure for tracking problem peers
    async fn record_peer_failure(&self, addr: SocketAddr) {
        let mut failures = self.peer_failures.write().await;
        *failures.entry(addr).or_insert(0) += 1;
    }

    // Reset peer failures counter
    async fn reset_peer_failures(&self, addr: SocketAddr) {
        let mut failures = self.peer_failures.write().await;
        failures.remove(&addr);
    }

    async fn prune_runtime_maps(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        {
            let mut attempts = self.inbound_attempts.write().await;
            attempts.retain(|_, (_, last_seen)| {
                now.saturating_sub(*last_seen) <= INBOUND_ATTEMPT_WINDOW
            });
            if attempts.len() > INBOUND_ATTEMPT_MAX_KEYS {
                let overflow = attempts.len().saturating_sub(INBOUND_ATTEMPT_MAX_KEYS);
                let mut oldest: Vec<(IpAddr, u64)> = attempts
                    .iter()
                    .map(|(ip, (_, last_seen))| (*ip, *last_seen))
                    .collect();
                oldest.sort_unstable_by_key(|(_, last_seen)| *last_seen);
                for (ip, _) in oldest.into_iter().take(overflow) {
                    attempts.remove(&ip);
                }
            }
        }

        let active_peers: HashSet<SocketAddr> = {
            let peers = self.peers.read().await;
            peers.keys().copied().collect()
        };
        let mut failures = self.peer_failures.write().await;
        failures.retain(|addr, _| active_peers.contains(addr));
        if failures.len() > PEER_FAILURE_MAX_KEYS {
            let overflow = failures.len().saturating_sub(PEER_FAILURE_MAX_KEYS);
            let remove: Vec<SocketAddr> = failures.keys().copied().take(overflow).collect();
            for addr in remove {
                failures.remove(&addr);
            }
        }

        self.compact_capable_peers.retain(|addr, seen| {
            active_peers.contains(addr) && seen.elapsed() < COMPACT_CAPABILITY_TTL
        });
        self.compact_inflight
            .retain(|_, state| state.started.elapsed() < COMPACT_INFLIGHT_TTL);

        // Outbound circuit breakers: an entry is created for EVERY address we ever
        // dial (gateway candidates, PEX, seeds), but removal was keyed on peer
        // membership — an address that failed a few dials and never became a peer
        // leaked its entry for the process lifetime, and check_outbound_circuit
        // read-locks this map on every outbound message. Keep breakers that are
        // still OPEN (their verdict still matters) or belong to a current peer;
        // a dropped closed breaker merely resets a failure count we no longer care
        // about.
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut breakers = self.outbound_circuit_breakers.write().await;
            breakers.retain(|addr, state| {
                state.open_until.is_some_and(|until| until > now)
                    || active_peers.contains(addr)
            });
        }
    }

    pub async fn request_blocks(
        &self,
        addr: SocketAddr,
        start: u32,
        end: u32,
    ) -> Result<Vec<Block>, NodeError> {
        // Validate request parameters
        if end < start {
            return Err(NodeError::Network("Invalid block range".to_string()));
        }

        // Keep the batch size in lockstep with the server's GetBlocks ingress cap, or a
        // batch would be rejected outright.
        const MAX_BATCH_SIZE: u32 = MAX_GETBLOCKS_SPAN;
        const MAX_RETRIES: u32 = 3;

        // Batch large requests so peers with strict range limits can still serve us.
        // `span + 1 > MAX` is value-identical to `span >= MAX` but overflows at
        // u32::MAX, which the saturating_sub beside it was there to prevent. This
        // form is also textually identical to the server-side cap it tracks.
        if end.saturating_sub(start) >= MAX_BATCH_SIZE {
            let mut all_blocks = Vec::new();
            let mut batch_start = start;
            while batch_start <= end {
                let batch_end = batch_start.saturating_add(MAX_BATCH_SIZE - 1).min(end);
                let mut batch = self
                    .request_blocks_batch(addr, batch_start, batch_end, MAX_RETRIES)
                    .await?;
                // Advance by what the server ACTUALLY returned, not the requested boundary:
                // the server may size-cap its reply to a prefix [batch_start, k] with
                // k < batch_end, and jumping to batch_end+1 would silently SKIP [k+1,
                // batch_end], leaving a permanent hole in the synced chain.
                let highest = batch.iter().map(|b| b.index).max();
                all_blocks.append(&mut batch);
                match highest {
                    // Empty reply: the peer can't serve this range — stop rather than spin.
                    None => break,
                    // At the ceiling there is no next height to advance to; `>=` here
                    // read as a range guard but can only ever be equality, which made
                    // clippy's absurd_extreme_comparisons deny fire and blocked the
                    // lint from running over the rest of the crate.
                    Some(h) if h == u32::MAX => break,
                    Some(h) => batch_start = h.saturating_add(1),
                }
            }
            all_blocks.sort_by_key(|b| b.index);
            all_blocks.dedup_by_key(|b| b.index);
            return Ok(all_blocks);
        }

        self.request_blocks_batch(addr, start, end, MAX_RETRIES)
            .await
    }

    async fn query_peer_heights(
        &self,
        addrs: Vec<SocketAddr>,
        timeout_ms: u64,
    ) -> Vec<(SocketAddr, u32)> {
        let height_queries = addrs.into_iter().map(|addr| {
            let node = self.clone();
            async move {
                match tokio::time::timeout(
                    Duration::from_millis(timeout_ms),
                    node.request_peer_height(addr),
                )
                .await
                {
                    Ok(Ok(height)) => Some((addr, height)),
                    _ => None,
                }
            }
        });

        let mut peer_heights: Vec<(SocketAddr, u32)> = join_all(height_queries)
            .await
            .into_iter()
            .flatten()
            .collect();

        if !peer_heights.is_empty() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut peers = self.peers.write().await;
            for (addr, height) in &peer_heights {
                if let Some(info) = peers.get_mut(addr) {
                    info.blocks = *height;
                    info.last_seen = now;
                }
            }
        }

        peer_heights.sort_by_key(|(_, height)| std::cmp::Reverse(*height));
        peer_heights
    }

    async fn request_blocks_batch(
        &self,
        addr: SocketAddr,
        start: u32,
        end: u32,
        max_retries: u32,
    ) -> Result<Vec<Block>, NodeError> {
        let message = NetworkMessage::GetBlocks { start, end };
        // Record that we solicited blocks from this peer so a matching inbound
        // ChainResponse can be correlated (see handle_network_event).
        self.solicited_block_peers.insert(addr, Instant::now());
        let mut retries = 0;
        while retries < max_retries {
            match self.send_message_with_response(addr, &message).await {
                Ok(NetworkMessage::Blocks(blocks)) => {
                    let mut valid_blocks = Vec::with_capacity(blocks.len());
                    for block in blocks {
                        // Hash AND PoW-floor here, once: every caller filtered on
                        // both anyway, and the third recompute (merkle+header hash
                        // over the full tx set) tripled catch-up CPU for nothing.
                        // Full witness/linkage validation still happens on ingest.
                        if block.index >= start
                            && block.index <= end
                            && block.calculate_hash_for_block() == block.hash
                            && block.verify_pow_meets_floor()
                        {
                            valid_blocks.push(block);
                        }
                    }
                    return Ok(valid_blocks);
                }
                Ok(_) => {
                    // A wrong-typed response means this pooled stream is desynced
                    // (a cancelled earlier exchange shifted its framing) — retrying
                    // on the same connection returns garbage forever. Drop it so
                    // the retry redials fresh.
                    self.remove_outbound_connection(addr).await;
                    retries += 1;
                    tokio::time::sleep(Duration::from_millis(500 * retries as u64)).await;
                }
                Err(e) => {
                    retries += 1;
                    warn!(
                        "Failed to get blocks from {}, attempt {}/{}: {}",
                        addr, retries, max_retries, e
                    );
                    tokio::time::sleep(Duration::from_millis((500 * retries).into())).await;
                }
            }
        }

        Err(NodeError::Network(format!(
            "Failed to get blocks from {} after {} attempts",
            addr, max_retries
        )))
    }

    /// Request-correlation for inbound block responses: true only if we sent this
    /// peer a GetBlocks recently. Opportunistically prunes stale entries so the
    /// set cannot grow unbounded.
    fn is_solicited_block_source(&self, addr: SocketAddr) -> bool {
        const SOLICIT_TTL: Duration = Duration::from_secs(120);
        let now = Instant::now();
        self.solicited_block_peers
            .retain(|_, ts| now.duration_since(*ts) < SOLICIT_TTL);
        self.solicited_block_peers.contains_key(&addr)
    }

    /// Apply a peer-sourced block only after verifying every transaction's full
    /// ML-DSA signature against a witness resolved from `peer`. Compact "receipt"
    /// blocks carry a truncated signature plus a `sig_hash`, which is not a proof
    /// of anything on its own; `save_receipt_verified_block` trusts it. Verifying
    /// the witness first re-establishes the truncated-after-verification invariant
    /// that receipt storage assumes, so a peer cannot inject forged transactions.
    async fn accept_peer_block(
        &self,
        block: &Block,
        peer: Option<SocketAddr>,
    ) -> Result<(), NodeError> {
        if !self.verify_block_with_witness(block, peer).await? {
            return Err(NodeError::InvalidBlock(format!(
                "block {} rejected: transaction witness/signature verification failed",
                block.index
            )));
        }
        self.blockchain
            .write()
            .await
            .save_receipt_verified_block(block)
            .await
            .map_err(|e| NodeError::Blockchain(e.to_string()))
    }

    async fn remove_outbound_connection(&self, addr: SocketAddr) {
        self.outbound_connections.write().await.remove(&addr);
    }

    /// Drop every pooled outbound connection and forget every circuit-breaker
    /// verdict. For wake-from-suspend recovery: after a sleep the pool holds only
    /// half-open sockets (each worth a full response-timeout stall) and the
    /// breakers hold pre-sleep verdicts about peers that may be fine now.
    /// Dropping a TcpStream closes it; the next use simply redials. Worst case
    /// cost is one extra handshake per peer — always cheaper than probing a dead
    /// socket.
    pub async fn reset_connection_pool(&self) {
        let dropped = {
            let mut pool = self.outbound_connections.write().await;
            let n = pool.len();
            pool.clear();
            n
        };
        self.outbound_circuit_breakers.write().await.clear();
        if dropped > 0 {
            info!(
                "Reset outbound connection pool after suspend ({} stale connections dropped)",
                dropped
            );
        }
    }

    async fn check_outbound_circuit(&self, addr: SocketAddr) -> Result<(), NodeError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let breakers = self.outbound_circuit_breakers.read().await;
        if let Some(state) = breakers.get(&addr) {
            if let Some(until) = state.open_until {
                if until > now {
                    return Err(NodeError::Network(format!(
                        "Outbound circuit open for {} (retry in {}s)",
                        addr,
                        until.saturating_sub(now)
                    )));
                }
            }
        }
        Ok(())
    }

    async fn record_outbound_failure(&self, addr: SocketAddr) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut breakers = self.outbound_circuit_breakers.write().await;
        let state = breakers.entry(addr).or_default();
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= OUTBOUND_CIRCUIT_FAILURE_THRESHOLD {
            state.open_until = Some(now.saturating_add(OUTBOUND_CIRCUIT_OPEN_SECS));
        }
    }

    async fn record_outbound_success(&self, addr: SocketAddr) {
        let mut breakers = self.outbound_circuit_breakers.write().await;
        breakers.remove(&addr);
    }

    async fn cleanup_outbound_connections(&self) {
        let pool_snapshot: Vec<(SocketAddr, Arc<Mutex<OutboundConnection>>)> = {
            let pool = self.outbound_connections.read().await;
            pool.iter()
                .map(|(addr, conn)| (*addr, Arc::clone(conn)))
                .collect()
        };

        let now = Instant::now();
        let now_wall = SystemTime::now();
        let idle = Duration::from_secs(OUTBOUND_POOL_IDLE_SECS);
        let mut remove_addrs = Vec::new();

        for (addr, conn) in pool_snapshot {
            // try_lock, not lock: a connection mid-exchange is by definition in use
            // (not idle), and awaiting its mutex here serialized this sweep — and the
            // whole maintenance loop behind it — on a possibly-30s response read.
            let Ok(conn_guard) = conn.try_lock() else {
                continue;
            };
            // Idle by monotonic age, OR by wall-clock age: Instant freezes across an
            // OS suspend (macOS/Linux), so post-sleep half-open sockets looked
            // freshly-used forever. duration_since fails only on clock regression —
            // treat that as "not stale" (fail-open).
            let wall_stale = now_wall
                .duration_since(conn_guard.last_used_wall)
                .map(|d| d > idle)
                .unwrap_or(false);
            if now.duration_since(conn_guard.last_used) > idle || wall_stale {
                remove_addrs.push(addr);
            }
        }

        if !remove_addrs.is_empty() {
            let mut pool = self.outbound_connections.write().await;
            for addr in remove_addrs {
                pool.remove(&addr);
            }
        }
    }

    async fn evict_lru_outbound_connection(&self) {
        let snapshot: Vec<(SocketAddr, Arc<Mutex<OutboundConnection>>)> = {
            let pool = self.outbound_connections.read().await;
            pool.iter()
                .map(|(addr, conn)| (*addr, Arc::clone(conn)))
                .collect()
        };

        let mut lru: Option<(SocketAddr, Instant)> = None;
        for (addr, conn) in snapshot {
            // try_lock: a connection mid-exchange is in use — recently used by
            // definition, so it can't be the LRU victim; awaiting it here stalled
            // every NEW outbound connection (this runs on the create path) for up
            // to a full response timeout.
            let Ok(conn_guard) = conn.try_lock() else {
                continue;
            };
            match lru {
                Some((_, oldest)) if conn_guard.last_used >= oldest => {}
                _ => {
                    lru = Some((addr, conn_guard.last_used));
                }
            }
        }

        if let Some((addr, _)) = lru {
            self.outbound_connections.write().await.remove(&addr);
        }
    }

    async fn get_or_create_outbound_connection(
        &self,
        addr: SocketAddr,
    ) -> Result<Arc<Mutex<OutboundConnection>>, NodeError> {
        // Take the guard in a scoped read: the if-let scrutinee would otherwise
        // hold the read guard across the write().remove() below and self-deadlock.
        let existing = self.outbound_connections.read().await.get(&addr).cloned();
        if let Some(existing) = existing {
            return Ok(existing);
        }

        let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
            .await
            .map_err(|_| NodeError::Network(format!("Connection timeout to {}", addr)))??;
        stream.set_nodelay(true)?;
        // Keepalive on the OUTBOUND pool too (the inbound path has always had it,
        // handle_connection): without probes a silently-dead NAT/suspend path lingers
        // until a write forces the error; with them the kernel retires it on its own.
        {
            let std_stream = stream.into_std()?;
            let socket = Socket::from(std_stream);
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(60))
                .with_interval(Duration::from_secs(15));
            socket.set_tcp_keepalive(&keepalive)?;
            stream = TcpStream::from_std(socket.into())?;
        }

        let (peer_info, shared_secret) = tokio::time::timeout(
            Duration::from_secs(5),
            self.perform_handshake(&mut stream, true),
        )
        .await
        .map_err(|_| NodeError::Network(format!("Handshake timeout with {}", addr)))??;

        if peer_info.version != NETWORK_VERSION {
            return Err(NodeError::Network(format!(
                "Version mismatch with {}: {} (expected {})",
                addr, peer_info.version, NETWORK_VERSION
            )));
        }

        {
            let mut peers = self.peers.write().await;
            // Bound the peer table on the outbound path too (the inbound path already enforces
            // this): without it an attacker could grow the map past max_peers via connections we
            // initiate. Existing peers may always reconnect.
            if peers.len() >= self.max_peers && !peers.contains_key(&addr) {
                return Err(NodeError::Network("Maximum peers reached".into()));
            }
            peers.insert(addr, peer_info);
        }
        self.peer_secrets
            .write()
            .await
            .insert(addr, shared_secret.clone());

        Ok(self
            .insert_outbound_connection(addr, stream, shared_secret)
            .await)
    }

    async fn insert_outbound_connection(
        &self,
        addr: SocketAddr,
        stream: TcpStream,
        shared_secret: Vec<u8>,
    ) -> Arc<Mutex<OutboundConnection>> {
        let connection = Arc::new(Mutex::new(OutboundConnection {
            stream,
            shared_secret,
            last_used: Instant::now(),
            last_used_wall: SystemTime::now(),
            exchange_armed: false,
        }));
        let max_pool_size = (self
            .max_connections
            .saturating_mul(OUTBOUND_POOL_MAX_FACTOR))
        .max(32);
        if self.outbound_connections.read().await.len() >= max_pool_size {
            self.evict_lru_outbound_connection().await;
        }

        {
            let mut pool = self.outbound_connections.write().await;
            if let Some(existing) = pool.get(&addr).cloned() {
                return existing;
            }
            if pool.len() >= max_pool_size {
                let eviction_key = pool.keys().copied().find(|peer| *peer != addr);
                if let Some(key) = eviction_key {
                    pool.remove(&key);
                }
            }
            pool.insert(addr, Arc::clone(&connection));
        }

        connection
    }

    pub async fn send_message_with_response(
        &self,
        addr: SocketAddr,
        message: &NetworkMessage,
    ) -> Result<NetworkMessage, NodeError> {
        const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
        const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
        const MAX_ATTEMPTS: u32 = 2;
        // Response budget by request class: bulk block transfers legitimately take a
        // while, but small control messages (height, peers, ping) answer in one frame —
        // waiting the full 30s on those just pins recovery paths to dead or half-open
        // sockets (post-suspend wake is the main producer of these).
        let response_timeout = if matches!(message, NetworkMessage::GetBlocks { .. })
            || Self::is_tcp_compact_extension(message)
        {
            RESPONSE_TIMEOUT
        } else {
            Duration::from_secs(8)
        };

        if !TCP_COMPACT_V1_ENABLED && Self::is_tcp_compact_extension(message) {
            return Err(NodeError::Network(
                "TCP compact transport is disabled".to_string(),
            ));
        }

        // Rate limit check
        let rate_key = format!("msg_to_{}", addr);
        if !self.rate_limiter.check_limit(&rate_key) {
            return Err(NodeError::Network("Rate limit exceeded".to_string()));
        }

        let mut last_error = None;
        for attempt in 0..MAX_ATTEMPTS {
            self.check_outbound_circuit(addr).await?;

            let conn = match self.get_or_create_outbound_connection(addr).await {
                Ok(conn) => conn,
                Err(e) => {
                    self.record_outbound_failure(addr).await;
                    last_error = Some(e);
                    if attempt + 1 < MAX_ATTEMPTS {
                        tokio::time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
                        continue;
                    }
                    break;
                }
            };

            let mut stream_guard = conn.lock().await;
            // DESYNC GUARD: a previous exchange on this pooled connection was cancelled
            // between arming and disarming (a caller-side timeout dropped the future
            // mid-request/response), so the socket may hold an unconsumed response
            // frame. Using it would return the WRONG message — the stream is shifted
            // by one frame from then on. Discard and redial on the next attempt. Not a
            // peer fault: no circuit-breaker strike.
            if stream_guard.exchange_armed {
                drop(stream_guard);
                self.remove_outbound_connection(addr).await;
                last_error = Some(NodeError::Network(format!(
                    "Discarded desynced pooled connection to {}",
                    addr
                )));
                continue;
            }
            stream_guard.exchange_armed = true;
            let result: Result<NetworkMessage, NodeError> = async {
                let shared_secret = stream_guard.shared_secret.clone();
                let data = self.encrypt_message(message, &shared_secret)?;
                if data.is_empty() {
                    return Err(NodeError::Network(
                        "Refusing to send empty request".to_string(),
                    ));
                }
                if data.len() > MAX_MESSAGE_SIZE {
                    return Err(NodeError::Network("Outgoing message too large".to_string()));
                }

                tokio::time::timeout(CONNECTION_TIMEOUT, async {
                    stream_guard
                        .stream
                        .write_all(&(data.len() as u32).to_be_bytes())
                        .await?;
                    stream_guard.stream.write_all(&data).await?;
                    stream_guard.stream.flush().await?;
                    Ok::<_, std::io::Error>(())
                })
                .await
                .map_err(|_| NodeError::Network(format!("Send timeout to {}", addr)))??;

                let mut len_bytes = [0u8; 4];
                tokio::time::timeout(
                    response_timeout,
                    stream_guard.stream.read_exact(&mut len_bytes),
                )
                .await
                .map_err(|_| NodeError::Network(format!("Response timeout from {}", addr)))??;

                let len = u32::from_be_bytes(len_bytes) as usize;
                if len == 0 {
                    return Err(NodeError::Network("Empty response".to_string()));
                }
                if len > MAX_MESSAGE_SIZE {
                    return Err(NodeError::Network("Response too large".to_string()));
                }

                let mut response_data = vec![0u8; len];
                tokio::time::timeout(
                    response_timeout,
                    stream_guard.stream.read_exact(&mut response_data),
                )
                .await
                .map_err(|_| {
                    NodeError::Network(format!("Response data timeout from {}", addr))
                })??;

                let response = self.decrypt_message(&response_data, &shared_secret)?;
                Ok(response)
            }
            .await;
            // The exchange future COMPLETED (was not cancelled): the socket is either
            // clean (Ok) or about to be evicted (Err) — safe to disarm either way.
            stream_guard.exchange_armed = false;
            stream_guard.last_used = Instant::now();
            stream_guard.last_used_wall = SystemTime::now();
            drop(stream_guard);

            match result {
                Ok(response) => {
                    self.record_outbound_success(addr).await;
                    return Ok(response);
                }
                Err(e) => {
                    self.record_outbound_failure(addr).await;
                    self.remove_outbound_connection(addr).await;
                    last_error = Some(e);
                    if attempt + 1 < MAX_ATTEMPTS {
                        tokio::time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            NodeError::Network(format!("Failed request to {} after retries", addr))
        }))
    }

    // Core verification method for blocks
    pub async fn verify_block_parallel(&self, block: &Block) -> Result<bool, NodeError> {
        self.verify_block_with_witness(block, None).await
    }

    pub async fn verify_block_with_witness(
        &self,
        block: &Block,
        peer: Option<SocketAddr>,
    ) -> Result<bool, NodeError> {
        // Cheap structural checks run FIRST — before the cache key, before any validation permit
        // or fetch — so a garbage block (bad hash / sub-floor PoW / over the tx-count limit) costs
        // nothing scarce to reject. The key covers the transaction signature material, which makes
        // deriving it proportional to block size (hundreds of microseconds on a full block); doing
        // that ahead of these checks would hand an attacker that work for the price of one
        // malformed block.
        //
        // A block's CLAIMED hash (block.hash, attacker-controlled off the wire) must equal its COMPUTED
        // hash. If it lies, reject it WITHOUT negative-caching — the cache is keyed on the claimed hash,
        // so caching a false verdict under an attacker-chosen hash would let a garbage block suppress the
        // REAL block that legitimately has that hash (a low-cost valid-block censorship on every path).
        if block.calculate_hash_for_block() != block.hash {
            return Ok(false);
        }
        // Correct hash but PoW below floor -> definitively invalid. NOT negative-cached: the verdict
        // depends only on the header, so re-deriving it costs a single header hash and a compare —
        // strictly less than building the cache key needed to file it.
        if !block.verify_pow_meets_floor() {
            return Ok(false);
        }

        // A block exceeding the ledger's transaction-count limit is already invalid; rejecting it
        // here, before any witness resolution runs, uses the same bound validate_block enforces.
        if !Self::witness_count_within_limit(block.transactions.len()) {
            return Ok(false);
        }

        // Past the cheap rejects, so the block has earned the cost of a real key. Everything below
        // is witness resolution and full signature verification — orders of magnitude more than
        // deriving this — so a hit still pays for itself many times over.
        let block_hash = Self::validation_cache_key(block);
        if let Some(entry) = self
            .validation_cache
            .get(&block_hash)
            .map(|entry| entry.clone())
        {
            if Self::is_validation_cache_entry_fresh(&entry, SystemTime::now()) {
                return Ok(entry.valid);
            }
            self.validation_cache.remove(&block_hash);
        }

        // ---- Phase 1: resolve every transaction's witness. This is the network-bound phase and it
        // holds NO validation permit, so a peer that answers witness fetches slowly can never occupy
        // the scarce validation pool. Fetches draw from their own bounded pool inside
        // resolve_full_tx_for_block; locally-resolvable blocks never contend at all. The deadline
        // caps how long a single block may spend here.
        let witness_deadline = Instant::now() + WITNESS_RESOLVE_DEADLINE;
        let mut witness_fetch_budget = if peer.is_some() {
            block
                .transactions
                .iter()
                .filter(|tx| !SYSTEM_ADDRESSES.contains(&tx.sender.as_str()))
                .count()
        } else {
            0
        };
        let mut resolved: Vec<Transaction> = Vec::with_capacity(block.transactions.len());

        for tx in &block.transactions {
            if Instant::now() >= witness_deadline {
                return Ok(false);
            }
            if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                continue;
            }

            // A witness we cannot resolve — missing, the fetch pool was saturated, or a transport
            // error while fetching — means this block cannot be verified right now. Defer it
            // (Ok(false), not negative-cached, re-verified later) rather than surfacing an error, so
            // a transient hiccup on an honest block self-corrects and Phase 1 never returns Err.
            let mut full_tx = match self
                .resolve_full_tx_for_block(
                    tx,
                    peer,
                    witness_deadline,
                    &mut witness_fetch_budget,
                )
                .await
            {
                Ok(Some(tx)) => tx,
                Ok(None) | Err(_) => return Ok(false),
            };

            if full_tx.get_tx_id() != tx.get_tx_id() {
                return Ok(false);
            }

            if tx.pub_key.is_some() && full_tx.pub_key.is_some() && tx.pub_key != full_tx.pub_key {
                return Ok(false);
            }

            if full_tx.pub_key.is_none() {
                full_tx.pub_key = tx.pub_key.clone();
            }

            // Bind the resolved witness's sig_hash to its OWN signature locally, on every path — not
            // only when sig_hash is absent. A witness can arrive with a pre-populated sig_hash (from
            // a peer, the mempool, or the witness cache); trusting it and leaving the
            // sig_hash<->signature check to verify_transaction_signature (Phase 2) would make this
            // frontier path depend on that function's internal bind. Deriving here keeps the bind
            // self-contained: a claimed sig_hash disagreeing with SHA256(signature) is defer-rejected
            // (Ok(false), self-healing) before the witness is ever trusted or cached.
            if !Self::bind_witness_sig_hash_to_signature(&mut full_tx) {
                return Ok(false);
            }

            if let Some(expected_hash) = &tx.sig_hash {
                if full_tx.sig_hash.as_ref() != Some(expected_hash) {
                    return Ok(false);
                }
            }

            resolved.push(full_tx);
        }

        // ---- Phase 2: hold a validation permit only for the CPU/lock-bound work — signature
        // verification and validate_block. Because the permit is never held across a network fetch,
        // an honest block acquires one promptly even while slow-fetch blocks are in flight.
        let _permit = match tokio::time::timeout(
            Duration::from_millis(500),
            self.validation_pool.acquire_validation_permit(),
        )
        .await
        {
            Ok(permit) => permit?,
            Err(_) => {
                return Ok(false);
            }
        };

        for full_tx in &resolved {
            let signature_ok = {
                let blockchain = self.blockchain.read().await;
                blockchain.verify_transaction_signature(full_tx).is_ok()
            };

            if !signature_ok {
                return Ok(false);
            }

            // Signature verified — safe to memoize so a sibling or later block carrying the same
            // transaction resolves it without another fetch. This is the only path that writes the
            // witness cache, which is precisely what lets the read side trust a cached entry.
            self.cache_verified_compact_transaction(full_tx);
        }

        let validation_result = {
            let blockchain = self.blockchain.read().await;
            match blockchain.validate_block(block).await {
                Ok(()) => true,
                Err(_) => {
                    // Accept structurally valid out-of-order blocks so the blockchain layer can
                    // park them as orphans and retry when parents arrive.
                    let parent_known = if block.index == 0 {
                        true
                    } else {
                        blockchain
                            .get_block(block.index.saturating_sub(1))
                            .map(|parent| parent.hash == block.previous_hash)
                            .unwrap_or(false)
                    };
                    let ahead_of_tip = block.index
                        > (blockchain.get_latest_block_index() as u32).saturating_add(1);
                    let orphan_candidate = (!parent_known) || ahead_of_tip;
                    orphan_candidate
                        && Blockchain::calculate_merkle_root(&block.transactions)
                            .map(|root| root == block.merkle_root)
                            .unwrap_or(false)
                }
            }
        };

        // BPoS is monitoring/finality telemetry only. Its peer-derived, local and
        // time-varying state must never alter the deterministic PoW/ledger verdict.
        // Keeping `validation_result` immutable makes that boundary compiler-enforced.
        if validation_result {
            if let Some(ref sentinel) = self.header_sentinel {
                if sentinel
                    .has_monitoring_quorum_for_block(block.index)
                    .await
                {
                    if sentinel
                        .has_conflicting_verified_header(block.index, &block.hash)
                        .await
                    {
                        warn!(
                            "BPoS observed a conflicting verified header at height {}; canonical PoW validity is unchanged",
                            block.index
                        );
                    } else {
                        let has_record = sentinel.has_verification_record(&block.hash);
                        if sentinel.should_require_verified_header_record_for_block(block.index)
                            && !has_record
                        {
                            debug!(
                                "Accepting block {} with pending header verification record; header sync may arrive after block gossip",
                                block.index
                            );
                        } else if has_record && !sentinel.is_header_verified(&block.hash).await {
                            debug!(
                                "Block {} has a pending BPoS verifier quorum; canonical PoW validity is unchanged",
                                block.index
                            );
                        }
                    }
                }
            }
        }

        self.validation_cache.insert(
            block_hash,
            ValidationCacheEntry {
                valid: validation_result,
                timestamp: SystemTime::now(),
            },
        );
        self.maybe_prune_validation_cache();

        if validation_result {
            if let Some(ref sentinel) = self.header_sentinel {
                let header_info = BlockHeaderInfo {
                    height: block.index,
                    hash: block.hash,
                    prev_hash: block.previous_hash,
                    timestamp: block.timestamp,
                };
                let node_id = self.node_id.clone();

                let sentinel = sentinel.clone();
                tokio::spawn(async move {
                    let _ = sentinel.add_verified_header(header_info).await;
                    let _ = node_id;
                });
            }
        }

        Ok(validation_result)
    }

    async fn resolve_full_tx_for_block(
        &self,
        tx: &Transaction,
        peer: Option<SocketAddr>,
        witness_deadline: Instant,
        witness_fetch_budget: &mut usize,
    ) -> Result<Option<Transaction>, NodeError> {
        let tx_id = tx.get_tx_id();
        // The cache holds only witnesses that already passed signature verification during block
        // validation; as a belt-and-suspenders check a returned entry must still match its key, and a
        // stray one is dropped so resolution falls through to the signature / mempool / peer path.
        let cached = {
            let mut cache = self.tx_witness_cache.lock();
            match cache.get(&tx_id).cloned() {
                Some(c) if Self::witness_matches_committed_receipt(tx, &c) => Some(c),
                Some(c) if c.get_tx_id() != tx_id => {
                    cache.pop(&tx_id);
                    None
                }
                // A legitimately re-signed transaction can share get_tx_id()
                // while committing to a different sig_hash/Merkle leaf. Keep the
                // cached variant for its own block, but fall through to the
                // incoming full body or peer fetch for this exact receipt.
                Some(_) => None,
                None => None,
            }
        };
        if let Some(cached) = cached {
            return Ok(Some(cached));
        }

        if let Some(sig_hex) = &tx.signature {
            if !Self::is_signature_truncated(sig_hex) {
                return Ok(Some(tx.clone()));
            }
        }

        if let Some(mempool_tx) = self
            .blockchain
            .read()
            .await
            .get_mempool_transaction_by_id(&tx_id)
            .await
        {
            if let Some(sig_hex) = &mempool_tx.signature {
                if !Self::is_signature_truncated(sig_hex)
                    && Self::witness_matches_committed_receipt(tx, &mempool_tx)
                {
                    return Ok(Some(mempool_tx));
                }
            }
        }

        if let Some(peer_addr) = peer {
            let Some(remaining) = witness_deadline.checked_duration_since(Instant::now()) else {
                return Ok(None);
            };
            if *witness_fetch_budget == 0 {
                return Ok(None);
            }
            // Consume one budget slot per remote witness resolution attempt before entering the
            // outbound-request path. This keeps resource usage bounded when every entry is
            // unresolvable and blocks verification from being monopolized by one block.
            *witness_fetch_budget = witness_fetch_budget.saturating_sub(1);
            // Bound concurrent outbound fetches on their own pool; if it is saturated, report the
            // witness as unresolved so the block defers instead of piling up behind slow peers.
            let _fetch_slot = match self.validation_pool.acquire_fetch_slot() {
                Some(slot) => slot,
                None => return Ok(None),
            };
            let timeout = remaining.min(WITNESS_RESOLVE_REQUEST_TIMEOUT);
            if timeout.is_zero() {
                return Ok(None);
            }
            return self.request_tx_witness(peer_addr, &tx_id, timeout).await;
        }

        Ok(None)
    }

    // `Option::is_none_or` requires Rust 1.82; preserve the crate's 1.70 MSRV.
    #[allow(clippy::unnecessary_map_or)]
    fn witness_matches_committed_receipt(receipt: &Transaction, candidate: &Transaction) -> bool {
        candidate.get_tx_id() == receipt.get_tx_id()
            && receipt.pub_key.as_ref().map_or(true, |expected| {
                candidate.pub_key.as_ref() == Some(expected)
            })
            && receipt.sig_hash.as_ref().map_or(true, |expected| {
                candidate.sig_hash.as_ref() == Some(expected)
            })
    }

    fn is_signature_truncated(sig_hex: &str) -> bool {
        match hex::decode(sig_hex) {
            Ok(bytes) => bytes.len() <= 64,
            Err(_) => true,
        }
    }

    /// Bind a resolved witness's `sig_hash` to its own signature. Returns `false` (the witness
    /// should be deferred with `Ok(false)`) when the signature hex is invalid or a pre-populated
    /// `sig_hash` disagrees with `SHA256(signature)`; otherwise sets `sig_hash` to the derived value
    /// and returns `true`. A missing signature is left untouched (a later check rejects it). Pure and
    /// synchronous so the frontier-path bind is self-contained and unit-testable without a node.
    fn bind_witness_sig_hash_to_signature(full_tx: &mut Transaction) -> bool {
        if let Some(sig_hex) = &full_tx.signature {
            let sig_bytes = match hex::decode(sig_hex) {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            let derived = Transaction::signature_hash_hex(&sig_bytes);
            if full_tx
                .sig_hash
                .as_ref()
                .is_some_and(|claimed| claimed != &derived)
            {
                return false;
            }
            full_tx.sig_hash = Some(derived);
        }
        true
    }

    // Witness resolution is bounded to the same transaction count validate_block permits, so it
    // never runs over a list larger than a valid block could carry. Because both sites use the
    // identical limit, a node with this check accepts/rejects by count exactly as one without it.
    fn witness_count_within_limit(tx_count: usize) -> bool {
        tx_count <= MAX_BLOCK_TX_COUNT
    }

    async fn request_tx_witness(
        &self,
        addr: SocketAddr,
        tx_id: &str,
        timeout: Duration,
    ) -> Result<Option<Transaction>, NodeError> {
        let request = NetworkMessage::TxRequest {
            tx_id: tx_id.to_string(),
        };
        match tokio::time::timeout(
            timeout,
            self.send_message_with_response(addr, &request),
        )
        .await
        {
            Ok(Ok(NetworkMessage::TxResponse {
                tx_id: response_id,
                tx,
            })) if response_id == tx_id => Ok(tx),
            Ok(Ok(_)) => Ok(None),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(None),
        }
    }

    fn cache_verified_compact_transaction(&self, tx: &Transaction) {
        if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
            return;
        }
        // Preserve the witness cache's verified-full-body invariant. This helper
        // is also called while preparing a stored block for relay, and stored
        // receipts intentionally carry only a 64-byte signature prefix.
        let Some(signature) = tx.signature.as_ref().and_then(|sig| hex::decode(sig).ok()) else {
            return;
        };
        if signature.len() <= 64
            || tx.sig_hash.as_deref() != Some(Transaction::signature_hash_hex(&signature).as_str())
        {
            return;
        }
        let Ok(leaf) = Blockchain::calculate_merkle_leaf_hash(tx) else {
            return;
        };
        let tx_id = tx.get_tx_id();
        self.tx_witness_cache.lock().put(tx_id.clone(), tx.clone());
        self.compact_tx_index.lock().put(leaf, tx_id);
    }

    async fn seed_compact_index_from_admitted_transaction(&self, transaction: &Transaction) {
        if let Some(admitted) = self
            .blockchain
            .read()
            .await
            .get_mempool_transaction_by_id(&transaction.get_tx_id())
            .await
        {
            if Self::witness_matches_committed_receipt(transaction, &admitted) {
                self.cache_verified_compact_transaction(&admitted);
            }
        }
    }

    fn lookup_verified_compact_transaction(&self, leaf: &[u8; 32]) -> Option<Transaction> {
        let tx_id = self.compact_tx_index.lock().get(leaf).cloned()?;
        let tx = match self.tx_witness_cache.lock().get(&tx_id).cloned() {
            Some(tx) => tx,
            None => {
                self.compact_tx_index.lock().pop(leaf);
                return None;
            }
        };
        match Blockchain::calculate_merkle_leaf_hash(&tx) {
            Ok(actual) if &actual == leaf => Some(tx),
            _ => {
                self.compact_tx_index.lock().pop(leaf);
                None
            }
        }
    }

    fn compact_transaction_encoded_bytes(tx: &Transaction) -> Option<usize> {
        codec::serialize(tx).ok().map(|bytes| bytes.len())
    }

    fn compact_hex_field_has_decoded_len(value: &str, decoded_len: usize) -> bool {
        decoded_len
            .checked_mul(2)
            .is_some_and(|encoded_len| value.len() == encoded_len)
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    }

    /// Compact transaction bodies are a witness-bearing transport contract, not
    /// stored receipts.  Merkle leaves deliberately normalize a full signature
    /// and its 64-byte stored prefix to the same commitment, so a leaf match
    /// alone cannot distinguish a body that can be validated without another
    /// network fetch.  Require the canonical full ML-DSA shape and bind the
    /// signature to its committed sig_hash before treating a body as resolved.
    fn compact_transaction_has_full_bound_witness(tx: &Transaction) -> bool {
        if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
            return true;
        }
        let (Some(signature), Some(public_key), Some(sig_hash)) = (
            tx.signature.as_deref(),
            tx.pub_key.as_deref(),
            tx.sig_hash.as_deref(),
        ) else {
            return false;
        };
        if !Self::compact_hex_field_has_decoded_len(signature, mldsa::SIGNATURE_BYTES)
            || !Self::compact_hex_field_has_decoded_len(public_key, mldsa::PUBLIC_KEY_BYTES)
            || !Self::compact_hex_field_has_decoded_len(sig_hash, 32)
        {
            return false;
        }
        let Ok(signature_bytes) = hex::decode(signature) else {
            return false;
        };
        sig_hash == Transaction::signature_hash_hex(&signature_bytes)
    }

    fn compact_block_transport_ok_at(block: &Block, activation_height: u32) -> bool {
        if block.transactions.is_empty()
            || block.transactions.len() > MAX_BLOCK_TX_COUNT
            || block.transactions[0].sender != "MINING_REWARDS"
            || !block
                .transactions
                .iter()
                .skip(1)
                .all(Self::compact_transaction_has_full_bound_witness)
        {
            return false;
        }
        let encoded_ok = codec::serialize(block)
            .map(|encoded| encoded.len() <= COMPACT_SAFE_ASSEMBLED_BYTES)
            .unwrap_or(false);
        if !encoded_ok {
            return false;
        }
        block.index < activation_height
            || Blockchain::full_witness_weight(block)
                .map(|weight| weight <= MAX_BLOCK_WEIGHT_BYTES)
                .unwrap_or(false)
    }

    fn compact_block_transport_ok(block: &Block) -> bool {
        Self::compact_block_transport_ok_at(block, FEE_SYSTEM_ACTIVATION_HEIGHT)
    }

    fn compact_full_block_matches_announcement(
        announcement: &CompactBlockV1,
        block: &Block,
    ) -> bool {
        Self::compact_block_transport_ok(block)
            && CompactBlockV1::from_block(block)
                .map(|candidate| candidate == *announcement)
                .unwrap_or(false)
    }

    fn remember_compact_full_block(&self, block: Arc<Block>, verified: bool) -> bool {
        if !Self::compact_block_transport_ok(&block) {
            return false;
        }
        let Some(encoded_bytes) = codec::serialize(block.as_ref())
            .ok()
            .map(|encoded| encoded.len())
        else {
            return false;
        };
        let retained = self.compact_full_blocks.lock().insert(
            block.hash,
            CompactFullBlockEntry {
                block: Arc::clone(&block),
                encoded_bytes,
            },
        );
        if verified {
            for tx in &block.transactions {
                self.cache_verified_compact_transaction(tx);
            }
        }
        retained
    }

    fn add_compact_source(sources: &mut Vec<SocketAddr>, source: SocketAddr) {
        if !sources.contains(&source) && sources.len() < COMPACT_SOURCE_MAX {
            sources.push(source);
        }
    }

    fn remember_pending_compact(&self, announcement: CompactBlockV1, source: SocketAddr) -> bool {
        let mut pending = self.compact_pending.lock();
        if let Some(existing) = pending.entries.get_mut(&announcement.hash) {
            if existing.announcement != announcement {
                return false;
            }
            Self::add_compact_source(&mut existing.sources, source);
            return true;
        }

        let Some(announcement_bytes) = codec::serialize(&announcement)
            .ok()
            .map(|encoded| encoded.len())
        else {
            return false;
        };
        let Some(coinbase_bytes) = Self::compact_transaction_encoded_bytes(&announcement.coinbase)
        else {
            return false;
        };
        let Some(cache_bytes) = announcement_bytes.checked_add(coinbase_bytes) else {
            return false;
        };
        if announcement_bytes > COMPACT_ANNOUNCEMENT_MAX_BYTES
            || cache_bytes > COMPACT_SAFE_ASSEMBLED_BYTES
            || coinbase_bytes > COMPACT_TRANSACTION_MAX_ENCODED_BYTES
        {
            return false;
        }

        let mut transactions = HashMap::new();
        transactions.insert(0, announcement.coinbase.clone());
        let mut transaction_sizes = HashMap::new();
        transaction_sizes.insert(0, coinbase_bytes);
        let block_hash = announcement.hash;
        pending.insert(
            block_hash,
            PendingCompactBlock {
                announcement,
                sources: vec![source],
                transactions,
                transaction_sizes,
                assembled_bytes: coinbase_bytes,
                cache_bytes,
            },
        )
    }

    fn compact_sources(&self, block_hash: &[u8; 32], primary: SocketAddr) -> Vec<SocketAddr> {
        let mut sources = vec![primary];
        if let Some(inflight) = self.compact_inflight.get(block_hash) {
            for source in &inflight.sources {
                Self::add_compact_source(&mut sources, *source);
            }
        }
        if let Some(pending) = self.compact_pending.lock().entries.peek(block_hash) {
            for source in &pending.sources {
                Self::add_compact_source(&mut sources, *source);
            }
        }
        sources
    }

    fn cache_pending_compact_transaction(
        &self,
        block_hash: &[u8; 32],
        index: u16,
        transaction: &Transaction,
    ) -> bool {
        if !Self::compact_transaction_has_full_bound_witness(transaction) {
            return false;
        }
        let Some(encoded_bytes) = Self::compact_transaction_encoded_bytes(transaction) else {
            return false;
        };
        if encoded_bytes > COMPACT_TRANSACTION_MAX_ENCODED_BYTES {
            return false;
        }

        let mut pending = self.compact_pending.lock();
        let Some((expected_hash, previous_bytes, old_assembled, old_cache_bytes)) =
            pending.entries.peek(block_hash).and_then(|entry| {
                entry
                    .announcement
                    .transaction_hashes
                    .get(index as usize)
                    .map(|expected| {
                        (
                            *expected,
                            entry.transaction_sizes.get(&index).copied().unwrap_or(0),
                            entry.assembled_bytes,
                            entry.cache_bytes,
                        )
                    })
            })
        else {
            return false;
        };
        if !Blockchain::calculate_merkle_leaf_hash(transaction)
            .map(|leaf| leaf == expected_hash)
            .unwrap_or(false)
        {
            return false;
        }
        let new_assembled = old_assembled
            .saturating_sub(previous_bytes)
            .saturating_add(encoded_bytes);
        let new_cache_bytes = old_cache_bytes
            .saturating_sub(previous_bytes)
            .saturating_add(encoded_bytes);
        let new_total_cache = pending
            .bytes
            .saturating_sub(old_cache_bytes)
            .saturating_add(new_cache_bytes);
        if new_assembled > COMPACT_SAFE_ASSEMBLED_BYTES
            || new_cache_bytes > COMPACT_SAFE_ASSEMBLED_BYTES
            || new_total_cache > COMPACT_PENDING_CACHE_BYTE_BUDGET
        {
            return false;
        }

        pending.bytes = new_total_cache;
        let Some(entry) = pending.entries.get_mut(block_hash) else {
            return false;
        };
        entry.assembled_bytes = new_assembled;
        entry.cache_bytes = new_cache_bytes;
        entry.transaction_sizes.insert(index, encoded_bytes);
        entry.transactions.insert(index, transaction.clone());
        true
    }

    fn local_compact_transactions(
        &self,
        block_hash: &[u8; 32],
        indexes: &[u16],
    ) -> (
        Vec<IndexedCompactTransactionV1>,
        Option<PendingCompactRoute>,
    ) {
        if let Some(block) = self
            .compact_full_blocks
            .lock()
            .entries
            .get(block_hash)
            .map(|entry| Arc::clone(&entry.block))
        {
            let transactions = indexes
                .iter()
                .filter_map(|index| {
                    block
                        .transactions
                        .get(*index as usize)
                        .cloned()
                        .map(|transaction| IndexedCompactTransactionV1 {
                            index: *index,
                            transaction,
                        })
                })
                .collect();
            return (transactions, None);
        }

        let (mut transactions, route) = {
            let mut pending = self.compact_pending.lock();
            let Some(entry) = pending.entries.get(block_hash) else {
                return (Vec::new(), None);
            };
            let mut transactions = Vec::with_capacity(indexes.len());
            for index in indexes {
                if let Some(transaction) = entry.transactions.get(index).cloned() {
                    transactions.push(IndexedCompactTransactionV1 {
                        index: *index,
                        transaction,
                    });
                }
            }
            (
                transactions,
                PendingCompactRoute {
                    announcement: entry.announcement.clone(),
                    sources: entry.sources.clone(),
                },
            )
        };
        if route.announcement.transaction_hashes.is_empty() {
            return (Vec::new(), None);
        }
        let mut have: HashSet<u16> = transactions.iter().map(|item| item.index).collect();
        for index in indexes {
            if have.contains(index) {
                continue;
            }
            let idx = *index as usize;
            if let Some(leaf) = route.announcement.transaction_hashes.get(idx) {
                if let Some(transaction) = self.lookup_verified_compact_transaction(leaf) {
                    have.insert(*index);
                    transactions.push(IndexedCompactTransactionV1 {
                        index: *index,
                        transaction,
                    });
                }
            }
        }
        (transactions, Some(route))
    }

    async fn request_compact_transaction_batch(
        &self,
        addr: SocketAddr,
        block_hash: [u8; 32],
        indexes: Vec<u16>,
        proxy_hops: u8,
        request_timeout: Duration,
    ) -> Result<Vec<IndexedCompactTransactionV1>, NodeError> {
        if !TCP_COMPACT_V1_ENABLED {
            return Err(NodeError::Network(
                "TCP compact transport is disabled".into(),
            ));
        }
        if indexes.is_empty() || indexes.len() > COMPACT_TX_BATCH_MAX {
            return Err(NodeError::Network(
                "Invalid compact transaction request batch".into(),
            ));
        }
        let requested: HashSet<u16> = indexes.iter().copied().collect();
        if requested.len() != indexes.len() {
            return Err(NodeError::Network(
                "Duplicate compact transaction request index".into(),
            ));
        }
        let request = NetworkMessage::GetCompactTransactionsV1 {
            block_hash,
            indexes,
            proxy_hops: proxy_hops.min(COMPACT_PROXY_HOPS_MAX),
        };
        let response = tokio::time::timeout(
            request_timeout.min(Duration::from_secs(5)),
            self.send_message_with_response(addr, &request),
        )
        .await
        .map_err(|_| NodeError::Timeout("Compact transaction request timed out".into()))??;
        match response {
            NetworkMessage::CompactTransactionsV1 {
                block_hash: response_hash,
                transactions,
            } if response_hash == block_hash => {
                let mut seen = HashSet::with_capacity(transactions.len());
                if transactions.len() > COMPACT_TX_BATCH_MAX
                    || transactions
                        .iter()
                        .any(|item| !requested.contains(&item.index) || !seen.insert(item.index))
                    || codec::serialize(&transactions)
                        .map(|encoded| encoded.len() > COMPACT_RESPONSE_MAX_BYTES)
                        .unwrap_or(true)
                    || transactions.iter().any(|item| {
                        Self::compact_transaction_encoded_bytes(&item.transaction)
                            .map(|bytes| bytes > COMPACT_TRANSACTION_MAX_ENCODED_BYTES)
                            .unwrap_or(true)
                    })
                {
                    return Err(NodeError::Network(
                        "Invalid compact transaction response".into(),
                    ));
                }
                Ok(transactions)
            }
            _ => Err(NodeError::Network(
                "Unexpected compact transaction response".into(),
            )),
        }
    }

    async fn serve_compact_transactions(
        &self,
        requester: SocketAddr,
        block_hash: [u8; 32],
        indexes: Vec<u16>,
        proxy_hops: u8,
    ) -> Result<Vec<IndexedCompactTransactionV1>, NodeError> {
        if !TCP_COMPACT_V1_ENABLED {
            return Ok(Vec::new());
        }
        if indexes.is_empty() || indexes.len() > COMPACT_TX_BATCH_MAX {
            return Err(NodeError::Network(
                "Invalid compact transaction request size".into(),
            ));
        }
        let requested: HashSet<u16> = indexes.iter().copied().collect();
        if requested.len() != indexes.len()
            || indexes
                .iter()
                .any(|index| *index as usize >= MAX_BLOCK_TX_COUNT)
        {
            return Err(NodeError::Network(
                "Invalid compact transaction request index".into(),
            ));
        }
        let rate_key = format!("compact_tx_body:{}", requester);
        let rate_cost = 1usize.saturating_add(indexes.len().div_ceil(16));
        if !(0..rate_cost).all(|_| self.rate_limiter.check_limit(&rate_key)) {
            return Err(NodeError::Network(
                "Compact transaction request rate limited".into(),
            ));
        }

        let (mut found, pending) = self.local_compact_transactions(&block_hash, &indexes);
        let mut have: HashSet<u16> = found.iter().map(|item| item.index).collect();
        let missing: Vec<u16> = indexes
            .iter()
            .copied()
            .filter(|index| !have.contains(index))
            .collect();

        // A cut-through relay may not have finished reconstructing when its
        // downstream asks. Proxy the single bounded batch toward the original
        // source, then retain exact-commitment-matched bodies for later peers.
        if !missing.is_empty() && proxy_hops > 0 {
            if let Some(route) = pending {
                for source in route.sources {
                    if source == requester || !self.peer_supports_compact_v1(source) {
                        continue;
                    }
                    if let Ok(proxied) = self
                        .request_compact_transaction_batch(
                            source,
                            block_hash,
                            missing.clone(),
                            proxy_hops.saturating_sub(1),
                            Duration::from_secs(5),
                        )
                        .await
                    {
                        for item in proxied {
                            let idx = item.index as usize;
                            let valid = route
                                .announcement
                                .transaction_hashes
                                .get(idx)
                                .and_then(|expected| {
                                    Blockchain::calculate_merkle_leaf_hash(&item.transaction)
                                        .ok()
                                        .map(|actual| &actual == expected)
                                })
                                .unwrap_or(false)
                                && Self::compact_transaction_has_full_bound_witness(
                                    &item.transaction,
                                );
                            if valid && have.insert(item.index) {
                                self.cache_pending_compact_transaction(
                                    &block_hash,
                                    item.index,
                                    &item.transaction,
                                );
                                found.push(item);
                            }
                        }
                    }
                    if have.len() == indexes.len() {
                        break;
                    }
                }
            }
        }

        found.sort_unstable_by_key(|item| item.index);
        // The request count is bounded, but historical/pre-activation transaction
        // strings can still be unusually large. Bound the response by encoded
        // bytes as well so the connection writer never discovers too late that a
        // syntactically valid batch exceeds the encrypted 4 MiB frame.
        let mut encoded_bytes = 1024usize; // enum/vector/envelope + AEAD headroom
        let mut bounded = Vec::with_capacity(found.len());
        for item in found {
            let item_bytes = codec::serialize(&item)
                .map(|bytes| bytes.len())
                .unwrap_or(MAX_MESSAGE_SIZE);
            let Some(next) = encoded_bytes.checked_add(item_bytes) else {
                break;
            };
            if next > COMPACT_RESPONSE_MAX_BYTES {
                break;
            }
            encoded_bytes = next;
            bounded.push(item);
        }
        Ok(bounded)
    }

    async fn request_compact_full_block(
        &self,
        addr: SocketAddr,
        block_hash: [u8; 32],
        proxy_hops: u8,
        request_timeout: Duration,
    ) -> Result<Option<Block>, NodeError> {
        if !TCP_COMPACT_V1_ENABLED {
            return Err(NodeError::Network(
                "TCP compact transport is disabled".into(),
            ));
        }
        let request = NetworkMessage::GetCompactBlockV1 {
            block_hash,
            proxy_hops: proxy_hops.min(COMPACT_PROXY_HOPS_MAX),
        };
        let response = tokio::time::timeout(
            request_timeout.min(Duration::from_secs(5)),
            self.send_message_with_response(addr, &request),
        )
        .await
        .map_err(|_| NodeError::Timeout("Compact block fallback timed out".into()))??;
        match response {
            NetworkMessage::CompactBlockResponseV1 {
                block_hash: response_hash,
                block,
            } if response_hash == block_hash => Ok(block.filter(|b| b.hash == block_hash)),
            _ => Err(NodeError::Network(
                "Unexpected compact block fallback response".into(),
            )),
        }
    }

    async fn serve_compact_full_block(
        &self,
        requester: SocketAddr,
        block_hash: [u8; 32],
        proxy_hops: u8,
    ) -> Option<Block> {
        if !TCP_COMPACT_V1_ENABLED {
            return None;
        }
        let rate_key = format!("compact_full_body:{}", requester);
        if !(0..16).all(|_| self.rate_limiter.check_limit(&rate_key)) {
            return None;
        }
        if let Some(block) = self
            .compact_full_blocks
            .lock()
            .entries
            .get(&block_hash)
            .map(|entry| Arc::clone(&entry.block))
        {
            return Some((*block).clone());
        }

        let sources = self
            .compact_pending
            .lock()
            .entries
            .peek(&block_hash)
            .map(|entry| entry.sources.clone())
            .unwrap_or_default();
        if proxy_hops > 0 {
            for source in sources {
                if source == requester || !self.peer_supports_compact_v1(source) {
                    continue;
                }
                if let Ok(Some(block)) = self
                    .request_compact_full_block(
                        source,
                        block_hash,
                        proxy_hops.saturating_sub(1),
                        Duration::from_secs(5),
                    )
                    .await
                {
                    if block.calculate_hash_for_block() == block.hash
                        && block.verify_pow_meets_floor()
                        && Blockchain::calculate_merkle_root(&block.transactions)
                            .map(|root| root == block.merkle_root)
                            .unwrap_or(false)
                        && Self::compact_block_transport_ok(&block)
                    {
                        let block = Arc::new(block);
                        self.remember_compact_full_block(Arc::clone(&block), false);
                        return Some((*block).clone());
                    }
                }
            }
        }
        None
    }

    fn apply_compact_body(
        announcement: &CompactBlockV1,
        transactions: &mut [Option<Transaction>],
        assembled_bytes: &mut usize,
        item: IndexedCompactTransactionV1,
    ) -> Result<bool, NodeError> {
        let idx = item.index as usize;
        if idx >= transactions.len() || transactions[idx].is_some() {
            return Ok(false);
        }
        if !Self::compact_transaction_has_full_bound_witness(&item.transaction) {
            return Ok(false);
        }
        let Some(encoded_bytes) = Self::compact_transaction_encoded_bytes(&item.transaction) else {
            return Ok(false);
        };
        if encoded_bytes > COMPACT_TRANSACTION_MAX_ENCODED_BYTES {
            return Err(NodeError::Network(
                "Compact transaction body exceeds transport limit".into(),
            ));
        }
        if !Blockchain::calculate_merkle_leaf_hash(&item.transaction)
            .map(|leaf| leaf == announcement.transaction_hashes[idx])
            .unwrap_or(false)
        {
            return Ok(false);
        }
        let Some(next_bytes) = assembled_bytes.checked_add(encoded_bytes) else {
            return Err(NodeError::Network(
                "Compact transaction assembly overflow".into(),
            ));
        };
        if next_bytes > COMPACT_SAFE_ASSEMBLED_BYTES {
            return Err(NodeError::Network(
                "Compact transaction assembly exceeds transport limit".into(),
            ));
        }
        *assembled_bytes = next_bytes;
        transactions[idx] = Some(item.transaction);
        Ok(true)
    }

    fn missing_compact_indexes(transactions: &[Option<Transaction>]) -> Vec<u16> {
        transactions
            .iter()
            .enumerate()
            .filter_map(|(idx, tx)| tx.is_none().then_some(idx as u16))
            .collect()
    }

    fn compact_deadline_remaining(deadline: Instant) -> Option<Duration> {
        deadline.checked_duration_since(Instant::now())
    }

    fn reconstruct_compact_block_locally(
        &self,
        announcement: &CompactBlockV1,
    ) -> Result<Option<Block>, NodeError> {
        let mut transactions = Vec::with_capacity(announcement.transaction_hashes.len());
        transactions.push(announcement.coinbase.clone());
        let mut assembled_bytes =
            Self::compact_transaction_encoded_bytes(&announcement.coinbase)
                .ok_or_else(|| NodeError::Network("Compact coinbase encoding failed".into()))?;
        for leaf in announcement.transaction_hashes.iter().skip(1) {
            let Some(transaction) = self.lookup_verified_compact_transaction(leaf) else {
                return Ok(None);
            };
            let Some(encoded_bytes) = Self::compact_transaction_encoded_bytes(&transaction) else {
                return Ok(None);
            };
            if encoded_bytes > COMPACT_TRANSACTION_MAX_ENCODED_BYTES {
                return Ok(None);
            }
            assembled_bytes = assembled_bytes
                .checked_add(encoded_bytes)
                .ok_or_else(|| NodeError::Network("Compact local assembly overflow".into()))?;
            if assembled_bytes > COMPACT_SAFE_ASSEMBLED_BYTES {
                return Ok(None);
            }
            transactions.push(transaction);
        }
        let block = announcement.reconstruct(transactions)?;
        if !Self::compact_block_transport_ok(&block) {
            return Ok(None);
        }
        Ok(Some(block))
    }

    async fn reconstruct_compact_block(
        &self,
        announcement: &CompactBlockV1,
        primary_source: SocketAddr,
    ) -> Result<Option<(Block, SocketAddr)>, NodeError> {
        let deadline = Instant::now() + COMPACT_RESOLVE_DEADLINE;
        let mut transactions: Vec<Option<Transaction>> =
            vec![None; announcement.transaction_hashes.len()];
        transactions[0] = Some(announcement.coinbase.clone());
        let mut assembled_bytes =
            Self::compact_transaction_encoded_bytes(&announcement.coinbase)
                .ok_or_else(|| NodeError::Network("Compact coinbase encoding failed".into()))?;
        if assembled_bytes > COMPACT_SAFE_ASSEMBLED_BYTES {
            return Ok(None);
        }

        for (idx, leaf) in announcement.transaction_hashes.iter().enumerate().skip(1) {
            if let Some(tx) = self.lookup_verified_compact_transaction(leaf) {
                let Some(tx_bytes) = Self::compact_transaction_encoded_bytes(&tx) else {
                    continue;
                };
                if tx_bytes > COMPACT_TRANSACTION_MAX_ENCODED_BYTES {
                    continue;
                }
                let Some(next) = assembled_bytes.checked_add(tx_bytes) else {
                    return Ok(None);
                };
                if next > COMPACT_SAFE_ASSEMBLED_BYTES {
                    return Ok(None);
                }
                assembled_bytes = next;
                transactions[idx] = Some(tx);
            }
        }

        let mut attempted = HashSet::new();
        let mut witness_source = primary_source;
        loop {
            let source = self
                .compact_sources(&announcement.hash, primary_source)
                .into_iter()
                .find(|candidate| attempted.insert(*candidate));
            let Some(source) = source else {
                break;
            };
            let missing = Self::missing_compact_indexes(&transactions);
            if missing.is_empty() {
                break;
            }
            for batch in missing.chunks(COMPACT_TX_BATCH_MAX) {
                let Some(remaining) = Self::compact_deadline_remaining(deadline) else {
                    break;
                };
                let response = match self
                    .request_compact_transaction_batch(
                        source,
                        announcement.hash,
                        batch.to_vec(),
                        COMPACT_PROXY_HOPS_MAX,
                        remaining,
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(_) => break,
                };
                for item in response {
                    let index = item.index;
                    if Self::apply_compact_body(
                        announcement,
                        &mut transactions,
                        &mut assembled_bytes,
                        item,
                    )? {
                        if let Some(transaction) =
                            transactions.get(index as usize).and_then(Option::as_ref)
                        {
                            self.cache_pending_compact_transaction(
                                &announcement.hash,
                                index,
                                transaction,
                            );
                        }
                        witness_source = source;
                    }
                }
            }
        }

        if transactions.iter().any(Option::is_none) {
            let mut fallback_attempted = HashSet::new();
            loop {
                let source = self
                    .compact_sources(&announcement.hash, primary_source)
                    .into_iter()
                    .find(|candidate| fallback_attempted.insert(*candidate));
                let Some(source) = source else {
                    return Ok(None);
                };
                let Some(remaining) = Self::compact_deadline_remaining(deadline) else {
                    return Ok(None);
                };
                if let Ok(Some(full)) = self
                    .request_compact_full_block(
                        source,
                        announcement.hash,
                        COMPACT_PROXY_HOPS_MAX,
                        remaining,
                    )
                    .await
                {
                    if Self::compact_full_block_matches_announcement(announcement, &full) {
                        return Ok(Some((full, source)));
                    }
                }
            }
        }

        let complete = transactions
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| NodeError::InvalidBlock("compact reconstruction incomplete".into()))?;
        let block = announcement.reconstruct(complete)?;
        if !Self::compact_block_transport_ok(&block) {
            return Ok(None);
        }
        Ok(Some((block, witness_source)))
    }

    async fn process_compact_block(
        &self,
        announcement: CompactBlockV1,
        source: SocketAddr,
        events: &mpsc::Sender<NetworkEvent>,
    ) -> Result<(), NodeError> {
        if !TCP_COMPACT_V1_ENABLED {
            return Ok(());
        }
        if !self.remember_pending_compact(announcement.clone(), source) {
            return Ok(());
        }

        // Cut-through is deliberately narrower than acceptance: only a strict
        // local-tip extension is relayed, and only after the compact's header,
        // PoW and ordered Merkle commitment passed. Full transaction validation
        // remains mandatory below before state is touched.
        if self.compact_extends_local_tip(&announcement).await {
            let targets: Vec<_> = {
                let peers = self.peers.read().await;
                self.select_broadcast_peers(&peers, peers.len().min(16))
            }
            .into_iter()
            .filter(|peer| *peer != source && self.peer_supports_compact_v1(*peer))
            .collect();
            if !targets.is_empty() {
                let node = self.clone();
                let compact = Arc::new(announcement.clone());
                tokio::spawn(async move {
                    if let Err(err) = node
                        .broadcast_compact_block(compact, Some(source), targets)
                        .await
                    {
                        warn!("Compact cut-through relay failed: {}", err);
                    }
                });
            }
        }

        let Some((block, witness_source)) = self
            .reconstruct_compact_block(&announcement, source)
            .await?
        else {
            debug!(
                "Compact block {} deferred: transaction bodies unavailable",
                announcement.index
            );
            return Ok(());
        };
        let block = Arc::new(block);
        self.remember_compact_full_block(Arc::clone(&block), false);

        if !self
            .verify_block_with_witness(&block, Some(witness_source))
            .await?
        {
            return Ok(());
        }

        self.network_bloom.insert(&block.hash);
        self.blockchain.write().await.save_block(&block).await?;
        self.remember_compact_full_block(Arc::clone(&block), true);
        self.compact_pending.lock().remove(&block.hash);
        self.publish_discovery_state("Accepted compact block").await;
        events
            .send(NetworkEvent::NewBlock((*block).clone()))
            .await
            .map_err(|e| NodeError::Network(format!("Failed to send block event: {}", e)))?;

        // The compact relay claim is independent, so older peers still receive
        // the fully-validated body exactly once after acceptance.
        if self.claim_relay(&block.hash) {
            let selected_peers = {
                let peers = self.peers.read().await;
                self.select_broadcast_peers(&peers, peers.len().min(16))
            };
            if let Err(err) = self
                .broadcast_block(Arc::clone(&block), Some(source), selected_peers, true)
                .await
            {
                warn!("Post-accept compact block propagation failed: {}", err);
            }
        }
        Ok(())
    }

    async fn process_compact_competitor_fallback(
        &self,
        announcement: CompactBlockV1,
        source: SocketAddr,
        events: &mpsc::Sender<NetworkEvent>,
    ) -> Result<(), NodeError> {
        if !TCP_COMPACT_V1_ENABLED {
            return Ok(());
        }
        if !self.remember_pending_compact(announcement.clone(), source) {
            return Ok(());
        }
        let Some(started) = Self::claim_compact_inflight_in(
            &self.compact_inflight,
            announcement.hash,
            source,
            Instant::now(),
        ) else {
            return Ok(());
        };

        let block_hash = announcement.hash;
        let result = async {
            let deadline = Instant::now() + COMPACT_FORK_FALLBACK_DEADLINE;
            let Some(wait) = Self::compact_deadline_remaining(deadline) else {
                return Ok(());
            };
            let Ok(Ok(_permit)) = tokio::time::timeout(
                wait,
                Arc::clone(&self.compact_fork_fallback_slots).acquire_owned(),
            )
            .await
            else {
                return Ok(());
            };

            let mut attempted = HashSet::new();
            loop {
                let candidate = self
                    .compact_sources(&block_hash, source)
                    .into_iter()
                    .find(|peer| attempted.insert(*peer));
                let Some(candidate) = candidate else {
                    return Ok(());
                };
                let Some(remaining) = Self::compact_deadline_remaining(deadline) else {
                    return Ok(());
                };
                let Ok(Some(full)) = self
                    .request_compact_full_block(
                        candidate,
                        block_hash,
                        COMPACT_PROXY_HOPS_MAX,
                        remaining,
                    )
                    .await
                else {
                    continue;
                };
                if !Self::compact_full_block_matches_announcement(&announcement, &full) {
                    continue;
                }

                // Re-enter the ordinary full-block event path. It performs the
                // same standalone validation, save/orphan/reorg handling, bloom
                // commit, and relay semantics as pre-compact TCP delivery.
                self.remember_compact_full_block(Arc::new(full.clone()), false);
                events
                    .send(NetworkEvent::NewBlock(full))
                    .await
                    .map_err(|err| {
                        NodeError::Network(format!(
                            "Failed to enqueue compact competitor fallback: {}",
                            err
                        ))
                    })?;
                self.compact_pending.lock().remove(&block_hash);
                return Ok(());
            }
        }
        .await;
        self.release_compact_inflight(&block_hash, started);
        result
    }

    /// Atomically claim reconstruction work for one block hash. Returning the
    /// start token lets the caller release only its own claim; an older timed-out
    /// worker can never erase a replacement worker's entry.
    fn claim_compact_inflight_in(
        inflight: &DashMap<[u8; 32], CompactInflight>,
        block_hash: [u8; 32],
        source: SocketAddr,
        started: Instant,
    ) -> Option<Instant> {
        match inflight.entry(block_hash) {
            Entry::Occupied(mut entry) => {
                if entry.get().started.elapsed() < COMPACT_INFLIGHT_TTL {
                    Self::add_compact_source(&mut entry.get_mut().sources, source);
                    None
                } else {
                    entry.insert(CompactInflight {
                        started,
                        sources: vec![source],
                    });
                    Some(started)
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(CompactInflight {
                    started,
                    sources: vec![source],
                });
                Some(started)
            }
        }
    }

    /// Admit scarce reconstruction work only for a compact header that is an
    /// exact next-block candidate for the supplied parent. The parent/difficulty
    /// check intentionally happens before both the in-flight claim and semaphore:
    /// unrelated-fork announcements remain available to the ordinary
    /// header/full-block convergence paths, but cannot starve the low-latency
    /// local-tip path.
    fn try_claim_compact_reconstruction_in(
        compact: &CompactBlockV1,
        parent: &Block,
        inflight: &DashMap<[u8; 32], CompactInflight>,
        slots: &Arc<Semaphore>,
        source: SocketAddr,
        started: Instant,
    ) -> Option<(Instant, tokio::sync::OwnedSemaphorePermit)> {
        if !Self::compact_header_extends_parent(compact, parent) {
            return None;
        }
        let claimed = Self::claim_compact_inflight_in(inflight, compact.hash, source, started)?;
        match Arc::clone(slots).try_acquire_owned() {
            Ok(permit) => Some((claimed, permit)),
            Err(_) => {
                inflight.remove_if(&compact.hash, |_, current| current.started == claimed);
                None
            }
        }
    }

    async fn try_claim_compact_reconstruction(
        &self,
        compact: &CompactBlockV1,
        source: SocketAddr,
    ) -> Option<(Instant, tokio::sync::OwnedSemaphorePermit)> {
        let parent = self.blockchain.read().await.get_last_block()?;
        Self::try_claim_compact_reconstruction_in(
            compact,
            &parent,
            &self.compact_inflight,
            &self.compact_reconstruction_slots,
            source,
            Instant::now(),
        )
    }

    fn release_compact_inflight(&self, block_hash: &[u8; 32], started: Instant) {
        self.compact_inflight
            .remove_if(block_hash, |_, current| current.started == started);
    }

    /// Cache key for a block's validation verdict.
    ///
    /// `block.hash` identifies a block; it does not determine the transaction
    /// bytes that were validated to produce a verdict about it. The merkle leaf
    /// is built through `with_truncated_signature`, which normalises and shortens
    /// the per-transaction signature material, so the committed root — and hence
    /// the hash — is not a function of all of it. Filing a verdict under the bare
    /// hash therefore describes bytes the next block bearing that hash need not
    /// have, and that is unsound in both directions.
    ///
    /// Nor does the header pin the bodies at all: it carries the merkle_root as
    /// a CLAIMED field, so a block can present an honest header over transactions
    /// that do not reproduce it. The key therefore folds in every transaction
    /// field, not merely the authenticating ones — a body that fails to
    /// reproduce its claimed root is precisely the sort that loses validation,
    /// and its verdict must not be filed against the block that legitimately
    /// owns that header.
    ///
    /// The result is the property this cache assumed it already had: an entry
    /// describes exactly the bytes that earned it, and identical bytes still
    /// short-circuit, so the replay protection the cache exists for is kept.
    ///
    /// Local only — this key never leaves the process, so a node running it
    /// agrees with every older node on exactly which blocks are valid.
    fn validation_cache_key(block: &Block) -> String {
        let mut hasher = blake3::Hasher::new();
        for tx in &block.transactions {
            // EVERY field, not only the authenticating ones. `block.hash` covers a
            // 92-byte header carrying the CLAIMED merkle_root, and nothing forces
            // that claim to describe the transactions actually attached — a body
            // whose root does not reproduce is exactly the kind that fails
            // validation, and it must not file its verdict against the honest
            // block that legitimately owns the header.
            hasher.update(&tx.fee_units.to_le_bytes());
            hasher.update(&tx.amount_units.to_le_bytes());
            hasher.update(&tx.timestamp.to_le_bytes());
            // Length-prefixed so ("ab","") and ("a","b") cannot collide.
            for field in [
                Some(tx.sender.as_str()),
                Some(tx.recipient.as_str()),
                tx.signature.as_deref(),
                tx.pub_key.as_deref(),
                tx.sig_hash.as_deref(),
            ] {
                let bytes = field.unwrap_or("").as_bytes();
                hasher.update(&(bytes.len() as u64).to_le_bytes());
                hasher.update(bytes);
            }
        }
        let bodies = hasher.finalize();
        // Domain-tagged: block and transaction verdicts share one map, and without
        // the tag their key shapes are format-identical (64-hex, colon, 32-hex).
        // A cross-domain collision would need a 128-bit prefix match on distinct
        // content — astronomically unlikely; the byte makes it impossible instead.
        format!("b:{}:{}", hex::encode(block.hash), &bodies.to_hex()[..32])
    }

    /// Whether a watchdog probe counts as evidence the node is wedged.
    ///
    /// A failed lock probe alone does not: tokio's RwLock is write-preferring, so any long
    /// legitimate write — a balance rebuild, a catch-up, a dirty-state recovery, a bootstrap
    /// import — starves a read probe exactly the way a deadlock would. The two are only
    /// separable by whether work is still getting done, so chain progress excuses a failed
    /// chain probe. It can only ever suppress a strike: a wedged chain cannot advance its
    /// progress counter, so a real wedge still strikes on schedule.
    ///
    /// Pure, so the policy is testable without a clock, a lock or a chain.
    fn watchdog_strikes(chain_ok: bool, chain_progressing: bool, peers_ok: bool) -> bool {
        !((chain_ok || chain_progressing) && peers_ok)
    }

    /// Cache key for a transaction's validation verdict.
    ///
    /// A cached verdict must be retrievable only by the message that earned it.
    /// `create_hash()` covers the envelope — sender, recipient, amount, fee,
    /// timestamp — and none of the fields that authenticate it, so it is an
    /// identifier, not a key: distinct messages share one. Folding the
    /// authenticating fields in restores the property this cache assumed it
    /// already had, in both directions — a verdict can neither answer for a
    /// message it never saw, nor let one short-circuit to a re-broadcast on the
    /// strength of another's result.
    ///
    /// Local only; this key never reaches the wire, so it changes nothing about
    /// which transactions any node considers valid.
    fn transaction_cache_key(tx: &Transaction) -> String {
        let mut hasher = blake3::Hasher::new();
        for field in [
            tx.signature.as_deref(),
            tx.pub_key.as_deref(),
            tx.sig_hash.as_deref(),
        ] {
            let bytes = field.unwrap_or("").as_bytes();
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        // Domain-tagged for the same reason the block key is: one map, two kinds
        // of verdict, and a tag byte that keeps them structurally disjoint.
        format!("t:{}:{}", tx.create_hash(), &hasher.finalize().to_hex()[..32])
    }

    fn is_validation_cache_entry_fresh(entry: &ValidationCacheEntry, now: SystemTime) -> bool {
        now.duration_since(entry.timestamp)
            .map(|age| age.as_secs() < VALIDATION_CACHE_TTL_SECS)
            .unwrap_or(false)
    }

    fn prune_validation_cache_entries(
        cache: &DashMap<String, ValidationCacheEntry>,
        now: SystemTime,
        ttl_secs: u64,
        ceiling: usize,
        trim_target: usize,
    ) {
        let expired_keys: Vec<String> = cache
            .iter()
            .filter_map(|entry| {
                let expired = now
                    .duration_since(entry.timestamp)
                    .map(|age| age.as_secs() >= ttl_secs)
                    .unwrap_or(true);
                expired.then(|| entry.key().clone())
            })
            .collect();
        for key in expired_keys {
            cache.remove(&key);
        }

        // Gate the size pass on the CEILING, trim down to the low-water mark — and own
        // that gate here, so every caller pays it identically. The insert path already
        // gated on the ceiling before calling in, but the maintenance tick called in
        // unconditionally: any tick that found the cache in the band between the mark
        // and the ceiling paid a full collect-and-select pass and evicted up to the
        // whole band of still-fresh entries — the same wrong bound the bpos trim
        // shipped with, in mirror form (the gate lived on one caller and not the
        // other). Expiry above runs regardless; freshness has no size threshold.
        if cache.len() <= ceiling {
            return;
        }

        let mut entries: Vec<(String, u64)> = cache
            .iter()
            .map(|entry| {
                let timestamp = entry
                    .timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                (entry.key().clone(), timestamp)
            })
            .collect();
        // Only the oldest `excess` are wanted and their order among themselves does not
        // matter, so partition rather than sort. The count comes from what was actually
        // collected rather than the earlier length read, which concurrent inserts and
        // removals can already have invalidated.
        let excess = entries.len().saturating_sub(trim_target);
        if excess < entries.len() {
            entries.select_nth_unstable_by_key(excess, |(_, timestamp)| *timestamp);
        }
        for (key, _) in entries.into_iter().take(excess) {
            cache.remove(&key);
        }
    }

    fn prune_validation_cache(&self) {
        Self::prune_validation_cache_entries(
            &self.validation_cache,
            SystemTime::now(),
            VALIDATION_CACHE_TTL_SECS,
            VALIDATION_CACHE_MAX_ENTRIES,
            VALIDATION_CACHE_TRIM_TARGET,
        );
    }

    fn maybe_prune_validation_cache(&self) {
        // Cheap short-circuit only — the authoritative gate lives inside the prune,
        // which the maintenance tick also calls. Without this check every insert
        // would pay the full expiry scan; with it, only inserts at the ceiling do.
        if self.validation_cache.len() > VALIDATION_CACHE_MAX_ENTRIES {
            self.prune_validation_cache();
        }
    }

    pub async fn validate_transaction(
        &self,
        tx: &Transaction,
        block: Option<&Block>,
    ) -> Result<bool, NodeError> {
        let blockchain = self.blockchain.read().await;

        // Skip validation for mining rewards in blocks
        if tx.sender == "MINING_REWARDS" && block.is_some() {
            return Ok(true);
        }

        // Validate transaction using blockchain logic
        match blockchain.validate_transaction(tx, block).await {
            Ok(_) => Ok(true),
            Err(e) => {
                debug!("Transaction validation failed: {}", e);
                Ok(false)
            }
        }
    }

    pub async fn send_message(
        &self,
        addr: SocketAddr,
        message: &NetworkMessage,
    ) -> Result<(), NodeError> {
        const TIMEOUT: Duration = Duration::from_secs(5);
        const MAX_ATTEMPTS: u32 = 2;

        if !TCP_COMPACT_V1_ENABLED && Self::is_tcp_compact_extension(message) {
            return Err(NodeError::Network(
                "TCP compact transport is disabled".to_string(),
            ));
        }

        // Rate limit check. Blocks are exempt: a burst of tx/gossip traffic to a peer must
        // never spend the budget that a block send needs, since dropping a block send stalls
        // propagation and raises the orphan rate. Our own block sends are already bounded by
        // the valid-PoW production rate and guarded by the outbound circuit breaker below, so
        // exempting them adds no amplification. All other message types stay paced per peer.
        if !matches!(
            message,
            NetworkMessage::Block(_) | NetworkMessage::CompactBlockV1(_)
        ) {
            let rate_key = format!("send_to_{}", addr);
            if !self.rate_limiter.check_limit(&rate_key) {
                return Err(NodeError::Network("Rate limit exceeded".to_string()));
            }
        }

        let mut last_error = None;
        for attempt in 0..MAX_ATTEMPTS {
            self.check_outbound_circuit(addr).await?;

            let conn = match self.get_or_create_outbound_connection(addr).await {
                Ok(conn) => conn,
                Err(e) => {
                    self.record_outbound_failure(addr).await;
                    last_error = Some(e);
                    if attempt + 1 < MAX_ATTEMPTS {
                        tokio::time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
                        continue;
                    }
                    break;
                }
            };

            let mut stream_guard = conn.lock().await;
            // Same desync guard as send_message_with_response: a cancelled prior
            // exchange (or cancelled partial write) leaves this socket's framing in an
            // unknown state — discard instead of stacking a fresh frame onto it.
            if stream_guard.exchange_armed {
                drop(stream_guard);
                self.remove_outbound_connection(addr).await;
                last_error = Some(NodeError::Network(format!(
                    "Discarded desynced pooled connection to {}",
                    addr
                )));
                continue;
            }
            stream_guard.exchange_armed = true;
            let result: Result<(), NodeError> = async {
                let shared_secret = stream_guard.shared_secret.clone();
                let data = self.encrypt_message(message, &shared_secret)?;
                if data.is_empty() {
                    return Err(NodeError::Network(
                        "Refusing to send empty message".to_string(),
                    ));
                }
                if data.len() > MAX_MESSAGE_SIZE {
                    return Err(NodeError::Network("Outgoing message too large".to_string()));
                }

                tokio::time::timeout(TIMEOUT, async {
                    stream_guard
                        .stream
                        .write_all(&(data.len() as u32).to_be_bytes())
                        .await?;
                    stream_guard.stream.write_all(&data).await?;
                    stream_guard.stream.flush().await?;
                    Ok::<_, std::io::Error>(())
                })
                .await
                .map_err(|_| NodeError::Network(format!("Send timeout to {}", addr)))?
                .map_err(NodeError::from)
            }
            .await;
            // Completed (not cancelled): the frame either went out whole (Ok) or the
            // connection is about to be evicted (Err) — disarm either way.
            stream_guard.exchange_armed = false;
            stream_guard.last_used = Instant::now();
            stream_guard.last_used_wall = SystemTime::now();
            drop(stream_guard);

            match result {
                Ok(()) => {
                    self.record_outbound_success(addr).await;
                    return Ok(());
                }
                Err(e) => {
                    self.record_outbound_failure(addr).await;
                    self.remove_outbound_connection(addr).await;
                    last_error = Some(e);
                    if attempt + 1 < MAX_ATTEMPTS {
                        tokio::time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            NodeError::Network(format!("Failed to send message to {} after retries", addr))
        }))
    }

    fn witness_cache_capacity() -> NonZeroUsize {
        let default_size = 20_000usize;
        let size = std::env::var("ALPHANUMERIC_TX_WITNESS_CACHE_SIZE")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(default_size);
        NonZeroUsize::new(size)
            .or_else(|| NonZeroUsize::new(default_size))
            .unwrap_or(NonZeroUsize::MIN)
    }

    // Process incoming network messages from other nodes
    pub async fn receive_message(&self, addr: SocketAddr) -> Result<NetworkMessage, NodeError> {
        const TIMEOUT: Duration = Duration::from_secs(10);

        // Connect with timeout
        let mut stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| NodeError::Network(format!("Connection timeout to {}", addr)))??;

        // Read message length
        let mut len_bytes = [0u8; 4];
        tokio::time::timeout(TIMEOUT, stream.read_exact(&mut len_bytes))
            .await
            .map_err(|_| NodeError::Network(format!("Read timeout from {}", addr)))??;

        let len = u32::from_be_bytes(len_bytes) as usize;
        if len == 0 {
            return Err(NodeError::Network("Empty message".to_string()));
        }
        if len > MAX_MESSAGE_SIZE {
            return Err(NodeError::Network("Message too large".to_string()));
        }

        // Read message data
        let mut data = vec![0u8; len];
        tokio::time::timeout(TIMEOUT, stream.read_exact(&mut data))
            .await
            .map_err(|_| NodeError::Network(format!("Read timeout from {}", addr)))??;

        // Decrypt if needed
        let shared_secret = self.peer_secrets.read().await.get(&addr).cloned();
        let message = if let Some(secret) = shared_secret {
            self.decrypt_message(&data, &secret)?
        } else {
            codec::deserialize(&data)?
        };

        Ok(message)
    }

    pub async fn handle_network_event(&self, event: NetworkEvent) -> Result<(), NodeError> {
        match event {
            NetworkEvent::NewTransaction(tx) => {
                // Deduplicate transactions using bloom filter
                let tx_bytes = codec::serialize(&tx)?;
                // READ-ONLY until admission succeeds — the same rule the NewBlock
                // arm below documents. Inserting first meant a tx dropped for a
                // TRANSIENT reason (a stale balances index during catch-up makes
                // validate_transaction report InsufficientFunds) still marked the
                // hash as seen, so every later re-gossip of that same transaction
                // was silently swallowed at this gate until the bloom rotated. The
                // retry mechanism was defeated by the poison it created.
                if self.network_bloom.check(&tx_bytes) {
                    return Ok(());
                }

                // Validate transaction before adding
                if self.validate_transaction(&tx, None).await? {
                    // Add to blockchain. M2: read lock suffices -- add_transaction
                    // self-serializes on state_mutation_lock, so the write lock only held
                    // the exclusive lock across the ML-DSA verify (see submit-tx handler).
                    {
                        let blockchain = self.blockchain.read().await;
                        if let Err(e) = blockchain.add_transaction(tx.clone()).await {
                            if matches!(e, BlockchainError::FeeBelowRelayFloor) {
                                // Policy reject, not a fault — don't error!-spam
                                // the event pump for pre-floor peers' cheap txs.
                                debug!("Dropping below-floor-fee gossip tx");
                                return Ok(());
                            }
                            return Err(e.into());
                        }
                    }
                    self.seed_compact_index_from_admitted_transaction(&tx).await;

                    // SPAWN the gossip off the single-consumer event pump: gossip_transaction
                    // sends to up to 8 peers with a 5s per-peer timeout, and a cold NAT peer
                    // costs a full 5s TCP connect — awaiting it inline stalled the pump (the
                    // ONLY server of GetBlocks/ChainRequest) for up to ~40s per inbound tx,
                    // timing out syncing peers' block fetches (2026-07-12 audit). Same spawn
                    // pattern as the re-announce and create paths.
                    let node = self.clone();
                    let gossip_tx = tx.clone();
                    tokio::spawn(async move {
                        node.gossip_transaction(&gossip_tx).await;
                    });
                }
            }

            NetworkEvent::NewBlock(block) => {
                // A bloom hit is read-only until validation succeeds.  Event
                // sources include best-effort transports, so a transient permit
                // or witness miss must not poison the hash and suppress a later
                // unchanged full-block delivery.
                let block_hash = block.calculate_hash_for_block();
                if !Self::event_block_should_validate(&self.network_bloom, &block_hash) {
                    return Ok(());
                }

                // Verify block before processing
                if self.verify_block_parallel(&block).await? {
                    Self::commit_validated_event_block(&self.network_bloom, &block_hash);
                    // Save block to blockchain
                    self.blockchain.write().await.save_block(&block).await?;

                    // Relay exactly once across ingress arms: if another arm (a concurrent TCP early
                    // relay) already claimed this block's relay slot, skip re-flooding it here. The
                    // block is already saved above; this gates only the outbound relay.
                    if !self.claim_relay(&block_hash) {
                        return Ok(());
                    }

                    // Broadcast to peers using velocity protocol if available
                    if let Some(velocity) = &self.velocity_manager {
                        let (peer_map, selected_peers) = {
                            let peers = self.peers.read().await;
                            let peer_map: std::collections::HashMap<SocketAddr, PeerInfo> = peers
                                .iter()
                                .map(|(&addr, info)| (addr, info.clone()))
                                .collect();
                            let selected_peers =
                                self.select_broadcast_peers(&peers, peers.len().min(16));
                            (peer_map, selected_peers)
                        };

                        // Try velocity protocol first for efficient block propagation
                        if let Err(e) = velocity.process_block(&block, &peer_map).await {
                            warn!(
                                "Velocity broadcast failed, falling back to traditional: {}",
                                e
                            );

                            // Fallback to traditional broadcast (broadcast_block also floods the mesh)
                            if let Err(e) = self
                                .broadcast_block(
                                    Arc::new(block.clone()),
                                    None,
                                    selected_peers,
                                    true,
                                )
                                .await
                            {
                                warn!("Failed to broadcast block to selected peers: {}", e);
                            }
                        } else {
                            // Velocity succeeded and SKIPS broadcast_block, so flood the mesh here —
                            // exactly once (the fallback branch above already gossips via broadcast_block).
                            #[cfg(feature = "webrtc_mesh")]
                            self.mesh_gossip_block(&block).await;
                        }
                    } else {
                        // Traditional broadcast method. SPAWN it off the single-consumer event
                        // pump (which processes NetworkEvents strictly serially): broadcast_block
                        // fans out to up to 16 peers with per-peer connect/write, and awaited
                        // inline it stalls every following event (txs, peer joins, chain requests,
                        // further blocks). Gossip is best-effort and peers dedup, so detaching it
                        // is safe. Same spawn pattern as the transaction-gossip path above.
                        let peers = self.peers.read().await;
                        let selected_peers =
                            self.select_broadcast_peers(&peers, peers.len().min(16));
                        drop(peers);
                        let node = self.clone();
                        // `block` is owned here and unused afterwards — cloning deep-copied
                // a whole Block (up to MAX_BLOCK_TX_COUNT txs with witnesses) once
                // per accepted block for nothing.
                let block_arc = Arc::new(block);
                        tokio::spawn(async move {
                            if let Err(e) = node
                                .broadcast_block(block_arc, None, selected_peers, true)
                                .await
                            {
                                warn!("Failed to broadcast block to selected peers: {}", e);
                            }
                        });
                    }
                }
            }

            NetworkEvent::PeerJoin(addr) => {
                // Add new peer only if not already present
                let should_monitor = {
                    let mut peers = self.peers.write().await;
                    if let std::collections::hash_map::Entry::Vacant(e) = peers.entry(addr) {
                        e.insert(PeerInfo::new(addr));
                        true
                    } else {
                        false
                    }
                };

                // Start connection monitoring outside the peers write lock
                if should_monitor {
                    let node = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node.monitor_peer_connection(addr).await {
                            warn!("Peer monitoring ended for {}: {}", addr, e);
                        }
                    });
                }
            }

            NetworkEvent::PeerLeave(addr) => {
                // Remove peer and clean up
                self.peers.write().await.remove(&addr);
                self.peer_secrets.write().await.remove(&addr);
                self.outbound_connections.write().await.remove(&addr);
                self.outbound_circuit_breakers.write().await.remove(&addr);
                self.compact_capable_peers.remove(&addr);

                // If peer count too low, trigger discovery
                let peer_count = self.peers.read().await.len();
                if peer_count < MIN_PEERS {
                    tokio::spawn({
                        let node = self.clone();
                        async move {
                            if let Err(e) = node.discover_network_nodes().await {
                                warn!("Peer discovery after leave failed: {}", e);
                            }
                        }
                    });
                }
            }

            NetworkEvent::ChainRequest {
                start,
                end,
                requester: _,
                response_channel,
            } => {
                let blocks = {
                    // Read the range in bounded chunks, RELEASING the blockchain read
                    // lock and yielding between chunks. Blocks were fully validated when
                    // saved, so no verify_pow/rehash here (that was ~1000 rehashes on the
                    // event loop); and holding one read guard across all ~256 sled reads
                    // blocked a queued block-ingest write() for the whole range. Chunking
                    // lets ingest and other events interleave. Serving is best-effort: a
                    // block that changes across a chunk boundary is caught by the
                    // requester's per-block hash check, so releasing the lock is safe.
                    const CHAIN_SERVE_CHUNK: u32 = 32;
                    let mut out = Vec::new();
                    let mut bytes = 0usize;
                    let mut idx = start;
                    'serve: while idx <= end {
                        let chunk_end = idx.saturating_add(CHAIN_SERVE_CHUNK - 1).min(end);
                        {
                            let blockchain = self.blockchain.read().await;
                            for i in idx..=chunk_end {
                                if let Ok(block) = blockchain.get_block(i) {
                                    bytes += codec::serialize(&block).map(|v| v.len()).unwrap_or(0);
                                    if bytes > COMPACT_SAFE_ASSEMBLED_BYTES {
                                        break 'serve;
                                    }
                                    out.push(block);
                                }
                            }
                        }
                        // checked_add, NOT saturating: at the height ceiling
                        // saturating_add(1) yields the ceiling again, so the advance
                        // makes no progress and `idx <= end` stays true. Ranges up
                        // there serve no stored blocks, so the accumulated-size break
                        // does not bound the loop either — the advance itself has to.
                        // request_blocks guards its mirror loop the same way; keep both.
                        let Some(next) = chunk_end.checked_add(1) else {
                            break 'serve;
                        };
                        idx = next;
                        tokio::task::yield_now().await;
                    }
                    out
                };

                // Send response through dedicated channel
                {
                    let mut channel_guard = response_channel.lock().await;
                    if let Some(sender) = channel_guard.take() {
                        // Move, don't clone: `blocks` is unused after this send, and
                        // the clone deep-copied up to ~4 MiB of Block structs per
                        // served request.
                        if sender.send(blocks).is_err() {
                            warn!("Failed to send chain response through channel");
                        }
                    } else {
                        warn!("Chain response channel already consumed");
                    }
                }
            }

            NetworkEvent::ChainResponse { blocks, sender } => {
                // Request-correlation: a `Blocks` message from a peer we never
                // asked is an unsolicited push. Legitimate sync responses are
                // consumed inline by send_message_with_response and never reach
                // this event, so unsolicited pushes are dropped without touching
                // state. This closes the "any peer feeds a forged block" vector.
                if !self.is_solicited_block_source(sender) {
                    debug!(
                        "Ignoring unsolicited ChainResponse ({} blocks) from {}",
                        blocks.len(),
                        sender
                    );
                    return Ok(());
                }
                for block in blocks {
                    if block.calculate_hash_for_block() != block.hash
                        || !block.verify_pow_meets_floor()
                    {
                        continue;
                    }
                    // Verify transaction signatures (via witnesses fetched from the
                    // serving peer) before applying balances. The bare receipt path
                    // skips this and would apply forged transactions.
                    if let Err(e) = self.accept_peer_block(&block, Some(sender)).await {
                        warn!("Rejected block {} from {}: {}", block.index, sender, e);
                    }
                }
            }
        }

        Ok(())
    }

    fn event_block_should_validate(network_bloom: &NetworkBloom, block_hash: &[u8; 32]) -> bool {
        !network_bloom.check(block_hash)
    }

    fn commit_validated_event_block(network_bloom: &NetworkBloom, block_hash: &[u8; 32]) {
        let _ = network_bloom.insert(block_hash);
    }

    async fn handle_peer_message(
        &self,
        message: NetworkMessage,
        raw: &[u8],
        addr: SocketAddr,
        tx: &mpsc::Sender<NetworkEvent>,
    ) -> Result<Option<NetworkMessage>, NodeError> {
        // `raw` is the codec-framed plaintext the message was decoded from (equal to
        // codec::serialize(&message)); the caller already decoded it, so there is no re-deserialize.
        if raw.len() > MAX_MESSAGE_SIZE {
            self.record_peer_failure(addr).await;
            return Err(NodeError::Network("Message too large".into()));
        }

        // Fail closed before dedup, rate accounting, cache access, reconstruction,
        // proxying, or response generation.  The extension variants remain
        // decodable for wire compatibility, but are inert in this release.
        if !TCP_COMPACT_V1_ENABLED && Self::is_tcp_compact_extension(&message) {
            return Ok(None);
        }

        // Deduplicate gossip only. Requests/responses must always be processed, otherwise one
        // peer's GetBlocks/Ping/TxRequest can suppress another peer's identical request. Hash the
        // CANONICAL re-serialization rather than the wire bytes: MessagePack decoding is not
        // injective, so a hostile peer could otherwise re-encode the same message many ways to slip
        // every copy past the bloom. Only gossip messages pay this (requests/responses skip it).
        if Self::should_dedup_message(&message) {
            let canonical = codec::serialize(&message)
                .map_err(|_| NodeError::Network("Failed to serialize message".into()))?;
            let message_hash = blake3::hash(&canonical);
            if !self.network_bloom.insert(message_hash.as_bytes()) {
                return Ok(None);
            }
        }

        // Rate limiting
        let rate_key = format!("peer_msg:{}:{:?}", addr, std::mem::discriminant(&message));
        if !self.rate_limiter.check_limit(&rate_key) {
            self.record_peer_failure(addr).await;
            return Err(NodeError::Network("Rate limit exceeded".into()));
        }

        match message {
            NetworkMessage::TxRequest { tx_id } => {
                let mempool_tx = self
                    .blockchain
                    .read()
                    .await
                    .get_mempool_transaction_by_id(&tx_id)
                    .await;
                // Fall back to a retained confirmed-transaction witness so peers can
                // verify recently-confirmed blocks during near-tip sync.
                let tx_opt = match mempool_tx {
                    Some(tx) => Some(tx),
                    None => self
                        .blockchain
                        .read()
                        .await
                        .get_confirmed_witness_tx(&tx_id),
                };

                return Ok(Some(NetworkMessage::TxResponse { tx_id, tx: tx_opt }));
            }

            NetworkMessage::TxResponse { .. } => {
                // Ignored here: the correlated request/response path is request_tx_witness,
                // which matches its reply synchronously via send_message_with_response and does
                // not route through this dispatch. A TxResponse arriving here is unsolicited.
            }

            NetworkMessage::Transaction(tx_data) => {
                let tx_ref = Arc::new(tx_data);
                // Relay-policy floor, BEFORE the validation cache: the cache
                // marks validity ahead of admission, so without this gate a
                // repeat receipt of a cached below-floor tx would re-broadcast
                // it to 8 peers and defeat the floor. Silent ignore — policy,
                // not a peer fault (no penalty, no negative cache entry).
                if tx_ref.fee_units < MIN_RELAY_FEE_UNITS {
                    return Ok(None);
                }
                let tx_hash = Self::transaction_cache_key(&tx_ref);

                // Check validation cache
                if let Some(cached) = self
                    .validation_cache
                    .get(&tx_hash)
                    .map(|entry| entry.clone())
                {
                    if !Self::is_validation_cache_entry_fresh(&cached, SystemTime::now()) {
                        self.validation_cache.remove(&tx_hash);
                    } else if cached.valid {
                        // If previously validated, just broadcast
                        let peers = self.peers.read().await;
                        let selected_peers = self.select_broadcast_peers(&peers, 8);
                        drop(peers);
                        self.broadcast_transaction(tx_ref, addr, selected_peers)
                            .await?;
                        return Ok(None);
                    } else {
                        return Ok(None);
                    }
                }

                // Validate transaction
                let tx_valid = {
                    let blockchain = self.blockchain.read().await;
                    blockchain.validate_transaction(&tx_ref, None).await.is_ok()
                };
                if tx_valid {
                    // Update cache
                    self.validation_cache.insert(
                        tx_hash.clone(),
                        ValidationCacheEntry {
                            valid: true,
                            timestamp: SystemTime::now(),
                        },
                    );
                    self.maybe_prune_validation_cache();

                    // Add to blockchain. M2: read lock suffices (add_transaction
                    // self-serializes on state_mutation_lock; write held it across verify).
                    let tx_added = {
                        let blockchain = self.blockchain.read().await;
                        blockchain.add_transaction((*tx_ref).clone()).await.is_ok()
                    };
                    if tx_added {
                        self.seed_compact_index_from_admitted_transaction(&tx_ref)
                            .await;
                        // Broadcast to peers
                        let peers = self.peers.read().await;
                        let selected_peers = self.select_broadcast_peers(&peers, 8);
                        drop(peers);

                        // Execute broadcasts and notifications concurrently
                        let broadcast_fut =
                            self.broadcast_transaction(Arc::clone(&tx_ref), addr, selected_peers);
                        let notify_fut = tx.send(NetworkEvent::NewTransaction((*tx_ref).clone()));

                        let (broadcast_res, notify_res) = tokio::join!(broadcast_fut, notify_fut);
                        broadcast_res?;
                        notify_res.map_err(|e| {
                            NodeError::Network(format!("Notification error: {}", e))
                        })?;
                    }
                }
            }

            NetworkMessage::CompactBlockV1(compact) => {
                if !compact.validate_commitment() {
                    self.record_peer_failure(addr).await;
                    return Err(NodeError::Network(
                        "Invalid compact block commitment".into(),
                    ));
                }
                if self.network_bloom.check(&compact.hash) {
                    return Ok(None);
                }

                match self.compact_ingress_route(&compact).await {
                    CompactIngressRoute::ReconstructLocalTip => {
                        // Require an exact local-tip parent and consensus-next
                        // difficulty before touching either the in-flight table
                        // or one of the four reconstruction work slots. Recheck
                        // while claiming so a concurrent tip change fails closed.
                        let claim = self.try_claim_compact_reconstruction(&compact, addr).await;
                        let Some((started, _work_permit)) = claim else {
                            if self.compact_ingress_route(&compact).await
                                == CompactIngressRoute::FetchFullCompetitor
                            {
                                self.process_compact_competitor_fallback(compact, addr, tx)
                                    .await?;
                            }
                            return Ok(None);
                        };
                        let block_hash = compact.hash;
                        let result = self.process_compact_block(compact, addr, tx).await;
                        self.release_compact_inflight(&block_hash, started);
                        result?;
                    }
                    CompactIngressRoute::FetchFullCompetitor => {
                        // Same-height fork tie-breaks and one-ahead alternate
                        // tips retain pre-compact delivery semantics, but use a
                        // separate low-concurrency full-body lane and never a
                        // reconstruction permit.
                        self.process_compact_competitor_fallback(compact, addr, tx)
                            .await?;
                    }
                    CompactIngressRoute::DeferToChainSync => {
                        debug!(
                            "Deferring compact block {} to ordered chain sync",
                            compact.index
                        );
                    }
                }
            }

            NetworkMessage::GetCompactTransactionsV1 {
                block_hash,
                indexes,
                proxy_hops,
            } => {
                let transactions = self
                    .serve_compact_transactions(addr, block_hash, indexes, proxy_hops)
                    .await?;
                return Ok(Some(NetworkMessage::CompactTransactionsV1 {
                    block_hash,
                    transactions,
                }));
            }

            NetworkMessage::CompactTransactionsV1 { .. } => {
                // Correlated responses are consumed synchronously by
                // request_compact_transaction_batch. Unsolicited bodies never
                // enter a cache or validation path.
            }

            NetworkMessage::GetCompactBlockV1 {
                block_hash,
                proxy_hops,
            } => {
                let block = self
                    .serve_compact_full_block(addr, block_hash, proxy_hops)
                    .await;
                return Ok(Some(NetworkMessage::CompactBlockResponseV1 {
                    block_hash,
                    block,
                }));
            }

            NetworkMessage::CompactBlockResponseV1 { .. } => {
                // Correlated fallback responses are consumed synchronously.
            }

            NetworkMessage::Block(block) => {
                let block_ref = Arc::new(block);

                // Quick validation before processing
                if !block_ref.verify_pow_meets_floor() {
                    self.record_peer_failure(addr).await;
                    return Err(NodeError::Network("Invalid block proof of work".into()));
                }
                let block_hash = block_ref.calculate_hash_for_block();
                // Dedup with a READ-ONLY check, and only COMMIT the hash to the shared bloom
                // after a definitive accept. verify_block_with_witness returns Ok(false)
                // (not an error, not negative-cached) when a transaction witness can't be
                // resolved right now — a recoverable case. Inserting before verify would leave
                // that hash in the bloom, so a later re-delivery from a peer that CAN supply the
                // witness would be dropped here, permanently suppressing a recoverable block.
                // Truly-invalid blocks are still cheap to reject (the PoW-floor gate above and
                // verify's internal negative-cache). Same rationale as the mesh ingest path.
                if self.network_bloom.check(&block_hash) {
                    return Ok(None);
                }

                // EARLY PROPAGATION, always ahead of the save lock:
                // - compact-capable peers receive the ordered commitment after header,
                //   parent difficulty, PoW and Merkle checks;
                // - traditional full-block relay still waits for standalone ML-DSA
                //   validation.
                // Acceptance is unchanged: every path reconstructs and fully validates
                // the block below before saving it.
                let mut early_relayed = false;
                {
                    // Cheap local pre-filter against a dropped chain snapshot. Only
                    // tip-extenders cut through; fork/orphan blocks take the
                    // post-accept relay.
                    let cheap_ok = {
                        let bc = self.blockchain.read().await;
                        let tip_index = bc.get_latest_block_index();
                        match bc.get_last_block_hash() {
                            Ok(tip_hash) => {
                                Self::early_relay_cheap_gate(&block_ref, tip_index, &tip_hash)
                            }
                            Err(_) => false,
                        }
                    };

                    // TCP compact is release-gated off before construction as
                    // well as at send/ingress.  This avoids hashing/serializing
                    // an announcement or mutating its unverified body cache on
                    // an ordinary full-block receive while the extension is
                    // dormant.
                    if TCP_COMPACT_V1_ENABLED && cheap_ok {
                        if let Ok(compact) = CompactBlockV1::from_block(&block_ref) {
                            if compact.validate_commitment()
                                && self.compact_extends_local_tip(&compact).await
                            {
                                // Retain the committed full body for bounded missing-tx
                                // replies, but do not seed the verified witness index
                                // until the normal validation pipeline succeeds.
                                self.remember_compact_full_block(Arc::clone(&block_ref), false);
                                let compact_targets: Vec<SocketAddr> = {
                                    let peers = self.peers.read().await;
                                    self.select_broadcast_peers(&peers, peers.len().min(16))
                                }
                                .into_iter()
                                .filter(|peer| {
                                    *peer != addr && self.peer_supports_compact_v1(*peer)
                                })
                                .collect();
                                if !compact_targets.is_empty() {
                                    let node = self.clone();
                                    tokio::spawn(async move {
                                        if let Err(err) = node
                                            .broadcast_compact_block(
                                                Arc::new(compact),
                                                Some(addr),
                                                compact_targets,
                                            )
                                            .await
                                        {
                                            warn!("Compact cut-through relay failed: {}", err);
                                        }
                                    });
                                }
                            } else {
                                debug!(
                                    "Skipping compact cut-through for block {}: header does not match the local next-block rules",
                                    block_ref.index
                                );
                            }
                        }
                    }

                    if cheap_ok
                        && self
                            .verify_block_parallel(&block_ref)
                            .await
                            .unwrap_or(false)
                    {
                        // Standalone-VALID tip-extender. Source-filter the targets FIRST and only
                        // claim the single relay slot when there is somewhere to forward it, so a node
                        // whose only peer IS the source does not burn the claim and suppress the
                        // post-accept relay. The claim (disjoint from network_bloom) fires at most once
                        // per block hash across all ingress arms.
                        let targets: Vec<SocketAddr> = {
                            let peers = self.peers.read().await;
                            self.select_broadcast_peers(&peers, peers.len().min(16))
                        }
                        .into_iter()
                        .filter(|p| *p != addr)
                        .collect();

                        if !targets.is_empty() && self.claim_relay(&block_hash) {
                            let node = self.clone();
                            let relay_block = Arc::clone(&block_ref);
                            tokio::spawn(async move {
                                if let Err(e) = node
                                    .broadcast_block(relay_block, Some(addr), targets, true)
                                    .await
                                {
                                    warn!("Early block relay failed: {}", e);
                                }
                            });
                            early_relayed = true;
                        }
                    }
                }

                // Verify and propagate block
                if self
                    .verify_block_with_witness(&block_ref, Some(addr))
                    .await?
                {
                    self.network_bloom.insert(&block_hash);
                    // Save block to blockchain. Idempotent for an already-present block (the
                    // brief check-then-insert race is closed by save_block's state lock +
                    // same-hash short-circuit), so a duplicate delivery is a safe no-op.
                    self.blockchain.write().await.save_block(&block_ref).await?;
                    self.remember_compact_full_block(Arc::clone(&block_ref), true);
                    self.publish_discovery_state("Accepted block").await;

                    // Send network event
                    tx.send(NetworkEvent::NewBlock((*block_ref).clone()))
                        .await
                        .map_err(|e| {
                            NodeError::Network(format!("Failed to send block event: {}", e))
                        })?;

                    // Post-accept relay, made exactly-once: fire only if the early path did NOT
                    // already relay this block AND we win the relay claim. Covers blocks that did not
                    // qualify for the early relay (non-tip-extenders, or standalone-deferred
                    // truncated-signature blocks) but were accepted after full validation.
                    if !early_relayed && self.claim_relay(&block_hash) {
                        let peers = self.peers.read().await;
                        let selected_peers =
                            self.select_broadcast_peers(&peers, peers.len().min(16));
                        drop(peers);

                        if let Err(e) = self
                            .broadcast_block(
                                Arc::clone(&block_ref),
                                Some(addr),
                                selected_peers,
                                true,
                            )
                            .await
                        {
                            warn!("Failed to propagate block to selected peers: {}", e);
                        }
                    }
                }
            }

            NetworkMessage::GetBlocks { start, end } => {
                // Validate request parameters
                if end.saturating_sub(start) >= MAX_GETBLOCKS_SPAN {
                    self.record_peer_failure(addr).await;
                    return Err(NodeError::Network("Requested block range too large".into()));
                }

                // Create response channel
                let (response_tx, response_rx) = oneshot::channel();
                let response_channel = Arc::new(tokio::sync::Mutex::new(Some(response_tx)));

                // Send request event
                tx.send(NetworkEvent::ChainRequest {
                    start,
                    end,
                    requester: addr,
                    response_channel,
                })
                .await
                .map_err(|e| NodeError::Network(format!("Failed to send chain request: {}", e)))?;

                // Wait for response and return it to the active connection writer.
                // BOUNDED: an unbounded await here parked this connection's reader
                // task forever whenever the event pump was backed up — and a parked
                // reader also can't consume responses for in-flight requests to the
                // same peer. 30s comfortably covers serving a full 64-block window.
                match tokio::time::timeout(Duration::from_secs(30), response_rx).await {
                    Ok(Ok(blocks)) => return Ok(Some(NetworkMessage::Blocks(blocks))),
                    Ok(Err(_)) => {}
                    Err(_) => {
                        warn!(
                            "GetBlocks [{}..{}] response timed out internally",
                            start, end
                        );
                    }
                }
            }

            NetworkMessage::Blocks(blocks) => {
                // Request-correlation at the INGRESS. A `Blocks` push from a peer we did not recently
                // ask is unsolicited; the ChainResponse event handler already drops it, but only
                // AFTER it has been enqueued. `Blocks` is not gossip-deduplicated and carries up to a
                // ~4 MiB batch, so a single peer can flood distinct pushes that each occupy one of the
                // bounded 1000 event-queue slots — doomed events that back-pressure `tx.send().await`
                // and starve legitimate events (NewBlock, ChainRequest, …). Dropping here, before the
                // enqueue, keeps unsolicited pushes out of the queue entirely. Legitimate sync
                // responses are consumed inline by send_message_with_response and never reach this
                // handler; a genuinely solicited late reply still passes (same 120s-TTL predicate the
                // event handler re-checks).
                if !self.is_solicited_block_source(addr) {
                    return Ok(None);
                }
                tx.send(NetworkEvent::ChainResponse {
                    blocks,
                    sender: addr,
                })
                .await
                .map_err(|e| {
                    NodeError::Network(format!("Failed to send chain response event: {}", e))
                })?;
            }

            NetworkMessage::GetBlockHeight => {
                let blockchain = self.blockchain.read().await;
                let height = blockchain.get_latest_block_index() as u32;
                return Ok(Some(NetworkMessage::BlockHeight(height)));
            }

            NetworkMessage::GetPeers => {
                let peers = self.peers.read().await;
                let peer_addrs: Vec<_> = peers.keys().cloned().collect();
                return Ok(Some(NetworkMessage::Peers(peer_addrs)));
            }

            NetworkMessage::Shred(shred) => {
                if let Some(velocity) = &self.velocity_manager {
                    if let Ok(Some(block)) = velocity.handle_shred(shred, addr).await {
                        let block_ref = Arc::new(block);
                        if self
                            .verify_block_with_witness(&block_ref, Some(addr))
                            .await?
                        {
                            self.blockchain.write().await.save_block(&block_ref).await?;
                        }
                    }
                }
            }

            NetworkMessage::ShredRequest(request) => {
                if let Some(velocity) = &self.velocity_manager {
                    match request {
                        ShredRequestType::Missing {
                            block_hash,
                            indices,
                        } => {
                            velocity
                                .handle_shred_request(ShredRequest {
                                    block_hash,
                                    indices,
                                    from: addr,
                                    permit: None,
                                })
                                .await?;
                        }
                        ShredRequestType::Range {
                            start_height,
                            end_height,
                        } => {
                            // ANTI-AMPLIFICATION: a Range request must NEVER trigger a
                            // network-wide rebroadcast (velocity.process_block fanned every
                            // block out to the whole peer set — one small request flooded
                            // thousands of messages while holding blockchain+peers read locks
                            // across all the I/O). Serve the requested blocks ONLY back to the
                            // requester on this connection (same mechanism as GetBlocks), with
                            // a small span cap, a dedicated per-peer rate limit, and the locks
                            // dropped before any reply. (No sender of Range exists — this is an
                            // attacker-only path, so tightening it regresses no real sync.)
                            const MAX_SHRED_RANGE_SPAN: u32 = 128;
                            if end_height < start_height
                                || end_height.saturating_sub(start_height) >= MAX_SHRED_RANGE_SPAN
                            {
                                self.record_peer_failure(addr).await;
                                return Err(NodeError::Network("Shred range too large".into()));
                            }
                            if !self
                                .rate_limiter
                                .check_limit(&format!("shred_range:{}", addr))
                            {
                                self.record_peer_failure(addr).await;
                                return Err(NodeError::Network("Shred range rate limited".into()));
                            }
                            // Clone the blocks under a scoped read lock, accumulating serialized
                            // size and stopping before the frame limit; drop the lock before
                            // replying. No peers lock, no broadcast.
                            let blocks: Vec<Block> = {
                                let blockchain = self.blockchain.read().await;
                                let mut out = Vec::new();
                                let mut bytes = 0usize;
                                for height in start_height..=end_height {
                                    if let Ok(block) = blockchain.get_block(height) {
                                        bytes +=
                                            codec::serialize(&block).map(|v| v.len()).unwrap_or(0);
                                        if bytes > COMPACT_SAFE_ASSEMBLED_BYTES {
                                            break;
                                        }
                                        out.push(block);
                                    }
                                }
                                out
                            };
                            return Ok(Some(NetworkMessage::Blocks(blocks)));
                        }
                    }
                }
            }

            NetworkMessage::ShredResponse {
                block_hash: _block_hash,
                shreds,
            } => {
                if let Some(velocity) = &self.velocity_manager {
                    // Process each shred in the response
                    for shred in shreds {
                        if let Err(e) = velocity.handle_shred(shred, addr).await {
                            warn!("Failed to handle shred response from {}: {}", addr, e);
                        }
                    }
                }
            }

            NetworkMessage::Ping { timestamp, node_id } => {
                self.observe_compact_capability(addr, &node_id);
                // Update peer info
                let mut peers = self.peers.write().await;
                if let Some(info) = peers.get_mut(&addr) {
                    info.last_seen = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                }

                return Ok(Some(NetworkMessage::Pong {
                    timestamp,
                    node_id: self.capability_node_id(),
                }));
            }

            NetworkMessage::Pong { timestamp, node_id } => {
                self.observe_compact_capability(addr, &node_id);
                // Calculate and update latency
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let latency = now.saturating_sub(timestamp);

                let mut peers = self.peers.write().await;
                if let Some(info) = peers.get_mut(&addr) {
                    info.latency = latency;
                    info.last_seen = now;
                }
            }

            NetworkMessage::HeaderVerification {
                header,
                node_id,
                signature,
            } => {
                if let Some(ref sentinel) = self.header_sentinel {
                    if let Err(e) = sentinel
                        .verify_and_add_header(header, &node_id, signature)
                        .await
                    {
                        debug!("Header verification rejected from {}: {}", addr, e);
                    }
                }
            }

            NetworkMessage::HeaderSync {
                headers,
                node_id,
                signature,
            } => {
                if let Some(ref sentinel) = self.header_sentinel {
                    if let Err(e) = sentinel
                        .verify_headers_batch(headers, &node_id, signature)
                        .await
                    {
                        debug!("Header sync rejected from {}: {}", addr, e);
                    }
                }
            }

            NetworkMessage::MldsaKeyRegistration {
                node_id,
                mldsa_public_key,
                ed25519_signature,
            } => {
                // Rate-limit registration globally AND per source IP before any work — an
                // unauthenticated key-registration flood must never be free (memory DoS +
                // verifier-Sybil). The sentinel additionally caps keys per IP and bounds the
                // map, and counts distinct IPs (not raw keys) toward the quorum denominator.
                if !self.rate_limiter.check_limit("mldsa_reg:global")
                    || !self
                        .rate_limiter
                        .check_limit(&format!("mldsa_reg_ip:{}", addr.ip()))
                {
                    self.record_peer_failure(addr).await;
                } else if let Some(ref sentinel) = self.header_sentinel {
                    if let Err(e) = sentinel.register_peer_mldsa_key(
                        &node_id,
                        mldsa_public_key,
                        ed25519_signature,
                        addr.ip(),
                    ) {
                        debug!(
                            "ML-DSA key registration rejected from {} (node {}): {}",
                            addr, node_id, e
                        );
                    }
                }
            }

            // Handle other message types with default implementation
            _ => {}
        }

        Ok(None)
    }

    fn is_tcp_compact_extension(message: &NetworkMessage) -> bool {
        matches!(
            message,
            NetworkMessage::CompactBlockV1(_)
                | NetworkMessage::GetCompactTransactionsV1 { .. }
                | NetworkMessage::CompactTransactionsV1 { .. }
                | NetworkMessage::GetCompactBlockV1 { .. }
                | NetworkMessage::CompactBlockResponseV1 { .. }
        )
    }

    fn should_dedup_message(message: &NetworkMessage) -> bool {
        matches!(
            message,
            NetworkMessage::Block(_)
                | NetworkMessage::Transaction(_)
                | NetworkMessage::AlertMessage(_)
                | NetworkMessage::HeaderVerification { .. }
                | NetworkMessage::HeaderSync { .. }
                | NetworkMessage::MldsaKeyRegistration { .. }
                | NetworkMessage::Shred(_)
        )
    }

    async fn broadcast_transaction(
        &self,
        tx: Arc<Transaction>,
        source: SocketAddr,
        peers: Vec<SocketAddr>,
    ) -> Result<(), NodeError> {
        // Don't broadcast to source peer
        let targets: Vec<_> = peers.into_iter().filter(|&addr| addr != source).collect();
        if targets.is_empty() {
            return Ok(());
        }

        // Limit concurrent broadcasts to avoid network congestion
        const MAX_CONCURRENT: usize = 10;
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));

        let broadcast_futures = targets.into_iter().map(|peer| {
            let tx = Arc::clone(&tx);
            let permit = semaphore.clone().acquire_owned();
            let node = self.clone();

            async move {
                let _permit = permit.await.map_err(|e| {
                    NodeError::Network(format!("Broadcast semaphore acquisition failed: {}", e))
                })?;
                node.send_message(peer, &NetworkMessage::Transaction((*tx).clone()))
                    .await
            }
        });

        // Execute broadcasts concurrently
        let results: Vec<Result<(), NodeError>> =
            futures::future::join_all(broadcast_futures).await;

        // Check if any broadcasts succeeded
        if results.iter().any(|r| r.is_ok()) {
            Ok(())
        } else if let Some(Err(first_error)) = results.into_iter().find(|r| r.is_err()) {
            Err(first_error)
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "webrtc_mesh")]
    fn webrtc_mesh_enabled() -> bool {
        // Default ON as of v7.6.1: the mesh is a pure additive layer — a node with no mesh peers is
        // dormant and runs entirely on the gateway relay + TCP, blocks are validated identically on
        // every path, and the gateway kill switch (mesh_enabled) can disable it network-wide in ~30s.
        // So enabling it can only help propagation, never reduce base reachability. Opt out explicitly
        // with ALPHANUMERIC_WEBRTC_MESH=false (or 0/no/off).
        match std::env::var("ALPHANUMERIC_WEBRTC_MESH") {
            Ok(v) => !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            ),
            Err(_) => true,
        }
    }

    /// Peer node_ids from the gateway directory — who to dial into the mesh (signaling is keyed by
    /// node_id). Reuses the same /api/peers the TCP discovery already reads.
    /// Some(ids) when at least one discovery endpoint answered with an ok body
    /// (even an empty roster); None when every endpoint failed. The distinction
    /// matters: a gateway outage must NOT read as "zero peers" — the dialer loop
    /// keeps its last-good directory on None (2026-07-10 incident: blanking the
    /// directory dropped every dial target and disarmed the inbound-offer gate,
    /// which fails OPEN on an empty set).
    #[cfg(feature = "webrtc_mesh")]
    async fn fetch_mesh_peer_ids(&self) -> Option<Vec<String>> {
        let mut ids: Vec<String> = Vec::new();
        let mut any_ok = false;
        for url in Self::discovery_peers_urls() {
            if let Ok(res) = self.http_client.get(&url).send().await {
                if let Ok(body) = res.json::<DiscoveryResponse>().await {
                    if body.ok {
                        any_ok = true;
                        for p in body.peers {
                            if let Some(id) = p.node_id {
                                if id != self.node_id && id.len() == 64 {
                                    ids.push(id);
                                }
                            }
                        }
                    }
                }
            }
            if !ids.is_empty() {
                break;
            }
        }
        if !any_ok {
            return None;
        }
        ids.sort();
        ids.dedup();
        Some(ids)
    }

    /// Live WebRTC mesh DataChannel count, for status displays. 0 when the mesh is
    /// disabled, not yet spawned, or compiled out.
    #[cfg(feature = "webrtc_mesh")]
    pub async fn mesh_link_count(&self) -> usize {
        match self.webrtc_mesh.read().await.as_ref() {
            Some(mesh) => mesh.connected_peers().await.len(),
            None => 0,
        }
    }

    #[cfg(not(feature = "webrtc_mesh"))]
    pub async fn mesh_link_count(&self) -> usize {
        0
    }

    /// Bring up the WebRTC mesh, retrying until it succeeds. The three init
    /// steps inside try_spawn_webrtc_mesh can fail transiently (TLS/client
    /// construction, API build); before this supervisor, ONE such failure at
    /// boot silently disabled the mesh for the whole process lifetime — the
    /// node ran TCP/relay-only with nothing but an invisible-at-default-filter
    /// warn to say why. Now a failed bring-up logs at error level (the default
    /// field filter shows it) and retries with backoff; success ends the loop.
    #[cfg(feature = "webrtc_mesh")]
    fn spawn_webrtc_mesh(&self) {
        if !Self::webrtc_mesh_enabled() {
            return;
        }
        let node = self.clone();
        tokio::spawn(async move {
            let mut delay = Duration::from_secs(60);
            loop {
                match node.try_spawn_webrtc_mesh() {
                    Ok(()) => return,
                    Err(e) => {
                        error!(
                            "WebRTC mesh bring-up failed ({}); retrying in {}s — running TCP/relay-only until it succeeds",
                            e,
                            delay.as_secs()
                        );
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(600));
                    }
                }
            }
        });
    }

    /// One mesh bring-up attempt: build transport + API + mesh state, then spawn the signaling
    /// poll, topology dialer, and inbound processor. The node's own handshake key gives the mesh
    /// its real identity, so the gateway accepts its signaling exactly like its announce.
    #[cfg(feature = "webrtc_mesh")]
    fn try_spawn_webrtc_mesh(&self) -> Result<(), String> {
        use crate::a9::webrtc::{
            build_api, default_stun_urls, HttpSignalTransport, SignalTransport, WebRtcMesh,
        };
        const MESH_DEGREE: usize = 12;
        let gateway_base = Self::discovery_bases()
            .into_iter()
            .next()
            .unwrap_or_default();
        let transport: Arc<dyn SignalTransport> =
            match HttpSignalTransport::new(
                zeroize::Zeroizing::new(self.handshake_key_bytes.as_ref().clone()),
                gateway_base,
            )
            {
                Ok(t) => Arc::new(t),
                Err(e) => return Err(format!("transport init failed: {}", e)),
            };
        let api = match build_api(false) {
            Ok(a) => Arc::new(a),
            Err(e) => return Err(format!("API init failed: {}", e)),
        };
        let (mesh, mut inbound_rx) = match WebRtcMesh::new(transport, api, default_stun_urls()) {
            Ok(x) => x,
            Err(e) => return Err(format!("init failed: {}", e)),
        };
        info!(
            "WebRTC mesh enabled — gossiping blocks over direct DataChannels ({}…)",
            &self.node_id[..8.min(self.node_id.len())]
        );

        // Remote kill switch: nodes disable the mesh within ~30s if the gateway flips mesh_enabled to
        // false, so the whole additive layer can be turned off WITHOUT a node re-release if it ever
        // misbehaves at scale. `enabled` gates every loop below; the base network is unaffected.
        let enabled = Arc::new(std::sync::atomic::AtomicBool::new(true));

        {
            let store = self.webrtc_mesh.clone();
            let mesh = mesh.clone();
            tokio::spawn(async move {
                *store.write().await = Some(mesh);
            });
        }
        {
            let node = self.clone();
            let mesh = mesh.clone();
            let store = self.webrtc_mesh.clone();
            let enabled = enabled.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    // Fail-safe: only an explicit gateway `mesh_enabled: false` disables the mesh.
                    if !node.fetch_mesh_enabled().await {
                        // error-level: this permanently disables the mesh for the
                        // process lifetime, and the default field filter must show it.
                        error!(
                            "WebRTC mesh disabled by gateway kill switch — shutting the mesh down (restart the node to re-enable)"
                        );
                        enabled.store(false, std::sync::atomic::Ordering::Relaxed);
                        *store.write().await = None; // stop mesh_gossip immediately
                        mesh.wake(); // break the poll loop out of its sleep so it exits promptly
                        mesh.shutdown().await; // close all direct connections
                        return;
                    }
                }
            });
        }
        {
            let mesh = mesh.clone();
            let enabled = enabled.clone();
            tokio::spawn(async move {
                loop {
                    if !enabled.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    let _ = mesh.poll_signals().await;
                    // EVENT-DRIVEN cadence: poll fast only while a handshake is actually forming, or
                    // signaling was recently active / expected (a dial, an inbound offer, a directory
                    // change, or a lost lower-id link — all of which call touch()). Otherwise fall to a
                    // cheap safety-net cadence. A settled node in a stable network barely touches the
                    // gateway, so Redis cost scales with CHURN, not with N*time — the free-tier budget
                    // stops being the scaling constraint. The directory it watches is edge-cached (~0
                    // Redis), so detecting "a new peer might dial me" costs nothing.
                    let active = mesh.has_forming_conns().await
                        || mesh.quiet_for().await < Duration::from_secs(25);
                    let delay_ms = if active { 2_500 } else { 180_000 };
                    // Interruptible: a touch() (dial, inbound offer, directory change, lost lower-id
                    // link) or the kill switch wakes us out of the long safety-net sleep at once, so
                    // event-driven draining is actually prompt — not delayed up to 180s.
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
                        _ = mesh.wait_for_wake() => {}
                    }
                }
            });
        }
        {
            let node = self.clone();
            let mesh = mesh.clone();
            let enabled = enabled.clone();
            tokio::spawn(async move {
                use crate::a9::webrtc::select_dial_targets;
                let mut prev_ids: Vec<String> = Vec::new();
                loop {
                    if !enabled.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    // Keep-last-good: a failed fetch (gateway outage) keeps the previous
                    // directory instead of blanking it — see fetch_mesh_peer_ids.
                    let ids = node
                        .fetch_mesh_peer_ids()
                        .await
                        .unwrap_or_else(|| prev_ids.clone());
                    // A directory change (fetched from the ~free edge-cached /api/peers) may mean a new
                    // peer will dial us — wake the signaling poll so it drains promptly instead of
                    // waiting out the slow safety cadence. This is what makes draining event-driven.
                    if ids != prev_ids {
                        mesh.touch().await;
                        prev_ids = ids.clone();
                    }
                    // Publish the directory so inbound offers can be gated to real, announced peers.
                    mesh.set_known_peers(&ids).await;
                    // Dial targets chosen RELATIVE to our own id (nearest higher-id successors +
                    // spread), so every node forms edges and the whole network meshes — not just the
                    // ~13 lowest-id nodes that the old "take the 12 smallest ids" rule connected.
                    let local = mesh.local_id().to_string();
                    for id in select_dial_targets(&local, &ids, MESH_DEGREE) {
                        let _ = mesh.dial(&id).await;
                    }
                    tokio::time::sleep(Duration::from_secs(15)).await;
                }
            });
        }
        {
            // Reaper: close + drop connections stuck un-Connected (half-open handshakes never reach
            // Failed on their own, so nothing else frees them or unblocks a re-dial). webrtc 0.17 has
            // no Drop, so this is also what actually releases the ICE agent + UDP socket.
            let mesh = mesh.clone();
            let enabled = enabled.clone();
            tokio::spawn(async move {
                loop {
                    if !enabled.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_secs(20)).await;
                    mesh.reap_stale().await;
                }
            });
        }
        {
            // Heartbeat: periodic operator-visible mesh degree, so a rollout can watch how many DIRECT
            // peer links are up (vs. relay fallback). Only logs when at least one link is up.
            let mesh = mesh.clone();
            let enabled = enabled.clone();
            tokio::spawn(async move {
                loop {
                    if !enabled.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    let peers = mesh.connected_peers().await;
                    if !peers.is_empty() {
                        info!("mesh: {} direct peer link(s) up", peers.len());
                    }
                }
            });
        }
        {
            let node = self.clone();
            // Mesh-local seen-set: dedups block replays / gossip loops WITHOUT touching the shared
            // network_bloom, so a mesh block that fails standalone validation never poisons the shared
            // dedup path (and can't be re-validated on every replay).
            let mesh_seen: Arc<PLMutex<LruCache<String, ()>>> = Arc::new(PLMutex::new(
                LruCache::new(NonZeroUsize::new(8192).unwrap()),
            ));
            // Logged, not supervised: the receiver is owned by the future, so a
            // panic loses the mesh ingest until restart — make it loud.
            spawn_logged("mesh-ingest", async move {
                while let Some((_peer, bytes)) = inbound_rx.recv().await {
                    node.handle_mesh_message(bytes, &mesh_seen).await;
                }
            });
        }
        Ok(())
    }

    /// Inbound mesh bytes -> validated processing. Transport-only: no consensus change.
    ///
    /// The mesh runs peer=None (there is no request-a-witness channel over a DataChannel), so a block
    /// that needs a peer-fetched ML-DSA witness cannot be validated here. Rather than feed such a block
    /// into the shared bloom-before-validate path — where a witness-missing failure would poison the
    /// bloom and suppress the later TCP delivery that CAN fetch the witness — we pre-validate STANDALONE
    /// and only hand VALID blocks to the shared path. A block we can't validate standalone is simply
    /// left for TCP/relay. Two properties make this safe where three consensus-core attempts failed:
    /// (1) the shared consensus path is untouched; (2) peer=None means there is no peer witness for an
    /// attacker to supply, so this ingest cannot be used to poison/censor. A mesh-local seen-set dedups
    /// replays so an invalid block can't be re-validated on every arrival.
    #[cfg(feature = "webrtc_mesh")]
    fn mesh_block_already_seen(
        mesh_seen: &Arc<PLMutex<LruCache<String, ()>>>,
        network_bloom: &NetworkBloom,
        block_hash: &[u8; 32],
    ) -> bool {
        mesh_seen.lock().contains(&hex::encode(block_hash)) || network_bloom.check(block_hash)
    }

    #[cfg(feature = "webrtc_mesh")]
    async fn handle_mesh_message(
        &self,
        bytes: Vec<u8>,
        mesh_seen: &Arc<PLMutex<LruCache<String, ()>>>,
    ) {
        let msg: NetworkMessage = match codec::deserialize(&bytes) {
            Ok(m) => m,
            Err(_) => return,
        };
        match msg {
            NetworkMessage::RawData(raw) => {
                let Some(compact) = CompactBlockV1::decode_mesh_envelope(&raw) else {
                    return;
                };
                if !compact.validate_commitment()
                    || !self.compact_extends_local_tip(&compact).await
                    || Self::mesh_block_already_seen(mesh_seen, &self.network_bloom, &compact.hash)
                {
                    return;
                }
                let hash = hex::encode(compact.hash);
                let Ok(_work_permit) =
                    Arc::clone(&self.compact_reconstruction_slots).try_acquire_owned()
                else {
                    return;
                };
                let Some(block) = self
                    .reconstruct_compact_block_locally(&compact)
                    .unwrap_or(None)
                else {
                    // The full block is sent immediately after this envelope on
                    // the same ordered DataChannel task and remains the fallback.
                    return;
                };
                if !self.verify_block_parallel(&block).await.unwrap_or(false) {
                    return;
                }
                if self
                    .handle_network_event(NetworkEvent::NewBlock(block))
                    .await
                    .is_ok()
                {
                    mesh_seen.lock().put(hash, ());
                }
            }
            NetworkMessage::Block(b) => {
                let calculated_hash = b.calculate_hash_for_block();
                let hash = hex::encode(calculated_hash);
                if Self::mesh_block_already_seen(mesh_seen, &self.network_bloom, &calculated_hash) {
                    return; // mesh-local dedup: replay, compact success, or gossip loop
                }
                // Reject below-floor PoW cheaply, BEFORE acquiring a validation permit — the same gate
                // every other ingress applies (mirrors the TCP block handler). Keeps a no-PoW mesh flood
                // from consuming validation work.
                if !b.verify_pow_meets_floor() {
                    return;
                }
                // Only forward blocks we can validate standalone; witness-requiring blocks are left for
                // the TCP/relay path (peer=Some) which can fetch the witness. The shared path re-checks
                // and hits its validation cache, so this costs no extra verification.
                if self.verify_block_parallel(&b).await.unwrap_or(false) {
                    if let Err(err) = self.handle_network_event(NetworkEvent::NewBlock(b)).await {
                        debug!("WebRTC mesh: block processing error: {}", err);
                    } else {
                        mesh_seen.lock().put(hash, ());
                    }
                }
            }
            NetworkMessage::Transaction(t) => {
                if let Err(err) = self
                    .handle_network_event(NetworkEvent::NewTransaction(t))
                    .await
                {
                    debug!("WebRTC mesh: tx processing error: {}", err);
                }
            }
            _ => {}
        }
    }

    /// Announce a transaction to the network: mesh DataChannel flood + a bounded TCP
    /// broadcast to a subset of direct peers. This is the ONLY tx propagation there is —
    /// the gateway relay carries blocks, not transactions — and until v7.6.8 the CLI
    /// `create`/`send` path never called it: a locally-created tx sat in the sender's own
    /// mempool, invisible to every other miner, so in practice only the sender could ever
    /// confirm it. Now both the network ingest path (NewTransaction event) and the local
    /// create path announce through here.
    ///
    /// The bloom insert makes this idempotent AND absorbs our own echo: a peer that
    /// gossips the tx back to us is dropped at the NewTransaction dedup gate instead of
    /// erroring on a duplicate mempool add. Sends are time-boxed and the peers guard is
    /// snapshot-then-drop (never held across an await — the 2026-07-08/09 wedge class).
    pub async fn gossip_transaction(&self, tx_ref: &Transaction) {
        // Confirm O(1) mempool membership before treating this as verified. This
        // covers local CLI and periodic re-gossip paths while avoiding any
        // per-announcement scan of the up-to-50k transaction pool.
        self.seed_compact_index_from_admitted_transaction(tx_ref)
            .await;
        if let Ok(tx_bytes) = codec::serialize(tx_ref) {
            let _ = self.network_bloom.insert(&tx_bytes);
        }

        #[cfg(feature = "webrtc_mesh")]
        self.mesh_gossip(&NetworkMessage::Transaction(tx_ref.clone()))
            .await;

        let selected_peers = {
            let peers = self.peers.read().await;
            self.select_broadcast_peers(&peers, peers.len().min(8))
        };
        for &addr in &selected_peers {
            match tokio::time::timeout(
                Duration::from_secs(5),
                self.send_message(addr, &NetworkMessage::Transaction(tx_ref.clone())),
            )
            .await
            {
                Ok(Err(e)) => {
                    warn!("Failed to broadcast transaction to {}: {}", addr, e)
                }
                Err(_) => warn!("Transaction broadcast to {} timed out", addr),
                Ok(Ok(())) => {}
            }
        }
    }

    /// Flood a message to every connected mesh peer, parallel to the TCP flood. No-op if the mesh is
    /// off / not up / has no peers. The actual send is SPAWNED, so a slow or backpressured DataChannel
    /// can never add latency to the caller's base-path (TCP/relay) propagation. Peers dedup via the
    /// bloom, so double-delivery is harmless.
    #[cfg(feature = "webrtc_mesh")]
    async fn mesh_gossip(&self, msg: &NetworkMessage) {
        let mesh = { self.webrtc_mesh.read().await.clone() };
        if let Some(mesh) = mesh {
            if mesh.connected_peers().await.is_empty() {
                return;
            }
            if let Ok(bytes) = codec::serialize(msg) {
                tokio::spawn(async move {
                    let _ = mesh.broadcast(&bytes).await;
                });
            }
        }
    }

    /// Block-specific gossip: identical to `mesh_gossip` but defers the (up to ~1 MiB) Block clone
    /// until AFTER confirming the mesh is up and has peers, so the base path pays nothing — not even
    /// the clone — when the mesh is off or empty.
    #[cfg(feature = "webrtc_mesh")]
    async fn mesh_gossip_block(&self, block: &Block) {
        let mesh = { self.webrtc_mesh.read().await.clone() };
        if let Some(mesh) = mesh {
            if mesh.connected_peers().await.is_empty() {
                return;
            }
            let Ok((compact_frame, full_frame)) = Self::mesh_block_frames(block) else {
                return;
            };
            // One spawned task owns both frames. Each peer's future writes the
            // compact envelope first and the unchanged full block second on the
            // same ordered DataChannel. Older nodes ignore RawData and still see
            // the full fallback; one slow peer cannot delay another.
            //
            // Frames are wrapped in Bytes ONCE: the per-peer clones are refcount
            // bumps, and send_to_bytes hands the same buffer to the DataChannel.
            // The old per-peer Vec clones + send_to's copy_from_slice memcpy'd
            // every frame twice per peer (~24 MiB per 1 MiB block at mesh
            // degree 12).
            let compact_frame = compact_frame.map(bytes::Bytes::from);
            let full_frame = bytes::Bytes::from(full_frame);
            tokio::spawn(async move {
                let peer_ids = mesh.connected_peers().await;
                let sends = peer_ids.into_iter().map(|peer_id| {
                    let mesh = Arc::clone(&mesh);
                    let compact_frame = compact_frame.clone();
                    let full_frame = full_frame.clone();
                    async move {
                        if let Some(compact_frame) = compact_frame {
                            let _ = tokio::time::timeout(
                                Duration::from_secs(5),
                                mesh.send_to_bytes(&peer_id, &compact_frame),
                            )
                            .await;
                        }
                        let _ = tokio::time::timeout(
                            Duration::from_secs(5),
                            mesh.send_to_bytes(&peer_id, &full_frame),
                        )
                        .await;
                    }
                });
                join_all(sends).await;
            });
        }
    }

    #[cfg(feature = "webrtc_mesh")]
    fn mesh_block_frames(block: &Block) -> Result<(Option<Vec<u8>>, Vec<u8>), NodeError> {
        let compact_frame = CompactBlockV1::from_block(block)
            .and_then(|compact| {
                compact.encode_mesh_envelope().and_then(|raw| {
                    codec::serialize(&NetworkMessage::RawData(raw)).map_err(NodeError::from)
                })
            })
            .ok();
        let full_frame = codec::serialize(&NetworkMessage::Block(block.clone()))?;
        Ok((compact_frame, full_frame))
    }

    fn compact_targets_not_delivered(
        &self,
        block_hash: &[u8; 32],
        targets: impl IntoIterator<Item = SocketAddr>,
    ) -> Vec<SocketAddr> {
        let mut delivered = self.compact_relay_delivered.lock();
        Self::compact_targets_not_delivered_in(&mut delivered, block_hash, targets)
    }

    fn compact_targets_not_delivered_in(
        delivered: &mut LruCache<[u8; 32], HashSet<SocketAddr>>,
        block_hash: &[u8; 32],
        targets: impl IntoIterator<Item = SocketAddr>,
    ) -> Vec<SocketAddr> {
        let already = delivered.get(block_hash).cloned().unwrap_or_default();
        targets
            .into_iter()
            .filter(|target| !already.contains(target))
            .collect()
    }

    fn mark_compact_delivered(&self, block_hash: &[u8; 32], peer: SocketAddr) {
        let mut delivered = self.compact_relay_delivered.lock();
        Self::mark_compact_delivered_in(&mut delivered, block_hash, peer);
    }

    fn mark_compact_delivered_in(
        delivered: &mut LruCache<[u8; 32], HashSet<SocketAddr>>,
        block_hash: &[u8; 32],
        peer: SocketAddr,
    ) {
        if !delivered.contains(block_hash) {
            delivered.put(*block_hash, HashSet::new());
        }
        if let Some(peers) = delivered.get_mut(block_hash) {
            peers.insert(peer);
        }
    }

    async fn compact_extends_local_tip(&self, compact: &CompactBlockV1) -> bool {
        let blockchain = self.blockchain.read().await;
        let Some(parent) = blockchain.get_last_block() else {
            return false;
        };
        Self::compact_header_extends_parent(compact, &parent)
    }

    fn compact_ingress_route_against_tip(
        compact: &CompactBlockV1,
        tip: &Block,
    ) -> CompactIngressRoute {
        if Self::compact_header_extends_parent(compact, tip) {
            return CompactIngressRoute::ReconstructLocalTip;
        }

        // Preserve the full-block behavior compact-capable TCP peers had before
        // negotiation: a competing block at our height must still reach normal
        // orphan/tie-break processing, and a one-ahead block on another tip must
        // still be available to start convergence. Fetch its exact full body in
        // the separate fallback lane; older/deeper gaps are recovered by range
        // sync, where ancestry can be validated in order.
        if compact.index == tip.index || compact.index == tip.index.saturating_add(1) {
            CompactIngressRoute::FetchFullCompetitor
        } else {
            CompactIngressRoute::DeferToChainSync
        }
    }

    async fn compact_ingress_route(&self, compact: &CompactBlockV1) -> CompactIngressRoute {
        let Some(tip) = self.blockchain.read().await.get_last_block() else {
            return CompactIngressRoute::DeferToChainSync;
        };
        Self::compact_ingress_route_against_tip(compact, &tip)
    }

    fn compact_header_extends_parent(compact: &CompactBlockV1, parent: &Block) -> bool {
        if compact.index != parent.index.saturating_add(1)
            || compact.previous_hash != parent.hash
            || compact.timestamp < parent.timestamp
        {
            return false;
        }
        let expected_difficulty = Block::consensus_next_difficulty(
            parent.difficulty,
            compact.timestamp.saturating_sub(parent.timestamp),
            compact.index,
        );
        compact.difficulty == expected_difficulty
    }

    async fn broadcast_compact_block(
        &self,
        compact: Arc<CompactBlockV1>,
        source: Option<SocketAddr>,
        peers: Vec<SocketAddr>,
    ) -> Result<usize, NodeError> {
        if !TCP_COMPACT_V1_ENABLED {
            return Ok(0);
        }
        let targets = self.compact_targets_not_delivered(
            &compact.hash,
            peers
                .into_iter()
                .filter(|addr| Some(*addr) != source && self.peer_supports_compact_v1(*addr)),
        );
        if targets.is_empty() {
            return Ok(0);
        }

        const MAX_CONCURRENT: usize = 10;
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));
        let sends = targets.into_iter().map(|peer| {
            let compact = Arc::clone(&compact);
            let permit = semaphore.clone().acquire_owned();
            let node = self.clone();
            async move {
                let result = async {
                    let _permit = permit.await.map_err(|e| {
                        NodeError::Network(format!(
                            "Compact broadcast semaphore acquisition failed: {}",
                            e
                        ))
                    })?;
                    node.send_message(peer, &NetworkMessage::CompactBlockV1((*compact).clone()))
                        .await
                }
                .await;
                (peer, result)
            }
        });
        let results = join_all(sends).await;
        let delivered = results.iter().filter(|(_, result)| result.is_ok()).count();
        for (peer, result) in &results {
            match result {
                Ok(()) => self.mark_compact_delivered(&compact.hash, *peer),
                Err(err) => {
                    self.compact_capable_peers.remove(peer);
                    warn!("Failed to broadcast compact block to {}: {}", peer, err);
                }
            }
        }
        if delivered > 0 {
            Ok(delivered)
        } else if let Some((_, Err(err))) = results.into_iter().find(|(_, result)| result.is_err())
        {
            Err(err)
        } else {
            Ok(0)
        }
    }

    /// Claim the single relay slot for a block hash. Returns true exactly once per hash (the
    /// caller that wins the claim), false on every subsequent call. Backed by a bounded LRU that
    /// is DISJOINT from network_bloom, so relay-once accounting never touches acceptance dedup.
    /// Used to move the relay hop ahead of full validation without ever relaying a block twice.
    fn claim_relay(&self, block_hash: &[u8; 32]) -> bool {
        self.early_relay_seen.lock().put(*block_hash, ()).is_none()
    }

    /// Cheap, local pre-filter deciding whether a received block is eligible to be RELAYED before
    /// full validation: it must claim its own computed hash, strictly extend `tip` (height + 1, and
    /// previous_hash == the tip hash), and its transaction set must hash to its committed merkle
    /// root. This only decides whether to run the standalone poison-free verify (the real gate) and
    /// which blocks skip straight to the post-accept relay — it is an optimization filter, not a
    /// security boundary. Note: a matching merkle root does NOT prove signature validity (the root
    /// binds truncated signatures + sig_hash receipts), which is exactly why the caller still runs
    /// verify_block_parallel before relaying.
    fn early_relay_cheap_gate(block: &Block, tip_index: u64, tip_hash: &[u8; 32]) -> bool {
        block.hash == block.calculate_hash_for_block()
            && block.index as u64 == tip_index.saturating_add(1)
            && &block.previous_hash == tip_hash
            && Blockchain::calculate_merkle_root(&block.transactions)
                .map(|root| root == block.merkle_root)
                .unwrap_or(false)
    }

    async fn broadcast_block(
        &self,
        block: Arc<Block>,
        source: Option<SocketAddr>,
        peers: Vec<SocketAddr>,
        gossip_mesh: bool,
    ) -> Result<usize, NodeError> {
        // Flood the block over the WebRTC mesh in parallel to TCP (covers mined + relayed blocks).
        // Callers that already flooded the mesh themselves pass gossip_mesh=false so a block is
        // never mesh-gossiped twice — the mined-egress path floods the mesh FIRST and then does a
        // TCP-only broadcast. No-op unless the mesh feature is on and up.
        #[cfg(feature = "webrtc_mesh")]
        if gossip_mesh {
            self.mesh_gossip_block(block.as_ref()).await;
        }
        #[cfg(not(feature = "webrtc_mesh"))]
        let _ = gossip_mesh;
        self.remember_compact_full_block(Arc::clone(&block), true);

        let targets: Vec<_> = peers
            .into_iter()
            .filter(|addr| Some(*addr) != source)
            .collect();
        if targets.is_empty() {
            return Ok(0);
        }

        // Snapshot each peer's capability exactly once. Besides avoiding a
        // duplicate lookup, this prevents a simultaneous ping refresh from
        // placing a peer in neither partition (or both).
        let mut compact_targets = Vec::new();
        let mut full_targets = Vec::new();
        for addr in targets {
            if self.peer_supports_compact_v1(addr) {
                compact_targets.push(addr);
            } else {
                full_targets.push(addr);
            }
        }

        let compact = (!compact_targets.is_empty())
            .then(|| CompactBlockV1::from_block(&block).ok())
            .flatten()
            .map(Arc::new);

        // If compact construction ever fails, preserve delivery by treating all
        // targets as traditional full-block peers. Successful compact delivery is
        // tracked per target; peers not actually reached remain eligible on every
        // later relay pass.
        let mut sends: Vec<(SocketAddr, bool)> =
            full_targets.into_iter().map(|peer| (peer, false)).collect();
        if compact.is_some() {
            sends.extend(
                self.compact_targets_not_delivered(&block.hash, compact_targets)
                    .into_iter()
                    .map(|peer| (peer, true)),
            );
        } else {
            sends.extend(compact_targets.into_iter().map(|peer| (peer, false)));
        }
        if sends.is_empty() {
            return Ok(0);
        }

        const MAX_CONCURRENT: usize = 10;
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));

        let broadcast_futures = sends.into_iter().map(|(peer, use_compact)| {
            let block = Arc::clone(&block);
            let compact = compact.clone();
            let permit = semaphore.clone().acquire_owned();
            let node = self.clone();

            async move {
                let result = async {
                    let _permit = permit.await.map_err(|e| {
                        NodeError::Network(format!("Broadcast semaphore acquisition failed: {}", e))
                    })?;
                    if use_compact {
                        let compact = compact.ok_or_else(|| {
                            NodeError::Network("Compact broadcast body unavailable".into())
                        })?;
                        match node
                            .send_message(peer, &NetworkMessage::CompactBlockV1((*compact).clone()))
                            .await
                        {
                            Ok(()) => Ok(()),
                            Err(compact_error) => {
                                node.compact_capable_peers.remove(&peer);
                                debug!(
                                    "Compact broadcast to {} failed ({}); retrying full block",
                                    peer, compact_error
                                );
                                node.send_message(peer, &NetworkMessage::Block((*block).clone()))
                                    .await
                            }
                        }
                    } else {
                        node.send_message(peer, &NetworkMessage::Block((*block).clone()))
                            .await
                    }
                }
                .await;
                (peer, use_compact, result)
            }
        });

        let results: Vec<(SocketAddr, bool, Result<(), NodeError>)> =
            futures::future::join_all(broadcast_futures).await;
        let delivered = results
            .iter()
            .filter(|(_, _, result)| result.is_ok())
            .count();
        for (peer, used_compact, result) in &results {
            match result {
                Ok(()) if *used_compact => self.mark_compact_delivered(&block.hash, *peer),
                Err(e) => warn!("Failed to broadcast block to {}: {}", peer, e),
                _ => {}
            }
        }

        if delivered > 0 {
            Ok(delivered)
        } else if let Some((_, _, Err(first_error))) =
            results.into_iter().find(|(_, _, result)| result.is_err())
        {
            Err(first_error)
        } else {
            Ok(0)
        }
    }

    pub fn select_broadcast_peers(
        &self,
        peers: &HashMap<SocketAddr, PeerInfo>,
        target_count: usize,
    ) -> Vec<SocketAddr> {
        const MAX_PER_SUBNET: usize = 3;
        const MIN_DIFFERENT_SUBNETS: usize = 3;

        if peers.is_empty() || target_count == 0 {
            return Vec::new();
        }

        let peer_count = peers.len();
        let actual_target = std::cmp::min(target_count, peer_count);

        // Pre-allocate collections with appropriate capacity
        let mut selected = Vec::with_capacity(actual_target);
        let mut subnet_counts =
            HashMap::with_capacity(std::cmp::min(actual_target, peer_count / MAX_PER_SUBNET));
        let mut different_subnets = HashSet::with_capacity(MIN_DIFFERENT_SUBNETS);

        // Group peers by subnet
        let mut subnet_peers: HashMap<SubnetGroup, Vec<(&SocketAddr, &PeerInfo)>> = HashMap::new();

        for (addr, info) in peers {
            subnet_peers
                .entry(info.subnet_group)
                .or_default()
                .push((addr, info));
        }

        // First ensure subnet diversity by selecting one peer from each subnet
        let mut subnets: Vec<_> = subnet_peers.keys().cloned().collect();
        // Random shuffle to avoid selecting the same subnets every time
        subnets.shuffle(&mut thread_rng());

        for subnet in subnets.iter().take(MIN_DIFFERENT_SUBNETS) {
            if let Some(peers_in_subnet) = subnet_peers.get(subnet) {
                // Sort by latency within subnet and select best peer
                let mut subnet_peers_sorted = peers_in_subnet.clone();
                subnet_peers_sorted.sort_by_key(|(_, info)| info.latency);

                if let Some((addr, _)) = subnet_peers_sorted.first() {
                    selected.push(**addr);
                    different_subnets.insert(*subnet);
                    *subnet_counts.entry(*subnet).or_insert(0) += 1;

                    if selected.len() >= actual_target {
                        return selected;
                    }
                }
            }
        }

        // Then fill remaining slots with best available peers
        // Sort all peers by latency for the second phase
        let mut all_peers: Vec<_> = peers.iter().collect();
        all_peers.sort_by(|(_, a), (_, b)| a.latency.cmp(&b.latency));

        for (addr, info) in all_peers {
            // Skip already selected peers
            if selected.contains(addr) {
                continue;
            }

            let subnet = info.subnet_group;
            let subnet_count = subnet_counts.get(&subnet).copied().unwrap_or(0);

            // Check if we can add more peers from this subnet
            if subnet_count < MAX_PER_SUBNET || different_subnets.len() >= MIN_DIFFERENT_SUBNETS {
                selected.push(*addr);
                *subnet_counts.entry(subnet).or_insert(0) += 1;
                different_subnets.insert(subnet);

                if selected.len() >= actual_target {
                    break;
                }
            }
        }

        selected
    }

    async fn write_encrypted_frame<W>(
        &self,
        writer: &mut W,
        message: &NetworkMessage,
        shared_secret: &[u8],
    ) -> Result<(), NodeError>
    where
        W: AsyncWrite + Unpin,
    {
        let data = self.encrypt_message(message, shared_secret)?;
        if data.is_empty() {
            return Err(NodeError::Network("Refusing to send empty frame".into()));
        }
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(NodeError::Network("Outgoing frame too large".into()));
        }

        writer.write_all(&(data.len() as u32).to_be_bytes()).await?;
        writer.write_all(&data).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn handle_connection(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
        tx: mpsc::Sender<NetworkEvent>,
    ) -> Result<(), NodeError> {
        let socket_addr = addr;

        // Rate limit handshake attempts per IP
        let rate_key = format!("handshake_{}", socket_addr.ip());
        if !self.rate_limiter.check_limit(&rate_key) {
            return Err(NodeError::RateLimit("Handshake rate limit exceeded".into()));
        }

        // Enforce max inbound attempts per IP in a short window
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut attempts = self.inbound_attempts.write().await;
            let entry = attempts.entry(socket_addr.ip()).or_insert((0, now));
            // The timestamp marks when this window OPENED, and is written only by the reset
            // below. Refreshing it per attempt turned the window into a quiet-period cooldown:
            // a peer that kept retrying pushed the start forward with every rejected attempt,
            // so its counter never aged out and it stayed blocked until it went fully silent
            // for the whole window — long after whatever caused the burst had cleared.
            if now.saturating_sub(entry.1) > INBOUND_ATTEMPT_WINDOW {
                *entry = (0, now);
            }
            entry.0 = entry.0.saturating_add(1);
            if entry.0 > MAX_INBOUND_ATTEMPTS_PER_IP {
                return Err(NodeError::RateLimit("Too many inbound attempts".into()));
            }
        }

        // Configure TCP socket
        stream.set_nodelay(true)?;

        // Set keepalive to detect dead connections
        // Use into_std() before converting to Socket
        let std_stream = stream.into_std()?;
        let socket = Socket::from(std_stream);

        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(15));
        socket.set_tcp_keepalive(&keepalive)?;

        // Convert socket back to TcpStream
        let mut stream = TcpStream::from_std(socket.into())?;

        // Perform secure handshake with timeout
        let (peer_info, shared_secret) = tokio::time::timeout(
            Duration::from_secs(10),
            self.perform_handshake(&mut stream, false), // false = responder mode
        )
        .await
        .map_err(|_| NodeError::Network("Handshake timeout".into()))??;

        // Do NOT clear this IP's inbound-attempt counter on a successful handshake: that let an
        // attacker reset the per-IP limit at will by completing one handshake, neutering the cap.
        // The counter already decays after INBOUND_ATTEMPT_WINDOW, which is the intended reset.
        let peer_addr = peer_info.address;

        // Version check
        if peer_info.version != NETWORK_VERSION {
            return Err(NodeError::Network(format!(
                "Version mismatch: {} (expected {})",
                peer_info.version, NETWORK_VERSION
            )));
        }

        // Verify peer slots and subnet diversity
        {
            let mut peers = self.peers.write().await;
            if peers.len() >= self.max_peers {
                return Err(NodeError::Network("Maximum peers reached".into()));
            }

            // Check subnet diversity
            let subnet_peers = peers
                .values()
                .filter(|p| p.subnet_group == peer_info.subnet_group)
                .count();

            if subnet_peers >= MAX_PEERS_PER_SUBNET {
                return Err(NodeError::Network("Subnet peer limit reached".into()));
            }

            // Add peer to our list
            peers.insert(peer_addr, peer_info.clone());
        }

        // Store encryption secret
        self.peer_secrets
            .write()
            .await
            .insert(peer_addr, shared_secret.clone());

        // Notify peer join. try_send, never send().await: these events are advisory
        // (peer bookkeeping), and awaiting a FULL bounded queue here pinned this
        // connection task — and its accept-semaphore permit — forever if the event
        // pump ever died. Losing one advisory event under backpressure is strictly
        // better than wedging the listener (the permit leak cascaded to "node stops
        // accepting connections entirely").
        if let Err(e) = tx.try_send(NetworkEvent::PeerJoin(peer_addr)) {
            warn!("Dropped PeerJoin event for {}: {}", peer_addr, e);
        }

        // Message handling loop
        let (mut reader, mut writer) = tokio::io::split(stream);

        // Cumulative handler-failure ceiling for a single connection. Higher than the
        // health-check MAX_FAILURES (3) so a couple of transient malformed frames don't drop
        // an otherwise-honest peer, but bounded so a peer streaming invalid frames can't hold
        // the connection open forever.
        const MAX_HANDLER_FAILURES: u32 = 10;

        'connection: loop {
            // Read message length prefix with timeout
            let mut len_bytes = [0u8; 4];
            match tokio::time::timeout(
                Duration::from_secs(PEER_TIMEOUT),
                reader.read_exact(&mut len_bytes),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => break, // Connection closed or error
                Err(_) => break,     // Timeout
            }

            // Parse message length and validate
            let message_len = u32::from_be_bytes(len_bytes) as usize;
            if message_len == 0 {
                warn!("Empty message frame from {}", peer_addr);
                self.record_peer_failure(peer_addr).await;
                break;
            }
            if message_len > MAX_MESSAGE_SIZE {
                warn!(
                    "Oversized message from {}: {} bytes",
                    peer_addr, message_len
                );
                self.record_peer_failure(peer_addr).await;
                break;
            }

            // Create a mutable slice for reading
            let mut data_buf = vec![0u8; message_len];

            // Read message data with timeout
            match tokio::time::timeout(
                Duration::from_secs(PEER_TIMEOUT),
                reader.read_exact(&mut data_buf),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let data_to_process = &data_buf;

                    // Enforce authenticated transport after a successful handshake.
                    // Any decrypt failure or missing secret is treated as a protocol violation.
                    let (message, plaintext) = match self
                        .decrypt_message_with_plaintext(data_to_process, &shared_secret)
                    {
                        Ok(pair) => pair,
                        Err(e) => {
                            warn!("Decryption failed from {}: {}", peer_addr, e);
                            self.record_peer_failure(peer_addr).await;
                            break 'connection;
                        }
                    };

                    // Process message; the plaintext bytes carry the dedup/length checks (no
                    // re-serialize, no second deserialize).
                    let response = match self
                        .handle_peer_message(message, &plaintext, peer_addr, &tx)
                        .await
                    {
                        Ok(response) => response,
                        Err(e) => {
                            warn!("Message handling error from {}: {}", peer_addr, e);

                            // Check if error suggests malicious behavior
                            let mut recorded = false;
                            match &e {
                                NodeError::Network(msg)
                                    if msg.contains("Rate limit")
                                        || msg.contains("too large")
                                        || msg.contains("Invalid") =>
                                {
                                    self.record_peer_failure(peer_addr).await;
                                    recorded = true;
                                }
                                _ => {}
                            }

                            // A 'Rate limit' error drops the connection immediately.
                            if matches!(&e, NodeError::Network(msg) if msg.contains("Rate limit")) {
                                break 'connection;
                            }

                            // Other malicious-looking errors are tolerated transiently — but a peer
                            // that keeps streaming malformed/invalid frames must not be served
                            // forever. Once its cumulative failure count (the same signal the
                            // health-check loop evicts on) crosses the handler ceiling, drop it.
                            if recorded {
                                let n = self
                                    .peer_failures
                                    .read()
                                    .await
                                    .get(&peer_addr)
                                    .copied()
                                    .unwrap_or(0);
                                if n >= MAX_HANDLER_FAILURES {
                                    warn!("Dropping {} after {} handler failures", peer_addr, n);
                                    break 'connection;
                                }
                            }

                            // Continue for transient errors
                            continue;
                        }
                    };

                    if let Some(response) = response {
                        match tokio::time::timeout(
                            Duration::from_secs(10),
                            self.write_encrypted_frame(&mut writer, &response, &shared_secret),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                warn!("Response write failed to {}: {}", peer_addr, e);
                                self.record_peer_failure(peer_addr).await;
                                break 'connection;
                            }
                            Err(_) => {
                                warn!("Response write timed out to {}", peer_addr);
                                self.record_peer_failure(peer_addr).await;
                                break 'connection;
                            }
                        }
                    }

                    // Update peer timestamp
                    if let Some(peer) = self.peers.write().await.get_mut(&peer_addr) {
                        peer.last_seen = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                    }
                }
                Ok(Err(e)) => {
                    warn!("Read error from {}: {}", peer_addr, e);
                    break 'connection;
                }
                Err(_) => {
                    warn!("Read timeout from {}", peer_addr);
                    break 'connection;
                }
            }
        }

        // Cleanup
        self.peers.write().await.remove(&peer_addr);
        self.peer_secrets.write().await.remove(&peer_addr);
        self.outbound_connections.write().await.remove(&peer_addr);
        self.outbound_circuit_breakers
            .write()
            .await
            .remove(&peer_addr);
        self.compact_capable_peers.remove(&peer_addr);

        // Notify disconnect. Same rationale as the PeerJoin try_send above.
        if let Err(e) = tx.try_send(NetworkEvent::PeerLeave(peer_addr)) {
            warn!("Dropped PeerLeave event for {}: {}", peer_addr, e);
        }

        Ok(())
    }

    async fn monitor_peer_connection(&self, addr: SocketAddr) -> Result<(), NodeError> {
        const PING_INTERVAL: Duration = Duration::from_secs(30);
        const MAX_FAILURES: u32 = 3;

        let mut interval = tokio::time::interval(PING_INTERVAL);
        // No burst replay of slept-through pings after an OS suspend (see the
        // beacon-watch ticker): one immediate ping, then the normal cadence.
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut failures = 0;

        // Send initial ping to measure latency
        if self.send_ping(addr).await.is_err() {
            failures += 1;
        }

        while failures < MAX_FAILURES {
            interval.tick().await;

            // Check if peer is still in our list
            if !self.peers.read().await.contains_key(&addr) {
                break;
            }

            // Send ping and wait for response
            match self.send_ping(addr).await {
                Ok(_) => {
                    failures = 0;
                }
                Err(e) => {
                    failures += 1;
                    warn!(
                        "Ping failed for {} ({}/{}): {}",
                        addr, failures, MAX_FAILURES, e
                    );

                    // Exponential backoff
                    tokio::time::sleep(Duration::from_secs(1 << failures.min(6))).await;
                }
            }
        }

        // Remove unresponsive peer
        if failures >= MAX_FAILURES {
            warn!("Removing unresponsive peer {}", addr);
            self.peers.write().await.remove(&addr);
            self.peer_secrets.write().await.remove(&addr);
        }

        Ok(())
    }

    async fn send_ping(&self, addr: SocketAddr) -> Result<(), NodeError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let ping = NetworkMessage::Ping {
            timestamp,
            node_id: self.capability_node_id(),
        };

        // Send ping with timeout and consume the direct pong response on the same stream.
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            self.send_message_with_response(addr, &ping),
        )
        .await
        .map_err(|_| NodeError::Network("Ping timeout".to_string()))??;

        match response {
            NetworkMessage::Pong { timestamp, node_id } => {
                self.observe_compact_capability(addr, &node_id);
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut peers = self.peers.write().await;
                if let Some(info) = peers.get_mut(&addr) {
                    info.latency = now.saturating_sub(timestamp);
                    info.last_seen = now;
                }
                Ok(())
            }
            _ => Err(NodeError::Network("Invalid ping response".to_string())),
        }
    }

    // Method to convert Multiaddr to SocketAddr (needed for libp2p integration)
    #[allow(dead_code)]
    fn multiaddr_to_socketaddr(&self, addr: &Multiaddr) -> Result<SocketAddr, NodeError> {
        use libp2p_core::multiaddr::Protocol;

        let components: Vec<_> = addr.iter().collect();

        match (components.first(), components.get(1)) {
            (Some(Protocol::Ip4(ip)), Some(Protocol::Tcp(port))) => {
                Ok(SocketAddr::new(IpAddr::V4(*ip), *port))
            }
            (Some(Protocol::Ip6(ip)), Some(Protocol::Tcp(port))) => {
                Ok(SocketAddr::new(IpAddr::V6(*ip), *port))
            }
            _ => Err(NodeError::Network("Invalid multiaddr format".to_string())),
        }
    }

    // Verification - essential for security
    pub async fn verify_peer(&self, addr: SocketAddr) -> Result<(), NodeError> {
        const CONNECTION_RETRIES: u32 = 2;
        const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

        // Best-effort failure gating:
        // keep trying peers even after prior failures so transient outages can recover.
        {
            let failures = self.peer_failures.read().await;
            if let Some(&count) = failures.get(&addr) {
                if count >= 3 {
                    debug!(
                        "Peer {} had {} prior failures; retrying with backoff",
                        addr, count
                    );
                }
            }
        }

        // Try to establish connection with retries
        let mut stream = None;
        let mut last_error = None;

        for retry in 0..CONNECTION_RETRIES {
            match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
                Ok(Ok(s)) => {
                    stream = Some(s);
                    break;
                }
                Ok(Err(e)) => {
                    last_error = Some(e);
                    // Exponential backoff
                    if retry < CONNECTION_RETRIES - 1 {
                        tokio::time::sleep(Duration::from_millis(200 * (1 << retry))).await;
                    }
                }
                Err(_) => {
                    last_error = Some(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Connection timed out",
                    ));
                    // Exponential backoff
                    if retry < CONNECTION_RETRIES - 1 {
                        tokio::time::sleep(Duration::from_millis(200 * (1 << retry))).await;
                    }
                }
            }
        }

        let stream = match stream {
            Some(s) => s,
            None => {
                // Record failure for this peer
                self.record_peer_failure(addr).await;
                return Err(NodeError::Network(format!(
                    "Failed to connect to {}: {}",
                    addr,
                    last_error.unwrap_or_else(|| std::io::Error::other("Unknown error"))
                )));
            }
        };

        debug!("verify_peer({}): tcp connected", addr);
        // IMPROVEMENT: Configure TCP socket for better performance
        stream.set_nodelay(true)?;

        // Use into_std() before converting to Socket
        let std_stream = stream.into_std()?;
        let socket = Socket::from(std_stream);

        // Set better TCP keepalive settings
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(5));
        socket.set_tcp_keepalive(&keepalive)?;

        // Convert socket back to TcpStream
        let mut stream = TcpStream::from_std(socket.into())?;

        debug!("verify_peer({}): starting handshake", addr);
        // IMPROVEMENT: Perform handshake with better timeout handling
        let handshake_result =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, self.perform_handshake(&mut stream, true))
                .await;
        debug!("verify_peer({}): handshake returned", addr);

        let (peer_info, shared_secret) = match handshake_result {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                self.record_peer_failure(addr).await;
                return Err(NodeError::Network(format!(
                    "Handshake failed with {}: {}",
                    addr, e
                )));
            }
            Err(_) => {
                self.record_peer_failure(addr).await;
                return Err(NodeError::Network(format!(
                    "Handshake timed out with {}",
                    addr
                )));
            }
        };

        // IMPROVEMENT: More comprehensive peer validation

        // 1. Version check
        if peer_info.version != NETWORK_VERSION {
            self.record_peer_failure(addr).await;
            return Err(NodeError::Network(format!(
                "Version mismatch with {}: {} (expected {})",
                addr, peer_info.version, NETWORK_VERSION
            )));
        }

        // 3. Check for subnet limits
        debug!("verify_peer({}): acquiring peers write lock", addr);
        let mut peers = self.peers.write().await;
        let subnet_peers = peers
            .values()
            .filter(|p| p.subnet_group == peer_info.subnet_group)
            .count();

        if subnet_peers >= MAX_PEERS_PER_SUBNET && peers.len() >= MIN_PEERS {
            return Err(NodeError::Network(format!(
                "Subnet limit reached for {}",
                addr
            )));
        }

        // Bound the peer table (matches the inbound handshake path); existing peers may reconnect.
        if peers.len() >= self.max_peers && !peers.contains_key(&addr) {
            return Err(NodeError::Network("Maximum peers reached".into()));
        }

        // 4. Store peer information
        peers.insert(addr, peer_info);
        drop(peers);

        debug!("verify_peer({}): storing secret", addr);
        let mut peer_secrets = self.peer_secrets.write().await;
        peer_secrets.insert(addr, shared_secret.clone());
        drop(peer_secrets);

        debug!("verify_peer({}): registering outbound connection", addr);
        self.insert_outbound_connection(addr, stream, shared_secret)
            .await;

        debug!("verify_peer({}): advertising ML-DSA key", addr);
        if let Err(e) = self.advertise_mldsa_key(addr).await {
            debug!("Failed to advertise ML-DSA key to {}: {}", addr, e);
        }

        debug!("verify_peer({}): resetting failure counter", addr);
        // Reset failure counter
        self.reset_peer_failures(addr).await;
        debug!("verify_peer({}): done", addr);

        // IMPROVEMENT: Trigger initial latency measurement
        tokio::spawn({
            let node = self.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = node.send_ping(addr).await;
            }
        });

        Ok(())
    }

    /// Role flag: mark this node as a PUBLIC full-history server so a reachable node
    /// (VPS / cloudflared tunnel) can carry brand-new nodes genesis..tip over GetBlocks,
    /// making the gateway a fallback rather than a single point of failure. This is a
    /// ROLE / advertising flag ONLY — every validation and trust check stays unconditional
    /// and unchanged, so it does not weaken security. Serving already works from height 0.
    fn public_full_history_node_enabled() -> bool {
        Self::env_flag_enabled("ALPHANUMERIC_PUBLIC_NODE")
    }

    /// Anchor height for a peer full-sync: the beacon tip, but only if the chosen peer is at
    /// least that tall. An inflated peer height can never raise the target; a peer SHORTER
    /// than the beacon is unusable (it would hand us a truncated chain) -> None.
    fn full_sync_anchor_height(beacon_height: u32, peer_height: u32) -> Option<u32> {
        if peer_height >= beacon_height {
            Some(beacon_height)
        } else {
            None
        }
    }

    /// Connected peers to try for the boot / idle / mine-prep delta-sync: peers whose RECORDED
    /// height already covers the beacon first (tallest first), then everyone else (tallest
    /// first; address as a deterministic tiebreak), capped at FULL_SYNC_MAX_CANDIDATES.
    ///
    /// The recorded height is a RANKING hint, never a filter. After an OS sleep every
    /// PeerInfo.blocks is hours stale — uniformly BELOW the live beacon — and the old
    /// `blocks >= beacon_height` pre-filter starved the delta-sync of every live candidate
    /// exactly when it was the only cure (Windows wake-after-idle, 2026-07-27: "cannot mine
    /// right now … restart to re-bootstrap" on a node whose peers could all have served the
    /// gap). sync_full_history_from_peer independently re-verifies each candidate
    /// (verify_peer + a FRESH request_peer_height + the signed-beacon tip probe) before
    /// applying any block, so a stale — or lying — recorded height can cost a bounded probe,
    /// never correctness.
    fn full_sync_candidate_peers(
        peers: &HashMap<SocketAddr, PeerInfo>,
        beacon_height: u32,
    ) -> Vec<SocketAddr> {
        let mut ranked: Vec<(SocketAddr, u32)> = peers
            .iter()
            .map(|(addr, info)| (*addr, info.blocks))
            .collect();
        ranked.sort_by(|a, b| {
            let a_covers = a.1 >= beacon_height;
            let b_covers = b.1 >= beacon_height;
            b_covers
                .cmp(&a_covers)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.0.cmp(&b.0))
        });
        ranked.truncate(FULL_SYNC_MAX_CANDIDATES);
        ranked.into_iter().map(|(addr, _)| addr).collect()
    }

    /// True when a caller-imposed slice deadline has passed. None = unbounded
    /// (background loops run the sync to completion).
    fn full_sync_deadline_expired(deadline: Option<Instant>) -> bool {
        deadline.is_some_and(|d| Instant::now() >= d)
    }

    /// Next GetBlocks span [start, end], bounded so (end - start) < MAX_GETBLOCKS_SPAN (the
    /// server ingress cap) and `end` never exceeds the fixed target height.
    fn full_sync_next_span(cursor: u32, target: u32) -> (u32, u32) {
        let end = cursor
            .saturating_add(MAX_GETBLOCKS_SPAN.saturating_sub(1))
            .min(target);
        (cursor, end)
    }

    /// One link of the backward commitment walk: this block must BE the hash the block above
    /// it demanded, and its header must actually hash to that value. Substitution, reordering
    /// and omission all fail here, which is what makes the span self-proving. Split out from
    /// the PoW check so the commitment rule itself stays unit-testable without mining.
    fn committed_link_ok(block: &Block, demanded_hash: [u8; 32]) -> bool {
        block.hash == demanded_hash && block.calculate_hash_for_block() == block.hash
    }

    /// Pull [local_tip+1 ..= beacon.height] and prove the whole span against the signed
    /// beacon BEFORE any of it is applied.
    ///
    /// Why this exists: peers retain full ML-DSA witnesses for only WITNESS_RETENTION_BLOCKS
    /// past confirmation. A client that was closed for hours comes back needing thousands of
    /// blocks whose witnesses no longer exist ANYWHERE, so routing them through
    /// verify_block_with_witness cannot succeed — it inches through coinbase-only blocks and
    /// stalls on the first block carrying a real transaction. The receipt path is the correct
    /// path for witness-pruned history (that is what it is for); the only thing it needs is
    /// proof that the span is canonical.
    ///
    /// The proof is self-contained and does NOT trust the serving peer. Walking DOWNWARD from
    /// the gateway-signed beacon hash, each block's `previous_hash` dictates the hash the next
    /// block down must have, so every block is transitively committed by a signature the node
    /// already trusts for bootstrap manifests. The walk terminates by requiring the bottom of
    /// the span to chain into THIS node's own current tip hash — so the result is strictly
    /// stronger than a snapshot, which is committed by the same key but anchored to nothing we
    /// hold. A peer that substitutes, reorders, omits or forges any block breaks the chain and
    /// gets None, and the caller falls through to today's behaviour.
    ///
    /// Returns the span ASCENDING, ready to apply in order.
    async fn fetch_beacon_committed_span(
        &self,
        peer: SocketAddr,
        beacon: &TipBeaconInfo,
        local_tip: u32,
        local_tip_hash: [u8; 32],
        deadline: Option<Instant>,
    ) -> Option<Vec<Block>> {
        if beacon.height <= local_tip {
            return None;
        }
        if beacon.height.saturating_sub(local_tip) > COMMITTED_SPAN_MAX_BLOCKS {
            return None;
        }

        let mut expected_hash = beacon.hash;
        let mut needed = beacon.height;
        let mut collected: Vec<Block> = Vec::new();
        let mut buffered_bytes = 0usize;

        while needed > local_tip {
            if Self::full_sync_deadline_expired(deadline) {
                return None;
            }
            let window_start = needed
                .saturating_sub(MAX_GETBLOCKS_SPAN.saturating_sub(1))
                .max(local_tip.saturating_add(1));
            let blocks = self.request_blocks(peer, window_start, needed).await.ok()?;
            let mut by_height: std::collections::HashMap<u32, Block> = blocks
                .into_iter()
                .filter(|b| b.index >= window_start && b.index <= needed)
                .map(|b| (b.index, b))
                .collect();

            let progressed_from = needed;
            while needed > local_tip {
                let Some(block) = by_height.remove(&needed) else {
                    break;
                };
                // The hash this block MUST have was fixed by the block above it (and the
                // topmost by the signed beacon). PoW is checked alongside, so a peer cannot
                // hand back a cheaply-forged body under a demanded hash.
                if !Self::committed_link_ok(&block, expected_hash) || !block.verify_pow_meets_floor()
                {
                    return None;
                }
                buffered_bytes = buffered_bytes.saturating_add(
                    codec::serialize(&block).map(|v| v.len()).unwrap_or(0),
                );
                if buffered_bytes > COMMITTED_SPAN_MAX_BYTES {
                    return None;
                }
                expected_hash = block.previous_hash;
                needed = needed.saturating_sub(1);
                collected.push(block);
            }
            // A window that advanced nothing means this peer cannot serve the span.
            if needed == progressed_from {
                return None;
            }
        }

        // The span must attach to history WE already hold; otherwise it is a foreign
        // chain that merely happens to end at the beacon.
        if expected_hash != local_tip_hash {
            return None;
        }

        collected.reverse();
        Some(collected)
    }

    /// Loop guard: continue only while below the target AND the last batch advanced the tip.
    /// A no-progress batch (empty / all-orphaned / non-linking) terminates the sync — this is
    /// what guarantees termination against a stalling peer.
    fn full_sync_should_continue(cursor: u32, target: u32, made_progress: bool) -> bool {
        cursor <= target && made_progress
    }

    /// A block at/above verification_floor()+1 is on the unfinalized frontier and MUST pass
    /// full ML-DSA witness verification; at/below the floor it takes the receipt fast-path
    /// (witness-pruned history, pinned by hash between genesis and the confirmed tip).
    fn routes_via_witness(block_index: u32, verification_floor: u32) -> bool {
        block_index >= verification_floor.saturating_add(1)
    }

    /// Probe connected peers (ranked by full_sync_candidate_peers) for one that can serve the
    /// signed beacon: verify_peer + a FRESH height read gate each candidate — the recorded
    /// heights only order the attempts. Bounded by FULL_SYNC_MAX_CANDIDATES, the per-message
    /// timeouts, and the caller's slice deadline.
    async fn probe_full_sync_candidates(
        &self,
        beacon: &TipBeaconInfo,
        deadline: Option<Instant>,
    ) -> Option<SocketAddr> {
        let candidates = {
            let peers = self.peers.read().await;
            Self::full_sync_candidate_peers(&peers, beacon.height)
        };
        for addr in candidates {
            if Self::full_sync_deadline_expired(deadline) {
                return None;
            }
            // No verify_peer here: connected candidates already passed the full
            // handshake at connect time (and a pool miss re-handshakes inside the
            // send anyway) — re-dialing cost ~15s per dead candidate on the wake
            // path. The fresh height read (bounded tight: post-suspend half-open
            // sockets are the common failure) plus the STEP-2 signed-beacon tip
            // probe are the real gates; the exchange guard makes the cancel safe.
            let Ok(Ok(peer_height)) =
                timeout(Duration::from_secs(5), self.request_peer_height(addr)).await
            else {
                continue;
            };
            if Self::full_sync_anchor_height(beacon.height, peer_height).is_some() {
                return Some(addr);
            }
        }
        None
    }

    /// TIER-2 bootstrap fallback: reconstruct genesis..tip directly from a reachable SEED PEER
    /// over GetBlocks when the gateway snapshot is unavailable/stale — removing the heavy
    /// bootstrap zip as a single point of failure. This is BODY ACQUISITION only:
    /// converge_to_canonical remains the sole canonicality arbiter (Step 4), every block passes
    /// the IDENTICAL ingest validation as any other source (PoW floor, hash, difficulty
    /// progression, parent linkage, genesis pin, full ML-DSA witnesses above the floor), and the
    /// finality checkpoint is advanced ONLY after the reconstructed tip is confirmed == the
    /// gateway-attested beacon hash. Genesis is the built-in pinned block, never fetched. Returns
    /// a Converge outcome; touches NO state on the no-peer / no-beacon path, so every existing
    /// gateway/relay path is byte-for-byte unchanged when this cannot help.
    pub async fn sync_full_history_from_peer(&self, include_connected_peers: bool) -> Converge {
        self.sync_full_history_from_peer_bounded(include_connected_peers, None)
            .await
    }

    /// Deadline-sliced, single-flight variant. `deadline` bounds interactive callers
    /// (mine-prep works inside a declared prep budget): it is checked between candidate
    /// probes, between committed-span block applies, and between GetBlocks spans —
    /// never mid-block — so expiry always leaves a consistent applied prefix and the
    /// next call resumes from the advanced tip.
    /// `None` = run to completion (the background loops).
    async fn sync_full_history_from_peer_bounded(
        &self,
        include_connected_peers: bool,
        deadline: Option<Instant>,
    ) -> Converge {
        // SINGLE-FLIGHT: the idle reconcile loop, the beacon-watch loop and mine-prep can
        // all decide to heal the same far-behind chain at once (on a wake-from-sleep they
        // all fire together). Streaming the same span twice doubles peer load for zero
        // benefit, so an overlapping call reports Progressed — "the tip is being advanced"
        // — which no caller escalates on (the idle loop resets its strikes, mine-prep keeps
        // waiting inside its budget). Drop-guard, not a tail store: the future can be
        // cancelled at any await point and the flag must never stay latched.
        struct InFlight<'a>(&'a AtomicBool);
        impl Drop for InFlight<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        if self
            .full_sync_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Converge::Progressed;
        }
        let _in_flight = InFlight(&self.full_sync_in_flight);

        // STEP 0: trusted anchor = the signed tip beacon (the SAME canonical (height,hash)
        // converge_to_canonical already trusts). No beacon -> no anchor -> caller falls through.
        let Some(beacon) = self.fetch_tip_beacon().await else {
            return Converge::BeaconStale;
        };

        // STEP 1: choose ONE seed peer at least as tall as the beacon. Target is ALWAYS the
        // beacon height, never the peer's self-reported height.
        let mut chosen: Option<SocketAddr> = None;
        'seed: for seed in self.configured_seed_nodes().to_vec() {
            if Self::full_sync_deadline_expired(deadline) {
                break;
            }
            let Ok(addrs) = tokio::net::lookup_host(&seed).await else {
                continue;
            };
            for addr in addrs {
                if self.verify_peer(addr).await.is_err() {
                    continue;
                }
                let Ok(peer_height) = self.request_peer_height(addr).await else {
                    continue;
                };
                if Self::full_sync_anchor_height(beacon.height, peer_height).is_some() {
                    chosen = Some(addr);
                    break 'seed;
                }
            }
        }
        // If no configured seed served the beacon and the caller allows it (the boot / idle client
        // path — NOT the publisher live loop), fall back to already-CONNECTED peers. Source is
        // irrelevant to safety: the STEP-2 tip probe and the per-block PoW/hash/witness checks
        // below reject any peer not truly on the canonical chain, so this only WIDENS who can
        // serve the delta, never what is accepted. A seedless client (the common case) thus gets
        // a real delta-sync path instead of the full snapshot.
        if chosen.is_none() && include_connected_peers {
            chosen = self.probe_full_sync_candidates(&beacon, deadline).await;
        }
        // WAKE-FROM-SLEEP RECOVERY: after an OS suspend the peers map holds only half-open
        // sockets and hours-stale recorded heights, so every probe above can fail even though
        // the network is one dial away. Kick a bounded discovery pass (fresh dials, fresh
        // handshake heights) and re-scan ONCE. This is what lets a woken laptop/desktop heal
        // in place instead of falling through to the snapshot re-bootstrap escape.
        if chosen.is_none()
            && include_connected_peers
            && !Self::full_sync_deadline_expired(deadline)
        {
            let _ = timeout(Duration::from_secs(5), self.connect_discovery_peers(8)).await;
            chosen = self.probe_full_sync_candidates(&beacon, deadline).await;
        }

        let Some(peer) = chosen else {
            return Converge::NeedsBootstrap;
        };
        let target = beacon.height;

        // STEP 2: tip PROBE (anti-forgery). The peer must return the block at beacon.height
        // whose hash == beacon.hash BEFORE we apply any lower block — proving it holds the
        // gateway-attested tip. A peer not on the canonical chain cannot pass this.
        let probe_ok = matches!(self.request_blocks(peer, target, target).await, Ok(blocks) if blocks
            .iter()
            .any(|b| b.index == target && b.hash == beacon.hash && b.calculate_hash_for_block() == b.hash));
        if !probe_ok {
            return Converge::NeedsBootstrap;
        }

        // STEP 2b: DEEP gap — past the witness retention window the per-block witness path
        // below cannot succeed, because those witnesses no longer exist on any peer. Prove the
        // whole span against the signed beacon first, then apply it through the receipt path
        // (the path witness-pruned history is meant to take). Purely additive: if the span
        // cannot be proven, or is too deep to buffer, this yields nothing and STEP 3 runs
        // exactly as before.
        {
            let (local_tip, local_tip_hash) = {
                let bc = self.blockchain.read().await;
                let tip = bc.get_latest_block_index() as u32;
                (tip, bc.get_block(tip).ok().map(|b| b.hash))
            };
            let gap = target.saturating_sub(local_tip);
            if gap > crate::a9::blockchain::WITNESS_RETENTION_BLOCKS as u32 {
                if let Some(tip_hash) = local_tip_hash {
                    if let Some(span) = self
                        .fetch_beacon_committed_span(peer, &beacon, local_tip, tip_hash, deadline)
                        .await
                    {
                        info!(
                            "peer full-sync: applying {} beacon-committed blocks ({}..={})",
                            span.len(),
                            local_tip.saturating_add(1),
                            target
                        );
                        // Amortize durability across the span: one dirty
                        // window instead of 4-5 full-DB fsyncs per block (the
                        // 11-13 blk/s catch-up ceiling). Failure to open is
                        // non-fatal — the loop then runs with today's
                        // per-block durability.
                        let batch = {
                            let bc = self.blockchain.read().await;
                            bc.begin_receipt_batch()
                                .await
                                .map_err(|e| {
                                    warn!(
                                        "peer full-sync: apply window unavailable, using per-block durability: {}",
                                        e
                                    )
                                })
                                .ok()
                        };
                        for block in &span {
                            // Same slice contract as the GetBlocks loop in STEP 3: expiry
                            // between block applies, never mid-block. A proven span can run
                            // to 8,192 sequential writes — tens of seconds a mine-prep
                            // caller never agreed to spend. The applied prefix stays
                            // consistent, and STEP 3 (this call's, or a later caller's)
                            // resumes from wherever the tip actually got to.
                            if Self::full_sync_deadline_expired(deadline) {
                                break;
                            }
                            if let Err(e) = self
                                .blockchain
                                .write()
                                .await
                                .save_receipt_verified_block(block)
                                .await
                            {
                                // Stop at the first refusal: the rest cannot link past a gap,
                                // and STEP 3 will resume from wherever the tip actually got to.
                                warn!(
                                    "peer full-sync: committed block {} rejected: {}",
                                    block.index, e
                                );
                                break;
                            }
                        }
                        if let Some(batch) = batch {
                            if let Err(e) = {
                                let bc = self.blockchain.read().await;
                                bc.commit_receipt_batch(batch).await
                            } {
                                warn!(
                                    "peer full-sync: apply window commit failed; dirty marker left for recovery: {}",
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }

        // STEP 3: bulk-pull [local_tip+1 .. target] ascending, applying each block through the
        // SAME ingest path as every other source. The checkpoint is NOT advanced here (Step 4).
        let mut cursor =
            { self.blockchain.read().await.get_latest_block_index() as u32 }.saturating_add(1);
        loop {
            if cursor > target {
                break;
            }
            // Slice expiry between spans only: the applied prefix stays consistent and a
            // later call (same or another caller) resumes from the advanced tip.
            if Self::full_sync_deadline_expired(deadline) {
                break;
            }
            let (start, end) = Self::full_sync_next_span(cursor, target);
            let Ok(blocks) = self.request_blocks(peer, start, end).await else {
                break;
            };
            let mut candidates: Vec<_> = blocks
                .into_iter()
                // Hash + PoW-floor already verified inside request_blocks (batch
                // filter) — re-hashing every block here doubled catch-up CPU.
                .filter(|b| b.index >= start && b.index <= end)
                .collect();
            candidates.sort_by_key(|b| b.index);

            let before_tip = { self.blockchain.read().await.get_latest_block_index() as u32 };
            let floor = { self.blockchain.read().await.verification_floor() };
            // One dirty window per span: amortizes the per-block fsyncs for
            // both the receipt path and the witness path (they funnel into the
            // same persist). Non-fatal if unavailable.
            let batch = {
                let bc = self.blockchain.read().await;
                bc.begin_receipt_batch()
                    .await
                    .map_err(|e| {
                        warn!(
                            "peer full-sync: apply window unavailable, using per-block durability: {}",
                            e
                        )
                    })
                    .ok()
            };
            for block in candidates {
                let res = if Self::routes_via_witness(block.index, floor) {
                    self.accept_peer_block(&block, Some(peer)).await
                } else {
                    self.blockchain
                        .write()
                        .await
                        .save_receipt_verified_block(&block)
                        .await
                        .map_err(|e| NodeError::Blockchain(e.to_string()))
                };
                if let Err(e) = res {
                    warn!("peer full-sync: block {} rejected: {}", block.index, e);
                }
            }
            if let Some(batch) = batch {
                if let Err(e) = {
                    let bc = self.blockchain.read().await;
                    bc.commit_receipt_batch(batch).await
                } {
                    warn!(
                        "peer full-sync: apply window commit failed; dirty marker left for recovery: {}",
                        e
                    );
                }
            }
            let after_tip = { self.blockchain.read().await.get_latest_block_index() as u32 };
            let made_progress = after_tip > before_tip;
            cursor = after_tip.saturating_add(1);
            if !Self::full_sync_should_continue(cursor, target, made_progress) {
                break;
            }
        }

        // STEP 4: confirm + finalize via the existing arbiter. converge_to_canonical returns
        // Converged/AtTipAhead only if our reconstructed tip hash == the beacon hash; ONLY then
        // do we trail the finality checkpoint (mirroring snapshot semantics). Peer data can
        // never raise finality on its own.
        let outcome = self.converge_to_canonical(&beacon).await;
        if matches!(outcome, Converge::Converged | Converge::AtTipAhead) {
            let _ = self
                .blockchain
                .read()
                .await
                .advance_checkpoint_behind(beacon.height);
        }
        outcome
    }

    // Sync with network to keep blockchain updated
    /// A relay-fallback failure is only a real sync failure when a peer is genuinely AHEAD of us.
    /// With zero blocks synced from peers and no known peer above `current_height`, we are caught up
    /// to the peer frontier, so a transient relay-backfill error is benign (the periodic beacon-driven
    /// converge loop still tracks the relay head). This keeps "failed to sync" meaningful for a
    /// genuinely-stuck node instead of crying wolf on every at-tip relay blip.
    fn any_peer_ahead(peer_heights: &[(SocketAddr, u32)], current_height: u32) -> bool {
        peer_heights.iter().any(|(_, h)| *h > current_height)
    }

    pub async fn sync_with_network(&self) -> Result<(), NodeError> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY_MS: u64 = 1000;
        const PEER_TIMEOUT_MS: u64 = 5000;
        // Full server span: GetBlocks serving caps at MAX_GETBLOCKS_SPAN and
        // request_blocks re-batches at the same size, so asking for less (the old
        // 50) just multiplied round-trips 5x on every p2p catch-up. Short replies
        // are already handled (the cursor advances by what actually applied).
        const MAX_BATCH_SIZE: u32 = MAX_GETBLOCKS_SPAN;

        // 1. Get current blockchain state
        let current_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_latest_block_index() as u32
        };

        // 2. Check peer count and discover if needed. Scope the read guard to the
        // count itself: binding it to a named `peers` and re-binding later SHADOWED
        // the first guard instead of dropping it, so on the peer_count > 0 path it
        // stayed held across every network await below (query_peer_heights fan-out,
        // the whole batch sync) — a fair-RwLock writer queued behind it parked every
        // later reader and wedged the node (watchdog peers_ok=false, 2026-07-09).
        let peer_count = self.peers.read().await.len();

        if peer_count == 0 {
            info!("No peers available, discovering network nodes");
            if let Err(connect_err) = self.connect_discovery_peers(8).await {
                debug!("Fast discovery peer connect deferred: {}", connect_err);
                if let Err(discovery_err) = self.discover_network_nodes().await {
                    debug!("Failed to discover peers for sync: {}", discovery_err);
                    return self
                        .sync_with_block_relay(current_height)
                        .await
                        .map(|_| ())
                        .map_err(|relay_err| {
                            NodeError::Network(format!(
                                "No peers available for sync and relay sync failed: {}",
                                relay_err
                            ))
                        });
                }
            }
        }

        // 3. IMPROVEMENT: Find multiple peers with highest block height
        // Get a fresh peer list after possible discovery
        let peers = self.peers.read().await;

        // IMPROVEMENT: Track peer heights with better error handling
        let peer_ips: Vec<_> = peers.keys().cloned().collect();
        drop(peers); // Release lock before making network requests

        let mut peer_heights = self.query_peer_heights(peer_ips, PEER_TIMEOUT_MS).await;

        if peer_heights.is_empty() {
            if let Err(e) = self.connect_discovery_peers(8).await {
                debug!("Discovery retry before sync failed: {}", e);
            }
            let peers = self.peers.read().await;
            let peer_ips: Vec<_> = peers.keys().cloned().collect();
            drop(peers);
            peer_heights = self.query_peer_heights(peer_ips, PEER_TIMEOUT_MS).await;
        }

        // Reliability fallback: the GetBlockHeight RPC can miss responses, but the
        // handshake always exchanges chain heights. Use the height each peer reported
        // at connect time for any peer that is ahead of us, so a behind node still
        // knows who to sync from instead of giving up.
        if peer_heights.is_empty() {
            let peers = self.peers.read().await;
            let mut handshake_heights: Vec<(SocketAddr, u32)> = peers
                .iter()
                .filter(|(_, info)| info.blocks > current_height)
                .map(|(addr, info)| (*addr, info.blocks))
                .collect();
            drop(peers);
            handshake_heights.sort_by(|a, b| b.1.cmp(&a.1));
            if !handshake_heights.is_empty() {
                debug!(
                    "sync_with_network: RPC returned no heights; using {} handshake-known peer(s), best={}",
                    handshake_heights.len(),
                    handshake_heights[0].1
                );
                peer_heights = handshake_heights;
            }
        }
        debug!(
            "sync_with_network: local={} candidates={}",
            current_height,
            peer_heights.len()
        );

        // IMPROVEMENT: Check if we already have the latest blocks
        if let Some((_, best_height)) = peer_heights.first() {
            if *best_height <= current_height {
                info!(
                    "Already at best height ({}/{})",
                    current_height, best_height
                );
                return Ok(());
            }

            info!("Syncing from height {} to {}", current_height, best_height);
        } else {
            debug!("No peers reported their height");
            return self
                .sync_with_block_relay(current_height)
                .await
                .map(|_| ())
                .map_err(|relay_err| {
                    NodeError::Network(format!(
                        "No peers reported their height and relay sync failed: {}",
                        relay_err
                    ))
                });
        }

        // 4. IMPROVEMENT: Try multiple peers for sync
        // Use up to 3 best peers for sync
        let sync_candidates = peer_heights.iter().take(3).cloned().collect::<Vec<_>>();

        if sync_candidates.is_empty() {
            return Err(NodeError::Network("No suitable peers for sync".to_string()));
        }

        let mut blocks_synced = 0;
        let mut current_sync_height = current_height;

        // 5. IMPROVEMENT: Process blocks in smaller batches with parallel validation
        'outer: for sync_attempt in 0..MAX_RETRIES {
            // Try each candidate in order
            for (candidate_idx, (peer_addr, peer_height)) in sync_candidates.iter().enumerate() {
                if current_sync_height >= *peer_height {
                    continue;
                }

                info!(
                    "Sync attempt {}/{} using peer {} ({}/{})",
                    sync_attempt + 1,
                    MAX_RETRIES,
                    candidate_idx + 1,
                    peer_addr,
                    peer_height
                );

                // Sync in smaller batches
                let mut start = current_sync_height.saturating_add(1);

                while start <= *peer_height {
                    let end = std::cmp::min(
                        start.saturating_add(MAX_BATCH_SIZE.saturating_sub(1)),
                        *peer_height,
                    );

                    match self.request_blocks(*peer_addr, start, end).await {
                        Ok(blocks) => {
                            let mut candidate_blocks: Vec<_> = blocks
                                .into_iter()
                                // Hash + PoW-floor already verified inside
                                // request_blocks (batch filter) — no re-hash here.
                                .filter(|block| {
                                    block.index >= start
                                        && block.index <= end
                                })
                                .collect();
                            candidate_blocks.sort_by_key(|block| block.index);

                            let actual_count = candidate_blocks.len();
                            if actual_count > 0 {
                                let mut saved_count = 0;

                                // Every block ABOVE the trusted checkpoint — the
                                // unfinalized frontier — is verified against full ML-DSA
                                // witnesses fetched from the serving peer. Catch-up blocks
                                // at/below the checkpoint keep the receipt fast-path; the
                                // signed snapshot vouches for that history, which is what
                                // lets catch-up over witness-pruned blocks proceed.
                                //
                                // Anchored to finality, never to the peer's claimed height:
                                // an inflated handshake height cannot lower the checkpoint,
                                // so it cannot route tip-extending blocks into the receipt
                                // fast-path.
                                let verify_from =
                                    { self.blockchain.read().await.verification_floor() }
                                        .saturating_add(1);
                                // One dirty window per batch: amortizes the
                                // per-block fsyncs (the 11-13 blk/s catch-up
                                // ceiling). Non-fatal if unavailable.
                                let batch = {
                                    let bc = self.blockchain.read().await;
                                    bc.begin_receipt_batch()
                                        .await
                                        .map_err(|e| {
                                            warn!(
                                                "sync: apply window unavailable, using per-block durability: {}",
                                                e
                                            )
                                        })
                                        .ok()
                                };
                                for block in candidate_blocks {
                                    let before = {
                                        self.blockchain.read().await.get_latest_block_index() as u32
                                    };
                                    let result = if block.index >= verify_from {
                                        self.accept_peer_block(&block, Some(*peer_addr)).await
                                    } else {
                                        self.blockchain
                                            .write()
                                            .await
                                            .save_receipt_verified_block(&block)
                                            .await
                                            .map_err(|e| NodeError::Blockchain(e.to_string()))
                                    };

                                    match result {
                                        Ok(()) => {
                                            let after = {
                                                self.blockchain
                                                    .read()
                                                    .await
                                                    .get_latest_block_index()
                                                    as u32
                                            };
                                            if after > before {
                                                saved_count += after.saturating_sub(before);
                                                current_sync_height = after;
                                                if block.index >= verify_from {
                                                    // Frontier block verified against peer
                                                    // witnesses; trail the checkpoint behind
                                                    // it so finality advances.
                                                    let _ = self
                                                        .blockchain
                                                        .read()
                                                        .await
                                                        .advance_checkpoint_behind(block.index);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Failed to accept block {}: {}", block.index, e)
                                        }
                                    }
                                }
                                if let Some(batch) = batch {
                                    if let Err(e) = {
                                        let bc = self.blockchain.read().await;
                                        bc.commit_receipt_batch(batch).await
                                    } {
                                        warn!(
                                            "sync: apply window commit failed; dirty marker left for recovery: {}",
                                            e
                                        );
                                    }
                                }

                                info!(
                                    "Saved {}/{} blocks ({}-{}), now at {}/{}",
                                    saved_count,
                                    actual_count,
                                    start,
                                    end,
                                    current_sync_height,
                                    peer_height
                                );

                                blocks_synced += saved_count;
                                if saved_count == 0 {
                                    break;
                                }
                            } else {
                                warn!("No valid blocks received for range {}-{}", start, end);
                                break; // Try next peer
                            }

                            // Move to next batch based on what we actually processed
                            start = current_sync_height.saturating_add(1);
                        }
                        Err(e) => {
                            warn!(
                                "Failed to get blocks {}-{} from peer {}: {}",
                                start, end, peer_addr, e
                            );

                            // Add short delay before retry
                            tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                            break; // Try next peer
                        }
                    }

                    // Check if we're done
                    if current_sync_height >= *peer_height {
                        info!("Sync complete to height {}", current_sync_height);
                        break 'outer;
                    }
                }
            }

            // If we've tried all peers without success, delay before next attempt
            if sync_attempt < MAX_RETRIES - 1 {
                tokio::time::sleep(Duration::from_millis(
                    RETRY_DELAY_MS * (sync_attempt as u64 + 1),
                ))
                .await;
            }
        }

        // 6. IMPROVEMENT: Report success even with partial progress
        if blocks_synced > 0 {
            info!(
                "Blockchain synchronized: added {} blocks to height {}",
                blocks_synced, current_sync_height
            );
            self.publish_discovery_state("Post-sync").await;
            Ok(())
        } else {
            // Zero blocks from peers. Fall back to the relay for a best-effort backfill, but only
            // treat a relay error as a REAL sync failure when a peer is genuinely ahead of us. If no
            // known peer is ahead, zero-from-peers means we are caught up to the peer frontier, so a
            // transient relay-backfill hiccup is not a failure: log it quietly and report success
            // (the periodic beacon-driven converge loop still pulls us to the relay head if anything
            // is actually behind). This stops an at-tip miner from repeatedly logging "failed to
            // sync" on benign relay blips while keeping the error meaningful for a stuck node.
            match self.sync_with_block_relay(current_height).await {
                Ok(_) => Ok(()),
                Err(relay_err) if Self::any_peer_ahead(&peer_heights, current_sync_height) => {
                    Err(NodeError::Network(format!(
                        "Failed to sync any blocks from peers and relay sync failed: {}",
                        relay_err
                    )))
                }
                Err(relay_err) => {
                    debug!(
                        "Caught up at height {} (no peer ahead); ignoring transient relay-backfill error: {}",
                        current_sync_height, relay_err
                    );
                    Ok(())
                }
            }
        }
    }

    async fn perform_handshake(
        &self,
        stream: &mut TcpStream,
        is_initiator: bool,
    ) -> Result<(PeerInfo, Vec<u8>), NodeError> {
        const MAX_HANDSHAKE_SIZE: usize = 1024;

        // Generate ephemeral X25519 key material for forward-secret transport encryption.
        let rng = ring::rand::SystemRandom::new();
        let local_private = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .map_err(|_| NodeError::Network("Failed to generate handshake key".into()))?;
        let local_public = local_private
            .compute_public_key()
            .map_err(|_| NodeError::Network("Failed to derive handshake public key".into()))?;
        let local_public_bytes: [u8; 32] = local_public
            .as_ref()
            .try_into()
            .map_err(|_| NodeError::Network("Invalid handshake public key length".into()))?;

        debug!("perform_handshake(init={}): getting height", is_initiator);
        let blockchain_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_latest_block_index() as u32
        };
        debug!(
            "perform_handshake(init={}): height={}",
            is_initiator, blockchain_height
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create our handshake message
        let mut our_handshake = HandshakeMessage {
            version: NETWORK_VERSION,
            timestamp: now,
            nonce: local_public_bytes,
            public_key: self.handshake_public_key.clone(),
            node_id: self.node_id.clone(),
            network_id: self.network_id,
            listen_port: self.bind_addr.port(),
            blockchain_height,
            signature: Vec::new(), // Will sign below
        };
        our_handshake.signature = self.sign_handshake(&our_handshake)?;

        if is_initiator {
            // Send our handshake first
            let data = codec::serialize(&our_handshake)?;
            if data.is_empty() || data.len() > MAX_HANDSHAKE_SIZE {
                return Err(NodeError::Network("Invalid handshake size".into()));
            }
            debug!("perform_handshake(init): sending {} bytes", data.len());
            stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
            stream.write_all(&data).await?;
            stream.flush().await?;
            debug!("perform_handshake(init): sent, awaiting reply");

            // Read peer's handshake
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await?;
            debug!("perform_handshake(init): got reply len");
            let len = u32::from_be_bytes(len_bytes) as usize;

            if len == 0 || len > MAX_HANDSHAKE_SIZE {
                return Err(NodeError::Network("Handshake too large".into()));
            }

            let mut data = vec![0u8; len];
            stream.read_exact(&mut data).await?;

            let peer_handshake: HandshakeMessage = codec::deserialize(&data)?;
            if peer_handshake.node_id == self.node_id {
                return Err(NodeError::Network("Refusing self connection".into()));
            }

            // Verify peer's handshake
            if peer_handshake.network_id != self.network_id {
                return Err(NodeError::Network("Network ID mismatch".into()));
            }
            self.verify_handshake(&peer_handshake)?;

            let socket_addr = stream.peer_addr()?;
            let peer_addr = Self::peer_listen_addr(socket_addr, peer_handshake.listen_port)?;

            // Create and return PeerInfo
            let peer_info = PeerInfo {
                address: peer_addr,
                version: peer_handshake.version,
                last_seen: now,
                blocks: peer_handshake.blockchain_height,
                latency: 0,
                subnet_group: SubnetGroup::from_ip(
                    peer_addr.ip(),
                    SUBNET_MASK_IPV4,
                    SUBNET_MASK_IPV6,
                ),
            };

            // Derive shared secret
            let shared_secret = self.derive_shared_secret(local_private, &peer_handshake.nonce)?;

            Ok((peer_info, shared_secret))
        } else {
            // Read peer's handshake first
            debug!("perform_handshake(resp): awaiting peer handshake");
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await?;
            let len = u32::from_be_bytes(len_bytes) as usize;

            if len == 0 || len > MAX_HANDSHAKE_SIZE {
                return Err(NodeError::Network("Handshake too large".into()));
            }

            let mut data = vec![0u8; len];
            stream.read_exact(&mut data).await?;
            debug!("perform_handshake(resp): got {} bytes, verifying", len);

            let peer_handshake: HandshakeMessage = codec::deserialize(&data)?;
            if peer_handshake.node_id == self.node_id {
                return Err(NodeError::Network("Refusing self connection".into()));
            }

            // Verify peer's handshake
            if peer_handshake.network_id != self.network_id {
                return Err(NodeError::Network("Network ID mismatch".into()));
            }
            self.verify_handshake(&peer_handshake)?;
            debug!("perform_handshake(resp): verified, sending reply");

            // Send our response
            let data = codec::serialize(&our_handshake)?;
            if data.is_empty() || data.len() > MAX_HANDSHAKE_SIZE {
                return Err(NodeError::Network("Invalid handshake size".into()));
            }
            stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
            stream.write_all(&data).await?;
            stream.flush().await?;

            let socket_addr = stream.peer_addr()?;
            let peer_addr = Self::peer_listen_addr(socket_addr, peer_handshake.listen_port)?;

            // Create and return PeerInfo
            let peer_info = PeerInfo {
                address: peer_addr,
                version: peer_handshake.version,
                last_seen: now,
                blocks: peer_handshake.blockchain_height,
                latency: 0,
                subnet_group: SubnetGroup::from_ip(
                    peer_addr.ip(),
                    SUBNET_MASK_IPV4,
                    SUBNET_MASK_IPV6,
                ),
            };

            // Derive shared secret
            let shared_secret = self.derive_shared_secret(local_private, &peer_handshake.nonce)?;

            Ok((peer_info, shared_secret))
        }
    }

    // Encryption/decryption utilities
    fn encrypt_message(
        &self,
        message: &NetworkMessage,
        shared_secret: &[u8],
    ) -> Result<Vec<u8>, NodeError> {
        // Use ChaCha20-Poly1305 for authenticated encryption
        let key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, shared_secret)
                .map_err(|_| NodeError::Network("Invalid encryption key".into()))?,
        );

        // Generate nonce
        let mut nonce_bytes = [0u8; 12];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| NodeError::Network("Failed to generate nonce".into()))?;
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);

        // Serialize message
        let message_bytes = codec::serialize(message)?;

        // Encrypt in-place
        let mut in_out = message_bytes;
        key.seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), &mut in_out)
            .map_err(|_| NodeError::Network("Encryption failed".into()))?;

        // Combine nonce and ciphertext
        let mut result = Vec::with_capacity(12 + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);

        Ok(result)
    }

    fn decrypt_message(
        &self,
        encrypted: &[u8],
        shared_secret: &[u8],
    ) -> Result<NetworkMessage, NodeError> {
        Ok(self
            .decrypt_message_with_plaintext(encrypted, shared_secret)?
            .0)
    }

    // Decrypt AND return the codec-framed plaintext alongside the decoded message, so the caller can
    // length-check and dedup-hash the plaintext instead of re-serializing the message. rmp_serde is
    // canonical and deserialize rejects trailing bytes, so the plaintext equals
    // codec::serialize(&message) byte-for-byte — the checks are unchanged.
    fn decrypt_message_with_plaintext(
        &self,
        encrypted: &[u8],
        shared_secret: &[u8],
    ) -> Result<(NetworkMessage, Vec<u8>), NodeError> {
        if encrypted.len() < 12 + 16 {
            // Nonce + min ciphertext + auth tag
            return Err(NodeError::Network("Invalid encrypted message".into()));
        }

        // Split nonce and ciphertext
        let nonce_bytes = &encrypted[..12];
        let ciphertext = &encrypted[12..];

        // Create decryption key
        let key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, shared_secret)
                .map_err(|_| NodeError::Network("Invalid decryption key".into()))?,
        );

        let nonce = ring::aead::Nonce::assume_unique_for_key(*array_ref!(nonce_bytes, 0, 12));

        // Decrypt in-place
        let mut in_out = ciphertext.to_vec();
        let decrypted = key
            .open_in_place(nonce, ring::aead::Aad::empty(), &mut in_out)
            .map_err(|_| NodeError::Network("Decryption failed".into()))?;

        // Deserialize message, then hand back the plaintext bytes too.
        let message = codec::deserialize(decrypted)?;
        Ok((message, decrypted.to_vec()))
    }

    // Method to derive shared secret for secure communication
    fn derive_shared_secret(
        &self,
        local_private: agreement::EphemeralPrivateKey,
        remote_public: &[u8; 32],
    ) -> Result<Vec<u8>, NodeError> {
        let peer_key = agreement::UnparsedPublicKey::new(&agreement::X25519, remote_public);
        let ikm =
            agreement::agree_ephemeral(local_private, &peer_key, |material| material.to_vec())
                .map_err(|_| NodeError::Network("Failed to derive shared secret".into()))?;

        // Derive 32-byte shared secret
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(&ikm);
        let mut shared_secret = [0u8; 32];
        prk.expand(&[b"blockchain_p2p"], ring::hkdf::HKDF_SHA256)
            .map_err(|_| NodeError::Network("Failed to derive shared secret".into()))?
            .fill(&mut shared_secret)
            .map_err(|_| NodeError::Network("Failed to fill shared secret".into()))?;

        Ok(shared_secret.to_vec())
    }
}

// RAII guard for the node-identity lock file (temp_dir/node_locks/<pubkey>.lock). Held inside an
// Arc shared by every Node clone, so the file is removed EXACTLY ONCE — when the last clone drops
// (process teardown). The previous `impl Drop for Node` unlinked the shared path on EVERY clone
// drop, so the first transient clone to drop (e.g. a per-connection handler task, ~node.rs:6571)
// deleted the lock while the node kept running — silently defeating single-instance exclusion and
// letting a second process reuse the same node_identity.key.
#[derive(Debug)]
struct IdentityLock {
    path: String,
}

impl Drop for IdentityLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// Implementation to support other modules that reference these functions
impl From<&Node> for Node {
    fn from(node: &Node) -> Self {
        node.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A self-consistent block at `index` whose parent is `previous_hash`. PoW is not mined —
    // these exercise the COMMITMENT rule, which is what stands between us and a hostile peer;
    // proof-of-work is enforced separately by verify_pow_meets_floor at the call site.
    fn linked_block(index: u32, previous_hash: [u8; 32], nonce: u64) -> Block {
        let mut b = Block {
            index,
            previous_hash,
            timestamp: 1_700_000_000 + index as u64,
            transactions: Vec::new(),
            nonce,
            difficulty: 464,
            hash: [0u8; 32],
            merkle_root: [0u8; 32],
        };
        b.hash = b.calculate_hash_for_block();
        b
    }

    // Builds `len` blocks ascending from `root`, each chaining to the previous.
    fn linked_chain(root: [u8; 32], start_index: u32, len: u32) -> Vec<Block> {
        let mut out = Vec::new();
        let mut parent = root;
        for i in 0..len {
            let b = linked_block(start_index + i, parent, i as u64);
            parent = b.hash;
            out.push(b);
        }
        out
    }

    // A transaction whose signature is `sig`, with a FIXED sig_hash so the merkle leaf is
    // pinned to that value rather than derived from the signature bytes.
    fn tx_with_signature(sig: &str) -> Transaction {
        Transaction {
            sender: "aa11bb22cc33dd44ee55ff6677889900aabbccdd".to_string(),
            recipient: "1122334455667788990011223344556677889900".to_string(),
            fee_units: 10_000,
            amount_units: 100_000_000,
            timestamp: 1_700_000_000,
            signature: Some(sig.to_string()),
            pub_key: Some("cc".repeat(32)),
            sig_hash: Some("dd".repeat(32)),
        }
    }

    fn block_carrying(tx: Transaction) -> Block {
        let mut b = linked_block(9, [7u8; 32], 1);
        b.transactions = vec![tx];
        b.merkle_root = Blockchain::calculate_merkle_root(&b.transactions).expect("merkle");
        b.hash = b.calculate_hash_for_block();
        b
    }

    // Two bodies that the merkle root does not distinguish must not share a cache entry. The
    // root is not a function of all the per-transaction signature material, so the block hash
    // cannot stand in for the bytes a verdict was formed over.
    #[test]
    fn bodies_sharing_a_block_hash_do_not_share_a_cache_entry() {
        let honest_sig = format!("{}{}", "ab".repeat(64), "cd".repeat(40));
        let variant_a = honest_sig.to_uppercase();
        let variant_b = format!("{}{}", "ab".repeat(64), "ef".repeat(40));

        let honest = block_carrying(tx_with_signature(&honest_sig));
        for (label, variant_sig) in [("a", variant_a), ("b", variant_b)] {
            let variant = block_carrying(tx_with_signature(&variant_sig));

            // Premise: the committed root does not separate these two bodies.
            assert_eq!(
                honest.merkle_root, variant.merkle_root,
                "{label}: premise — the root does not distinguish these bodies"
            );
            assert_eq!(honest.hash, variant.hash, "{label}: premise — one block hash");

            // Requirement: the cache does separate them.
            assert_ne!(
                Node::validation_cache_key(&honest),
                Node::validation_cache_key(&variant),
                "{label}: one verdict must not answer for the other body"
            );
        }
    }

    // Replays the sequence verify_block_with_witness performs against the real cache type: one
    // body's verdict is filed, then the other consults the cache. The identifier-only key is
    // computed alongside and asserted to FAIL the same sequence — without that half this test
    // would pass against the defect it exists to hold closed.
    //
    // A Node cannot be constructed in tests, so this drives the cache mechanism, not the whole
    // ingress path. That the function reaches this cache with these arguments rests on the two
    // call sites being the only ones, and on the key being used for nothing else there.
    #[test]
    fn a_filed_verdict_does_not_answer_for_a_different_body() {
        let honest_sig = format!("{}{}", "ab".repeat(64), "cd".repeat(40));
        let other_sig = format!("{}{}", "ab".repeat(64), "ef".repeat(40));
        let honest = block_carrying(tx_with_signature(&honest_sig));
        let other = block_carrying(tx_with_signature(&other_sig));

        let filed = |k: String| {
            let cache: DashMap<String, ValidationCacheEntry> = DashMap::new();
            // One body fails validation; its verdict is filed.
            cache.insert(
                k,
                ValidationCacheEntry {
                    valid: false,
                    timestamp: SystemTime::now(),
                },
            );
            cache
        };

        // Identifier-only key: the second body is answered from the first's verdict.
        let bare = |b: &Block| hex::encode(b.hash);
        assert_eq!(bare(&honest), bare(&other), "premise: one block hash");
        let cache = filed(bare(&other));
        assert!(
            matches!(cache.get(&bare(&honest)), Some(e) if !e.valid),
            "the identifier-only key MUST reproduce this, or the test proves nothing"
        );

        // Body-aware key: it is not.
        let cache = filed(Node::validation_cache_key(&other));
        assert!(
            cache.get(&Node::validation_cache_key(&honest)).is_none(),
            "must miss and be validated on its own merits"
        );
    }

    // The transaction half. create_hash() is an envelope identifier and authenticates nothing,
    // so messages differing only in signature material collide under it — in both directions,
    // since a warm entry short-circuits straight to a re-broadcast.
    #[test]
    fn messages_sharing_an_envelope_do_not_share_a_cache_entry() {
        let genuine = tx_with_signature(&"ab".repeat(80));
        let mut other = genuine.clone();
        other.signature = Some("ff".repeat(80));

        assert_eq!(
            genuine.create_hash(),
            other.create_hash(),
            "premise: create_hash covers the envelope only, so these collide"
        );
        assert_ne!(
            Node::transaction_cache_key(&genuine),
            Node::transaction_cache_key(&other),
            "one verdict must not answer for the other message"
        );

        // A different claimed pub_key over the same signature must also miss.
        let mut swapped_key = genuine.clone();
        swapped_key.pub_key = Some("ee".repeat(32));
        assert_ne!(
            Node::transaction_cache_key(&genuine),
            Node::transaction_cache_key(&swapped_key),
            "the key must bind pub_key, not just the signature"
        );

        // And the same message still resolves to one entry.
        assert_eq!(
            Node::transaction_cache_key(&genuine),
            Node::transaction_cache_key(&genuine.clone()),
            "identical messages must still short-circuit"
        );
    }

    // The header carries merkle_root as a CLAIMED field, so an honest header can sit over
    // transactions that do not reproduce it. Such a body loses validation — which is exactly why
    // its verdict must not be filed against the block that legitimately owns the header. Folding
    // in only the authenticating fields is NOT enough to separate them; the envelope has to be in
    // the key too.
    #[test]
    fn a_body_that_does_not_reproduce_its_claimed_root_keys_apart_from_the_honest_one() {
        let sig = "ab".repeat(80);
        let honest = block_carrying(tx_with_signature(&sig));

        // Same header, same signature material, different envelope.
        let mut restated = tx_with_signature(&sig);
        restated.amount_units = 999_999_999;
        restated.recipient = "9999999999999999999999999999999999999999".to_string();
        let mut divergent = honest.clone();
        divergent.transactions = vec![restated];
        // Header untouched: the claimed root and therefore the hash still stand.
        assert_eq!(
            divergent.calculate_hash_for_block(),
            divergent.hash,
            "premise: the header still self-certifies, so the cheap gates pass it through"
        );
        assert_eq!(honest.hash, divergent.hash, "premise: one header, one hash");

        assert_ne!(
            Node::validation_cache_key(&honest),
            Node::validation_cache_key(&divergent),
            "the envelope must be in the key, or a losing body files against the honest one"
        );
    }

    // Block and transaction verdicts share one map, and without the tags their key
    // shapes are format-identical: 64 hex chars, a colon, 32 hex chars. The tag makes
    // the two key spaces structurally disjoint instead of collision-resistant, and
    // this pins the tags so a reformat cannot silently merge them again.
    #[test]
    fn block_and_transaction_verdicts_key_into_disjoint_spaces() {
        let sig = "ab".repeat(80);
        let block_key = Node::validation_cache_key(&block_carrying(tx_with_signature(&sig)));
        let tx_key = Node::transaction_cache_key(&tx_with_signature(&sig));
        assert!(block_key.starts_with("b:"), "block verdicts carry the b: tag");
        assert!(tx_key.starts_with("t:"), "transaction verdicts carry the t: tag");
    }

    // Replay protection is the reason the cache exists; keying on the body must not cost it.
    #[test]
    fn an_identical_body_still_resolves_to_one_cache_entry() {
        let sig = "ab".repeat(80);
        let a = block_carrying(tx_with_signature(&sig));
        let b = block_carrying(tx_with_signature(&sig));
        assert_eq!(
            Node::validation_cache_key(&a),
            Node::validation_cache_key(&b),
            "the same bytes must still short-circuit on replay"
        );
    }

    // Walk the chain downward exactly as fetch_beacon_committed_span does, and report the
    // parent hash the span bottoms out on (the value that must equal our own tip hash).
    fn walk_down(chain: &[Block], beacon_hash: [u8; 32]) -> Option<[u8; 32]> {
        let mut expected = beacon_hash;
        for block in chain.iter().rev() {
            if !Node::committed_link_ok(block, expected) {
                return None;
            }
            expected = block.previous_hash;
        }
        Some(expected)
    }

    // The span is only safe because it is self-proving: starting from the gateway-signed
    // beacon hash, every block down to our own tip is pinned by the block above it.
    #[test]
    fn committed_span_walks_from_the_beacon_down_to_our_own_tip() {
        let our_tip_hash = [7u8; 32];
        let chain = linked_chain(our_tip_hash, 101, 40);
        let beacon_hash = chain.last().unwrap().hash;

        assert_eq!(
            walk_down(&chain, beacon_hash),
            Some(our_tip_hash),
            "an honest span must bottom out on the tip we already hold"
        );
    }

    // A peer that swaps in a different block anywhere in the span breaks the chain of
    // demanded hashes. This is the property that lets us skip witness verification safely.
    #[test]
    fn committed_span_rejects_substitution_reorder_and_omission() {
        let our_tip_hash = [7u8; 32];
        let chain = linked_chain(our_tip_hash, 101, 40);
        let beacon_hash = chain.last().unwrap().hash;

        // SUBSTITUTION: a foreign block spliced into the middle.
        let mut swapped = chain.clone();
        swapped[20] = linked_block(121, [9u8; 32], 999);
        assert!(
            walk_down(&swapped, beacon_hash).is_none(),
            "a substituted block must break the commitment"
        );

        // TAMPERING: right hash claimed, contents changed — header no longer hashes to it.
        let mut tampered = chain.clone();
        tampered[20].timestamp += 1;
        assert!(
            walk_down(&tampered, beacon_hash).is_none(),
            "a body that does not hash to its claimed hash must be rejected"
        );

        // REORDER: two adjacent blocks transposed.
        let mut reordered = chain.clone();
        reordered.swap(20, 21);
        assert!(
            walk_down(&reordered, beacon_hash).is_none(),
            "reordering must break the commitment"
        );

        // OMISSION: a block dropped from the middle.
        let mut omitted = chain.clone();
        omitted.remove(20);
        assert!(
            walk_down(&omitted, beacon_hash).is_none(),
            "omitting a block must break the commitment"
        );

        // FOREIGN CHAIN: internally valid, ends at the beacon, but does not attach to us.
        let foreign = linked_chain([42u8; 32], 101, 40);
        let foreign_beacon = foreign.last().unwrap().hash;
        assert_eq!(
            walk_down(&foreign, foreign_beacon),
            Some([42u8; 32]),
            "a foreign chain walks cleanly but bottoms out somewhere we do not hold"
        );
        assert_ne!(
            walk_down(&foreign, foreign_beacon),
            Some(our_tip_hash),
            "which is exactly what the bottom-anchor check catches"
        );
    }

    // A span claiming to end at the beacon must actually END there.
    #[test]
    fn committed_span_requires_the_top_to_be_the_beacon_hash() {
        let our_tip_hash = [7u8; 32];
        let chain = linked_chain(our_tip_hash, 101, 40);
        assert!(
            walk_down(&chain, [0xABu8; 32]).is_none(),
            "a top block that is not the signed beacon hash must be rejected"
        );
    }

    // A block-serving range that ends at the height ceiling must terminate. The
    // serve loop advances with `idx = chunk_end + 1`; a saturating advance makes
    // no progress there while `idx <= end` stays true. The span cap alone does
    // not bound this, so the advance is checked — see the serve loop.
    #[test]
    fn block_serve_range_terminates_at_the_height_ceiling() {
        let start = u32::MAX - (MAX_GETBLOCKS_SPAN - 1);
        let end = u32::MAX;
        assert!(
            end.saturating_sub(start) < MAX_GETBLOCKS_SPAN,
            "this range must pass the span cap, or the test proves nothing"
        );

        // Mirror of the serve loop's advance, with the fix in place.
        const CHAIN_SERVE_CHUNK: u32 = 32; // mirrors the constant in the serve loop
        let mut idx = start;
        let mut iterations = 0u32;
        while idx <= end {
            let chunk_end = idx.saturating_add(CHAIN_SERVE_CHUNK - 1).min(end);
            let Some(next) = chunk_end.checked_add(1) else {
                break;
            };
            idx = next;
            iterations += 1;
            assert!(iterations < 10_000, "serve loop failed to terminate");
        }
        assert!(iterations > 0, "the loop should have run at least once");
    }

    // Connected-peer candidate selection for the boot/idle/mine-prep delta-sync. The recorded
    // height RANKS candidates (covering peers first, then tallest first) but never filters them:
    // after an OS sleep every recorded height is hours stale — uniformly below the live beacon —
    // and a height pre-filter starved the sync of every live candidate (Windows wake-after-idle,
    // 2026-07-27). The real per-peer verification is a fresh height read + the signed-beacon tip
    // probe inside sync_full_history_from_peer.
    #[test]
    fn full_sync_candidate_peers_ranks_tallest_first_never_filters() {
        use std::collections::HashMap;
        let mk = |octet: u8, blocks: u32| -> (SocketAddr, PeerInfo) {
            let addr: SocketAddr = format!("10.0.0.{}:7000", octet).parse().unwrap();
            let mut info = PeerInfo::new(addr);
            info.blocks = blocks;
            (addr, info)
        };
        let beacon = 1000u32;
        let entries = [mk(1, 1005), mk(2, 1000), mk(3, 999), mk(4, 2000)];
        let peers: HashMap<SocketAddr, PeerInfo> = entries.iter().cloned().collect();

        let ranked = Node::full_sync_candidate_peers(&peers, beacon);
        let heights: Vec<u32> = ranked
            .iter()
            .map(|a| peers.get(a).unwrap().blocks)
            .collect();
        // Covering peers first (tallest first), then the below-beacon peer — INCLUDED, last.
        assert_eq!(
            heights,
            vec![2000, 1005, 1000, 999],
            "rank covering-tallest first and keep stale/below peers as fallbacks"
        );

        // The wake-after-sleep shape: every recorded height is below the live beacon. All
        // peers must still be offered (tallest first) — this returned [] before the fix.
        let stale_ranked = Node::full_sync_candidate_peers(&peers, 3000);
        let stale_heights: Vec<u32> = stale_ranked
            .iter()
            .map(|a| peers.get(a).unwrap().blocks)
            .collect();
        assert_eq!(
            stale_heights,
            vec![2000, 1005, 1000, 999],
            "uniformly-stale heights must never starve the candidate set"
        );

        // Probe-cost bound: candidates are capped at FULL_SYNC_MAX_CANDIDATES, keeping the
        // tallest (a covering peer must survive the cut ahead of stale ones).
        let mut many: HashMap<SocketAddr, PeerInfo> =
            (1..=20u8).map(|o| mk(o, 100 + o as u32)).collect();
        let (tall_addr, tall_info) = mk(200, 5000);
        many.insert(tall_addr, tall_info);
        let capped = Node::full_sync_candidate_peers(&many, 1000);
        assert_eq!(capped.len(), FULL_SYNC_MAX_CANDIDATES, "cap bounds probes");
        assert_eq!(
            capped[0], tall_addr,
            "the covering peer outranks every stale one"
        );
    }

    // The slice deadline is a pure between-steps check: None never expires; a past instant
    // has, a future one has not.
    #[test]
    fn full_sync_deadline_expiry_semantics() {
        assert!(!Node::full_sync_deadline_expired(None));
        let now = Instant::now();
        assert!(Node::full_sync_deadline_expired(Some(
            now - Duration::from_millis(1)
        )));
        assert!(!Node::full_sync_deadline_expired(Some(
            now + Duration::from_secs(3600)
        )));
    }

    // #11: the witness cache enforces a BYTE budget, not just an entry count. Insert many large
    // witnesses under a tight byte budget (high count cap) and confirm the resident bytes stay within
    // budget, the newest entry survives (LRU), the oldest is evicted, and the counter tracks pop.
    #[test]
    fn witness_cache_evicts_to_byte_budget() {
        // Tight byte budget, generous count cap -> the byte bound binds first.
        let mut wc = WitnessCache::new(NonZeroUsize::new(1000).unwrap(), 50_000);
        for i in 0..100u32 {
            let mut tx = Transaction::new(
                format!("s{}", i),
                "r".to_string(),
                1.0,
                0.0,
                i as u64,
                Some("ab".repeat(5000)), // ~10 KB "signature"
            );
            tx.pub_key = Some("cd".repeat(2500)); // ~5 KB pub_key
            wc.put(format!("tx{}", i), tx);
        }
        // Each entry ~15 KB; budget 50 KB -> only a few entries retained.
        assert!(
            wc.bytes <= 50_000,
            "resident bytes must stay within the byte budget: {}",
            wc.bytes
        );
        assert!(
            (1..=4).contains(&wc.cache.len()),
            "a tight byte budget retains only a few large entries: {}",
            wc.cache.len()
        );
        assert!(wc.get("tx99").is_some(), "the newest witness is retained");
        assert!(wc.get("tx0").is_none(), "the oldest witness was evicted");

        // pop keeps the byte counter in sync.
        let before = wc.bytes;
        assert!(wc.pop("tx99").is_some());
        assert!(
            wc.bytes < before,
            "pop decrements the resident byte counter"
        );
    }

    // #11: with a generous byte budget the COUNT cap binds — and because the inner LruCache is
    // unbounded, every eviction goes through the wrapper, so the byte counter never leaks (which it
    // would if the inner cache did its own count-cap eviction without decrementing bytes).
    #[test]
    fn witness_cache_count_cap_enforced_without_byte_leak() {
        let mut wc = WitnessCache::new(NonZeroUsize::new(5).unwrap(), 100 * 1024 * 1024);
        let mk = |i: u32| {
            Transaction::new(
                format!("s{}", i),
                "r".to_string(),
                1.0,
                0.0,
                i as u64,
                Some("aa".to_string()),
            )
        };
        for i in 0..50u32 {
            wc.put(format!("tx{}", i), mk(i));
        }
        assert_eq!(wc.cache.len(), 5, "the wrapper enforces the count cap");
        let expected: usize = (45..50u32).map(|i| WitnessCache::entry_bytes(&mk(i))).sum();
        assert_eq!(
            wc.bytes, expected,
            "byte counter equals the surviving entries — no leak from count-cap eviction"
        );
    }

    // #3 witness-sidecar bind: a resolved witness's sig_hash is bound to its OWN signature locally,
    // on every path — not only when sig_hash was absent. A pre-populated sig_hash that disagrees
    // with SHA256(signature) is defer-rejected here (self-contained on this frontier path) instead
    // of being trusted and left for verify_transaction_signature (Phase 2) to catch.
    #[test]
    fn bind_witness_sig_hash_matches_signature() {
        let sig_hex = "abcd1234".to_string();
        let derived = Transaction::signature_hash_hex(&hex::decode(&sig_hex).unwrap());

        // (1) Absent sig_hash: derived from the signature and set.
        let mut tx = Transaction::new("s".into(), "r".into(), 1.0, 0.0, 1, Some(sig_hex.clone()));
        tx.sig_hash = None;
        assert!(Node::bind_witness_sig_hash_to_signature(&mut tx));
        assert_eq!(tx.sig_hash.as_deref(), Some(derived.as_str()));

        // (2) Pre-populated and matching: accepted, unchanged.
        let mut tx = Transaction::new("s".into(), "r".into(), 1.0, 0.0, 1, Some(sig_hex.clone()));
        tx.sig_hash = Some(derived.clone());
        assert!(Node::bind_witness_sig_hash_to_signature(&mut tx));
        assert_eq!(tx.sig_hash.as_deref(), Some(derived.as_str()));

        // (3) Pre-populated and MISMATCHING: defer-rejected by the new local guard. Without it this
        // forged-sig_hash witness would be trusted here and only caught (post-P0) in Phase 2.
        let mut tx = Transaction::new("s".into(), "r".into(), 1.0, 0.0, 1, Some(sig_hex.clone()));
        tx.sig_hash = Some("deadbeef".repeat(8));
        assert!(!Node::bind_witness_sig_hash_to_signature(&mut tx));

        // (4) Invalid signature hex: defer-rejected.
        let mut tx = Transaction::new("s".into(), "r".into(), 1.0, 0.0, 1, Some("zzzz".into()));
        assert!(!Node::bind_witness_sig_hash_to_signature(&mut tx));

        // (5) No signature: left untouched (a witness with no signature is rejected downstream).
        let mut tx = Transaction::new("s".into(), "r".into(), 1.0, 0.0, 1, None);
        tx.sig_hash = None;
        assert!(Node::bind_witness_sig_hash_to_signature(&mut tx));
        assert_eq!(tx.sig_hash, None);
    }

    #[test]
    fn witness_cache_match_binds_fields_omitted_from_display_tx_id() {
        let mut receipt = Transaction::new(
            "sender".into(),
            "recipient".into(),
            1.0,
            0.0005,
            7,
            Some("aa".repeat(64)),
        );
        receipt.pub_key = Some("11".repeat(32));
        receipt.sig_hash = Some("22".repeat(32));

        let mut exact = receipt.clone();
        exact.signature = Some("bb".repeat(4_627));
        assert!(Node::witness_matches_committed_receipt(&receipt, &exact));

        let mut resigned = exact.clone();
        resigned.sig_hash = Some("33".repeat(32));
        assert_eq!(receipt.get_tx_id(), resigned.get_tx_id());
        assert!(
            !Node::witness_matches_committed_receipt(&receipt, &resigned),
            "same display tx id is insufficient when the Merkle-committed signature hash differs"
        );

        let mut wrong_key = exact;
        wrong_key.pub_key = Some("44".repeat(32));
        assert!(!Node::witness_matches_committed_receipt(
            &receipt, &wrong_key
        ));
    }

    // Regression: a dropped Node clone must NOT unlink the shared identity lock file while other
    // clones (and the running node) are alive — only the LAST owner may. Before IdentityLock,
    // `impl Drop for Node` removed the file on every clone drop, so the first transient clone to
    // drop deleted the lock mid-run and a second process could reuse the same node_identity.key.
    #[test]
    fn identity_lock_removed_only_when_last_owner_drops() {
        let dir = std::env::temp_dir().join(format!("idlock_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.lock").to_string_lossy().into_owned();
        std::fs::write(&path, "0").unwrap();

        let lock = std::sync::Arc::new(IdentityLock { path: path.clone() });
        let clone1 = std::sync::Arc::clone(&lock);
        let clone2 = std::sync::Arc::clone(&lock);
        drop(clone1);
        drop(clone2);
        assert!(
            std::path::Path::new(&path).exists(),
            "identity lock was removed while an owner still lives"
        );

        drop(lock);
        assert!(
            !std::path::Path::new(&path).exists(),
            "identity lock not removed after the final owner dropped"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The dedup bloom seeds its hash per process, so the ~1% false-positive pattern is not
    // identical on every node: the same item must hash to different positions in two instances.
    #[test]
    fn bloom_seed_decorrelates_across_instances() {
        let a = NetworkBloom::new(4096, 0.01);
        let b = NetworkBloom::new(4096, 0.01);
        let item = b"block-hash-fingerprint";
        let a_pos: Vec<u64> = (0..a.num_hashes).map(|i| a.hash(item, i)).collect();
        let b_pos: Vec<u64> = (0..b.num_hashes).map(|i| b.hash(item, i)).collect();
        assert_ne!(
            a_pos, b_pos,
            "two bloom instances must hash the same item differently"
        );
    }

    // Cloning a bloom must carry its seed, or the copied bits stop matching the items that set
    // them: a member of the original must still read as present in the clone.
    #[test]
    fn bloom_clone_preserves_membership() {
        let a = NetworkBloom::new(4096, 0.01);
        let item = b"a-seen-message";
        a.insert(item);
        let b = a.clone();
        assert!(b.check(item), "clone must still recognize an inserted item");
    }

    // M3: IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) must be folded to IPv4 before the address
    // filters run, or an attacker-supplied ::ffff:<internal-ipv4> slips past the IPv6 arm as a
    // public, dialable peer (SSRF / internal-host dialing). A mapped PUBLIC address stays dialable.
    #[test]
    fn ipv4_mapped_ipv6_is_canonicalized_before_filtering() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let mapped =
            |a: u8, b: u8, c: u8, d: u8| IpAddr::V6(Ipv4Addr::new(a, b, c, d).to_ipv6_mapped());
        let metadata = mapped(169, 254, 169, 254); // link-local cloud metadata endpoint
        let private = mapped(10, 0, 0, 1);
        let loopback = mapped(127, 0, 0, 1);
        let public = mapped(8, 8, 8, 8);

        // Folded internal mapped addresses classify as private; a mapped public one does not.
        assert!(Node::is_private_ip(&metadata));
        assert!(Node::is_private_ip(&private));
        assert!(Node::is_private_ip(&loopback));
        assert!(!Node::is_private_ip(&public));

        // And they are NOT dialable in public discovery mode, while the mapped public one is.
        let dial = |ip| Node::is_dialable_discovery_addr(&SocketAddr::new(ip, 8333), false);
        assert!(!dial(metadata));
        assert!(!dial(private));
        assert!(!dial(loopback));
        assert!(dial(public));
    }

    // sync_with_network must not cry wolf: with zero blocks synced from peers, a relay-fallback
    // error is a real "failed to sync" ONLY when a peer is genuinely ahead. No peer ahead == caught
    // up to the peer frontier == a transient relay blip is benign (report success, retry later).
    #[test]
    fn any_peer_ahead_flags_only_a_genuinely_higher_peer() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let peer = |p: u16, h: u32| {
            (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), p),
                h,
            )
        };
        // No peers, or every peer at/below us -> caught up, not behind.
        assert!(!Node::any_peer_ahead(&[], 100));
        assert!(!Node::any_peer_ahead(
            &[peer(1, 100), peer(2, 99), peer(3, 1)],
            100
        ));
        // A peer strictly ahead -> genuinely behind.
        assert!(Node::any_peer_ahead(&[peer(1, 100), peer(2, 101)], 100));
    }

    // Guards the relay-once primitive: claim_relay's body is exactly
    // `early_relay_seen.lock().put(h, ()).is_none()`. put must return None only on the first
    // insert of a hash (the claimer) and Some(()) after — if an lru change altered that, the early
    // relay would fire twice (double-flood) or never (silent no-relay). Distinct hashes are
    // independent.
    #[test]
    fn early_relay_claim_is_single_winner() {
        let seen: Arc<PLMutex<LruCache<[u8; 32], ()>>> = Arc::new(PLMutex::new(LruCache::new(
            NonZeroUsize::new(8192).unwrap(),
        )));
        let claim = |h: [u8; 32]| seen.lock().put(h, ()).is_none();
        let h = [7u8; 32];
        assert!(claim(h), "first claim wins");
        assert!(!claim(h), "second claim loses");
        assert!(!claim(h), "still loses");
        assert!(claim([8u8; 32]), "a different hash claims independently");
    }

    // Under real thread contention on the same hash, exactly one caller may win the claim (the
    // PLMutex serializes the put), so the early relay is fired by exactly one of N racing ingests.
    #[test]
    fn early_relay_claim_has_exactly_one_concurrent_winner() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let seen: Arc<PLMutex<LruCache<[u8; 32], ()>>> = Arc::new(PLMutex::new(LruCache::new(
            NonZeroUsize::new(8192).unwrap(),
        )));
        let wins = Arc::new(AtomicUsize::new(0));
        let h = [42u8; 32];
        let mut handles = Vec::new();
        for _ in 0..32 {
            let seen = Arc::clone(&seen);
            let wins = Arc::clone(&wins);
            handles.push(std::thread::spawn(move || {
                if seen.lock().put(h, ()).is_none() {
                    wins.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for hd in handles {
            hd.join().unwrap();
        }
        assert_eq!(
            wins.load(Ordering::Relaxed),
            1,
            "exactly one thread may claim the hash"
        );
    }

    // The early-relay cheap gate must accept a well-formed tip-extender and reject anything that is
    // not one: wrong height, wrong parent, a lied-about hash, or a merkle root that does not match
    // the transactions. It is only a pre-filter (the standalone verify is the real gate), but a bug
    // here would silently over- or under-relay, so pin the exact predicate.
    #[test]
    fn early_relay_cheap_gate_accepts_only_well_formed_tip_extenders() {
        let tip_index: u64 = 100;
        let tip_hash = [9u8; 32];
        let make = || {
            let mut b = Block {
                index: (tip_index + 1) as u32,
                previous_hash: tip_hash,
                timestamp: 0,
                transactions: Vec::new(),
                nonce: 0,
                difficulty: 1,
                hash: [0u8; 32],
                merkle_root: [0u8; 32],
            };
            b.merkle_root = Blockchain::calculate_merkle_root(&b.transactions).unwrap();
            b.hash = b.calculate_hash_for_block();
            b
        };

        // Well-formed tip-extender: accepted.
        assert!(Node::early_relay_cheap_gate(&make(), tip_index, &tip_hash));

        // Wrong height (not tip+1): rejected (recompute hash so only the height check fails).
        let mut wrong_height = make();
        wrong_height.index = (tip_index + 2) as u32;
        wrong_height.hash = wrong_height.calculate_hash_for_block();
        assert!(!Node::early_relay_cheap_gate(
            &wrong_height,
            tip_index,
            &tip_hash
        ));

        // Wrong parent: rejected.
        let mut wrong_parent = make();
        wrong_parent.previous_hash = [1u8; 32];
        wrong_parent.hash = wrong_parent.calculate_hash_for_block();
        assert!(!Node::early_relay_cheap_gate(
            &wrong_parent,
            tip_index,
            &tip_hash
        ));

        // Lied-about hash (claimed != computed): rejected.
        let mut hash_liar = make();
        hash_liar.hash = [7u8; 32];
        assert!(!Node::early_relay_cheap_gate(
            &hash_liar, tip_index, &tip_hash
        ));

        // Merkle root not matching the tx set: rejected (recompute hash so only merkle fails).
        let mut merkle_liar = make();
        merkle_liar.merkle_root = [3u8; 32];
        merkle_liar.hash = merkle_liar.calculate_hash_for_block();
        assert!(!Node::early_relay_cheap_gate(
            &merkle_liar,
            tip_index,
            &tip_hash
        ));
    }

    fn compact_test_block() -> Block {
        let coinbase = Transaction {
            sender: "MINING_REWARDS".to_string(),
            recipient: "11".repeat(20),
            amount_units: Transaction::to_units(10.0),
            fee_units: 0,
            timestamp: 1,
            signature: None,
            pub_key: None,
            sig_hash: None,
        };
        let signature_bytes = vec![0xabu8; 4_627];
        let payment = Transaction {
            sender: "22".repeat(20),
            recipient: "33".repeat(20),
            amount_units: Transaction::to_units(2.0),
            fee_units: Transaction::to_units(0.0005),
            timestamp: 2,
            signature: Some(hex::encode(&signature_bytes)),
            pub_key: Some(hex::encode(vec![0xcdu8; 2_592])),
            sig_hash: Some(Transaction::signature_hash_hex(&signature_bytes)),
        };
        let transactions = vec![coinbase, payment];
        let merkle_root = Blockchain::calculate_merkle_root(&transactions).unwrap();
        let mut block = Block {
            index: 0,
            previous_hash: [0u8; 32],
            timestamp: 2,
            transactions,
            nonce: 7,
            difficulty: 0,
            hash: [0u8; 32],
            merkle_root,
        };
        block.hash = block.calculate_hash_for_block();
        block
    }

    #[test]
    fn compact_block_round_trip_binds_exact_normalized_merkle_leaves() {
        let block = compact_test_block();
        let compact = CompactBlockV1::from_block(&block).expect("compact construction");
        assert!(compact.validate_commitment());
        assert_eq!(compact.transaction_hashes.len(), block.transactions.len());
        for (leaf, tx) in compact.transaction_hashes.iter().zip(&block.transactions) {
            assert_eq!(
                *leaf,
                Blockchain::calculate_merkle_leaf_hash(tx).unwrap(),
                "announcement must carry the exact consensus leaf, in order"
            );
        }

        let reconstructed = compact
            .reconstruct(block.transactions.clone())
            .expect("exact bodies reconstruct");
        assert_eq!(reconstructed.hash, block.hash);
        assert_eq!(reconstructed.merkle_root, block.merkle_root);
        assert_eq!(reconstructed.transactions, block.transactions);

        // get_tx_id() does not bind pub_key, but the compact identifier must.
        let mut wrong_bodies = block.transactions.clone();
        wrong_bodies[1].pub_key = Some("ef".repeat(2_592));
        assert_eq!(
            wrong_bodies[1].get_tx_id(),
            block.transactions[1].get_tx_id(),
            "test precondition: display transaction id collides"
        );
        assert!(
            compact.reconstruct(wrong_bodies).is_err(),
            "an exact Merkle-leaf mismatch must never reconstruct"
        );
    }

    #[test]
    fn compact_commitment_gate_rejects_mutation_and_oversized_lists() {
        let compact = CompactBlockV1::from_block(&compact_test_block()).unwrap();

        let mut wrong_coinbase = compact.clone();
        wrong_coinbase.coinbase.recipient = "44".repeat(20);
        assert!(!wrong_coinbase.validate_commitment());

        let mut wrong_ordered_leaf = compact.clone();
        wrong_ordered_leaf.transaction_hashes[1][0] ^= 1;
        assert!(!wrong_ordered_leaf.validate_commitment());

        let mut too_many = compact;
        too_many.transaction_hashes = vec![[1u8; 32]; MAX_BLOCK_TX_COUNT.saturating_add(1)];
        assert!(!too_many.validate_commitment());

        let mut oversized_coinbase = compact_test_block();
        oversized_coinbase.transactions[0].recipient =
            "44".repeat(COMPACT_COINBASE_MAX_ENCODED_BYTES);
        oversized_coinbase.merkle_root =
            Blockchain::calculate_merkle_root(&oversized_coinbase.transactions).unwrap();
        oversized_coinbase.hash = oversized_coinbase.calculate_hash_for_block();
        assert!(
            CompactBlockV1::from_block(&oversized_coinbase).is_err(),
            "an oversized coinbase must fall back to full-block transport"
        );
    }

    #[test]
    fn compact_cut_through_requires_exact_parent_difficulty_rule() {
        let mut parent = compact_test_block();
        parent.index = 100;
        parent.timestamp = 1_000;
        parent.difficulty = 670;
        parent.hash = parent.calculate_hash_for_block();

        let mut compact = CompactBlockV1::from_block(&compact_test_block()).unwrap();
        compact.index = 101;
        compact.previous_hash = parent.hash;
        compact.timestamp = 1_005;
        compact.difficulty = Block::consensus_next_difficulty(
            parent.difficulty,
            compact.timestamp - parent.timestamp,
            compact.index,
        );
        compact.hash = compact.header_block().calculate_hash_for_block();
        assert!(Node::compact_header_extends_parent(&compact, &parent));

        let mut wrong_difficulty = compact.clone();
        wrong_difficulty.difficulty = wrong_difficulty.difficulty.saturating_sub(1);
        assert!(!Node::compact_header_extends_parent(
            &wrong_difficulty,
            &parent
        ));

        let mut time_regression = compact;
        time_regression.timestamp = parent.timestamp.saturating_sub(1);
        assert!(!Node::compact_header_extends_parent(
            &time_regression,
            &parent
        ));
    }

    #[test]
    fn off_tip_compacts_cannot_starve_reconstruction_slots() {
        let mut parent = compact_test_block();
        parent.index = 100;
        parent.timestamp = 1_000;
        parent.difficulty = 670;
        parent.hash = parent.calculate_hash_for_block();

        let mut honest = CompactBlockV1::from_block(&compact_test_block()).unwrap();
        honest.index = parent.index + 1;
        honest.previous_hash = parent.hash;
        honest.timestamp = parent.timestamp + 5;
        honest.difficulty = Block::consensus_next_difficulty(
            parent.difficulty,
            honest.timestamp - parent.timestamp,
            honest.index,
        );
        honest.hash = honest.header_block().calculate_hash_for_block();

        let inflight = DashMap::new();
        let slots = Arc::new(Semaphore::new(COMPACT_RECONSTRUCTION_CONCURRENCY));
        let source = |port| SocketAddr::from(([192, 0, 2, 1], port));

        // Regression: four unrelated, otherwise well-shaped announcements used
        // to acquire all four permits before their parent/difficulty mismatch was
        // discovered in normal block validation. The mismatch must now reject
        // before either scarce resource is touched.
        for i in 0..COMPACT_RECONSTRUCTION_CONCURRENCY {
            let mut unrelated = honest.clone();
            unrelated.hash[0] ^= (i as u8).saturating_add(1);
            unrelated.previous_hash[0] ^= 1;
            assert!(Node::try_claim_compact_reconstruction_in(
                &unrelated,
                &parent,
                &inflight,
                &slots,
                source(8_000 + i as u16),
                Instant::now(),
            )
            .is_none());
        }
        assert_eq!(
            slots.available_permits(),
            COMPACT_RECONSTRUCTION_CONCURRENCY
        );
        assert!(inflight.is_empty());

        let (started, permit) = Node::try_claim_compact_reconstruction_in(
            &honest,
            &parent,
            &inflight,
            &slots,
            source(9_000),
            Instant::now(),
        )
        .expect("an exact local-tip candidate must still get a reconstruction slot");
        assert_eq!(
            slots.available_permits(),
            COMPACT_RECONSTRUCTION_CONCURRENCY - 1
        );
        assert!(inflight.contains_key(&honest.hash));
        inflight.remove_if(&honest.hash, |_, current| current.started == started);
        drop(permit);
        assert_eq!(
            slots.available_permits(),
            COMPACT_RECONSTRUCTION_CONCURRENCY
        );
    }

    #[test]
    fn compact_route_preserves_same_height_fork_delivery() {
        let mut tip = compact_test_block();
        tip.index = 100;
        tip.timestamp = 1_000;
        tip.difficulty = 670;
        tip.hash = tip.calculate_hash_for_block();

        let mut next = CompactBlockV1::from_block(&compact_test_block()).unwrap();
        next.index = tip.index + 1;
        next.previous_hash = tip.hash;
        next.timestamp = tip.timestamp + 5;
        next.difficulty = Block::consensus_next_difficulty(
            tip.difficulty,
            next.timestamp - tip.timestamp,
            next.index,
        );
        next.hash = next.header_block().calculate_hash_for_block();
        assert_eq!(
            Node::compact_ingress_route_against_tip(&next, &tip),
            CompactIngressRoute::ReconstructLocalTip
        );

        let mut same_height_competitor = next.clone();
        same_height_competitor.index = tip.index;
        same_height_competitor.previous_hash = [0xabu8; 32];
        same_height_competitor.hash = same_height_competitor
            .header_block()
            .calculate_hash_for_block();
        assert_eq!(
            Node::compact_ingress_route_against_tip(&same_height_competitor, &tip),
            CompactIngressRoute::FetchFullCompetitor,
            "a same-height competing block must enter ordinary full-body tie-break processing"
        );

        let mut alternate_next = next;
        alternate_next.previous_hash = [0xcdu8; 32];
        alternate_next.hash = alternate_next.header_block().calculate_hash_for_block();
        assert_eq!(
            Node::compact_ingress_route_against_tip(&alternate_next, &tip),
            CompactIngressRoute::FetchFullCompetitor
        );

        let mut gap = alternate_next;
        gap.index = tip.index + 2;
        gap.hash = gap.header_block().calculate_hash_for_block();
        assert_eq!(
            Node::compact_ingress_route_against_tip(&gap, &tip),
            CompactIngressRoute::DeferToChainSync
        );
    }

    #[test]
    fn compact_inflight_retains_bounded_alternate_sources_under_race() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Barrier;

        let inflight = Arc::new(DashMap::new());
        let barrier = Arc::new(Barrier::new(COMPACT_SOURCE_MAX));
        let winners = Arc::new(AtomicUsize::new(0));
        let hash = [0x5au8; 32];
        let mut handles = Vec::new();
        for i in 0..COMPACT_SOURCE_MAX {
            let inflight = Arc::clone(&inflight);
            let barrier = Arc::clone(&barrier);
            let winners = Arc::clone(&winners);
            handles.push(std::thread::spawn(move || {
                let source = SocketAddr::from(([198, 51, 100, 1], 8_000 + i as u16));
                barrier.wait();
                if Node::claim_compact_inflight_in(&inflight, hash, source, Instant::now())
                    .is_some()
                {
                    winners.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(winners.load(Ordering::Relaxed), 1);
        let entry = inflight.get(&hash).expect("one in-flight route");
        assert_eq!(
            entry.sources.len(),
            COMPACT_SOURCE_MAX,
            "every simultaneous duplicate is retained as a bounded alternate"
        );
        let unique: HashSet<_> = entry.sources.iter().copied().collect();
        assert_eq!(unique.len(), COMPACT_SOURCE_MAX);
    }

    #[test]
    fn compact_receipt_body_stays_missing_until_full_alternate_completes() {
        let mut block = compact_test_block();
        let mut third = block.transactions[1].clone();
        third.timestamp += 1;
        block.transactions.push(third.clone());
        block.merkle_root = Blockchain::calculate_merkle_root(&block.transactions).unwrap();
        block.hash = block.calculate_hash_for_block();
        let compact = CompactBlockV1::from_block(&block).unwrap();

        let mut bodies = vec![None; block.transactions.len()];
        bodies[0] = Some(block.transactions[0].clone());
        let mut assembled =
            Node::compact_transaction_encoded_bytes(&block.transactions[0]).unwrap();

        let mut wrong = block.transactions[1].clone();
        wrong.pub_key = Some("ef".repeat(2_592));
        assert!(
            !Node::apply_compact_body(
                &compact,
                &mut bodies,
                &mut assembled,
                IndexedCompactTransactionV1 {
                    index: 1,
                    transaction: wrong,
                },
            )
            .unwrap(),
            "a commitment-mismatched body from the first source is ignored"
        );
        assert_eq!(Node::missing_compact_indexes(&bodies), vec![1, 2]);

        // Full and stored receipt forms intentionally commit to the same Merkle
        // leaf.  A hostile/under-hydrated source must not turn that receipt into
        // a "resolved" compact body and capture later witness resolution.
        let sig_hash = block.transactions[1].sig_hash.clone().unwrap();
        let receipt = block.transactions[1].with_truncated_signature(sig_hash);
        assert_eq!(
            Blockchain::calculate_merkle_leaf_hash(&receipt).unwrap(),
            compact.transaction_hashes[1]
        );
        assert!(!Node::compact_transaction_has_full_bound_witness(&receipt));
        assert!(
            !Node::apply_compact_body(
                &compact,
                &mut bodies,
                &mut assembled,
                IndexedCompactTransactionV1 {
                    index: 1,
                    transaction: receipt.clone(),
                },
            )
            .unwrap(),
            "a committed receipt is still missing, not a usable witness body"
        );
        assert_eq!(Node::missing_compact_indexes(&bodies), vec![1, 2]);

        let mut receipt_fallback = block.clone();
        receipt_fallback.transactions[1] = receipt;
        assert_eq!(receipt_fallback.merkle_root, block.merkle_root);
        assert_eq!(receipt_fallback.calculate_hash_for_block(), block.hash);
        assert!(
            !Node::compact_full_block_matches_announcement(&compact, &receipt_fallback),
            "receipt-only full fallback must be rejected so another source can heal it"
        );

        assert!(Node::apply_compact_body(
            &compact,
            &mut bodies,
            &mut assembled,
            IndexedCompactTransactionV1 {
                index: 1,
                transaction: block.transactions[1].clone(),
            },
        )
        .unwrap());
        assert_eq!(
            Node::missing_compact_indexes(&bodies),
            vec![2],
            "a partial response remains explicitly incomplete"
        );

        assert!(Node::apply_compact_body(
            &compact,
            &mut bodies,
            &mut assembled,
            IndexedCompactTransactionV1 {
                index: 2,
                transaction: third,
            },
        )
        .unwrap());
        let reconstructed = compact
            .reconstruct(bodies.into_iter().collect::<Option<Vec<_>>>().unwrap())
            .unwrap();
        assert_eq!(reconstructed.hash, block.hash);
    }

    #[test]
    fn compact_caches_enforce_entry_and_global_byte_budgets() {
        let base_announcement = CompactBlockV1::from_block(&compact_test_block()).unwrap();
        let entry_bytes = 3 * 1024 * 1024;
        let mut pending = CompactPendingCache {
            entries: LruCache::new(
                NonZeroUsize::new(COMPACT_PENDING_CACHE_ENTRIES).expect("nonzero pending cache"),
            ),
            bytes: 0,
        };
        for tag in 0..10u8 {
            let mut announcement = base_announcement.clone();
            announcement.hash = [tag; 32];
            assert!(pending.insert(
                announcement.hash,
                PendingCompactBlock {
                    announcement,
                    sources: vec![SocketAddr::from(([192, 0, 2, tag], 7_000))],
                    transactions: HashMap::new(),
                    transaction_sizes: HashMap::new(),
                    assembled_bytes: 0,
                    cache_bytes: entry_bytes,
                },
            ));
        }
        assert_eq!(pending.entries.len(), 8);
        assert_eq!(pending.bytes, 8 * entry_bytes);
        assert!(pending.bytes <= COMPACT_PENDING_CACHE_BYTE_BUDGET);

        let mut oversized_announcement = base_announcement.clone();
        oversized_announcement.hash = [0xfe; 32];
        assert!(!pending.insert(
            oversized_announcement.hash,
            PendingCompactBlock {
                announcement: oversized_announcement,
                sources: Vec::new(),
                transactions: HashMap::new(),
                transaction_sizes: HashMap::new(),
                assembled_bytes: 0,
                cache_bytes: COMPACT_SAFE_ASSEMBLED_BYTES + 1,
            },
        ));

        let full_entry_bytes = 3_500_000;
        let base_block = Arc::new(compact_test_block());
        let mut full = CompactFullBlockCache {
            entries: LruCache::new(
                NonZeroUsize::new(COMPACT_FULL_BLOCK_CACHE_ENTRIES).expect("nonzero full cache"),
            ),
            bytes: 0,
        };
        for tag in 0..12u8 {
            assert!(full.insert(
                [tag; 32],
                CompactFullBlockEntry {
                    block: Arc::clone(&base_block),
                    encoded_bytes: full_entry_bytes,
                },
            ));
        }
        assert_eq!(full.entries.len(), 11);
        assert_eq!(full.bytes, 11 * full_entry_bytes);
        assert!(full.bytes <= COMPACT_FULL_CACHE_BYTE_BUDGET);
        assert!(
            pending.bytes + full.bytes <= COMPACT_GLOBAL_CACHE_BYTE_BUDGET,
            "the independently enforced cache partitions cannot exceed the global cap"
        );
    }

    #[test]
    fn compact_transport_accepts_max_weight_and_rejects_next_transaction() {
        let mut block = compact_test_block();
        block.index = 1;
        let payment = block.transactions[1].clone();
        let mut sequence = 3u64;
        let overflow_transaction = loop {
            let mut next = payment.clone();
            next.timestamp = sequence;
            sequence += 1;
            block.transactions.push(next);
            if Blockchain::full_witness_weight(&block).unwrap() > MAX_BLOCK_WEIGHT_BYTES {
                break block.transactions.pop().unwrap();
            }
        };
        block.merkle_root = Blockchain::calculate_merkle_root(&block.transactions).unwrap();
        block.hash = block.calculate_hash_for_block();

        let valid_weight = Blockchain::full_witness_weight(&block).unwrap();
        let valid_encoded = codec::serialize(&block).unwrap().len();
        assert!(valid_weight <= MAX_BLOCK_WEIGHT_BYTES);
        assert!(
            valid_weight + 20_000 > MAX_BLOCK_WEIGHT_BYTES,
            "test block must exercise the upper edge, not a small sample"
        );
        assert!(valid_encoded <= COMPACT_SAFE_ASSEMBLED_BYTES);
        assert!(Node::compact_block_transport_ok_at(&block, block.index));

        let mut over = block.clone();
        over.transactions.push(overflow_transaction);
        over.merkle_root = Blockchain::calculate_merkle_root(&over.transactions).unwrap();
        over.hash = over.calculate_hash_for_block();
        assert!(Blockchain::full_witness_weight(&over).unwrap() > MAX_BLOCK_WEIGHT_BYTES);
        assert!(
            !Node::compact_block_transport_ok_at(&over, over.index),
            "post-activation transport must never reconstruct an overweight block"
        );
        assert!(
            Node::compact_block_transport_ok_at(&over, over.index + 1),
            "the transport rule must not retroactively reject pre-activation history"
        );
    }

    #[test]
    fn oversized_for_compact_block_keeps_unchanged_full_mesh_fallback() {
        let mut block = compact_test_block();
        let payment = block.transactions[1].clone();
        let encoded_payment = codec::serialize(&payment).unwrap().len().max(1);
        let approximate_count = COMPACT_SAFE_ASSEMBLED_BYTES
            .saturating_div(encoded_payment)
            .saturating_sub(8);
        for offset in 1..approximate_count {
            let mut next = payment.clone();
            next.timestamp = next.timestamp.saturating_add(offset as u64);
            block.transactions.push(next);
        }
        while codec::serialize(&block).unwrap().len() <= COMPACT_SAFE_ASSEMBLED_BYTES {
            let mut next = payment.clone();
            next.timestamp = next
                .timestamp
                .saturating_add(block.transactions.len() as u64);
            block.transactions.push(next);
        }
        block.merkle_root = Blockchain::calculate_merkle_root(&block.transactions).unwrap();
        block.hash = block.calculate_hash_for_block();

        let encoded_block = codec::serialize(&block).unwrap().len();
        let encoded_full_frame = codec::serialize(&NetworkMessage::Block(block.clone())).unwrap();
        assert!(encoded_block > COMPACT_SAFE_ASSEMBLED_BYTES);
        assert!(
            encoded_full_frame.len() <= MAX_MESSAGE_SIZE,
            "fixture must remain valid for the unchanged full TCP/frame path"
        );
        assert!(!Node::compact_block_transport_ok(&block));
        assert!(
            CompactBlockV1::from_block(&block).is_err(),
            "an unreconstructable block must never become a compact announcement"
        );

        #[cfg(feature = "webrtc_mesh")]
        {
            let (compact_frame, full_frame) =
                Node::mesh_block_frames(&block).expect("full fallback frame");
            assert!(
                compact_frame.is_none(),
                "oversized compact hint is omitted, never substituted for delivery"
            );
            match codec::deserialize::<NetworkMessage>(&full_frame).unwrap() {
                NetworkMessage::Block(fallback) => {
                    assert_eq!(fallback.hash, block.hash);
                    assert_eq!(fallback.transactions, block.transactions);
                }
                _ => panic!("eligible unchanged full frame must remain the fallback"),
            }
        }
    }

    #[test]
    fn compact_delivery_success_is_tracked_per_target() {
        let mut delivered = LruCache::new(NonZeroUsize::new(8).expect("nonzero delivery cache"));
        let hash = [0x33u8; 32];
        let a = SocketAddr::from(([203, 0, 113, 1], 7_001));
        let b = SocketAddr::from(([203, 0, 113, 2], 7_002));
        let c = SocketAddr::from(([203, 0, 113, 3], 7_003));

        assert_eq!(
            Node::compact_targets_not_delivered_in(&mut delivered, &hash, [a, b, c],),
            vec![a, b, c]
        );
        Node::mark_compact_delivered_in(&mut delivered, &hash, a);
        assert_eq!(
            Node::compact_targets_not_delivered_in(&mut delivered, &hash, [a, b, c],),
            vec![b, c],
            "one successful peer must not suppress retries to untouched peers"
        );
        Node::mark_compact_delivered_in(&mut delivered, &hash, c);
        assert_eq!(
            Node::compact_targets_not_delivered_in(&mut delivered, &hash, [a, b, c],),
            vec![b],
            "a failed/unsent target remains eligible"
        );
    }

    #[test]
    fn compact_announcement_is_materially_smaller_than_full_witness_block() {
        let mut block = compact_test_block();
        let payment = block.transactions[1].clone();
        for offset in 1..11u64 {
            let mut next = payment.clone();
            next.timestamp = next.timestamp.saturating_add(offset);
            block.transactions.push(next);
        }
        block.merkle_root = Blockchain::calculate_merkle_root(&block.transactions).unwrap();
        block.hash = block.calculate_hash_for_block();
        let compact = CompactBlockV1::from_block(&block).unwrap();
        let full_bytes = codec::serialize(&NetworkMessage::Block(block)).unwrap();
        let compact_bytes = codec::serialize(&NetworkMessage::CompactBlockV1(compact)).unwrap();
        assert!(
            compact_bytes.len() < 2 * 1024,
            "11-payment compact announcement unexpectedly large: {}",
            compact_bytes.len()
        );
        assert!(
            compact_bytes.len() * 100 < full_bytes.len(),
            "compact={} full={}",
            compact_bytes.len(),
            full_bytes.len()
        );
    }

    #[test]
    fn compact_protocol_messages_round_trip() {
        let block = compact_test_block();
        let compact = CompactBlockV1::from_block(&block).unwrap();
        let encoded = codec::serialize(&NetworkMessage::CompactBlockV1(compact.clone())).unwrap();
        match codec::deserialize::<NetworkMessage>(&encoded).unwrap() {
            NetworkMessage::CompactBlockV1(decoded) => assert_eq!(decoded, compact),
            _ => panic!("wrong compact announcement variant"),
        }

        let body = IndexedCompactTransactionV1 {
            index: 1,
            transaction: block.transactions[1].clone(),
        };
        let response = NetworkMessage::CompactTransactionsV1 {
            block_hash: block.hash,
            transactions: vec![body.clone()],
        };
        let encoded_response = codec::serialize(&response).unwrap();
        match codec::deserialize::<NetworkMessage>(&encoded_response).unwrap() {
            NetworkMessage::CompactTransactionsV1 {
                block_hash,
                transactions,
            } => {
                assert_eq!(block_hash, block.hash);
                assert_eq!(transactions, vec![body]);
            }
            _ => panic!("wrong compact transaction response variant"),
        }

        for request in [
            NetworkMessage::GetCompactTransactionsV1 {
                block_hash: block.hash,
                indexes: vec![1],
                proxy_hops: COMPACT_PROXY_HOPS_MAX,
            },
            NetworkMessage::GetCompactBlockV1 {
                block_hash: block.hash,
                proxy_hops: COMPACT_PROXY_HOPS_MAX,
            },
        ] {
            let encoded = codec::serialize(&request).unwrap();
            let decoded: NetworkMessage = codec::deserialize(&encoded).unwrap();
            match (request, decoded) {
                (
                    NetworkMessage::GetCompactTransactionsV1 {
                        block_hash: expected_hash,
                        indexes: expected_indexes,
                        proxy_hops: expected_hops,
                    },
                    NetworkMessage::GetCompactTransactionsV1 {
                        block_hash,
                        indexes,
                        proxy_hops,
                    },
                ) => {
                    assert_eq!(block_hash, expected_hash);
                    assert_eq!(indexes, expected_indexes);
                    assert_eq!(proxy_hops, expected_hops);
                }
                (
                    NetworkMessage::GetCompactBlockV1 {
                        block_hash: expected_hash,
                        proxy_hops: expected_hops,
                    },
                    NetworkMessage::GetCompactBlockV1 {
                        block_hash,
                        proxy_hops,
                    },
                ) => {
                    assert_eq!(block_hash, expected_hash);
                    assert_eq!(proxy_hops, expected_hops);
                }
                _ => panic!("compact request variant changed during round trip"),
            }
        }
    }

    #[cfg(feature = "webrtc_mesh")]
    #[test]
    fn mesh_compact_envelope_precedes_unchanged_full_fallback() {
        let block = compact_test_block();
        let expected_compact = CompactBlockV1::from_block(&block).unwrap();
        let (compact_frame, full_frame) =
            Node::mesh_block_frames(&block).expect("mesh block frames");
        let compact_frame = compact_frame.expect("eligible block has compact envelope");

        // This is exactly what an older node sees first: a pre-existing RawData
        // variant it safely ignores. Its next ordered frame remains the unchanged
        // full Block variant.
        let raw = match codec::deserialize::<NetworkMessage>(&compact_frame).unwrap() {
            NetworkMessage::RawData(raw) => raw,
            _ => panic!("first mesh frame must use the backward-safe RawData variant"),
        };
        assert_eq!(
            CompactBlockV1::decode_mesh_envelope(&raw),
            Some(expected_compact)
        );
        match codec::deserialize::<NetworkMessage>(&full_frame).unwrap() {
            NetworkMessage::Block(fallback) => {
                assert_eq!(fallback.hash, block.hash);
                assert_eq!(fallback.transactions, block.transactions);
            }
            _ => panic!("second ordered mesh frame must remain the full-block fallback"),
        }

        let mut wrong_version = raw;
        wrong_version[MESH_COMPACT_V1_MAGIC.len()] = MESH_COMPACT_V1_VERSION.saturating_add(1);
        assert!(
            CompactBlockV1::decode_mesh_envelope(&wrong_version).is_none(),
            "unknown envelopes remain ignorable by version"
        );
    }

    #[cfg(feature = "webrtc_mesh")]
    #[test]
    fn mesh_compact_acceptance_suppresses_full_fallback_reprocessing() {
        let hash = compact_test_block().hash;
        let bloom = NetworkBloom::new(4_096, 0.01);
        let mesh_seen = Arc::new(PLMutex::new(LruCache::new(
            NonZeroUsize::new(8).expect("nonzero mesh seen cache"),
        )));
        assert!(!Node::mesh_block_already_seen(&mesh_seen, &bloom, &hash));

        // The normal NewBlock path commits the accepted hash to network_bloom
        // before relaying. Therefore the immediately-following ordered full
        // fallback is dropped even before the mesh-local success marker is
        // consulted; it cannot be revalidated or trigger a second gossip.
        bloom.insert(&hash);
        assert!(Node::mesh_block_already_seen(&mesh_seen, &bloom, &hash));

        mesh_seen.lock().put(hex::encode(hash), ());
        bloom.clear();
        assert!(
            Node::mesh_block_already_seen(&mesh_seen, &bloom, &hash),
            "mesh-local success remains a second independent replay guard"
        );
    }

    #[test]
    fn tcp_compact_extension_is_fail_closed_for_this_release() {
        let node_id = "ab".repeat(32);
        assert!(!Node::advertises_compact_v1(&node_id));
        let marked = format!("{}{}", node_id, COMPACT_BLOCK_V1_CAPABILITY_SUFFIX);
        assert!(Node::compact_v1_marker_well_formed(&marked));
        assert!(
            !Node::advertises_compact_v1(&marked),
            "even a well-formed remote marker cannot activate dormant TCP compact"
        );
        assert_eq!(
            Node::tcp_capability_node_id(&node_id),
            node_id,
            "the local ping/pong node id must not emit the capability suffix"
        );
        assert!(
            !Node::tcp_compact_peer_eligible(true),
            "a fresh injected capability record still cannot enable TCP compact"
        );
        assert!(!Node::advertises_compact_v1(
            COMPACT_BLOCK_V1_CAPABILITY_SUFFIX
        ));
        assert!(!Node::advertises_compact_v1(&format!(
            "{}{}",
            "zz".repeat(32),
            COMPACT_BLOCK_V1_CAPABILITY_SUFFIX
        )));

        let block = compact_test_block();
        let compact = CompactBlockV1::from_block(&block).unwrap();
        let extension_messages = [
            NetworkMessage::CompactBlockV1(compact),
            NetworkMessage::GetCompactTransactionsV1 {
                block_hash: block.hash,
                indexes: vec![1],
                proxy_hops: 0,
            },
            NetworkMessage::CompactTransactionsV1 {
                block_hash: block.hash,
                transactions: Vec::new(),
            },
            NetworkMessage::GetCompactBlockV1 {
                block_hash: block.hash,
                proxy_hops: 0,
            },
            NetworkMessage::CompactBlockResponseV1 {
                block_hash: block.hash,
                block: Some(block),
            },
        ];
        assert!(
            extension_messages
                .iter()
                .all(Node::is_tcp_compact_extension),
            "every compact request, response, and announcement must hit the inert ingress/egress gate"
        );
        assert!(!Node::is_tcp_compact_extension(&NetworkMessage::Block(
            compact_test_block()
        )));
    }

    // The witness-resolution count bound must mirror the ledger's own block-body limit exactly:
    // a block over the limit is invalid on every node, and a block at/under it is resolved
    // normally. Sharing MAX_BLOCK_TX_COUNT is what guarantees a node carrying this pre-check
    // reaches the same accept/reject-by-count verdict as one without it — no rollout divergence.
    #[test]
    fn witness_count_within_limit_matches_ledger_boundary() {
        assert!(Node::witness_count_within_limit(0));
        assert!(Node::witness_count_within_limit(1));
        assert!(Node::witness_count_within_limit(MAX_BLOCK_TX_COUNT)); // full valid block: ok
        assert!(!Node::witness_count_within_limit(MAX_BLOCK_TX_COUNT + 1)); // over the limit: rejected
                                                                            // The pre-check bound is the ledger bound, not an independent number.
        assert_eq!(
            MAX_BLOCK_TX_COUNT,
            crate::a9::blockchain::MAX_BLOCK_TX_COUNT
        );
    }

    // The read-endpoint token bucket shared by /stats and the explorer reads admits a burst up
    // to its cap and then rate-limits, so an unauthenticated flood cannot hammer the chain lock.
    #[test]
    fn read_bucket_admits_burst_up_to_cap_then_limits() {
        // Drained bucket: the first call has no tokens and is refused.
        let empty = Arc::new(PLMutex::new((Instant::now(), 0.0)));
        assert!(!Node::allow_read_bucket(&empty));

        // Full bucket (cap 30): 30 back-to-back calls are admitted, the next is limited. The
        // refill over the microseconds these calls take is far below a single token.
        let full = Arc::new(PLMutex::new((Instant::now(), 30.0)));
        for i in 0..30 {
            assert!(
                Node::allow_read_bucket(&full),
                "call {i} within the burst cap must be admitted"
            );
        }
        assert!(
            !Node::allow_read_bucket(&full),
            "a call past the burst cap must be rate-limited"
        );
    }

    // The per-block witness-resolve deadline has to clear a comfortable multiple of a single
    // fetch's timeout so an honest block (which needs at most a few fetches, each capped at that
    // timeout) never trips it and gets deferred, while staying finite so resolution over a block
    // whose witnesses only a slow peer can supply cannot run unbounded.
    #[test]
    fn witness_resolve_deadline_leaves_honest_headroom_yet_stays_bounded() {
        let per_fetch = WITNESS_RESOLVE_REQUEST_TIMEOUT;
        assert!(
            WITNESS_RESOLVE_DEADLINE >= per_fetch * 8,
            "deadline too tight — an honest block with a few slow fetches could be deferred"
        );
        assert!(
            WITNESS_RESOLVE_DEADLINE <= Duration::from_secs(120),
            "deadline too loose to bound resolution work"
        );
    }

    // Outbound witness fetches draw from a bounded pool kept separate from validation permits, so a
    // slow-responding peer can only ever contend with other fetches. The pool must cap concurrency
    // and refuse (so a fetch-needing block defers) when saturated, then recover as slots release.
    #[test]
    fn witness_fetch_slots_are_bounded_and_recover() {
        let pool = ValidationPool::new();
        let mut held = Vec::new();
        for _ in 0..MAX_PARALLEL_WITNESS_FETCHES {
            let slot = pool.acquire_fetch_slot();
            assert!(
                slot.is_some(),
                "a fetch slot must be available up to the pool size"
            );
            held.push(slot.unwrap());
        }
        // Saturated: refuse rather than queue behind slow peers (the caller defers the block).
        assert!(
            pool.acquire_fetch_slot().is_none(),
            "a saturated fetch pool must refuse so a fetch-needing block defers"
        );
        // Releasing one slot frees capacity again.
        held.pop();
        assert!(
            pool.acquire_fetch_slot().is_some(),
            "releasing a fetch slot must free capacity"
        );
    }

    // Ghost-block guard: a node mines only when at/ahead of the best-known network
    // tip or within a same/next-height race; a node that KNOWS it is meaningfully
    // behind (a higher beacon was seen) refuses, even if a momentarily-stale beacon
    // read made converge report "at the tip" (the 41370-mining-#41371-while-network-
    // at-41395 ghost-block, 2026-07-11).
    #[test]
    fn stale_tip_mine_guard_refuses_when_known_behind_but_mines_at_or_ahead() {
        // Genuinely behind by more than a race -> refuse.
        assert!(Node::stale_tip_mine_refused(41370, 41395));
        assert!(Node::stale_tip_mine_refused(41370, 41373)); // exactly 3 behind
                                                             // Same/next-height race (<=2) -> mine.
        assert!(!Node::stale_tip_mine_refused(41395, 41395)); // at tip
        assert!(!Node::stale_tip_mine_refused(41395, 41396)); // 1-block race
        assert!(!Node::stale_tip_mine_refused(41395, 41397)); // 2-block race (edge)
                                                              // Legitimately AHEAD of the last-seen beacon (we mined faster) -> mine.
        assert!(!Node::stale_tip_mine_refused(41397, 41395));
        // No beacon ever seen (known_tip 0) -> never refuses.
        assert!(!Node::stale_tip_mine_refused(41395, 0));
    }

    // The rolling beacon high-water must (a) keep a stale-LOW read from ever becoming
    // the guard's known_tip while a fresher-HIGHER read is still in-window (ghost-block
    // safety — the exact protection the old monotonic high-water gave), yet (b) let a
    // genuinely regressed height take over once the old stuck-high value ages out of
    // the window (the exit-after-regression the monotonic version never had).
    #[test]
    fn beacon_rolling_high_water_ghost_safe_yet_regression_recoverable() {
        use std::collections::VecDeque;
        use std::time::Duration;
        const W: u64 = 600;
        let now = Instant::now();

        // (a) GHOST-SAFETY: fresh reads at 41395 plus one stale-low 41370 -> max stays
        // 41395, so the guard still refuses a node at 41370. A stale-low read cannot
        // launder the node into ghost-mining.
        let mut obs: VecDeque<(Instant, u32)> = VecDeque::new();
        obs.push_back((now - Duration::from_secs(10), 41395));
        obs.push_back((now - Duration::from_secs(5), 41370)); // stale CDN copy
        obs.push_back((now - Duration::from_secs(1), 41395));
        assert_eq!(Node::window_high_water(&obs, now, W), 41395);
        assert!(Node::stale_tip_mine_refused(
            41370,
            Node::window_high_water(&obs, now, W)
        ));

        // (b) REGRESSION RECOVERY: the old high 41395 is now OUTSIDE the window; only a
        // fresh regressed height 41380 remains in-window -> max drops to 41380, so a node
        // at 41380 is no longer pinned (guard clears) — the exit the monotonic max lacked.
        let mut regressed: VecDeque<(Instant, u32)> = VecDeque::new();
        regressed.push_back((now - Duration::from_secs(W + 60), 41395)); // aged out
        regressed.push_back((now - Duration::from_secs(30), 41380)); // fresh, regressed
        regressed.push_back((now - Duration::from_secs(2), 41380));
        assert_eq!(Node::window_high_water(&regressed, now, W), 41380);
        assert!(!Node::stale_tip_mine_refused(
            41380,
            Node::window_high_water(&regressed, now, W)
        ));

        // Empty / nothing in-window -> 0 (fail-open, never pins).
        assert_eq!(Node::window_high_water(&VecDeque::new(), now, W), 0);
    }

    // Stall watchdog: only zero-progress calls beyond the reorg margin count;
    // escalation PERSISTS while the stall lasts (a single escalation followed by
    // a counter reset would let interleaved BeaconStale results starve the
    // caller's 2-consecutive-strike marker machinery — review, 2026-07-11).
    #[test]
    fn converge_stall_escalates_persistently_only_on_real_stalls() {
        let margin = crate::a9::blockchain::CHECKPOINT_REORG_MARGIN;
        let n = CONVERGE_STALL_ESCALATE_CALLS as u64;
        // Small gap: never counts, always resets.
        assert_eq!(
            Node::converge_stall_verdict(500, 500, margin, 99),
            (0, false)
        );
        // Progress: resets even when far behind.
        assert_eq!(
            Node::converge_stall_verdict(500, 501, margin + 300, 99),
            (0, false)
        );
        // No progress, far behind: accumulates without escalating below the bar…
        assert_eq!(
            Node::converge_stall_verdict(500, 500, margin + 300, n - 2),
            (n - 1, false)
        );
        // …escalates at the bar…
        assert_eq!(
            Node::converge_stall_verdict(500, 500, margin + 300, n - 1),
            (n, true)
        );
        // …and KEEPS escalating while the stall persists.
        assert_eq!(
            Node::converge_stall_verdict(500, 500, margin + 300, n),
            (n + 1, true)
        );
        // Recovery after escalation: any progress clears it.
        assert_eq!(
            Node::converge_stall_verdict(500, 620, margin + 300, n + 5),
            (0, false)
        );
    }

    // The announce gate must re-arm on SUCCESS (full interval) but only throttle
    // failures for the short retry window — one failed announce during a gateway
    // blip must not silence the node for the whole interval (2026-07-10 incident:
    // roster read empty for minutes after a short outage).
    #[test]
    fn announce_gate_retries_failures_fast_but_respects_success_interval() {
        let (interval, retry) = (300u64, 30u64);
        // Never announced, never attempted -> allowed.
        assert!(Node::announce_gate(1000, 0, 0, interval, retry));
        // Recent success -> blocked, regardless of attempt age.
        assert!(!Node::announce_gate(1000, 900, 900, interval, retry));
        assert!(!Node::announce_gate(1000, 900, 0, interval, retry));
        // Old success, recent (failed) attempt -> blocked by the retry throttle.
        assert!(!Node::announce_gate(1000, 500, 990, interval, retry));
        // Old success, old attempt -> allowed (this is the fast post-outage retry:
        // 30s after the failed attempt, NOT 300s after it).
        assert!(Node::announce_gate(1000, 500, 960, interval, retry));
        // No success ever (all attempts failed), attempt just now -> blocked...
        assert!(!Node::announce_gate(1000, 0, 995, interval, retry));
        // ...but allowed once the retry window passes.
        assert!(Node::announce_gate(1030, 0, 995, interval, retry));
        // Success exactly interval ago -> allowed again.
        assert!(Node::announce_gate(1000, 700, 700, interval, retry));
    }

    // The peer cache must live INSIDE the chain-DB directory (reboot-safe AND
    // guaranteed writable — sled writes there continuously; the parent dir can be
    // read-only in system-wide installs), not in the OS temp dir (wiped exactly
    // when the address book matters: restarting during a gateway outage). Env
    // override is tested implicitly by these branches running with the var unset.
    #[test]
    fn peer_cache_path_lives_inside_the_chain_db_dir() {
        let with_dir = Node::resolve_peer_cache_path(Some("/data/alphanumeric/blockchain.db"));
        assert_eq!(
            std::path::Path::new(&with_dir),
            std::path::Path::new("/data/alphanumeric/blockchain.db/alphanumeric_peers.json")
        );
        // No (or blank) data dir -> legacy temp-dir fallback.
        for missing in [None, Some("  ")] {
            let fallback = Node::resolve_peer_cache_path(missing);
            assert_eq!(
                std::path::Path::new(&fallback),
                std::env::temp_dir().join("alphanumeric_peers.json")
            );
        }
    }

    // Retry backoff: flat-and-fast while the gateway is unreachable (streak 0),
    // doubling per consecutive HTTP rejection, capped at the announce interval —
    // a persistently-rejecting gateway must see at most the pre-existing
    // 1-per-interval volume (the 2026-07-08 storm class), while outage recovery
    // stays at ANNOUNCE_RETRY_SECS.
    #[test]
    fn announce_retry_backs_off_on_rejections_and_caps_at_interval() {
        let interval = 300;
        assert_eq!(Node::announce_retry_secs_for_streak(0, interval), 30);
        assert_eq!(Node::announce_retry_secs_for_streak(1, interval), 60);
        assert_eq!(Node::announce_retry_secs_for_streak(2, interval), 120);
        assert_eq!(Node::announce_retry_secs_for_streak(3, interval), 240);
        assert_eq!(Node::announce_retry_secs_for_streak(4, interval), 300);
        // Streak beyond the shift cap must neither overflow nor exceed the interval.
        assert_eq!(Node::announce_retry_secs_for_streak(50, interval), 300);
        assert_eq!(
            Node::announce_retry_secs_for_streak(u64::MAX, interval),
            300
        );
        // A pathologically small interval can't push retry below the floor.
        assert_eq!(Node::announce_retry_secs_for_streak(4, 10), 30);
    }

    #[test]
    fn network_bloom_uses_nonzero_hash_count() {
        let bloom = NetworkBloom::new(BLOOM_FILTER_SIZE, BLOOM_FILTER_FPR);

        assert!(bloom.num_hashes > 0);
        assert!(bloom.max_items_before_reset > 0);
        assert!(bloom.max_items_before_reset < BLOOM_FILTER_SIZE);
    }

    #[test]
    fn stun_parse_rejects_oob_and_spoofed_and_accepts_valid() {
        let txid = [7u8; 12];
        let mut header = vec![0x01u8, 0x01, 0x00, 0x00];
        header.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        header.extend_from_slice(&txid);

        // 1) Malicious XOR-MAPPED-ADDRESS: attr_len=0 with an IPv4 family byte, packet
        //    ending exactly where the address bytes would begin. The old guard passed
        //    and then indexed past the end (remote panic / DoS). Must return Err, not panic.
        let mut oob = header.clone();
        oob.extend_from_slice(&[0x00, 0x20, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        assert!(Node::parse_stun_response(&oob, &txid).is_err());

        // 2) Well-formed IPv4 XOR-MAPPED-ADDRESS for 1.2.3.4 with a matching txid.
        let ip = [1u8, 2, 3, 4];
        let magic = STUN_MAGIC_COOKIE.to_be_bytes();
        let xor = [
            ip[0] ^ magic[0],
            ip[1] ^ magic[1],
            ip[2] ^ magic[2],
            ip[3] ^ magic[3],
        ];
        // Attribute value layout: reserved(1) + family(1=IPv4) + X-Port(2) + X-Address(4).
        let mut valid = header.clone();
        valid.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0x12, 0x34]);
        valid.extend_from_slice(&xor);
        assert_eq!(
            Node::parse_stun_response(&valid, &txid).unwrap(),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );

        // 3) Same packet, wrong transaction id -> rejected (defeats a spoofed response).
        assert!(Node::parse_stun_response(&valid, &[9u8; 12]).is_err());
    }

    // Peer full-history sync (Tier-2 bootstrap fallback): the safety-relevant driver logic.
    // The block VALIDATION itself is the same accept_peer_block / save_receipt_verified_block
    // path every other source uses (covered by the genesis-pin / PoW-floor / linkage tests);
    // these assert the driver can't be steered by a lying peer and always terminates.
    #[test]
    fn peer_full_sync_helpers_are_safe() {
        // Anchor height: peer must be >= the beacon; an INFLATED peer height is clamped to the
        // beacon (peer can't raise the target), and a peer BEHIND the beacon is unusable.
        assert_eq!(Node::full_sync_anchor_height(500, 500), Some(500));
        assert_eq!(Node::full_sync_anchor_height(500, 9_999_999), Some(500));
        assert_eq!(Node::full_sync_anchor_height(500, 499), None);

        // Span: end = min(cursor+255, target); (end-start) always < MAX_GETBLOCKS_SPAN so every
        // batch passes the server ingress cap; end never overshoots the fixed target.
        for &(cursor, target) in &[(1u32, 10u32), (1, 1000), (900, 1000), (1000, 1000)] {
            let (s, e) = Node::full_sync_next_span(cursor, target);
            assert_eq!(s, cursor);
            assert!(e <= target);
            assert!(e.saturating_sub(s) < MAX_GETBLOCKS_SPAN);
        }
        assert_eq!(Node::full_sync_next_span(1, 1000), (1, 256));

        // Termination: stop once past the target OR on any no-progress batch (stalling peer).
        assert!(Node::full_sync_should_continue(5, 10, true));
        assert!(!Node::full_sync_should_continue(11, 10, true));
        assert!(!Node::full_sync_should_continue(5, 10, false));

        // Witness routing: a block at/above verification_floor()+1 must be witness-verified;
        // at/below the floor it takes the receipt fast-path.
        assert!(Node::routes_via_witness(36, 35));
        assert!(!Node::routes_via_witness(35, 35));
        assert!(!Node::routes_via_witness(10, 35));
    }

    #[test]
    fn version_compare_flags_older_builds() {
        // Older -> flagged.
        assert!(Node::version_is_older("7.4.1", "7.5.0"));
        assert!(Node::version_is_older("7.4.9", "7.5.0"));
        assert!(Node::version_is_older("6.9.9", "7.0.0"));
        assert!(Node::version_is_older("7.5.0", "7.5.1"));
        // Equal or newer -> not flagged (no false update nag).
        assert!(!Node::version_is_older("7.5.0", "7.5.0"));
        assert!(!Node::version_is_older("7.5.1", "7.5.0"));
        assert!(!Node::version_is_older("8.0.0", "7.5.0"));
        // Tolerant parsing: leading `v`, pre-release suffix, short strings.
        assert!(Node::version_is_older("v7.4.0", "7.5.0"));
        assert!(!Node::version_is_older("7.5.0-rc1", "7.5.0"));
        assert_eq!(Node::parse_semver("7.5"), (7, 5, 0));
    }

    #[test]
    fn network_bloom_deduplicates_and_rotates_before_saturation() {
        let bloom = NetworkBloom::new(64, 0.01);

        assert!(bloom.insert(b"same-message"));
        assert!(!bloom.insert(b"same-message"));
        assert!(bloom.check(b"same-message"));

        let reset_after = bloom.max_items_before_reset;
        for i in 0..reset_after + 5 {
            let item = format!("message-{i}");
            bloom.insert(item.as_bytes());
        }

        assert!(bloom.item_count() <= reset_after);
        assert!(bloom.load_factor() < 1.0);
    }

    #[test]
    fn event_block_bloom_commits_only_after_successful_validation() {
        let bloom = NetworkBloom::new(4_096, 0.01);
        let hash = [0x5cu8; 32];

        assert!(Node::event_block_should_validate(&bloom, &hash));
        // A transient validation failure performs no commit, so a later full
        // delivery remains eligible for validation.
        assert!(Node::event_block_should_validate(&bloom, &hash));

        Node::commit_validated_event_block(&bloom, &hash);
        assert!(
            !Node::event_block_should_validate(&bloom, &hash),
            "only a successfully validated hash becomes a dedup hit"
        );
    }

    #[test]
    fn validation_cache_prune_removes_expired_and_caps_oldest() {
        let cache = DashMap::new();
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        cache.insert(
            "expired".to_string(),
            ValidationCacheEntry {
                valid: true,
                timestamp: now - Duration::from_secs(4_000),
            },
        );

        for i in 0..5 {
            cache.insert(
                format!("fresh-{i}"),
                ValidationCacheEntry {
                    valid: true,
                    timestamp: now - Duration::from_secs(10 * (i + 1) as u64),
                },
            );
        }

        // Five fresh entries survive expiry; a ceiling of 4 arms the size pass,
        // which trims to the mark of 3, dropping the two oldest.
        Node::prune_validation_cache_entries(&cache, now, 3_600, 4, 3);

        assert!(cache.get("expired").is_none());
        assert_eq!(cache.len(), 3);
        assert!(cache.get("fresh-0").is_some());
        assert!(cache.get("fresh-1").is_some());
        assert!(cache.get("fresh-2").is_some());
        assert!(cache.get("fresh-3").is_none());
        assert!(cache.get("fresh-4").is_none());
    }

    // AMORTISATION at the maintenance tick, asserted rather than described — the
    // node.rs mirror of the bpos trim_verifications assertion. The periodic caller
    // now passes the same bounds as the insert path, so a pass that finds the
    // cache anywhere in the band between the low-water mark and the ceiling must
    // leave it alone: trimming there would evict still-fresh verdicts on every
    // tick and force their revalidation. Crossing the ceiling is what trims, and
    // it trims to the mark. Bounds are parameters, so the property is provable at
    // toy scale without walking a 50,000-entry band.
    #[test]
    fn validation_cache_size_trim_gates_on_ceiling_not_mark() {
        let cache = DashMap::new();
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        let fresh = |age: u64| ValidationCacheEntry {
            valid: true,
            timestamp: now - Duration::from_secs(age),
        };
        let (ceiling, mark) = (10usize, 7usize);

        // Fill to the mark, then walk the band up to the ceiling: no pass may trim.
        for i in 0..ceiling as u64 {
            cache.insert(format!("k{i}"), fresh(i));
            if i < mark as u64 {
                continue;
            }
            let before = cache.len();
            Node::prune_validation_cache_entries(&cache, now, 3_600, ceiling, mark);
            assert_eq!(
                cache.len(),
                before,
                "a pass at {before} entries, inside the band, must not trim"
            );
        }

        // One entry over the ceiling trims back to the mark, evicting oldest-first:
        // the newcomer (age 0 = newest) and the youngest of the band survive.
        cache.insert("over".to_string(), fresh(0));
        Node::prune_validation_cache_entries(&cache, now, 3_600, ceiling, mark);
        assert_eq!(cache.len(), mark, "crossing the ceiling trims to the mark");
        assert!(cache.get("over").is_some());
        assert!(
            cache.get(&format!("k{}", ceiling - 1)).is_none(),
            "the oldest entries are the ones evicted"
        );
    }

    #[test]
    fn network_dedup_applies_only_to_gossip_messages() {
        // RawData was the final pre-compact variant. Pin its wire bytes so a
        // future insertion before the appended compact variants cannot silently
        // renumber messages understood by already-running peers.
        assert_eq!(
            hex::encode(codec::serialize(&NetworkMessage::RawData(vec![1, 2, 3])).unwrap()),
            "41394d5347320000020081a75261774461746193010203"
        );
        assert!(Node::should_dedup_message(&NetworkMessage::AlertMessage(
            "notice".to_string()
        )));
        assert!(!Node::should_dedup_message(&NetworkMessage::GetBlocks {
            start: 1,
            end: 2,
        }));
        assert!(!Node::should_dedup_message(&NetworkMessage::TxRequest {
            tx_id: "abc".to_string(),
        }));
        assert!(!Node::should_dedup_message(&NetworkMessage::Ping {
            timestamp: 123,
            node_id: "node".to_string(),
        }));
        assert!(!Node::should_dedup_message(
            &NetworkMessage::CompactBlockV1(
                CompactBlockV1::from_block(&compact_test_block()).unwrap()
            )
        ));
        assert!(!Node::should_dedup_message(&NetworkMessage::BlockHeight(1)));
    }

    #[test]
    fn peer_listen_addr_uses_signed_listen_port() {
        let socket_addr = SocketAddr::from(([192, 0, 2, 1], 52_011));
        assert_eq!(
            Node::peer_listen_addr(socket_addr, 7242).unwrap(),
            SocketAddr::from(([192, 0, 2, 1], 7242))
        );
        assert!(Node::peer_listen_addr(socket_addr, 0).is_err());
    }

    #[test]
    fn discovery_peer_filter_rejects_non_routable_addresses_by_default() {
        let blocked = [
            "0.0.0.0:7177",
            "10.0.0.1:7177",
            "100.64.0.1:7177",
            "127.0.0.1:7177",
            "169.254.1.1:7177",
            "172.16.0.1:7177",
            "192.168.1.10:7177",
            "192.0.2.1:7177",
            "198.18.0.1:7177",
            "203.0.113.1:7177",
            "224.0.0.1:7177",
            "240.0.0.1:7177",
            "[::]:7177",
            "[::1]:7177",
            "[fc00::1]:7177",
            "[fe80::1]:7177",
            "[2001:db8::1]:7177",
            "8.8.8.8:0",
        ];

        for addr in blocked {
            let addr: SocketAddr = addr.parse().unwrap();
            assert!(
                !Node::is_dialable_discovery_addr(&addr, false),
                "{addr} should not be accepted from public discovery"
            );
        }
    }

    #[test]
    fn discovery_peer_filter_allows_public_addresses_by_default() {
        let allowed = [
            "1.1.1.1:7177",
            "8.8.8.8:7177",
            "[2606:4700:4700::1111]:7177",
        ];

        for addr in allowed {
            let addr: SocketAddr = addr.parse().unwrap();
            assert!(
                Node::is_dialable_discovery_addr(&addr, false),
                "{addr} should be accepted from public discovery"
            );
        }
    }

    #[test]
    fn discovery_peer_filter_allows_private_addresses_only_when_explicit() {
        let private_addr: SocketAddr = "10.0.0.2:7177".parse().unwrap();
        let loopback_addr: SocketAddr = "127.0.0.1:7177".parse().unwrap();
        let unspecified_addr: SocketAddr = "0.0.0.0:7177".parse().unwrap();

        assert!(!Node::is_dialable_discovery_addr(&private_addr, false));
        assert!(!Node::is_dialable_discovery_addr(&loopback_addr, false));
        assert!(Node::is_dialable_discovery_addr(&private_addr, true));
        assert!(Node::is_dialable_discovery_addr(&loopback_addr, true));
        assert!(!Node::is_dialable_discovery_addr(&unspecified_addr, true));
    }

    #[test]
    fn discovery_candidate_filter_dedupes_and_skips_current_or_private_peers() {
        let bind_addr: SocketAddr = "0.0.0.0:7177".parse().unwrap();
        let current_peer: SocketAddr = "1.1.1.1:7177".parse().unwrap();
        let public_peer: SocketAddr = "8.8.8.8:7177".parse().unwrap();
        let private_peer: SocketAddr = "10.0.0.2:7177".parse().unwrap();
        let mut current_peers = HashSet::new();
        current_peers.insert(current_peer);

        let filtered = Node::filter_dialable_discovery_candidates(
            [
                bind_addr,
                current_peer,
                private_peer,
                public_peer,
                public_peer,
                "8.8.4.4:0".parse().unwrap(),
            ],
            bind_addr,
            &current_peers,
            false,
        );

        assert_eq!(filtered, vec![public_peer]);
    }

    #[test]
    fn discovery_candidate_filter_can_include_private_peers_when_explicit() {
        let bind_addr: SocketAddr = "0.0.0.0:7177".parse().unwrap();
        let private_peer: SocketAddr = "10.0.0.2:7177".parse().unwrap();
        let current_peers = HashSet::new();

        let filtered = Node::filter_dialable_discovery_candidates(
            [private_peer],
            bind_addr,
            &current_peers,
            true,
        );

        assert_eq!(filtered, vec![private_peer]);
    }

    // The rule the lock watchdog turns on: a failed lock probe is only evidence of a wedge
    // when nothing is getting done. A write-preferring RwLock starves a read probe during any
    // long legitimate write, so probe-failure alone cannot distinguish BUSY from WEDGED.
    //
    // Pure decision function, so the policy is testable without a clock, a lock or a chain.
    #[test]
    fn a_busy_chain_is_not_a_wedged_chain() {
        use Node as watchdog;
        let watchdog_strikes = watchdog::watchdog_strikes;
        // The false positive that shipped: probe lost the race to a catch-up, but the chain
        // was advancing the whole time.
        assert!(
            !watchdog_strikes(false, true, true),
            "a failed probe while the chain advances must NOT strike"
        );
        // A genuine wedge: nothing acquires, nothing advances.
        assert!(
            watchdog_strikes(false, false, true),
            "no lock and no progress is exactly the wedge this exists to catch"
        );
        // Progress must not paper over the OTHER lock.
        assert!(
            watchdog_strikes(true, true, false),
            "a wedged peers lock still strikes regardless of chain progress"
        );
        // The healthy case.
        assert!(!watchdog_strikes(true, true, true));
        assert!(!watchdog_strikes(true, false, true), "an idle chain is not wedged");
    }

    #[test]
    fn subnet_group_canonicalizes_ipv4_prefixes() {
        let group = SubnetGroup::from_ip("192.168.42.99".parse().unwrap(), 24, 64);
        assert_eq!(group.len, 24);
        assert_eq!(&group.data[0..4], &[192, 168, 42, 0]);
        assert_eq!(&group.data[4..], &[0; 12]);

        let group = SubnetGroup::from_ip("10.20.30.40".parse().unwrap(), 16, 64);
        assert_eq!(group.len, 16);
        assert_eq!(&group.data[0..4], &[10, 20, 0, 0]);

        let group = SubnetGroup::from_ip("172.16.255.255".parse().unwrap(), 17, 64);
        assert_eq!(group.len, 17);
        assert_eq!(&group.data[0..4], &[172, 16, 128, 0]);
    }

    // A dual-stack listener sees an IPv4 peer as ::ffff:a.b.c.d. It must land in the SAME
    // bucket as the plain IPv4 form, or the mapped spelling is a free way around the
    // subnet-diversity cap. Grouping and mask selection both belong to from_ip, so every
    // caller — including the handshake sites that build a PeerInfo literal — gets this.
    #[test]
    fn subnet_group_folds_ipv4_mapped_ipv6_onto_plain_ipv4() {
        let plain = SubnetGroup::from_ip(
            "192.168.42.99".parse().unwrap(),
            SUBNET_MASK_IPV4,
            SUBNET_MASK_IPV6,
        );
        let mapped = SubnetGroup::from_ip(
            "::ffff:192.168.42.99".parse().unwrap(),
            SUBNET_MASK_IPV4,
            SUBNET_MASK_IPV6,
        );
        assert_eq!(mapped, plain, "the mapped form must not be its own group");
        assert_eq!(mapped.len, SUBNET_MASK_IPV4, "and it is capped as IPv4");

        // Every entry point agrees, including the one the handshake path used to bypass.
        let via_peer_info =
            PeerInfo::new("[::ffff:192.168.42.99]:8333".parse().unwrap()).subnet_group;
        assert_eq!(via_peer_info, plain);

        // A genuine IPv6 address is untouched by the fold.
        let real_v6 = SubnetGroup::from_ip(
            "2001:db8::1".parse().unwrap(),
            SUBNET_MASK_IPV4,
            SUBNET_MASK_IPV6,
        );
        assert_eq!(real_v6.len, SUBNET_MASK_IPV6);
    }

    #[test]
    fn subnet_group_canonicalizes_ipv6_prefixes() {
        let group = SubnetGroup::from_ip(
            "2001:db8:abcd:1234:5678:90ab:cdef:1111".parse().unwrap(),
            24,
            64,
        );
        assert_eq!(group.len, 64);
        assert_eq!(
            &group.data,
            &[0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let group = SubnetGroup::from_ip(
            "2001:db8:abcd:1234:5678:90ab:cdef:1111".parse().unwrap(),
            24,
            73,
        );
        assert_eq!(group.len, 73);
        assert_eq!(
            &group.data[0..8],
            &[0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x12, 0x34]
        );
        assert_eq!(group.data[8], 0x56);
        assert_eq!(group.data[9], 0);
    }

    /// CONSENSUS BOUNDARY REGRESSION GUARD.
    ///
    /// BPoS is monitoring/finality telemetry. Its inputs are peer-derived, local and
    /// time-varying, so letting it reach the block verdict would make validity
    /// non-deterministic across nodes — different nodes accepting different blocks at
    /// the same height is a partition, not a disagreement about telemetry. The boundary
    /// is enforced structurally rather than by policy: `validation_result` is bound once,
    /// immutably, before the sentinel runs, so the monitoring path physically cannot
    /// assign it and the compiler rejects any attempt.
    ///
    /// A behavioural test cannot cover this — there is no code path left to exercise —
    /// so the binding form itself is what gets asserted. If this fails, the boundary was
    /// reopened and the change needs consensus review, not a test fix.
    #[test]
    fn bpos_telemetry_cannot_reach_the_canonical_block_verdict() {
        // Scan production code only: this test's own literals live in the test module
        // and would otherwise match the patterns it forbids.
        let src = include_str!("node.rs");
        let src = src
            .split("#[cfg(test)]")
            .next()
            .expect("split always yields a first segment");
        assert!(
            src.contains("let validation_result = {"),
            "validation_result must remain a single immutable binding"
        );
        assert!(
            !src.contains("let mut validation_result"),
            "validation_result must never be mutable: telemetry could then change PoW validity"
        );
        assert!(
            !src.contains("validation_result = false"),
            "no path may assign the canonical verdict; PoW and ledger rules are the sole authority"
        );
    }

    /// The relay-post error contract: a round with ANY accepting endpoint is a
    /// success; rate limiting outranks transient (a 429 anywhere means the per-IP
    /// window is closed, whatever the other endpoints said); transient-only rounds
    /// carry the transient marker; permanent rejections carry neither marker.
    #[test]
    fn relay_post_outcomes_fold_to_the_documented_contract() {
        assert!(Node::fold_relay_post_outcomes(true, false, false).is_ok());
        assert!(
            Node::fold_relay_post_outcomes(true, true, true).is_ok(),
            "one accepting endpoint is a success even when others failed"
        );
        let rate = Node::fold_relay_post_outcomes(false, true, true).unwrap_err();
        assert!(
            rate.to_string().contains(RELAY_POST_RATE_LIMITED),
            "rate limiting must outrank transient"
        );
        let transient = Node::fold_relay_post_outcomes(false, false, true).unwrap_err();
        assert!(transient.to_string().contains(RELAY_POST_TRANSIENT));
        let permanent = Node::fold_relay_post_outcomes(false, false, false).unwrap_err();
        let text = permanent.to_string();
        assert!(
            !text.contains(RELAY_POST_RATE_LIMITED) && !text.contains(RELAY_POST_TRANSIENT),
            "a permanent rejection must not look retryable"
        );
    }

    #[test]
    fn transient_relay_statuses_are_exactly_timeout_and_server_errors() {
        for code in [408u16, 500, 502, 503, 504] {
            let status = reqwest::StatusCode::from_u16(code).expect("status");
            assert!(
                Node::relay_post_status_is_transient(status),
                "{code} is a momentary condition and must be retryable"
            );
        }
        for code in [400u16, 401, 403, 404, 409, 413, 422] {
            let status = reqwest::StatusCode::from_u16(code).expect("status");
            assert!(
                !Node::relay_post_status_is_transient(status),
                "{code} is the relay's permanent verdict and must not be retried"
            );
        }
    }

    /// Permanent rejections — and errors that never came from the relay POST at
    /// all — get no retry: the identical request would meet the identical answer.
    #[test]
    fn permanent_relay_rejections_are_never_retried() {
        let permanent = Node::fold_relay_post_outcomes(false, false, false).unwrap_err();
        assert!(Node::relay_post_retry_delay(&permanent).is_none());
        let unrelated = NodeError::Blockchain("No local chain tip found".to_string());
        assert!(Node::relay_post_retry_delay(&unrelated).is_none());
    }

    /// Retryable failures get exactly one bounded delay each: a transient blip
    /// retries promptly (after the 3s client timeout has had time to clear), a
    /// closed per-IP window waits out its rollover. The single-shot property
    /// itself is structural: publish_block consults relay_post_retry_delay once,
    /// and the retry task's failure arm only warns — a double failure is terminal
    /// until the periodic relay-tip heal.
    #[test]
    fn retryable_relay_failures_get_one_bounded_delay_each() {
        let transient = Node::fold_relay_post_outcomes(false, false, true).unwrap_err();
        let prompt = Node::relay_post_retry_delay(&transient).expect("transient must retry");
        let rate = Node::fold_relay_post_outcomes(false, true, false).unwrap_err();
        let waited = Node::relay_post_retry_delay(&rate).expect("rate-limited must retry");
        assert!(
            prompt < waited,
            "a blip must retry sooner than a closed rate window"
        );
        assert!(waited >= Duration::from_secs(10));
    }
}
