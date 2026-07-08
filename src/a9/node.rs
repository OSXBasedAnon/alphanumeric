use arrayref::array_ref;
use axum::{extract::State, routing::get, Json, Router};
use dashmap::DashMap;
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
    time::{interval, sleep, timeout},
};

use crate::a9::blockchain::{
    Block, Blockchain, BlockchainError, RateLimiter, Transaction, SYSTEM_ADDRESSES,
};
use crate::a9::bpos::{BlockHeaderInfo, HeaderSentinel, NetworkHealth};
use crate::a9::codec;
use crate::a9::mempool::TemporalVerification;
use crate::a9::velocity::{Shred, ShredRequest, ShredRequestType, VelocityError, VelocityManager};

//----------------------------------------------------------------------
// Constants
//----------------------------------------------------------------------

// Network parameters
pub const DEFAULT_PORT: u16 = 7177;
const MIN_PEERS: usize = 3;
const MAX_PEERS_PER_SUBNET: usize = 3;
// Max span a single GetBlocks request may ask for (and the client's batch size, kept in
// lockstep). Bounds the per-request disk reads on the event loop and the reply size. 256 =
// 4x the 64-aligned convergence window, so it never throttles catch-up.
pub const MAX_GETBLOCKS_SPAN: u32 = 256;
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
/// How often a client polls the tiny edge-cached tip beacon. Cache HITS cost the
/// origin/Redis nothing, so this stays O(1) in client count; a version change is
/// the ONLY thing that triggers a block fetch, so there is no redundant pulling.
// 3s (was 2s): with ~10s+ block intervals the extra second of worst-case discovery
// latency is invisible, but it cuts every client's edge-request volume against the
// gateway by a third (43k -> 29k requests/day per node) — the fleet is the dominant
// consumer of the Vercel edge budget.
const BEACON_POLL_INTERVAL_SECS: u64 = 3;

/// The canonical tip as advertised by the signed beacon (height, hash, version).
#[derive(Clone, Copy)]
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
const DEFAULT_STATS_SNAPSHOT_INTERVAL_SECS: u64 = 300;
const DEFAULT_PERIODIC_RELAY_SYNC_INTERVAL_SECS: u64 = 60;
const DISCOVERY_HTTP_TIMEOUT_MS: u64 = 3000;
const DISCOVERY_BACKOFF_BASE_SECS: u64 = 60;
const DISCOVERY_BACKOFF_MAX_SECS: u64 = 900;
const DEFAULT_DISCOVERY_BASE: &str = "https://alphanumeric.blue";
// DNS seeds are optional fallback only. Primary discovery should come from alphanumeric.blue.
const DEFAULT_DNS_SEEDS: &[&str] = &[
    "seed.alphanumeric.network:7177",
    "seed2.alphanumeric.network:7177",
    "a9seed.mynode.network:7177",
];
const MAX_INBOUND_ATTEMPTS_PER_IP: u32 = 5;
const INBOUND_ATTEMPT_WINDOW: u64 = 60; // seconds
const INBOUND_ATTEMPT_MAX_KEYS: usize = 10_000;
const PEER_FAILURE_MAX_KEYS: usize = 10_000;

// Protocol
const NETWORK_VERSION: u32 = 3;

// Resource limits
const MAX_PARALLEL_VALIDATIONS: usize = 200;
const EVENT_QUEUE_CAPACITY: usize = 1000;
const EVENT_QUEUE_WARN_THRESHOLD: usize = 800;
const EVENT_BROADCAST_CAPACITY: usize = 1000;
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4MB hard cap per frame
const OUTBOUND_POOL_IDLE_SECS: u64 = 90;
const OUTBOUND_POOL_MAX_FACTOR: usize = 2;
const OUTBOUND_CIRCUIT_FAILURE_THRESHOLD: u32 = 3;
const OUTBOUND_CIRCUIT_OPEN_SECS: u64 = 30;
const BLOOM_FILTER_SIZE: usize = 100_000;
const BLOOM_FILTER_FPR: f64 = 0.01;
const VALIDATION_CACHE_TTL_SECS: u64 = 3600;
const VALIDATION_CACHE_MAX_ENTRIES: usize = 50_000;
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

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
    fn from_ip(ip: IpAddr, mask_v4: u8, mask_v6: u8) -> Self {
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
        // Normalize an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to real IPv4 before
        // grouping, so it is capped as IPv4 /24 rather than treated as a distinct IPv6
        // group an attacker could trivially vary to dodge the subnet-diversity cap.
        let ip = match addr.ip() {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        let subnet_group = match ip {
            IpAddr::V4(_) => SubnetGroup::from_ip(ip, SUBNET_MASK_IPV4, 0),
            IpAddr::V6(_) => SubnetGroup::from_ip(ip, 0, SUBNET_MASK_IPV6),
        };

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
        match ip {
            IpAddr::V4(_) => Some(SubnetGroup::from_ip(ip, SUBNET_MASK_IPV4, 0)),
            IpAddr::V6(_) => Some(SubnetGroup::from_ip(ip, 0, SUBNET_MASK_IPV6)),
        }
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
        }
    }

    pub fn insert(&self, item: &[u8]) -> bool {
        self.rotate_if_needed();

        let mut was_new = false;

        for i in 0..self.num_hashes {
            let hash = Self::hash(item, i);
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
            let hash = Self::hash(item, i);
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

    fn hash(data: &[u8], seed: usize) -> u64 {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        data.hash(&mut hasher);
        hasher.finish()
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
        }
    }
}

//----------------------------------------------------------------------
// Validation Pool
//----------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ValidationPool {
    available: Arc<Semaphore>,
    pub active_validations: Arc<AtomicU64>,
    timeout: Duration,
}

impl ValidationPool {
    pub fn new() -> Self {
        Self {
            available: Arc::new(Semaphore::new(MAX_PARALLEL_VALIDATIONS)),
            active_validations: Arc::new(AtomicU64::new(0)),
            timeout: Duration::from_secs(30),
        }
    }

    async fn acquire_validation_permit(&self) -> Result<ValidationPermit<'_>, NodeError> {
        match timeout(self.timeout, self.available.acquire()).await {
            Ok(Ok(permit)) => {
                self.active_validations.fetch_add(1, Ordering::SeqCst);
                Ok(ValidationPermit {
                    _permit: permit,
                    pool: self.clone(),
                })
            }
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

// RAII guard for validation permits
struct ValidationPermit<'a> {
    _permit: tokio::sync::SemaphorePermit<'a>,
    pool: ValidationPool,
}

impl<'a> Drop for ValidationPermit<'a> {
    fn drop(&mut self) {
        self.pool.active_validations.fetch_sub(1, Ordering::SeqCst);
    }
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
    relay_dead_targets: Arc<PLMutex<LruCache<(u32, [u8; 32]), (Instant, bool)>>>,
    last_public_announce_at: Arc<AtomicU64>,
    last_header_snapshot_at: Arc<AtomicU64>,
    last_stats_snapshot_at: Arc<AtomicU64>,
    p2p_swarm: Arc<Mutex<Option<HybridSwarm>>>,
    pub peer_id: String,
    inbound_attempts: Arc<RwLock<HashMap<IpAddr, (u32, u64)>>>,
    peer_cache_path: Arc<String>,
    configured_seed_nodes: Arc<Vec<String>>,

    // Consensus state
    tx_response_channels: Arc<RwLock<HashMap<String, oneshot::Sender<Option<Transaction>>>>>,
    tx_witness_cache: Arc<PLMutex<LruCache<String, Transaction>>>,
    pub validation_pool: Arc<ValidationPool>,
    validation_cache: Arc<DashMap<String, ValidationCacheEntry>>,
    // Peers we recently sent a GetBlocks request to. Inbound block responses are
    // correlated against this set: a `ChainResponse` from a peer we did not
    // solicit is untrusted and never applied to canonical state.
    solicited_block_peers: Arc<DashMap<SocketAddr, Instant>>,
    tx: broadcast::Sender<NetworkEvent>,

    // Feature components
    pub temporal_verification: Arc<TemporalVerification>,
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
    pub lock_path: Arc<String>,
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

#[derive(Debug)]
struct OutboundConnection {
    stream: TcpStream,
    shared_secret: Vec<u8>,
    last_used: Instant,
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
}

#[derive(Serialize)]
struct StatsResponse {
    network_id: String,
    height: u32,
    difficulty: u64,
    hashrate_ths: f64,
    last_block_time: u64,
    peers: usize,
    version: String,
    uptime_secs: u64,
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
        } = runtime_config;
        let (tx, _) = broadcast::channel(EVENT_BROADCAST_CAPACITY);
        let keypair = Ed25519KeyPair::from_pkcs8(&handshake_key_bytes)
            .map_err(|_| NodeError::Network("Invalid handshake key bytes".into()))?;
        let p2p_key = identity::Keypair::generate_ed25519();

        let witness_cache_capacity = Self::witness_cache_capacity();
        let peer_id = PeerId::from(p2p_key.public()).to_string();
        let temporal_verification = Arc::new(TemporalVerification::new());
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
        let peer_cache_path = std::env::var("ALPHANUMERIC_PEER_CACHE_PATH").unwrap_or_else(|_| {
            let path = std::env::temp_dir().join("alphanumeric_peers.json");
            path.to_string_lossy().into_owned()
        });

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
            tx_response_channels: Arc::new(RwLock::new(HashMap::with_capacity(2000))),
            tx_witness_cache: Arc::new(PLMutex::new(LruCache::new(witness_cache_capacity))),
            relay_dead_targets: Arc::new(PLMutex::new(LruCache::new(
                // Must comfortably exceed the number of distinct dead tips a post-storm
                // relay window can hold, or eviction re-admits chewed-through dead
                // candidates and starves the live tip out of the per-tick budget.
                std::num::NonZeroUsize::new(512).expect("nonzero"),
            ))),
            network_bloom: Arc::new(NetworkBloom::new(BLOOM_FILTER_SIZE, BLOOM_FILTER_FPR)),
            rate_limiter: Arc::new(RateLimiter::new(60, 100)),
            bind_addr,
            listener,
            p2p_swarm: Arc::new(Mutex::new(None)),
            http_client,
            discovery_state: Arc::new(Mutex::new(DiscoveryState::new())),
            discovery_in_progress: Arc::new(AtomicBool::new(false)),
            public_relay_tip: Arc::new(RwLock::new(None)),
            last_public_announce_at: Arc::new(AtomicU64::new(0)),
            last_header_snapshot_at: Arc::new(AtomicU64::new(0)),
            last_stats_snapshot_at: Arc::new(AtomicU64::new(0)),
            peer_id,
            peer_failures: Arc::new(RwLock::new(HashMap::new())),
            temporal_verification,
            header_sentinel: Some(Arc::new(HeaderSentinel::new())),
            lock_path: Arc::new(lock_path.to_string_lossy().into_owned()),
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
                let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
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
        std::env::var("ALPHANUMERIC_STATS_ENABLED")
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(false)
    }

    fn upnp_explicitly_enabled() -> bool {
        std::env::var("ALPHANUMERIC_ENABLE_UPNP")
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(false)
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

    fn discovery_snapshot_urls() -> Vec<String> {
        Self::discovery_bases()
            .into_iter()
            .map(|base| format!("{}/api/chain-snapshot", base))
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

    fn periodic_relay_sync_interval_secs() -> Option<u64> {
        // Always on and LIVE: every node stays current with the network tip by
        // pulling the relay on a short timer (block-time cadence), so new blocks —
        // and any payments they carry — land within a few seconds with no restart
        // and no configuration. The env var only tunes the cadence.
        if let Ok(value) = std::env::var("ALPHANUMERIC_RELAY_SYNC_INTERVAL_SECS") {
            if let Ok(parsed) = value.trim().parse::<u64>() {
                if parsed > 0 {
                    return Some(parsed.clamp(1, 3600));
                }
            }
        }
        Some(DEFAULT_PERIODIC_RELAY_SYNC_INTERVAL_SECS)
    }

    fn relay_sync_backfill_depth() -> u32 {
        std::env::var("ALPHANUMERIC_RELAY_SYNC_BACKFILL_DEPTH")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0)
            .min(256)
    }

    fn relay_sync_max_rounds() -> usize {
        std::env::var("ALPHANUMERIC_RELAY_SYNC_MAX_ROUNDS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4)
            .clamp(1, 24)
    }

    fn json_height(value: Option<&Value>) -> Option<u32> {
        value
            .and_then(|value| value.get("height"))
            .and_then(Value::as_u64)
            .and_then(|height| u32::try_from(height).ok())
    }

    fn public_tip_height_from_snapshot(body: &Value) -> Option<u32> {
        let mut best = 0u32;

        if body
            .get("canonical_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            if let Some(height) = Self::json_height(body.get("canonical_stats")) {
                best = best.max(height);
            }
        }

        if body
            .get("observed_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            if let Some(height) = Self::json_height(body.get("observed_stats")) {
                best = best.max(height);
            }
        }

        let source = body.get("source").and_then(Value::as_str).unwrap_or("");
        let observed_source = body
            .get("observed_source")
            .and_then(Value::as_str)
            .unwrap_or("");
        if matches!(source, "pending" | "push" | "snapshot" | "indexer")
            || matches!(observed_source, "pending" | "push" | "snapshot" | "indexer")
        {
            if let Some(height) = Self::json_height(body.get("stats")) {
                best = best.max(height);
            }
            if let Some(height) = Self::json_height(body.get("observed_stats")) {
                best = best.max(height);
            }
        }

        if let Some(height) = body
            .get("diagnostics")
            .and_then(|diagnostics| diagnostics.get("relay_backed_height"))
            .and_then(Value::as_u64)
            .and_then(|height| u32::try_from(height).ok())
        {
            best = best.max(height);
        }

        (best > 0).then_some(best)
    }

    async fn mark_block_relayed(&self, block: &Block) {
        let mut public_tip = self.public_relay_tip.write().await;
        let should_update = public_tip
            .map(|tip| {
                block.index > tip.height || (block.index == tip.height && block.hash == tip.hash)
            })
            .unwrap_or(true);
        if should_update {
            *public_tip = Some(RelayTipState {
                height: block.index,
                hash: block.hash,
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

        if let Ok((Some(ip), _v6)) = self.discover_external_addresses(STUN_SERVERS).await {
            return Some(ip);
        }

        None
    }

    fn is_private_ip(addr: &IpAddr) -> bool {
        match addr {
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

        if allow_private {
            return !addr.ip().is_unspecified();
        }

        match addr.ip() {
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

    fn load_peer_cache(&self) -> Vec<SocketAddr> {
        let path = &*self.peer_cache_path;
        let data = std::fs::read_to_string(path);
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
        if !Self::should_publish_now(
            &self.last_public_announce_at,
            Self::announce_interval_secs(),
            now,
        ) {
            return Ok(());
        }

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

        let Some(public_tip) = self.public_advertisable_tip().await else {
            return Ok(());
        };
        let height = public_tip.index;
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
        payload.insert(
            "signature".to_string(),
            json!(hex::encode(signature.as_ref())),
        );
        let payload = serde_json::Value::Object(payload);

        let mut any_ok = false;
        for url in Self::discovery_announce_urls() {
            let res = self.http_client.post(url).json(&payload).send().await;
            match res {
                Ok(res) if res.status().is_success() => any_ok = true,
                Ok(res) => {
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

        if !any_ok {
            debug!("Discovery announce failed on all endpoints");
        }

        Ok(())
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
        if !Self::should_publish_now(
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
        }

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
            let same_network = body
                .get("network_id")
                .and_then(|v| v.as_str())
                .map(|nid| nid.eq_ignore_ascii_case(&hex::encode(self.network_id)))
                .unwrap_or(true); // absent network_id: don't hard-fail (older gateway)
            if !same_network {
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
            return Some(TipBeaconInfo {
                height: height as u32,
                hash,
                version,
            });
        }
        None
    }

    /// Current signed network beacon height, if reachable. Public accessor for
    /// pacing decisions (e.g. continuous mining waits for the network to absorb a
    /// mined block before starting the next). Read-only; one edge-cached HTTP GET.
    pub async fn network_beacon_height(&self) -> Option<u32> {
        self.fetch_tip_beacon().await.map(|b| b.height)
    }

    /// Reconcile to the beacon (thin wrapper kept for existing call sites). The real
    /// work is the single always-converge op below.
    async fn reconcile_to_beacon(&self, beacon: &TipBeaconInfo) {
        let _ = self.converge_to_canonical(beacon).await;
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
    async fn find_common_ancestor(&self, beacon: &TipBeaconInfo, floor: u32) -> Ancestor {
        const WIN: u32 = 64;
        // Canonical blocks indexed by their OWN hash so we can follow previous_hash
        // links regardless of which fork shares a given height.
        let mut by_hash: std::collections::HashMap<[u8; 32], Block> =
            std::collections::HashMap::new();
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
            // Fetch the 64-aligned window containing the height we need next.
            let win_base = expected_height - (expected_height % WIN);
            let win_end = win_base + WIN - 1;
            match self.fetch_relay_blocks(win_base, win_end).await {
                Ok(v) if !v.is_empty() => {
                    for b in v {
                        by_hash.entry(b.hash).or_insert(b);
                    }
                }
                // Empty-but-200 in a below-tip window, or an outright error: a gap. If it
                // is within reorg reach retry (Transient); if deeper, the history is gone
                // and only a snapshot recovers it (NeedsBootstrap).
                Ok(_) | Err(_) => return gap_verdict(expected_height),
            }

            // Walk the prev-hash chain down through the bodies we now hold.
            loop {
                let Some(cb) = by_hash.get(&expected_hash).cloned() else {
                    // The body for this exact (height,hash) is not on the relay even
                    // after fetching its window -> broken link (same transient-vs-deep
                    // distinction as an empty window).
                    return gap_verdict(expected_height);
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
            let (ancestor, canon) = match self.find_common_ancestor(beacon, floor).await {
                Ancestor::Found(a, canon) => (a, canon),
                Ancestor::NoneBelowFloor | Ancestor::NeedsBootstrap => {
                    return Converge::NeedsBootstrap
                }
                Ancestor::Transient => return Converge::BeaconStale,
            };

            let before = tip;
            if ancestor >= tip {
                // Same chain, strictly behind (ancestor == tip): forward-stream the
                // canonical blocks that chain onto our tip. This path already applies
                // the S-01 frontier gate + trails the finality checkpoint.
                let _ = self.sync_with_block_relay(tip).await;
            } else {
                // Divergent: our tip forks from canonical at `ancestor` < tip.
                let d = ancestor + 1;
                // Reuse the bodies find_common_ancestor already fetched: [d ..= beacon].
                let branch: Vec<Block> = canon.into_iter().filter(|b| b.index >= d).collect();
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

        let synced = matches!(
            self.blockchain.read().await.get_block(beacon.height),
            Ok(b) if b.hash == beacon.hash
        );
        if synced {
            Converge::Converged
        } else {
            Converge::Progressed
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
        const MAX_TIP_CANDIDATES: usize = 4;
        const DEAD_TARGET_RETRY_SECS: u64 = 300;
        // TRUE TIPS ONLY: a block some other wire block names as its parent is not a
        // tip — converging to its tip covers it. Without this filter, an abandoned
        // fork contributes EVERY one of its blocks as a candidate (a post-storm relay
        // held a ~120-block dead fork), and the per-tick candidate budget could burn
        // entirely on dead mid-fork blocks before ever reaching the live chain's
        // fresh tip.
        let parent_hashes: HashSet<[u8; 32]> =
            blocks.iter().map(|b| b.previous_hash).collect();
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
                if let Some(&(when, hard)) = dead.peek(&(h, cursor)) {
                    // Only HARD (validation-failure) deadness propagates.
                    if hard && when.elapsed() < Duration::from_secs(DEAD_TARGET_RETRY_SECS) {
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
            let present: std::collections::HashSet<u32> =
                blocks.iter().map(|b| b.index).collect();
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
                // Lowest-hash block at the reachable-top height = deterministic target.
                if let Some(b) = blocks
                    .iter()
                    .filter(|b| b.index == reachable_top)
                    .min_by_key(|b| b.hash)
                {
                    let key = (b.index, b.hash);
                    // Prepend if not already the first candidate.
                    if candidates.first() != Some(&key) {
                        candidates.retain(|c| *c != key);
                        candidates.insert(0, key);
                    }
                }
            }
        }

        let mut last = Converge::BeaconStale;
        let mut tried = 0usize;
        let mut all_needs_bootstrap = true;
        for (height, hash) in candidates {
            if tried >= MAX_TIP_CANDIDATES {
                break;
            }
            if height == local_tip && Some(hash) == local_hash {
                // Our own tip: nothing above us that converged — we are as caught up
                // as the relay allows this tick.
                return if tried == 0 { Converge::Converged } else { last };
            }
            {
                let mut dead = self.relay_dead_targets.lock();
                if let Some(&(when, _)) = dead.get(&(height, hash)) {
                    if when.elapsed() < Duration::from_secs(DEAD_TARGET_RETRY_SECS) {
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
            match self.converge_to_canonical(&target).await {
                done @ (Converge::Converged | Converge::AtTipAhead | Converge::Progressed) => {
                    return done;
                }
                failed @ (Converge::BeaconStale
                | Converge::NeedsBootstrap
                | Converge::BranchInvalid) => {
                    if !matches!(failed, Converge::NeedsBootstrap) {
                        all_needs_bootstrap = false;
                    }
                    let hard = matches!(failed, Converge::BranchInvalid);
                    self.relay_dead_targets
                        .lock()
                        .put((height, hash), (Instant::now(), hard));
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
        if tried > 0 && !matches!(last, Converge::Converged | Converge::AtTipAhead) {
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
        for url in Self::discovery_blocks_urls() {
            let res = self.http_client.post(url).json(&payload).send().await;
            match res {
                Ok(res) if res.status().is_success() => any_ok = true,
                Ok(res) => {
                    let status = res.status();
                    let body = res.text().await.unwrap_or_default();
                    warn!(
                        "Block relay post failed: {} {}",
                        status,
                        Self::response_body_snippet(&body)
                    );
                }
                Err(e) => warn!("Block relay post error: {}", e),
            }
        }

        if !any_ok {
            warn!("Block relay post failed on all endpoints");
            return Err(NodeError::Network(
                "Block relay post failed on all endpoints".into(),
            ));
        }

        self.mark_block_relayed(block).await;
        Ok(())
    }

    async fn post_recent_blocks_to_relay(&self, limit: u32) {
        if limit == 0 || !Self::block_relay_publish_enabled() {
            return;
        }

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

        for block in blocks {
            if let Err(e) = self.post_block_relay(&block).await {
                debug!("Recent block relay failed for #{}: {}", block.index, e);
            }
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
            let start = cursor;
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

            for block in blocks {
                // Checkpoint-anchored verification (S-01). Blocks ABOVE the trusted
                // checkpoint are the unfinalized frontier: a relay-only node cannot
                // receipt-trust the tip, so they MUST carry full, valid ML-DSA
                // witnesses — post_block_relay rehydrates them from the miner — or we
                // decline them. Blocks at/below the checkpoint were vouched for by a
                // verified signed snapshot and are receipt-trusted, which is what lets
                // catch-up over witness-pruned history proceed.
                let floor = self.blockchain.read().await.verification_floor();
                if block.index > floor
                    && !self
                        .blockchain
                        .read()
                        .await
                        .block_signatures_fully_verified(&block)
                {
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
                        relay_confirmed_blocks.push(block.clone());
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

            let after_batch = {
                let blockchain = self.blockchain.read().await;
                blockchain.get_latest_block_index() as u32
            };
            for block in relay_confirmed_blocks {
                self.mark_block_relayed(&block).await;
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

    async fn fetch_public_tip_height(&self) -> Result<Option<u32>, NodeError> {
        let expected_network_id = hex::encode(self.network_id);
        let mut best_height: Option<u32> = None;

        for url in Self::discovery_snapshot_urls() {
            let res = match self.http_client.get(url).send().await {
                Ok(res) => res,
                Err(e) => {
                    debug!("Public tip check failed: {}", e);
                    continue;
                }
            };

            if !res.status().is_success() {
                debug!("Public tip check returned {}", res.status());
                continue;
            }

            let body = match res.json::<Value>().await {
                Ok(body) => body,
                Err(e) => {
                    debug!("Public tip response parse failed: {}", e);
                    continue;
                }
            };

            let same_network = body
                .get("network_id")
                .and_then(Value::as_str)
                .map(|network_id| network_id.eq_ignore_ascii_case(&expected_network_id))
                .unwrap_or(false);
            if !same_network {
                continue;
            }

            if let Some(height) = Self::public_tip_height_from_snapshot(&body) {
                best_height = Some(best_height.map_or(height, |best| best.max(height)));
            }
        }

        Ok(best_height)
    }

    async fn best_connected_peer_height_for_mining(
        &self,
        max_wait: Duration,
    ) -> Result<u32, NodeError> {
        let peer_addrs = {
            let peers = self.peers.read().await;
            peers.keys().copied().collect::<Vec<_>>()
        };

        if peer_addrs.is_empty() {
            return Err(NodeError::ConsensusFailure(
                "no connected peers available for pre-mine sync".to_string(),
            ));
        }

        let timeout_ms = u64::try_from(max_wait.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let peer_heights = timeout(max_wait, self.query_peer_heights(peer_addrs, timeout_ms))
            .await
            .map_err(|_| {
                NodeError::ConsensusFailure(
                    "connected peers did not report height before timeout".to_string(),
                )
            })?;

        peer_heights
            .first()
            .map(|(_, height)| *height)
            .ok_or_else(|| {
                NodeError::ConsensusFailure("no connected peer reported chain height".to_string())
            })
    }

    async fn guard_public_tip_before_mining(&self, max_wait: Duration) -> Result<(), NodeError> {
        // Prefer the FRESH signed beacon as the canonical network tip (the header
        // snapshot lags by its publish interval). Fall back to the snapshot only if
        // the beacon is unavailable, and fail open if neither is reachable.
        let public_height = if let Some(beacon) = self.fetch_tip_beacon().await {
            beacon.height
        } else {
            match timeout(max_wait, self.fetch_public_tip_height()).await {
                Ok(Ok(Some(height))) => height,
                Ok(Ok(None)) => return Ok(()),
                Ok(Err(e)) => {
                    debug!("Public tip check unavailable before mining: {}", e);
                    return Ok(());
                }
                Err(_) => {
                    debug!("Public tip check timed out before mining");
                    return Ok(());
                }
            }
        };

        let local_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_latest_block_index() as u32
        };

        if local_height < public_height {
            return Err(NodeError::ConsensusFailure(format!(
                "verified network tip {} is ahead of local tip {}; mining paused until the node syncs",
                public_height, local_height
            )));
        }

        Ok(())
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

    pub async fn prepare_local_mining(&self, max_wait: Duration) -> Result<(), NodeError> {
        debug!("mine-prep: enter");
        // Best-effort peer discovery (harmless no-op when NAT'd and empty). Capped
        // WELL below max_wait: across NAT this almost never yields a peer, and at the
        // old cap (= max_wait) it silently ate the entire mining-prep window before
        // convergence even started — the "mine command hangs with no output" stall.
        // Convergence uses the relay, not p2p peers, so a short cap loses nothing.
        // The peers-lock read is itself time-boxed: a wedged peers lock elsewhere
        // must degrade this into "skip discovery", never into a hang.
        let peers_empty = match timeout(Duration::from_secs(2), async {
            self.peers.read().await.is_empty()
        })
        .await
        {
            Ok(empty) => empty,
            Err(_) => {
                debug!("mine-prep: peers lock busy; skipping discovery");
                false
            }
        };
        debug!("mine-prep: peers checked (empty={})", peers_empty);
        if peers_empty {
            let cap = max_wait.min(Duration::from_secs(3));
            let _ = timeout(cap, self.connect_discovery_peers(8)).await;
        }
        debug!("mine-prep: discovery done, entering converge loop");

        // ALWAYS CONVERGE, THEN COMPETE — never pause-and-concede.
        //
        // When behind or forked, actively converge to the signed-beacon canonical tip
        // and THEN mine on that fresh tip to compete for the next block. This is the
        // fix for the monopoly failure: a node that is behind used to just refuse to
        // mine ("mining paused until the node syncs") and sit it out, so whoever was
        // ahead kept winning and nobody could catch up. Now "behind" means "actively
        // syncing then racing", from ANY state (behind, forked-at-tip, forked-and-
        // behind). The loop re-fetches the beacon each round so a block that lands
        // mid-prep is adopted and we re-target onto it before mining. The backoff keeps
        // the cadence >= a block time so a run of rounds can't self-rate-limit the relay
        // into the very non-convergence it is meant to cure.
        let deadline = Instant::now() + max_wait;
        let mut backoff = Duration::from_millis(500);
        loop {
            debug!("mine-prep: fetching beacon");
            let Some(beacon) = self.fetch_tip_beacon().await else {
                // Beacon genuinely unreachable => FAIL OPEN and mine on the local tip.
                // Producing on our best-known chain beats conceding; the reorg engine
                // still resolves any fork when connectivity returns.
                warn!("Tip beacon unreachable; mining on local tip (fail-open)");
                return Ok(());
            };
            debug!("mine-prep: beacon h{} v{}; converge round", beacon.height, beacon.version);
            // Backstop timeout per round: the deadline is only checked BETWEEN rounds,
            // and one converge round can fan out into many relay window fetches (each
            // individually HTTP-bounded but unbounded in count on a deeply forked
            // relay) — the rare "mine hangs for a minute with zero output" stall.
            // Cancelling here is state-safe: adoption is atomic (apply_batch) and any
            // partially staged sync work is re-derived on the next round.
            let round = match timeout(
                Duration::from_secs(20),
                self.converge_to_canonical(&beacon),
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(_) => {
                    warn!("Converge round timed out; retrying against a fresh beacon");
                    Converge::BeaconStale
                }
            };
            match round {
                // At the canonical tip, or holding an equal/heavier chain: go COMPETE.
                Converge::Converged | Converge::AtTipAhead => return Ok(()),
                // Diverged below the finality window — incremental convergence cannot
                // fix this (rare); surface so the reconcile loop can escalate.
                Converge::NeedsBootstrap => {
                    return Err(NodeError::ConsensusFailure(
                        "chain diverged below the finality window; re-bootstrap required".into(),
                    ));
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
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
                // Transient relay gap. A DEEP gap (history aged out) already escalated to
                // NeedsBootstrap above (M3), so this is a near-the-tip hiccup: after the
                // deadline, FAIL OPEN and mine on our local tip rather than sit out. We
                // are near the tip, so the local tip is almost certainly current; a losing
                // local block is reorged away by the normal path. This upholds the
                // "never dead-pause" contract even when the relay momentarily can't answer.
                Converge::BeaconStale => {
                    if Instant::now() >= deadline {
                        warn!("Relay gap while preparing to mine; mining on local tip (fail-open)");
                        return Ok(());
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
                // The canonical branch we were pointed at failed validation locally.
                // Terminal for that branch, not for us: mine on our local tip and let
                // PoW settle it (same fail-open posture as a relay gap, immediately —
                // retrying the same invalid branch cannot succeed).
                Converge::BranchInvalid => {
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

    pub async fn publish_block(&self, block: Block, context: &str) -> Result<(), NodeError> {
        let post_mine = context == "Post-mine";

        let block_hash = block.calculate_hash_for_block();
        let _ = self.network_bloom.insert(&block_hash);

        // PROPAGATION-CRITICAL, FIRST: POST to the gateway relay immediately — it is the
        // authoritative propagation path across NAT, so it must NOT wait behind the
        // peerless p2p discovery (~6s timeout) below, which almost never yields a
        // reachable peer. Fronting the relay POST shaves that latency off the time a
        // freshly-mined block takes to reach every other miner — the exact window during
        // which they would otherwise mine a competing fork.
        if let Err(e) = self.post_block_relay(&block).await {
            warn!("{} block relay failed: {}", context, e);
        } else {
            self.post_recent_blocks_to_relay(Self::relay_backfill_limit())
                .await;
        }

        // Best-effort direct p2p broadcast (usually a no-op across NAT), done AFTER the
        // relay post so its discovery timeout can never delay propagation.
        if self.peers.read().await.is_empty() {
            if let Err(e) = self.connect_discovery_peers(8).await {
                if post_mine {
                    warn!("{} discovery failed: {}", context, e);
                } else {
                    debug!("{} discovery deferred: {}", context, e);
                }
            }
        }

        let selected_peers = {
            let peers = self.peers.read().await;
            self.select_broadcast_peers(&peers, peers.len().min(16))
        };

        if selected_peers.is_empty() {
            // No TCP peers — but we may have DIRECT mesh peers. Gossip the mined block over the mesh
            // so a peerless NAT miner (exactly the case the mesh targets) still propagates P2P, not
            // only via the relay. The peered branch below already gossips inside broadcast_block.
            #[cfg(feature = "webrtc_mesh")]
            self.mesh_gossip_block(&block).await;
            if post_mine {
                warn!("Mined block saved locally, but no peers were available for block broadcast");
            } else {
                debug!(
                    "{} publish deferred: no peers available for broadcast",
                    context
                );
            }
        } else {
            match self
                .broadcast_block(Arc::new(block.clone()), None, selected_peers)
                .await
            {
                Ok(0) => {
                    if post_mine {
                        warn!("Mined block broadcast had no eligible target peers");
                    } else {
                        debug!("{} publish deferred: no eligible target peers", context);
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
        }

        self.publish_discovery_state(context).await;

        Ok(())
    }

    async fn stats_handler(State(state): State<StatsState>) -> Json<StatsResponse> {
        let height = {
            let blockchain = state.blockchain.read().await;
            blockchain.get_latest_block_index() as u32
        };

        let last_block_time = {
            let blockchain = state.blockchain.read().await;
            blockchain
                .get_last_block()
                .map(|b| b.timestamp)
                .unwrap_or(0)
        };

        let difficulty = {
            let blockchain = state.blockchain.read().await;
            blockchain.get_tip_difficulty().await
        };

        let hashrate_ths = {
            let blockchain = state.blockchain.read().await;
            blockchain.calculate_network_hashrate().await
        };

        let peers = state.peers.read().await.len();
        let uptime_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(state.start_time);

        Json(StatsResponse {
            network_id: hex::encode(state.network_id),
            height,
            difficulty,
            hashrate_ths,
            last_block_time,
            peers,
            version: format!("rust-{}", NETWORK_VERSION),
            uptime_secs,
        })
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
        const MIN_TARGET_PEERS: usize = 3;
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

    #[allow(dead_code)]
    async fn scan_range_with_limit(
        &self,
        range: &ScanRange,
        semaphore: Arc<Semaphore>,
        limit: usize,
    ) -> Result<HashSet<SocketAddr>, NodeError> {
        let mut discovered = HashSet::new();

        // Get addresses to scan based on network type
        let mut addrs = match &range.network {
            ScanNetwork::V4(net) => {
                let mut addrs = Vec::new();
                // Generate addresses from the subnet, but limit to reasonable number
                for host in net.hosts().take(limit) {
                    addrs.push(SocketAddr::new(IpAddr::V4(host), DEFAULT_PORT));
                }
                addrs
            }
            ScanNetwork::V6(net) => {
                let mut addrs = Vec::new();
                let mut rng = thread_rng();

                // For IPv6, generate limited random addresses in the subnet
                for _ in 0..limit.min(25) {
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

        // Randomize order for better distribution
        addrs.shuffle(&mut thread_rng());

        // Take only the first 'limit' addresses
        addrs.truncate(limit);

        // Concurrently scan addresses with improved error handling
        let scan_tasks: Vec<_> = addrs
            .into_iter()
            .map(|addr| {
                let permit = semaphore.clone().acquire_owned();
                let node = self.clone();

                tokio::spawn(async move {
                    let _permit = permit.await.ok()?;

                    if addr == node.bind_addr {
                        return None;
                    }

                    // Quick TCP check with better timeout
                    match tokio::time::timeout(Duration::from_millis(300), TcpStream::connect(addr))
                        .await
                    {
                        Ok(Ok(_)) => Some(addr),
                        _ => None,
                    }
                })
            })
            .collect();

        // Gather results
        for result in futures::future::join_all(scan_tasks).await {
            if let Ok(Some(addr)) = result {
                discovered.insert(addr);
            }
        }

        Ok(discovered)
    }

    #[allow(dead_code)]
    async fn build_optimized_scan_ranges(
        &self,
        v4_addr: IpAddr,
        v6_addr: Option<IpAddr>,
    ) -> Result<Vec<ScanRange>, NodeError> {
        let mut ranges = Vec::new();

        // Add current peer subnet ranges first (most likely to find peers)
        {
            let peers = self.peers.read().await;
            for (_, info) in peers.iter() {
                // Direct access to subnet_group - it's not an Option
                // Convert subnet group to scan range
                match info.address.ip() {
                    IpAddr::V4(ip) => {
                        let octets = ip.octets();
                        let subnet_str = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);

                        if let Ok(net) = subnet_str.parse::<Ipv4Net>() {
                            // Add with high priority
                            ranges.push(ScanRange {
                                network: ScanNetwork::V4(net),
                                priority: 1, // Highest priority
                            });
                        }
                    }
                    IpAddr::V6(_) => {} // Skip IPv6 for now
                }
            }
        }

        // Add IPv4 subnet from current address (your likely subnet)
        if let IpAddr::V4(ipv4) = v4_addr {
            let octets = ipv4.octets();

            // Current /24 subnet
            let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
            if let Ok(net) = subnet.parse::<Ipv4Net>() {
                ranges.push(ScanRange {
                    network: ScanNetwork::V4(net),
                    priority: 1, // Highest priority
                });
            }

            // Add adjacent subnets
            for i in -2i32..=2i32 {
                if i == 0 {
                    continue;
                }

                // Try to handle wraparound properly
                let third_octet = ((octets[2] as i32) + i) & 0xFF;
                let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], third_octet);

                if let Ok(net) = subnet.parse::<Ipv4Net>() {
                    ranges.push(ScanRange {
                        network: ScanNetwork::V4(net),
                        priority: 2,
                    });
                }
            }

            // Add broader subnet (faster search across larger network)
            let broader_subnet = format!("{}.{}.0.0/16", octets[0], octets[1]);
            if let Ok(net) = broader_subnet.parse::<Ipv4Net>() {
                ranges.push(ScanRange {
                    network: ScanNetwork::V4(net),
                    priority: 3,
                });
            }
        }

        // Add common cloud provider and ISP ranges
        for &(range, priority) in &[
            // Major cloud providers (likely to host nodes)
            ("3.0.0.0/8", 3),   // AWS
            ("35.0.0.0/8", 3),  // GCP
            ("52.0.0.0/8", 3),  // AWS
            ("104.0.0.0/8", 3), // Cloud
            // ISP ranges
            ("24.0.0.0/8", 4), // Comcast
            ("71.0.0.0/8", 4), // AT&T
            ("73.0.0.0/8", 4), // Verizon
            // Private networks (for local testing)
            ("192.168.0.0/16", 2), // Local
            ("10.0.0.0/8", 3),     // Private
        ] {
            if let Ok(net) = range.parse::<Ipv4Net>() {
                ranges.push(ScanRange {
                    network: ScanNetwork::V4(net),
                    priority,
                });
            }
        }

        // Add IPv6 ranges if available
        if let Some(IpAddr::V6(ipv6)) = v6_addr {
            let segments = ipv6.segments();
            // Try to get a reasonable IPv6 subnet
            let subnet = format!(
                "{:x}:{:x}:{:x}:{:x}::/64",
                segments[0], segments[1], segments[2], segments[3]
            );

            if let Ok(net) = subnet.parse::<Ipv6Net>() {
                ranges.push(ScanRange {
                    network: ScanNetwork::V6(net),
                    priority: 5, // Lower priority since IPv6 is less common
                });
            }
        }

        // Sort ranges by priority (lower number = higher priority)
        ranges.sort_by_key(|range| range.priority);

        Ok(ranges)
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
                                    // This might be a valid peer - check with a full TCP connection
                                    if TcpStream::connect(addr).await.is_ok() {
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

        let futures: Vec<_> = addrs
            .into_iter()
            .map(|addr| timeout(Duration::from_secs(5), self.request_peer_list(addr)))
            .collect();
        for peer_list in join_all(futures)
            .await
            .into_iter()
            .filter_map(|res| res.ok().and_then(|inner| inner.ok()))
        {
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

        // Keep libp2p swarm events flowing only when a swarm was initialized.
        if self.p2p_swarm.lock().await.is_some() {
            let p2p_node = self.clone();
            tokio::spawn(async move {
                loop {
                    if let Err(e) = p2p_node.handle_p2p_events().await {
                        warn!("P2P event pump cycle failed: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    } else {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            });
        }

        // Create message processing channel
        let (msg_tx, mut msg_rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        let node = self.clone();

        // Start connection handler for incoming connections
        if let Some(listener) = &self.listener {
            let listener_clone = Arc::clone(listener);
            let node_clone = node.clone();
            let msg_tx_clone = msg_tx.clone();

            tokio::spawn(async move {
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

                                    // Configure TCP socket
                                    if let Err(e) = stream.set_nodelay(true) {
                                        warn!("Failed to set TCP_NODELAY for {}: {}", addr, e);
                                        continue;
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
                            warn!("Connection limiter error: {}", e);
                            sleep(Duration::from_millis(200)).await;
                        }
                    }
                }
            });
        } else {
            info!("No listener configured - node will not accept incoming connections");
        }

        // Start network maintenance in the background
        let node_clone = node.clone();
        tokio::spawn(async move {
            let mut maintenance_interval = interval(Duration::from_secs(MAINTENANCE_INTERVAL));

            loop {
                maintenance_interval.tick().await;

                if let Err(e) = node_clone.maintain_peer_connections().await {
                    warn!("Peer maintenance error: {}", e);
                }
                node_clone.cleanup_outbound_connections().await;
                node_clone.prune_runtime_maps().await;
                node_clone.prune_validation_cache();
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

        // Periodic announce to discovery service
        let node_clone = node.clone();
        tokio::spawn(async move {
            let mut announce_interval =
                interval(Duration::from_secs(Self::announce_interval_secs()));
            loop {
                announce_interval.tick().await;
                if let Err(e) = node_clone.ensure_public_tip_relayed().await {
                    debug!("Public relay tip refresh failed: {}", e);
                }
                if let Err(e) = node_clone.announce_to_discovery().await {
                    debug!("Announce error: {}", e);
                }
            }
        });

        // Periodic header snapshot submissions
        if Self::public_header_snapshots_enabled() {
            let node_clone = node.clone();
            tokio::spawn(async move {
                let mut header_interval =
                    interval(Duration::from_secs(Self::header_snapshot_interval_secs()));
                loop {
                    header_interval.tick().await;
                    if let Err(e) = node_clone.post_header_snapshot().await {
                        debug!("Header snapshot error: {}", e);
                    }
                }
            });
        }

        // Event-driven tip beacon: the publisher pushes the tiny signed beacon on
        // EVERY tip change (append or reorg) by subscribing to the in-process
        // ChainTipSignal — no timer, per-block fresh — so a new block is visible
        // to every client within one edge-cached beacon poll.
        if Self::public_header_snapshots_enabled() {
            let node_clone = node.clone();
            tokio::spawn(async move {
                let mut rx = { node_clone.blockchain.read().await.subscribe_tip_changes() };
                // Heartbeat so the beacon never expires during idle (no mining): it
                // is re-posted on every tip change AND at least this often, keeping
                // the network's live tip visible to anyone who opens their client.
                let mut heartbeat = interval(Duration::from_secs(60));
                if let Err(e) = node_clone.post_tip_beacon().await {
                    debug!("Initial tip beacon post: {}", e);
                }
                loop {
                    tokio::select! {
                        changed = rx.changed() => {
                            if changed.is_err() {
                                break;
                            }
                        }
                        _ = heartbeat.tick() => {}
                    }
                    if let Err(e) = node_clone.post_tip_beacon().await {
                        debug!("Tip beacon post: {}", e);
                    }
                }
            });
        }

        // Periodic stats snapshot submissions (push)
        if Self::public_stats_snapshots_enabled() {
            let node_clone = node.clone();
            tokio::spawn(async move {
                let mut stats_interval =
                    interval(Duration::from_secs(Self::stats_snapshot_interval_secs()));
                loop {
                    stats_interval.tick().await;
                    if let Err(e) = node_clone.post_stats_snapshot().await {
                        debug!("Stats snapshot error: {}", e);
                    }
                }
            });
        }

        // Notice-only client-version check (all nodes). The first interval tick fires
        // immediately, giving a startup check, then repeats every VERSION_CHECK_INTERVAL_SECS.
        // Notice only — never auto-updates.
        {
            let node_clone = node.clone();
            tokio::spawn(async move {
                let mut version_check =
                    interval(Duration::from_secs(VERSION_CHECK_INTERVAL_SECS));
                loop {
                    version_check.tick().await;
                    node_clone.check_client_version_and_warn().await;
                }
            });
        }

        // Periodic peer cache persistence
        let node_clone = node.clone();
        tokio::spawn(async move {
            let mut cache_interval = interval(Duration::from_secs(120));
            loop {
                cache_interval.tick().await;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let peers: Vec<SocketAddr> = {
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
                if let Err(e) = node_clone.save_peer_cache(&peers) {
                    debug!("Peer cache save error: {}", e);
                }
            }
        });

        // Periodic backpressure metrics
        let metrics_node = node.clone();
        let metrics_tx = msg_tx.clone();
        tokio::spawn(async move {
            let mut metrics_interval = interval(Duration::from_secs(15));
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

        // Message processing loop
        let node_clone = node.clone();
        tokio::spawn(async move {
            while let Some(msg) = msg_rx.recv().await {
                if let Err(e) = node_clone.handle_network_event(msg).await {
                    error!("Error handling network event: {}", e);
                }
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

        // Periodic catch-up safety net: a behind or forked node must keep converging
        // to the network tip even if a live beacon-version tick was missed. Driven by
        // the signed beacon (NOT p2p, which is empty across NAT), so it runs in BOTH
        // interactive and headless modes and needs no peers. Cheap no-op at the tip.
        let node_clone = node.clone();
        tokio::spawn(async move {
            let mut sync_interval = interval(Duration::from_secs(20));
            sync_interval.tick().await; // consume immediate first tick
            loop {
                sync_interval.tick().await;
                let _ = node_clone.sync_to_beacon().await;
            }
        });

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
            let tick_secs = if is_publisher { 1 } else { BEACON_POLL_INTERVAL_SECS };
            let safety_secs = if is_publisher { 1 } else { 30 };
            tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(tick_secs));
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
                                    match node_clone.sync_full_history_from_peer().await {
                                        Converge::Converged
                                        | Converge::AtTipAhead
                                        | Converge::Progressed => {
                                            publisher_bootstrap_strikes = 0;
                                            info!("Publisher: recovered via peer full-history sync; not restarting");
                                        }
                                        _ => {
                                            warn!("Publisher: restarting to re-bootstrap onto the canonical chain");
                                            std::process::exit(0);
                                        }
                                    }
                                }
                            }
                        }
                    } else if let Some(b) = beacon {
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
                                // TIER 2: reconstruct the canonical chain from a seed peer
                                // (gateway-independent body acquisition) instead of relying
                                // solely on the gateway snapshot. No-op without a seed peer.
                                match node_clone.sync_full_history_from_peer().await {
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
                                debug!("Beacon branch failed local validation; awaiting next beacon");
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
            tokio::spawn(async move {
                let mut strikes: u32 = 0;
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    let chain_ok = timeout(Duration::from_secs(10), wd.blockchain.read())
                        .await
                        .is_ok();
                    let peers_ok = timeout(Duration::from_secs(10), wd.peers.read())
                        .await
                        .is_ok();
                    if chain_ok && peers_ok {
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
                            std::process::exit(0);
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
            });
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
        let mut swarm = swarm_guard
            .take()
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

        // Put the swarm back
        *swarm_guard = Some(swarm);

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
            if peers.is_empty() {
                0
            } else {
                peers.values().map(|p| p.latency).sum::<u64>() / peers.len() as u64
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
    async fn request_peer_list(&self, addr: SocketAddr) -> Result<Vec<SocketAddr>, NodeError> {
        let message = NetworkMessage::GetPeers;

        match self.send_message_with_response(addr, &message).await {
            Ok(NetworkMessage::Peers(peers)) => Ok(peers),
            Ok(_) => Err(NodeError::Network("Invalid response type".into())),
            Err(e) => Err(e),
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
            node_id: self.node_id.clone(),
        };

        // Send ping with timeout and expect pong
        let response = self.send_message_with_response(addr, &ping).await?;

        match response {
            NetworkMessage::Pong {
                timestamp,
                node_id: _,
            } => {
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
        if end.saturating_sub(start) + 1 > MAX_BATCH_SIZE {
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
                    Some(h) if h >= u32::MAX => break,
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
                        if block.index >= start
                            && block.index <= end
                            && block.calculate_hash_for_block() == block.hash
                        {
                            valid_blocks.push(block);
                        }
                    }
                    return Ok(valid_blocks);
                }
                Ok(_) => {
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
        let idle = Duration::from_secs(OUTBOUND_POOL_IDLE_SECS);
        let mut remove_addrs = Vec::new();

        for (addr, conn) in pool_snapshot {
            let conn_guard = conn.lock().await;
            if now.duration_since(conn_guard.last_used) > idle {
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
            let conn_guard = conn.lock().await;
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
                    RESPONSE_TIMEOUT,
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
                    RESPONSE_TIMEOUT,
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
            stream_guard.last_used = Instant::now();
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
        let block_hash = hex::encode(block.hash);

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

        // A block's CLAIMED hash (block.hash, attacker-controlled off the wire) must equal its COMPUTED
        // hash. If it lies, reject it WITHOUT negative-caching — the cache is keyed by the claimed hash,
        // so caching a false verdict under an attacker-chosen hash would let a garbage block suppress the
        // REAL block that legitimately has that hash (a low-cost valid-block censorship on every path).
        if block.calculate_hash_for_block() != block.hash {
            return Ok(false);
        }
        // Correct hash but PoW below floor -> definitively invalid; safe to negative-cache under its
        // OWN (now verified-correct) hash so replays short-circuit.
        if !block.verify_pow_meets_floor() {
            self.validation_cache.insert(
                block_hash,
                ValidationCacheEntry {
                    valid: false,
                    timestamp: SystemTime::now(),
                },
            );
            return Ok(false);
        }

        for tx in &block.transactions {
            if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                continue;
            }

            let mut full_tx = match self.resolve_full_tx_for_block(tx, peer).await? {
                Some(tx) => tx,
                None => return Ok(false),
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

            if full_tx.sig_hash.is_none() {
                if let Some(sig_hex) = &full_tx.signature {
                    let sig_bytes = hex::decode(sig_hex).map_err(|_| {
                        NodeError::InvalidTransaction("Invalid signature bytes".into())
                    })?;
                    full_tx.sig_hash = Some(Transaction::signature_hash_hex(&sig_bytes));
                }
            }

            if let Some(expected_hash) = &tx.sig_hash {
                if full_tx.sig_hash.as_ref() != Some(expected_hash) {
                    return Ok(false);
                }
            }

            let signature_ok = {
                let blockchain = self.blockchain.read().await;
                blockchain.verify_transaction_signature(&full_tx).is_ok()
            };

            if !signature_ok {
                return Ok(false);
            }
        }

        let mut validation_result = {
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

        if validation_result {
            if let Some(ref sentinel) = self.header_sentinel {
                // Header consensus is versioned by activation height:
                // - v1: enforce only when verifier context is mature
                // - v2+: enforce unconditionally from activation height
                if sentinel
                    .should_enforce_consensus_for_block(block.index)
                    .await
                {
                    if sentinel
                        .has_conflicting_verified_header(block.index, &block.hash)
                        .await
                    {
                        debug!(
                            "Rejecting block {} due to conflicting verified header at same height",
                            block.index
                        );
                        validation_result = false;
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
                                "Accepting block {} with pending BPoS verifier quorum; rejecting only proven header conflicts",
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
    ) -> Result<Option<Transaction>, NodeError> {
        let tx_id = tx.get_tx_id();
        // Defense-in-depth: only trust a cached witness whose id matches its key. An entry that doesn't
        // (a bogus TxResponse poison) is dropped so resolution falls through to the block's own
        // signature / mempool / peer fetch instead of censoring a valid block. Done under one lock.
        let cached = {
            let mut cache = self.tx_witness_cache.lock();
            match cache.get(&tx_id).cloned() {
                Some(c) if c.get_tx_id() == tx_id => Some(c),
                Some(_) => {
                    cache.pop(&tx_id);
                    None
                }
                None => None,
            }
        };
        if let Some(cached) = cached {
            return Ok(Some(cached));
        }

        if let Some(sig_hex) = &tx.signature {
            if !Self::is_signature_truncated(sig_hex) {
                self.tx_witness_cache.lock().put(tx_id.clone(), tx.clone());
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
                if !Self::is_signature_truncated(sig_hex) {
                    self.tx_witness_cache
                        .lock()
                        .put(tx_id.clone(), mempool_tx.clone());
                    return Ok(Some(mempool_tx));
                }
            }
        }

        if let Some(peer_addr) = peer {
            let fetched = self.request_tx_witness(peer_addr, &tx_id).await?;
            if let Some(ref full_tx) = fetched {
                self.tx_witness_cache
                    .lock()
                    .put(tx_id.clone(), full_tx.clone());
            }
            return Ok(fetched);
        }

        Ok(None)
    }

    fn is_signature_truncated(sig_hex: &str) -> bool {
        match hex::decode(sig_hex) {
            Ok(bytes) => bytes.len() <= 64,
            Err(_) => true,
        }
    }

    async fn request_tx_witness(
        &self,
        addr: SocketAddr,
        tx_id: &str,
    ) -> Result<Option<Transaction>, NodeError> {
        let request = NetworkMessage::TxRequest {
            tx_id: tx_id.to_string(),
        };
        match tokio::time::timeout(
            Duration::from_secs(3),
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

    fn is_validation_cache_entry_fresh(entry: &ValidationCacheEntry, now: SystemTime) -> bool {
        now.duration_since(entry.timestamp)
            .map(|age| age.as_secs() < VALIDATION_CACHE_TTL_SECS)
            .unwrap_or(false)
    }

    fn prune_validation_cache_entries(
        cache: &DashMap<String, ValidationCacheEntry>,
        now: SystemTime,
        ttl_secs: u64,
        max_entries: usize,
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

        let len = cache.len();
        if len <= max_entries {
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
        entries.sort_unstable_by_key(|(_, timestamp)| *timestamp);

        for (key, _) in entries.into_iter().take(len.saturating_sub(max_entries)) {
            cache.remove(&key);
        }
    }

    fn prune_validation_cache(&self) {
        Self::prune_validation_cache_entries(
            &self.validation_cache,
            SystemTime::now(),
            VALIDATION_CACHE_TTL_SECS,
            VALIDATION_CACHE_MAX_ENTRIES,
        );
    }

    fn maybe_prune_validation_cache(&self) {
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

        // Rate limit check
        let rate_key = format!("send_to_{}", addr);
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
            stream_guard.last_used = Instant::now();
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
                if !self.network_bloom.insert(&tx_bytes) {
                    return Ok(());
                }

                // Validate transaction before adding
                if self.validate_transaction(&tx, None).await? {
                    // Add to blockchain
                    {
                        let blockchain = self.blockchain.write().await;
                        blockchain.add_transaction(tx.clone()).await?;
                    }

                    #[cfg(feature = "webrtc_mesh")]
                    self.mesh_gossip(&NetworkMessage::Transaction(tx.clone())).await;

                    // Broadcast to subset of peers. SNAPSHOT-THEN-DROP before sending:
                    // this held the peers READ guard across per-peer TCP sends — one
                    // stalled socket parked the guard indefinitely and (fair RwLock)
                    // wedged every later peers-lock user. The SECOND wedge of
                    // 2026-07-08, caught live by the lock watchdog (peers_ok=false)
                    // on a client that had just gossiped transactions.
                    let selected_peers = {
                        let peers = self.peers.read().await;
                        self.select_broadcast_peers(&peers, peers.len().min(8))
                    };
                    for &addr in &selected_peers {
                        match tokio::time::timeout(
                            Duration::from_secs(5),
                            self.send_message(addr, &NetworkMessage::Transaction(tx.clone())),
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
            }

            NetworkEvent::NewBlock(block) => {
                // Deduplicate blocks using bloom filter
                let block_hash = block.calculate_hash_for_block();
                if !self.network_bloom.insert(&block_hash) {
                    return Ok(());
                }

                // Verify block before processing
                if self.verify_block_parallel(&block).await? {
                    // Save block to blockchain
                    self.blockchain.write().await.save_block(&block).await?;

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
                                .broadcast_block(Arc::new(block.clone()), None, selected_peers)
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
                        // Traditional broadcast method
                        let peers = self.peers.read().await;
                        let selected_peers =
                            self.select_broadcast_peers(&peers, peers.len().min(16));
                        drop(peers);
                        if let Err(e) = self
                            .broadcast_block(Arc::new(block.clone()), None, selected_peers)
                            .await
                        {
                            warn!("Failed to broadcast block to selected peers: {}", e);
                        }
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

                // Clear from validation cache
                let peer_key = format!("peer_{}", addr);
                self.validation_cache.remove(&peer_key);

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
                                    bytes +=
                                        codec::serialize(&block).map(|v| v.len()).unwrap_or(0);
                                    if bytes > MAX_MESSAGE_SIZE - 64 * 1024 {
                                        break 'serve;
                                    }
                                    out.push(block);
                                }
                            }
                        }
                        idx = chunk_end.saturating_add(1);
                        tokio::task::yield_now().await;
                    }
                    out
                };

                // Send response through dedicated channel
                {
                    let mut channel_guard = response_channel.lock().await;
                    if let Some(sender) = channel_guard.take() {
                        if sender.send(blocks.clone()).is_err() {
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
                    if block.calculate_hash_for_block() != block.hash || !block.verify_pow_meets_floor() {
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

    async fn handle_peer_message(
        &self,
        data: &[u8],
        addr: SocketAddr,
        tx: &mpsc::Sender<NetworkEvent>,
    ) -> Result<Option<NetworkMessage>, NodeError> {
        if data.len() > MAX_MESSAGE_SIZE {
            self.record_peer_failure(addr).await;
            return Err(NodeError::Network("Message too large".into()));
        }

        // Deserialize message
        let message: NetworkMessage = match codec::deserialize(data) {
            Ok(msg) => msg,
            Err(_) => {
                self.record_peer_failure(addr).await;
                return Err(NodeError::Network("Invalid message format".into()));
            }
        };

        // Deduplicate gossip only. Requests/responses must always be processed, otherwise one
        // peer's GetBlocks/Ping/TxRequest can suppress another peer's identical request.
        if Self::should_dedup_message(&message) {
            let message_hash = blake3::hash(data);
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

            NetworkMessage::TxResponse { tx_id, tx } => {
                if let Some(ref full_tx) = tx {
                    // Only cache a witness whose id actually matches its key. An unsolicited/bogus
                    // TxResponse{tx_id:T, tx:<mismatched>} must NOT poison the witness cache — otherwise
                    // it would censor every valid block carrying tx T (resolve_full_tx_for_block reads
                    // this cache first). Downstream still verifies the signature, so this is liveness-only
                    // defense, but it closes a low-cost targeted valid-block censorship on all paths.
                    if full_tx.get_tx_id() == tx_id {
                        self.tx_witness_cache.lock().put(tx_id.clone(), full_tx.clone());
                    }
                }

                let sender = {
                    let mut channels = self.tx_response_channels.write().await;
                    channels.remove(&tx_id)
                };

                if let Some(sender) = sender {
                    let _ = sender.send(tx);
                }
            }

            NetworkMessage::Transaction(tx_data) => {
                let tx_ref = Arc::new(tx_data);
                let tx_hash = tx_ref.create_hash();

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

                    // Add to blockchain
                    let tx_added = {
                        let blockchain = self.blockchain.write().await;
                        blockchain.add_transaction((*tx_ref).clone()).await.is_ok()
                    };
                    if tx_added {
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

            NetworkMessage::Block(block) => {
                let block_ref = Arc::new(block);

                // Quick validation before processing
                if !block_ref.verify_pow_meets_floor() {
                    self.record_peer_failure(addr).await;
                    return Err(NodeError::Network("Invalid block proof of work".into()));
                }
                let block_hash = block_ref.calculate_hash_for_block();
                if !self.network_bloom.insert(&block_hash) {
                    return Ok(None);
                }

                // Verify and propagate block
                if self
                    .verify_block_with_witness(&block_ref, Some(addr))
                    .await?
                {
                    // Save block to blockchain
                    self.blockchain.write().await.save_block(&block_ref).await?;
                    self.publish_discovery_state("Accepted block").await;

                    // Send network event
                    tx.send(NetworkEvent::NewBlock((*block_ref).clone()))
                        .await
                        .map_err(|e| {
                            NodeError::Network(format!("Failed to send block event: {}", e))
                        })?;

                    // Broadcast block to peers
                    let peers = self.peers.read().await;
                    let selected_peers = self.select_broadcast_peers(&peers, peers.len().min(16));
                    drop(peers);

                    if let Err(e) = self
                        .broadcast_block(Arc::clone(&block_ref), Some(addr), selected_peers)
                        .await
                    {
                        warn!("Failed to propagate block to selected peers: {}", e);
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
                        warn!("GetBlocks [{}..{}] response timed out internally", start, end);
                    }
                }
            }

            NetworkMessage::Blocks(blocks) => {
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
                            if !self.rate_limiter.check_limit(&format!("shred_range:{}", addr)) {
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
                                        bytes += codec::serialize(&block)
                                            .map(|v| v.len())
                                            .unwrap_or(0);
                                        if bytes > MAX_MESSAGE_SIZE - 64 * 1024 {
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

            NetworkMessage::Ping {
                timestamp,
                node_id: _node_id,
            } => {
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
                    node_id: self.node_id.clone(),
                }));
            }

            NetworkMessage::Pong {
                timestamp,
                node_id: _,
            } => {
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
            Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"),
            Err(_) => true,
        }
    }

    /// Peer node_ids from the gateway directory — who to dial into the mesh (signaling is keyed by
    /// node_id). Reuses the same /api/peers the TCP discovery already reads.
    #[cfg(feature = "webrtc_mesh")]
    async fn fetch_mesh_peer_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = Vec::new();
        for url in Self::discovery_peers_urls() {
            if let Ok(res) = self.http_client.get(&url).send().await {
                if let Ok(body) = res.json::<DiscoveryResponse>().await {
                    if body.ok {
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
        ids.sort();
        ids.dedup();
        ids
    }

    /// Build + spawn the WebRTC mesh (opt-in via ALPHANUMERIC_WEBRTC_MESH): signaling poll, topology
    /// dialer, and inbound processor. The node's own handshake key gives the mesh its real identity,
    /// so the gateway accepts its signaling exactly like its announce.
    #[cfg(feature = "webrtc_mesh")]
    fn spawn_webrtc_mesh(&self) {
        use crate::a9::webrtc::{
            build_api, default_stun_urls, HttpSignalTransport, SignalTransport, WebRtcMesh,
        };
        const MESH_DEGREE: usize = 12;
        if !Self::webrtc_mesh_enabled() {
            return;
        }
        let gateway_base = Self::discovery_bases().into_iter().next().unwrap_or_default();
        let transport: Arc<dyn SignalTransport> =
            match HttpSignalTransport::new(self.handshake_key_bytes.as_ref().clone(), gateway_base) {
                Ok(t) => Arc::new(t),
                Err(e) => {
                    warn!("WebRTC mesh: transport init failed: {}", e);
                    return;
                }
            };
        let api = match build_api(false) {
            Ok(a) => Arc::new(a),
            Err(e) => {
                warn!("WebRTC mesh: API init failed: {}", e);
                return;
            }
        };
        let (mesh, mut inbound_rx) = match WebRtcMesh::new(transport, api, default_stun_urls()) {
            Ok(x) => x,
            Err(e) => {
                warn!("WebRTC mesh: init failed: {}", e);
                return;
            }
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
                        warn!("WebRTC mesh disabled by gateway kill switch — shutting the mesh down");
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
                    let ids = node.fetch_mesh_peer_ids().await;
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
            let mesh_seen: Arc<PLMutex<LruCache<String, ()>>> =
                Arc::new(PLMutex::new(LruCache::new(NonZeroUsize::new(8192).unwrap())));
            tokio::spawn(async move {
                while let Some((_peer, bytes)) = inbound_rx.recv().await {
                    node.handle_mesh_message(bytes, &mesh_seen).await;
                }
            });
        }
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
    async fn handle_mesh_message(&self, bytes: Vec<u8>, mesh_seen: &Arc<PLMutex<LruCache<String, ()>>>) {
        let msg: NetworkMessage = match codec::deserialize(&bytes) {
            Ok(m) => m,
            Err(_) => return,
        };
        match msg {
            NetworkMessage::Block(b) => {
                let hash = hex::encode(b.calculate_hash_for_block());
                {
                    let mut seen = mesh_seen.lock();
                    if seen.get(&hash).is_some() {
                        return; // mesh-local dedup: replay or gossip loop
                    }
                    seen.put(hash, ());
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
            if let Ok(bytes) = codec::serialize(&NetworkMessage::Block(block.clone())) {
                tokio::spawn(async move {
                    let _ = mesh.broadcast(&bytes).await;
                });
            }
        }
    }

    async fn broadcast_block(
        &self,
        block: Arc<Block>,
        source: Option<SocketAddr>,
        peers: Vec<SocketAddr>,
    ) -> Result<usize, NodeError> {
        // Flood the block over the WebRTC mesh in parallel to TCP (covers mined + relayed blocks;
        // all broadcast_block callers). No-op unless the mesh feature is on and up.
        #[cfg(feature = "webrtc_mesh")]
        self.mesh_gossip_block(block.as_ref()).await;
        let targets: Vec<_> = peers
            .into_iter()
            .filter(|addr| Some(*addr) != source)
            .collect();
        if targets.is_empty() {
            return Ok(0);
        }

        const MAX_CONCURRENT: usize = 10;
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));

        let broadcast_futures = targets.into_iter().map(|peer| {
            let block = Arc::clone(&block);
            let permit = semaphore.clone().acquire_owned();
            let node = self.clone();

            async move {
                let result = async {
                    let _permit = permit.await.map_err(|e| {
                        NodeError::Network(format!("Broadcast semaphore acquisition failed: {}", e))
                    })?;
                    node.send_message(peer, &NetworkMessage::Block((*block).clone()))
                        .await
                }
                .await;
                (peer, result)
            }
        });

        let results: Vec<(SocketAddr, Result<(), NodeError>)> =
            futures::future::join_all(broadcast_futures).await;
        let delivered = results.iter().filter(|(_, result)| result.is_ok()).count();
        for (peer, result) in &results {
            if let Err(e) = result {
                warn!("Failed to broadcast block to {}: {}", peer, e);
            }
        }

        if delivered > 0 {
            Ok(delivered)
        } else if let Some((_, Err(first_error))) =
            results.into_iter().find(|(_, result)| result.is_err())
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
            if now.saturating_sub(entry.1) > INBOUND_ATTEMPT_WINDOW {
                *entry = (0, now);
            }
            entry.0 = entry.0.saturating_add(1);
            entry.1 = now;
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

        // Notify peer join
        tx.send(NetworkEvent::PeerJoin(peer_addr))
            .await
            .map_err(|e| NodeError::Network(format!("Failed to send join event: {}", e)))?;

        // Message handling loop
        let (mut reader, mut writer) = tokio::io::split(stream);

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
                    let message: NetworkMessage =
                        match self.decrypt_message(data_to_process, &shared_secret) {
                            Ok(data) => data,
                            Err(e) => {
                                warn!("Decryption failed from {}: {}", peer_addr, e);
                                self.record_peer_failure(peer_addr).await;
                                break 'connection;
                            }
                        };

                    // Serialize the message for handle_peer_message dedup/rate tracking.
                    let serialized_message = codec::serialize(&message)?;

                    // Process message
                    let response = match self
                        .handle_peer_message(&serialized_message, peer_addr, &tx)
                        .await
                    {
                        Ok(response) => response,
                        Err(e) => {
                            warn!("Message handling error from {}: {}", peer_addr, e);

                            // Check if error suggests malicious behavior
                            match &e {
                                NodeError::Network(msg)
                                    if msg.contains("Rate limit")
                                        || msg.contains("too large")
                                        || msg.contains("Invalid") =>
                                {
                                    self.record_peer_failure(peer_addr).await;
                                }
                                _ => {}
                            }

                            // Continue for transient errors
                            if !matches!(e, NodeError::Network(msg) if msg.contains("Rate limit")) {
                                continue;
                            }

                            break 'connection;
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

        // Notify disconnect
        tx.send(NetworkEvent::PeerLeave(peer_addr))
            .await
            .map_err(|e| NodeError::Network(format!("Failed to send leave event: {}", e)))?;

        Ok(())
    }

    async fn monitor_peer_connection(&self, addr: SocketAddr) -> Result<(), NodeError> {
        const PING_INTERVAL: Duration = Duration::from_secs(30);
        const MAX_FAILURES: u32 = 3;

        let mut interval = tokio::time::interval(PING_INTERVAL);
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
            node_id: self.node_id.clone(),
        };

        // Send ping with timeout and consume the direct pong response on the same stream.
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            self.send_message_with_response(addr, &ping),
        )
        .await
        .map_err(|_| NodeError::Network("Ping timeout".to_string()))??;

        match response {
            NetworkMessage::Pong { timestamp, .. } => {
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

    /// Next GetBlocks span [start, end], bounded so (end - start) < MAX_GETBLOCKS_SPAN (the
    /// server ingress cap) and `end` never exceeds the fixed target height.
    fn full_sync_next_span(cursor: u32, target: u32) -> (u32, u32) {
        let end = cursor
            .saturating_add(MAX_GETBLOCKS_SPAN.saturating_sub(1))
            .min(target);
        (cursor, end)
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
    pub async fn sync_full_history_from_peer(&self) -> Converge {
        // STEP 0: trusted anchor = the signed tip beacon (the SAME canonical (height,hash)
        // converge_to_canonical already trusts). No beacon -> no anchor -> caller falls through.
        let Some(beacon) = self.fetch_tip_beacon().await else {
            return Converge::BeaconStale;
        };

        // STEP 1: choose ONE seed peer at least as tall as the beacon. Target is ALWAYS the
        // beacon height, never the peer's self-reported height.
        let mut chosen: Option<SocketAddr> = None;
        'seed: for seed in self.configured_seed_nodes().to_vec() {
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

        // STEP 3: bulk-pull [local_tip+1 .. target] ascending, applying each block through the
        // SAME ingest path as every other source. The checkpoint is NOT advanced here (Step 4).
        let mut cursor = { self.blockchain.read().await.get_latest_block_index() as u32 }
            .saturating_add(1);
        loop {
            if cursor > target {
                break;
            }
            let (start, end) = Self::full_sync_next_span(cursor, target);
            let Ok(blocks) = self.request_blocks(peer, start, end).await else {
                break;
            };
            let mut candidates: Vec<_> = blocks
                .into_iter()
                .filter(|b| {
                    b.index >= start
                        && b.index <= end
                        && b.calculate_hash_for_block() == b.hash
                        && b.verify_pow_meets_floor()
                })
                .collect();
            candidates.sort_by_key(|b| b.index);

            let before_tip = { self.blockchain.read().await.get_latest_block_index() as u32 };
            let floor = { self.blockchain.read().await.verification_floor() };
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
    pub async fn sync_with_network(&self) -> Result<(), NodeError> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY_MS: u64 = 1000;
        const PEER_TIMEOUT_MS: u64 = 5000;
        const MAX_BATCH_SIZE: u32 = 50; // More reasonable batch size

        // 1. Get current blockchain state
        let current_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_latest_block_index() as u32
        };

        // 2. Check peer count and discover if needed
        let peers = self.peers.read().await;
        let peer_count = peers.len();

        if peer_count == 0 {
            drop(peers); // Release lock before discovery
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
                                .filter(|block| {
                                    block.index >= start
                                        && block.index <= end
                                        && block.calculate_hash_for_block() == block.hash
                                        && block.verify_pow_meets_floor()
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
                                let verify_from = {
                                    self.blockchain.read().await.verification_floor()
                                }
                                .saturating_add(1);
                                for block in candidate_blocks {
                                    let before = {
                                        self.blockchain.read().await.get_latest_block_index()
                                            as u32
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
                            start = current_sync_height + 1;
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
            self.sync_with_block_relay(current_height)
                .await
                .map(|_| ())
                .map_err(|relay_err| {
                    NodeError::Network(format!(
                        "Failed to sync any blocks from peers and relay sync failed: {}",
                        relay_err
                    ))
                })
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

        // Deserialize message
        Ok(codec::deserialize(decrypted)?)
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

impl Drop for Node {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&*self.lock_path);
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

        Node::prune_validation_cache_entries(&cache, now, 3_600, 3);

        assert!(cache.get("expired").is_none());
        assert_eq!(cache.len(), 3);
        assert!(cache.get("fresh-0").is_some());
        assert!(cache.get("fresh-1").is_some());
        assert!(cache.get("fresh-2").is_some());
        assert!(cache.get("fresh-3").is_none());
        assert!(cache.get("fresh-4").is_none());
    }

    #[test]
    fn network_dedup_applies_only_to_gossip_messages() {
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
}
