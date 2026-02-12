use arrayref::array_ref;
use axum::{extract::State, routing::get, Json, Router};
use bytes::{BufMut, BytesMut};
use dashmap::DashMap;
use futures_util::{
    future::{join_all, Either},
    stream::{FuturesUnordered, StreamExt},
    TryFutureExt,
};
use ipnet::{Ipv4Net, Ipv6Net};
use libp2p::{
    core::{
        connection::ConnectedPoint, muxing::StreamMuxerBox, transport::upgrade, upgrade::Version,
    },
    identity,
    kad::{
        handler::{KademliaHandler, KademliaHandlerIn},
        record::store::MemoryStore,
        store::RecordStore,
        Kademlia, KademliaConfig, KademliaEvent, QueryId, QueryResult,
    },
    noise,
    swarm::{
        derive_prelude::*, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, FromSwarm,
        IntoConnectionHandler, NetworkBehaviour, PollParameters, Swarm, SwarmBuilder, SwarmEvent,
        ToSwarm,
    },
    yamux, Multiaddr, PeerId, Transport,
};
use log::{debug, error, info, trace, warn};
use parking_lot::{Mutex as PLMutex, RwLock as PLRwLock};
use rand::{seq::SliceRandom, thread_rng, Rng};
use reqwest::Client;
use igd_next::{search_gateway, PortMappingProtocol};
use ring::{
    aead, hkdf,
    rand::SecureRandom,
    signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sled::Db;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet, VecDeque},
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
    task::Poll,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{broadcast, mpsc, oneshot, Mutex, RwLock, Semaphore},
    time::{interval, sleep, timeout},
};
use lru::LruCache;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, FromRawSocket};

use crate::a9::blockchain::{
    Block, Blockchain, BlockchainError, RateLimiter, Transaction, SYSTEM_ADDRESSES,
};
use crate::a9::bpos::{BlockHeaderInfo, HeaderSentinel, NetworkHealth};
use crate::a9::mempool::TemporalVerification;
use crate::a9::oracle::DifficultyOracle;
use crate::a9::velocity::{Shred, ShredRequest, ShredRequestType, VelocityError, VelocityManager};
use crate::a9::wallet::Wallet;

//----------------------------------------------------------------------
// Constants
//----------------------------------------------------------------------

// Network parameters
pub const DEFAULT_PORT: u16 = 7177;
const MIN_PEERS: usize = 3;
const MAX_PEERS: usize = 128;
const MAX_PEERS_PER_SUBNET: usize = 3;
const SUBNET_MASK_IPV4: u8 = 24; // /24 subnet
const SUBNET_MASK_IPV6: u8 = 64; // /64 subnet

// Timeouts and intervals
const PEER_TIMEOUT: u64 = 300; // seconds
const MAINTENANCE_INTERVAL: u64 = 60; // 1 minute
const ANNOUNCE_INTERVAL: u64 = 60; // seconds
const HEADER_SNAPSHOT_INTERVAL: u64 = 60; // seconds
const DISCOVERY_HTTP_TIMEOUT_MS: u64 = 3000;
const DEFAULT_DISCOVERY_BASE: &str = "https://alphanumeric.blue";
const DEFAULT_DNS_SEEDS: &[&str] = &[
    "seed.alphanumeric.network:7177",
    "seed2.alphanumeric.network:7177",
    "a9seed.mynode.network:7177",
];
const MAX_INBOUND_ATTEMPTS_PER_IP: u32 = 5;
const INBOUND_ATTEMPT_WINDOW: u64 = 60; // seconds

// Protocol
const NETWORK_VERSION: u32 = 1;
const CONSENSUS_THRESHOLD: f64 = 0.67; // 2/3 majority for BFT
const MAX_SHRED_SIZE: usize = 2048; // 2KB max shred size
const MAX_BLOCK_SIZE: usize = 2000;

// Resource limits
const MAX_PARALLEL_VALIDATIONS: usize = 200;
const EVENT_QUEUE_CAPACITY: usize = 1000;
const EVENT_QUEUE_WARN_THRESHOLD: usize = 800;
const EVENT_BROADCAST_CAPACITY: usize = 1000;
pub const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024; // 32MB
const OUTBOUND_POOL_IDLE_SECS: u64 = 90;
const OUTBOUND_POOL_MAX_FACTOR: usize = 2;
const OUTBOUND_CIRCUIT_FAILURE_THRESHOLD: u32 = 3;
const OUTBOUND_CIRCUIT_OPEN_SECS: u64 = 30;
const BLOOM_FILTER_SIZE: usize = 100_000;
const BLOOM_FILTER_FPR: f64 = 0.01;
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

impl From<Box<bincode::ErrorKind>> for NodeError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        NodeError::Serialization(format!("Bincode error: {}", err))
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
    fn new() -> Self {
        Self {
            data: [0u8; 16],
            len: 0,
        }
    }

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

                for i in (full_bytes + 1)..4 {
                    data[i] = 0;
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

                for i in (full_bytes + 1)..16 {
                    data[i] = 0;
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
        let subnet_group = match addr.ip() {
            IpAddr::V4(_) => SubnetGroup::from_ip(addr.ip(), SUBNET_MASK_IPV4, 0),
            IpAddr::V6(_) => SubnetGroup::from_ip(addr.ip(), 0, SUBNET_MASK_IPV6),
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
    items_count: AtomicUsize,
}

impl NetworkBloom {
    pub fn new(size: usize, fpr: f64) -> Self {
        let num_hashes = Self::optimal_num_hashes(size, fpr);
        let bits = (0..size).map(|_| AtomicBool::new(false)).collect();

        Self {
            bits,
            num_hashes,
            size,
            items_count: AtomicUsize::new(0),
        }
    }

    pub fn insert(&self, item: &[u8]) -> bool {
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

    fn optimal_num_hashes(size: usize, fpr: f64) -> usize {
        ((size as f64) * fpr.ln() / (-2f64).ln()).round() as usize
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

impl NetworkBehaviour for HybridBehaviour {
    type ConnectionHandler = KademliaHandler<QueryId>;
    type OutEvent = HybridBehaviourEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        self.kademlia.new_handler()
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        self.kademlia.addresses_of_peer(peer_id)
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_, Self::ConnectionHandler>) {
        self.kademlia.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: <KademliaHandler<QueryId> as ConnectionHandler>::OutEvent,
    ) {
        self.kademlia
            .on_connection_handler_event(peer_id, connection_id, event);
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
        params: &mut impl PollParameters,
    ) -> Poll<ToSwarm<Self::OutEvent, KademliaHandlerIn<QueryId>>> {
        match self.kademlia.poll(cx, params) {
            Poll::Ready(ToSwarm::GenerateEvent(event)) => Poll::Ready(ToSwarm::GenerateEvent(
                HybridBehaviourEvent::Kademlia(event),
            )),
            Poll::Ready(ToSwarm::NotifyHandler {
                peer_id,
                handler,
                event,
            }) => Poll::Ready(ToSwarm::NotifyHandler {
                peer_id,
                handler,
                event,
            }),
            Poll::Ready(ToSwarm::CloseConnection {
                peer_id,
                connection,
            }) => Poll::Ready(ToSwarm::CloseConnection {
                peer_id,
                connection,
            }),
            Poll::Ready(ToSwarm::Dial { opts }) => Poll::Ready(ToSwarm::Dial { opts }),
            Poll::Ready(ToSwarm::ReportObservedAddr { address, score }) => {
                Poll::Ready(ToSwarm::ReportObservedAddr { address, score })
            }
            Poll::Pending => Poll::Pending,
        }
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

unsafe impl Send for HybridSwarm {}
unsafe impl Sync for HybridSwarm {}

//----------------------------------------------------------------------
// TcpNatConfig
//----------------------------------------------------------------------

#[derive(Clone)]
pub struct TcpNatConfig {
    external_port: u16,
    supports_upnp: bool,
    supports_nat_pmp: bool,
    connect_timeout: Duration,
    mapping_lifetime: Duration,
    max_retries: u32,
}

//----------------------------------------------------------------------
// Node Implementation
//----------------------------------------------------------------------

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
    p2p_swarm: Arc<RwLock<Option<HybridSwarm>>>,
    peer_id: String,
    inbound_attempts: Arc<RwLock<HashMap<IpAddr, (u32, u64)>>>,
    peer_cache_path: Arc<String>,

    // Consensus state
    tx_response_channels: Arc<RwLock<HashMap<String, oneshot::Sender<Option<Transaction>>>>>,
    tx_witness_cache: Arc<PLMutex<LruCache<String, Transaction>>>,
    pub validation_pool: Arc<ValidationPool>,
    validation_cache: Arc<DashMap<String, ValidationCacheEntry>>,
    tx: broadcast::Sender<NetworkEvent>,

    // Feature components
    pub temporal_verification: Arc<TemporalVerification>,
    pub header_sentinel: Option<Arc<HeaderSentinel>>,
    pub velocity_manager: Option<Arc<VelocityManager>>,

    // Security
    network_id: [u8; 32],
    handshake_public_key: Vec<u8>,
    handshake_key_bytes: Arc<Vec<u8>>,

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
    pub verification_count: u32,
}

#[derive(Debug)]
struct OutboundConnection {
    stream: TcpStream,
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
}

#[derive(Serialize)]
struct StatsResponse {
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ConsensusMessage {
    PrepareRequest(Block),
    PrepareResponse(bool, String),
    CommitRequest(Block),
    CommitResponse(bool, String),
}

impl Node {
    //----------------------------------------------------------------------
    // Initialization
    //----------------------------------------------------------------------

    pub async fn new(
        db: Arc<Db>,
        blockchain: Arc<RwLock<Blockchain>>,
        handshake_key_bytes: Vec<u8>,
        bind_addr: Option<SocketAddr>,
        velocity_enabled: bool,
        max_peers: usize,
        max_connections: usize,
    ) -> Result<Self, NodeError> {
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
                if let Ok(pid) = content.parse::<u32>() {
                    #[cfg(unix)]
                    {
                        use nix::sys::signal;
                        use nix::unistd::Pid;
                        if signal::kill(Pid::from_raw(pid as i32), None).is_ok() {
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

        let velocity_manager = if velocity_enabled {
            let vm = Arc::new(VelocityManager::new());
            vm.clone().start_request_processor();
            Some(vm)
        } else {
            None
        };

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
            tx_response_channels: Arc::new(RwLock::new(HashMap::with_capacity(2000))),
            tx_witness_cache: Arc::new(PLMutex::new(LruCache::new(witness_cache_capacity))),
            network_bloom: Arc::new(NetworkBloom::new(BLOOM_FILTER_SIZE, BLOOM_FILTER_FPR)),
            rate_limiter: Arc::new(RateLimiter::new(60, 100)),
            bind_addr,
            listener,
            p2p_swarm: Arc::new(RwLock::new(None)),
            http_client,
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
            inbound_attempts: Arc::new(RwLock::new(HashMap::new())),
            peer_cache_path: Arc::new(peer_cache_path),
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
                #[cfg(unix)]
                socket.set_reuse_port(true)?;
                socket.set_nodelay(true)?;

                info!("Attempting to bind to address: {}", addr);
                socket.bind(&addr.into())?;
                socket.listen(1024)?;

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
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
        socket.set_nodelay(true)?;

        // Bind to all interfaces (0.0.0.0) with default port
        let primary_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), DEFAULT_PORT);
        info!("Attempting to bind to all interfaces: {}", primary_addr);

        socket.bind(&primary_addr.into())?;
        socket.listen(1024)?;
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
        Ok(bincode::serialize(&msg)?)
    }

    fn sign_handshake(&self, message: &HandshakeMessage) -> Result<Vec<u8>, NodeError> {
        let keypair = Ed25519KeyPair::from_pkcs8(&self.handshake_key_bytes)
            .map_err(|_| NodeError::Network("Invalid handshake key bytes".into()))?;
        let payload = Self::handshake_payload(message)?;
        Ok(keypair.sign(&payload).as_ref().to_vec())
    }

    fn verify_handshake(&self, message: &HandshakeMessage) -> Result<(), NodeError> {
        if message.public_key.len() != 32 || message.signature.len() != 64 {
            return Err(NodeError::Network("Invalid handshake key/signature length".into()));
        }
        let payload = Self::handshake_payload(message)?;
        let public_key = UnparsedPublicKey::new(&ED25519, &message.public_key);
        public_key
            .verify(&payload, &message.signature)
            .map_err(|_| NodeError::Network("Invalid handshake signature".into()))
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

    fn dns_seeds() -> Vec<&'static str> {
        let override_seeds = std::env::var("ALPHANUMERIC_DNS_SEEDS").ok();
        if let Some(seeds) = override_seeds {
            let parsed: Vec<String> = seeds
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            // Store in leaked static to satisfy lifetime; minimal footprint.
            if !parsed.is_empty() {
                let leaked: Vec<&'static str> = parsed
                    .into_iter()
                    .map(|s| Box::leak(s.into_boxed_str()) as &'static str)
                    .collect();
                return leaked;
            }
        }
        DEFAULT_DNS_SEEDS.to_vec()
    }

    fn discovery_bases() -> Vec<String> {
        let bases = std::env::var("ALPHANUMERIC_DISCOVERY_BASES")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if !bases.is_empty() {
            return bases;
        }

        vec![std::env::var("ALPHANUMERIC_DISCOVERY_BASE").unwrap_or_else(|_| {
            DEFAULT_DISCOVERY_BASE.to_string()
        })]
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

    async fn get_external_ip(&self) -> Option<IpAddr> {
        // Prefer a concrete bind address if available
        let ip = self.bind_addr.ip();
        if !ip.is_unspecified() && !ip.is_loopback() {
            return Some(ip);
        }

        if let Ok((v4, _v6)) = self.discover_external_addresses(STUN_SERVERS).await {
            if let Some(ip) = v4 {
                return Some(ip);
            }
        }

        None
    }

    fn is_private_ip(addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(ip) => {
                ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()
            }
            IpAddr::V6(ip) => {
                ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local()
            }
        }
    }

    async fn fetch_discovery_peers(&self) -> Result<Vec<SocketAddr>, NodeError> {
        let mut all_addrs = Vec::new();
        let mut any_ok = false;

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
                if let Ok(ip) = peer.ip.parse::<IpAddr>() {
                    all_addrs.push(SocketAddr::new(ip, peer.port));
                }
            }
        }

        if !any_ok {
            return Err(NodeError::Network("Discovery fetch failed".into()));
        }

        Ok(all_addrs)
    }

    async fn connect_discovery_peers(&self, limit: usize) -> Result<(), NodeError> {
        let mut addrs = self.fetch_discovery_peers().await?;
        addrs.retain(|addr| *addr != self.bind_addr);
        addrs.shuffle(&mut thread_rng());

        let mut connected = 0usize;
        for addr in addrs.into_iter().take(limit) {
            match timeout(Duration::from_secs(5), self.verify_peer(addr)).await {
                Ok(Ok(_)) => {
                    connected += 1;
                }
                _ => {}
            }
        }

        if connected > 0 {
            info!("Connected to {} peer(s) via discovery service", connected);
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
        let list: Vec<String> = peers.iter().map(|p| p.to_string()).collect();
        let data = serde_json::to_string(&list)
            .map_err(|e| NodeError::Serialization(format!("Peer cache error: {}", e)))?;
        std::fs::write(&tmp_path, data)
            .map_err(|e| NodeError::Io(format!("Peer cache write error: {}", e)))?;
        let _ = std::fs::rename(&tmp_path, path);
        Ok(())
    }

    fn score_peer_for_cache(peer: &PeerInfo, now: u64) -> f64 {
        let age = now.saturating_sub(peer.last_seen) as f64;
        let latency = peer.latency as f64;
        let height = peer.blocks as f64;
        // Higher is better
        height * 0.002 - age * 0.02 - latency * 0.005
    }

    async fn announce_to_discovery(&self) -> Result<(), NodeError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

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

        let height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_block_count() as u32
        };

        let stats_enabled = std::env::var("ALPHANUMERIC_STATS_ENABLED")
            .map(|v| v.to_lowercase() != "false")
            .unwrap_or(true);
        let stats_port: Option<u16> = if stats_enabled {
            std::env::var("ALPHANUMERIC_STATS_PORT")
                .ok()
                .and_then(|p| p.parse::<u16>().ok())
                .or(Some(8787))
        } else {
            None
        };

        let message = json!({
            "ip": ip.clone().unwrap_or_default(),
            "port": self.bind_addr.port(),
            "node_id": &self.node_id,
            "public_key": &self.node_id,
            "version": format!("rust-{}", NETWORK_VERSION),
            "height": height,
            "last_seen": now,
            "latency_ms": 0,
            "stats_port": stats_port
        });

        let canonical = Self::canonical_json_string(&message)?;
        let keypair = Ed25519KeyPair::from_pkcs8(&self.handshake_key_bytes)
            .map_err(|_| NodeError::Network("Invalid handshake key bytes".into()))?;
        let signature = keypair.sign(canonical.as_bytes());

        let payload = json!({
            "ip": ip.unwrap_or_default(),
            "port": self.bind_addr.port(),
            "node_id": &self.node_id,
            "public_key": &self.node_id,
            "version": format!("rust-{}", NETWORK_VERSION),
            "height": height,
            "last_seen": now,
            "latency_ms": 0,
            "stats_port": stats_port,
            "signature": hex::encode(signature.as_ref())
        });

        let mut any_ok = false;
        for url in Self::discovery_announce_urls() {
            let res = self.http_client.post(url).json(&payload).send().await;
            match res {
                Ok(res) if res.status().is_success() => any_ok = true,
                Ok(res) => warn!("Discovery announce failed: {}", res.status()),
                Err(e) => warn!("Discovery announce error: {}", e),
            }
        }

        if !any_ok {
            warn!("Discovery announce failed on all endpoints");
        }

        Ok(())
    }

    async fn post_header_snapshot(&self) -> Result<(), NodeError> {
        let blockchain = self.blockchain.read().await;
        let last_block = match blockchain.get_last_block() {
            Some(b) => b,
            None => return Ok(()),
        };
        let height = last_block.index;

        let start = height.saturating_sub(20);
        let mut headers = Vec::new();
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

        let message = json!({
            "height": height,
            "network_id": hex::encode(self.network_id),
            "last_block_time": last_block_time,
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
                Ok(res) => warn!("Header snapshot post failed: {}", res.status()),
                Err(e) => warn!("Header snapshot error: {}", e),
            }
        }

        if !any_ok {
            warn!("Header snapshot post failed on all endpoints");
        }

        Ok(())
    }

    async fn post_stats_snapshot(&self) -> Result<(), NodeError> {
        let height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_block_count() as u32
        };

        let last_block_time = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_last_block().map(|b| b.timestamp).unwrap_or(0)
        };

        let difficulty = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_current_difficulty().await
        };

        let hashrate_ths = {
            let blockchain = self.blockchain.read().await;
            blockchain.calculate_network_hashrate().await
        };
        let hashrate_ths_str = format!("{:.6}", hashrate_ths);

        let peers = self.peers.read().await.len() as u32;
        let uptime_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.start_time);

        let message = json!({
            "node_id": &self.node_id,
            "public_key": &self.node_id,
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
                Ok(res) => warn!("Stats snapshot post failed: {}", res.status()),
                Err(e) => warn!("Stats snapshot error: {}", e),
            }
        }

        if !any_ok {
            warn!("Stats snapshot post failed on all endpoints");
        }

        Ok(())
    }

    async fn stats_handler(State(state): State<StatsState>) -> Json<StatsResponse> {
        let height = {
            let blockchain = state.blockchain.read().await;
            blockchain.get_block_count() as u32
        };

        let last_block_time = {
            let blockchain = state.blockchain.read().await;
            blockchain.get_last_block().map(|b| b.timestamp).unwrap_or(0)
        };

        let difficulty = {
            let blockchain = state.blockchain.read().await;
            blockchain.get_current_difficulty().await
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
        let bind_ip = std::env::var("ALPHANUMERIC_STATS_BIND").unwrap_or_else(|_| "0.0.0.0".to_string());
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
        };

        let app = Router::new()
            .route("/stats", get(Self::stats_handler))
            .route("/health", get(Self::health_handler))
            .with_state(state);

        tokio::spawn(async move {
            if let Err(e) = axum::Server::bind(&addr)
                .serve(app.into_make_service())
                .await
            {
                error!("Stats server error: {}", e);
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
    info!("Starting network discovery");

    self.discover_network_nodes_with_retry(0).await
}

// Separate implementation for recursive calls with retry counter
async fn discover_network_nodes_with_retry(&self, retry_count: u32) -> Result<(), NodeError> {
    const MAX_DISCOVERY_RETRIES: u32 = 3;
    const MAX_TARGET_PEERS: usize = 32;
    const MIN_TARGET_PEERS: usize = 5;
    const VERIFY_BATCH_SIZE: usize = 24;
    const VERIFY_CONCURRENCY: usize = 12;

    let gateway_only = std::env::var("ALPHANUMERIC_DISCOVERY_GATEWAY_ONLY")
        .map(|v| v.to_lowercase() != "false")
        .unwrap_or(true);
    let enable_dns_fallback = std::env::var("ALPHANUMERIC_DISCOVERY_ENABLE_DNS_FALLBACK")
        .map(|v| v.to_lowercase() != "false")
        .unwrap_or(true);
    let enable_kad_fallback = std::env::var("ALPHANUMERIC_DISCOVERY_ENABLE_KAD_FALLBACK")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false);
    let enable_aggressive_discovery = std::env::var("ALPHANUMERIC_ENABLE_AGGRESSIVE_DISCOVERY")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false);

    let mut discovered_addrs = HashSet::new();
    let mut verified_peers = Vec::new();

    let current_peers: HashSet<SocketAddr> = {
        let peers = self.peers.read().await;
        peers.keys().copied().collect()
    };

    let needs_more_peers = current_peers.len() < MIN_TARGET_PEERS;

    // Priority 1: alphanumeric.blue discovery service
    let mut gateway_ok = false;
    match self.fetch_discovery_peers().await {
        Ok(peer_addrs) => {
            gateway_ok = true;
            discovered_addrs.extend(peer_addrs);
            debug!("Discovery gateway provided {} candidate peers", discovered_addrs.len());
        }
        Err(e) => {
            warn!("Discovery gateway unavailable: {}", e);
        }
    }

    // Fallbacks are only used when gateway is unavailable, or explicitly allowed.
    let allow_fallback = !gateway_ok || !gateway_only;
    if allow_fallback {
        discovered_addrs.extend(self.load_peer_cache());

        if !current_peers.is_empty() {
            if let Ok(peer_addrs) = self.discover_from_existing_peers().await {
                discovered_addrs.extend(peer_addrs);
            }
        }

        if enable_dns_fallback {
            for seed in Self::dns_seeds() {
                match tokio::net::lookup_host(seed).await {
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

    // Heavy scan mode is strictly opt-in and only when connectivity is weak.
    if enable_aggressive_discovery && needs_more_peers && !gateway_ok {
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

    let mut new_addrs: Vec<_> = discovered_addrs
        .into_iter()
        .filter(|addr| *addr != self.bind_addr && !current_peers.contains(addr))
        .collect();

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
    new_addrs.truncate(MAX_TARGET_PEERS.saturating_mul(2));

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
                    match tokio::time::timeout(Duration::from_secs(5), node.verify_peer(addr)).await {
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

async fn discover_from_dns_seeds(&self) -> Result<HashSet<SocketAddr>, NodeError> {
    const DNS_SEEDS: &[&str] = &[
        "seed.alphanumeric.network",
        "seed2.alphanumeric.network",
        "a9seed.mynode.network",
    ];
    
    let mut discovered = HashSet::new();
    
    for &seed in DNS_SEEDS {
        match tokio::net::lookup_host(format!("{}:{}", seed, DEFAULT_PORT)).await {
            Ok(addrs) => {
                for addr in addrs {
                    discovered.insert(addr);
                }
            }
            Err(e) => {
                debug!("DNS lookup failed for {}: {}", seed, e);
            }
        }
    }
    
    Ok(discovered)
}

async fn discover_from_kademlia(&self) -> Result<HashSet<SocketAddr>, NodeError> {
    let mut discovered = HashSet::new();
    
    // Safely access the swarm without using addresses_of_peer
    let swarm_guard = self.p2p_swarm.read().await;
    if swarm_guard.is_none() {
        return Ok(discovered);
    }
    
    // Try to collect known peer addresses using safer methods
    if let Ok(_) = self.handle_p2p_events().await {
        // After handling events, extract any discovered addresses
        // from swarm's connected peers using direct access methods
        if let Some(swarm) = &*swarm_guard {
            // Get connected peers from the swarm
            for peer_id in swarm.0.connected_peers() {
                // Fixed: add .await here to properly await the future
                if let Ok(addrs) = self.get_peer_addresses_from_connections(&peer_id).await {
                    for addr in addrs {
                        discovered.insert(addr);
                    }
                }
            }
        }
    }
    
    Ok(discovered)
}

// Helper function to safely get peer addresses
async fn get_peer_addresses_from_connections(&self, _peer_id: &PeerId) -> Result<Vec<SocketAddr>, NodeError> {
    // Simple implementation that doesn't depend on addresses_of_peer
    let mut result = Vec::new();
    
    // If we have existing connections in peers map, use those
    let peers = self.peers.read().await;
    for (addr, _) in peers.iter() {
        result.push(*addr);
    }
    
    Ok(result)
}

async fn scan_range_with_limit(
    &self, 
    range: &ScanRange,
    semaphore: Arc<Semaphore>,
    limit: usize
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
                for i in 0..prefix_len {
                    segments[i] = net.addr().segments()[i];
                }
                
                // Randomize host part
                for i in prefix_len..8 {
                    segments[i] = rng.gen();
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
                match tokio::time::timeout(
                    Duration::from_millis(300), 
                    TcpStream::connect(addr)
                ).await {
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
            let subnet = info.subnet_group;
            
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
        ("24.0.0.0/8", 4),  // Comcast
        ("71.0.0.0/8", 4),  // AT&T
        ("73.0.0.0/8", 4),  // Verizon
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
                    for i in 0..prefix_len {
                        segments[i] = net.addr().segments()[i];
                    }

                    // Randomize host part
                    for i in prefix_len..8 {
                        segments[i] = rng.gen();
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
        let peers = self.peers.read().await;

        let mut futures = Vec::with_capacity(peers.len());
        for &addr in peers.keys() {
            futures.push(self.request_peer_list(addr));
        }

        for result in join_all(futures).await {
            if let Ok(peer_list) = result {
                discovered.extend(peer_list);
            }
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

        // Parse STUN response
        self.parse_stun_response(&buf[..size])
    }

    fn parse_stun_response(&self, data: &[u8]) -> Result<IpAddr, NodeError> {
        if data.len() < 20 {
            return Err(NodeError::Network("Invalid STUN response".into()));
        }

        let mut pos = 20;
        while pos + 4 <= data.len() {
            let attr_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
            let attr_len = ((data[pos + 2] as u16) << 8) | (data[pos + 3] as u16);

            if attr_type == 0x0020 || attr_type == 0x8020 {
                // XOR-MAPPED-ADDRESS
                if pos + 8 + attr_len as usize <= data.len() {
                    let ip_family = data[pos + 5];
                    if ip_family == 0x01 {
                        // IPv4
                        let xor_port = ((data[pos + 6] as u16) << 8) | (data[pos + 7] as u16);
                        let port = xor_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;

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

            pos += 4 + attr_len as usize;
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

        #[cfg(unix)]
        sock.set_reuse_port(true)?;

        // Set non-blocking to allow concurrent connections
        sock.set_nonblocking(true)?;

        // Configure keepalive
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(15));

        sock.set_tcp_keepalive(&keepalive)?;

        let enable_upnp = std::env::var("ALPHANUMERIC_ENABLE_UPNP")
            .map(|v| v.to_lowercase() != "false")
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
                    .add_port(PortMappingProtocol::TCP, port, socket, 3600, "alphanumeric node")
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
                    warn!("UPnP port mapping failed: {}", e);
                }
                Err(e) => {
                    warn!("UPnP mapping task failed: {}", e);
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

        // Initialize P2P services
        self.initialize_p2p().await?;

        // Start stats API (optional)
        if std::env::var("ALPHANUMERIC_STATS_ENABLED")
            .map(|v| v.to_lowercase() != "false")
            .unwrap_or(true)
        {
            if let Err(e) = self.start_stats_server().await {
                warn!("Stats server failed to start: {}", e);
            }
        }

        // Keep libp2p swarm events flowing for the lifetime of the node.
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
                                        let result = timeout(
                                            Duration::from_secs(30),
                                            node.handle_connection(stream, addr, tx),
                                        )
                                        .await;

                                        match result {
                                            Ok(Ok(_)) => {
                                                info!("Connection handler completed successfully for {}", addr);
                                            }
                                            Ok(Err(e)) => {
                                                warn!("Connection error from {}: {}", addr, e);
                                                node.record_peer_failure(addr).await;
                                            }
                                            Err(_) => {
                                                warn!("Connection handler timed out for {}", addr);
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
            warn!("No listener configured - node will not accept incoming connections");
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

                if node_clone.peers.read().await.len() < MIN_PEERS {
                    if let Err(e) = node_clone.discover_network_nodes().await {
                        warn!("Peer discovery error: {}", e);
                    }
                }
            }
        });

        // Initial discovery boost via serverless gateway
        let node_clone = node.clone();
        tokio::spawn(async move {
            sleep(Duration::from_secs(3)).await;
            if let Err(e) = node_clone.connect_discovery_peers(8).await {
                warn!("Discovery connect error: {}", e);
            }
        });

        // Periodic announce to discovery service
        let node_clone = node.clone();
        tokio::spawn(async move {
            let mut announce_interval = interval(Duration::from_secs(ANNOUNCE_INTERVAL));
            loop {
                announce_interval.tick().await;
                if let Err(e) = node_clone.announce_to_discovery().await {
                    debug!("Announce error: {}", e);
                }
            }
        });

        // Periodic header snapshot submissions
        let node_clone = node.clone();
        tokio::spawn(async move {
            let mut header_interval = interval(Duration::from_secs(HEADER_SNAPSHOT_INTERVAL));
            loop {
                header_interval.tick().await;
                if let Err(e) = node_clone.post_header_snapshot().await {
                    debug!("Header snapshot error: {}", e);
                }
            }
        });

        // Periodic stats snapshot submissions (push)
        let node_clone = node.clone();
        tokio::spawn(async move {
            let mut stats_interval = interval(Duration::from_secs(30));
            loop {
                stats_interval.tick().await;
                if let Err(e) = node_clone.post_stats_snapshot().await {
                    debug!("Stats snapshot error: {}", e);
                }
            }
        });

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
                    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
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
                warn!("Initial sync failed: {}", e);
            }
        });

        info!("Node startup complete - ready to accept connections");
        Ok(())
    }

async fn initialize_p2p(&self) -> Result<(), NodeError> {
    use libp2p::core::transport::Transport;
    use libp2p::core::upgrade;
    use std::time::Duration;
    
    // Generate new identity key
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    info!("Generated peer ID: {}", local_peer_id);
    
    // Setup transport with noise for encryption
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&local_key)
        .map_err(|e| NodeError::Network(format!("Noise key generation failed: {}", e)))?;
    
    // Use the appropriate approach for libp2p 0.51.4
    let transport = {
        // Try to detect if we're using tokio runtime (should be the case)
        #[cfg(feature = "tcp")]
        let tcp_config = libp2p::tcp::GenTcpConfig::default().nodelay(true);
        
        // Attempt to use a more direct method to create TCP transport
        #[cfg(feature = "tcp")]
        let transport = {
            // First attempt - should work for most tokio-enabled builds
            let transport = match libp2p::tcp::TokioTcpTransport::new(tcp_config) {
                Ok(t) => t,
                Err(e) => {
                    warn!("Could not create TCP transport: {}", e);
                    warn!("Falling back to memory transport. Only in-process communication will work.");
                    libp2p::core::transport::MemoryTransport::default()
                }
            };
            
            transport
                .upgrade(upgrade::Version::V1)
                .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
                .multiplex(yamux::Config::default())
                .timeout(Duration::from_secs(20))
                .boxed()
        };
        
        // Fallback if tcp feature is not available
        #[cfg(not(feature = "tcp"))]
        let transport = {
            warn!("TCP feature not enabled. Using memory transport (in-process only).");
            libp2p::core::transport::MemoryTransport::default()
                .upgrade(upgrade::Version::V1)
                .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
                .multiplex(yamux::Config::default())
                .timeout(Duration::from_secs(20))
                .boxed()
        };
        
        transport
    };
    
    // Configure Kademlia DHT
    let mut cfg = KademliaConfig::default();
    if let Some(parallelism) = NonZeroUsize::new(32) {
        cfg.set_parallelism(parallelism);
    }
    cfg.set_query_timeout(Duration::from_secs(60));
    let store = MemoryStore::new(local_peer_id);
    let mut kademlia = Kademlia::with_config(local_peer_id, store, cfg);
    
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
    
    // Initialize behavior and swarm with the correct executor
    let behaviour = HybridBehaviour { kademlia };
    
    // Use without_executor for the older version of libp2p - this is the safest option
    let mut swarm = SwarmBuilder::without_executor(transport, behaviour, local_peer_id).build();
    
    // Start listening on appropriate address
    #[cfg(feature = "tcp")]
    let listen_addr = "/ip4/0.0.0.0/tcp/0";
    
    #[cfg(not(feature = "tcp"))]
    let listen_addr = "/memory/0";
    
    if let Ok(addr) = listen_addr.parse() {
        match swarm.listen_on(addr) {
            Ok(id) => {
                info!("P2P listening started successfully (id: {:?})", id);
                
                #[cfg(feature = "tcp")]
                info!("P2P listening started on TCP transport");
                
                #[cfg(not(feature = "tcp"))]
                info!("P2P listening started on memory transport (in-process only)");
            }
            Err(e) => return Err(NodeError::Network(format!("Failed to listen: {}", e))),
        }
    }
    
    // Store swarm
    *self.p2p_swarm.write().await = Some(HybridSwarm(swarm));
    
    Ok(())
}

    async fn handle_p2p_events(&self) -> Result<(), NodeError> {
        // Use explicit import to avoid ambiguity
        use futures_util::StreamExt;
        use libp2p::swarm::SwarmEvent;

        let mut swarm_guard = self.p2p_swarm.write().await;
        let mut swarm = swarm_guard
            .take()
            .ok_or_else(|| NodeError::Network("Swarm not initialized".to_string()))?;

        let event_count_limit = 200;
        let mut event_count = 0;

        // Create a temporary future to drive the swarm
        let mut swarm_future = Box::pin(async move {
            loop {
                if event_count >= event_count_limit {
                    return (swarm, Ok(()));
                }

                // Use select_next_some() instead of next_event()
                match swarm.select_next_some().await {
                    SwarmEvent::Behaviour(HybridBehaviourEvent::Kademlia(event)) => {
                        match event {
                            KademliaEvent::OutboundQueryProgressed { result, .. } => {
                                if let QueryResult::GetClosestPeers(Ok(closest_peers)) = result {
                                    // Process closest peers
                                    debug!("Found {} closest peers", closest_peers.peers.len());
                                }
                            }
                            _ => {}
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("P2P listening on {:?}", address);
                    }
                    _ => {}
                }

                event_count += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        // Run the future with timeout
        let (swarm_result, result) = tokio::time::timeout(Duration::from_secs(30), swarm_future)
            .await
            .map_err(|_| NodeError::Timeout("P2P event processing timeout".to_string()))?;

        // Put the swarm back
        *swarm_guard = Some(swarm_result);

        // Return the result
        result
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
    let mut inactive_peers = 0;
    let mut high_latency_peers = 0;
    let mut peers_to_check = Vec::new();
    let mut peers_to_remove = Vec::new();
    
    // Identify peers that need health checks
    {
        let peers = self.peers.read().await;
        
        // Gather peer info first
        let peer_info: Vec<(SocketAddr, u64, u64)> = peers.iter()
            .map(|(addr, info)| (*addr, info.last_seen, info.latency))
            .collect();
            
        // Now analyze without holding the lock
        for (addr, last_seen, latency) in peer_info {
            let inactive_time = now.saturating_sub(last_seen);
            
            if inactive_time > PEER_TIMEOUT_SECS {
                inactive_peers += 1;
                peers_to_remove.push(addr);
            } else if inactive_time > PING_INTERVAL_SECS {
                // Needs a health check
                peers_to_check.push(addr);
            } else {
                active_peers += 1;
                
                // Track latency
                if latency > MAX_PING_LATENCY {
                    high_latency_peers += 1;
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
    let health_check_batch = peers_to_check.into_iter()
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
        debug!("Low peer count ({}), initiating discovery", current_peer_count);
        
        // Spawn discovery as a separate task to avoid blocking maintenance
        tokio::spawn({
            let node = self.clone();
            async move {
                if let Err(e) = node.discover_network_nodes().await {
                    warn!("Peer discovery during maintenance failed: {}", e);
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
    
    // IMPROVEMENT: Update network health metrics
    {
        let mut network_health = self.network_health.write().await;
        // Fix the type issue - use proper type for active_nodes
        network_health.active_nodes = active_peers;  // Assuming active_peers is already a usize
        
        network_health.average_response_time = {
            let peers = self.peers.read().await;
            if peers.is_empty() {
                0
            } else {
                peers.values().map(|p| p.latency).sum::<u64>() / peers.len() as u64
            }
        };
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
                let score = info.latency as i64 - 
                           (info.blocks as i64) + 
                           (now.saturating_sub(info.last_seen) as i64) / 60;
                
                // Fixed: Don't double-dereference the address
                peer_ratings.push((*addr, score));
            }
            
            // Sort by score (lower is better)
            peer_ratings.sort_by_key(|&(_, score)| score);
            
            // Keep the best max_per_subnet, remove the rest
            let excess_count = count - max_per_subnet;
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
            Ok(NetworkMessage::BlockHeight(height)) => Ok(height),
            Ok(_) => Err(NodeError::Network("Invalid response type".into())),
            Err(e) => Err(e),
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

        const MAX_BATCH_SIZE: u32 = 500; // Limit batch size to avoid timeouts
        const MAX_RETRIES: u32 = 3;

        // Batch large requests so peers with strict range limits can still serve us.
        if end.saturating_sub(start) + 1 > MAX_BATCH_SIZE {
            let mut all_blocks = Vec::new();
            let mut batch_start = start;
            while batch_start <= end {
                let batch_end = batch_start
                    .saturating_add(MAX_BATCH_SIZE - 1)
                    .min(end);
                let mut batch = self
                    .request_blocks_batch(addr, batch_start, batch_end, MAX_RETRIES)
                    .await?;
                all_blocks.append(&mut batch);
                if batch_end == u32::MAX {
                    break;
                }
                batch_start = batch_end.saturating_add(1);
            }
            all_blocks.sort_by_key(|b| b.index);
            all_blocks.dedup_by_key(|b| b.index);
            return Ok(all_blocks);
        }

        self.request_blocks_batch(addr, start, end, MAX_RETRIES).await
    }

    async fn request_blocks_batch(
        &self,
        addr: SocketAddr,
        start: u32,
        end: u32,
        max_retries: u32,
    ) -> Result<Vec<Block>, NodeError> {
        let message = NetworkMessage::GetBlocks { start, end };
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
            pool.iter().map(|(addr, conn)| (*addr, Arc::clone(conn))).collect()
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
            pool.iter().map(|(addr, conn)| (*addr, Arc::clone(conn))).collect()
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
        if let Some(existing) = self.outbound_connections.read().await.get(&addr).cloned() {
            return Ok(existing);
        }

        let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
            .await
            .map_err(|_| NodeError::Network(format!("Connection timeout to {}", addr)))??;
        stream.set_nodelay(true)?;

        let connection = Arc::new(Mutex::new(OutboundConnection {
            stream,
            last_used: Instant::now(),
        }));

        let max_pool_size = (self.max_connections.saturating_mul(OUTBOUND_POOL_MAX_FACTOR)).max(32);
        if self.outbound_connections.read().await.len() >= max_pool_size {
            self.evict_lru_outbound_connection().await;
        }

        {
            let mut pool = self.outbound_connections.write().await;
            if let Some(existing) = pool.get(&addr).cloned() {
                return Ok(existing);
            }
            if pool.len() >= max_pool_size {
                let eviction_key = pool.keys().copied().find(|peer| *peer != addr);
                if let Some(key) = eviction_key {
                    pool.remove(&key);
                }
            }
            pool.insert(addr, Arc::clone(&connection));
        }

        Ok(connection)
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

        // Encrypt message if we have a shared secret
        let shared_secret = self.peer_secrets.read().await.get(&addr).cloned();
        let data = if let Some(ref secret) = shared_secret {
            self.encrypt_message(message, &secret)?
        } else {
            bincode::serialize(message)?
        };
        if data.is_empty() {
            return Err(NodeError::Network("Refusing to send empty request".to_string()));
        }
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(NodeError::Network("Outgoing message too large".to_string()));
        }

        let mut last_error = None;
        for attempt in 0..MAX_ATTEMPTS {
            if let Err(e) = self.check_outbound_circuit(addr).await {
                return Err(e);
            }

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
                tokio::time::timeout(RESPONSE_TIMEOUT, stream_guard.stream.read_exact(&mut len_bytes))
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
                .map_err(|_| NodeError::Network(format!("Response data timeout from {}", addr)))??;

                let response = if let Some(ref secret) = shared_secret {
                    self.decrypt_message(&response_data, secret)?
                } else {
                    bincode::deserialize(&response_data)?
                };
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
        let block_hash = hex::encode(&block.hash);

        if let Some(entry) = self.validation_cache.get(&block_hash) {
            if SystemTime::now()
                .duration_since(entry.timestamp)
                .map_or(true, |d| d.as_secs() < 3600)
            {
                return Ok(entry.valid);
            }
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

        if block.calculate_hash_for_block() != block.hash || !block.verify_pow() {
            self.validation_cache.insert(
                block_hash,
                ValidationCacheEntry {
                    valid: false,
                    timestamp: SystemTime::now(),
                    verification_count: 1,
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
                    let sig_bytes = hex::decode(sig_hex)
                        .map_err(|_| NodeError::InvalidTransaction("Invalid signature bytes".into()))?;
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

        let validation_result = {
            let blockchain = self.blockchain.read().await;
            blockchain.validate_block(block).await.is_ok()
        };

        self.validation_cache.insert(
            block_hash,
            ValidationCacheEntry {
                valid: validation_result,
                timestamp: SystemTime::now(),
                verification_count: 1,
            },
        );

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
                    let _ = sentinel.verify_and_add_header(header_info, &node_id, Vec::new()).await;
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
        if let Some(cached) = self.tx_witness_cache.lock().get(&tx_id).cloned() {
            return Ok(Some(cached));
        }

        if let Some(sig_hex) = &tx.signature {
            if !Self::is_signature_truncated(sig_hex) {
                self.tx_witness_cache
                    .lock()
                    .put(tx_id.clone(), tx.clone());
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
        let (tx, rx) = oneshot::channel();
        {
            let mut channels = self.tx_response_channels.write().await;
            channels.insert(tx_id.to_string(), tx);
        }

        let send_result = self
            .send_message(
                addr,
                &NetworkMessage::TxRequest {
                    tx_id: tx_id.to_string(),
                },
            )
            .await;

        if let Err(e) = send_result {
            let mut channels = self.tx_response_channels.write().await;
            channels.remove(tx_id);
            return Err(e);
        }

        let result = tokio::time::timeout(Duration::from_secs(3), rx).await;
        let mut channels = self.tx_response_channels.write().await;
        channels.remove(tx_id);

        match result {
            Ok(Ok(tx_opt)) => Ok(tx_opt),
            _ => Ok(None),
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

        // Get shared secret if available
        let shared_secret = self.peer_secrets.read().await.get(&addr).cloned();

        // Serialize and optionally encrypt message
        let data = if let Some(ref secret) = shared_secret {
            self.encrypt_message(message, &secret)?
        } else {
            bincode::serialize(message)?
        };
        if data.is_empty() {
            return Err(NodeError::Network("Refusing to send empty message".to_string()));
        }
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(NodeError::Network("Outgoing message too large".to_string()));
        }

        let mut last_error = None;
        for attempt in 0..MAX_ATTEMPTS {
            if let Err(e) = self.check_outbound_circuit(addr).await {
                return Err(e);
            }

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
            let result: Result<(), NodeError> = tokio::time::timeout(TIMEOUT, async {
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
            .map_err(NodeError::from);
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
        NonZeroUsize::new(size).or_else(|| NonZeroUsize::new(default_size)).unwrap_or(NonZeroUsize::MIN)
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
            bincode::deserialize(&data)?
        };

        Ok(message)
    }

    pub async fn handle_network_event(&self, event: NetworkEvent) -> Result<(), NodeError> {
        match event {
            NetworkEvent::NewTransaction(tx) => {
                // Deduplicate transactions using bloom filter
                let tx_bytes = bincode::serialize(&tx)?;
                if !self.network_bloom.insert(&tx_bytes) {
                    return Ok(());
                }

                // Validate transaction before adding
                if self.validate_transaction(&tx, None).await? {
                    // Add to blockchain
                    let blockchain = self.blockchain.read().await;
                    blockchain.add_transaction(tx.clone()).await?;

                    // Broadcast to subset of peers
                    let peers = self.peers.read().await;
                    let selected_peers = self.select_broadcast_peers(&peers, peers.len().min(8));
                    for &addr in &selected_peers {
                        if let Err(e) = self
                            .send_message(addr, &NetworkMessage::Transaction(tx.clone()))
                            .await
                        {
                            warn!("Failed to broadcast transaction to {}: {}", addr, e);
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
                    self.blockchain.read().await.save_block(&block).await?;

                    // Broadcast to peers using velocity protocol if available
                    if let Some(velocity) = &self.velocity_manager {
                        let peers = self.peers.read().await;
                        let peer_map: std::collections::HashMap<SocketAddr, PeerInfo> = peers
                            .iter()
                            .map(|(&addr, info)| (addr, info.clone()))
                            .collect();
                        
                        // Try velocity protocol first for efficient block propagation
                        if let Err(e) = velocity.process_block(&block, &peer_map).await {
                            warn!("Velocity broadcast failed, falling back to traditional: {}", e);
                            
                            // Fallback to traditional broadcast
                            let selected_peers = self.select_broadcast_peers(&peers, peers.len().min(16));
                            for &addr in &selected_peers {
                                if let Err(e) = self
                                    .send_message(addr, &NetworkMessage::Block(block.clone()))
                                    .await
                                {
                                    warn!("Failed to broadcast block to {}: {}", addr, e);
                                }
                            }
                        }
                    } else {
                        // Traditional broadcast method
                        let peers = self.peers.read().await;
                        let selected_peers = self.select_broadcast_peers(&peers, peers.len().min(16));
                        for &addr in &selected_peers {
                            if let Err(e) = self
                                .send_message(addr, &NetworkMessage::Block(block.clone()))
                                .await
                            {
                                warn!("Failed to broadcast block to {}: {}", addr, e);
                            }
                        }
                    }
                }
            }

            NetworkEvent::PeerJoin(addr) => {
                // Add new peer only if not already present
                let should_monitor = {
                    let mut peers = self.peers.write().await;
                    if !peers.contains_key(&addr) {
                        peers.insert(addr, PeerInfo::new(addr));
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
                requester,
                response_channel,
            } => {
                let blocks = {
                    let blockchain = self.blockchain.read().await;
                    let mut validated_blocks = Vec::new();
                    for idx in start..=end {
                        if let Ok(block) = blockchain.get_block(idx) {
                            // Basic validation for response blocks
                            if block.verify_pow() && block.calculate_hash_for_block() == block.hash
                            {
                                validated_blocks.push(block);
                            }
                        }
                    }
                    validated_blocks
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

                // Also send through network message
                if let Some(_) = self.peers.read().await.get(&requester) {
                    let response = NetworkMessage::Blocks(blocks);
                    if let Err(e) = self.send_message(requester, &response).await {
                        warn!("Failed to send chain response to {}: {}", requester, e);
                    }
                }
            }

            NetworkEvent::ChainResponse { blocks, sender } => {
                for block in blocks {
                    if self.verify_block_with_witness(&block, Some(sender)).await? {
                        let blockchain = self.blockchain.read().await;
                        if let Err(e) = blockchain.save_block(&block).await {
                            warn!("Failed to save valid block {}: {}", block.index, e);
                        }
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
    ) -> Result<(), NodeError> {
        pub const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024; // 32MB

        if data.len() > MAX_MESSAGE_SIZE {
            self.record_peer_failure(addr).await;
            return Err(NodeError::Network("Message too large".into()));
        }

        // Deduplication using bloom filter
        let message_hash = blake3::hash(data);
        if !self.network_bloom.insert(message_hash.as_bytes()) {
            return Ok(());
        }

        // Deserialize message
        let message: NetworkMessage = match bincode::deserialize(data) {
            Ok(msg) => msg,
            Err(_) => {
                self.record_peer_failure(addr).await;
                return Err(NodeError::Network("Invalid message format".into()));
            }
        };

        // Rate limiting
        let rate_key = format!("peer_msg:{}:{:?}", addr, std::mem::discriminant(&message));
        if !self.rate_limiter.check_limit(&rate_key) {
            self.record_peer_failure(addr).await;
            return Err(NodeError::Network("Rate limit exceeded".into()));
        }

            match message {
                NetworkMessage::TxRequest { tx_id } => {
                    let tx_opt = self
                        .blockchain
                        .read()
                        .await
                        .get_mempool_transaction_by_id(&tx_id)
                        .await;

                    let response = NetworkMessage::TxResponse { tx_id, tx: tx_opt };
                    self.send_message(addr, &response).await?;
                }

                NetworkMessage::TxResponse { tx_id, tx } => {
                    if let Some(ref full_tx) = tx {
                        let mut cache = self.tx_witness_cache.lock();
                        cache.put(tx_id.clone(), full_tx.clone());
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
                if let Some(cached) = self.validation_cache.get(&tx_hash) {
                    if cached.valid {
                        // If previously validated, just broadcast
                        let peers = self.peers.read().await;
                        let selected_peers = self.select_broadcast_peers(&peers, 8);
                        drop(peers);
                        return self
                            .broadcast_transaction(tx_ref, addr, selected_peers)
                            .await;
                    }
                    return Ok(());
                }

                // Validate transaction
                let blockchain = self.blockchain.read().await;
                if blockchain.validate_transaction(&tx_ref, None).await.is_ok() {
                    // Update cache
                    self.validation_cache.insert(
                        tx_hash.clone(),
                        ValidationCacheEntry {
                            valid: true,
                            timestamp: SystemTime::now(),
                            verification_count: 1,
                        },
                    );

                    // Add to blockchain
                    if blockchain.add_transaction((*tx_ref).clone()).await.is_ok() {
                        // Broadcast to peers
                        let peers = self.peers.read().await;
                        let selected_peers = self.select_broadcast_peers(&peers, 8);
                        drop(peers);
                        drop(blockchain);

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
                if !block_ref.verify_pow() {
                    self.record_peer_failure(addr).await;
                    return Err(NodeError::Network("Invalid block proof of work".into()));
                }

                // Process through velocity manager if available
                if let Some(velocity) = &self.velocity_manager {
                    let peers = self.peers.read().await;
                    if velocity.process_block(&block_ref, &peers).await.is_ok() {
                        return Ok(());
                    }
                    drop(peers);
                }

                // Verify and propagate block
                if self.verify_block_with_witness(&block_ref, Some(addr)).await? {
                    // Save block to blockchain
                    self.blockchain.read().await.save_block(&block_ref).await?;

                    // Send network event
                    tx.send(NetworkEvent::NewBlock((*block_ref).clone()))
                        .await
                        .map_err(|e| {
                            NodeError::Network(format!("Failed to send block event: {}", e))
                        })?;

                    // Broadcast block to peers
                    let peers = self.peers.read().await;
                    let selected_peers = self.select_broadcast_peers(&peers, peers.len() / 2);
                    drop(peers);

                    for peer_addr in selected_peers {
                        if peer_addr != addr {
                            if let Err(e) = self
                                .send_message(
                                    peer_addr,
                                    &NetworkMessage::Block((*block_ref).clone()),
                                )
                                .await
                            {
                                warn!("Failed to propagate block to {}: {}", peer_addr, e);
                            }
                        }
                    }
                }
            }

            NetworkMessage::GetBlocks { start, end } => {
                // Validate request parameters
                if end.saturating_sub(start) > 1000 {
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

                // Wait for response and send to peer
                if let Ok(blocks) = response_rx.await {
                    self.send_message(addr, &NetworkMessage::Blocks(blocks))
                        .await?;
                }
            }

            NetworkMessage::Blocks(blocks) => {
                tx.send(NetworkEvent::ChainResponse { blocks, sender: addr })
                    .await
                    .map_err(|e| {
                        NodeError::Network(format!("Failed to send chain response event: {}", e))
                    })?;
            }

            NetworkMessage::GetBlockHeight => {
                let blockchain = self.blockchain.read().await;
                let height = blockchain.get_block_count() as u32;
                self.send_message(addr, &NetworkMessage::BlockHeight(height))
                    .await?;
            }

            NetworkMessage::GetPeers => {
                let peers = self.peers.read().await;
                let peer_addrs: Vec<_> = peers.keys().cloned().collect();
                self.send_message(addr, &NetworkMessage::Peers(peer_addrs))
                    .await?;
            }

            NetworkMessage::Shred(shred) => {
                if let Some(velocity) = &self.velocity_manager {
                    if let Ok(Some(block)) = velocity.handle_shred(shred, addr).await {
                        let block_ref = Arc::new(block);
                        if self.verify_block_with_witness(&block_ref, Some(addr)).await? {
                            self.blockchain.read().await.save_block(&block_ref).await?;
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
                            if end_height.saturating_sub(start_height) > 1000 {
                                return Err(NodeError::Network("Block range too large".into()));
                            }

                            let blockchain = self.blockchain.read().await;
                            let peers = self.peers.read().await;

                            // Move the loop inside to avoid keeping blockchain across await points
                            for height in start_height..=end_height {
                                // Get the block and clone it early to avoid Send issues
                                let block_clone = match blockchain.get_block(height) {
                                    Ok(block) => block.clone(),
                                    Err(e) => {
                                        warn!("Failed to get block {}: {}", height, e);
                                        continue;
                                    }
                                };

                                // Use Arc to share immutable data safely
                                let block_ref = Arc::new(block_clone);

                                if let Err(e) = velocity.process_block(&block_ref, &peers).await {
                                    warn!("Failed to process block {}: {}", height, e);
                                }
                            }
                        }
                    }
                }
            }

            NetworkMessage::ShredResponse { block_hash, shreds } => {
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
                // Respond to ping with pong
                let response = NetworkMessage::Pong {
                    timestamp,
                    node_id: self.node_id.clone(),
                };

                self.send_message(addr, &response).await?;

                // Update peer info
                let mut peers = self.peers.write().await;
                if let Some(info) = peers.get_mut(&addr) {
                    info.last_seen = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                }
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

            // Handle other message types with default implementation
            _ => {}
        }

        Ok(())
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
                    different_subnets.insert(subnet.clone());
                    *subnet_counts.entry(subnet.clone()).or_insert(0) += 1;

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

    async fn handle_connection(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
        tx: mpsc::Sender<NetworkEvent>,
    ) -> Result<(), NodeError> {
        // Rate limit handshake attempts per IP
        let rate_key = format!("handshake_{}", addr.ip());
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
            let entry = attempts.entry(addr.ip()).or_insert((0, now));
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

        // Reset inbound attempts on successful handshake
        {
            let mut attempts = self.inbound_attempts.write().await;
            attempts.remove(&addr.ip());
        }

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
            peers.insert(addr, peer_info.clone());
        }

        // Store encryption secret
        self.peer_secrets.write().await.insert(addr, shared_secret);

        // Notify peer join
        tx.send(NetworkEvent::PeerJoin(addr))
            .await
            .map_err(|e| NodeError::Network(format!("Failed to send join event: {}", e)))?;

        // Message handling loop
        let (mut reader, _writer) = tokio::io::split(stream);
        let mut buffer = BytesMut::with_capacity(64 * 1024);

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
                warn!("Empty message frame from {}", addr);
                self.record_peer_failure(addr).await;
                break;
            }
            if message_len > MAX_MESSAGE_SIZE {
                warn!("Oversized message from {}: {} bytes", addr, message_len);
                self.record_peer_failure(addr).await;
                break;
            }

            // Ensure buffer has enough capacity
            buffer.reserve(message_len);

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
                    // Extend buffer with the read data
                    buffer.put_slice(&data_buf);

                    // Get data to process
                    let data_to_process = buffer.split_to(message_len);

                    // Decrypt message if we have a shared secret - FIXED TYPE MISMATCH
                    let message: NetworkMessage =
                        if let Some(secret) = self.peer_secrets.read().await.get(&addr).cloned() {
                            match self.decrypt_message(&data_to_process, &secret) {
                                Ok(data) => data,
                                Err(e) => {
                                    warn!("Decryption failed from {}: {}", addr, e);
                                    break 'connection;
                                }
                            }
                        } else {
                            // Try to deserialize directly
                            match bincode::deserialize(&data_to_process) {
                                Ok(msg) => msg,
                                Err(_) => {
                                    // If all else fails, wrap in RawData
                                    NetworkMessage::RawData(data_to_process.to_vec())
                                }
                            }
                        };

                    // Serialize the message for handle_peer_message
                    let serialized_message = bincode::serialize(&message)?;

                    // Process message
                    if let Err(e) = self
                        .handle_peer_message(&serialized_message, addr, &tx)
                        .await
                    {
                        warn!("Message handling error from {}: {}", addr, e);

                        // Check if error suggests malicious behavior
                        match &e {
                            NodeError::Network(msg)
                                if msg.contains("Rate limit")
                                    || msg.contains("too large")
                                    || msg.contains("Invalid") =>
                            {
                                self.record_peer_failure(addr).await;
                            }
                            _ => {}
                        }

                        // Continue for transient errors
                        if !matches!(e, NodeError::Network(msg) if msg.contains("Rate limit")) {
                            continue;
                        }

                        break 'connection;
                    }

                    // Update peer timestamp
                    if let Some(peer) = self.peers.write().await.get_mut(&addr) {
                        peer.last_seen = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                    }
                }
                Ok(Err(e)) => {
                    warn!("Read error from {}: {}", addr, e);
                    break 'connection;
                }
                Err(_) => {
                    warn!("Read timeout from {}", addr);
                    break 'connection;
                }
            }
        }

        // Cleanup
        self.peers.write().await.remove(&addr);
        self.peer_secrets.write().await.remove(&addr);
        self.outbound_connections.write().await.remove(&addr);
        self.outbound_circuit_breakers.write().await.remove(&addr);

        // Notify disconnect
        tx.send(NetworkEvent::PeerLeave(addr))
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
        if let Err(_) = self.send_ping(addr).await {
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

        // Send ping with timeout
        tokio::time::timeout(Duration::from_secs(5), self.send_message(addr, &ping))
            .await
            .map_err(|_| NodeError::Network("Ping timeout".to_string()))??;

        Ok(())
    }

    // Method to convert Multiaddr to SocketAddr (needed for libp2p integration)
    fn multiaddr_to_socketaddr(&self, addr: &Multiaddr) -> Result<SocketAddr, NodeError> {
        use libp2p::core::multiaddr::Protocol;

        let components: Vec<_> = addr.iter().collect();

        match (components.get(0), components.get(1)) {
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
        match tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(addr)
        ).await {
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
                    "Connection timed out"
                ));
                // Exponential backoff
                if retry < CONNECTION_RETRIES - 1 {
                    tokio::time::sleep(Duration::from_millis(200 * (1 << retry))).await;
                }
            }
        }
    }
    
    let mut stream = match stream {
        Some(s) => s,
        None => {
            // Record failure for this peer
            self.record_peer_failure(addr).await;
            return Err(NodeError::Network(format!(
                "Failed to connect to {}: {}", 
                addr, 
                last_error.unwrap_or_else(|| std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    "Unknown error"
                ))
            )));
        }
    };
    
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
    
    // IMPROVEMENT: Perform handshake with better timeout handling
    let handshake_result = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        self.perform_handshake(&mut stream, true)
    ).await;
    
    let (peer_info, shared_secret) = match handshake_result {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            self.record_peer_failure(addr).await;
            return Err(NodeError::Network(format!(
                "Handshake failed with {}: {}", 
                addr, 
                e
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
            addr, 
            peer_info.version, 
            NETWORK_VERSION
        )));
    }
    
    // 3. Check for subnet limits
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
    
    // 4. Store peer information
    peers.insert(addr, peer_info);
    drop(peers);
    
    let mut peer_secrets = self.peer_secrets.write().await;
    peer_secrets.insert(addr, shared_secret);
    
    // Reset failure counter
    self.reset_peer_failures(addr).await;
    
    // IMPROVEMENT: Trigger initial latency measurement
    tokio::spawn({
        let node = self.clone();
        let addr = addr;
        async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let _ = node.send_ping(addr).await;
        }
    });
    
    Ok(())
}

    // Sync with network to keep blockchain updated
pub async fn sync_with_network(&self) -> Result<(), NodeError> {
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_MS: u64 = 1000;
    const PEER_TIMEOUT_MS: u64 = 5000;
    const MAX_BATCH_SIZE: u32 = 50;  // More reasonable batch size
    
    // 1. Get current blockchain state
    let current_height = {
        let blockchain = self.blockchain.read().await;
        blockchain.get_block_count() as u32
    };
    
    // 2. Check peer count and discover if needed
    let peers = self.peers.read().await;
    let peer_count = peers.len();
    
    if peer_count == 0 {
        drop(peers); // Release lock before discovery
        info!("No peers available, discovering network nodes");
        if let Err(e) = self.discover_network_nodes().await {
            warn!("Failed to discover peers for sync: {}", e);
            return Err(NodeError::Network("No peers available for sync".to_string()));
        }
    }
    
    // 3. IMPROVEMENT: Find multiple peers with highest block height
    // Get a fresh peer list after possible discovery
    let peers = self.peers.read().await;
    
    // IMPROVEMENT: Track peer heights with better error handling
    let mut peer_heights = Vec::new();
    let peer_ips: Vec<_> = peers.keys().cloned().collect();
    drop(peers);  // Release lock before making network requests
    
    // Query peer heights in parallel with better error handling
    let height_queries: Vec<_> = peer_ips
        .iter()
        .map(|&addr| {
            let node = self.clone();
            async move {
                match tokio::time::timeout(
                    Duration::from_millis(PEER_TIMEOUT_MS),
                    node.request_peer_height(addr)
                ).await {
                    Ok(Ok(height)) => Some((addr, height)),
                    _ => None,
                }
            }
        })
        .collect();
    
    // Gather results
    for result in futures::future::join_all(height_queries).await {
        if let Some(pair) = result {
            peer_heights.push(pair);
        }
    }
    
    // Sort by height descending
    peer_heights.sort_by_key(|(_, height)| std::cmp::Reverse(*height));
    
    // IMPROVEMENT: Check if we already have the latest blocks
    if let Some((_, best_height)) = peer_heights.first() {
        if *best_height <= current_height {
            info!("Already at best height ({}/{})", current_height, best_height);
            return Ok(());
        }
        
        info!("Syncing from height {} to {}", current_height, best_height);
    } else {
        warn!("No peers reported their height");
        return Err(NodeError::Network("No peers reported their height".to_string()));
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
            let mut start = current_sync_height;
            
            while start < *peer_height {
                let end = std::cmp::min(start + MAX_BATCH_SIZE, *peer_height);
                
                match self.request_blocks(*peer_addr, start, end).await {
                    Ok(blocks) => {
                        // IMPROVEMENT: Process blocks in parallel
                        let verification_tasks: Vec<_> = blocks
                            .iter()
                            .map(|block| {
                                let node = self.clone();
                                let block = block.clone();
                                let peer_addr = *peer_addr;
                                async move {
                                    if node
                                        .verify_block_with_witness(&block, Some(peer_addr))
                                        .await
                                        .unwrap_or(false)
                                    {
                                        Some(block)
                                    } else {
                                        None
                                    }
                                }
                            })
                            .collect();
                        
                        let verified_blocks: Vec<_> = futures::future::join_all(verification_tasks)
                            .await
                            .into_iter()
                            .filter_map(|result| result)
                            .collect();
                        
                        // Save verified blocks
                        let actual_count = verified_blocks.len();
                        if actual_count > 0 {
                            let blockchain = self.blockchain.read().await;
                            let mut saved_count = 0;
                            
                            for block in verified_blocks {
                                if let Err(e) = blockchain.save_block(&block).await {
                                    warn!("Failed to save block {}: {}", block.index, e);
                                } else {
                                    saved_count += 1;
                                    current_sync_height = current_sync_height.max(block.index);
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
                            start, 
                            end, 
                            peer_addr, 
                            e
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
            tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS * (sync_attempt as u64 + 1))).await;
        }
    }
    
    // 6. IMPROVEMENT: Report success even with partial progress
    if blocks_synced > 0 {
        info!("Blockchain synchronized: added {} blocks to height {}", blocks_synced, current_sync_height);
        Ok(())
    } else {
        Err(NodeError::Network("Failed to sync any blocks".to_string()))
    }
}

    async fn perform_handshake(
        &self,
        stream: &mut TcpStream,
        is_initiator: bool,
    ) -> Result<(PeerInfo, Vec<u8>), NodeError> {
        const MAX_HANDSHAKE_SIZE: usize = 1024;

        // Generate random nonce for this handshake
        let mut local_nonce = [0u8; 32];
        thread_rng().fill(&mut local_nonce);

        let blockchain_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_block_count() as u32
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create our handshake message
        let mut our_handshake = HandshakeMessage {
            version: NETWORK_VERSION,
            timestamp: now,
            nonce: local_nonce,
            public_key: self.handshake_public_key.clone(),
            node_id: self.node_id.clone(),
            network_id: self.network_id,
            blockchain_height,
            signature: Vec::new(), // Will sign below
        };
        our_handshake.signature = self.sign_handshake(&our_handshake)?;

        if is_initiator {
            // Send our handshake first
            let data = bincode::serialize(&our_handshake)?;
            if data.len() == 0 || data.len() > MAX_HANDSHAKE_SIZE {
                return Err(NodeError::Network("Invalid handshake size".into()));
            }
            stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
            stream.write_all(&data).await?;
            stream.flush().await?;

            // Read peer's handshake
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await?;
            let len = u32::from_be_bytes(len_bytes) as usize;

            if len == 0 || len > MAX_HANDSHAKE_SIZE {
                return Err(NodeError::Network("Handshake too large".into()));
            }

            let mut data = vec![0u8; len];
            stream.read_exact(&mut data).await?;

            let peer_handshake: HandshakeMessage = bincode::deserialize(&data)?;

            // Verify peer's handshake
            if peer_handshake.network_id != self.network_id {
                return Err(NodeError::Network("Network ID mismatch".into()));
            }
            self.verify_handshake(&peer_handshake)?;

            // Create and return PeerInfo
            let peer_info = PeerInfo {
                address: stream.peer_addr()?,
                version: peer_handshake.version,
                last_seen: now,
                blocks: peer_handshake.blockchain_height,
                latency: 0,
                subnet_group: SubnetGroup::from_ip(
                    stream.peer_addr()?.ip(),
                    SUBNET_MASK_IPV4,
                    SUBNET_MASK_IPV6,
                ),
            };

            // Derive shared secret
            let shared_secret = self.derive_shared_secret(&local_nonce, &peer_handshake.nonce)?;

            Ok((peer_info, shared_secret))
        } else {
            // Read peer's handshake first
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await?;
            let len = u32::from_be_bytes(len_bytes) as usize;

            if len == 0 || len > MAX_HANDSHAKE_SIZE {
                return Err(NodeError::Network("Handshake too large".into()));
            }

            let mut data = vec![0u8; len];
            stream.read_exact(&mut data).await?;

            let peer_handshake: HandshakeMessage = bincode::deserialize(&data)?;

            // Verify peer's handshake
            if peer_handshake.network_id != self.network_id {
                return Err(NodeError::Network("Network ID mismatch".into()));
            }
            self.verify_handshake(&peer_handshake)?;

            // Send our response
            let data = bincode::serialize(&our_handshake)?;
            if data.len() == 0 || data.len() > MAX_HANDSHAKE_SIZE {
                return Err(NodeError::Network("Invalid handshake size".into()));
            }
            stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
            stream.write_all(&data).await?;
            stream.flush().await?;

            // Create and return PeerInfo
            let peer_info = PeerInfo {
                address: stream.peer_addr()?,
                version: peer_handshake.version,
                last_seen: now,
                blocks: peer_handshake.blockchain_height,
                latency: 0,
                subnet_group: SubnetGroup::from_ip(
                    stream.peer_addr()?.ip(),
                    SUBNET_MASK_IPV4,
                    SUBNET_MASK_IPV6,
                ),
            };

            // Derive shared secret
            let shared_secret = self.derive_shared_secret(&local_nonce, &peer_handshake.nonce)?;

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
        let message_bytes = bincode::serialize(message)?;

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
        Ok(bincode::deserialize(decrypted)?)
    }

    // Method to derive shared secret for secure communication
    fn derive_shared_secret(
        &self,
        local_nonce: &[u8; 32],
        remote_nonce: &[u8; 32],
    ) -> Result<Vec<u8>, NodeError> {
        // Combine nonces deterministically
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(local_nonce);
        combined.extend_from_slice(remote_nonce);

        // Use HKDF to derive key material
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(&combined);

        // Derive 32-byte shared secret
        let mut shared_secret = [0u8; 32];
        prk.expand(&[b"blockchain_p2p"], ring::hkdf::HKDF_SHA256)
            .map_err(|_| NodeError::Network("Failed to derive shared secret".into()))?
            .fill(&mut shared_secret)
            .map_err(|_| NodeError::Network("Failed to fill shared secret".into()))?;

        Ok(shared_secret.to_vec())
    }
}

// Implementation to support other modules that reference these functions
impl From<&Node> for Node {
    fn from(node: &Node) -> Self {
        node.clone()
    }
}
