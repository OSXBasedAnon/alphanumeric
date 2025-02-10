use arrayref::array_ref;
use bytes::BytesMut;
use dashmap::DashMap;
use futures::{executor::block_on, future::join_all, StreamExt};
use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use libp2p::{
    core::upgrade,
    identity,
    kad::{
        record::store::MemoryStore, store::RecordStore, Kademlia, KademliaConfig, KademliaEvent,
        QueryResult,
    },
    noise,
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Transport,
};
use log::{error, info, warn};
use rand::Rng;
use rand::{seq::SliceRandom, thread_rng};
use rayon::iter::ParallelIterator;
use rayon::prelude::*;
use ring::rand::SecureRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sled::Db;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::hash_map::RandomState;
use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
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
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::error::Elapsed;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{broadcast, mpsc, oneshot, RwLock, Semaphore, SemaphorePermit},
    time::interval,
};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, FromRawSocket};

use crate::a9::blockchain::{Block, Blockchain, BlockchainError, RateLimiter, Transaction};
use crate::a9::bpos::{BlockHeaderInfo, HeaderSentinel, NetworkHealth};
use crate::a9::mempool::TemporalVerification;
use crate::a9::oracle::DifficultyOracle;
use crate::a9::velocity::{Shred, ShredRequest, ShredRequestType, VelocityError, VelocityManager};
use crate::a9::wallet::Wallet;

const MAX_PARALLEL_VALIDATIONS: usize = 200;
const CONSENSUS_THRESHOLD: f64 = 0.67; // 2/3 majority for BFT
const MAX_BLOCK_SIZE: usize = 2000;
const NETWORK_VERSION: u32 = 1;
const PING_INTERVAL: u64 = 30;
const PEER_TIMEOUT: u64 = 300;
const MIN_PEERS: usize = 3;
const MAX_PEERS: usize = 128;
pub const DEFAULT_PORT: u16 = 7177;

#[derive(Clone)]
pub struct TcpNatConfig {
    external_port: u16,
    supports_upnp: bool,
    supports_nat_pmp: bool,
    connect_timeout: Duration,
    mapping_lifetime: Duration,
    max_retries: u32,
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

#[derive(Debug, Clone)]
struct PeerHandshakeState {
    remote_nonce: [u8; 32],
    shared_secret: [u8; 32],
    timestamp: u64,
    last_seen: u64,
}

enum ScanNetwork {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

enum ScanResult {
    V4 { socket: Socket, addr: Ipv4Addr },
    V6 { socket: Socket, addr: Ipv6Addr },
}

struct ScanRange {
    network: ScanNetwork,
    priority: u8,
}

impl ScanRange {
    fn new(network: ScanNetwork, priority: u8) -> Self {
        Self { network, priority }
    }

    fn ips(&self) -> Box<dyn Iterator<Item = IpAddr> + Send> {
        match &self.network {
            ScanNetwork::V4(net) => Box::new(net.hosts().map(IpAddr::V4)),
            ScanNetwork::V6(net) => {
                // For IPv6, we sample addresses within the subnet
                let prefix_len = net.prefix_len();
                let base = net.addr().segments();

                Box::new((0..100).filter_map(move |_| {
                    let mut rng = thread_rng();
                    let mut addr = base;

                    // Randomize host portion
                    for i in (prefix_len as usize / 16)..8 {
                        addr[i] = rng.gen();
                    }

                    Some(IpAddr::V6(Ipv6Addr::from(addr)))
                }))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidationCacheEntry {
    pub valid: bool,
    pub timestamp: SystemTime,
    pub verification_count: u32,
}

#[derive(Debug)]
struct NetworkMetrics {
    peer_count: usize,
    message_latency: Duration,
    last_maintenance: Instant,
}

#[derive(Debug)]
pub enum NodeError {
    Network(String),
    Blockchain(String),
    Database(String),
    InvalidBlock(String),
    InvalidTransaction(String),
    ConsensusFailure(String),
    InvalidAddress(String),
    InvalidAddressFormat(String),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Network(msg) => write!(f, "Network error: {}", msg),
            NodeError::Blockchain(msg) => write!(f, "Blockchain error: {}", msg),
            NodeError::Database(msg) => write!(f, "Database error: {}", msg),
            NodeError::InvalidBlock(msg) => write!(f, "Invalid block: {}", msg),
            NodeError::InvalidTransaction(msg) => write!(f, "Invalid transaction: {}", msg),
            NodeError::ConsensusFailure(msg) => write!(f, "Consensus failure: {}", msg),
            NodeError::InvalidAddress(msg) => write!(f, "Invalid address: {}", msg),
            NodeError::InvalidAddressFormat(msg) => write!(f, "Invalid address format: {}", msg),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<Box<bincode::ErrorKind>> for NodeError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        NodeError::Network(format!("Serialization error: {}", err))
    }
}

impl From<Elapsed> for NodeError {
    fn from(err: Elapsed) -> Self {
        NodeError::Network("Operation timed out".to_string())
    }
}

impl From<tokio::sync::AcquireError> for NodeError {
    fn from(err: tokio::sync::AcquireError) -> Self {
        NodeError::Network(format!("Lock acquisition error: {}", err))
    }
}

impl From<BlockchainError> for NodeError {
    fn from(err: BlockchainError) -> Self {
        NodeError::Blockchain(err.to_string())
    }
}

impl From<std::io::Error> for NodeError {
    fn from(err: std::io::Error) -> Self {
        NodeError::Network(format!("IO error: {}", err))
    }
}

impl From<sled::Error> for NodeError {
    fn from(err: sled::Error) -> Self {
        NodeError::Database(err.to_string())
    }
}

impl From<String> for NodeError {
    fn from(err: String) -> Self {
        NodeError::Network(err)
    }
}

impl From<VelocityError> for NodeError {
    fn from(err: VelocityError) -> Self {
        NodeError::Network(err.to_string())
    }
}

#[derive(Debug)]
pub struct NetworkBloom {
    bits: Vec<AtomicU64>,
    hash_funcs: [u64; 3],
    size: usize,              // Track the size of the bit array
    items_count: AtomicUsize, // Track number of items
}

impl NetworkBloom {
    pub fn new() -> Self {
        Self::new_with_capacity(10000) // Default capacity
    }

    pub fn new_with_capacity(capacity: usize) -> Self {
        // Calculate optimal bit array size based on capacity
        let size = (capacity as f64 * 1.44).ceil() as usize;

        // Initialize bit array
        let bits = (0..size).map(|_| AtomicU64::new(0)).collect::<Vec<_>>();

        Self {
            bits,
            hash_funcs: [0x51_73_84_69, 0x74_29_58_12, 0x98_12_37_21],
            size,
            items_count: AtomicUsize::new(0),
        }
    }

    pub fn insert(&self, item: &[u8]) -> bool {
        // Reduce hash functions from 3 to 2 for better performance
        let hash_funcs = [self.hash_funcs[0], self.hash_funcs[1]];
        let mut was_new = false;

        // Calculate all indices first to reduce atomic operations
        let indices: Vec<_> = hash_funcs
            .iter()
            .map(|&seed| {
                let hash = self.calculate_hash(item, seed);
                (hash as usize >> 6) % self.size
            })
            .collect();

        // Batch atomic operations
        for &idx in &indices {
            if let Some(atomic) = self.bits.get(idx) {
                let old = atomic.fetch_or(1u64 << (idx & 63), Ordering::Relaxed);
                if old & (1u64 << (idx & 63)) == 0 {
                    was_new = true;
                }
            }
        }

        if was_new {
            self.items_count.fetch_add(1, Ordering::Relaxed);
        }

        was_new
    }

    pub fn check(&self, item: &[u8]) -> bool {
        self.hash_funcs.iter().all(|&seed| {
            let hash = self.calculate_hash(item, seed);
            let idx = (hash as usize >> 6) % self.size;
            let bit = 1u64 << (hash & 63);

            if let Some(atomic) = self.bits.get(idx) {
                atomic.load(Ordering::Relaxed) & bit != 0
            } else {
                false
            }
        })
    }

    pub fn clear(&self) {
        for bits in &self.bits {
            bits.store(0, Ordering::Relaxed);
        }
        self.items_count.store(0, Ordering::Relaxed);
    }

    fn calculate_hash(&self, data: &[u8], seed: u64) -> u64 {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        data.hash(&mut hasher);
        hasher.finish()
    }

    pub fn load_factor(&self) -> f64 {
        let set_bits = self
            .bits
            .iter()
            .map(|x| x.load(Ordering::Relaxed).count_ones() as usize)
            .sum::<usize>();
        set_bits as f64 / (self.size * 64) as f64
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
            .map(|x| AtomicU64::new(x.load(Ordering::Relaxed)))
            .collect();

        Self {
            bits,
            hash_funcs: self.hash_funcs,
            size: self.size,
            items_count: AtomicUsize::new(self.items_count.load(Ordering::Relaxed)),
        }
    }
}

// Optional
impl Drop for NetworkBloom {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Debug, Clone)]
struct BFTState {
    validators: HashSet<String>,
    prepare_votes: HashMap<String, HashSet<String>>,
    commit_votes: HashMap<String, HashSet<String>>,
    recent_faults: HashMap<String, (u64, u32)>,
    last_consensus: u64,
}

impl BFTState {
    fn new() -> Self {
        Self {
            validators: HashSet::new(),
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            recent_faults: HashMap::new(),
            last_consensus: 0,
        }
    }

    fn record_vote(&mut self, phase: &str, block_hash: &str, validator: &str) -> bool {
        let votes = match phase {
            "prepare" => &mut self.prepare_votes,
            "commit" => &mut self.commit_votes,
            _ => return false,
        };

        votes
            .entry(block_hash.to_string())
            .or_insert_with(HashSet::new)
            .insert(validator.to_string());

        let vote_count = votes.get(block_hash).unwrap().len();
        vote_count as f64 / self.validators.len() as f64 >= CONSENSUS_THRESHOLD
    }

    fn clear_old_votes(&mut self, max_age: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.recent_faults
            .retain(|_, (timestamp, _)| now - *timestamp < max_age);
    }
}

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
        match tokio::time::timeout(self.timeout, self.available.acquire()).await {
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
            Err(_) => Err(NodeError::Network("Validation timeout".to_string())),
        }
    }
}

// RAII guard for validation permits
struct ValidationPermit<'a> {
    _permit: SemaphorePermit<'a>,
    pool: ValidationPool,
}

impl<'a> Drop for ValidationPermit<'a> {
    fn drop(&mut self) {
        self.pool.active_validations.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: SocketAddr,
    pub version: u32,
    pub last_seen: u64,
    pub blocks: u32,
    pub latency: u64,
    subnet_group: SubnetGroup, // Use a dedicated struct for subnet grouping
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubnetGroup {
    data: [u8; 16], // Store up to 128 bits for IPv6 or 32 bits for IPv4
    len: u8,        // Store the prefix length (0-128)
}

impl SubnetGroup {
    const fn new() -> Self {
        Self {
            data: [0u8; 16],
            len: 0,
        }
    }
}

impl PeerInfo {
    pub fn new(addr: SocketAddr) -> Self {
        let subnet_group = match addr.ip() {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                let mut data = [0u8; 16];
                data[0..4].copy_from_slice(&octets);
                SubnetGroup {
                    data,
                    len: 24, // Use /24 for IPv4 subnets
                }
            }
            IpAddr::V6(ip) => {
                let segments = ip.segments();
                let mut data = [0u8; 16];
                data[..].copy_from_slice(&ip.octets());
                data[8..].fill(0); // Zero out last 64 bits
                SubnetGroup {
                    data,
                    len: 64, // Use /64 for IPv6 per RFC recommendations
                }
            }
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

    pub fn get_subnet(&self, ip: IpAddr) -> Option<SubnetGroup> {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                let mut data = [0u8; 16];
                data[0..4].copy_from_slice(&octets);

                // Apply subnet mask (24 bits)
                data[3] &= 0xFF >> (24 % 8);
                Some(SubnetGroup { data, len: 24 })
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                let mut data = [0u8; 16];
                for i in 0..8 {
                    data[i * 2..(i + 1) * 2].copy_from_slice(&segments[i].to_be_bytes());
                }
                data[12..].fill(0); // Apply /96 mask for IPv6
                Some(SubnetGroup { data, len: 96 })
            }
        }
    }
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
        response_channel: oneshot::Sender<Vec<Block>>,
    },
    ChainResponse(Vec<Block>),
}

// Only clone what we need, ChainRequest is handled specially
impl Clone for NetworkEvent {
    fn clone(&self) -> Self {
        match self {
            NetworkEvent::NewTransaction(tx) => NetworkEvent::NewTransaction(tx.clone()),
            NetworkEvent::NewBlock(block) => NetworkEvent::NewBlock(block.clone()),
            NetworkEvent::PeerJoin(addr) => NetworkEvent::PeerJoin(*addr),
            NetworkEvent::PeerLeave(addr) => NetworkEvent::PeerLeave(*addr),
            NetworkEvent::ChainResponse(blocks) => NetworkEvent::ChainResponse(blocks.clone()),
            NetworkEvent::ChainRequest {
                start,
                end,
                requester,
                ..
            } => {
                panic!("Cannot clone ChainRequest")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ConsensusMessage {
    PrepareRequest(Block),
    PrepareResponse(bool, String),
    CommitRequest(Block),
    CommitResponse(bool, String),
}

#[derive(Clone)]
struct SendWrapper<T>(T);

impl<T> SendWrapper<T> {
    fn new(inner: T) -> Self {
        SendWrapper(inner)
    }
}

unsafe impl<T> Send for SendWrapper<T> {}
unsafe impl<T> Sync for SendWrapper<T> {}

impl<T> std::ops::Deref for SendWrapper<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

unsafe impl Send for Node {}
unsafe impl Sync for Node {}

#[derive(Debug)]
pub struct Node {
    pub db: Arc<Db>,
    pub blockchain: Arc<RwLock<Blockchain>>,
    pub peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    pub network_health: Arc<RwLock<NetworkHealth>>,
    pub node_id: String,
    tx: broadcast::Sender<NetworkEvent>,
    pub start_time: u64,
    bft_state: Arc<RwLock<BFTState>>,
    pub validation_pool: Arc<ValidationPool>,
    validation_cache: Arc<DashMap<String, ValidationCacheEntry, RandomState>>,
    block_response_channels: Arc<RwLock<HashMap<Uuid, mpsc::Sender<NetworkMessage>>>>,
    network_bloom: Arc<NetworkBloom>,
    rate_limiter: Arc<RateLimiter>,
    pub bind_addr: SocketAddr,
    pub listener: Option<Arc<TcpListener>>,
    p2p_swarm: Arc<RwLock<Option<HybridSwarm>>>,
    peer_id: String,
    peer_failures: Arc<RwLock<HashMap<SocketAddr, u32>>>,
    temporal_verification: Arc<TemporalVerification>,
    pub header_sentinel: Option<Arc<HeaderSentinel>>,
    pub lock_path: Arc<String>,
    pub velocity_manager: Option<Arc<VelocityManager>>,
    pub peer_secrets: Arc<RwLock<HashMap<SocketAddr, Vec<u8>>>>,
    private_key_der: Vec<u8>,
    network_id: [u8; 32],
}

impl Node {
    pub async fn new(
        db: Arc<Db>,
        blockchain: Arc<RwLock<Blockchain>>,
        private_key: Ed25519KeyPair,
        bind_addr: Option<SocketAddr>,
    ) -> Result<Self, NodeError> {
        let (tx, _) = broadcast::channel(1000);
        let p2p_key = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(p2p_key.public()).to_string();
        let temporal_verification = Arc::new(TemporalVerification::new());
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();

        // Socket and listener initialization
        let (bind_addr, listener) = match bind_addr {
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
                (addr, Some(Arc::new(listener)))
            }
            None => {
                let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                socket.set_reuse_address(true)?;
                #[cfg(unix)]
                socket.set_reuse_port(true)?;
                socket.set_nodelay(true)?;

                // Bind to all interfaces (0.0.0.0) with default port
                let primary_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), DEFAULT_PORT);
                info!("Attempting to bind to all interfaces: {}", primary_addr);

                match socket.bind(&primary_addr.into()) {
                    Ok(_) => {
                        info!("Successfully bound to primary port");
                        socket.listen(1024)?;
                        let std_listener = socket.into();
                        let listener = TcpListener::from_std(std_listener)?;
                        let addr = listener.local_addr()?;
                        info!("Listener active on all interfaces: {}", addr);
                        (addr, Some(Arc::new(listener)))
                    }
                    Err(e) => {
                        info!("Primary port binding failed: {}, trying alternative", e);
                        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                        socket.set_reuse_address(true)?;
                        socket.set_nodelay(true)?;

                        // Try binding to a random port as fallback
                        let alt_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
                        socket.bind(&alt_addr.into())?;
                        socket.listen(1024)?;

                        let std_listener = socket.into();
                        let listener = TcpListener::from_std(std_listener)?;
                        let addr = listener.local_addr()?;
                        info!("Bound to alternative port on all interfaces: {}", addr);
                        (addr, Some(Arc::new(listener)))
                    }
                }
            }
        };

        // If we have a listener, start the connection handler
        if let Some(listener) = &listener {
            let listener_clone = Arc::clone(listener);
            info!("Starting connection handler for {}", bind_addr);
            tokio::spawn(async move {
                info!("Connection handler running for {}", bind_addr);
                while let Ok((stream, addr)) = listener_clone.accept().await {
                    info!("Accepted new connection from: {}", addr);
                }
            });
        }

        // Create lock file path
        let lock_dir = std::env::temp_dir().join("node_locks");
        std::fs::create_dir_all(&lock_dir)
            .map_err(|e| NodeError::Network(format!("Failed to create lock directory: {}", e)))?;

        let lock_path = lock_dir.join(format!(
            "{}.lock",
            hex::encode(private_key.public_key().as_ref())
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

        let velocity_manager = Some(Arc::new(VelocityManager::new()));

        Ok(Self {
            db,
            peers: Arc::new(RwLock::new(HashMap::new())),
            blockchain,
            network_health: Arc::new(RwLock::new(NetworkHealth::new())),
            node_id: hex::encode(private_key.public_key().as_ref()),
            tx,
            start_time,
            bft_state: Arc::new(RwLock::new(BFTState::new())),
            validation_pool: Arc::new(ValidationPool::new()),
            validation_cache: Arc::new(DashMap::with_capacity_and_hasher(
                10000,
                RandomState::new(),
            )),
            block_response_channels: Arc::new(RwLock::new(HashMap::with_capacity_and_hasher(
                1000,
                RandomState::new(),
            ))),
            network_bloom: Arc::new(NetworkBloom::new()),
            rate_limiter: Arc::new(RateLimiter::new(60, 100)),
            bind_addr,
            listener,
            p2p_swarm: Arc::new(RwLock::new(None)),
            peer_id,
            peer_failures: Arc::new(RwLock::new(HashMap::new())),
            temporal_verification,
            header_sentinel: None,
            lock_path: Arc::new(lock_path.to_string_lossy().into_owned()),
            velocity_manager,
            network_id,
            peer_secrets: Arc::new(RwLock::new(HashMap::new())),
            private_key_der: Self::get_private_key_bytes(&private_key)?,
        })
    }

    pub fn id(&self) -> &str {
        &self.node_id
    }

    pub fn clone_for_thread(&self) -> Self {
        self.clone()
    }

    fn get_private_key_bytes(private_key: &Ed25519KeyPair) -> Result<Vec<u8>, NodeError> {
        let key_bytes = private_key.public_key().as_ref().to_vec();
        Ok(key_bytes)
    }

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

    pub async fn start(&self) -> Result<(), NodeError> {
        info!("Starting node on {}", self.bind_addr);

        // Initialize core services with retry
        let max_init_attempts = 3;
        let mut attempt = 0;
        while attempt < max_init_attempts {
            match self.initialize_p2p().await {
                Ok(_) => {
                    info!("P2P services initialized successfully");
                    break;
                }
                Err(e) => {
                    attempt += 1;
                    if attempt == max_init_attempts {
                        error!(
                            "Failed to initialize P2P services after {} attempts: {}",
                            max_init_attempts, e
                        );
                        return Err(e);
                    }
                    warn!(
                        "P2P initialization attempt {}/{} failed: {}",
                        attempt, max_init_attempts, e
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }

        // Create message channel with appropriate buffer
        let (msg_tx, mut msg_rx) = mpsc::channel(1000);
        let node = Arc::new(self.clone());

        // Start connection handler for incoming connections
        if let Some(listener) = &self.listener {
            let listener_clone = Arc::clone(listener);
            let node_clone = Arc::clone(&node);
            let msg_tx_clone = msg_tx.clone();

            tokio::spawn(async move {
                info!("Starting connection handler on {}", node_clone.bind_addr);

                // Connection limiter to prevent DOS
                let connection_limiter = Arc::new(Semaphore::new(100));
                let mut backoff_delay = Duration::from_millis(100);
                const MAX_BACKOFF: Duration = Duration::from_secs(5);

                loop {
                    match connection_limiter.clone().try_acquire() {
                        Ok(permit) => {
                            match listener_clone.accept().await {
                                Ok((stream, addr)) => {
                                    info!("New incoming connection from {}", addr);

                                    // Reset backoff on successful connection
                                    backoff_delay = Duration::from_millis(100);

                                    // Configure TCP socket
                                    if let Err(e) = stream.set_nodelay(true) {
                                        warn!("Failed to set TCP_NODELAY for {}: {}", addr, e);
                                        continue;
                                    }

                                    let node = node_clone.clone();
                                    let tx = msg_tx_clone.clone();
                                    let permit_owned = permit;

                                    tokio::spawn(async move {
                                        let connection_result = tokio::time::timeout(
                                            Duration::from_secs(30),
                                            node.handle_connection(stream, addr, tx),
                                        )
                                        .await;

                                        match connection_result {
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

                                        // Permit is automatically dropped here, freeing up a connection slot
                                    });
                                }
                                Err(e) => {
                                    error!("Accept error: {}", e);

                                    // Implement exponential backoff
                                    tokio::time::sleep(backoff_delay).await;
                                    backoff_delay = std::cmp::min(backoff_delay * 2, MAX_BACKOFF);
                                }
                            }
                        }
                        Err(_) => {
                            warn!("Connection limit reached, waiting for slots to free up");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            });
        } else {
            warn!("No listener configured - node will not accept incoming connections");
        }

        // Message processing loop with integrated peer management
        let node_clone = Arc::clone(&node);
        tokio::spawn(async move {
            let mut peer_check_interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                tokio::select! {
                    // Process network events
                    Some(msg) = msg_rx.recv() => {
                        if let Err(e) = node_clone.handle_network_event(msg).await {
                            error!("Error handling network event: {}", e);
                        }
                    }

                    // Periodic peer management
                    _ = peer_check_interval.tick() => {
                        let peer_count = node_clone.peers.read().await.len();
                        if peer_count < MIN_PEERS {
                            match node_clone.discover_network_nodes().await {
                                Ok(_) => info!("Successfully discovered new peers. Current count: {}",
                                             node_clone.peers.read().await.len()),
                                Err(e) => warn!("Peer discovery failed: {}", e)
                            }
                        }

                        // Maintain existing connections
                        if let Err(e) = node_clone.maintain_peer_connections().await {
                            warn!("Peer maintenance failed: {}", e);
                        }
                    }
                }
            }
        });

        // Network state management with health checks
        let node_clone = Arc::clone(&node);
        tokio::spawn(async move {
            let mut state_interval = tokio::time::interval(Duration::from_secs(60));
            let mut consecutive_failures = 0u32;
            const MAX_FAILURES: u32 = 3;

            loop {
                state_interval.tick().await;

                // Update network health metrics
                let peers = node_clone.peers.read().await;
                let mut health = node_clone.network_health.write().await;

                health.active_nodes = peers.len();
                health.last_update = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Check for network isolation
                if peers.is_empty() {
                    warn!("Node appears to be isolated - no active peers");
                    consecutive_failures += 1;

                    if consecutive_failures >= MAX_FAILURES {
                        error!("Network appears to be persistently isolated - initiating recovery");
                        if let Err(e) = node_clone.discover_network_nodes().await {
                            error!("Recovery attempt failed: {}", e);
                        }
                        consecutive_failures = 0;
                    }
                } else {
                    consecutive_failures = 0;
                }

                // Blockchain sync check
                let blockchain = node_clone.blockchain.read().await;
                let current_height = blockchain.get_block_count();
                drop(blockchain);

                for (addr, peer) in peers.iter() {
                    if peer.blocks > current_height as u32 {
                        info!(
                            "Detected peer {} with higher block height {}, initiating sync",
                            addr, peer.blocks
                        );
                        if let Err(e) = node_clone.request_chain_sync().await {
                            warn!("Chain sync failed: {}", e);
                        }
                        break;
                    }
                }
            }
        });

        info!("Node startup complete - ready to accept connections");
        Ok(())
    }
    async fn initialize_p2p(&self) -> Result<(), NodeError> {
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        let transport = tcp::TokioTcpTransport::new(tcp::Config::default())
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::NoiseAuthenticated::xx(&local_key).unwrap())
            .multiplex(yamux::YamuxConfig::default())
            .boxed();

        let mut cfg = KademliaConfig::default();
        cfg.set_parallelism(NonZeroUsize::new(32).unwrap());
        let store = MemoryStore::new(local_peer_id);
        let kademlia = Kademlia::with_config(local_peer_id, store, cfg);

        let behaviour = HybridBehaviour { kademlia };
        let mut swarm = Swarm::with_tokio_executor(transport, behaviour, local_peer_id);

        match format!("/ip4/0.0.0.0/tcp/0").parse() {
            Ok(addr) => {
                if let Err(e) = swarm.listen_on(addr) {
                    return Err(NodeError::Network(format!("Failed to listen: {}", e)));
                }
            }
            Err(e) => return Err(NodeError::Network(format!("Invalid listen address: {}", e))),
        }

        *self.p2p_swarm.write().await = Some(HybridSwarm(swarm));
        Ok(())
    }

    async fn handle_p2p_events(&self) -> Result<(), NodeError> {
        let mut swarm = self
            .p2p_swarm
            .write()
            .await
            .take()
            .ok_or_else(|| NodeError::Network("Swarm not initialized".to_string()))?;

        let mut event_count = 0;
        const MAX_EVENTS: u32 = 200; // Reduced from 1000

        while event_count < MAX_EVENTS {
            match swarm.next().await {
                Some(SwarmEvent::Behaviour(HybridBehaviourEvent::Kademlia(event))) => {
                    match event {
                        KademliaEvent::OutboundQueryProgressed { result, .. } => {
                            if let QueryResult::GetClosestPeers(Ok(peers)) = result {
                                let mut peer_set = self.peers.write().await;
                                // Only add a few peers at a time
                                for peer in peers.peers.iter().take(5) {
                                    if let Ok(addr) = self.multiaddr_to_socketaddr(
                                        &peer.to_string().parse::<Multiaddr>().unwrap(),
                                    ) {
                                        peer_set.insert(addr, PeerInfo::new(addr));
                                    }
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Some(SwarmEvent::NewListenAddr { address, .. }) => {
                    info!("P2P listening on {:?}", address);
                }
                _ => {}
            }
            event_count += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Add delay before next event processing cycle
        tokio::time::sleep(Duration::from_secs(5)).await;
        Ok(())
    }

    pub async fn discover_network_nodes(&self) -> Result<(), NodeError> {
        #[derive(Clone)]
        enum NetworkRange {
            V4((Ipv4Net, usize)),
            V6((Ipv6Net, usize)),
        }

        const STUN_SERVERS: &[&str] = &[
            "stun.l.google.com:19302",
            "stun1.l.google.com:19302",
            "stun2.l.google.com:19302",
            "stun.stunprotocol.org:3478",
        ];

        // Network ranges remain the same as they're well-structured
        const RANGES: &[(&str, usize, bool)] = &[
            // Cloud and Enterprise ranges
            ("3.0.0.0/8", 50, false),      // AWS
            ("35.0.0.0/8", 50, false),     // GCP
            ("52.0.0.0/8", 50, false),     // AWS
            ("104.0.0.0/8", 25, false),    // Cloud
            ("128.0.0.0/8", 25, false),    // Academic
            ("130.0.0.0/8", 25, false),    // Research
            ("157.0.0.0/8", 25, false),    // Enterprise
            ("165.0.0.0/8", 25, false),    // Enterprise
            ("192.168.0.0/16", 50, false), // Local
            ("10.0.0.0/8", 50, false),     // Private
            // Residential ISP ranges
            ("24.0.0.0/8", 50, false),  // Comcast
            ("71.0.0.0/8", 50, false),  // AT&T
            ("67.0.0.0/8", 50, false),  // Various ISPs
            ("73.0.0.0/8", 50, false),  // Verizon
            ("98.0.0.0/8", 50, false),  // Various ISPs
            ("108.0.0.0/8", 50, false), // Various residential
            // IPv6 ranges
            ("2400::/16", 10, true), // AWS IPv6
            ("2600::/16", 10, true), // GCP IPv6
            ("2a00::/16", 10, true), // Cloud
            ("2001::/32", 5, true),  // Teredo
            ("2002::/16", 5, true),  // 6to4
            ("fc00::/7", 10, true),  // Local
        ];

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        static LAST_DISCOVERY: AtomicU64 = AtomicU64::new(0);
        if now - LAST_DISCOVERY.load(Ordering::Relaxed) < 300 {
            return Ok(());
        }
        LAST_DISCOVERY.store(now, Ordering::Relaxed);

        // Initialize NAT traversal
        let nat_config = self.initialize_tcp_nat_traversal().await?;

        // Parse network ranges
        let mut ranges: Vec<NetworkRange> = RANGES
            .iter()
            .filter_map(|(range, size, is_ipv6)| {
                if *is_ipv6 {
                    range
                        .parse::<Ipv6Net>()
                        .ok()
                        .map(|net| NetworkRange::V6((net, *size)))
                } else {
                    range
                        .parse::<Ipv4Net>()
                        .ok()
                        .map(|net| NetworkRange::V4((net, *size)))
                }
            })
            .collect();

        // Try STUN for external address discovery
        if let Ok((Some(v4), v6)) = self.discover_external_addresses(STUN_SERVERS).await {
            if let Ok(stun_ranges) = self.build_ipv4_scan_ranges(&v4).await {
                for range in stun_ranges {
                    if let ScanNetwork::V4(net) = range.network {
                        ranges.push(NetworkRange::V4((net, 50)));
                    }
                }
            }

            if let Some(v6_addr) = v6 {
                if let Ok(v6_ranges) = self.build_ipv6_scan_ranges(&v6_addr).await {
                    for range in v6_ranges {
                        if let ScanNetwork::V6(net) = range.network {
                            ranges.push(NetworkRange::V6((net, 10)));
                        }
                    }
                }
            }
        }

        let semaphore = Arc::new(Semaphore::new(15));
        let active_connections = Arc::new(AtomicUsize::new(0));
        let peer_count = Arc::new(AtomicUsize::new(0));
        let discovery_complete = Arc::new(AtomicBool::new(false));
        let node = Arc::new(self.clone());

        let discovery_tasks: Vec<_> = ranges
            .into_iter()
            .map(|range| {
                let permit = semaphore.clone().acquire_owned();
                let node = node.clone();
                let active_counter = active_connections.clone();
                let peer_counter = peer_count.clone();
                let complete_flag = discovery_complete.clone();
                let nat_config = nat_config.clone();

                tokio::spawn(async move {
                    let _permit = permit.await?;

                    let addresses = match range {
                        NetworkRange::V4((net, size)) => {
                            let mut addrs = net
                                .hosts()
                                .take(size)
                                .map(|ip| SocketAddr::new(IpAddr::V4(ip), DEFAULT_PORT))
                                .collect::<Vec<_>>();
                            addrs.shuffle(&mut thread_rng());
                            addrs
                        }
                        NetworkRange::V6((net, size)) => {
                            let prefix =
                                net.addr().segments()[..net.prefix_len() as usize / 16].to_vec();
                            let mut addrs = Vec::with_capacity(size);
                            let mut rng = thread_rng();

                            for _ in 0..size {
                                let mut segments = [0u16; 8];
                                segments[..prefix.len()].copy_from_slice(&prefix);
                                let host_part = rng.gen::<u64>();
                                segments[4] = (host_part >> 48) as u16;
                                segments[5] = (host_part >> 32) as u16;
                                segments[6] = (host_part >> 16) as u16;
                                segments[7] = host_part as u16;
                                addrs.push(SocketAddr::new(
                                    IpAddr::V6(Ipv6Addr::from(segments)),
                                    DEFAULT_PORT,
                                ));
                            }
                            addrs
                        }
                    };

                    for addr in addresses {
                        if peer_counter.load(Ordering::Relaxed) >= MAX_PEERS
                            || complete_flag.load(Ordering::Relaxed)
                        {
                            break;
                        }

                        if addr != node.bind_addr {
                            active_counter.fetch_add(1, Ordering::Release);

                            // Try direct connection with secure handshake
                            let verified =
                                match tokio::time::timeout(Duration::from_millis(100), async {
                                    // Initial TCP connection
                                    if let Ok(mut stream) = TcpStream::connect(addr).await {
                                        stream.set_nodelay(true)?;

                                        // Perform secure handshake
                                        match node.perform_handshake(&mut stream, true).await {
                                            Ok((peer_info, shared_secret)) => {
                                                // Store shared secret for encrypted communication
                                                node.peer_secrets
                                                    .write()
                                                    .await
                                                    .insert(addr, shared_secret);

                                                // Version and network checks are done in handshake
                                                return Ok::<_, NodeError>(Some(peer_info));
                                            }
                                            Err(_) => Ok(None),
                                        }
                                    } else {
                                        Ok(None)
                                    }
                                })
                                .await
                                {
                                    Ok(Ok(Some(peer_info))) => {
                                        let mut peers = node.peers.write().await;
                                        if peers.len() < MAX_PEERS {
                                            peers.insert(addr, peer_info);
                                            peer_counter.fetch_add(1, Ordering::AcqRel) >= MAX_PEERS
                                        } else {
                                            false
                                        }
                                    }
                                    _ => {
                                        // Try NAT traversal if direct connection fails
                                        if let Ok(()) = node.tcp_hole_punch(addr, &nat_config).await
                                        {
                                            // After NAT traversal, attempt handshake again
                                            if let Ok(mut stream) = TcpStream::connect(addr).await {
                                                if let Ok((peer_info, shared_secret)) =
                                                    node.perform_handshake(&mut stream, true).await
                                                {
                                                    // Store shared secret
                                                    node.peer_secrets
                                                        .write()
                                                        .await
                                                        .insert(addr, shared_secret);

                                                    let mut peers = node.peers.write().await;
                                                    if peers.len() < MAX_PEERS {
                                                        peers.insert(addr, peer_info);
                                                        peer_counter.fetch_add(1, Ordering::AcqRel)
                                                            >= MAX_PEERS
                                                    } else {
                                                        false
                                                    }
                                                } else {
                                                    false
                                                }
                                            } else {
                                                false
                                            }
                                        } else {
                                            false
                                        }
                                    }
                                };

                            if verified {
                                complete_flag.store(true, Ordering::Release);
                                break;
                            }

                            active_counter.fetch_sub(1, Ordering::Release);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                    Ok::<(), NodeError>(())
                })
            })
            .collect();

        let discovery_timeout = tokio::time::sleep(Duration::from_secs(15));
        tokio::pin!(discovery_timeout);

        tokio::select! {
            _ = discovery_timeout => {
                discovery_complete.store(true, Ordering::Release);
            }
            _ = async {
                while peer_count.load(Ordering::Relaxed) < MAX_PEERS &&
                      active_connections.load(Ordering::Relaxed) > 0 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } => {
                discovery_complete.store(true, Ordering::Release);
            }
        }

        Ok(())
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

            if v4_addr.is_some() || v6_addr.is_some() {
                break;
            }
        }

        Ok((v4_addr, v6_addr))
    }

    pub async fn initialize_tcp_nat_traversal(&self) -> Result<TcpNatConfig, NodeError> {
        // Setup port mapping first
        self.setup_port_mapping(self.bind_addr.port()).await?;

        // Create simplified config
        let config = TcpNatConfig {
            external_port: self.bind_addr.port(),
            supports_upnp: false,
            supports_nat_pmp: false,
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
        let mut retries = 0u64; // Change to u64
        while retries < config.max_retries as u64 {
            // Convert max_retries to u64
            if let Ok(Ok(_)) =
                tokio::time::timeout(config.connect_timeout, TcpStream::connect(addr)).await
            {
                return Ok(());
            }

            retries += 1;
            tokio::time::sleep(Duration::from_millis(100 * retries)).await;
        }

        Err(NodeError::Network("TCP hole punching failed".to_string()))
    }

    async fn setup_port_mapping(&self, port: u16) -> Result<(), NodeError> {
        // Configure the TCP socket first using our existing method
        let socket = self
            .configure_tcp_socket(TcpStream::connect(format!("0.0.0.0:{}", port)).await?)
            .await?;

        // Set socket options for hole punching
        let sock = Socket::from(socket.into_std()?);
        sock.set_reuse_address(true)?;

        #[cfg(unix)]
        sock.set_reuse_port(true)?;

        // Set non-blocking to allow concurrent connections
        sock.set_nonblocking(true)?;

        // Configure keepalive with existing settings
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(15));

        sock.set_tcp_keepalive(&keepalive)?;

        // Convert back to TcpStream
        let _ = TcpStream::from_std(sock.into())?;

        Ok(())
    }

    async fn configure_tcp_socket(&self, stream: TcpStream) -> Result<TcpStream, NodeError> {
        let std_stream = stream.into_std()?;
        let sock = Socket::from(std_stream);

        sock.set_nonblocking(true)?;

        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(15));

        sock.set_tcp_keepalive(&keepalive)?;
        sock.set_nodelay(true)?;

        let std_stream = sock.into();
        let stream = TcpStream::from_std(std_stream)?;

        Ok(stream)
    }

    #[cfg(windows)]
    pub async fn clone_tcp_stream(stream: &TcpStream) -> Result<TcpStream, NodeError> {
        // Get raw socket
        let raw_socket = stream.as_raw_socket();

        // Create new socket from raw
        let std_stream = unsafe {
            let socket = socket2::Socket::from_raw_socket(raw_socket);
            std::net::TcpStream::from(socket)
        };

        // Clone the std stream
        let cloned_std = std_stream
            .try_clone()
            .map_err(|e| NodeError::Network(format!("Failed to clone stream: {}", e)))?;

        // Don't drop original socket
        std::mem::forget(std_stream);

        // Convert to tokio stream
        let new_stream = TcpStream::from_std(cloned_std)
            .map_err(|e| NodeError::Network(format!("Failed to convert to tokio stream: {}", e)))?;

        // Set TCP_NODELAY
        new_stream
            .set_nodelay(true)
            .map_err(|e| NodeError::Network(format!("Failed to set TCP_NODELAY: {}", e)))?;

        Ok(new_stream)
    }

    async fn build_ipv6_scan_ranges(
        &self,
        local_addr: &IpAddr,
    ) -> Result<Vec<ScanRange>, NodeError> {
        let mut ranges = Vec::new();

        if let IpAddr::V6(ipv6) = local_addr {
            // Get /64 prefix from address
            let prefix = ipv6.segments()[..4].to_vec();

            // Create range for local subnet (common in residential IPv6)
            let subnet = format!(
                "{}:{}:{}:{:x}::/64",
                prefix[0], prefix[1], prefix[2], prefix[3]
            );

            if let Ok(net) = subnet.parse() {
                ranges.push(ScanRange::new(ScanNetwork::V6(net), 10));
            }

            // Add common residential IPv6 ranges
            // Note: These would be your ISP's IPv6 ranges
            let residential_v6 = [
                "2001::/32", // Teredo tunneling
                "2002::/16", // 6to4 transition
                "fc00::/7",  // Unique local addresses
            ];

            for &range in residential_v6.iter() {
                if let Ok(net) = range.parse() {
                    ranges.push(ScanRange::new(ScanNetwork::V6(net), 5));
                }
            }
        }

        Ok(ranges)
    }

    async fn build_ipv4_scan_ranges(&self, local_ip: &IpAddr) -> Result<Vec<ScanRange>, NodeError> {
        let mut ranges = Vec::new();

        if let IpAddr::V4(ipv4) = *local_ip {
            // Create range for immediate local network (/24)
            if let Ok(local_net) = Ipv4Net::new(ipv4, 24) {
                ranges.push(ScanRange::new(ScanNetwork::V4(local_net), 10));

                // Add adjacent subnets with lower priority
                for i in -2i32..=2i32 {
                    if i == 0 {
                        continue;
                    }
                    let base = (ipv4.octets()[2] as i32 + i) as u8;
                    let net_str =
                        format!("{}.{}.{}.0/24", ipv4.octets()[0], ipv4.octets()[1], base);
                    if let Ok(subnet) = net_str.parse::<Ipv4Net>() {
                        ranges.push(ScanRange::new(ScanNetwork::V4(subnet), 8));
                    }
                }
            }
        }

        Ok(ranges)
    }

    async fn perform_stun_request(&self, server: &str) -> Result<IpAddr, NodeError> {
        const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

        // Create UDP socket for STUN
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let mut transaction_id = [0u8; 12];
        rand::thread_rng().fill(&mut transaction_id);

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
        let timeout = Duration::from_secs(3);
        if let Err(_) = tokio::time::timeout(timeout, socket.send_to(&msg, server)).await {
            return Err(NodeError::Network("STUN request timeout".into()));
        }

        // Receive response
        let mut buf = [0u8; 512];
        let (size, _) = socket.recv_from(&mut buf).await?;

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

            if attr_type == 0x0001 {
                // XOR-MAPPED-ADDRESS
                if pos + 8 + attr_len as usize <= data.len() {
                    let ip_family = data[pos + 5];
                    if ip_family == 0x01 {
                        // IPv4
                        let port = ((data[pos + 6] as u16) << 8) | (data[pos + 7] as u16);
                        let ip = Ipv4Addr::new(
                            data[pos + 8],
                            data[pos + 9],
                            data[pos + 10],
                            data[pos + 11],
                        );
                        return Ok(IpAddr::V4(ip));
                    }
                }
            }
            pos += 4 + attr_len as usize;
        }

        Err(NodeError::Network(
            "No valid IP found in STUN response".into(),
        ))
    }

    pub async fn receive_message(&self, addr: SocketAddr) -> Result<NetworkMessage, NodeError> {
        let stream = TcpStream::connect(addr).await?;
        let mut reader = tokio::io::BufReader::new(stream);
        let mut buffer = Vec::new();

        reader.read_to_end(&mut buffer).await?;

        let message: NetworkMessage = bincode::deserialize(&buffer)?;
        Ok(message)
    }

    pub async fn validate_block(&self, block: &Block) -> Result<bool, NodeError> {
        // Header info validation
        let header_info = BlockHeaderInfo {
            height: block.index,
            hash: block.hash,
            prev_hash: block.previous_hash,
            timestamp: block.timestamp,
        };

        // Basic validation steps unchanged
        if block.calculate_hash_for_block() != block.hash {
            return Ok(false);
        }

        let blockchain = self.blockchain.read().await;

        // Validate block against blockchain
        if let Err(_) = blockchain.validate_new_block(block).await {
            return Ok(false);
        }

        // Validate height
        let current_height = blockchain.get_block_count() as u32;
        if block.index != current_height {
            return Ok(false);
        }
        drop(blockchain);

        // Sequential validation with bounded concurrency
        let mut valid = true;

        // Process in chunks to avoid overwhelming the system
        for chunk in block.transactions.chunks(20) {
            let mut chunk_handles = Vec::new();

            for tx in chunk {
                if tx.sender == "MINING_REWARDS" {
                    continue;
                }

                let tx = tx.clone();
                let blockchain = self.blockchain.clone();

                // Do synchronous validation checks before spawning
                let sender_valid = {
                    let bc = blockchain.read().await;
                    let wallets = bc.wallets.read().await;
                    wallets.contains_key(&tx.sender)
                };

                if !sender_valid {
                    valid = false;
                    break;
                }

                let block_clone = block.clone();

                // Now spawn task with simplified validation that won't involve complex error types
                let handle = tokio::spawn(async move {
                    let bc = blockchain.read().await;
                    match bc.get_wallet_balance(&tx.sender).await {
                        Ok(balance) => balance >= tx.amount,
                        Err(_) => false,
                    }
                });

                chunk_handles.push(handle);
            }

            // Early exit if validation fails
            if !valid {
                break;
            }

            // Wait for current chunk to complete
            for handle in chunk_handles {
                match handle.await {
                    Ok(is_valid) => valid &= is_valid,
                    Err(_) => valid = false,
                }
            }

            if !valid {
                break;
            }
        }

        Ok(valid)
    }

    async fn verify_block_temporal(&self, block: &Block) -> Result<bool, NodeError> {
        let header_info = BlockHeaderInfo {
            height: block.index,
            hash: block.hash,
            prev_hash: block.previous_hash,
            timestamp: block.timestamp,
        };

        let temporal = self.temporal_verification.verify_header(&header_info);

        // Add verification if passed
        if temporal {
            self.temporal_verification
                .add_verified_header(&header_info)
                .await;
        }

        Ok(temporal)
    }

    pub async fn verify_block_header(&self, block: &Block) -> Result<bool, NodeError> {
        // Verify timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if block.timestamp > now + 7200 {
            // 2 hours future max
            return Ok(false);
        }

        // Verify hash matches content
        if block.calculate_hash_for_block() != block.hash {
            return Ok(false);
        }

        // Verify previous hash if not genesis
        if block.index > 0 {
            let blockchain = self.blockchain.read().await;
            if let Ok(prev_block) = blockchain.get_block(block.index - 1) {
                if block.previous_hash != prev_block.hash {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub async fn basic_header_checks(&self, header: &BlockHeaderInfo) -> Result<bool, NodeError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Time check
        if header.timestamp > now + 7200 {
            return Ok(false);
        }

        // Previous hash check for non-genesis (simplified)
        if header.height > 0 {
            match self.blockchain.read().await.get_block(header.height - 1) {
                Ok(prev_block) => {
                    if header.prev_hash != prev_block.hash {
                        return Ok(false);
                    }
                }
                Err(_) => return Ok(false), // Any error means invalid block
            }
        }

        Ok(true)
    }

    async fn request_chain_sync(&self) -> Result<(), NodeError> {
        info!("Initiating blockchain resync...");

        // Fetch the current height of our local chain
        let local_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_block_count() as u32
        };

        // Request the latest block height from connected peers
        let mut peer_heights = HashMap::new();
        for (addr, _) in self.peers.read().await.iter() {
            let peer_height = self.request_peer_height(*addr).await?;
            peer_heights.insert(*addr, peer_height);
        }

        // Find the peer with the highest block height
        let (max_peer, max_height) = peer_heights
            .into_iter()
            .max_by_key(|(_, height)| *height)
            .ok_or(NodeError::Network(
                "No suitable peer found for chain sync".to_string(),
            ))?;

        // If our chain is behind, initiate the sync process
        if max_height > local_height {
            info!(
                "Local chain height: {}. Highest peer height: {}. Syncing...",
                local_height, max_height
            );

            // Request missing blocks in batches
            let mut current_height = local_height + 1;
            while current_height <= max_height {
                let batch_size = ((max_height - current_height + 1) as usize).min(1000); // Sync in batches of 1000 blocks
                let batch_end = current_height + batch_size as u32 - 1;

                info!(
                    "Requesting blocks {} to {} from peer {}...",
                    current_height, batch_end, max_peer
                );

                let blocks = self
                    .request_blocks(max_peer, current_height, batch_end)
                    .await?;

                // Verify and save received blocks
                for block in blocks {
                    // Perform any necessary block verification (PoW, signatures, etc.)
                    if !self.verify_block_parallel(&block).await? {
                        return Err(NodeError::Blockchain(
                            "Received invalid block during sync".to_string(),
                        ));
                    }

                    // Save the block to our local chain
                    self.blockchain.write().await.save_block(&block).await?;

                    // Update sync progress
                    current_height = block.index + 1;
                }
            }

            info!(
                "Blockchain sync completed. Local height: {}",
                current_height - 1
            );
        } else {
            info!("Local chain is up to date. No sync needed.");
        }

        Ok(())
    }

    pub async fn request_peer_height(&self, addr: SocketAddr) -> Result<u32, NodeError> {
        let mut stream = TcpStream::connect(addr).await?;
        let request = NetworkMessage::GetBlockHeight;

        let data = bincode::serialize(&request)?;
        stream.write_all(&data).await?;

        let mut buffer = vec![0; 1024];
        let bytes_read = stream.read(&mut buffer).await?;

        let response: NetworkMessage = bincode::deserialize(&buffer[..bytes_read])?;
        match response {
            NetworkMessage::BlockHeight(height) => Ok(height),
            _ => Err(NodeError::Network(
                "Unexpected response for block height request".to_string(),
            )),
        }
    }

    fn start_periodic_tasks(&self) {
        let node = Arc::new(self.clone());
        let last_tick = Arc::new(AtomicU64::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ));

        // Maintenance task with integrated sleep detection
        let maintenance_node = Arc::clone(&node);
        let maintenance_tick = Arc::clone(&last_tick);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            let mut last_cleanup = Instant::now();
            let mut last_check = Instant::now();
            let mut maintenance_backoff = 1u64;

            loop {
                interval.tick().await;
                let now = Instant::now();
                let current_time = SystemTime::now();

                // Sleep detection
                if now.duration_since(last_check) > Duration::from_secs(10) {
                    maintenance_node
                        .validation_pool
                        .active_validations
                        .store(0, Ordering::SeqCst);
                    maintenance_node.validation_cache.clear();
                    maintenance_node.peers.write().await.clear();
                    maintenance_node.discover_network_nodes().await.ok();
                }
                last_check = now;

                // Periodic cleanup
                if now.duration_since(last_cleanup) >= Duration::from_secs(300) {
                    // Batch process expired validations
                    let expired: Vec<_> = maintenance_node
                        .validation_cache
                        .iter()
                        .filter(|entry| {
                            current_time
                                .duration_since(entry.timestamp)
                                .unwrap_or_default()
                                .as_secs()
                                >= 3600
                        })
                        .map(|entry| entry.key().clone())
                        .collect();

                    for chunk in expired.chunks(1000) {
                        for key in chunk {
                            maintenance_node.validation_cache.remove(key);
                        }
                        tokio::task::yield_now().await;
                    }

                    // Network maintenance with backoff
                    match maintenance_node.maintain_peer_connections().await {
                        Ok(_) => {
                            maintenance_backoff = 1;
                        }
                        Err(e) => {
                            error!("Peer maintenance error: {}", e);
                            maintenance_backoff = maintenance_backoff.saturating_mul(2).min(60);
                            tokio::time::sleep(Duration::from_secs(maintenance_backoff)).await;
                        }
                    }

                    // Update network health
                    let peers = maintenance_node.peers.read().await;
                    let mut health = maintenance_node.network_health.write().await;
                    health.active_nodes = health.active_nodes.max(1);
                    health.average_peer_count = peers.len() as f64;
                    health.last_update = current_time
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    last_cleanup = now;
                }

                maintenance_tick.store(
                    current_time
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    Ordering::Release,
                );
            }
        });

        // P2P event monitoring with adaptive batching
        let p2p_node = Arc::clone(&node);
        let p2p_tick = Arc::clone(&last_tick);
        tokio::spawn(async move {
            let mut consecutive_failures = 0;
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            let mut batch_size = 100;

            loop {
                interval.tick().await;

                // Sleep detection
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let last = p2p_tick.load(Ordering::Acquire);

                if now - last > 10 {
                    if let Err(e) = p2p_node.initialize_p2p().await {
                        error!("P2P reinitialization after wake failed: {}", e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    consecutive_failures = 0;
                    continue;
                }

                // Batch process P2P events
                let mut events_processed = 0;
                let start_time = Instant::now();

                while events_processed < batch_size
                    && start_time.elapsed() < Duration::from_millis(100)
                {
                    match p2p_node.handle_p2p_events().await {
                        Ok(_) => {
                            consecutive_failures = 0;
                            events_processed += 1;

                            if start_time.elapsed() < Duration::from_millis(50) {
                                batch_size = (batch_size + 10).min(500);
                            }
                        }
                        Err(e) => {
                            error!("P2P event handling error: {}", e);
                            consecutive_failures += 1;
                            batch_size = (batch_size / 2).max(50);

                            if consecutive_failures > 3 {
                                let backoff =
                                    Duration::from_secs(2u64.pow(consecutive_failures.min(6)));
                                tokio::time::sleep(backoff).await;

                                if let Err(e) = p2p_node.initialize_p2p().await {
                                    error!("Failed to reinitialize P2P: {}", e);
                                    interval = tokio::time::interval(Duration::from_secs(5));
                                } else {
                                    interval = tokio::time::interval(Duration::from_millis(100));
                                    consecutive_failures = 0;
                                }
                                break;
                            }
                        }
                    }
                }

                // Adaptive interval based on peer count
                let peers_len = p2p_node.peers.read().await.len();
                let new_interval = if peers_len > 20_000 {
                    Duration::from_millis(150)
                } else if peers_len > 10_000 {
                    Duration::from_millis(125)
                } else {
                    Duration::from_millis(100)
                };

                if interval.period() != new_interval {
                    interval = tokio::time::interval(new_interval);
                }

                // Memory optimization for medium-sized networks
                if peers_len > 15_000 && events_processed > 0 {
                    tokio::task::yield_now().await;
                }
            }
        });
    }

    async fn check_validation_cache(&self, tx_hash: &str) -> Option<bool> {
        if let Some(entry) = self.validation_cache.get(tx_hash) {
            let now = SystemTime::now();
            if now
                .duration_since(entry.timestamp)
                .unwrap_or_default()
                .as_secs()
                < 3600
            // 1 hour cache validity
            {
                return Some(entry.valid);
            }
            // Remove expired entry
            self.validation_cache.remove(tx_hash);
        }
        None
    }

    async fn update_validation_cache(&self, tx_hash: &str, valid: bool) {
        self.validation_cache.insert(
            tx_hash.to_string(),
            ValidationCacheEntry {
                valid,
                timestamp: SystemTime::now(),
                verification_count: 1,
            },
        );
    }

    pub async fn maintain_peer_connections(&self) -> Result<(), NodeError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Batch process peer health checks
        let peers = self.peers.read().await;
        let mut health_checks = Vec::new();

        for (&addr, info) in peers.iter() {
            // Skip recently checked peers
            if now - info.last_seen < 30 {
                // Only check peers not seen in last 30 seconds
                continue;
            }

            let node = self.clone();
            health_checks.push(tokio::spawn(async move {
                let start = Instant::now();
                let result = node.check_peer_health_internal(addr).await;
                (addr, result, start.elapsed())
            }));
        }
        drop(peers);

        // Process health check results
        let results = futures::future::join_all(health_checks).await;
        let mut removals = Vec::new();
        let mut updates = Vec::new();

        for result in results {
            if let Ok((addr, health_result, latency)) = result {
                match health_result {
                    Ok(_) => {
                        updates.push((addr, latency.as_millis() as u64));
                    }
                    Err(_) => {
                        removals.push(addr);
                    }
                }
            }
        }

        // Update peer states
        let mut peers = self.peers.write().await;

        // Remove unhealthy peers
        for addr in removals {
            peers.remove(&addr);
            self.peer_secrets.write().await.remove(&addr);
        }

        // Update latency for healthy peers
        for (addr, latency) in updates {
            if let Some(info) = peers.get_mut(&addr) {
                info.latency = latency;
                info.last_seen = now;
            }
        }

        // Check if we need more peers
        let current_peers = peers.len();
        drop(peers);

        if current_peers < MIN_PEERS {
            // Discover new peers if needed
            self.discover_network_nodes().await?;
        }

        // Maintain subnet diversity
        self.rebalance_peer_subnets().await?;

        Ok(())
    }

    async fn get_peer_asn(&self, addr: &SocketAddr) -> Option<String> {
        let connected_peers = self.peers.read().await;

        if let Some(peer_info) = connected_peers.get(addr) {
            let subnet_group = peer_info.get_subnet(addr.ip()).unwrap();
            let subnet_bytes = subnet_group.data;
            let subnet_len = subnet_group.len;

            // Convert subnet bytes to a string representation
            let subnet_str = subnet_bytes
                .iter()
                .take((subnet_len / 8) as usize)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":");

            Some(format!(
                "Subnet_{subnet}_v{version}",
                subnet = subnet_str,
                version = peer_info.version
            ))
        } else {
            None
        }
    }

    async fn rebalance_peer_subnets(&self) -> Result<(), NodeError> {
        let peers = self.peers.read().await;
        let mut subnet_counts = HashMap::new();
        let mut subnet_peers = HashMap::new();

        // Count peers per subnet and build subnet mapping
        for (&addr, info) in peers.iter() {
            let subnet = info.subnet_group;
            *subnet_counts.entry(subnet).or_insert(0) += 1;
            subnet_peers
                .entry(subnet)
                .or_insert_with(Vec::new)
                .push((addr, info.clone()));
        }
        drop(peers);

        // Find overrepresented subnets
        let max_per_subnet = (MAX_PEERS / 8).max(3); // Allow max 1/8 of peers from one subnet
        let mut removals = Vec::new();

        for (subnet, count) in subnet_counts.iter() {
            if *count > max_per_subnet {
                if let Some(subnet_peer_list) = subnet_peers.get(subnet) {
                    // Sort peers by latency and uptime
                    let mut ranked_peers = subnet_peer_list.clone();
                    ranked_peers.sort_by(|a, b| {
                        let current_time = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();

                        let a_score =
                            a.1.latency as f64 * 0.7 + (current_time - a.1.last_seen) as f64 * 0.3;
                        let b_score =
                            b.1.latency as f64 * 0.7 + (current_time - b.1.last_seen) as f64 * 0.3;
                        a_score.partial_cmp(&b_score).unwrap()
                    });

                    // Keep the best peers up to max_per_subnet
                    let excess = ranked_peers.split_off(max_per_subnet);
                    removals.extend(excess.into_iter().map(|(addr, _)| addr));
                }
            }
        }

        // Remove excess peers
        if !removals.is_empty() {
            let mut peers = self.peers.write().await;
            for addr in removals {
                peers.remove(&addr);
                self.peer_secrets.write().await.remove(&addr);
            }
        }

        Ok(())
    }

    // Add method to track peer failures
    async fn record_peer_failure(&self, addr: SocketAddr) {
        let mut failures = self.peer_failures.write().await;
        *failures.entry(addr).or_insert(0) += 1;
    }

    // Add method to reset peer failures
    async fn reset_peer_failures(&self, addr: SocketAddr) {
        self.peer_failures.write().await.remove(&addr);
    }

    async fn maintain_network_state(&self) -> Result<(), NodeError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now % 3600 == 0 {
            self.network_bloom.clear();
        }

        Ok(())
    }

    pub async fn get_node_status(&self) -> Result<serde_json::Value, NodeError> {
        let peers = self.peers.read().await;
        Ok(serde_json::json!({
            "node_status": {
                "node_id": self.node_id.clone(),
                "peers": peers.len(),
                "blockchain_height": self.blockchain.read().await.get_block_count(),
                "uptime": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() - self.start_time
            }
        }))
    }

    pub fn get_public_key(&self) -> String {
        self.node_id.clone()
    }

    pub async fn sync_with_network(&self) -> Result<(), NodeError> {
        let current_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_block_count() as u32
        };

        let peers = self.peers.read().await;
        let mut highest_block = current_height;

        for (_, info) in peers.iter() {
            if info.blocks > highest_block {
                highest_block = info.blocks;
            }
        }

        if highest_block > current_height {
            let mut current_block = current_height + 1;

            while current_block <= highest_block {
                let batch_size = (highest_block - current_block + 1).min(100);
                let batch_end = current_block + batch_size - 1;

                let mut futures = Vec::new();
                for peer_addr in peers.keys() {
                    futures.push(self.request_blocks(*peer_addr, current_block, batch_end));
                }

                let results = join_all(futures).await;
                let valid_blocks: Vec<Block> = results
                    .into_iter()
                    .filter_map(Result::ok)
                    .flatten()
                    .collect();

                if !valid_blocks.is_empty() {
                    let blockchain = self.blockchain.write().await;
                    for block in valid_blocks {
                        blockchain.save_block(&block).await?;
                    }
                }

                current_block = batch_end + 1;
            }
        }

        Ok(())
    }

    // Continuing inside impl Node
    async fn discover_peers(&self) -> Result<(), NodeError> {
        let mut new_peers = HashSet::new();

        // Get local network peers
        if let Ok(local_peers) = self.discover_local_network().await {
            for peer in local_peers {
                if new_peers.len() >= MAX_PEERS {
                    break;
                }
                new_peers.insert(peer);
            }
        }

        // Get peers from existing connections
        let peers = self.peers.read().await;
        for &addr in peers.keys() {
            if new_peers.len() >= MAX_PEERS {
                break;
            }
            if let Ok(peer_list) = self.request_peer_list(addr).await {
                for peer in peer_list {
                    if new_peers.len() >= MAX_PEERS {
                        break;
                    }
                    let rate_limit_key = format!("peer_connect_{}", peer);
                    if !self.rate_limiter.check_limit(&rate_limit_key) {
                        continue;
                    }
                    new_peers.insert(peer);
                }
            }
        }

        // Verify and add new peers
        let mut verified_peers = HashSet::new();
        for addr in new_peers {
            if addr == self.bind_addr {
                continue;
            }

            if let Ok(()) = self.verify_peer(addr).await {
                verified_peers.insert(addr);
            }
        }

        // Update peer list
        if !verified_peers.is_empty() {
            let mut peers = self.peers.write().await;
            for addr in verified_peers {
                if peers.len() >= MAX_PEERS {
                    break;
                }
                peers.insert(addr, PeerInfo::new(addr));
            }
        }

        Ok(())
    }

    async fn start_local_discovery(&self, port: u16) -> Result<(), NodeError> {
        let local_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        if let IpAddr::V4(ipv4) = local_addr {
            let base_addr = ipv4.octets();
            let node = Arc::new(self.clone());

            let tasks: Vec<_> = (1..=254)
                .filter_map(|i| {
                    let test_addr = SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(base_addr[0], base_addr[1], base_addr[2], i)),
                        port,
                    );
                    if test_addr.ip() == local_addr {
                        None
                    } else {
                        let node = Arc::clone(&node);
                        Some(tokio::spawn(async move {
                            if let Ok(()) = node.verify_peer(test_addr).await {
                                let mut peers = node.peers.write().await;
                                peers.insert(test_addr, PeerInfo::new(test_addr));
                            }
                        }))
                    }
                })
                .collect();

            for task in tasks {
                task.await
                    .map_err(|e| NodeError::Network(format!("Task join error: {}", e)))?;
            }
        }

        Ok(())
    }

    async fn discover_local_network(&self) -> Result<HashSet<SocketAddr>, NodeError> {
        let mut discovered = HashSet::new();
        let port = self.bind_addr.port();

        let scan_result = match self.bind_addr.ip() {
            IpAddr::V4(ip) => {
                let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                socket.set_nonblocking(true)?;
                socket.set_reuse_address(true)?;

                #[cfg(unix)]
                socket.set_reuse_port(true)?;

                Some(ScanResult::V4 { socket, addr: ip })
            }
            IpAddr::V6(ip) if !ip.is_loopback() && !ip.is_unspecified() => {
                let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
                socket.set_nonblocking(true)?;
                socket.set_reuse_address(true)?;
                socket.set_only_v6(true)?;

                #[cfg(unix)]
                socket.set_reuse_port(true)?;

                Some(ScanResult::V6 { socket, addr: ip })
            }
            _ => None,
        };

        if let Some(result) = scan_result {
            let (socket, ip_addr) = match result {
                ScanResult::V4 { socket, addr } => (socket, IpAddr::V4(addr)),
                ScanResult::V6 { socket, addr } => (socket, IpAddr::V6(addr)),
            };

            let scan_range = match ip_addr {
                IpAddr::V4(ipv4) => {
                    // Scan local IPv4 subnet
                    let octets = ipv4.octets();
                    let subnet = format!("{}.{}.{}", octets[0], octets[1], octets[2]);

                    // Create batched scan ranges
                    (1..255)
                        .collect::<Vec<_>>()
                        .chunks(32)
                        .map(|chunk| {
                            chunk
                                .iter()
                                .map(|&i| {
                                    format!("{}{}:{}", subnet, i, port)
                                        .parse::<SocketAddr>()
                                        .map_err(|e: std::net::AddrParseError| {
                                            NodeError::InvalidAddress(e.to_string())
                                        })
                                })
                                .collect::<Result<Vec<SocketAddr>, NodeError>>()
                        })
                        .collect::<Result<Vec<_>, _>>()?
                }
                IpAddr::V6(ipv6) => {
                    // Scan local IPv6 subnet more efficiently
                    let segments = ipv6.segments();
                    let prefix = segments[..4].to_vec();

                    // Use randomized scanning for large IPv6 space
                    let mut rng = thread_rng();
                    (0..64)
                        .map(|_| {
                            let mut addr_segments = [0u16; 8];
                            addr_segments[..4].copy_from_slice(&prefix);

                            // Randomize last 4 segments
                            for i in 4..8 {
                                addr_segments[i] = rng.gen();
                            }

                            Ok(vec![SocketAddr::new(
                                IpAddr::V6(Ipv6Addr::from(addr_segments)),
                                port,
                            )])
                        })
                        .collect::<Result<Vec<_>, NodeError>>()?
                }
            };

            // Process scan ranges with concurrent connections
            for batch in scan_range {
                let mut connection_futures = Vec::new();

                for addr in batch {
                    if addr == self.bind_addr {
                        continue;
                    }

                    let socket_clone = socket.try_clone()?;
                    let future = async move {
                        match tokio::time::timeout(
                            Duration::from_millis(100),
                            TcpStream::connect(addr),
                        )
                        .await
                        {
                            Ok(Ok(_)) => Some(addr),
                            _ => None,
                        }
                    };

                    connection_futures.push(future);
                }

                // Wait for batch completion with timeout
                let results = futures::future::join_all(connection_futures).await;

                for result in results.into_iter().flatten() {
                    discovered.insert(result);
                }
            }
        }

        Ok(discovered)
    }

    async fn discover_from_existing(self: Arc<Self>) -> Result<HashSet<SocketAddr>, NodeError> {
        let mut discovered = HashSet::new();
        let peers = self.peers.read().await;

        let mut futures = Vec::new();
        for &addr in peers.keys() {
            let node_clone = Arc::clone(&self);

            futures.push(tokio::spawn(async move {
                // Perform the peer list request inside the task
                if let Ok(peer_list) = node_clone.request_peer_list(addr).await {
                    peer_list
                } else {
                    Vec::new()
                }
            }));
        }

        // Process the results of all spawned futures
        for result in futures::future::join_all(futures).await {
            if let Ok(peer_list) = result {
                discovered.extend(peer_list);
            }
        }

        Ok(discovered)
    }

    async fn check_peer_health(&self, addr: SocketAddr) -> bool {
        match self.check_peer_health_internal(addr).await {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub async fn check_peer_health_internal(&self, addr: SocketAddr) -> Result<(), NodeError> {
        let mut stream = TcpStream::connect(addr).await?;

        // Verify connection is active
        if let Err(e) = stream.set_nodelay(true) {
            return Err(NodeError::Network(format!(
                "Socket verification failed: {}",
                e
            )));
        }

        Ok(())
    }

    async fn maintain_peer_network(&self) -> Result<(), NodeError> {
        let peers = self.peers.read().await;
        let current_peers = peers.len();

        // Health check existing peers
        let mut removals = Vec::new();
        for (&addr, _) in peers.iter() {
            if !self.check_peer_health(addr).await {
                removals.push(addr);
            }
        }
        drop(peers);

        // Remove unhealthy peers
        if !removals.is_empty() {
            let mut peers = self.peers.write().await;
            for addr in removals {
                peers.remove(&addr);
            }
        }

        // Discover new peers if needed
        if current_peers < MIN_PEERS {
            self.discover_peers().await?;
        }

        Ok(())
    }

    pub async fn verify_peer(&self, addr: SocketAddr) -> Result<(), NodeError> {
        let mut attempts = 0;
        let max_attempts = 3;
        let mut delay = Duration::from_millis(500);

        while attempts < max_attempts {
            attempts += 1;

            // Initial TCP connection with timeout
            let stream = match tokio::time::timeout(
                Duration::from_secs(5),
                TcpStream::connect(addr),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                    continue;
                }
                Err(_) => {
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                    continue;
                }
            };

            // Configure socket
            let mut stream = match self.configure_tcp_socket(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                    continue;
                }
            };

            // Attempt handshake
            match tokio::time::timeout(
                Duration::from_secs(10),
                self.perform_handshake(&mut stream, true),
            )
            .await
            {
                Ok(Ok((peer_info, shared_secret))) => {
                    // Check peer count
                    let mut peers = self.peers.write().await;
                    if peers.len() >= MAX_PEERS {
                        return Err(NodeError::Network("Maximum peers reached".into()));
                    }

                    // Store peer info and secret
                    peers.insert(addr, peer_info);
                    self.peer_secrets.write().await.insert(addr, shared_secret);

                    return Ok(());
                }
                Ok(Err(e)) => {
                    // Failed handshake - retry with backoff
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                    continue;
                }
                Err(_) => {
                    // Timeout - retry with backoff
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                    continue;
                }
            }
        }

        Err(NodeError::Network(format!(
            "Could not connect to {} after {} attempts",
            addr, max_attempts
        )))
    }

    pub async fn perform_handshake(
        &self,
        stream: &mut TcpStream,
        is_initiator: bool,
    ) -> Result<(PeerInfo, Vec<u8>), NodeError> {
        // Configure TCP socket first
        stream.set_nodelay(true)?;

        // Generate local nonce for this handshake instance
        let mut local_nonce = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut local_nonce)
            .map_err(|_| NodeError::Network("Failed to generate nonce".into()))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let blockchain_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_block_count() as u32
        };

        // Create base handshake message
        let handshake = HandshakeMessage {
            version: NETWORK_VERSION,
            timestamp,
            nonce: local_nonce,
            public_key: self.private_key_der.clone(),
            node_id: self.node_id.clone(),
            network_id: self.network_id,
            blockchain_height,
            signature: Vec::new(), // Will fill after serializing
        };

        // Create and sign the message
        let mut data_to_sign = Vec::with_capacity(40 + self.node_id.len());
        data_to_sign.extend_from_slice(&local_nonce);
        data_to_sign.extend_from_slice(&timestamp.to_be_bytes());
        data_to_sign.extend_from_slice(self.node_id.as_bytes());

        let key_pair = Ed25519KeyPair::from_pkcs8(&self.private_key_der)
            .map_err(|_| NodeError::Network("Invalid private key".into()))?;

        let signature = key_pair.sign(&data_to_sign);

        // Complete handshake message with signature
        let mut complete_handshake = handshake;
        complete_handshake.signature = signature.as_ref().to_vec();

        // Exchange messages based on role
        let (our_msg, their_msg) = if is_initiator {
            // INITIATOR FLOW

            // Send our handshake first
            let encoded = match bincode::serialize(&complete_handshake) {
                Ok(e) => e,
                Err(e) => return Err(NodeError::Network(format!("Serialization error: {}", e))),
            };

            // Send length prefix and message with timeout
            match tokio::time::timeout(Duration::from_secs(5), async {
                stream
                    .write_all(&(encoded.len() as u32).to_be_bytes())
                    .await?;
                stream.write_all(&encoded).await?;
                stream.flush().await?;
                Ok::<_, NodeError>(())
            })
            .await
            {
                Ok(Ok(_)) => (),
                Ok(Err(e)) => return Err(NodeError::Network(format!("Write error: {}", e))),
                Err(_) => return Err(NodeError::Network("Write timeout".into())),
            }

            // Wait for their response
            let mut len_bytes = [0u8; 4];
            match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_bytes))
                .await
            {
                Ok(Ok(_)) => (),
                Ok(Err(e)) => return Err(NodeError::Network(format!("Read length error: {}", e))),
                Err(_) => return Err(NodeError::Network("Read timeout".into())),
            }

            // Validate message length
            let len = u32::from_be_bytes(len_bytes) as usize;
            if len > 1024 * 1024 {
                // 1MB max message size
                return Err(NodeError::Network("Incoming message too large".into()));
            }

            // Read their handshake message
            let mut buffer = vec![0u8; len];
            match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buffer)).await
            {
                Ok(Ok(_)) => (),
                Ok(Err(e)) => return Err(NodeError::Network(format!("Read message error: {}", e))),
                Err(_) => return Err(NodeError::Network("Read timeout".into())),
            }

            let their_handshake = match bincode::deserialize(&buffer) {
                Ok(msg) => msg,
                Err(e) => return Err(NodeError::Network(format!("Deserialization error: {}", e))),
            };

            (complete_handshake, their_handshake)
        } else {
            // RESPONDER FLOW

            // Read their handshake first
            let mut len_bytes = [0u8; 4];
            match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_bytes))
                .await
            {
                Ok(Ok(_)) => (),
                Ok(Err(e)) => return Err(NodeError::Network(format!("Read length error: {}", e))),
                Err(_) => return Err(NodeError::Network("Read timeout".into())),
            }

            let len = u32::from_be_bytes(len_bytes) as usize;
            if len > 1024 * 1024 {
                return Err(NodeError::Network("Incoming message too large".into()));
            }

            let mut buffer = vec![0u8; len];
            match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buffer)).await
            {
                Ok(Ok(_)) => (),
                Ok(Err(e)) => return Err(NodeError::Network(format!("Read message error: {}", e))),
                Err(_) => return Err(NodeError::Network("Read timeout".into())),
            }

            let their_handshake: HandshakeMessage = match bincode::deserialize(&buffer) {
                Ok(msg) => msg,
                Err(e) => return Err(NodeError::Network(format!("Deserialization error: {}", e))),
            };

            // Now send our response
            let encoded = match bincode::serialize(&complete_handshake) {
                Ok(e) => e,
                Err(e) => return Err(NodeError::Network(format!("Serialization error: {}", e))),
            };

            match tokio::time::timeout(Duration::from_secs(5), async {
                stream
                    .write_all(&(encoded.len() as u32).to_be_bytes())
                    .await?;
                stream.write_all(&encoded).await?;
                stream.flush().await?;
                Ok::<_, NodeError>(())
            })
            .await
            {
                Ok(Ok(_)) => (),
                Ok(Err(e)) => return Err(NodeError::Network(format!("Write error: {}", e))),
                Err(_) => return Err(NodeError::Network("Write timeout".into())),
            }

            (complete_handshake, their_handshake)
        };

        // Validate their handshake (same for both initiator and responder)
        match self.validate_handshake(&their_msg, &our_msg.nonce).await {
            Ok(_) => (),
            Err(e) => {
                return Err(NodeError::Network(format!(
                    "Handshake validation failed: {}",
                    e
                )))
            }
        }

        // Generate shared secret for ongoing communication
        let shared_secret = self.derive_shared_secret(&local_nonce, &their_msg.nonce)?;

        // Return peer info and shared secret
        Ok((PeerInfo::new(stream.peer_addr()?), shared_secret))
    }

    async fn validate_handshake(
        &self,
        msg: &HandshakeMessage,
        our_nonce: &[u8; 32],
    ) -> Result<(), NodeError> {
        // Check network ID
        if msg.network_id != self.network_id {
            return Err(NodeError::Network(format!(
                "Network ID mismatch: {:?} != {:?}",
                msg.network_id, self.network_id
            )));
        }

        // Check protocol version
        if msg.version != NETWORK_VERSION {
            return Err(NodeError::Network(format!(
                "Version mismatch: {} != {}",
                msg.version, NETWORK_VERSION
            )));
        }

        // Verify timestamp is within acceptable range (2 minutes)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if msg.timestamp < now.saturating_sub(120) || msg.timestamp > now + 120 {
            return Err(NodeError::Network("Invalid timestamp".into()));
        }

        // Reconstruct signed data
        let mut verify_data = Vec::new();
        verify_data.extend_from_slice(&msg.nonce);
        verify_data.extend_from_slice(&msg.timestamp.to_be_bytes());
        verify_data.extend_from_slice(msg.node_id.as_bytes());

        // Verify signature
        match ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &msg.public_key)
            .verify(&verify_data, &msg.signature)
        {
            Ok(_) => Ok(()),
            Err(_) => Err(NodeError::Network("Invalid signature".into())),
        }
    }

    fn derive_shared_secret(
        &self,
        local_nonce: &[u8; 32],
        remote_nonce: &[u8; 32],
    ) -> Result<Vec<u8>, NodeError> {
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(local_nonce);
        combined.extend_from_slice(remote_nonce);

        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(&combined);

        let mut shared_secret = [0u8; 32];
        prk.expand(&[b"blockchain_p2p"], ring::hkdf::HKDF_SHA256)
            .map_err(|_| NodeError::Network("Failed to derive shared secret".into()))?
            .fill(&mut shared_secret)
            .map_err(|_| NodeError::Network("Failed to fill shared secret".into()))?;

        Ok(shared_secret.to_vec())
    }

    pub fn check_subnet_diversity(
        &self,
        peer_info: &PeerInfo,
        peers: &HashMap<SocketAddr, PeerInfo>,
    ) -> bool {
        const MAX_SUBNET_RATIO: f64 = 0.125; // 1/8 maximum per subnet
        const MIN_DIFFERENT_SUBNETS: usize = 3;

        let mut subnet_counts: HashMap<SubnetGroup, usize> = HashMap::new();
        let mut total_peers = 0;

        // Count peers per subnet
        for peer in peers.values() {
            *subnet_counts.entry(peer.subnet_group).or_insert(0) += 1;
            total_peers += 1;
        }

        // Check if adding this peer would violate our diversity requirements
        let current_subnet_count = subnet_counts.get(&peer_info.subnet_group).unwrap_or(&0);
        let max_allowed = (total_peers as f64 * MAX_SUBNET_RATIO).ceil() as usize;

        // Allow more peers per subnet if we don't have minimum different subnets yet
        if subnet_counts.len() < MIN_DIFFERENT_SUBNETS {
            return true;
        }

        current_subnet_count + 1 <= max_allowed
    }

    async fn add_verified_peer(&self, addr: SocketAddr, info: PeerInfo) -> Result<(), NodeError> {
        // Check subnet distribution
        let mut peers = self.peers.write().await;
        let mut subnet_counts = HashMap::new();

        for (peer_addr, peer_info) in peers.iter() {
            if let Some(subnet) = peer_info.get_subnet(peer_addr.ip()) {
                *subnet_counts.entry(subnet).or_insert(0) += 1;
            }
        }

        if let Some(subnet) = info.get_subnet(addr.ip()) {
            const MAX_PER_SUBNET: usize = 3;
            if subnet_counts.get(&subnet).unwrap_or(&0) >= &MAX_PER_SUBNET {
                return Err(NodeError::Network(
                    "Too many peers from same subnet".to_string(),
                ));
            }
        }

        // Add peer if passes all checks
        peers.insert(addr, info);
        Ok(())
    }

    // Monitor peer connection - used by both incoming and outgoing connections
    async fn monitor_peer_connection(&self, addr: SocketAddr) -> Result<(), NodeError> {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut failures = 0;
        const MAX_FAILURES: u32 = 3;

        while failures < MAX_FAILURES {
            interval.tick().await;

            // Check if peer is still in our list
            if !self.peers.read().await.contains_key(&addr) {
                break;
            }

            // Verify peer is responsive
            match self.check_peer_health_internal(addr).await {
                Ok(_) => {
                    failures = 0;
                    // Update last seen
                    if let Some(peer) = self.peers.write().await.get_mut(&addr) {
                        peer.last_seen = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                    }
                }
                Err(_) => {
                    failures += 1;
                    warn!(
                        "Peer health check failed for {} ({}/{})",
                        addr, failures, MAX_FAILURES
                    );
                    tokio::time::sleep(Duration::from_secs(1 << failures)).await;
                }
            }
        }

        // Remove unresponsive peer
        if failures >= MAX_FAILURES {
            warn!("Removing unresponsive peer {}", addr);
            let mut peers = self.peers.write().await;
            peers.remove(&addr);
        }

        Ok(())
    }

    async fn request_peer_list(&self, addr: SocketAddr) -> Result<Vec<SocketAddr>, NodeError> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| NodeError::Network(format!("Connection failed: {}", e)))?;

        let (mut reader, mut writer) = stream.into_split();

        let request = NetworkMessage::GetPeers;
        let message = bincode::serialize(&request)?;
        writer.write_all(&message).await?;

        let mut response = Vec::new();
        let read_future = reader.read_to_end(&mut response);

        match tokio::time::timeout(Duration::from_secs(5), read_future).await {
            Ok(Ok(_)) => {
                let peer_list: NetworkMessage = bincode::deserialize(&response)?;
                match peer_list {
                    NetworkMessage::Peers(peers) => Ok(peers),
                    _ => Err(NodeError::Network("Invalid response type".to_string())),
                }
            }
            Ok(Err(e)) => Err(NodeError::Network(format!("Read error: {}", e))),
            Err(_) => Err(NodeError::Network("Request timeout".to_string())),
        }
    }

    pub async fn handle_connection(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
        tx: mpsc::Sender<NetworkEvent>,
    ) -> Result<(), NodeError> {
        // Configure socket
        let socket = Socket::from(stream.into_std()?);
        socket.set_nodelay(true)?;

        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(15));
        socket.set_tcp_keepalive(&keepalive)?;

        socket.set_recv_buffer_size(256 * 1024)?;
        socket.set_send_buffer_size(256 * 1024)?;

        #[cfg(unix)]
        socket.set_reuse_port(true)?;

        // Convert back to TcpStream
        let mut stream = TcpStream::from_std(socket.into())?;

        // Perform handshake
        let (peer_info, shared_secret) = tokio::time::timeout(
            Duration::from_secs(10),
            self.perform_handshake(&mut stream, false),
        )
        .await
        .map_err(|_| NodeError::Network("Handshake timeout".into()))??;

        // Version check
        if peer_info.version != NETWORK_VERSION {
            return Err(NodeError::Network(format!(
                "Version mismatch: {} (expected {})",
                peer_info.version, NETWORK_VERSION
            )));
        }

        // Verify peer slots and diversity
        {
            let mut peers = self.peers.write().await;
            if peers.len() >= MAX_PEERS {
                return Err(NodeError::Network("Maximum peers reached".into()));
            }

            let subnet_group = peer_info.subnet_group;
            let subnet_peers = peers
                .values()
                .filter(|p| p.subnet_group == subnet_group)
                .count();

            if subnet_peers >= MAX_PEERS / 8 {
                return Err(NodeError::Network("Subnet peer limit reached".into()));
            }

            peers.insert(addr, peer_info.clone());
        }

        // Store encryption secret
        self.peer_secrets
            .write()
            .await
            .insert(addr, shared_secret.clone());

        // Notify peer join
        tx.send(NetworkEvent::PeerJoin(addr))
            .await
            .map_err(|e| NodeError::Network(format!("Failed to send join event: {}", e)))?;

        // Message handling loop
        let (mut reader, _writer) = stream.into_split();
        let mut buffer = vec![0u8; 64 * 1024]; // Use Vec instead of BytesMut

        'connection: loop {
            let read_result =
                tokio::time::timeout(Duration::from_secs(60), reader.read(&mut buffer)).await;

            match read_result {
                Ok(Ok(0)) => break, // Connection closed normally
                Ok(Ok(n)) => {
                    let msg_data = &buffer[..n];

                    // Decrypt and process message
                    let decrypted = match self.decrypt_message(msg_data, &shared_secret) {
                        Ok(msg) => msg,
                        Err(e) => {
                            warn!("Decryption failed from {}: {}", addr, e);
                            break 'connection;
                        }
                    };

                    // Handle message
                    if let Err(e) = self.handle_peer_message(msg_data, addr, &tx).await {
                        warn!("Message handling error from {}: {}", addr, e);
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
        {
            let mut peers = self.peers.write().await;
            peers.remove(&addr);
        }

        self.peer_secrets.write().await.remove(&addr);

        // Notify disconnect
        tx.send(NetworkEvent::PeerLeave(addr))
            .await
            .map_err(|e| NodeError::Network(format!("Failed to send leave event: {}", e)))?;

        Ok(())
    }

    async fn handle_peer_message(
        &self,
        data: &[u8],
        addr: SocketAddr,
        tx: &mpsc::Sender<NetworkEvent>,
    ) -> Result<(), NodeError> {
        const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024;
        const TX_BROADCAST_MIN_PEERS: usize = 8;
        const MAX_BLOCK_RANGE: u32 = 1000;
        const MAX_PARALLEL_BROADCASTS: usize = 10;

        if data.len() > MAX_MESSAGE_SIZE {
            self.record_peer_failure(addr).await;
            return Err(NodeError::Network("Message too large".into()));
        }

        let message_hash = blake3::hash(data);
        if !self.network_bloom.insert(message_hash.as_bytes()) {
            return Ok(());
        }

        let message: NetworkMessage = match bincode::deserialize(data) {
            Ok(msg) => msg,
            Err(_) => {
                self.record_peer_failure(addr).await;
                return Err(NodeError::Network("Invalid message format".into()));
            }
        };

        let rate_key = format!("peer_msg:{}:{:?}", addr, std::mem::discriminant(&message));
        if !self.rate_limiter.check_limit(&rate_key) {
            self.record_peer_failure(addr).await;
            return Err(NodeError::Network("Rate limit exceeded".into()));
        }

        match message {
            NetworkMessage::WalletInfo { .. } | NetworkMessage::GetWalletInfo { .. } => {
                self.handle_wallet_message(message, addr).await?
            }

            NetworkMessage::Transaction(tx_data) => {
                let tx_ref = Arc::new(tx_data);
                let tx_hash = tx_ref.create_hash();

                if let Some(cached) = self.validation_cache.get(&tx_hash) {
                    if cached.valid {
                        let peers = self.peers.read().await;
                        let selected_peers =
                            self.select_broadcast_peers(&peers, TX_BROADCAST_MIN_PEERS);
                        drop(peers);
                        return self
                            .broadcast_transaction(tx_ref, addr, selected_peers)
                            .await;
                    }
                    return Ok(());
                }

                let blockchain = self.blockchain.read().await;
                if blockchain.validate_transaction(&tx_ref, None).await.is_ok() {
                    self.validation_cache.insert(
                        tx_hash.clone(),
                        ValidationCacheEntry {
                            valid: true,
                            timestamp: SystemTime::now(),
                            verification_count: 1,
                        },
                    );

                    blockchain.add_transaction((*tx_ref).clone()).await?;

                    let peers = self.peers.read().await;
                    let selected_peers =
                        self.select_broadcast_peers(&peers, TX_BROADCAST_MIN_PEERS);
                    drop(peers);

                    let broadcast_fut =
                        self.broadcast_transaction(Arc::clone(&tx_ref), addr, selected_peers);
                    let notify_fut = tx.send(NetworkEvent::NewTransaction((*tx_ref).clone()));

                    let (broadcast_res, notify_res) = tokio::join!(broadcast_fut, notify_fut);
                    broadcast_res?;
                    notify_res
                        .map_err(|e| NodeError::Network(format!("Notification error: {}", e)))?;
                }
            }

            NetworkMessage::Block(block) => {
                let block_ref = Arc::new(block);

                // Get current state with minimal locking
                let (current_difficulty, last_block) = {
                    let blockchain = self.blockchain.read().await;
                    (
                        blockchain.get_current_difficulty().await,
                        blockchain.get_last_block(),
                    )
                };

                // Enforce chain continuity first - cheapest check
                if let Some(last_block) = last_block {
                    if block_ref.previous_hash != last_block.hash {
                        self.record_peer_failure(addr).await;
                        return Err(NodeError::Network("Invalid block continuity".into()));
                    }

                    // Calculate allowable difficulty range for 2-second blocks
                    let time_diff = block_ref.timestamp.saturating_sub(last_block.timestamp);
                    let expected_difficulty = Block::adjust_dynamic_difficulty(
                        last_block.difficulty,
                        time_diff,
                        block_ref.index,
                        &mut DifficultyOracle::new(),
                        block_ref.timestamp,
                    );

                    // Allow for network propagation with 2-second blocks
                    // But prevent more than 4x difficulty swing in either direction
                    let min_allowed = expected_difficulty.saturating_sub(expected_difficulty / 4);
                    let max_allowed = expected_difficulty + (expected_difficulty / 4);

                    if block_ref.difficulty < min_allowed || block_ref.difficulty > max_allowed {
                        warn!(
                            "Rejected block {} - difficulty {} outside allowed range ({} to {})",
                            block_ref.index, block_ref.difficulty, min_allowed, max_allowed
                        );
                        self.record_peer_failure(addr).await;
                        return Err(NodeError::Network(
                            "Block difficulty outside allowed range".into(),
                        ));
                    }
                } else {
                    // Genesis block or initial sync
                    if block_ref.difficulty < 16 {
                        // Minimum difficulty floor
                        return Err(NodeError::Network("Block difficulty below minimum".into()));
                    }
                }

                // Verify the PoW meets claimed difficulty
                if !block_ref.verify_pow() {
                    warn!(
                        "Rejected block {} - hash doesn't meet claimed difficulty {}",
                        block_ref.index, block_ref.difficulty
                    );
                    self.record_peer_failure(addr).await;
                    return Err(NodeError::Network(
                        "Block hash doesn't meet claimed difficulty".into(),
                    ));
                }

                // Only process through velocity manager after security checks pass
                if let Some(velocity) = &self.velocity_manager {
                    let peers = self.peers.read().await;
                    if velocity.process_block(&block_ref, &peers).await.is_ok() {
                        return Ok(());
                    }
                    drop(peers);
                }

                // Verify and propagate block
                if self.verify_block_parallel(&block_ref).await? {
                    self.blockchain.write().await.save_block(&block_ref).await?;

                    // Send network event
                    tx.send(NetworkEvent::NewBlock((*block_ref).clone()))
                        .await
                        .map_err(|e| {
                            NodeError::Network(format!("Failed to send block event: {}", e))
                        })?;

                    // Broadcast to subset of peers for better scalability
                    let selected_peers = {
                        let peers = self.peers.read().await;
                        let peer_count = (peers.len() / 2).max(8); // At least 8 peers, up to 50% of total
                        self.select_broadcast_peers(&peers, peer_count)
                    };

                    for peer_addr in selected_peers {
                        if peer_addr != addr {
                            // Don't send back to source
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
                // Create response channel
                let (response_tx, response_rx) = oneshot::channel();

                // Send request event with struct variant
                tx.send(NetworkEvent::ChainRequest {
                    start,
                    end,
                    requester: addr,
                    response_channel: response_tx,
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
                tx.send(NetworkEvent::ChainResponse(blocks))
                    .await
                    .map_err(|e| {
                        NodeError::Network(format!("Failed to send chain response event: {}", e))
                    })?;
            }

            NetworkMessage::Shred(shred) => {
                if let Some(velocity) = &self.velocity_manager {
                    if let Ok(Some(block)) = velocity.handle_shred(shred, addr).await {
                        let block_ref = Arc::new(block);
                        if self.verify_block_parallel(&block_ref).await? {
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
                            let range = end_height.saturating_sub(start_height);
                            if range > MAX_BLOCK_RANGE {
                                return Err(NodeError::Network("Block range too large".into()));
                            }

                            let blockchain = self.blockchain.read().await;
                            let peers = self.peers.read().await;

                            for chunk_start in (start_height..=end_height).step_by(100) {
                                let chunk_end = (chunk_start + 100).min(end_height);

                                let blocks: Vec<Arc<Block>> = (chunk_start..=chunk_end)
                                    .filter_map(|height| blockchain.get_block(height).ok())
                                    .map(Arc::new)
                                    .collect();

                                let futures: Vec<_> = blocks
                                    .iter()
                                    .map(|block_ref| velocity.process_block(block_ref, &peers))
                                    .collect();

                                futures::future::join_all(futures)
                                    .await
                                    .into_iter()
                                    .collect::<Result<Vec<_>, _>>()
                                    .map_err(|e| NodeError::Network(e.to_string()))?;
                            }
                        }
                    }
                }
            }

            _ => {}
        }

        Ok(())
    }

    #[inline]
    async fn broadcast_transaction(
        &self,
        tx: Arc<Transaction>,
        source: SocketAddr,
        peers: Vec<SocketAddr>,
    ) -> Result<(), NodeError> {
        let broadcast_futures = peers
            .into_iter()
            .filter(|&peer| peer != source)
            .map(|peer| {
                let tx = Arc::clone(&tx);
                async move {
                    self.send_message(peer, &NetworkMessage::Transaction((*tx).clone()))
                        .await
                }
            });

        futures::future::join_all(broadcast_futures)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }

    fn encrypt_message(
        &self,
        message: &NetworkMessage,
        shared_secret: &[u8],
    ) -> Result<Vec<u8>, NodeError> {
        // Use ChaCha20-Poly1305 for encryption
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

        // Encrypt
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
        if encrypted.len() < 12 {
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

        // Decrypt
        let mut in_out = ciphertext.to_vec();
        key.open_in_place(nonce, ring::aead::Aad::empty(), &mut in_out)
            .map_err(|_| NodeError::Network("Decryption failed".into()))?;

        // Deserialize message
        Ok(bincode::deserialize(&in_out)?)
    }

    async fn handle_wallet_message(
        &self,
        message: NetworkMessage,
        addr: SocketAddr,
    ) -> Result<(), NodeError> {
        match message {
            NetworkMessage::WalletInfo {
                address,
                public_key_hex,
                signature,
            } => {
                // Compute the hash of the address and public key
                let mut hasher = DefaultHasher::new();
                address.hash(&mut hasher);
                public_key_hex.hash(&mut hasher);
                let msg_hash = hasher.finish().to_be_bytes();

                // If the message hash is already processed, return early
                if !self.network_bloom.insert(&msg_hash) {
                    return Ok(());
                }

                // Decode the public key and prepare the message for signature verification
                let pub_key_bytes = match hex::decode(&public_key_hex) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return Err(NodeError::Network(format!("Invalid public key hex: {}", e)))
                    }
                };

                let msg = {
                    let mut msg = Vec::with_capacity(address.len() + public_key_hex.len());
                    msg.extend_from_slice(address.as_bytes());
                    msg.extend_from_slice(&pub_key_bytes);
                    msg
                };

                // Verify the wallet's signature
                if !Wallet::verify_signature(&msg, &signature, &pub_key_bytes)? {
                    return Err(NodeError::Network("Invalid wallet signature".to_string()));
                }

                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn query_wallet_exists(
        &self,
        peer: SocketAddr,
        address: &str,
    ) -> Result<bool, NodeError> {
        let message = NetworkMessage::GetWalletInfo {
            address: address.to_string(),
        };
        let response = self.send_message_with_response(peer, &message).await?;

        match response {
            NetworkMessage::WalletInfoResponse { exists, .. } => Ok(exists),
            _ => Ok(false),
        }
    }

    pub async fn send_message_with_response(
        &self,
        addr: SocketAddr,
        message: &NetworkMessage,
    ) -> Result<NetworkMessage, NodeError> {
        let mut stream = TcpStream::connect(addr).await?;
        let data = bincode::serialize(message)?;
        stream.write_all(&data).await?;

        let mut buffer = Vec::new();
        let mut reader = tokio::io::BufReader::new(stream);
        reader.read_to_end(&mut buffer).await?;

        Ok(bincode::deserialize(&buffer)?)
    }

    pub async fn process_block_velocity(
        &self,
        block: &Block,
        from_peer: Option<SocketAddr>,
    ) -> Result<(), NodeError> {
        if let Some(velocity) = &self.velocity_manager {
            let peers = self.peers.read().await;

            // Select peers based on latency and reliability
            let selected_peers: Vec<SocketAddr> = peers
                .iter()
                .filter(|(addr, info)| {
                    if let Some(from) = from_peer {
                        if *addr == &from {
                            return false;
                        }
                    }

                    // Only select peers with good latency
                    info.latency < 200
                        && info.last_seen
                            > SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                                - 300
                })
                .map(|(addr, _)| *addr)
                .collect();

            if selected_peers.is_empty() {
                return Ok(());
            }

            // Process with Velocity
            velocity
                .process_block(block, &peers)
                .await
                .map_err(|e| NodeError::Network(e.to_string()))?;
        } else {
            // Legacy processing
            let peers = self.peers.read().await;
            let broadcast_peers = self.select_broadcast_peers(&peers, peers.len() / 2);

            let message = NetworkMessage::Block(block.clone());
            for peer_addr in broadcast_peers {
                if let Some(from) = from_peer {
                    if from == peer_addr {
                        continue;
                    }
                }

                if let Err(e) = self.send_message(peer_addr, &message).await {
                    warn!("Failed to send block to {}: {}", peer_addr, e);
                    self.record_peer_failure(peer_addr).await;
                }
            }
        }
        Ok(())
    }

    pub fn select_broadcast_peers(
        &self,
        peers: &HashMap<SocketAddr, PeerInfo>,
        target_count: usize,
    ) -> Vec<SocketAddr> {
        const MAX_PER_ASN: usize = 3;
        const MIN_DIFFERENT_ASNS: usize = 3;
        const BATCH_SIZE: usize = 100; // Process peers in batches for large networks

        if peers.is_empty() || target_count == 0 {
            return Vec::new();
        }

        let peer_count = peers.len();
        let actual_target_count = std::cmp::min(target_count, peer_count);

        // Pre-allocate collections with exact sizes
        let mut selected = Vec::with_capacity(actual_target_count);
        let mut asn_counts =
            HashMap::with_capacity(actual_target_count.min(peer_count / MAX_PER_ASN));
        let mut different_asns = HashSet::with_capacity(MIN_DIFFERENT_ASNS);

        // Use custom sorting to avoid collecting whole peer list
        let mut peer_list: Vec<_> = peers
            .iter()
            .map(|(addr, info)| (info.latency, std::cmp::Reverse(info.last_seen), addr, info))
            .collect();

        // Sort in place
        peer_list.sort_unstable_by_key(|&(latency, last_seen, _, _)| (latency, last_seen));

        // Process in batches
        for chunk in peer_list.chunks(BATCH_SIZE) {
            let mut futures = Vec::with_capacity(chunk.len());

            // Prepare ASN lookups in batch
            for (_, _, addr, _) in chunk {
                futures.push(self.get_peer_asn(addr));
            }

            // Process batch results
            let asn_results = block_on(futures::future::join_all(futures));

            for ((_, _, addr, _), asn) in chunk.iter().zip(asn_results) {
                if selected.len() >= actual_target_count {
                    return selected;
                }

                if let Some(asn) = asn {
                    let asn_count = asn_counts.entry(asn.clone()).or_insert(0);
                    if *asn_count < MAX_PER_ASN
                        && (different_asns.len() >= MIN_DIFFERENT_ASNS
                            || !different_asns.contains(&asn))
                    {
                        selected.push(**addr);
                        *asn_count += 1;
                        different_asns.insert(asn);
                    }
                }
            }
        }

        selected
    }

    async fn handle_network_event(&self, event: NetworkEvent) -> Result<(), NodeError> {
        match event {
            NetworkEvent::NewTransaction(tx) => {
                let tx_bytes = bincode::serialize(&tx)?;
                if self.network_bloom.insert(&tx_bytes) {
                    // Clone tx before validation and moving
                    let tx_for_blockchain = tx.clone();

                    // Validate transaction before adding
                    if self.validate_transaction(&tx, None).await? {
                        self.blockchain
                            .write()
                            .await
                            .add_transaction(tx_for_blockchain)
                            .await?;

                        // Broadcast to subset of peers
                        let peers = self.peers.read().await;
                        let selected_peers =
                            self.select_broadcast_peers(&peers, peers.len().min(8));
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
            }

            NetworkEvent::NewBlock(block) => {
                let block_hash = block.calculate_hash_for_block();
                if self.network_bloom.insert(&block_hash) {
                    // Verify block before processing
                    if self.verify_block_parallel(&block).await? {
                        self.blockchain.write().await.save_block(&block).await?;

                        // Broadcast to peers
                        let peers = self.peers.read().await;
                        let selected_peers =
                            self.select_broadcast_peers(&peers, peers.len().min(16));
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
                if let Err(_) = response_channel.send(blocks.clone()) {
                    warn!("Failed to send chain response through channel");
                }

                // Also send through network message
                if let Some(peer_info) = self.peers.read().await.get(&requester) {
                    let response = NetworkMessage::Blocks(blocks);
                    if let Err(e) = self.send_message(requester, &response).await {
                        warn!("Failed to send chain response to {}: {}", requester, e);
                    }
                }
            }

            NetworkEvent::ChainResponse(blocks) => {
                let mut blockchain = self.blockchain.write().await;
                for block in blocks {
                    if self.verify_block_parallel(&block).await? {
                        if let Err(e) = blockchain.validate_new_block(&block).await {
                            warn!("Invalid block {} in chain response: {}", block.index, e);
                            continue;
                        }
                        if let Err(e) = blockchain.save_block(&block).await {
                            warn!("Failed to save valid block {}: {}", block.index, e);
                        }
                    }
                }
            }
            NetworkEvent::PeerJoin(addr) => {
                let mut peers = self.peers.write().await;
                if !peers.contains_key(&addr) {
                    // Add with fresh PeerInfo
                    peers.insert(addr, PeerInfo::new(addr));

                    // Start connection monitoring for new peer
                    let node = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node.monitor_peer_connection(addr).await {
                            warn!("Peer monitoring ended for {}: {}", addr, e);
                        }
                    });
                }
            }

            NetworkEvent::PeerLeave(addr) => {
                // Clean up peer state
                self.peers.write().await.remove(&addr);
                self.peer_secrets.write().await.remove(&addr);

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
        }
        Ok(())
    }

    pub async fn verify_block_parallel(&self, block: &Block) -> Result<bool, NodeError> {
        const PERMIT_TIMEOUT: Duration = Duration::from_millis(500);
        const CACHE_DURATION_SECS: u64 = 3600;

        // Quick hash lookup using existing hash
        let block_hash = hex::encode(block.hash);

        // Fast cache check with early return
        if let Some(entry) = self.validation_cache.get(&block_hash) {
            if SystemTime::now()
                .duration_since(entry.timestamp)
                .map_or(true, |d| d.as_secs() < CACHE_DURATION_SECS)
            {
                return Ok(entry.valid);
            }
        }

        // Fast permit acquisition
        let _permit = match tokio::time::timeout(
            PERMIT_TIMEOUT,
            self.validation_pool.acquire_validation_permit(),
        )
        .await
        {
            Ok(permit) => permit?,
            Err(_) => return Ok(false), // Fail fast if can't get permit
        };

        // Minimal blockchain lock time
        let validation_result = {
            let blockchain = self.blockchain.read().await;
            blockchain.validate_block(block).await.is_ok()
        };

        if validation_result {
            // Update cache immediately
            self.validation_cache.insert(
                block_hash,
                ValidationCacheEntry {
                    valid: true,
                    timestamp: SystemTime::now(),
                    verification_count: 1,
                },
            );

            // Update header sentinel if available
            if let Some(ref sentinel) = self.header_sentinel {
                let block_info = BlockHeaderInfo {
                    height: block.index,
                    hash: block.hash,
                    prev_hash: block.previous_hash,
                    timestamp: block.timestamp,
                };

                // Process header verification
                if let Err(e) = sentinel.add_verified_header(block_info).await {
                    warn!(
                        "Failed to add verified header for block {}: {}",
                        block.index, e
                    );
                }
            }

            // Quick atomic counter update
            self.validation_pool
                .active_validations
                .fetch_add(1, Ordering::Release);
        }

        Ok(validation_result)
    }

    pub async fn send_message(
        &self,
        addr: SocketAddr,
        message: &NetworkMessage,
    ) -> Result<(), NodeError> {
        let mut stream = TcpStream::connect(addr).await?;
        let data = bincode::serialize(message)?;
        stream.write_all(&data).await?;
        Ok(())
    }

    fn multiaddr_to_socketaddr(&self, addr: &Multiaddr) -> Result<SocketAddr, NodeError> {
        use libp2p::core::multiaddr::Protocol;

        let components: Vec<_> = addr.iter().collect();
        match (components.get(0), components.get(1)) {
            (Some(Protocol::Ip4(ip)), Some(Protocol::Tcp(port))) => {
                Ok(SocketAddr::new(IpAddr::V4(*ip), *port))
            }
            _ => Err(NodeError::Network("Invalid multiaddr format".to_string())),
        }
    }

    async fn local_addr(&self) -> SocketAddr {
        self.peers
            .read()
            .await
            .iter()
            .next()
            .map(|(addr, _)| *addr)
            .unwrap_or_else(|| {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), DEFAULT_PORT)
            })
    }

    async fn get_blocks(&self, start: u32, end: u32) -> Result<Vec<Block>, NodeError> {
        let mut blocks = Vec::new();
        let blockchain = self.blockchain.read().await;

        for idx in start..=end {
            if let Ok(block) = blockchain.get_block(idx) {
                blocks.push(block);
            }
        }

        Ok(blocks)
    }

    async fn update_validation_count(&self, delta: i64) {
        self.validation_pool
            .active_validations
            .fetch_add(1, Ordering::SeqCst);
    }

    async fn validate_transaction(
        &self,
        tx: &Transaction,
        block: Option<&Block>,
    ) -> Result<bool, NodeError> {
        let blockchain = self.blockchain.read().await;
        match blockchain.validate_transaction(tx, block).await {
            Ok(_) => Ok(true),
            Err(e) => Err(NodeError::InvalidTransaction(e.to_string())),
        }
    }

    // BFT Consensus related methods
    async fn handle_consensus_message(
        &self,
        message: ConsensusMessage,
        sender: &str,
    ) -> Result<(), NodeError> {
        match message {
            ConsensusMessage::PrepareRequest(block) => {
                let is_valid = self.verify_block_parallel(&block).await?;
                let response = ConsensusMessage::PrepareResponse(is_valid, self.node_id.clone());

                // Broadcast response to all peers
                for peer in self.peers.read().await.keys() {
                    self.send_message(*peer, &NetworkMessage::Block(block.clone()))
                        .await?;
                }
            }
            ConsensusMessage::PrepareResponse(valid, validator) => {
                let mut bft_state = self.bft_state.write().await;
                let blockchain = block_on(self.blockchain.read());
                let block = blockchain
                    .get_last_block()
                    .ok_or_else(|| NodeError::Blockchain("No last block found".to_string()))?;
                let block_hash = hex::encode(block.calculate_hash_for_block());
                let block_hash = hex::encode(block.calculate_hash_for_block());

                if valid && bft_state.record_vote("prepare", &block_hash, &validator) {
                    // If we have enough prepare votes, move to commit phase
                    let commit_request = ConsensusMessage::CommitRequest(block_on(async {
                        self.blockchain
                            .read()
                            .await
                            .get_last_block()
                            .ok_or_else(|| NodeError::Blockchain("No block found".to_string()))
                    })?);

                    // Broadcast commit request
                    for peer in self.peers.read().await.keys() {
                        let last_block = self.blockchain.read().await.get_last_block();
                        match last_block {
                            Some(block) => {
                                self.send_message(*peer, &NetworkMessage::Block(block))
                                    .await?;
                            }
                            None => {
                                error!("Error getting last block: No block found");
                            }
                        }
                    }
                }
            }
            ConsensusMessage::CommitRequest(block) => {
                let is_valid = self.verify_block_parallel(&block).await?;
                let response = ConsensusMessage::CommitResponse(is_valid, self.node_id.clone());

                // Broadcast response to all peers
                for peer in self.peers.read().await.keys() {
                    self.send_message(*peer, &NetworkMessage::Block(block.clone()))
                        .await?;
                }
            }
            ConsensusMessage::CommitResponse(valid, validator) => {
                let mut bft_state = self.bft_state.write().await;
                let block_hash = {
                    let blockchain = block_on(self.blockchain.read());
                    let block = blockchain
                        .get_last_block()
                        .ok_or_else(|| NodeError::Blockchain("No last block found".to_string()))?;
                    hex::encode(block.calculate_hash_for_block())
                };

                if valid && bft_state.record_vote("commit", &block_hash, &validator) {
                    // If we have enough commit votes, finalize the block
                    let blockchain = block_on(self.blockchain.read());
                    let block = blockchain
                        .get_last_block()
                        .ok_or_else(|| NodeError::Blockchain("No last block found".to_string()))?;

                    self.blockchain.write().await.save_block(&block).await?;
                    bft_state.last_consensus = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                }
            }
        }
        Ok(())
    }

    async fn request_blocks_velocity(
        &self,
        addr: SocketAddr,
        start: u32,
        end: u32,
    ) -> Result<Vec<Block>, NodeError> {
        if let Some(velocity) = &self.velocity_manager {
            // Use Velocity's optimized block retrieval
            let request = ShredRequestType::Range {
                start_height: start,
                end_height: end,
            };

            let message = NetworkMessage::ShredRequest(request);
            self.send_message(addr, &message).await?;

            self.wait_for_blocks().await
        } else {
            // Use existing block request method
            self.request_blocks(addr, start, end).await
        }
    }

    // Add request tracking
    async fn track_request_completion(
        &self,
        block_hash: [u8; 32],
        request_id: Uuid,
    ) -> Result<(), NodeError> {
        let timeout = Duration::from_secs(30);
        let start = Instant::now();

        while start.elapsed() < timeout {
            if let Some(velocity) = &self.velocity_manager {
                if velocity.is_block_complete(&block_hash).await {
                    self.block_response_channels
                        .write()
                        .await
                        .remove(&request_id);
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Err(NodeError::Network("Block request timeout".into()))
    }

    async fn sync_blockchain(&self) -> Result<(), NodeError> {
        let current_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_block_count() as u32
        };

        let peers = self.peers.read().await;
        let mut highest_block = current_height;

        // Find highest block among peers
        for (_, info) in peers.iter() {
            if info.blocks > highest_block {
                highest_block = info.blocks;
            }
        }

        if highest_block > current_height {
            info!(
                "Syncing blocks {} to {} using Velocity protocol...",
                current_height + 1,
                highest_block
            );

            if let Some(velocity) = &self.velocity_manager {
                // Use Velocity's batch sync
                let request = ShredRequestType::Range {
                    start_height: current_height + 1,
                    end_height: highest_block,
                };

                let selected_peers = self
                    .select_sync_peers(&peers)
                    .into_iter()
                    .take(3)
                    .collect::<Vec<_>>();

                for &peer_addr in &selected_peers {
                    let message = NetworkMessage::ShredRequest(request.clone());
                    if let Err(e) = self.send_message(peer_addr, &message).await {
                        warn!("Failed to request blocks from {}: {}", peer_addr, e);
                        continue;
                    }
                }

                self.wait_for_blocks().await?;
            }
        }

        Ok(())
    }

    fn select_sync_peers(&self, peers: &HashMap<SocketAddr, PeerInfo>) -> Vec<SocketAddr> {
        let mut peer_list: Vec<_> = peers.iter().collect();

        // Sort by latency and block height
        peer_list.sort_by(|a, b| {
            let latency_cmp = a.1.latency.cmp(&b.1.latency);
            if latency_cmp == std::cmp::Ordering::Equal {
                b.1.blocks.cmp(&a.1.blocks)
            } else {
                latency_cmp
            }
        });

        peer_list.into_iter().map(|(addr, _)| *addr).collect()
    }

    pub async fn request_blocks(
        &self,
        addr: SocketAddr,
        start: u32,
        end: u32,
    ) -> Result<Vec<Block>, NodeError> {
        const MAX_BATCH_SIZE: u32 = 500;
        const MAX_PARALLEL_REQUESTS: usize = 4;
        const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

        let mut all_blocks = Vec::new();
        let mut current = start;

        while current <= end {
            let mut batch_futures = Vec::new();

            // Create multiple parallel batch requests
            for _ in 0..MAX_PARALLEL_REQUESTS {
                if current > end {
                    break;
                }

                let batch_end = (current + MAX_BATCH_SIZE - 1).min(end);
                let message = NetworkMessage::GetBlocks {
                    start: current,
                    end: batch_end,
                };

                let request_start = Instant::now();
                let peer_addr = addr;
                let node = self.clone();

                let future = async move {
                    let stream = TcpStream::connect(addr).await?;
                    let mut reader = tokio::io::BufReader::new(stream);

                    let blocks = tokio::time::timeout(REQUEST_TIMEOUT, async {
                        let data = bincode::serialize(&message)?;
                        reader.write_all(&data).await?;

                        let mut buffer = Vec::new();
                        reader.read_to_end(&mut buffer).await?;

                        let response: NetworkMessage = bincode::deserialize(&buffer)?;
                        match response {
                            NetworkMessage::Blocks(blocks) => {
                                let valid_blocks: Vec<_> = blocks
                                    .into_par_iter()
                                    .filter(|block| {
                                        futures::executor::block_on(
                                            node.verify_block_parallel(block),
                                        )
                                        .unwrap_or(false)
                                    })
                                    .collect();
                                Ok(valid_blocks)
                            }
                            _ => Err(NodeError::Network("Unexpected response".into())),
                        }
                    })
                    .await??;

                    // Update peer metrics
                    let mut peers = node.peers.write().await;
                    if let Some(info) = peers.get_mut(&peer_addr) {
                        info.latency = request_start.elapsed().as_millis() as u64;
                    }
                    drop(peers);

                    Ok::<Vec<Block>, NodeError>(blocks)
                };

                batch_futures.push(future);
                current = batch_end + 1;
            }

            // Wait for all batch requests with timeout
            let batch_results = futures::future::join_all(batch_futures).await;

            // Process results and handle errors
            for result in batch_results {
                match result {
                    Ok(blocks) => {
                        all_blocks.extend(blocks);
                    }
                    Err(e) => {
                        // Record failure but continue with other batches
                        self.record_peer_failure(addr).await;
                        warn!("Batch request failed: {}", e);
                    }
                }
            }
        }

        // Sort blocks by index before returning
        all_blocks.sort_by_key(|b| b.index);
        Ok(all_blocks)
    }

    async fn wait_for_blocks(&self) -> Result<Vec<Block>, NodeError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let request_id = Uuid::new_v4();
        let timeout = Duration::from_secs(30);
        let start_time = Instant::now();

        {
            let mut channels = self.block_response_channels.write().await;
            channels.insert(request_id, tx);
        }

        let mut blocks = Vec::new();

        while start_time.elapsed() < timeout {
            match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
                Ok(Some(NetworkMessage::Blocks(new_blocks))) => {
                    for block in new_blocks.iter() {
                        if self.verify_block_parallel(block).await? {
                            blocks.push(block.clone());
                        }
                    }
                    if !blocks.is_empty() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                _ => continue,
            }
        }

        {
            let mut channels = self.block_response_channels.write().await;
            channels.remove(&request_id);
        }

        if blocks.is_empty() {
            return Err(NodeError::Network("No valid blocks received".to_string()));
        }

        // Sort blocks by index before returning
        blocks.sort_by_key(|b| b.index);
        Ok(blocks)
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

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "HybridBehaviourEvent")]
pub struct HybridBehaviour {
    kademlia: Kademlia<MemoryStore>,
}

#[derive(Debug)]
pub enum HybridBehaviourEvent {
    Kademlia(KademliaEvent),
}

// Single implementation of From<KademliaEvent>
impl From<KademliaEvent> for HybridBehaviourEvent {
    fn from(event: KademliaEvent) -> Self {
        HybridBehaviourEvent::Kademlia(event)
    }
}

// Required Debug implementation for components that need it
impl std::fmt::Debug for HybridBehaviour {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridBehaviour")
            .field("kademlia", &"Kademlia<MemoryStore>")
            .finish()
    }
}

// Required trait implementations
impl Clone for Node {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            peers: Arc::clone(&self.peers),
            blockchain: Arc::clone(&self.blockchain),
            network_health: Arc::clone(&self.network_health),
            node_id: self.node_id.clone(),
            tx: self.tx.clone(),
            start_time: self.start_time,
            bft_state: Arc::clone(&self.bft_state),
            validation_pool: Arc::clone(&self.validation_pool),
            validation_cache: Arc::clone(&self.validation_cache),
            block_response_channels: Arc::clone(&self.block_response_channels),
            network_bloom: Arc::clone(&self.network_bloom),
            rate_limiter: Arc::clone(&self.rate_limiter),
            bind_addr: self.bind_addr,
            listener: self.listener.clone(),
            p2p_swarm: Arc::clone(&self.p2p_swarm),
            peer_id: self.peer_id.clone(),
            peer_failures: Arc::clone(&self.peer_failures),
            temporal_verification: Arc::clone(&self.temporal_verification),
            header_sentinel: self.header_sentinel.clone(),
            lock_path: Arc::clone(&self.lock_path),
            velocity_manager: self.velocity_manager.clone(),
            network_id: self.network_id,
            peer_secrets: Arc::clone(&self.peer_secrets),
            private_key_der: self.private_key_der.clone(),
        }
    }
}
