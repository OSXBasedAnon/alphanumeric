use async_trait::async_trait;
use crossbeam_channel::{bounded, Receiver, Sender};
use dashmap::DashMap;
use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use log::warn;
use lru::LruCache;
use reed_solomon_erasure::{galois_8, ReedSolomon};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::a9::blockchain::Block;
use crate::a9::node::Node;
use crate::a9::node::PeerInfo;

// Constants for tuning
const MAX_CONCURRENT_REQUESTS: usize = 100;
const SHRED_CACHE_SIZE: usize = 10_000;
const ERASURE_SHARD_COUNT: usize = 16;
const ERASURE_PARITY_SHARD_COUNT: usize = 4;
const ERASURE_TOTAL_SHARD_COUNT: usize = ERASURE_SHARD_COUNT + ERASURE_PARITY_SHARD_COUNT;
const DIRECT_BLOCK_SHRED_COUNT: u32 = 1;
const ERASURE_FRAME_MAGIC: &[u8; 4] = b"A9E1";
const ERASURE_FRAME_HEADER_LEN: usize = ERASURE_FRAME_MAGIC.len() + std::mem::size_of::<u64>();
const MAX_SUBNET_PEERS: usize = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const BLOOM_FILTER_SIZE: usize = 100_000;
const BLOOM_FILTER_FPR: f64 = 0.01;

#[derive(Error, Debug)]
pub enum VelocityError {
    #[error("Shred validation failed: {0}")]
    ShredValidation(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Block reconstruction failed: {0}")]
    BlockReconstruction(String),
    #[error("Encoding error: {0}")]
    Encoding(String),
    #[error("Rate limit exceeded")]
    RateLimit,
    #[error("No shreds found")]
    NoShredsFound,
    #[error("Hash mismatch")]
    HashMismatch,
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("Reconstruction error: {0}")]
    ReconstructionError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShredRequestType {
    Missing {
        block_hash: [u8; 32],
        indices: Vec<u32>,
    },
    Range {
        start_height: u32,
        end_height: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubnetGroup {
    data: [u8; 16],
    len: u8,
}

type ShredCacheStore = Arc<parking_lot::Mutex<LruCache<[u8; 32], Vec<Option<Shred>>>>>;

/// High-performance shred cache using LRU
#[derive(Debug)]
pub struct ShredCache {
    cache: ShredCacheStore,
    bloom: Arc<BloomFilter>,
}

/// Lock-free bloom filter for deduplication
#[derive(Debug)]
pub struct BloomFilter {
    bits: Vec<AtomicBool>,
    num_hashes: usize,
    max_items_before_reset: usize,
    items_count: AtomicU64,
}

/// Manages erasure coding for reliability
#[derive(Debug)]
pub struct ErasureManager {
    encoder: Arc<ReedSolomon<galois_8::Field>>,
}

/// Core velocity protocol manager
#[derive(Debug)]
pub struct VelocityManager {
    shred_cache: Arc<ShredCache>,
    erasure_manager: Arc<ErasureManager>,
    subnet_manager: Arc<SubnetManager>,
    metrics: Arc<VelocityMetrics>,
    request_limiter: Arc<Semaphore>,
    pending_requests: Arc<DashMap<[u8; 32], Instant>>,
    request_tx: Sender<ShredRequest>,
    request_rx: Receiver<ShredRequest>,
}

/// Subnet manager
#[derive(Debug)]
pub struct SubnetManager {
    coverage: Arc<Vec<AtomicBool>>,
    bloom: Arc<BloomFilter>,
    last_update: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShredRequest {
    pub block_hash: [u8; 32],
    pub indices: Vec<u32>,
    pub from: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shred {
    pub block_hash: [u8; 32],
    pub index: u32,
    pub total_shreds: u32,
    pub data: Vec<u8>,
    pub subnet_hint: Option<SubnetGroup>,
    pub timestamp: u64,
    pub nonce: u64,
}

/// Ipv4 and Ipv6
impl SubnetGroup {
    pub fn from_ipv4(net: Ipv4Net) -> Self {
        let mut data = [0u8; 16];
        data[0..4].copy_from_slice(&net.addr().octets());
        Self {
            data,
            len: net.prefix_len(),
        }
    }

    pub fn from_ipv6(net: Ipv6Net) -> Self {
        let mut data = [0u8; 16];
        data.copy_from_slice(&net.addr().octets());
        Self {
            data,
            len: net.prefix_len(),
        }
    }

    pub fn as_ip(&self) -> IpAddr {
        if self.len <= 32 {
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&self.data[0..4]);
            IpAddr::V4(Ipv4Addr::from(addr))
        } else {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&self.data);
            IpAddr::V6(Ipv6Addr::from(addr))
        }
    }
}

/// Optimized implementation of ShredCache
impl ShredCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(parking_lot::Mutex::new(LruCache::new(
                NonZeroUsize::new(SHRED_CACHE_SIZE).unwrap_or(NonZeroUsize::MIN),
            ))),
            bloom: Arc::new(BloomFilter::new(BLOOM_FILTER_SIZE, BLOOM_FILTER_FPR)),
        }
    }

    pub fn add_shred(&self, shred: Shred) -> bool {
        if !Self::is_erasure_shred_shape(&shred) {
            return false;
        }

        let key = Self::create_shred_key(&shred);
        if self.bloom.check(&key) {
            return false;
        }

        let mut cache = self.cache.lock();

        let shreds = match cache.get_mut(&shred.block_hash) {
            Some(existing) => existing,
            None => {
                let vec = vec![None; shred.total_shreds as usize];
                cache.put(shred.block_hash, vec);
                let Some(inserted) = cache.get_mut(&shred.block_hash) else {
                    return false;
                };
                inserted
            }
        };

        if shred.index as usize >= shreds.len() {
            return false;
        }

        shreds[shred.index as usize] = Some(shred.clone());
        self.bloom.add(&key);
        true
    }

    fn is_erasure_shred_shape(shred: &Shred) -> bool {
        shred.total_shreds as usize == ERASURE_TOTAL_SHARD_COUNT
            && (shred.index as usize) < ERASURE_TOTAL_SHARD_COUNT
            && !shred.data.is_empty()
    }

    fn create_shred_key(shred: &Shred) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(&shred.block_hash);
        hasher.update(&shred.index.to_le_bytes());
        hasher.update(&shred.nonce.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

impl Default for ShredCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Lock-free bloom filter implementation
impl BloomFilter {
    pub fn new(size: usize, fpr: f64) -> Self {
        let size = size.max(8);
        let max_items_before_reset = Self::optimal_item_capacity(size, fpr);
        let num_hashes = Self::optimal_num_hashes(size, max_items_before_reset);
        let bits = (0..size).map(|_| AtomicBool::new(false)).collect();
        Self {
            bits,
            num_hashes,
            max_items_before_reset,
            items_count: AtomicU64::new(0),
        }
    }

    pub fn check(&self, item: &[u8]) -> bool {
        (0..self.num_hashes).all(|i| {
            let hash = Self::hash(item, i);
            let idx = (hash as usize) % self.bits.len();
            self.bits[idx].load(Ordering::Relaxed)
        })
    }

    pub fn add(&self, item: &[u8]) -> bool {
        self.rotate_if_needed();

        let mut was_new = false;
        for i in 0..self.num_hashes {
            let hash = Self::hash(item, i);
            let idx = (hash as usize) % self.bits.len();
            // CRITICAL FIX: Actually set the bit!
            let old = self.bits[idx].swap(true, Ordering::Relaxed);
            was_new |= !old; // Track if any bit was newly set
        }
        if was_new {
            self.items_count.fetch_add(1, Ordering::Relaxed);
        }
        was_new
    }

    fn clear(&self) {
        for bit in &self.bits {
            bit.store(false, Ordering::Relaxed);
        }
        self.items_count.store(0, Ordering::Relaxed);
    }

    fn rotate_if_needed(&self) {
        if self.items_count.load(Ordering::Relaxed) >= self.max_items_before_reset as u64 {
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
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[seed as u8]);
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&result.as_bytes()[..8]);
        u64::from_le_bytes(bytes)
    }
}

/// Erasure coding manager implementation
impl ErasureManager {
    pub fn new() -> Self {
        let encoder = ReedSolomon::new(ERASURE_SHARD_COUNT, ERASURE_PARITY_SHARD_COUNT)
            .expect("Failed to create Reed-Solomon encoder");

        Self {
            encoder: Arc::new(encoder),
        }
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, VelocityError> {
        let payload = Self::frame_payload(data);
        let mut shards = Vec::new();
        let shard_size = payload.len().div_ceil(ERASURE_SHARD_COUNT).max(1);

        // Create data shards
        for chunk in payload.chunks(shard_size) {
            let mut shard = vec![0u8; shard_size];
            shard[..chunk.len()].copy_from_slice(chunk);
            shards.push(shard);
        }

        // Add padding if needed
        while shards.len() < ERASURE_SHARD_COUNT {
            shards.push(vec![0u8; shard_size]);
        }

        // Create parity shards
        let mut parity = vec![vec![0u8; shard_size]; ERASURE_PARITY_SHARD_COUNT];
        self.encoder
            .encode_sep(&shards, &mut parity)
            .map_err(|e| VelocityError::Encoding(e.to_string()))?;

        shards.extend(parity);
        Ok(shards)
    }

    pub fn decode(&self, mut shards: Vec<Option<Vec<u8>>>) -> Result<Vec<u8>, VelocityError> {
        if shards.len() != ERASURE_TOTAL_SHARD_COUNT {
            return Err(VelocityError::Encoding(format!(
                "expected {} shards, got {}",
                ERASURE_TOTAL_SHARD_COUNT,
                shards.len()
            )));
        }

        let available = shards.iter().filter(|shard| shard.is_some()).count();
        if available < ERASURE_SHARD_COUNT {
            return Err(VelocityError::Encoding(format!(
                "need at least {} shards, got {}",
                ERASURE_SHARD_COUNT, available
            )));
        }

        self.encoder
            .reconstruct(&mut shards)
            .map_err(|e| VelocityError::Encoding(e.to_string()))?;

        let mut result = Vec::new();
        for shard in shards.into_iter().take(ERASURE_SHARD_COUNT).flatten() {
            result.extend(shard);
        }
        Self::unframe_payload(result)
    }

    fn frame_payload(data: &[u8]) -> Vec<u8> {
        let mut framed = Vec::with_capacity(ERASURE_FRAME_HEADER_LEN + data.len());
        framed.extend_from_slice(ERASURE_FRAME_MAGIC);
        framed.extend_from_slice(&(data.len() as u64).to_le_bytes());
        framed.extend_from_slice(data);
        framed
    }

    fn unframe_payload(data: Vec<u8>) -> Result<Vec<u8>, VelocityError> {
        if data.len() < ERASURE_FRAME_HEADER_LEN
            || &data[..ERASURE_FRAME_MAGIC.len()] != ERASURE_FRAME_MAGIC
        {
            return Ok(data);
        }

        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&data[ERASURE_FRAME_MAGIC.len()..ERASURE_FRAME_HEADER_LEN]);
        let payload_len = u64::from_le_bytes(len_bytes) as usize;
        let payload_start = ERASURE_FRAME_HEADER_LEN;
        let payload_end = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| VelocityError::Encoding("framed payload length overflow".into()))?;

        if payload_end > data.len() {
            return Err(VelocityError::Encoding(
                "framed payload length exceeds decoded data".into(),
            ));
        }

        Ok(data[payload_start..payload_end].to_vec())
    }
}

impl Default for ErasureManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Main VelocityManager implementation
impl VelocityManager {
    pub fn new() -> Self {
        let (request_tx, request_rx) = bounded(MAX_CONCURRENT_REQUESTS);

        Self {
            shred_cache: Arc::new(ShredCache::new()),
            erasure_manager: Arc::new(ErasureManager::new()),
            subnet_manager: Arc::new(SubnetManager::new()),
            metrics: Arc::new(VelocityMetrics::default()),
            request_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
            pending_requests: Arc::new(DashMap::new()),
            request_tx,
            request_rx,
        }
    }

    pub async fn process_shreds(
        &self,
        block_hash: [u8; 32],
        shreds: Vec<Shred>,
    ) -> Result<Option<Block>, VelocityError> {
        // Track shreds in the cache
        for shred in &shreds {
            self.shred_cache.add_shred(shred.clone());
        }

        // Check if we can reconstruct the block
        if self.is_block_complete(&block_hash).await {
            return self.try_reconstruct_block(&block_hash).await;
        }

        Ok(None)
    }

    async fn reconstruct_block(&self, block_hash: &[u8; 32]) -> Result<Block, VelocityError> {
        let cache = self.shred_cache.cache.lock();

        if let Some(shreds) = cache.peek(block_hash) {
            if Self::has_enough_erasure_shards(shreds) {
                let shards: Vec<Option<Vec<u8>>> = shreds
                    .iter()
                    .map(|s| s.as_ref().map(|s| s.data.to_vec()))
                    .collect();

                drop(cache); // Release lock before potentially lengthy operation

                let data = self.erasure_manager.decode(shards)?;

                // Deserialize the block
                let reconstructed_block: Block = bincode::deserialize(&data)
                    .map_err(|e| VelocityError::DeserializationError(e.to_string()))?;
                if reconstructed_block.calculate_hash_for_block() != *block_hash {
                    return Err(VelocityError::HashMismatch);
                }
                return Ok(reconstructed_block);
            }
        }

        Err(VelocityError::NoShredsFound)
    }

    pub async fn get_block_shreds(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<Vec<Shred>, VelocityError> {
        let cache = self.shred_cache.cache.lock();

        if let Some(shreds) = cache.peek(block_hash) {
            let result: Vec<_> = shreds.iter().filter_map(|s| s.clone()).collect();
            Ok(result)
        } else {
            Ok(Vec::new())
        }
    }

    pub async fn process_block(
        &self,
        block: &Block,
        peers: &HashMap<SocketAddr, PeerInfo>,
    ) -> Result<(), VelocityError> {
        const FAST_PATH_SIZE: usize = 150_000;
        const MAX_PARALLEL_SENDS: usize = 24;
        const MIN_LATENCY: u64 = 100;
        const PROPAGATION_TIMEOUT: u64 = 5; // Increased for production stability
        const MIN_SUCCESS_RATIO: f64 = 0.60; // Reduced for better reliability on slower networks
        let propagation_started = Instant::now();

        // Calculate block size
        let block_bytes =
            bincode::serialize(&block).map_err(|e| VelocityError::Encoding(e.to_string()))?;

        log::debug!(
            "Velocity: Processing block {} ({} bytes) with {} peers",
            hex::encode(&block.hash[..8]),
            block_bytes.len(),
            peers.len()
        );

        // Fast path for small blocks
        if block_bytes.len() < FAST_PATH_SIZE {
            log::debug!("Velocity: Using fast path for small block");
            let mut fast_peers: Vec<_> = peers
                .iter()
                .filter(|(_, info)| info.latency < MIN_LATENCY)
                .filter(|(addr, _)| self.subnet_manager.lookup_coverage(addr.ip()))
                .collect::<Vec<_>>();

            // If we don't have coverage history yet, fall back to all low-latency peers.
            if fast_peers.is_empty() {
                fast_peers = peers
                    .iter()
                    .filter(|(_, info)| info.latency < MIN_LATENCY)
                    .collect::<Vec<_>>();
            }

            fast_peers.sort_by_key(|(_addr, info)| info.latency);

            let selected_peers = fast_peers
                .iter()
                .take(MAX_PARALLEL_SENDS)
                .collect::<Vec<_>>();

            if !selected_peers.is_empty() {
                let min_confirmations = (selected_peers.len() * 3) / 4;

                let futures: Vec<_> = selected_peers
                    .iter()
                    .map(|(addr, _)| {
                        self.send_shred(
                            **addr,
                            Shred {
                                block_hash: block.hash,
                                index: 0,
                                total_shreds: 1,
                                data: block_bytes.clone(),
                                subnet_hint: None,
                                timestamp: block.timestamp,
                                nonce: 0,
                            },
                        )
                    })
                    .collect();

                let results = futures::future::join_all(futures).await;
                let successes = results.iter().filter(|r| r.is_ok()).count();

                if successes >= min_confirmations {
                    self.metrics
                        .record_propagation_latency(propagation_started.elapsed());
                    log::info!(
                        "Velocity: Fast path successful, {} confirmations",
                        successes
                    );
                    return Ok(());
                } else {
                    log::warn!(
                        "Velocity: Fast path failed, {} confirmations (needed {})",
                        successes,
                        min_confirmations
                    );
                }
            }
        }

        // Regular path with erasure coding
        log::debug!("Velocity: Using erasure coding path");
        let shards = self
            .erasure_manager
            .encode(&block_bytes)
            .map_err(|e| VelocityError::Encoding(e.to_string()))?;

        log::debug!(
            "Velocity: Created {} shards for block propagation",
            shards.len()
        );

        let mut subnet_peers: HashMap<IpAddr, Vec<(SocketAddr, u64)>> =
            HashMap::with_capacity(peers.len() / 4);

        for (&addr, info) in peers {
            let subnet = match addr.ip() {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    IpAddr::V4(std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 0))
                }
                IpAddr::V6(ipv6) => {
                    let segments = ipv6.segments();
                    IpAddr::V6(std::net::Ipv6Addr::new(
                        segments[0],
                        segments[1],
                        segments[2],
                        segments[3],
                        0,
                        0,
                        0,
                        0,
                    ))
                }
            };

            subnet_peers
                .entry(subnet)
                .or_default()
                .push((addr, info.latency));
        }

        let mut futures = Vec::with_capacity(shards.len());
        let shred_count = shards.len() as u32;

        for (_, mut peer_group) in subnet_peers {
            peer_group.sort_by_key(|(_, latency)| *latency);

            let peer_count = peer_group.len().min(MAX_SUBNET_PEERS);
            if peer_count == 0 {
                continue;
            }

            let selected = peer_group.into_iter().take(peer_count).collect::<Vec<_>>();
            for (shard_idx, shard_data) in shards.iter().enumerate() {
                let (peer_addr, _) = selected[shard_idx % selected.len()];
                let shred = Shred {
                    block_hash: block.hash,
                    index: shard_idx as u32,
                    total_shreds: shred_count,
                    data: shard_data.clone(),
                    subnet_hint: None,
                    timestamp: block.timestamp,
                    nonce: shard_idx as u64,
                };

                futures.push(tokio::time::timeout(
                    Duration::from_secs(PROPAGATION_TIMEOUT),
                    self.send_shred(peer_addr, shred),
                ));
            }
        }

        let results = futures::future::join_all(futures).await;

        let success_ratio = results
            .iter()
            .filter(|r| match r {
                Ok(inner_result) => inner_result.is_ok(),
                Err(_) => false,
            })
            .count() as f64
            / results.len().max(1) as f64;

        if success_ratio >= MIN_SUCCESS_RATIO {
            self.metrics
                .record_propagation_latency(propagation_started.elapsed());
            log::info!(
                "Velocity: Block propagation successful, {:.1}% success rate",
                success_ratio * 100.0
            );
            Ok(())
        } else {
            log::error!(
                "Velocity: Block propagation failed, {:.1}% success rate (needed {:.1}%)",
                success_ratio * 100.0,
                MIN_SUCCESS_RATIO * 100.0
            );
            Err(VelocityError::ShredValidation(format!(
                "Insufficient propagation: {:.1}%",
                success_ratio * 100.0
            )))
        }
    }

    pub async fn is_block_complete(&self, block_hash: &[u8; 32]) -> bool {
        let cache = self.shred_cache.cache.lock();
        if let Some(shreds) = cache.peek(block_hash) {
            Self::has_enough_erasure_shards(shreds)
        } else {
            false
        }
    }

    pub async fn handle_shred_request(&self, request: ShredRequest) -> Result<(), VelocityError> {
        let ShredRequest {
            block_hash,
            indices,
            from,
        } = request;
        let available_shreds = {
            let cache = self.shred_cache.cache.lock();
            if let Some(shreds) = cache.peek(&block_hash) {
                indices
                    .iter()
                    .filter_map(|&idx| shreds.get(idx as usize).and_then(|s| s.clone()))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        };

        if !available_shreds.is_empty() {
            self.send_shred_response(from, block_hash, available_shreds)
                .await?;
        }
        Ok(())
    }

    async fn send_shred(&self, peer: SocketAddr, shred: Shred) -> Result<(), VelocityError> {
        use crate::a9::node::{NetworkMessage, MAX_MESSAGE_SIZE};
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        const TIMEOUT: Duration = Duration::from_secs(3);

        // Create network message
        let message = NetworkMessage::Shred(shred);

        // Serialize message
        let data =
            bincode::serialize(&message).map_err(|e| VelocityError::Encoding(e.to_string()))?;

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(VelocityError::Network("Shred too large".into()));
        }

        // Connect with timeout
        let mut stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(peer))
            .await
            .map_err(|_| VelocityError::Network(format!("Connection timeout to {}", peer)))?
            .map_err(|e| VelocityError::Network(format!("Failed to connect to {}: {}", peer, e)))?;

        // Send message with length prefix
        tokio::time::timeout(TIMEOUT, async {
            stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
            stream.write_all(&data).await?;
            stream.flush().await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| VelocityError::Network(format!("Send timeout to {}", peer)))?
        .map_err(|e| VelocityError::Network(format!("Send error to {}: {}", peer, e)))?;

        self.subnet_manager.update_coverage(peer.ip(), true);
        Ok(())
    }

    pub async fn handle_shred(
        &self,
        shred: Shred,
        from: SocketAddr,
    ) -> Result<Option<Block>, VelocityError> {
        if shred.total_shreds == DIRECT_BLOCK_SHRED_COUNT {
            return self.handle_direct_block_shred(shred, from).await;
        }

        // Add shred to cache
        if !self.shred_cache.add_shred(shred.clone()) {
            return Ok(None);
        }
        self.metrics.record_shred_processed();
        self.subnet_manager.update_coverage(from.ip(), true);

        // Check if we can reconstruct the block
        if let Some(block) = self.try_reconstruct_block(&shred.block_hash).await? {
            self.metrics.record_block_reconstructed();
            return Ok(Some(block));
        }

        // Request missing shreds if needed
        self.request_missing_shreds(shred.block_hash, from).await?;

        Ok(None)
    }

    async fn handle_direct_block_shred(
        &self,
        shred: Shred,
        from: SocketAddr,
    ) -> Result<Option<Block>, VelocityError> {
        if shred.index != 0 {
            return Err(VelocityError::ShredValidation(
                "direct block shred index must be zero".into(),
            ));
        }

        let block: Block = bincode::deserialize(&shred.data)
            .map_err(|e| VelocityError::DeserializationError(e.to_string()))?;
        let calculated_hash = block.calculate_hash_for_block();
        if calculated_hash != block.hash || block.hash != shred.block_hash {
            return Err(VelocityError::HashMismatch);
        }

        self.metrics.record_shred_processed();
        self.metrics.record_block_reconstructed();
        self.subnet_manager.update_coverage(from.ip(), true);
        Ok(Some(block))
    }

    fn has_enough_erasure_shards(shreds: &[Option<Shred>]) -> bool {
        shreds.len() == ERASURE_TOTAL_SHARD_COUNT
            && shreds.iter().filter(|shred| shred.is_some()).count() >= ERASURE_SHARD_COUNT
    }

    async fn try_reconstruct_block(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<Option<Block>, VelocityError> {
        if !self.is_block_complete(block_hash).await {
            return Ok(None);
        }
        self.reconstruct_block(block_hash).await.map(Some)
    }

    async fn request_missing_shreds(
        &self,
        block_hash: [u8; 32],
        from: SocketAddr,
    ) -> Result<(), VelocityError> {
        let request_started = Instant::now();
        if !self.should_request_shreds(&block_hash) {
            return Ok(());
        }

        let missing = {
            let cache = self.shred_cache.cache.lock();
            if let Some(shreds) = cache.peek(&block_hash) {
                shreds
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.is_none())
                    .map(|(i, _)| i as u32)
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        };

        if missing.is_empty() {
            return Ok(());
        }

        // Check if we've already sent a request recently
        if let Some(last_request) = self.pending_requests.get(&block_hash) {
            if last_request.elapsed() < REQUEST_TIMEOUT {
                return Ok(());
            }
            self.pending_requests.remove(&block_hash);
        }

        // Acquire request permit with timeout
        let _permit = tokio::time::timeout(Duration::from_secs(1), self.request_limiter.acquire())
            .await
            .map_err(|_| VelocityError::RateLimit)?;

        // Send request to request processor
        let request = ShredRequest {
            block_hash,
            indices: missing,
            from,
        };

        self.request_tx
            .send(request)
            .map_err(|_| VelocityError::Network("Failed to send shred request".into()))?;

        // Mark request as pending
        self.pending_requests.insert(block_hash, Instant::now());
        self.metrics
            .record_request_latency(request_started.elapsed());

        Ok(())
    }

    pub fn start_request_processor(self: Arc<Self>) {
        tokio::spawn(async move {
            while let Ok(request) = self.request_rx.recv() {
                if let Err(e) = self.process_shred_request(request).await {
                    warn!("Error processing shred request: {}", e);
                }
            }
        });
    }

    async fn process_shred_request(&self, request: ShredRequest) -> Result<(), VelocityError> {
        let request_started = Instant::now();
        let ShredRequest {
            block_hash,
            indices,
            from,
        } = request;

        // Get available shreds from cache
        let available_shreds = {
            let cache = self.shred_cache.cache.lock();
            if let Some(shreds) = cache.peek(&block_hash) {
                indices
                    .iter()
                    .filter_map(|&idx| shreds.get(idx as usize).and_then(|s| s.as_ref()).cloned())
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        };

        if !available_shreds.is_empty() {
            // Send available shreds back to requester
            // This would integrate with your network layer
            self.send_shred_response(from, block_hash, available_shreds)
                .await?;
            self.metrics
                .record_request_latency(request_started.elapsed());
        }

        Ok(())
    }

    async fn send_shred_response(
        &self,
        to: SocketAddr,
        block_hash: [u8; 32],
        shreds: Vec<Shred>,
    ) -> Result<(), VelocityError> {
        use crate::a9::node::{NetworkMessage, MAX_MESSAGE_SIZE};
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        const TIMEOUT: Duration = Duration::from_secs(5);

        // Create response message
        let message = NetworkMessage::ShredResponse { block_hash, shreds };

        // Serialize message
        let data =
            bincode::serialize(&message).map_err(|e| VelocityError::Encoding(e.to_string()))?;

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(VelocityError::Network("Response too large".into()));
        }

        // Connect with timeout
        let mut stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(to))
            .await
            .map_err(|_| VelocityError::Network(format!("Connection timeout to {}", to)))?
            .map_err(|e| VelocityError::Network(format!("Failed to connect to {}: {}", to, e)))?;

        // Send message with length prefix
        tokio::time::timeout(TIMEOUT, async {
            stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
            stream.write_all(&data).await?;
            stream.flush().await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| VelocityError::Network(format!("Send timeout to {}", to)))?
        .map_err(|e| VelocityError::Network(format!("Send error to {}: {}", to, e)))?;

        self.subnet_manager.update_coverage(to.ip(), true);
        Ok(())
    }

    fn should_request_shreds(&self, block_hash: &[u8; 32]) -> bool {
        if let Some(last_request) = self.pending_requests.get(block_hash) {
            last_request.elapsed() >= REQUEST_TIMEOUT
        } else {
            true
        }
    }
}

impl Default for VelocityManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Subnet implementation
impl SubnetManager {
    pub fn new() -> Self {
        const COVERAGE_SIZE: usize = 65536; // 64K entries for IPv4
        Self {
            coverage: Arc::new((0..COVERAGE_SIZE).map(|_| AtomicBool::new(false)).collect()),
            bloom: Arc::new(BloomFilter::new(COVERAGE_SIZE * 2, 0.01)),
            last_update: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn lookup_coverage(&self, ip: IpAddr) -> bool {
        let idx = self.ip_to_index(ip);
        self.bloom.check(&idx.to_le_bytes()) && self.coverage[idx].load(Ordering::Relaxed)
    }

    pub fn update_coverage(&self, ip: IpAddr, has_coverage: bool) {
        let idx = self.ip_to_index(ip);
        if has_coverage {
            self.bloom.add(&idx.to_le_bytes());
        }
        self.coverage[idx].store(has_coverage, Ordering::Relaxed);
        self.last_update.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
    }

    fn ip_to_index(&self, ip: IpAddr) -> usize {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ip.to_string().as_bytes());
        (hasher.finalize().as_bytes()[0] as usize) % self.coverage.len()
    }
}

impl Default for SubnetManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Extension trait for integrating with existing Node implementation
#[async_trait]
pub trait VelocityProtocol {
    async fn init_velocity(&self) -> Result<Arc<VelocityManager>, VelocityError>;
    async fn broadcast_block_velocity(&self, block: &Block) -> Result<(), VelocityError>;
    async fn handle_shred_velocity(
        &self,
        shred: Shred,
        from: SocketAddr,
    ) -> Result<(), VelocityError>;
}

#[async_trait]
impl VelocityProtocol for Node {
    async fn init_velocity(&self) -> Result<Arc<VelocityManager>, VelocityError> {
        let manager = Arc::new(VelocityManager::new());
        let manager_clone = manager.clone();
        manager_clone.start_request_processor();
        Ok(manager)
    }

    async fn broadcast_block_velocity(&self, block: &Block) -> Result<(), VelocityError> {
        let peers = self.peers.read().await;
        let velocity = self
            .velocity_manager
            .as_ref()
            .ok_or_else(|| VelocityError::Network("Velocity manager not initialized".into()))?;

        velocity.process_block(block, &peers).await
    }

    async fn handle_shred_velocity(
        &self,
        shred: Shred,
        from: SocketAddr,
    ) -> Result<(), VelocityError> {
        let velocity = self
            .velocity_manager
            .as_ref()
            .ok_or_else(|| VelocityError::Network("Velocity manager not initialized".into()))?;

        if let Some(block) = velocity.handle_shred(shred, from).await? {
            // Process reconstructed block through regular validation
            if self
                .verify_block_with_witness(&block, Some(from))
                .await
                .map_err(|e| VelocityError::BlockReconstruction(e.to_string()))?
            {
                self.blockchain
                    .write()
                    .await
                    .save_block(&block)
                    .await
                    .map_err(|e| VelocityError::BlockReconstruction(e.to_string()))?;
            }
        }

        Ok(())
    }
}

// Statistics and metrics tracking
#[derive(Debug, Default)]
pub struct VelocityMetrics {
    shreds_processed: AtomicU64,
    blocks_reconstructed: AtomicU64,
    request_latency: Arc<parking_lot::Mutex<Vec<f64>>>,
    propagation_latency: Arc<parking_lot::Mutex<Vec<f64>>>,
}

impl VelocityMetrics {
    pub fn record_shred_processed(&self) {
        self.shreds_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_block_reconstructed(&self) {
        self.blocks_reconstructed.fetch_add(1, Ordering::Relaxed);
    }

    fn record_latency(storage: &Arc<parking_lot::Mutex<Vec<f64>>>, value: f64) {
        let mut data = storage.lock();
        data.push(value);
        if data.len() > 1000 {
            data.remove(0);
        }
    }

    pub fn record_request_latency(&self, duration: Duration) {
        Self::record_latency(&self.request_latency, duration.as_micros() as f64);
    }

    pub fn record_propagation_latency(&self, duration: Duration) {
        Self::record_latency(&self.propagation_latency, duration.as_micros() as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a9::blockchain::Transaction;

    fn test_shred(block_hash: [u8; 32], index: u32) -> Shred {
        Shred {
            block_hash,
            index,
            total_shreds: ERASURE_TOTAL_SHARD_COUNT as u32,
            data: vec![index as u8 + 1],
            subnet_hint: None,
            timestamp: 1,
            nonce: index as u64,
        }
    }

    #[test]
    fn bloom_filter_accepts_first_insert_and_rejects_duplicate() {
        let bloom = BloomFilter::new(64, 0.01);

        assert!(bloom.num_hashes > 0);
        assert!(bloom.max_items_before_reset > 0);
        assert!(!bloom.check(b"first-shred"));
        assert!(bloom.add(b"first-shred"));
        assert!(bloom.check(b"first-shred"));
        assert!(!bloom.add(b"first-shred"));
    }

    #[test]
    fn shred_cache_rejects_unbounded_total_shreds() {
        let cache = ShredCache::new();
        let mut shred = test_shred([7u8; 32], 0);
        shred.total_shreds = u32::MAX;

        assert!(!cache.add_shred(shred));
        assert_eq!(cache.cache.lock().len(), 0);
    }

    #[test]
    fn erasure_encode_decode_handles_empty_payload() {
        let manager = ErasureManager::new();
        let shards = manager.encode(&[]).expect("empty payload should encode");

        assert_eq!(shards.len(), ERASURE_TOTAL_SHARD_COUNT);

        let decoded = manager
            .decode(shards.into_iter().map(Some).collect())
            .expect("empty payload should decode");
        assert!(decoded.is_empty());
    }

    #[test]
    fn erasure_decode_reconstructs_with_data_threshold() {
        let manager = ErasureManager::new();
        let payload = b"payload that should survive four missing shards";
        let shards = manager.encode(payload).expect("payload should encode");
        let mut shards = shards.into_iter().map(Some).collect::<Vec<_>>();

        shards[0] = None;
        shards[3] = None;
        shards[16] = None;
        shards[19] = None;

        let decoded = manager
            .decode(shards)
            .expect("threshold shards should reconstruct");
        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn velocity_considers_erasure_block_complete_at_data_threshold() {
        let manager = VelocityManager::new();
        let block_hash = [9u8; 32];

        for index in 0..ERASURE_SHARD_COUNT {
            assert!(manager
                .shred_cache
                .add_shred(test_shred(block_hash, index as u32)));
        }

        assert!(manager.is_block_complete(&block_hash).await);
    }

    #[tokio::test]
    async fn direct_block_shred_returns_block_without_erasure_decode() {
        let manager = VelocityManager::new();
        let tx = Transaction::new("alice".into(), "bob".into(), 1.0, 0.001, 1, None);
        let block = Block::new(1, [0u8; 32], 1, vec![tx], 0, 1).expect("block should build");
        let shred = Shred {
            block_hash: block.hash,
            index: 0,
            total_shreds: DIRECT_BLOCK_SHRED_COUNT,
            data: bincode::serialize(&block).expect("block should serialize"),
            subnet_hint: None,
            timestamp: block.timestamp,
            nonce: 0,
        };

        let reconstructed = manager
            .handle_shred(shred, "127.0.0.1:8333".parse().unwrap())
            .await
            .expect("direct shred should decode")
            .expect("direct shred should return a block");

        assert_eq!(reconstructed.hash, block.hash);
    }
}
