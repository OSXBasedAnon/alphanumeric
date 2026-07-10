use dashmap::DashMap;
use log::{debug, error, info, warn};
use rand::{thread_rng, Rng};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::interval;

use crate::a9::blockchain::{Block, Blockchain, BlockchainError, Transaction};
use crate::a9::codec;
use crate::a9::mldsa;
use crate::a9::node::NetworkMessage;
use crate::a9::node::{Node, NodeError};

type VerifiedHeaderQueue = Arc<RwLock<VecDeque<(u32, [u8; 32])>>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionType {
    BlockValidation,
    AnomalyDetection,
    ForkResolution,
    HeaderValidation,
    ChainVerification,
}

// Performance and reward constants
const SENTINEL_CHECK_INTERVAL: u64 = 300; // Check network health
const MAX_HEADER_CACHE_SIZE: usize = 5000; // Reduced to prevent memory exhaustion attacks
const CHAIN_VERIFICATION_INTERVAL: u64 = 300; // Verify chain every 5 minutes
#[allow(dead_code)]
const SENTINEL_VERIFY_INTERVAL: u64 = 300; // 5 minute verification cycle
const MLDSA_BINDING_CONTEXT: &[u8] = b"ALPHANUMERIC_MLDSA87_BIND_V2";

pub fn build_mldsa_binding_payload(node_id: &str, mldsa_public_key: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        MLDSA_BINDING_CONTEXT.len() + node_id.len() + mldsa_public_key.len() + 6,
    );
    payload.extend_from_slice(MLDSA_BINDING_CONTEXT);
    payload.extend_from_slice(&(node_id.len() as u16).to_be_bytes());
    payload.extend_from_slice(node_id.as_bytes());
    payload.extend_from_slice(&(mldsa_public_key.len() as u16).to_be_bytes());
    payload.extend_from_slice(mldsa_public_key);
    payload
}

const MAX_BLOCK_SIZE: usize = 1_000_000;
const BLOCK_VERIFICATION_BATCH_SIZE: usize = 1000; // Increased for better scaling

pub const AUTO_STAKE_PERCENTAGE: f64 = 0.20; // 20% automatic stake
pub const WITHDRAWAL_COOLDOWN: u64 = 24 * 60 * 60; // 24 hours in seconds
const HEADER_RULES_VERSION: u32 = 2;
const HEADER_MAX_FUTURE_SECONDS: u64 = 600;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValidatorTier {
    RedDiamond,
    Diamond,
    Emerald,
    Gold,
    Silver,
    Inactive,
}

impl ValidatorTier {
    pub fn calculate_tier(uptime: f64, blocks_verified: u64, network_contribution: f64) -> Self {
        // Calculate verification score (50% weight)
        let verification_score = if blocks_verified > 0 {
            // Logarithmic scaling for blocks verified to reward consistent participation
            // but prevent runaway scoring
            let log_factor = (1.0 + (blocks_verified as f64 / 100.0).ln()).min(1.0);
            log_factor * 0.5 // 50% total weight
        } else {
            0.0
        };

        // Uptime score (25% weight)
        let uptime_score = (uptime / 100.0).clamp(0.0, 1.0) * 0.25;

        // Network stake score (25% weight)
        let stake_score = network_contribution * 0.25;

        // Combined score
        let total_score = verification_score + uptime_score + stake_score;

        // Tier thresholds
        match total_score {
            s if s >= 0.80 => ValidatorTier::RedDiamond, // Exceptional validation history + good uptime/stake
            s if s >= 0.65 => ValidatorTier::Diamond, // Strong validation history + decent uptime/stake
            s if s >= 0.50 => ValidatorTier::Emerald, // Good validation history + average uptime/stake
            s if s >= 0.35 => ValidatorTier::Gold,    // Decent validation history
            s if s > 0.20 => ValidatorTier::Silver,   // Some validation history
            _ => ValidatorTier::Inactive,
        }
    }
}

#[derive(Debug)]
struct NodeSentinel {
    secret_key: Vec<u8>,
    last_challenge: u64,
    verified_peers: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SentinelChallenge {
    timestamp: u64,
    nonce: [u8; 32],
    header_hash: [u8; 32],
    signature: Vec<u8>,
}

#[derive(Debug)]
pub struct BPoSSentinel {
    blockchain: Arc<RwLock<Blockchain>>,
    node: Arc<Node>,
    node_metrics: Arc<DashMap<String, NodeMetrics>>,
    header_cache: Arc<RwLock<VecDeque<Block>>>,
    network_health: Arc<RwLock<NetworkHealth>>,
    stats: Arc<RwLock<SentinelStats>>,
    header_sentinel: Arc<HeaderSentinel>,
    anomaly_detector: Arc<RwLock<AnomalyDetector>>,
    sync_manager: Arc<RwLock<SyncManager>>,
    last_anomaly_broadcast: Arc<RwLock<u64>>, // Rate limiting for anomaly broadcasts
    node_sentinel: Option<Arc<RwLock<NodeSentinel>>>,
    peer_sentinels: Arc<RwLock<DashMap<String, Vec<u8>>>>,
    verified_headers: VerifiedHeaderQueue,
    initialized: Arc<std::sync::atomic::AtomicBool>,
}

#[allow(dead_code)]
impl BPoSSentinel {
    // Memory constants
    const MAX_PERFORMANCE_HISTORY: usize = 24;
    const MAX_ACTION_HISTORY: usize = 100;
    const MAX_VERIFIED_BLOCKS: usize = 200;
    const MAX_ANOMALIES: usize = 100;

    pub fn new(
        blockchain: Arc<RwLock<Blockchain>>,
        node: Arc<Node>,
        header_sentinel: Arc<HeaderSentinel>,
    ) -> Self {
        Self {
            blockchain,
            node,
            node_metrics: Arc::new(DashMap::new()),
            header_cache: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_HEADER_CACHE_SIZE))),
            network_health: Arc::new(RwLock::new(NetworkHealth::new())),
            stats: Arc::new(RwLock::new(SentinelStats::default())),
            header_sentinel,
            anomaly_detector: Arc::new(RwLock::new(AnomalyDetector {
                recent_anomalies: VecDeque::with_capacity(100),
            })),
            sync_manager: Arc::new(RwLock::new(SyncManager {})),
            last_anomaly_broadcast: Arc::new(RwLock::new(0)),
            node_sentinel: None,
            peer_sentinels: Arc::new(RwLock::new(DashMap::new())),
            verified_headers: Arc::new(RwLock::new(VecDeque::new())),
            initialized: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub async fn initialize(&self) -> Result<(), String> {
        if self
            .initialized
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        // Removed info log for production - initialization is implicit

        // Start independent monitoring tasks
        self.start_monitoring_tasks();
        self.start_header_verification();

        // Initial state verification
        self.verify_chain_state().await?;
        self.update_network_health(false).await?;

        // Start continuous metrics tracking
        let sentinel = self.clone();
        tokio::task::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                // Monitor chain for validations
                if let Err(e) = sentinel.monitor_chain().await {
                    error!("Chain monitoring error: {}", e);
                }

                // Update metrics
                if let Err(e) = sentinel.update_metrics().await {
                    error!("Metrics update error: {}", e);
                }
            }
        });

        // Removed info log for production - success is implicit
        Ok(())
    }

    pub async fn update_metrics(&self) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let _total_blocks = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_latest_block_index()
        };

        // Update all node metrics
        for mut metrics_ref in self.node_metrics.iter_mut() {
            let metrics = metrics_ref.value_mut();

            // Don't reset blocks_verified, only update if new verifications found
            let headers = self.header_sentinel.headers.read().await;
            let verified_count = headers
                .iter()
                .filter(|state| state.verified_by.contains(&metrics.address))
                .count();

            if verified_count > metrics.blocks_verified as usize {
                metrics.blocks_verified = verified_count as u64;
            }

            // Update other metrics
            let time_since_start = now.saturating_sub(metrics.last_active);
            metrics.uptime = if time_since_start > 0 {
                ((time_since_start - metrics.total_downtime) as f64 / time_since_start as f64
                    * 100.0)
                    .min(100.0)
            } else {
                100.0
            };

            // Update success rate based on verification history
            if metrics.blocks_verified > 0 {
                if time_since_start <= 3600 {
                    metrics.success_rate = 100.0;
                } else {
                    let decay_factor = (-((time_since_start - 3600) as f64) / 86400.0).exp();
                    metrics.success_rate = 100.0 * decay_factor;
                }
            }

            // Calculate stake contribution
            let blockchain = self.blockchain.read().await;
            if let Ok(balance) = blockchain.get_wallet_balance(&metrics.address).await {
                metrics.staked_amount = balance * AUTO_STAKE_PERCENTAGE;
            }

            // Update tier and performance score
            metrics.current_tier = ValidatorTier::calculate_tier(
                metrics.uptime,
                metrics.blocks_verified,
                metrics.staked_amount,
            );

            metrics.calculate_performance_score();
        }

        Ok(())
    }

    fn start_memory_management(&self) {
        let sentinel = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Hourly cleanup
            loop {
                interval.tick().await;
                if let Err(e) = sentinel.cleanup_memory().await {
                    error!("Memory cleanup error: {}", e);
                }
            }
        });
    }

    async fn cleanup_memory(&self) -> Result<(), String> {
        // Each section scopes its own guard: the old flow held header_cache.write
        // while acquiring verified_headers.write while acquiring anomaly_detector
        // .write — a four-lock chain where one contended lock wedges them all
        // (2026-07-08 guard-chaining class). The cleanups are independent.
        {
            // Clean header cache - only keep last blocks
            let mut header_cache = self.header_cache.write().await;
            if header_cache.len() > Self::MAX_VERIFIED_BLOCKS {
                let drain_count = header_cache.len() - Self::MAX_VERIFIED_BLOCKS;
                header_cache.drain(..drain_count);
            }
        }

        {
            // Clean verified headers
            let mut verified = self.verified_headers.write().await;
            if verified.len() > Self::MAX_VERIFIED_BLOCKS {
                let drain_count = verified.len() - Self::MAX_VERIFIED_BLOCKS;
                verified.drain(..drain_count);
            }
        }

        // Cleanup NodeMetrics
        for mut metrics in self.node_metrics.iter_mut() {
            // Trim performance history
            while metrics.performance_history.len() >= Self::MAX_PERFORMANCE_HISTORY {
                metrics.performance_history.pop_front();
            }

            // Trim action history
            while metrics.action_history.len() >= Self::MAX_ACTION_HISTORY {
                metrics.action_history.pop_front();
            }

            // Trim verified blocks to recent ones
            if metrics.verified_blocks.len() > Self::MAX_VERIFIED_BLOCKS {
                let mut blocks: Vec<_> = metrics.verified_blocks.iter().copied().collect();
                blocks.sort_unstable();
                let to_remove = blocks.len() - Self::MAX_VERIFIED_BLOCKS;
                for old_block in blocks.iter().take(to_remove) {
                    metrics.verified_blocks.remove(old_block);
                }
            }
        }

        // Cleanup anomaly detector
        {
            let mut detector = self.anomaly_detector.write().await;
            detector.recent_anomalies.truncate(Self::MAX_ANOMALIES);
        }

        // Cleanup peer sentinels
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Handle sentinel and peer sentinel cleanup
        if let Some(sentinel_lock) = &self.node_sentinel {
            if let Ok(sentinel) = sentinel_lock.try_read() {
                let peers = self.peer_sentinels.write().await;
                peers.retain(|_, _| now - sentinel.last_challenge < 3600);
            }
        }

        Ok(())
    }

    fn start_monitoring_tasks(&self) {
        // BPoS chain monitoring with ML-DSA verification
        let sentinel = self.clone();
        tokio::task::spawn(async move {
            let mut interval = interval(Duration::from_secs(CHAIN_VERIFICATION_INTERVAL));
            let mut last_height = 0u32;

            loop {
                interval.tick().await;

                let current_height = {
                    let blockchain = sentinel.blockchain.read().await;
                    blockchain.get_latest_block_index() as u32
                };

                if current_height != last_height {
                    if let Err(e) = sentinel.monitor_chain().await {
                        error!("Chain monitoring error: {}", e);
                    }
                    last_height = current_height;
                }
            }
        });

        // BPoS metrics and health monitoring
        let sentinel = self.clone();
        tokio::task::spawn(async move {
            let mut interval = interval(Duration::from_secs(SENTINEL_CHECK_INTERVAL));
            let mut last_metrics_update = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            loop {
                interval.tick().await;

                // Update network health with force parameter
                if let Err(e) = sentinel.update_network_health(false).await {
                    error!("Network health update error: {}", e);
                }

                // Update BPoS metrics every 5 minutes
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if now.saturating_sub(last_metrics_update) >= SENTINEL_CHECK_INTERVAL {
                    if let Err(e) = sentinel.update_metrics().await {
                        error!("Metrics update error: {}", e);
                    }
                    // Force full network health update with metrics
                    if let Err(e) = sentinel.update_network_health(false).await {
                        error!("Network health update error: {}", e);
                    }
                    last_metrics_update = now;
                }
            }
        });

        // Add daily wallet pruning task
        tokio::task::spawn(async move {
            // Wallet pruning is no longer needed since we removed the wallet registry

            // Run periodic tasks every 24 hours
            let mut interval = interval(Duration::from_secs(24 * 3600));
            loop {
                interval.tick().await;
                // Future periodic tasks can be added here
            }
        });

        // Add cleanup task
        let sentinel = self.clone();
        tokio::task::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600)); // Hourly cleanup
            loop {
                interval.tick().await;
                if let Err(e) = sentinel.cleanup_memory().await {
                    error!("Memory cleanup error: {}", e);
                }
            }
        });
    }

    pub async fn monitor_chain(&self) -> Result<(), String> {
        let current_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_latest_block_index() as u32
        };

        const FORK_DETECTION_WINDOW: u64 = 900; // Configurable window
        const SYNC_THRESHOLD: u32 = 10; // Allow up to 10 blocks difference

        let fork_info = {
            let mut height_versions: HashMap<u32, HashSet<[u8; 32]>> = HashMap::with_capacity(10);
            let headers = self.header_sentinel.headers.read().await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            for header_state in headers.iter().take(100) {
                if now - header_state.timestamp < FORK_DETECTION_WINDOW {
                    let verified_count = header_state.verified_by.len();
                    let total_nodes = self.node_metrics.len().max(1);

                    if verified_count >= (total_nodes / 3) {
                        height_versions
                            .entry(header_state.header.height)
                            .or_default()
                            .insert(header_state.header.hash);
                    }
                }
            }

            height_versions
                .into_iter()
                .filter(|(_, versions)| versions.len() > 1)
                .map(|(height, _)| height)
                .collect::<HashSet<_>>()
        };

        if !fork_info.is_empty() {
            self.handle_chain_fork(fork_info).await?;
        }

        let max_peer_height = {
            // Snapshot peers first, then read headers — never hold both guards at
            // once (couples the locks: a wedged headers writer would wedge peers).
            let peer_infos: Vec<(String, u32)> = {
                let peers = self.node.peers.read().await;
                peers
                    .values()
                    .map(|info| (info.address.to_string(), info.blocks))
                    .collect()
            };
            let headers = self.header_sentinel.headers.read().await;

            peer_infos
                .iter()
                .filter(|(address, _)| headers.iter().any(|h| h.verified_by.contains(address)))
                .map(|(_, blocks)| *blocks)
                .max()
                .unwrap_or(0)
        };

        if max_peer_height > current_height + SYNC_THRESHOLD {
            self.node.sync_with_network().await?;
        }

        Ok(())
    }

    async fn handle_chain_fork(&self, fork_blocks: HashSet<u32>) -> Result<(), String> {
        let mut stats = self.stats.write().await;
        stats.anomalies_detected += 1;

        // Same-height races are routine on this network (multiple miners at the
        // difficulty floor) and canonical choice is settled by the PoW reorg engine,
        // not this layer — see the note above resolve_fork. Log at debug: an error
        // here reads as "unresolved fork" when nothing is wrong.
        debug!("Competing headers observed at blocks: {:?}", fork_blocks);

        // Get reputable validators (Emerald tier and above)
        let trusted_validators: HashSet<String> = self
            .node_metrics
            .iter()
            .filter(|metrics| {
                matches!(
                    metrics.current_tier,
                    ValidatorTier::RedDiamond | ValidatorTier::Diamond | ValidatorTier::Emerald
                )
            })
            .map(|metrics| metrics.key().clone())
            .collect();

        if trusted_validators.is_empty() {
            // node_metrics is never populated on a live node (register_wallet_metrics
            // has no callers), so this set is always empty and the diagnostics-only
            // resolution below has nothing to do. That is the expected state, not an
            // error: the PoW reorg engine resolves the race independently.
            debug!("bPoS validator registry empty; leaving fork resolution to the reorg engine");
            return Ok(());
        }

        // Resolve each fork point
        let mut resolved = 0;
        for height in fork_blocks {
            if let Ok(()) = self.resolve_fork(height, &trusted_validators).await {
                resolved += 1;
            }
        }

        stats.forks_resolved += resolved as u64;
        Ok(())
    }

    // NOT a live canonical-override safety net. This bPoS fork-resolution layer
    // (resolve_fork / emergency_fork_resolution / enforce_canonical_chain / get_block_from_network)
    // is non-functional — get_block_from_network requests the fixed [0,0] height range and can't
    // fetch a competing block — and is retained only for diagnostics/telemetry. Canonical choice is
    // decided solely by PoW work-weight in the reorg engine (converge_to_canonical /
    // try_adopt_orphan_branch). Do not wire this into block acceptance.
    async fn resolve_fork(
        &self,
        block_height: u32,
        trusted_validators: &HashSet<String>,
    ) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let blockchain = self.blockchain.read().await;
        let current_height = blockchain.get_latest_block_index() as u32;
        let blocks_since_fork = current_height.saturating_sub(block_height);
        drop(blockchain);

        // Emergency resolution check
        if blocks_since_fork > 1000 {
            return self.emergency_fork_resolution(block_height).await;
        }

        // Security hardening: Never drop below safe consensus threshold
        let min_validators = 3;

        if trusted_validators.len() < min_validators {
            warn!(
                "Insufficient validators ({}) for fork resolution - block age: {}",
                trusted_validators.len(),
                blocks_since_fork
            );

            if blocks_since_fork > 100 {
                // Fall back to any validators in emergency
                info!("Using fallback validator set due to fork duration");
            } else {
                return Ok(());
            }
        }

        let headers = self.header_sentinel.headers.read().await;
        let mut versions: HashMap<[u8; 32], Vec<(String, ValidatorTier, u64)>> = HashMap::new();

        // Process headers with adaptive time window
        let time_window = match blocks_since_fork {
            0..=50 => 300,   // 5 minutes normally
            51..=100 => 600, // 10 minutes if unresolved
            _ => 1800,       // 30 minutes in emergency
        };

        for header_state in headers.iter() {
            // Adaptive future timestamp tolerance
            let max_future = if self.network_health.read().await.fork_count > 0 {
                600 // 10 minutes during network issues
            } else {
                300 // 5 minutes normally
            };

            if header_state.timestamp > now + max_future {
                warn!(
                    "Skipping future header: {} (max allowed: {})",
                    header_state.timestamp,
                    now + max_future
                );
                continue;
            }

            if header_state.header.height == block_height {
                for verifier in &header_state.verified_by {
                    if let Some(metrics) = self.node_metrics.get(verifier) {
                        // Adaptive validator requirements
                        if blocks_since_fork > 100 || metrics.uptime >= 95.0 {
                            versions.entry(header_state.header.hash).or_default().push((
                                verifier.clone(),
                                metrics.current_tier.clone(),
                                header_state.timestamp,
                            ));
                        }
                    }
                }
            }
        }

        // Require minimum versions unless emergency
        if versions.is_empty() && blocks_since_fork < 100 {
            info!("No valid versions found for height {}", block_height);
            return Ok(());
        }

        // Score calculation with safety bounds
        let mut hash_scores: HashMap<[u8; 32], f64> = HashMap::new();
        for (hash, verifiers) in versions {
            // Minimum verifiers requirement reduces over time
            let min_verifiers = match blocks_since_fork {
                0..=50 => 3,
                51..=100 => 2,
                _ => 1,
            };

            if verifiers.len() < min_verifiers && blocks_since_fork < 100 {
                continue;
            }

            let base_score: f64 = verifiers
                .iter()
                .map(|(_, tier, timestamp)| {
                    // Base tier score
                    let tier_score = match tier {
                        ValidatorTier::RedDiamond => 5.0,
                        ValidatorTier::Diamond => 4.0,
                        ValidatorTier::Emerald => 3.0,
                        ValidatorTier::Gold => 2.0,
                        ValidatorTier::Silver => 1.0,
                        ValidatorTier::Inactive => 0.0,
                    };

                    // Time weighting with adaptive window
                    let age = now.saturating_sub(*timestamp);
                    if age > time_window {
                        return 0.0;
                    }

                    let time_factor = 1.0 + (age as f64 / time_window as f64).min(1.0);
                    (tier_score * time_factor).min(10.0)
                })
                .sum::<f64>();

            // Time consistency verification
            let timestamps: Vec<_> = verifiers.iter().map(|(_, _, t)| t).collect();
            if let (Some(&min_time), Some(&max_time)) =
                (timestamps.iter().min(), timestamps.iter().max())
            {
                if max_time - min_time > time_window && blocks_since_fork < 50 {
                    continue;
                }
            }

            hash_scores.insert(hash, base_score);
        }

        // Adaptive threshold based on fork duration
        let network_health = self.network_health.read().await;
        let base_threshold = match blocks_since_fork {
            0..=50 => 10.0,  // Normal threshold
            51..=100 => 7.0, // Reduced threshold
            _ => 5.0,        // Emergency threshold
        };

        let threshold_multiplier = if blocks_since_fork > 100 {
            0.5 // Emergency mode
        } else {
            (1.0 + (network_health.fork_count as f64 * 0.2)).min(2.0)
        };

        let required_score = base_threshold * threshold_multiplier;

        // Find best version with sufficient score
        if let Some((&canonical_hash, score)) = hash_scores
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
        {
            let blockchain = self.blockchain.read().await;
            let current_block = blockchain.get_block(block_height)?;

            if current_block.hash != canonical_hash && *score >= required_score {
                // Double verification unless emergency
                let should_switch = if blocks_since_fork > 100 {
                    true
                } else {
                    let confirmation_score = self
                        .verify_fork_switch(&current_block, canonical_hash)
                        .await?;
                    confirmation_score >= required_score
                };

                if should_switch {
                    drop(blockchain);
                    if let Some(block) = self.get_block_from_network(canonical_hash).await? {
                        info!(
                            "Switching to fork version with score {} (required {})",
                            score, required_score
                        );
                        self.enforce_canonical_chain(block).await?;

                        let mut health = self.network_health.write().await;
                        health.update_fork_count(true);
                    }
                }
            }
        }

        Ok(())
    }

    async fn emergency_fork_resolution(&self, block_height: u32) -> Result<(), String> {
        warn!(
            "EMERGENCY: Initiating forced fork resolution for height {}",
            block_height
        );

        // Get ALL versions from ANY validator
        let versions = self.get_all_block_versions(block_height).await?;

        if versions.is_empty() {
            return Err("No versions available for emergency resolution".into());
        }

        // Count occurrences of each version
        let mut version_counts: HashMap<[u8; 32], usize> = HashMap::new();
        for block in versions {
            *version_counts.entry(block.hash).or_insert(0) += 1;
        }

        // Take most common version
        if let Some((&hash, _)) = version_counts.iter().max_by_key(|&(_, count)| count) {
            if let Some(block) = self.get_block_from_network(hash).await? {
                warn!("EMERGENCY: Forcing switch to most common version");
                self.enforce_canonical_chain(block).await?;

                let mut health = self.network_health.write().await;
                health.update_fork_count(true);
            }
        }

        Ok(())
    }

    async fn verify_fork_switch(&self, current: &Block, new_hash: [u8; 32]) -> Result<f64, String> {
        let peers = self.node.peers.read().await;
        let mut confirmation_score = 0.0;

        let peer_futures: Vec<_> = peers
            .iter()
            .take(5)
            .map(|(addr, _)| {
                self.node
                    .request_blocks(*addr, current.index, current.index)
            })
            .collect();

        for blocks in futures::future::join_all(peer_futures)
            .await
            .into_iter()
            .flatten()
        {
            if let Some(block) = blocks.first() {
                if block.hash == new_hash {
                    confirmation_score += 2.0;
                }
            }
        }

        Ok(confirmation_score)
    }

    async fn get_all_block_versions(&self, height: u32) -> Result<Vec<Block>, String> {
        let peers = self.node.peers.read().await;
        let mut all_versions = Vec::new();

        let peer_futures: Vec<_> = peers
            .keys()
            .map(|addr| self.node.request_blocks(*addr, height, height))
            .collect();

        for mut blocks in futures::future::join_all(peer_futures)
            .await
            .into_iter()
            .flatten()
        {
            all_versions.append(&mut blocks);
        }

        Ok(all_versions)
    }

    fn start_header_verification(&self) {
        let sentinel = Arc::clone(&self.header_sentinel);
        let blockchain = Arc::clone(&self.blockchain);
        let node = Arc::clone(&self.node);
        let node_copy = Arc::clone(&self.node);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10)); // Much longer interval
            let mut last_height = 0u32;

            loop {
                interval.tick().await;

                // Only process if height has changed
                let current_height = {
                    let chain = blockchain.read().await;
                    chain.get_latest_block_index() as u32
                };

                if current_height <= last_height {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }

                // Get only new headers since last check — RANGED reads, never
                // get_blocks(): that decoded the ENTIRE chain into memory every 10s
                // cycle just to take 100 headers (O(chain) RAM + CPU, growing
                // forever), the same unbounded-materialization class as the whisper
                // scan fix.
                let headers = {
                    let chain = blockchain.read().await;
                    let from = last_height.saturating_add(1);
                    let to = current_height.min(last_height.saturating_add(100));
                    let mut out = Vec::with_capacity((to.saturating_sub(from) + 1) as usize);
                    for i in from..=to {
                        if let Ok(block) = chain.get_block(i) {
                            out.push(BlockHeaderInfo {
                                height: block.index,
                                hash: block.hash,
                                prev_hash: block.previous_hash,
                                timestamp: block.timestamp,
                            });
                        }
                    }
                    out
                };

                if let Ok(signature) = sentinel.sign_header(&headers).await {
                    // Snapshot-then-drop: this held the peers guard across up to 5
                    // network broadcasts plus inter-peer sleeps every cycle — with one
                    // stalled peer socket that is a repeated ~10-50s guard hold, i.e.
                    // the 2026-07-08 livelock class.
                    let targets: Vec<SocketAddr> = {
                        let peers = node.peers.read().await;
                        peers.keys().copied().take(5).collect()
                    };
                    for addr in targets {
                        if let Err(e) = sentinel
                            .broadcast_verified_headers(addr, &headers, &signature, &node_copy)
                            .await
                        {
                            warn!("Failed to broadcast headers to {}: {}", addr, e);
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await; // Add delay between peers
                    }
                }

                last_height = current_height;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    pub async fn process_header_sync(
        &self,
        headers: Vec<BlockHeaderInfo>,
        node_id: &str,
        signature: Vec<u8>,
    ) -> Result<(), String> {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Batch verify headers
        if let Ok(valid_count) = self
            .header_sentinel
            .verify_headers_batch(headers.clone(), node_id, signature)
            .await
        {
            // Update metrics if we verified any headers
            if valid_count > 0 {
                if let Some(mut metrics) = self.node_metrics.get_mut(node_id) {
                    metrics.last_active = start_time;
                    metrics.blocks_verified += valid_count as u64;
                    metrics.success_rate = 100.0;

                    // Update header heights in verified set
                    for header in headers {
                        metrics.verified_blocks.insert(header.height);
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn record_action(
        &self,
        address: &str,
        action_type: ActionType,
        success: bool,
        height: Option<u32>,
    ) -> Result<(), String> {
        let mut metrics = self
            .node_metrics
            .get_mut(address)
            .ok_or("Node metrics not found")?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if success && action_type == ActionType::BlockValidation {
            metrics.blocks_verified += 1;
            if let Some(height) = height {
                metrics.verified_blocks.insert(height);
            }
        }

        metrics
            .action_history
            .push_back((now, action_type, success));
        metrics.calculate_performance_score();

        Ok(())
    }

    async fn calculate_cooldown_remaining(&self, address: &str) -> Option<u64> {
        if let Some(metrics) = self.node_metrics.get(address) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if now > metrics.last_withdrawal + WITHDRAWAL_COOLDOWN {
                return Some(0);
            }

            return Some(metrics.last_withdrawal + WITHDRAWAL_COOLDOWN - now);
        }
        None
    }

    pub async fn register_wallet_metrics(&self, address: &str, balance: f64) -> Result<(), String> {
        let metrics = NodeMetrics::new(address.to_string(), balance);
        self.node_metrics.insert(address.to_string(), metrics);
        Ok(())
    }

    pub async fn get_node_metrics(&self, address: &str) -> Result<NodeMetrics, String> {
        self.node_metrics
            .get(address)
            .map(|m| m.clone())
            .ok_or_else(|| "Node metrics not found for address".to_string())
    }

    pub async fn get_network_metrics(&self) -> Result<NetworkHealth, String> {
        Ok(self.network_health.read().await.clone())
    }

    async fn update_network_health(&self, force_full_update: bool) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // LOCK ORDER MATTERS: gather every slow input BEFORE taking the health write
        // lock. This lock is read by interactive status paths (the `info` command);
        // holding it across blockchain/peers/mempool reads meant a long reorg (which
        // holds the chain write lock for its whole validation pass) wedged the entire
        // console for minutes — the "info prints Network Status then hangs" bug.
        let chain_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_latest_block_index() as u32
        };

        let needs_full = force_full_update || {
            let health = self.network_health.read().await;
            now - health.last_update > 300
        };
        let full_snapshot = if needs_full {
            let peer_count = self.node.peers.read().await.len();
            // Active nodes should reflect live network participants (self + connected peers),
            // not wallet metric entries.
            let active_nodes = peer_count.saturating_add(1);
            let network_load = {
                let blockchain = self.blockchain.read().await;
                let pending_tx_count = blockchain.get_pending_transactions().await?.len();
                (pending_tx_count as f64 / MAX_BLOCK_SIZE as f64).min(1.0)
            };
            Some((peer_count, active_nodes, network_load))
        } else {
            None
        };

        // Store under a briefly-held write lock — no awaits on other locks inside.
        let mut health = self.network_health.write().await;
        health.chain_height = chain_height;
        if let Some((peer_count, active_nodes, network_load)) = full_snapshot {
            let total_nodes = active_nodes.max(1);
            health.active_nodes = active_nodes.max(1);
            health.participation_rate = (active_nodes as f64 / total_nodes as f64).min(1.0);
            health.network_load = network_load;
            health.average_peer_count = peer_count as f64;
            health.last_update = now;
        }

        Ok(())
    }

    async fn verify_temporal_consistency(&self, header: &BlockHeaderInfo) -> bool {
        let blockchain = self.blockchain.read().await;
        let current_height = blockchain.get_latest_block_index() as u32;

        // Must be within 2 blocks of current height
        if header.height > current_height + 2 || header.height < current_height.saturating_sub(2) {
            return false;
        }

        // Verify timestamp is within 6 seconds (3 block times)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now - header.timestamp > 6 || header.timestamp > now + 2 {
            return false;
        }

        true
    }

    async fn verify_chain_health(&self) -> bool {
        let blockchain = self.blockchain.read().await;

        // Get last few blocks
        let blocks = blockchain.get_blocks();
        if blocks.len() < 2 {
            return true; // Not enough blocks to check
        }

        // Verify block times
        let recent_blocks: Vec<_> = blocks.iter().rev().take(10).collect();
        for window in recent_blocks.windows(2) {
            let time_diff = window[0].timestamp - window[1].timestamp;
            if time_diff > 3 || time_diff == 0 {
                return false; // Block time violation
            }
        }

        // Verify hash chain
        let mut prev_hash = recent_blocks[0].hash;
        for block in recent_blocks.iter().skip(1) {
            if block.previous_hash != prev_hash {
                return false; // Hash chain broken
            }
            prev_hash = block.hash;
        }

        true
    }

    async fn repair_chain(&self) -> Result<(), String> {
        let blockchain = self.blockchain.read().await;
        let current_height = blockchain.get_latest_block_index() as u32;

        // Get peer blocks
        let peers = self.node.peers.read().await;
        let mut peer_blocks = Vec::new();

        for (addr, _) in peers.iter() {
            if let Ok(blocks) = self
                .node
                .request_blocks(*addr, current_height.saturating_sub(10), current_height)
                .await
            {
                peer_blocks.push(blocks);
            }
        }

        // Find consensus chain
        let consensus_chain = self.find_consensus_chain(peer_blocks).await?;

        // Replace broken chain section
        self.replace_chain_section(consensus_chain).await?;

        Ok(())
    }

    async fn get_competing_blocks(&self, block_height: u32) -> Result<Vec<Block>, String> {
        let mut competing_blocks = Vec::new();
        let peers = self.node.peers.read().await;

        for (addr, _) in peers.iter() {
            if let Ok(blocks) = self
                .node
                .request_blocks(*addr, block_height, block_height)
                .await
            {
                competing_blocks.extend(blocks);
            }
        }

        Ok(competing_blocks)
    }

    async fn get_block_from_network(&self, hash: [u8; 32]) -> Result<Option<Block>, String> {
        // Try to get block from connected peers
        let peers = self.node.peers.read().await;
        for (addr, _) in peers.iter().take(3) {
            // Try up to 3 peers
            if let Ok(blocks) = self.node.request_blocks(*addr, 0, 0).await {
                if let Some(block) = blocks.into_iter().find(|b| b.hash == hash) {
                    return Ok(Some(block));
                }
            }
        }
        Ok(None)
    }

    async fn determine_canonical_block(&self, blocks: Vec<Block>) -> Result<Block, String> {
        if blocks.is_empty() {
            return Err("No blocks to analyze".to_string());
        }

        // Group blocks by hash and count occurrences
        let mut block_counts: HashMap<[u8; 32], (usize, Block)> = HashMap::new();

        for block in blocks {
            block_counts
                .entry(block.hash)
                .and_modify(|(count, _)| *count += 1)
                .or_insert((1, block));
        }

        // Find the block with the most attestations
        block_counts
            .into_iter()
            .max_by_key(|(_, (count, _))| *count)
            .map(|(_, (_, block))| block)
            .ok_or_else(|| "Failed to determine canonical block".to_string())
    }

    async fn enforce_canonical_chain(&self, canonical: Block) -> Result<(), String> {
        // Simple enforcement - just save the canonical block
        let blockchain = self.blockchain.read().await;
        blockchain
            .save_block(&canonical)
            .await
            .map_err(|e| format!("Failed to save canonical block: {}", e))?;
        Ok(())
    }

    async fn request_headers(&self, addr: SocketAddr) -> Result<(), String> {
        let current_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_latest_block_index() as u32
        };

        let message = NetworkMessage::GetHeaders {
            start_height: current_height.saturating_sub(1000),
            end_height: current_height,
        };

        self.node
            .send_message(addr, &message)
            .await
            .map_err(|e| e.to_string())
    }

    async fn broadcast_verification(
        &self,
        addr: SocketAddr,
        header: &BlockHeaderInfo,
        signature: &[u8],
    ) -> Result<(), String> {
        self.node
            .advertise_mldsa_key(addr)
            .await
            .map_err(|e| e.to_string())?;
        let message = NetworkMessage::HeaderVerification {
            header: header.clone(),
            node_id: self.node.id().to_string(), // Using accessor method instead of direct field access
            signature: signature.to_vec(),
        };

        self.node
            .send_message(addr, &message)
            .await
            .map_err(|e| e.to_string())
    }

    async fn get_latest_verified_header(&self) -> Result<[u8; 32], String> {
        let headers = self.verified_headers.read().await;
        headers
            .back()
            .map(|(_, hash)| *hash)
            .ok_or_else(|| "No verified headers".to_string())
    }

    async fn await_challenge_response(&self, addr: SocketAddr) -> Result<Vec<u8>, String> {
        let timeout = Duration::from_secs(5);
        let start = Instant::now();

        while start.elapsed() < timeout {
            if let Ok(response) = self.node.receive_message(addr).await {
                match response {
                    NetworkMessage::ChallengeResponse { signature, .. } => {
                        return Ok(signature);
                    }
                    _ => continue,
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Err("Challenge response timeout".to_string())
    }

    async fn find_consensus_chain(
        &self,
        peer_blocks: Vec<Vec<Block>>,
    ) -> Result<Vec<Block>, String> {
        if peer_blocks.is_empty() {
            return Err("No peer blocks available".to_string());
        }

        // Count block occurrences
        let mut block_counts: HashMap<[u8; 32], (usize, Block)> = HashMap::new();

        for chain in &peer_blocks {
            for block in chain {
                block_counts
                    .entry(block.hash)
                    .and_modify(|(count, _)| *count += 1)
                    .or_insert((1, block.clone()));
            }
        }

        // Find most common chain
        let mut consensus_chain: Vec<_> = block_counts
            .into_iter()
            .filter(|(_, (count, _))| *count >= peer_blocks.len().div_ceil(2))
            .map(|(_, (_, block))| block)
            .collect();

        // Sort by height
        consensus_chain.sort_by_key(|block| block.index);

        Ok(consensus_chain)
    }

    async fn replace_chain_section(&self, consensus_chain: Vec<Block>) -> Result<(), String> {
        let blockchain = self.blockchain.read().await;

        // Verify chain section
        for window in consensus_chain.windows(2) {
            if window[1].previous_hash != window[0].hash {
                return Err("Invalid chain section".to_string());
            }
        }

        // Replace blocks
        for block in consensus_chain {
            blockchain
                .save_block(&block)
                .await
                .map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    async fn calculate_consensus_participation(&self) -> Result<f64, String> {
        let total_nodes = self.node_metrics.len();
        if total_nodes == 0 {
            return Ok(0.0);
        }

        let participating = self
            .node_metrics
            .iter()
            .filter(|m| {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                m.last_active + SENTINEL_CHECK_INTERVAL > now && m.blocks_verified > 0
            })
            .count();

        Ok(participating as f64 / total_nodes as f64)
    }

    async fn calculate_network_load(&self) -> Result<f64, String> {
        // Take a single atomic read of both blockchain and headers
        let headers_guard = self.header_cache.read().await;

        // Early return if no blocks to analyze
        if headers_guard.is_empty() {
            return Ok(0.0);
        }

        // Consider only recent blocks for more accurate current load
        let recent_blocks: Vec<_> = headers_guard
            .iter()
            .rev()
            .take(100) // Look at last 100 blocks for stable average
            .collect();

        if recent_blocks.is_empty() {
            return Ok(0.0);
        }

        // Use iterator adaptors for efficient computation
        let total_txs: usize = recent_blocks.iter().map(|b| b.transactions.len()).sum();

        let avg_txs = (total_txs as f64) / (recent_blocks.len() as f64);
        let capacity_usage = (avg_txs / MAX_BLOCK_SIZE as f64).min(1.0);

        Ok(capacity_usage)
    }

    async fn verify_chain_state(&self) -> Result<(), String> {
        // Snapshot the tip height under a SHORT read lock and release it BEFORE the
        // join_all below. verify_block_at_height re-acquires blockchain.read() per child;
        // holding a parent read across that reentrant re-acquire can stall block-writes
        // up to the startup timeout under tokio's write-preferring RwLock (audit M5).
        let current_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.get_latest_block_index() as u32
        };

        let mut verified_blocks = HashSet::new();
        let mut anomalies = Vec::new();

        // Verify recent blocks in parallel, but skip very old blocks (genesis era)
        // Old blocks may have different formats and validation rules
        const MIN_BLOCK_AGE_FOR_VERIFICATION: u32 = 100; // Skip blocks older than 100 blocks
        let start_height = current_height.saturating_sub(BLOCK_VERIFICATION_BATCH_SIZE as u32);
        let min_height = MIN_BLOCK_AGE_FOR_VERIFICATION.max(start_height);

        let blocks: Vec<_> = (min_height..current_height).rev().collect();

        let results = futures::future::join_all(
            blocks
                .iter()
                .map(|&height| self.verify_block_at_height(height)),
        )
        .await;

        // Process verification results
        for (height, result) in blocks.iter().zip(results) {
            match result {
                Ok(true) => {
                    verified_blocks.insert(*height);
                }
                Ok(false) => {
                    anomalies.push(*height);
                }
                Err(e) => {
                    warn!("Error verifying block {}: {}", height, e);
                }
            }
        }

        // Update sentinel stats under a short write lock (not held across the work above).
        {
            let mut stats = self.stats.write().await;
            stats.last_chain_verification = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if !anomalies.is_empty() {
                stats.anomalies_detected += anomalies.len() as u64;
            }
        }

        if !anomalies.is_empty() {
            self.handle_chain_anomalies(anomalies).await?;
        }

        Ok(())
    }

    async fn verify_block_at_height(&self, height: u32) -> Result<bool, String> {
        const BATCH_SIZE: usize = 50;

        let blockchain = self.blockchain.read().await;
        let mut blocks_to_verify = Vec::with_capacity(BATCH_SIZE);

        // Get the target block and context blocks
        let target_block = blockchain.get_block(height)?;
        blocks_to_verify.push(target_block.clone());

        // Get some context blocks if available
        let context_start = height.saturating_sub((BATCH_SIZE - 1) as u32);
        for h in context_start..height {
            if let Ok(block) = blockchain.get_block(h) {
                blocks_to_verify.push(block);
            }
        }

        // Run batch verification
        let results = self.verify_block_batch(&blocks_to_verify).await?;

        // Target block is first in the batch
        Ok(results[0])
    }

    async fn verify_block_batch(&self, blocks: &[Block]) -> Result<Vec<bool>, String> {
        use rayon::prelude::*;

        // Prepare validation context
        let _blockchain = self.blockchain.read().await;

        // Convert blocks to validation tasks
        let validation_tasks: Vec<_> = blocks
            .into_par_iter()
            .map(|block| {
                // Phase 1: Basic validation (can run in parallel)
                let basic_valid = {
                    // For confirmed blocks in the chain, skip detailed validation
                    // These blocks have already been validated when they were mined and accepted
                    // BPoS anomaly detection should focus on network-level attacks, not re-validation

                    // Basic sanity checks only
                    if block.transactions.is_empty() && block.index > 0 {
                        // Empty non-genesis blocks are suspicious
                        return false;
                    }

                    // Check for obviously invalid data (negative values, etc.)
                    for tx in &block.transactions {
                        if tx.amount_units < 0 || tx.fee_units < 0 {
                            return false;
                        }
                    }

                    true
                };

                if !basic_valid {
                    return false;
                }

                // Return validation result
                basic_valid
            })
            .collect();

        // Run all validations in parallel
        let results: Vec<bool> = validation_tasks
            .into_par_iter()
            .map(|valid| valid)
            .collect();

        Ok(results)
    }

    async fn verify_block_integrity(&self, block: &Block) -> Result<bool, String> {
        // Verify block hash
        let calculated_hash = block.calculate_hash_for_block();
        if calculated_hash != block.hash {
            return Ok(false);
        }

        // Verify merkle root
        let merkle_root = Blockchain::calculate_merkle_root(&block.transactions)?;
        if merkle_root != block.merkle_root {
            return Ok(false);
        }

        Ok(true)
    }

    async fn verify_transaction(&self, tx: &Transaction) -> Result<bool, String> {
        // For transactions in confirmed blocks, we only need to verify structural integrity
        // Balance and signature verification was already done when the block was mined

        // Basic sanity checks for confirmed transactions
        if tx.amount_units < 0 || tx.fee_units < 0 {
            return Ok(false);
        }

        // System addresses are always valid in confirmed blocks
        if tx.sender == "MINING_REWARDS" {
            return Ok(true);
        }

        // For regular transactions in confirmed blocks, assume they were valid when confirmed
        // The fact that they're in a confirmed block means they passed validation when created
        Ok(true)
    }

    async fn handle_chain_anomalies(&self, anomalies: Vec<u32>) -> Result<(), String> {
        for height in anomalies {
            error!(
                "CRITICAL: Chain anomaly detected at height {} - requires immediate attention",
                height
            );

            // Alert network
            self.broadcast_anomaly_alert(height).await?;

            // Attempt recovery
            if let Err(e) = self.attempt_chain_recovery(height).await {
                error!("Failed to recover chain at height {}: {}", height, e);
            }
        }
        Ok(())
    }

    async fn broadcast_anomaly_alert(&self, height: u32) -> Result<(), String> {
        // Rate limiting: Only broadcast once per minute to prevent flooding
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut last_broadcast = self.last_anomaly_broadcast.write().await;
        if now - *last_broadcast < 60 {
            // Skip broadcast if less than 60 seconds since last one
            return Ok(());
        }
        *last_broadcast = now;
        drop(last_broadcast);

        // Snapshot-then-drop: never hold the peers guard across network sends (the
        // guard-across-send pattern livelocked the whole node on 2026-07-08).
        let addrs: Vec<SocketAddr> = {
            let peers = self.node.peers.read().await;
            peers.keys().copied().collect()
        };
        for addr in addrs {
            let message = NetworkMessage::AlertMessage(format!("ANOMALY:{}", height));

            if let Err(e) = self.node.send_message(addr, &message).await {
                error!("Failed to alert peer {} of critical anomaly: {}", addr, e);
            }
        }
        Ok(())
    }

    async fn attempt_chain_recovery(&self, height: u32) -> Result<(), String> {
        // Snapshot-then-drop (see broadcast_anomaly_alert).
        let peer_addrs: Vec<SocketAddr> = {
            let peers = self.node.peers.read().await;
            peers.keys().copied().collect()
        };
        let mut valid_blocks = Vec::new();

        // Request blocks from peers in parallel
        let requests = peer_addrs.iter().map(|addr| async {
            match self.node.request_blocks(*addr, height, height).await {
                Ok(mut blocks) => {
                    if blocks.len() == 1
                        && self
                            .verify_block_integrity(&blocks[0])
                            .await
                            .unwrap_or(false)
                    {
                        Some(blocks.remove(0))
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        });

        let results = futures::future::join_all(requests).await;
        valid_blocks.extend(results.into_iter().flatten());

        // If we have valid blocks, select the consensus block
        if !valid_blocks.is_empty() {
            let consensus_block = self.select_consensus_block(valid_blocks)?;

            // Replace block in blockchain
            let blockchain = self.blockchain.read().await;
            blockchain
                .save_block(&consensus_block)
                .await
                .map_err(|e| format!("Failed to save consensus block: {}", e))?;

            // Update network health metrics
            let mut health = self.network_health.write().await;
            health.fork_count += 1;
            health.last_update = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }

        Ok(())
    }

    fn select_consensus_block(&self, blocks: Vec<Block>) -> Result<Block, String> {
        // Group blocks by hash and select the most common
        let mut block_counts: HashMap<[u8; 32], (usize, Block)> = HashMap::new();

        for block in blocks {
            block_counts
                .entry(block.hash)
                .and_modify(|(count, _)| *count += 1)
                .or_insert((1, block));
        }

        block_counts
            .into_iter()
            .max_by_key(|(_, (count, _))| *count)
            .map(|(_, (_, block))| block)
            .ok_or_else(|| "No consensus block found".to_string())
    }

    async fn initialize_sentinel(&mut self) -> Result<(), String> {
        // Generate fresh mldsa keypair for this node instance
        let (_public_key, secret_key) = mldsa::generate_keypair();

        let sentinel = NodeSentinel {
            secret_key,
            last_challenge: 0,
            verified_peers: HashSet::new(),
        };

        self.node_sentinel = Some(Arc::new(RwLock::new(sentinel)));

        // Start sentinel monitoring tasks
        self.start_sentinel_tasks();

        info!("Quantum-resistant sentinel initialized");
        Ok(())
    }

    fn start_sentinel_tasks(&self) {
        let sentinel = self.clone();

        // Spawn sentinel verification cycle
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(SENTINEL_VERIFY_INTERVAL));
            loop {
                interval.tick().await;
                if let Err(e) = sentinel.verify_network_integrity().await {
                    error!("Sentinel verification error: {}", e);
                }
            }
        });

        // Spawn header verification task
        let sentinel = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(SENTINEL_VERIFY_INTERVAL / 2));
            loop {
                interval.tick().await;
                if let Err(e) = sentinel.verify_network_integrity().await {
                    error!("Header verification error: {}", e);
                }
            }
        });
    }

    // Verify network integrity
    pub async fn verify_network_integrity(&self) -> Result<(), String> {
        // Snapshot-then-drop: this ran periodically holding the peers guard across
        // challenge generation AND the whole network verification fan-out — a prime
        // wedge/livelock source (2026-07-08 class: guard-across-network-io).
        let peer_addrs: Vec<SocketAddr> = {
            let peers = self.node.peers.read().await;
            peers.keys().copied().collect()
        };
        let mut verifications = Vec::new();

        // Generate and send challenges in parallel
        for addr in peer_addrs {
            let challenge = self
                .generate_challenge()
                .await
                .map_err(|e| format!("Failed to generate challenge: {}", e))?;

            verifications.push((addr, challenge));
        }

        // Clone the necessary data for each verification task
        // Process verifications in parallel
        let verification_results = futures::future::join_all(verifications.into_iter().map(
            |(addr, challenge)| async move {
                let sentinel = self.clone();
                match sentinel.verify_peer_sentinel(addr, &challenge).await {
                    Ok(_) => Ok(addr),
                    Err(e) => {
                        warn!("Peer sentinel verification failed {}: {}", addr, e);
                        Err((addr, e))
                    }
                }
            },
        ))
        .await;

        // Handle failed verifications
        let failed_peers: Vec<_> = verification_results
            .into_iter()
            .filter_map(|r| match r {
                Err((addr, _)) => Some(addr),
                _ => None,
            })
            .collect();

        for addr in failed_peers {
            self.handle_failed_verification(addr).await?;
        }

        // Update network health metrics
        let mut health = self.network_health.write().await;
        health.last_update = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(())
    }

    async fn generate_challenge(&self) -> Result<SentinelChallenge, String> {
        if let Some(sentinel) = &self.node_sentinel {
            let sentinel = sentinel.write().await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Generate random nonce
            let mut nonce = [0u8; 32];
            thread_rng().fill(&mut nonce);

            // Get latest header hash
            let header_hash = self.get_latest_verified_header().await?;

            // Create challenge data
            let mut challenge_data = Vec::with_capacity(48);
            challenge_data.extend_from_slice(&now.to_le_bytes());
            challenge_data.extend_from_slice(&nonce);
            challenge_data.extend_from_slice(&header_hash);

            // Sign with sentinel's mldsa key
            let signature = mldsa::sign(&challenge_data, &sentinel.secret_key)?;

            Ok(SentinelChallenge {
                timestamp: now,
                nonce,
                header_hash,
                signature,
            })
        } else {
            Err("Sentinel not initialized".to_string())
        }
    }

    async fn verify_peer_sentinel(
        &self,
        addr: SocketAddr,
        challenge: &SentinelChallenge,
    ) -> Result<(), String> {
        let message = NetworkMessage::Challenge(
            codec::serialize(challenge).map_err(|e| format!("Serialization error: {}", e))?,
        );

        self.node.send_message(addr, &message).await?;

        if let Ok(response) = self.await_challenge_response(addr).await {
            let peer_sentinels = self.peer_sentinels.read().await;
            let peer_sentinel = peer_sentinels
                .get(&addr.to_string())
                .ok_or("Peer sentinel not registered")?;

            let response_data = [
                &challenge.timestamp.to_le_bytes(),
                &challenge.nonce[..],
                &response,
            ]
            .concat();

            let verification_result =
                mldsa::verify(&response_data, &response, peer_sentinel.as_slice());
            if verification_result.is_ok() {
                // ... rest of verification logic
                Ok(())
            } else {
                Err("Invalid sentinel response".to_string())
            }
        } else {
            Err("Peer challenge timeout".to_string())
        }
    }

    async fn handle_failed_verification(&self, addr: SocketAddr) -> Result<(), String> {
        if let Some(sentinel) = &self.node_sentinel {
            let mut sentinel = sentinel.write().await;
            sentinel.verified_peers.remove(&addr.to_string());
        }

        // Snapshot-then-drop: never hold the peers guard across sends.
        let peer_addrs: Vec<SocketAddr> = {
            let peers = self.node.peers.read().await;
            peers.keys().copied().collect()
        };
        for peer_addr in peer_addrs {
            if peer_addr != addr {
                let alert = NetworkMessage::AlertMessage(format!(
                    "SENTINEL_ALERT:{}:VERIFICATION_FAILED",
                    addr
                ));
                if let Err(e) = self.node.send_message(peer_addr, &alert).await {
                    warn!("Failed to send sentinel alert to {}: {}", peer_addr, e);
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NodeMetrics {
    pub address: String,
    pub total_balance: f64,
    pub staked_amount: f64,
    pub cumulative_rewards: f64,
    pub current_tier: ValidatorTier,
    pub tier_progress: f64,
    pub uptime: f64,
    pub response_time: u64,
    pub blocks_verified: u64,
    pub last_active: u64,
    pub success_rate: f64,
    pub network_contribution: f64,
    pub performance_history: VecDeque<(u64, f64)>,
    pub last_reward_calculation: u64,
    pub chain_position: u32,
    pub last_withdrawal: u64,
    pub verified_blocks: HashSet<u32>,
    pub fork_resolutions: u32,
    pub total_downtime: u64,
    pub last_header_broadcast: u64,
    pub peer_response_times: Vec<u64>,
    pub action_history: VecDeque<(u64, ActionType, bool)>,
    pub performance_score: f64,
}

impl NodeMetrics {
    pub fn new(address: String, total_balance: f64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            address,
            total_balance,
            staked_amount: total_balance * AUTO_STAKE_PERCENTAGE,
            cumulative_rewards: 0.0,
            current_tier: ValidatorTier::Silver,
            tier_progress: 0.0,
            uptime: 100.0,
            response_time: 0,
            blocks_verified: 0,
            last_active: now,
            success_rate: 0.0,
            network_contribution: 0.0,
            performance_history: VecDeque::with_capacity(168),
            last_reward_calculation: now,
            chain_position: 0,
            last_withdrawal: 0,
            verified_blocks: HashSet::new(),
            fork_resolutions: 0,
            total_downtime: 0,
            last_header_broadcast: now,
            peer_response_times: Vec::new(),
            action_history: VecDeque::new(),
            performance_score: 0.0,
        }
    }

    pub fn update_performance(&mut self) -> f64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Keep existing block verification status but allow decay
        let blocks_score = if self.blocks_verified > 0 {
            let scaled = (1.0 + (self.blocks_verified as f64 / 5.0).ln()).min(1.0);
            let inactivity_period = now.saturating_sub(self.last_active);

            // Decay if inactive (exponential decay)
            if inactivity_period > 3600 {
                let decay_factor = (-((inactivity_period - 3600) as f64) / 86400.0).exp();
                (scaled * 0.6) * decay_factor
            } else {
                scaled * 0.6
            }
        } else {
            0.0
        };

        // Factor in recent activity without resetting
        let active_score = if now.saturating_sub(self.last_active) < 3600 {
            0.4
        } else {
            0.0
        };

        // Calculate final score while preserving block verification status
        let performance_score = blocks_score + active_score;
        self.performance_score = performance_score;

        // Keep success rate at 100% while blocks are being verified
        self.success_rate = if self.blocks_verified > 0 {
            if now.saturating_sub(self.last_active) > 3600 {
                50.0 // Drop to 50% when inactive
            } else {
                100.0
            }
        } else {
            0.0
        };

        performance_score
    }

    pub fn calculate_performance_score(&mut self) -> f64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let time_since_active = now.saturating_sub(self.last_active) as f64;
        let decay_factor = (-time_since_active / 3600.0).exp(); // Decay over 1 hour (3600 seconds)

        let active_score = if time_since_active < 60.0 {
            0.5
        } else {
            0.5 * decay_factor // Gradual decay for active score
        };

        let verification_score = if self.blocks_verified > 0 {
            let base_score = (1.0 + (self.blocks_verified as f64 / 100.0).ln()).min(1.0) * 0.5;

            // Apply decay to verification score as well
            base_score * decay_factor
        } else {
            0.0
        };

        self.performance_score = active_score + verification_score;

        self.success_rate = if self.blocks_verified > 0 {
            if time_since_active < 60.0 {
                100.0
            } else {
                // Decay success rate proportionally to verification score
                50.0 * decay_factor
            }
        } else {
            0.0
        };

        self.performance_score
    }

    pub fn verify_and_prune_actions(&mut self, _now: u64) -> (u64, u64) {
        const MAX_HISTORY: usize = 1000;
        const PRUNE_THRESHOLD: usize = 900;

        let total_before = self.verified_blocks.len() as u64;

        // Prune old verifications if needed
        if self.verified_blocks.len() > MAX_HISTORY {
            let blocks: Vec<_> = self.verified_blocks.iter().copied().collect();
            let to_remove = blocks.len() - PRUNE_THRESHOLD;

            for &height in blocks.iter().take(to_remove) {
                self.verified_blocks.remove(&height);
            }
        }

        // Update blocks_verified count
        self.blocks_verified = self.verified_blocks.len() as u64;

        // Calculate valid actions (recent verifications)
        let valid_actions = self.blocks_verified;

        self.calculate_performance_score();

        (valid_actions, total_before)
    }
}

#[derive(Debug, Clone)]
pub struct NetworkHealth {
    pub active_nodes: usize,
    pub average_block_time: f64,
    pub chain_height: u32,
    pub total_staked: f64,
    pub average_response_time: u64,
    pub participation_rate: f64,
    pub fork_count: u32,
    pub anomaly_count: u32,
    pub last_update: u64,
    pub recent_blocks: VecDeque<u32>,
    pub peer_distribution: HashMap<String, usize>,
    pub network_load: f64,
    pub consensus_participation: f64,
    pub average_peer_count: f64,
}

impl NetworkHealth {
    pub fn new() -> Self {
        Self {
            active_nodes: 0,
            average_block_time: 0.0,
            chain_height: 0,
            total_staked: 0.0,
            average_response_time: 0,
            participation_rate: 0.0,
            fork_count: 0,
            anomaly_count: 0,
            last_update: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            recent_blocks: VecDeque::with_capacity(1000),
            peer_distribution: HashMap::new(),
            network_load: 0.0,
            consensus_participation: 0.0,
            average_peer_count: 0.0,
        }
    }

    pub fn update_fork_count(&mut self, new_fork: bool) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // More aggressive decay - every 30 minutes
        let time_delta = now.saturating_sub(self.last_update);
        let periods_elapsed = time_delta / 1800; // 30 minute periods

        if periods_elapsed > 0 {
            // Decay by 2 per period, ensuring we clear forks more quickly
            self.fork_count = self.fork_count.saturating_sub((periods_elapsed * 2) as u32);
        }

        // Add new fork with stricter limits
        if new_fork {
            self.fork_count = self.fork_count.saturating_add(1).min(50);
        }

        self.last_update = now;
    }

    pub fn adjust_for_slow_blocks(&mut self, avg_block_time: f64) {
        // Update block time metrics
        self.average_block_time = avg_block_time;

        // Adjust network load based on block time
        // Higher block times indicate higher network stress
        let stress_factor = (avg_block_time / 2.0).min(1.0);
        self.network_load = self.network_load.max(stress_factor);

        // Update consensus participation based on block timing
        if avg_block_time > 4.0 {
            self.consensus_participation *= 0.9; // Reduce participation score for slow blocks
        }

        // Adjust response time expectation
        self.average_response_time = (avg_block_time * 1000.0) as u64;
    }
}

impl Default for NetworkHealth {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct AnomalyDetector {
    recent_anomalies: VecDeque<String>,
}

#[derive(Debug)]
struct SyncManager {}

#[derive(Debug, Clone, Default)]
pub struct SentinelStats {
    pub total_headers_processed: u64,
    pub anomalies_detected: u64,
    pub forks_resolved: u64,
    pub nodes_synced: u64,
    pub rewards_distributed: f64,
    pub last_chain_verification: u64,
    pub total_uptime: u64,
}

// Implementation for cloning
impl Clone for BPoSSentinel {
    fn clone(&self) -> Self {
        Self {
            blockchain: Arc::clone(&self.blockchain),
            node: Arc::clone(&self.node),
            node_metrics: Arc::clone(&self.node_metrics),
            header_cache: Arc::clone(&self.header_cache),
            network_health: Arc::clone(&self.network_health),
            stats: Arc::clone(&self.stats),
            header_sentinel: Arc::clone(&self.header_sentinel),
            anomaly_detector: Arc::clone(&self.anomaly_detector),
            sync_manager: Arc::clone(&self.sync_manager),
            last_anomaly_broadcast: Arc::clone(&self.last_anomaly_broadcast),
            node_sentinel: self.node_sentinel.clone(),
            peer_sentinels: Arc::clone(&self.peer_sentinels),
            verified_headers: Arc::clone(&self.verified_headers),
            initialized: Arc::clone(&self.initialized),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderInfo {
    pub height: u32,
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
struct HeaderState {
    header: BlockHeaderInfo,
    timestamp: u64,
    verification_count: u32,
    verified_by: HashSet<String>,
}

#[derive(Debug)]
struct VerificationState {
    timestamp: u64,
    verifiers: HashSet<String>,
    mldsa_signatures: HashMap<String, Vec<u8>>,
}

#[derive(Debug)]
struct NetworkSyncState {
    participating_nodes: HashSet<String>,
}

/// A peer's registered ML-DSA verifier key plus the source IP that registered it and when it
/// was last seen active. Source IP is the anti-Sybil anchor (consensus counts DISTINCT IPs,
/// not raw keys) and last_seen drives LRU eviction of the bounded map.
#[derive(Debug, Clone)]
struct RegisteredKey {
    mldsa_public_key: Vec<u8>,
    source_ip: IpAddr,
    last_seen: u64,
}

/// Hard cap on the registered-verifier map (>> any real validator set; bounds memory).
const MAX_PEER_MLDSA_KEYS: usize = 4096;
/// Max distinct verifier keys accepted from one source IP — the primary DoS/Sybil bound:
/// one host cannot fill the map or masquerade as many verifiers.
const MAX_MLDSA_KEYS_PER_IP: usize = 2;
/// Cap on the in-memory header-verification cache. height>0 headers already require a valid
/// prev-hash link (bounded), but height-0 headers insert unconditionally, so an attacker
/// spamming random height-0 headers could grow this without limit (remote OOM). Bounded with
/// oldest-first eviction; 8192 is far above any live reorg/fork-resolution window.
const MAX_VERIFICATIONS: usize = 8192;

#[derive(Debug)]
pub struct HeaderSentinel {
    headers: Arc<RwLock<VecDeque<HeaderState>>>,
    verifications: Arc<DashMap<[u8; 32], VerificationState>>,
    peer_mldsa_keys: Arc<DashMap<String, RegisteredKey>>,
    sync_state: Arc<RwLock<NetworkSyncState>>,
    consensus_threshold: f64,
    max_headers: usize,
    #[allow(dead_code)]
    sentinel: Option<Arc<RwLock<NodeSentinel>>>,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    #[allow(dead_code)]
    node_sentinel: Option<Arc<RwLock<NodeSentinel>>>,
    header_rules_version: u32,
}

impl HeaderSentinel {
    const LOCAL_VERIFIER_ID: &'static str = "__local__";

    fn strict_header_signatures() -> bool {
        true
    }

    fn is_header_rules_v2_active(&self) -> bool {
        self.header_rules_version >= 2
    }

    fn max_future_skew_seconds(&self) -> u64 {
        HEADER_MAX_FUTURE_SECONDS
    }

    fn signature_required(&self) -> bool {
        if self.is_header_rules_v2_active() {
            true
        } else {
            Self::strict_header_signatures()
        }
    }

    fn external_verifier_count(verifiers: &HashSet<String>) -> usize {
        verifiers
            .iter()
            .filter(|id| id.as_str() != Self::LOCAL_VERIFIER_ID)
            .count()
    }

    fn verify_signature_with_registered_node_key(
        &self,
        payload: &[u8],
        node_id: &str,
        signature: &[u8],
    ) -> Result<bool, String> {
        if signature.is_empty() {
            return Ok(false);
        }
        // get_mut so we can refresh last_seen: a verifier actively participating in header
        // consensus must not be LRU-evicted from the bounded key map.
        let public_key_bytes = {
            let mut entry = self
                .peer_mldsa_keys
                .get_mut(node_id)
                .ok_or_else(|| format!("No ML-DSA key registered for node {}", node_id))?;
            entry.last_seen = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            entry.mldsa_public_key.clone()
        };
        Ok(mldsa::verify(payload, signature, &public_key_bytes).is_ok())
    }

    pub fn local_mldsa_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub fn register_peer_mldsa_key(
        &self,
        node_id: &str,
        mldsa_public_key: Vec<u8>,
        ed25519_signature: Vec<u8>,
        source_ip: IpAddr,
    ) -> Result<(), String> {
        if node_id.trim().is_empty() {
            return Err("Node ID is empty".to_string());
        }
        if ed25519_signature.is_empty() {
            return Err("Missing Ed25519 attestation signature".to_string());
        }

        let ed_pub = hex::decode(node_id)
            .map_err(|e| format!("Node ID must be Ed25519 public key hex: {}", e))?;
        if ed_pub.len() != 32 {
            return Err("Invalid Ed25519 public key length in node_id".to_string());
        }

        mldsa::validate_public_key(&mldsa_public_key)?;

        let payload = build_mldsa_binding_payload(node_id, &mldsa_public_key);
        let verifier = UnparsedPublicKey::new(&ED25519, &ed_pub);
        verifier
            .verify(&payload, &ed25519_signature)
            .map_err(|_| "Invalid Ed25519 attestation signature".to_string())?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Existing node_id: accept a key rotation, always refresh last_seen + source_ip.
        if let Some(mut existing) = self.peer_mldsa_keys.get_mut(node_id) {
            if existing.mldsa_public_key.as_slice() != mldsa_public_key.as_slice() {
                warn!(
                    "ML-DSA key rotated for node {} (updating attested key binding)",
                    node_id
                );
                existing.mldsa_public_key = mldsa_public_key;
            }
            existing.last_seen = now;
            existing.source_ip = source_ip;
            return Ok(());
        }

        // NEW node_id. Primary bound: at most MAX_MLDSA_KEYS_PER_IP distinct keys per source
        // IP, so one host can't fill the map or masquerade as many verifiers.
        let per_ip = self
            .peer_mldsa_keys
            .iter()
            .filter(|e| e.value().source_ip == source_ip)
            .count();
        if per_ip >= MAX_MLDSA_KEYS_PER_IP {
            return Err(format!("Too many ML-DSA registrations from {}", source_ip));
        }
        // Backstop: if the map is genuinely full (only reachable with many diverse IPs given
        // the per-IP cap), evict the least-recently-seen entry to make room. Active verifiers
        // refresh last_seen on every signature check, so honest participants are not evicted.
        if self.peer_mldsa_keys.len() >= MAX_PEER_MLDSA_KEYS {
            if let Some(oldest) = self
                .peer_mldsa_keys
                .iter()
                .min_by_key(|e| e.value().last_seen)
                .map(|e| e.key().clone())
            {
                self.peer_mldsa_keys.remove(&oldest);
            }
        }
        self.peer_mldsa_keys.insert(
            node_id.to_string(),
            RegisteredKey {
                mldsa_public_key,
                source_ip,
                last_seen: now,
            },
        );
        Ok(())
    }

    /// Number of DISTINCT source IPs among registered verifier keys — the anti-Sybil
    /// consensus denominator. A host registering many self-signed node_ids counts once, so it
    /// cannot inflate the verifier set to self-satisfy the header quorum.
    fn registered_verifier_ip_count(&self) -> usize {
        let ips: std::collections::HashSet<IpAddr> = self
            .peer_mldsa_keys
            .iter()
            .map(|e| e.value().source_ip)
            .collect();
        ips.len()
    }

    pub fn new() -> Self {
        let (public_key, secret_key) = mldsa::generate_keypair();
        Self {
            headers: Arc::new(RwLock::new(VecDeque::with_capacity(10000))),
            verifications: Arc::new(DashMap::new()),
            peer_mldsa_keys: Arc::new(DashMap::new()),
            sync_state: Arc::new(RwLock::new(NetworkSyncState {
                participating_nodes: HashSet::new(),
            })),
            consensus_threshold: 0.67,
            max_headers: 10000,
            sentinel: None,
            public_key,
            secret_key,
            node_sentinel: None,
            header_rules_version: HEADER_RULES_VERSION,
        }
    }

    #[allow(dead_code)]
    async fn get_sentinel(&self) -> Result<tokio::sync::RwLockReadGuard<'_, NodeSentinel>, String> {
        match &self.sentinel {
            Some(sentinel) => Ok(sentinel.read().await),
            None => Err("Sentinel not initialized".to_string()),
        }
    }

    pub fn spawn_add_verified_header(sentinel: Arc<HeaderSentinel>, header_info: BlockHeaderInfo) {
        tokio::spawn(async move {
            if let Err(e) = sentinel.add_verified_header(header_info).await {
                warn!("Failed to add verified header: {}", e);
            }
        });
    }

    pub async fn verify_header(&self, header: &BlockHeaderInfo) -> bool {
        if let Some(last_header) = self.headers.read().await.back() {
            // Verify hash chain
            if header.prev_hash != last_header.header.hash {
                return false;
            }

            // Verify temporal ordering
            if header.timestamp <= last_header.header.timestamp {
                return false;
            }

            true
        } else {
            // First header is always valid
            true
        }
    }

    pub async fn verify_headers_batch(
        &self,
        headers: Vec<BlockHeaderInfo>,
        node_id: &str,
        signature: Vec<u8>,
    ) -> Result<usize, String> {
        let mut valid_count = 0;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let headers_payload = codec::serialize(&headers)
            .map_err(|e| format!("Headers serialization error: {}", e))?;
        let signature_valid =
            self.verify_signature_with_registered_node_key(&headers_payload, node_id, &signature)?;
        let batch_requires_signature = self.signature_required();
        if !signature_valid && batch_requires_signature {
            return Err("Header batch signature verification failed".to_string());
        }
        // Index stored headers by hash once (hash -> height, timestamp) instead of a linear scan
        // per incoming header: the incoming batch is attacker-influenced, so the old
        // O(incoming x stored) find made a large header batch quadratic.
        let existing_headers: std::collections::HashMap<[u8; 32], (u32, u64)> = {
            self.headers
                .read()
                .await
                .iter()
                .map(|h| (h.header.hash, (h.header.height, h.header.timestamp)))
                .collect()
        };

        // Process up to 200 headers at a time
        for chunk in headers.chunks(200) {
            let mut verified_headers = Vec::with_capacity(chunk.len());

            // Verify headers in chunk
            for header in chunk {
                let strict_v2 = self.is_header_rules_v2_active();
                // Skip duplicates
                if self.verifications.contains_key(&header.hash) {
                    continue;
                }

                // Do quick temporal verification
                if header.timestamp > now + self.max_future_skew_seconds() {
                    continue;
                }

                // Check previous hash links
                if header.height > 0 {
                    let prev_in_chunk = verified_headers
                        .iter()
                        .find(|h: &&BlockHeaderInfo| h.hash == header.prev_hash)
                        .map(|h| (h.height, h.timestamp));
                    let prev_in_store = existing_headers.get(&header.prev_hash).copied();
                    let Some((prev_height, prev_timestamp)) = prev_in_chunk.or(prev_in_store)
                    else {
                        continue;
                    };

                    if strict_v2 && header.height != prev_height.saturating_add(1) {
                        continue;
                    }
                    if strict_v2 && header.timestamp <= prev_timestamp {
                        continue;
                    }
                }

                verified_headers.push(header.clone());
            }

            // Batch add verified headers
            if !verified_headers.is_empty() {
                let mut header_states = self.headers.write().await;

                for header in verified_headers {
                    // Bound the verification cache on the HeaderSync path too, so a peer
                    // streaming long header chains can't grow it without bound.
                    self.evict_oldest_verification_if_full(&header.hash);

                    let mut verification =
                        self.verifications.entry(header.hash).or_insert_with(|| {
                            VerificationState {
                                timestamp: now,
                                verifiers: HashSet::with_capacity(10),
                                mldsa_signatures: HashMap::with_capacity(10),
                            }
                        });

                    // Add verification
                    if verification.verifiers.insert(node_id.to_string()) {
                        valid_count += 1;
                    }
                    if signature_valid {
                        verification
                            .mldsa_signatures
                            .insert(node_id.to_string(), signature.clone());
                    }

                    header_states.push_back(HeaderState {
                        header,
                        timestamp: now,
                        verification_count: verification.verifiers.len() as u32,
                        verified_by: verification.verifiers.clone(),
                    });

                    // Keep fixed size
                    if header_states.len() > 1000 {
                        header_states.pop_front();
                    }
                }
            }
        }

        Ok(valid_count)
    }

    #[allow(dead_code)]
    async fn get_node_sentinel(
        &self,
    ) -> Result<tokio::sync::RwLockReadGuard<'_, NodeSentinel>, String> {
        match &self.node_sentinel {
            Some(sentinel) => Ok(sentinel.read().await),
            None => Err("Node sentinel not initialized".to_string()),
        }
    }

    pub async fn is_header_verified(&self, hash: &[u8; 32]) -> bool {
        let verifications = self.verifications.get(hash);
        let Some(v) = verifications else {
            return false;
        };

        let participating = self.sync_state.read().await.participating_nodes.len();
        let registered = self.registered_verifier_ip_count();
        let eligible = participating.max(registered).max(1);
        let required = self.required_verifier_count(eligible);
        let actual = Self::external_verifier_count(&v.verifiers);

        actual >= required
    }

    pub async fn eligible_verifier_count(&self) -> usize {
        let participating = self.sync_state.read().await.participating_nodes.len();
        let registered = self.registered_verifier_ip_count();
        participating.max(registered).max(1)
    }

    pub async fn should_enforce_consensus_for_headers(&self) -> bool {
        // Only enforce quorum checks when there is enough validator context to avoid
        // breaking bootstrap/single-node operation.
        let eligible = self.eligible_verifier_count().await;
        eligible >= 3
    }

    pub async fn should_enforce_consensus_for_block(&self, height: u32) -> bool {
        let _ = height;
        if self.is_header_rules_v2_active() {
            true
        } else {
            self.should_enforce_consensus_for_headers().await
        }
    }

    pub fn should_require_verified_header_record_for_block(&self, height: u32) -> bool {
        let _ = height;
        self.is_header_rules_v2_active()
    }

    pub fn has_verification_record(&self, hash: &[u8; 32]) -> bool {
        self.verifications.contains_key(hash)
    }

    pub async fn has_conflicting_verified_header(
        &self,
        height: u32,
        expected_hash: &[u8; 32],
    ) -> bool {
        let candidates: Vec<[u8; 32]> = {
            let headers = self.headers.read().await;
            headers
                .iter()
                .filter(|state| {
                    state.header.height == height && state.header.hash != *expected_hash
                })
                .map(|state| state.header.hash)
                .collect()
        };

        for hash in candidates {
            if self.is_header_verified(&hash).await {
                return true;
            }
        }
        false
    }

    fn required_verifier_count(&self, eligible: usize) -> usize {
        let eligible = eligible.max(1);
        // Ratio-based threshold with deterministic integer ceiling.
        let threshold_ppm = (self.consensus_threshold * 1_000_000.0)
            .round()
            .clamp(0.0, 1_000_000.0) as u128;
        let required = ((eligible as u128)
            .saturating_mul(threshold_ppm)
            .saturating_add(999_999))
            / 1_000_000;
        (required as usize).clamp(1, eligible)
    }

    async fn manage_header_cache(&self) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Header-cache cleanup under the `headers` lock ONLY, in its own scope so the
        // guard is RELEASED before we touch `sync_state` below. Holding `headers`
        // across `sync_state.write()` (as this used to) is the inverse of the order
        // `add_verified_header` uses (sync_state -> headers): an ABBA deadlock that,
        // once the cache filled (max_headers), could permanently wedge the header
        // subsystem when two per-block tasks interleaved (2026-07-09 audit H2). These
        // two cleanups are independent, so releasing early is behavior-preserving.
        {
            let mut headers = self.headers.write().await;
            // Remove old headers (older than 24 hours)
            headers.retain(|state| now - state.timestamp < 24 * 3600);
            // If still too many headers, keep only the most recent ones
            if headers.len() > self.max_headers {
                let excess = headers.len() - self.max_headers;
                for _ in 0..excess {
                    headers.pop_front();
                }
            }
        }

        // Clean up verifications (DashMap — no lock needed)
        self.verifications
            .retain(|_, v| now - v.timestamp < 24 * 3600);

        // Update sync state — acquired AFTER the `headers` guard above is dropped.
        let mut sync_state = self.sync_state.write().await;
        sync_state.participating_nodes.retain(|node| {
            self.verifications
                .iter()
                .any(|v| v.verifiers.contains(node))
        });

        Ok(())
    }

    /// Evict the oldest verification entry when the cache is at MAX_VERIFICATIONS and
    /// `hash` is not already present, so no header path can grow `verifications`
    /// without bound — height-0 spam (verify_and_add_header), long HeaderSync chains
    /// (verify_headers_batch), or fresh-hash announces (add_verified_header).
    /// manage_header_cache only age-prunes (24h), so a count cap is still required.
    fn evict_oldest_verification_if_full(&self, hash: &[u8; 32]) {
        if !self.verifications.contains_key(hash)
            && self.verifications.len() >= MAX_VERIFICATIONS
        {
            if let Some(oldest) = self
                .verifications
                .iter()
                .min_by_key(|e| e.value().timestamp)
                .map(|e| e.key().clone())
            {
                self.verifications.remove(&oldest);
            }
        }
    }

    pub async fn add_verified_header(&self, header: BlockHeaderInfo) -> Result<(), String> {
        // Quick add to headers
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let local_verifier = Self::LOCAL_VERIFIER_ID.to_string();

        let mut headers = self.headers.write().await;
        if headers.len() >= self.max_headers {
            drop(headers);
            self.manage_header_cache().await?;
            headers = self.headers.write().await;
        }

        let mut verified_by = HashSet::new();
        verified_by.insert(local_verifier.clone());
        headers.push_back(HeaderState {
            header: header.clone(),
            timestamp: now,
            verification_count: 1,
            verified_by,
        });
        drop(headers);

        // Get sync state and record verification
        let sync_state = self.sync_state.read().await;
        // Bound the verification cache before inserting a new hash — this announce
        // path adds one entry per unique header and manage_header_cache only
        // age-prunes, so an attacker announcing many fresh hashes within 24h would
        // otherwise grow it without bound.
        self.evict_oldest_verification_if_full(&header.hash);
        {
            let mut state =
                self.verifications
                    .entry(header.hash)
                    .or_insert_with(|| VerificationState {
                        timestamp: now,
                        verifiers: HashSet::new(),
                        mldsa_signatures: HashMap::new(),
                    });
            state.verifiers.insert(local_verifier);
        }
        for node_id in &sync_state.participating_nodes {
            // Update verification state
            let _ = self
                .verifications
                .entry(header.hash)
                .or_insert_with(|| VerificationState {
                    timestamp: now,
                    verifiers: HashSet::new(),
                    mldsa_signatures: HashMap::new(),
                })
                .verifiers
                .insert(node_id.clone());
        }
        // Release the sync_state read guard BEFORE acquiring headers.write() below.
        // Holding a sync_state guard across headers.write() is the second half of the
        // ABBA with manage_header_cache (headers -> sync_state); sync_state is not read
        // past this point, so dropping it here keeps the two locks strictly ordered
        // (2026-07-09 audit H2).
        drop(sync_state);

        let (verification_count, verified_by) = self
            .verifications
            .get(&header.hash)
            .map(|state| {
                (
                    Self::external_verifier_count(&state.verifiers) as u32,
                    state.verifiers.clone(),
                )
            })
            .unwrap_or((0, HashSet::new()));

        let mut headers = self.headers.write().await;
        if let Some(last) = headers.back_mut() {
            if last.header.hash == header.hash {
                last.verification_count = verification_count;
                last.verified_by = verified_by;
            }
        }

        Ok(())
    }

    pub async fn verify_and_add_header(
        &self,
        header: BlockHeaderInfo,
        node_id: &str,
        signature: Vec<u8>,
    ) -> Result<bool, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let header_payload =
            codec::serialize(&header).map_err(|e| format!("Serialization error: {}", e))?;
        let signature_valid =
            self.verify_signature_with_registered_node_key(&header_payload, node_id, &signature)?;
        if !signature_valid && self.signature_required() {
            return Err("Header signature verification failed".to_string());
        }
        if header.timestamp > now + self.max_future_skew_seconds() {
            return Err("Header timestamp too far in the future".to_string());
        }
        if header.height > 0 {
            let prev = self
                .headers
                .read()
                .await
                .iter()
                .rev()
                .find(|h| h.header.hash == header.prev_hash)
                .map(|h| h.header.clone())
                .ok_or_else(|| "Header previous hash not found".to_string())?;
            if self.is_header_rules_v2_active() && header.height != prev.height.saturating_add(1) {
                return Err("Header height continuity check failed".to_string());
            }
            if self.is_header_rules_v2_active() && header.timestamp <= prev.timestamp {
                return Err("Header timestamp continuity check failed".to_string());
            }
        }

        // Bound the verification cache before inserting a NEW hash, so height-0 spam
        // (random hashes, no prev-link check) can't OOM us.
        self.evict_oldest_verification_if_full(&header.hash);

        // Quick lookup in recent verifications using DashMap
        let mut verification =
            self.verifications
                .entry(header.hash)
                .or_insert_with(|| VerificationState {
                    timestamp: now,
                    verifiers: HashSet::with_capacity(10),
                    mldsa_signatures: HashMap::with_capacity(10),
                });

        // Add verification atomically
        verification.verifiers.insert(node_id.to_string());
        if signature_valid {
            verification
                .mldsa_signatures
                .insert(node_id.to_string(), signature);
        }

        // Add to headers queue with fixed size
        let mut headers = self.headers.write().await;
        if headers.len() >= 1000 {
            // Keep only last 1000 headers
            headers.pop_front(); // Remove oldest
        }
        headers.push_back(HeaderState {
            header,
            timestamp: now,
            verification_count: verification.verifiers.len() as u32,
            verified_by: verification.verifiers.clone(),
        });

        Ok(true)
    }

    // Regular cleanup of old verifications
    #[allow(dead_code)]
    async fn prune_old_verifications(&self, now: u64) {
        const MAX_AGE: u64 = 60; // Only keep last minute of verifications

        self.verifications
            .retain(|_, v| now.saturating_sub(v.timestamp) < MAX_AGE);

        let mut headers = self.headers.write().await;
        headers.retain(|state| now.saturating_sub(state.timestamp) < MAX_AGE);
    }

    #[allow(dead_code)]
    async fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, String> {
        Ok(mldsa::verify(data, signature, public_key).is_ok())
    }

    #[allow(dead_code)]
    async fn sign_single_header(&self, header: &BlockHeaderInfo) -> Result<Vec<u8>, String> {
        let header_bytes =
            codec::serialize(header).map_err(|e| format!("Serialization error: {}", e))?;

        mldsa::sign(&header_bytes, &self.secret_key)
    }

    // Add new method for signing multiple headers
    async fn sign_header(&self, headers: &[BlockHeaderInfo]) -> Result<Vec<u8>, String> {
        // Serialize all headers into a single byte array
        let headers_bytes =
            codec::serialize(headers).map_err(|e| format!("Headers serialization error: {}", e))?;

        // Sign the entire batch of headers
        mldsa::sign(&headers_bytes, &self.secret_key)
    }
    pub async fn verify_chain_consistency(&self) -> Result<bool, String> {
        let headers = self.headers.read().await;
        let mut prev_header: Option<&BlockHeaderInfo> = None;

        for state in headers.iter() {
            if let Some(prev) = prev_header {
                if state.header.prev_hash != prev.hash {
                    return Ok(false);
                }
                if state.header.timestamp <= prev.timestamp {
                    return Ok(false);
                }
            }
            prev_header = Some(&state.header);
        }
        Ok(true)
    }

    async fn broadcast_verified_headers(
        &self,
        addr: SocketAddr,
        headers: &[BlockHeaderInfo],
        signature: &[u8],
        node: &Arc<Node>,
    ) -> Result<(), String> {
        node.advertise_mldsa_key(addr)
            .await
            .map_err(|e| e.to_string())?;
        let message = NetworkMessage::HeaderSync {
            headers: headers.to_vec(),
            node_id: node.id().to_string(),
            signature: signature.to_vec(),
        };

        node.send_message(addr, &message)
            .await
            .map_err(|e| e.to_string())
    }
}

impl Default for HeaderSentinel {
    fn default() -> Self {
        Self::new()
    }
}

// Helper types for temporal provenance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerification {
    pub height: u32,
    pub timestamp: u64,
    pub verified_by: String,
    pub verification_time: u64,
    pub result: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalMetric {
    pub timestamp: u64,
    pub metric_type: MetricType,
    pub value: f64,
    pub node: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    BlockTime,
    ResponseTime,
    NetworkLoad,
    ConsensusParticipation,
    ValidationSuccess,
}

impl From<NodeError> for String {
    fn from(error: NodeError) -> Self {
        error.to_string()
    }
}

impl From<BlockchainError> for String {
    fn from(error: BlockchainError) -> Self {
        error.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    // A registered key from a DISTINCT source IP (octet), so N such entries count as N
    // distinct eligible verifiers under the anti-Sybil distinct-IP quorum count.
    fn reg_key(pk: u8, ip_octet: u8) -> RegisteredKey {
        RegisteredKey {
            mldsa_public_key: vec![pk; 32],
            source_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, ip_octet)),
            last_seen: 0,
        }
    }

    #[test]
    fn verifier_threshold_is_ratio_based_for_small_sets() {
        let sentinel = HeaderSentinel::new();
        // Default threshold is 0.67, so 3 eligible validators require 3 confirmations (ceil(2.01)).
        assert_eq!(sentinel.required_verifier_count(3), 3);
        // 4 eligible validators require 3 confirmations (ceil(2.68)).
        assert_eq!(sentinel.required_verifier_count(4), 3);
    }

    #[test]
    fn verifier_threshold_is_clamped_to_valid_range() {
        let sentinel = HeaderSentinel::new();
        let required = sentinel.required_verifier_count(10);
        assert!(required >= 1);
        assert!(required <= 10);
    }

    #[tokio::test]
    async fn header_quorum_enforcement_is_disabled_for_small_networks() {
        let sentinel = HeaderSentinel::new();
        assert!(!sentinel.should_enforce_consensus_for_headers().await);
    }

    #[tokio::test]
    async fn header_quorum_enforcement_is_enabled_with_three_eligible_nodes() {
        let sentinel = HeaderSentinel::new();
        sentinel
            .peer_mldsa_keys
            .insert("n1".to_string(), reg_key(1, 1));
        sentinel
            .peer_mldsa_keys
            .insert("n2".to_string(), reg_key(2, 2));
        sentinel
            .peer_mldsa_keys
            .insert("n3".to_string(), reg_key(3, 3));
        assert!(sentinel.should_enforce_consensus_for_headers().await);
    }

    #[tokio::test]
    async fn conflicting_verified_header_is_detected() {
        let sentinel = HeaderSentinel::new();

        sentinel
            .peer_mldsa_keys
            .insert("n1".to_string(), reg_key(1, 1));
        sentinel
            .peer_mldsa_keys
            .insert("n2".to_string(), reg_key(2, 2));
        sentinel
            .peer_mldsa_keys
            .insert("n3".to_string(), reg_key(3, 3));

        let conflicting_hash = [0xAA; 32];
        let expected_hash = [0xBB; 32];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        sentinel.headers.write().await.push_back(HeaderState {
            header: BlockHeaderInfo {
                height: 10,
                hash: conflicting_hash,
                prev_hash: [0x10; 32],
                timestamp: now,
            },
            timestamp: now,
            verification_count: 3,
            verified_by: HashSet::new(),
        });

        sentinel.verifications.insert(
            conflicting_hash,
            VerificationState {
                timestamp: now,
                verifiers: ["n1".to_string(), "n2".to_string(), "n3".to_string()]
                    .into_iter()
                    .collect(),
                mldsa_signatures: HashMap::new(),
            },
        );

        assert!(
            sentinel
                .has_conflicting_verified_header(10, &expected_hash)
                .await
        );
    }

    #[test]
    fn header_rule_v2_is_chain_wide() {
        let sentinel = HeaderSentinel::new();
        assert!(sentinel.is_header_rules_v2_active());
        assert!(sentinel.should_require_verified_header_record_for_block(1));
        assert!(sentinel.should_require_verified_header_record_for_block(1_000_000));
    }

    #[test]
    fn header_rule_v2_uses_fixed_future_skew() {
        let sentinel = HeaderSentinel::new();
        assert_eq!(
            sentinel.max_future_skew_seconds(),
            HEADER_MAX_FUTURE_SECONDS
        );
    }
}
