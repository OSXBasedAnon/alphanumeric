use blake3::Hasher;
use dashmap::DashMap;
use log::error;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};

const DISTRIBUTION_INTERVAL: u64 = 3600; // 1 hour
const MIN_DISTRIBUTION_AMOUNT: f64 = 0.000001;
const MAX_BATCH_SIZE: usize = 1000;
const METRICS_SHARDS: usize = 64;

#[derive(Error, Debug)]
pub enum FeePoolError {
    #[error("Distribution error: {0}")]
    Distribution(String),
    #[error("State error: {0}")]
    State(String),
    #[error("Security error: {0}")]
    Security(String),
}

type Result<T> = std::result::Result<T, FeePoolError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub successful_validations: u64,
    pub anomaly_detections: u64,
    pub fork_resolutions: u64,
    pub header_validations: u64,
    pub chain_verifications: u64,
    pub last_active: u64,
    pub exponential_score: f64,
    pub cumulative_rewards: f64,
    pub last_reward: u64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            successful_validations: 0,
            anomaly_detections: 0,
            fork_resolutions: 0,
            header_validations: 0,
            chain_verifications: 0,
            last_active: 0,
            exponential_score: 0.0,
            cumulative_rewards: 0.0,
            last_reward: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PoolState {
    balance: f64,
    last_distribution: u64,
    distribution_count: u64,
    total_distributed: f64,
    state_hash: [u8; 32],
}

impl PoolState {
    fn new() -> Self {
        Self {
            balance: 0.0,
            last_distribution: 0,
            distribution_count: 0,
            total_distributed: 0.0,
            state_hash: [0; 32],
        }
    }

    fn update_hash(&mut self) {
        let mut hasher = Hasher::new();
        hasher.update(&self.balance.to_le_bytes());
        hasher.update(&self.last_distribution.to_le_bytes());
        hasher.update(&self.distribution_count.to_le_bytes());
        hasher.update(&self.total_distributed.to_le_bytes());
        self.state_hash = *hasher.finalize().as_bytes();
    }
}

struct ShardedMetrics {
    shards: Vec<Arc<DashMap<String, PerformanceMetrics>>>,
}

impl ShardedMetrics {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(METRICS_SHARDS);
        for _ in 0..METRICS_SHARDS {
            shards.push(Arc::new(DashMap::new()));
        }
        Self { shards }
    }

    fn get_shard(&self, key: &str) -> usize {
        let mut hasher = Hasher::new();
        hasher.update(key.as_bytes());
        let hash = hasher.finalize();
        (hash.as_bytes()[0] as usize) % METRICS_SHARDS
    }

    fn get(&self, key: &str) -> Option<dashmap::mapref::one::Ref<'_, String, PerformanceMetrics>> {
        let shard = self.get_shard(key);
        self.shards[shard].get(key)
    }

    fn insert(&self, key: String, value: PerformanceMetrics) {
        let shard = self.get_shard(&key);
        self.shards[shard].insert(key, value);
    }
}

#[derive(Clone)]
pub struct FeePool {
    metrics: Arc<ShardedMetrics>,
    state: Arc<RwLock<PoolState>>,
    event_sender: mpsc::UnboundedSender<PoolEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PoolEvent {
    FeeReceived {
        amount: f64,
        timestamp: u64,
    },
    Distribution {
        recipient: String,
        amount: f64,
        timestamp: u64,
    },
    MetricsUpdated {
        address: String,
        timestamp: u64,
    },
}

impl FeePool {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<PoolEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();

        let pool = Self {
            metrics: Arc::new(ShardedMetrics::new()),
            state: Arc::new(RwLock::new(PoolState::new())),
            event_sender: tx,
        };

        pool.clone().start_background_tasks();

        (pool, rx)
    }

    fn start_background_tasks(&self) {
        let pool = self.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(DISTRIBUTION_INTERVAL));
            loop {
                interval.tick().await;
                if let Err(e) = pool.try_distribute().await {
                    error!("Distribution error: {}", e);
                }
            }
        });
    }

    pub async fn add_fee(&self, amount: f64) -> Result<()> {
        if amount <= 0.0 {
            return Err(FeePoolError::Distribution("Invalid amount".into()));
        }

        let mut state = self.state.write().await;
        state.balance += amount;
        state.update_hash();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let _ = self
            .event_sender
            .send(PoolEvent::FeeReceived { amount, timestamp });

        Ok(())
    }

    pub async fn record_action(
        &self,
        address: &str,
        action_type: ActionType,
        success: bool,
    ) -> Result<()> {
        if !success {
            return Ok(());
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metrics = self
            .metrics
            .get(address)
            .map(|m| m.clone())
            .unwrap_or_default();

        let mut updated = metrics.clone();
        match action_type {
            ActionType::BlockValidation => {
                updated.successful_validations += 1;
            }
            ActionType::AnomalyDetection => {
                updated.anomaly_detections += 1;
            }
            ActionType::ForkResolution => {
                updated.fork_resolutions += 1;
            }
            ActionType::HeaderValidation => {
                updated.header_validations += 1;
            }
            ActionType::ChainVerification => {
                updated.chain_verifications += 1;
            }
        }

        updated.last_active = timestamp;
        updated.exponential_score = self.calculate_score(&updated);

        self.metrics.insert(address.to_string(), updated);

        let _ = self.event_sender.send(PoolEvent::MetricsUpdated {
            address: address.to_string(),
            timestamp,
        });

        Ok(())
    }

    fn calculate_score(&self, metrics: &PerformanceMetrics) -> f64 {
        const VALIDATION_WEIGHT: f64 = 1.0;
        const ANOMALY_WEIGHT: f64 = 2.0;
        const FORK_WEIGHT: f64 = 3.0;
        const HEADER_WEIGHT: f64 = 1.0;
        const CHAIN_WEIGHT: f64 = 2.0;

        let base_score = (metrics.successful_validations as f64 * VALIDATION_WEIGHT)
            + (metrics.anomaly_detections as f64 * ANOMALY_WEIGHT)
            + (metrics.fork_resolutions as f64 * FORK_WEIGHT)
            + (metrics.header_validations as f64 * HEADER_WEIGHT)
            + (metrics.chain_verifications as f64 * CHAIN_WEIGHT);

        // Apply exponential moving average
        let alpha = 0.1;
        (alpha * base_score) + ((1.0 - alpha) * metrics.exponential_score)
    }

    async fn try_distribute(&self) -> Result<()> {
        let mut state = self.state.write().await;
        if state.balance < MIN_DISTRIBUTION_AMOUNT {
            return Ok(());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now - state.last_distribution < DISTRIBUTION_INTERVAL {
            return Ok(());
        }

        let total_balance = state.balance;
        let distributions = self.calculate_distributions(total_balance)?;

        // Process distributions in batches
        for batch in distributions.chunks(MAX_BATCH_SIZE) {
            self.process_distribution_batch(batch, &mut *state).await?;
        }

        state.last_distribution = now;
        state.update_hash();

        Ok(())
    }

    fn calculate_distributions(&self, total_balance: f64) -> Result<Vec<(String, f64)>> {
        let mut scores = BTreeMap::new();
        let mut total_score = 0.0;

        // Calculate scores and total
        for shard in &self.metrics.shards {
            for entry in shard.iter() {
                if entry.exponential_score > 0.0 {
                    scores.insert(entry.key().clone(), entry.exponential_score);
                    total_score += entry.exponential_score;
                }
            }
        }

        if total_score == 0.0 {
            return Ok(vec![]);
        }

        // Calculate distributions
        let mut distributions = Vec::new();
        for (address, score) in scores {
            let amount = (score / total_score) * total_balance;
            if amount >= MIN_DISTRIBUTION_AMOUNT {
                distributions.push((address, amount));
            }
        }

        Ok(distributions)
    }

    async fn process_distribution_batch(
        &self,
        distributions: &[(String, f64)],
        state: &mut PoolState,
    ) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (address, amount) in distributions {
            // Update metrics
            if let Some(metrics) = self.metrics.get(address) {
                let mut updated = metrics.clone();
                updated.cumulative_rewards += amount;
                updated.last_reward = timestamp;
                self.metrics.insert(address.clone(), updated);
            }

            // Update state
            state.balance -= amount;
            state.total_distributed += amount;
            state.distribution_count += 1;

            // Emit event
            let _ = self.event_sender.send(PoolEvent::Distribution {
                recipient: address.clone(),
                amount: *amount,
                timestamp,
            });
        }

        Ok(())
    }

    // Public API
    pub async fn get_balance(&self) -> f64 {
        self.state.read().await.balance
    }

    pub async fn get_metrics(&self, address: &str) -> Option<PerformanceMetrics> {
        self.metrics.get(address).map(|m| m.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionType {
    BlockValidation,
    AnomalyDetection,
    ForkResolution,
    HeaderValidation,
    ChainVerification,
}

// Easy integration trait
#[async_trait::async_trait]
pub trait FeePoolIntegration {
    async fn create_distribution_transaction(&self, recipient: &str, amount: f64) -> Result<()>;
}
