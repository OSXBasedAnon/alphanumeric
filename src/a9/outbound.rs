//! Bounded, class-aware admission for authenticated TCP egress.
//!
//! This module deliberately does not own sockets or spawn worker tasks. Callers keep the
//! existing request/response and retry semantics, while every encoded frame is admitted before
//! it can wait for the shared per-peer connection. The design gives us three properties that a
//! plain connection mutex cannot provide:
//!
//! * queued allocations are bounded globally, by traffic class, and per peer;
//! * block/control work cannot sit behind an arbitrary number of transaction/bootstrap waiters;
//! * cancellation releases every byte, message, concurrency, and priority reservation by RAII.
//!
//! No value in this module is serialized or persisted. It is transport policy only.

use parking_lot::Mutex;
use std::{
    array,
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    time::{timeout_at, Instant},
};

const MIB: usize = 1024 * 1024;
const DEFAULT_GLOBAL_QUEUE_MESSAGES: usize = 512;
const DEFAULT_PEER_QUEUE_MESSAGES: usize = 16;
const MAX_PEER_STATES: usize = 4_096;

/// Environment-variable rollback switch. Setting it to `false`, `0`, `no`, or `off` restores
/// the previous direct connection-mutex path without changing the wire or any stored data.
pub const ENABLE_ENV: &str = "ALPHANUMERIC_OUTBOUND_SCHEDULER";
pub const GLOBAL_QUEUE_MIB_ENV: &str = "ALPHANUMERIC_OUTBOUND_GLOBAL_QUEUE_MIB";
pub const PEER_QUEUE_MIB_ENV: &str = "ALPHANUMERIC_OUTBOUND_PEER_QUEUE_MIB";
pub const MAX_QUEUE_AGE_MS_ENV: &str = "ALPHANUMERIC_OUTBOUND_MAX_QUEUE_AGE_MS";
pub const TX_RATE_MIB_ENV: &str = "ALPHANUMERIC_OUTBOUND_TX_MIB_PER_SEC";
pub const TX_WORK_RATE_ENV: &str = "ALPHANUMERIC_OUTBOUND_TX_WORK_PER_SEC";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(usize)]
pub enum TrafficClass {
    Block = 0,
    Control = 1,
    Transaction = 2,
    Bootstrap = 3,
    Registration = 4,
}

impl TrafficClass {
    pub const ALL: [Self; 5] = [
        Self::Block,
        Self::Control,
        Self::Transaction,
        Self::Bootstrap,
        Self::Registration,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Control => "control",
            Self::Transaction => "transaction",
            Self::Bootstrap => "bootstrap",
            Self::Registration => "registration",
        }
    }

    const fn priority(self) -> u8 {
        match self {
            // A block waiting on the authenticated channel affects stale rate, so it is the only
            // absolute top priority. Control remains ahead of all bulk/application traffic.
            Self::Block => 0,
            Self::Control => 1,
            Self::Registration => 2,
            Self::Transaction => 3,
            Self::Bootstrap => 4,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MessageCost {
    pub class: TrafficClass,
    /// Exact encrypted frame bytes, excluding the four-byte TCP length prefix.
    pub bytes: usize,
    /// Class-specific work units (transactions, blocks, headers, shreds, or one control action).
    pub work: usize,
}

#[derive(Clone, Debug)]
struct ClassConfig {
    queue_bytes: usize,
    peer_queue_bytes: usize,
    queue_messages: usize,
    peer_queue_messages: usize,
    max_in_flight: usize,
    max_queue_age: Duration,
    peer_byte_rate: f64,
    peer_byte_burst: f64,
    peer_work_rate: f64,
    peer_work_burst: f64,
}

#[derive(Clone, Debug)]
pub struct SchedulerConfig {
    enabled: bool,
    global_queue_bytes: usize,
    peer_queue_bytes: usize,
    global_queue_messages: usize,
    peer_queue_messages: usize,
    peer_state_limit: usize,
    classes: [ClassConfig; 5],
}

impl SchedulerConfig {
    pub fn from_env(max_peers: usize) -> Self {
        let enabled = bool_env_or(ENABLE_ENV, true);
        let global_mib = bounded_usize_env_or(GLOBAL_QUEUE_MIB_ENV, 32, 512, 64);
        let peer_mib = bounded_usize_env_or(PEER_QUEUE_MIB_ENV, 16, 64, 16);
        let max_queue_age_ms = bounded_usize_env_or(MAX_QUEUE_AGE_MS_ENV, 1_000, 60_000, 10_000);
        let tx_rate_mib = bounded_usize_env_or(TX_RATE_MIB_ENV, 1, 256, 16);
        let tx_work_rate = bounded_usize_env_or(TX_WORK_RATE_ENV, 256, 65_536, 4_096);

        Self::new(
            enabled,
            global_mib * MIB,
            peer_mib * MIB,
            Duration::from_millis(max_queue_age_ms as u64),
            tx_rate_mib * MIB,
            tx_work_rate,
            max_peers,
        )
    }

    fn new(
        enabled: bool,
        global_queue_bytes: usize,
        peer_queue_bytes: usize,
        max_queue_age: Duration,
        tx_rate_bytes: usize,
        tx_work_rate: usize,
        max_peers: usize,
    ) -> Self {
        let global_queue_bytes = global_queue_bytes.max(32 * MIB);
        let peer_queue_bytes = peer_queue_bytes.max(16 * MIB);
        let half_age = (max_queue_age / 2).max(Duration::from_secs(1));

        // Lower-priority class byte ceilings sum to less than the global ceiling. At the 64 MiB
        // default, fully saturated transaction/bootstrap/registration classes still leave 14 MiB:
        // enough for all ten concurrent sends of a full 1 MiB producer block. Per-peer class
        // ceilings follow the same rule, so one slow peer cannot fill its reservation entirely
        // with transactions.
        let class_bytes = [
            global_queue_bytes,
            (global_queue_bytes / 16).max(4 * MIB),
            (global_queue_bytes / 2).max(4 * MIB),
            (global_queue_bytes / 4).max(4 * MIB),
            (global_queue_bytes / 32).max(MIB),
        ];
        let peer_class_bytes = [
            (peer_queue_bytes / 2).max(4 * MIB),
            (peer_queue_bytes / 8).max(4 * MIB),
            (peer_queue_bytes / 4).max(4 * MIB),
            (peer_queue_bytes / 4).max(4 * MIB),
            (peer_queue_bytes / 16).max(256 * 1024),
        ];
        let message_caps = [64, 256, 256, 64, 64];
        // Lower-priority classes total ten of sixteen peer slots, reserving six for block/control.
        let peer_message_caps = [4, 4, 6, 3, 1];
        let concurrency = [16, 32, 16, 4, 4];
        let ages = [max_queue_age, half_age, half_age, max_queue_age, half_age];

        // Per-peer token buckets are intentionally generous relative to one saturated 1 MiB / 5.4
        // second chain. They replace message-count throttling (which punished ML-DSA transactions
        // regardless of size) while still bounding a local relay loop or abusive caller. Blocks
        // receive a large burst/rate because valid-PoW production, not this transport policy, is
        // their admission boundary.
        let byte_rates = [64 * MIB, 2 * MIB, tx_rate_bytes, 16 * MIB, MIB];
        let byte_bursts = [
            64 * MIB,
            4 * MIB,
            tx_rate_bytes.saturating_mul(2).max(8 * MIB),
            32 * MIB,
            2 * MIB,
        ];
        let work_rates = [65_536, 1_024, tx_work_rate, 8_192, 128];
        let work_bursts = [
            65_536,
            2_048,
            tx_work_rate.saturating_mul(2).max(512),
            16_384,
            256,
        ];

        let classes = array::from_fn(|index| ClassConfig {
            queue_bytes: class_bytes[index].max(1),
            peer_queue_bytes: peer_class_bytes[index].max(1),
            queue_messages: message_caps[index],
            peer_queue_messages: peer_message_caps[index],
            max_in_flight: concurrency[index],
            max_queue_age: ages[index],
            peer_byte_rate: byte_rates[index] as f64,
            peer_byte_burst: byte_bursts[index] as f64,
            peer_work_rate: work_rates[index] as f64,
            peer_work_burst: work_bursts[index] as f64,
        });

        Self {
            enabled,
            global_queue_bytes,
            peer_queue_bytes,
            global_queue_messages: DEFAULT_GLOBAL_QUEUE_MESSAGES,
            peer_queue_messages: DEFAULT_PEER_QUEUE_MESSAGES,
            // Outbound targets normally come from the bounded peer table. The multiplier leaves
            // room for discovery races and in-progress connection attempts while keeping the
            // scheduler map independently finite.
            peer_state_limit: max_peers.saturating_mul(4).clamp(32, MAX_PEER_STATES),
            classes,
        }
    }

    #[cfg(test)]
    fn for_test() -> Self {
        let mut config = Self::new(
            true,
            32 * MIB,
            16 * MIB,
            Duration::from_millis(250),
            64 * MIB,
            65_536,
            8,
        );
        for class in &mut config.classes {
            class.peer_byte_rate = f64::MAX;
            class.peer_byte_burst = f64::MAX;
            class.peer_work_rate = f64::MAX;
            class.peer_work_burst = f64::MAX;
        }
        config
    }
}

fn bool_env_or(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => {
                log::warn!("Ignoring invalid {} value; using default {}", name, default);
                default
            }
        },
        Err(std::env::VarError::NotPresent) => default,
        Err(std::env::VarError::NotUnicode(_)) => {
            log::warn!(
                "Ignoring non-Unicode {} value; using default {}",
                name,
                default
            );
            default
        }
    }
}

fn bounded_usize_env_or(name: &str, min: usize, max: usize, default: usize) -> usize {
    match std::env::var(name) {
        Ok(value) => match value.trim().parse::<usize>() {
            Ok(value) if (min..=max).contains(&value) => value,
            _ => {
                log::warn!(
                    "Ignoring invalid {} value; expected {}..={}, using default {}",
                    name,
                    min,
                    max,
                    default
                );
                default
            }
        },
        Err(std::env::VarError::NotPresent) => default,
        Err(std::env::VarError::NotUnicode(_)) => {
            log::warn!(
                "Ignoring non-Unicode {} value; using default {}",
                name,
                default
            );
            default
        }
    }
}

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("outbound {class} frame is too large for the configured {scope} byte budget ({bytes} bytes)")]
    Oversized {
        class: &'static str,
        scope: &'static str,
        bytes: usize,
    },
    #[error("outbound {class} {scope} queue is full")]
    QueueFull {
        class: &'static str,
        scope: &'static str,
    },
    #[error("outbound {class} byte/work token bucket is exhausted")]
    RateLimited { class: &'static str },
    #[error("outbound {class} work exceeded its {age_ms} ms maximum queue age")]
    QueueExpired { class: &'static str, age_ms: u128 },
    #[error("outbound scheduler is closed")]
    Closed,
    #[error("outbound peer scheduler table is full")]
    PeerTableFull,
}

#[derive(Debug)]
struct TrafficTokenBucket {
    byte_rate_per_second: f64,
    byte_burst: f64,
    work_rate_per_second: f64,
    work_burst: f64,
    state: Mutex<TrafficTokenBucketState>,
}

#[derive(Debug)]
struct TrafficTokenBucketState {
    byte_tokens: f64,
    work_tokens: f64,
    updated_at: Instant,
}

impl TrafficTokenBucket {
    fn new(
        byte_rate_per_second: f64,
        byte_burst: f64,
        work_rate_per_second: f64,
        work_burst: f64,
    ) -> Self {
        Self {
            byte_rate_per_second,
            byte_burst,
            work_rate_per_second,
            work_burst,
            state: Mutex::new(TrafficTokenBucketState {
                byte_tokens: byte_burst,
                work_tokens: work_burst,
                updated_at: Instant::now(),
            }),
        }
    }

    /// Refill, test, and debit byte/work tokens under one lock. A work rejection must not silently
    /// burn byte tokens (or vice versa), otherwise one exhausted dimension makes later legitimate
    /// traffic recover more slowly than its configured bucket specifies.
    fn try_consume(&self, bytes: usize, work: usize) -> bool {
        let bytes = bytes.max(1) as f64;
        let work = work.max(1) as f64;
        if bytes > self.byte_burst || work > self.work_burst {
            return false;
        }
        let now = Instant::now();
        let mut state = self.state.lock();
        let elapsed = now
            .saturating_duration_since(state.updated_at)
            .as_secs_f64();
        state.byte_tokens =
            (state.byte_tokens + elapsed * self.byte_rate_per_second).min(self.byte_burst);
        state.work_tokens =
            (state.work_tokens + elapsed * self.work_rate_per_second).min(self.work_burst);
        state.updated_at = now;
        if state.byte_tokens < bytes || state.work_tokens < work {
            return false;
        }
        state.byte_tokens -= bytes;
        state.work_tokens -= work;
        true
    }
}

#[derive(Debug)]
struct PeerClassBudget {
    bytes: Arc<Semaphore>,
    messages: Arc<Semaphore>,
    tokens: TrafficTokenBucket,
}

#[derive(Debug)]
struct PeerBudget {
    total_bytes: Arc<Semaphore>,
    total_messages: Arc<Semaphore>,
    classes: [PeerClassBudget; 5],
    dispatch: Arc<PriorityDispatch>,
}

impl PeerBudget {
    fn new(config: &SchedulerConfig) -> Self {
        Self {
            total_bytes: Arc::new(Semaphore::new(config.peer_queue_bytes)),
            total_messages: Arc::new(Semaphore::new(config.peer_queue_messages)),
            classes: array::from_fn(|index| {
                let class = &config.classes[index];
                PeerClassBudget {
                    bytes: Arc::new(Semaphore::new(class.peer_queue_bytes)),
                    messages: Arc::new(Semaphore::new(class.peer_queue_messages)),
                    tokens: TrafficTokenBucket::new(
                        class.peer_byte_rate,
                        class.peer_byte_burst,
                        class.peer_work_rate,
                        class.peer_work_burst,
                    ),
                }
            }),
            dispatch: Arc::new(PriorityDispatch::default()),
        }
    }

    fn is_idle(&self, config: &SchedulerConfig) -> bool {
        self.total_bytes.available_permits() == config.peer_queue_bytes
            && self.total_messages.available_permits() == config.peer_queue_messages
            && self.dispatch.is_idle()
    }
}

#[derive(Debug, Default)]
struct PriorityDispatch {
    state: Mutex<PriorityState>,
    changed: Notify,
}

#[derive(Debug, Default)]
struct PriorityState {
    active: bool,
    next_ticket: u64,
    waiters: VecDeque<PriorityWaiter>,
}

#[derive(Clone, Copy, Debug)]
struct PriorityWaiter {
    ticket: u64,
    priority: u8,
}

impl PriorityDispatch {
    fn is_idle(&self) -> bool {
        let state = self.state.lock();
        !state.active && state.waiters.is_empty()
    }

    async fn acquire(
        self: &Arc<Self>,
        class: TrafficClass,
        deadline: Instant,
    ) -> Result<DispatchPermit, AdmissionError> {
        let ticket = {
            let mut state = self.state.lock();
            let mut ticket = state.next_ticket;
            while state.waiters.iter().any(|waiter| waiter.ticket == ticket) {
                ticket = ticket.wrapping_add(1);
            }
            state.next_ticket = ticket.wrapping_add(1);
            state.waiters.push_back(PriorityWaiter {
                ticket,
                priority: class.priority(),
            });
            ticket
        };
        let mut registration = WaiterRegistration {
            dispatch: Arc::clone(self),
            ticket,
            queued: true,
        };

        loop {
            // Enable the notification before checking state. `notify_waiters` intentionally does
            // not retain a permit for a future waiter; enabling first closes the check-to-await
            // race without waking an arbitrary lower-priority waiter via `notify_one`.
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let acquired = {
                let mut state = self.state.lock();
                let selected = state
                    .waiters
                    .iter()
                    .enumerate()
                    .min_by_key(|(position, waiter)| (waiter.priority, *position))
                    .map(|(_, waiter)| waiter.ticket);
                if !state.active && selected == Some(ticket) {
                    state.active = true;
                    if let Some(position) = state
                        .waiters
                        .iter()
                        .position(|waiter| waiter.ticket == ticket)
                    {
                        state.waiters.remove(position);
                    }
                    true
                } else {
                    false
                }
            };
            if acquired {
                registration.queued = false;
                return Ok(DispatchPermit {
                    dispatch: Arc::clone(self),
                });
            }

            if timeout_at(deadline, changed.as_mut()).await.is_err() {
                return Err(AdmissionError::QueueExpired {
                    class: class.as_str(),
                    age_ms: 0,
                });
            }
        }
    }
}

struct WaiterRegistration {
    dispatch: Arc<PriorityDispatch>,
    ticket: u64,
    queued: bool,
}

impl Drop for WaiterRegistration {
    fn drop(&mut self) {
        if !self.queued {
            return;
        }
        let mut state = self.dispatch.state.lock();
        if let Some(position) = state
            .waiters
            .iter()
            .position(|waiter| waiter.ticket == self.ticket)
        {
            state.waiters.remove(position);
        }
        drop(state);
        self.dispatch.changed.notify_waiters();
    }
}

#[derive(Debug)]
pub struct DispatchPermit {
    dispatch: Arc<PriorityDispatch>,
}

impl Drop for DispatchPermit {
    fn drop(&mut self) {
        let mut state = self.dispatch.state.lock();
        debug_assert!(state.active, "dispatch permit released while inactive");
        state.active = false;
        drop(state);
        self.dispatch.changed.notify_waiters();
    }
}

#[derive(Debug, Default)]
struct ClassMetrics {
    admitted_messages: AtomicU64,
    admitted_bytes: AtomicU64,
    admitted_work: AtomicU64,
    completed_messages: AtomicU64,
    failed_messages: AtomicU64,
    cancelled_messages: AtomicU64,
    rejected_oversized: AtomicU64,
    rejected_queue_full: AtomicU64,
    rejected_rate_limited: AtomicU64,
    queue_timeouts: AtomicU64,
    queued_messages: AtomicU64,
    queued_bytes: AtomicU64,
    in_flight_messages: AtomicU64,
    in_flight_bytes: AtomicU64,
    queue_wait_samples: AtomicU64,
    queue_wait_ns_total: AtomicU64,
    queue_wait_ns_max: AtomicU64,
}

#[derive(Debug)]
struct SchedulerMetrics {
    classes: [ClassMetrics; 5],
    peer_table_full: AtomicU64,
}

impl Default for SchedulerMetrics {
    fn default() -> Self {
        Self {
            classes: array::from_fn(|_| ClassMetrics::default()),
            peer_table_full: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ClassMetricsSnapshot {
    pub queue_capacity_bytes: usize,
    pub peer_queue_capacity_bytes: usize,
    pub queue_capacity_messages: usize,
    pub peer_queue_capacity_messages: usize,
    pub max_in_flight: usize,
    pub max_queue_age_ms: u64,
    pub peer_byte_rate_per_second: u64,
    pub peer_work_rate_per_second: u64,
    pub admitted_messages: u64,
    pub admitted_bytes: u64,
    pub admitted_work: u64,
    pub completed_messages: u64,
    pub failed_messages: u64,
    pub cancelled_messages: u64,
    pub rejected_oversized: u64,
    pub rejected_queue_full: u64,
    pub rejected_rate_limited: u64,
    pub queue_timeouts: u64,
    pub queued_messages: u64,
    pub queued_bytes: u64,
    pub in_flight_messages: u64,
    pub in_flight_bytes: u64,
    pub queue_wait_samples: u64,
    pub queue_wait_ns_total: u64,
    pub queue_wait_ns_max: u64,
}

impl ClassMetricsSnapshot {
    pub fn average_queue_wait_ms(self) -> f64 {
        if self.queue_wait_samples == 0 {
            0.0
        } else {
            self.queue_wait_ns_total as f64 / self.queue_wait_samples as f64 / 1_000_000.0
        }
    }

    pub fn maximum_queue_wait_ms(self) -> f64 {
        self.queue_wait_ns_max as f64 / 1_000_000.0
    }
}

#[derive(Clone, Debug)]
pub struct MetricsSnapshot {
    pub enabled: bool,
    pub global_queue_capacity_bytes: usize,
    pub peer_queue_capacity_bytes: usize,
    pub peer_states: usize,
    pub peer_state_capacity: usize,
    pub peer_table_full: u64,
    pub classes: [ClassMetricsSnapshot; 5],
}

#[derive(Debug)]
pub struct OutboundScheduler {
    config: SchedulerConfig,
    global_bytes: Arc<Semaphore>,
    global_messages: Arc<Semaphore>,
    class_bytes: [Arc<Semaphore>; 5],
    class_messages: [Arc<Semaphore>; 5],
    class_in_flight: [Arc<Semaphore>; 5],
    peers: Mutex<HashMap<SocketAddr, Arc<PeerBudget>>>,
    metrics: Arc<SchedulerMetrics>,
}

impl OutboundScheduler {
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            global_bytes: Arc::new(Semaphore::new(config.global_queue_bytes)),
            global_messages: Arc::new(Semaphore::new(config.global_queue_messages)),
            class_bytes: array::from_fn(|index| {
                Arc::new(Semaphore::new(config.classes[index].queue_bytes))
            }),
            class_messages: array::from_fn(|index| {
                Arc::new(Semaphore::new(config.classes[index].queue_messages))
            }),
            class_in_flight: array::from_fn(|index| {
                Arc::new(Semaphore::new(config.classes[index].max_in_flight))
            }),
            config,
            peers: Mutex::new(HashMap::new()),
            metrics: Arc::new(SchedulerMetrics::default()),
        }
    }

    pub fn from_env(max_peers: usize) -> Self {
        Self::new(SchedulerConfig::from_env(max_peers))
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn remove_peer(&self, peer: SocketAddr) {
        let mut peers = self.peers.lock();
        if peers
            .get(&peer)
            .is_some_and(|budget| Arc::strong_count(budget) == 1 && budget.is_idle(&self.config))
        {
            peers.remove(&peer);
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let classes = array::from_fn(|index| {
            let metrics = &self.metrics.classes[index];
            let config = &self.config.classes[index];
            ClassMetricsSnapshot {
                queue_capacity_bytes: config.queue_bytes,
                peer_queue_capacity_bytes: config.peer_queue_bytes,
                queue_capacity_messages: config.queue_messages,
                peer_queue_capacity_messages: config.peer_queue_messages,
                max_in_flight: config.max_in_flight,
                max_queue_age_ms: config.max_queue_age.as_millis() as u64,
                peer_byte_rate_per_second: config.peer_byte_rate as u64,
                peer_work_rate_per_second: config.peer_work_rate as u64,
                admitted_messages: metrics.admitted_messages.load(Ordering::Relaxed),
                admitted_bytes: metrics.admitted_bytes.load(Ordering::Relaxed),
                admitted_work: metrics.admitted_work.load(Ordering::Relaxed),
                completed_messages: metrics.completed_messages.load(Ordering::Relaxed),
                failed_messages: metrics.failed_messages.load(Ordering::Relaxed),
                cancelled_messages: metrics.cancelled_messages.load(Ordering::Relaxed),
                rejected_oversized: metrics.rejected_oversized.load(Ordering::Relaxed),
                rejected_queue_full: metrics.rejected_queue_full.load(Ordering::Relaxed),
                rejected_rate_limited: metrics.rejected_rate_limited.load(Ordering::Relaxed),
                queue_timeouts: metrics.queue_timeouts.load(Ordering::Relaxed),
                queued_messages: metrics.queued_messages.load(Ordering::Relaxed),
                queued_bytes: metrics.queued_bytes.load(Ordering::Relaxed),
                in_flight_messages: metrics.in_flight_messages.load(Ordering::Relaxed),
                in_flight_bytes: metrics.in_flight_bytes.load(Ordering::Relaxed),
                queue_wait_samples: metrics.queue_wait_samples.load(Ordering::Relaxed),
                queue_wait_ns_total: metrics.queue_wait_ns_total.load(Ordering::Relaxed),
                queue_wait_ns_max: metrics.queue_wait_ns_max.load(Ordering::Relaxed),
            }
        });
        MetricsSnapshot {
            enabled: self.config.enabled,
            global_queue_capacity_bytes: self.config.global_queue_bytes,
            peer_queue_capacity_bytes: self.config.peer_queue_bytes,
            peer_states: self.peers.lock().len(),
            peer_state_capacity: self.config.peer_state_limit,
            peer_table_full: self.metrics.peer_table_full.load(Ordering::Relaxed),
            classes,
        }
    }

    pub async fn admit(
        &self,
        peer: SocketAddr,
        cost: MessageCost,
    ) -> Result<Reservation, AdmissionError> {
        if !self.config.enabled {
            return Ok(Reservation::bypass());
        }
        let index = cost.class as usize;
        let class_config = &self.config.classes[index];
        let bytes = cost.bytes.max(1);
        let work = cost.work.max(1);
        let metrics = &self.metrics.classes[index];

        if bytes > self.config.global_queue_bytes {
            metrics.rejected_oversized.fetch_add(1, Ordering::Relaxed);
            return Err(AdmissionError::Oversized {
                class: cost.class.as_str(),
                scope: "global",
                bytes,
            });
        }
        if bytes > class_config.queue_bytes {
            metrics.rejected_oversized.fetch_add(1, Ordering::Relaxed);
            return Err(AdmissionError::Oversized {
                class: cost.class.as_str(),
                scope: "class",
                bytes,
            });
        }
        if bytes > self.config.peer_queue_bytes || bytes > class_config.peer_queue_bytes {
            metrics.rejected_oversized.fetch_add(1, Ordering::Relaxed);
            return Err(AdmissionError::Oversized {
                class: cost.class.as_str(),
                scope: "peer",
                bytes,
            });
        }
        let byte_permits = match u32::try_from(bytes) {
            Ok(permits) => permits,
            Err(_) => {
                metrics.rejected_oversized.fetch_add(1, Ordering::Relaxed);
                return Err(AdmissionError::Oversized {
                    class: cost.class.as_str(),
                    scope: "semaphore",
                    bytes,
                });
            }
        };

        let peer_budget = self.peer_budget(peer)?;
        let peer_class = &peer_budget.classes[index];

        let global_message = try_one(&self.global_messages, cost.class, "global", metrics)?;
        let class_message = try_one(&self.class_messages[index], cost.class, "class", metrics)?;
        let peer_message = try_one(&peer_budget.total_messages, cost.class, "peer", metrics)?;
        let peer_class_message = try_one(&peer_class.messages, cost.class, "peer-class", metrics)?;
        let global_bytes = try_bytes(
            &self.global_bytes,
            byte_permits,
            cost.class,
            "global",
            metrics,
        )?;
        let class_bytes = try_bytes(
            &self.class_bytes[index],
            byte_permits,
            cost.class,
            "class",
            metrics,
        )?;
        let peer_bytes = try_bytes(
            &peer_budget.total_bytes,
            byte_permits,
            cost.class,
            "peer",
            metrics,
        )?;
        let peer_class_bytes = try_bytes(
            &peer_class.bytes,
            byte_permits,
            cost.class,
            "peer-class",
            metrics,
        )?;

        metrics.queued_messages.fetch_add(1, Ordering::Relaxed);
        metrics
            .queued_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        let mut pending = PendingMetrics {
            metrics: Arc::clone(&self.metrics),
            class: cost.class,
            bytes,
            active: true,
        };

        let enqueued_at = Instant::now();
        let deadline = enqueued_at + class_config.max_queue_age;
        let class_slot = match timeout_at(
            deadline,
            self.class_in_flight[index].clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                pending.reject();
                return Err(AdmissionError::Closed);
            }
            Err(_) => {
                metrics.queue_timeouts.fetch_add(1, Ordering::Relaxed);
                pending.reject();
                return Err(AdmissionError::QueueExpired {
                    class: cost.class.as_str(),
                    age_ms: class_config.max_queue_age.as_millis(),
                });
            }
        };

        // Debit tokens only after queue admission succeeds. A class-concurrency timeout must not
        // also delay a later retry by consuming its byte/work allowance.
        if !peer_class.tokens.try_consume(bytes, work) {
            metrics
                .rejected_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            pending.reject();
            return Err(AdmissionError::RateLimited {
                class: cost.class.as_str(),
            });
        }
        metrics.admitted_messages.fetch_add(1, Ordering::Relaxed);
        metrics
            .admitted_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        metrics
            .admitted_work
            .fetch_add(work as u64, Ordering::Relaxed);
        pending.active = false;

        Ok(Reservation {
            metrics: Some(Arc::clone(&self.metrics)),
            peer: Some(peer_budget),
            class: cost.class,
            bytes,
            enqueued_at,
            deadline,
            max_queue_age: class_config.max_queue_age,
            dispatched: AtomicBool::new(false),
            finished: false,
            _global_message: Some(global_message),
            _class_message: Some(class_message),
            _peer_message: Some(peer_message),
            _peer_class_message: Some(peer_class_message),
            _global_bytes: Some(global_bytes),
            _class_bytes: Some(class_bytes),
            _peer_bytes: Some(peer_bytes),
            _peer_class_bytes: Some(peer_class_bytes),
            _class_slot: Some(class_slot),
        })
    }

    fn peer_budget(&self, peer: SocketAddr) -> Result<Arc<PeerBudget>, AdmissionError> {
        let mut peers = self.peers.lock();
        if let Some(budget) = peers.get(&peer) {
            return Ok(Arc::clone(budget));
        }
        if peers.len() >= self.config.peer_state_limit {
            let idle = peers.iter().find_map(|(addr, budget)| {
                (Arc::strong_count(budget) == 1 && budget.is_idle(&self.config)).then_some(*addr)
            });
            if let Some(addr) = idle {
                peers.remove(&addr);
            } else {
                self.metrics.peer_table_full.fetch_add(1, Ordering::Relaxed);
                return Err(AdmissionError::PeerTableFull);
            }
        }
        let budget = Arc::new(PeerBudget::new(&self.config));
        peers.insert(peer, Arc::clone(&budget));
        Ok(budget)
    }
}

fn try_one(
    semaphore: &Arc<Semaphore>,
    class: TrafficClass,
    scope: &'static str,
    metrics: &ClassMetrics,
) -> Result<OwnedSemaphorePermit, AdmissionError> {
    semaphore.clone().try_acquire_owned().map_err(|_| {
        metrics.rejected_queue_full.fetch_add(1, Ordering::Relaxed);
        AdmissionError::QueueFull {
            class: class.as_str(),
            scope,
        }
    })
}

fn try_bytes(
    semaphore: &Arc<Semaphore>,
    permits: u32,
    class: TrafficClass,
    scope: &'static str,
    metrics: &ClassMetrics,
) -> Result<OwnedSemaphorePermit, AdmissionError> {
    semaphore
        .clone()
        .try_acquire_many_owned(permits)
        .map_err(|_| {
            metrics.rejected_queue_full.fetch_add(1, Ordering::Relaxed);
            AdmissionError::QueueFull {
                class: class.as_str(),
                scope,
            }
        })
}

struct PendingMetrics {
    metrics: Arc<SchedulerMetrics>,
    class: TrafficClass,
    bytes: usize,
    active: bool,
}

impl Drop for PendingMetrics {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let metrics = &self.metrics.classes[self.class as usize];
        metrics.queued_messages.fetch_sub(1, Ordering::Relaxed);
        metrics
            .queued_bytes
            .fetch_sub(self.bytes as u64, Ordering::Relaxed);
        metrics.cancelled_messages.fetch_add(1, Ordering::Relaxed);
    }
}

impl PendingMetrics {
    /// Finish an explicit admission rejection without misclassifying it as caller cancellation.
    fn reject(&mut self) {
        if !self.active {
            return;
        }
        let metrics = &self.metrics.classes[self.class as usize];
        metrics.queued_messages.fetch_sub(1, Ordering::Relaxed);
        metrics
            .queued_bytes
            .fetch_sub(self.bytes as u64, Ordering::Relaxed);
        self.active = false;
    }
}

#[derive(Debug)]
pub struct Reservation {
    metrics: Option<Arc<SchedulerMetrics>>,
    peer: Option<Arc<PeerBudget>>,
    class: TrafficClass,
    bytes: usize,
    enqueued_at: Instant,
    deadline: Instant,
    max_queue_age: Duration,
    dispatched: AtomicBool,
    finished: bool,
    _global_message: Option<OwnedSemaphorePermit>,
    _class_message: Option<OwnedSemaphorePermit>,
    _peer_message: Option<OwnedSemaphorePermit>,
    _peer_class_message: Option<OwnedSemaphorePermit>,
    _global_bytes: Option<OwnedSemaphorePermit>,
    _class_bytes: Option<OwnedSemaphorePermit>,
    _peer_bytes: Option<OwnedSemaphorePermit>,
    _peer_class_bytes: Option<OwnedSemaphorePermit>,
    _class_slot: Option<OwnedSemaphorePermit>,
}

impl Reservation {
    fn bypass() -> Self {
        let now = Instant::now();
        Self {
            metrics: None,
            peer: None,
            class: TrafficClass::Control,
            bytes: 0,
            enqueued_at: now,
            deadline: now,
            max_queue_age: Duration::ZERO,
            dispatched: AtomicBool::new(true),
            finished: false,
            _global_message: None,
            _class_message: None,
            _peer_message: None,
            _peer_class_message: None,
            _global_bytes: None,
            _class_bytes: None,
            _peer_bytes: None,
            _peer_class_bytes: None,
            _class_slot: None,
        }
    }

    pub async fn acquire_dispatch(&self) -> Result<Option<DispatchPermit>, AdmissionError> {
        let Some(peer) = &self.peer else {
            return Ok(None);
        };
        // The original deadline bounds first dispatch from initial admission. A retry gets a fresh
        // queue-age window: time spent actively writing/awaiting a response is an I/O timeout, not
        // queued age, and must not silently disable the existing second connection attempt.
        let dispatch_deadline = if self.dispatched.load(Ordering::Acquire) {
            Instant::now() + self.max_queue_age
        } else {
            self.deadline
        };
        let permit = match peer.dispatch.acquire(self.class, dispatch_deadline).await {
            Ok(permit) => permit,
            Err(AdmissionError::QueueExpired { .. }) => {
                if let Some(metrics) = &self.metrics {
                    metrics.classes[self.class as usize]
                        .queue_timeouts
                        .fetch_add(1, Ordering::Relaxed);
                }
                return Err(AdmissionError::QueueExpired {
                    class: self.class.as_str(),
                    age_ms: self
                        .deadline
                        .saturating_duration_since(self.enqueued_at)
                        .as_millis(),
                });
            }
            Err(error) => return Err(error),
        };

        self.mark_dispatched();
        Ok(Some(permit))
    }

    /// Mark work sent on an already-independent connection (the response half of an accepted
    /// inbound channel). It still owns all byte/message/class reservations, but must not acquire
    /// the pooled outbound channel's priority lock: crossed simultaneous requests would otherwise
    /// each hold that lock while preventing the other node from writing its response.
    pub fn start_independent_dispatch(&self) {
        self.mark_dispatched();
    }

    fn mark_dispatched(&self) {
        if self.dispatched.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(metrics) = &self.metrics {
            let metrics = &metrics.classes[self.class as usize];
            metrics.queued_messages.fetch_sub(1, Ordering::Relaxed);
            metrics
                .queued_bytes
                .fetch_sub(self.bytes as u64, Ordering::Relaxed);
            metrics.in_flight_messages.fetch_add(1, Ordering::Relaxed);
            metrics
                .in_flight_bytes
                .fetch_add(self.bytes as u64, Ordering::Relaxed);
            let waited = Instant::now().saturating_duration_since(self.enqueued_at);
            let waited_ns = waited.as_nanos().min(u64::MAX as u128) as u64;
            metrics.queue_wait_samples.fetch_add(1, Ordering::Relaxed);
            metrics
                .queue_wait_ns_total
                .fetch_add(waited_ns, Ordering::Relaxed);
            metrics
                .queue_wait_ns_max
                .fetch_max(waited_ns, Ordering::Relaxed);
        }
    }

    pub fn finish(mut self, success: bool) {
        self.finished = true;
        if let Some(metrics) = &self.metrics {
            let metrics = &metrics.classes[self.class as usize];
            if success {
                metrics.completed_messages.fetch_add(1, Ordering::Relaxed);
            } else {
                metrics.failed_messages.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let Some(metrics) = &self.metrics else {
            return;
        };
        let metrics = &metrics.classes[self.class as usize];
        if self.dispatched.load(Ordering::Acquire) {
            metrics.in_flight_messages.fetch_sub(1, Ordering::Relaxed);
            metrics
                .in_flight_bytes
                .fetch_sub(self.bytes as u64, Ordering::Relaxed);
        } else {
            metrics.queued_messages.fetch_sub(1, Ordering::Relaxed);
            metrics
                .queued_bytes
                .fetch_sub(self.bytes as u64, Ordering::Relaxed);
        }
        if !self.finished {
            metrics.cancelled_messages.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn cost(class: TrafficClass, bytes: usize) -> MessageCost {
        MessageCost {
            class,
            bytes,
            work: 1,
        }
    }

    #[tokio::test]
    async fn critical_capacity_is_reserved_from_transaction_saturation() {
        let mut config = SchedulerConfig::for_test();
        config.global_queue_bytes = 100;
        config.peer_queue_bytes = 100;
        config.classes[TrafficClass::Transaction as usize].queue_bytes = 60;
        config.classes[TrafficClass::Transaction as usize].peer_queue_bytes = 60;
        config.classes[TrafficClass::Block as usize].queue_bytes = 100;
        config.classes[TrafficClass::Block as usize].peer_queue_bytes = 100;
        let scheduler = OutboundScheduler::new(config);

        let transaction = scheduler
            .admit(peer(1), cost(TrafficClass::Transaction, 60))
            .await
            .expect("transaction fills only its class reservation");
        let block = scheduler
            .admit(peer(2), cost(TrafficClass::Block, 40))
            .await
            .expect("reserved global capacity remains available to block traffic");
        drop((transaction, block));

        let snapshot = scheduler.snapshot();
        assert_eq!(
            snapshot.classes[TrafficClass::Block as usize].queued_bytes,
            0
        );
        assert_eq!(
            snapshot.classes[TrafficClass::Transaction as usize].queued_bytes,
            0
        );
    }

    #[tokio::test]
    async fn per_peer_byte_cap_rejects_without_consuming_other_peers_capacity() {
        let mut config = SchedulerConfig::for_test();
        config.peer_queue_bytes = 100;
        for class in &mut config.classes {
            class.peer_queue_bytes = 100;
        }
        let scheduler = OutboundScheduler::new(config);
        let held = scheduler
            .admit(peer(1), cost(TrafficClass::Control, 80))
            .await
            .unwrap();
        assert!(matches!(
            scheduler
                .admit(peer(1), cost(TrafficClass::Control, 21))
                .await,
            Err(AdmissionError::QueueFull { scope: "peer", .. })
        ));
        assert_eq!(
            scheduler.snapshot().classes[TrafficClass::Control as usize].rejected_queue_full,
            1
        );
        scheduler
            .admit(peer(2), cost(TrafficClass::Control, 21))
            .await
            .expect("another peer owns an independent reservation");
        drop(held);
    }

    #[tokio::test]
    async fn block_overtakes_older_transaction_waiter_after_current_frame() {
        let scheduler = Arc::new(OutboundScheduler::new(SchedulerConfig::for_test()));
        let holder = scheduler
            .admit(peer(1), cost(TrafficClass::Transaction, 1))
            .await
            .unwrap();
        let active = holder.acquire_dispatch().await.unwrap().unwrap();

        let (order_tx, mut order_rx) = tokio::sync::mpsc::unbounded_channel();
        let tx_scheduler = Arc::clone(&scheduler);
        let tx_order = order_tx.clone();
        let transaction_waiter = tokio::spawn(async move {
            let reservation = tx_scheduler
                .admit(peer(1), cost(TrafficClass::Transaction, 1))
                .await
                .unwrap();
            let _permit = reservation.acquire_dispatch().await.unwrap().unwrap();
            tx_order.send("transaction").unwrap();
            reservation.finish(true);
        });

        tokio::task::yield_now().await;
        let block_scheduler = Arc::clone(&scheduler);
        let block_waiter = tokio::spawn(async move {
            let reservation = block_scheduler
                .admit(peer(1), cost(TrafficClass::Block, 1))
                .await
                .unwrap();
            let _permit = reservation.acquire_dispatch().await.unwrap().unwrap();
            order_tx.send("block").unwrap();
            reservation.finish(true);
        });
        tokio::task::yield_now().await;

        drop(active);
        assert_eq!(order_rx.recv().await.unwrap(), "block");
        assert_eq!(order_rx.recv().await.unwrap(), "transaction");
        holder.finish(true);
        block_waiter.await.unwrap();
        transaction_waiter.await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_removes_priority_waiter_and_releases_all_budgets() {
        let scheduler = Arc::new(OutboundScheduler::new(SchedulerConfig::for_test()));
        let holder = scheduler
            .admit(peer(1), cost(TrafficClass::Control, 1_024))
            .await
            .unwrap();
        let active = holder.acquire_dispatch().await.unwrap().unwrap();

        let waiting_scheduler = Arc::clone(&scheduler);
        let (queued_tx, queued_rx) = oneshot::channel();
        let waiter = tokio::spawn(async move {
            let reservation = waiting_scheduler
                .admit(peer(1), cost(TrafficClass::Block, 2_048))
                .await
                .unwrap();
            queued_tx.send(()).unwrap();
            let _permit = reservation.acquire_dispatch().await.unwrap();
        });
        queued_rx.await.unwrap();
        tokio::task::yield_now().await;
        waiter.abort();
        let _ = waiter.await;
        drop(active);
        holder.finish(true);

        let replacement = scheduler
            .admit(peer(1), cost(TrafficClass::Block, 2_048))
            .await
            .expect("cancelled reservation released byte and message permits");
        let _dispatch = replacement
            .acquire_dispatch()
            .await
            .expect("cancelled waiter was removed")
            .unwrap();
        replacement.finish(true);

        let snapshot = scheduler.snapshot();
        let block = snapshot.classes[TrafficClass::Block as usize];
        assert_eq!(block.queued_messages, 0);
        assert_eq!(block.in_flight_messages, 0);
        assert_eq!(block.cancelled_messages, 1);
        assert_eq!(
            block.queue_wait_samples, 1,
            "only the replacement reached dispatch; the cancelled waiter is not an average sample"
        );
    }

    #[tokio::test]
    async fn peer_table_is_bounded_when_every_entry_is_active() {
        let mut config = SchedulerConfig::for_test();
        config.peer_state_limit = 2;
        let scheduler = OutboundScheduler::new(config);
        let first = scheduler
            .admit(peer(1), cost(TrafficClass::Control, 1))
            .await
            .unwrap();
        let second = scheduler
            .admit(peer(2), cost(TrafficClass::Control, 1))
            .await
            .unwrap();
        assert!(matches!(
            scheduler
                .admit(peer(3), cost(TrafficClass::Control, 1))
                .await,
            Err(AdmissionError::PeerTableFull)
        ));
        assert_eq!(scheduler.snapshot().peer_states, 2);
        assert_eq!(scheduler.snapshot().peer_table_full, 1);
        drop((first, second));
    }

    #[tokio::test]
    async fn queue_timeout_is_bounded_and_observable() {
        let scheduler = OutboundScheduler::new(SchedulerConfig::for_test());
        let holder = scheduler
            .admit(peer(1), cost(TrafficClass::Block, 1))
            .await
            .unwrap();
        let _active = holder.acquire_dispatch().await.unwrap().unwrap();
        let queued = scheduler
            .admit(peer(1), cost(TrafficClass::Control, 1))
            .await
            .unwrap();
        assert!(matches!(
            queued.acquire_dispatch().await,
            Err(AdmissionError::QueueExpired { .. })
        ));
        queued.finish(false);
        let control = scheduler.snapshot().classes[TrafficClass::Control as usize];
        assert_eq!(control.queue_timeouts, 1);
        assert_eq!(control.queued_messages, 0);
        assert_eq!(control.failed_messages, 1);
        assert_eq!(control.cancelled_messages, 0);
    }

    #[tokio::test]
    async fn peer_message_slots_also_reserve_critical_capacity() {
        let scheduler = OutboundScheduler::new(SchedulerConfig::for_test());
        let target = peer(1);
        let mut held = Vec::new();
        for _ in 0..6 {
            held.push(
                scheduler
                    .admit(target, cost(TrafficClass::Transaction, 1))
                    .await
                    .unwrap(),
            );
        }
        for _ in 0..3 {
            held.push(
                scheduler
                    .admit(target, cost(TrafficClass::Bootstrap, 1))
                    .await
                    .unwrap(),
            );
        }
        held.push(
            scheduler
                .admit(target, cost(TrafficClass::Registration, 1))
                .await
                .unwrap(),
        );

        // Ten lower-priority reservations cannot consume the six slots reserved by construction.
        for _ in 0..4 {
            held.push(
                scheduler
                    .admit(target, cost(TrafficClass::Block, 1))
                    .await
                    .expect("block slot remains reserved"),
            );
        }
        for _ in 0..2 {
            held.push(
                scheduler
                    .admit(target, cost(TrafficClass::Control, 1))
                    .await
                    .expect("control slot remains reserved"),
            );
        }
        assert!(matches!(
            scheduler
                .admit(target, cost(TrafficClass::Control, 1))
                .await,
            Err(AdmissionError::QueueFull { scope: "peer", .. })
        ));
        drop(held);
    }

    #[tokio::test]
    async fn independent_response_dispatch_cannot_deadlock_on_outbound_gate() {
        let scheduler = OutboundScheduler::new(SchedulerConfig::for_test());
        let outbound = scheduler
            .admit(peer(1), cost(TrafficClass::Control, 1))
            .await
            .unwrap();
        let _outbound_gate = outbound.acquire_dispatch().await.unwrap().unwrap();

        let response = scheduler
            .admit(peer(1), cost(TrafficClass::Control, 1))
            .await
            .unwrap();
        response.start_independent_dispatch();
        let snapshot = scheduler.snapshot().classes[TrafficClass::Control as usize];
        assert_eq!(snapshot.in_flight_messages, 2);
        assert_eq!(snapshot.queued_messages, 0);
        response.finish(true);
        outbound.finish(true);
    }

    #[tokio::test]
    async fn retry_dispatch_gets_a_fresh_queue_age_window() {
        let scheduler = OutboundScheduler::new(SchedulerConfig::for_test());
        let reservation = scheduler
            .admit(peer(1), cost(TrafficClass::Control, 1))
            .await
            .unwrap();
        drop(reservation.acquire_dispatch().await.unwrap());
        tokio::time::sleep(Duration::from_millis(300)).await;
        // The original 125 ms control deadline has elapsed; a retry is active work re-entering the
        // queue and receives its own bounded window rather than being rejected immediately.
        drop(reservation.acquire_dispatch().await.unwrap());
        reservation.finish(true);
    }

    #[test]
    fn byte_and_work_tokens_are_debited_atomically() {
        let bucket = TrafficTokenBucket::new(0.0, 10.0, 0.0, 1.0);
        assert!(!bucket.try_consume(5, 2), "work burst rejects the pair");
        assert!(
            bucket.try_consume(10, 1),
            "failed work check must not have consumed byte tokens"
        );
    }

    #[test]
    fn peer_state_capacity_has_an_absolute_operator_independent_ceiling() {
        let config = SchedulerConfig::new(
            true,
            64 * MIB,
            16 * MIB,
            Duration::from_secs(10),
            16 * MIB,
            4_096,
            usize::MAX,
        );
        assert_eq!(config.peer_state_limit, MAX_PEER_STATES);
    }

    #[test]
    fn every_full_frame_transport_class_fits_default_single_message_caps() {
        let config = SchedulerConfig::new(
            true,
            64 * MIB,
            16 * MIB,
            Duration::from_secs(10),
            16 * MIB,
            4_096,
            32,
        );
        for class in [
            TrafficClass::Block,
            TrafficClass::Control,
            TrafficClass::Transaction,
            TrafficClass::Bootstrap,
        ] {
            let class = &config.classes[class as usize];
            assert!(class.queue_bytes >= 4 * MIB);
            assert!(class.peer_queue_bytes >= 4 * MIB);
        }
    }

    #[tokio::test]
    async fn disabled_scheduler_is_an_exact_allocation_free_bypass() {
        let mut config = SchedulerConfig::for_test();
        config.enabled = false;
        let scheduler = OutboundScheduler::new(config);
        let reservation = scheduler
            .admit(
                peer(1),
                MessageCost {
                    class: TrafficClass::Transaction,
                    bytes: usize::MAX,
                    work: usize::MAX,
                },
            )
            .await
            .expect("rollback mode bypasses the new transport policy");
        assert!(reservation.acquire_dispatch().await.unwrap().is_none());
        reservation.finish(true);
        let snapshot = scheduler.snapshot();
        assert!(!snapshot.enabled);
        assert_eq!(snapshot.peer_states, 0);
        assert!(snapshot
            .classes
            .iter()
            .all(|class| class.admitted_messages == 0));
    }
}
