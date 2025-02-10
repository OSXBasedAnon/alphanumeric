use dashmap::DashMap;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use inquire::{Password, PasswordDisplayMode};
use log::{debug, error, warn};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::VecDeque;
use std::error::Error;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tokio::fs;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, RwLock};

use ipnet::Ipv4Net;
use std::collections::HashSet;
use std::net::IpAddr;
use std::net::Ipv4Addr;

use crate::a9::{
    blockchain::{Blockchain, RateLimiter, Transaction},
    bpos::{BPoSSentinel, ValidatorTier},
    mgmt::{Mgmt, WalletKeyData},
    node::{Node, NodeError, PeerInfo, DEFAULT_PORT},
    oracle::DifficultyOracle,
    progpow::{Miner, MiningManager},
    whisper::WhisperModule,
};
mod a9;

const KEY_FILE_PATH: &str = "private.key";

// Modify result to take only one type parameter
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

impl std::fmt::Display for Blockchain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Blockchain {{ ... }}")
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    print_ascii_intro();

    let pb = ProgressBar::new(9);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {msg}")
            .progress_chars("█▓░"),
    );

    let local = tokio::task::LocalSet::new();
    local.run_until(async move {

// Database init
pb.set_message("Initializing database...");
let db = match sled::open("blockchain.db") {
    Ok(db) => db,
    Err(e) => {
        error!("Error opening database: {}", e);
        return Err(Box::new(e) as Box<dyn Error>);
    }
};
let db_arc = Arc::new(RwLock::new(db.clone()));
pb.inc(1);

pb.set_message("Creating blockchain...");
let rate_limiter = Arc::new(RateLimiter::new(60, 100));
let difficulty = Arc::new(Mutex::new(0_u64));

let blockchain = Arc::new(RwLock::new(Blockchain::new(
    db.clone(),
    0.000563063063,
    50.0,
    100,
    5,
    rate_limiter.clone(),
    difficulty.clone(), // Pass in the Arc<Mutex>
)));

pb.inc(1);

// Set specific message for balance verification
pb.set_message("Verifying blockchain state...");
if let Err(e) = blockchain.write().await.initialize().await {
    error!("Failed to initialize blockchain: {}", e);
    return Err(Box::new(e));
}
pb.inc(1);

// Continue with rest of initialization
pb.set_message("Setting up management...");
let (transaction_fee, mining_reward, difficulty_adjustment_interval, block_time) = {
    let blockchain_lock = blockchain.read().await;
    (
        blockchain_lock.transaction_fee,
        blockchain_lock.mining_reward,
        blockchain_lock.difficulty_adjustment_interval,
        blockchain_lock.block_time,
    )
}; // blockchain_lock is dropped here

let mgmt = Box::new(Mgmt::new(
    db.clone(),
    blockchain.clone(),
));
pb.inc(1);

// First generate the keypair
pb.set_message("Generating node keypair...");
let rng = SystemRandom::new();
let key_pair = Ed25519KeyPair::generate_pkcs8(&rng)
    .map_err(|e| format!("Failed to generate key pair: {}", e))?;
let key_pair = Ed25519KeyPair::from_pkcs8(key_pair.as_ref())
    .map_err(|e| format!("Failed to create key pair from PKCS8: {}", e))?;
let public_key = key_pair.public_key().as_ref();
pb.inc(1);

// Then create the node (single instance)
pb.set_message("Creating node...");
let bind_addr = match Node::get_bind_address() {
    Ok(ip) => Some(SocketAddr::new(ip, DEFAULT_PORT)),
    Err(e) => {
        error!("Failed to determine bind address: {}", e);
        None
    }
};

let node = match Node::new(Arc::new(db.clone()), blockchain.clone(), key_pair, bind_addr).await {
    Ok(node) => Arc::new(node),
    Err(e) => {
        error!("Failed to create node: {}", e);
        return Err(e.into());
    }
};

pb.inc(1);
pb.finish_and_clear();

// Spawn node task with integrated monitoring
let node_clone = Arc::clone(&node);
tokio::task::spawn_local(async move {
    let local = tokio::task::LocalSet::new();

    local.spawn_local(async move {
        const FAST_SYNC_LATENCY: u64 = 50;       // 50ms target latency
        const RECOVERY_LATENCY: u64 = 500;        // 500ms acceptable during network stress
        const BLOCK_BUFFER_SIZE: usize = 100;     // ~200s worth of blocks
        const MIN_VIABLE_PEERS: usize = 3;        // Minimum peers for operation
        const MAX_SYNC_ATTEMPTS: u32 = 3;         // Maximum sync retries before backing off
        const HEALTH_CHECK_INTERVAL: u64 = 100;   // 100ms health checks
        const SYNC_CHECK_INTERVAL: u64 = 500;     // 500ms sync checks
        const SLEEP_THRESHOLD: u64 = 10;          // 10s threshold for sleep detection
        const MAX_BLOCK_AGE: u64 = 2;            // Maximum acceptable block age deviation
        const MIN_PEER_LATENCY: u64 = 10;        // Minimum acceptable peer latency
        const MAX_DISCOVERIES_PER_CYCLE: u32 = 5; // Maximum peer discoveries per cycle
        const RECENT_PEER_THRESHOLD: u64 = 300;   // Peer considered recent within 300s
        const MAX_DISCOVERY_ATTEMPTS: u32 = 5;    // Maximum discovery retry attempts

        // Track last activity time for sleep detection
        let last_active = Arc::new(AtomicU64::new(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()));

        // Initialize core services
        if let Err(e) = node_clone.start().await {
            error!("Critical error during startup: {}", e);
            return;
        }

        // Combined monitor for network and chain
        let monitor_handle = {
            let node = Arc::clone(&node_clone);
            let activity_time = Arc::clone(&last_active);

            tokio::task::spawn_local(async move {
                let mut sync_interval = tokio::time::interval(Duration::from_millis(SYNC_CHECK_INTERVAL));
                let mut health_interval = tokio::time::interval(Duration::from_millis(HEALTH_CHECK_INTERVAL));
                let mut block_times = VecDeque::with_capacity(50);
                let mut sync_attempts: u32 = 0;
                let mut discovery_failures: u32 = 0;
                let mut consecutive_timeouts: u32 = 0;
                let peer_state: DashMap<SocketAddr, PeerInfo> = DashMap::new();

                loop {
                    tokio::select! {
                        // Network sync check
                        _ = sync_interval.tick() => {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();

                            // Sleep detection with state reset
                            let last = activity_time.load(Ordering::Acquire);
                            if now - last > SLEEP_THRESHOLD {
                                debug!("Sleep detected, resetting network state");
                                // Reset all counters
                                sync_attempts = 0;
                                discovery_failures = 0;
                                consecutive_timeouts = 0;
                                block_times.clear();

                                // Reset validation state
                                node.validation_pool.active_validations.store(0, Ordering::SeqCst);
                                peer_state.clear();

                                // Attempt immediate network recovery
                                if let Err(e) = node.discover_network_nodes().await {
                                    error!("Network rediscovery after wake failed: {}", e);
                                }
                            }
                            activity_time.store(now, Ordering::Release);

                            // Network state check
                            let peers = node.peers.read().await;
                            let active_peers = peers.len();

                            if active_peers >= MIN_VIABLE_PEERS {
                                // Calculate network health with safe division
                                let avg_latency = peers.iter()
                                    .filter(|(_, info)| info.latency >= MIN_PEER_LATENCY)
                                    .map(|(_, info)| info.latency)
                                    .sum::<u64>()
                                    .checked_div(active_peers.max(1) as u64)
                                    .unwrap_or(RECOVERY_LATENCY);

                                let target_latency = if avg_latency > FAST_SYNC_LATENCY {
                                    RECOVERY_LATENCY
                                } else {
                                    FAST_SYNC_LATENCY
                                };

                                // Efficient peer selection with latency filtering
                                let available_peers: Vec<_> = peers.iter()
                                    .filter(|(_, info)| {
                                        info.latency <= target_latency &&
                                        now.saturating_sub(info.last_seen) <= RECENT_PEER_THRESHOLD
                                    })
                                    .map(|(addr, _)| *addr)
                                    .collect();

                                if !available_peers.is_empty() {
                                    // Check chain state with safe conversion
                                    let local_height = {
                                        let blockchain = node.blockchain.read().await;
                                        match u32::try_from(blockchain.get_block_count()) {
                                            Ok(height) => height,
                                            Err(e) => {
                                                error!("Error converting block height: {}", e);
                                                return;
                                            }
                                        }
                                    };

                                    // Parallel height checks with timeout handling
                                    let heights = futures::future::join_all(
                                        available_peers.iter().map(|&peer| {
                                            let node = node.clone();
                                            async move {
                                                match tokio::time::timeout(
                                                    Duration::from_millis(target_latency),
                                                    node.request_peer_height(peer)
                                                ).await {
                                                    Ok(Ok(height)) => Some(height),
                                                    _ => {
                                                        consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                                                        None
                                                    }
                                                }
                                            }
                                        })
                                    ).await;

                                    // Process height differences with backoff
                                    if let Some(&max_height) = heights.iter().flatten().max() {
                                        if max_height > local_height + 1 {
                                            sync_attempts = sync_attempts.saturating_add(1);
                                            if sync_attempts < MAX_SYNC_ATTEMPTS {
                                                match handle_chain_sync(&node).await {
                                                    Ok(_) => {
                                                        sync_attempts = 0;
                                                        consecutive_timeouts = 0;
                                                    }
                                                    Err(e) => {
                                                        error!("Chain sync failed (attempt {}/{}): {}", 
                                                            sync_attempts, MAX_SYNC_ATTEMPTS, e);
                                                        if sync_attempts == MAX_SYNC_ATTEMPTS - 1 {
                                                            warn!("Max sync attempts reached, backing off");
                                                            tokio::time::sleep(Duration::from_secs(5)).await;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                // Emergency peer discovery with exponential backoff
                                let backoff_delay = if discovery_failures > 0 {
                                    let max_delay = 30_u64;
                                    let shift = u64::from(discovery_failures.min(MAX_DISCOVERY_ATTEMPTS));
                                    let delay = (1_u64).checked_shl(shift as u32)
                                        .unwrap_or(1_u64 << MAX_DISCOVERY_ATTEMPTS)
                                        .saturating_sub(1);
                                    Duration::from_secs(delay.min(max_delay))
                                } else {
                                    Duration::from_secs(1)
                                };

                                tokio::time::sleep(backoff_delay).await;

                                match node.discover_network_nodes().await {
                                    Ok(_) => {
                                        discovery_failures = 0;
                                        consecutive_timeouts = 0;
                                    }
                                    Err(e) => {
                                        error!("Emergency peer discovery failed: {}", e);
                                        discovery_failures = discovery_failures.saturating_add(1);
                                    }
                                }
                            }
                        }

                        // Chain health check
                        _ = health_interval.tick() => {
                            let blockchain = node.blockchain.read().await;
                            if let Some(last_block) = blockchain.get_last_block() {
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();

                                let block_time = now.saturating_sub(last_block.timestamp);
                                block_times.push_back(block_time);
                                if block_times.len() > 50 {
                                    block_times.pop_front();
                                }

                                // Monitor block times with moving average
                                let avg_block_time = if !block_times.is_empty() {
                                    block_times.iter().sum::<u64>() as f64 / block_times.len() as f64
                                } else {
                                    0.0
                                };

                                // Handle slow blocks
                                if avg_block_time > MAX_BLOCK_AGE as f64 {
                                    let mut health = node.network_health.write().await;
                                    health.adjust_for_slow_blocks(avg_block_time);

                                    let peers = node.peers.read().await;
                                    if peers.len() < MIN_VIABLE_PEERS ||
                                       peers.values().all(|p| p.latency > RECOVERY_LATENCY) {
                                        drop(peers);
                                        if let Err(e) = node.discover_network_nodes().await {
                                            error!("Failed to discover peers during health check: {}", e);
                                        }
                                    }
                                }

                                // Reset timeout counter on successful block
                                if block_time <= MAX_BLOCK_AGE {
                                    consecutive_timeouts = 0;
                                }
                            }
                        }
                    }
                }
            })
        };

        // Wait for monitor failure with error context
        if let Err(e) = monitor_handle.await {
            error!("Critical monitor failure: {} - Check system resources and network connectivity", e);
        }
    });

    local.await;
});

        // Mining manager
        pb.set_message("Setting up mining manager...");
        let mining_manager = MiningManager::new(Arc::clone(&blockchain));
        pb.inc(1);

        pb.set_message("Loading wallets...");
        let key_data = fs::read_to_string(KEY_FILE_PATH).await.unwrap_or_else(|_| "[]".to_string());
        let wallet_data: Vec<WalletKeyData> = serde_json::from_str(&key_data).unwrap_or_else(|_| Vec::new());

        let passphrase = String::new();
        let mut wallet_encryption_state: Option<Vec<u8>> = None;

    if !wallet_data.is_empty() {
        println!("\nWallet(s) found. Enter passphrase (leave blank for unencrypted wallets):");

        let passphrase = Password::new("Passphrase:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .prompt()
            .unwrap_or_default();

        if !passphrase.trim().is_empty() {
            wallet_encryption_state = Some(passphrase.trim().as_bytes().to_vec());
        }
    }

        let mut wallets = if wallet_encryption_state.is_some() {
            mgmt.load_wallets(&db_arc, wallet_encryption_state.as_deref()).await?
        } else {
            mgmt.load_wallets(&db_arc, None).await?
        };
        pb.inc(1);

        // Staking
let staking_node = Arc::new(RwLock::new(BPoSSentinel::new(
    blockchain.clone(),
    Arc::clone(&node)
)));

        // Whisper
let whisper_module = Arc::new(RwLock::new(WhisperModule::new()));

        // Mining params
        pb.set_message("Setting up mining parameters...");

        let miner = Miner::new(blockchain.clone(), mining_manager);
        pb.inc(1);

loop {
let mut stdout = StandardStream::stdout(ColorChoice::Always);
let mut color_spec = ColorSpec::new();
color_spec.set_fg(Some(Color::White)).set_bold(true);
stdout.set_color(&color_spec).unwrap();
print!("αlphanumeric:");
stdout.reset().unwrap();
println!();
println!("1. Create Transaction (format: create sender recipient amount)");
println!("2. Whisper Code (format: whisper address msg)");
println!("3. Show Balance (format: balance)");
println!("4. Make New Wallet (format: new [wallet_name])");
println!("5. Account Lookup (format: account address)");
println!("6. Mine Block (format: mine miner_wallet_name)");
println!("7. Exit");

let mut command = String::new();
std::io::stdin().read_line(&mut command)?;
let command = command.trim();

match command.split_whitespace().next() {
    Some("create") | Some("send") | Some("transfer") => {
// Handle the creation of the transaction
if let Err(e) = mgmt
.handle_create_transaction(&command, &mut wallets, &blockchain, &db_arc)
.await
{
println!("Error: {}", e);
println!("Failed to create transaction: {}", e);
}
}
Some("info") => {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let mut color_spec = ColorSpec::new();

    // Get total wallets and balance first
    let mut total_balance = 0.0;
    let mut processed_wallets = 0;

    // Get the blockchain guard once and use it for both operations
    let blockchain_guard = blockchain.read().await;

    // Calculate total balance
    for wallet in wallets.values() {
        if let Ok(balance) = blockchain_guard.get_wallet_balance(&wallet.address).await {
            total_balance += balance;
            processed_wallets += 1;
        }
    }

    // Initialize sentinel and register metrics
    {
        let sentinel = staking_node.write().await;
        if let Err(e) = sentinel.initialize().await {
            error!("Failed to initialize staking sentinel: {}", e);
        } else {
            // Register metrics for all wallets
            for wallet in wallets.values() {
                let balance = blockchain_guard.get_wallet_balance(&wallet.address).await.unwrap_or(0.0);
                if let Err(e) = sentinel.register_wallet_metrics(&wallet.address, balance).await {
                    error!("Failed to register metrics for wallet {}: {}", wallet.address, e);
                }
            }
        }
    }

    // Drop blockchain guard explicitly after we're done with it
    drop(blockchain_guard);

    // Wallet Summary
    color_spec.set_fg(Some(Color::Rgb(230, 230, 230))).set_bold(true);
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "\n Wallet Status ")?;
    color_spec.set_fg(Some(Color::Rgb(20, 51, 36)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "───────────────────")?;
    color_spec.set_fg(Some(Color::Rgb(230, 230, 230)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "Total Wallets:   {}", processed_wallets)?;
    color_spec.set_fg(Some(Color::Rgb(40, 204, 217)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "Total Balance:   {:.8} ♦", total_balance)?;
    stdout.reset()?;

    // Node Status
    let sentinel = staking_node.read().await;
    if let Some(wallet) = wallets.values().next() {
        if let Ok(metrics) = sentinel.get_node_metrics(&wallet.address).await {
            color_spec.set_fg(Some(Color::Rgb(230, 230, 230))).set_bold(true);
            stdout.set_color(&color_spec)?;
            writeln!(stdout, "\n Node Status ")?;
            color_spec.set_fg(Some(Color::Rgb(51, 43, 23)));
            stdout.set_color(&color_spec)?;
            writeln!(stdout, "───────────────────")?;
            color_spec.set_fg(Some(match metrics.current_tier {
                ValidatorTier::RedDiamond => Color::Rgb(136, 0, 21),
                ValidatorTier::Diamond => Color::Rgb(40, 204, 217),
                ValidatorTier::Emerald => Color::Rgb(141, 203, 129),
                ValidatorTier::Gold => Color::Rgb(237, 124, 51),
                ValidatorTier::Silver => Color::Rgb(230, 230, 230),
                ValidatorTier::Inactive => Color::Rgb(128, 128, 128),
            })).set_bold(true);
            stdout.set_color(&color_spec)?;
            write!(stdout, "Node Tier:       {:?}", metrics.current_tier)?;
            color_spec.set_fg(Some(Color::Rgb(128, 128, 128))).set_bold(false);
            stdout.set_color(&color_spec)?;
            writeln!(stdout, " ({:.1}% performance)", metrics.performance_score * 100.0)?;
            color_spec.set_fg(Some(Color::Rgb(230, 230, 230)));
            stdout.set_color(&color_spec)?;
            writeln!(stdout, "Blocks Verified: {}", metrics.blocks_verified)?;
            color_spec.set_fg(Some(Color::Rgb(59, 242, 173)));
            stdout.set_color(&color_spec)?;
            writeln!(stdout, "Success Rate:    {:.1}%", metrics.success_rate)?;
            color_spec.set_fg(Some(Color::Rgb(137, 207, 211)));
            stdout.set_color(&color_spec)?;
            writeln!(stdout, "Response Time:   {}ms", metrics.response_time)?;
            stdout.reset()?;
        }
    }

    // Network Status  
    color_spec.set_fg(Some(Color::Rgb(230, 230, 230))).set_bold(true);
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "\n Network Status ")?;
    color_spec.set_fg(Some(Color::Rgb(237, 124, 51)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "───────────────────")?;

    if let Ok(health) = sentinel.get_network_metrics().await {
        let peers = node.peers.read().await;
        let active_peers = peers.len();
        let active_nodes = health.active_nodes.max(active_peers).max(processed_wallets);

        color_spec.set_fg(Some(Color::Rgb(230, 230, 230)));
        stdout.set_color(&color_spec)?;
        writeln!(stdout, "Active Nodes:    {}", active_nodes)?;
        color_spec.set_fg(Some(Color::Rgb(167, 165, 198)));
        stdout.set_color(&color_spec)?;
        writeln!(stdout, "Connected Peers: {}", active_peers)?;
        color_spec.set_fg(Some(Color::Rgb(247, 111, 142)));
        stdout.set_color(&color_spec)?;
        writeln!(stdout, "Network Load:    {:.1}%", health.network_load * 100.0)?; 
        color_spec.set_fg(Some(Color::Rgb(247, 111, 142)));
        stdout.set_color(&color_spec)?;
        writeln!(stdout, "Fork Count:      {}", health.fork_count)?;
        stdout.reset()?;
        color_spec.set_fg(Some(Color::Rgb(242, 237, 161)));
        stdout.set_color(&color_spec)?;
        writeln!(stdout, "Avg Response:    {}ms", health.average_response_time)?;
    }

    // Chain Status
    let blockchain_guard = blockchain.read().await;
    let current_height = blockchain_guard.get_latest_block_index();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    color_spec.set_fg(Some(Color::Rgb(230, 230, 230))).set_bold(true);
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "\n Chain Status ")?;
    color_spec.set_fg(Some(Color::Rgb(40, 204, 217)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "───────────────────")?; 
    color_spec.set_fg(Some(Color::Rgb(230, 230, 230)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "Height:            {}", blockchain_guard.get_block_count())?;
    color_spec.set_fg(Some(Color::Rgb(59, 242, 173)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "Difficulty:        {}", blockchain_guard.get_current_difficulty().await)?;
    color_spec.set_fg(Some(Color::Rgb(137, 207, 211)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "Hashrate:          {:.2} TH/s", blockchain_guard.calculate_network_hashrate().await)?;
    color_spec.set_fg(Some(Color::Rgb(40, 204, 217)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "Fee Rate:          {:.8}%", blockchain_guard.transaction_fee * 100.0)?;
    writeln!(stdout, "Block Time Target: {}s", blockchain_guard.block_time)?;

    if let Some(last_block) = blockchain_guard.get_last_block() {
        color_spec.set_fg(Some(Color::Rgb(237, 124, 51)));
        stdout.set_color(&color_spec)?;
        let age = now - last_block.timestamp;
        writeln!(stdout, "Last Block Time:   {}s", age)?;
    }
    stdout.reset()?;

    // Memory Pool
    let pending_txs = blockchain_guard.get_pending_transactions().await?;
    color_spec.set_fg(Some(Color::Rgb(230, 230, 230))).set_bold(true);
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "\n Memory Pool ")?;
    color_spec.set_fg(Some(Color::Rgb(237, 124, 51)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "───────────────────")?;
    color_spec.set_fg(Some(Color::Rgb(230, 230, 230)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "Pending Txs:        {}\n", pending_txs.len())?;

    // Calculate total pending value with absolute values
    let pending_value: f64 = pending_txs.iter().map(|tx| tx.amount.abs()).sum();
    let pending_fees: f64 = pending_txs.iter().map(|tx| tx.fee.abs()).sum();

if pending_txs.len() > 0 {
    color_spec.set_fg(Some(Color::Rgb(88, 240, 181)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "Total Value:        {:.8} ♦", pending_value)?;

    color_spec.set_fg(Some(Color::Rgb(180, 219, 210)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "Total Pending Fees: {:.8} ♦\n", pending_fees)?;
}
    stdout.reset()?;
},

Some("balance") | Some("wallet") => mgmt.show_balances(&wallets).await,
Some("new") => {
let wallet_name = command.split_whitespace().nth(1).map(|s| s.to_string());
if let Err(e) = mgmt
.create_new_wallet(&mut wallets, wallet_encryption_state.as_deref(), wallet_name)
.await
{
println!("Error creating wallet: {}", e);
} else {
if let Err(e) = mgmt.save_wallets(&db_arc, &wallets, wallet_encryption_state.as_deref()).await {
error!("Failed to save wallets after creation: {}", e);
}
}
}
Some("rename") => {
let parts: Vec<&str> = command.split_whitespace().collect();
if parts.len() != 3 {
println!("Usage: rename <old_name> <new_name>");
} else {
let old_name = parts[1];
let new_name = parts[2];
if let Err(e) = mgmt.rename_wallet(old_name, new_name).await {
error!("Wallet rename failed: {}", e);
println!("Failed to rename wallet: {}", e);
} else {
println!("Wallet renamed successfully");
}
}
}
Some("mine") => {
let parts: Vec<&str> = command.split_whitespace().collect();
if parts.len() != 2 {
println!("Usage: mine <miner_wallet_name>");
continue;
}
if let Err(e) = mgmt
.handle_mine_command(&parts, &miner, &mut wallets, &blockchain, &db_arc)
.await
{
println!("Mining error: {}", e);
}
}
Some("whisper") => {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let whisper = whisper_module.read().await;

    // Split command into parts, handling quoted messages
    let parts: Vec<String> = if command.contains('"') {
        let mut parts = Vec::new();
        let mut in_quotes = false;
        let mut current = String::new();

        for c in command.chars() {
            match c {
                '"' => {
                    if !in_quotes && !current.is_empty() {
                        parts.push(current.clone());
                        current.clear();
                    }
                    in_quotes = !in_quotes;
                }
                ' ' if !in_quotes => {
                    if !current.is_empty() {
                        parts.push(current.clone());
                        current.clear();
                    }
                }
                _ => current.push(c),
            }
        }

        if !current.is_empty() {
            parts.push(current);
        }

        parts
    } else {
        command.split_whitespace()
            .map(String::from)
            .collect()
    };

if parts.len() == 1 {
    let mut header_style = ColorSpec::new();
    header_style.set_fg(Some(Color::Rgb(247, 111, 142))).set_bold(true);
    stdout.set_color(&header_style)?;
    println!("\n Whisper Messages (Last 48 Hours)");
    stdout.reset()?;
    writeln!(stdout, "───────────────────")?;

let mut all_messages = Vec::new();
let blockchain_guard = blockchain.read().await;

for wallet in wallets.values() {
    // Get confirmed messages from blockchain
    let blockchain_messages = whisper.scan_blockchain_for_messages(&blockchain_guard, &wallet.address).await;
    all_messages.extend(blockchain_messages);

    // Get pending messages but mark them as unconfirmed
    let pending_messages = whisper.get_unconfirmed_messages(&blockchain_guard, &wallet.address).await;
    all_messages.extend(pending_messages);
}

// Sort by timestamp and remove duplicates
all_messages.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
all_messages.dedup_by(|a, b| a.tx_hash == b.tx_hash);

if !all_messages.is_empty() {
    // Sort messages with most recent at the bottom
    let mut messages = all_messages;
    messages.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    for msg in messages {
        let wallet_addresses: Vec<_> = wallets.values().map(|w| &w.address).collect();
        let is_sender = wallet_addresses.contains(&&msg.from);

        if is_sender {
            // Grey header for sent messages
            let mut header_style = ColorSpec::new();
            header_style.set_fg(Some(Color::Rgb(106, 160, 163))).set_bold(true);
            stdout.set_color(&header_style)?;
            println!("SENT:");
            stdout.reset()?;

            // Grey recipient address
            let mut to_style = ColorSpec::new();
            to_style.set_fg(Some(Color::Rgb(132, 132, 132))).set_bold(false);
            stdout.set_color(&to_style)?;
            println!("  {}", msg.to);
        } else {
            // Received
let mut header_style = ColorSpec::new();
header_style.set_fg(Some(Color::Rgb(88, 240, 181))).set_bold(true);
stdout.set_color(&header_style)?;
println!("RECEIVED:");
stdout.reset()?;

            // Blue sender address
            let mut from_style = ColorSpec::new();
            from_style.set_fg(Some(Color::Cyan)).set_bold(true);
            stdout.set_color(&from_style)?;
            println!("  {}", msg.from);
        }

let mut amount_style = ColorSpec::new();
amount_style.set_fg(Some(Color::Rgb(255, 255, 255))).set_bold(false);
stdout.set_color(&amount_style)?; // Borrow stdout
writeln!(&mut stdout,"  Amount: {:.8} Fee: {:.8}", msg.amount, msg.fee)?;

        let mut content_style = ColorSpec::new();
        content_style.set_fg(Some(Color::Rgb(169, 169, 169))).set_bold(true);
        stdout.set_color(&content_style)?;
        print!("  Time: ");
        println!("{}", WhisperModule::format_message_time(msg.timestamp));

        let mut content_style = ColorSpec::new();
        content_style.set_fg(Some(Color::Rgb(180, 219, 210))).set_bold(true);
        stdout.set_color(&content_style)?;
        print!("  Message: ");

        if msg.content.starts_with("[PENDING]") {
            let mut pending_style = ColorSpec::new();
            pending_style.set_fg(Some(Color::Yellow)).set_bold(true);
            stdout.set_color(&pending_style)?;
        }
        stdout.reset()?;
        println!("{}", msg.content);
        println!("-------------------");
    }
} else {
    println!("No messages in the last 48 hours.\n");
}
    continue;

    } else {
        let (recipient, amount, message) = match parts.len() {
            3 => {
                let msg = parts[2].trim_matches('"');
                if msg.as_bytes().len() > crate::a9::whisper::MAX_MESSAGE_BYTES {
                    let mut error_style = ColorSpec::new();
                    error_style.set_fg(Some(Color::Red)).set_bold(true);
                    stdout.set_color(&error_style)?;
                    println!("Message must be 4 characters/bytes");
                    stdout.reset()?;
                    continue;
                }
                (&parts[1], crate::a9::whisper::WHISPER_MIN_AMOUNT, msg)
            },
            4 => {
                let amount = match parts[2].parse::<f64>() {
                    Ok(a) if a >= crate::a9::whisper::WHISPER_MIN_AMOUNT => a,
                    _ => {
                        let mut error_style = ColorSpec::new();
                        error_style.set_fg(Some(Color::Red)).set_bold(true);
                        stdout.set_color(&error_style)?;
                        println!("Minimum {} token required for whisper messages", 
                            crate::a9::whisper::WHISPER_MIN_AMOUNT);
                        stdout.reset()?;
                        continue;
                    }
                };

                let msg = parts[3].trim_matches('"');
                if msg.as_bytes().len() > crate::a9::whisper::MAX_MESSAGE_BYTES {
                    let mut error_style = ColorSpec::new();
                    error_style.set_fg(Some(Color::Red)).set_bold(true);
                    stdout.set_color(&error_style)?;
                    println!("Message must be 32 bytes or less");
                    stdout.reset()?;
                    continue;
                }
                (&parts[1], amount, msg)
            },
            _ => {

let mut section_style = ColorSpec::new();
section_style.set_fg(Some(Color::Rgb(147, 124, 184))) // A softer color for section titles
             .set_bold(true);

let mut description_style = ColorSpec::new();
description_style.set_fg(Some(Color::Rgb(165, 251, 255))); // Light blue for descriptions

let mut stdout = StandardStream::stdout(ColorChoice::Always);

stdout.set_color(&section_style)?;
write!(&mut stdout, "\n Usage")?;
stdout.reset()?;
    writeln!(stdout, "\n───────────────────")?;


write!(&mut stdout, "whisper (Displays recent whispers.)\n")?;
write!(&mut stdout, "whisper <recipient> <amount> <message> Send a new whisper to <recipient>.\n")?;

stdout.set_color(&section_style)?;
write!(&mut stdout, "\n Whisper Code")?;
stdout.reset()?;
    writeln!(stdout, "\n───────────────────")?;

write!(&mut stdout, "Embed a short alphabetic message, 4-character (4-byte) code.\n")?;
write!(&mut stdout, "This optional feature provides a vanity fee code that can be seen by decoding the fee with a cipher.\n")?;
stdout.set_color(&description_style)?;
write!(&mut stdout, "Whisper codes can be decoded from the public ledger so do not share sensitive information.\n\n")?;

stdout.flush()?;
continue;
}
        };

        // Rest of the whisper sending code remains the same...
        let sender_wallet = match wallets.values().next() {
            Some(w) => w,
            None => {
                let mut error_style = ColorSpec::new();
                error_style.set_fg(Some(Color::Red)).set_bold(true);
                stdout.set_color(&error_style)?;
                print!("error");
                stdout.reset()?;
                println!(": No wallet available to send message");
                continue;
            }
        };

        let blockchain_guard = blockchain.read().await;
        let sender_balance = match blockchain_guard.get_wallet_balance(&sender_wallet.address).await {
            Ok(b) => b,
            Err(e) => {
                let mut error_style = ColorSpec::new();
                error_style.set_fg(Some(Color::Red)).set_bold(true);
                stdout.set_color(&error_style)?;
                print!("error");
                stdout.reset()?;
                println!(": Failed to check balance: {}", e);
                continue;
            }
        };

        let base_tx = Transaction::new(
            sender_wallet.address.clone(),
            recipient.to_string(),
            amount,
            0.0,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            None,
        );

match whisper.create_whisper_transaction(
    base_tx,
    recipient,
    message,
    sender_wallet,
    sender_balance,
).await {
Ok(whisper_tx) => {
    // Drop blockchain guard before getting write lock
    drop(blockchain_guard);
    let blockchain_guard = blockchain.write().await;
    // Add wallet to blockchain state if not present
    blockchain_guard.wallets.write().await.entry(sender_wallet.address.clone())
        .or_insert_with(|| sender_wallet.clone());
    match blockchain_guard.add_transaction(whisper_tx.clone()).await {
        Ok(_) => {
let mut stdout = StandardStream::stdout(ColorChoice::Always);
let mut style = ColorSpec::new();

style.set_fg(Some(Color::Rgb(132, 132, 132))).set_bold(false);
stdout.set_color(&style)?;
writeln!(stdout, "\n    ...CRYSTALS-dilithium verification complete")?;
writeln!(stdout, "    ...Establishing secure atomic lock for transaction")?;
stdout.reset()?;

style.set_fg(Some(Color::Rgb(59, 242, 173))).set_bold(true);
stdout.set_color(&style)?;
writeln!(stdout, "\nWhisper message sent successfully")?;

stdout.reset()?;

style.set_fg(Some(Color::Rgb(132, 132, 132))).set_bold(false);
stdout.set_color(&style)?;
writeln!(stdout, "\n  Receipt:")?;
stdout.reset()?;
style.set_fg(Some(Color::Rgb(180, 219, 210)));
stdout.set_color(&style)?;
writeln!(stdout, "  Amount: {:.8}", whisper_tx.amount)?;
writeln!(stdout, "  Fee: {:.8}", whisper_tx.fee)?;
writeln!(stdout, "  Message: {}\n", message)?;
stdout.reset()?;

        },
        Err(e) => {
            let mut error_style = ColorSpec::new();
            error_style.set_fg(Some(Color::Red)).set_bold(true);
            stdout.set_color(&error_style)?;
            print!("error");
            stdout.reset()?;
            println!(": Failed to send message: {}", e);
        }
    }
},
    Err(e) => {
        let mut error_style = ColorSpec::new();
        error_style.set_fg(Some(Color::Red)).set_bold(true);
        stdout.set_color(&error_style)?;
        print!("error");
        stdout.reset()?;
        println!(": Failed to create whisper transaction: {}", e);
    }
        }
    }
},

Some("history") => {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let whisper = whisper_module.read().await;
    let blockchain_guard = blockchain.read().await;

    let mut title_style = ColorSpec::new();
    title_style.set_fg(Some(Color::Rgb(132, 132, 132))).set_bold(true);
    stdout.set_color(&title_style)?;
    writeln!(&mut stdout, "\n Transaction History (Last 7 Days)")?;
    stdout.reset()?;
        writeln!(&mut stdout, "───────────────────")?;

    // Collect all transactions across all wallets
    let mut all_transactions = Vec::new();
    for wallet in wallets.values() {
        let wallet_transactions = whisper
            .get_transaction_history(&blockchain_guard, &wallet.address, 7)
            .await;
        all_transactions.extend(wallet_transactions);
    }

    // Sort all transactions by timestamp (oldest first)
    all_transactions.sort_by(|a, b| {
        // First compare timestamps
        let time_cmp = a.timestamp.cmp(&b.timestamp);
        if time_cmp == std::cmp::Ordering::Equal {
            // If timestamps are equal, use other fields for consistent ordering
            match (a.from.as_str(), b.from.as_str()) {
                ("MINING_REWARDS", "MINING_REWARDS") => std::cmp::Ordering::Equal,
                ("MINING_REWARDS", _) => std::cmp::Ordering::Less,
                (_, "MINING_REWARDS") => std::cmp::Ordering::Greater,
                _ => a.from.cmp(&b.from) // Sort by sender address as final tiebreaker
            }
        } else {
            time_cmp
        }
    });

    // Deduplicate transactions while preserving order
    all_transactions.dedup_by(|a, b| {
        a.timestamp == b.timestamp &&
        a.from == b.from &&
        a.to == b.to &&
        (a.amount - b.amount).abs() < f64::EPSILON
    });

    for tx in all_transactions {
        let wallet_is_sender = wallets.values().any(|w| w.address == tx.from);

        let mut sent_received_style = ColorSpec::new();
        if wallet_is_sender {
            sent_received_style.set_fg(Some(Color::Rgb(255, 84, 73))).set_bold(true);
            stdout.set_color(&sent_received_style)?;
            write!(&mut stdout, "SENT")?;
        } else {
            sent_received_style.set_fg(Some(Color::Rgb(59, 242, 173))).set_bold(true);
            stdout.set_color(&sent_received_style)?;
            write!(&mut stdout, "RECEIVED")?;
        }
        stdout.reset()?;

        let mut time_style = ColorSpec::new();
        time_style.set_fg(Some(Color::Rgb(169, 169, 169))).set_bold(true);
        stdout.set_color(&time_style)?;
        writeln!(&mut stdout, " {}", WhisperModule::format_message_time(tx.timestamp))?;

        writeln!(&mut stdout, "  Amount: {:.8} ", tx.amount)?;

        let mut fee_style = ColorSpec::new();
        fee_style.set_fg(Some(Color::Rgb(192, 192, 192)));
        stdout.set_color(&fee_style)?;
        writeln!(&mut stdout, "  Fee: {:.8} ", tx.fee)?;
        stdout.reset()?;

        if wallet_is_sender {
            writeln!(&mut stdout, "  To: {}", tx.to)?;
        } else {
            writeln!(&mut stdout, "  From: {}", tx.from)?;
        }
        writeln!(&mut stdout, "-------------------")?;
    }
},
Some("reset") => {
    let blockchain_guard = blockchain.write().await;
    let mut difficulty_guard = blockchain_guard.difficulty.lock().await;
    *difficulty_guard = 200;

    // Optionally save to persistent storage
    if let Ok(config_tree) = blockchain_guard.db.open_tree("config") {
        if let Ok(bytes) = bincode::serialize(&16u64) {
            if let Err(e) = config_tree.insert("current_difficulty", bytes) {
                println!("Warning: Could not persist difficulty: {}", e);
            }
        }
    }

    println!("Network difficulty reset to 16 for future blocks");
},
    Some(cmd) if cmd.starts_with("--") => {
        if let Err(e) = handle_network_commands(&command, &node, &blockchain).await {
            println!("Network command error: {}", e);
        }
    },
    Some("account") => {
        if let Err(e) = mgmt.handle_account_command(&command, &blockchain, &wallets).await {
            println!("Error displaying account info: {}", e);
        }
    },

Some("diagnostics") | Some("diag") => {
    let blockchain_guard = blockchain.read().await;
    let oracle = DifficultyOracle::new();

    if let Some(last_block) = blockchain_guard.get_last_block() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let timestamp_diff = now.saturating_sub(last_block.timestamp);
        let current_difficulty = blockchain_guard.get_current_difficulty().await;

        if let Err(e) = oracle.display_difficulty_metrics(current_difficulty, timestamp_diff).await {
            error!("Failed to display diagnostics: {}", e);
            println!("Error displaying diagnostics: {}", e);
        }
    } else {
        println!("No blocks available for diagnostics");
    }
},

Some("help") => {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let mut header_style = ColorSpec::new();
    header_style.set_fg(Some(Color::Rgb(40, 204, 217)))
        .set_bold(true);

    stdout.set_color(&header_style)?;
    writeln!(stdout, "\n Available Commands")?;
    stdout.reset()?;
    println!("───────────────────");
    println!("create <sender> <recipient> <amount>  - Create a new transaction");
    println!("whisper <address> <msg>               - Send a whisper message (amount optional)");
    println!("balance                               - Show all wallet balances");
    println!("new [wallet_name]                     - Create a new wallet");
    println!("account <address>                     - Show account information");
    println!("history                               - Show transaction history");
    println!("mine <wallet_name>                    - Mine a new block");
    println!("rename <wallet_name> <new_wallet>     - Rename wallet");
    println!("info                                  - Show blockchain information");

    // For Network Commands header
    stdout.set_color(&header_style)?;
    println!("\n Network Commands");
    stdout.reset()?;
    println!("───────────────────");
    println!("--status    (-s)      - Show network status");
    println!("--sync              - Attempt normal sync");
    println!("--sync --force      - Force full resync");
    println!("--connect <ip:port> - Connect to specific node");
    println!("--getpeers          - List available peers");
    println!("--discover          - Search for new nodes\n");
}

Some("version") => {
print_ascii_intro();
},
Some("exit") => {
use std::process::Command;
if cfg!(windows) {
Command::new("cmd").args(["/C", "pause"]).status()?;
}
std::process::exit(0);
},

Some(_) => println!("Invalid command. Type 'help' for command list or 'info' for blockchain details."),
None => println!("Please enter a command."),
}
}
// Ensure this block properly closes the `async move {` scope
})
.await
}

async fn handle_chain_sync(node: &Node) -> Result<()> {
    const PARALLEL_BATCH_SIZE: usize = 32768;
    const MAX_PARALLEL_DOWNLOADS: usize = 128;
    const QUEUE_SIZE: usize = 32768;
    const MAX_PEER_LATENCY: u64 = 100;
    const SYNC_TIMEOUT: Duration = Duration::from_secs(300);

    let mp = MultiProgress::new();
    let status_pb = mp.add(ProgressBar::new_spinner());
    status_pb.set_message("Finding fastest network peers...");

    // Get network health metrics
    let network_health = node.network_health.read().await;
    let target_peers = (network_health.active_nodes / 4).clamp(3, MAX_PARALLEL_DOWNLOADS);
    drop(network_health);

    // Discover peers
    tokio::time::timeout(Duration::from_secs(5), node.discover_network_nodes())
        .await
        .unwrap_or_else(|_| Ok(()))?;

    // Select peers based on latency
    let peers = node.peers.read().await;
    let sync_peers: Vec<_> = peers
        .iter()
        .filter(|(_, info)| info.latency < MAX_PEER_LATENCY)
        .map(|(addr, info)| (*addr, info.blocks, info.latency))
        .collect();
    drop(peers);

    if sync_peers.len() < 3 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Insufficient fast peers available",
        )));
    }

    // Get target height
    let target_height = sync_peers
        .iter()
        .map(|(_, height, _)| *height)
        .max()
        .unwrap_or(0);

    let local_height = {
        let blockchain = node.blockchain.read().await;
        blockchain.get_block_count() as u32
    };

    if target_height <= local_height {
        status_pb.finish_with_message(format!("Chain at height {}", local_height));
        return Ok(());
    }

    // Setup progress bars
    let blocks_remaining = target_height - local_height;
    let main_pb = mp.add(ProgressBar::new(blocks_remaining as u64));
    main_pb.set_message("Fast syncing blocks...");

    // Sort peers by latency
    let mut sync_peers: Vec<_> = sync_peers
        .into_iter()
        .map(|(addr, _, latency)| (addr, latency))
        .collect();
    sync_peers.sort_by_key(|(_, latency)| *latency);

    // Setup sync channels and counters
    let (tx, mut rx) = mpsc::channel(QUEUE_SIZE);
    let current_height = Arc::new(AtomicU32::new(local_height));
    let processed_height = Arc::new(AtomicU32::new(local_height));

    // Spawn download tasks
    let download_tasks: Vec<_> = sync_peers
        .iter()
        .take(target_peers)
        .map(|(peer, _)| {
            let tx = tx.clone();
            let current_height = Arc::clone(&current_height);
            let node = node.clone();
            let peer = *peer;

            tokio::spawn(async move {
                let mut curr_height = current_height.load(Ordering::Acquire);
                while curr_height < target_height {
                    let batch_end = (curr_height + PARALLEL_BATCH_SIZE as u32).min(target_height);

                    match node.request_blocks(peer, curr_height, batch_end).await {
                        Ok(blocks) => {
                            for block in blocks {
                                if block.index > curr_height && block.index <= target_height {
                                    if tx.send(block).await.is_err() {
                                        return Ok::<(), Box<dyn Error + Send + Sync>>(());
                                    }
                                }
                            }
                            current_height.fetch_add(PARALLEL_BATCH_SIZE as u32, Ordering::Release);
                        }
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                    curr_height = current_height.load(Ordering::Acquire);
                }
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            })
        })
        .collect();

    // Single processing task
    let process_handle = {
        let blockchain = Arc::clone(&node.blockchain);
        let processed_height = Arc::clone(&processed_height);
        let main_pb = main_pb.clone();

        tokio::spawn(async move {
            let mut block_buffer = Vec::with_capacity(1000);

            while let Some(block) = rx.recv().await {
                if block.calculate_hash_for_block() != block.hash {
                    continue;
                }

                block_buffer.push(block);

                if block_buffer.len() >= 1000 {
                    let blockchain = blockchain.write().await;
                    for block in block_buffer.drain(..) {
                        if let Err(_) = blockchain.save_block(&block).await {
                            continue;
                        }
                        processed_height.fetch_add(1, Ordering::Release);
                        main_pb.inc(1);
                    }
                }
            }

            if !block_buffer.is_empty() {
                let blockchain = blockchain.write().await;
                for block in block_buffer.drain(..) {
                    if let Err(_) = blockchain.save_block(&block).await {
                        continue;
                    }
                    processed_height.fetch_add(1, Ordering::Release);
                    main_pb.inc(1);
                }
            }
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
    };

    match tokio::time::timeout(SYNC_TIMEOUT, async {
        futures::future::join_all(download_tasks).await;
        drop(tx);
        process_handle.await??;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    })
    .await
    {
        Ok(Ok(_)) => {
            let final_height = processed_height.load(Ordering::Acquire);
            main_pb.finish_and_clear();
            status_pb.finish_with_message(format!("Fast sync complete at height {}", final_height));
            Ok(())
        }
        _ => {
            main_pb.finish_and_clear();
            status_pb.finish_with_message("Sync failed");
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Sync failed or timed out",
            )))
        }
    }
}

async fn handle_network_commands(
    command: &str,
    node: &Node,
    blockchain: &Arc<RwLock<Blockchain>>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Changed from Result<(), NodeError>
    let parts: Vec<&str> = command.split_whitespace().collect();
    let cmd = parts.get(0).map(|s| *s).unwrap_or("");

    match cmd {
        "--status" | "-s" => {
            let mut stdout = StandardStream::stdout(ColorChoice::Always);
            let mut header_style = ColorSpec::new();
            header_style.set_fg(Some(Color::Cyan)).set_bold(true);

            stdout.set_color(&header_style)?;
            writeln!(stdout, "\nNetwork Status")?;
            stdout.reset()?;
            println!("───────────────────");

            let peers = node.peers.read().await;

            // Calculate uptime
            let uptime_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(node.start_time);

            let uptime_days = uptime_secs / 86400;
            let uptime_hours = (uptime_secs % 86400) / 3600;
            let uptime_minutes = (uptime_secs % 3600) / 60;

            println!(
                "Connection Status: {}",
                if peers.len() > 0 { "Online" } else { "Offline" }
            );
            println!("Connected Peers: {}", peers.len());
            println!("Node Address: {}", node.get_public_key());
            println!("P2P Port: {}", DEFAULT_PORT);
            println!(
                "Uptime: {}d {}h {}m",
                uptime_days, uptime_hours, uptime_minutes
            );
            println!("");
        }

        "--connect" => {
            if let Some(addr) = parts.get(1) {
                let test_mode = parts.get(2).map(|s| *s == "--test").unwrap_or(false);
                println!("\nStarting connection process");
                println!("Target: {}", addr);
                println!("Test mode: {}", test_mode);
                println!("Local bind address: {}", node.bind_addr);

                match addr.parse::<SocketAddr>() {
                    Ok(socket_addr) => {
                        println!("✓ Address parsed successfully: {}", socket_addr);

                        if !test_mode && socket_addr == node.bind_addr {
                            println!("Attempted self-connection without test mode");
                            println!("Use --test flag to allow self-connection");
                            return Ok(());
                        }

                        let mut attempts = 0;
                        const MAX_ATTEMPTS: u32 = 3;

                        while attempts < MAX_ATTEMPTS {
                            attempts += 1;
                            println!("\nConnection attempt {}/{}", attempts, MAX_ATTEMPTS);

                            // First try TCP connection
                            println!("Step 1: Testing TCP connection...");
                            match TcpStream::connect(socket_addr).await {
                                Ok(_) => println!("✓ TCP connection successful"),
                                Err(e) => {
                                    println!("✗ TCP connection failed: {}", e);
                                    println!(
                                        "  - Check if port {} is open on target",
                                        socket_addr.port()
                                    );
                                    println!("  - Verify no firewall blocking connection");
                                    println!("  - Ensure target node is running");
                                    tokio::time::sleep(Duration::from_secs(2)).await;
                                    continue;
                                }
                            }

                            // Try full peer verification
                            println!("Step 2: Attempting peer verification...");
                            match tokio::time::timeout(
                                Duration::from_secs(10),
                                node.verify_peer(socket_addr),
                            )
                            .await
                            {
                                Ok(Ok(_)) => {
                                    println!("✓ Peer verification successful!");
                                    println!("✓ Successfully connected to {}", addr);

                                    // Show peer details
                                    let peers = node.peers.read().await;
                                    if let Some(peer_info) = peers.get(&socket_addr) {
                                        println!("\nPeer Details:");
                                        println!("Version: {}", peer_info.version);
                                        println!("Blocks: {}", peer_info.blocks);
                                        println!("Latency: {}ms", peer_info.latency);
                                    }

                                    println!("\nAttempting initial sync...");
                                    if let Err(e) = handle_chain_sync(&node).await {
                                        println!("Initial sync failed: {}", e);
                                    } else {
                                        println!("✓ Initial sync completed");
                                    }
                                    return Ok(());
                                }
                                Ok(Err(e)) => {
                                    println!("✗ Peer verification failed:");
                                    println!("  Error: {}", e);
                                    println!("  - Check if both nodes are running same version");
                                    println!("  - Verify network IDs match");
                                    println!("  - Check for failed handshake");
                                }
                                Err(_) => {
                                    println!("✗ Peer verification timed out");
                                    println!("  - Handshake may have stalled");
                                    println!("  - Network might be congested");
                                }
                            }

                            if attempts < MAX_ATTEMPTS {
                                println!("\n⟳ Retrying in 2 seconds...");
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                        }

                        println!("\n✗ Connection failed after {} attempts", MAX_ATTEMPTS);
                        println!("Try running with --test flag for local connections");
                        println!("Check target node is running and accessible");
                        return Err(Box::new(NodeError::Network(
                            "Connection failed".to_string(),
                        )));
                    }
                    Err(e) => {
                        println!("✗ Failed to parse address: {}", e);
                        println!("Format should be: <ip>:<port>");
                        println!("Example: --connect 192.168.1.100:7177");
                        return Err(Box::new(NodeError::Network(
                            "Invalid address format".to_string(),
                        )));
                    }
                }
            } else {
                println!("Usage: --connect <ip:port> [--test]");
                println!("Example: --connect 192.168.1.100:7177");
                println!("Add --test to allow self-connection for testing");
                return Ok(());
            }
        }

        "--discover" => {
            let pb = ProgressBar::new_spinner();
            pb.set_message("Discovering network nodes...");

            // Use the existing peer count as baseline
            let initial_peers = node.peers.read().await.len();

            // Call the comprehensive discover_network_nodes implementation
            match node.discover_network_nodes().await {
                Ok(_) => {
                    // Get final peer count to show progress
                    let peers = node.peers.read().await;
                    let final_peers = peers.len();
                    let new_peers = final_peers.saturating_sub(initial_peers);

                    // Show detailed peer information
                    if new_peers > 0 {
                        let mut connected_subnets = HashSet::new();
                        for (addr, info) in peers.iter() {
                            if let Some(subnet) = info.get_subnet(addr.ip()) {
                                connected_subnets.insert(subnet);
                            }
                        }

                        pb.finish_with_message(format!(
                            "Found {} new peers (total: {}) across {} subnets",
                            new_peers,
                            final_peers,
                            connected_subnets.len()
                        ));

                        // If we have peers, try to sync
                        if final_peers > 0 {
                            if let Err(e) = handle_chain_sync(&node).await {
                                warn!("Initial sync with discovered peers failed: {}", e);
                            }
                        }
                    } else {
                        pb.finish_with_message(format!(
                            "No new peers found. Connected to {} peers",
                            final_peers
                        ));
                    }
                }
                Err(e) => {
                    pb.finish_with_message(format!("Peer discovery failed: {}", e));
                    return Err(Box::new(e));
                }
            }
        }

        "--getpeers" => {
            let peers = node.peers.read().await;
            println!("\nConnected Peers");
            println!("---------------");

            if peers.is_empty() {
                println!("No peers connected");
                println!("Try: --sync or --connect <ip:port>");
            } else {
                for (addr, info) in peers.iter() {
                    let last_seen = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .saturating_sub(info.last_seen);

                    println!(
                        "{} (latency: {}ms, last seen: {}s ago)",
                        addr, info.latency, last_seen
                    );
                }
            }
        }

        "--sync" => {
            let pb = ProgressBar::new_spinner();
            pb.set_message("Synchronizing with network...");

            // First try to discover peers if needed
            let peers = node.peers.read().await;
            if peers.len() < 3 {
                drop(peers); // Release the lock
                if let Err(e) = node.discover_network_nodes().await {
                    warn!("Peer discovery during sync failed: {}", e);
                }
            }

            match handle_chain_sync(&node).await {
                Ok(_) => {
                    let blockchain = blockchain.read().await;
                    pb.finish_with_message(format!(
                        "Sync completed. Current height: {}",
                        blockchain.get_block_count()
                    ));
                }
                Err(e) => {
                    pb.finish_with_message(format!("Sync failed: {}", e));
                    return Err(e);
                }
            }
        }

        _ => {
            println!("Available commands:");
            println!("--status    (-s)      Show network status");
            println!("--sync              Start blockchain sync");
            println!("--sync --force      Force full resync");
            println!("--connect <ip:port> Connect to specific node");
            println!("--getpeers          List connected peers");
            println!("--discover          Search for nodes");
        }
    }

    Ok(())
}

// Boot sequence
fn print_step(message: &str, step: &str, color: Color) {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let mut color_spec = ColorSpec::new();
    color_spec.set_fg(Some(color)).set_bold(true);

    // Print the step
    stdout.set_color(&color_spec).unwrap();
    writeln!(&mut stdout, "{} {}", step, message).unwrap();
    stdout.reset().unwrap();
}

// ASCII Art - version
fn interpolate_channel(start: u8, end: u8, t: f32) -> u8 {
    (start as f32 + t * (end as f32 - start as f32)) as u8
}

fn interpolate_color(start: (u8, u8, u8), end: (u8, u8, u8), t: f32) -> Color {
    Color::Rgb(
        interpolate_channel(start.0, end.0, t),
        interpolate_channel(start.1, end.1, t),
        interpolate_channel(start.2, end.2, t),
    )
}

fn print_ascii_intro() {
    // Replace with your ASCII art
    let ascii_art = r#"

                        -++-    -++-                                  alphanumeric beta 7.2.1
                       -+++.   .+++
                .++++++++++++++++++++++-                              Architecture: Rust
                -####++++#####++++#####+                              Algorithm: SHA-256
                    -++++-   --+++.                                              BLAKE3
             .++++++++++++++++++++++++-                               Database: sled
             +#####+++######++++######+                               Encryption: Argon2
                 -+++++----++++-                                      Quantum DSS: CRYSTALS-dilithium
                .+++++.  .-+++-
                 ++++     ++++.
"#;

    let start_color = (42, 93, 253); // White
    let end_color = (190, 252, 233); // Neon Green

    let lines: Vec<&str> = ascii_art.split('\n').collect();
    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    for (line_idx, line) in lines.iter().enumerate() {
        let t = line_idx as f32 / (lines.len() as f32 - 1.0); // Normalize between 0 and 1
        let line_color = interpolate_color(start_color, end_color, t);

        let mut color_spec = ColorSpec::new();
        color_spec.set_fg(Some(line_color));

        stdout.set_color(&color_spec).unwrap();
        writeln!(&mut stdout, "{}", line).unwrap();
    }

    stdout.reset().unwrap();
}
