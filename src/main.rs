use dashmap::DashMap;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use inquire::{Password, PasswordDisplayMode};
use log::{debug, error, warn};
use rand::Rng;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::error::Error;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tokio::fs;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, RwLock};

use std::collections::HashSet;

use crate::a9::{
    blockchain::{Block, Blockchain, RateLimiter, Transaction},
    bpos::{BPoSSentinel, ValidatorTier},
    mgmt::{Mgmt, WalletKeyData},
    node::{Node, NodeError, DEFAULT_PORT},
    oracle::DifficultyOracle,
    progpow::{Miner, MiningManager},
    whisper::WhisperModule,
};
use crate::config::AppConfig;
mod a9;
mod config;

const KEY_FILE_PATH: &str = "private.key";
const DEFAULT_BOOTSTRAP_URL: &str = "https://alphanumeric.blue/bootstrap/blockchain.db.zip";
const INSTANCE_LOCK_PATH: &str = ".alphanumeric.instance.lock";

// Modify result to take only one type parameter
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

impl std::fmt::Display for Blockchain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Blockchain {{ ... }}")
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    // Initialize logging with ERROR level during startup to avoid UI interference
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Error)
        .init();

    print_ascii_intro();

    // Load configuration from environment variables
    let config = AppConfig::from_env();
    config.log_config();

    let pb = ProgressBar::new(9);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("\r{spinner:.green} [{bar:40.cyan/blue}] {msg}")
            .progress_chars("█▓░"),
    );

    let db_path = config.database.path.clone();
    let local = tokio::task::LocalSet::new();
    local.run_until(async move {
        // Database init
        pb.set_message("Checking bootstrap snapshot...");
        if let Err(e) = ensure_bootstrap_db(&db_path).await {
            error!("Bootstrap failed: {}", e);
        }
        pb.set_message("Initializing database...");
        ensure_instance_lock()?;
        ensure_db_lock(&db_path)?;
        let db = match sled::Config::new()
            .path(&db_path)
            .flush_every_ms(Some(1000))
            .open()
        {
            Ok(db) => db,
            Err(e) => {
                let is_corruption = matches!(e, sled::Error::Corruption { .. })
                    || e.to_string().contains("Corruption");
                if is_corruption {
                    warn!("Sled reported corruption. Attempting snapshot cleanup...");
                    if let Err(clean_err) = cleanup_sled_snapshots(&db_path) {
                        error!("Snapshot cleanup failed: {}", clean_err);
                    }
                    match sled::Config::new()
                        .path(&db_path)
                        .flush_every_ms(Some(1000))
                        .open()
                    {
                        Ok(db) => db,
                        Err(reopen_err) => {
                            warn!("Reopen failed after cleanup: {}", reopen_err);
                            let quarantined = quarantine_db(&db_path);
                            if let Err(q_err) = quarantined {
                                error!("Failed to quarantine DB: {}", q_err);
                                return Err(Box::new(reopen_err) as Box<dyn Error>);
                            }
                            sled::Config::new()
                                .path(&db_path)
                                .flush_every_ms(Some(1000))
                                .open()
                                .map_err(|fresh_err| {
                                error!("Failed to open fresh DB: {}", fresh_err);
                                Box::new(fresh_err) as Box<dyn Error>
                            })?
                        }
                    }
                } else {
                    error!("Error opening database: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            }
        };
        {
            let db_for_signal = db.clone();
            let lock_path = format!("{}.lock", &db_path);
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = db_for_signal.flush();
                let _ = remove_db_lock(&lock_path);
                let _ = remove_instance_lock();
                eprintln!("Shutting down cleanly...");
                std::process::exit(0);
            });
        }
        {
            let db_for_flush = db.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    let _ = db_for_flush.flush();
                }
            });
        }
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
        let (transaction_fee, mining_reward, _difficulty_adjustment_interval, block_time) = {
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
        let key_pair_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| format!("Failed to generate key pair: {}", e))?;
        pb.inc(1);

        // Then create the node (single instance)
        pb.set_message("Creating node...");
        let bind_ip = if std::env::var("ALPHANUMERIC_BIND_IP").is_ok() {
            config.network.bind_ip
        } else {
            match Node::get_bind_address() {
                Ok(ip) => ip,
                Err(e) => {
                    error!("Failed to determine bind address: {}", e);
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                }
            }
        };
        let bind_addr = Some(SocketAddr::new(bind_ip, config.network.port));

        let node = match Node::new(
            Arc::new(db.clone()),
            blockchain.clone(),
            key_pair_pkcs8.as_ref().to_vec(),
            bind_addr,
            config.network.velocity_enabled,
            config.network.max_peers,
            config.network.max_connections,
        )
        .await {
            Ok(node) => Arc::new(node),
            Err(e) => {
                error!("Failed to create node: {}", e);
                return Err(e.into());
            }
        };

        pb.inc(1);

        // Complete the progress bar and clear the line
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

                                // Attempt immediate network recovery
                                if let Err(e) = node.discover_network_nodes().await {
                                    error!("Network rediscovery after wake failed: {}", e);
                                }
                            }
                            activity_time.store(now, Ordering::Release);

                            // Network state check
                            let peers = node.peers.read().await;
                            let active_peers = peers.len();

                            if active_peers > 0 {
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
                                        match u32::try_from(blockchain.get_latest_block_index()) {
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
        let header_sentinel = node.header_sentinel().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "Missing header sentinel")
        })?;
        let staking_node = Arc::new(RwLock::new(BPoSSentinel::new(
            blockchain.clone(),
            Arc::clone(&node),
            header_sentinel,
        )));

        // Whisper
        let whisper_module = Arc::new(RwLock::new(WhisperModule::new_with_db(Arc::new(db.clone()))));
        let wallet_addresses: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(
            wallets.values().map(|w| w.address.clone()).collect(),
        ));

        {
            let whisper_module = whisper_module.clone();
            let wallet_addresses = wallet_addresses.clone();
            let blockchain = blockchain.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(15));
                loop {
                    interval.tick().await;
                    let addresses = wallet_addresses.read().await.clone();
                    if addresses.is_empty() {
                        continue;
                    }
                    let blockchain_guard = blockchain.read().await;
                    let whisper = whisper_module.read().await;
                    for addr in &addresses {
                        let _ = whisper.sync_index_for_wallet(addr, &blockchain_guard).await;
                    }
                }
            });
        }

        // Mining params
        pb.set_message("Setting up mining parameters...");

        let miner = Miner::new(blockchain.clone(), mining_manager);
        pb.inc(1);

        // Initialize BPoS sentinel at startup
        {
            let sentinel = staking_node.write().await;
            if let Err(e) = sentinel.initialize().await {
                error!("Failed to initialize staking sentinel: {}", e);
            }
        }

        loop {
            let mut stdout = StandardStream::stdout(ColorChoice::Always);
            let mut color_spec = ColorSpec::new();
            color_spec.set_fg(Some(Color::White)).set_bold(true);
            let _ = stdout.set_color(&color_spec);
            print!("αlphanumeric:");
            let _ = stdout.reset();
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

    // Initialize sentinel
    {
        let sentinel = staking_node.write().await;
        if let Err(e) = sentinel.initialize().await {
            error!("Failed to initialize staking sentinel: {}", e);
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
    {
        let node_id = node.id().to_string();
        if let Ok(metrics) = sentinel.get_node_metrics(&node_id).await {
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
        let active_nodes = health.active_nodes.max(active_peers);

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
    writeln!(
        stdout,
        "Height:            {}",
        blockchain_guard.get_latest_block_index()
    )?;
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
{
    let mut addresses = wallet_addresses.write().await;
    *addresses = wallets.values().map(|w| w.address.clone()).collect();
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
    // No wallet registry needed - transactions are self-contained with public keys
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

async fn handle_chain_sync(
    node: &Node,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const PARALLEL_BATCH_SIZE: usize = 16384; // Reduced batch size for better reliability
    const MAX_PARALLEL_DOWNLOADS: usize = 64;
    const QUEUE_SIZE: usize = 16384;
    const MAX_PEER_LATENCY: u64 = 200; // Increased latency threshold
    const SYNC_TIMEOUT: Duration = Duration::from_secs(600); // Increased timeout
    const BLOCK_REQUEST_TIMEOUT: Duration = Duration::from_secs(60); // Timeout for individual requests
    const RETRY_DELAY_BASE: u64 = 250; // Base delay in ms before retry
    const MAX_RETRIES: u32 = 5; // Maximum number of retries per batch

    let mp = MultiProgress::new();
    let status_pb = mp.add(ProgressBar::new_spinner());
    status_pb.set_message("Finding fastest network peers...");

    // IMPROVEMENT: Better peer selection with health metrics
    let network_health = node.network_health.read().await;
    let target_peers = ((network_health.active_nodes / 4) as usize).clamp(3, MAX_PARALLEL_DOWNLOADS);
    drop(network_health);

    // Try to discover peers if we don't have enough
    let peer_count = node.peers.read().await.len();
    if peer_count < 5 {
        status_pb.set_message("Discovering more network peers...");
        match tokio::time::timeout(Duration::from_secs(10), node.discover_network_nodes()).await {
            Ok(Ok(_)) => {
                status_pb.set_message(format!("Found new peers, now at {}", node.peers.read().await.len()));
            }
            _ => {
                status_pb.set_message("Continuing with existing peers");
            }
        }
    }

    // IMPROVEMENT: Better peer selection with health checks and rating
    let peers = node.peers.read().await;
    let mut sync_peers: Vec<_> = peers
        .iter()
        .filter(|(_, info)| {
            info.latency < MAX_PEER_LATENCY && 
            // Avoid peers we haven't seen in 5 minutes
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(info.last_seen) < 300
        })
        .map(|(addr, info)| (*addr, info.blocks, info.latency))
        .collect();
    drop(peers);

    if sync_peers.is_empty() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "No peers available for sync"
        )));
    }

    // IMPROVEMENT: Better peer sorting - prioritize higher blocks AND lower latency
    sync_peers.sort_by(|a, b| {
        // First by block height (descending)
        let height_cmp = b.1.cmp(&a.1);
        if height_cmp != std::cmp::Ordering::Equal {
            return height_cmp;
        }
        // Then by latency (ascending)
        a.2.cmp(&b.2)
    });

    // Get target height from best peers
    let target_height = sync_peers
        .iter()
        .take(3) // Use consensus from top 3 peers
        .map(|(_, height, _)| *height)
        .max()
        .unwrap_or(0);

    let local_height = {
        let blockchain = node.blockchain.read().await;
        blockchain.get_latest_block_index() as u32
    };

    if target_height <= local_height {
        status_pb.finish_with_message(format!("Already at current height: {}", local_height));
        return Ok(());
    }

    // Setup progress bars with better info
    let blocks_remaining = target_height - local_height;
    let main_pb = mp.add(ProgressBar::new(blocks_remaining as u64));
    main_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} blocks ({eta}) {msg}")
            .progress_chars("█▓░"),
    );
    main_pb.set_message("Syncing blockchain...");

    // IMPROVEMENT: Sort peers by block height AND latency for better reliability
    let mut sync_peers: Vec<_> = sync_peers
        .into_iter()
        .map(|(addr, height, latency)| (addr, height, latency))
        .collect();
    
    sync_peers.sort_by(|a, b| {
        let a_score = a.1 as f64 * 0.8 - a.2 as f64 * 0.2; // 80% height, 20% latency
        let b_score = b.1 as f64 * 0.8 - b.2 as f64 * 0.2;
        b_score.partial_cmp(&a_score).unwrap_or(std::cmp::Ordering::Equal)
    });

    // Setup sync channels with better buffer management
    let (tx, mut rx) = mpsc::channel(QUEUE_SIZE);
    let current_height = Arc::new(AtomicU32::new(local_height));
    let processed_height = Arc::new(AtomicU32::new(local_height));
    let active_requests = Arc::new(AtomicU32::new(0));
    let failed_batches = Arc::new(DashMap::new());

    // IMPROVEMENT: More resilient download tasks with retry logic
let download_tasks: Vec<_> = sync_peers
    .iter()
    .take(target_peers)
    .map(|(peer, _, _)| {
        let tx = tx.clone();
        let current_height = Arc::clone(&current_height);
        let failed_batches = Arc::clone(&failed_batches);
        let active_requests = Arc::clone(&active_requests);
        let node = node.clone();
        let peer = *peer;

        tokio::spawn(async move {
            let mut consecutive_failures = 0;

            'outer: while current_height.load(Ordering::Acquire) < target_height {
                // Get a batch to download
                let curr_height = current_height.load(Ordering::Acquire);
                if curr_height >= target_height {
                    break;
                }

                let batch_end = (curr_height + PARALLEL_BATCH_SIZE as u32).min(target_height);
                let batch_key = format!("{}-{}", curr_height, batch_end);
                
                // Check if this batch has already failed too many times
                if let Some(failures) = failed_batches.get(&batch_key) {
                    if *failures > MAX_RETRIES {
                        // Skip this batch, it's been tried too many times
                        current_height.fetch_add(batch_end - curr_height, Ordering::Release);
                        continue;
                    }
                }

                // Track active requests for load balancing
                active_requests.fetch_add(1, Ordering::SeqCst);

                // FIX: Create RNG here - don't keep it across awaits
                if consecutive_failures > 0 {
                    // Create new RNG each time to avoid Send issues
                    let backoff = RETRY_DELAY_BASE * (1 << consecutive_failures.min(5));
                    let jitter = rand::thread_rng().gen_range(0..=backoff/4);
                    tokio::time::sleep(Duration::from_millis(backoff + jitter)).await;
                }

                // Proper timeout and error handling
                let result = tokio::time::timeout(
                    BLOCK_REQUEST_TIMEOUT,
                    node.request_blocks(peer, curr_height, batch_end)
                ).await;

                match result {
                    Ok(Ok(blocks)) => {
                        let mut sent_count = 0;
                        for block in blocks {
                            // Validate hash before sending to process queue
                            if block.index > curr_height && 
                               block.index <= batch_end &&
                               block.hash == block.calculate_hash_for_block() {
                                match tx.send((peer, block)).await {
                                    Ok(_) => sent_count += 1,
                                    Err(_) => break 'outer, // Channel closed
                                }
                            }
                        }

                        if sent_count > 0 {
                            // Reset failure counter on success
                            consecutive_failures = 0;
                            current_height.fetch_add(batch_end - curr_height, Ordering::Release);
                        } else {
                            // Got a response but no valid blocks
                            consecutive_failures += 1;
                            failed_batches.entry(batch_key.clone())
                                .and_modify(|e| *e += 1)
                                .or_insert(1);
                        }
                    }
                    _ => {
                        // Request failed or timed out
                        consecutive_failures += 1;
                        failed_batches.entry(batch_key.clone())
                            .and_modify(|e| *e += 1)
                            .or_insert(1);
                        
                        // If we've failed too many times consecutively, back off this peer
                        if consecutive_failures > 3 {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                }

                active_requests.fetch_sub(1, Ordering::SeqCst);
            }

            // Task completed
            Ok::<(), String>(())
        })
    })
    .collect();

    // IMPROVEMENT: Processing task with batching for efficiency
    let process_handle = {
        let blockchain = Arc::clone(&node.blockchain);
        let verifier_node = node.clone();
        let processed_height = Arc::clone(&processed_height);
        let main_pb = main_pb.clone();
        let failed_batches = Arc::clone(&failed_batches);

        tokio::spawn(async move {
            // Use a buffer to batch process blocks
            let mut block_buffer: Vec<(SocketAddr, Block)> = Vec::with_capacity(1000);
            let mut last_update = Instant::now();
            let mut last_save_height = local_height;
            
            while let Some((peer, block)) = rx.recv().await {
                // Basic validation again for safety
                if block.calculate_hash_for_block() != block.hash {
                    continue;
                }

                // Add to buffer
                block_buffer.push((peer, block));

                // Batch process when buffer gets large enough or every second
                if block_buffer.len() >= 1000 || last_update.elapsed() > Duration::from_secs(1) {
                    let blockchain = blockchain.write().await;
                    
                    // Sort blocks by index before processing
                    block_buffer.sort_by_key(|(_, b)| b.index);
                    
                    let mut saved_count = 0;
                    for (peer, block) in block_buffer.drain(..) {
                        // Skip blocks we already have
                        if block.index <= last_save_height {
                            continue;
                        }
                        
                        match verifier_node.verify_block_with_witness(&block, Some(peer)).await {
                            Ok(true) => {}
                            Ok(false) => continue,
                            Err(_) => continue,
                        }

                        if let Err(e) = blockchain.save_block(&block).await {
                            // Log error but continue with next blocks
                            println!("Error saving block {}: {}", block.index, e);
                            
                            // Mark this batch as failed so it can be retried
                            let batch_key = format!("{}-{}", 
                                (block.index / PARALLEL_BATCH_SIZE as u32) * PARALLEL_BATCH_SIZE as u32,
                                ((block.index / PARALLEL_BATCH_SIZE as u32) + 1) * PARALLEL_BATCH_SIZE as u32);
                            
                            failed_batches.entry(batch_key)
                                .and_modify(|e| *e += 1)
                                .or_insert(1);
                            
                            continue;
                        }
                        
                        last_save_height = block.index;
                        saved_count += 1;
                        processed_height.store(block.index, Ordering::Release);
                        main_pb.inc(1);
                    }
                    
                    if saved_count > 0 {
                        main_pb.set_message(format!("Saved to height {}", last_save_height));
                    }
                    
                    last_update = Instant::now();
                }
            }
            
            // Process any remaining blocks
            if !block_buffer.is_empty() {
                let blockchain = blockchain.write().await;
                
                // Sort blocks by index before final processing
                block_buffer.sort_by_key(|(_, b)| b.index);
                
                for (peer, block) in block_buffer.drain(..) {
                    if block.index <= last_save_height {
                        continue;
                    }

                    match verifier_node.verify_block_with_witness(&block, Some(peer)).await {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(_) => continue,
                    }
                    
                    if let Err(e) = blockchain.save_block(&block).await {
                        println!("Error saving final block {}: {}", block.index, e);
                        continue;
                    }
                    
                    processed_height.store(block.index, Ordering::Release);
                    main_pb.inc(1);
                }
            }
            
            Ok::<(), String>(())
        })
    };

    // IMPROVEMENT: Wait for completion with more robust error handling
    match tokio::time::timeout(SYNC_TIMEOUT, async {
        // Monitor progress and handle stalled sync
        let monitor_handle = {
            let current_height = Arc::clone(&current_height);
            let processed_height = Arc::clone(&processed_height);
            let active_requests = Arc::clone(&active_requests);
            let main_pb = main_pb.clone();
            let status_pb = status_pb.clone();
            let tx = tx.clone();
            let node = node.clone();
            
            tokio::spawn(async move {
                let mut last_progress = Instant::now();
                let mut last_processed = processed_height.load(Ordering::Acquire);
                
                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    
                    let now_processed = processed_height.load(Ordering::Acquire);
                    let active = active_requests.load(Ordering::Acquire);
                    
                    // Update status message
                    status_pb.set_message(format!(
                        "Progress: {}/{} (active: {})", 
                        now_processed - local_height,
                        target_height - local_height,
                        active
                    ));
                    
                    // Check for progress
                    if now_processed > last_processed {
                        last_progress = Instant::now();
                        last_processed = now_processed;
                    } else if last_progress.elapsed() > Duration::from_secs(60) {
                        // No progress for 60 seconds - try to recover
                        status_pb.set_message("Sync stalled - attempting recovery");
                        
                        // Try to find a new peer to get blocks from
                        if let Ok(peers) = node.discover_network_nodes().await {
                            let peers = node.peers.read().await;
                            if let Some((addr, _)) = peers.iter()
                                .filter(|(_, p)| p.blocks > now_processed)
                                .min_by_key(|(_, p)| p.latency) {
                                    
                                // Request blocks directly from this peer
                                let start = now_processed;
                                let end = (start + 100).min(target_height);
                                
                                if let Ok(blocks) = node.request_blocks(*addr, start, end).await {
                                    // Send blocks to processing queue
                                    for block in blocks {
                                        let _ = tx.send((*addr, block)).await;
                                    }
                                    status_pb.set_message("Recovery successful - continuing sync");
                                }
                            }
                        }
                        
                        // Reset timer so we don't retry too often
                        last_progress = Instant::now();
                    }
                    
                    // Check if we're done
                    if now_processed >= target_height || 
                       current_height.load(Ordering::Acquire) >= target_height {
                        break;
                    }
                }
            })
        };
        
        // Only collect results, don't propagate individual task errors
        futures::future::join_all(download_tasks).await;
        drop(tx); // Drop sender to signal process_handle to finish
        
        // Wait for processor and monitor to finish
        let _ = tokio::join!(process_handle, monitor_handle);
        
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await
    {
        Ok(Ok(_)) => {
            let final_height = processed_height.load(Ordering::Acquire);
            main_pb.finish_with_message(format!("Sync complete at height {}", final_height));
            status_pb.finish_and_clear();
            Ok(())
        }
        _ => {
            // Even with timeout, we still made progress
            let final_height = processed_height.load(Ordering::Acquire);
            let progress_pct = (final_height - local_height) as f64 / (target_height - local_height) as f64 * 100.0;
            
            main_pb.finish_with_message(format!(
                "Partial sync: {} blocks ({:.1}%) to height {}", 
                final_height - local_height,
                progress_pct,
                final_height
            ));
            status_pb.finish_with_message("Sync timed out but made partial progress");
            
            // Return success if we made significant progress (>80%)
            if progress_pct > 80.0 {
                Ok(())
            } else {
                Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("Sync timed out at {:.1}% completion", progress_pct)
                )))
            }
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
                        blockchain.get_latest_block_index()
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
    let _ = stdout.set_color(&color_spec);
    let _ = writeln!(&mut stdout, "{} {}", step, message);
    let _ = stdout.reset();
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

                        -++-    -++-                                  alphanumeric beta 7.3.3
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

        let _ = stdout.set_color(&color_spec);
        let _ = writeln!(&mut stdout, "{}", line);
    }

    let _ = stdout.reset();
}

fn cleanup_sled_snapshots(path: &str) -> std::io::Result<()> {
    let dir = std::path::Path::new(path);
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name.starts_with("snap.") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

fn quarantine_db(path: &str) -> std::io::Result<()> {
    let dir = std::path::Path::new(path);
    if !dir.exists() {
        return Ok(());
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let quarantine_path = format!("{}.corrupt.{}", path, ts);
    std::fs::rename(dir, quarantine_path)?;
    Ok(())
}

fn ensure_db_lock(path: &str) -> std::io::Result<()> {
    let lock_path = format!("{}.lock", path);
    ensure_pid_lock(&lock_path, "ALPHANUMERIC_IGNORE_DB_LOCK")
}

fn ensure_instance_lock() -> std::io::Result<()> {
    ensure_pid_lock(INSTANCE_LOCK_PATH, "ALPHANUMERIC_IGNORE_INSTANCE_LOCK")
}

fn remove_instance_lock() -> std::io::Result<()> {
    remove_db_lock(INSTANCE_LOCK_PATH)
}

fn ensure_pid_lock(lock_path: &str, ignore_env: &str) -> std::io::Result<()> {
    if std::path::Path::new(&lock_path).exists() {
        let allow = std::env::var(ignore_env)
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        if !allow {
            if let Ok(pid_str) = std::fs::read_to_string(&lock_path) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if !is_process_alive(pid) {
                        let _ = std::fs::remove_file(&lock_path);
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Database lock exists. Another instance may be running.",
                        ));
                    }
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Database lock exists. Another instance may be running.",
                    ));
                }
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Database lock exists. Another instance may be running.",
                ));
            }
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&lock_path)?;
    let pid = std::process::id();
    use std::io::Write;
    writeln!(file, "{}", pid)?;
    Ok(())
}

fn remove_db_lock(path: &str) -> std::io::Result<()> {
    if std::path::Path::new(path).exists() {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

fn is_process_alive(pid: u32) -> bool {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_processes();
    sys.process(sysinfo::Pid::from_u32(pid)).is_some()
}

async fn ensure_bootstrap_db(db_path: &str) -> Result<()> {
    let force_bootstrap = std::env::var("ALPHANUMERIC_FORCE_BOOTSTRAP")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !force_bootstrap && has_local_block_data(db_path) {
        return Ok(());
    }

    let url = std::env::var("ALPHANUMERIC_BOOTSTRAP_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BOOTSTRAP_URL.to_string());

    if url.is_empty() {
        return Ok(());
    }

    let required = std::env::var("ALPHANUMERIC_BOOTSTRAP_REQUIRED")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // Optional: signed manifest verification.
    // When ALPHANUMERIC_BOOTSTRAP_PUBLISHER_PUBKEY is set, we require a valid ed25519 signature
    // over the manifest returned by ALPHANUMERIC_BOOTSTRAP_MANIFEST_URL.
    let publisher_pubkey = std::env::var("ALPHANUMERIC_BOOTSTRAP_PUBLISHER_PUBKEY")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    #[derive(serde::Deserialize)]
    struct ManifestResponse {
        ok: bool,
        manifest: BootstrapManifest,
    }

    #[derive(serde::Deserialize, serde::Serialize, Clone)]
    struct BootstrapManifest {
        url: String,
        #[serde(default)]
        height: Option<u64>,
        #[serde(default)]
        tip_hash: Option<String>,
        #[serde(default)]
        sha256: Option<String>,
        #[serde(default)]
        publisher_pubkey: Option<String>,
        #[serde(default)]
        manifest_sig: Option<String>,
        updated_at: u64,
    }

    let mut download_url = url.clone();
    let mut expected_sha256: Option<String> = None;

    if let Some(expected_pubkey_hex) = publisher_pubkey {
        let manifest_url = std::env::var("ALPHANUMERIC_BOOTSTRAP_MANIFEST_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "https://alphanumeric.blue/api/bootstrap/manifest".to_string());

        let manifest_res = reqwest::get(&manifest_url).await;
        let manifest_res = match manifest_res {
            Ok(r) => r,
            Err(e) => {
                if required {
                    return Err(Box::new(e));
                }
                return Ok(());
            }
        };
        if !manifest_res.status().is_success() {
            if required {
                return Err(format!(
                    "Bootstrap manifest fetch failed: {}",
                    manifest_res.status()
                )
                .into());
            }
            return Ok(());
        }

        let body = manifest_res.bytes().await?;
        let parsed: ManifestResponse = serde_json::from_slice(&body)?;
        if !parsed.ok {
            if required {
                return Err("Bootstrap manifest response not ok".into());
            }
            return Ok(());
        }

        let manifest = parsed.manifest;
        if manifest.url.trim().is_empty() {
            if required {
                return Err("Bootstrap manifest missing url".into());
            }
            return Ok(());
        }

        // Signature check over the canonical JSON form of the manifest fields.
        // We sign exactly the JSON.stringify output used by the publisher (field insertion order).
        // To mirror that, we rebuild a minimal ordered struct and serialize it.
        #[derive(serde::Serialize)]
        struct SignedFields<'a> {
            url: &'a String,
            #[serde(skip_serializing_if = "Option::is_none")]
            height: &'a Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            tip_hash: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            sha256: &'a Option<String>,
            updated_at: u64,
        }

        let signed_fields = SignedFields {
            url: &manifest.url,
            height: &manifest.height,
            tip_hash: &manifest.tip_hash,
            sha256: &manifest.sha256,
            updated_at: manifest.updated_at,
        };
        let msg = serde_json::to_vec(&signed_fields)?;

        let sig_hex = manifest
            .manifest_sig
            .as_ref()
            .ok_or("Bootstrap manifest missing manifest_sig")?
            .trim()
            .to_string();
        let pub_hex = manifest
            .publisher_pubkey
            .as_ref()
            .ok_or("Bootstrap manifest missing publisher_pubkey")?
            .trim()
            .to_string();

        if pub_hex.to_ascii_lowercase() != expected_pubkey_hex.to_ascii_lowercase() {
            return Err("Bootstrap manifest publisher_pubkey does not match expected".into());
        }

        let sig_bytes = hex::decode(sig_hex).map_err(|_| "Bootstrap manifest sig hex invalid")?;
        let pub_bytes = hex::decode(pub_hex).map_err(|_| "Bootstrap manifest pubkey hex invalid")?;

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(
            pub_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "Bootstrap manifest pubkey wrong length")?,
        )
        .map_err(|_| "Bootstrap manifest pubkey parse failed")?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| "Bootstrap manifest sig parse failed")?;
        vk.verify_strict(&msg, &sig)
            .map_err(|_| "Bootstrap manifest signature invalid")?;

        download_url = manifest.url.clone();
        expected_sha256 = manifest.sha256.clone();
    }

    let res = reqwest::get(&download_url).await;
    let res = match res {
        Ok(r) => r,
        Err(e) => {
            if required {
                return Err(Box::new(e));
            }
            return Ok(());
        }
    };

    if !res.status().is_success() {
        if required {
            return Err(format!("Bootstrap download failed: {}", res.status()).into());
        }
        return Ok(());
    }

    let bytes = res.bytes().await?;

    // If a signed manifest provided sha256, enforce it. Otherwise fall back to optional env pin.
    if let Some(expected) = expected_sha256
        .as_deref()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
    {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let actual = hex::encode(hasher.finalize());
        if actual != expected {
            return Err(format!(
                "Bootstrap SHA-256 mismatch: expected {}, got {}",
                expected, actual
            )
            .into());
        }
    } else if let Ok(expected_hash) = std::env::var("ALPHANUMERIC_BOOTSTRAP_SHA256") {
        let expected = expected_hash.trim().to_ascii_lowercase();
        if !expected.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let actual = hex::encode(hasher.finalize());
            if actual != expected {
                return Err(format!(
                    "Bootstrap SHA-256 mismatch: expected {}, got {}",
                    expected, actual
                )
                .into());
            }
        }
    }
    let zip_path = format!("{}.zip", db_path);
    fs::write(&zip_path, &bytes).await?;

    if std::path::Path::new(db_path).exists() {
        let _ = std::fs::remove_dir_all(db_path);
    }

    let extract_path = db_path.to_string();
    let zip_path_clone = zip_path.clone();
    let extract_result = tokio::task::spawn_blocking(move || -> std::result::Result<(), String> {
        let file = std::fs::File::open(&zip_path_clone).map_err(|e| e.to_string())?;
        let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&extract_path).map_err(|e| e.to_string())?;
        let base_dir = std::fs::canonicalize(&extract_path).map_err(|e| e.to_string())?;
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| e.to_string())?;
            let entry_name = file.name();
            let relative = std::path::Path::new(entry_name);
            if relative.is_absolute()
                || relative
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(format!("Unsafe bootstrap archive entry path: {}", entry_name));
            }
            let outpath = std::path::Path::new(&extract_path).join(relative);
            if let Some(parent) = outpath.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let canonical_parent = std::fs::canonicalize(
                outpath
                    .parent()
                    .ok_or_else(|| "Invalid archive entry parent path".to_string())?,
            )
            .map_err(|e| e.to_string())?;
            if !canonical_parent.starts_with(&base_dir) {
                return Err(format!("Blocked bootstrap archive escape path: {}", entry_name));
            }
            if file.name().ends_with('/') {
                std::fs::create_dir_all(&outpath).map_err(|e| e.to_string())?;
            } else {
                let mut outfile = std::fs::File::create(&outpath).map_err(|e| e.to_string())?;
                std::io::copy(&mut file, &mut outfile).map_err(|e| e.to_string())?;
            }
        }
        std::fs::remove_file(&zip_path_clone).ok();
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?;

    if let Err(e) = extract_result {
        return Err(Box::<dyn Error>::from(e));
    }
    Ok(())
}

fn has_local_block_data(db_path: &str) -> bool {
    let path = std::path::Path::new(db_path);
    if !path.exists() || !path.is_dir() {
        return false;
    }

    // Only treat DB as initialized when at least one block key exists.
    // This avoids skipping bootstrap when sled created internal files only.
    let db = match sled::Config::new()
        .path(db_path)
        .flush_every_ms(Some(1000))
        .open()
    {
        Ok(db) => db,
        Err(_) => return false,
    };

    db.scan_prefix("block_").next().is_some()
}
