use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use inquire::{Password, PasswordDisplayMode};
use log::{debug, error, info, warn};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use rustyline::{error::ReadlineError, ColorMode, Config, DefaultEditor};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};

use std::collections::HashSet;
use std::path::Path;

#[cfg(feature = "bootstrap_publisher")]
use alphanumeric::a9::codec;
use alphanumeric::a9::{
    blockchain::{
        Block, Blockchain, RateLimiter, Transaction, CONSENSUS_HEADER_RULES_VERSION,
        MAX_BLOCK_FUTURE_TIME, MINT_CLIP, NETWORK_FEE, TARGET_BLOCK_TIME,
    },
    bpos::{BPoSSentinel, ValidatorTier},
    mgmt::{Mgmt, WalletKeyData},
    node::{
        force_rebootstrap_marker_path, rebootstrap_cooldown_path,
        rebootstrap_hard_cooldown_active,
        Converge, Node, NodeError, NodeRuntimeConfig, DEFAULT_PORT,
    },
    oracle::DifficultyOracle,
    miner::{Miner, MiningManager},
    whisper::WhisperModule,
};
use alphanumeric::config::AppConfig;

const KEY_FILE_PATH: &str = "private.key";
const NODE_IDENTITY_KEY_PATH: &str = "node_identity.key";
// Use the canonical host directly (avoid 307 redirects that can strip Authorization headers).
const BOOTSTRAP_MANIFEST_URL: &str = "https://alphanumeric.blue/api/bootstrap/manifest";
const DEFAULT_MAX_BOOTSTRAP_ZIP_BYTES: u64 = 1024 * 1024 * 1024;
const MIN_MAX_BOOTSTRAP_ZIP_BYTES: u64 = 1024 * 1024;
const MAX_MAX_BOOTSTRAP_ZIP_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const DEFAULT_MAX_UNVERIFIED_BOOTSTRAP_EXTRACT_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const MIN_MAX_UNVERIFIED_BOOTSTRAP_EXTRACT_BYTES: u64 = 1024 * 1024;
const MAX_MAX_UNVERIFIED_BOOTSTRAP_EXTRACT_BYTES: u64 = 1024 * 1024 * 1024 * 1024 * 1024;
const BOOTSTRAP_MIN_DISK_BUFFER_BYTES: u64 = 1024 * 1024 * 1024;
const PEERS_URL: &str = "https://alphanumeric.blue/api/peers?limit=50";
const TIP_URL: &str = "https://alphanumeric.blue/api/tip";
// Verified header-snapshot history: dense canonical (height, hash) anchors over
// the last ~24h, used by the boot reconcile to tell FORKED from merely BEHIND.
// limit=240 requests the gateway's full retention (the default response is a
// shallow display-sized page).
const SNAPSHOT_HISTORY_URL: &str = "https://alphanumeric.blue/api/snapshot-history?limit=240";
const BOOTSTRAP_PUBLISHER_PUBKEY: &str =
    "dc38ec5560c514d96d331244ae76a7ec7a47ece8d994ded09b6831164dd337b3";
const INSTANCE_LOCK_PATH: &str = ".alphanumeric.instance.lock";
#[cfg(feature = "bootstrap_publisher")]
const BOOTSTRAP_META_TREE: &str = "bootstrap_publish_meta";
#[cfg(feature = "bootstrap_publisher")]
const BOOTSTRAP_META_LAST_PUBLISH_AT: &[u8] = b"last_publish_at";
#[cfg(feature = "bootstrap_publisher")]
const BOOTSTRAP_META_LAST_PUBLISHED_HEIGHT: &[u8] = b"last_published_height";
#[cfg(feature = "bootstrap_publisher")]
const BOOTSTRAP_META_LAST_PUBLISHED_NETWORK_ID: &[u8] = b"last_published_network_id";

// Modify result to take only one type parameter
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(serde::Deserialize)]
struct BootstrapManifestResponse {
    ok: bool,
    manifest: BootstrapManifestPointer,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct BootstrapManifestPointer {
    url: String,
    #[serde(default)]
    network_id: Option<String>,
    #[serde(default)]
    height: Option<u64>,
    #[serde(default)]
    tip_hash: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    compressed_bytes: Option<u64>,
    #[serde(default)]
    extracted_bytes: Option<u64>,
    #[serde(default)]
    file_count: Option<u64>,
    publisher_pubkey: String,
    manifest_sig: String,
    updated_at: u64,
}

#[derive(Clone, Debug, Default)]
struct GatewayOverview {
    peers: Option<u64>,
    height: Option<u64>,
    verified: Option<bool>,
}

#[derive(serde::Serialize)]
struct BootstrapManifestSignedFields {
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tip_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compressed_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extracted_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_count: Option<u64>,
    updated_at: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BootstrapArchiveStats {
    extracted_bytes: u64,
    file_count: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct BootstrapArchiveExpectations {
    expected_extracted_bytes: Option<u64>,
    expected_file_count: Option<u64>,
    unverified_extract_limit: Option<u64>,
}

impl BootstrapManifestPointer {
    fn signed_fields(&self) -> BootstrapManifestSignedFields {
        BootstrapManifestSignedFields {
            url: self.url.clone(),
            network_id: self.network_id.clone(),
            height: self.height,
            tip_hash: self.tip_hash.clone(),
            sha256: self.sha256.clone(),
            compressed_bytes: self.compressed_bytes,
            extracted_bytes: self.extracted_bytes,
            file_count: self.file_count,
            updated_at: self.updated_at,
        }
    }
}

fn is_hex_with_len(value: &str, len: usize) -> bool {
    value.len() == len && value.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
}

fn launch_network_id_hex() -> Result<String> {
    let genesis = Blockchain::genesis_launch_block()?;
    Ok(hex::encode(genesis.hash))
}

fn verify_bootstrap_manifest(manifest: &BootstrapManifestPointer) -> Result<()> {
    verify_bootstrap_manifest_with_publisher(manifest, BOOTSTRAP_PUBLISHER_PUBKEY)
}

async fn fetch_gateway_overview() -> Option<GatewayOverview> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(2500))
        .build()
        .ok()?;

    let manifest_request = async {
        client
            .get(BOOTSTRAP_MANIFEST_URL)
            .send()
            .await
            .ok()?
            .json::<serde_json::Value>()
            .await
            .ok()
    };
    let peers_request = async {
        client
            .get(PEERS_URL)
            .send()
            .await
            .ok()?
            .json::<serde_json::Value>()
            .await
            .ok()
    };
    // The live tip beacon is the freshest canonical height (~1-2s); the bootstrap
    // manifest height lags by its publish cadence, so it is only a fallback.
    let tip_request = async {
        client
            .get(TIP_URL)
            .send()
            .await
            .ok()?
            .json::<serde_json::Value>()
            .await
            .ok()
    };
    let (manifest_body, peers_body, tip_body) =
        tokio::join!(manifest_request, peers_request, tip_request);

    let beacon_height = tip_body
        .as_ref()
        .filter(|body| body.get("ok").and_then(|v| v.as_bool()) == Some(true))
        .and_then(|body| body.get("height"))
        .and_then(|v| v.as_u64());
    let manifest_height = manifest_body
        .as_ref()
        .filter(|body| body.get("ok").and_then(|v| v.as_bool()) == Some(true))
        .and_then(|body| body.get("manifest"))
        .and_then(|manifest| manifest.get("height"))
        .and_then(|v| v.as_u64());
    let height = beacon_height.or(manifest_height);
    let peers = peers_body
        .as_ref()
        .filter(|body| body.get("ok").and_then(|v| v.as_bool()) == Some(true))
        .and_then(|body| body.get("count"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            peers_body
                .as_ref()
                .and_then(|body| body.get("peers"))
                .and_then(|v| v.as_array())
                .map(|peers| peers.len() as u64)
        });

    if height.is_none() && peers.is_none() {
        return None;
    }

    Some(GatewayOverview {
        peers,
        height,
        verified: height.map(|_| true),
    })
}

fn verify_bootstrap_manifest_with_publisher(
    manifest: &BootstrapManifestPointer,
    pinned_publisher_pubkey: &str,
) -> Result<()> {
    if manifest.url.trim().is_empty() {
        return Err("Bootstrap manifest URL is empty".into());
    }
    if !manifest.url.starts_with("https://") {
        return Err("Bootstrap manifest URL must use https".into());
    }

    let publisher_pubkey = manifest.publisher_pubkey.trim().to_ascii_lowercase();
    if publisher_pubkey != pinned_publisher_pubkey.trim().to_ascii_lowercase() {
        return Err("Bootstrap manifest publisher key is not pinned".into());
    }
    if !is_hex_with_len(&publisher_pubkey, 64) {
        return Err("Bootstrap manifest publisher key is malformed".into());
    }

    let Some(network_id) = manifest.network_id.as_deref() else {
        return Err("Bootstrap manifest is missing network id".into());
    };
    let network_id = network_id.trim().to_ascii_lowercase();
    if !is_hex_with_len(&network_id, 64) {
        return Err("Bootstrap manifest network id is malformed".into());
    }
    let expected_network_id = launch_network_id_hex()?;
    if network_id != expected_network_id {
        return Err(format!(
            "Bootstrap manifest network id mismatch: expected {}, got {}",
            expected_network_id, network_id
        )
        .into());
    }

    if manifest.height.is_none() {
        return Err("Bootstrap manifest is missing height".into());
    };
    let Some(tip_hash) = manifest.tip_hash.as_deref() else {
        return Err("Bootstrap manifest is missing tip hash".into());
    };
    if !is_hex_with_len(tip_hash.trim(), 64) {
        return Err("Bootstrap manifest tip hash is malformed".into());
    }

    let Some(sha256) = manifest.sha256.as_deref() else {
        return Err("Bootstrap manifest is missing SHA-256".into());
    };
    if !is_hex_with_len(sha256.trim(), 64) {
        return Err("Bootstrap manifest SHA-256 is malformed".into());
    }

    validate_bootstrap_manifest_size_fields(manifest)?;

    let sig_hex = manifest.manifest_sig.trim();
    if !is_hex_with_len(sig_hex, 128) {
        return Err("Bootstrap manifest signature is malformed".into());
    }

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pubkey_bytes: [u8; 32] = hex::decode(&publisher_pubkey)?
        .try_into()
        .map_err(|_| "Bootstrap publisher key must be 32 bytes")?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)?
        .try_into()
        .map_err(|_| "Bootstrap manifest signature must be 64 bytes")?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| format!("Bootstrap publisher key rejected: {}", e))?;
    let signature = Signature::from_bytes(&sig_bytes);
    let signed_payload = serde_json::to_vec(&manifest.signed_fields())?;

    verifying_key
        .verify(&signed_payload, &signature)
        .map_err(|e| format!("Bootstrap manifest signature verification failed: {}", e))?;

    Ok(())
}

fn validate_bootstrap_manifest_size_fields(manifest: &BootstrapManifestPointer) -> Result<()> {
    if matches!(manifest.compressed_bytes, Some(0)) {
        return Err("Bootstrap manifest compressed byte count must be nonzero".into());
    }
    if matches!(manifest.extracted_bytes, Some(0)) {
        return Err("Bootstrap manifest extracted byte count must be nonzero".into());
    }
    if matches!(manifest.file_count, Some(0)) {
        return Err("Bootstrap manifest file count must be nonzero".into());
    }
    Ok(())
}

fn bootstrap_block_index_from_key(key: &[u8]) -> Option<u32> {
    let key_str = std::str::from_utf8(key).ok()?;
    let index_str = key_str.strip_prefix("block_")?;
    index_str.parse::<u32>().ok()
}

fn verify_bootstrap_snapshot_tip(
    db_path: &str,
    expected_height: Option<u64>,
    expected_tip_hash: Option<&str>,
) -> Result<()> {
    let db = sled::Config::new()
        .path(db_path)
        .flush_every_ms(Some(1000))
        .open()?;

    let tip_index = db
        .scan_prefix("block_")
        .filter_map(|entry| {
            entry
                .ok()
                .and_then(|(k, _)| bootstrap_block_index_from_key(&k))
        })
        .max()
        .ok_or("Bootstrap snapshot does not contain block data")?;

    // The downloaded zip is already SHA-256-bound to the signed manifest (checked
    // before this runs), so its content is authentic canonical data no matter what.
    // The manifest's DECLARED height/tip_hash, though, can legitimately differ from
    // the blob's actual tip by a block or two: the publisher reads the height and
    // exports the DB at slightly different instants, and the manifest we read for
    // the reconcile decision may be one publish behind the blob we downloaded (the
    // "expected 12832, got 12833" abort that stranded catching-up clients). So these
    // checks tolerate a small skew — they still catch a truncated / wrong snapshot
    // (a large discrepancy) while never rejecting authentic, slightly-fresher data.
    const BOOTSTRAP_HEIGHT_SKEW: u64 = 16;
    if let Some(expected_height) = expected_height {
        let th = u64::from(tip_index);
        let below = expected_height.saturating_sub(th);
        let above = th.saturating_sub(expected_height);
        if below > BOOTSTRAP_HEIGHT_SKEW || above > BOOTSTRAP_HEIGHT_SKEW {
            return Err(format!(
                "Bootstrap snapshot height mismatch beyond tolerance: expected ~{}, got {}",
                expected_height, tip_index
            )
            .into());
        }
    }

    let key = format!("block_{}", tip_index);
    let raw = db
        .get(key.as_bytes())?
        .ok_or("Bootstrap snapshot tip block is missing")?;
    let block = Block::from_bytes(raw.as_ref())?;
    if block.calculate_hash_for_block() != block.hash {
        return Err("Bootstrap snapshot tip block hash is invalid".into());
    }

    // Only bind against the manifest tip hash when the heights match exactly; a
    // fresher snapshot has a different (newer) tip whose hash can't equal the
    // manifest's declared one — its own hash integrity (checked above) plus the
    // SHA-256 manifest binding are the authenticity guarantees there.
    if let (Some(expected_tip_hash), Some(expected_height)) = (expected_tip_hash, expected_height) {
        if u64::from(tip_index) == expected_height {
            let expected_tip_hash = expected_tip_hash.trim().to_ascii_lowercase();
            if !expected_tip_hash.is_empty() {
                let actual = hex::encode(block.hash);
                if actual != expected_tip_hash {
                    return Err(format!(
                        "Bootstrap snapshot tip mismatch: expected {}, got {}",
                        expected_tip_hash, actual
                    )
                    .into());
                }
            }
        }
    }

    drop(db);
    Ok(())
}

fn compute_consensus_fingerprint(blockchain: &Blockchain) -> (String, String) {
    let genesis_hash = blockchain
        .get_block(0)
        .map(|b| hex::encode(b.hash))
        .unwrap_or_else(|_| "missing_genesis".to_string());

    let descriptor = format!(
        "fee={:.12};reward={:.8};adj={};block_time={};target_block_time={};network_fee={:.8};mint_clip={:.8};genesis={};hdr_rules_ver={};hdr_future={}",
        blockchain.transaction_fee,
        blockchain.mining_reward,
        blockchain.difficulty_adjustment_interval,
        blockchain.block_time,
        TARGET_BLOCK_TIME,
        NETWORK_FEE,
        MINT_CLIP,
        genesis_hash,
        CONSENSUS_HEADER_RULES_VERSION,
        MAX_BLOCK_FUTURE_TIME
    );

    let mut hasher = Sha256::new();
    hasher.update(descriptor.as_bytes());
    let fingerprint = hex::encode(hasher.finalize());
    (descriptor, fingerprint)
}

/// App-thread stack. Windows gives the process main thread only 1MB (Unix: 8MB),
/// and debug builds use far larger frames — `cargo run` on Windows overflowed in
/// node creation (STATUS_STACK_OVERFLOW). #[tokio::main]'s block_on runs the
/// whole async body on that 1MB thread, so instead main() spawns the runtime on
/// a thread with an explicit stack. Reserve is address space, not committed
/// memory, so generous is free; this also makes every platform/toolchain behave
/// identically (no MSVC vs GNU linker-flag games).
const MAIN_THREAD_STACK_BYTES: usize = 32 * 1024 * 1024;
/// Tokio worker stacks (default 2MB) get the same debug-frame headroom.
const WORKER_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;

fn main() -> Result<()> {
    let app = std::thread::Builder::new()
        .name("alphanumeric-main".to_string())
        .stack_size(MAIN_THREAD_STACK_BYTES)
        .spawn(|| -> std::result::Result<(), String> {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(WORKER_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|e| format!("failed to start async runtime: {}", e))?;
            // Errors cross the thread join as strings because the error chain is
            // not Send (BlockchainError); the message is what main reported anyway.
            runtime.block_on(async_main()).map_err(|e| e.to_string())
        })
        .expect("failed to spawn app thread")
        .join();
    match app {
        Ok(Ok(())) => Ok(()),
        Ok(Err(message)) => Err(message.into()),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// True only for a bare arrow-up escape typed as the ENTIRE line in the raw-stdin
/// fallback. rustyline consumes arrow-up itself, so recall must never fire when an
/// editor is present; and matching a substring (an ESC byte or "[A" anywhere) would
/// let an arbitrary payment message/address silently re-fire the previous command,
/// which can be a funded create/whisper.
fn is_recall_line(command: &str, editor_present: bool) -> bool {
    !editor_present && matches!(command, "\u{1b}[A" | "\u{1b}OA")
}

async fn async_main() -> Result<()> {
    // Initialize logging with ERROR level during startup to avoid UI interference.
    // RUST_LOG still wins when set so field diagnostics stay possible.
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Error)
        .parse_default_env()
        .init();

    print_ascii_intro();

    // Load configuration from environment variables
    let config = AppConfig::from_env();
    config.log_config();
    let headless = env_flag_enabled("ALPHANUMERIC_HEADLESS");

    let pb = ProgressBar::new(7);
    pb.set_style(
        ProgressStyle::with_template("\r{spinner:.green} [{bar:40.cyan/blue}] {msg}")?
            .progress_chars("█▓░"),
    );

    // Resolve relative DB paths robustly:
    // - Prefer any path that already contains block data.
    // - Otherwise, create new relative databases under the current working directory.
    //
    // This keeps dev/source runs from silently creating a second DB under `target/release`.
    let db_path = {
        let raw = config.database.path.clone();
        let p = Path::new(&raw);
        if p.is_absolute() {
            raw
        } else {
            let cwd = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                .unwrap_or_else(|| cwd.clone());

            let cwd_candidate = cwd.join(p);
            let exe_candidate = exe_dir.join(p);

            let cwd_str = cwd_candidate.to_string_lossy().to_string();
            let exe_str = exe_candidate.to_string_lossy().to_string();

            let cwd_is_launch = local_db_matches_launch_genesis(&cwd_str);
            let exe_is_launch = local_db_matches_launch_genesis(&exe_str);
            let cwd_has_blocks = has_local_block_data(&cwd_str);
            let exe_has_blocks = has_local_block_data(&exe_str);

            if cwd_is_launch {
                cwd_str
            } else if exe_is_launch {
                exe_str
            } else if cwd_has_blocks {
                cwd_str
            } else if exe_has_blocks {
                exe_str
            } else {
                cwd_str
            }
        }
    };
    let local = tokio::task::LocalSet::new();
    local.run_until(async move {
        // Database init
        let _startup_locks = acquire_startup_locks(&db_path)
            .map_err(|e| format!("Startup lock failed for {}: {}", db_path, e))?;
        pb.set_message("Checking bootstrap snapshot...");
        let create_launch_genesis = env_flag_enabled("ALPHANUMERIC_CREATE_LAUNCH_GENESIS")
            || env_flag_enabled("ALPHANUMERIC_RESET_TO_LAUNCH_GENESIS");
        // Mirror config.rs seed-node precedence exactly: ALPHANUMERIC_SEED_NODES wins if set,
        // else the ALPHANUMERIC_BOOTSTRAP_PEERS alias. Reading only SEED_NODES here meant a node
        // configured via the alias had seed_peer_configured=false, so a snapshot outage failed
        // CLOSED instead of entering the P2P peer-bootstrap fallback. True iff config.seed_nodes
        // would be non-empty (any non-blank comma entry).
        let seed_peer_configured = std::env::var("ALPHANUMERIC_SEED_NODES")
            .or_else(|_| std::env::var("ALPHANUMERIC_BOOTSTRAP_PEERS"))
            .map(|s| s.split(',').any(|p| !p.trim().is_empty()))
            .unwrap_or(false);
        let mut peer_bootstrap_mode = false;
        if create_launch_genesis && !has_local_block_data(&db_path) {
            println!("Bootstrap skipped: creating deterministic launch genesis");
        } else if !has_local_block_data(&db_path) {
            // Fresh node (no local blocks): the gateway snapshot is the primary bootstrap.
            // If it is unavailable (Upstash / gateway outage) AND a seed peer is configured,
            // a snapshot failure is NOT fatal — create the deterministic genesis locally and
            // reconstruct the chain from the seed peer over P2P GetBlocks (Tier-2 fallback; the
            // reconcile loop's peer full-history sync does the pull, with the SAME validation).
            // With no seed peer, fail closed exactly as before.
            match ensure_bootstrap_db(&db_path).await {
                Ok(()) => {}
                Err(e) if seed_peer_configured => {
                    println!(
                        "Bootstrap snapshot unavailable ({}); will reconstruct the chain from a seed peer over P2P",
                        e
                    );
                    peer_bootstrap_mode = true;
                }
                Err(e) => return Err(e),
            }
        } else {
            // Existing local chain: reconcile it against the signed manifest as before.
            ensure_bootstrap_db(&db_path).await?;
        }
        pb.set_message("Initializing database...");
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
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        {
            let shutdown_flag = shutdown_requested.clone();
            let db_for_signal = db.clone();
            tokio::spawn(async move {
                // Treat SIGTERM (systemd/docker `stop`) identically to SIGINT (Ctrl-C):
                // without it, `systemctl stop` kills the node with no graceful flush and
                // the last ~interval of writes rely on sled log recovery.
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{signal, SignalKind};
                    match signal(SignalKind::terminate()) {
                        Ok(mut term) => {
                            tokio::select! {
                                _ = tokio::signal::ctrl_c() => {}
                                _ = term.recv() => {}
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to install SIGTERM handler ({e}); Ctrl-C only");
                            let _ = tokio::signal::ctrl_c().await;
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = tokio::signal::ctrl_c().await;
                }
                shutdown_flag.store(true, Ordering::Release);
                let _ = db_for_signal.flush();
                eprintln!("Shutting down cleanly...");
            });
        }
        {
            let db_for_flush = db.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    // Flush on the blocking pool, never a runtime worker: a synchronous sled
                    // flush that stalls under storage contention must not pin a tokio worker.
                    // All-4-worker pins on inline sled I/O are what froze the publisher runtime
                    // (2026-07-16 park); off-worker => the runtime + watchdog stay alive.
                    let dbf = db_for_flush.clone();
                    let _ = tokio::task::spawn_blocking(move || dbf.flush()).await;
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

        if (create_launch_genesis || peer_bootstrap_mode) && db.scan_prefix("block_").next().is_none()
        {
            pb.set_message("Creating launch genesis...");
            blockchain.write().await.create_genesis_block().await?;
        }

        // Set specific message for balance verification
        pb.set_message("Verifying blockchain state...");
        if let Err(e) = blockchain.write().await.initialize().await {
            error!("Failed to initialize blockchain: {}", e);
            return Err(Box::new(e));
        }
        pb.inc(1);

        // Seed the trusted checkpoint on first run under this build. Everything we
        // already hold — genesis, the verified bootstrap snapshot, prior sync — is
        // trusted as of this tip; only blocks arriving ABOVE it must pass full
        // ML-DSA verification. For a fresh node this tip IS the signed bootstrap
        // snapshot height, so witness-pruned history below it never has to be
        // re-verified. Idempotent: a no-op once a checkpoint exists.
        if let Err(e) = blockchain.read().await.seed_trusted_checkpoint_if_unset() {
            warn!("Failed to seed trusted checkpoint: {}", e);
        }

        // Build the replay registry from the chain we already hold if it hasn't
        // been built yet (first run under this feature, or after a bootstrap
        // import). Existing history is grandfathered; only new blocks are checked.
        if let Err(e) = blockchain.read().await.ensure_confirmed_tx_index() {
            warn!("Failed to build the replay registry: {}", e);
        }

        let (consensus_descriptor, consensus_fingerprint) = {
            let blockchain_lock = blockchain.read().await;
            compute_consensus_fingerprint(&blockchain_lock)
        };
        // Bootstrap publishing (zip+upload+sign) is compiled out by default to reduce false positives.
        // Enable with `--features bootstrap_publisher` for the ONE canonical node that should publish.
        #[cfg(feature = "bootstrap_publisher")]
        {
            // Single env var enables it:
            // - ALPHANUMERIC_BOOTSTRAP_PUBLISH_TOKEN
            if let Ok(token) = std::env::var("ALPHANUMERIC_BOOTSTRAP_PUBLISH_TOKEN") {
                let token = token.trim().to_string();
                if !token.is_empty() {
                    let db_path_for_publish = db_path.clone();
                    let blockchain_for_publish = blockchain.clone();
                    tokio::spawn(async move {
                        bootstrap_publish_loop(db_path_for_publish, blockchain_for_publish, token)
                            .await;
                    });
                }
            }
        }

        // Continue with rest of initialization
        pb.set_message("Setting up management...");
        let (_transaction_fee, _mining_reward, _difficulty_adjustment_interval, _block_time) = {
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
        pb.set_message("Loading node identity...");
        let key_pair_pkcs8 = load_or_create_node_identity_key(NODE_IDENTITY_KEY_PATH).await?;
        pb.inc(1);

        // Then create the node (single instance)
        pb.set_message("Creating node...");
        let explicit_bind = std::env::var("ALPHANUMERIC_BIND_IP").is_ok()
            || std::env::var("ALPHANUMERIC_PORT").is_ok();
        let bind_addr = if explicit_bind {
            Some(SocketAddr::new(config.network.bind_ip, config.network.port))
        } else {
            None
        };

        let node = match Node::new(
            Arc::new(db.clone()),
            blockchain.clone(),
            key_pair_pkcs8.clone(),
            NodeRuntimeConfig {
                bind_addr,
                velocity_enabled: config.network.velocity_enabled,
                max_peers: config.network.max_peers,
                max_connections: config.network.max_connections,
                seed_nodes: config.network.seed_nodes.clone(),
                // Peer cache lives next to the chain DB so it survives reboots
                // (the temp-dir default gets wiped exactly when it matters).
                data_dir: Some(db_path.clone()),
            },
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
        const MIN_VIABLE_PEERS: usize = 3;        // Minimum peers for operation
        const MAX_SYNC_ATTEMPTS: u32 = 3;         // Maximum sync retries before backing off
        const HEALTH_CHECK_INTERVAL: u64 = 1000;  // 1s health checks
        const SYNC_CHECK_INTERVAL: u64 = 2000;    // 2s sync checks
        const SLEEP_THRESHOLD: u64 = 10;          // 10s threshold for sleep detection
        const MAX_BLOCK_AGE: u64 = 2;            // Maximum acceptable block age deviation
        const MIN_PEER_LATENCY: u64 = 10;        // Minimum acceptable peer latency
        const RECENT_PEER_THRESHOLD: u64 = 300;   // Peer considered recent within 300s
        const MAX_DISCOVERY_ATTEMPTS: u32 = 5;    // Maximum discovery retry attempts

        // Track last activity time for sleep detection
        let last_active = Arc::new(AtomicU64::new(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()));

        // Initialize core services. On failure the task returns here — before sync and before
        // the monitor is spawned — so the node has no networking, yet the REPL still opens its
        // normal menu and looks healthy. error! alone can be suppressed by RUST_LOG, so also
        // print a stderr WARNING. Kept non-fatal so local wallet/balance inspection off the
        // on-disk DB still works; the operator must restart to get networking back.
        if let Err(e) = node_clone.start().await {
            error!("Critical error during startup: {}", e);
            eprintln!(
                "WARNING: node networking failed to start ({}). Running OFFLINE — sync, mining \
                 and sends will not work until you restart.",
                e
            );
            return;
        }

        // Converge to the network tip immediately on launch. "Bootstrapped" only means
        // the local DB is genesis-valid — NOT that it is at the current tip — so a node
        // that was behind (or on a stale fork) used to start up "done" yet several
        // blocks behind. Sync to the signed beacon now, before the node is usable; the
        // live beacon-watch loop keeps it current afterward. Bounded and best-effort.
        let _ = node_clone.sync_to_beacon().await;

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

                loop {
                    tokio::select! {
                        // Network sync check
                        _ = sync_interval.tick() => {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();

                            // Sleep detection with state reset. saturating_sub: `now`/`last` are
                            // wall-clock seconds, so a backward clock step (NTP, host time sync)
                            // makes now < last — a bare subtraction panics in debug and wraps to a
                            // huge value in release, firing false "sleep detected" resets every
                            // tick. Matches the sibling checks elsewhere in this monitor.
                            let last = activity_time.load(Ordering::Acquire);
                            if now.saturating_sub(last) > SLEEP_THRESHOLD {
                                debug!("Sleep detected, resetting network state");
                                // Reset all counters
                                sync_attempts = 0;
                                discovery_failures = 0;
                                block_times.clear();

                                // Attempt immediate network recovery
                                if let Err(e) = node.discover_network_nodes().await {
                                    error!("Network rediscovery after wake failed: {}", e);
                                }
                            }
                            activity_time.store(now, Ordering::Release);

                            // Network state check. Snapshot under a short-lived guard:
                            // holding this read lock across the sleeps/discovery/sync
                            // awaits below deadlocks every peers.write() in verify_peer.
                            let (active_peers, target_latency, available_peers) = {
                                let peers = node.peers.read().await;
                                let active_peers = peers.len();

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

                                (active_peers, target_latency, available_peers)
                            };

                            if active_peers > 0 {
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
                                                    _ => None
                                                }
                                            }
                                        })
                                    ).await;

                                    // Process height differences with backoff
                                    if let Some(&max_height) = heights.iter().flatten().max() {
                                        if max_height > local_height {
                                            sync_attempts = sync_attempts.saturating_add(1);
                                            if sync_attempts < MAX_SYNC_ATTEMPTS {
                                                match node.sync_with_network().await {
                                                    Ok(_) => {
                                                        if let Err(e) = node.publish_local_tip().await {
                                                            warn!("Post-sync publish failed: {}", e);
                                                        }
                                                        sync_attempts = 0;
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
                            // Snapshot the tip timestamp under a short-lived guard and drop it
                            // before any network await below. Holding the blockchain read lock
                            // across discover_network_nodes().await deadlocks: the discovery ->
                            // verify_peer -> perform_handshake path re-acquires blockchain.read(),
                            // and a block-ingest write() queued between the two reads blocks the
                            // re-entrant read forever (tokio's fair RwLock). Mirrors the sync arm.
                            let last_ts = {
                                let blockchain = node.blockchain.read().await;
                                blockchain.get_last_block().map(|b| b.timestamp)
                            };
                            if let Some(last_ts) = last_ts {
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();

                                let block_time = now.saturating_sub(last_ts);
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
                                    {
                                        let mut health = node.network_health.write().await;
                                        health.adjust_for_slow_blocks(avg_block_time);
                                    }

                                    // Decide whether to rediscover under a short peers guard,
                                    // then release it before the discovery await (same lock-
                                    // across-await hazard as above).
                                    let need_discovery = {
                                        let peers = node.peers.read().await;
                                        peers.len() < MIN_VIABLE_PEERS
                                            || peers.values().all(|p| p.latency > RECOVERY_LATENCY)
                                    };
                                    if need_discovery {
                                        if let Err(e) = node.discover_network_nodes().await {
                                            error!("Failed to discover peers during health check: {}", e);
                                        }
                                    }
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

        pb.set_message("Loading wallets...");
        let key_data_result = fs::read_to_string(KEY_FILE_PATH).await;
        let wallet_data: Vec<WalletKeyData> = key_data_result
            .as_deref()
            .ok()
            .and_then(|data| serde_json::from_str(data).ok())
            .unwrap_or_default();

        let mut wallet_encryption_state: Option<Vec<u8>> = None;

        if !headless && !wallet_data.is_empty() {
            println!("\nWallet(s) found. Enter passphrase (leave blank for unencrypted wallets):");

            let passphrase = Password::new("Passphrase:")
                .with_display_mode(PasswordDisplayMode::Masked)
                .prompt()
                .unwrap_or_default();

            if !passphrase.trim().is_empty() {
                wallet_encryption_state = Some(passphrase.trim().as_bytes().to_vec());
            }
        }

        let mut wallets = if headless
            && matches!(&key_data_result, Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        {
            println!("Headless mode: no private.key found; continuing without a local wallet.");
            HashMap::new()
        } else if headless && key_data_result.is_err() {
            // Existing-but-unreadable key file (EACCES / non-UTF-8 / AV lock): do NOT silently run
            // walletless on a key-holding node — that masks the condition. Abort loudly, mirroring
            // the H4 guard in load_wallets.
            let e = key_data_result.as_ref().err().unwrap();
            return Err(format!(
                "{} exists but could not be read ({:?}: {}). Refusing to start walletless so the \
                 condition is not masked — fix permissions or restore from backup.",
                KEY_FILE_PATH,
                e.kind(),
                e
            )
            .into());
        } else if wallet_encryption_state.is_some() {
            mgmt.load_wallets(&db_arc, wallet_encryption_state.as_deref()).await?
        } else {
            mgmt.load_wallets(&db_arc, None).await?
        };
        pb.inc(1);

        // Staking
        let header_sentinel = node.header_sentinel().ok_or_else(|| {
            std::io::Error::other("Missing header sentinel")
        })?;
        let staking_node = Arc::new(RwLock::new(BPoSSentinel::new(
            blockchain.clone(),
            Arc::clone(&node),
            header_sentinel,
        )));

        // Whisper
        let whisper_module = Arc::new(RwLock::new(WhisperModule::new()));
        let wallet_addresses: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(
            wallets.values().map(|w| w.address.clone()).collect(),
        ));

        // Instant received-funds notification. Subscribes to the in-process tip
        // signal (fired by the live beacon-watch sync on every applied block) and
        // scans the newly-applied block(s) for credits to a local wallet — no
        // polling, no server state, no per-wallet index; it rides the delta the
        // node already pulled. This is what makes an incoming payment show up
        // instantly without restarting or refreshing.
        {
            let wallet_addresses = wallet_addresses.clone();
            let blockchain = blockchain.clone();
            let whisper_module = whisper_module.clone();
            tokio::spawn(async move {
                let mut rx = { blockchain.read().await.subscribe_tip_changes() };
                let mut last_scanned: u32 =
                    { blockchain.read().await.get_latest_block_index() as u32 };
                loop {
                    if rx.changed().await.is_err() {
                        break;
                    }
                    let height = rx.borrow().height;
                    let addresses = { wallet_addresses.read().await.clone() };
                    if addresses.is_empty() {
                        last_scanned = height;
                        continue;
                    }
                    // Scan every block applied since the last signal (covers a
                    // multi-block catch-up); on a reorg just re-scan the new tip.
                    let from = if height > last_scanned {
                        last_scanned.saturating_add(1)
                    } else {
                        height
                    };
                    for h in from..=height {
                        let block = { blockchain.read().await.get_block(h).ok() };
                        let Some(block) = block else { continue };
                        for tx in &block.transactions {
                            if tx.sender == "MINING_REWARDS" {
                                continue; // mining rewards are reported by the miner
                            }
                            if !addresses.iter().any(|a| *a == tx.recipient) {
                                continue;
                            }
                            let from_short = &tx.sender[..tx.sender.len().min(10)];
                            // A whisper carries its message in the fee; show the
                            // message. Otherwise it is a plain payment.
                            let whisper = { whisper_module.read().await.decode_whisper_in_tx(tx) };
                            if let Some(message) = whisper {
                                println!(
                                    "\n\x1b[1;95m✉ Whisper\x1b[0m from {}…  (block {}):\n  {}",
                                    from_short, block.index, message
                                );
                            } else {
                                let amount = Transaction::from_units(tx.amount_units);
                                let to_short = &tx.recipient[..tx.recipient.len().min(10)];
                                println!(
                                    "\n\x1b[1;96m◆ Received {:.8} ♦\x1b[0m  to {}…  from {}…  (block {})",
                                    amount, to_short, from_short, block.index
                                );
                            }
                        }
                    }
                    last_scanned = height;
                }
            });
        }

        // Initialize the BPoS sentinel in the BACKGROUND. initialize() runs
        // verify_chain_state, whose anomaly path chases peers over the network — at a
        // high block rate it reliably finds work and takes the full time-box, which
        // (when awaited in-band) stalled EVERY startup for up to 8s right after
        // "Loaded N wallets successfully" before the menu appeared. It is idempotent,
        // its monitoring tasks spawn before the blocking part, and the 60s monitor
        // loop covers the rest — so running it off the startup path is safe and just
        // removes the visible stall; the menu now appears immediately. Still
        // time-boxed inside the task so it can never sit forever.
        {
            let staking_bg = staking_node.clone();
            tokio::spawn(async move {
                let sentinel = staking_bg.write().await;
                match tokio::time::timeout(Duration::from_secs(8), sentinel.initialize()).await {
                    Ok(Err(e)) => error!("Failed to initialize staking sentinel: {}", e),
                    Err(_) => {
                        warn!("Staking sentinel initialization deferred (node busy)")
                    }
                    Ok(Ok(())) => {}
                }
            });
        }

        // Runtime canonical reconciliation — for EVERY node, interactive included
        // (v7.6.5: this used to run only in headless mode, so an interactive `a#:`
        // client had NO background sync at all — it only converged inside mine-prep,
        // fell behind the racing tip the whole time it sat at the menu, and then had
        // to cross the entire accumulated gap inside one prep budget: the "my client
        // is always behind / can't compete" complaint all night). A 20s cadence
        // keeps an idle client within a block or two of the tip; when already at the
        // tip a check is one CDN-cached beacon poll and a local compare. A node that
        // drifts onto a fork heals in place (incremental reorg); only a genuine,
        // repeated below-finality divergence escalates to restart + re-bootstrap.
        {
            let node_recon = node.clone();
            let shutdown_recon = shutdown_requested.clone();
            let db_path_recon = db_path.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(20));
                let mut strikes = 0u32;
                let mut cooldown_logged = false;
                let mut behind_logged = false;
                loop {
                    ticker.tick().await;
                    if shutdown_recon.load(Ordering::Acquire) {
                        return;
                    }
                    match node_recon.sync_to_beacon().await {
                        Converge::Converged => {
                            strikes = 0;
                            // PROVEN convergence invalidates any stale marker: a node
                            // that recovered in place during a fail-open (gateway-down)
                            // boot must not get its now-healthy chain wiped at the next
                            // gateway-up restart (review finding, 2026-07-11). Every
                            // Converged tick, not once: mine-prep can write a marker at
                            // any later moment (transient fork-storm NeedsBootstrap),
                            // and a one-shot cleanup left that marker to wipe a chain
                            // that then converged healthily for hours (audit finding).
                            // Cost: one unlink of a usually-absent path per 20s tick.
                            let _ = std::fs::remove_file(force_rebootstrap_marker_path(
                                &db_path_recon,
                            ));
                            behind_logged = false;
                        }
                        Converge::AtTipAhead
                        | Converge::Progressed
                        | Converge::BeaconStale
                        | Converge::BranchInvalid => {
                            strikes = 0;
                            behind_logged = false;
                        }
                        Converge::NeedsBootstrap => {
                            // RESILIENT SERVICE CLIENTS (exchange / explorer /
                            // web-wallet API): a NeedsBootstrap from an idle node
                            // is almost always a FALSE POSITIVE — the node mints
                            // nothing, so it is a canonical PREFIX (not a fork),
                            // just behind and momentarily unable to fetch the
                            // intervening bodies (relay holes / thin mesh /
                            // partition). The old code escalated that to a process
                            // exit every ~minute, taking the SERVICE down and
                            // thinning the mesh. Only a genuine "fallen more than
                            // ORPHAN_REORG_DEPTH behind" (bodies aged out, snapshot
                            // is the only cure) warrants the disruptive exit +
                            // re-bootstrap. Below that, STAY UP and keep serving —
                            // the in-place converge / Tier-2 peer-sync / gossip
                            // loops recover the node, and if it never catches up it
                            // crosses the threshold on its own and re-bootstraps
                            // then. Read-only + mining-neutral: mine-prep still
                            // re-checks convergence and writes its own marker
                            // (schedule_force_rebootstrap_hard) untouched.
                            let genuinely_too_far = {
                                let local_tip = node_recon
                                    .blockchain
                                    .read()
                                    .await
                                    .get_latest_block_index()
                                    as u32;
                                // FORK vs BEHIND: NeedsBootstrap is overloaded. A
                                // genuine FORK (our tip is not on canonical) can
                                // have a small — or even negative — height gap, so
                                // gap alone would leave a forked service node
                                // serving wrong-chain data. Re-derive the two fork
                                // checks the boot reconcile uses, read through the
                                // OPEN handle (no DB re-open), touching nothing on
                                // the mine path:
                                let beacon = node_recon.network_beacon_tip().await;
                                //  (B) anchor at-or-below our tip: fetch a signed
                                //      canonical header <= local_tip and compare its
                                //      hash to the block we hold there. Catches a
                                //      fork whose divergence point is at/below our
                                //      tip and below the beacon.
                                let mut forked = match fetch_canonical_anchor_at_or_below(
                                    local_tip,
                                )
                                .await
                                {
                                    Some((anchor_h, anchor_hash)) if anchor_h <= local_tip => {
                                        match node_recon
                                            .blockchain
                                            .read()
                                            .await
                                            .get_block(anchor_h)
                                        {
                                            Ok(b) => !hex::encode(b.hash)
                                                .eq_ignore_ascii_case(&anchor_hash),
                                            Err(_) => false,
                                        }
                                    }
                                    _ => false,
                                };
                                //  (A) at the beacon tip: when we are AT/ABOVE the
                                //      beacon height, compare our block at the beacon
                                //      height to the signed beacon hash. Catches an
                                //      out-extended taller-but-losing fork (gap<=0),
                                //      which check (B)'s anchor — landing on the
                                //      shared fork point — would miss.
                                if !forked {
                                    if let Some((bh, bhash)) = &beacon {
                                        if local_tip >= *bh {
                                            if let Ok(b) = node_recon
                                                .blockchain
                                                .read()
                                                .await
                                                .get_block(*bh)
                                            {
                                                forked = !hex::encode(b.hash)
                                                    .eq_ignore_ascii_case(bhash);
                                            }
                                        }
                                    }
                                }
                                let beacon_height = beacon.as_ref().map(|(h, _)| *h);
                                idle_reconcile_needs_snapshot(local_tip, beacon_height, forked)
                            };
                            if !genuinely_too_far {
                                strikes = 0;
                                if !behind_logged {
                                    println!(
                                        "Behind the network tip; catching up in the background. The node stays up and keeps serving."
                                    );
                                    behind_logged = true;
                                }
                                continue;
                            }
                            behind_logged = false;
                            strikes += 1;
                            if strikes >= 2 {
                                // Bootstrap-cycle cooldown: on a genuinely shattered
                                // network this exit repeats; without a floor the old
                                // cheap ~21s crash-loop becomes a snapshot-download
                                // loop. This verdict is a PROVEN below-finality
                                // divergence against the signed beacon, so it uses the
                                // HARD (short) window: suppressing it for the generic
                                // 30 minutes left a node that knew it was stranded
                                // sitting stale doing nothing (2026-07-11). Within the
                                // short window, stay up and keep retrying converge —
                                // same eventual recovery, bounded cost.
                                if rebootstrap_hard_cooldown_active(&db_path_recon) {
                                    if !cooldown_logged {
                                        println!(
                                            "Chain cannot converge, but a forced re-bootstrap ran recently; staying up and retrying until the cooldown passes"
                                        );
                                        cooldown_logged = true;
                                    }
                                    strikes = 0;
                                    continue;
                                }
                                // Drop the force-rebootstrap marker BEFORE exiting: the
                                // boot-time manifest comparison lags its publish cadence,
                                // so a fork AT tip height read as "in sync" at boot and
                                // this exit crash-looped ~21s at a time until the manifest
                                // caught up (observed 7x back-to-back, 2026-07-10). The
                                // marker makes the next boot re-bootstrap unconditionally
                                // — the live loop has PROVEN convergence is impossible,
                                // which outranks any boot-time guess.
                                let marker = force_rebootstrap_marker_path(&db_path_recon);
                                if let Err(e) = std::fs::write(&marker, b"runtime too-far-behind exit\n") {
                                    eprintln!(
                                        "Warning: could not write re-bootstrap marker {}: {}",
                                        marker.display(),
                                        e
                                    );
                                }
                                println!(
                                    "Node is on a fork or has fallen too far behind (>{} blocks) to catch up incrementally; re-bootstrapping from a fresh snapshot. Run under a supervisor (systemd/docker restart) so the service comes back automatically.",
                                    alphanumeric::a9::blockchain::ORPHAN_REORG_DEPTH
                                );
                                // Nonzero: this exit exists to BE re-launched (the marker written
                                // above makes the next boot re-bootstrap). exit(0) reads as success,
                                // so systemd Restart=on-failure / docker restart:on-failure would
                                // leave the stranded node dead instead of restarting it.
                                std::process::exit(3);
                            }
                        }
                    }
                }
            });
        }

        if headless {
            println!("Headless mode enabled. Node services are running.");
            // (Runtime canonical reconciliation runs for every node — spawned above.)
            // Poll the shutdown flag every 1s (not 60s) so Ctrl-C / SIGTERM is noticed
            // promptly and systemd doesn't have to SIGKILL after TimeoutStopSec. The tight
            // poll is negligible cost since the actual work runs in the spawned tasks.
            while !shutdown_requested.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            return Ok(());
        }

        println!("1. Create Transaction (format: create sender recipient amount)");
        println!("2. Whisper Code (format: whisper address msg)");
        println!("3. Show Balance (format: balance)");
        println!("4. Make New Wallet (format: new [wallet_name])");
        println!("5. Account Lookup (format: account address)");
        println!("6. Mine Block (format: mine miner_wallet_name)");
        println!("7. Exit");

        let editor_config = Config::builder()
            .color_mode(ColorMode::Forced)
            .build();
        let mut line_editor = match DefaultEditor::with_config(editor_config) {
            Ok(mut editor) => {
                editor.set_helper(Some(()));
                Some(editor)
            }
            Err(e) => {
                debug!("Line editor unavailable; falling back to standard input: {}", e);
                None
            }
        };
        let mut last_console_command: Option<String> = None;
        let console_prompt = ("a#:", "\x1b[1;97ma#:\x1b[0m");

        loop {
            if shutdown_requested.load(Ordering::Acquire) {
                return Ok(());
            }
            let mut command = if line_editor.is_some() {
                // Run the blocking readline on the blocking pool so this LocalSet thread keeps
                // driving the spawn_local node monitor (health/discovery/wake-recovery) while the
                // user sits at the prompt — a synchronous readline on this thread froze it. The
                // owned editor is moved in and handed back; console_prompt is Copy (&'static str
                // pair). The main reconciliation loop runs on other workers and is unaffected.
                let editor_owned = line_editor.take().expect("line editor checked");
                let prompt = console_prompt;
                let read_result = match tokio::task::spawn_blocking(move || {
                    let mut ed = editor_owned;
                    let res = ed.readline(&prompt);
                    (ed, res)
                })
                .await
                {
                    Ok((ed_back, res)) => {
                        line_editor = Some(ed_back);
                        res
                    }
                    Err(_) => {
                        // The blocking read task panicked; clean up and exit gracefully.
                        let _ = remove_db_lock(&format!("{}.lock", db_path));
                        let _ = remove_instance_lock();
                        return Ok(());
                    }
                };
                match read_result {
                    Ok(line) => line.trim().to_string(),
                    Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                        let _ = remove_db_lock(&format!("{}.lock", db_path));
                        let _ = remove_instance_lock();
                        return Ok(());
                    }
                    Err(e) => {
                        debug!("Line editor failed; falling back to standard input: {}", e);
                        line_editor = None;
                        continue;
                    }
                }
            } else {
                let mut stdout = StandardStream::stdout(ColorChoice::Always);
                let mut prompt_style = ColorSpec::new();
                prompt_style.set_fg(Some(Color::White)).set_bold(true);
                let _ = stdout.set_color(&prompt_style);
                let _ = write!(&mut stdout, "αlphanumeric: ");
                let _ = stdout.reset();
                let _ = stdout.flush();

                // Same rationale as the rustyline branch: read on the blocking pool so this
                // LocalSet thread keeps driving the spawn_local monitor instead of freezing on a
                // synchronous stdin read.
                let (command, read_res) = match tokio::task::spawn_blocking(|| {
                    let mut command = String::new();
                    let res = std::io::stdin().read_line(&mut command);
                    (command, res)
                })
                .await
                {
                    Ok(v) => v,
                    Err(_) => {
                        let _ = remove_db_lock(&format!("{}.lock", db_path));
                        let _ = remove_instance_lock();
                        return Ok(());
                    }
                };
                match read_res {
                    Ok(0) => {
                        let _ = remove_db_lock(&format!("{}.lock", db_path));
                        let _ = remove_instance_lock();
                        return Ok(());
                    }
                    Ok(_) => command.trim().to_string(),
                    Err(e) => {
                        warn!("Input loop interrupted: {}", e);
                        let _ = remove_db_lock(&format!("{}.lock", db_path));
                        let _ = remove_instance_lock();
                        return Ok(());
                    }
                }
            };
            command = command
                .trim_start_matches("αlphanumeric:")
                .trim()
                .to_string();

            let recalled_previous = is_recall_line(&command, line_editor.is_some());
            if recalled_previous {
                if let Some(previous) = last_console_command.clone() {
                    println!("{}", previous);
                    command = previous;
                } else {
                    println!("No previous command.");
                    continue;
                }
            }

            if command.is_empty() {
                println!("Please enter a command.");
                continue;
            }

            if !recalled_previous {
                if let Some(editor) = line_editor.as_mut() {
                    let _ = editor.add_history_entry(command.as_str());
                }
                last_console_command = Some(command.clone());
            }

            match command.split_whitespace().next() {
                Some("create") | Some("send") | Some("transfer") => {
                    // Handle the creation of the transaction
                    match mgmt
                        .handle_create_transaction(&command, &mut wallets, &blockchain, &db_arc)
                        .await
                    {
                        Ok(tx) => {
                            // Announce it: submission only reaches the LOCAL mempool, and
                            // the gateway relay carries blocks, not transactions — without
                            // this gossip no other miner ever hears about the tx and only
                            // the sender could confirm it (pre-v7.6.8 behavior).
                            node.gossip_transaction(&tx).await;
                        }
                        Err(e) => {
                            println!("Error: {}", e);
                            println!("Failed to create transaction: {}", e);
                        }
                    }
                }
                Some("info") => {
                    let mut stdout = StandardStream::stdout(ColorChoice::Always);
                    let mut color_spec = ColorSpec::new();
                    let gateway_overview = fetch_gateway_overview().await;

    // Get total wallets and balance first
    let mut total_balance = 0.0;
    let mut total_maturing = 0.0;
    let mut processed_wallets = 0;

    // Calculate total balance under a SHORT-LIVED guard, dropped before anything
    // else runs. Holding this read across sentinel.initialize() deadlocked the whole
    // REPL: initialize() re-reads the blockchain, and tokio's fair RwLock parks that
    // second read behind any writer queued in between (block ingest queues writers
    // every few seconds on a live chain) while the writer waits on our first read.
    {
        let blockchain_guard = blockchain.read().await;
        for wallet in wallets.values() {
            if let Ok(breakdown) = blockchain_guard
                .get_wallet_balance_breakdown(&wallet.address)
                .await
            {
                total_balance += breakdown.spendable;
                total_maturing += breakdown.maturing.iter().map(|(_, amount)| amount).sum::<f64>();
                processed_wallets += 1;
            }
        }
    }

    // Initialize sentinel (idempotent; first info call only). Time-boxed so a busy
    // node can never wedge the console — it will simply initialize on a later call.
    {
        let sentinel = staking_node.write().await;
        match tokio::time::timeout(Duration::from_secs(5), sentinel.initialize()).await {
            Ok(Err(e)) => error!("Failed to initialize staking sentinel: {}", e),
            Err(_) => warn!("Staking sentinel initialization deferred (node busy)"),
            Ok(Ok(())) => {}
        }
    }

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
    // M06: freshly mined coinbases are credited but not yet spendable; without this
    // line a miner's info screen under-reads their holdings for ~8 minutes per reward.
    if total_maturing > 0.0 {
        color_spec.set_fg(Some(Color::Rgb(128, 128, 128)));
        stdout.set_color(&color_spec)?;
        writeln!(stdout, "Maturing:        {:.8} ♦ (mining rewards, not yet spendable)", total_maturing)?;
    }
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

    // Time-boxed: get_network_metrics reads a lock whose writer used to be held
    // across slow chain reads for the length of a reorg — the "info prints the
    // Network Status divider then hangs forever" bug. The lock ordering is fixed in
    // bpos too; the timeout guarantees the console stays responsive regardless.
    let network_snapshot = tokio::time::timeout(Duration::from_secs(3), async {
        let health = sentinel.get_network_metrics().await.ok()?;
        let active_peers = node.peers.read().await.len();
        let mesh_links = node.mesh_link_count().await;
        Some((health, active_peers, mesh_links))
    })
    .await
    .ok()
    .flatten();
    if network_snapshot.is_none() {
        color_spec.set_fg(Some(Color::Rgb(128, 128, 128)));
        stdout.set_color(&color_spec)?;
        writeln!(stdout, "Unavailable while the node syncs — try again shortly.")?;
        stdout.reset()?;
    }
    if let Some((health, active_peers, mesh_links)) = network_snapshot {
        let gateway_peers = gateway_overview
            .as_ref()
            .and_then(|overview| overview.peers)
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or(0);
        let active_nodes = health.active_nodes.max(active_peers).max(gateway_peers);

        color_spec.set_fg(Some(Color::Rgb(230, 230, 230)));
        stdout.set_color(&color_spec)?;
        writeln!(stdout, "Active Nodes:    {}", active_nodes)?;
        if gateway_peers > 0 {
            color_spec.set_fg(Some(Color::Rgb(137, 207, 211)));
            stdout.set_color(&color_spec)?;
            writeln!(stdout, "Network Peers:   {}", gateway_peers)?;
        }
        color_spec.set_fg(Some(Color::Rgb(167, 165, 198)));
        stdout.set_color(&color_spec)?;
        // LOCAL connectivity, distinct from the gateway roster above: during a
        // gateway outage the roster reads 0 while these links keep gossiping
        // (2026-07-10 incident: "every node lost its peer list" was the roster
        // display, not real connections). 0 TCP is normal for NAT'd nodes — the
        // mesh is their direct-link layer.
        if active_peers == 0 && mesh_links == 0 {
            writeln!(stdout, "Direct P2P:      0 (relay mode)")?;
        } else {
            writeln!(
                stdout,
                "Direct P2P:      {} TCP + {} mesh link(s)",
                active_peers, mesh_links
            )?;
        }
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

    // Chain Status. Time-boxed: a long reorg/branch adoption holds the chain WRITE
    // lock for its whole validation pass, and an unbounded read here parked the
    // console behind it (the "info hangs mid-print, restart the client" bug).
    let Ok(blockchain_guard) =
        tokio::time::timeout(Duration::from_secs(3), blockchain.read()).await
    else {
        color_spec.set_fg(Some(Color::Rgb(230, 230, 230))).set_bold(true);
        stdout.set_color(&color_spec)?;
        writeln!(stdout, "\n Chain Status ")?;
        color_spec.set_fg(Some(Color::Rgb(128, 128, 128))).set_bold(false);
        stdout.set_color(&color_spec)?;
        writeln!(stdout, "───────────────────")?;
        writeln!(stdout, "Chain busy (sync/reorg in progress) — try again shortly.")?;
        stdout.reset()?;
        continue;
    };
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
        current_height
    )?;
    if let Some(network_height) = gateway_overview.as_ref().and_then(|overview| overview.height) {
        color_spec.set_fg(Some(Color::Rgb(137, 207, 211)));
        stdout.set_color(&color_spec)?;
        writeln!(stdout, "Network Height:    {}", network_height)?;
    }
    if let Some(verified) = gateway_overview
        .as_ref()
        .and_then(|overview| overview.verified)
    {
        color_spec.set_fg(Some(Color::Rgb(59, 242, 173)));
        stdout.set_color(&color_spec)?;
        writeln!(
            stdout,
            "Network Verified:  {}",
            if verified { "yes" } else { "pending" }
        )?;
    }
    color_spec.set_fg(Some(Color::Rgb(59, 242, 173)));
    stdout.set_color(&color_spec)?;
    let tip_difficulty = blockchain_guard.get_tip_difficulty().await;
    let next_difficulty = blockchain_guard.get_current_difficulty().await;
    writeln!(stdout, "Difficulty:        {}", tip_difficulty)?;
    if next_difficulty != tip_difficulty {
        writeln!(stdout, "Next Difficulty:   {}", next_difficulty)?;
    }
    color_spec.set_fg(Some(Color::Rgb(137, 207, 211)));
    stdout.set_color(&color_spec)?;
    // Auto-scale: a CPU-mined BLAKE3 network's hashrate lives in MH/s-GH/s, and a
    // fixed TH/s display read "0.00" even while difficulty climbed past 550.
    let hashrate_ths = blockchain_guard.calculate_network_hashrate().await;
    let hashrate_hs = hashrate_ths * 1e12;
    let (hr_value, hr_unit) = if hashrate_hs >= 1e12 {
        (hashrate_hs / 1e12, "TH/s")
    } else if hashrate_hs >= 1e9 {
        (hashrate_hs / 1e9, "GH/s")
    } else if hashrate_hs >= 1e6 {
        (hashrate_hs / 1e6, "MH/s")
    } else if hashrate_hs >= 1e3 {
        (hashrate_hs / 1e3, "kH/s")
    } else {
        (hashrate_hs, "H/s")
    };
    writeln!(stdout, "Hashrate:          {:.2} {}", hr_value, hr_unit)?;
    color_spec.set_fg(Some(Color::Rgb(40, 204, 217)));
    stdout.set_color(&color_spec)?;
    writeln!(stdout, "Fee Rate:          {:.8}%", blockchain_guard.transaction_fee * 100.0)?;
    writeln!(stdout, "Block Time Target: {}s", blockchain_guard.block_time)?;

    if let Some(last_block) = blockchain_guard.get_last_block() {
        color_spec.set_fg(Some(Color::Rgb(237, 124, 51)));
        stdout.set_color(&color_spec)?;
        let age = now.saturating_sub(last_block.timestamp);
        // Past a minute the raw-seconds age is the "am I stalled?" signal but reads
        // as an unparseable wall of digits (11506s); annotate it human-readably.
        if age >= 60 {
            writeln!(stdout, "Last Block Time:   {}s ({} ago)", age, human_duration_secs(age))?;
        } else {
            writeln!(stdout, "Last Block Time:   {}s", age)?;
        }
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

    let pending_value: f64 = pending_txs.iter().map(|tx| tx.amount()).sum();
    let pending_fees: f64 = pending_txs.iter().map(|tx| tx.fee()).sum();

    if !pending_txs.is_empty() {
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
// create_new_wallet has already persisted the merged key file (including any wallets that
// failed to load, e.g. wrong passphrase — they are read from disk and re-written). A follow-up
// save_wallets here would rewrite the file from the IN-MEMORY map only and erase those skipped
// wallets, permanently destroying their keys — so it is deliberately omitted.
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
                Some("push") => {
                    #[cfg(feature = "bootstrap_publisher")]
                    {
                        if let Err(e) = handle_push_command(&db_path, &blockchain).await {
                            println!("Error: {}", e);
                        }
                    }
                    #[cfg(not(feature = "bootstrap_publisher"))]
                    {
                        println!(
                            "Error: push support is not compiled in. Rebuild with `--features bootstrap_publisher`."
                        );
                    }
                }
                Some("mine") => {
                    let parts: Vec<&str> = command.split_whitespace().collect();
                    let continuous =
                        parts.len() == 3 && matches!(parts[2], "--continuous" | "-c");
                    if !(parts.len() == 2 || continuous) {
                        println!("Usage: mine <miner_wallet_name> [--continuous]");
                        continue;
                    }
                    // Normalized args for the handler regardless of trailing flags.
                    let mine_parts: Vec<&str> = vec![parts[0], parts[1]];

                    // Enter-to-stop for continuous mode: one detached reader consumes a
                    // single stdin line and flips the flag; the mining loop checks it
                    // between every wait slice and round.
                    let stop_flag = Arc::new(AtomicBool::new(false));
                    if continuous {
                        println!(
                            "Continuous mining started. Paced to the network: each block \
                             waits to propagate before the next round, with jittered \
                             delays and backoff so miners never hammer the gateway."
                        );
                        println!("Press Enter at any time to stop.");
                        let stop = Arc::clone(&stop_flag);
                        std::thread::spawn(move || {
                            let mut buf = String::new();
                            let _ = std::io::stdin().read_line(&mut buf);
                            stop.store(true, Ordering::SeqCst);
                        });
                    }

                    // Sleep in short slices so Enter stops continuous mode promptly.
                    async fn sleep_interruptible(total: Duration, stop: &AtomicBool) {
                        let mut remaining = total;
                        while remaining > Duration::ZERO && !stop.load(Ordering::SeqCst) {
                            let slice = remaining.min(Duration::from_millis(250));
                            tokio::time::sleep(slice).await;
                            remaining = remaining.saturating_sub(slice);
                        }
                    }

                    // Failure backoff: doubles on trouble (5s -> 60s cap), resets on a
                    // mined block. Keeps a struggling client patient instead of letting
                    // it hammer the relay, and keeps N continuous miners from
                    // synchronizing their retries.
                    let mut backoff = Duration::from_secs(5);
                    let mut mined_count: u64 = 0;
                    // Permanent-error guard for continuous mode: a mining error that
                    // repeats back-to-back (bad wallet name, corrupt state) will never
                    // heal by retrying — stop with a clear message instead of backing
                    // off forever. Network-side prep trouble does NOT count here.
                    const MAX_CONSECUTIVE_MINE_ERRORS: u32 = 5;
                    let mut consecutive_mine_errors: u32 = 0;

                    'mining: loop {
                        if continuous && stop_flag.load(Ordering::SeqCst) {
                            break 'mining;
                        }

                        if !continuous || mined_count == 0 {
                            println!(
                                "Preparing mining: syncing to the network tip so we can compete..."
                            );
                        }
                        // Liveness heartbeat: every prep step is time-bounded, but the
                        // bounds can stack to ~30s per attempt on a churning network,
                        // which USERS read as "it's stuck, restart the client". Print
                        // elapsed progress every 5s so silence never looks like a hang.
                        let prep_heartbeat = tokio::spawn(async {
                            let started = Instant::now();
                            loop {
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                println!(
                                    "  …still syncing to the network tip ({}s elapsed — bounded, will report)",
                                    started.elapsed().as_secs()
                                );
                            }
                        });
                        // Converge-then-compete with a bounded retry. Only a genuine
                        // below-finality divergence (needs re-bootstrap) is a hard stop.
                        const MINE_PREP_ATTEMPTS: u32 = 3;
                        let mut prep_ok = false;
                        let mut prep_stop: Option<String> = None;
                        for attempt in 1..=MINE_PREP_ATTEMPTS {
                            match node.prepare_local_mining(Duration::from_secs(8)).await {
                                Ok(()) => {
                                    prep_ok = true;
                                    break;
                                }
                                Err(NodeError::Retryable(_)) => {
                                    if attempt < MINE_PREP_ATTEMPTS {
                                        println!(
                                            "Still catching up to the network tip (attempt {}/{})…",
                                            attempt, MINE_PREP_ATTEMPTS
                                        );
                                        tokio::time::sleep(Duration::from_secs(2)).await;
                                    }
                                }
                                Err(NodeError::ConsensusFailure(reason)) => {
                                    prep_stop = Some(reason);
                                    break;
                                }
                                Err(other) => {
                                    prep_stop = Some(other.to_string());
                                    break;
                                }
                            }
                        }
                        prep_heartbeat.abort();
                        if let Some(reason) = prep_stop {
                            println!("Cannot mine right now: {}", reason);
                            break 'mining;
                        }
                        if !prep_ok {
                            if continuous {
                                println!(
                                    "Network tip still syncing; waiting {}s before the next attempt…",
                                    backoff.as_secs()
                                );
                                sleep_interruptible(backoff, &stop_flag).await;
                                backoff = (backoff * 2).min(Duration::from_secs(60));
                                continue 'mining;
                            }
                            println!(
                                "Still syncing to the network tip; it keeps catching up in the background — run `mine` again in a moment."
                            );
                            break 'mining;
                        }

                        let mining_manager = MiningManager::new(Arc::clone(&blockchain));
                        let miner = Miner::new(blockchain.clone(), mining_manager);
                        match mgmt
                            .handle_mine_command(&mine_parts, &miner, &mut wallets, &blockchain, &db_arc)
                            .await
                        {
                            Ok(mined_block) => {
                                backoff = Duration::from_secs(5);
                                consecutive_mine_errors = 0;
                                mined_count += 1;
                                let mined_height = mined_block.index;
                                let publish_node = Arc::clone(&node);
                                tokio::spawn(async move {
                                    const MAX_PUBLISH_ATTEMPTS: u32 = 4;
                                    for attempt in 1..=MAX_PUBLISH_ATTEMPTS {
                                        match publish_node
                                            .publish_block(mined_block.clone(), "Post-mine")
                                            .await
                                        {
                                            Ok(()) => return,
                                            Err(e) if attempt < MAX_PUBLISH_ATTEMPTS => {
                                                warn!(
                                                    "Failed to publish mined block (attempt {}/{}): {}",
                                                    attempt, MAX_PUBLISH_ATTEMPTS, e
                                                );
                                                tokio::time::sleep(Duration::from_secs(
                                                    2 * attempt as u64,
                                                ))
                                                .await;
                                            }
                                            Err(e) => {
                                                warn!(
                                                    "Failed to publish mined block after {} attempts: {}",
                                                    MAX_PUBLISH_ATTEMPTS, e
                                                );
                                            }
                                        }
                                    }
                                });

                                if !continuous {
                                    break 'mining;
                                }

                                // NETWORK-CITIZEN PACING between rounds:
                                // 1) Absorption wait — poll the signed beacon (edge-
                                //    cached, same cadence as the background watch)
                                //    until the network reflects a block at our height
                                //    (ours or a competitor's), so we never stack new
                                //    blocks faster than the network can propagate
                                //    them. Bounded at 20s and fail-open: a beacon
                                //    hiccup falls through to the next prep, which
                                //    re-converges anyway.
                                // 2) Jittered courtesy delay — desynchronizes multiple
                                //    continuous miners so their prep/poll cycles never
                                //    line up into synchronized bursts against the
                                //    free-tier gateway.
                                let absorb_deadline = Instant::now() + Duration::from_secs(20);
                                loop {
                                    if stop_flag.load(Ordering::SeqCst)
                                        || Instant::now() >= absorb_deadline
                                    {
                                        break;
                                    }
                                    match node.network_beacon_height().await {
                                        Some(h) if h >= mined_height => break,
                                        _ => sleep_interruptible(
                                            Duration::from_secs(2),
                                            &stop_flag,
                                        )
                                        .await,
                                    }
                                }
                                let jitter_ms = 2_000
                                    + (SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .subsec_nanos() as u64
                                        % 3_000);
                                sleep_interruptible(
                                    Duration::from_millis(jitter_ms),
                                    &stop_flag,
                                )
                                .await;
                            }
                            Err(e) => {
                                // LOST RACE, not a fault: we solved a height, but the
                                // network's block for it arrived first and the background
                                // sync adopted it, so finalization correctly rejects our
                                // now-stale header ("Block header is invalid"). Routine
                                // under heavy racing (difficulty climbing = more miners) —
                                // it must NOT count toward the permanent-error stop, or 5
                                // straight photo-finish losses would kill the mining loop
                                // exactly when competition is most interesting. Retarget
                                // the new tip immediately with only the small jitter.
                                let lost_race = e.to_string().contains("Block header is invalid");
                                if lost_race && continuous {
                                    consecutive_mine_errors = 0;
                                    println!(
                                        "Lost the race for this block (another miner's was adopted, no reward for this solve) — retargeting the new tip…"
                                    );
                                    let jitter_ms = 1_000
                                        + (SystemTime::now()
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .subsec_nanos() as u64
                                            % 2_000);
                                    sleep_interruptible(
                                        Duration::from_millis(jitter_ms),
                                        &stop_flag,
                                    )
                                    .await;
                                    continue 'mining;
                                }
                                if lost_race {
                                    // Single-shot mine: same lost race, but the loop exits.
                                    // Say what actually happened — "Mining error: Block
                                    // header is invalid" reads as a fault when it's a
                                    // photo-finish loss to another miner.
                                    println!(
                                        "Lost the race for this block (another miner's was adopted) — no reward for this solve. Run `mine` again to compete for the next one."
                                    );
                                    break 'mining;
                                }
                                println!("Mining error: {}", e);
                                if !continuous {
                                    break 'mining;
                                }
                                consecutive_mine_errors += 1;
                                if consecutive_mine_errors >= MAX_CONSECUTIVE_MINE_ERRORS {
                                    println!(
                                        "Stopping continuous mining: {} mining errors in a row — fix the issue and run mine again.",
                                        consecutive_mine_errors
                                    );
                                    break 'mining;
                                }
                                println!(
                                    "Backing off {}s before the next attempt…",
                                    backoff.as_secs()
                                );
                                sleep_interruptible(backoff, &stop_flag).await;
                                backoff = (backoff * 2).min(Duration::from_secs(60));
                            }
                        }
                    }
                    if continuous {
                        if stop_flag.load(Ordering::SeqCst) {
                            println!(
                                "Continuous mining stopped ({} block(s) mined this run).",
                                mined_count
                            );
                        } else {
                            println!(
                                "Continuous mining ended ({} block(s) mined this run) — press Enter to return to the console.",
                                mined_count
                            );
                        }
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

for wallet in wallets.values() {
    // Short-lived per-wallet read guard (mirrors the whisper sync loop and the `info`
    // handler). scan_blockchain_for_messages walks tip->cutoff with a get_block per height
    // (~tens of thousands of reads over the 48h window), repeated for every wallet. Holding
    // ONE guard across the whole batch would park a queued block-save writer — and then every
    // reader behind it — on tokio's write-preferring RwLock for the entire scan.
    let blockchain_guard = blockchain.read().await;

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
writeln!(&mut stdout,"  Amount: {:.8} Fee: {:.8}", msg.amount, msg.fee)?;

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
                if msg.chars().count() > alphanumeric::a9::whisper::MAX_WHISPER_CHARS {
                    let mut error_style = ColorSpec::new();
                    error_style.set_fg(Some(Color::Red)).set_bold(true);
                    stdout.set_color(&error_style)?;
                    println!("Whisper carries a 4-letter (a-z) code only; shorten the message.");
                    stdout.reset()?;
                    continue;
                }
                (&parts[1], alphanumeric::a9::whisper::WHISPER_MIN_AMOUNT, msg)
            },
            4 => {
                let amount = match parts[2].parse::<f64>() {
                    Ok(a) if a.is_finite() && a >= alphanumeric::a9::whisper::WHISPER_MIN_AMOUNT => a,
                    _ => {
                        let mut error_style = ColorSpec::new();
                        error_style.set_fg(Some(Color::Red)).set_bold(true);
                        stdout.set_color(&error_style)?;
                        println!("Minimum {} token required for whisper messages", 
                            alphanumeric::a9::whisper::WHISPER_MIN_AMOUNT);
                        stdout.reset()?;
                        continue;
                    }
                };

                let msg = parts[3].trim_matches('"');
                if msg.chars().count() > alphanumeric::a9::whisper::MAX_WHISPER_CHARS {
                    let mut error_style = ColorSpec::new();
                    error_style.set_fg(Some(Color::Red)).set_bold(true);
                    stdout.set_color(&error_style)?;
                    println!("Whisper carries a 4-letter (a-z) code only; shorten the message.");
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


writeln!(&mut stdout, "whisper (Displays recent whispers.)")?;
writeln!(&mut stdout, "whisper <recipient> <amount> <message> Send a new whisper to <recipient>.")?;

stdout.set_color(&section_style)?;
write!(&mut stdout, "\n Whisper Code")?;
stdout.reset()?;
    writeln!(stdout, "\n───────────────────")?;

writeln!(&mut stdout, "Embed a short alphabetic message, 4-character (4-byte) code.")?;
writeln!(&mut stdout, "This optional feature provides a vanity fee code that can be seen by decoding the fee with a cipher.")?;
stdout.set_color(&description_style)?;
write!(&mut stdout, "Whisper codes can be decoded from the public ledger so do not share sensitive information.\n\n")?;

stdout.flush()?;
continue;
}
        };

        // Deterministic payer: `wallets` is a HashMap, so .values().next() funded the whisper
        // from an ARBITRARY wallet each run (a mild fund-safety surprise). Pick the
        // lowest-address wallet so the same one signs every time; the receipt prints it below.
        let sender_wallet = match wallets.values().min_by(|a, b| a.address.cmp(&b.address)) {
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
    // Scope the WRITE guard to the submit itself: the success arm below does console
    // IO and (since v7.6.8) network gossip, and holding a chain write guard across
    // awaits is the known wedge class.
    let submit_res = {
        let blockchain_guard = blockchain.write().await;
        // No wallet registry needed - transactions are self-contained with public keys
        blockchain_guard.add_transaction(whisper_tx.clone()).await
    };
    match submit_res {
        Ok(_) => {
// Announce like any other tx: whispers ride the same mempool/gossip path, and
// without this only the sender could ever mine the whisper into a block.
node.gossip_transaction(&whisper_tx).await;
let mut stdout = StandardStream::stdout(ColorChoice::Always);
let mut style = ColorSpec::new();

style.set_fg(Some(Color::Rgb(132, 132, 132))).set_bold(false);
stdout.set_color(&style)?;
writeln!(stdout, "\n    ...ML-DSA-87 verification complete")?;
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
writeln!(stdout, "  From: {}", sender_wallet.address)?;
writeln!(stdout, "  Amount: {:.8}", whisper_tx.amount())?;
writeln!(stdout, "  Fee: {:.8}", whisper_tx.fee())?;
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
    Some(cmd) if cmd.starts_with("--") => {
        if let Err(e) = handle_network_commands(&command, &node, &blockchain).await {
            println!("Network command error: {}", e);
        }
    },
    Some("account") => {
        if let Err(e) = mgmt
            .handle_account_command(&command, &blockchain, &wallets)
            .await
        {
            println!("Error displaying account info: {}", e);
        }
    },

Some("debug") | Some("diagnostics") | Some("diag") => {
    let blockchain_guard = blockchain.read().await;
    let oracle = DifficultyOracle::new();

    if let Some(last_block) = blockchain_guard.get_last_block() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let timestamp_diff = now.saturating_sub(last_block.timestamp);
        let tip_difficulty = blockchain_guard.get_tip_difficulty().await;
        let next_difficulty = blockchain_guard.get_current_difficulty().await;

        if let Err(e) = oracle
            .display_difficulty_metrics(tip_difficulty, next_difficulty, timestamp_diff)
            .await
        {
            error!("Failed to display diagnostics: {}", e);
            println!("Error displaying diagnostics: {}", e);
        }
    } else {
        println!("No blocks available for diagnostics");
    }

    println!("Consensus Fingerprint: {}", consensus_fingerprint);
    println!("Consensus Descriptor:  {}", consensus_descriptor);
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
    println!("debug                                 - Show dynamic network diagnostics");

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
 // Avoid spawning `cmd.exe` (common heuristic trigger). If you really want pause-on-exit
 // for double-click runs, opt in with `ALPHANUMERIC_PAUSE_ON_EXIT=true`.
 if cfg!(windows) && std::env::var("ALPHANUMERIC_PAUSE_ON_EXIT").ok().as_deref() == Some("true") {
     let _ = Command::new("cmd").args(["/C", "pause"]).status();
 }
let _ = remove_db_lock(&format!("{}.lock", db_path));
let _ = remove_instance_lock();
return Ok(());
},

Some(_) => {
                    // Bare-transfer shorthand: "<from_addr> <to_addr> <amount>" with no
                    // "create" keyword is treated as a create transaction — two 40-hex
                    // addresses followed by a positive amount has no other meaning, so
                    // accept it instead of rejecting as an invalid command.
                    let parts: Vec<&str> = command.split_whitespace().collect();
                    let is_addr =
                        |s: &str| s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit());
                    if parts.len() == 3
                        && is_addr(parts[0])
                        && is_addr(parts[1])
                        && parts[2].parse::<f64>().map(|a| a > 0.0).unwrap_or(false)
                    {
                        let synthesized = format!("create {} {} {}", parts[0], parts[1], parts[2]);
                        match mgmt
                            .handle_create_transaction(
                                &synthesized,
                                &mut wallets,
                                &blockchain,
                                &db_arc,
                            )
                            .await
                        {
                            Ok(tx) => {
                                // Same as the explicit create arm: announce or nobody mines it.
                                node.gossip_transaction(&tx).await;
                            }
                            Err(e) => {
                                println!("Error: {}", e);
                                println!("Failed to create transaction: {}", e);
                            }
                        }
                    } else {
                        println!("Invalid command. Type 'help' for command list or 'info' for blockchain details.");
                    }
                }
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
    // Beacon-driven sync. Across NAT the p2p peer table is empty, so the authoritative
    // network tip is the signed beacon — NOT a peer-reported height. The old code read
    // `peers.values().map(|i| i.blocks).max().unwrap_or(0)`, which with no peers always
    // concluded "already at current height" and no-oped, so `--sync` never actually
    // synced. converge_to_canonical drives us to the beacon tip from ANY state: forward-
    // stream when merely behind, incremental reorg when our tip has diverged.
    let mp = MultiProgress::new();
    let status_pb = mp.add(ProgressBar::new_spinner());
    status_pb.enable_steady_tick(Duration::from_millis(120));
    status_pb.set_message("Syncing to the network tip…");

    let local_height = { node.blockchain.read().await.get_latest_block_index() as u32 };
    let outcome = node.sync_to_beacon().await;
    let tip_now = { node.blockchain.read().await.get_latest_block_index() as u32 };

    match outcome {
        Converge::Converged => {
            status_pb.finish_with_message(format!("Synced to the network tip: {}", tip_now));
            Ok(())
        }
        Converge::AtTipAhead => {
            status_pb.finish_with_message(format!(
                "At or ahead of the network tip ({}) — ready to mine",
                tip_now
            ));
            Ok(())
        }
        Converge::Progressed => {
            status_pb.finish_with_message(format!(
                "Synced from {} to {} — run --sync again to finish catching up",
                local_height, tip_now
            ));
            Ok(())
        }
        Converge::NeedsBootstrap => {
            status_pb.finish_with_message(
                "Local chain diverged below the finality window; a re-bootstrap is required",
            );
            Ok(())
        }
        Converge::BeaconStale => {
            status_pb
                .finish_with_message("Network tip beacon unavailable; try --sync again shortly");
            Ok(())
        }
        Converge::BranchInvalid => {
            status_pb.finish_with_message(
                "Canonical branch failed local validation; staying on the local chain — try --sync again shortly",
            );
            Ok(())
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
    let cmd = parts.first().copied().unwrap_or("");

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
                if !peers.is_empty() {
                    "Online"
                } else {
                    "Offline"
                }
            );
            println!("Connected Peers: {}", peers.len());
            println!("Node Address: {}", node.get_public_key());
            println!("P2P Port: {}", DEFAULT_PORT);
            println!(
                "Uptime: {}d {}h {}m",
                uptime_days, uptime_hours, uptime_minutes
            );
            println!();
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
                            // Bound the raw connect: verify_peer below has its own 10s timeout,
                            // but an untimed TcpStream::connect against a black-holing firewall
                            // can hang for the OS SYN-retry default (tens of seconds), freezing
                            // this diagnostic far longer than the retry logic assumes.
                            match tokio::time::timeout(
                                Duration::from_secs(10),
                                TcpStream::connect(socket_addr),
                            )
                            .await
                            {
                                Ok(Ok(_)) => println!("✓ TCP connection successful"),
                                Ok(Err(e)) => {
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
                                Err(_) => {
                                    println!("✗ TCP connection timed out after 10s");
                                    println!("  - Target unreachable or packets filtered/dropped");
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

                                    // Show peer details (guard dropped BEFORE the long
                                    // sync below — never hold the peers lock across
                                    // network work).
                                    {
                                        let peers = node.peers.read().await;
                                        if let Some(peer_info) = peers.get(&socket_addr) {
                                            println!("\nPeer Details:");
                                            println!("Version: {}", peer_info.version);
                                            println!("Blocks: {}", peer_info.blocks);
                                            println!("Latency: {}ms", peer_info.latency);
                                        }
                                    }

                                    println!("\nAttempting initial sync...");
                                    if let Err(e) = handle_chain_sync(node).await {
                                        println!("Initial sync failed: {}", e);
                                    } else {
                                        if let Err(e) = node.publish_local_tip().await {
                                            warn!("Post-sync publish failed: {}", e);
                                        }
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
                    // Snapshot peer stats and DROP the guard before the sync below —
                    // never hold the peers lock across network work.
                    let (final_peers, connected_subnets) = {
                        let peers = node.peers.read().await;
                        let mut subnets = HashSet::new();
                        for (addr, info) in peers.iter() {
                            if let Some(subnet) = info.get_subnet(addr.ip()) {
                                subnets.insert(subnet);
                            }
                        }
                        (peers.len(), subnets)
                    };
                    let new_peers = final_peers.saturating_sub(initial_peers);

                    // Show detailed peer information
                    if new_peers > 0 {

                        pb.finish_with_message(format!(
                            "Found {} new peers (total: {}) across {} subnets",
                            new_peers,
                            final_peers,
                            connected_subnets.len()
                        ));

                        // If we have peers, try to sync
                        if final_peers > 0 {
                            if let Err(e) = handle_chain_sync(node).await {
                                warn!("Initial sync with discovered peers failed: {}", e);
                            } else if let Err(e) = node.publish_local_tip().await {
                                warn!("Post-sync publish failed: {}", e);
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
            println!("\nNetwork Participants");
            println!("--------------------");

            if peers.is_empty() {
                // Direct p2p is expected to be empty for NAT'd nodes — the network runs
                // over the gateway relay, not a p2p mesh — so this is normal, not a fault.
                println!("Direct p2p peers: 0 (relay mode — normal for NAT'd nodes)");
            } else {
                for (addr, info) in peers.iter() {
                    let last_seen = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .saturating_sub(info.last_seen);

                    println!(
                        "  p2p {} (latency: {}ms, last seen: {}s ago)",
                        addr, info.latency, last_seen
                    );
                }
            }
            drop(peers);

            // Real network participation: the gateway roster of live nodes + the tip.
            if let Some(overview) = fetch_gateway_overview().await {
                if let Some(p) = overview.peers {
                    println!("Network peers (gateway): {}", p);
                }
                if let Some(h) = overview.height {
                    println!("Network height:          {}", h);
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

            match handle_chain_sync(node).await {
                Ok(_) => {
                    if let Err(e) = node.publish_local_tip().await {
                        warn!("Post-sync publish failed: {}", e);
                    }
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
    // Version is templated from Cargo.toml at compile time so the banner never drifts
    // out of sync with the actual build (it previously hardcoded an older version).
    let ascii_art = r#"

                        -++-    -++-                                  alphanumeric v__VERSION__
                       -+++.   .+++
                .++++++++++++++++++++++-                              Architecture: Rust
                -####++++#####++++#####+                              Algorithm: SHA-256
                    -++++-   --+++.                                              BLAKE3
             .++++++++++++++++++++++++-                               Database: sled
             +#####+++######++++######+                               Encryption: Argon2
                 -+++++----++++-                                      Quantum DSS: ML-DSA-87
                .+++++.  .-+++-
                ++++     ++++.

"#
    .replace("__VERSION__", env!("CARGO_PKG_VERSION"));

    let start_color = (42, 93, 253); // White
    let end_color = (190, 252, 233); // Neon Green

    let lines: Vec<&str> = ascii_art.lines().collect();
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

struct StartupLockGuard {
    db_lock_path: String,
}

impl Drop for StartupLockGuard {
    fn drop(&mut self) {
        let _ = remove_db_lock(&self.db_lock_path);
        let _ = remove_instance_lock();
    }
}

fn acquire_startup_locks(db_path: &str) -> std::io::Result<StartupLockGuard> {
    ensure_instance_lock()?;
    if let Err(err) = ensure_db_lock(db_path) {
        let _ = remove_instance_lock();
        return Err(err);
    }
    Ok(StartupLockGuard {
        db_lock_path: format!("{}.lock", db_path),
    })
}

fn ensure_instance_lock() -> std::io::Result<()> {
    ensure_pid_lock(INSTANCE_LOCK_PATH, "ALPHANUMERIC_IGNORE_INSTANCE_LOCK")
}

fn remove_instance_lock() -> std::io::Result<()> {
    remove_db_lock(INSTANCE_LOCK_PATH)
}

fn ensure_pid_lock(lock_path: &str, ignore_env: &str) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(lock_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    if std::path::Path::new(&lock_path).exists() {
        let allow = std::env::var(ignore_env)
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if allow {
            let _ = std::fs::remove_file(lock_path);
        } else if let Ok(pid_str) = std::fs::read_to_string(lock_path) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                if !is_process_alive(pid) {
                    let _ = std::fs::remove_file(lock_path);
                } else {
                    return Err(std::io::Error::other(
                        "Database lock exists. Another instance may be running.",
                    ));
                }
            } else {
                return Err(std::io::Error::other(
                    "Database lock exists. Another instance may be running.",
                ));
            }
        } else {
            return Err(std::io::Error::other(
                "Database lock exists. Another instance may be running.",
            ));
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(lock_path)?;
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

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            let v = v.trim();
            v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("1")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

fn bootstrap_zip_size_limit_from_env_value(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value.clamp(MIN_MAX_BOOTSTRAP_ZIP_BYTES, MAX_MAX_BOOTSTRAP_ZIP_BYTES))
        .unwrap_or(DEFAULT_MAX_BOOTSTRAP_ZIP_BYTES)
}

fn bootstrap_zip_size_limit_bytes() -> u64 {
    let value = std::env::var("ALPHANUMERIC_MAX_BOOTSTRAP_ZIP_BYTES").ok();
    bootstrap_zip_size_limit_from_env_value(value.as_deref())
}

fn unverified_bootstrap_extract_limit_from_env_value(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| {
            value.clamp(
                MIN_MAX_UNVERIFIED_BOOTSTRAP_EXTRACT_BYTES,
                MAX_MAX_UNVERIFIED_BOOTSTRAP_EXTRACT_BYTES,
            )
        })
        .unwrap_or(DEFAULT_MAX_UNVERIFIED_BOOTSTRAP_EXTRACT_BYTES)
}

fn unverified_bootstrap_extract_limit_bytes() -> u64 {
    let value = std::env::var("ALPHANUMERIC_MAX_UNVERIFIED_BOOTSTRAP_EXTRACT_BYTES").ok();
    unverified_bootstrap_extract_limit_from_env_value(value.as_deref())
}

fn ensure_bootstrap_zip_size(size: u64, limit: u64, context: &str) -> Result<()> {
    if size > limit {
        return Err(format!(
            "Bootstrap download too large: {} is {} bytes, limit is {} bytes",
            context, size, limit
        )
        .into());
    }
    Ok(())
}

fn ensure_bootstrap_download_progress(
    size: u64,
    expected_size: Option<u64>,
    fallback_limit: Option<u64>,
    context: &str,
) -> Result<()> {
    if let Some(expected_size) = expected_size {
        if size > expected_size {
            return Err(format!(
                "Bootstrap download too large for signed manifest: {} is {} bytes, expected {} bytes",
                context, size, expected_size
            )
            .into());
        }
        return Ok(());
    }

    if let Some(limit) = fallback_limit {
        ensure_bootstrap_zip_size(size, limit, context)?;
    }
    Ok(())
}

fn ensure_bootstrap_download_complete(
    size: u64,
    expected_size: Option<u64>,
    fallback_limit: Option<u64>,
    context: &str,
) -> Result<()> {
    if let Some(expected_size) = expected_size {
        if size != expected_size {
            return Err(format!(
                "Bootstrap download size mismatch: {} is {} bytes, signed manifest expected {} bytes",
                context, size, expected_size
            )
            .into());
        }
        return Ok(());
    }

    if let Some(limit) = fallback_limit {
        ensure_bootstrap_zip_size(size, limit, context)?;
    }
    Ok(())
}

fn bootstrap_disk_buffer_bytes(extracted_bytes: u64) -> u64 {
    (extracted_bytes / 20).max(BOOTSTRAP_MIN_DISK_BUFFER_BYTES)
}

fn bootstrap_required_disk_bytes(compressed_bytes: Option<u64>, extracted_bytes: u64) -> u64 {
    compressed_bytes
        .unwrap_or(0)
        .saturating_add(extracted_bytes)
        .saturating_add(bootstrap_disk_buffer_bytes(extracted_bytes))
}

fn nearest_existing_path(path: &Path) -> Option<std::path::PathBuf> {
    let mut candidate = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    };

    loop {
        if candidate.exists() {
            return std::fs::canonicalize(&candidate).ok();
        }
        if !candidate.pop() {
            return None;
        }
    }
}

fn available_disk_space_for_path(path: &Path) -> Option<u64> {
    let target = nearest_existing_path(path)?;
    let disks = sysinfo::Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .filter(|disk| target.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map(|disk| disk.available_space())
}

fn ensure_bootstrap_disk_space(
    db_path: &Path,
    compressed_bytes: Option<u64>,
    extracted_bytes: Option<u64>,
) -> Result<()> {
    let Some(extracted_bytes) = extracted_bytes else {
        return Ok(());
    };
    let required = bootstrap_required_disk_bytes(compressed_bytes, extracted_bytes);
    let Some(available) = available_disk_space_for_path(db_path) else {
        debug!(
            "Bootstrap disk preflight skipped: could not determine available space for {}",
            db_path.display()
        );
        return Ok(());
    };
    if available < required {
        return Err(format!(
            "Insufficient disk space for bootstrap: available {} bytes, need at least {} bytes for signed snapshot extraction",
            available, required
        )
        .into());
    }
    Ok(())
}

fn update_bootstrap_archive_stats(
    stats: &mut BootstrapArchiveStats,
    copied_bytes: u64,
    expectations: BootstrapArchiveExpectations,
) -> std::result::Result<(), String> {
    stats.file_count = stats
        .file_count
        .checked_add(1)
        .ok_or_else(|| "Bootstrap archive file count overflow".to_string())?;
    stats.extracted_bytes = stats
        .extracted_bytes
        .checked_add(copied_bytes)
        .ok_or_else(|| "Bootstrap archive extracted byte count overflow".to_string())?;

    if let Some(expected_file_count) = expectations.expected_file_count {
        if stats.file_count > expected_file_count {
            return Err(format!(
                "Bootstrap archive has more files than signed manifest: saw {}, expected {}",
                stats.file_count, expected_file_count
            ));
        }
    }
    if let Some(expected_extracted_bytes) = expectations.expected_extracted_bytes {
        if stats.extracted_bytes > expected_extracted_bytes {
            return Err(format!(
                "Bootstrap archive extracted more data than signed manifest: saw {} bytes, expected {} bytes",
                stats.extracted_bytes, expected_extracted_bytes
            ));
        }
    } else if let Some(limit) = expectations.unverified_extract_limit {
        if stats.extracted_bytes > limit {
            return Err(format!(
                "Unverified bootstrap archive extraction exceeded limit: saw {} bytes, limit is {} bytes",
                stats.extracted_bytes, limit
            ));
        }
    }

    Ok(())
}

fn finalize_bootstrap_archive_stats(
    stats: BootstrapArchiveStats,
    expectations: BootstrapArchiveExpectations,
) -> std::result::Result<(), String> {
    if let Some(expected_file_count) = expectations.expected_file_count {
        if stats.file_count != expected_file_count {
            return Err(format!(
                "Bootstrap archive file count mismatch: extracted {}, signed manifest expected {}",
                stats.file_count, expected_file_count
            ));
        }
    }
    if let Some(expected_extracted_bytes) = expectations.expected_extracted_bytes {
        if stats.extracted_bytes != expected_extracted_bytes {
            return Err(format!(
                "Bootstrap archive extracted size mismatch: extracted {} bytes, signed manifest expected {} bytes",
                stats.extracted_bytes, expected_extracted_bytes
            ));
        }
    }
    Ok(())
}

fn bootstrap_manifest_http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()?)
}

fn bootstrap_download_http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(30))
        .build()?)
}

#[cfg(feature = "bootstrap_publisher")]
fn env_u64_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn set_restrictive_file_permissions(path: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(windows)]
    {
        // A private key MUST NOT be world-readable. Restricting NTFS access needs ACLs
        // (winapi), which we don't apply here — and `set_readonly` restricts WRITE, not
        // READ, so the previous code was a security no-op that pretended the key was
        // protected. Warn loudly instead of silently lying about protection.
        let _ = path;
        eprintln!(
            "WARNING: key file {} cannot be permission-restricted on Windows without ACLs; \
             protect it manually (its directory should be user-only).",
            path
        );
    }
    Ok(())
}

/// Write secret bytes to `path` such that the file is 0600 from the instant it is CREATED,
/// closing the TOCTOU window in which a plain write-then-chmod leaves a freshly-created key
/// briefly world/group-readable. For a pre-existing file we also re-assert 0600.
async fn write_secret_file(path: &str, data: &[u8]) -> std::io::Result<()> {
    // Atomic replace: write to a sibling temp file, fsync it, then rename over the
    // target. A crash / power loss / ENOSPC mid-write leaves either the intact old
    // file or the complete new one — never a truncated key that fails to parse and
    // bricks the wallet / node identity on next launch. mode(0o600) on creation keeps
    // the temp (and thus the renamed target) from ever being world-readable.
    use tokio::io::AsyncWriteExt;
    let tmp = format!("{}.tmp", path);
    #[cfg(unix)]
    {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .await?;
        f.write_all(data).await?;
        f.flush().await?;
        f.sync_all().await?;
    }
    #[cfg(not(unix))]
    {
        let mut f = tokio::fs::File::create(&tmp).await?;
        f.write_all(data).await?;
        f.flush().await?;
        f.sync_all().await?;
    }
    tokio::fs::rename(&tmp, path).await?;
    // Best-effort: fsync the parent directory so the rename itself survives power loss.
    #[cfg(unix)]
    {
        let parent = std::path::Path::new(path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        if let Ok(dir) = tokio::fs::File::open(&parent).await {
            let _ = dir.sync_all().await;
        }
    }
    // Belt-and-suspenders: re-assert perms for a file that pre-existed this write.
    // No-op-with-warning on Windows.
    let _ = set_restrictive_file_permissions(path);
    Ok(())
}

async fn load_or_create_node_identity_key(path: &str) -> Result<Vec<u8>> {
    if std::path::Path::new(path).exists() {
        let key_bytes = fs::read(path).await?;
        let _ = Ed25519KeyPair::from_pkcs8(&key_bytes)
            .map_err(|_| format!("Invalid node identity key bytes at {}", path))?;
        let _ = set_restrictive_file_permissions(path);
        return Ok(key_bytes);
    }

    let rng = SystemRandom::new();
    let key_pair_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| format!("Failed to generate node identity key pair: {}", e))?;
    write_secret_file(path, key_pair_pkcs8.as_ref()).await?;
    Ok(key_pair_pkcs8.as_ref().to_vec())
}

async fn ensure_bootstrap_db(db_path: &str) -> Result<()> {
    let force_bootstrap = env_flag_enabled("ALPHANUMERIC_FORCE_BOOTSTRAP");
    // Whether this run was demanded by the runtime divergence marker — captured
    // before the decision (remove_local_db deletes the marker with the dir), so
    // a successful restore can stamp the bootstrap-cycle cooldown.
    let was_marker_forced = force_rebootstrap_marker_path(db_path).exists();

    // Fetch and verify the signed bootstrap manifest up front. It carries the
    // canonical tip (height + hash) we reconcile a genesis-valid local DB against,
    // and the download URL if we do end up (re)bootstrapping.
    let manifest_client = bootstrap_manifest_http_client()?;
    let manifest_result: Result<BootstrapManifestPointer> =
        match manifest_client.get(BOOTSTRAP_MANIFEST_URL).send().await {
            Ok(r) if r.status().is_success() => match r.bytes().await {
                Ok(body) => match serde_json::from_slice::<BootstrapManifestResponse>(&body) {
                    Ok(parsed) if parsed.ok => match verify_bootstrap_manifest(&parsed.manifest) {
                        Ok(()) => Ok(parsed.manifest),
                        Err(e) => Err(e),
                    },
                    Ok(_) => Err("Bootstrap manifest response is not ok".into()),
                    Err(e) => Err(format!("Bootstrap manifest payload parse failed: {}", e).into()),
                },
                Err(e) => Err(format!("Bootstrap manifest body read failed: {}", e).into()),
            },
            Ok(r) => Err(format!("Bootstrap manifest endpoint failed: {}", r.status()).into()),
            Err(e) => Err(format!("Bootstrap manifest request failed: {}", e).into()),
        };

    if !force_bootstrap {
        match local_launch_db_status(db_path) {
            LaunchDbStatus::Valid => {
                // Genesis is correct — but is this chain actually canonical? Compare
                // our tip against the signed manifest tip. If we hold the canonical
                // block (or are ahead of it on the same chain) we are in sync. If we
                // forked or fell behind, re-bootstrap to the canonical chain rather
                // than keep running on a stale/losing chain. Unreachable manifest =>
                // keep the local DB (fail-open, so an offline start still works).
                // Best-effort live tip beacon: the freshest canonical height for the
                // behind/in-sync decision (the manifest can lag by its publish
                // cadence — or by hours when snapshot publishing is broken).
                let live_beacon_height: Option<u32> = async {
                    let client = reqwest::Client::builder()
                        .timeout(Duration::from_millis(2500))
                        .build()
                        .ok()?;
                    let body = client
                        .get(TIP_URL)
                        .send()
                        .await
                        .ok()?
                        .json::<serde_json::Value>()
                        .await
                        .ok()?;
                    if body.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                        return None;
                    }
                    body.get("height")
                        .and_then(|v| v.as_u64())
                        .and_then(|h| u32::try_from(h).ok())
                }
                .await;
                // Canonical anchor at-or-below our tip: only needed (and only
                // fetched) when we are behind the manifest height, i.e. when the
                // manifest-height hash comparison inside the decision can't run.
                let canonical_anchor: Option<(u32, String)> = match (
                    &manifest_result,
                    local_tip_height(db_path),
                ) {
                    (Ok(m), Some(tip)) if m.height.map(|h| h as u32 > tip).unwrap_or(false) => {
                        fetch_canonical_anchor_at_or_below(tip).await
                    }
                    _ => None,
                };
                match canonical_reconcile_decision(db_path, &manifest_result, live_beacon_height, canonical_anchor) {
                    CanonicalReconcile::InSyncOrUnknown => {
                        println!(
                            "Bootstrap skipped: launch network DB is on the canonical chain at {}",
                            db_path
                        );
                        return Ok(());
                    }
                    CanonicalReconcile::Diverged {
                        local,
                        canonical_height,
                        canonical_hash,
                    } => {
                        println!(
                            "Local chain is not canonical (canonical tip {}={}…, local had {}); re-bootstrapping to the canonical chain",
                            canonical_height,
                            &canonical_hash[..canonical_hash.len().min(16)],
                            local
                        );
                        remove_local_db(db_path).await?;
                    }
                }
            }
            LaunchDbStatus::Missing | LaunchDbStatus::Empty => {}
            LaunchDbStatus::WrongGenesis(actual) => {
                println!(
                    "Replacing local DB at {}: wrong genesis {}",
                    db_path, actual
                );
                remove_local_db(db_path).await?;
            }
            LaunchDbStatus::Unreadable(err) => {
                println!("Replacing local DB at {}: {}", db_path, err);
                remove_local_db(db_path).await?;
            }
        }
    }
    if force_bootstrap {
        println!("Forcing bootstrap download (ALPHANUMERIC_FORCE_BOOTSTRAP=true)");
        remove_local_db(db_path).await?;
    }

    let (
        download_url,
        expected_sha256,
        expected_height,
        expected_tip_hash,
        expected_compressed_bytes,
        expected_extracted_bytes,
        expected_file_count,
        verified_manifest,
    ) = match manifest_result {
        Ok(manifest) => {
            let expected_sha256 = manifest
                .sha256
                .as_ref()
                .map(|v| v.trim().to_ascii_lowercase());
            let expected_tip_hash = manifest
                .tip_hash
                .as_ref()
                .map(|v| v.trim().to_ascii_lowercase());
            (
                manifest.url.clone(),
                expected_sha256,
                manifest.height,
                expected_tip_hash,
                manifest.compressed_bytes,
                manifest.extracted_bytes,
                manifest.file_count,
                true,
            )
        }
        Err(e) => {
            // Fail closed: a chain snapshot must always carry a SHA-256-bound, signed manifest.
            // The old ALPHANUMERIC_ALLOW_UNVERIFIED_BOOTSTRAP escape hatch is removed — a security
            // control must not be defeatable by an env var (an attacker who can set env or MITM
            // the download could otherwise seed a forged chain).
            return Err(format!("Bootstrap manifest verification failed: {}", e).into());
        }
    };

    if !download_url.starts_with("https://") {
        return Err("Bootstrap manifest URL must use https".into());
    }

    if let Some(parent) = std::path::Path::new(db_path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).await.map_err(|e| {
                format!(
                    "Bootstrap parent directory create failed at {}: {}",
                    parent.display(),
                    e
                )
            })?;
        }
    }

    ensure_bootstrap_disk_space(
        std::path::Path::new(db_path),
        expected_compressed_bytes,
        expected_extracted_bytes,
    )?;

    let zip_path = format!("{}.zip", db_path);
    let download_client = bootstrap_download_http_client()?;
    let mut res = download_client
        .get(&download_url)
        .send()
        .await
        .map_err(|e| {
            format!(
                "Bootstrap download request failed for {}: {}",
                download_url, e
            )
        })?;

    if !res.status().is_success() {
        return Err(format!("Bootstrap download failed: {}", res.status()).into());
    }

    let fallback_zip_limit = (!verified_manifest).then(bootstrap_zip_size_limit_bytes);
    if let Some(content_length) = res.content_length() {
        ensure_bootstrap_download_complete(
            content_length,
            expected_compressed_bytes,
            fallback_zip_limit,
            "advertised content length",
        )?;
    }

    let mut zip_file = fs::File::create(&zip_path)
        .await
        .map_err(|e| format!("Bootstrap zip write failed at {}: {}", zip_path, e))?;
    let mut downloaded_size = 0u64;
    let mut hasher = Sha256::new();
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| format!("Bootstrap download body read failed: {}", e))?
    {
        let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        downloaded_size = downloaded_size
            .checked_add(chunk_len)
            .ok_or("Bootstrap download byte count overflow")?;
        ensure_bootstrap_download_progress(
            downloaded_size,
            expected_compressed_bytes,
            fallback_zip_limit,
            "downloaded body",
        )?;
        hasher.update(&chunk);
        zip_file
            .write_all(&chunk)
            .await
            .map_err(|e| format!("Bootstrap zip write failed at {}: {}", zip_path, e))?;
    }
    zip_file
        .flush()
        .await
        .map_err(|e| format!("Bootstrap zip flush failed at {}: {}", zip_path, e))?;
    drop(zip_file);

    ensure_bootstrap_download_complete(
        downloaded_size,
        expected_compressed_bytes,
        fallback_zip_limit,
        "downloaded body",
    )?;
    ensure_bootstrap_disk_space(
        std::path::Path::new(db_path),
        None,
        expected_extracted_bytes,
    )?;

    // Verified manifests must provide SHA-256. The only no-hash path is the
    // explicit unsafe fallback for local/dev recovery.
    if let Some(expected) = expected_sha256
        .as_deref()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
    {
        let actual = hex::encode(hasher.finalize());
        if actual != expected {
            return Err(format!(
                "Bootstrap SHA-256 mismatch: expected {}, got {}",
                expected, actual
            )
            .into());
        }
    }

    let bootstrap_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let temp_extract_path = format!("{}.bootstrap_tmp_{}", db_path, bootstrap_ts);
    if std::path::Path::new(&temp_extract_path).exists() {
        let _ = std::fs::remove_dir_all(&temp_extract_path);
    }

    let extract_path = temp_extract_path.clone();
    let zip_path_clone = zip_path.clone();
    let archive_expectations = BootstrapArchiveExpectations {
        expected_extracted_bytes,
        expected_file_count,
        unverified_extract_limit: (!verified_manifest)
            .then(unverified_bootstrap_extract_limit_bytes),
    };
    let extract_result = tokio::task::spawn_blocking(
        move || -> std::result::Result<BootstrapArchiveStats, String> {
            let file = std::fs::File::open(&zip_path_clone).map_err(|e| e.to_string())?;
            let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&extract_path).map_err(|e| e.to_string())?;
            let base_dir = std::fs::canonicalize(&extract_path).map_err(|e| e.to_string())?;
            let mut stats = BootstrapArchiveStats::default();
            for i in 0..archive.len() {
                let mut file = archive.by_index(i).map_err(|e| e.to_string())?;
                let entry_name = file.name();
                let relative = std::path::Path::new(entry_name);
                if relative.is_absolute()
                    || relative
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    return Err(format!(
                        "Unsafe bootstrap archive entry path: {}",
                        entry_name
                    ));
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
                    return Err(format!(
                        "Blocked bootstrap archive escape path: {}",
                        entry_name
                    ));
                }
                if file.name().ends_with('/') {
                    std::fs::create_dir_all(&outpath).map_err(|e| e.to_string())?;
                } else {
                    let mut outfile = std::fs::File::create(&outpath).map_err(|e| e.to_string())?;
                    // Cap the per-entry copy so a single oversized entry can't exhaust disk
                    // BEFORE the cumulative-size check runs (the unverified path isn't SHA-pinned).
                    // Read at most (budget - already-extracted + 1) bytes; the +1 guarantees
                    // update_bootstrap_archive_stats sees the overflow and aborts mid-extract.
                    let budget = archive_expectations
                        .expected_extracted_bytes
                        .or(archive_expectations.unverified_extract_limit);
                    let copied = if let Some(limit) = budget {
                        let remaining =
                            limit.saturating_sub(stats.extracted_bytes).saturating_add(1);
                        std::io::copy(&mut std::io::Read::take(&mut file, remaining), &mut outfile)
                            .map_err(|e| e.to_string())?
                    } else {
                        std::io::copy(&mut file, &mut outfile).map_err(|e| e.to_string())?
                    };
                    update_bootstrap_archive_stats(&mut stats, copied, archive_expectations)?;
                }
            }
            finalize_bootstrap_archive_stats(stats, archive_expectations)?;
            std::fs::remove_file(&zip_path_clone).ok();
            Ok(stats)
        },
    )
    .await
    .map_err(|e| e.to_string())?;

    if let Err(e) = extract_result {
        let _ = std::fs::remove_dir_all(&temp_extract_path);
        let _ = fs::remove_file(&zip_path).await;
        return Err(Box::<dyn Error>::from(e));
    }

    if let Err(e) = verify_bootstrap_snapshot_tip(
        &temp_extract_path,
        expected_height,
        expected_tip_hash.as_deref(),
    ) {
        let _ = std::fs::remove_dir_all(&temp_extract_path);
        return Err(e);
    }

    let final_path = std::path::Path::new(db_path);
    let backup_path = format!("{}.bootstrap_backup_{}", db_path, bootstrap_ts);
    let replace_result = (|| -> std::io::Result<()> {
        if std::path::Path::new(&backup_path).exists() {
            let _ = std::fs::remove_dir_all(&backup_path);
        }
        if final_path.exists() {
            std::fs::rename(final_path, &backup_path)?;
        }
        match std::fs::rename(&temp_extract_path, final_path) {
            Ok(()) => {
                if std::path::Path::new(&backup_path).exists() {
                    let _ = std::fs::remove_dir_all(&backup_path);
                }
                Ok(())
            }
            Err(err) => {
                if std::path::Path::new(&backup_path).exists() {
                    let _ = std::fs::rename(&backup_path, final_path);
                }
                Err(err)
            }
        }
    })();
    if let Err(e) = replace_result {
        let _ = std::fs::remove_dir_all(&temp_extract_path);
        return Err(format!(
            "Bootstrap DB replace failed: {} -> {}: {}",
            temp_extract_path, db_path, e
        )
        .into());
    }
    if was_marker_forced {
        // Stamp the cooldown into the FRESH db dir: if this chain diverges again
        // immediately (shattered network), the divergence exit stays up and keeps
        // retrying converge instead of looping snapshot downloads.
        let _ = std::fs::write(rebootstrap_cooldown_path(db_path), b"");
    }
    Ok(())
}

#[derive(Debug)]
enum LaunchDbStatus {
    Valid,
    Missing,
    Empty,
    WrongGenesis(String),
    Unreadable(String),
}

fn local_launch_db_status(db_path: &str) -> LaunchDbStatus {
    let path = std::path::Path::new(db_path);
    if !path.exists() {
        return LaunchDbStatus::Missing;
    }
    if !path.is_dir() {
        return LaunchDbStatus::Unreadable("database path is not a directory".to_string());
    }

    let db = match sled::Config::new()
        .path(db_path)
        .flush_every_ms(Some(1000))
        .open()
    {
        Ok(db) => db,
        Err(e) => return LaunchDbStatus::Unreadable(format!("database open failed: {}", e)),
    };

    let genesis_raw = match db.get(b"block_0") {
        Ok(Some(raw)) => raw,
        Ok(None) => {
            return if db.scan_prefix("block_").next().is_some() {
                LaunchDbStatus::Unreadable("database has blocks but no genesis block".to_string())
            } else {
                LaunchDbStatus::Empty
            }
        }
        Err(e) => return LaunchDbStatus::Unreadable(format!("genesis read failed: {}", e)),
    };

    let genesis = match Block::from_bytes(genesis_raw.as_ref()) {
        Ok(block) => block,
        Err(e) => return LaunchDbStatus::Unreadable(format!("genesis decode failed: {}", e)),
    };

    let expected = match Blockchain::genesis_launch_block() {
        Ok(block) => block.hash,
        Err(e) => {
            return LaunchDbStatus::Unreadable(format!("launch genesis construction failed: {}", e))
        }
    };

    if genesis.hash == expected && genesis.calculate_hash_for_block() == genesis.hash {
        LaunchDbStatus::Valid
    } else {
        LaunchDbStatus::WrongGenesis(hex::encode(genesis.hash))
    }
}

/// Hex hash of the local block at `height`, or None if the DB can't be read or has
/// no block there. Opens the DB in its own short-lived handle (dropped on return).
fn local_block_hash_at(db_path: &str, height: u32) -> Option<String> {
    let db = sled::Config::new()
        .path(db_path)
        .flush_every_ms(Some(1000))
        .open()
        .ok()?;
    let raw = db.get(format!("block_{}", height).as_bytes()).ok()??;
    let block = Block::from_bytes(raw.as_ref()).ok()?;
    Some(hex::encode(block.hash))
}

/// Compact human-readable duration for status display, e.g. 11506 -> "3h 11m".
/// Display-only helper: `info` keeps the raw seconds and appends this so a
/// stalled node's block age reads at a glance instead of as a wall of seconds.
fn human_duration_secs(secs: u64) -> String {
    let (d, h, m, s) = (
        secs / 86_400,
        (secs % 86_400) / 3_600,
        (secs % 3_600) / 60,
        secs % 60,
    );
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m {s}s")
    }
}

/// Decision for whether a genesis-valid local DB is actually on the canonical
/// chain, judged against the signed bootstrap manifest's tip (height + hash).
enum CanonicalReconcile {
    /// We hold the canonical tip block (or are ahead of it on the canonical
    /// chain), or the manifest is unreachable/uninformative — keep the local DB.
    InSyncOrUnknown,
    /// The local chain is not the canonical block at the manifest height — it has
    /// forked or fallen behind — so it must be re-bootstrapped to canonical.
    Diverged {
        local: String,
        canonical_height: u64,
        canonical_hash: String,
    },
}

/// Reconcile a genesis-valid local DB against the signed canonical tip. We are in
/// sync iff our block at the manifest height equals the manifest tip hash (which
/// also covers being ahead of it on the same chain). A fork below the tip yields a
/// different hash there, and being behind yields no block there — both re-bootstrap.
/// Fail-open: if the manifest didn't verify or lacks a tip, we keep the local DB.
///
/// `canonical_anchor` is a known-good canonical `(height, hash)` at or below our
/// LOCAL tip (see fetch_canonical_anchor_at_or_below). Its job is to tell apart
/// two states that look identical from height alone:
///   - BEHIND: our chain is a valid prefix of canonical and just needs the newer
///     blocks fetched forward ("streaming"; cheap, done by the live sync loop).
///   - FORKED: at some height we hold a DIFFERENT block than canonical, so we
///     followed a branch that lost. Streaming can never recover this — the live
///     catch-up is forward-only (it adopts canonical children onto the tip), but
///     canonical blocks won't link onto our diverged tip and it never rewinds to
///     the fork point to rebuild the canonical branch. (A fork older than the
///     finality window is additionally blocked from reorging by the checkpoint,
///     but that is not the general reason.) The only cure is a fresh re-bootstrap.
/// A behind node and a forked node can BOTH lack a block at the manifest tip
/// height, so without the anchor a forked node reads as merely behind, tries to
/// stream forever, and never recovers (the stale-client trap seen live
/// 2026-07-11). The anchor hash-compare catches the fork and re-bootstraps.
fn canonical_reconcile_decision(
    db_path: &str,
    manifest: &Result<BootstrapManifestPointer>,
    live_beacon_height: Option<u32>,
    canonical_anchor: Option<(u32, String)>,
) -> CanonicalReconcile {
    let Ok(m) = manifest else {
        return CanonicalReconcile::InSyncOrUnknown;
    };
    let (Some(height), Some(tip_hash)) = (m.height, m.tip_hash.as_ref()) else {
        return CanonicalReconcile::InSyncOrUnknown;
    };
    let canonical_hash = tip_hash.trim().to_ascii_lowercase();
    let canonical_height = height as u32;
    // Runtime divergence exits drop a marker (see the beacon-watch NeedsBootstrap
    // path): the live loop PROVED this chain cannot converge, which outranks any
    // boot-time comparison — the manifest lags its publish cadence, so a fork AT
    // tip height reads as "in sync" against a stale manifest (the 2026-07-10
    // restart crash-loop). Honoring the marker is also what makes the wide
    // STREAM_WINDOW safe: a genuinely stuck node always has a guaranteed way out.
    // Checked only once the manifest verified (above): with the gateway down a
    // re-bootstrap is impossible anyway, so offline starts stay fail-open and the
    // marker simply persists for the next boot. remove_local_db clears it together
    // with the chain it condemned.
    if force_rebootstrap_marker_path(db_path).exists() {
        return CanonicalReconcile::Diverged {
            local: "forced re-bootstrap (runtime divergence exit)".to_string(),
            canonical_height: height,
            canonical_hash,
        };
    }
    // FRESHNESS (v7.6.5, 2026-07-08 night): the manifest height lags by its publish
    // cadence — and when snapshot publishing broke (413s), it lagged by HOURS, so a
    // node 150+ blocks behind read as "in sync with the manifest" at boot, skipped
    // re-bootstrap, and stayed stranded. The live tip beacon is the freshest signed
    // canonical height (~1-2s), so use it for the AM-I-TOO-FAR-BEHIND decision; the
    // manifest keeps the checkpoint-hash comparison at ITS height (the snapshot is
    // what we would download). A wrong/poisoned beacon can at worst trigger one
    // unnecessary re-bootstrap whose snapshot manifest is still signature-verified.
    let live_height = live_beacon_height.unwrap_or(0).max(canonical_height);

    // Already holding the canonical tip block (or ahead of it on the same chain)?
    // Then we are in sync.
    if let Some(local_hash) = local_block_hash_at(db_path, canonical_height) {
        if local_hash.eq_ignore_ascii_case(&canonical_hash) {
            return CanonicalReconcile::InSyncOrUnknown;
        }
        // BOOT-TIME SIGNED CHECKPOINT (v7.6.5, from the 2026-07-08 shatter): we HOLD
        // a block at the canonical height but its hash DIFFERS from the signed
        // manifest's — this node is on a genuine fork, not merely behind. Treating
        // "ahead by height" as in-sync here left a forked miner that had out-mined
        // the canonical tip stranded FOREVER (its fork's history was unservable, so
        // no one could join it, and no restart could bring it back). At BOOT, the
        // publisher-signed manifest is the recovery anchor: re-bootstrap onto it.
        // This never overrides live work-based fork choice — a running node still
        // follows the heaviest chain; this only makes "restart the node" a reliable
        // way OUT of a stranded fork. Same-height race blocks are unaffected: their
        // holder is not at boot mid-race, and losing 1-2 racing blocks on a restart
        // is normal reorg cost.
        return CanonicalReconcile::Diverged {
            local: format!(
                "forked at {} (local {}…)",
                canonical_height,
                &local_hash[..local_hash.len().min(12)]
            ),
            canonical_height: height,
            canonical_hash,
        };
    }

    // FORK CHECK (see the behind-vs-forked note on this fn). Having no block at
    // the manifest tip height, on its own, only means "behind". Before treating
    // that as a cheap forward catch-up, confirm our tip region is actually ON
    // canonical: compare the local block we hold at the anchor height to the
    // known-good canonical hash there. A mismatch means we are on a lost fork
    // that the forward-only catch-up can never fix (canonical blocks won't link
    // onto our diverged tip, and it never rewinds to rebuild the branch), so
    // re-bootstrap now. Without this check a forked node booted "in sync" and
    // stayed stale until a human forced a bootstrap (2026-07-11, live). No
    // anchor, or no local block at the anchor height, falls through to the plain
    // behind path below.
    let local_tip = local_tip_height(db_path).unwrap_or(0);
    if let Some((anchor_height, anchor_hash)) = canonical_anchor {
        if anchor_height <= local_tip {
            if let Some(local_hash) = local_block_hash_at(db_path, anchor_height) {
                if !local_hash.eq_ignore_ascii_case(&anchor_hash) {
                    return CanonicalReconcile::Diverged {
                        local: format!(
                            "behind and forked: local block at {} is {}… but canonical is {}…",
                            anchor_height,
                            &local_hash[..local_hash.len().min(12)],
                            &anchor_hash[..anchor_hash.len().min(12)]
                        ),
                        canonical_height: height,
                        canonical_hash,
                    };
                }
            }
        }
    }

    // Plain BEHIND (anchor region on canonical, or no anchor to check). If the
    // gap to the live tip is within STREAM_WINDOW, the running node catches up by fetching
    // those blocks forward (the beacon-watch loop's exact-walked adoption) — do
    // NOT re-download the whole chain for a gap the node will close on its own;
    // that is what normal syncing is. Only a gap deeper than the window (or a
    // near-empty DB) is worth a full re-bootstrap.
    if local_tip.saturating_add(STREAM_WINDOW) >= live_height {
        return CanonicalReconcile::InSyncOrUnknown;
    }

    CanonicalReconcile::Diverged {
        local: format!("tip {} ({} behind live tip {})", local_tip, live_height.saturating_sub(local_tip), live_height),
        canonical_height: height,
        canonical_hash,
    }
}

/// How far behind a genesis-valid chain may be and still be caught up by the
/// live beacon-watch loop instead of a full re-download. History of this value:
/// it was 96 (≈8 min at 5s blocks) because the boot decision had to stay
/// conservative — if live convergence was broken, "restart the node" had to
/// reliably trigger a re-bootstrap; a wide window once told a 181-behind node it
/// was in sync at boot while its live loop couldn't converge either, trapping it
/// with no way out (2026-07-08). That escape now comes from the
/// force-rebootstrap marker instead (the runtime divergence exit drops it and
/// the next boot honors it unconditionally), so the window no longer carries the
/// recovery burden and can reflect what streaming is actually good at: any
/// casual close-and-reopen used to trigger a FULL re-download past 8 minutes
/// ("every time I open the client it's behind", 2026-07-10).
///
/// The value is TIED to the converge engine's hard per-append bound
/// (ORPHAN_REORG_DEPTH): a boot window wider than what the live loop will
/// actually stream boots "in sync" and then marker-exits ~40s later — strictly
/// worse than re-bootstrapping at boot (review finding, 2026-07-11; an initial
/// 2000 overshot the 1024 engine bound and the 1025..=2000 band deterministically
/// took the exit path). 1024 blocks ≈ 85 min at target cadence, ~16 relay
/// windows — streams in seconds-to-a-minute in the background while the client
/// is already usable. Gaps the relay can't actually serve (24h TIME-based
/// retention vs slow-cadence eras, fork-storm slot holes) are caught by the
/// converge stall watchdog, which escalates to the marker path within minutes.
/// Forked-at-checkpoint chains (hash mismatch above) never reach this window and
/// still re-bootstrap immediately.
const STREAM_WINDOW: u32 = alphanumeric::a9::blockchain::ORPHAN_REORG_DEPTH;

// Marker + cooldown live in a9::node (single source, shared by the runtime
// divergence exit, mine-prep scheduling, and this boot-time reconcile):
// force_rebootstrap_marker_path / rebootstrap_cooldown_path /
// rebootstrap_cooldown_active — imported above.

/// Whether an idle-reconcile `NeedsBootstrap` warrants the DISRUPTIVE snapshot
/// re-bootstrap (process exit + boot-time re-bootstrap) instead of staying up
/// and catching up in place.
///
/// Returns TRUE when EITHER:
///  - `forked` — the local chain is a genuine FORK of canonical (a proven hash
///    mismatch against a canonical anchor we also hold). This re-bootstraps
///    PROMPTLY regardless of height gap: a forked service node (exchange / wallet
///    API) is serving WRONG-chain data, and incremental convergence cannot cross
///    a below-finality fork. `Converge::NeedsBootstrap` is overloaded — it covers
///    both "diverged fork" and "behind prefix" — and a genuine fork can sit at a
///    SMALL height gap, so the caller re-derives the fork/behind distinction the
///    boot reconcile already uses (a gap check alone would miss the small-gap
///    fork and leave the service on the wrong chain).
///  - the node has fallen MORE than `ORPHAN_REORG_DEPTH` blocks behind — too far
///    to close incrementally (bodies aged out of the relay window), so a fresh
///    snapshot is the only cure.
///
/// Returns FALSE for everything else: a canonical PREFIX that is merely behind
/// and momentarily body-starved (relay holes / thin mesh). This is the whole
/// point of the fix — such a SERVICE node must NOT self-terminate. Staying up
/// lets the in-place converge / Tier-2 peer-sync / gossip paths recover it while
/// it keeps serving. Recovery is never LOST, only deferred: a stuck prefix keeps
/// falling behind and crosses the depth threshold on its own, rather than being
/// nuked every ~minute on a transient stall (which took services offline).
///
/// `beacon_height == None` (beacon unreachable) with `forked == false` returns
/// FALSE: never nuke a node on a gap we cannot confirm against a live tip.
///
/// Read-only and mining-neutral: mine-prep re-checks convergence and writes its
/// own re-bootstrap marker independently of this decision.
fn idle_reconcile_needs_snapshot(local_tip: u32, beacon_height: Option<u32>, forked: bool) -> bool {
    if forked {
        return true;
    }
    match beacon_height {
        Some(bh) => bh.saturating_sub(local_tip) > alphanumeric::a9::blockchain::ORPHAN_REORG_DEPTH,
        None => false,
    }
}

/// Highest block index present in the local DB, or None if unreadable/empty.
fn local_tip_height(db_path: &str) -> Option<u32> {
    let db = sled::Config::new()
        .path(db_path)
        .flush_every_ms(Some(1000))
        .open()
        .ok()?;
    db.scan_prefix(b"block_")
        .filter_map(|entry| entry.ok().and_then(|(k, _)| bootstrap_block_index_from_key(&k)))
        .max()
}

/// Best-effort canonical anchor at-or-below `local_tip`: the highest header from
/// the gateway's verified snapshot history whose height we also hold locally.
/// This is what lets the boot reconcile distinguish FORKED from merely BEHIND —
/// a node whose tip is below the manifest height has NO hash to compare against
/// the manifest, and treating "behind by less than the stream window" as in-sync
/// left a node forked at its own tip claiming "on the canonical chain" forever
/// (observed live 2026-07-11: tip 42025 on a dead side branch, canonical 42239+,
/// boot skipped bootstrap, runtime detector cooldown-suppressed — fully stale).
/// Trust level matches the boot beacon precedent (main.rs freshness note): a
/// wrong anchor can at worst trigger one unnecessary re-bootstrap whose snapshot
/// manifest is still independently signature-verified. Sanity: headers must be
/// prev_hash-linked within their window before use.
async fn fetch_canonical_anchor_at_or_below(local_tip: u32) -> Option<(u32, String)> {
    // Size discipline: this is the one boot-path fetch whose response we parse
    // wholesale, and at limit=240 a legitimate reply is single-digit MB. Cap it
    // so a misbehaving/hostile gateway can't balloon boot memory — fail-open to
    // "no anchor", same as any other fetch trouble.
    const MAX_ANCHOR_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(2500))
        .build()
        .ok()?;
    let raw = client
        .get(SNAPSHOT_HISTORY_URL)
        .send()
        .await
        .ok()?
        .bytes()
        .await
        .ok()?;
    if raw.len() > MAX_ANCHOR_RESPONSE_BYTES {
        return None;
    }
    let body: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    if body.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    // Anchors are only meaningful for OUR network. A gateway serving a
    // different network (config drift, future testnet) would hand back
    // guaranteed-mismatching anchors, turning every boot into a spurious
    // Diverged -> delete-DB -> re-bootstrap cycle (audit finding, 2026-07-11).
    // Absent network_id (older gateway): fail-open to NO anchor rather than
    // risk a wrong one.
    let expected_network = launch_network_id_hex().ok()?;
    let same_network = body
        .get("network_id")
        .and_then(|v| v.as_str())
        .map(|n| n.eq_ignore_ascii_case(&expected_network));
    if same_network != Some(true) {
        return None;
    }
    best_anchor_from_history(&body, local_tip)
}

/// Pure anchor selection from a (network-gated) snapshot-history response: the
/// highest header height <= local_tip, and among entries that disagree about
/// that height — which legitimately happens when a short reorg rewrote it
/// between two snapshots — the hash from the NEWEST snapshot (highest snapshot
/// tip height) wins, because it reflects the settled chain. Selection is
/// deliberately independent of the response's array order: the old code kept
/// whichever entry the gateway sent first, which was only correct because the
/// route happens to sort newest-first — an ordering nobody promised. Windows
/// whose headers do not prev_hash-chain are rejected wholesale (a malformed or
/// tampered entry must not become the fork verdict), as are non-64-hex hashes.
fn best_anchor_from_history(body: &serde_json::Value, local_tip: u32) -> Option<(u32, String)> {
    // (anchor height, snapshot tip height it came from, hash)
    let mut best: Option<(u32, u64, String)> = None;
    for entry in body.get("history")?.as_array()? {
        let Some(headers) = entry.get("headers").and_then(|v| v.as_array()) else {
            continue;
        };
        let snapshot_height = entry.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
        let mut linked = true;
        for pair in headers.windows(2) {
            let child_prev = pair[1].get("prev_hash").and_then(|v| v.as_str());
            let parent_hash = pair[0].get("hash").and_then(|v| v.as_str());
            if child_prev.is_none() || parent_hash.is_none() || child_prev != parent_hash {
                linked = false;
                break;
            }
        }
        if !linked {
            continue;
        }
        for h in headers {
            let (Some(height), Some(hash)) = (
                h.get("height").and_then(|v| v.as_u64()).and_then(|v| u32::try_from(v).ok()),
                h.get("hash").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            if height > local_tip || hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let better = match &best {
                None => true,
                Some((bh, bsnap, _)) => {
                    height > *bh || (height == *bh && snapshot_height > *bsnap)
                }
            };
            if better {
                best = Some((height, snapshot_height, hash.to_ascii_lowercase()));
            }
        }
    }
    best.map(|(height, _, hash)| (height, hash))
}

fn local_db_matches_launch_genesis(db_path: &str) -> bool {
    matches!(local_launch_db_status(db_path), LaunchDbStatus::Valid)
}

async fn remove_local_db(db_path: &str) -> Result<()> {
    let path = std::path::Path::new(db_path);
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        fs::remove_dir_all(path)
            .await
            .map_err(|e| format!("Failed to remove local DB at {}: {}", db_path, e))?;
    } else {
        fs::remove_file(path)
            .await
            .map_err(|e| format!("Failed to remove local DB file at {}: {}", db_path, e))?;
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

#[cfg(feature = "bootstrap_publisher")]
async fn bootstrap_publish_loop(
    db_path: String,
    blockchain: Arc<RwLock<Blockchain>>,
    token: String,
) {
    let publish_url = "https://alphanumeric.blue/api/bootstrap/publish".to_string();

    let db = { blockchain.read().await.db.clone() };
    let (mut last_published_at, mut last_published_height, mut last_published_network_id) =
        read_bootstrap_publish_meta(&db).unwrap_or((0, 0, None));

    let mut last_tip_hash: Option<String> = None;
    let mut last_tip_change = Instant::now();
    let mut next_attempt_at: u64 = 0;

    loop {
        // Sample every ~3s, NOT every 30s. Tip stability is measured off last_tip_change,
        // so a coarse 30s sample quantized "stable for stable_secs" to 30s and would stop
        // republishing entirely once the block interval drops below ~30s (higher
        // hashpower) — re-stranding fresh nodes at a stale snapshot. A fine sample keeps
        // stability real-time; publishing is still gated by the cooldown/min-delta below,
        // so this does not increase publish frequency, only its responsiveness.
        tokio::time::sleep(Duration::from_secs(3)).await;

        let (height, tip_hash_hex, network_id_hex) = {
            let bc = blockchain.read().await;
            let h = bc.get_latest_block_index();
            let tip = bc.get_latest_block_hash();
            let network_id = bc
                .get_block(0)
                .map(|block| hex::encode(block.hash))
                .unwrap_or_else(|_| hex::encode(tip));
            (h, hex::encode(tip), network_id)
        };

        // NOTE on stability: the snapshot only needs to be a VALID recent canonical
        // point, not a perfectly-settled tip. On an active chain the tip changes every
        // few seconds, so a large stability window would keep the snapshot frozen far
        // behind the tip (the exact failure that stranded fresh nodes — they bootstrap
        // to a stale snapshot the relay window can no longer bridge). A small window is
        // enough to avoid snapshotting mid-reorg; if the published height is later
        // reorged, the next snapshot corrects it and clients reconcile via converge.
        let (default_cooldown_secs, default_min_delta, default_stable_secs) = if height < 100 {
            (30, 1, 3)
        } else if height < 10_000 {
            (120, 5, 5)
        } else {
            (300, 25, 8)
        };
        let cooldown_secs = env_u64_or(
            "ALPHANUMERIC_BOOTSTRAP_PUBLISH_COOLDOWN_SECS",
            default_cooldown_secs,
        );
        let min_delta = env_u64_or(
            "ALPHANUMERIC_BOOTSTRAP_PUBLISH_MIN_DELTA",
            default_min_delta,
        );
        let stable_secs = env_u64_or(
            "ALPHANUMERIC_BOOTSTRAP_PUBLISH_STABLE_SECS",
            default_stable_secs,
        );

        if last_tip_hash.as_deref() != Some(tip_hash_hex.as_str()) {
            last_tip_hash = Some(tip_hash_hex.clone());
            last_tip_change = Instant::now();
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now_secs < next_attempt_at {
            continue;
        }

        let same_network = last_published_network_id.as_deref() == Some(network_id_hex.as_str());

        if same_network && now_secs.saturating_sub(last_published_at) < cooldown_secs {
            continue;
        }

        if same_network && height < last_published_height.saturating_add(min_delta) {
            continue;
        }

        if last_tip_change.elapsed().as_secs() < stable_secs {
            continue;
        }

        if let Err(e) = publish_bootstrap_snapshot(
            &db,
            &blockchain,
            &db_path,
            height,
            &tip_hash_hex,
            &network_id_hex,
            &publish_url,
            &token,
        )
        .await
        {
            error!("bootstrap publish failed: {}", e);
            // Backoff: avoid spamming the endpoint if configuration is wrong or transient errors occur.
            // - Redirect/auth errors: 10 minutes
            // - Other errors: 2 minutes
            let msg = e.to_string();
            let backoff = if msg.contains("redirected")
                || msg.contains("401")
                || msg.contains("unauthorized")
            {
                600u64
            } else {
                120u64
            };
            next_attempt_at = now_secs.saturating_add(backoff);
            continue;
        }

        last_published_height = height;
        last_published_at = now_secs;
        last_published_network_id = Some(network_id_hex.clone());
        next_attempt_at = 0;
        let _ = write_bootstrap_publish_meta(
            &db,
            last_published_at,
            last_published_height,
            &network_id_hex,
        );
    }
}

#[cfg(feature = "bootstrap_publisher")]
async fn publish_bootstrap_snapshot(
    db: &sled::Db,
    blockchain: &Arc<RwLock<Blockchain>>,
    _db_path: &str,
    height: u64,
    tip_hash_hex: &str,
    network_id_hex: &str,
    publish_url: &str,
    token: &str,
) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct PublishLatest {
        url: String,
    }

    #[derive(serde::Deserialize)]
    struct PublishResponse {
        ok: bool,
        latest: PublishLatest,
    }

    #[derive(serde::Serialize)]
    struct PointerUpdate {
        url: String,
        network_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        height: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tip_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        compressed_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        extracted_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        file_count: Option<u64>,
        updated_at: u64,
        publisher_pubkey: String,
        manifest_sig: String,
    }

    let tmp = std::env::temp_dir();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // UNIQUE per attempt (timestamp + pid): this used to be keyed on height alone,
    // so two publisher processes racing the same height (watchdog respawn overlap,
    // manual-vs-launchd) shared ONE temp file — writer B truncating/rewriting it
    // under reader A is the standing suspect for the h2727 manifest whose sha/size
    // didn't match the blob its own url served (2026-07-09 audit finding).
    let zip_path = tmp.join(format!(
        "alphanumeric-bootstrap-{}-{}-{}.zip",
        height,
        now_secs,
        std::process::id()
    ));
    let zip_path_string = zip_path.to_string_lossy().to_string();
    let export_dir = tmp.join(format!(
        "alphanumeric-bootstrap-export-{}-{}",
        height, now_secs
    ));
    let export_dir_string = export_dir.to_string_lossy().to_string();

    // Remove the temp zip and the re-imported DB export dir on EVERY exit path. Most of the
    // early returns below propagate with `?` and would otherwise leak them; during a gateway
    // outage the loop rebuilds and leaks a full-DB-sized zip every cycle, filling the disk shared
    // with the live chain DB. RAII Drop runs on success and on any error return.
    struct TempCleanup {
        zip: std::path::PathBuf,
        export_dir: std::path::PathBuf,
    }
    impl Drop for TempCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.zip);
            let _ = std::fs::remove_dir_all(&self.export_dir);
        }
    }
    let _temp_cleanup = TempCleanup {
        zip: zip_path.clone(),
        export_dir: export_dir.clone(),
    };

    // Clone DB handle for spawn_blocking.
    let db_clone = db.clone();

    // BOUNDED QUIESCE (2026-07-16 park fix): hold the chain write lock across the full-DB
    // export/import so it CANNOT run concurrently with the workers' inline sled ops. The
    // concurrent export used to bypass this lock (via a cloned Db handle); that true
    // concurrency on sled 0.34 is what let all 4 tokio workers pin inside sled at once and
    // freeze the whole runtime (so the in-runtime watchdog was never polled and never exited).
    // Under the lock, other tasks async-wait (freed — the runtime + watchdog stay alive) and
    // the export sees an exclusive, internally-consistent DB (also fixes the torn-snapshot
    // risk). Bounded + cheap: publish cadence is 300s at mainnet height, so the ~seconds pause
    // is <2% ingest downtime. Released explicitly below, BEFORE any network I/O.
    let quiesce = blockchain.write().await;
    let quiesce_started = Instant::now();

    // Build a zip of a re-imported sled database in a temp directory (not the live DB dir)
    // to avoid Windows file locks (os error 33) when reading active log files.
    let archive_stats = tokio::task::spawn_blocking(
        move || -> std::result::Result<BootstrapArchiveStats, String> {
            let export_path = std::path::Path::new(&export_dir_string);
            if export_path.exists() {
                std::fs::remove_dir_all(export_path).map_err(|e| e.to_string())?;
            }
            std::fs::create_dir_all(export_path).map_err(|e| e.to_string())?;

            // Flush and logically export/import into a temp DB directory.
            db_clone.flush().map_err(|e| e.to_string())?;
            let export = db_clone.export();
            let tmp_db = sled::open(export_path).map_err(|e| e.to_string())?;
            // sled::Db::import panics on IO problems; if it panics the task will fail and publish will be skipped.
            tmp_db.import(export);
            tmp_db.flush().map_err(|e| e.to_string())?;
            drop(tmp_db);

            let file = std::fs::File::create(&zip_path_string).map_err(|e| e.to_string())?;
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(0o644);

            fn add_dir(
                zip: &mut zip::ZipWriter<std::fs::File>,
                base: &std::path::Path,
                path: &std::path::Path,
                options: zip::write::SimpleFileOptions,
                stats: &mut BootstrapArchiveStats,
            ) -> std::result::Result<(), String> {
                for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
                    let entry = entry.map_err(|e| e.to_string())?;
                    let p = entry.path();
                    let rel = p
                        .strip_prefix(base)
                        .map_err(|e| format!("strip_prefix: {}", e))?;
                    let name = rel.to_string_lossy().replace('\\', "/");
                    if p.is_dir() {
                        let dir_name = if name.ends_with('/') {
                            name
                        } else {
                            format!("{}/", name)
                        };
                        zip.add_directory(dir_name, options)
                            .map_err(|e| e.to_string())?;
                        add_dir(zip, base, &p, options, stats)?;
                    } else if p.is_file() {
                        zip.start_file(name, options).map_err(|e| e.to_string())?;
                        let mut f = std::fs::File::open(&p).map_err(|e| e.to_string())?;
                        let copied = std::io::copy(&mut f, zip).map_err(|e| e.to_string())?;
                        update_bootstrap_archive_stats(
                            stats,
                            copied,
                            BootstrapArchiveExpectations::default(),
                        )?;
                    }
                }
                Ok(())
            }

            let mut stats = BootstrapArchiveStats::default();
            add_dir(&mut zip, export_path, export_path, options, &mut stats)?;
            zip.finish().map_err(|e| e.to_string())?;

            // Best-effort cleanup of export directory.
            let _ = std::fs::remove_dir_all(export_path);
            Ok(stats)
        },
    )
    .await
    .map_err(|e| format!("zip task failed: {}", e))??;

    // Live-DB work is done; release the quiesce lock BEFORE any file read / network I/O so
    // ingest resumes and the lock never spans the (slow, possibly-blackholed) upload.
    drop(quiesce);

    // SCALING GUARD (v7.8.0): the write-lock hold == full-DB export wall-time, which grows with
    // the chain. If it ever nears the in-process lock watchdog's 10s read-probe window an export
    // could self-exit the headless publisher every publish (a crash-loop). Warn loudly well
    // before that so the bounded flush+clone export (export off-lock — v7.8.1) ships with runway.
    // ~3s today at ~266MB logical.
    let quiesce_secs = quiesce_started.elapsed().as_secs();
    if quiesce_secs >= 8 {
        log::warn!(
            "bootstrap export held the chain write lock {}s (>=8s; lock-watchdog probe=10s) — \
             bound/chunk the export (flush+clone, export off-lock) before the DB grows into a \
             publish-cycle crash-loop",
            quiesce_secs
        );
    }

    let bytes = fs::read(&zip_path).await?;
    let compressed_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = hex::encode(hasher.finalize());

    // SOAK SAFETY (env-gated, OFF in production): the upload target is hardcoded to the real
    // gateway, so an isolated soak node must never push to it. The park-triggering work
    // (flush+export+import+zip) has already run above under the quiesce lock; this only skips
    // shipping the result. With ALPHANUMERIC_SOAK_NO_UPLOAD unset, behavior is identical.
    if std::env::var("ALPHANUMERIC_SOAK_NO_UPLOAD").is_ok() {
        log::info!(
            "soak: bootstrap snapshot built ({} bytes, sha {}…) — skipping upload",
            compressed_bytes,
            &sha256[..12.min(sha256.len())]
        );
        return Ok(());
    }

    // Disable auto-redirects so we don't lose Authorization headers on cross-host redirects.
    // Bound every request so a blackholed/half-open connection (e.g. a tunnel flap) cannot block
    // the publish loop forever and freeze the manifest: a tight connect timeout catches the common
    // "can't (re)establish the connection" case fast on all requests, and a generous total timeout
    // is the backstop for a stalled transfer — sized to comfortably cover the worst-case blob PUT.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(40 * 60))
        .build()?;

    // Step 1: upload the snapshot zip DIRECTLY to Vercel Blob (v7.6.5). The zip
    // outgrew the gateway's ~4.5MB platform request-body cap, so shipping it
    // THROUGH /api/bootstrap/publish 413s before the function even runs — the
    // manifest then goes stale for hours and stranded/fresh nodes bootstrap
    // against an ancient snapshot (the 2026-07-08 night incident). The gateway
    // hands us its Blob credentials over the same bearer-authenticated channel
    // (upload-grant), we PUT straight to the Blob API (no body cap), and then
    // publish only the tiny manifest pointer. If the grant endpoint is missing
    // (older gateway) or the direct PUT fails, fall back to the legacy
    // through-the-gateway upload, which still works for small snapshots.
    let publish_base = publish_url
        .trim_end_matches("/api/bootstrap/publish")
        .to_string();
    let mut direct_blob_url: Option<String> = None;
    'direct: {
        #[derive(serde::Deserialize)]
        struct UploadGrant {
            ok: bool,
            token: String,
            api_url: String,
            api_version: String,
            store_id: String,
        }
        let grant_resp = match client
            .post(format!("{}/api/bootstrap/upload-grant", publish_base))
            .header("authorization", format!("Bearer {}", token))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!("bootstrap upload-grant unavailable ({}); using legacy upload", r.status());
                break 'direct;
            }
            Err(e) => {
                warn!("bootstrap upload-grant request failed ({}); using legacy upload", e);
                break 'direct;
            }
        };
        let grant: UploadGrant = match grant_resp.json().await {
            Ok(g) => g,
            Err(e) => {
                warn!("bootstrap upload-grant parse failed ({}); using legacy upload", e);
                break 'direct;
            }
        };
        if !grant.ok || grant.token.trim().is_empty() {
            warn!("bootstrap upload-grant response invalid; using legacy upload");
            break 'direct;
        }
        let pathname = format!(
            "bootstrap/{}/blockchain.db-h{}-{}.zip",
            network_id_hex, height, tip_hash_hex
        );
        let put_url = {
            let mut u = match reqwest::Url::parse(&format!("{}/", grant.api_url.trim_end_matches('/'))) {
                Ok(u) => u,
                Err(e) => {
                    warn!("bootstrap upload-grant api_url invalid ({}); using legacy upload", e);
                    break 'direct;
                }
            };
            u.query_pairs_mut().append_pair("pathname", &pathname);
            u.to_string()
        };
        #[derive(serde::Deserialize)]
        struct BlobPutResponse {
            url: String,
        }
        match client
            .put(&put_url)
            .header("authorization", format!("Bearer {}", grant.token))
            .header("x-api-version", grant.api_version.as_str())
            .header("x-vercel-blob-store-id", grant.store_id.as_str())
            .header("x-vercel-blob-access", "public")
            .header("x-add-random-suffix", "1")
            .header("x-content-type", "application/zip")
            .body(bytes.clone())
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => match r.json::<BlobPutResponse>().await {
                Ok(b) if !b.url.trim().is_empty() => {
                    info!(
                        "bootstrap snapshot uploaded directly to blob ({} bytes): {}",
                        compressed_bytes, b.url
                    );
                    direct_blob_url = Some(b.url);
                }
                Ok(_) => warn!("blob put returned empty url; using legacy upload"),
                Err(e) => warn!("blob put response parse failed ({}); using legacy upload", e),
            },
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                warn!(
                    "blob put failed ({}: {}); using legacy upload",
                    status,
                    body.trim()
                );
            }
            Err(e) => warn!("blob put request failed ({}); using legacy upload", e),
        }
    }

    // Step 2: publish through the gateway — manifest-only when the direct blob
    // upload succeeded (tiny request), full zip body otherwise (legacy).
    let mut upload_url = format!(
        "{}?network_id={}&height={}&tip={}&sha256={}&compressed_bytes={}&extracted_bytes={}&file_count={}",
        publish_url,
        network_id_hex,
        height,
        tip_hash_hex,
        sha256,
        compressed_bytes,
        archive_stats.extracted_bytes,
        archive_stats.file_count
    );
    if let Some(blob_url) = &direct_blob_url {
        let mut u = reqwest::Url::parse(&upload_url)?;
        u.query_pairs_mut().append_pair("blob_url", blob_url);
        upload_url = u.to_string();
    }
    let request = client
        .post(&upload_url)
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/zip");
    let resp = if direct_blob_url.is_some() {
        request.send().await?
    } else {
        request.body(bytes).send().await?
    };

    if resp.status().is_redirection() {
        let loc = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        return Err(format!(
            "bootstrap publish URL redirected ({}). Fix your alphanumeric.blue canonical domain routing (no redirect on /api/bootstrap/publish). Location={}",
            resp.status(),
            loc
        )
        .into());
    }

    if !resp.status().is_success() {
        let _ = fs::remove_file(&zip_path).await;
        // Include response body to make server-side misconfiguration debuggable (Blob/KV/env issues).
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let body = body.trim();
        if body.is_empty() {
            return Err(format!("bootstrap publish failed: {}", status).into());
        }
        return Err(format!("bootstrap publish failed: {}: {}", status, body).into());
    }

    let parsed: PublishResponse = resp.json().await?;
    if !parsed.ok || parsed.latest.url.trim().is_empty() {
        let _ = fs::remove_file(&zip_path).await;
        return Err("bootstrap publish response invalid".into());
    }

    // Step 2: sign the manifest (with final blob URL) and update pointer in KV.
    let updated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let signed_fields = BootstrapManifestSignedFields {
        url: parsed.latest.url.clone(),
        network_id: Some(network_id_hex.to_string()),
        height: Some(height),
        tip_hash: Some(tip_hash_hex.to_string()),
        sha256: Some(sha256),
        compressed_bytes: Some(compressed_bytes),
        extracted_bytes: Some(archive_stats.extracted_bytes),
        file_count: Some(archive_stats.file_count),
        updated_at,
    };
    let msg = serde_json::to_vec(&signed_fields)?;

    // Derive a deterministic ed25519 keypair from the publish token so one secret enables:
    // - API authorization
    // - manifest signing
    let mut t_hasher = Sha256::new();
    t_hasher.update(token.as_bytes());
    let seed = t_hasher.finalize();
    let seed_bytes: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| "failed to derive signing seed")?;

    use ed25519_dalek::{Signer, SigningKey};
    let signing = SigningKey::from_bytes(&seed_bytes);
    let pub_hex = hex::encode(signing.verifying_key().to_bytes());
    let sig = signing.sign(&msg);
    let sig_hex = hex::encode(sig.to_bytes());

    let pointer_url = if publish_url.contains("/api/bootstrap/publish") {
        publish_url.replace("/api/bootstrap/publish", "/api/bootstrap/pointer")
    } else {
        format!(
            "{}/api/bootstrap/pointer",
            publish_url.trim_end_matches('/')
        )
    };

    let pointer_update = PointerUpdate {
        url: signed_fields.url,
        network_id: network_id_hex.to_string(),
        height: signed_fields.height,
        tip_hash: signed_fields.tip_hash,
        sha256: signed_fields.sha256,
        compressed_bytes: signed_fields.compressed_bytes,
        extracted_bytes: signed_fields.extracted_bytes,
        file_count: signed_fields.file_count,
        updated_at: signed_fields.updated_at,
        publisher_pubkey: pub_hex,
        manifest_sig: sig_hex,
    };

    let pointer_resp = client
        .post(&pointer_url)
        .header("authorization", format!("Bearer {}", token))
        .json(&pointer_update)
        .send()
        .await?;

    if pointer_resp.status().is_redirection() {
        let loc = pointer_resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        return Err(format!(
            "bootstrap pointer URL redirected ({}). Fix your alphanumeric.blue canonical domain routing (no redirect on /api/bootstrap/pointer). Location={}",
            pointer_resp.status(),
            loc
        )
        .into());
    }

    // Best-effort cleanup of temp zip file.
    let _ = fs::remove_file(&zip_path).await;

    if !pointer_resp.status().is_success() {
        let status = pointer_resp.status();
        let body = pointer_resp.text().await.unwrap_or_default();
        let body = body.trim();
        if body.is_empty() {
            return Err(format!("bootstrap pointer update failed: {}", status).into());
        }
        return Err(format!("bootstrap pointer update failed: {}: {}", status, body).into());
    }

    // READ-BACK SELF-CONSISTENCY CHECK (2026-07-09). Whatever manifest the gateway
    // now serves, the blob its `url` points at must actually serve `compressed_bytes`
    // bytes — the one invariant every bootstrapping node depends on before sha
    // verification even runs. The audit caught a live manifest violating it (fresh
    // nodes failed verification until the next publish happened to overwrite it).
    // FAIL-OPEN on any transient error (a Blob/CDN hiccup must never fail a good
    // publish — a frozen manifest is its own past incident); fail ONLY on a
    // confirmed byte-count mismatch, which returns Err WITHOUT writing the publish
    // meta so the publish loop re-publishes (and overwrites the bad manifest) on
    // its next cycle instead of sleeping through the full cadence.
    let manifest_url = pointer_url.replace("/api/bootstrap/pointer", "/api/bootstrap/manifest");
    let readback: Option<(String, u64, u64)> = async {
        let resp = client.get(&manifest_url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = resp.json().await.ok()?;
        let m = v.get("manifest")?;
        let url = m.get("url")?.as_str()?.to_string();
        let claimed = m.get("compressed_bytes")?.as_u64()?;
        let head = client.head(&url).send().await.ok()?;
        if !head.status().is_success() {
            return None;
        }
        let served = head
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)?
            .to_str()
            .ok()?
            .parse::<u64>()
            .ok()?;
        Some((url, claimed, served))
    }
    .await;
    if let Some((url, claimed, served)) = readback {
        if claimed != served {
            return Err(format!(
                "bootstrap manifest readback INCONSISTENT: manifest claims {} bytes but its blob {} serves {}; retrying publish next cycle to overwrite it",
                claimed, url, served
            )
            .into());
        }
    }

    let _ = write_bootstrap_publish_meta(db, updated_at, height, network_id_hex);
    Ok(())
}

#[cfg(feature = "bootstrap_publisher")]
fn read_bootstrap_publish_meta(db: &sled::Db) -> Option<(u64, u64, Option<String>)> {
    let tree = db.open_tree(BOOTSTRAP_META_TREE).ok()?;
    let last_at = tree
        .get(BOOTSTRAP_META_LAST_PUBLISH_AT)
        .ok()
        .flatten()
        .and_then(|v| codec::deserialize::<u64>(&v).ok())
        .unwrap_or(0);
    let last_height = tree
        .get(BOOTSTRAP_META_LAST_PUBLISHED_HEIGHT)
        .ok()
        .flatten()
        .and_then(|v| codec::deserialize::<u64>(&v).ok())
        .unwrap_or(0);
    let last_network_id = tree
        .get(BOOTSTRAP_META_LAST_PUBLISHED_NETWORK_ID)
        .ok()
        .flatten()
        .and_then(|v| String::from_utf8(v.to_vec()).ok())
        .filter(|v| is_hex_with_len(v, 64));
    Some((last_at, last_height, last_network_id))
}

#[cfg(feature = "bootstrap_publisher")]
fn write_bootstrap_publish_meta(
    db: &sled::Db,
    last_at: u64,
    last_height: u64,
    network_id: &str,
) -> std::result::Result<(), sled::Error> {
    let tree = db.open_tree(BOOTSTRAP_META_TREE)?;
    let mut batch = sled::Batch::default();
    batch.insert(
        BOOTSTRAP_META_LAST_PUBLISH_AT,
        codec::serialize(&last_at).unwrap_or_default(),
    );
    batch.insert(
        BOOTSTRAP_META_LAST_PUBLISHED_HEIGHT,
        codec::serialize(&last_height).unwrap_or_default(),
    );
    batch.insert(BOOTSTRAP_META_LAST_PUBLISHED_NETWORK_ID, network_id);
    tree.apply_batch(batch)?;
    tree.flush()?;
    Ok(())
}

#[cfg(feature = "bootstrap_publisher")]
async fn handle_push_command(db_path: &str, blockchain: &Arc<RwLock<Blockchain>>) -> Result<()> {
    let token = std::env::var("ALPHANUMERIC_BOOTSTRAP_PUBLISH_TOKEN")
        .map_err(|_| "push requires ALPHANUMERIC_BOOTSTRAP_PUBLISH_TOKEN to be set")?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err("push requires ALPHANUMERIC_BOOTSTRAP_PUBLISH_TOKEN to be set".into());
    }

    let publish_url = "https://alphanumeric.blue/api/bootstrap/publish".to_string();

    let cooldown_secs = env_u64_or("ALPHANUMERIC_BOOTSTRAP_PUBLISH_COOLDOWN_SECS", 30);
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (db, height, tip_hash_hex, network_id_hex) = {
        let bc = blockchain.read().await;
        let db = bc.db.clone();
        let height = bc.get_latest_block_index();
        let tip = bc.get_latest_block_hash();
        let tip_hash_hex = hex::encode(tip);
        let network_id_hex = bc
            .get_block(0)
            .map(|block| hex::encode(block.hash))
            .unwrap_or_else(|_| hex::encode(tip));
        (db, height, tip_hash_hex, network_id_hex)
    };

    let (last_at, _last_height, last_network_id) =
        read_bootstrap_publish_meta(&db).unwrap_or((0, 0, None));
    let same_network = last_network_id.as_deref() == Some(network_id_hex.as_str());
    if same_network && now_secs.saturating_sub(last_at) < cooldown_secs {
        let remaining = cooldown_secs.saturating_sub(now_secs.saturating_sub(last_at));
        return Err(format!("push is rate-limited: wait {}s", remaining).into());
    }

    publish_bootstrap_snapshot(
        &db,
        blockchain,
        db_path,
        height,
        &tip_hash_hex,
        &network_id_hex,
        &publish_url,
        &token,
    )
    .await?;
    println!("Bootstrap snapshot published at height {}", height);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Arrow-up recall must fire ONLY for a bare arrow-up escape typed as the whole line in the
    // raw-stdin fallback — never for a payload that merely contains an ESC byte or "[A", which
    // the old substring heuristic matched and could use to silently re-fire a funded command.
    #[test]
    fn is_recall_line_matches_only_bare_arrow_up_in_fallback() {
        // Fallback (no editor): the two bare arrow-up escapes recall; nothing else does.
        assert!(is_recall_line("\u{1b}[A", false));
        assert!(is_recall_line("\u{1b}OA", false));
        assert!(!is_recall_line("whisper addr 5 [A]", false));
        assert!(!is_recall_line("create a b 5", false));
        assert!(!is_recall_line("a message with an \u{1b} esc byte", false));
        assert!(!is_recall_line("[A", false));
        assert!(!is_recall_line("", false));

        // With an editor present, rustyline consumes arrow-up itself, so recall never fires —
        // not even for the raw escape (it cannot reach `command` in that path).
        assert!(!is_recall_line("\u{1b}[A", true));
        assert!(!is_recall_line("\u{1b}OA", true));
    }

    fn reconcile_test_block(index: u32, tag: u8) -> Block {
        Block {
            index,
            previous_hash: [tag; 32],
            timestamp: 1_000 + index as u64,
            transactions: Vec::new(),
            nonce: 0,
            difficulty: 0,
            hash: [tag; 32],
            merkle_root: [0u8; 32],
        }
    }

    /// Fresh sled DB at a unique temp path holding the given (height, hash-tag)
    /// blocks; handle dropped so canonical_reconcile_decision can re-open by path.
    fn reconcile_test_db(name: &str, heights: &[(u32, u8)]) -> String {
        let path = std::env::temp_dir().join(format!(
            "a9_reconcile_{}_{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&path);
        let db = sled::Config::new().path(&path).open().unwrap();
        for (h, tag) in heights {
            let b = reconcile_test_block(*h, *tag);
            db.insert(
                format!("block_{}", h).as_bytes(),
                alphanumeric::a9::codec::serialize(&b).unwrap(),
            )
            .unwrap();
        }
        db.flush().unwrap();
        drop(db);
        path.to_string_lossy().into_owned()
    }

    fn manifest_at(height: u64, tag: u8) -> Result<BootstrapManifestPointer> {
        Ok(BootstrapManifestPointer {
            url: String::new(),
            network_id: None,
            height: Some(height),
            tip_hash: Some(hex::encode([tag; 32])),
            sha256: None,
            compressed_bytes: None,
            extracted_bytes: None,
            file_count: None,
            publisher_pubkey: String::new(),
            manifest_sig: String::new(),
            updated_at: 0,
        })
    }

    // In sync: we hold the canonical block at the manifest height -> keep the DB.
    #[test]
    fn reconcile_in_sync_when_local_holds_canonical_tip_hash() {
        let db = reconcile_test_db("insync", &[(100, 7)]);
        let m = manifest_at(100, 7);
        assert!(matches!(
            canonical_reconcile_decision(&db, &m, Some(100), None),
            CanonicalReconcile::InSyncOrUnknown
        ));
    }

    // The idle-reconcile snapshot gate: a SERVICE node (exchange/explorer/
    // web-wallet) must self-terminate ONLY when it is genuinely too far behind
    // to catch up incrementally (> ORPHAN_REORG_DEPTH), never on a transient
    // "behind but catchable" body-starvation stall — that false positive used
    // to take services offline every ~minute.
    #[test]
    fn idle_snapshot_gate_stays_up_on_behind_prefix_but_exits_on_fork_or_too_far() {
        let depth = alphanumeric::a9::blockchain::ORPHAN_REORG_DEPTH;
        // NOT forked, within incremental range: STAY UP (false).
        assert!(!idle_reconcile_needs_snapshot(1000, Some(1000), false)); // caught up
        assert!(!idle_reconcile_needs_snapshot(1000, Some(1001), false)); // 1 behind
        assert!(!idle_reconcile_needs_snapshot(1000, Some(1000 + 64), false)); // finality window
        assert!(!idle_reconcile_needs_snapshot(1000, Some(1000 + depth), false)); // exactly at bound = not > bound
        // NOT forked, beyond the bound: genuinely aged out -> re-bootstrap (true).
        assert!(idle_reconcile_needs_snapshot(1000, Some(1000 + depth + 1), false));
        assert!(idle_reconcile_needs_snapshot(0, Some(50_000), false));
        // NOT forked, beacon behind local (we are AHEAD): never re-bootstrap.
        assert!(!idle_reconcile_needs_snapshot(1000, Some(500), false));
        // NOT forked, beacon unreachable: never nuke on an unconfirmable gap.
        assert!(!idle_reconcile_needs_snapshot(1000, None, false));
        // FORKED overrides EVERYTHING — re-bootstrap even at a tiny gap, even
        // "caught up", even with no beacon: a forked service serves wrong data.
        assert!(idle_reconcile_needs_snapshot(1000, Some(1001), true)); // 1 behind but forked
        assert!(idle_reconcile_needs_snapshot(1000, Some(1000), true)); // "caught up" on a fork
        assert!(idle_reconcile_needs_snapshot(1000, None, true)); // forked, beacon unknown
        assert!(idle_reconcile_needs_snapshot(1000, Some(500), true)); // forked, ahead-by-height
        // Saturation safety: no underflow/overflow at the u32 extremes.
        assert!(!idle_reconcile_needs_snapshot(u32::MAX, Some(0), false));
        assert!(idle_reconcile_needs_snapshot(0, Some(u32::MAX), false));
    }

    // Fork at the signed checkpoint: hash mismatch at the manifest height must
    // re-bootstrap immediately (2026-07-08 stranded-fork recovery), never stream.
    #[test]
    fn reconcile_fork_at_checkpoint_diverges_immediately() {
        let db = reconcile_test_db("fork", &[(100, 8)]);
        let m = manifest_at(100, 7);
        assert!(matches!(
            canonical_reconcile_decision(&db, &m, Some(100), None),
            CanonicalReconcile::Diverged { .. }
        ));
    }

    // Merely behind, within the stream window: the live loop catches up — the
    // "every open re-downloads the chain" fix (2026-07-10: a client 100 behind
    // at 5s blocks = closed for ~8 minutes = full re-bootstrap, under the old 96).
    #[test]
    fn reconcile_behind_within_stream_window_streams() {
        let db = reconcile_test_db("behind_small", &[(100, 7)]);
        let m = manifest_at(150, 9); // no local block at 150
        assert!(matches!(
            canonical_reconcile_decision(&db, &m, Some(150), None),
            CanonicalReconcile::InSyncOrUnknown
        ));
        // Gap right at the window edge still streams…
        assert!(matches!(
            canonical_reconcile_decision(&db, &m, Some(100 + STREAM_WINDOW), None),
            CanonicalReconcile::InSyncOrUnknown
        ));
    }

    // A node that is behind AND on a lost fork must re-bootstrap, not stream.
    // Here the canonical block at height 100 (the anchor) has a different hash
    // than the block we hold at 100, proving we are on a diverged branch, not a
    // clean prefix. The running node's forward-only catch-up could never recover
    // us (canonical blocks won't link onto our forked tip, and it never rewinds
    // to the fork point), so the verdict must be Diverged even though the height
    // gap alone looks small enough to just sync. Without the anchor this node
    // booted "in sync" and stayed stale forever (the 2026-07-11 stale-client trap).
    #[test]
    fn reconcile_behind_and_forked_at_anchor_rebootstraps() {
        let db = reconcile_test_db("behind_forked", &[(90, 7), (100, 8)]);
        let m = manifest_at(150, 9); // behind: no local block at 150
        let anchor = Some((100u32, hex::encode([5u8; 32]))); // canonical differs at 100
        assert!(matches!(
            canonical_reconcile_decision(&db, &m, Some(150), anchor),
            CanonicalReconcile::Diverged { .. }
        ));
    }

    // Behind with a MATCHING anchor: genuinely just behind on canonical — stream.
    #[test]
    fn reconcile_behind_with_matching_anchor_streams() {
        let db = reconcile_test_db("behind_anchored", &[(90, 7), (100, 8)]);
        let m = manifest_at(150, 9);
        let anchor = Some((100u32, hex::encode([8u8; 32]))); // matches local tip
        assert!(matches!(
            canonical_reconcile_decision(&db, &m, Some(150), anchor),
            CanonicalReconcile::InSyncOrUnknown
        ));
    }

    fn history_body(entries: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({ "ok": true, "history": entries })
    }

    fn history_entry(snapshot_height: u64, headers: Vec<(u32, &str, &str)>) -> serde_json::Value {
        serde_json::json!({
            "height": snapshot_height,
            "headers": headers
                .into_iter()
                .map(|(h, hash, prev)| serde_json::json!({
                    "height": h, "hash": hash, "prev_hash": prev, "timestamp": 0
                }))
                .collect::<Vec<_>>()
        })
    }

    // When two snapshots disagree about the same height (a short reorg rewrote
    // it between them), the NEWEST snapshot's hash must win — independent of
    // the order the gateway serialized the entries. The old positional logic
    // kept whichever came first and was only correct by an unpromised sort.
    #[test]
    fn anchor_same_height_conflict_newest_snapshot_wins_any_order() {
        let old_hash = "a".repeat(64);
        let new_hash = "b".repeat(64);
        let older = history_entry(100, vec![(90, old_hash.as_str(), &"0".repeat(64))]);
        let newer = history_entry(150, vec![(90, new_hash.as_str(), &"0".repeat(64))]);
        for entries in [
            vec![older.clone(), newer.clone()],
            vec![newer.clone(), older.clone()],
        ] {
            let got = best_anchor_from_history(&history_body(entries), 95);
            assert_eq!(got, Some((90, new_hash.clone())));
        }
    }

    // Highest height at-or-below the local tip wins over a newer-but-lower one.
    #[test]
    fn anchor_prefers_highest_usable_height() {
        let low = history_entry(200, vec![(80, &"c".repeat(64), &"0".repeat(64))]);
        let high = history_entry(120, vec![(92, &"d".repeat(64), &"0".repeat(64))]);
        let got = best_anchor_from_history(&history_body(vec![low, high]), 95);
        assert_eq!(got, Some((92, "d".repeat(64))));
    }

    // A window whose headers don't chain is rejected wholesale; malformed
    // hashes and above-tip heights are skipped.
    #[test]
    fn anchor_rejects_unlinked_windows_and_junk() {
        let good_parent = "e".repeat(64);
        let linked = history_entry(
            100,
            vec![
                (90, good_parent.as_str(), &"0".repeat(64)),
                (91, &"f".repeat(64), good_parent.as_str()),
            ],
        );
        let unlinked = history_entry(
            300,
            vec![
                (93, &"1".repeat(64), &"0".repeat(64)),
                (94, &"2".repeat(64), &"9".repeat(64)), // prev doesn't match
            ],
        );
        let junk = history_entry(400, vec![(92, "not-hex", &"0".repeat(64)), (99, &"3".repeat(64), &"0".repeat(64))]);
        let got = best_anchor_from_history(
            &history_body(vec![linked, unlinked, junk]),
            95,
        );
        // unlinked window's 93/94 rejected; junk's 92 non-hex skipped and its
        // window is unlinked anyway; linked window's 91 is the best survivor.
        assert_eq!(got, Some((91, "f".repeat(64))));
    }

    // An anchor ABOVE our tip tells us nothing about our chain (we hold no block
    // there to compare), so it is ignored: we fall through to the plain behind
    // path and, since the gap is within the window, just stream to catch up.
    #[test]
    fn reconcile_anchor_above_local_tip_is_ignored() {
        let db = reconcile_test_db("anchor_above", &[(100, 8)]);
        let m = manifest_at(150, 9);
        let anchor = Some((120u32, hex::encode([5u8; 32])));
        assert!(matches!(
            canonical_reconcile_decision(&db, &m, Some(150), anchor),
            CanonicalReconcile::InSyncOrUnknown
        ));
    }

    // …and one past it re-bootstraps. The LIVE beacon height governs the gap
    // (v7.6.5 freshness rule), not the lagging manifest height.
    #[test]
    fn reconcile_behind_beyond_stream_window_rebootstraps() {
        let db = reconcile_test_db("behind_big", &[(100, 7)]);
        let m = manifest_at(150, 9);
        assert!(matches!(
            canonical_reconcile_decision(&db, &m, Some(100 + STREAM_WINDOW + 1), None),
            CanonicalReconcile::Diverged { .. }
        ));
    }

    // The runtime divergence exit's marker outranks an otherwise-in-sync verdict:
    // the live loop PROVED the chain can't converge while the manifest was stale
    // (the 2026-07-10 restart crash-loop). remove_local_db clears the marker with
    // the condemned chain.
    #[test]
    fn reconcile_marker_forces_rebootstrap_even_when_in_sync() {
        let db = reconcile_test_db("marker", &[(100, 7)]);
        std::fs::write(force_rebootstrap_marker_path(&db), b"test\n").unwrap();
        let m = manifest_at(100, 7);
        assert!(matches!(
            canonical_reconcile_decision(&db, &m, Some(100), None),
            CanonicalReconcile::Diverged { .. }
        ));
    }

    // Fail-open is preserved: with no verified manifest a re-bootstrap is
    // impossible anyway, so the marker persists silently and offline starts work.
    #[test]
    fn reconcile_marker_ignored_when_manifest_unreachable() {
        let db = reconcile_test_db("marker_offline", &[(100, 7)]);
        std::fs::write(force_rebootstrap_marker_path(&db), b"test\n").unwrap();
        let m: Result<BootstrapManifestPointer> = Err("gateway unreachable".into());
        assert!(matches!(
            canonical_reconcile_decision(&db, &m, None, None),
            CanonicalReconcile::InSyncOrUnknown
        ));
    }

    fn signed_bootstrap_manifest() -> BootstrapManifestPointer {
        use ed25519_dalek::{Signer, SigningKey};

        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let publisher_pubkey = hex::encode(signing.verifying_key().to_bytes());
        let network_id = launch_network_id_hex().unwrap();
        let mut manifest = BootstrapManifestPointer {
            url: "https://dyyq00nyrwpgq1yi.public.blob.vercel-storage.com/bootstrap/test.zip"
                .to_string(),
            network_id: Some(network_id.clone()),
            height: Some(0),
            tip_hash: Some(network_id),
            sha256: Some(
                "f199e63d0a621e7df67a1c7644ba78a87c8706f96d5d52610026b2c2d27ed843".to_string(),
            ),
            compressed_bytes: None,
            extracted_bytes: None,
            file_count: None,
            publisher_pubkey,
            manifest_sig: String::new(),
            updated_at: 1_783_184_400,
        };
        let payload = serde_json::to_vec(&manifest.signed_fields()).unwrap();
        let sig = signing.sign(&payload);
        manifest.manifest_sig = hex::encode(sig.to_bytes());
        manifest
    }

    #[test]
    fn bootstrap_zip_limit_env_value_is_clamped() {
        assert_eq!(
            bootstrap_zip_size_limit_from_env_value(None),
            DEFAULT_MAX_BOOTSTRAP_ZIP_BYTES
        );
        assert_eq!(
            bootstrap_zip_size_limit_from_env_value(Some("not-a-number")),
            DEFAULT_MAX_BOOTSTRAP_ZIP_BYTES
        );
        assert_eq!(
            bootstrap_zip_size_limit_from_env_value(Some("1")),
            MIN_MAX_BOOTSTRAP_ZIP_BYTES
        );
        assert_eq!(
            bootstrap_zip_size_limit_from_env_value(Some("2097152")),
            2_097_152
        );
        let over_max = (MAX_MAX_BOOTSTRAP_ZIP_BYTES + 1).to_string();
        assert_eq!(
            bootstrap_zip_size_limit_from_env_value(Some(over_max.as_str())),
            MAX_MAX_BOOTSTRAP_ZIP_BYTES
        );
    }

    #[test]
    fn bootstrap_zip_size_rejects_oversized_downloads() {
        assert!(ensure_bootstrap_zip_size(10, 10, "test body").is_ok());
        let err = ensure_bootstrap_zip_size(11, 10, "test body")
            .unwrap_err()
            .to_string();

        assert!(err.contains("too large"));
        assert!(err.contains("test body"));
    }

    #[test]
    fn unverified_bootstrap_extract_limit_env_value_is_clamped() {
        assert_eq!(
            unverified_bootstrap_extract_limit_from_env_value(None),
            DEFAULT_MAX_UNVERIFIED_BOOTSTRAP_EXTRACT_BYTES
        );
        assert_eq!(
            unverified_bootstrap_extract_limit_from_env_value(Some("not-a-number")),
            DEFAULT_MAX_UNVERIFIED_BOOTSTRAP_EXTRACT_BYTES
        );
        assert_eq!(
            unverified_bootstrap_extract_limit_from_env_value(Some("1")),
            MIN_MAX_UNVERIFIED_BOOTSTRAP_EXTRACT_BYTES
        );
        let over_max = (MAX_MAX_UNVERIFIED_BOOTSTRAP_EXTRACT_BYTES + 1).to_string();
        assert_eq!(
            unverified_bootstrap_extract_limit_from_env_value(Some(over_max.as_str())),
            MAX_MAX_UNVERIFIED_BOOTSTRAP_EXTRACT_BYTES
        );
    }

    #[test]
    fn bootstrap_download_size_checks_signed_exact_size() {
        assert!(ensure_bootstrap_download_progress(9, Some(10), Some(1), "body").is_ok());
        assert!(ensure_bootstrap_download_complete(10, Some(10), Some(1), "body").is_ok());

        let too_large = ensure_bootstrap_download_progress(11, Some(10), None, "body")
            .unwrap_err()
            .to_string();
        assert!(too_large.contains("too large for signed manifest"));

        let incomplete = ensure_bootstrap_download_complete(9, Some(10), None, "body")
            .unwrap_err()
            .to_string();
        assert!(incomplete.contains("size mismatch"));
    }

    #[test]
    fn bootstrap_required_disk_bytes_includes_archive_sizes_and_buffer() {
        assert_eq!(
            bootstrap_required_disk_bytes(Some(2_048), 8_192),
            2_048 + 8_192 + BOOTSTRAP_MIN_DISK_BUFFER_BYTES
        );

        let large_extracted = 200 * 1024 * 1024 * 1024u64;
        assert_eq!(
            bootstrap_required_disk_bytes(None, large_extracted),
            large_extracted + (large_extracted / 20)
        );
    }

    #[test]
    fn bootstrap_archive_stats_enforce_signed_expectations() {
        let expectations = BootstrapArchiveExpectations {
            expected_extracted_bytes: Some(12),
            expected_file_count: Some(2),
            unverified_extract_limit: None,
        };
        let mut stats = BootstrapArchiveStats::default();

        update_bootstrap_archive_stats(&mut stats, 5, expectations).unwrap();
        update_bootstrap_archive_stats(&mut stats, 7, expectations).unwrap();
        finalize_bootstrap_archive_stats(stats, expectations).unwrap();

        let mut too_many_bytes = BootstrapArchiveStats::default();
        let err =
            update_bootstrap_archive_stats(&mut too_many_bytes, 13, expectations).unwrap_err();
        assert!(err.contains("more data than signed manifest"));

        let mismatch = BootstrapArchiveStats {
            extracted_bytes: 12,
            file_count: 1,
        };
        let err = finalize_bootstrap_archive_stats(mismatch, expectations).unwrap_err();
        assert!(err.contains("file count mismatch"));
    }

    #[test]
    fn unverified_bootstrap_archive_stats_enforce_extract_limit() {
        let expectations = BootstrapArchiveExpectations {
            expected_extracted_bytes: None,
            expected_file_count: None,
            unverified_extract_limit: Some(10),
        };
        let mut stats = BootstrapArchiveStats::default();

        update_bootstrap_archive_stats(&mut stats, 10, expectations).unwrap();
        let err = update_bootstrap_archive_stats(&mut stats, 1, expectations).unwrap_err();
        assert!(err.contains("Unverified bootstrap archive extraction exceeded limit"));
    }

    #[test]
    fn bootstrap_manifest_signature_accepts_pinned_publisher() {
        let manifest = signed_bootstrap_manifest();

        assert!(
            verify_bootstrap_manifest_with_publisher(&manifest, &manifest.publisher_pubkey).is_ok()
        );
    }

    #[test]
    fn bootstrap_manifest_signature_rejects_tampering() {
        let mut manifest = signed_bootstrap_manifest();
        manifest.sha256 = Some("0".repeat(64));

        assert!(
            verify_bootstrap_manifest_with_publisher(&manifest, &manifest.publisher_pubkey)
                .is_err()
        );
    }

    #[test]
    fn bootstrap_manifest_signature_rejects_size_metadata_tampering() {
        let mut manifest = signed_bootstrap_manifest();
        manifest.extracted_bytes = Some(42);

        assert!(
            verify_bootstrap_manifest_with_publisher(&manifest, &manifest.publisher_pubkey)
                .is_err()
        );
    }

    #[test]
    fn bootstrap_manifest_rejects_zero_size_metadata() {
        let mut manifest = signed_bootstrap_manifest();
        manifest.compressed_bytes = Some(0);

        let err = verify_bootstrap_manifest_with_publisher(&manifest, &manifest.publisher_pubkey)
            .unwrap_err()
            .to_string();
        assert!(err.contains("compressed byte count must be nonzero"));
    }

    #[test]
    fn bootstrap_manifest_rejects_wrong_network() {
        let mut manifest = signed_bootstrap_manifest();
        manifest.network_id = Some("0".repeat(64));

        assert!(
            verify_bootstrap_manifest_with_publisher(&manifest, &manifest.publisher_pubkey)
                .is_err()
        );
    }
}
