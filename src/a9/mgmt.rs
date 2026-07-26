use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Password, PasswordDisplayMode};
use log::info;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use sled::Db;
use std::collections::HashMap;
use std::error::Error;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tokio::fs;
use tokio::sync::RwLock;

use crate::a9::blockchain::{is_canonical_user_address, MIN_RELAY_FEE_UNITS};
use crate::a9::{
    blockchain::{
        Block, Blockchain, BlockchainError, Transaction, MINING_REWARD_MATURITY,
        TARGET_BLOCK_TIME,
    },
    miner::{BlockHeader as ProgPowHeader, Miner},
    wallet::Wallet,
};

const KEY_FILE_PATH: &str = "private.key";
const MINING_NONCE_WINDOW: u64 = 67_108_864;
/// Reference-wallet fee policy. These are wallet defaults, not consensus rules:
/// externally signed transactions may choose their own fee subject to current
/// relay admission and block-accounting policy.
const DEFAULT_WALLET_FEE_DIVISOR: i128 = 1_776;
const DEFAULT_WALLET_FEE_CAP_UNITS: i128 = 50_000; // 0.0005 ALPHA
/// Hard safety ceiling for the reference wallet's explicit-fee path. This is
/// wallet policy, not a universal network limit; externally signed integrations
/// retain control subject to current admission and block-accounting policy.
const EXPLICIT_FEE_SAFETY_LIMIT_UNITS: i128 = 1_000_000; // 0.01 ALPHA
const CREATE_TRANSACTION_USAGE: &str =
    "Usage: create <sender_address> <recipient_address> <amount> [--fee <ALPHA>]";

/// Blocks until the coinbase mined at `reward_height` leaves the M06 immature set — i.e.
/// until the wallet's spendable balance includes it. It drops out once the tip reaches
/// reward_height + MINING_REWARD_MATURITY − 1 (the display's spend height is tip+1).
/// Display-only; the enforced set comes from the breakdown itself.
fn blocks_until_mature(reward_height: u32, as_of_height: u64) -> u64 {
    (reward_height as u64)
        .saturating_add(MINING_REWARD_MATURITY as u64 - 1)
        .saturating_sub(as_of_height)
}

/// "47 blocks (≈3m55s)" — human ETA for a coinbase that becomes spendable `blocks_left`
/// blocks from now, at the TARGET_BLOCK_TIME cadence. Display-only.
fn format_maturity_eta(blocks_left: u64) -> String {
    let secs = blocks_left.saturating_mul(TARGET_BLOCK_TIME);
    let eta = if secs >= 60 {
        format!("≈{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("≈{}s", secs)
    };
    format!(
        "{} block{} ({})",
        blocks_left,
        if blocks_left == 1 { "" } else { "s" },
        eta
    )
}

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, Eq, PartialEq)]
struct CreateTransactionArgs {
    sender_address: String,
    recipient_address: String,
    amount_units: i128,
    fee_units: i128,
}

/// Parse a CLI coin amount without routing user input through `f64`. Transaction
/// values have eight decimal places on the wire, so accepting exponent notation
/// or silently rounding a ninth decimal would make the displayed fee differ from
/// the value actually signed.
fn parse_coin_units(value: &str, field: &str) -> std::result::Result<i128, String> {
    let mut components = value.split('.');
    let whole = components.next().unwrap_or_default();
    let fractional = components.next();

    if components.next().is_some()
        || (whole.is_empty() && fractional.unwrap_or_default().is_empty())
        || !whole.chars().all(|c| c.is_ascii_digit())
        || fractional
            .map(|part| !part.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false)
    {
        return Err(format!(
            "{} must be a plain non-negative decimal number",
            field
        ));
    }

    let fractional = fractional.unwrap_or_default();
    if fractional.len() > 8 {
        return Err(format!("{} may have at most 8 decimal places", field));
    }

    let whole_units = if whole.is_empty() {
        0
    } else {
        whole
            .parse::<i128>()
            .map_err(|_| format!("{} is too large", field))?
            .checked_mul(100_000_000)
            .ok_or_else(|| format!("{} is too large", field))?
    };

    let mut fractional_units = if fractional.is_empty() {
        0
    } else {
        fractional
            .parse::<i128>()
            .map_err(|_| format!("{} is invalid", field))?
    };
    for _ in fractional.len()..8 {
        fractional_units = fractional_units
            .checked_mul(10)
            .ok_or_else(|| format!("{} is too large", field))?;
    }

    whole_units
        .checked_add(fractional_units)
        .ok_or_else(|| format!("{} is too large", field))
}

/// Round a positive integer ratio to the nearest atomic unit, with exact halves
/// rounded upward (matching the reference wallet's historical positive-value
/// rounding), then apply the wallet policy bounds.
fn default_wallet_fee_units(amount_units: i128) -> i128 {
    let quotient = amount_units / DEFAULT_WALLET_FEE_DIVISOR;
    let remainder = amount_units % DEFAULT_WALLET_FEE_DIVISOR;
    let rounded = quotient + i128::from(remainder >= (DEFAULT_WALLET_FEE_DIVISOR + 1) / 2);
    rounded.clamp(MIN_RELAY_FEE_UNITS, DEFAULT_WALLET_FEE_CAP_UNITS)
}

fn ensure_wire_exact(units: i128, field: &str) -> std::result::Result<(), String> {
    if Transaction::to_units(Transaction::from_units(units)) != units {
        return Err(format!(
            "{} is outside the transaction format's exact numeric range",
            field
        ));
    }
    Ok(())
}

fn parse_create_transaction_command(
    command: &str,
) -> std::result::Result<CreateTransactionArgs, String> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.len() < 4 {
        return Err("invalid command format".to_string());
    }

    let amount_units = parse_coin_units(parts[3], "amount")?;
    if amount_units <= 0 {
        return Err("amount must be greater than zero".to_string());
    }
    ensure_wire_exact(amount_units, "amount")?;

    let mut explicit_fee_units = None;
    let mut index = 4;
    while index < parts.len() {
        match parts[index] {
            "--fee" => {
                if explicit_fee_units.is_some() {
                    return Err("--fee may only be specified once".to_string());
                }
                index += 1;
                let value = parts
                    .get(index)
                    .ok_or_else(|| "--fee requires a decimal ALPHA value".to_string())?;
                explicit_fee_units = Some(parse_coin_units(value, "fee")?);
            }
            option if option.starts_with("--fee=") => {
                if explicit_fee_units.is_some() {
                    return Err("--fee may only be specified once".to_string());
                }
                let value = option.strip_prefix("--fee=").expect("prefix checked above");
                if value.is_empty() {
                    return Err("--fee requires a decimal ALPHA value".to_string());
                }
                explicit_fee_units = Some(parse_coin_units(value, "fee")?);
            }
            unknown => {
                return Err(format!("unrecognized transaction option: {}", unknown));
            }
        }
        index += 1;
    }

    let fee_units = match explicit_fee_units {
        Some(fee_units) => {
            ensure_wire_exact(fee_units, "fee")?;
            if fee_units < MIN_RELAY_FEE_UNITS {
                return Err(format!(
                    "fee is below the relay floor of {:.8} ALPHA",
                    Transaction::from_units(MIN_RELAY_FEE_UNITS)
                ));
            }
            if fee_units > EXPLICIT_FEE_SAFETY_LIMIT_UNITS {
                return Err(format!(
                    "fee exceeds the reference wallet safety limit of {:.8} ALPHA",
                    Transaction::from_units(EXPLICIT_FEE_SAFETY_LIMIT_UNITS)
                ));
            }
            fee_units
        }
        None => default_wallet_fee_units(amount_units),
    };

    amount_units
        .checked_add(fee_units)
        .ok_or_else(|| "amount plus fee is too large".to_string())?;

    Ok(CreateTransactionArgs {
        sender_address: parts[1].to_string(),
        recipient_address: parts[2].to_string(),
        amount_units,
        fee_units,
    })
}

fn validate_wallet_transaction_addresses(
    sender: &str,
    recipient: &str,
) -> std::result::Result<(), String> {
    if !is_canonical_user_address(sender) {
        return Err(
            "sender address must be exactly 40 lowercase hexadecimal characters".to_string(),
        );
    }
    if !is_canonical_user_address(recipient) {
        return Err(
            "recipient address must be exactly 40 lowercase hexadecimal characters".to_string(),
        );
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WalletKeyData {
    pub wallet_name: String,
    pub wallet_address: String,
    pub private_key: Option<Vec<u8>>,
    pub last_sync_timestamp: u64,
    pub is_encrypted: bool,
    pub key_verification_hash: Vec<u8>,
}

impl WalletKeyData {
    pub fn new(
        wallet_name: String,
        wallet_address: String,
        private_key: Option<Vec<u8>>,
        is_encrypted: bool,
    ) -> Self {
        // Keep existing hash verification - it works with any key bytes
        let key_verification_hash = if let Some(key) = &private_key {
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update([is_encrypted as u8]);
            hasher.finalize().to_vec()
        } else {
            vec![0u8; 32]
        };

        Self {
            wallet_name,
            wallet_address,
            private_key,
            last_sync_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            is_encrypted,
            key_verification_hash,
        }
    }
}

pub struct Mgmt {
    pub blockchain: Arc<RwLock<Blockchain>>, // Just store the reference
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
        // Restricting NTFS READ access needs ACLs (winapi); `set_readonly` only affects
        // WRITE, so the old code was a security no-op. Warn instead of pretending.
        let _ = path;
        eprintln!(
            "WARNING: wallet key file {} cannot be permission-restricted on Windows without \
             ACLs; protect it manually.",
            path
        );
    }
    Ok(())
}

/// Write secret bytes to `path` at 0600 from creation (no world-readable TOCTOU window),
/// re-asserting perms for a pre-existing file. Mirrors main.rs::write_secret_file.
async fn write_secret_file(path: &str, data: &[u8]) -> std::io::Result<()> {
    // Atomic replace: write to a sibling temp file, fsync it, then rename over the
    // target. A crash / power loss / ENOSPC mid-write leaves either the intact old
    // file or the complete new one — never a truncated key that fails to parse and
    // bricks the wallet on next launch.
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
    let _ = set_restrictive_file_permissions(path);
    Ok(())
}

/// Persist the serialized wallet key set to `key_file_path`, returning Err on either an I/O
/// failure or the 5s timeout. Persisting the key is a PRECONDITION for treating a wallet as
/// created: the ML-DSA seed lives only in RAM until this write, and `save_wallets` was removed,
/// so a swallowed write failure would lose the key on the next launch and permanently strand any
/// funds sent to the address. The read side (`load_wallets`) was already hardened to fail loudly
/// on this class; this closes the corresponding write side.
async fn persist_wallet_keys(key_file_path: &str, key_data_vec: &[WalletKeyData]) -> Result<()> {
    let serialized = serde_json::to_string(key_data_vec)?;
    match tokio::time::timeout(Duration::from_secs(5), async {
        write_secret_file(key_file_path, serialized.as_ref()).await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("failed to persist wallet key to {}: {}", key_file_path, e).into()),
        Err(_) => Err(format!("timed out persisting wallet key to {}", key_file_path).into()),
    }
}

/// Classify a `private.key` read error. ONLY `NotFound` is a genuine first run (safe to create a
/// default wallet). Any other error — permissions (EACCES), a Windows AV share-lock, non-UTF-8
/// corruption (`InvalidData`), or a transient I/O error — means the key file EXISTS but is
/// currently unreadable; treating that as first-run would overwrite it with a fresh wallet and
/// permanently destroy funds. Those must fail loudly instead.
fn load_error_is_first_run(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound
}

impl Mgmt {
    pub fn new(
        _db: sled::Db,
        blockchain: Arc<RwLock<Blockchain>>, // Take blockchain directly
    ) -> Self {
        Mgmt { blockchain }
    }

    pub fn get_current_timestamp() -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|e| format!("Failed to get current timestamp: {}", e).into())
    }

    pub async fn create_new_wallet(
        &self,
        wallets: &mut HashMap<String, Wallet>,
        passphrase: Option<&[u8]>,
        wallet_name: Option<String>,
    ) -> Result<Wallet> {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);

        // Read the key file - we know it exists because create_default_wallet must have run
        let existing_data = fs::read_to_string(KEY_FILE_PATH).await?;
        let existing_keys = serde_json::from_str::<Vec<WalletKeyData>>(&existing_data)?;

        let is_encrypted = passphrase.map(|p| !p.is_empty()).unwrap_or(false);

        // Generate name for the new wallet
        let name = wallet_name.unwrap_or_else(|| format!("wallet_{}", wallets.len() + 1));
        if wallets.contains_key(&name) {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))?;
            writeln!(stdout, "\nError: Wallet with this name already exists")?;
            stdout.reset()?;
            return Err("Duplicate wallet name".into());
        }

        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(132, 132, 132))))?;
        writeln!(stdout, "\nInitializing wallet creation process...")?;
        stdout.reset()?;

        // Progress bar with async operations
        let steps = 10;
        for i in 0..=steps {
            // Progress bar
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
            write!(stdout, "\rProgress: [")?;
            for j in 0..steps {
                if j < i {
                    write!(stdout, "=")?;
                } else if j == i {
                    write!(stdout, ">")?;
                } else {
                    write!(stdout, " ")?;
                }
            }
            write!(stdout, "] {}%", (i as u32 * 100) / steps as u32)?;
            stdout.flush()?;

            // Status messages
            match i {
                2 => {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(132, 132, 132))))?;
                    writeln!(stdout, " Generating cryptographic keys...")?;
                }
                4 => {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(132, 132, 132))))?;
                    writeln!(stdout, " Initializing wallet structure...")?;
                }
                6 => {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(132, 132, 132))))?;
                    writeln!(stdout, " Preparing network propagation...")?;
                }
                8 => {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(132, 132, 132))))?;
                    writeln!(stdout, " Syncing with network peers...")?;
                }
                _ => {}
            }
            stdout.reset()?;

            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        writeln!(stdout)?;

        // Create the wallet with timeout
        let wallet = match tokio::time::timeout(Duration::from_secs(5), async {
            if is_encrypted {
                Wallet::new(passphrase)
            } else {
                Wallet::new(None)
            }
        })
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
                writeln!(
                    stdout,
                    "Wallet creation timed out, but proceeding with local setup..."
                )?;
                stdout.reset()?;
                if is_encrypted {
                    Wallet::new(passphrase)?
                } else {
                    Wallet::new(None)?
                }
            }
        };

        // Save key data with timeout
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(132, 132, 132))))?;
        writeln!(stdout, "\nSaving wallet data...")?;
        stdout.reset()?;

        let key_data = WalletKeyData::new(
            name.clone(),
            wallet.address.clone(),
            wallet.encrypted_private_key.clone(),
            is_encrypted,
        );

        let mut key_data_vec = existing_keys;
        key_data_vec.push(key_data);

        // Persist the key BEFORE registering the wallet: a write failure or timeout returns Err
        // here rather than handing back a wallet whose ML-DSA seed exists only in RAM (which the
        // next launch would not find, permanently stranding any funds sent to the address).
        persist_wallet_keys(KEY_FILE_PATH, &key_data_vec).await?;

        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(59, 242, 173))))?;
        writeln!(stdout, "\n✓ Wallet created successfully!")?;
        stdout.reset()?;

        // Display wallet information
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;
        writeln!(stdout, "\nWallet Address: {}", wallet.address)?;
        if is_encrypted {
            writeln!(stdout, "Encryption: Enabled")?;
        } else {
            writeln!(stdout, "Encryption: Disabled")?;
        }
        stdout.reset()?;

        // Register the wallet only after its key is durably persisted.
        wallets.insert(name, wallet.clone());

        Ok(wallet)
    }

    pub async fn create_default_wallet(
        &self,
        _passphrase: Option<&[u8]>,
    ) -> Result<HashMap<String, Wallet>> {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);
        let mut wallets = HashMap::new();
        let default_wallet_name = "default_wallet".to_string();

        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(132, 132, 132))))?;
        writeln!(stdout, "\nInitializing wallet creation process...")?;
        stdout.reset()?;

        println!("\nWould you like to encrypt your wallet with a passphrase? (y/n): ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        let (wallet_pass, is_encrypted) = if input.trim().to_lowercase() == "y" {
            let pass = match Password::new("Enter passphrase (or press Enter for no encryption):")
                .with_display_mode(PasswordDisplayMode::Masked)
                .prompt()
            {
                Ok(p) => p,
                Err(e) => {
                    // The user asked to encrypt (typed "y"); a prompt failure (non-TTY, EOF,
                    // terminal error) must NOT silently fall through to an unencrypted,
                    // plaintext-on-disk wallet. Abort so they can retry.
                    return Err(format!(
                        "passphrase prompt failed ({}); aborting so the wallet is not created \
                         unencrypted by mistake",
                        e
                    )
                    .into());
                }
            };

            if !pass.trim().is_empty() {
                let pass_bytes = pass.trim().as_bytes().to_vec();
                println!("\nImportant Security Information: Your passphrase and the private.key file are essential for accessing your wallet. If you lose either of these, your funds will be irretrievable. Store them securely and create backups.");
                (Some(pass_bytes), true)
            } else {
                println!("Creating unencrypted wallet...");
                (None, false)
            }
        } else {
            println!("Creating unencrypted wallet...");
            println!("\nSecurity Risk: This wallet is unencrypted. Protect your private.key—loss is irreversible. Encryption is strongly advised to mitigate risk.");
            (None, false)
        };

        // Progress bar with async operations
        let steps = 10;
        for i in 0..=steps {
            // Progress bar
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
            write!(stdout, "\rProgress: [")?;
            for j in 0..steps {
                if j < i {
                    write!(stdout, "=")?;
                } else if j == i {
                    write!(stdout, ">")?;
                } else {
                    write!(stdout, " ")?;
                }
            }
            write!(stdout, "] {}%", (i * 100) / steps)?;
            stdout.flush()?;

            match i {
                2 => {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(132, 132, 132))))?;
                    writeln!(stdout, " Generating cryptographic keys...")?;
                }
                4 => {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(132, 132, 132))))?;
                    writeln!(stdout, " Initializing wallet structure...")?;
                }
                6 => {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(132, 132, 132))))?;
                    writeln!(stdout, " Preparing network propagation...")?;
                }
                8 => {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(132, 132, 132))))?;
                    writeln!(stdout, " Syncing with network peers...")?;
                }
                _ => {}
            }
            stdout.reset()?;

            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        writeln!(stdout)?;

        // Create the wallet with timeout
        let wallet = {
            let pass_slice = wallet_pass.as_deref();

            match tokio::time::timeout(Duration::from_secs(5), async { Wallet::new(pass_slice) })
                .await
            {
                Ok(result) => result?,
                Err(_) => {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
                    writeln!(
                        stdout,
                        "Wallet creation timed out, but proceeding with local setup..."
                    )?;
                    stdout.reset()?;
                    Wallet::new(pass_slice)?
                }
            }
        };

        // Save key data with timeout
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(132, 132, 132))))?;
        writeln!(stdout, "\nSaving wallet data...")?;
        stdout.reset()?;

        let key_data = WalletKeyData::new(
            default_wallet_name.clone(),
            wallet.address.clone(),
            wallet.encrypted_private_key.clone(),
            is_encrypted,
        );

        let key_data_vec = vec![key_data];

        // Persist the key BEFORE registering the wallet (see persist_wallet_keys). On first run no
        // key file exists yet, so a swallowed write failure here would make the NEXT launch treat
        // it as a fresh first run and generate a DIFFERENT default wallet — orphaning this one's
        // address and any funds it received. Fail loudly instead.
        persist_wallet_keys(KEY_FILE_PATH, &key_data_vec).await?;

        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(59, 242, 173))))?;
        writeln!(stdout, "\n✓ Wallet created successfully!")?;
        stdout.reset()?;

        // Display wallet information
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;
        writeln!(stdout, "\nWallet Address: {}", wallet.address)?;
        stdout.reset()?;

        // Register the wallet only after its key is durably persisted.
        wallets.insert(default_wallet_name, wallet);

        // Avoid self-relaunch: spawning a second copy of the executable is a common heuristic trigger
        // for endpoint protection tools. The app can continue running; the newly-created wallet is
        // already in memory, and callers can re-init any derived state without restarting.
        println!("\nWallet created. If you need a clean re-init, restart the application.");

        Ok(wallets)
    }

    pub async fn load_wallets(
        &self,
        _db_arc: &Arc<RwLock<Db>>,
        passphrase: Option<&[u8]>,
    ) -> Result<HashMap<String, Wallet>> {
        let mut wallets = HashMap::new();

        match fs::read_to_string(KEY_FILE_PATH).await {
            Ok(key_data) => {
                let wallet_key_data: Vec<WalletKeyData> = serde_json::from_str(&key_data)?;
                let mut stdout = StandardStream::stdout(ColorChoice::Auto);
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)).set_bold(true))?;
                writeln!(stdout, "\nFound {} wallets to load", wallet_key_data.len())?;
                stdout.reset()?;

                for wallet_data in wallet_key_data {
                    let wallet_name = wallet_data.wallet_name.clone();

                    if let Some(private_key) = wallet_data.private_key {
                        if wallet_data.is_encrypted && passphrase.is_none() {
                            println!(
                                "Failed to load encrypted wallet {}: passphrase required",
                                wallet_name
                            );
                            continue;
                        }

                        match Wallet::from_key_bytes(
                            wallet_name.clone(),
                            wallet_data.wallet_address.clone(),
                            private_key,
                            passphrase,
                            wallet_data.is_encrypted,
                        ) {
                            Ok(wallet) => {
                                wallets.insert(wallet_name.clone(), wallet);
                            }
                            Err(e) => {
                                println!("Failed to load wallet {}: {}", wallet_name, e);
                                continue;
                            }
                        }
                    }
                }

                println!("Loaded {} wallets successfully\n", wallets.len());
                Ok(wallets)
            }
            Err(e) if load_error_is_first_run(&e) => {
                // No key file yet: genuine first run.
                self.create_default_wallet(passphrase).await
            }
            Err(e) => {
                // The key file exists but could not be read. Do NOT fall through to
                // create_default_wallet — that would overwrite the existing key with a fresh
                // wallet and destroy funds. Fail loudly so the operator can fix perms / restore.
                Err(format!(
                    "{} exists but could not be read ({:?}: {}). Refusing to start so the \
                     existing wallet is not overwritten — fix permissions or restore from backup.",
                    KEY_FILE_PATH,
                    e.kind(),
                    e
                )
                .into())
            }
        }
    }

    // NOTE: `save_wallets` was removed. It rewrote private.key from the
    // in-memory wallet map, which erased wallets that had failed to load (e.g. wrong passphrase),
    // and additionally persisted plaintext keys into the shared chain DB's `wallets` tree (never
    // read on load). Every wallet-mutation path (create_new_wallet / create_default_wallet /
    // rename_wallet) already persists private.key by merging with the on-disk contents, so the
    // function was both redundant and destructive.

    pub async fn rename_wallet(&self, old_name: &str, new_name: &str) -> Result<()> {
        let mut wallet_key_data = match fs::read_to_string(KEY_FILE_PATH).await {
            Ok(data) => serde_json::from_str::<Vec<WalletKeyData>>(&data)?,
            Err(_) => {
                return Err(Box::new(BlockchainError::InvalidCommand(
                    "No wallet file found".into(),
                )))
            }
        };

        // Find the wallet by old name and update it
        if let Some(wallet) = wallet_key_data
            .iter_mut()
            .find(|w| w.wallet_name == old_name)
        {
            let updated_wallet = WalletKeyData::new(
                new_name.to_string(),
                wallet.wallet_address.clone(),
                wallet.private_key.clone(),
                wallet.is_encrypted,
            );
            *wallet = updated_wallet;

            // Write the updated wallet key data back to the file
            let updated_data = serde_json::to_string(&wallet_key_data)?;
            write_secret_file(KEY_FILE_PATH, updated_data.as_ref()).await?;

            info!("Wallet renamed from '{}' to '{}'", old_name, new_name);
            Ok(())
        } else {
            Err(Box::new(BlockchainError::WalletNotFound))
        }
    }

    pub async fn handle_mine_command(
        &self,
        command: &[&str],
        miner: &Miner,
        wallets: &mut HashMap<String, Wallet>,
        blockchain: &Arc<RwLock<Blockchain>>,
        _db_arc: &Arc<RwLock<Db>>,
    ) -> Result<Block> {
        if command.len() < 2 {
            return Err("Usage: mine <wallet_name_or_address>".into());
        }

        let mut stdout = StandardStream::stdout(ColorChoice::Auto);
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)).set_bold(true))?;
        writeln!(stdout, "\nStarting mining operation")?;
        stdout.reset()?;

        let prep_bar = ProgressBar::new_spinner();
        let style = ProgressStyle::with_template("{prefix} {spinner:.cyan/blue} {msg}")
            .map_err(|e| format!("Progress style error: {}", e))?;
        prep_bar.set_style(style);
        prep_bar.set_prefix("Mining");
        prep_bar.set_message("Preparing block template...");
        prep_bar.enable_steady_tick(Duration::from_millis(100));

        let wallet_input = command[1].to_string();
        let miner_wallet = if let Some(w) = wallets.get(&wallet_input) {
            w
        } else {
            wallets
                .values()
                .find(|w| w.address == wallet_input)
                .ok_or_else(|| format!("No wallet found with name or address: {}", wallet_input))?
        };

        // Tip snapshot ONLY — no mempool selection here. mine_block rebuilds its
        // template from the LIVE mempool on every pass (with its own
        // drop_confirmed sweep, confirmed/amount/age/signature filters, fee
        // ordering, and per-sender affordability), and discards the command-time
        // transaction list outright. The old code still swept and filtered the
        // mempool, computed the reward, and built the merkle root TWICE right
        // here — pure dead work that also queued behind block-ingest writers on
        // the chain read lock before the first hash could be ground.
        let (last_hash, next_block_index, difficulty) = {
            prep_bar.set_message("Reading chain tip...");
            let blockchain_guard = blockchain.read().await;
            let tip = blockchain_guard
                .get_last_block()
                .ok_or_else(|| "No tip block found".to_string())?;
            let last_hash = tip.hash;
            let next_block_index = tip.index.saturating_add(1);
            let difficulty = blockchain_guard.get_current_difficulty().await;
            (last_hash, next_block_index, difficulty)
        };

        prep_bar.set_message("Starting hash search...");
        prep_bar.finish_and_clear();

        // Placeholder header: number/parent seed the tip-change guards inside
        // mine_block; merkle root, timestamp, and difficulty are recomputed per
        // template rebuild from live state.
        let mut header = ProgPowHeader {
            number: next_block_index,
            parent_hash: last_hash,
            timestamp: Self::get_current_timestamp()?,
            merkle_root: Blockchain::calculate_merkle_root(&[])?,
            difficulty,
        };

        match miner
            .mine_block(
                &mut header,
                &[],
                MINING_NONCE_WINDOW,
                miner_wallet.address.clone(),
            )
            .await
        {
            Ok((_nonce, _hash, mined_block)) => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Blue)).set_bold(true))?;
                writeln!(stdout, "\n Mining successful")?;
                stdout.reset()?;
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(167, 165, 198))))?;
                writeln!(stdout, "───────────────────")?;
                stdout.reset()?;

                // The reward actually minted, from the mined block's coinbase.
                // mine_block's template builder always inserts the coinbase first,
                // so the fallback is unreachable in practice (kept only so a
                // malformed block can't panic the display path).
                let mining_reward = mined_block
                    .transactions
                    .first()
                    .filter(|tx| tx.sender == "MINING_REWARDS")
                    .map(|tx| tx.amount())
                    .unwrap_or_default();

                let breakdown = {
                    let blockchain_guard = blockchain.read().await;
                    blockchain_guard
                        .get_wallet_balance_breakdown(&miner_wallet.address)
                        .await?
                };

                if breakdown.maturing.is_empty() {
                    // Below the M06 activation height the reward is spendable at once.
                    writeln!(stdout, "Mining reward: {} ♦", mining_reward)?;
                    writeln!(stdout, "New balance: {}", breakdown.spendable)?;
                } else {
                    // M06: the coinbase is credited on-chain immediately but withheld from
                    // the spendable balance until buried MINING_REWARD_MATURITY deep.
                    // Say so explicitly — an unchanged "New balance" right after "Mining
                    // successful" reads as a lost reward, not a maturing one.
                    let eta = format_maturity_eta(blocks_until_mature(
                        mined_block.index,
                        breakdown.as_of_height,
                    ));
                    let maturing_total: f64 =
                        breakdown.maturing.iter().map(|(_, amount)| amount).sum();
                    writeln!(
                        stdout,
                        "Mining reward: {} ♦ — credited, spendable in {}",
                        mining_reward, eta
                    )?;
                    writeln!(stdout, "Spendable balance: {}", breakdown.spendable)?;
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(128, 128, 128))))?;
                    writeln!(
                        stdout,
                        "Maturing: {:.8} ♦ ({} reward{} on the way)",
                        maturing_total,
                        breakdown.maturing.len(),
                        if breakdown.maturing.len() == 1 { "" } else { "s" }
                    )?;
                    stdout.reset()?;
                }
                writeln!(stdout)?;

                Ok(mined_block)
            }
            Err(e) => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
                write!(stdout, "error")?;
                stdout.reset()?;
                writeln!(stdout, ": {}", e)?;
                Err(Box::new(e))
            }
        }
    }

    /// Create, sign, and submit a transaction to the LOCAL mempool. On success returns
    /// the submitted transaction so the caller can announce it to the network
    /// (`Node::gossip_transaction`) — submission alone reaches no other miner.
    pub async fn handle_create_transaction(
        &self,
        command: &str,
        wallets: &mut HashMap<String, Wallet>,
        blockchain: &Arc<RwLock<Blockchain>>,
        _db_arc: &Arc<RwLock<Db>>,
    ) -> Result<Transaction> {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);

        let parsed = match parse_create_transaction_command(command) {
            Ok(parsed) => parsed,
            Err(error) => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
                write!(stdout, "error")?;
                stdout.reset()?;
                writeln!(stdout, ": {}", error)?;
                writeln!(stdout, "{}", CREATE_TRANSACTION_USAGE)?;
                return Err(error.into());
            }
        };

        let sender_address = parsed.sender_address;
        let recipient_address = parsed.recipient_address;
        let amount_units = parsed.amount_units;
        let fee_units = parsed.fee_units;
        let amount = Transaction::from_units(amount_units);
        let fee = Transaction::from_units(fee_units);

        if let Err(error) =
            validate_wallet_transaction_addresses(&sender_address, &recipient_address)
        {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
            write!(stdout, "error")?;
            stdout.reset()?;
            writeln!(stdout, ": {}", error)?;
            return Err(error.into());
        }

        // Prevent self-transfers
        if sender_address == recipient_address {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
            write!(stdout, "error")?;
            stdout.reset()?;
            writeln!(stdout, ": cannot transfer to the same address")?;
            return Err("Self-transfer not allowed".into());
        }

        // Progress bar header
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)).set_bold(true))?;
        writeln!(stdout, "    Creating Transaction")?;
        stdout.reset()?;

        // Progress bar uses the exact cargo yellow
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true))?;
        write!(stdout, "    Checking")?;
        stdout.reset()?;
        write!(stdout, " wallet state...")?;
        stdout.flush()?;

        // Wallets are already loaded and available for transaction creation

        // Get sender wallet
        let sender_wallet = match wallets
            .values()
            .find(|wallet| wallet.address == sender_address)
        {
            Some(wallet) => {
                writeln!(stdout, "Done")?;
                wallet
            }
            None => {
                writeln!(stdout)?;
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
                write!(stdout, "error")?;
                stdout.reset()?;
                writeln!(stdout, ": sender wallet not found")?;
                writeln!(stdout, "\nAvailable wallets:")?;
                for wallet in wallets.values() {
                    writeln!(stdout, "  {}", wallet.address)?;
                }
                return Err("Sender wallet not found".into());
            }
        };

        // Balance check
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true))?;
        write!(stdout, "    Verifying")?;
        stdout.reset()?;
        write!(stdout, " balance...")?;
        stdout.flush()?;

        let blockchain_guard = blockchain.read().await;
        // Keep affordability entirely in exact atomic units. Conversions below
        // are presentation-only and never influence admission.
        let total_cost_units = amount_units
            .checked_add(fee_units)
            .ok_or("amount plus fee is too large")?;
        let total_cost = Transaction::from_units(total_cost_units);
        let sender_balance_units = blockchain_guard
            .get_spendable_balance_units(&sender_address)
            .await?;

        if sender_balance_units < total_cost_units {
            writeln!(stdout)?;
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
            write!(stdout, "error")?;
            stdout.reset()?;
            writeln!(stdout, ": insufficient balance")?;
            writeln!(stdout, "required: {}", total_cost)?;
            writeln!(
                stdout,
                "available: {}",
                Transaction::from_units(sender_balance_units)
            )?;
            return Err("Insufficient balance".into());
        }
        writeln!(stdout, "Done")?;
        drop(blockchain_guard);

        // Signing phase
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true))?;
        write!(stdout, "    Signing")?;
        stdout.reset()?;
        write!(stdout, " transaction...")?;
        stdout.flush()?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Failed to get timestamp")?
            .as_secs();

        let message = format!(
            "{}:{}:{:.8}:{:.8}:{}",
            sender_address, recipient_address, amount, fee, timestamp
        );

        let signature = match sender_wallet.sign_transaction(message.as_bytes()).await {
            Some(sig) => {
                writeln!(stdout, "Done")?;
                sig
            }
            None => {
                writeln!(stdout)?;
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
                write!(stdout, "error")?;
                stdout.reset()?;
                writeln!(stdout, ": failed to sign transaction")?;
                return Err("Failed to sign transaction".into());
            }
        };

        // Submit phase
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true))?;
        write!(stdout, "    Submitting")?;
        stdout.reset()?;
        writeln!(stdout, " to blockchain...")?;
        stdout.flush()?;

        let mut transaction = Transaction {
            sender: sender_address.clone(),
            recipient: recipient_address.clone(),
            amount_units,
            fee_units,
            timestamp,
            signature: Some(signature),
            pub_key: None,
            sig_hash: None,
        };
        transaction.pub_key = sender_wallet.get_public_key_hex().await;
        if transaction.pub_key.is_none() {
            writeln!(stdout)?;
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
            write!(stdout, "error")?;
            stdout.reset()?;
            writeln!(
                stdout,
                ": wallet key material is missing a ML-DSA public key"
            )?;
            writeln!(
                stdout,
                "wallet data appears incomplete; restore a full key backup or recreate this wallet"
            )?;
            return Err("Wallet key data missing ML-DSA public key".into());
        }

        // No wallet registry needed - transactions are self-contained with public keys

        // M2: a read guard suffices — add_transaction self-serializes on its internal
        // state_mutation_lock and runs the ML-DSA verify before taking it, so an exclusive
        // outer guard here only blocked concurrent block-ingest for no gain (matches the
        // network callers). Still scoped to the submit alone: the Ok arm re-reads the chain
        // for the balance (get_wallet_balance), which under a held guard self-deadlocked
        // right after "Done".
        let submit_result = {
            let chain = blockchain.read().await;
            chain.add_transaction(transaction.clone()).await
        };
        match submit_result {
            Ok(_) => {
                writeln!(stdout, "Done")?;

                // Get final balances
                let new_sender_balance = blockchain
                    .read()
                    .await
                    .get_wallet_balance(&sender_address)
                    .await?;

                // Completion message
                stdout.set_color(
                    ColorSpec::new()
                        .set_fg(Some(Color::Rgb(59, 242, 173)))
                        .set_bold(true),
                )?;
                writeln!(stdout, "\nTransaction completed successfully")?;
                stdout.reset()?;

                // Transaction summary
                writeln!(stdout, "\n  From:     {}", sender_address)?;
                writeln!(stdout, "  To:       {}", recipient_address)?;
                writeln!(stdout, "  Amount:   {}", amount)?;
                writeln!(stdout, "  Fee:      {}", fee)?;
                writeln!(stdout, "  Balance:  {}\n", new_sender_balance)?;

                Ok(transaction)
            }
            Err(e) => {
                writeln!(stdout)?;
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
                write!(stdout, "error")?;
                stdout.reset()?;
                writeln!(stdout, ": failed to submit transaction: {}", e)?;
                Err(format!("Failed to create transaction: {}", e).into())
            }
        }
    }

    pub async fn handle_account_command(
        &self,
        args: &str,
        blockchain: &Arc<RwLock<Blockchain>>,
        wallets: &HashMap<String, Wallet>,
    ) -> Result<()> {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);
        let address = args.split_whitespace().nth(1);

        match address {
            None => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))?;
                writeln!(stdout, "\nUsage: account <address>")?;
                stdout.reset()?;
                return Ok(());
            }
            Some(addr) => {
                // Time-boxed like `balance`: after a re-bootstrap/deep sync the chain write
                // lock can be held by block application for a long stretch, and an unbounded
                // read here made `account` sit silently until it was released.
                let Ok(blockchain_guard) =
                    tokio::time::timeout(std::time::Duration::from_secs(3), blockchain.read())
                        .await
                else {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))?;
                    writeln!(
                        stdout,
                        "Chain busy (syncing/reorg in progress) — try `account` again shortly."
                    )?;
                    stdout.reset()?;
                    return Ok(());
                };

                // Get balance atomically
                let breakdown = match blockchain_guard.get_wallet_balance_breakdown(addr).await {
                    Ok(breakdown) => breakdown,
                    Err(e) => {
                        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
                        writeln!(stdout, "Error getting balance: {}", e)?;
                        stdout.reset()?;
                        return Ok(());
                    }
                };
                let balance = breakdown.spendable;

                // Get pending transactions
                let mut pending_stats = (0, 0, 0.0, 0.0); // (out_count, in_count, out_amount, in_amount)
                if let Ok(pending_txs) = blockchain_guard.get_pending_transactions().await {
                    for tx in pending_txs {
                        if tx.sender == addr {
                            pending_stats.0 += 1;
                            pending_stats.2 += tx.amount() + tx.fee();
                        }
                        if tx.recipient == addr {
                            pending_stats.1 += 1;
                            pending_stats.3 += tx.amount();
                        }
                    }
                }

                // Whole-chain history off the address index. The old code scanned
                // only the newest 2000 blocks (a full decoded-chain load, twice),
                // so any account whose activity predated that window showed a
                // correct balance next to "Total Transactions: 0".
                let history = blockchain_guard
                    .address_history_summary(addr)
                    .unwrap_or_default();

                // Materialize EVERYTHING the display needs, then DROP the chain
                // guard BEFORE the styled dump below (hundreds of sync console
                // writes, incl. the 50-row recent list). A blocked console
                // (Windows QuickEdit select / Ctrl-S) would otherwise park this
                // read guard, and the write-preferring chain lock queue would
                // halt block ingest and mining node-wide — the 2026-07-16
                // publisher-park class. Every read below returns owned data.
                const RECENT_TX_LIMIT: usize = 50;
                let recent = blockchain_guard
                    .address_recent_txs(addr, RECENT_TX_LIMIT, None)
                    .unwrap_or_default();
                let total_supply_units = blockchain_guard.total_confirmed_supply_units().ok();
                drop(blockchain_guard);

                // Print account information. All styled output goes THROUGH the termcolor
                // `stdout` stream (writeln!/write!), never println!/print!: mixing the two puts
                // the color/bold attribute on one handle and the text on another, so headers
                // rendered bold only on Windows (Console API) and plain on Unix. Section headers
                // are explicitly bold so they look identical on both platforms.
                stdout.set_color(
                    ColorSpec::new()
                        .set_fg(Some(Color::Rgb(40, 204, 217)))
                        .set_bold(true),
                )?;
                writeln!(stdout, "\n Account Information")?;
                stdout.reset()?;
                writeln!(stdout, "───────────────────")?;

                // Address
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)).set_bold(true))?;
                write!(stdout, "Address: ")?;
                stdout.reset()?;
                writeln!(stdout, "{}", addr)?;

                // Wallet Status
                if wallets.contains_key(addr) {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
                    write!(stdout, "Status: ")?;
                    stdout.reset()?;
                    writeln!(stdout, "Local Wallet")?;
                }

                // Balance
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)).set_bold(true))?;
                write!(stdout, "Balance: ")?;
                stdout.reset()?;

                stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;
                write!(stdout, "{:.8}", balance)?;
                stdout.reset()?;
                stdout
                    .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(237, 124, 51))))
                    .ok();
                writeln!(stdout, " ♦")?;
                stdout.reset()?;

                // M06: coinbases still inside the maturity window are credited on-chain
                // but excluded from the spendable figure above — show them or a freshly
                // mined reward reads as missing.
                if !breakdown.maturing.is_empty() {
                    let maturing_total: f64 =
                        breakdown.maturing.iter().map(|(_, amount)| amount).sum();
                    let next_left = breakdown
                        .maturing
                        .iter()
                        .map(|(height, _)| blocks_until_mature(*height, breakdown.as_of_height))
                        .min()
                        .unwrap_or(0);
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(128, 128, 128))))
                        .ok();
                    writeln!(
                        stdout,
                        "  + {:.8} ♦ maturing ({} reward{}; next spendable in {})",
                        maturing_total,
                        breakdown.maturing.len(),
                        if breakdown.maturing.len() == 1 { "" } else { "s" },
                        format_maturity_eta(next_left)
                    )?;
                    stdout.reset()?;
                }

                // Pending Transactions Section
                if pending_stats.0 > 0 || pending_stats.1 > 0 {
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true))?;
                    writeln!(stdout, "\n Pending Transactions")?;
                    stdout.reset()?;
                    writeln!(stdout, "───────────────────")?;
                    writeln!(
                        stdout,
                        "Outgoing: {} (Total: {:.8})",
                        pending_stats.0, pending_stats.2
                    )?;
                    writeln!(
                        stdout,
                        "Incoming: {} (Total: {:.8})",
                        pending_stats.1, pending_stats.3
                    )?;
                }

                // Transaction History Section
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Blue)).set_bold(true))?;
                writeln!(stdout, "\n Transaction History")?;
                stdout.reset()?;
                writeln!(stdout, "───────────────────")?;
                match &history {
                    Some(stats) => {
                        writeln!(stdout, "Total Transactions: {}", stats.tx_count)?;
                        writeln!(
                            stdout,
                            "Volume Sent: {:.8}",
                            Transaction::from_units(stats.sent_units)
                        )?;
                        writeln!(
                            stdout,
                            "Volume Received: {:.8}",
                            Transaction::from_units(stats.received_units)
                        )?;
                        writeln!(
                            stdout,
                            "Total Fees Paid: {:.8}",
                            Transaction::from_units(stats.fees_units)
                        )?;
                        if let (Some(first), Some(last)) = (stats.first_height, stats.last_height)
                        {
                            writeln!(stdout, "First Activity: block {}", first)?;
                            writeln!(stdout, "Last Activity: block {}", last)?;
                        }

                        // Recent Transactions — a fixed last-N list off the same address
                        // index (O(N), no block decodes), materialized ABOVE before the
                        // guard was dropped. Rendered only inside this Some(stats) arm so
                        // it appears only when the index is READY: address_recent_txs
                        // returns an empty Vec both when the index is unbuilt AND when the
                        // address is inactive, so gating on the index-backed summary avoids
                        // a misleading empty "Recent Transactions".
                        {
                            if !recent.is_empty() {
                                stdout.set_color(
                                    ColorSpec::new()
                                        .set_fg(Some(Color::Blue))
                                        .set_bold(true),
                                )?;
                                writeln!(
                                    stdout,
                                    "\n Recent Transactions (last {})",
                                    RECENT_TX_LIMIT
                                )?;
                                stdout.reset()?;
                                writeln!(stdout, "───────────────────")?;
                                for entry in &recent {
                                    if entry.is_sender() {
                                        stdout.set_color(
                                            ColorSpec::new()
                                                .set_fg(Some(Color::Rgb(255, 84, 73)))
                                                .set_bold(true),
                                        )?;
                                        write!(stdout, "SENT    ")?;
                                    } else {
                                        stdout.set_color(
                                            ColorSpec::new()
                                                .set_fg(Some(Color::Rgb(59, 242, 173)))
                                                .set_bold(true),
                                        )?;
                                        write!(stdout, "RECEIVED")?;
                                    }
                                    stdout.reset()?;
                                    write!(
                                        stdout,
                                        "  {:.8} ♦  {} {}",
                                        Transaction::from_units(entry.amount_units),
                                        if entry.is_sender() { "to  " } else { "from" },
                                        entry.counterparty
                                    )?;
                                    stdout.set_color(
                                        ColorSpec::new().set_fg(Some(Color::Rgb(128, 128, 128))),
                                    )?;
                                    writeln!(stdout, "  (block {})", entry.height)?;
                                    stdout.reset()?;
                                }
                            }
                        }
                    }
                    None => {
                        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))?;
                        writeln!(
                            stdout,
                            "History index unavailable — it builds at startup; restart the node if this persists."
                        )?;
                        stdout.reset()?;
                    }
                }

                // Network Statistics Section. Circulating supply = sum of positive
                // confirmed balances; the old per-transaction sum double-counted
                // every onward transfer and decoded the whole chain to do it.
                // (Materialized above, before the guard was dropped.)
                if let Some(total_supply_units) = total_supply_units {
                    let total_supply = Transaction::from_units(total_supply_units);
                    if total_supply > 0.0 {
                        // Confirmed (not spendable) over confirmed supply — same units on
                        // both sides; the old spendable numerator under-read the share of
                        // any address holding maturing coinbases or pending debits.
                        let network_share = (breakdown.confirmed / total_supply) * 100.0;
                        stdout
                            .set_color(ColorSpec::new().set_fg(Some(Color::Blue)).set_bold(true))?;
                        writeln!(stdout, "\n Network Statistics")?;
                        stdout.reset()?;
                        writeln!(stdout, "───────────────────")?;
                        writeln!(stdout, "Network Share: {:.4}% \n", network_share)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn show_balances(&self, wallets: &HashMap<String, Wallet>) {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);

        // Header + divider are written THROUGH the termcolor stream (writeln!(stdout,…)),
        // never println!. Mixing the two left the text on std stdout while the color/bold
        // attribute lived on the termcolor handle — on Unix the ANSI escape leaked through
        // and colored it (no bold), on Windows the Console-API attribute made it render
        // intense/bold. Same code, different look per platform. Set the style explicitly and
        // emit the text on the same stream so it renders identically everywhere.
        stdout
            .set_color(
                ColorSpec::new()
                    .set_fg(Some(Color::Rgb(242, 237, 161)))
                    .set_bold(true),
            )
            .ok();
        let _ = writeln!(stdout, "\n Wallet Balances and Addresses:");
        let _ = stdout.reset();

        stdout
            .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(51, 43, 23))))
            .ok();
        let _ = writeln!(stdout, "────────────────────");
        let _ = stdout.reset();

        // Time-boxed: after a re-bootstrap/deep sync the chain lock can be held by
        // block application for a long stretch, and an unbounded read here made
        // `balance` sit silently forever ("client hangs, needs restart" reports).
        let Ok(blockchain_guard) =
            tokio::time::timeout(std::time::Duration::from_secs(3), self.blockchain.read()).await
        else {
            let _ = writeln!(stdout, "Chain busy (syncing/reorg in progress) — try `balance` again shortly.");
            return;
        };

        for (name, wallet) in wallets {
            match blockchain_guard
                .get_wallet_balance_breakdown(&wallet.address)
                .await
            {
                Ok(breakdown) => {
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Cyan)).set_bold(true))
                        .ok();
                    let _ = writeln!(stdout, "Wallet Name: {}", name);
                    let _ = stdout.reset();

                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(100, 149, 237))))
                        .ok();
                    let _ = write!(stdout, "Address: ");
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::White)))
                        .ok();
                    let _ = writeln!(stdout, "{}", wallet.address);
                    let _ = stdout.reset();

                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(135, 206, 250))))
                        .ok();
                    let _ = write!(stdout, "Balance: ");
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::White)).set_bold(true))
                        .ok();
                    let _ = write!(stdout, "{}", breakdown.spendable);
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(88, 240, 181))))
                        .ok();
                    let _ = writeln!(stdout, " ♦");

                    // M06: the spendable figure above excludes coinbases still inside the
                    // MINING_REWARD_MATURITY window. Show that portion — sourced from the
                    // SAME overlay the affordability gates enforce (the old 12-block hint
                    // under-scanned the 100-block window and claimed the balance
                    // "includes" rewards the spendable figure actually excludes).
                    // Display-only; spendability/consensus are unchanged.
                    if !breakdown.maturing.is_empty() {
                        let maturing_total: f64 =
                            breakdown.maturing.iter().map(|(_, amount)| amount).sum();
                        let next_left = breakdown
                            .maturing
                            .iter()
                            .map(|(height, _)| {
                                blocks_until_mature(*height, breakdown.as_of_height)
                            })
                            .min()
                            .unwrap_or(0);
                        stdout
                            .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(128, 128, 128))))
                            .ok();
                        let _ = writeln!(
                            stdout,
                            "  + {:.8} ♦ maturing ({} reward{}; next spendable in {})",
                            maturing_total,
                            breakdown.maturing.len(),
                            if breakdown.maturing.len() == 1 { "" } else { "s" },
                            format_maturity_eta(next_left)
                        );
                    }

                    let _ = stdout.reset();
                    let _ = writeln!(stdout, "-------------------");
                }
                Err(e) => {
                    let _ = writeln!(stdout, "Failed to get balance for wallet {}: {}", name, e);
                }
            }
        }
        let _ = writeln!(stdout);
        let _ = stdout.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a9::codec;
    use std::io::{Error, ErrorKind};

    #[test]
    fn wallet_coin_parser_is_exact_and_never_silently_rounds() {
        assert_eq!(parse_coin_units("1", "amount").unwrap(), 100_000_000);
        assert_eq!(parse_coin_units("1.2", "amount").unwrap(), 120_000_000);
        assert_eq!(
            parse_coin_units("1.23456789", "amount").unwrap(),
            123_456_789
        );
        assert_eq!(parse_coin_units(".0001", "fee").unwrap(), 10_000);

        for invalid in ["", ".", "-1", "+1", "1e-4", "1.2.3", "0.000000001"] {
            assert!(
                parse_coin_units(invalid, "value").is_err(),
                "{invalid:?} must not be silently rounded or reinterpreted"
            );
        }
    }

    #[test]
    fn default_wallet_fee_is_exact_rounded_ratio_with_floor_and_cap() {
        assert_eq!(
            default_wallet_fee_units(parse_coin_units("0.1", "amount").unwrap()),
            MIN_RELAY_FEE_UNITS
        );
        assert_eq!(
            default_wallet_fee_units(parse_coin_units("0.5", "amount").unwrap()),
            28_153
        );
        assert_eq!(
            default_wallet_fee_units(parse_coin_units("0.888", "amount").unwrap()),
            DEFAULT_WALLET_FEE_CAP_UNITS
        );
        assert_eq!(
            default_wallet_fee_units(parse_coin_units("1000000", "amount").unwrap()),
            DEFAULT_WALLET_FEE_CAP_UNITS
        );

        let exact_half = 20_000 * DEFAULT_WALLET_FEE_DIVISOR
            + DEFAULT_WALLET_FEE_DIVISOR / 2;
        assert_eq!(
            default_wallet_fee_units(exact_half),
            20_001,
            "an exact half atomic unit rounds upward"
        );
    }

    #[test]
    fn create_command_keeps_existing_syntax_and_accepts_exact_fee_override() {
        let existing = parse_create_transaction_command("create sender recipient 0.5").unwrap();
        assert_eq!(existing.amount_units, 50_000_000);
        assert_eq!(existing.fee_units, 28_153);

        let explicit =
            parse_create_transaction_command("create sender recipient 2 --fee 0.001").unwrap();
        assert_eq!(explicit.amount_units, 200_000_000);
        assert_eq!(explicit.fee_units, 100_000);

        let equals =
            parse_create_transaction_command("create sender recipient 2 --fee=0.0005").unwrap();
        assert_eq!(equals.fee_units, 50_000);

        for alias in ["send", "transfer"] {
            let command = format!("{alias} sender recipient 2 --fee 0.001");
            let parsed = parse_create_transaction_command(&command).unwrap();
            assert_eq!(parsed.amount_units, 200_000_000);
            assert_eq!(parsed.fee_units, 100_000);
        }
    }

    #[tokio::test]
    async fn exact_wallet_values_survive_signed_json_and_codec_round_trips() {
        let wallet = Wallet::new(None).expect("test wallet");
        let mut tx = Transaction {
            sender: wallet.address.clone(),
            recipient: "22".repeat(20),
            amount_units: 123_456_789,
            fee_units: 28_153,
            timestamp: 1_783_600_000,
            signature: None,
            pub_key: wallet.get_public_key_hex().await,
            sig_hash: None,
        };
        let signed_message = format!(
            "{}:{}:{:.8}:{:.8}:{}",
            tx.sender,
            tx.recipient,
            tx.amount(),
            tx.fee(),
            tx.timestamp
        );
        tx.signature = wallet.sign_transaction(signed_message.as_bytes()).await;
        let signature = hex::decode(tx.signature.as_deref().expect("signed")).expect("hex");
        tx.sig_hash = Some(Transaction::signature_hash_hex(&signature));
        assert!(
            tx.is_valid(tx.pub_key.as_deref().expect("public key")),
            "source transaction signature"
        );

        let json = serde_json::to_vec(&tx).expect("transaction JSON");
        let from_json: Transaction =
            serde_json::from_slice(&json).expect("transaction JSON round-trip");
        assert_eq!(from_json.amount_units, tx.amount_units);
        assert_eq!(from_json.fee_units, tx.fee_units);
        assert!(from_json.is_valid(from_json.pub_key.as_deref().unwrap()));

        let encoded = codec::serialize(&tx).expect("transaction codec");
        let from_codec: Transaction =
            codec::deserialize(&encoded).expect("transaction codec round-trip");
        assert_eq!(from_codec.amount_units, tx.amount_units);
        assert_eq!(from_codec.fee_units, tx.fee_units);
        assert!(from_codec.is_valid(from_codec.pub_key.as_deref().unwrap()));
    }

    #[test]
    fn create_command_fee_guards_are_deterministic_for_automation() {
        let floor =
            parse_create_transaction_command("create sender recipient 1 --fee 0.0001").unwrap();
        assert_eq!(floor.fee_units, MIN_RELAY_FEE_UNITS);

        let safety_limit =
            parse_create_transaction_command("create sender recipient 1 --fee 0.01").unwrap();
        assert_eq!(safety_limit.fee_units, EXPLICIT_FEE_SAFETY_LIMIT_UNITS);

        assert!(
            parse_create_transaction_command("create sender recipient 1 --fee 0.00009999")
                .unwrap_err()
                .contains("relay floor")
        );
        assert!(
            parse_create_transaction_command("create sender recipient 1 --fee 0.01000001")
                .unwrap_err()
                .contains("safety limit")
        );

        for malformed in [
            "create sender recipient 1 --fee",
            "create sender recipient 1 --fee 0.001 --fee 0.002",
            "create sender recipient 1 --unknown",
            "create sender recipient 1 --fee 1e-4",
        ] {
            assert!(
                parse_create_transaction_command(malformed).is_err(),
                "{malformed:?} must fail closed"
            );
        }
    }

    #[test]
    fn wallet_rejects_noncanonical_addresses_before_signing() {
        let sender = "ab".repeat(20);
        let recipient = "cd".repeat(20);
        assert!(validate_wallet_transaction_addresses(&sender, &recipient).is_ok());

        assert!(
            validate_wallet_transaction_addresses(&sender.to_uppercase(), &recipient)
                .unwrap_err()
                .contains("sender address")
        );
        assert!(
            validate_wallet_transaction_addresses(&sender, &recipient.to_uppercase())
                .unwrap_err()
                .contains("recipient address")
        );
        assert!(
            validate_wallet_transaction_addresses(&sender, "not-an-address")
                .unwrap_err()
                .contains("recipient address")
        );
    }

    // H4: only a NotFound read error is a genuine first run. Every other read error must NOT be
    // treated as first-run — doing so would overwrite an existing private.key and destroy funds.
    #[test]
    fn only_notfound_read_error_is_first_run() {
        assert!(load_error_is_first_run(&Error::from(ErrorKind::NotFound)));

        assert!(!load_error_is_first_run(&Error::from(ErrorKind::PermissionDenied)));
        assert!(!load_error_is_first_run(&Error::new(
            ErrorKind::InvalidData,
            "non-utf8 key file"
        )));
        assert!(!load_error_is_first_run(&Error::from(ErrorKind::Other)));
        assert!(!load_error_is_first_run(&Error::new(
            ErrorKind::WouldBlock,
            "AV share-lock"
        )));
    }

    // H2: persisting the wallet key is a PRECONDITION for creating the wallet. A write failure or
    // timeout must surface as Err (never be swallowed), so the caller never registers/returns a
    // wallet whose ML-DSA seed exists only in RAM and would be lost on the next launch.
    #[tokio::test]
    async fn persist_wallet_keys_surfaces_write_failure_and_persists_on_success() {
        // FAILURE (fault injection): a path whose parent directory does not exist makes
        // write_secret_file's temp-file create fail, so persist_wallet_keys must return Err.
        let bad_path = "/nonexistent-a9-wallet-test-dir-zzq/private.key";
        assert!(
            persist_wallet_keys(bad_path, &[]).await.is_err(),
            "a wallet-key write failure must surface as Err, never be swallowed"
        );
        assert!(!std::path::Path::new(bad_path).exists());

        // SUCCESS: a writable path persists the key set and returns Ok.
        let ok_path = std::env::temp_dir().join(format!("a9-persist-ok-{}.key", std::process::id()));
        let ok_path_str = ok_path.to_str().expect("temp path is valid utf-8");
        assert!(
            persist_wallet_keys(ok_path_str, &[]).await.is_ok(),
            "a writable path must persist the key set successfully"
        );
        assert!(ok_path.exists());
        let _ = std::fs::remove_file(&ok_path);
    }
}
