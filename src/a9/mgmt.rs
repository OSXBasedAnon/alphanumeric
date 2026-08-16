use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Password, PasswordDisplayMode};
use log::info;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use sled::Db;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tokio::fs;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::a9::blockchain::{
    is_canonical_user_address, MIN_RELAY_FEE_UNITS, SYSTEM_ADDRESSES, WALLET_FEE_SAFETY_LIMIT_UNITS,
};
use crate::a9::ui::{
    ui_address, ui_age, ui_grid_header, ui_grid_row, ui_money, ui_pad, ui_right, ui_seg, ui_text,
    ui_thousands, UI_BLUE, UI_CYAN, UI_DIM, UI_FAINT, UI_GREEN, UI_HAIRLINE, UI_LABEL, UI_LAVENDER,
    UI_MUTED, UI_ORANGE, UI_PINK, UI_RULE, UI_VALUE,
};
use crate::a9::whisper::max_non_whisper_fee_units;
use crate::a9::{
    blockchain::{
        Block, Blockchain, BlockchainError, Transaction, MINING_REWARD_MATURITY, TARGET_BLOCK_TIME,
    },
    miner::{BlockHeader as ProgPowHeader, Miner},
    wallet::Wallet,
    wallet_ledger::{PaymentTuple, WalletLedger},
};

const KEY_FILE_PATH: &str = "private.key";
const MINING_NONCE_WINDOW: u64 = 67_108_864;
/// Reference-wallet fee policy. Wallet POLICY, not consensus rules: externally
/// signed transactions may choose their own fee subject to current relay
/// admission and block-accounting policy. The wallet's default fee is no longer
/// a fixed amount ratio — `create` without --fee resolves through the live
/// mempool fee estimator (Blockchain::fee_estimate): the flat anchor
/// (FEE_ESTIMATE_ANCHOR_UNITS, 2x the relay floor) on a quiet network, one
/// unit above the marginal next-block fee under congestion, always clamped to
/// the safety ceiling below.
///
/// Hard safety ceiling for ANY wallet fee (explicit --fee or auto). Anchored to
/// the single source in blockchain.rs so the estimator and the --fee guard can
/// never disagree.
const EXPLICIT_FEE_SAFETY_LIMIT_UNITS: i128 = WALLET_FEE_SAFETY_LIMIT_UNITS; // 0.01 ALPHA
const CREATE_TRANSACTION_USAGE: &str =
    "Usage: create <sender_address> <recipient_address> <amount> [--fee <ALPHA>]";

/// The three counterparties worth printing in full: the most recent inbound, the most recent
/// outbound, and the one appearing most often.
///
/// `recent` is newest-first — address_recent_txs scans the height-ordered index in reverse —
/// so the first match in each direction IS the latest one.
///
/// Two judgement calls live here rather than in the renderer, so they can be tested:
///
/// * Coinbase rows are excluded. MINING_REWARDS is not somebody anyone deals with, and on a
///   miner it would win `frequent` outright and crowd out the answer that was wanted.
/// * `frequent` requires more than one appearance. A single transaction is not a pattern, and
///   calling it one would make the row noise on an address with no repeat counterparty.
///
/// Ties break on the address so the row is stable across runs instead of following hash order.
#[allow(clippy::type_complexity)]
fn notable_counterparties(
    recent: &[crate::a9::blockchain::AddressTxEntry],
) -> (
    Option<&crate::a9::blockchain::AddressTxEntry>,
    Option<&crate::a9::blockchain::AddressTxEntry>,
    Option<(&str, usize)>,
) {
    let real = |party: &str| !SYSTEM_ADDRESSES.contains(&party);
    let last_in = recent
        .iter()
        .find(|e| e.is_recipient() && real(&e.counterparty));
    let last_out = recent
        .iter()
        .find(|e| e.is_sender() && real(&e.counterparty));
    let mut tally: HashMap<&str, usize> = HashMap::new();
    for e in recent.iter().filter(|e| real(&e.counterparty)) {
        *tally.entry(e.counterparty.as_str()).or_insert(0) += 1;
    }
    let frequent = tally
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
        .filter(|(_, n)| *n > 1);
    (last_in, last_out, frequent)
}

/// Ranking reads one balances-tree entry per wallet — no block decodes — and is
/// time-boxed, degrading to the name-ordered first wallet if the chain lock is
/// busy rather than blocking the console.
pub async fn resolve_default_wallet(
    wallets: &std::collections::HashMap<String, crate::a9::wallet::Wallet>,
    blockchain: &Arc<RwLock<Blockchain>>,
) -> Option<(String, String)> {
    if let Some((name, wallet)) = wallets.get_key_value("default_wallet") {
        return Some((name.clone(), wallet.address.clone()));
    }
    if wallets.len() <= 1 {
        return wallets
            .iter()
            .next()
            .map(|(name, wallet)| (name.clone(), wallet.address.clone()));
    }

    let mut ordered: Vec<(&String, &crate::a9::wallet::Wallet)> = wallets.iter().collect();
    ordered.sort_by(|a, b| a.0.cmp(b.0));

    if let Ok(guard) = tokio::time::timeout(Duration::from_secs(3), blockchain.read()).await {
        let mut best: Option<(i128, String, String)> = None;
        for (name, wallet) in &ordered {
            let units = guard
                .get_confirmed_balance_units(&wallet.address)
                .await
                .unwrap_or(0);
            // `Option::is_none_or` requires Rust 1.82; preserve the crate's 1.70 MSRV.
            #[allow(clippy::unnecessary_map_or)]
            if best.as_ref().map_or(true, |(top, _, _)| units > *top) {
                best = Some((units, (*name).clone(), wallet.address.clone()));
            }
        }
        if let Some((_, name, address)) = best {
            return Some((name, address));
        }
    }

    ordered
        .first()
        .map(|(name, wallet)| ((*name).clone(), wallet.address.clone()))
}

/// Blocks until the coinbase mined at `reward_height` leaves the M06 immature set — i.e.
/// until the wallet's spendable balance includes it. It drops out once the tip reaches
/// reward_height + MINING_REWARD_MATURITY − 1 (the display's spend height is tip+1), which
/// is where the `- 1` below comes from.
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
    /// Some = explicit --fee (validated against floor and safety ceiling at
    /// parse time). None = auto: the handler resolves it through the live
    /// mempool fee estimator (Blockchain::fee_estimate) — parsing stays a pure
    /// string function with no chain access.
    fee_units: Option<i128>,
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
                // The match arm above guarantees the prefix; bind rather than expect so a
                // future arm edit cannot turn a CLI typo into a panic.
                let Some(value) = option.strip_prefix("--fee=") else {
                    return Err("--fee requires a decimal ALPHA value".to_string());
                };
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

    // Explicit --fee is fully validated here at parse time; the auto default is
    // deliberately NOT resolved here — parsing stays a pure string function, and
    // the handler prices the fee off the live mempool (Blockchain::fee_estimate)
    // at send time. The estimator's output is clamped to the same
    // [relay floor, safety ceiling] band by construction, so both paths obey
    // the identical policy bounds.
    if let Some(fee_units) = explicit_fee_units {
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
        amount_units
            .checked_add(fee_units)
            .ok_or_else(|| "amount plus fee is too large".to_string())?;
    }

    Ok(CreateTransactionArgs {
        sender_address: parts[1].to_string(),
        recipient_address: parts[2].to_string(),
        amount_units,
        fee_units: explicit_fee_units,
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
    /// Key material as persisted. When `is_encrypted` is false this is the RAW
    /// combined ML-DSA key, not ciphertext -- the field name describes the
    /// encrypted case only. Zeroized on drop so a freed allocation does not keep
    /// a spendable key; `Zeroizing` is a transparent wrapper, so the serialized
    /// form is a bare byte array exactly as before (pinned by the frozen-format
    /// fixtures in this module's tests).
    #[serde(with = "zeroizing_key_bytes")]
    pub private_key: Option<Zeroizing<Vec<u8>>>,
    pub last_sync_timestamp: u64,
    pub is_encrypted: bool,
    pub key_verification_hash: Vec<u8>,
}

/// Serde adapter keeping `Option<Zeroizing<Vec<u8>>>` on the wire EXACTLY as
/// `Option<Vec<u8>>` was: a bare JSON array, or null. Written out rather than
/// enabling zeroize's serde feature so the transparency is visible at the point
/// it matters -- this is the field whose representation decides whether existing
/// key files still load. Deserialization moves the buffer into `Zeroizing`
/// instead of copying, so no unzeroized duplicate is left behind.
pub mod zeroizing_key_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(
        value: &Option<Zeroizing<Vec<u8>>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(bytes.as_slice()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Zeroizing<Vec<u8>>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Option::<Vec<u8>>::deserialize(deserializer)?.map(Zeroizing::new))
    }
}

// Hand-written so key material can never reach a log line, a panic backtrace or a
// crash report. Derived Debug on a secret-bearing struct is a footgun that stays
// dormant until someone adds a `{:?}` years later, which is precisely when it is
// hardest to notice. Non-secret fields stay legible so the type is still useful
// in diagnostics.
impl std::fmt::Debug for WalletKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let private_key = match &self.private_key {
            Some(key) => format!("<redacted {} bytes>", key.len()),
            None => "<none>".to_string(),
        };
        f.debug_struct("WalletKeyData")
            .field("wallet_name", &self.wallet_name)
            .field("wallet_address", &self.wallet_address)
            .field("private_key", &private_key)
            .field("last_sync_timestamp", &self.last_sync_timestamp)
            .field("is_encrypted", &self.is_encrypted)
            .field(
                "key_verification_hash",
                &format_args!("{} bytes", self.key_verification_hash.len()),
            )
            .finish()
    }
}

impl WalletKeyData {
    pub fn new(
        wallet_name: String,
        wallet_address: String,
        private_key: Option<Zeroizing<Vec<u8>>>,
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

/// A wallet name is the durable identity the CLI uses to select a private key. Two records with
/// the same name cannot be represented faithfully in the in-memory `HashMap`: the later insert
/// shadows the earlier key. Validate the file BEFORE decryption/loading and BEFORE every write so
/// an ambiguous file is never silently accepted or made worse.
fn validate_unique_wallet_names(wallets: &[WalletKeyData]) -> Result<()> {
    let mut seen = HashSet::with_capacity(wallets.len());
    let mut duplicates = Vec::new();

    for wallet in wallets {
        if !seen.insert(wallet.wallet_name.as_str()) {
            duplicates.push(wallet.wallet_name.as_str());
        }
    }

    if duplicates.is_empty() {
        return Ok(());
    }

    duplicates.sort_unstable();
    duplicates.dedup();
    Err(format!(
        "{} contains duplicate wallet name(s) {:?}. Refusing to load or modify an ambiguous wallet file; restore a backup or repair the duplicate records before retrying.",
        KEY_FILE_PATH, duplicates
    )
    .into())
}

/// Resolve an explicit or automatic wallet name against BOTH views of wallet state. `loaded_names`
/// contains only keys that decrypted successfully; `durable_wallets` also contains encrypted or
/// otherwise unloadable records. Checking only the former allowed `new X` to append a second `X`
/// while the original encrypted wallet was skipped for lack of a passphrase.
fn select_new_wallet_name(
    requested: Option<String>,
    loaded_names: &HashSet<&str>,
    durable_wallets: &[WalletKeyData],
) -> Result<String> {
    let name_is_taken = |name: &str| {
        loaded_names.contains(name)
            || durable_wallets
                .iter()
                .any(|wallet| wallet.wallet_name == name)
    };

    if let Some(name) = requested {
        if name_is_taken(&name) {
            return Err("Duplicate wallet name".into());
        }
        return Ok(name);
    }

    // Preserve the existing numbering convention (loaded count + 1), but advance past names held
    // only on disk instead of failing or colliding with them.
    let mut index = loaded_names
        .len()
        .checked_add(1)
        .ok_or("Unable to allocate an automatic wallet name")?;
    loop {
        let candidate = format!("wallet_{}", index);
        if !name_is_taken(&candidate) {
            return Ok(candidate);
        }
        index = index
            .checked_add(1)
            .ok_or("Unable to allocate an automatic wallet name")?;
    }
}

pub struct Mgmt {
    pub blockchain: Arc<RwLock<Blockchain>>, // Just store the reference
    /// Durable operator-side payment ledger for collision-free timestamps and honest retries.
    /// `None` only if the ledger file could not be opened, in which case the signing path warns
    /// once and falls back to raw wall-clock timestamps (the pre-ledger behavior).
    wallet_ledger: Option<Arc<WalletLedger>>,
}

/// User-facing transaction creation result. Only `Submitted` authorizes gossip;
/// duplicate outcomes are successful idempotent requests, not newly created payments.
pub enum CreateTransactionOutcome {
    Submitted(Transaction),
    AlreadyPending,
    AlreadyConfirmed(u32),
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
    // Last-line invariant at the durable boundary: even if a future wallet-mutation path forgets
    // its own preflight check, it cannot persist a file in which one name aliases multiple keys.
    validate_unique_wallet_names(key_data_vec)?;

    // The serialized buffer contains every wallet's key material in the clear for
    // passphrase-less wallets, so it is wiped on drop rather than left in a freed
    // allocation. Zeroizing<String> derefs to str, so the write path is unchanged.
    let serialized = Zeroizing::new(serde_json::to_string(key_data_vec)?);
    match tokio::time::timeout(Duration::from_secs(5), async {
        write_secret_file(key_file_path, serialized.as_ref()).await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            Err(format!("failed to persist wallet key to {}: {}", key_file_path, e).into())
        }
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
        wallet_ledger: Option<Arc<WalletLedger>>,
    ) -> Self {
        Mgmt {
            blockchain,
            wallet_ledger,
        }
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
        validate_unique_wallet_names(&existing_keys)?;

        let is_encrypted = passphrase.map(|p| !p.is_empty()).unwrap_or(false);

        // Resolve against the durable file, not only the successfully decrypted in-memory subset.
        // Keep the borrowed name set scoped here so it cannot overlap the later mutable insert.
        let name = {
            let loaded_names: HashSet<&str> = wallets.keys().map(String::as_str).collect();
            match select_new_wallet_name(wallet_name, &loaded_names, &existing_keys) {
                Ok(name) => name,
                Err(error) => {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))?;
                    writeln!(stdout, "\nError: {}", error)?;
                    stdout.reset()?;
                    return Err(error);
                }
            }
        };

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
            let pass = zeroize::Zeroizing::new(
                match Password::new("Enter passphrase (or press Enter for no encryption):")
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
                },
            );

            if !pass.trim().is_empty() {
                let pass_bytes = zeroize::Zeroizing::new(pass.trim().as_bytes().to_vec());
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

            match tokio::time::timeout(Duration::from_secs(5), async {
                Wallet::new(pass_slice.map(Vec::as_slice))
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
                    Wallet::new(pass_slice.map(Vec::as_slice))?
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
                // Validate before attempting any decryption. Otherwise two loadable records with the
                // same name are inserted sequentially and the latter silently hides the former.
                validate_unique_wallet_names(&wallet_key_data)?;
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
                                // Defensive fail-closed guard at the representation boundary. The
                                // durable preflight above makes this unreachable for a valid file.
                                if wallets.contains_key(&wallet_name) {
                                    return Err(format!(
                                        "Duplicate wallet name {:?} encountered while loading {}",
                                        wallet_name, KEY_FILE_PATH
                                    )
                                    .into());
                                }
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

    pub async fn rename_wallet(
        &self,
        wallets: &mut HashMap<String, Wallet>,
        old_name: &str,
        new_name: &str,
    ) -> Result<()> {
        if old_name == new_name {
            return Err("Wallet name is unchanged".into());
        }
        if new_name.trim().is_empty() {
            return Err("New wallet name cannot be empty".into());
        }
        if !wallets.contains_key(old_name) {
            return Err(Box::new(BlockchainError::WalletNotFound));
        }
        if wallets.contains_key(new_name) {
            return Err("Duplicate wallet name".into());
        }

        let mut wallet_key_data = match fs::read_to_string(KEY_FILE_PATH).await {
            Ok(data) => serde_json::from_str::<Vec<WalletKeyData>>(&data)?,
            Err(_) => {
                return Err(Box::new(BlockchainError::InvalidCommand(
                    "No wallet file found".into(),
                )))
            }
        };
        // Do not mutate a pre-existing ambiguous file. `old_name` cannot identify which duplicate
        // key the operator intended to rename, so automatic repair here would risk renaming the
        // wrong wallet.
        validate_unique_wallet_names(&wallet_key_data)?;

        if wallet_key_data.iter().any(|w| w.wallet_name == new_name) {
            return Err("Duplicate wallet name".into());
        }

        // Find the wallet by old name and update it
        if let Some(wallet) = wallet_key_data
            .iter_mut()
            .find(|w| w.wallet_name == old_name)
        {
            wallet.wallet_name = new_name.to_string();

            // Write the updated wallet key data back to the file
            persist_wallet_keys(KEY_FILE_PATH, &wallet_key_data).await?;

            if let Some(mut wallet) = wallets.remove(old_name) {
                wallet.name = new_name.to_string();
                wallets.insert(new_name.to_string(), wallet);
            }

            info!("Wallet renamed from '{}' to '{}'", old_name, new_name);
            Ok(())
        } else {
            Err(Box::new(BlockchainError::WalletNotFound))
        }
    }

    /// Mine one block.
    ///
    /// `announce` is called the moment the block is finalized, before any of the reporting
    /// that follows. It exists so the network hears about a block as early as this code can
    /// possibly say it — see the call site for why that ordering matters. It must only hand
    /// the block off (spawn, queue); anything that blocks or awaits inside it is stalling a
    /// freshly-mined block against the clock that decides whether it orphans.
    // The arguments are explicit capabilities/state owned by the caller. Bundling them would create
    // a second mining context whose lifetime and synchronization invariants could drift.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_mine_command(
        &self,
        command: &[&str],
        miner: &Miner,
        wallets: &mut HashMap<String, Wallet>,
        blockchain: &Arc<RwLock<Blockchain>>,
        _db_arc: &Arc<RwLock<Db>>,
        use_gpu: bool,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        announce: &dyn Fn(&Block),
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
        // template rebuild / per dispatch from live state.
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
                use_gpu,
                stop,
            )
            .await
        {
            Ok((_nonce, _hash, mined_block)) => {
                // ANNOUNCE FIRST. mine_block has returned, so the block is validated and
                // durably committed — there is nothing left to learn about it, and every
                // instant it stays on this machine is time a competitor's block spends
                // propagating instead. What follows is display work, and the balance
                // breakdown below takes a fresh chain READ guard: tokio's RwLock is
                // write-preferring, so right after finalize releases the write guard that
                // read queues behind any block already waiting to be applied. Under load —
                // exactly when blocks are contested — that is tens of milliseconds of
                // silence bought for a console line.
                //
                // The hook only hands the block off (it spawns, it does not send), so this
                // holds no lock and cannot block the miner.
                announce(&mined_block);

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
                    writeln!(stdout, "Mining reward: {:.8} ♦", mining_reward)?;
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
                        "Mining reward: {:.8} ♦ — credited, spendable in {}",
                        mining_reward, eta
                    )?;
                    writeln!(stdout, "Spendable balance: {}", breakdown.spendable)?;
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(128, 128, 128))))?;
                    writeln!(
                        stdout,
                        "Maturing: {:.8} ♦ ({} reward{} on the way)",
                        maturing_total,
                        breakdown.maturing.len(),
                        if breakdown.maturing.len() == 1 {
                            ""
                        } else {
                            "s"
                        }
                    )?;
                    stdout.reset()?;
                }
                writeln!(stdout)?;

                Ok(mined_block)
            }
            Err(crate::a9::miner::MiningError::Stopped) => {
                // Clean user stop (Enter), not a fault — no red "error" line.
                writeln!(stdout, "Mining stopped.")?;
                Err(Box::new(crate::a9::miner::MiningError::Stopped))
            }
            Err(e) => {
                // Deliberately silent: the CALLER classifies this error and prints the
                // right thing. Printing a red "error:" here meant a routine lost block
                // race showed a fault line and THEN "Lost the race for this block…",
                // and pressing Enter to stop printed "error: Mining failed: Mining
                // cancelled". Neither is an error; both are normal outcomes.
                Err(Box::new(e))
            }
        }
    }

    /// Create, sign, and atomically classify a transaction against canonical and
    /// durable pending state. Only `Submitted` may be announced to the network.
    pub async fn handle_create_transaction(
        &self,
        command: &str,
        wallets: &mut HashMap<String, Wallet>,
        blockchain: &Arc<RwLock<Blockchain>>,
        _db_arc: &Arc<RwLock<Db>>,
    ) -> Result<CreateTransactionOutcome> {
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
        // Auto fee (no --fee given): price next-block inclusion off the live
        // mempool (Blockchain::fee_estimate) at send time — the flat anchor on
        // a quiet network, one unit above the marginal next-block fee under
        // congestion, clamped to the wallet safety ceiling by construction. The
        // brief chain read guard here only reaches the mempool and is released
        // before the send flow's own guard below.
        let fee_units = match parsed.fee_units {
            Some(units) => units,
            None => {
                let estimate = blockchain.read().await.fee_estimate().await;
                // Never emit a fee that would be READ as a whisper. Classification
                // is a fee-band test and the code space saturates the band, so this
                // cannot be fixed when decoding — an ordinary payment whose fee
                // lands in the band is announced to the recipient as a whisper
                // carrying a meaningless code, and its amount is not shown at all.
                // The estimator is amount-independent, so the clamp belongs here,
                // where the amount is known. Lowering a fee is always safe: the
                // relay floor is the only hard requirement, and the band opens
                // strictly above it for any positive amount.
                let ceiling = max_non_whisper_fee_units(amount_units);
                let recommended = estimate
                    .recommended_units
                    .min(ceiling)
                    .max(MIN_RELAY_FEE_UNITS);
                // Show the auto fee BEFORE signing and submitting: the user
                // never typed this number, so it must not first appear in the
                // success summary (and never at all on the error path).
                writeln!(
                    stdout,
                    "  Auto fee: {:.8} ({})",
                    Transaction::from_units(recommended),
                    if recommended < estimate.recommended_units {
                        "capped below the whisper band"
                    } else if estimate.congested {
                        "next-block price, network contended"
                    } else {
                        "network quiet"
                    }
                )?;
                recommended
            }
        };
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

        // Collision-free timestamp allocation. The chain's transaction identity is
        // sender:recipient:amount:fee:timestamp, which is also the signed message, so two
        // intended-distinct payments that share the first four fields are the SAME transaction —
        // identical id, identical signed bytes — if signed in the same second. The second would be
        // silently absorbed as a duplicate and never paid. The ledger advances the timestamp so an
        // identical-looking second payment becomes a genuinely distinct transaction instead.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Failed to get timestamp")?
            .as_secs();
        let payment_tuple = PaymentTuple::new(
            sender_address.clone(),
            recipient_address.clone(),
            amount_units,
            fee_units,
        );
        let timestamp = match self.wallet_ledger.as_ref() {
            Some(ledger) => match ledger.allocate_timestamp(&payment_tuple, now) {
                Ok(allocated) => {
                    if allocated != now {
                        writeln!(
                            stdout,
                            "  Identical payment (same recipient, amount and fee) already prepared \
                             this second; using timestamp {allocated} so this is a distinct \
                             transaction, not a silently-merged duplicate."
                        )?;
                    }
                    allocated
                }
                Err(_) => {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
                    write!(stdout, "error")?;
                    stdout.reset()?;
                    writeln!(
                        stdout,
                        ": too many identical payments (same recipient, amount and fee) in a short \
                         window to schedule a distinct one; vary the amount or fee to make it a \
                         separate payment"
                    )?;
                    return Err(
                        "cannot allocate a distinct timestamp for an identical payment burst"
                            .into(),
                    );
                }
            },
            // Fail closed: the whole point of the ledger is that a payment is never silently
            // dropped to a same-second collision. Falling back to a raw timestamp would reintroduce
            // exactly that risk, so refuse to sign instead.
            None => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
                write!(stdout, "error")?;
                stdout.reset()?;
                writeln!(
                    stdout,
                    ": payment ledger unavailable; refusing to sign without collision-safe timestamp \
                     allocation (a raw timestamp could silently merge two distinct payments)"
                )?;
                return Err(
                    "wallet payment ledger unavailable; cannot reserve a collision-safe timestamp"
                        .into(),
                );
            }
        };

        // Signing phase
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true))?;
        write!(stdout, "    Signing")?;
        stdout.reset()?;
        write!(stdout, " transaction...")?;
        stdout.flush()?;

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

        // Persist the reservation durably BEFORE submitting (persist-before-expose). If we crash
        // after this, the payment is recoverable and its timestamp allocation survives restart; if
        // we crash before it, nothing was ever admitted. Fail closed: never submit a payment we
        // could not first record, or a crash could destroy the only evidence it was sent. The
        // fsync runs on a blocking thread so it never stalls the shared node runtime.
        if let Some(ledger) = self.wallet_ledger.as_ref() {
            let ledger = Arc::clone(ledger);
            let tuple = payment_tuple.clone();
            let tx_id = transaction.get_tx_id();
            let signed_tx = serde_json::to_string(&transaction).ok();
            match tokio::task::spawn_blocking(move || {
                ledger.record(None, tuple, timestamp, tx_id, signed_tx, now)
            })
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    writeln!(stdout)?;
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
                    write!(stdout, "error")?;
                    stdout.reset()?;
                    writeln!(
                        stdout,
                        ": could not record the payment before submitting: {error}"
                    )?;
                    return Err(format!("wallet ledger record failed: {error}").into());
                }
                Err(join_error) => {
                    return Err(format!("wallet ledger task failed: {join_error}").into());
                }
            }
        }

        // M2: a read guard suffices — add_transaction self-serializes on its internal
        // state_mutation_lock and runs the ML-DSA verify before taking it, so an exclusive
        // outer guard here only blocked concurrent block-ingest for no gain (matches the
        // network callers). Still scoped to the submit alone: the Ok arm re-reads the chain
        // for the balance (get_wallet_balance), which under a held guard self-deadlocked
        // right after "Done".
        let submit_result = {
            let chain = blockchain.read().await;
            chain.admit_transaction(transaction.clone()).await
        };
        match submit_result {
            Ok(crate::a9::blockchain::TransactionAdmissionOutcome::Inserted) => {
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
                writeln!(stdout, "\nTransaction submitted — pending confirmation")?;
                stdout.reset()?;

                // Transaction summary
                writeln!(stdout, "\n  From:     {}", sender_address)?;
                writeln!(stdout, "  To:       {}", recipient_address)?;
                writeln!(stdout, "  Amount:   {}", amount)?;
                writeln!(stdout, "  Fee:      {}", fee)?;
                writeln!(stdout, "  Balance:  {}\n", new_sender_balance)?;

                Ok(CreateTransactionOutcome::Submitted(transaction))
            }
            Ok(crate::a9::blockchain::TransactionAdmissionOutcome::AlreadyPending) => {
                writeln!(
                    stdout,
                    "Not submitted: an identical transaction is already pending."
                )?;
                writeln!(
                    stdout,
                    "To make a distinct payment, change the amount or fee, or retry in the next second."
                )?;
                Ok(CreateTransactionOutcome::AlreadyPending)
            }
            Ok(crate::a9::blockchain::TransactionAdmissionOutcome::AlreadyConfirmed(height)) => {
                writeln!(
                    stdout,
                    "Not submitted: an identical transaction is already confirmed at block {}.",
                    height
                )?;
                writeln!(
                    stdout,
                    "To make a distinct payment, change the amount or fee, or retry in the next second."
                )?;
                Ok(CreateTransactionOutcome::AlreadyConfirmed(height))
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
        // Auto, not Always: `account <addr> | grep` was receiving raw ANSI
        // escapes. The sibling load_wallets already uses Auto.
        let mut stdout = StandardStream::stdout(ColorChoice::Auto);
        // `account` looks up ANY address — that is the point of it. Bare, it resolves the
        // same default wallet `mine` and a bare send use, so the common case costs no typing;
        // a wallet NAME resolves too, because a name is what the operator actually remembers.
        // Anything else is passed through as a raw address.
        let requested = args.split_whitespace().nth(1);
        let resolved: Option<String> = match requested {
            Some(arg) => Some(
                wallets
                    .get(arg)
                    .map(|w| w.address.clone())
                    .unwrap_or_else(|| arg.to_string()),
            ),
            None => match resolve_default_wallet(wallets, blockchain).await {
                Some((name, addr)) => {
                    ui_seg(&mut stdout, &mut ColorSpec::new(), UI_DIM, false, " ")?;
                    writeln!(
                        stdout,
                        "showing {} — `account <address>` looks up any other",
                        name
                    )?;
                    Some(addr)
                }
                None => None,
            },
        };

        match resolved.as_deref() {
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
                // rendered bold only on Windows (Console API) and plain on Unix. Weight is set
                // explicitly on every run (ui_seg) so nothing inherits a stale bold flag.
                let spec = &mut ColorSpec::new();
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // ── banner: identity, then a balance that RECONCILES ───────────
                // spendable + maturing + pending_debit = confirmed. The old screen
                // printed spendable under a bare "Balance:" label and put the
                // pending figure in its own section four lines away, so the two
                // could not be related by eye.
                let maturing_total: f64 = breakdown.maturing.iter().map(|(_, amount)| amount).sum();
                writeln!(stdout)?;
                ui_seg(&mut stdout, spec, UI_LABEL, false, " ")?;
                ui_seg(&mut stdout, spec, UI_CYAN, true, "Account")?;
                ui_seg(&mut stdout, spec, UI_LABEL, false, "   ")?;
                ui_text(&mut stdout, spec, false, addr)?;
                writeln!(stdout)?;

                ui_seg(&mut stdout, spec, UI_LABEL, false, " ")?;
                let seen = history.as_ref().is_some_and(|s| s.tx_count > 0);
                if seen {
                    ui_seg(&mut stdout, spec, UI_GREEN, false, "✓ ACTIVE")?;
                } else {
                    ui_seg(&mut stdout, spec, UI_DIM, false, "○ UNSEEN")?;
                }
                ui_pad(&mut stdout, spec, 9, 17)?;
                // Local-wallet match against wallet ADDRESSES. The old check was
                // `wallets.contains_key(addr)`, but the map is keyed by wallet
                // NAME — so "Local Wallet" only ever fired for a wallet literally
                // named after its own address.
                let local = wallets
                    .iter()
                    .find(|(_, wallet)| wallet.address == addr)
                    .map(|(name, _)| name.clone());
                let mut col = 17usize;
                if let Some(name) = local.as_ref() {
                    ui_seg(&mut stdout, spec, UI_CYAN, false, "● local")?;
                    ui_seg(&mut stdout, spec, UI_DIM, false, " · ")?;
                    ui_seg(&mut stdout, spec, UI_CYAN, false, name)?;
                    col += 10 + name.chars().count();
                } else {
                    ui_seg(&mut stdout, spec, UI_DIM, false, "○ not local")?;
                    col += 11;
                }
                // A long wallet name (default_wallet) reaches the tx column and
                // used to butt straight into it — "default_wallet16 txs". The
                // next field always starts at least two spaces clear.
                let tx_count = history.as_ref().map_or(0, |s| s.tx_count);
                let tx_text = format!("{} txs", tx_count);
                let tx_col = 41usize.max(col + 2);
                ui_pad(&mut stdout, spec, col, tx_col)?;
                ui_seg(&mut stdout, spec, UI_BLUE, false, &tx_text)?;
                col = tx_col + tx_text.chars().count();
                ui_pad(&mut stdout, spec, col, 57usize.max(col + 2))?;
                ui_seg(&mut stdout, spec, UI_DIM, false, "tip ")?;
                ui_seg(
                    &mut stdout,
                    spec,
                    UI_BLUE,
                    false,
                    &ui_thousands(breakdown.as_of_height),
                )?;
                writeln!(stdout)?;

                // MEASURE the money field, never assume its width. `ui_money(x, 4)`
                // right-pads the whole part to 4 digits, so it is 15 columns up to
                // 9999.99999999 and WIDER above it — the hardcoded 15 this replaces
                // drifted the right-hand column one cell per extra digit (one at
                // 10k, two at 100k, four at 33M). chars(), not len(): the ♦ is three
                // bytes and one column.
                let spendable_text = ui_money(balance, 4);
                ui_seg(&mut stdout, spec, UI_LABEL, false, " ")?;
                ui_seg(&mut stdout, spec, UI_CYAN, false, &spendable_text)?;
                ui_seg(&mut stdout, spec, UI_DIM, false, " spendable")?;
                ui_pad(
                    &mut stdout,
                    spec,
                    1 + spendable_text.chars().count() + " spendable".chars().count(),
                    41,
                )?;
                if maturing_total > 0.0 {
                    ui_seg(
                        &mut stdout,
                        spec,
                        UI_ORANGE,
                        false,
                        &ui_money(maturing_total, 4),
                    )?;
                    ui_seg(
                        &mut stdout,
                        spec,
                        UI_DIM,
                        false,
                        &format!(" maturing · {}", breakdown.maturing.len()),
                    )?;
                } else {
                    ui_seg(&mut stdout, spec, UI_DIM, false, "no maturing rewards")?;
                }
                writeln!(stdout)?;

                if pending_stats.0 > 0 || pending_stats.1 > 0 {
                    let pending_text = ui_money(pending_stats.2, 4);
                    let pending_label = format!(" pending out · {}", pending_stats.0);
                    ui_seg(&mut stdout, spec, UI_LABEL, false, " ")?;
                    ui_seg(&mut stdout, spec, UI_ORANGE, false, &pending_text)?;
                    ui_seg(&mut stdout, spec, UI_DIM, false, &pending_label)?;
                    // Same measured form. The label carries a "·" (two bytes, one
                    // column) as well as the money field's ♦, so byte length would
                    // over-count both.
                    ui_pad(
                        &mut stdout,
                        spec,
                        1 + pending_text.chars().count() + pending_label.chars().count(),
                        41,
                    )?;
                    ui_seg(
                        &mut stdout,
                        spec,
                        UI_CYAN,
                        false,
                        &ui_money(breakdown.confirmed, 4),
                    )?;
                    ui_seg(&mut stdout, spec, UI_DIM, false, " = confirmed")?;
                    writeln!(stdout)?;
                }

                ui_seg(&mut stdout, spec, UI_DIM, false, UI_RULE)?;
                writeln!(stdout)?;

                // ── Maturing Rewards │ History ─────────────────────────────────
                // The per-reward (height, amount) detail is already decoded by
                // immature_coinbase_details; the old screen collapsed it to a sum
                // and threw the rest away.
                ui_grid_header(
                    &mut stdout,
                    spec,
                    "Maturing Rewards",
                    UI_CYAN,
                    "History",
                    UI_BLUE,
                )?;
                let stats = history.clone().unwrap_or_default();
                let right_rows: Vec<(String, Vec<(Color, String)>)> = vec![
                    (
                        "Received:".to_string(),
                        vec![(
                            UI_BLUE,
                            ui_money(Transaction::from_units(stats.received_units), 4),
                        )],
                    ),
                    (
                        "Sent:".to_string(),
                        vec![(
                            UI_BLUE,
                            ui_money(Transaction::from_units(stats.sent_units), 4),
                        )],
                    ),
                    (
                        "Fees Paid:".to_string(),
                        vec![(
                            UI_BLUE,
                            ui_money(Transaction::from_units(stats.fees_units), 4),
                        )],
                    ),
                    (
                        "First Activity:".to_string(),
                        vec![(
                            UI_BLUE,
                            stats.first_height.map_or_else(
                                || "—".to_string(),
                                |h| format!("block {}", ui_thousands(h as u64)),
                            ),
                        )],
                    ),
                    (
                        "Last Activity:".to_string(),
                        vec![(
                            UI_BLUE,
                            stats.last_height.map_or_else(
                                || "—".to_string(),
                                |h| format!("block {}", ui_thousands(h as u64)),
                            ),
                        )],
                    ),
                ];
                let mut left_rows: Vec<(String, Vec<(Color, String)>)> = breakdown
                    .maturing
                    .iter()
                    .map(|(height, amount)| {
                        (
                            format!("block {}:", ui_thousands(*height as u64)),
                            vec![
                                (UI_CYAN, format!("{:.8} ♦", amount)),
                                (
                                    UI_ORANGE,
                                    format!(
                                        "  {} blk",
                                        blocks_until_mature(*height, breakdown.as_of_height)
                                    ),
                                ),
                            ],
                        )
                    })
                    .collect();
                if left_rows.is_empty() {
                    left_rows.push(("Maturing:".to_string(), vec![(UI_DIM, "none".to_string())]));
                } else {
                    let next_left = breakdown
                        .maturing
                        .iter()
                        .map(|(height, _)| blocks_until_mature(*height, breakdown.as_of_height))
                        .min()
                        .unwrap_or(0);
                    left_rows.push((
                        "Next spendable:".to_string(),
                        vec![
                            (UI_ORANGE, format!("{} blk", next_left)),
                            (UI_DIM, format!(" · {}", format_maturity_eta(next_left))),
                        ],
                    ));
                }
                // Supply share rides the right pane rather than owning a section
                // with a header, a rule and one number.
                let mut right_rows = right_rows;
                if let Some(total_supply_units) = total_supply_units {
                    let total_supply = Transaction::from_units(total_supply_units);
                    if total_supply > 0.0 {
                        right_rows.push((
                            "Supply Share:".to_string(),
                            vec![(
                                UI_BLUE,
                                format!("{:.4}%", (breakdown.confirmed / total_supply) * 100.0),
                            )],
                        ));
                    }
                }
                for index in 0..left_rows.len().max(right_rows.len()) {
                    let left = left_rows
                        .get(index)
                        .map(|(label, runs)| (label.as_str(), runs.as_slice()));
                    let right = right_rows
                        .get(index)
                        .map(|(label, runs)| (label.as_str(), runs.as_slice()));
                    ui_grid_row(&mut stdout, spec, left, right)?;
                }

                ui_seg(&mut stdout, spec, UI_DIM, false, UI_RULE)?;
                writeln!(stdout)?;

                // ── Recent Activity ───────────────────────────────────────────
                const SHOWN: usize = 8;
                ui_seg(&mut stdout, spec, UI_LABEL, false, " ")?;
                ui_seg(&mut stdout, spec, UI_BLUE, true, "Recent Activity")?;
                match &history {
                    Some(stats) => {
                        let shown = recent.len().min(SHOWN);
                        let note = format!("last {} of {}", shown, stats.tx_count);
                        ui_pad(&mut stdout, spec, 16, 78 - note.chars().count())?;
                        ui_seg(&mut stdout, spec, UI_DIM, false, &note)?;
                        writeln!(stdout)?;
                        if recent.is_empty() {
                            ui_seg(&mut stdout, spec, UI_LABEL, false, " ")?;
                            ui_seg(
                                &mut stdout,
                                spec,
                                UI_DIM,
                                false,
                                "no confirmed transactions — this address has never appeared in a block",
                            )?;
                            writeln!(stdout)?;
                        } else {
                            // Column right edges. Every cell is right-aligned to
                            // one of these, so an over-wide value can never shove
                            // the columns after it.
                            const PARTY: usize = 9;
                            const AMOUNT_END: usize = 46;
                            const AGE_END: usize = 53;
                            const HEIGHT_END: usize = 63;
                            const CONF_END: usize = 71;

                            ui_pad(&mut stdout, spec, 0, PARTY)?;
                            ui_seg(&mut stdout, spec, UI_DIM, false, "counterparty")?;
                            let mut col = PARTY + 12;
                            col = ui_right(
                                &mut stdout,
                                spec,
                                col,
                                AMOUNT_END,
                                UI_DIM,
                                false,
                                "amount",
                            )?;
                            col = ui_right(&mut stdout, spec, col, AGE_END, UI_DIM, false, "age")?;
                            col = ui_right(
                                &mut stdout,
                                spec,
                                col,
                                HEIGHT_END,
                                UI_DIM,
                                false,
                                "height",
                            )?;
                            ui_right(&mut stdout, spec, col, CONF_END, UI_DIM, false, "conf")?;
                            writeln!(stdout)?;

                            for entry in recent.iter().take(SHOWN) {
                                // A coinbase indexes with the system address as the
                                // counterparty, so it used to render as an ordinary
                                // "RECEIVED ... from MINING_REWARDS". It gets its own
                                // token and hue.
                                let coinbase = entry.is_recipient()
                                    && SYSTEM_ADDRESSES.contains(&entry.counterparty.as_str());
                                let (token, hue, sign) = if coinbase {
                                    ("▾ mine", UI_LAVENDER, "+")
                                } else if entry.is_sender() {
                                    ("▴ out ", UI_PINK, "-")
                                } else {
                                    ("▾ in  ", UI_GREEN, "+")
                                };
                                ui_seg(&mut stdout, spec, UI_LABEL, false, " ")?;
                                ui_seg(&mut stdout, spec, hue, false, token)?;
                                ui_seg(&mut stdout, spec, UI_LABEL, false, "  ")?;
                                let party = ui_address(&entry.counterparty);
                                ui_text(&mut stdout, spec, false, &party)?;
                                let mut col = PARTY + party.chars().count();
                                // int_digits 5: the widest coin amount the column
                                // must hold without eating the gap to `age`.
                                let amount = format!(
                                    "{}{}",
                                    sign,
                                    ui_money(Transaction::from_units(entry.amount_units), 5)
                                );
                                col = ui_right(
                                    &mut stdout,
                                    spec,
                                    col,
                                    AMOUNT_END,
                                    hue,
                                    false,
                                    &amount,
                                )?;
                                let age = ui_age(now_secs.saturating_sub(entry.timestamp));
                                col =
                                    ui_right(&mut stdout, spec, col, AGE_END, UI_DIM, false, &age)?;
                                let height = ui_thousands(entry.height as u64);
                                col = ui_right(
                                    &mut stdout,
                                    spec,
                                    col,
                                    HEIGHT_END,
                                    UI_BLUE,
                                    false,
                                    &height,
                                )?;
                                // Depth from the SAME height the balance was read at,
                                // so confirmations can never disagree with the figures
                                // in the banner above.
                                let conf = ui_thousands(
                                    breakdown
                                        .as_of_height
                                        .saturating_sub(entry.height as u64)
                                        .saturating_add(1),
                                );
                                ui_right(&mut stdout, spec, col, CONF_END, UI_DIM, false, &conf)?;
                                // The locked marker is membership in the SAME Vec the
                                // spendable figure was computed from, so the row and
                                // the balance can never drift apart.
                                if coinbase
                                    && breakdown
                                        .maturing
                                        .iter()
                                        .any(|(height, _)| *height == entry.height)
                                {
                                    ui_seg(&mut stdout, spec, UI_LABEL, false, "   ")?;
                                    ui_seg(&mut stdout, spec, UI_ORANGE, false, "locked")?;
                                }
                                writeln!(stdout)?;
                            }

                            // ── Counterparties ────────────────────────────────
                            // The table above truncates every address to stay in its
                            // columns, which is exactly wrong for the addresses a reader
                            // most likely wants to act on — pay again, check, paste
                            // somewhere. These three are printed IN FULL for that reason.
                            //
                            // Free: derived from `recent`, already fetched and already in
                            // memory. No extra chain query, no extra time under the guard.
                            //
                            // Scoped honestly. `frequent` is the most common counterparty
                            // WITHIN the fetched window, not all time — the header says so
                            // rather than letting the label overclaim. Coinbase rows are
                            // excluded: MINING_REWARDS is not a counterparty anyone deals
                            // with, and it would win `frequent` outright on a miner.
                            let (last_in, last_out, frequent) = notable_counterparties(&recent);

                            if last_in.is_some() || last_out.is_some() || frequent.is_some() {
                                writeln!(stdout)?;
                                ui_seg(&mut stdout, spec, UI_LABEL, false, " ")?;
                                ui_seg(&mut stdout, spec, UI_BLUE, true, "Counterparties")?;
                                let note = format!("within the last {} shown", recent.len());
                                ui_pad(&mut stdout, spec, 16, 78 - note.chars().count())?;
                                ui_seg(&mut stdout, spec, UI_DIM, false, &note)?;
                                writeln!(stdout)?;

                                const ADDR_AT: usize = 12;
                                const VALUE_END: usize = 78;
                                let mut row = |label: &str,
                                               hue: Color,
                                               party: &str,
                                               value: String|
                                 -> Result<()> {
                                    ui_seg(&mut stdout, spec, UI_LABEL, false, "   ")?;
                                    ui_seg(&mut stdout, spec, hue, false, label)?;
                                    ui_pad(&mut stdout, spec, 3 + label.chars().count(), ADDR_AT)?;
                                    // Terminal default foreground: an address must stay
                                    // legible on any theme.
                                    ui_text(&mut stdout, spec, false, party)?;
                                    ui_right(
                                        &mut stdout,
                                        spec,
                                        ADDR_AT + party.chars().count(),
                                        VALUE_END,
                                        UI_DIM,
                                        false,
                                        &value,
                                    )?;
                                    writeln!(stdout)?;
                                    Ok(())
                                };

                                if let Some(e) = last_in {
                                    row(
                                        "last in",
                                        UI_GREEN,
                                        &e.counterparty,
                                        format!(
                                            "+{:.8} ♦",
                                            Transaction::from_units(e.amount_units)
                                        ),
                                    )?;
                                }
                                if let Some(e) = last_out {
                                    row(
                                        "last out",
                                        UI_PINK,
                                        &e.counterparty,
                                        format!(
                                            "-{:.8} ♦",
                                            Transaction::from_units(e.amount_units)
                                        ),
                                    )?;
                                }
                                if let Some((party, n)) = frequent {
                                    row(
                                        "frequent",
                                        UI_LAVENDER,
                                        party,
                                        format!("{} of {}", n, recent.len()),
                                    )?;
                                }
                            }
                        }
                    }
                    // address_recent_txs returns an empty Vec for BOTH "no activity"
                    // and "index not built yet" — only the index-backed summary
                    // separates them, so the two cases finally say different things.
                    None => {
                        ui_pad(&mut stdout, spec, 16, 64)?;
                        ui_seg(&mut stdout, spec, UI_ORANGE, false, "index building")?;
                        writeln!(stdout)?;
                        ui_seg(&mut stdout, spec, UI_LABEL, false, " ")?;
                        ui_seg(
                            &mut stdout,
                            spec,
                            UI_ORANGE,
                            false,
                            "history unavailable — the address index is still building; retry shortly",
                        )?;
                        writeln!(stdout)?;
                    }
                }
                writeln!(stdout)?;
                stdout.reset()?;
            }
        }
        Ok(())
    }

    /// The wallet ledger: every wallet's spendable / locked / outbound split,
    /// footed against a total that reconciles.
    ///
    /// Colour states spendability and nothing else — cyan is movable money,
    /// warm hues are money you cannot spend yet (orange still maturing, pink
    /// already leaving), green is the derived confirmed sum. A zero balance
    /// renders dim, because a zero is not money.
    ///
    /// Recent activity across every loaded wallet, newest first.
    ///
    /// Reads the address index directly rather than going through the whisper
    /// module: `whisper::get_recent_transactions` flattened `AddressTxEntry`
    /// into a 5-field struct that discarded height, position and the
    /// sender/recipient flag bits — so direction had to be re-inferred by
    /// string comparison and confirmations could not be shown at all. Every
    /// column here is already decoded by the index.
    pub async fn handle_history_command(
        &self,
        args: &str,
        blockchain: &Arc<RwLock<Blockchain>>,
        wallets: &HashMap<String, Wallet>,
    ) -> Result<()> {
        let mut stdout = StandardStream::stdout(ColorChoice::Auto);
        let spec = &mut ColorSpec::new();

        // `history 200` and `history <addr>` used to be silently ignored.
        let mut rows_wanted = 12usize;
        if let Some(arg) = args.split_whitespace().nth(1) {
            match arg.parse::<usize>() {
                Ok(n) if (1..=50).contains(&n) => rows_wanted = n,
                _ => {
                    ui_seg(
                        &mut stdout,
                        spec,
                        UI_DIM,
                        false,
                        " Usage: history [rows]   ",
                    )?;
                    ui_seg(&mut stdout, spec, UI_MUTED, false, "rows 1-50, default 12")?;
                    ui_seg(
                        &mut stdout,
                        spec,
                        UI_DIM,
                        false,
                        "   ·   one address: account <address>\n",
                    )?;
                    stdout.reset()?;
                    return Ok(());
                }
            }
        }

        let Ok(guard) =
            tokio::time::timeout(std::time::Duration::from_secs(3), blockchain.read()).await
        else {
            ui_seg(
                &mut stdout,
                spec,
                UI_ORANGE,
                false,
                " chain busy (syncing/reorg in progress) — try history again shortly\n",
            )?;
            stdout.reset()?;
            return Ok(());
        };

        struct Entry {
            wallet: String,
            counterparty: String,
            amount_units: i128,
            fee_units: i128,
            is_out: bool,
            is_self: bool,
            coinbase: bool,
            height: Option<u32>,
            position: u32,
            timestamp: u64,
        }

        let tip = guard.get_latest_block_index();
        let index_ready = guard.address_index_ready();
        let mut entries: Vec<Entry> = Vec::new();

        if index_ready {
            for (name, wallet) in wallets {
                let recent = guard
                    .address_recent_txs(&wallet.address, 50, None)
                    .unwrap_or_default();
                for e in recent {
                    // Read every flag BEFORE moving the counterparty string out.
                    let (sender, recipient) = (e.is_sender(), e.is_recipient());
                    let coinbase = recipient && SYSTEM_ADDRESSES.contains(&e.counterparty.as_str());
                    entries.push(Entry {
                        wallet: name.clone(),
                        counterparty: e.counterparty,
                        amount_units: e.amount_units,
                        fee_units: e.fee_units,
                        is_out: sender && !recipient,
                        is_self: sender && recipient,
                        coinbase,
                        height: Some(e.height),
                        position: e.position,
                        timestamp: e.timestamp,
                    });
                }
            }
        }

        // Mempool rows. get_mempool_transactions is a prune + clone; the old
        // code called get_pending_transactions ONCE PER WALLET, and each call
        // ran sync_mempool_with_sled — state_mutation_lock, full signature
        // re-verification of every pending tx, two sled flushes and a
        // pending-debits rebuild. A read-only screen was doing N mempool
        // rebuilds under the chain guard.
        let mempool = guard.get_mempool_transactions().await.unwrap_or_default();
        for tx in mempool {
            for (name, wallet) in wallets {
                let is_sender = tx.sender == wallet.address;
                let is_recipient = tx.recipient == wallet.address;
                if !is_sender && !is_recipient {
                    continue;
                }
                entries.push(Entry {
                    wallet: name.clone(),
                    counterparty: if is_sender {
                        tx.recipient.clone()
                    } else {
                        tx.sender.clone()
                    },
                    amount_units: tx.amount_units,
                    fee_units: tx.fee_units,
                    is_out: is_sender && !is_recipient,
                    is_self: is_sender && is_recipient,
                    coinbase: false,
                    height: None,
                    position: 0,
                    timestamp: tx.timestamp,
                });
            }
        }
        drop(guard);

        // Identity is (height, position) — the old dedup keyed on
        // (timestamp, from, to, |Δamount| < f64::EPSILON), which cannot see
        // identity because the exact units had already been discarded.
        entries.sort_by(|a, b| {
            b.height
                .cmp(&a.height)
                .then_with(|| b.position.cmp(&a.position))
                .then_with(|| b.timestamp.cmp(&a.timestamp))
        });
        entries.dedup_by(|a, b| {
            a.wallet == b.wallet
                && a.height == b.height
                && a.position == b.position
                && a.height.is_some()
        });
        // Pending first, then confirmed newest-first.
        entries.sort_by(|a, b| {
            a.height
                .is_some()
                .cmp(&b.height.is_some())
                .then_with(|| b.height.cmp(&a.height))
                .then_with(|| b.position.cmp(&a.position))
                .then_with(|| b.timestamp.cmp(&a.timestamp))
        });

        let total = entries.len();
        let pending = entries.iter().filter(|e| e.height.is_none()).count();
        let shown = entries.len().min(rows_wanted);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        writeln!(stdout)?;
        ui_seg(&mut stdout, spec, UI_LABEL, false, " ")?;
        ui_seg(&mut stdout, spec, UI_BLUE, true, "History")?;
        let note = if !index_ready {
            format!(
                "{} wallets · tip {} · index building",
                wallets.len(),
                ui_thousands(tip)
            )
        } else if pending > 0 {
            format!(
                "{} wallets · {} pending · tip {}",
                wallets.len(),
                pending,
                ui_thousands(tip)
            )
        } else {
            format!("{} wallets · tip {}", wallets.len(), ui_thousands(tip))
        };
        ui_pad(
            &mut stdout,
            spec,
            8,
            78usize.saturating_sub(note.chars().count()),
        )?;
        ui_seg(
            &mut stdout,
            spec,
            if index_ready { UI_DIM } else { UI_ORANGE },
            false,
            &note,
        )?;
        writeln!(stdout)?;

        if index_ready && total > 0 {
            let net: i128 = entries
                .iter()
                .map(|e| {
                    if e.is_self {
                        0
                    } else if e.is_out {
                        -(e.amount_units + e.fee_units)
                    } else {
                        e.amount_units
                    }
                })
                .sum();
            ui_seg(&mut stdout, spec, UI_DIM, false, " confirmed  ")?;
            ui_seg(
                &mut stdout,
                spec,
                UI_BLUE,
                false,
                &format!("{} of {}", shown, total),
            )?;
            ui_pad(
                &mut stdout,
                spec,
                12 + format!("{} of {}", shown, total).chars().count(),
                30,
            )?;
            ui_seg(&mut stdout, spec, UI_DIM, false, "net  ")?;
            ui_seg(
                &mut stdout,
                spec,
                if net < 0 { UI_PINK } else { UI_GREEN },
                false,
                &format!(
                    "{}{:.8} ♦",
                    if net < 0 { "-" } else { "+" },
                    Transaction::from_units(net.abs())
                ),
            )?;
            writeln!(stdout)?;
        }
        ui_seg(&mut stdout, spec, UI_DIM, false, UI_RULE)?;
        writeln!(stdout)?;

        if !index_ready {
            ui_seg(
                &mut stdout,
                spec,
                UI_ORANGE,
                false,
                " history unavailable — the address index is still building; retry shortly",
            )?;
            writeln!(stdout)?;
            writeln!(stdout)?;
            stdout.reset()?;
            return Ok(());
        }
        if total == 0 {
            ui_seg(
                &mut stdout,
                spec,
                UI_DIM,
                false,
                &format!(
                    " no activity — none of your {} wallet{} appears in a block or in the mempool",
                    wallets.len(),
                    if wallets.len() == 1 { "" } else { "s" }
                ),
            )?;
            writeln!(stdout)?;
            writeln!(stdout)?;
            stdout.reset()?;
            return Ok(());
        }

        // Column right edges, sharing the account table's geometry so the two
        // screens read as one system.
        const PARTY: usize = 9;
        const AMOUNT_END: usize = 46;
        const AGE_END: usize = 53;
        const HEIGHT_END: usize = 62;
        const CONF_END: usize = 70;
        const WALLET_AT: usize = 72;

        ui_pad(&mut stdout, spec, 0, PARTY)?;
        ui_seg(&mut stdout, spec, UI_DIM, false, "counterparty")?;
        let mut col = PARTY + 12;
        col = ui_right(&mut stdout, spec, col, AMOUNT_END, UI_DIM, false, "amount")?;
        col = ui_right(&mut stdout, spec, col, AGE_END, UI_DIM, false, "age")?;
        col = ui_right(&mut stdout, spec, col, HEIGHT_END, UI_DIM, false, "height")?;
        col = ui_right(&mut stdout, spec, col, CONF_END, UI_DIM, false, "conf")?;
        ui_pad(&mut stdout, spec, col, WALLET_AT)?;
        ui_seg(&mut stdout, spec, UI_DIM, false, "wallet")?;
        writeln!(stdout)?;

        for e in entries.iter().take(shown) {
            let (token, hue, sign) = if e.coinbase {
                ("▾ mine", UI_LAVENDER, "+")
            } else if e.is_self {
                ("↔ self", UI_BLUE, " ")
            } else if e.is_out {
                ("▴ out ", UI_PINK, "-")
            } else {
                ("▾ in  ", UI_GREEN, "+")
            };
            ui_seg(&mut stdout, spec, UI_LABEL, false, " ")?;
            ui_seg(&mut stdout, spec, hue, false, token)?;
            ui_seg(&mut stdout, spec, UI_LABEL, false, "  ")?;
            let party = ui_address(&e.counterparty);
            ui_text(&mut stdout, spec, false, &party)?;
            let mut col = PARTY + party.chars().count();
            let amount = format!("{}{:.8} ♦", sign, Transaction::from_units(e.amount_units));
            col = ui_right(&mut stdout, spec, col, AMOUNT_END, hue, true, &amount)?;
            let age = ui_age(now.saturating_sub(e.timestamp));
            col = ui_right(&mut stdout, spec, col, AGE_END, UI_DIM, false, &age)?;
            match e.height {
                Some(h) => {
                    let height = ui_thousands(h as u64);
                    col = ui_right(&mut stdout, spec, col, HEIGHT_END, UI_BLUE, false, &height)?;
                    let conf = tip.saturating_sub(h as u64).saturating_add(1);
                    // A coinbase inside the maturity window shows its progress
                    // toward spendable instead of a bare depth.
                    let conf_text = if e.coinbase && conf < MINING_REWARD_MATURITY as u64 {
                        format!("{}/{}", conf, MINING_REWARD_MATURITY)
                    } else {
                        ui_thousands(conf)
                    };
                    let conf_hue = if e.coinbase && conf < MINING_REWARD_MATURITY as u64 {
                        UI_ORANGE
                    } else {
                        UI_DIM
                    };
                    col = ui_right(
                        &mut stdout,
                        spec,
                        col,
                        CONF_END,
                        conf_hue,
                        false,
                        &conf_text,
                    )?;
                }
                None => {
                    col = ui_right(&mut stdout, spec, col, HEIGHT_END, UI_DIM, false, "—")?;
                    col = ui_right(
                        &mut stdout,
                        spec,
                        col,
                        CONF_END,
                        UI_ORANGE,
                        false,
                        "pending",
                    )?;
                }
            }
            ui_pad(&mut stdout, spec, col, WALLET_AT)?;
            let name: String = if e.wallet.chars().count() > 8 {
                format!("{}…", e.wallet.chars().take(7).collect::<String>())
            } else {
                e.wallet.clone()
            };
            ui_seg(&mut stdout, spec, UI_LAVENDER, false, &name)?;
            writeln!(stdout)?;
        }

        writeln!(stdout)?;
        stdout.reset()?;
        Ok(())
    }

    /// `network_tip` is the node's beacon high-water height — a local read, never a
    /// network call. 0 means no beacon has been seen yet, in which case the header
    /// makes no claim rather than guessing.
    pub async fn show_balances(&self, wallets: &HashMap<String, Wallet>, network_tip: u32) {
        // Auto, not Always: `balance | grep` was receiving raw ANSI escapes.
        let mut stdout = StandardStream::stdout(ColorChoice::Auto);
        let spec = &mut ColorSpec::new();

        // Time-boxed: after a re-bootstrap/deep sync the chain lock can be held by
        // block application for a long stretch, and an unbounded read here made
        // `balance` sit silently forever ("client hangs, needs restart" reports).
        let Ok(blockchain_guard) =
            tokio::time::timeout(std::time::Duration::from_secs(3), self.blockchain.read()).await
        else {
            let _ = ui_seg(
                &mut stdout,
                spec,
                UI_ORANGE,
                false,
                "\nChain busy (syncing/reorg in progress) — try `balance` again shortly.\n",
            );
            let _ = stdout.reset();
            return;
        };

        // Materialise EVERYTHING, then DROP the guard BEFORE the first styled
        // write. The old code held this read across the whole render while
        // paying ~100 uncached block decodes per wallet inside it; a blocked
        // console (Windows QuickEdit / Ctrl-S) would park the guard and the
        // write-preferring chain lock would halt block ingest node-wide — the
        // 2026-07-16 publisher-park class that `account` already avoids.
        struct Row {
            name: String,
            address: String,
            spendable: f64,
            maturing: f64,
            maturing_count: usize,
            next_unlock: u64,
            pending: f64,
            incoming: f64,
            confirmed: f64,
            error: Option<String>,
        }
        let mut rows: Vec<Row> = Vec::with_capacity(wallets.len());
        let mut tip = 0u64;
        for (name, wallet) in wallets {
            match blockchain_guard
                .get_wallet_balance_breakdown(&wallet.address)
                .await
            {
                Ok(breakdown) => {
                    tip = tip.max(breakdown.as_of_height);
                    let maturing: f64 = breakdown.maturing.iter().map(|(_, a)| a).sum();
                    let next_unlock = breakdown
                        .maturing
                        .iter()
                        .map(|(h, _)| blocks_until_mature(*h, breakdown.as_of_height))
                        .min()
                        .unwrap_or(0);
                    rows.push(Row {
                        name: name.clone(),
                        address: wallet.address.clone(),
                        spendable: breakdown.spendable,
                        maturing,
                        maturing_count: breakdown.maturing.len(),
                        next_unlock,
                        pending: breakdown.pending_debit,
                        incoming: breakdown.pending_credit,
                        confirmed: breakdown.confirmed,
                        error: None,
                    });
                }
                Err(e) => rows.push(Row {
                    name: name.clone(),
                    address: wallet.address.clone(),
                    spendable: 0.0,
                    maturing: 0.0,
                    maturing_count: 0,
                    next_unlock: 0,
                    pending: 0.0,
                    incoming: 0.0,
                    confirmed: 0.0,
                    error: Some(e.to_string()),
                }),
            }
        }
        drop(blockchain_guard);

        // Deterministic order. The old screen iterated the HashMap directly, so
        // the wallet order changed between two runs of the same command.
        rows.sort_by(|a, b| {
            b.spendable
                .partial_cmp(&a.spendable)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });

        let total_spendable: f64 = rows.iter().map(|r| r.spendable).sum();
        let total_maturing: f64 = rows.iter().map(|r| r.maturing).sum();
        let total_pending: f64 = rows.iter().map(|r| r.pending).sum();
        let total_incoming: f64 = rows.iter().map(|r| r.incoming).sum();
        let total_confirmed: f64 = rows.iter().map(|r| r.confirmed).sum();
        let funded = rows.iter().filter(|r| r.spendable > 0.0).count();

        // Amount column: every figure right-aligned to one edge so the decimal
        // points share a column across wallets AND the totals block.
        // ── E4 "contrast" geometry ──────────────────────────────────────────
        // Wallet name and its FULL 40-hex address own the wallet line (19 + 40 =
        // 59 cells); State / Amount / Share are the columns beneath. They never
        // needed to share a row — that requirement is the only thing that would
        // force an address to be truncated, and an address you cannot copy or
        // verify is worth less than the column it saves.
        const NAME_COL: usize = 1;
        const ADDR_COL: usize = 19;
        const STATE_COL: usize = 21;
        const AMOUNT_END: usize = 58;
        const SHARE_END: usize = 71;
        const SUBRULE_END: usize = 60;
        const GAUGE: usize = 8;

        // A macro, not a closure: a closure capturing `stdout` holds the only
        // mutable borrow for its whole lifetime, which locks out every other
        // write in this function.
        //
        // Colour names the CATEGORY, never the money: every settled figure is
        // UI_VALUE white and the brightest thing on the row, while hue sits on
        // the state label. Outbound and incoming keep their hue on the figure
        // too, because those are the two states where the number itself is the
        // exception worth seeing.
        macro_rules! out {
            ($label:expr, $lhue:expr, $amount:expr, $hue:expr, $bold:expr, $share:expr, $note:expr) => {{
                let label: &str = $label;
                let _ = ui_pad(&mut stdout, spec, 0, STATE_COL);
                let _ = ui_seg(&mut stdout, spec, $lhue, false, label);
                // ui_money bakes in the unit mark; the figure and the ♦ need
                // different hues here, so the number is formatted alone.
                let text = format!("{:.8}", $amount);
                let mut col = ui_right(
                    &mut stdout,
                    spec,
                    STATE_COL + label.chars().count(),
                    AMOUNT_END,
                    $hue,
                    $bold,
                    &text,
                )
                .unwrap_or(AMOUNT_END);
                let _ = ui_seg(&mut stdout, spec, $hue, false, " ♦");
                col += 2;
                let share: Option<String> = $share;
                if let Some(s) = share {
                    col = ui_right(&mut stdout, spec, col, SHARE_END, UI_FAINT, false, &s)
                        .unwrap_or(col);
                }
                let note: &str = $note;
                if !note.is_empty() {
                    let _ = ui_seg(&mut stdout, spec, UI_FAINT, false, "  ");
                    let _ = ui_seg(&mut stdout, spec, UI_FAINT, false, note);
                }
                let _ = col;
                let _ = writeln!(stdout);
            }};
        }

        // Subtotal rule, sized and placed to sit under the amount column.
        macro_rules! subrule {
            () => {{
                let _ = ui_pad(&mut stdout, spec, 0, SUBRULE_END - 15);
                let _ = ui_seg(&mut stdout, spec, UI_HAIRLINE, false, "───────────────");
                let _ = writeln!(stdout);
            }};
        }

        let _ = writeln!(stdout);
        let _ = ui_seg(&mut stdout, spec, UI_LABEL, false, " ");
        let _ = ui_seg(&mut stdout, spec, UI_VALUE, true, "Wallet Ledger");
        let head = format!(
            "{} wallet{} · {} funded · ",
            rows.len(),
            if rows.len() == 1 { "" } else { "s" },
            funded
        );
        // A balance is only as current as the chain it was read from. A bare
        // height is a number the reader cannot judge, so say whether it is up to
        // date instead. Mirrors `info`'s rule: within one block counts as synced.
        let behind = network_tip.saturating_sub(tip as u32);
        let (status_text, status_hue) = if network_tip == 0 {
            (format!("tip {}", ui_thousands(tip)), UI_BLUE)
        } else if behind <= 1 {
            (format!("synced · {}", ui_thousands(tip)), UI_GREEN)
        } else {
            (
                format!(
                    "{} behind · {}",
                    ui_thousands(behind as u64),
                    ui_thousands(tip)
                ),
                UI_ORANGE,
            )
        };
        let _ = ui_pad(
            &mut stdout,
            spec,
            14,
            78usize
                .saturating_sub(head.chars().count() + status_text.chars().count())
                .max(15),
        );
        let _ = ui_seg(&mut stdout, spec, UI_DIM, false, &head);
        let _ = ui_seg(&mut stdout, spec, status_hue, false, &status_text);
        let _ = writeln!(stdout);
        let _ = ui_seg(&mut stdout, spec, UI_HAIRLINE, false, UI_RULE);
        let _ = writeln!(stdout);

        // Column headers. Bold + faint rather than shouted capitals: the reader
        // needs to know which column they are in, not to be addressed by it.
        let _ = ui_pad(&mut stdout, spec, 0, NAME_COL);
        let _ = ui_seg(&mut stdout, spec, UI_FAINT, true, "Wallet");
        let _ = ui_pad(&mut stdout, spec, NAME_COL + 6, ADDR_COL);
        let _ = ui_seg(&mut stdout, spec, UI_FAINT, true, "Address");
        let col = ui_right(
            &mut stdout,
            spec,
            ADDR_COL + 7,
            AMOUNT_END,
            UI_FAINT,
            true,
            "Amount",
        )
        .unwrap_or(AMOUNT_END);
        let _ = ui_right(&mut stdout, spec, col, SHARE_END, UI_FAINT, true, "Share");
        let _ = writeln!(stdout);
        let _ = ui_seg(&mut stdout, spec, UI_HAIRLINE, false, UI_RULE);
        let _ = writeln!(stdout);

        for row in &rows {
            let _ = ui_pad(&mut stdout, spec, 0, NAME_COL);
            let _ = ui_seg(&mut stdout, spec, UI_DIM, false, &row.name);
            let name_end = NAME_COL + row.name.chars().count();
            let _ = ui_pad(&mut stdout, spec, name_end, ADDR_COL.max(name_end + 2));
            let _ = ui_seg(&mut stdout, spec, UI_VALUE, false, &row.address);
            let _ = writeln!(stdout);

            // A wallet whose balance could not be read keeps the row shape
            // instead of falling out of the layout, and is excluded from the
            // totals — which then say how many wallets they cover.
            if let Some(err) = &row.error {
                let _ = ui_pad(&mut stdout, spec, 0, STATE_COL);
                let _ = ui_seg(
                    &mut stdout,
                    spec,
                    UI_ORANGE,
                    false,
                    &format!("unavailable — {}", err),
                );
                let _ = writeln!(stdout);
                continue;
            }

            let share = if total_spendable > 0.0 {
                row.spendable / total_spendable
            } else {
                0.0
            };
            out!(
                "spendable",
                UI_DIM,
                row.spendable,
                if row.spendable > 0.0 {
                    UI_CYAN
                } else {
                    UI_FAINT
                },
                row.spendable > 0.0,
                Some(if row.spendable > 0.0 {
                    format!("{:>5.1}%", share * 100.0)
                } else {
                    "    —".to_string()
                }),
                ""
            );
            let _ = GAUGE;

            if row.maturing > 0.0 {
                out!(
                    "locked",
                    UI_DIM,
                    row.maturing,
                    UI_ORANGE,
                    false,
                    None,
                    &format!(
                        "{} reward{} · next {}",
                        row.maturing_count,
                        if row.maturing_count == 1 { "" } else { "s" },
                        format_maturity_eta(row.next_unlock)
                    )
                );
            }
            if row.pending > 0.0 {
                out!(
                    "outbound",
                    UI_DIM,
                    row.pending,
                    UI_PINK,
                    false,
                    None,
                    "in mempool"
                );
            }
            // The identity only earns a line when there is something to add up.
            if row.maturing > 0.0 || row.pending > 0.0 {
                subrule!();
                out!(
                    "= confirmed",
                    UI_DIM,
                    row.confirmed,
                    UI_GREEN,
                    true,
                    None,
                    ""
                );
            }
            // Money on its way IN, placed BELOW the confirmed identity and marked
            // three separate ways — outdented past every other component, behind a
            // dashed tick, and tagged `excluded`. An unmined credit is not yours,
            // so no reading of this row should suggest it is in the total.
            if row.incoming > 0.0 {
                let _ = ui_pad(&mut stdout, spec, 0, ADDR_COL);
                let _ = ui_seg(&mut stdout, spec, UI_HAIRLINE, false, "╌ ");
                let _ = ui_seg(&mut stdout, spec, UI_DIM, false, "incoming");
                let text = format!("{:.8}", row.incoming);
                let col = ui_right(
                    &mut stdout,
                    spec,
                    ADDR_COL + 10,
                    AMOUNT_END,
                    UI_ORANGE,
                    false,
                    &text,
                )
                .unwrap_or(AMOUNT_END);
                let _ = ui_seg(&mut stdout, spec, UI_ORANGE, false, " ♦");
                let _ = col;
                let _ = ui_seg(&mut stdout, spec, UI_FAINT, false, "  excluded");
                let _ = writeln!(stdout);
            }
        }

        let _ = ui_seg(&mut stdout, spec, UI_HAIRLINE, false, UI_RULE);
        let _ = writeln!(stdout);
        let _ = ui_pad(&mut stdout, spec, 0, NAME_COL);
        let _ = ui_seg(&mut stdout, spec, UI_DIM, false, "Total");
        let covered = rows.iter().filter(|r| r.error.is_none()).count();
        // "Total" occupies the wallet-name column, so what follows it belongs in the
        // ADDRESS column — the same slot a wallet's address takes on its own row.
        // Bracketed because it qualifies the Total rather than being a value.
        //
        // The bracket HANGS one column into the gutter so the first letter, not the
        // punctuation, lands on ADDR_COL. Starting the "(" itself at ADDR_COL is
        // arithmetically aligned but reads as indented, because every address below
        // begins with a glyph that fills its cell and "(" does not.
        let _ = ui_pad(&mut stdout, spec, NAME_COL + 5, ADDR_COL.saturating_sub(1));
        let _ = ui_seg(
            &mut stdout,
            spec,
            UI_FAINT,
            false,
            &if covered == rows.len() {
                format!(
                    "(sum of {} wallet{})",
                    rows.len(),
                    if rows.len() == 1 { "" } else { "s" }
                )
            } else {
                format!("(sum of {} of {} wallets)", covered, rows.len())
            },
        );
        let _ = writeln!(stdout);

        // One decimal place silently lied at both ends: a spendable total that is
        // 99.983% of confirmed printed "100.0%" — indistinguishable from the
        // confirmed line's true 100% — and an outbound of 0.017% printed "0.0%",
        // which reads as nothing at all. Saturate instead of rounding through:
        // a value that is not the whole never claims to be, and a value that is
        // not zero never claims to be.
        let pct = |v: f64| {
            if total_confirmed <= 0.0 {
                return "    —".to_string();
            }
            let p = v / total_confirmed * 100.0;
            if p > 0.0 && p < 0.05 {
                " <0.1%".to_string()
            } else if (99.95..100.0).contains(&p) {
                ">99.9%".to_string()
            } else {
                format!("{:>5.1}%", p)
            }
        };
        out!(
            "spendable",
            UI_DIM,
            total_spendable,
            UI_CYAN,
            true,
            Some(pct(total_spendable)),
            ""
        );
        if total_maturing > 0.0 {
            out!(
                "locked",
                UI_DIM,
                total_maturing,
                UI_ORANGE,
                false,
                Some(pct(total_maturing)),
                ""
            );
        }
        if total_pending > 0.0 {
            out!(
                "outbound",
                UI_DIM,
                total_pending,
                UI_PINK,
                false,
                Some(pct(total_pending)),
                ""
            );
        }
        // Only draw the identity when there is something to add up. With nothing
        // locked, outbound or arriving, confirmed IS spendable, and printing it
        // again under a rule reads as a mistake rather than a subtotal.
        if total_maturing > 0.0 || total_pending > 0.0 {
            subrule!();
            out!(
                "= confirmed",
                UI_DIM,
                total_confirmed,
                UI_GREEN,
                true,
                Some(pct(total_confirmed)),
                ""
            );
        }
        // Below the identity on purpose: not yet confirmed, so it is reported but
        // never summed into the total.
        if total_incoming > 0.0 {
            let _ = ui_pad(&mut stdout, spec, 0, ADDR_COL);
            let _ = ui_seg(&mut stdout, spec, UI_HAIRLINE, false, "╌ ");
            let _ = ui_seg(&mut stdout, spec, UI_DIM, false, "incoming");
            let text = format!("{:.8}", total_incoming);
            let _ = ui_right(
                &mut stdout,
                spec,
                ADDR_COL + 10,
                AMOUNT_END,
                UI_ORANGE,
                false,
                &text,
            );
            let _ = ui_seg(&mut stdout, spec, UI_ORANGE, false, " ♦");
            let _ = ui_seg(&mut stdout, spec, UI_FAINT, false, "  excluded");
            let _ = writeln!(stdout);
        }

        let _ = writeln!(stdout);
        let _ = stdout.reset();
        let _ = stdout.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a9::blockchain::AddressTxEntry;
    use crate::a9::codec;
    use std::io::{Error, ErrorKind};

    /// ON-DISK WALLET KEY FORMAT — FROZEN.
    ///
    /// These bytes are what `persist_wallet_keys` writes and `load_wallets` reads.
    /// A user's ability to spend depends on this file staying readable, so the
    /// format is pinned literally rather than round-tripped through the same code
    /// that produces it: a round-trip test passes even when both sides change
    /// together, which is exactly the regression that would strand funds.
    ///
    /// Covers both branches, because they are structurally different on disk: an
    /// encrypted wallet's `private_key` is ciphertext, an unencrypted wallet's is
    /// the RAW combined key material. If a change to secret-holding types alters
    /// either byte sequence, this fails before anyone's key file does.
    const FROZEN_ENCRYPTED_WALLET_JSON: &str = r#"[{"wallet_name":"encrypted-fixture","wallet_address":"1111111111111111111111111111111111111111","private_key":[1,2,3,4,5,6,7,8],"last_sync_timestamp":1700000000,"is_encrypted":true,"key_verification_hash":[9,9,9,9]}]"#;
    const FROZEN_PLAINTEXT_WALLET_JSON: &str = r#"[{"wallet_name":"plaintext-fixture","wallet_address":"2222222222222222222222222222222222222222","private_key":[254,253,252],"last_sync_timestamp":1700000001,"is_encrypted":false,"key_verification_hash":[7,7]}]"#;
    const FROZEN_NO_KEY_WALLET_JSON: &str = r#"[{"wallet_name":"keyless-fixture","wallet_address":"3333333333333333333333333333333333333333","private_key":null,"last_sync_timestamp":1700000002,"is_encrypted":false,"key_verification_hash":[]}]"#;

    fn wallet_key_record(name: &str, is_encrypted: bool) -> WalletKeyData {
        WalletKeyData::new(
            name.to_string(),
            "1".repeat(40),
            Some(Zeroizing::new(vec![1, 2, 3, 4])),
            is_encrypted,
        )
    }

    #[test]
    fn wallet_name_preflight_rejects_ambiguous_durable_records() {
        let records = vec![
            wallet_key_record("vault", true),
            wallet_key_record("ordinary", false),
            wallet_key_record("vault", false),
        ];

        let error = validate_unique_wallet_names(&records)
            .expect_err("two durable records must never share one CLI wallet name")
            .to_string();
        assert!(error.contains("duplicate wallet name"));
        assert!(error.contains("vault"));
        assert!(error.contains("Refusing to load or modify"));
    }

    #[test]
    fn explicit_new_wallet_name_checks_records_skipped_from_memory() {
        // This is the original failure shape: `cold_vault` is encrypted on disk but absent from the
        // loaded-name set because the process started without its passphrase.
        let records = vec![
            wallet_key_record("default_wallet", false),
            wallet_key_record("cold_vault", true),
        ];
        let loaded_names: HashSet<&str> = HashSet::from(["default_wallet"]);

        let error = select_new_wallet_name(Some("cold_vault".to_string()), &loaded_names, &records)
            .expect_err("an encrypted disk-only wallet still owns its name")
            .to_string();
        assert_eq!(error, "Duplicate wallet name");

        assert_eq!(
            select_new_wallet_name(Some("new_vault".to_string()), &loaded_names, &records)
                .expect("an unused explicit name remains valid"),
            "new_vault"
        );
    }

    #[test]
    fn automatic_wallet_name_advances_past_disk_only_collision() {
        // One loaded wallet preserves the historical starting candidate `wallet_2`; a skipped
        // durable `wallet_2` must make selection advance, not fail or append a duplicate.
        let records = vec![
            wallet_key_record("default_wallet", false),
            wallet_key_record("wallet_2", true),
        ];
        let loaded_names: HashSet<&str> = HashSet::from(["default_wallet"]);

        assert_eq!(
            select_new_wallet_name(None, &loaded_names, &records)
                .expect("automatic naming should find the next durable-free name"),
            "wallet_3"
        );
    }

    /// Serializing a `WalletKeyData` must reproduce the frozen bytes EXACTLY --
    /// field names, field order, and the JSON representation of the key bytes.
    /// `Zeroizing<Vec<u8>>` must serialize as a bare array, not as a wrapper
    /// object, or every existing key file becomes unreadable.
    #[test]
    fn wallet_key_file_serialization_is_byte_identical_to_the_frozen_format() {
        for frozen in [
            FROZEN_ENCRYPTED_WALLET_JSON,
            FROZEN_PLAINTEXT_WALLET_JSON,
            FROZEN_NO_KEY_WALLET_JSON,
        ] {
            let parsed: Vec<WalletKeyData> =
                serde_json::from_str(frozen).expect("frozen wallet fixture must parse");
            let reserialized =
                serde_json::to_string(&parsed).expect("wallet key data must serialize");
            assert_eq!(
                reserialized, frozen,
                "on-disk wallet key format changed; existing key files would break"
            );
        }
    }

    /// The read side must recover the key material unchanged. Byte equality is
    /// asserted against literals, not against a value derived from the same
    /// deserialization, so a symmetric corruption cannot pass.
    #[test]
    fn frozen_wallet_fixtures_read_back_with_intact_key_material() {
        let encrypted: Vec<WalletKeyData> =
            serde_json::from_str(FROZEN_ENCRYPTED_WALLET_JSON).expect("encrypted fixture");
        assert_eq!(encrypted.len(), 1);
        assert_eq!(encrypted[0].wallet_name, "encrypted-fixture");
        assert!(encrypted[0].is_encrypted);
        assert_eq!(
            encrypted[0].private_key.as_ref().map(|k| k.as_slice()),
            Some([1u8, 2, 3, 4, 5, 6, 7, 8].as_slice()),
            "ciphertext must survive the round trip byte for byte"
        );
        assert_eq!(encrypted[0].last_sync_timestamp, 1_700_000_000);
        assert_eq!(encrypted[0].key_verification_hash, vec![9u8, 9, 9, 9]);

        let plaintext: Vec<WalletKeyData> =
            serde_json::from_str(FROZEN_PLAINTEXT_WALLET_JSON).expect("plaintext fixture");
        assert!(!plaintext[0].is_encrypted);
        assert_eq!(
            plaintext[0].private_key.as_ref().map(|k| k.as_slice()),
            Some([254u8, 253, 252].as_slice()),
            "raw key material must survive the round trip byte for byte"
        );

        let keyless: Vec<WalletKeyData> =
            serde_json::from_str(FROZEN_NO_KEY_WALLET_JSON).expect("keyless fixture");
        assert!(keyless[0].private_key.is_none());
        assert!(keyless[0].key_verification_hash.is_empty());
    }

    /// `key_verification_hash` gates whether a loaded key is trusted, so the way
    /// it is derived is part of the file contract: SHA-256 over the key bytes
    /// followed by the encryption flag. A change here would reject every stored
    /// wallet as tampered.
    #[test]
    fn key_verification_hash_derivation_is_stable() {
        let key = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let data = WalletKeyData::new(
            "hash-fixture".to_string(),
            "1".repeat(40),
            Some(Zeroizing::new(key.clone())),
            true,
        );
        let mut hasher = Sha256::new();
        hasher.update(&key);
        hasher.update([1u8]);
        assert_eq!(data.key_verification_hash, hasher.finalize().to_vec());

        let empty = WalletKeyData::new("none".to_string(), "1".repeat(40), None, false);
        assert_eq!(
            empty.key_verification_hash,
            vec![0u8; 32],
            "the keyless sentinel hash is part of the format"
        );
    }

    /// Secret-bearing wallet key data must never render its key material. This is
    /// the type-level guarantee: a future `{:?}` in a log or a panic backtrace
    /// cannot print the bytes.
    #[test]
    fn wallet_key_data_debug_redacts_key_material() {
        let data = WalletKeyData::new(
            "redaction-fixture".to_string(),
            "4".repeat(40),
            Some(Zeroizing::new(vec![0xAB, 0xCD, 0xEF])),
            false,
        );
        let rendered = format!("{:?}", data);
        assert!(
            !rendered.contains("171") && !rendered.contains("205") && !rendered.contains("239"),
            "key bytes must not appear in Debug output: {rendered}"
        );
        assert!(
            !rendered.to_ascii_lowercase().contains("abcdef"),
            "key bytes must not appear in any encoding: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "redaction must be visible rather than silent: {rendered}"
        );
        assert!(
            rendered.contains("redaction-fixture"),
            "non-secret fields stay legible for diagnostics: {rendered}"
        );
    }

    fn entry(counterparty: &str, height: u32, sender: bool) -> AddressTxEntry {
        AddressTxEntry {
            height,
            position: 0,
            // 1 = sender, 2 = recipient, mirroring the flag bits the index writes.
            flags: if sender { 1 } else { 2 },
            amount_units: 100_000_000,
            fee_units: 50_000,
            timestamp: 1_700_000_000 + height as u64,
            counterparty: counterparty.to_string(),
        }
    }

    // The account screen prints three counterparties in FULL, so which three it picks is
    // worth pinning. `recent` arrives newest-first.
    #[test]
    fn counterparties_pick_the_latest_in_each_direction() {
        let recent = vec![
            entry("bbbb", 300, true),  // newest: outbound
            entry("aaaa", 299, false), // inbound
            entry("cccc", 298, true),  // older outbound — must lose to bbbb
            entry("aaaa", 297, false),
        ];
        let (last_in, last_out, frequent) = notable_counterparties(&recent);
        assert_eq!(last_in.unwrap().counterparty, "aaaa");
        assert_eq!(
            last_out.unwrap().counterparty,
            "bbbb",
            "the LATEST outbound, not the first seen"
        );
        assert_eq!(frequent.unwrap(), ("aaaa", 2));
    }

    // A miner's history is mostly coinbase. MINING_REWARDS is not a counterparty anyone
    // deals with, and left in it wins `frequent` outright and hides the real answer.
    #[test]
    fn counterparties_ignore_the_coinbase() {
        let mut recent: Vec<AddressTxEntry> = (0..20)
            .map(|i| entry("MINING_REWARDS", 400 - i, false))
            .collect();
        recent.push(entry("dddd", 300, false));
        recent.push(entry("dddd", 299, true));

        let (last_in, last_out, frequent) = notable_counterparties(&recent);
        assert_eq!(
            last_in.unwrap().counterparty,
            "dddd",
            "coinbase is not an inbound counterparty"
        );
        assert_eq!(last_out.unwrap().counterparty, "dddd");
        assert_eq!(
            frequent.unwrap(),
            ("dddd", 2),
            "20 coinbase rows must not outvote the real counterparty"
        );
    }

    // One transaction is not a pattern; calling it `frequent` would make the row noise.
    #[test]
    fn a_single_appearance_is_not_frequent() {
        let recent = vec![entry("aaaa", 300, false), entry("bbbb", 299, true)];
        let (last_in, last_out, frequent) = notable_counterparties(&recent);
        assert!(last_in.is_some() && last_out.is_some());
        assert!(
            frequent.is_none(),
            "no repeat counterparty means no frequent row"
        );
    }

    // Ties must not follow hash order, or the row changes between runs on identical data.
    #[test]
    fn a_frequency_tie_breaks_deterministically() {
        let recent = vec![
            entry("bbbb", 300, false),
            entry("aaaa", 299, false),
            entry("bbbb", 298, false),
            entry("aaaa", 297, false),
        ];
        let first = notable_counterparties(&recent).2.unwrap();
        for _ in 0..40 {
            assert_eq!(notable_counterparties(&recent).2.unwrap(), first);
        }
    }

    // An address with no activity yet renders no section at all.
    #[test]
    fn an_empty_history_yields_nothing_to_show() {
        let (a, b, c) = notable_counterparties(&[]);
        assert!(a.is_none() && b.is_none() && c.is_none());
    }

    // `ui_money(x, 4)` is 15 columns only while the whole part fits 4 digits. The
    // account screen used to pad with a hardcoded 15, so every extra digit shoved
    // its right-hand column one cell — a real drift at 10,000 coins, which is
    // ordinary mining territory. Pin the widths the layout now measures.
    #[test]
    fn ui_money_width_grows_past_four_whole_digits() {
        // chars(), not len(): the ♦ is three bytes and one display column.
        assert_eq!(ui_money(0.0, 4).chars().count(), 15);
        assert_eq!(ui_money(9_999.999_999_99, 4).chars().count(), 15);
        assert_eq!(
            ui_money(10_000.0, 4).chars().count(),
            16,
            "10k adds a column"
        );
        assert_eq!(ui_money(123_456.789, 4).chars().count(), 17);
        assert_eq!(ui_money(33_554_432.0, 4).chars().count(), 19);
        // byte length would over-count the ♦ by two and mis-place every column.
        assert_eq!(ui_money(0.0, 4).len(), 17);
        assert_ne!(ui_money(0.0, 4).len(), ui_money(0.0, 4).chars().count());
    }

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
    fn create_without_fee_defers_to_the_live_estimator() {
        // No --fee no longer resolves to the historical amount/1776 ratio at
        // parse time: the parser stays a pure string function and returns None,
        // and the handler prices the fee off the live mempool at send time
        // (Blockchain::fee_estimate — anchor on a quiet network, marginal+1
        // under congestion, clamped to the safety ceiling by construction).
        let auto = parse_create_transaction_command("create sender recipient 0.5").unwrap();
        assert_eq!(auto.amount_units, 50_000_000);
        assert_eq!(auto.fee_units, None, "auto fee is resolved by the handler");

        let large = parse_create_transaction_command("create sender recipient 1000000").unwrap();
        assert_eq!(
            large.fee_units, None,
            "no amount-proportional default remains"
        );
    }

    #[test]
    fn create_command_keeps_existing_syntax_and_accepts_exact_fee_override() {
        let existing = parse_create_transaction_command("create sender recipient 0.5").unwrap();
        assert_eq!(existing.amount_units, 50_000_000);
        assert_eq!(existing.fee_units, None, "no --fee = auto (estimator)");

        let explicit =
            parse_create_transaction_command("create sender recipient 2 --fee 0.001").unwrap();
        assert_eq!(explicit.amount_units, 200_000_000);
        assert_eq!(explicit.fee_units, Some(100_000));

        let equals =
            parse_create_transaction_command("create sender recipient 2 --fee=0.0005").unwrap();
        assert_eq!(equals.fee_units, Some(50_000));

        for alias in ["send", "transfer"] {
            let command = format!("{alias} sender recipient 2 --fee 0.001");
            let parsed = parse_create_transaction_command(&command).unwrap();
            assert_eq!(parsed.amount_units, 200_000_000);
            assert_eq!(parsed.fee_units, Some(100_000));
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
        assert_eq!(floor.fee_units, Some(MIN_RELAY_FEE_UNITS));

        let safety_limit =
            parse_create_transaction_command("create sender recipient 1 --fee 0.01").unwrap();
        assert_eq!(
            safety_limit.fee_units,
            Some(EXPLICIT_FEE_SAFETY_LIMIT_UNITS)
        );

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

        assert!(!load_error_is_first_run(&Error::from(
            ErrorKind::PermissionDenied
        )));
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
        let ok_path =
            std::env::temp_dir().join(format!("a9-persist-ok-{}.key", std::process::id()));
        let ok_path_str = ok_path.to_str().expect("temp path is valid utf-8");
        assert!(
            persist_wallet_keys(ok_path_str, &[]).await.is_ok(),
            "a writable path must persist the key set successfully"
        );
        assert!(ok_path.exists());
        let _ = std::fs::remove_file(&ok_path);
    }

    #[tokio::test]
    async fn persistence_rejects_duplicate_names_without_touching_the_existing_file() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "a9-persist-duplicate-{}-{}.key",
            std::process::id(),
            unique
        ));
        std::fs::write(&path, b"existing-wallet-file").expect("seed protected target");

        let duplicate_records = vec![
            wallet_key_record("same-name", false),
            wallet_key_record("same-name", true),
        ];
        let error = persist_wallet_keys(
            path.to_str().expect("temp path is valid utf-8"),
            &duplicate_records,
        )
        .await
        .expect_err("the durable write boundary must reject aliases")
        .to_string();

        assert!(error.contains("duplicate wallet name"));
        assert_eq!(
            std::fs::read(&path).expect("existing target remains readable"),
            b"existing-wallet-file",
            "validation must happen before the temporary file or target is written"
        );
        let _ = std::fs::remove_file(path);
    }
}
