use hex;
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

use crate::a9::blockchain::FEE_PERCENTAGE;
use crate::a9::{
    blockchain::{Blockchain, BlockchainError, Transaction},
    progpow::{BlockHeader as ProgPowHeader, Miner, ProgPowTransaction},
    wallet::Wallet,
};

const KEY_FILE_PATH: &str = "private.key";

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

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
            hasher.update(&[is_encrypted as u8]);
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

    pub fn verify_encryption_status(&self) -> std::result::Result<bool, Box<dyn Error>> {
        if let Some(key) = &self.private_key {
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(&[self.is_encrypted as u8]);
            let hash = hasher.finalize();
            Ok(hash.as_slice() == self.key_verification_hash.as_slice())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Missing private key",
            )))
        }
    }
}

pub struct Mgmt {
    pub wallets: HashMap<String, Wallet>,
    pub blockchain: Arc<RwLock<Blockchain>>, // Just store the reference
}

impl Mgmt {
    pub fn new(
        _db: sled::Db,
        blockchain: Arc<RwLock<Blockchain>>, // Take blockchain directly
    ) -> Self {
        Mgmt {
            wallets: HashMap::new(),
            blockchain,
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

        let serialized_key_data = serde_json::to_string(&key_data_vec)?;

        // Save wallet to key file with timeout
        match tokio::time::timeout(Duration::from_secs(5), async {
            fs::write(KEY_FILE_PATH, serialized_key_data).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await
        {
            Ok(Ok(())) => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(59, 242, 173))))?;
                writeln!(stdout, "\n✓ Wallet created successfully!")?;
                stdout.reset()?;
            }
            _ => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))?;
                writeln!(stdout, "\n⚠ Wallet created with warnings")?;
                stdout.reset()?;
            }
        };

        // Display wallet information
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;
        writeln!(stdout, "\nWallet Address: {}", wallet.address)?;
        if is_encrypted {
            writeln!(stdout, "Encryption: Enabled")?;
        } else {
            writeln!(stdout, "Encryption: Disabled")?;
        }
        stdout.reset()?;

        // Add to active wallets map
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
            let pass = Password::new("Enter passphrase (or press Enter for no encryption):")
                .with_display_mode(PasswordDisplayMode::Masked)
                .prompt()
                .unwrap_or_default();

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

        let mut key_data_vec = Vec::new();
        key_data_vec.push(key_data);

        let serialized_key_data = serde_json::to_string(&key_data_vec)?;

        // Save wallet to key file with timeout
        match tokio::time::timeout(Duration::from_secs(5), async {
            fs::write(KEY_FILE_PATH, serialized_key_data).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await
        {
            Ok(Ok(())) => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(59, 242, 173))))?;
                writeln!(stdout, "\n✓ Wallet created successfully!")?;
                stdout.reset()?;
            }
            _ => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))?;
                writeln!(stdout, "\n⚠ Wallet created with warnings")?;
                stdout.reset()?;
            }
        };

        // Display wallet information
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;
        writeln!(stdout, "\nWallet Address: {}", wallet.address)?;
        stdout.reset()?;

        // Add wallet to local map
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
            Err(_) => self.create_default_wallet(passphrase).await,
        }
    }

    pub async fn save_wallets(
        &self,
        db_arc: &Arc<RwLock<Db>>,
        wallets: &HashMap<String, Wallet>,
        _passphrase: Option<&[u8]>,
    ) -> std::result::Result<(), Box<dyn Error>> {
        let wallet_key_data: Vec<WalletKeyData> = wallets
            .iter()
            .map(|(name, wallet)| {
                WalletKeyData::new(
                    name.clone(),
                    wallet.address.clone(),
                    wallet.encrypted_private_key.clone(),
                    wallet.is_encrypted,
                )
            })
            .collect();

        let serialized_key_data = serde_json::to_string(&wallet_key_data)?;
        tokio::fs::write(KEY_FILE_PATH, serialized_key_data).await?;

        let db_guard = db_arc.write().await;
        let wallets_tree = db_guard
            .open_tree("wallets")
            .map_err(|e| format!("Failed to open wallets tree: {}", e))?;

        for (_, wallet) in wallets {
            let encrypted_private_key = wallet
                .encrypted_private_key
                .as_ref()
                .ok_or("Missing encrypted private key")?
                .to_vec();
            wallets_tree
                .insert(wallet.address.as_bytes(), encrypted_private_key)
                .map_err(|e| format!("Failed to save wallet: {}", e))?;
        }

        wallets_tree
            .flush()
            .map_err(|e| format!("Failed to flush database: {}", e))?;

        Ok(())
    }

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
            fs::write(KEY_FILE_PATH, updated_data).await?;

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
    ) -> Result<()> {
        if command.len() < 2 {
            return Err("Usage: mine <wallet_name_or_address>".into());
        }

        let wallet_input = command[1].to_string();
        let miner_wallet = if let Some(w) = wallets.get(&wallet_input) {
            w
        } else {
            wallets
                .values()
                .find(|w| w.address == wallet_input)
                .ok_or_else(|| format!("No wallet found with name or address: {}", wallet_input))?
        };

        let (transactions, last_hash, next_block_index, difficulty, mining_reward) = {
            let blockchain_guard = blockchain.read().await;

            // Initialize temporal verification
            blockchain_guard
                .temporal_verification
                .initialize_from_blockchain(&blockchain_guard)
                .await?;

            // Get mempool transactions (full signatures only)
            let mempool_transactions = blockchain_guard.get_mempool_transactions().await?;
            let regular_transactions: Vec<Transaction> = mempool_transactions
                .into_iter()
                .filter(|tx| {
                    if tx.sender == "MINING_REWARDS" {
                        return false;
                    }
                    if let Some(sig_hex) = &tx.signature {
                        if let Ok(bytes) = hex::decode(sig_hex) {
                            return bytes.len() > 64;
                        }
                    }
                    false
                })
                .collect();

            // Calculate mining reward
            let mining_reward = blockchain_guard.get_block_reward(&regular_transactions);

            // Pass as slice to calculate_merkle_root
            let _merkle_root = Blockchain::calculate_merkle_root(&regular_transactions)?;

            let tip = blockchain_guard
                .get_last_block()
                .ok_or_else(|| "No tip block found".to_string())?;
            let last_hash = tip.hash;
            let next_block_index = tip.index.saturating_add(1);
            let difficulty = blockchain_guard.get_current_difficulty().await;

            (
                regular_transactions,
                last_hash,
                next_block_index,
                difficulty,
                mining_reward,
            )
        };

        // Ensure header uses a slice of transactions
        let mut header = ProgPowHeader {
            number: next_block_index,
            parent_hash: last_hash,
            timestamp: Self::get_current_timestamp()?,
            merkle_root: Blockchain::calculate_merkle_root(&transactions[..])?,
            difficulty,
        };

        // Convert transactions
        let progpow_transactions: Vec<ProgPowTransaction> = transactions
            .iter()
            .map(|tx| ProgPowTransaction {
                fee: tx.fee(),
                sender: tx.sender.clone(),
                recipient: tx.recipient.clone(),
                amount: tx.amount(),
                timestamp: tx.timestamp,
                signature: tx.signature.clone(),
                pub_key: tx.pub_key.clone(),
                sig_hash: tx.sig_hash.clone(),
            })
            .collect();

        let mut stdout = StandardStream::stdout(ColorChoice::Auto);
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)).set_bold(true))?;
        writeln!(stdout, "\nStarting mining operation")?;
        stdout.reset()?;

        match miner
            .mine_block(
                &mut header,
                &progpow_transactions,
                1_000_000,
                9001,
                miner_wallet.address.clone(),
                mining_reward,
            )
            .await
        {
            Ok((_nonce, _hash)) => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Blue)).set_bold(true))?;
                writeln!(stdout, "\n Mining successful")?;
                stdout.reset()?;
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(167, 165, 198))))?;
                writeln!(stdout, "───────────────────")?;
                stdout.reset()?;

                let final_balance = {
                    let blockchain_guard = blockchain.read().await;
                    blockchain_guard
                        .get_wallet_balance(&miner_wallet.address)
                        .await?
                };

                writeln!(stdout, "Mining reward: {} ♦", mining_reward)?;
                writeln!(stdout, "New balance: {}", final_balance)?;
                writeln!(stdout)?;

                Ok(())
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

    pub async fn handle_create_transaction(
        &self,
        command: &str,
        wallets: &mut HashMap<String, Wallet>,
        blockchain: &Arc<RwLock<Blockchain>>,
        _db_arc: &Arc<RwLock<Db>>,
    ) -> Result<()> {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);

        // Parse command
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.len() != 4 {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
            write!(stdout, "error")?;
            stdout.reset()?;
            writeln!(stdout, ": invalid command format")?;
            writeln!(
                stdout,
                "Usage: create <sender_address> <recipient_address> <amount>"
            )?;
            return Err("Invalid command format".into());
        }

        let sender_address = parts[1].to_string();
        let recipient_address = parts[2].to_string();

        // Prevent self-transfers
        if sender_address == recipient_address {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
            write!(stdout, "error")?;
            stdout.reset()?;
            writeln!(stdout, ": cannot transfer to the same address")?;
            return Err("Self-transfer not allowed".into());
        }

        let amount: f64 = match parts[3].parse() {
            Ok(amount) => amount,
            Err(_) => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
                write!(stdout, "error")?;
                stdout.reset()?;
                writeln!(stdout, ": invalid amount format")?;
                return Err("Invalid amount".into());
            }
        };

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
        let fee = amount * FEE_PERCENTAGE;
        let total_cost = amount + fee;
        let sender_balance = blockchain_guard.get_wallet_balance(&sender_address).await?;

        if sender_balance < total_cost {
            writeln!(stdout)?;
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
            write!(stdout, "error")?;
            stdout.reset()?;
            writeln!(stdout, ": insufficient balance")?;
            writeln!(stdout, "required: {}", total_cost)?;
            writeln!(stdout, "available: {}", sender_balance)?;
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
        write!(stdout, " to blockchain...\n")?;
        stdout.flush()?;

        let mut transaction = Transaction::new(
            sender_address.clone(),
            recipient_address.clone(),
            amount,
            fee,
            timestamp,
            Some(signature),
        );
        transaction.pub_key = sender_wallet.get_public_key_hex().await;
        if transaction.pub_key.is_none() {
            writeln!(stdout)?;
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
            write!(stdout, "error")?;
            stdout.reset()?;
            writeln!(
                stdout,
                ": wallet key material is missing a Dilithium public key"
            )?;
            writeln!(
                stdout,
                "wallet data appears incomplete; restore a full key backup or recreate this wallet"
            )?;
            return Err("Wallet key data missing Dilithium public key".into());
        }

        // No wallet registry needed - transactions are self-contained with public keys

        match blockchain.read().await.add_transaction(transaction).await {
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

                Ok(())
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
                let blockchain_guard = blockchain.read().await;

                // Get balance atomically
                let balance = match blockchain_guard.get_wallet_balance(addr).await {
                    Ok(bal) => bal,
                    Err(e) => {
                        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
                        writeln!(stdout, "Error getting balance: {}", e)?;
                        stdout.reset()?;
                        return Ok(());
                    }
                };

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

                // Get recent history stats
                let mut tx_stats = (0, 0.0, 0.0, 0.0); // (count, sent, received, fees)
                for block in blockchain_guard.get_blocks().iter().rev().take(2000) {
                    for tx in &block.transactions {
                        if tx.sender == addr {
                            tx_stats.0 += 1;
                            tx_stats.1 += tx.amount();
                            tx_stats.3 += tx.fee();
                        }
                        if tx.recipient == addr {
                            tx_stats.0 += 1;
                            tx_stats.2 += tx.amount();
                        }
                    }
                }

                // Print account information with proper formatting
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(40, 204, 217))))?;
                writeln!(stdout, "\n Account Information")?;
                stdout.reset()?;
                println!("───────────────────");

                // Address
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)).set_bold(true))?;
                write!(stdout, "Address: ")?;
                stdout.reset()?;
                println!("{}", addr);

                // Wallet Status
                if wallets.contains_key(addr) {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
                    write!(stdout, "Status: ")?;
                    stdout.reset()?;
                    println!("Local Wallet");
                }

                // Balance
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)).set_bold(true))?;
                write!(stdout, "Balance: ")?;
                stdout.reset()?;

                stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;
                write!(stdout, "{:.8}", balance)?;
                stdout.reset()?;
                stdout
                    .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(237, 124, 51)))).ok();
                write!(stdout, " ♦\n")?;
                stdout.reset()?;

                // Pending Transactions Section
                if pending_stats.0 > 0 || pending_stats.1 > 0 {
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true))?;
                    writeln!(stdout, "\n Pending Transactions")?;
                    stdout.reset()?;
                    println!("───────────────────");
                    println!(
                        "Outgoing: {} (Total: {:.8})",
                        pending_stats.0, pending_stats.2
                    );
                    println!(
                        "Incoming: {} (Total: {:.8})",
                        pending_stats.1, pending_stats.3
                    );
                }

                // Transaction History Section
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Blue)).set_bold(true))?;
                writeln!(stdout, "\n Transaction History (Recent)")?;
                stdout.reset()?;
                println!("───────────────────");
                println!("Total Transactions: {}", tx_stats.0);
                println!("Volume Sent: {:.8}", tx_stats.1);
                println!("Volume Received: {:.8}", tx_stats.2);
                println!("Total Fees Paid: {:.8}", tx_stats.3);

                // Network Statistics Section
                let blocks = blockchain_guard.get_blocks();
                if !blocks.is_empty() {
                    let total_supply: f64 = blocks
                        .iter()
                        .flat_map(|block| &block.transactions)
                        .map(|tx| tx.amount())
                        .sum();

                    if total_supply > 0.0 {
                        let network_share = (balance / total_supply) * 100.0;
                        stdout
                            .set_color(ColorSpec::new().set_fg(Some(Color::Blue)).set_bold(true))?;
                        writeln!(stdout, "\n Network Statistics")?;
                        stdout.reset()?;
                        println!("───────────────────");
                        println!("Network Share: {:.4}% \n", network_share);
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn show_balances(&self, wallets: &HashMap<String, Wallet>) {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);

        // Set the color for the first line
        stdout
            .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(242, 237, 161))))
            .ok();
        println!("\n Wallet Balances and Addresses:");
        let _ = stdout.reset(); // Reset the color to default

        // Optionally, add a divider with color
        stdout
            .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(51, 43, 23))))
            .ok();
        println!("────────────────────");
        let _ = stdout.reset();

        let blockchain_guard = self.blockchain.read().await;

        for (name, wallet) in wallets {
            match blockchain_guard.get_wallet_balance(&wallet.address).await {
                Ok(balance) => {
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Cyan)).set_bold(true))
                        .ok();
                    let _ = writeln!(stdout, "Wallet Name: {}", name);
                    let _ = stdout.reset();

                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(100, 149, 237)))).ok();
                    let _ = write!(stdout, "Address: ");
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::White))).ok();
                    let _ = writeln!(stdout, "{}", wallet.address);
                    let _ = stdout.reset();

                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(135, 206, 250)))).ok();
                    let _ = write!(stdout, "Balance: ");
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::White)).set_bold(true)).ok();
                    let _ = write!(stdout, "{}", balance);
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Rgb(88, 240, 181)))).ok();
                    let _ = writeln!(stdout, " ♦");

                    let _ = stdout.reset();
                    println!("-------------------");
                }
                Err(e) => {
                    println!("Failed to get balance for wallet {}: {}", name, e);
                }
            }
        }
    }
}
