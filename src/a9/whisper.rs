use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use sled::Db;
use bincode;

use crate::a9::blockchain::{
    Blockchain, BlockchainError, Transaction, FEE_PERCENTAGE, SYSTEM_ADDRESSES,
};
use crate::a9::wallet::Wallet;

pub const WHISPER_MIN_AMOUNT: f64 = 0.0001;
pub const MAX_FEE: f64 = 0.01;
pub const MESSAGE_HISTORY_HOURS: i64 = 48;
pub const MAX_MESSAGE_BYTES: usize = 128;

const PRIME_TABLE: &[u64] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
];

const FREQUENCY_TABLE: &[(char, f64)] = &[
    (' ', 0.180),
    ('e', 0.127),
    ('t', 0.090),
    ('a', 0.082),
    ('o', 0.075),
    ('i', 0.070),
    ('n', 0.067),
    ('s', 0.063),
    ('r', 0.060),
    ('h', 0.060),
    ('d', 0.043),
    ('l', 0.040),
    ('u', 0.028),
    ('c', 0.027),
    ('m', 0.024),
];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FeeInfo {
    pub fee: f64,
    pub amount: f64,
    pub from: String,
    pub to: String,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletIndex {
    last_scanned_block: u32,
    fee_cache: Vec<FeeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperMessage {
    pub from: String,
    pub to: String,
    pub content: String,
    pub tx_hash: String,
    pub timestamp: u64,
    pub amount: f64,
    pub fee: f64,
}

pub struct WhisperModule {
    frequency_map: HashMap<char, (f64, f64, u64)>,
    wallet_indices: DashMap<String, WalletIndex>,
    last_height: Arc<RwLock<u32>>,
    pending_amounts: DashMap<String, f64>,
    db: Option<Arc<Db>>,
}

impl WhisperModule {
    const INDEX_TREE: &'static str = "whisper_index";
    const MAX_INDEX_MESSAGES: usize = 2000;

    pub fn new() -> Self {
        Self {
            frequency_map: Self::build_frequency_map(),
            wallet_indices: DashMap::new(),
            last_height: Arc::new(RwLock::new(0)),
            pending_amounts: DashMap::new(),
            db: None,
        }
    }

    pub fn new_with_db(db: Arc<Db>) -> Self {
        Self {
            db: Some(db),
            ..Self::new()
        }
    }

    fn build_frequency_map() -> HashMap<char, (f64, f64, u64)> {
        let mut frequency_map = HashMap::new();
        let mut cumulative = 0.0;

        // Optimized letter frequencies with precise ranges for 4-character encoding
        let letter_frequencies: &[(char, f64)] = &[
            ('a', 0.040),
            ('b', 0.040),
            ('c', 0.040),
            ('d', 0.040),
            ('e', 0.040),
            ('f', 0.040),
            ('g', 0.040),
            ('h', 0.040),
            ('i', 0.040),
            ('j', 0.035),
            ('k', 0.035),
            ('l', 0.040),
            ('m', 0.040),
            ('n', 0.040),
            ('o', 0.040),
            ('p', 0.040),
            ('q', 0.035),
            ('r', 0.040),
            ('s', 0.040),
            ('t', 0.040),
            ('u', 0.040),
            ('v', 0.035),
            ('w', 0.040),
            ('x', 0.035),
            ('y', 0.035),
            ('z', 0.035),
        ];

        let total: f64 = letter_frequencies.iter().map(|(_, freq)| freq).sum();

        for (i, &(ch, freq)) in letter_frequencies.iter().enumerate() {
            let normalized_freq = freq / total;
            let start = cumulative;
            cumulative += normalized_freq;

            // Use precise binary-aligned boundaries
            let aligned_start = (start * 16384.0).round() / 16384.0;
            let aligned_end = (cumulative * 16384.0).round() / 16384.0;

            let prime = PRIME_TABLE[i % PRIME_TABLE.len()];
            frequency_map.insert(ch, (aligned_start, aligned_end, prime));
        }

        frequency_map
    }

    // Initialize or update wallet index
    async fn ensure_wallet_indexed(
        &self,
        address: &str,
        blockchain: &Blockchain,
    ) -> Result<(), BlockchainError> {
        let current_height = blockchain.get_latest_block_index() as u32;
        let mut should_update = false;

        // Fast check if we need to update
        if let Some(index) = self.wallet_indices.get(address) {
            if index.last_scanned_block < current_height {
                should_update = true;
            }
        } else {
            // Try to load from persisted index first
            if let Some(index) = self.load_index_from_db(address) {
                self.wallet_indices.insert(address.to_string(), index);
            } else {
                // Initialize new wallet index with empty fee_cache
                self.wallet_indices.insert(
                    address.to_string(),
                    WalletIndex {
                        last_scanned_block: 0,
                        fee_cache: Vec::new(),
                    },
                );
            }
            should_update = true;
        }

        if should_update {
            self.update_wallet_index(address, blockchain, false).await?;
        }

        Ok(())
    }

    pub async fn sync_index_for_wallet(
        &self,
        address: &str,
        blockchain: &Blockchain,
    ) -> Result<(), BlockchainError> {
        self.ensure_wallet_indexed(address, blockchain).await
    }

    async fn update_wallet_index(
        &self,
        address: &str,
        blockchain: &Blockchain,
        force_full_scan: bool,
    ) -> Result<(), BlockchainError> {
        let current_height = blockchain.get_latest_block_index() as u32;
        let mut start_height = 0;

        // Get or create index
        if !force_full_scan {
            if let Some(index) = self.wallet_indices.get(address) {
                start_height = index.last_scanned_block.saturating_add(1);
                if start_height >= current_height {
                    return Ok(());
                }
            }
        }

        let mut fee_cache = Vec::new();

        // Scan blocks in parallel chunks
        let blocks: Vec<_> = (start_height..=current_height)
            .collect::<Vec<_>>()
            .chunks(1000)
            .par_bridge()
            .flat_map(|heights| {
                heights
                    .iter()
                    .filter_map(|&height| blockchain.get_block(height).ok())
                    .collect::<Vec<_>>()
            })
            .collect();

        // Process transactions
        for block in blocks {
            for tx in &block.transactions {
                if (tx.sender == address || tx.recipient == address)
                    && (tx.fee - FEE_PERCENTAGE * tx.amount).abs() > 1e-8
                {
                    fee_cache.push(FeeInfo {
                        fee: tx.fee,
                        amount: tx.amount,
                        from: tx.sender.clone(),
                        to: tx.recipient.clone(),
                        timestamp: tx.timestamp,
                    });
                }
            }
        }

        // Update index
        self.wallet_indices.insert(
            address.to_string(),
            WalletIndex {
                last_scanned_block: current_height,
                fee_cache: Self::prune_fee_cache(fee_cache),
            },
        );

        self.save_index_to_db(address);

        Ok(())
    }

    fn prune_fee_cache(mut fee_cache: Vec<FeeInfo>) -> Vec<FeeInfo> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub((MESSAGE_HISTORY_HOURS as u64) * 3600);

        fee_cache.retain(|entry| entry.timestamp >= cutoff);
        fee_cache.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        if fee_cache.len() > Self::MAX_INDEX_MESSAGES {
            fee_cache.drain(0..fee_cache.len() - Self::MAX_INDEX_MESSAGES);
        }

        fee_cache
    }

    fn load_index_from_db(&self, address: &str) -> Option<WalletIndex> {
        let db = self.db.as_ref()?;
        let tree = db.open_tree(Self::INDEX_TREE).ok()?;
        let key = format!("idx:{}", address);
        let bytes = tree.get(key.as_bytes()).ok()??;
        bincode::deserialize(&bytes).ok()
    }

    fn save_index_to_db(&self, address: &str) {
        let db = match self.db.as_ref() {
            Some(db) => db,
            None => return,
        };
        let tree = match db.open_tree(Self::INDEX_TREE) {
            Ok(tree) => tree,
            Err(_) => return,
        };
        if let Some(index) = self.wallet_indices.get(address) {
            if let Ok(bytes) = bincode::serialize(&*index) {
                let key = format!("idx:{}", address);
                let _ = tree.insert(key.as_bytes(), bytes);
            }
        }
    }

    fn calculate_transaction_hash(&self, tx: &Transaction) -> String {
        let mut hasher = Sha256::new();

        // Create a deterministic string representation of the transaction
        let tx_string = format!(
            "{}:{}:{:.8}:{:.8}:{}",
            tx.sender, tx.recipient, tx.amount, tx.fee, tx.timestamp
        );

        // Update hasher with transaction data
        hasher.update(tx_string.as_bytes());

        // Convert the hash to a hexadecimal string
        hex::encode(hasher.finalize())
    }

    pub fn encode_message_as_fee(&self, message: &str, timestamp: u64, base_amount: f64) -> f64 {
        let mut low = 0.0;
        let mut high = 1.0;

        // First convert to lowercase to match our frequency map
        let normalized_message: String = message
            .chars()
            .map(|c| c.to_ascii_lowercase()) // Convert to lowercase for frequency lookup
            .take(4)
            .collect();

        for c in normalized_message.chars() {
            if let Some(&(start, end, prime)) = self.frequency_map.get(&c) {
                // Now c is already lowercase
                let range = high - low;
                high = low + range * end;
                low = low + range * start;
            }
        }

        let mid = (low + high) / 2.0;
        // Calculate the whisper component of the fee
        let whisper_component = WHISPER_MIN_AMOUNT + (mid * (MAX_FEE - WHISPER_MIN_AMOUNT));
        // Add the regular transaction fee
        let total_fee = whisper_component + (base_amount * FEE_PERCENTAGE);

        (total_fee * 100_000_000.0).round() / 100_000_000.0
    }

    pub fn decode_message_from_fee(
        &self,
        total_fee: f64,
        timestamp: u64,
        amount: f64,
    ) -> Option<String> {
        // First subtract the regular transaction fee to get the whisper component
        let whisper_fee = total_fee - (amount * FEE_PERCENTAGE);

        // Normalize the whisper component
        let normalized = (whisper_fee - WHISPER_MIN_AMOUNT) / (MAX_FEE - WHISPER_MIN_AMOUNT);
        if normalized < 0.0 || normalized > 1.0 {
            return None;
        }

        let mut message = String::new();
        let mut value = normalized;

        for _ in 0..4 {
            let mut found = false;
            for (&ch, &(start, end, _)) in &self.frequency_map {
                if value >= start && value < end {
                    message.push(ch);
                    value = (value - start) / (end - start);
                    found = true;
                    break;
                }
            }

            if !found {
                break;
            }
        }

        // Now we can safely convert to uppercase for display
        if message.len() == 4 {
            Some(message.to_uppercase())
        } else {
            None
        }
    }

    async fn check_balance(
        &self,
        wallet: &Wallet,
        total_cost: f64,
        sender_balance: f64,
    ) -> Result<(), BlockchainError> {
        let pending_amount = self
            .pending_amounts
            .get(&wallet.address)
            .map(|amount| *amount)
            .unwrap_or(0.0);

        if (sender_balance - pending_amount) < total_cost {
            return Err(BlockchainError::InsufficientFunds);
        }

        // Add to pending amounts
        self.pending_amounts
            .entry(wallet.address.clone())
            .and_modify(|e| *e += total_cost)
            .or_insert(total_cost);

        Ok(())
    }

    pub async fn create_whisper_transaction(
        &self,
        mut base_tx: Transaction,
        recipient: &str,
        message: &str,
        wallet: &Wallet,
        sender_balance: f64,
    ) -> Result<Transaction, BlockchainError> {
        if message.as_bytes().len() > MAX_MESSAGE_BYTES {
            return Err(BlockchainError::InvalidTransaction);
        }

        let normalized_message: String = message
            .chars()
            .map(|c| c.to_ascii_lowercase())
            .take(4)
            .collect();

        if base_tx.amount < WHISPER_MIN_AMOUNT {
            base_tx.amount = WHISPER_MIN_AMOUNT;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let total_fee = self.encode_message_as_fee(message, timestamp, base_tx.amount);
        let total_cost = base_tx.amount + total_fee;

        // Check balance including pending amounts
        self.check_balance(wallet, total_cost, sender_balance)
            .await?;

        let message_str = format!(
            "{}:{}:{:.8}:{:.8}:{}",
            wallet.address, recipient, base_tx.amount, total_fee, timestamp
        );

        let signature = wallet
            .sign_transaction(message_str.as_bytes())
            .await
            .ok_or(BlockchainError::InvalidTransaction)?;

        let tx = Transaction {
            sender: wallet.address.clone(),
            recipient: recipient.to_string(),
            amount: base_tx.amount,
            fee: total_fee,
            timestamp,
            signature: Some(signature),
            pub_key: wallet.get_public_key_hex().await,
            sig_hash: None,
        };

        Ok(tx)
    }

    // Modify scan_blockchain_for_messages to use this more robust approach
    pub async fn scan_blockchain_for_messages(
        &self,
        blockchain: &Blockchain,
        address: &str,
    ) -> Vec<WhisperMessage> {
        let mut messages = Vec::new();
        let now = Utc::now();
        let cutoff = now - Duration::hours(MESSAGE_HISTORY_HOURS);

        // Get all blocks from blockchain
        let blocks = blockchain.get_blocks();

        // Scan confirmed transactions
        for block in blocks {
            for tx in &block.transactions {
                if tx.sender == address || tx.recipient == address {
                    if let Some(content) =
                        self.decode_message_from_fee(tx.fee, tx.timestamp, tx.amount)
                    {
                        messages.push(WhisperMessage {
                            from: tx.sender.clone(),
                            to: tx.recipient.clone(),
                            content,
                            tx_hash: self.calculate_transaction_hash(tx),
                            timestamp: tx.timestamp,
                            amount: tx.amount,
                            fee: tx.fee,
                        });
                    }
                }
            }
        }

        // Add pending transactions
        if let Ok(pending) = blockchain.get_pending_transactions().await {
            for tx in &pending {
                if tx.sender == address || tx.recipient == address {
                    if let Some(content) =
                        self.decode_message_from_fee(tx.fee, tx.timestamp, tx.amount)
                    {
                        messages.push(WhisperMessage {
                            from: tx.sender.clone(),
                            to: tx.recipient.clone(),
                            content: format!("[PENDING] {}", content),
                            tx_hash: self.calculate_transaction_hash(tx),
                            timestamp: tx.timestamp,
                            amount: tx.amount,
                            fee: tx.fee,
                        });
                    }
                }
            }
        }

        // Filter by time and sort
        messages.retain(|msg| {
            DateTime::<Utc>::from_timestamp(msg.timestamp as i64, 0)
                .map(|dt| dt >= cutoff)
                .unwrap_or(false)
        });
        messages.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        messages
    }

    pub async fn get_unconfirmed_messages(
        &self,
        blockchain: &Blockchain,
        address: &str,
    ) -> Vec<WhisperMessage> {
        let mut messages = Vec::new();

        if let Ok(pending) = blockchain.get_pending_transactions().await {
            for tx in pending {
                if tx.sender == address || tx.recipient == address {
                    // Updated to include tx.amount as the third parameter
                    if let Some(content) =
                        self.decode_message_from_fee(tx.fee, tx.timestamp, tx.amount)
                    {
                        let msg = WhisperMessage {
                            from: tx.sender.clone(),
                            to: tx.recipient.clone(),
                            content: format!("[PENDING] {}", content),
                            tx_hash: self.calculate_transaction_hash(&tx),
                            timestamp: tx.timestamp,
                            amount: tx.amount,
                            fee: tx.fee,
                        };
                        messages.push(msg);
                    }
                }
            }
        }

        messages
    }

    pub async fn get_all_messages(
        &self,
        address: &str,
        blockchain: &Blockchain,
    ) -> Vec<WhisperMessage> {
        // Ensure index is up to date
        if let Err(_) = self.ensure_wallet_indexed(address, blockchain).await {
            return Vec::new();
        }

        let now = Utc::now();
        let cutoff = now - Duration::hours(MESSAGE_HISTORY_HOURS);

        if let Some(index) = self.wallet_indices.get(address) {
            let mut messages: Vec<_> = index
                .fee_cache
                .iter()
                .filter(|info| {
                    DateTime::<Utc>::from_timestamp(info.timestamp as i64, 0)
                        .map(|dt| dt >= cutoff)
                        .unwrap_or(false)
                })
                .filter_map(|info| {
                    self.decode_message_from_fee(info.fee, info.timestamp, info.amount)
                        .map(|content| WhisperMessage {
                            from: info.from.clone(),
                            to: info.to.clone(),
                            content,
                            tx_hash: self.calculate_transaction_hash(&Transaction {
                                sender: info.from.clone(),
                                recipient: info.to.clone(),
                                fee: info.fee,
                                amount: info.amount,
                                timestamp: info.timestamp,
                                signature: None,
                                pub_key: None,
                                sig_hash: None,
                            }),
                            timestamp: info.timestamp,
                            amount: info.amount,
                            fee: info.fee,
                        })
                })
                .collect();

            messages.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            messages
        } else {
            Vec::new()
        }
    }

    pub async fn process_new_transaction(&self, tx: &Transaction) -> Option<WhisperMessage> {
        if tx.fee < WHISPER_MIN_AMOUNT {
            return None;
        }

        // Remove from pending amounts when transaction is processed
        if let Some(mut pending) = self.pending_amounts.get_mut(&tx.sender) {
            *pending -= tx.amount + tx.fee;
            if *pending <= 0.0 {
                self.pending_amounts.remove(&tx.sender);
            }
        }

        if let Some(content) = self.decode_message_from_fee(tx.fee, tx.timestamp, tx.amount) {
            return Some(WhisperMessage {
                from: tx.sender.clone(),
                to: tx.recipient.clone(),
                content,
                tx_hash: self.calculate_transaction_hash(tx),
                timestamp: tx.timestamp,
                amount: tx.amount,
                fee: tx.fee,
            });
        }

        None
    }

    pub async fn get_transaction_history(
        &self,
        blockchain: &Blockchain,
        address: &str,
        days: i64,
    ) -> Vec<FeeInfo> {
        let mut transactions = Vec::new();
        let now = Utc::now();
        let cutoff = now - Duration::days(days);

        // Get confirmed transactions from blockchain
        let blocks = blockchain.get_blocks();
        for block in blocks {
            for tx in &block.transactions {
                if tx.sender == address || tx.recipient == address {
                    transactions.push(FeeInfo {
                        fee: tx.fee,
                        amount: tx.amount,
                        from: tx.sender.clone(),
                        to: tx.recipient.clone(),
                        timestamp: tx.timestamp,
                    });
                }
            }
        }

        // Add pending transactions (excluding system transactions)
        if let Ok(pending) = blockchain.get_pending_transactions().await {
            for tx in &pending {
                // Skip any pending system transactions
                if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                    continue;
                }
                if tx.sender == address || tx.recipient == address {
                    transactions.push(FeeInfo {
                        fee: tx.fee,
                        amount: tx.amount,
                        from: tx.sender.clone(),
                        to: tx.recipient.clone(),
                        timestamp: tx.timestamp,
                    });
                }
            }
        }

        // Filter by time and sort
        transactions.retain(|tx| {
            DateTime::<Utc>::from_timestamp(tx.timestamp as i64, 0)
                .map(|dt| dt >= cutoff)
                .unwrap_or(false)
        });

        // Sort transactions by date and timestamp
        transactions.sort_by(|a, b| {
            let a_datetime = DateTime::<Utc>::from_timestamp(a.timestamp as i64, 0);
            let b_datetime = DateTime::<Utc>::from_timestamp(b.timestamp as i64, 0);
            b_datetime.cmp(&a_datetime)
        });

        transactions
    }

    pub fn format_message_time(timestamp: u64) -> String {
        if let Some(datetime) = DateTime::<Utc>::from_timestamp(timestamp as i64, 0) {
            let now = Utc::now();
            let diff = now.signed_duration_since(datetime);

            // Get the exact time part
            let time_str = datetime.format("%H:%M:%S").to_string();

            // Calculate the relative part with more precise thresholds
            let relative = if diff.num_seconds() < 60 {
                "just now".to_string()
            } else if diff.num_minutes() < 60 {
                format!("{}m ago", diff.num_minutes())
            } else if diff.num_hours() < 24 {
                format!("{}h ago", diff.num_hours())
            } else {
                format!("{}d ago", diff.num_days())
            };

            format!("{} ({})", time_str, relative)
        } else {
            "invalid time".to_string()
        }
    }
}
