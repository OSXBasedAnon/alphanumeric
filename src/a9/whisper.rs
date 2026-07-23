use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::a9::blockchain::{
    Block, Blockchain, BlockchainError, Transaction, FEE_PERCENTAGE, SYSTEM_ADDRESSES,
};
use crate::a9::wallet::Wallet;

pub const WHISPER_MIN_AMOUNT: f64 = 0.0001;
pub const MAX_FEE: f64 = 0.01;
pub const MESSAGE_HISTORY_HOURS: i64 = 48;
pub const MAX_MESSAGE_BYTES: usize = 128;
/// The whisper payload is a <=4-letter code: encode_message_as_fee takes only the first 4
/// chars and decode reads exactly 4, so anything longer is silently dropped. Gate sends on
/// this so the contract matches the encoder instead of accepting a 128-byte message and
/// truncating it without warning.
pub const MAX_WHISPER_CHARS: usize = 4;

const PRIME_TABLE: &[u64] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FeeInfo {
    pub fee: f64,
    pub amount: f64,
    pub from: String,
    pub to: String,
    pub timestamp: u64,
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
}

impl WhisperModule {
    /// Hard fuse on the number of blocks the whisper message scan may hold in
    /// memory at once. The scan is time-windowed (the 48h whisper view), so this
    /// cap is never reached in practice (~29 days at 5s blocks);
    /// it exists only so an adversarially-skewed timestamp stream cannot defeat the
    /// early-cutoff break and drag the whole chain into RAM.
    const MAX_WINDOW_BLOCKS: usize = 500_000;

    /// Collect confirmed blocks whose timestamp is >= `cutoff_secs`, newest-first,
    /// walking backward from the tip. Block timestamps are consensus-monotonic in
    /// height (chain integrity rejects a block older than its parent), so the first
    /// block older than the cutoff proves every earlier block is older too and the
    /// walk can stop. Peak memory is bounded to the in-window blocks (plus the
    /// MAX_WINDOW_BLOCKS fuse) instead of materializing the entire decoded chain the
    /// way `Blockchain::get_blocks()` does — the unbounded-allocation DoS this
    /// replaces on `scan_blockchain_for_messages`.
    fn collect_blocks_since(blockchain: &Blockchain, cutoff_secs: u64) -> Vec<Block> {
        let tip = blockchain.get_latest_block_index();
        let mut out = Vec::new();
        let mut idx = tip as i64;
        while idx >= 0 && out.len() < Self::MAX_WINDOW_BLOCKS {
            match blockchain.get_block(idx as u32) {
                Ok(block) => {
                    if block.timestamp < cutoff_secs {
                        break;
                    }
                    out.push(block);
                }
                // Tolerate a transient/missing height (matches get_blocks' filter_map)
                // without aborting the window walk.
                Err(_) => {}
            }
            idx -= 1;
        }
        out
    }

    pub fn new() -> Self {
        Self {
            frequency_map: Self::build_frequency_map(),
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

    fn calculate_transaction_hash(&self, tx: &Transaction) -> String {
        let mut hasher = Sha256::new();

        // Create a deterministic string representation of the transaction
        let tx_string = format!(
            "{}:{}:{:.8}:{:.8}:{}",
            tx.sender,
            tx.recipient,
            tx.amount(),
            tx.fee(),
            tx.timestamp
        );

        // Update hasher with transaction data
        hasher.update(tx_string.as_bytes());

        // Convert the hash to a hexadecimal string
        hex::encode(hasher.finalize())
    }

    /// NOTE: `timestamp` is intentionally unused. The whisper component of the fee is a
    /// deterministic arithmetic coding of the (<=4-char) code alone — no per-message salt.
    /// Consequences: (1) ZERO confidentiality — anyone can decode any whisper straight from the
    /// public ledger; (2) the same code always maps to the same fee. Do NOT treat the code as
    /// private or unique, and do NOT add timestamp-dependent coding (it would break the decode
    /// of every historical whisper). The param is kept only to preserve the call sites.
    pub fn encode_message_as_fee(&self, message: &str, _timestamp: u64, base_amount: f64) -> f64 {
        let mut low = 0.0;
        let mut high = 1.0;

        // First convert to lowercase to match our frequency map
        let normalized_message: String = message
            .chars()
            .map(|c| c.to_ascii_lowercase()) // Convert to lowercase for frequency lookup
            .take(4)
            .collect();

        for c in normalized_message.chars() {
            if let Some(&(start, end, _prime)) = self.frequency_map.get(&c) {
                // Now c is already lowercase
                let range = high - low;
                high = low + range * end;
                low += range * start;
            }
        }

        let mid = (low + high) / 2.0;
        // Calculate the whisper component of the fee
        let whisper_component = WHISPER_MIN_AMOUNT + (mid * (MAX_FEE - WHISPER_MIN_AMOUNT));
        // Add the regular transaction fee
        let total_fee = whisper_component + (base_amount * FEE_PERCENTAGE);

        (total_fee * 100_000_000.0).round() / 100_000_000.0
    }

    /// NOTE: `timestamp` is intentionally unused — the code is recovered from the fee alone
    /// (see encode_message_as_fee's note on the deterministic, zero-confidentiality design).
    pub fn decode_message_from_fee(
        &self,
        total_fee: f64,
        _timestamp: u64,
        amount: f64,
    ) -> Option<String> {
        // First subtract the regular transaction fee to get the whisper component
        let whisper_fee = total_fee - (amount * FEE_PERCENTAGE);

        // Normalize the whisper component
        let normalized = (whisper_fee - WHISPER_MIN_AMOUNT) / (MAX_FEE - WHISPER_MIN_AMOUNT);
        if !(0.0..=1.0).contains(&normalized) {
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

    fn check_balance(
        &self,
        total_cost: f64,
        spendable_balance: f64,
    ) -> Result<(), BlockchainError> {
        if spendable_balance < total_cost {
            return Err(BlockchainError::InsufficientFunds);
        }

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
        // Reject rather than silently truncate: only the first MAX_WHISPER_CHARS are encoded.
        if message.chars().count() > MAX_WHISPER_CHARS {
            return Err(BlockchainError::InvalidTransaction);
        }

        if base_tx.amount() < WHISPER_MIN_AMOUNT {
            base_tx.amount_units = Transaction::to_units(WHISPER_MIN_AMOUNT);
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let base_amount = base_tx.amount();
        let total_fee = self.encode_message_as_fee(message, timestamp, base_amount);
        let total_cost = base_amount + total_fee;

        self.check_balance(total_cost, sender_balance)?;

        let message_str = format!(
            "{}:{}:{:.8}:{:.8}:{}",
            wallet.address, recipient, base_amount, total_fee, timestamp
        );

        let signature = wallet
            .sign_transaction(message_str.as_bytes())
            .await
            .ok_or(BlockchainError::InvalidTransaction)?;

        let tx = Transaction {
            sender: wallet.address.clone(),
            recipient: recipient.to_string(),
            amount_units: Transaction::to_units(base_amount),
            fee_units: Transaction::to_units(total_fee),
            timestamp,
            signature: Some(signature),
            pub_key: wallet.get_public_key_hex().await,
            sig_hash: None,
        };

        Ok(tx)
    }

    // Modify scan_blockchain_for_messages to use this more robust approach
    /// Decode a whisper message carried by a single transaction's fee, if any.
    /// Used for instant whisper notifications: scanning one just-applied block's
    /// transactions instead of re-scanning the whole chain.
    pub fn decode_whisper_in_tx(&self, tx: &Transaction) -> Option<String> {
        self.decode_message_from_fee(tx.fee(), tx.timestamp, tx.amount())
    }

    pub async fn scan_blockchain_for_messages(
        &self,
        blockchain: &Blockchain,
        address: &str,
    ) -> Vec<WhisperMessage> {
        let mut messages = Vec::new();
        let now = Utc::now();
        let cutoff = now - Duration::hours(MESSAGE_HISTORY_HOURS);

        // Bounded, time-windowed scan (walk back from the tip to the cutoff) rather
        // than materializing the entire decoded chain via get_blocks() — the latter
        // OOM-crashes the node as the chain ages (millions of Blocks in one Vec).
        let cutoff_secs = cutoff.timestamp().max(0) as u64;
        let blocks = Self::collect_blocks_since(blockchain, cutoff_secs);

        // Scan confirmed transactions
        for block in blocks {
            for tx in &block.transactions {
                if tx.sender == address || tx.recipient == address {
                    if let Some(content) =
                        self.decode_message_from_fee(tx.fee(), tx.timestamp, tx.amount())
                    {
                        messages.push(WhisperMessage {
                            from: tx.sender.clone(),
                            to: tx.recipient.clone(),
                            content,
                            tx_hash: self.calculate_transaction_hash(tx),
                            timestamp: tx.timestamp,
                            amount: tx.amount(),
                            fee: tx.fee(),
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
                        self.decode_message_from_fee(tx.fee(), tx.timestamp, tx.amount())
                    {
                        messages.push(WhisperMessage {
                            from: tx.sender.clone(),
                            to: tx.recipient.clone(),
                            content: format!("[PENDING] {}", content),
                            tx_hash: self.calculate_transaction_hash(tx),
                            timestamp: tx.timestamp,
                            amount: tx.amount(),
                            fee: tx.fee(),
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
                        self.decode_message_from_fee(tx.fee(), tx.timestamp, tx.amount())
                    {
                        let msg = WhisperMessage {
                            from: tx.sender.clone(),
                            to: tx.recipient.clone(),
                            content: format!("[PENDING] {}", content),
                            tx_hash: self.calculate_transaction_hash(&tx),
                            timestamp: tx.timestamp,
                            amount: tx.amount(),
                            fee: tx.fee(),
                        };
                        messages.push(msg);
                    }
                }
            }
        }

        messages
    }

    /// Newest-first "last N" confirmed history for one address, plus its pending
    /// txs. Unlike `get_transaction_history` this is a FIXED COUNT, not a time
    /// window: it reads at most `limit` entries straight off the address index
    /// (O(limit), no block decodes, no time cutoff), so a quiet-but-real address
    /// still shows its most recent activity instead of an empty 7-day window.
    pub async fn get_recent_transactions(
        &self,
        blockchain: &Blockchain,
        address: &str,
        limit: usize,
    ) -> Vec<FeeInfo> {
        let mut transactions = Vec::new();
        if blockchain.address_index_ready() {
            if let Ok(confirmed) = blockchain.address_recent_txs(address, limit, None) {
                for entry in confirmed {
                    let (from, to) = if entry.is_sender() && entry.is_recipient() {
                        (address.to_string(), address.to_string())
                    } else if entry.is_sender() {
                        (address.to_string(), entry.counterparty)
                    } else {
                        (entry.counterparty, address.to_string())
                    };
                    transactions.push(FeeInfo {
                        fee: Transaction::from_units(entry.fee_units),
                        amount: Transaction::from_units(entry.amount_units),
                        from,
                        to,
                        timestamp: entry.timestamp,
                    });
                }
            }
        }
        // Pending txs for this address are the very newest; include them (skipping
        // system senders), then keep only the newest `limit` overall.
        if let Ok(pending) = blockchain.get_pending_transactions().await {
            for tx in &pending {
                if SYSTEM_ADDRESSES.contains(&tx.sender.as_str()) {
                    continue;
                }
                if tx.sender == address || tx.recipient == address {
                    transactions.push(FeeInfo {
                        fee: tx.fee(),
                        amount: tx.amount(),
                        from: tx.sender.clone(),
                        to: tx.recipient.clone(),
                        timestamp: tx.timestamp,
                    });
                }
            }
        }
        transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        transactions.truncate(limit);
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

impl Default for WhisperModule {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn whisper_creation_does_not_double_count_previous_local_send() {
        let whisper = WhisperModule::new();
        let wallet = Wallet::new(None).expect("wallet should be created");
        let recipient = Wallet::new(None)
            .expect("recipient should be created")
            .address;

        let first = Transaction::new(
            wallet.address.clone(),
            recipient.clone(),
            10.0,
            0.0,
            1,
            None,
        );
        whisper
            .create_whisper_transaction(first, &recipient, "HEYD", &wallet, 25.0)
            .await
            .expect("first whisper should pass");

        let spendable_after_pending_one = 14.98927892;
        let second = Transaction::new(wallet.address.clone(), recipient.clone(), 5.0, 0.0, 2, None);

        whisper
            .create_whisper_transaction(
                second,
                &recipient,
                "dude",
                &wallet,
                spendable_after_pending_one,
            )
            .await
            .expect("second whisper should use caller-provided spendable balance only");
    }
}

#[cfg(test)]
mod relay_floor_tests {
    use super::*;
    use crate::a9::blockchain::{Transaction, MIN_RELAY_FEE_UNITS};

    // The relay fee floor (0.0001) must never clip a legitimate whisper: a
    // whisper's fee is WHISPER_MIN_AMOUNT plus a strictly positive
    // arithmetic-coded component plus the percentage fee, for ANY code and any
    // base amount. If this fails, MIN_RELAY_FEE_UNITS was raised past the
    // whisper-safe bound — lower it or rework the whisper band first.
    #[test]
    fn every_whisper_fee_clears_the_relay_floor() {
        let w = WhisperModule::new();
        for code in ["a", "aa", "aaaa", "mmmm", "zzzz"] {
            for base in [WHISPER_MIN_AMOUNT, 0.1, 1.0, 10.0, 1000.0] {
                let fee = w.encode_message_as_fee(code, 0, base);
                assert!(
                    Transaction::to_units(fee) >= MIN_RELAY_FEE_UNITS,
                    "whisper code {:?} base {} produced below-floor fee {}",
                    code,
                    base,
                    fee
                );
            }
        }
    }
}
