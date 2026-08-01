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
/// The whisper payload is a <=4-letter code: encode_message_as_fee takes only the first 4
/// chars and decode reads exactly 4, so anything longer is silently dropped. Gate sends on
/// this so the contract matches the encoder instead of accepting a 128-byte message and
/// truncating it without warning.
pub const MAX_WHISPER_CHARS: usize = 4;

/// The largest fee a transaction of `amount_units` may carry while still being
/// read as an ordinary payment rather than a whisper.
///
/// Whisper classification is a fee-BAND test (see `decode_message_from_fee`):
/// any fee at or above `amount * FEE_PERCENTAGE + WHISPER_MIN_AMOUNT` decodes to
/// a 4-letter code. That cannot be tightened on the reading side — the 26^4 =
/// 456,976 codes are spread over the 990,000 units between WHISPER_MIN_AMOUNT
/// and MAX_FEE, i.e. ~2.2 units per code, so essentially EVERY in-band fee is
/// some code's exact encoding. There is no "this was not a whisper" signal left
/// in the number to recover.
///
/// So the invariant has to hold at the sending end: a wallet that did not mean
/// to whisper must not emit a fee in the band. Historically this held by luck —
/// the old amount/1776 default sat at the relay floor for small payments, just
/// under the band — until a flat auto fee pushed every payment of <= 0.1776
/// coins into it, announcing ordinary receipts as whispers with meaningless
/// codes AND suppressing their amounts.
///
/// Returns the inclusive maximum, never below the relay floor: at amounts small
/// enough that the band starts at the floor itself, the floor is still safe
/// (the normalized position is negative for any positive amount).
pub fn max_non_whisper_fee_units(amount_units: i128) -> i128 {
    let band_start = Transaction::to_units(
        Transaction::from_units(amount_units) * FEE_PERCENTAGE + WHISPER_MIN_AMOUNT,
    );
    band_start.saturating_sub(1)
}

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
            // A transient/missing height is tolerated (matches get_blocks' filter_map)
            // rather than aborting the window walk.
            if let Ok(block) = blockchain.get_block(idx as u32) {
                if block.timestamp < cutoff_secs {
                    break;
                }
                out.push(block);
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

    /// THE REGRESSION. A wallet's automatic fee must never be readable as a
    /// whisper. Classification is a fee-band test that cannot be tightened when
    /// decoding (26^4 codes over 990,000 units is ~2.2 units per code, so almost
    /// every in-band fee IS some code's exact encoding) — so the invariant has to
    /// hold at the sending end. When it did not, every payment of <= 0.1776 coins
    /// at the flat 0.0002 auto fee was announced to the recipient as a whisper
    /// with a meaningless code, and its amount was never displayed at all.
    #[test]
    fn a_clamped_auto_fee_is_never_read_as_a_whisper() {
        let w = WhisperModule::new();
        // The three fees the estimator can emit, unclamped: floor, quiet anchor,
        // congested auto cap.
        for raw_fee_units in [10_000i128, 20_000, 200_000] {
            for amount in [
                0.00001f64, 0.0001, 0.001, 0.01, 0.05, 0.1, 0.1776, 0.2, 1.0, 25.0, 1000.0,
            ] {
                let amount_units = Transaction::to_units(amount);
                let ceiling = max_non_whisper_fee_units(amount_units);
                // Exactly what handle_create_transaction now emits.
                let sent = raw_fee_units.min(ceiling).max(10_000);
                assert_eq!(
                    w.decode_message_from_fee(Transaction::from_units(sent), 0, amount),
                    None,
                    "auto fee {} units on a {} coin payment decoded as a whisper",
                    sent,
                    amount
                );
            }
        }
    }

    /// The clamp must not break the feature it protects: a real whisper's fee is
    /// chosen by the encoder, not the estimator, so it stays above the ceiling and
    /// still decodes to exactly the code that was sent.
    #[test]
    fn clamping_payments_does_not_disturb_real_whispers() {
        let w = WhisperModule::new();
        for code in ["test", "heym", "abcd", "zzzz", "node"] {
            for amount in [0.0001f64, 0.05, 1.0, 25.0] {
                let fee = w.encode_message_as_fee(code, 0, amount);
                assert_eq!(
                    w.decode_message_from_fee(fee, 0, amount),
                    Some(code.to_uppercase()),
                    "whisper {:?} at {} coins stopped decoding",
                    code,
                    amount
                );
                assert!(
                    Transaction::to_units(fee)
                        > max_non_whisper_fee_units(Transaction::to_units(amount)),
                    "whisper {:?} at {} coins should sit above the payment ceiling",
                    code,
                    amount
                );
            }
        }
    }

    /// The ceiling is only ever a REDUCTION, and never below the relay floor —
    /// so clamping can never produce a fee the mempool would reject.
    #[test]
    fn the_whisper_ceiling_never_forces_a_sub_floor_fee() {
        for amount in [0.0f64, 0.00000001, 0.00001, 0.001, 1.0, 1_000_000.0] {
            let amount_units = Transaction::to_units(amount);
            let sent = 20_000i128
                .min(max_non_whisper_fee_units(amount_units))
                .max(10_000);
            assert!(
                sent >= 10_000,
                "clamped fee {} for amount {} fell below the relay floor",
                sent,
                amount
            );
        }
    }

    // PROOF, against the real decode path rather than a replica: an ORDINARY
    // payment carrying the reference wallet's default fee is misread as a whisper.
    //
    // decode_message_from_fee subtracts only the PERCENTAGE fee
    // (amount * FEE_PERCENTAGE) before testing the remainder against the whisper
    // band. But the wallet no longer prices the default fee as a percentage — it
    // is a flat FEE_ESTIMATE_ANCHOR_UNITS (0.0002). So for any small payment the
    // leftover lands inside [WHISPER_MIN_AMOUNT, MAX_FEE] and decodes to four
    // letters, which decode_whisper_in_tx reports as a message.
    #[test]
    fn ordinary_small_payment_is_misread_as_a_whisper() {
        let whisper = WhisperModule::new();
        let default_fee = 0.0002_f64; // FEE_ESTIMATE_ANCHOR_UNITS in coins

        // A plain transfer. No whisper was ever encoded into this fee.
        let mut misread = Vec::new();
        for amount in [0.00001_f64, 0.001, 0.01, 0.05, 0.1, 0.15] {
            let tx = Transaction {
                sender: "a".repeat(40),
                recipient: "b".repeat(40),
                amount_units: Transaction::to_units(amount),
                fee_units: Transaction::to_units(default_fee),
                timestamp: 1_783_600_000,
                signature: None,
                pub_key: None,
                sig_hash: None,
            };
            if let Some(code) = whisper.decode_whisper_in_tx(&tx) {
                misread.push((amount, code));
            }
        }
        assert!(
            !misread.is_empty(),
            "expected the default-fee payments to be misread; got none"
        );
        // Every one of them, not just an unlucky value.
        assert_eq!(
            misread.len(),
            6,
            "all six ordinary payments should misdecode, got {:?}",
            misread
        );

        // Above the crossover the misreading stops, which confirms the cause is
        // the flat fee and not something incidental.
        let big = Transaction {
            sender: "a".repeat(40),
            recipient: "b".repeat(40),
            amount_units: Transaction::to_units(1.0),
            fee_units: Transaction::to_units(default_fee),
            timestamp: 1_783_600_000,
            signature: None,
            pub_key: None,
            sig_hash: None,
        };
        assert!(
            whisper.decode_whisper_in_tx(&big).is_none(),
            "a 1-coin payment at the same fee must NOT decode as a whisper"
        );
    }

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

    /// The notice line and the digest both budget a whisper code as FOUR
    /// COLUMNS. That is only safe while the alphabet is single ASCII letters:
    /// `decode_message_from_fee` gates on `message.len() == 4`, which is a BYTE
    /// count, and `to_uppercase` can lengthen a char (ß -> SS). A future edit to
    /// `letter_frequencies` that added a digit, an accent or a multi-byte char
    /// would silently break the column budget instead of failing here.
    #[test]
    fn whisper_codes_are_always_four_ascii_uppercase() {
        let module = WhisperModule::new();
        for ch in module.frequency_map.keys() {
            assert!(
                ch.is_ascii_lowercase(),
                "alphabet char {ch:?} is not a single ASCII lowercase letter; the \
                 4-column width assumed by the notice/digest lines no longer holds"
            );
            let upper: Vec<char> = ch.to_uppercase().collect();
            assert_eq!(upper.len(), 1, "{ch:?} changes length when uppercased");
            assert!(upper[0].is_ascii_uppercase());
        }
    }
}
