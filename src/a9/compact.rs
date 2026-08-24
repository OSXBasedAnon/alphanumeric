//! Transport-only primitives for compact block relay.
//!
//! Nothing in this module participates in consensus.  The wire types deliberately
//! keep their own bounds and versioned representation so hostile peer input is
//! rejected before it can grow an unbounded allocation, and so a future compact
//! protocol can coexist with this one without changing block validity.

use crate::a9::blockchain::MAX_BLOCK_TX_COUNT;
use rand::{rngs::OsRng, RngCore};
use serde::{
    de::{Error as DeError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

pub const RELAY_TOKEN_BYTES: usize = 16;
const HASH_BYTES: usize = 32;
const MAX_PACKED_HASH_BYTES: usize = MAX_BLOCK_TX_COUNT.saturating_sub(1) * HASH_BYTES;

/// Correlates one block announcement with later body/full/ack messages.
///
/// The authenticated transport remains the peer-authentication boundary.  This
/// token is a replay and stale-generation guard, sized at 128 bits so it remains
/// safe to mint independently for every `(block, peer)` for the lifetime of the
/// protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RelayToken(pub [u8; RELAY_TOKEN_BYTES]);

impl RelayToken {
    pub fn random() -> Result<Self, rand::Error> {
        let mut token = [0u8; RELAY_TOKEN_BYTES];
        OsRng.try_fill_bytes(&mut token)?;
        Ok(Self(token))
    }
}

impl Serialize for RelayToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelayToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RelayTokenVisitor;

        impl<'de> Visitor<'de> for RelayTokenVisitor {
            type Value = RelayToken;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an exact {RELAY_TOKEN_BYTES}-byte relay token")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                let token: [u8; RELAY_TOKEN_BYTES] = bytes
                    .try_into()
                    .map_err(|_| E::invalid_length(bytes.len(), &self))?;
                Ok(RelayToken(token))
            }

            fn visit_borrowed_bytes<E>(self, bytes: &'de [u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                self.visit_bytes(bytes)
            }

            fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                self.visit_bytes(&bytes)
            }
        }

        deserializer.deserialize_bytes(RelayTokenVisitor)
    }
}

/// Ordered full Merkle-leaf hashes for every non-coinbase transaction.
///
/// `Vec<[u8; 32]>` is encoded by rmp-serde as an array of arrays, which spends
/// roughly 1.5 bytes per random hash byte.  Encoding one binary blob is both
/// smaller and lets the decoder reject malformed lengths before allocating the
/// destination vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedTransactionHashes(Vec<[u8; HASH_BYTES]>);

impl PackedTransactionHashes {
    pub fn new(hashes: Vec<[u8; HASH_BYTES]>) -> Result<Self, &'static str> {
        if hashes.len() > MAX_BLOCK_TX_COUNT.saturating_sub(1) {
            return Err("compact transaction hash count exceeds consensus limit");
        }
        Ok(Self(hashes))
    }

    pub fn as_slice(&self) -> &[[u8; HASH_BYTES]] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for PackedTransactionHashes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut packed = Vec::with_capacity(self.0.len() * HASH_BYTES);
        for hash in &self.0 {
            packed.extend_from_slice(hash);
        }
        serializer.serialize_bytes(&packed)
    }
}

impl<'de> Deserialize<'de> for PackedTransactionHashes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PackedHashesVisitor;

        impl<'de> Visitor<'de> for PackedHashesVisitor {
            type Value = PackedTransactionHashes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "a binary blob containing at most {} ordered 32-byte hashes",
                    MAX_BLOCK_TX_COUNT.saturating_sub(1)
                )
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                // `usize::is_multiple_of` is newer than the project's Rust
                // 1.89 deployment floor.
                #[allow(clippy::manual_is_multiple_of)]
                if bytes.len() > MAX_PACKED_HASH_BYTES || bytes.len() % HASH_BYTES != 0 {
                    return Err(E::invalid_length(bytes.len(), &self));
                }
                let mut hashes = Vec::with_capacity(bytes.len() / HASH_BYTES);
                for chunk in bytes.chunks_exact(HASH_BYTES) {
                    let mut hash = [0u8; HASH_BYTES];
                    hash.copy_from_slice(chunk);
                    hashes.push(hash);
                }
                Ok(PackedTransactionHashes(hashes))
            }

            fn visit_borrowed_bytes<E>(self, bytes: &'de [u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                self.visit_bytes(bytes)
            }

            fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                self.visit_bytes(&bytes)
            }
        }

        deserializer.deserialize_bytes(PackedHashesVisitor)
    }
}

/// Terminal states are mutually exclusive.  A pair of booleans can represent
/// impossible states such as both ACKed and full-served and is therefore not
/// suitable for an amplification-sensitive protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AnnounceStatus {
    Pending,
    Acked,
    FullServed,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AnnounceEntry {
    pub token: RelayToken,
    pub status: AnnounceStatus,
    pub body_served: bool,
    pub announced_at: Instant,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ReceivedEvidence {
    pub token: RelayToken,
    pub received_at: Instant,
}

/// Per-node counters used by beta soak review.  Keeping them on `Node` avoids
/// cross-contamination when tests run several nodes in one process.
#[derive(Debug, Default)]
pub(crate) struct CompactMetrics {
    pub announced: AtomicU64,
    pub reconstructed: AtomicU64,
    pub missing_requests: AtomicU64,
    pub want_full_sent: AtomicU64,
    pub want_full_served: AtomicU64,
    pub fallback_full_received: AtomicU64,
    pub ack_received: AtomicU64,
    pub saturated: AtomicU64,
    pub invalid: AtomicU64,
    pub compact_bytes_sent: AtomicU64,
    /// Exact TCP-framed encrypted bytes for every V2 frame written by this node:
    /// announcements, body requests/responses, ACKs, and WANT_FULL requests.
    /// Together with `full_bytes_avoided` and `fallback_bytes_sent`, this makes
    /// beta-soak net bandwidth observable instead of extrapolated.
    pub v2_wire_bytes_sent: AtomicU64,
    pub full_bytes_avoided: AtomicU64,
    pub fallback_bytes_sent: AtomicU64,
    pub reconstruction_micros: AtomicU64,
    pub reconstruction_micros_max: AtomicU64,
    pub handler_frames: AtomicU64,
    pub handler_micros: AtomicU64,
    pub handler_micros_max: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CompactMetricsSnapshot {
    pub announced: u64,
    pub reconstructed: u64,
    pub missing_requests: u64,
    pub want_full_sent: u64,
    pub want_full_served: u64,
    pub fallback_full_received: u64,
    pub ack_received: u64,
    pub saturated: u64,
    pub invalid: u64,
    pub compact_bytes_sent: u64,
    pub v2_wire_bytes_sent: u64,
    pub full_bytes_avoided: u64,
    pub fallback_bytes_sent: u64,
    pub reconstruction_micros: u64,
    pub reconstruction_micros_max: u64,
    pub handler_frames: u64,
    pub handler_micros: u64,
    pub handler_micros_max: u64,
}

impl CompactMetrics {
    pub fn observe_reconstruction(&self, elapsed_micros: u64) {
        self.reconstructed.fetch_add(1, Ordering::Relaxed);
        self.reconstruction_micros
            .fetch_add(elapsed_micros, Ordering::Relaxed);
        self.reconstruction_micros_max
            .fetch_max(elapsed_micros, Ordering::Relaxed);
    }

    fn observe_handler(&self, elapsed_micros: u64) {
        self.handler_frames.fetch_add(1, Ordering::Relaxed);
        self.handler_micros
            .fetch_add(elapsed_micros, Ordering::Relaxed);
        self.handler_micros_max
            .fetch_max(elapsed_micros, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> CompactMetricsSnapshot {
        CompactMetricsSnapshot {
            announced: self.announced.load(Ordering::Relaxed),
            reconstructed: self.reconstructed.load(Ordering::Relaxed),
            missing_requests: self.missing_requests.load(Ordering::Relaxed),
            want_full_sent: self.want_full_sent.load(Ordering::Relaxed),
            want_full_served: self.want_full_served.load(Ordering::Relaxed),
            fallback_full_received: self.fallback_full_received.load(Ordering::Relaxed),
            ack_received: self.ack_received.load(Ordering::Relaxed),
            saturated: self.saturated.load(Ordering::Relaxed),
            invalid: self.invalid.load(Ordering::Relaxed),
            compact_bytes_sent: self.compact_bytes_sent.load(Ordering::Relaxed),
            v2_wire_bytes_sent: self.v2_wire_bytes_sent.load(Ordering::Relaxed),
            full_bytes_avoided: self.full_bytes_avoided.load(Ordering::Relaxed),
            fallback_bytes_sent: self.fallback_bytes_sent.load(Ordering::Relaxed),
            reconstruction_micros: self.reconstruction_micros.load(Ordering::Relaxed),
            reconstruction_micros_max: self.reconstruction_micros_max.load(Ordering::Relaxed),
            handler_frames: self.handler_frames.load(Ordering::Relaxed),
            handler_micros: self.handler_micros.load(Ordering::Relaxed),
            handler_micros_max: self.handler_micros_max.load(Ordering::Relaxed),
        }
    }
}

/// Cancellation-safe timing for the small amount of V2 work allowed to remain
/// on a TCP reader task. Reconstruction and ML-DSA verification run elsewhere;
/// this timer makes any regression back onto the reader visible during soak.
pub(crate) struct CompactHandlerTimer<'a> {
    metrics: &'a CompactMetrics,
    started: Instant,
}

impl<'a> CompactHandlerTimer<'a> {
    pub fn start(metrics: &'a CompactMetrics) -> Self {
        Self {
            metrics,
            started: Instant::now(),
        }
    }
}

impl Drop for CompactHandlerTimer<'_> {
    fn drop(&mut self) {
        self.metrics
            .observe_handler(self.started.elapsed().as_micros().min(u64::MAX as u128) as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a9::codec;

    #[test]
    fn packed_hashes_round_trip_as_bounded_binary() {
        let hashes = vec![[0x11; 32], [0x80; 32], [0xff; 32]];
        let packed = PackedTransactionHashes::new(hashes.clone()).unwrap();
        let encoded = codec::serialize(&packed).unwrap();
        let decoded: PackedTransactionHashes = codec::deserialize(&encoded).unwrap();
        assert_eq!(decoded.as_slice(), hashes.as_slice());
        // Three hashes plus the codec and MessagePack binary prefixes should be
        // far below the array-of-u8 representation (~150 bytes for random data).
        assert!(
            encoded.len() < 120,
            "packed encoding was {} bytes",
            encoded.len()
        );
    }

    #[test]
    fn packed_hashes_reject_misaligned_binary() {
        #[derive(Serialize)]
        struct Raw(#[serde(with = "raw_bytes")] Vec<u8>);

        mod raw_bytes {
            use serde::Serializer;

            pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(bytes)
            }
        }

        let encoded = codec::serialize(&Raw(vec![0u8; 31])).unwrap();
        assert!(codec::deserialize::<PackedTransactionHashes>(&encoded).is_err());

        let oversized =
            codec::serialize(&Raw(vec![0u8; MAX_PACKED_HASH_BYTES + HASH_BYTES])).unwrap();
        assert!(codec::deserialize::<PackedTransactionHashes>(&oversized).is_err());
    }

    #[test]
    fn relay_token_is_fixed_width_binary_and_rejects_other_lengths() {
        #[derive(Serialize)]
        struct Raw(#[serde(with = "raw_bytes")] Vec<u8>);

        mod raw_bytes {
            use serde::Serializer;

            pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(bytes)
            }
        }

        let token = RelayToken([0xff; RELAY_TOKEN_BYTES]);
        let encoded = codec::serialize(&token).unwrap();
        assert!(encoded.len() <= crate::a9::codec::HEADER_LEN + RELAY_TOKEN_BYTES + 3);
        assert_eq!(codec::deserialize::<RelayToken>(&encoded).unwrap(), token);

        let short = codec::serialize(&Raw(vec![0u8; RELAY_TOKEN_BYTES - 1])).unwrap();
        let long = codec::serialize(&Raw(vec![0u8; RELAY_TOKEN_BYTES + 1])).unwrap();
        assert!(codec::deserialize::<RelayToken>(&short).is_err());
        assert!(codec::deserialize::<RelayToken>(&long).is_err());
    }

    #[test]
    fn announce_state_has_one_terminal_value() {
        let mut entry = AnnounceEntry {
            token: RelayToken([1; RELAY_TOKEN_BYTES]),
            status: AnnounceStatus::Pending,
            body_served: false,
            announced_at: Instant::now(),
        };
        entry.status = AnnounceStatus::Acked;
        assert_ne!(entry.status, AnnounceStatus::FullServed);
    }
}
