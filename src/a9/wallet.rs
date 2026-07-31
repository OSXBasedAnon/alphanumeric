use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, Version};
use log::debug;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::a9::mldsa;

const MLDSA87_SECRET_KEY_BYTES: usize = mldsa::SECRET_KEY_BYTES;
const MLDSA87_PUBLIC_KEY_BYTES: usize = mldsa::PUBLIC_KEY_BYTES;
const MLDSA87_COMBINED_KEY_BYTES: usize = MLDSA87_SECRET_KEY_BYTES + MLDSA87_PUBLIC_KEY_BYTES;

// Custom serializer for binary address
fn serialize_address<S>(address_str: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(address_str)
}

fn deserialize_address<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer)
}

#[derive(Clone)]
struct WalletKeys {
    mldsa_secret_key_bytes: Zeroizing<Vec<u8>>,
    mldsa_public_key_bytes: Vec<u8>,
}

// Secret key material must never leak via Debug (a `{:?}` on a Wallet, which holds this) or via
// serde. Serialize/Deserialize are removed (the encrypted key on Wallet is the only persisted
// form; keypair is #[serde(skip)]), and Debug is hand-written to redact the secret bytes.
impl std::fmt::Debug for WalletKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletKeys")
            .field("mldsa_secret_key_bytes", &"<redacted>")
            .field(
                "mldsa_public_key_bytes",
                &format_args!("{} bytes", self.mldsa_public_key_bytes.len()),
            )
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Wallet {
    #[serde(
        serialize_with = "serialize_address",
        deserialize_with = "deserialize_address"
    )]
    pub address: String,
    pub name: String,
    pub encrypted_private_key: Option<Vec<u8>>,
    #[serde(skip)]
    keypair: Option<Arc<Mutex<WalletKeys>>>,
    #[serde(skip)]
    pub is_encrypted: bool,
}

impl Wallet {
    const WALLET_ENVELOPE_MAGIC: &'static [u8; 8] = b"ANWALLET";
    const WALLET_ENVELOPE_VERSION: u8 = 1;
    const KDF_ARGON2ID_V19: u8 = 1;
    const ARGON2_M_COST: u32 = 19 * 1024;
    const ARGON2_T_COST: u32 = 2;
    const ARGON2_P_COST: u32 = 1;
    const WALLET_ENVELOPE_HEADER_LEN: usize = 8 + 1 + 1 + 4 + 4 + 4;

    fn split_combined_key_bytes(combined_bytes: &[u8]) -> Result<(&[u8], &[u8]), String> {
        if combined_bytes.len() < MLDSA87_COMBINED_KEY_BYTES {
            return Err(format!(
                "Invalid key data: expected at least {} bytes (secret+public), got {}",
                MLDSA87_COMBINED_KEY_BYTES,
                combined_bytes.len()
            ));
        }

        let (secret_bytes, rest) = combined_bytes.split_at(MLDSA87_SECRET_KEY_BYTES);

        if mldsa::validate_secret_key(secret_bytes).is_err() {
            return Err("Invalid key data: malformed ML-DSA secret key".to_string());
        }

        if rest.len() < MLDSA87_PUBLIC_KEY_BYTES {
            return Err(format!(
                "Invalid key data: expected {} public key bytes, got {}",
                MLDSA87_PUBLIC_KEY_BYTES,
                rest.len()
            ));
        }

        let public_bytes = &rest[..MLDSA87_PUBLIC_KEY_BYTES];
        if mldsa::validate_public_key(public_bytes).is_err() {
            return Err("Invalid key data: malformed ML-DSA public key".to_string());
        }

        // Bind the public key to the secret seed: reject a key file whose stored public key is not
        // the one derived from the secret (bit-rot, a hand-edited/merged file, a bad restore).
        // Without this the wallet would sign with the seed's real key but advertise a different
        // address, silently making the transactions it produces unverifiable and any funds it
        // received unspendable.
        let derived_public = mldsa::public_key_from_secret(secret_bytes)?;
        if derived_public.as_slice() != public_bytes {
            return Err("Invalid key data: public key does not match the secret key".to_string());
        }

        Ok((secret_bytes, public_bytes))
    }

    fn derive_aes_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        let mut key = Zeroizing::new([0u8; 32]);
        let params = Params::new(
            Self::ARGON2_M_COST,
            Self::ARGON2_T_COST,
            Self::ARGON2_P_COST,
            Some(key.len()),
        )
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase, salt, &mut *key)
            .map_err(|e| format!("Argon2 key derivation error: {}", e))?;
        Ok(key)
    }

    pub fn new(passphrase: Option<&[u8]>) -> Result<Self, String> {
        let (public_key_bytes, secret_key_bytes) = mldsa::generate_keypair();

        // Create wallet address from public key
        let mut hasher = Sha256::new();
        hasher.update(&public_key_bytes);
        let address = hex::encode(&hasher.finalize()[..20]);
        let wallet_name = format!("Wallet_{}", &address[0..6]);

        // Create combined key bytes with both secret and public. Zeroizing so the
        // transient plaintext seed is wiped on drop (defense-in-depth; audit M4/L07).
        let mut combined_key_bytes = Zeroizing::new(secret_key_bytes.clone());
        combined_key_bytes.extend_from_slice(&public_key_bytes);

        // Store the keypair
        let keys = WalletKeys {
            mldsa_secret_key_bytes: Zeroizing::new(secret_key_bytes),
            mldsa_public_key_bytes: public_key_bytes,
        };

        // Handle encryption if needed
        let private_key = if let Some(pass) = passphrase {
            if !pass.is_empty() {
                Self::encrypt_private_key(&combined_key_bytes, pass)?
            } else {
                combined_key_bytes.to_vec()
            }
        } else {
            combined_key_bytes.to_vec()
        };

        Ok(Self {
            address,
            name: wallet_name,
            encrypted_private_key: Some(private_key),
            keypair: Some(Arc::new(Mutex::new(keys))),
            is_encrypted: passphrase.map(|p| !p.is_empty()).unwrap_or(false),
        })
    }

    pub fn from_key_bytes(
        name: String,
        wallet_address: String,
        encrypted_private_key: Vec<u8>,
        passphrase: Option<&[u8]>,
        is_encrypted: bool,
    ) -> Result<Self, String> {
        // Zeroizing so the decrypted plaintext seed is wiped on drop (audit M4/L07).
        let combined_bytes = Zeroizing::new(if is_encrypted {
            let pass = passphrase.ok_or("Passphrase required for encrypted wallet")?;
            Self::decrypt_private_key(&encrypted_private_key, pass)?
        } else {
            encrypted_private_key.clone()
        });

        let (secret_bytes, public_bytes) = Self::split_combined_key_bytes(&combined_bytes)?;

        hex::decode(&wallet_address).map_err(|_| "Invalid wallet address".to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(public_bytes);
        let derived_address = hex::encode(&hasher.finalize()[..20]);
        if derived_address != wallet_address {
            return Err("Wallet address does not match public key".to_string());
        }

        let keys = WalletKeys {
            mldsa_secret_key_bytes: Zeroizing::new(secret_bytes.to_vec()),
            mldsa_public_key_bytes: public_bytes.to_vec(),
        };

        Ok(Self {
            address: wallet_address,
            name,
            encrypted_private_key: Some(encrypted_private_key),
            keypair: Some(Arc::new(Mutex::new(keys))),
            is_encrypted,
        })
    }

    pub fn verify_signature(
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, String> {
        debug!(
            "Verifying ML-DSA signature: signature_len={}, public_key_len={}",
            signature.len(),
            public_key.len()
        );
        match mldsa::verify(message, signature, public_key) {
            Ok(()) => Ok(true),
            Err(e) => {
                debug!("ML-DSA verification failed: {}", e);
                Ok(false)
            }
        }
    }

    pub async fn sign_transaction(&self, transaction_data: &[u8]) -> Option<String> {
        let keypair = self.keypair.as_ref()?;
        let keypair = keypair.lock().await;

        // Log rather than discard: a corrupt seed and "no keypair loaded" both
        // surfaced as a bare None, so a signing failure was indistinguishable
        // from having no wallet. verify_signature already logs the same way.
        mldsa::sign(transaction_data, &keypair.mldsa_secret_key_bytes)
            .map_err(|e| debug!("ML-DSA signing failed: {}", e))
            .ok()
            .map(hex::encode)
    }

    pub async fn get_public_key_hex(&self) -> Option<String> {
        let keypair = self.keypair.as_ref()?;
        let keypair = keypair.lock().await;
        if keypair.mldsa_public_key_bytes.is_empty() {
            return None;
        }
        Some(hex::encode(&keypair.mldsa_public_key_bytes))
    }

    fn encrypt_private_key(private_key: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, String> {
        let header = Self::wallet_envelope_header();
        let payload = Self::encrypt_private_key_payload(private_key, passphrase, &header)?;
        let mut envelope = Vec::with_capacity(header.len() + payload.len());
        envelope.extend_from_slice(&header);
        envelope.extend_from_slice(&payload);
        Ok(envelope)
    }

    fn wallet_envelope_header() -> Vec<u8> {
        let mut header = Vec::with_capacity(Self::WALLET_ENVELOPE_HEADER_LEN);
        header.extend_from_slice(Self::WALLET_ENVELOPE_MAGIC);
        header.push(Self::WALLET_ENVELOPE_VERSION);
        header.push(Self::KDF_ARGON2ID_V19);
        header.extend_from_slice(&Self::ARGON2_M_COST.to_be_bytes());
        header.extend_from_slice(&Self::ARGON2_T_COST.to_be_bytes());
        header.extend_from_slice(&Self::ARGON2_P_COST.to_be_bytes());
        header
    }

    #[cfg(test)]
    fn encrypt_private_key_legacy(
        private_key: &[u8],
        passphrase: &[u8],
    ) -> Result<Vec<u8>, String> {
        Self::encrypt_private_key_payload(private_key, passphrase, &[])
    }

    fn encrypt_private_key_payload(
        private_key: &[u8],
        passphrase: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut salt_bytes = [0u8; 16];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut salt_bytes)
            .map_err(|e| format!("Failed to generate salt: {}", e))?;

        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| format!("Failed to encode salt: {}", e))?;
        let key = Self::derive_aes_key(passphrase, salt.as_str().as_bytes())?;
        let cipher = Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|e| format!("Failed to initialize AES cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        rng.try_fill_bytes(&mut nonce_bytes)
            .map_err(|e| format!("Failed to generate nonce: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: private_key.as_ref(),
                    aad,
                },
            )
            .map_err(|e| format!("Error encrypting private key: {}", e))?;

        let mut encrypted = nonce.to_vec();
        encrypted.extend(&salt_bytes);
        encrypted.extend(ciphertext);

        Ok(encrypted)
    }

    fn decrypt_private_key(encrypted_data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, String> {
        if !encrypted_data.starts_with(Self::WALLET_ENVELOPE_MAGIC) {
            return Self::decrypt_private_key_payload(encrypted_data, passphrase, &[]);
        }
        if encrypted_data.len() < Self::WALLET_ENVELOPE_HEADER_LEN {
            return Err("Invalid wallet envelope: truncated header".to_string());
        }
        if encrypted_data[8] != Self::WALLET_ENVELOPE_VERSION {
            return Err(format!(
                "Unsupported wallet envelope version: {}",
                encrypted_data[8]
            ));
        }
        if encrypted_data[9] != Self::KDF_ARGON2ID_V19 {
            return Err(format!("Unsupported wallet KDF: {}", encrypted_data[9]));
        }

        let read_u32 = |offset: usize| {
            u32::from_be_bytes([
                encrypted_data[offset],
                encrypted_data[offset + 1],
                encrypted_data[offset + 2],
                encrypted_data[offset + 3],
            ])
        };
        let m_cost = read_u32(10);
        let t_cost = read_u32(14);
        let p_cost = read_u32(18);
        if (m_cost, t_cost, p_cost)
            != (
                Self::ARGON2_M_COST,
                Self::ARGON2_T_COST,
                Self::ARGON2_P_COST,
            )
        {
            return Err(format!(
                "Unsupported wallet KDF parameters: m={}, t={}, p={}",
                m_cost, t_cost, p_cost
            ));
        }

        let header = &encrypted_data[..Self::WALLET_ENVELOPE_HEADER_LEN];
        Self::decrypt_private_key_payload(
            &encrypted_data[Self::WALLET_ENVELOPE_HEADER_LEN..],
            passphrase,
            header,
        )
    }

    fn decrypt_private_key_payload(
        encrypted_data: &[u8],
        passphrase: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        if encrypted_data.len() < 28 {
            return Err("Invalid encrypted data".to_string());
        }

        let nonce = Nonce::from_slice(&encrypted_data[0..12]);
        let salt_bytes = &encrypted_data[12..28];
        let ciphertext = &encrypted_data[28..];

        let salt = SaltString::encode_b64(salt_bytes)
            .map_err(|e| format!("Failed to encode salt: {}", e))?;
        let key = Self::derive_aes_key(passphrase, salt.as_str().as_bytes())?;
        let cipher = Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|e| format!("Failed to initialize AES cipher: {}", e))?;

        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| "Decryption failed. Invalid passphrase or corrupted data".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A key file whose stored public key is not the one derived from the secret seed must be
    // rejected, even though each half is individually well-formed.
    #[test]
    fn split_rejects_public_key_not_bound_to_secret() {
        let (pub_a, sec_a) = mldsa::generate_keypair();
        let (pub_b, _sec_b) = mldsa::generate_keypair();

        // Matching secret+public: accepted.
        let mut good = sec_a.clone();
        good.extend_from_slice(&pub_a);
        assert!(Wallet::split_combined_key_bytes(&good).is_ok());

        // secret from A + public from B (each valid, but not bound to each other): rejected.
        let mut mismatched = sec_a;
        mismatched.extend_from_slice(&pub_b);
        assert!(Wallet::split_combined_key_bytes(&mismatched).is_err());
    }

    #[test]
    fn explicit_legacy_kdf_parameters_match_argon2_0_5_3_defaults() {
        let passphrase = b"legacy passphrase";
        let salt = b"fixed legacy salt";
        let mut defaults = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(passphrase, salt, &mut *defaults)
            .unwrap();

        let explicit = Wallet::derive_aes_key(passphrase, salt).unwrap();
        assert_eq!(defaults.as_slice(), explicit.as_slice());
    }

    #[test]
    fn wallet_envelope_round_trip_authenticates_header() {
        let plaintext = b"wallet-secret-material";
        let encrypted = Wallet::encrypt_private_key(plaintext, b"correct horse").unwrap();

        assert!(encrypted.starts_with(Wallet::WALLET_ENVELOPE_MAGIC));
        assert_eq!(
            Wallet::decrypt_private_key(&encrypted, b"correct horse").unwrap(),
            plaintext
        );

        let mut tampered = encrypted;
        tampered[10] ^= 1;
        assert!(Wallet::decrypt_private_key(&tampered, b"correct horse").is_err());
    }

    #[test]
    fn legacy_wallet_payload_remains_readable() {
        let plaintext = b"legacy-wallet-secret";
        let encrypted =
            Wallet::encrypt_private_key_legacy(plaintext, b"legacy passphrase").unwrap();

        assert!(!encrypted.starts_with(Wallet::WALLET_ENVELOPE_MAGIC));
        assert_eq!(
            Wallet::decrypt_private_key(&encrypted, b"legacy passphrase").unwrap(),
            plaintext
        );
    }

    #[test]
    fn wallet_envelope_rejects_unknown_version_and_wrong_passphrase() {
        let encrypted = Wallet::encrypt_private_key(b"wallet-secret", b"right password").unwrap();
        assert!(Wallet::decrypt_private_key(&encrypted, b"wrong password").is_err());

        let mut unknown_version = encrypted;
        unknown_version[8] = Wallet::WALLET_ENVELOPE_VERSION.saturating_add(1);
        assert!(Wallet::decrypt_private_key(&unknown_version, b"right password")
            .unwrap_err()
            .contains("Unsupported wallet envelope version"));
    }
}
