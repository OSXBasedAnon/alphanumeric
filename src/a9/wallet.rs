use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2};
use pqcrypto_dilithium::dilithium5::{
    detached_sign, keypair as dilithium_keypair, DetachedSignature, PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use sled::Db;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

use crate::a9::blockchain::Blockchain;

const DILITHIUM5_SECRET_KEY_BYTES: usize = 4896;
const DILITHIUM5_PUBLIC_KEY_BYTES: usize = 2592;
const DILITHIUM5_COMBINED_KEY_BYTES: usize =
    DILITHIUM5_SECRET_KEY_BYTES + DILITHIUM5_PUBLIC_KEY_BYTES;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Failed to parse JSON: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Missing encrypted private key")]
    MissingEncryptedPrivateKey,
    #[error("Blockchain error: {0}")]
    BlockchainError(String),
    #[error("Invalid balance: {0}")]
    InvalidBalance(String),
}

#[derive(Serialize, Deserialize)]
pub struct PrivateWalletData {
    pub name: String,
    pub encrypted_private_key: Option<Vec<u8>>,
    pub keypair: Option<Vec<u8>>,
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletKeys {
    dilithium_secret_key_bytes: Vec<u8>,
    dilithium_public_key_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Wallet {
    #[serde(skip)]
    address_binary: Vec<u8>,
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
    fn split_combined_key_bytes(combined_bytes: &[u8]) -> Result<(&[u8], &[u8]), String> {
        if combined_bytes.len() < DILITHIUM5_COMBINED_KEY_BYTES {
            return Err(format!(
                "Invalid key data: expected at least {} bytes (secret+public), got {}",
                DILITHIUM5_COMBINED_KEY_BYTES,
                combined_bytes.len()
            ));
        }

        let (secret_bytes, rest) = combined_bytes.split_at(DILITHIUM5_SECRET_KEY_BYTES);

        if SecretKey::from_bytes(secret_bytes).is_err() {
            return Err("Invalid key data: malformed Dilithium secret key".to_string());
        }

        if rest.len() < DILITHIUM5_PUBLIC_KEY_BYTES {
            return Err(format!(
                "Invalid key data: expected {} public key bytes, got {}",
                DILITHIUM5_PUBLIC_KEY_BYTES,
                rest.len()
            ));
        }

        let public_bytes = &rest[..DILITHIUM5_PUBLIC_KEY_BYTES];
        if PublicKey::from_bytes(public_bytes).is_err() {
            return Err("Invalid key data: malformed Dilithium public key".to_string());
        }

        Ok((secret_bytes, public_bytes))
    }

    fn derive_aes_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], String> {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase, salt, &mut key)
            .map_err(|e| format!("Argon2 key derivation error: {}", e))?;
        Ok(key)
    }

    pub fn new(passphrase: Option<&[u8]>) -> Result<Self, String> {
        // Generate dilithium keypair
        let (public_key, secret_key) = dilithium_keypair();

        // Create wallet address from public key
        let mut hasher = Sha256::new();
        hasher.update(PqPublicKey::as_bytes(&public_key));
        let address_binary = hasher.finalize()[..20].to_vec();
        let address = hex::encode(&address_binary);
        let wallet_name = format!("Wallet_{}", &address[0..6]);

        // Create combined key bytes with both secret and public
        let mut combined_key_bytes = PqSecretKey::as_bytes(&secret_key).to_vec();
        combined_key_bytes.extend(PqPublicKey::as_bytes(&public_key));

        // Store the keypair
        let keys = WalletKeys {
            dilithium_secret_key_bytes: PqSecretKey::as_bytes(&secret_key).to_vec(),
            dilithium_public_key_bytes: PqPublicKey::as_bytes(&public_key).to_vec(),
        };

        // Handle encryption if needed
        let private_key = if let Some(pass) = passphrase {
            if !pass.is_empty() {
                Self::encrypt_private_key(&combined_key_bytes, pass)?
            } else {
                combined_key_bytes
            }
        } else {
            combined_key_bytes
        };

        Ok(Self {
            address_binary,
            address: address.clone(),
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
        let combined_bytes = if is_encrypted {
            let pass = passphrase.ok_or("Passphrase required for encrypted wallet")?;
            Self::decrypt_private_key(encrypted_private_key.clone(), pass)?
        } else {
            encrypted_private_key.clone()
        };

        let (secret_bytes, public_bytes) = Self::split_combined_key_bytes(&combined_bytes)?;

        let address_binary =
            hex::decode(&wallet_address).map_err(|_| "Invalid wallet address".to_string())?;

        let keys = WalletKeys {
            dilithium_secret_key_bytes: secret_bytes.to_vec(),
            dilithium_public_key_bytes: public_bytes.to_vec(),
        };

        Ok(Self {
            address_binary,
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
        println!(
            "Verifying dilithium: {},{}",
            signature.len(),
            public_key.len()
        );

        match (
            DetachedSignature::from_bytes(signature),
            PublicKey::from_bytes(public_key),
        ) {
            (Ok(sig), Ok(pub_key)) => {
                match pqcrypto_dilithium::dilithium5::verify_detached_signature(
                    &sig, message, &pub_key,
                ) {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        println!("Verification error: {}", e);
                        Ok(false)
                    }
                }
            }
            _ => Ok(false),
        }
    }

    pub async fn sign_transaction(&self, transaction_data: &[u8]) -> Option<String> {
        let keypair = self.keypair.as_ref()?;
        let keypair = keypair.lock().await;

        if let Ok(secret_key) = SecretKey::from_bytes(&keypair.dilithium_secret_key_bytes) {
            let signature = detached_sign(transaction_data, &secret_key);
            // Return hex encoded full signature
            Some(hex::encode(PqDetachedSignature::as_bytes(&signature)))
        } else {
            None
        }
    }

    pub async fn deserialize_wallet(
        file_data: &str,
        passphrase: Option<&[u8]>,
    ) -> Result<Self, String> {
        let temp_wallet: Self = serde_json::from_str(file_data)
            .map_err(|e| format!("Failed to parse wallet JSON: {}", e))?;

        let address_binary = hex::decode(&temp_wallet.address)
            .map_err(|e| format!("Failed to decode address: {}", e))?;

        let encrypted_key = temp_wallet
            .encrypted_private_key
            .as_ref()
            .ok_or("Missing encrypted private key")?;

        if temp_wallet.keypair.is_some() && passphrase.is_none() {
            return Err("Passphrase required for encrypted wallet".to_string());
        }

        let combined_bytes = if let Some(pass) = passphrase {
            Self::decrypt_private_key(encrypted_key.to_vec(), pass)?
        } else {
            encrypted_key.to_vec()
        };

        let (secret_bytes, public_bytes) = Self::split_combined_key_bytes(&combined_bytes)?;

        let keys = WalletKeys {
            dilithium_secret_key_bytes: secret_bytes.to_vec(),
            dilithium_public_key_bytes: public_bytes.to_vec(),
        };

        Ok(Self {
            address_binary,
            address: temp_wallet.address,
            name: temp_wallet.name,
            encrypted_private_key: temp_wallet.encrypted_private_key,
            keypair: Some(Arc::new(Mutex::new(keys))),
            is_encrypted: passphrase.map(|p| !p.is_empty()).unwrap_or(false),
        })
    }

    pub async fn get_balance(&self, blockchain: &Arc<RwLock<Blockchain>>) -> Result<f64, String> {
        blockchain
            .read()
            .await
            .get_wallet_balance(&self.address)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn has_sufficient_balance(
        &self,
        blockchain: &Arc<RwLock<Blockchain>>,
        required_amount: f64,
    ) -> Result<bool, String> {
        let balance = self.get_balance(blockchain).await?;
        Ok(balance >= required_amount)
    }

    fn encrypt_data(data: &PrivateWalletData, passphrase: &[u8]) -> Result<Vec<u8>, String> {
        let mut nonce_bytes = [0u8; 12];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let salt = SaltString::generate(&mut OsRng);
        let key = Self::derive_aes_key(passphrase, salt.as_str().as_bytes())?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| format!("Failed to initialize AES cipher: {}", e))?;

        let payload = serde_json::to_vec(data)
            .map_err(|e| format!("Failed to serialize wallet data: {}", e))?;
        let encrypted_data = cipher
            .encrypt(nonce, &*payload)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut result = nonce.to_vec();
        result.extend(salt.as_bytes());
        result.extend(encrypted_data);

        Ok(result)
    }

    pub async fn get_public_key_hex(&self) -> Option<String> {
        let keypair = self.keypair.as_ref()?;
        let keypair = keypair.lock().await;
        if keypair.dilithium_public_key_bytes.is_empty() {
            return None;
        }
        Some(hex::encode(&keypair.dilithium_public_key_bytes))
    }

    pub async fn sync_private_key(
        &mut self,
        db: &RwLock<Db>,
        passphrase: &[u8],
    ) -> Result<(), String> {
        let private_key = self
            .encrypted_private_key
            .as_ref()
            .ok_or("No private key available")?
            .clone();

        // Decrypt combined key bytes
        let combined_bytes = if passphrase.is_empty() {
            private_key
        } else {
            Self::decrypt_private_key(private_key, passphrase)?
        };

        let (secret_bytes, public_bytes) = Self::split_combined_key_bytes(&combined_bytes)?;

        let keys = WalletKeys {
            dilithium_secret_key_bytes: secret_bytes.to_vec(),
            dilithium_public_key_bytes: public_bytes.to_vec(),
        };

        self.keypair = Some(Arc::new(Mutex::new(keys)));
        Ok(())
    }

    pub async fn get_full_signature(&self, transaction_data: &[u8]) -> Option<Vec<u8>> {
        let keypair = self.keypair.as_ref()?;
        let keypair = keypair.lock().await;
        let secret_key = SecretKey::from_bytes(&keypair.dilithium_secret_key_bytes).ok()?;
        let signature = detached_sign(transaction_data, &secret_key);
        Some(PqDetachedSignature::as_bytes(&signature).to_vec())
    }

    fn encrypt_private_key(private_key: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, String> {
        let mut salt_bytes = [0u8; 16];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut salt_bytes)
            .map_err(|e| format!("Failed to generate salt: {}", e))?;

        let salt = SaltString::b64_encode(&salt_bytes)
            .map_err(|e| format!("Failed to encode salt: {}", e))?;
        let key = Self::derive_aes_key(passphrase, salt.as_str().as_bytes())?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| format!("Failed to initialize AES cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        rng.try_fill_bytes(&mut nonce_bytes)
            .map_err(|e| format!("Failed to generate nonce: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, private_key.as_ref())
            .map_err(|e| format!("Error encrypting private key: {}", e))?;

        let mut encrypted = nonce.to_vec();
        encrypted.extend(&salt_bytes);
        encrypted.extend(ciphertext);

        Ok(encrypted)
    }

    fn decrypt_private_key(encrypted_data: Vec<u8>, passphrase: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted_data.len() < 28 {
            return Err("Invalid encrypted data".to_string());
        }

        let nonce = Nonce::from_slice(&encrypted_data[0..12]);
        let salt_bytes = &encrypted_data[12..28];
        let ciphertext = &encrypted_data[28..];

        let salt = SaltString::b64_encode(salt_bytes)
            .map_err(|e| format!("Failed to encode salt: {}", e))?;
        let key = Self::derive_aes_key(passphrase, salt.as_str().as_bytes())?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| format!("Failed to initialize AES cipher: {}", e))?;

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed. Invalid passphrase or corrupted data".to_string())
    }
}
