use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
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

        if combined_bytes.len() < 4896 {
            return Err("Invalid key data".to_string());
        }

        let (secret_bytes, public_bytes) = combined_bytes.split_at(4896);

        let address_binary = hex::decode(&wallet_address)
            .map_err(|_| "Invalid wallet address".to_string())?;

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

        let secret_key_bytes = if passphrase.is_some() {
            Self::decrypt_private_key(encrypted_key.to_vec(), passphrase.unwrap())?
        } else {
            encrypted_key.to_vec()
        };

        // Create new dilithium keypair
        let (public_key, _) = dilithium_keypair();

        let keys = WalletKeys {
            dilithium_secret_key_bytes: secret_key_bytes,
            dilithium_public_key_bytes: PqPublicKey::as_bytes(&public_key).to_vec(),
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
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(passphrase, &salt)
            .map_err(|e| e.to_string())?;

        let hashed_passphrase = hash
            .hash
            .ok_or_else(|| "Failed to hash passphrase".to_string())?;
        let key = Key::<Aes256Gcm>::from_slice(hashed_passphrase.as_bytes());
        let cipher = Aes256Gcm::new(key);

        let encrypted_data = cipher
            .encrypt(nonce, &*serde_json::to_vec(data).unwrap())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut result = nonce.to_vec();
        result.extend(salt.as_bytes());
        result.extend(encrypted_data);

        Ok(result)
    }

    pub async fn get_public_key_hex(&self) -> Option<String> {
        let keypair = self.keypair.as_ref()?;
        let keypair = keypair.lock().await;
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

        // Split back into secret and public parts
        let (secret_bytes, public_bytes) = combined_bytes.split_at(4896);

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
        let secret_key = SecretKey::from_bytes(&keypair.dilithium_secret_key_bytes)
            .expect("Invalid secret key bytes");
        let signature = detached_sign(transaction_data, &secret_key);
        Some(PqDetachedSignature::as_bytes(&signature).to_vec())
    }

    fn encrypt_private_key(private_key: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, String> {
        let mut salt_bytes = [0u8; 16];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut salt_bytes)
            .map_err(|e| format!("Failed to generate salt: {}", e))?;

        let argon2 = Argon2::default();
        let salt = SaltString::b64_encode(&salt_bytes)
            .map_err(|e| format!("Failed to encode salt: {}", e))?;

        // Rest of encryption remains the same...
        let hash = argon2
            .hash_password(passphrase, &salt)
            .map_err(|e| e.to_string())?;

        let hashed_passphrase = hash
            .hash
            .ok_or_else(|| "Failed to hash passphrase".to_string())?;

        let key = Key::<Aes256Gcm>::from_slice(hashed_passphrase.as_bytes());
        let cipher = Aes256Gcm::new(key);

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

        let argon2 = Argon2::default();
        let salt = SaltString::b64_encode(salt_bytes)
            .map_err(|e| format!("Failed to encode salt: {}", e))?;
        let hash = argon2
            .hash_password(passphrase, &salt)
            .map_err(|e| format!("Argon2 hash error: {}", e))?;

        let hashed_passphrase = hash
            .hash
            .ok_or_else(|| "Failed to hash passphrase".to_string())?;

        let key = Key::<Aes256Gcm>::from_slice(hashed_passphrase.as_bytes());
        let cipher = Aes256Gcm::new(key);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed. Invalid passphrase or corrupted data".to_string())
    }
}
