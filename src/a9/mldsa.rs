use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa87, Signature, Signer, SigningKey,
    Verifier, VerifyingKey,
};
use rand::RngCore;
use zeroize::Zeroizing;

pub const SECRET_KEY_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = 2_592;
pub const SIGNATURE_BYTES: usize = 4_627;

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    // Hold the raw seed in a Zeroizing buffer so the stack copy is wiped when this returns; the
    // returned Vec is the persisted secret, protected downstream (WalletKeys is also Zeroizing).
    let mut seed = Zeroizing::new([0u8; SECRET_KEY_BYTES]);
    rand::rngs::OsRng.fill_bytes(&mut *seed);
    let signing_key = SigningKey::<MlDsa87>::from_seed(&(*seed).into());
    let public_key = signing_key.verifying_key().encode().to_vec();
    (public_key, seed.to_vec())
}

pub fn validate_secret_key(secret_key: &[u8]) -> Result<(), String> {
    signing_key_from_secret(secret_key).map(|_| ())
}

pub fn validate_public_key(public_key: &[u8]) -> Result<(), String> {
    verifying_key_from_public(public_key).map(|_| ())
}

pub fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    let signing_key = signing_key_from_secret(secret_key)?;
    let signature: Signature<MlDsa87> = signing_key.sign(message);
    Ok(signature.encode().to_vec())
}

pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), String> {
    let verifying_key = verifying_key_from_public(public_key)?;
    let signature = signature_from_bytes(signature)?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| "ML-DSA signature verification failed".to_string())
}

fn signing_key_from_secret(secret_key: &[u8]) -> Result<SigningKey<MlDsa87>, String> {
    let seed = ml_dsa::Seed::try_from(secret_key).map_err(|_| {
        format!(
            "Invalid ML-DSA secret key length: expected {}, got {}",
            SECRET_KEY_BYTES,
            secret_key.len()
        )
    })?;
    Ok(SigningKey::<MlDsa87>::from_seed(&seed))
}

fn verifying_key_from_public(public_key: &[u8]) -> Result<VerifyingKey<MlDsa87>, String> {
    let encoded = EncodedVerifyingKey::<MlDsa87>::try_from(public_key).map_err(|_| {
        format!(
            "Invalid ML-DSA public key length: expected {}, got {}",
            PUBLIC_KEY_BYTES,
            public_key.len()
        )
    })?;
    Ok(VerifyingKey::<MlDsa87>::decode(&encoded))
}

fn signature_from_bytes(signature: &[u8]) -> Result<Signature<MlDsa87>, String> {
    let encoded = EncodedSignature::<MlDsa87>::try_from(signature).map_err(|_| {
        format!(
            "Invalid ML-DSA signature length: expected {}, got {}",
            SIGNATURE_BYTES,
            signature.len()
        )
    })?;
    Signature::<MlDsa87>::decode(&encoded)
        .ok_or_else(|| "Invalid ML-DSA signature encoding".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa_round_trip_signs_and_verifies() {
        let (public_key, secret_key) = generate_keypair();
        let message = b"alphanumeric mldsa";
        let signature = sign(message, &secret_key).expect("sign");

        assert_eq!(secret_key.len(), SECRET_KEY_BYTES);
        assert_eq!(public_key.len(), PUBLIC_KEY_BYTES);
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        assert!(verify(message, &signature, &public_key).is_ok());
        assert!(verify(b"wrong", &signature, &public_key).is_err());
    }
}
