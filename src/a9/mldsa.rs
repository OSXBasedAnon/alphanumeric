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

/// Derive the public (verifying) key from a secret seed, in the same encoding `generate_keypair`
/// produces. Used to check that a loaded key file's stored public key really matches its secret.
pub fn public_key_from_secret(secret_key: &[u8]) -> Result<Vec<u8>, String> {
    let signing_key = signing_key_from_secret(secret_key)?;
    Ok(signing_key.verifying_key().encode().to_vec())
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

#[cfg(test)]
mod signing_spec_vector {
    use super::*;
    use sha2::{Digest, Sha256};

    // SIGNING_SPEC.md is what a third-party implementer builds against, so its test vector
    // has to actually validate. It did not: the printed sender was not the address its own
    // seed derives, and since the sender is inside the signed message, the message, its hex
    // and the signature hash were all wrong with it. A transaction built literally from the
    // document was rejected by the node's sender-vs-pubkey check.
    //
    // These are the published values. If a change to signing, encoding or address derivation
    // moves any of them, this fails and the document gets corrected with the code — rather
    // than going stale in a way only an outside implementer discovers.
    #[test]
    fn published_test_vector_still_holds() {
        const SEED: [u8; 32] = [0x07; 32];
        const SENDER: &str = "9e1e860361994891b3165e611dc5aefcdd37dfbf";
        const RECIPIENT: &str = "84dab431b53e6522fe2e74914eec99f17758f4e3";
        const PK_SHA256: &str =
            "9e1e860361994891b3165e611dc5aefcdd37dfbf5f247943daaeb57141fe7b6e";
        const SIG_SHA256: &str =
            "e3b8ce82ea7c02c008d89049aff56fa86f34d3320bae82ccf000279c74144339";

        let sha = |b: &[u8]| {
            let mut h = Sha256::new();
            h.update(b);
            hex::encode(h.finalize())
        };
        let pk = public_key_from_secret(&SEED).expect("public key from seed");
        assert_eq!(pk.len(), 2592, "published public key length");
        assert_eq!(sha(&pk), PK_SHA256, "published public key hash");

        // The sender is DERIVED, never chosen: hex(sha256(pub_key)[..20]).
        assert_eq!(&sha(&pk)[..40], SENDER, "sender must be the derived address");

        let msg = format!(
            "{}:{}:{:.8}:{:.8}:{}",
            SENDER, RECIPIENT, 1.5_f64, 0.001_f64, 1_783_600_000u64
        );
        assert_eq!(
            msg,
            "9e1e860361994891b3165e611dc5aefcdd37dfbf:84dab431b53e6522fe2e74914eec99f17758f4e3:1.50000000:0.00100000:1783600000",
            "published signed message"
        );

        let sig = sign(msg.as_bytes(), &SEED).expect("sign");
        assert_eq!(sig.len(), 4627, "published signature length");
        assert_eq!(sha(&sig), SIG_SHA256, "published signature hash (also sig_hash)");
        assert!(verify(msg.as_bytes(), &sig, &pk).is_ok(), "the vector must verify");
    }
}
