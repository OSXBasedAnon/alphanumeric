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

/// NEGATIVE-VECTOR SUITE for the consensus signature primitive.
///
/// Every transaction's authorization ends here, and `ml-dsa` is pinned exactly
/// because a silent patch bump could change signature bytes and fork the chain.
/// RustCrypto states the implementation has never been independently audited, and
/// its published 2026 advisories included signature malleability and valid-signature
/// rejection. The pin is newer than all of those, and `signing_spec_vector` already
/// freezes the POSITIVE direction (a known seed still produces known bytes). This
/// module covers the NEGATIVE direction: nothing that is not a genuine signature may
/// ever verify.
///
/// Assertions are one-directional on purpose. Every case asserts REJECTION; none
/// asserts that a mutation is accepted, so the suite can never ratify malleability.
/// It is a tripwire on the pinned version's behaviour, not a substitute for the
/// independent review that crate still lacks.
#[cfg(test)]
mod negative_vectors {
    use super::*;

    // FIPS 204 sigEncode for ML-DSA-87: c~ (64) || z (4480) || h (omega + k = 83),
    // totalling SIGNATURE_BYTES. The hint is the trailing region, and it is the part
    // with non-canonical encodings that are not mere bit-flips -- the class a naive
    // mutation corpus is least likely to reach.
    const C_TILDE_BYTES: usize = 64;
    const Z_BYTES: usize = 4_480;
    const OMEGA: usize = 75;
    const K: usize = 8;
    const HINT_OFFSET: usize = C_TILDE_BYTES + Z_BYTES;
    /// Start of the k cumulative-count bytes that terminate the hint region.
    const COUNTS_OFFSET: usize = HINT_OFFSET + OMEGA;

    /// A named mutation of a signature's hint region, applied in place.
    type HintMutation = Box<dyn Fn(&mut Vec<u8>)>;

    const SEED: [u8; 32] = [0x2A; 32];
    const MESSAGE: &[u8] = b"alphanumeric negative vector message";

    fn keypair_from_seed() -> (Vec<u8>, Vec<u8>) {
        let public = public_key_from_secret(&SEED).expect("public key from seed");
        (public, SEED.to_vec())
    }

    fn valid_signature() -> (Vec<u8>, Vec<u8>) {
        let (public, secret) = keypair_from_seed();
        let signature = sign(MESSAGE, &secret).expect("signing must succeed");
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        verify(MESSAGE, &signature, &public).expect("a genuine signature must verify");
        (signature, public)
    }

    /// The layout the hint cases depend on. If a future crate version changes the
    /// encoding, this fails loudly rather than letting those cases silently degrade
    /// into ordinary byte-flip tests that pass for the wrong reason.
    #[test]
    fn signature_layout_matches_the_assumed_fips204_encoding() {
        assert_eq!(C_TILDE_BYTES + Z_BYTES + OMEGA + K, SIGNATURE_BYTES);
        assert_eq!(HINT_OFFSET + OMEGA + K, SIGNATURE_BYTES);
        let (signature, _) = valid_signature();
        assert_eq!(signature.len(), HINT_OFFSET + OMEGA + K);
    }

    /// NON-CANONICAL HINT ENCODINGS.
    ///
    /// HintBitPack (FIPS 204 Alg. 21) requires: cumulative counts non-decreasing and
    /// never above omega; indices strictly increasing within each polynomial; and all
    /// padding past the final count zero. Each case below violates exactly one of
    /// those rules. This is the repeated-hint / malleability class -- random mutation
    /// and truncation would not reliably reach it, which is why these are constructed
    /// rather than sampled.
    #[test]
    fn non_canonical_hint_encodings_are_rejected() {
        let (signature, public) = valid_signature();

        let cases: Vec<(&str, HintMutation)> = vec![
            (
                "duplicate index within one polynomial",
                Box::new(|s: &mut Vec<u8>| {
                    s[HINT_OFFSET..].fill(0);
                    s[HINT_OFFSET] = 5;
                    s[HINT_OFFSET + 1] = 5; // repeated -> not strictly increasing
                    for i in 0..K {
                        s[COUNTS_OFFSET + i] = 2;
                    }
                }),
            ),
            (
                "descending indices within one polynomial",
                Box::new(|s: &mut Vec<u8>| {
                    s[HINT_OFFSET..].fill(0);
                    s[HINT_OFFSET] = 9;
                    s[HINT_OFFSET + 1] = 3;
                    for i in 0..K {
                        s[COUNTS_OFFSET + i] = 2;
                    }
                }),
            ),
            (
                "cumulative counts decrease",
                Box::new(|s: &mut Vec<u8>| {
                    s[HINT_OFFSET..].fill(0);
                    s[HINT_OFFSET] = 1;
                    s[HINT_OFFSET + 1] = 2;
                    s[COUNTS_OFFSET] = 10;
                    for i in 1..K {
                        s[COUNTS_OFFSET + i] = 5; // < previous cumulative
                    }
                }),
            ),
            (
                "cumulative count exceeds omega",
                Box::new(|s: &mut Vec<u8>| {
                    s[COUNTS_OFFSET + K - 1] = (OMEGA + 1) as u8;
                }),
            ),
            (
                "nonzero padding past the final count",
                Box::new(|s: &mut Vec<u8>| {
                    s[HINT_OFFSET..].fill(0);
                    s[HINT_OFFSET + OMEGA - 1] = 1; // counts are all zero, so this is padding
                }),
            ),
            (
                "hint region saturated",
                Box::new(|s: &mut Vec<u8>| {
                    s[HINT_OFFSET..].fill(0xFF);
                }),
            ),
        ];

        for (name, mutate) in cases {
            let mut malformed = signature.clone();
            mutate(&mut malformed);
            assert_eq!(malformed.len(), SIGNATURE_BYTES, "{name} must keep the length");
            assert_ne!(malformed, signature, "{name} must actually change the bytes");

            // Rejected at DECODE, not merely by the signature math downstream. This
            // is the sharper property and the one that matters for malleability: a
            // decoder that tolerated non-canonical hints could admit two distinct
            // byte strings that both verify for one message, and this chain treats
            // signature bytes as part of transaction identity. Measured against the
            // pinned version -- if a future bump relaxes decoding to catch these
            // later (or not at all), this fails and the bump gets scrutinised.
            assert!(
                signature_from_bytes(&malformed).is_err(),
                "non-canonical hint must be rejected at decode, not left to verification: {name}"
            );
            assert!(
                verify(MESSAGE, &malformed, &public).is_err(),
                "non-canonical hint accepted: {name}"
            );
        }
    }

    /// A signature differing from a genuine one ONLY inside the hint region must not
    /// verify -- the hint is covered, not ignored padding. Distinct from the cases
    /// above: those are structurally illegal, this one is a targeted single-byte
    /// change to prove coverage.
    #[test]
    fn single_byte_hint_perturbation_is_rejected() {
        let (signature, public) = valid_signature();
        for offset in [HINT_OFFSET, HINT_OFFSET + OMEGA / 2, SIGNATURE_BYTES - 1] {
            let mut perturbed = signature.clone();
            perturbed[offset] ^= 0x01;
            assert!(
                verify(MESSAGE, &perturbed, &public).is_err(),
                "a signature altered only at hint byte {offset} must not verify"
            );
        }
    }

    /// Every structural region must be covered by verification, so a flip anywhere
    /// is fatal. Boundary offsets are included because off-by-one region handling is
    /// exactly where a length or slice bug would hide.
    #[test]
    fn bit_flips_in_every_signature_region_are_rejected() {
        let (signature, public) = valid_signature();
        let offsets = [
            0,
            C_TILDE_BYTES - 1,
            C_TILDE_BYTES,
            C_TILDE_BYTES + Z_BYTES / 2,
            HINT_OFFSET - 1,
            HINT_OFFSET,
            SIGNATURE_BYTES - 1,
        ];
        for offset in offsets {
            for bit in [0x01u8, 0x80] {
                let mut flipped = signature.clone();
                flipped[offset] ^= bit;
                assert!(
                    verify(MESSAGE, &flipped, &public).is_err(),
                    "flipping bit {bit:#x} at offset {offset} must invalidate the signature"
                );
            }
        }
    }

    /// Length is part of the encoding. Truncation and extension must be rejected at
    /// decode, never padded or silently accepted at a prefix.
    #[test]
    fn wrong_length_signatures_are_rejected() {
        let (signature, public) = valid_signature();
        let mut lengths: Vec<usize> = vec![
            0,
            1,
            C_TILDE_BYTES,
            HINT_OFFSET,
            SIGNATURE_BYTES - 1,
            SIGNATURE_BYTES - OMEGA - K,
        ];
        lengths.retain(|len| *len < SIGNATURE_BYTES);
        for len in lengths {
            assert!(
                verify(MESSAGE, &signature[..len], &public).is_err(),
                "a {len}-byte signature must be rejected"
            );
        }

        let mut extended = signature.clone();
        extended.push(0);
        assert!(
            verify(MESSAGE, &extended, &public).is_err(),
            "an over-long signature must be rejected"
        );
    }

    /// Degenerate buffers must never verify. Cheap, but this is the shape a caller
    /// passing an uninitialised or default-constructed buffer would produce.
    #[test]
    fn degenerate_signatures_are_rejected() {
        let (_, public) = valid_signature();
        for filler in [0x00u8, 0xFF, 0xAA] {
            let degenerate = vec![filler; SIGNATURE_BYTES];
            assert!(
                verify(MESSAGE, &degenerate, &public).is_err(),
                "an all-{filler:#04x} buffer must not verify"
            );
        }
    }

    /// Binding: a genuine signature must not transfer to another message or another
    /// key. These are the failures that would let a valid signature be replayed onto
    /// different transaction contents.
    #[test]
    fn signatures_do_not_transfer_across_messages_or_keys() {
        let (signature, public) = valid_signature();

        assert!(
            verify(b"a different message", &signature, &public).is_err(),
            "a signature must not verify over a different message"
        );
        assert!(
            verify(&[], &signature, &public).is_err(),
            "a signature must not verify over an empty message"
        );

        let mut extended = MESSAGE.to_vec();
        extended.push(0x00);
        assert!(
            verify(&extended, &signature, &public).is_err(),
            "appending to the message must invalidate the signature"
        );

        let other_public = public_key_from_secret(&[0x5B; 32]).expect("second public key");
        assert_ne!(other_public, public);
        assert!(
            verify(MESSAGE, &signature, &other_public).is_err(),
            "a signature must not verify under a different key"
        );

        let mut corrupted_key = public.clone();
        corrupted_key[0] ^= 0x01;
        assert!(
            verify(MESSAGE, &signature, &corrupted_key).is_err(),
            "a signature must not verify under a perturbed key"
        );
    }

    /// Malformed public keys must be rejected rather than coerced into some default
    /// key that a forged signature could then match.
    #[test]
    fn malformed_public_keys_are_rejected() {
        let (signature, public) = valid_signature();
        for len in [0usize, 1, PUBLIC_KEY_BYTES - 1] {
            assert!(
                verify(MESSAGE, &signature, &public[..len.min(public.len())]).is_err(),
                "a {len}-byte public key must be rejected"
            );
        }
        let mut extended = public.clone();
        extended.push(0);
        assert!(
            verify(MESSAGE, &signature, &extended).is_err(),
            "an over-long public key must be rejected"
        );
        assert!(validate_public_key(&vec![0u8; PUBLIC_KEY_BYTES]).is_err() || {
            // An all-zero key that happens to decode must still not verify a
            // signature made under a different key.
            verify(MESSAGE, &signature, &vec![0u8; PUBLIC_KEY_BYTES]).is_err()
        });
    }

    /// Signing is deterministic for a fixed seed and message in this configuration,
    /// which is what makes the frozen SIGNING_SPEC vector meaningful. If that ever
    /// changes, the published vector stops being reproducible for third-party
    /// implementers and this says so directly.
    #[test]
    fn signing_is_deterministic_for_a_fixed_seed_and_message() {
        let (_, secret) = keypair_from_seed();
        let first = sign(MESSAGE, &secret).expect("first signing");
        let second = sign(MESSAGE, &secret).expect("second signing");
        assert_eq!(
            first, second,
            "signing must be deterministic for a fixed seed and message"
        );
    }
}
