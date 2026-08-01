use alphanumeric::a9::mldsa;

const ML_DSA_87_OMEGA: usize = 75;
const ML_DSA_87_K: usize = 8;
const ML_DSA_87_HINT_BYTES: usize = ML_DSA_87_OMEGA + ML_DSA_87_K;

fn signed_message(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (public_key, secret_key) = mldsa::generate_keypair();
    let signature = mldsa::sign(message, &secret_key).expect("fixture message must sign");
    assert_eq!(signature.len(), mldsa::SIGNATURE_BYTES);
    mldsa::verify(message, &signature, &public_key)
        .expect("unmodified fixture signature must verify");
    (public_key, signature)
}

fn insert_repeated_hint(mut signature: Vec<u8>) -> Option<Vec<u8>> {
    let hint_offset = signature.len().checked_sub(ML_DSA_87_HINT_BYTES)?;
    let count_offset = signature.len().checked_sub(ML_DSA_87_K)?;
    let counts: Vec<usize> = signature[count_offset..]
        .iter()
        .map(|&count| count as usize)
        .collect();
    let total = *counts.last()?;
    if total >= ML_DSA_87_OMEGA {
        return None;
    }

    let mut start = 0usize;
    for (polynomial, &end) in counts.iter().enumerate() {
        if end > total || end < start {
            return None;
        }
        if end > start {
            let insert_at = start + 1;
            for index in (insert_at..total).rev() {
                signature[hint_offset + index + 1] = signature[hint_offset + index];
            }
            signature[hint_offset + insert_at] = signature[hint_offset + start];
            for count_index in polynomial..ML_DSA_87_K {
                signature[count_offset + count_index] =
                    signature[count_offset + count_index].checked_add(1)?;
            }
            return Some(signature);
        }
        start = end;
    }
    None
}

#[test]
fn malformed_signature_lengths_are_rejected() {
    let message = b"alphanumeric/ml-dsa/negative-lengths/v1";
    let (public_key, signature) = signed_message(message);

    for length in [0, 1, mldsa::SIGNATURE_BYTES - 1] {
        assert!(
            mldsa::verify(message, &signature[..length], &public_key).is_err(),
            "signature length {length} must be rejected"
        );
    }

    let mut extended = signature;
    extended.push(0);
    assert!(mldsa::verify(message, &extended, &public_key).is_err());
}

#[test]
fn nonzero_hint_padding_is_rejected() {
    for attempt in 0..32u8 {
        let message = [
            b"alphanumeric/ml-dsa/nonzero-hint-padding/v1/".as_slice(),
            &[attempt],
        ]
        .concat();
        let (public_key, mut signature) = signed_message(&message);
        let hint_offset = signature.len() - ML_DSA_87_HINT_BYTES;
        let count_offset = signature.len() - ML_DSA_87_K;
        let used = signature[signature.len() - 1] as usize;
        if used >= ML_DSA_87_OMEGA {
            continue;
        }

        signature[hint_offset + used] = 1;
        assert!(mldsa::verify(&message, &signature, &public_key).is_err());

        // Keep this assertion tied to the encoded layout used above. If the dependency ever changes
        // parameter sets or encodings, this test must be deliberately rewritten rather than weakened.
        assert_eq!(count_offset, hint_offset + ML_DSA_87_OMEGA);
        return;
    }

    panic!("could not produce a valid signature with unused hint padding");
}

#[test]
fn repeated_hint_indices_are_rejected() {
    for attempt in 0..32u8 {
        let message = [
            b"alphanumeric/ml-dsa/repeated-hint/v1/".as_slice(),
            &[attempt],
        ]
        .concat();
        let (public_key, signature) = signed_message(&message);
        let Some(mutated) = insert_repeated_hint(signature) else {
            continue;
        };

        assert!(
            mldsa::verify(&message, &mutated, &public_key).is_err(),
            "non-canonical repeated hint index was accepted"
        );
        return;
    }

    panic!("could not produce a valid signature with room for a repeated-hint mutation");
}
