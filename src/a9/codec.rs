use serde::{de::DeserializeOwned, Serialize};

const MAGIC: &[u8; 8] = b"A9MSG2\0\0";
const VERSION: u16 = 2;
const HEADER_LEN: usize = MAGIC.len() + std::mem::size_of::<u16>();

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("codec encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("codec decode error: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("missing alphanumeric codec envelope")]
    MissingEnvelope,
    #[error("unsupported alphanumeric codec version: {0}")]
    UnsupportedVersion(u16),
    #[error("codec trailing bytes: decoded {decoded} of {total}")]
    TrailingBytes { decoded: usize, total: usize },
}

pub fn serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CodecError> {
    // Serialize directly into the output buffer after the envelope header, avoiding a separate
    // payload Vec plus a full-payload memcpy. rmp_serde::encode::write drives the same default
    // Serializer that to_vec uses, so the encoded bytes are byte-for-byte identical.
    let mut out = Vec::with_capacity(HEADER_LEN + 64);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    rmp_serde::encode::write(&mut out, value)?;
    Ok(out)
}

pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    if bytes.len() < HEADER_LEN || &bytes[..MAGIC.len()] != MAGIC {
        return Err(CodecError::MissingEnvelope);
    }

    let version_offset = MAGIC.len();
    let version = u16::from_le_bytes([bytes[version_offset], bytes[version_offset + 1]]);
    if version != VERSION {
        return Err(CodecError::UnsupportedVersion(version));
    }

    let payload = &bytes[HEADER_LEN..];
    let mut cursor = std::io::Cursor::new(payload);
    let value = T::deserialize(&mut rmp_serde::Deserializer::new(&mut cursor))?;
    let decoded = cursor.position() as usize;
    if decoded != payload.len() {
        return Err(CodecError::TrailingBytes {
            decoded,
            total: payload.len(),
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_round_trip_requires_envelope() {
        let encoded = serialize(&42u64).expect("encode should work");
        assert_eq!(deserialize::<u64>(&encoded).unwrap(), 42);
        assert!(matches!(
            deserialize::<u64>(&42u64.to_le_bytes()),
            Err(CodecError::MissingEnvelope)
        ));
    }
}
