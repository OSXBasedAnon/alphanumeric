#![no_main]

use alphanumeric::a9::{blockchain::Transaction, codec};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 1_048_576;
const CODEC_MAGIC: &[u8; 8] = b"A9MSG2\0\0";
const CODEC_VERSION: u16 = 2;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let _ = codec::deserialize::<Transaction>(data);

    let mut framed = Vec::with_capacity(CODEC_MAGIC.len() + 2 + data.len());
    framed.extend_from_slice(CODEC_MAGIC);
    framed.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    framed.extend_from_slice(data);
    let _ = codec::deserialize::<Transaction>(&framed);
});
