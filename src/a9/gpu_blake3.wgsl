// BLAKE3 header-PoW kernel for alphanumeric (gpu_miner feature).
//
// Hashes the FIXED 92-byte mining header with a per-thread nonce and reports
// the first nonce whose hash clears the difficulty target (leading zero bits).
//
// Header layout (all fields 4-byte aligned, little-endian words):
//   w0        index (u32)
//   w1..w8    previous_hash (32 bytes)
//   w9..w10   timestamp (u64 LE)
//   w11..w12  nonce (u64 LE)      <- per-thread
//   w13..w14  difficulty (u64 LE)
//   w15..w22  merkle_root (32 bytes)
// = 92 bytes -> BLAKE3 single chunk, two blocks:
//   block0 = w0..w15  (64 bytes, flags CHUNK_START)
//   block1 = w16..w22 (28 bytes zero-padded, flags CHUNK_END | ROOT)

const IV = array<u32, 8>(
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
);

const CHUNK_START: u32 = 1u;
const CHUNK_END: u32 = 2u;
const ROOT: u32 = 8u;

struct Params {
    header: array<vec4<u32>, 6>, // w0..w23 (w23 unused/zero)
    nonce_lo: u32,
    nonce_hi: u32,
    zero_bits: u32,
    batch: u32,
};

struct Result {
    found: atomic<u32>,
    nonce_lo: u32,
    nonce_hi: u32,
    _pad: u32,
    // Debug/self-check output: raw hash of thread 0's nonce when zero_bits is
    // the 0xFFFFFFFF sentinel. Lets tests compare the kernel against the CPU
    // blake3 crate byte-for-byte.
    hash: array<u32, 8>,
};

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> result: Result;

fn rotr(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32u - n));
}

// The BLAKE3 quarter-round on four state words, returned by value. WGSL/naga
// forbids indexing a function-local array with a runtime variable, so the state
// is held in 16 scalar `var`s and mixed via this pure helper (all array indexing
// stays compile-time constant).
fn g(a: u32, b: u32, c: u32, d: u32, mx: u32, my: u32) -> vec4<u32> {
    var ra = a; var rb = b; var rc = c; var rd = d;
    ra = ra + rb + mx;
    rd = rotr(rd ^ ra, 16u);
    rc = rc + rd;
    rb = rotr(rb ^ rc, 12u);
    ra = ra + rb + my;
    rd = rotr(rd ^ ra, 8u);
    rc = rc + rd;
    rb = rotr(rb ^ rc, 7u);
    return vec4<u32>(ra, rb, rc, rd);
}

// One BLAKE3 compression; returns the 8 output words (chaining value / root words).
// `block` is indexed only by CONSTANT literals (the message schedule permutation
// is unrolled), satisfying naga's constant-index rule.
fn compress(cv: array<u32, 8>, block: array<u32, 16>, block_len: u32, flags: u32) -> array<u32, 8> {
    var s0 = cv[0]; var s1 = cv[1]; var s2 = cv[2]; var s3 = cv[3];
    var s4 = cv[4]; var s5 = cv[5]; var s6 = cv[6]; var s7 = cv[7];
    var s8 = IV[0]; var s9 = IV[1]; var s10 = IV[2]; var s11 = IV[3];
    var s12 = 0u; var s13 = 0u; var s14 = block_len; var s15 = flags;

    // Message words permuted per round. Round 0 uses the block as-is; each later
    // round applies the fixed BLAKE3 permutation, unrolled into constant indices.
    var m0 = block[0]; var m1 = block[1]; var m2 = block[2]; var m3 = block[3];
    var m4 = block[4]; var m5 = block[5]; var m6 = block[6]; var m7 = block[7];
    var m8 = block[8]; var m9 = block[9]; var m10 = block[10]; var m11 = block[11];
    var m12 = block[12]; var m13 = block[13]; var m14 = block[14]; var m15 = block[15];

    var r: vec4<u32>;
    for (var round = 0u; round < 7u; round = round + 1u) {
        // Column step.
        r = g(s0, s4, s8, s12, m0, m1);   s0 = r.x; s4 = r.y; s8 = r.z; s12 = r.w;
        r = g(s1, s5, s9, s13, m2, m3);   s1 = r.x; s5 = r.y; s9 = r.z; s13 = r.w;
        r = g(s2, s6, s10, s14, m4, m5);  s2 = r.x; s6 = r.y; s10 = r.z; s14 = r.w;
        r = g(s3, s7, s11, s15, m6, m7);  s3 = r.x; s7 = r.y; s11 = r.z; s15 = r.w;
        // Diagonal step.
        r = g(s0, s5, s10, s15, m8, m9);   s0 = r.x; s5 = r.y; s10 = r.z; s15 = r.w;
        r = g(s1, s6, s11, s12, m10, m11); s1 = r.x; s6 = r.y; s11 = r.z; s12 = r.w;
        r = g(s2, s7, s8, s13, m12, m13);  s2 = r.x; s7 = r.y; s8 = r.z; s13 = r.w;
        r = g(s3, s4, s9, s14, m14, m15);  s3 = r.x; s4 = r.y; s9 = r.z; s14 = r.w;

        if (round < 6u) {
            // permutation: new[i] = old[SIGMA[i]]
            let n0 = m2;  let n1 = m6;  let n2 = m3;  let n3 = m10;
            let n4 = m7;  let n5 = m0;  let n6 = m4;  let n7 = m13;
            let n8 = m1;  let n9 = m11; let n10 = m12; let n11 = m5;
            let n12 = m9; let n13 = m14; let n14 = m15; let n15 = m8;
            m0 = n0; m1 = n1; m2 = n2; m3 = n3; m4 = n4; m5 = n5; m6 = n6; m7 = n7;
            m8 = n8; m9 = n9; m10 = n10; m11 = n11; m12 = n12; m13 = n13; m14 = n14; m15 = n15;
        }
    }

    var out: array<u32, 8>;
    out[0] = s0 ^ s8;  out[1] = s1 ^ s9;  out[2] = s2 ^ s10; out[3] = s3 ^ s11;
    out[4] = s4 ^ s12; out[5] = s5 ^ s13; out[6] = s6 ^ s14; out[7] = s7 ^ s15;
    return out;
}

// Leading zero bits of one hash word in canonical BYTE order (little-endian-first
// byte within the word). Returns (zero_bits, stopped): stopped=true once a nonzero
// byte is hit, so the caller stops accumulating.
fn word_leading_zeros(x: u32) -> vec2<u32> {
    var total = 0u;
    for (var b = 0u; b < 4u; b = b + 1u) {
        let byte = (x >> (b * 8u)) & 0xFFu;
        if (byte == 0u) {
            total = total + 8u;
        } else {
            return vec2<u32>(total + (countLeadingZeros(byte) - 24u), 1u);
        }
    }
    return vec2<u32>(total, 0u);
}

// Leading zero bits across the 8 hash words (constant-indexed, naga-safe).
fn leading_zero_bits(h: array<u32, 8>) -> u32 {
    var total = 0u;
    var r: vec2<u32>;
    r = word_leading_zeros(h[0]); total = total + r.x; if (r.y == 1u) { return total; }
    r = word_leading_zeros(h[1]); total = total + r.x; if (r.y == 1u) { return total; }
    r = word_leading_zeros(h[2]); total = total + r.x; if (r.y == 1u) { return total; }
    r = word_leading_zeros(h[3]); total = total + r.x; if (r.y == 1u) { return total; }
    r = word_leading_zeros(h[4]); total = total + r.x; if (r.y == 1u) { return total; }
    r = word_leading_zeros(h[5]); total = total + r.x; if (r.y == 1u) { return total; }
    r = word_leading_zeros(h[6]); total = total + r.x; if (r.y == 1u) { return total; }
    r = word_leading_zeros(h[7]); total = total + r.x;
    return total;
}

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x >= params.batch) { return; }
    if (atomicLoad(&result.found) != 0u) { return; }

    // 64-bit nonce = base + gid.x (manual carry).
    let lo = params.nonce_lo + gid.x;
    var hi = params.nonce_hi;
    if (lo < params.nonce_lo) { hi = hi + 1u; }

    // header words: header[0]=w0..3, [1]=w4..7, [2]=w8..11, [3]=w12..15,
    // [4]=w16..19, [5]=w20..23. Nonce occupies w11 (lo) and w12 (hi).
    let h0 = params.header[0]; let h1 = params.header[1]; let h2 = params.header[2];
    let h3 = params.header[3]; let h4 = params.header[4]; let h5 = params.header[5];

    // block0 = w0..w15, with w11=lo (nonce), w12=hi (nonce). Constant indices only.
    let block0 = array<u32, 16>(
        h0.x, h0.y, h0.z, h0.w,
        h1.x, h1.y, h1.z, h1.w,
        h2.x, h2.y, h2.z, lo,
        hi,   h3.y, h3.z, h3.w
    );
    // block1 = w16..w22 (28 bytes), zero-padded to 16 words.
    let block1 = array<u32, 16>(
        h4.x, h4.y, h4.z, h4.w,
        h5.x, h5.y, h5.z, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
    );

    let cv = array<u32, 8>(IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7]);
    let cv1 = compress(cv, block0, 64u, CHUNK_START);
    let root = compress(cv1, block1, 28u, CHUNK_END | ROOT);

    if (params.zero_bits == 0xFFFFFFFFu) {
        // Self-check mode: emit thread 0's raw hash, never "find" anything.
        if (gid.x == 0u) {
            result.hash[0] = root[0]; result.hash[1] = root[1];
            result.hash[2] = root[2]; result.hash[3] = root[3];
            result.hash[4] = root[4]; result.hash[5] = root[5];
            result.hash[6] = root[6]; result.hash[7] = root[7];
        }
        return;
    }

    if (leading_zero_bits(root) >= params.zero_bits) {
        if (atomicExchange(&result.found, 1u) == 0u) {
            result.nonce_lo = lo;
            result.nonce_hi = hi;
        }
    }
}
