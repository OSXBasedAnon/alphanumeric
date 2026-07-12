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
    threads: u32, // number of GPU threads dispatched
    iters: u32,   // nonces each thread tests (throughput: amortizes readback)
    _pad: u32,
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
// FULLY UNROLLED: all 7 rounds are written out with the message-schedule
// permutation COMPOSED into constant indices (Alephium-miner style register
// renaming) instead of a runtime loop that physically shuffles m0..m15 through
// 16 lets per round. naga lowers every WGSL for-loop to a while(true)+bool-gate
// pattern in which no backend compiler can recover the trip count, so the
// rolled loop's ~96 moves/compression + loop overhead were REAL on every
// backend — measured +48% kernel throughput on Metal from this change alone
// (2026-07-12 variant bench; byte-exact vs the blake3 crate throughout).
// `block` is indexed only by CONSTANT literals, satisfying naga's rule.
fn compress(cv: array<u32, 8>, block: array<u32, 16>, block_len: u32, flags: u32) -> array<u32, 8> {
    var s0 = cv[0]; var s1 = cv[1]; var s2 = cv[2]; var s3 = cv[3];
    var s4 = cv[4]; var s5 = cv[5]; var s6 = cv[6]; var s7 = cv[7];
    var s8 = IV[0]; var s9 = IV[1]; var s10 = IV[2]; var s11 = IV[3];
    var s12 = 0u; var s13 = 0u; var s14 = block_len; var s15 = flags;
    let m0 = block[0];
    let m1 = block[1];
    let m2 = block[2];
    let m3 = block[3];
    let m4 = block[4];
    let m5 = block[5];
    let m6 = block[6];
    let m7 = block[7];
    let m8 = block[8];
    let m9 = block[9];
    let m10 = block[10];
    let m11 = block[11];
    let m12 = block[12];
    let m13 = block[13];
    let m14 = block[14];
    let m15 = block[15];
    var r: vec4<u32>;
    // round 0
    r = g(s0, s4, s8, s12, m0, m1); s0 = r.x; s4 = r.y; s8 = r.z; s12 = r.w;
    r = g(s1, s5, s9, s13, m2, m3); s1 = r.x; s5 = r.y; s9 = r.z; s13 = r.w;
    r = g(s2, s6, s10, s14, m4, m5); s2 = r.x; s6 = r.y; s10 = r.z; s14 = r.w;
    r = g(s3, s7, s11, s15, m6, m7); s3 = r.x; s7 = r.y; s11 = r.z; s15 = r.w;
    r = g(s0, s5, s10, s15, m8, m9); s0 = r.x; s5 = r.y; s10 = r.z; s15 = r.w;
    r = g(s1, s6, s11, s12, m10, m11); s1 = r.x; s6 = r.y; s11 = r.z; s12 = r.w;
    r = g(s2, s7, s8, s13, m12, m13); s2 = r.x; s7 = r.y; s8 = r.z; s13 = r.w;
    r = g(s3, s4, s9, s14, m14, m15); s3 = r.x; s4 = r.y; s9 = r.z; s14 = r.w;
    // round 1
    r = g(s0, s4, s8, s12, m2, m6); s0 = r.x; s4 = r.y; s8 = r.z; s12 = r.w;
    r = g(s1, s5, s9, s13, m3, m10); s1 = r.x; s5 = r.y; s9 = r.z; s13 = r.w;
    r = g(s2, s6, s10, s14, m7, m0); s2 = r.x; s6 = r.y; s10 = r.z; s14 = r.w;
    r = g(s3, s7, s11, s15, m4, m13); s3 = r.x; s7 = r.y; s11 = r.z; s15 = r.w;
    r = g(s0, s5, s10, s15, m1, m11); s0 = r.x; s5 = r.y; s10 = r.z; s15 = r.w;
    r = g(s1, s6, s11, s12, m12, m5); s1 = r.x; s6 = r.y; s11 = r.z; s12 = r.w;
    r = g(s2, s7, s8, s13, m9, m14); s2 = r.x; s7 = r.y; s8 = r.z; s13 = r.w;
    r = g(s3, s4, s9, s14, m15, m8); s3 = r.x; s4 = r.y; s9 = r.z; s14 = r.w;
    // round 2
    r = g(s0, s4, s8, s12, m3, m4); s0 = r.x; s4 = r.y; s8 = r.z; s12 = r.w;
    r = g(s1, s5, s9, s13, m10, m12); s1 = r.x; s5 = r.y; s9 = r.z; s13 = r.w;
    r = g(s2, s6, s10, s14, m13, m2); s2 = r.x; s6 = r.y; s10 = r.z; s14 = r.w;
    r = g(s3, s7, s11, s15, m7, m14); s3 = r.x; s7 = r.y; s11 = r.z; s15 = r.w;
    r = g(s0, s5, s10, s15, m6, m5); s0 = r.x; s5 = r.y; s10 = r.z; s15 = r.w;
    r = g(s1, s6, s11, s12, m9, m0); s1 = r.x; s6 = r.y; s11 = r.z; s12 = r.w;
    r = g(s2, s7, s8, s13, m11, m15); s2 = r.x; s7 = r.y; s8 = r.z; s13 = r.w;
    r = g(s3, s4, s9, s14, m8, m1); s3 = r.x; s4 = r.y; s9 = r.z; s14 = r.w;
    // round 3
    r = g(s0, s4, s8, s12, m10, m7); s0 = r.x; s4 = r.y; s8 = r.z; s12 = r.w;
    r = g(s1, s5, s9, s13, m12, m9); s1 = r.x; s5 = r.y; s9 = r.z; s13 = r.w;
    r = g(s2, s6, s10, s14, m14, m3); s2 = r.x; s6 = r.y; s10 = r.z; s14 = r.w;
    r = g(s3, s7, s11, s15, m13, m15); s3 = r.x; s7 = r.y; s11 = r.z; s15 = r.w;
    r = g(s0, s5, s10, s15, m4, m0); s0 = r.x; s5 = r.y; s10 = r.z; s15 = r.w;
    r = g(s1, s6, s11, s12, m11, m2); s1 = r.x; s6 = r.y; s11 = r.z; s12 = r.w;
    r = g(s2, s7, s8, s13, m5, m8); s2 = r.x; s7 = r.y; s8 = r.z; s13 = r.w;
    r = g(s3, s4, s9, s14, m1, m6); s3 = r.x; s4 = r.y; s9 = r.z; s14 = r.w;
    // round 4
    r = g(s0, s4, s8, s12, m12, m13); s0 = r.x; s4 = r.y; s8 = r.z; s12 = r.w;
    r = g(s1, s5, s9, s13, m9, m11); s1 = r.x; s5 = r.y; s9 = r.z; s13 = r.w;
    r = g(s2, s6, s10, s14, m15, m10); s2 = r.x; s6 = r.y; s10 = r.z; s14 = r.w;
    r = g(s3, s7, s11, s15, m14, m8); s3 = r.x; s7 = r.y; s11 = r.z; s15 = r.w;
    r = g(s0, s5, s10, s15, m7, m2); s0 = r.x; s5 = r.y; s10 = r.z; s15 = r.w;
    r = g(s1, s6, s11, s12, m5, m3); s1 = r.x; s6 = r.y; s11 = r.z; s12 = r.w;
    r = g(s2, s7, s8, s13, m0, m1); s2 = r.x; s7 = r.y; s8 = r.z; s13 = r.w;
    r = g(s3, s4, s9, s14, m6, m4); s3 = r.x; s4 = r.y; s9 = r.z; s14 = r.w;
    // round 5
    r = g(s0, s4, s8, s12, m9, m14); s0 = r.x; s4 = r.y; s8 = r.z; s12 = r.w;
    r = g(s1, s5, s9, s13, m11, m5); s1 = r.x; s5 = r.y; s9 = r.z; s13 = r.w;
    r = g(s2, s6, s10, s14, m8, m12); s2 = r.x; s6 = r.y; s10 = r.z; s14 = r.w;
    r = g(s3, s7, s11, s15, m15, m1); s3 = r.x; s7 = r.y; s11 = r.z; s15 = r.w;
    r = g(s0, s5, s10, s15, m13, m3); s0 = r.x; s5 = r.y; s10 = r.z; s15 = r.w;
    r = g(s1, s6, s11, s12, m0, m10); s1 = r.x; s6 = r.y; s11 = r.z; s12 = r.w;
    r = g(s2, s7, s8, s13, m2, m6); s2 = r.x; s7 = r.y; s8 = r.z; s13 = r.w;
    r = g(s3, s4, s9, s14, m4, m7); s3 = r.x; s4 = r.y; s9 = r.z; s14 = r.w;
    // round 6
    r = g(s0, s4, s8, s12, m11, m15); s0 = r.x; s4 = r.y; s8 = r.z; s12 = r.w;
    r = g(s1, s5, s9, s13, m5, m0); s1 = r.x; s5 = r.y; s9 = r.z; s13 = r.w;
    r = g(s2, s6, s10, s14, m1, m9); s2 = r.x; s6 = r.y; s10 = r.z; s14 = r.w;
    r = g(s3, s7, s11, s15, m8, m6); s3 = r.x; s7 = r.y; s11 = r.z; s15 = r.w;
    r = g(s0, s5, s10, s15, m14, m10); s0 = r.x; s5 = r.y; s10 = r.z; s15 = r.w;
    r = g(s1, s6, s11, s12, m2, m12); s1 = r.x; s6 = r.y; s11 = r.z; s12 = r.w;
    r = g(s2, s7, s8, s13, m3, m4); s2 = r.x; s7 = r.y; s8 = r.z; s13 = r.w;
    r = g(s3, s4, s9, s14, m7, m13); s3 = r.x; s4 = r.y; s9 = r.z; s14 = r.w;

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
    if (gid.x >= params.threads) { return; }

    // header words: header[0]=w0..3, [1]=w4..7, [2]=w8..11, [3]=w12..15,
    // [4]=w16..19, [5]=w20..23. Nonce occupies w11 (lo) and w12 (hi).
    let h0 = params.header[0]; let h1 = params.header[1]; let h2 = params.header[2];
    let h3 = params.header[3]; let h4 = params.header[4]; let h5 = params.header[5];
    let cv = array<u32, 8>(IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7]);

    // block1 is nonce-independent (w16..w22); build once per thread.
    let block1 = array<u32, 16>(
        h4.x, h4.y, h4.z, h4.w,
        h5.x, h5.y, h5.z, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
    );

    // Self-check: emit thread 0's raw hash for the exact base nonce, then stop.
    if (params.zero_bits == 0xFFFFFFFFu) {
        if (gid.x == 0u) {
            let block0 = array<u32, 16>(
                h0.x, h0.y, h0.z, h0.w, h1.x, h1.y, h1.z, h1.w,
                h2.x, h2.y, h2.z, params.nonce_lo, params.nonce_hi, h3.y, h3.z, h3.w
            );
            let cv1 = compress(cv, block0, 64u, CHUNK_START);
            let root = compress(cv1, block1, 28u, CHUNK_END | ROOT);
            result.hash[0] = root[0]; result.hash[1] = root[1];
            result.hash[2] = root[2]; result.hash[3] = root[3];
            result.hash[4] = root[4]; result.hash[5] = root[5];
            result.hash[6] = root[6]; result.hash[7] = root[7];
        }
        return;
    }

    // THROUGHPUT: this thread tests `iters` consecutive nonces. One dispatch thus
    // covers threads*iters nonces per GPU->CPU readback, amortizing the sync that
    // capped a one-nonce-per-thread kernel at ~0.8 GH/s. Offset = gid.x*iters + i
    // stays < 2^32 per dispatch (caller bounds threads*iters), so a single u32
    // add-with-carry onto the 64-bit base is exact.
    let thread_base = gid.x * params.iters;
    for (var i = 0u; i < params.iters; i = i + 1u) {
        // Cheap early-out so a found block ends the batch fast (checked per-iter,
        // it is a uniform-ish atomic read — negligible next to a BLAKE3 double
        // compression).
        if ((i & 63u) == 0u && atomicLoad(&result.found) != 0u) { return; }

        let offset = thread_base + i;
        let lo = params.nonce_lo + offset;
        var hi = params.nonce_hi;
        if (lo < params.nonce_lo) { hi = hi + 1u; }

        let block0 = array<u32, 16>(
            h0.x, h0.y, h0.z, h0.w,
            h1.x, h1.y, h1.z, h1.w,
            h2.x, h2.y, h2.z, lo,
            hi,   h3.y, h3.z, h3.w
        );
        let cv1 = compress(cv, block0, 64u, CHUNK_START);
        let root = compress(cv1, block1, 28u, CHUNK_END | ROOT);

        if (leading_zero_bits(root) >= params.zero_bits) {
            if (atomicExchange(&result.found, 1u) == 0u) {
                result.nonce_lo = lo;
                result.nonce_hi = hi;
            }
            return;
        }
    }
}
