# alphanumeric transaction signing spec

Everything a wallet needs to build and sign a transaction that the network
accepts — for web wallets, mobile wallets, exchange withdrawal signers, in any
language. Pair this with `EXPLORER_API.md` (which covers reading the chain and
the `POST /explorer/submit-tx` endpoint you send the signed result to).

This is a spec + test vectors, not a library. The signature scheme is a
standards-track primitive with existing implementations in most languages, so
no code from this repo is required to sign.

## Signature scheme

**ML-DSA-87 (FIPS 204)** — the NIST post-quantum lattice signature. Use any
conformant implementation, e.g. JavaScript/TypeScript `@noble/post-quantum`
(`ml_dsa87`), or a native FIPS 204 library. This node uses the RustCrypto
`ml-dsa` crate; any FIPS 204 ML-DSA-87 implementation is interoperable.

Sizes and encodings (all hex in the JSON are lowercase, unpadded byte hex):

| Item | Bytes | Notes |
|---|---|---|
| secret key (seed) | 32 | the ML-DSA **seed**; the signing key is derived from it |
| public (verifying) key | 2592 | standard FIPS 204 encoded verifying key |
| signature | 4627 | standard FIPS 204 encoded signature |

Signatures are **deterministic**: signing the same message with the same key
always yields the identical bytes. (This is what makes the test vector below an
exact check.)

## Keys

- **Secret key** is a 32-byte seed. Keep it on the client; it never leaves the
  device. The signing key is `ML-DSA-87.key_from_seed(seed)`.
- **Public key** is the encoded verifying key of that signing key (2592 bytes),
  hex-encoded into the transaction's `pub_key` field.
- An **address** is derived from the public key elsewhere in the wallet; a
  sending wallet already holds the address/pubkey pair, so address derivation is
  not needed just to sign. (Addresses are the 40-hex strings you see in the
  explorer.)

## The message that gets signed

The node verifies the signature over this exact byte string (UTF-8):

    {sender}:{recipient}:{amount}:{fee}:{timestamp}

with **amount and fee formatted to exactly 8 decimal places**, and timestamp as
a plain unsigned integer (unix seconds). Nothing else is included — not the
public key, not the sig_hash, not JSON. Colons separate the five fields.

- `sender`, `recipient`: the 40-hex address strings, verbatim.
- `amount`, `fee`: decimal coin values, **always 8 fractional digits**
  (e.g. `1.5` → `1.50000000`, `0.001` → `0.00100000`). This is the one place to
  get exactly right — match the test vector byte-for-byte.
- `timestamp`: unix seconds, no padding.

## Signing steps

1. Build the message string above and encode it UTF-8.
2. `signature = ML-DSA-87.sign(seed, message)` (deterministic).
3. `sig_hash = SHA-256(signature_bytes)` — hex. (A compact identifier the
   mempool uses; include it.)
4. Assemble the transaction JSON and POST it to `/explorer/submit-tx`:

       {
         "sender":    "<40-hex>",
         "recipient": "<40-hex>",
         "amount":    1.5,          // decimal coins (JSON number)
         "fee":       0.001,
         "timestamp": 1783600000,
         "signature": "<hex, 4627 bytes>",
         "pub_key":   "<hex, 2592 bytes>",
         "sig_hash":  "<hex, sha256(signature)>"
       }

   Note the JSON `amount`/`fee` are ordinary decimal numbers; only the *signed
   message* uses the fixed 8-decimal string form.

## Test vector (verify your implementation against this)

Deterministic — your bytes must match exactly.

    secret key (seed), hex:
      0707070707070707070707070707070707070707070707070707070707070707

    sender:    072a2799e9cda5eab68c64a15e71246ae4d3f11e
    recipient: 84dab431b53e6522fe2e74914eec99f17758f4e3
    amount:    1.5
    fee:       0.001
    timestamp: 1783600000

    signed message (exact string):
      072a2799e9cda5eab68c64a15e71246ae4d3f11e:84dab431b53e6522fe2e74914eec99f17758f4e3:1.50000000:0.00100000:1783600000

    signed message, hex:
      303732613237393965396364613565616236386336346131356537313234366165346433663131653a383464616234333162353365363532326665326537343931346565633939663137373538663465333a312e35303030303030303a302e30303130303030303a31373833363030303030

    expected public key:  2592 bytes; SHA-256 =
      9e1e860361994891b3165e611dc5aefcdd37dfbf5f247943daaeb57141fe7b6e

    expected signature:   4627 bytes; SHA-256 (this is also sig_hash) =
      87dc974f04d6ec612bd801b6e1bfda2fd838f15c04269dc4701e954babfd91a2

To validate your signer: derive the verifying key from the seed and confirm its
SHA-256 matches; sign the message and confirm the signature's SHA-256 matches.
If both match, your implementation is byte-compatible with the network.

## Notes

- The submit endpoint runs the same validation the node applies to every
  transaction: signature over the message above, sender balance, replay guard,
  already-confirmed guard, and (network-side) rate limits. A wrong message
  format is rejected as `transaction signature is invalid or missing`.
- Amounts overflowing 8 decimals or non-canonical formatting will change the
  signed bytes and fail verification — always format to exactly 8 places.
- This document describes the current format; the node source
  (`Transaction::get_message`, `src/a9/mldsa.rs`) is the ultimate reference.
