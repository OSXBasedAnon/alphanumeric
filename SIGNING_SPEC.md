# alphanumeric transaction signing spec

The network-facing key, address, message, and transaction encodings needed to
build and sign a transaction the network accepts — for web wallets, mobile
wallets, and exchange withdrawal signers. Pair this with `EXPLORER_API.md`
(which covers reading the chain and the `POST /explorer/submit-tx` endpoint).

This is a spec + test vectors, not a library. The signature scheme is a
standardized primitive with implementations in multiple ecosystems, so no code
from this repo is required to sign.

## Signature scheme

**ML-DSA-87 (FIPS 204)** — the NIST post-quantum lattice signature. Use any
conformant implementation, e.g. JavaScript/TypeScript `@noble/post-quantum`
(`ml_dsa87`), or a native FIPS 204 library. This node uses the RustCrypto
`ml-dsa` crate. Interoperability requires pure ML-DSA-87, the standard encoded
key/signature forms below, and an empty context string.

Sizes and encodings (all hex in the JSON are lowercase, unpadded byte hex):

| Item | Bytes | Notes |
|---|---|---|
| secret key (seed) | 32 | the ML-DSA **seed**; the signing key is derived from it |
| public (verifying) key | 2592 | standard FIPS 204 encoded verifying key |
| signature | 4627 | standard FIPS 204 encoded signature |

FIPS 204 permits randomized signatures and an optional deterministic variant.
The node accepts either when the signature is otherwise valid. The reference
client and the exact test vector below use the optional deterministic variant
with an empty context string.

## Keys

- **Secret key** is a 32-byte seed. Keep it on the client; it never leaves the
  device. The signing key is `ML-DSA-87.key_from_seed(seed)`.
- **Public key** is the encoded verifying key of that signing key (2592 bytes),
  hex-encoded into the transaction's `pub_key` field.
- An **address** is the lowercase hexadecimal encoding of the first 20 bytes of
  `SHA-256(encoded_public_key_bytes)`. It is therefore exactly 40 lowercase hex
  characters. Validate that the sender address supplied to a signer matches the
  public key before signing.

## The message that gets signed

The node verifies the signature over this exact byte string (UTF-8):

    {sender}:{recipient}:{amount}:{fee}:{timestamp}

with **amount and fee formatted to exactly 8 decimal places**, and timestamp as
a plain unsigned integer (unix seconds). Nothing else is included — not the
public key, not the sig_hash, not JSON. Colons separate the five fields.

- `sender`, `recipient`: exactly 40 lowercase ASCII hexadecimal characters,
  verbatim. Validate this before signing; never change case after constructing
  the signed message.
- `amount`, `fee`: decimal coin values, **always 8 fractional digits**
  (e.g. `1.5` → `1.50000000`, `0.001` → `0.00100000`). This is the one place to
  get exactly right — match the test vector byte-for-byte.
- `timestamp`: unix seconds, no padding.

## Signing steps

1. Build the message string above and encode it UTF-8.
2. Sign it with pure ML-DSA-87 and an empty context. Randomized and optional
   deterministic signing both verify; use deterministic mode to reproduce the
   exact vector below.
3. `sig_hash = SHA-256(encoded_signature_bytes)` — lowercase hex. This is the
   commitment to the signature bytes; include it.
4. Assemble the transaction JSON and POST it to `/explorer/submit-tx`:

   ```json
   {
     "sender": "<40-char lowercase hex address>",
     "recipient": "<40-char lowercase hex address>",
     "amount": 1.5,
     "fee": 0.001,
     "timestamp": 1783600000,
     "signature": "<9254-char lowercase hex signature>",
     "pub_key": "<5184-char lowercase hex public key>",
     "sig_hash": "<64-char lowercase hex SHA-256>"
   }
   ```

   The JSON `amount`/`fee` are ordinary decimal numbers; only the *signed
   message* uses the fixed 8-decimal string form. Quantize both values to integer
   atomic units first, then derive both representations from those same units.

## Choosing the fee

The fee is a **priority signal, not a fixed rate** — nodes enforce a relay
floor, so choose it deliberately:

- **Relay floor (policy): `0.0001`.** Nodes refuse to mempool or relay a
  transaction whose fee is below 0.0001 coins (`400 … below the relay floor`
  from submit-tx). This is relay policy, not consensus — but a below-floor
  transaction will not propagate, so treat it as a hard minimum.
- **Recommended policy:** query `GET /explorer/fee-estimate` on any node you
  already talk to and put its `recommended_fee` into the transaction's `fee`
  field. The reference wallet starts from the same number when `create` runs
  without `--fee`, but then clamps it below the whisper band for that amount
  (see the whisper note below) — so on small amounts the wallet may send
  slightly less than `recommended_fee`. Apply the same clamp if you do not want
  your payments displayed as messages. **The `fee` field on the wire is a decimal
  coin amount** (`"fee": 0.0002`); the `*_units` integers in the response are
  for exact accounting only (1 coin = 100,000,000 units), and putting `20000`
  in the `fee` field would sign a 20,000-coin fee. The estimate prices
  next-block inclusion off the live mempool: a flat `0.0002` anchor
  (`20,000` units, 2x the relay floor) on a quiet network, one unit above the
  marginal next-block fee under congestion, always clamped to the automatic
  ceiling of `0.002` (`200,000` units). Offline or estimator-unreachable
  fallback: use the `0.0002` anchor.

  Exchanges and payout processors may instead choose an explicit absolute fee
  for their batching policy. Explicit fees remain subject to current node
  admission and block-accounting policy; acceptance of one value does not imply
  that every larger value is accepted, nor does a larger fee guarantee a
  particular confirmation time.
- Whisper encodes a short message in the fee, and classification is **purely a
  fee-band test** — there is no flag and no marker. A fee is read as a whisper
  whenever `fee - amount * 0.000563063063` falls in `[0.0001, 0.01]`, and the
  reference client then decodes and displays a four-letter code.
  This band is wide enough to contain ordinary payments: the example transaction
  in this document (amount `1.5`, fee `0.001`) is inside it. If you are building
  a payer and do not want your transactions read as messages, keep the fee below
  `amount * 0.000563063063 + 0.0001`, which is what the reference wallet clamps
  an automatic fee to. Receivers must treat any such transaction as a payment
  first: the amount is authoritative, the decoded code is decoration.

## Test vector (verify your implementation against this)

Reference deterministic mode — your bytes must match exactly.

    secret key (seed), hex:
      0707070707070707070707070707070707070707070707070707070707070707

    sender:    9e1e860361994891b3165e611dc5aefcdd37dfbf
    recipient: 84dab431b53e6522fe2e74914eec99f17758f4e3
    amount:    1.5
    fee:       0.001
    timestamp: 1783600000

    signed message (exact string):
      9e1e860361994891b3165e611dc5aefcdd37dfbf:84dab431b53e6522fe2e74914eec99f17758f4e3:1.50000000:0.00100000:1783600000

    signed message, hex:
      396531653836303336313939343839316233313635653631316463356165666364643337646662663a383464616234333162353365363532326665326537343931346565633939663137373538663465333a312e35303030303030303a302e30303130303030303a31373833363030303030

    expected public key:  2592 bytes; SHA-256 =
      9e1e860361994891b3165e611dc5aefcdd37dfbf5f247943daaeb57141fe7b6e

    expected signature:   4627 bytes; SHA-256 (this is also sig_hash) =
      e3b8ce82ea7c02c008d89049aff56fa86f34d3320bae82ccf000279c74144339

The sender is NOT arbitrary: it is `hex(sha256(public_key)[..20])`, so it is the
first 40 hex characters of the public-key SHA-256 above. A node re-derives it and
rejects any transaction whose `sender` does not match its `pub_key`.

To validate your signer: derive the verifying key from the seed and confirm its
SHA-256 matches; derive the sender from it and confirm it matches; sign the
message and confirm the signature's SHA-256 matches. If all three match, your
implementation is byte-compatible with the network.

## Notes

- The submit endpoint runs the same validation the node applies to every
  transaction: signature over the message above, sender balance, replay guard,
  already-confirmed guard, and (network-side) rate limits. A wrong message
  format is rejected as `transaction signature is invalid or missing`.
- Quantize amounts to integer atomic units before signing. Do not submit more
  than eight decimal places or rely on language-specific floating-point
  rounding; sign the exact canonical eight-decimal value represented by those
  units.
- Use the current Unix timestamp close to submission. A transaction must be
  mined within 21,600 seconds (6 hours) of its signed timestamp. Pending
  retention defaults to 7,200 seconds (2 hours), so a valid transaction can
  return to `not_found` before its consensus freshness window ends; retry the
  identical signed transaction safely and handle that state explicitly.
- This document describes the current format; the node source
  (`Transaction::get_message`, `src/a9/mldsa.rs`) is the ultimate reference.
