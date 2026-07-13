# alphanumeric node API (explorer + transaction submit)

A read-only chain API plus a transaction-submit endpoint, for building explorers,
web wallets, and exchange integrations **on top of a node you run**. It is
**opt-in**: a node serves this only when started with `ALPHANUMERIC_EXPLORER_API`.
The public gateway (alphanumeric.blue) and the reference publisher do NOT run it,
and enabling it changes no consensus or network behavior — submit-tx reuses the
same validation and gossip path the built-in `create` command uses.

## Enabling

    ALPHANUMERIC_EXPLORER_API=8787 ./alphanumeric          # bind 127.0.0.1:8787
    ALPHANUMERIC_EXPLORER_API=0.0.0.0:8787 ./alphanumeric  # all interfaces (put a
                                                           # reverse proxy in front)

It binds loopback by default. The API is unauthenticated and serves public chain
data; if you expose it publicly, front it with your own proxy (TLS, auth on
submit-tx, rate limits). The node already applies a coarse submit-tx flood guard
and a per-sender mempool rate limit, but a public deployment should add its own.

## Read endpoints (GET)

| Endpoint | Returns |
|---|---|
| `/explorer/status` | node/chain status: version, network_id, height, index readiness |
| `/explorer/tip` | latest block header |
| `/explorer/block/{height}` | full block at height (canonical) |
| `/explorer/tx/{height}/{position}` | one transaction by block height + position |
| `/explorer/tx?id={tx_id}` | track one transaction by id: `confirmed` (with height, position, block_hash, confirmations, body), `pending` (in mempool), or 404 |
| `/explorer/address/{address}` | confirmed **balance** + paginated tx **history** |
| `/explorer/supply` | circulating supply |

`/explorer/address/{address}` query params: `limit` (1–200, default 50) and a
`before_height` + `before_pos` cursor (pass both) for pagination. Response
includes `balance`, `balance_units` (exact integer string), and `entries`.

Amounts appear both as a decimal `amount`/`balance` and an exact integer
`*_units` string — **use the `_units` integer for accounting**; the decimal is
for display (floats lose precision).

## Submit a transaction (POST /explorer/submit-tx)

Body: a signed transaction as JSON. Same shape the read endpoints return:

    {
      "sender":    "<40-hex address>",
      "recipient": "<40-hex address>",
      "amount":    1.5,                 // decimal coins
      "fee":       0.001,
      "timestamp": 1783600000,          // unix seconds
      "signature": "<hex ML-DSA-87 signature>",
      "pub_key":   "<hex ML-DSA public key>",
      "sig_hash":  "<hex>"
    }

Responses:

    200  {"ok": true, "tx_id": "<hex>"}                 accepted + broadcast
    400  {"error": "transaction rejected: <reason>"}    failed validation
    422  (malformed JSON body)
    429  {"error": "rate_limited"}
    503  {"error": "node busy"}                         chain lock contended

On `200` the node has admitted the tx to its mempool (after full signature,
balance, replay, and already-confirmed checks) and announced it to the network —
any miner can now include it. There is no separate confirmation step; poll
`/explorer/tx?id=` with the returned `tx_id` (it reports `pending` then
`confirmed` with a rising `confirmations` count), or watch `/explorer/address`
for the sender/recipient, to see it land in a block.

### Signing (client side — you build this)

Transactions are signed with **ML-DSA-87 (FIPS 204)**, a standards-track
post-quantum signature with existing libraries in most languages (e.g.
`@noble/post-quantum`'s `ml_dsa87` in JS/TS) — so no code from this repo is
needed. A wallet must sign **client-side** so the private key never leaves the
device.

**See [`SIGNING_SPEC.md`](SIGNING_SPEC.md)** for the exact signed-message format,
key/signature encodings, and a deterministic test vector to validate your
implementation byte-for-byte. In short: sign the UTF-8 string
`sender:recipient:amount:fee:timestamp` (amount/fee at 8 decimals) with
ML-DSA-87, then POST the transaction JSON to `/explorer/submit-tx`.

This repo intentionally ships no wallet UI — the spec is everything the
community needs to build one.

## Notes for exchanges

- Run a dedicated node with the API enabled behind your own proxy/auth.
- Deposits: watch `/explorer/address/{your_deposit_addrs}` (balance + history),
  or scan blocks via `/explorer/block/{height}`.
- Withdrawals: sign server-side (HSM/keystore) and POST to `/explorer/submit-tx`.
- Always reconcile with `*_units` integers, and wait the confirmations your risk
  model requires (the node advances a finality checkpoint behind the tip).
