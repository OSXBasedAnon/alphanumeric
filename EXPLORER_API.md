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
| `/explorer/status` | node/chain status: version, network_id, height, `finalized_height` + `finality_margin` (see Finality below), index readiness |
| `/explorer/tip` | latest block, including display-form transactions |
| `/explorer/block/{height}` | full block at height (canonical) |
| `/explorer/tx/{height}/{position}` | one transaction by block height + position (includes `final`) |
| `/explorer/tx?id={tx_id}` | track one transaction by id: `confirmed` (with height, position, block_hash, confirmations, `final`, body), `pending` (in mempool), or 404 |
| `/explorer/address/{address}` | confirmed **balance** + paginated tx **history** |
| `/explorer/supply` | total confirmed positive balances, including immature mining rewards |
| `/explorer/fee-estimate` | advisory next-block fee recommendation priced off this node's live mempool (see Fees below) |

`/explorer/address/{address}` query params: `limit` (1–200, default 50) and a
`before_height` + `before_pos` cursor (pass both) for pagination. Response
includes `balance`, `balance_units` (exact integer string), and `transactions`.

Amounts appear both as a decimal `amount`/`balance` and an exact integer
`*_units` string — **use the `_units` integer for accounting**; the decimal is
for display (floats lose precision).

## Finality (for exchanges — credit deposits safely)

The chain finalizes history behind a trusted checkpoint: **blocks at or below
`finalized_height` cannot be reorged by this node** — a reorg at/below that height
is rejected outright. `finalized_height` trails the tip by `finality_margin`
(currently 64 blocks) and is monotonic (never regresses). It is **this node's own
view**: it advances both as the node observes signed network beacons *and* as the
node locally verifies frontier blocks that extend its own canonical tip.

- **`/explorer/status`** reports `finalized_height` and `finality_margin`.
- **`/explorer/tx?id=`** and **`/explorer/tx/{height}/{position}`** include a
  boolean **`final`** = (`height` ≤ `finalized_height`).

**Credit a deposit as irreversible when its `final` is `true` AND the node is
fresh.** `final` is a strong signal, but it reflects the finality of the chain
*this node is on*. A node that is eclipsed or on the losing side of a network
partition keeps advancing its own checkpoint on that minority chain, so it can
report `final: true` for a transaction the majority chain later reorgs away —
the one direction that costs an exchange money. Guard against it: only trust
`final` when `/explorer/status` shows healthy freshness (`network_height` present
and `blocks_behind` small, 0–1), and run your own well-connected node with a seed
peer configured. On a healthy, majority-connected node, once `final` is `true` it
never reverts.

**Reorg handling:** a transaction that is confirmed but not yet `final` can still
be reorged out. When that happens `/explorer/tx?id=` moves `confirmed → pending`
(it is returned to the mempool for re-mining) or `404`, and `confirmations` can
decrease. **Always re-poll; never cache a one-time `confirmed`.**

## Submit a transaction (POST /explorer/submit-tx)

Body: a signed transaction as JSON. Read responses are display-oriented
(`from`/`to`) and are not valid submit payloads; construct this client-side
shape explicitly:

```json
{
  "sender": "<40-char lowercase hex address>",
  "recipient": "<40-char lowercase hex address>",
  "amount": 1.5,
  "fee": 0.001,
  "timestamp": 1783600000,
  "signature": "<hex ML-DSA-87 signature>",
  "pub_key": "<hex ML-DSA public key>",
  "sig_hash": "<hex>"
}
```

The `fee` is a priority signal with a **relay floor of 0.0001 coins** — lower
fees are rejected at admission (`400 … below the relay floor`). For ordinary
payments, query **`GET /explorer/fee-estimate`** and put its **`recommended_fee`**
value in the transaction's `fee` field — the same recommendation the reference
wallet uses when `create` is run without `--fee`.

> **The wire `fee` field is a decimal coin amount, not units.** Send
> `"fee": 0.0002`. The `*_units` integers in the estimate response are for exact
> accounting only (1 coin = 100,000,000 units); putting `20000` in the `fee`
> field would sign a **20,000-coin** fee.

The estimate prices next-block inclusion off the node's live mempool against the
exact template-selection rules:

- quiet network (capacity absorbs the backlog *and* your transaction): a flat
  anchor of `0.0002` coins (`20,000` units, 2x the relay floor — strictly ahead
  of floor-paying bulk templates);
- congested: one unit above the weakest fee that still fits the next block;
- always clamped to the automatic ceiling of `0.002` coins (`200,000` units).
  Only an explicitly chosen fee may exceed it, up to the reference wallet's
  `0.01` explicit ceiling.

Response fields: `recommended_fee`/`recommended_fee_units`,
`anchor_fee`/`anchor_fee_units`, `floor_fee`/`floor_fee_units`,
`auto_cap_fee`/`auto_cap_fee_units`, `explicit_cap_fee`/`explicit_cap_fee_units`,
`congested`, `pending_candidates`, `next_block_fits`, and `basis` (`"quiet"` or
`"next-block"`). Offline fallback: use the `0.0002` anchor. Exchange withdrawal
systems may instead choose an absolute fee appropriate to their batching and
service policy, subject to current node admission and block-accounting rules.
Miners can use fees to prioritize transactions when blocks are contested, but
paying far above the recommendation does not guarantee a particular confirmation
time.

Submission is idempotent: retrying the identical signed transaction cannot
create a second payment, and a processed duplicate is reported explicitly.

**The inverse is the hazard.** Transaction identity is
`sender:recipient:amount:fee:timestamp` at one-second granularity, with no nonce, so two
GENUINELY DISTINCT payments that share all five fields are the same transaction and only
one of them happens. `already_pending` therefore means *either* your own retry *or* a
second payment that collided. Compare the returned `tx_id` against the one you submitted,
and give a distinct payment a distinct timestamp or fee. See
[docs/EXCHANGE_INTEGRATION.md](docs/EXCHANGE_INTEGRATION.md#two-distinct-payments-can-silently-become-one).
Retries can still receive transient `429` or `503` responses:

    200  {"ok": true, "status": "accepted",         "tx_id": "<opaque id>"}   admitted; announcement scheduled
    200  {"ok": true, "status": "already_pending",  "tx_id": "<opaque id>"}   identical tx already in mempool
    200  {"ok": true, "status": "already_confirmed","tx_id": "<opaque id>",
          "height": <n>, "final": <bool>}                               already in a block
    400  {"error": "transaction rejected: <reason>"}    failed validation
    422  (malformed JSON body)
    429  {"error": "rate_limited"}
    503  {"error": "chain busy, retry shortly"}         chain lock contended

A withdrawal worker should treat `accepted` / `already_confirmed` as success, retry on
`503`, and back off on `429`.

Two `400`s are NOT terminal, so do not page on `400` alone. Rate-limit rejections arrive
as `400` with a `Rate limit exceeded: ...` message and mean back off, not fail:

    ... Too many transactions from this address   at the 100-pending-per-address cap
    ... Too many requests                          per-sender submission rate
    ... Mempool is full                            back off, then RE-SIGN AT A HIGHER FEE
                                                   (retrying the identical tx cannot succeed)

Genuinely terminal `400`s are `FeeBelowRelayFloor`, `InsufficientFunds` and
`InvalidTransactionSignature`. Treat `already_pending` as success only when the returned
`tx_id` matches the one you submitted — see the duplicate-identity note above.

On `accepted`, the node has admitted the tx to its mempool (after full signature,
balance, replay, and already-confirmed checks) and scheduled its network
announcement. It is then eligible for miner consideration. There is no separate
confirmation step; poll
`/explorer/tx?id=` with the returned `tx_id` (it reports `pending` then
`confirmed` with a rising `confirmations` count), or watch `/explorer/address`
for the sender/recipient, to see it land in a block.

Treat the returned `tx_id` as an opaque string, not a hex digest. URL-encode it
when passing it to `/explorer/tx?id=...`; its current representation contains
transaction fields and separators and may change independently of API clients.

### Signing (client side — you build this)

Transactions are signed with **ML-DSA-87 (FIPS 204)**, a standardized
post-quantum signature with implementations in multiple ecosystems (e.g.
`@noble/post-quantum`'s `ml_dsa87` in JS/TS) — so no code from this repo is
needed. A wallet must sign **client-side** so the private key never leaves the
device.

**See [`SIGNING_SPEC.md`](SIGNING_SPEC.md)** for the exact signed-message format,
key/signature encodings, and a deterministic test vector to validate your
implementation byte-for-byte. In short: sign the UTF-8 string
`sender:recipient:amount:fee:timestamp` (amount/fee at 8 decimals) with
ML-DSA-87, then POST the transaction JSON to `/explorer/submit-tx`.

This repo intentionally ships no wallet UI. The signing spec defines the
network-facing key, address, message, and transaction encodings an integration
must reproduce.

## Notes for exchanges

See [docs/EXCHANGE_INTEGRATION.md](docs/EXCHANGE_INTEGRATION.md) for asset identity
(ticker, decimals, network id), the scheduled consensus activations, withdrawal queue
limits, deposit-scanner pitfalls, and node operational requirements.

- Run a dedicated node with the API enabled behind your own proxy/auth.
- Deposits: watch `/explorer/address/{your_deposit_addrs}` (balance + history),
  or scan blocks via `/explorer/block/{height}`.
- Withdrawals: sign server-side (HSM/keystore) and POST to `/explorer/submit-tx`.
- Always reconcile with `*_units` integers, and wait the confirmations your risk
  model requires (the node advances a finality checkpoint behind the tip).
