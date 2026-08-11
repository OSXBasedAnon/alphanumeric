# Exchange integration

Companion to [`EXPLORER_API.md`](../EXPLORER_API.md), which documents the endpoints, the
finality model, and the signing contract. This file covers what a listing team and a
withdrawal engineer need that the endpoint reference does not: asset identity, the
scheduled consensus activations, the failure modes that cost money, and the operational
shape of running a node.

## Asset identity

| Field | Value |
|---|---|
| Asset name | alphanumeric |
| Ticker | `ALPHA` |
| Display glyph | `♦` |
| Decimals | 8 |
| Smallest unit | 1 `ALPHA` = 100,000,000 units |
| Address format | 40 lowercase hex characters, `SHA256(public_key)[..20]` |
| Network id | `66b401a212ee9cddab38ff73176a3eeca1733ac81a912376b63aa11afdd1e78c` |
| Signature scheme | ML-DSA-87 (post-quantum), signature 4,627 B, public key 2,592 B |
| Target block time | 5 s (measured ~5.4 s) |
| Finality margin | 64 blocks (~6 min) |

`network_id` is the launch genesis hash and is served by `/explorer/status`. Verify it on
connect: it is the only field that distinguishes this chain from a fork or a testnet that
shares the same address and transaction format.

Amounts appear twice in every response: a decimal string (`amount`) and an exact integer
(`amount_units`). **Reconcile on `*_units` only.** The decimal form exists for display.

## Scheduled consensus activations

Both are compiled into the binary. There is nothing to configure; you need the right
release before the height arrives.

| Height | ~Date | Change | Minimum release |
|---:|---|---|---|
| 517,583 | 2026-08-10 | Fee accounting arms: block-level net-issuance cap | v7.9.3 |
| 569,423 | 2026-08-13 | Reward curve V2: a block carrying transactions no longer pays less than an empty one | **v7.9.4** |

A node older than the required release computes a different coinbase from that height and
stops following the chain. Build from the release tag, not from `main`.

Between 517,583 and 569,423 the fee-accounting baseline uses a compatibility envelope, so
blocks carrying many minimum-fee transactions can be rejected with
`FeeAccountingLimitExceeded`. This affects miners building templates, not exchanges
submitting transactions.

## Withdrawals

### Two distinct payments can silently become one

Transaction identity is `sender:recipient:amount:fee:timestamp` with the timestamp at
**one-second granularity**. There is no nonce or sequence number.

So two genuinely separate withdrawals with the same sender, recipient, amount and fee,
signed within the same second, are **the same transaction**. The second is absorbed as a
duplicate and only one payment happens.

The node tells you, but not with an error:

```json
200  {"ok": true, "status": "already_pending",
      "hint": "identical transaction already pending; a distinct payment must differ in timestamp, amount, or fee"}
```

**A worker that checks only the HTTP status and `ok` will record two successful payouts
and send one.** Branch on `status`:

| `status` | Meaning |
|---|---|
| `accepted` | new transaction admitted |
| `already_pending` | **either** your own retry, **or** a distinct payment that collided |
| `already_confirmed` | already mined |

`already_pending` means the node already holds a transaction with your exact five identity
fields. It **cannot** tell you whether that is your own retry or a colliding second payment,
and comparing the returned `tx_id` does not help: `get_tx_id` is a pure function of the five
fields you just posted, so the returned id always equals the one you submitted — and a
collision is by definition two payments whose five fields are identical, which is precisely
when the ids match.

The defence has to be client-side. **Reserve the 5-tuple (sender, recipient, amount, fee,
timestamp) in your own store before signing**, and refuse to issue a second withdrawal that
reuses one. If `already_pending` comes back for a 5-tuple you have not previously submitted,
treat it as a COLLISION: do not mark the withdrawal paid — re-sign with a different
timestamp (wait one second) or vary the fee by one unit. Serialising withdrawals to one per
second per (recipient, amount) pair is the simplest correct policy.

### Queue limits

- **100 concurrently pending transactions per sender address** (`MEMPOOL_MAX_PER_ADDRESS`).
  A hot wallet is one address, so a burst of more than 100 queued withdrawals fails at the
  101st. Cap in-flight submissions below 100, or shard across several hot wallets.
- **100 submissions per 60 s per sender address** — 1.67 tx/s sustained. (Raised to 2,000
  on `main`; not in any released binary, so size your hot wallet against 100.)
- The submit endpoint is additionally fronted by a **node-wide** token bucket: 5
  submissions/s sustained, burst 20, shared across every sender regardless of the
  per-sender limit. Exceeding it returns `429 {"error": "rate_limited"}`. This, not the
  per-sender limit, is the ceiling on sustained submission throughput against one node.
- No server-side way to query current mempool depth for your address. Track in-flight
  count client-side.

### Classifying failures

On the current release **every** admission rejection — retryable backpressure included — is
returned as HTTP **400** with a single human-readable string:

```json
400 {"error": "transaction rejected: Rate limit exceeded: Too many transactions from this address"}
```

**A 400 is therefore NOT automatically terminal.** Match on the message text:

| Message contains | Retryable | Action |
|---|---|---|
| `Rate limit exceeded: Too many transactions from this address` | yes | at the 100-pending cap; back off, resend the same signed transaction |
| `Rate limit exceeded: Too many requests` | yes | per-sender submission rate; back off, resend the same signed transaction |
| `Rate limit exceeded: Mempool is full` | no | **re-sign at a higher fee** — eviction is fee-ordered and all-or-nothing, so resubmitting the identical transaction can never win a slot |
| `Insufficient funds`, `signature is invalid or missing`, `fee below the relay floor`, `amount is invalid or negative` | no | terminal — alert |

A **429** `{"error": "rate_limited"}` is also possible. It comes from the node-wide
submission token bucket (5/s sustained, burst 20) shared by all senders, carries no reason
field, and is always retryable.

Malformed requests are rejected by the HTTP layer before the handler runs and return PLAIN
TEXT, not JSON: `400` for a JSON syntax error, `415` for a missing/wrong `Content-Type`,
`422` for well-formed JSON that is not a transaction. Key off `Content-Type` — only a `400`
whose body parses as `{"error": "transaction rejected: …"}` came from validation.

> **Coming in the next release:** a structured `429` carrying `reason` / `retryable` /
> `retry_same_transaction`, so you can branch on a field instead of a string. Implemented on
> `main`, NOT in the current release — do not code against it yet. A client that matches the
> strings above and also tolerates the structured form upgrades without a redeploy.

Minimum relay fee is 10,000 units (0.0001 `ALPHA`). Minimum transfer is 564 units. Use
`/explorer/fee-estimate` rather than hardcoding.

### Fee band caution

Some historical fee values carry an encoding meaning in the reference wallet. Use the fee
returned by `/explorer/fee-estimate`, or the relay floor, and avoid choosing large
arbitrary fee values for ordinary withdrawals.

## Deposits

`/explorer/address/{addr}` returns confirmed ledger state.

The current release returns exactly these fields: `address`, `balance`, `balance_units`,
`index_ready`, `index_height`, `summary`, `transactions`, `next`.

**`balance_units` is the raw confirmed ledger total.** It includes mining rewards that are
still immature (coinbase maturity is **100 blocks**) and does not subtract in-flight mempool
debits, so it can exceed what the address can actually spend. For a deposit address that
never mines and that you never spend from concurrently, it is safe to credit against. For
any address you also withdraw from, subtract your own in-flight debits client-side.

> **Coming in the next release:** a precomputed `spendable` / `spendable_units` pair
> (confirmed minus pending debits minus immature rewards, `null` when it cannot be
> computed). Implemented on `main`, NOT in the current release.

**Check `index_ready` before trusting `transactions`.** The history is served off the
address index, which can be unbuilt or mid-rebuild after a bootstrap or re-index. On the
current release `transactions` is **always an array**, and an unbuilt index yields an
**empty array indistinguishable from "no deposits"** — so a scanner must refuse to conclude
anything from an empty `transactions` unless `index_ready` is `true`. Retry until it is, and
also confirm freshness via `/explorer/status` (`blocks_behind`).

> **Coming in the next release:** a `history_available` flag, with `transactions` served as
> `null` rather than an empty array when the index is not ready, so the two cases cannot be
> confused. Implemented on `main`, NOT in the current release.

`GET` endpoints can return **503** under chain-lock contention during heavy sync/indexing
(`{"error":"chain busy, retry shortly"}`) or when storage/index data cannot be read
(`{"error":"storage_unavailable"}`). A deposit scanner must treat either response as
"retry/alert", never as "no data", or it can skip deposits or accept a false zero.

Credit rules and reorg handling are covered in
[`EXPLORER_API.md`](../EXPLORER_API.md#finality-for-exchanges--credit-deposits-safely).

## Running a node

**The node deliberately terminates itself and must run under a supervisor.** Several
recovery paths call `exit(3)` expecting an external supervisor to restart the process, for
example when the local chain has fallen too far behind to catch up incrementally and needs
to re-bootstrap. Under `nohup` or a bare container with no restart policy, the node stays
down. Use systemd, Docker `restart: always`, launchd `KeepAlive`, or equivalent.

Storage notes:

- The database never shrinks. Deleted data is not reclaimed, and a re-bootstrapped
  database carries permanent import overhead.
- There is no prune mode and no compaction command. Provision for monotonic growth and
  re-bootstrap from a snapshot if a node's database becomes unwieldy.
- Bootstrap downloads a signed snapshot; check
  `https://alphanumeric.blue/api/bootstrap/manifest` for the current size before
  provisioning.

Bind the API to loopback and put your own auth in front of it. It has no authentication of
its own.

## Capabilities this chain does not have

| Capability | Status |
|---|---|
| Memo / destination tag | **None.** Use one deposit address per user; there is no shared-address tagging. |
| Batch withdrawal (one transaction, many recipients) | **None.** Send N separate transactions; the miner template drains many transactions per sender per block, so this works, subject to the 100-pending cap. |
| Fee bump / RBF | **None.** A stuck transaction is replaced by signing a distinct one (different timestamp or fee). |
| Mempool acceptance query | **None.** Submission response is the acceptance signal. |
| Block or deposit webhooks | No per-address webhooks and no outbound HTTP from the node. There IS a tip push: `ALPHANUMERIC_BLOCKNOTIFY="/path/to/script %s %h"` runs your command on every new tip (`%s` hash, `%h` height) — Bitcoin Core's `-blocknotify` contract. When a program path or argument contains spaces, use structured argv, for example `ALPHANUMERIC_BLOCKNOTIFY_ARGV='["C:\\Program Files\\Pool\\notify.exe","%s","%h"]'`; it takes precedence over the legacy variable and still executes directly without a shell. Built for pools, but it suits a deposit scanner just as well: trigger a block-walk on the hook instead of polling `/explorer/tip`. Single-flight, coalesces under load, killed after 10 s. |
| HD derivation standard | **None** published. Post-quantum keys do not use BIP32-style derivation. |
| Multisig | **None.** |
