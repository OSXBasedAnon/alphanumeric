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

Treat `already_pending` as success only when the `tx_id` matches the one you submitted. If
you intended a distinct payment, re-sign with a different timestamp (wait one second) or
vary the fee by one unit. Serialising withdrawals to one per second per (recipient, amount)
pair is the simplest correct policy.

### Queue limits

- **100 concurrently pending transactions per sender address** (`MEMPOOL_MAX_PER_ADDRESS`).
  A hot wallet is one address, so a burst of more than 100 queued withdrawals fails at the
  101st. Cap in-flight submissions below 100, or shard across several hot wallets.
- **2,000 submissions per 60 s per sender address.**
- No server-side way to query current mempool depth for your address. Track in-flight
  count client-side.

### Classifying failures

Backpressure returns **429** with a machine-readable reason. A **400** is terminal.

```json
429 {"error": "rate_limited", "reason": "mempool_full",
     "retryable": true, "retry_same_transaction": false, "detail": "..."}
```

| `reason` | `retry_same_transaction` | Action |
|---|---|---|
| `per_address_pending_cap` | `true` | back off, you are at the 100-pending cap |
| `per_sender_rate` | `true` | back off, per-sender submission rate |
| `mempool_full` | **`false`** | back off, then **re-sign at a higher fee** — eviction is fee-ordered and all-or-nothing, so resubmitting the identical transaction can never win a slot |

**Branch on `retry_same_transaction`, not on the reason string.** A 400
(`InsufficientFunds`, `InvalidTransactionSignature`, `FeeBelowRelayFloor`) is terminal.

Minimum relay fee is 10,000 units (0.0001 `ALPHA`). Minimum transfer is 564 units. Use
`/explorer/fee-estimate` rather than hardcoding.

### Fee band caution

Some historical fee values carry an encoding meaning in the reference wallet. Use the fee
returned by `/explorer/fee-estimate`, or the relay floor, and avoid choosing large
arbitrary fee values for ordinary withdrawals.

## Deposits

`/explorer/address/{addr}` returns confirmed ledger state.

**Use `spendable_units`, not `balance_units`.** `balance` is the raw confirmed ledger
total: it includes mining rewards that are still immature (coinbase maturity is **100
blocks**) and does not subtract in-flight mempool debits, so it can exceed what the address
can actually spend. `spendable` / `spendable_units` is confirmed minus pending debits minus
immature rewards, and is the number to credit a user against. It is `null` if it cannot be
computed.

**Check `history_available` before reading `transactions`.** The history is served off the
address index, which can be unbuilt or mid-rebuild after a bootstrap or re-index. When that
is the case `history_available` is `false` and `transactions` is **`null`** rather than an
empty array, so a scanner cannot mistake "index not ready" for "no deposits". Retry until
it is `true`, and also confirm freshness via `/explorer/status` (`blocks_behind`).

`GET` endpoints can return **503** under chain-lock contention during heavy sync or
indexing. A deposit scanner must treat non-200 as "retry", never as "no data", or it will
skip blocks.

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
| Block or deposit webhooks | **None** for exchanges. `ALPHANUMERIC_BLOCKNOTIFY` pushes tip changes to an external hook, intended for mining pools; poll `/explorer/status` otherwise. |
| HD derivation standard | **None** published. Post-quantum keys do not use BIP32-style derivation. |
| Multisig | **None.** |
