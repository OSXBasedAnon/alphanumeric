# Pool payouts via coinbase rotation

Pools and mining farms traditionally collect every block reward into one wallet and then pay
their miners with ordinary on-chain transactions. On this chain those payout transactions are
the majority of all traffic — and every one of them costs bytes, a fee, and a payout pipeline
you have to operate.

Coinbase rotation deletes all of that. The node's miner can point **each mined block's reward
directly at the miner it is owed to**: your payout ledger becomes the block reward itself.
Zero extra transactions, zero bytes, zero fees, no payout pipeline. The coinbase recipient has
never been constrained by consensus (every node since genesis accepts blocks paying any
address), so this is purely a producer-side setting on your own machines.

**Strictly opt-in.** Without the environment variable below, the miner behaves byte-for-byte
exactly as it always has, paying the mining wallet.

## Enabling

```
export ALPHANUMERIC_COINBASE_PAYOUTS=/path/to/payouts.txt
```

Then mine as usual. The schedule is re-read at every block attempt, so you can update the
owed-list without restarting — write the file atomically (write a temp file, then rename it
over the old one) so the miner never reads a half-written edit.

## The schedule file

One recipient per line: a 40-hex address, optionally followed by an integer weight
(default 1). `#` starts a comment; blank lines are ignored.

```
# payouts.txt — shares owed this round
a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0 5    # rig-A, 5 shares
1111111111111111111111111111111111111111 3    # rig-B
2222222222222222222222222222222222222222      # rig-C, weight 1
```

Weights are share counts: over every full cycle of `total_weight` blocks, each address
receives exactly `weight` of the rewards. Repeating an address on multiple lines accumulates
its weight. Limits: at most 10,000 entries, and the total weight must fit the block-height
range (<= 4,294,967,295).

## How selection works (and why you can audit it)

The recipient for the block at height `H` is the owner of slot `H % total_weight` in the
file's cumulative weight table. That makes the rotation:

- **deterministic** — a pure function of the file and the height; restarts change nothing;
- **proportional** — exact weight shares over every full cycle, no randomness, no drift;
- **auditable** — every participant can recompute, from the published file and the chain
  itself, exactly which address every block at every height should have paid.

## Fail-closed by design

If the variable is set but the file is missing, unreadable, empty, malformed, over the entry
or weight limits — or the variable itself is not valid UTF-8 — the miner **refuses to mine**
with a clear error instead of silently falling back to the default wallet. A payout
misconfiguration is loud, never a quiet misdirection of funds. In continuous mode the miner
retries with backoff and stops after repeated failures.

## Operational notes

- **Maturity:** block rewards observe the standard 100-block maturity hold before they are
  spendable (roughly eight minutes at current cadence) — slightly later than a confirmed
  payout transaction would have been, in exchange for costing nothing.
- **Fees ride along:** the block's transaction fees are paid to the coinbase recipient. If
  your accounting separates fees from rewards, net them out in your share ledger.
- **Console display:** the interactive `mine` summary currently shows the operator wallet's
  balance after a solve; with rotation active the reward went to the schedule address — the
  chain ledger is authoritative.
- Addresses are accepted in either case and normalized to lowercase (the on-chain form).

## Example: a 200-miner payout round, before and after

Before: 200 payout transactions per round — bytes, fees, batching, retries, monitoring.

After: a `payouts.txt` with 200 lines and their share weights. The next 200 (weighted) blocks
each pay one owed miner directly. Your payout system is a text file.
