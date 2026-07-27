# alphanumeric v7.9.1

Reliability release. **No change to block validity rules** — nothing about which
blocks are valid changes, so 7.9.1 and 7.9.0 nodes stay on the same chain and can
be upgraded in any order. macOS (Apple Silicon) prebuilt below; Linux/Windows/
other platforms build from source.

**Recommended for every node.** The headline fix ends a state in which a node
could stop following the chain until it was manually restarted.

## The main fix: a node could get permanently stuck

A node verifies recent blocks against full ML-DSA witnesses and only stops doing
so once a block falls below its *verification floor*. That floor comes from the
node's own trusted checkpoint — which only advances when the node **applies** a
block. So a node that could not apply one particular block, because that block's
witnesses were unobtainable from any peer, deadlocked: the block stayed above its
floor forever, so it kept demanding witnesses for it forever, long after the rest
of the network had buried it. It needed to apply the block to advance the floor,
and needed the floor to advance to apply the block. Seen in the wild as a node
frozen at a single height for 80+ minutes while the network ran on without it.

7.9.1 breaks the cycle with the signed tip beacon: if the local tip has not moved
for 90 seconds and the beacon is more than the reorg margin ahead, the node
advances its checkpoint from the beacon and applies the blocked block from its
receipt — exactly as it already trusts the history inside a bootstrap snapshot.
This grants no new authority: the beacon is signed by the same key as the
bootstrap manifest every node already receipt-trusts. It can never bring finality
nearer the tip than the normal reorg margin, checkpoint advancement stays
monotonic so finality cannot regress, and proof-of-work, hash, parent-linkage and
genesis pinning are all still enforced. Recovery is automatic in roughly 90
seconds to 5 minutes instead of never.

## Also fixed
- **The relay no longer gets poisoned with unverifiable blocks.** A node whose
  stored copy of a block had lost its full witnesses would still publish that
  witness-short body to the relay, where it squatted the height (first write
  wins) and wedged every node that later had to verify it. Nodes now decline to
  publish in that case — a gap is recoverable, a poisoned height is not.
- **Waking from sleep no longer demands a restart.** A client left idle past the
  reorg window used to answer `mine` with "chain diverged … restart this node".
  It now heals in place by pulling the gap from a peer.
- **Peer requests are cancellation-safe.** A timed-out request could leave a
  pooled connection out of step so later requests read the previous reply — the
  source of stray "unexpected response type" failures.
- **Background tasks survive panics.** Load-bearing loops are supervised and
  restart; the rest report loudly instead of disappearing silently.
- **Faster catch-up, lighter steady state:** larger block batches, no redundant
  re-hashing of downloaded blocks, fewer duplicate beacon fetches, and one
  database flush per applied block instead of roughly thirteen.
- **Reorg-reverted payments survive.** A transaction returned to the mempool by a
  reorg is now persisted, so it is no longer lost on the next restart or wallet
  command.
- **Mining:** the per-nonce clock call is gone from the hash loop (free
  throughput), the progress bar reports true aggregate hashrate in MH/s, and a
  block that gets reorged out is reported instead of the reward quietly
  vanishing.
- **Faster start-up:** boot no longer rescans the whole chain to find its tip.

## Install / verify
- **Standard**: use `alphanumeric-v7.9.1-macos-arm64.zip`
- **GPU mining (opt-in)**: use `alphanumeric-v7.9.1-gpu-macos-arm64.zip`
- **Signature model / protocol** unchanged; no protocol migration.
- Upgrading is a drop-in binary replacement: no database migration, no resync.

## Artifacts
| file | sha256 |
|---|---|
| alphanumeric-v7.9.1-macos-arm64.zip | `73d254f8ffc9218beba0381d25f892034102e037c6bb360241130a60ca2d8e1d` |
| alphanumeric-v7.9.1-gpu-macos-arm64.zip (opt-in GPU mining) | `6b2d810a158db54b9e1398a06465aae4e957e04c8d002cf24abcf72a8132e036` |

## Notes
- Build verification source: `cargo build --release` on `main`, and
  `cargo build --release --features gpu_miner` on `gpu-mining`.
- Version in this repo is `7.9.1`; this release uses the existing macOS packaging
  layout from prior releases.
