# alphanumeric v7.9.2

Reliability release, and it **supersedes v7.9.1** — same day, three further
client fixes found immediately after tagging. If you grabbed 7.9.1, take this
instead. **No change to block validity rules** — nothing about which blocks are
valid changes, so 7.9.2, 7.9.1 and 7.9.0 nodes stay on the same chain and can be
upgraded in any order. macOS (Apple Silicon) prebuilt below; Linux/Windows/
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

7.9.2 breaks the cycle with the signed tip beacon: if the local tip has not moved
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
- **A client closed for hours now catches up instead of giving up.** Peers keep
  full witnesses only for the most recent stretch of chain, but deep catch-up was
  demanding them for every block — including thousands whose witnesses no longer
  exist anywhere. It crawled through empty blocks, stalled on the first block
  containing a payment, and eventually closed the client outright, so the only
  practical fix was deleting the chain and starting over. Such spans are now
  pulled in one proven piece, verified end-to-end against the signed tip beacon
  down to the block you already hold, and applied the same way a fresh snapshot
  is. Nothing is applied until the whole span checks out.
- **Peer request handling hardened.** Block-range requests from peers are
  bounded in one more place. No behaviour change for normal peers, and no change
  to what any node accepts as valid — but it is a reason to take this release
  rather than stay where you are.
- **Block template building no longer slows down as the block fills.** Selecting
  transactions re-checked the whole selected set for every further candidate, so
  the cost grew with the square of the template size. It now carries running
  totals: assembling a 4,000-transaction template drops from ~62 ms to ~74 µs.
  The transactions chosen are unchanged — the equivalence is pinned by tests that
  compare the two paths bit-for-bit rather than approximately. This matters from
  block 517,583, where that check starts running.

## Interface
- **One display language across every screen.** Balances, wallets, mining,
  transactions, `info` and the boot sequence now share a single layout system —
  consistent columns, consistent colour meaning, consistent spacing — instead of
  each screen having grown its own conventions.
- **Readable on any terminal.** Anything you might retype or compare — addresses,
  transaction ids — now renders in your terminal's own foreground colour rather
  than a fixed grey that was unreadable on a light background.
- **Chain-event notices rewritten.** Incoming payments, whispers and reorg
  notices are now aligned keyword lines (`received`, `whisper`, `reorged`) with
  no symbols, so they line up and read the same as the rest of the client.
- **A block you mined that gets reorged out is now reported**, instead of the
  maturing reward quietly disappearing from your balance.
- **Whisper send no longer claims "visible to everyone."** Nothing displays
  whispers anywhere; the accurate caveat (decodable from the ledger by someone
  looking, so don't put anything sensitive in one) stays on the help screen.

## On alphanumeric.blue
- The hashrate shown beside the chart and the hashrate in the metrics row above
  it now always agree. They were computed differently — one showed the newest raw
  sample, the other a median of the recent window — so they could sit a spike
  apart. The chart itself still plots the raw per-sample series, bursts included.

## Fixed after 7.9.1 (this release)
- **Reopening a client after hours away no longer refuses to mine.** If catch-up
  could not finish inside one prep window — the normal case for a client that has
  been closed a while, or at startup before peers finish connecting — `mine`
  reported "cannot mine right now" and stopped, *and* scheduled a re-bootstrap
  that discarded a perfectly good local chain on the next launch. Being behind is
  not being diverged: it now reports how far behind it is and starts mining by
  itself once the chain is current.
- **The prompt no longer swallows your next command.** `mine --continuous` parks
  a thread on stdin for its Enter-to-stop, and when mining ended any other way
  that thread was still holding the terminal — so the next command went to it
  instead of the prompt and came back as "invalid command" with the cursor
  misplaced, needing a restart. Lines typed after mining ends are now handed back
  to the prompt and run normally.
- **Sync status is a single updating line** instead of a new line every few
  seconds burying the screen during a long catch-up.

## Heads-up for block 517,583 (~9 August)

Nothing below changes now, and nothing in this release changes it — this is what
the already-scheduled fee-accounting activation does when the chain reaches that
height. It is here because 7.9.2 is what most nodes will be running by then.

- **Upgrade before that height.** From 517,583 a block's *total* fees must stay
  within the scheduled allowance. An upgraded miner simply builds a slightly
  smaller block and is never affected. A miner still on older software can build
  a block that upgraded nodes reject — that, and only that, is what would split
  the network. Every node agreeing on the rule means no split at all.
- **A whisper on a very large transfer will stop sending.** A whisper carries its
  message in the fee, and that fee includes a component proportional to the
  amount sent, so a whisper on roughly 1,290 coins or more exceeds the per-block
  allowance on its own and is declined at submission. Ordinary whispers are far
  below this and are unaffected. Splitting a large transfer, or sending it
  without a whisper, both work normally.

## Install / verify
- **Standard**: use `alphanumeric-v7.9.2-macos-arm64.zip`
- **GPU mining (opt-in)**: use `alphanumeric-v7.9.2-gpu-macos-arm64.zip`
- **Signature model / protocol** unchanged; no protocol migration.
- Upgrading is a drop-in binary replacement: no database migration, no resync.

## Artifacts
| file | sha256 |
|---|---|
| alphanumeric-v7.9.2-macos-arm64.zip | `65ca4372eb0f1b5318774308d94a66f6b57dffe24b5c02acc1398970334bbe26` |
| alphanumeric-v7.9.2-gpu-macos-arm64.zip (opt-in GPU mining) | `7407c3de4ba1f9fd2afbcd4be237dfd6cb69ce7210d0ad8e98a1fd935f1cde6a` |

## Notes
- Build verification source: `cargo build --release` on `main`, and
  `cargo build --release --features gpu_miner` on `gpu-mining`.
- Version in this repo is `7.9.2`; this release uses the existing macOS packaging
  layout from prior releases.
