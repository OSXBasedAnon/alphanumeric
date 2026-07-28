**Alphanumeric v7.9.2 — nodes can no longer get permanently stuck**

Supersedes v7.9.1 (same day — three more client fixes landed right after
tagging; if you grabbed 7.9.1, take this instead). No change to block validity rules, wire format, or network
compatibility — 7.9.2, 7.9.1 and 7.9.0 nodes stay on the same chain and can be upgraded
in any order. **Recommended for every node.**

### The main fix
A node only stops re-verifying a block's full witnesses once that block falls
below its verification floor — and that floor only advances when the node
*applies* a block. So a node that couldn't apply one specific block (its
witnesses unobtainable from any peer) deadlocked: it needed to apply the block to
advance the floor, and needed the floor to advance to apply the block. In the
wild that looked like a node frozen at one height for 80+ minutes while the
network moved on.

It now breaks out using the signed tip beacon — the same key that signs the
bootstrap manifest every node already trusts — and recovers on its own in about
90 seconds to 5 minutes. Finality can't move nearer the tip than the normal reorg
margin, can't regress, and PoW/hash/linkage checks all still apply.

### Also fixed
- Nodes no longer publish witness-short blocks that poison a relay height for
  everyone else.
- Waking a client after a long idle no longer says "restart this node" — it heals
  in place.
- Timed-out peer requests can no longer desync a pooled connection.
- Background tasks survive panics instead of vanishing silently.
- Faster catch-up and start-up; ~13x fewer database flushes per block.
- Payments returned to the mempool by a reorg are no longer lost on restart.
- **A client closed for hours now catches up instead of giving up.** Deep
  catch-up was demanding witnesses that no longer exist on any peer, so it
  crawled, stalled, and eventually closed the client — leaving "delete the chain
  and start over" as the only real fix. Those spans are now pulled in one piece
  and verified end-to-end against the signed tip beacon before anything is
  applied.
- Peer block-range request handling is bounded in one more place — no behaviour
  change for normal peers, but a reason to take this release.
- Building a full block template is ~800x faster (62ms -> 74us at 4,000
  transactions). Same transactions chosen; the equivalence is tested bit-for-bit.
- Mining: faster hash loop, real MH/s in the progress bar, and you're told when a
  block you mined gets reorged out.

### Before block 517,583 (~9 August)
The already-scheduled fee-accounting activation starts at that height. Nothing
changes before it, and nothing in this release changes it — but **upgrade before
then**. Upgraded miners just build slightly smaller blocks; a miner left on older
software can produce a block upgraded nodes reject, which is the only thing that
would split the network. One note: a whisper on a very large transfer (~1,290
coins or more) will stop sending from that height, because a whisper's fee scales
with the amount sent. Ordinary whispers are nowhere near this.

### Also fixed after 7.9.1
- Reopening a client after hours away no longer says "cannot mine" — it reports
  how far behind it is and starts on its own (and no longer discards a good local
  chain on the next launch).
- The prompt no longer swallows the command you type after mining ends.
- Sync status is one updating line, not a wall of text.

### Wallet
- An incoming payment now shows in `balance`, not only in `history` — reported
  below the confirmed line and never added into it, since an unmined credit is
  not yours yet.
- `history [rows]` (1-50) is now documented; the default 12 read as the whole
  ledger. `help` also labels its columns, so it is clear which side you type.
- Inbound notices stop flooding a busy node: a person sees exactly what they saw
  before, while a pool or exchange gets one digest line per block instead of one
  per payment. Whispers are never folded in.

### Interface
- One display language across every screen — balances, wallets, mining,
  transactions and `info` now share the same layout, colours and spacing.
- Addresses and transaction ids render in your terminal's own foreground colour,
  so they're readable on light backgrounds too.
- Payment / whisper / reorg notices are aligned keyword lines with no symbols.
- Whisper send no longer claims "visible to everyone" — nothing displays whispers
  anywhere; the accurate caveat stays on the help screen.

### On alphanumeric.blue
- The hashrate beside the chart and the one in the metrics row now always agree
  (they were computed differently and could sit a spike apart). The chart still
  plots the raw per-sample series.
- The chart no longer re-animates while you scroll on a phone. Mobile Safari
  fires a resize whenever the address bar hides or reappears; it now redraws only
  when the width genuinely changes. Rotating still works, animation unchanged.

### Download (macOS, Apple Silicon)
Standard: `alphanumeric-v7.9.2-macos-arm64.zip`
GPU: `alphanumeric-v7.9.2-gpu-macos-arm64.zip`

### Artifacts + checksums
- `alphanumeric-v7.9.2-macos-arm64.zip`
  - `4684396880ea63a66f8ef20862554febbad660e45a0be6a98f9dd419a98b8307`
- `alphanumeric-v7.9.2-gpu-macos-arm64.zip`
  - `97a4d6391185a3c2b07f33876486d1399a63fbef73e3dddb9adb88fe508e1259`

Source build commands:
- Standard: `git checkout main && cargo build --release`
- GPU: `git checkout gpu-mining && cargo build --release --features gpu_miner`

GitHub tag placeholder:
https://github.com/OSXBasedAnon/alphanumeric/releases/tag/v7.9.2
