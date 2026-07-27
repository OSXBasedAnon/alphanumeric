**Alphanumeric v7.9.1 — nodes can no longer get permanently stuck**

Reliability release. No change to block validity rules, wire format, or network
compatibility — 7.9.1 and 7.9.0 nodes stay on the same chain and can be upgraded
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
- Mining: faster hash loop, real MH/s in the progress bar, and you're told when a
  block you mined gets reorged out.

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

### Download (macOS, Apple Silicon)
Standard: `alphanumeric-v7.9.1-macos-arm64.zip`
GPU: `alphanumeric-v7.9.1-gpu-macos-arm64.zip`

### Artifacts + checksums
- `alphanumeric-v7.9.1-macos-arm64.zip`
  - `73d254f8ffc9218beba0381d25f892034102e037c6bb360241130a60ca2d8e1d`
- `alphanumeric-v7.9.1-gpu-macos-arm64.zip`
  - `6b2d810a158db54b9e1398a06465aae4e957e04c8d002cf24abcf72a8132e036`

Source build commands:
- Standard: `git checkout main && cargo build --release`
- GPU: `git checkout gpu-mining && cargo build --release --features gpu_miner`

GitHub tag placeholder:
https://github.com/OSXBasedAnon/alphanumeric/releases/tag/v7.9.1
