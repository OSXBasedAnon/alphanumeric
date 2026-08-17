**Alphanumeric v8.0.0 — new storage engine, smaller bootstrap, optional upgrade**

Version 8.0.0 replaces the node's embedded database (`sled` → `redb`). **Block
validity rules do not change.** 8.0.0 and 7.9.x nodes stay on the same chain and
accept each other's blocks, so there is no activation height and no deadline —
upgrade whenever suits you.

### What changes for you
- Bootstrap download drops from ~170 MB to ~100 MB, and from ~1.9 GB across 70
  files to a single ~1.1 GB `chain.redb`.
- Faster commits, steadier disk usage under sustained load, instant startup after
  heavy write periods.
- Block feed limit rises 1 MB → 2 MB, roughly doubling sustained throughput.
  Producer-side only; not a consensus change.

### Operator action
- Replace the binary and restart. Confirm it reports version 8.0.0 and the banner
  reads `Database: redb`.
- It fetches a current bootstrap in the new format on first start. Wallet keys,
  node identity, and configuration are untouched.
- Your data folder is unchanged: `blockchain.db` stays a directory, with
  `chain.redb` inside it.
- The old engine's files are left in place, so downgrading is just running the
  old binary. Delete everything in `blockchain.db` except `chain.redb` once you
  are satisfied.

### New for pools (opt-in)
The miner can pay each block's reward straight to the participant owed it, using
a weighted schedule file — replacing batch payout transactions entirely. Off
unless you set `ALPHANUMERIC_COINBASE_PAYOUTS`. Guide: `docs/POOL_PAYOUTS.md`.

Source builds now require rustc 1.89 or newer (`rustup update`). No new system
dependencies — still pure Rust, so Linux and Windows build from the tag as before.

macOS release artifacts and SHA-256 checksums are published from the reviewed
v8.0.0 tag.
