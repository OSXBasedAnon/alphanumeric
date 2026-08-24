# alphanumeric v8.0.1

Reliability and operator-experience release on top of 8.0.0. **No change to
block validity rules** — 8.0.1, 8.0.0, and 7.9.x nodes stay on the same chain,
follow each other, and accept each other's blocks. Drop-in binary replacement:
no database migration, no wallet migration, no resync.

## What you get

- **`contacts` — an address book you never fill in.** Derived from your own
  transaction history in one bounded scan, sorted most active first, with a
  zero-state screen that explains itself. `send` and `history` understand the
  names it shows.
- **A help screen you can scan.** Rebuilt layout: named columns, tightened
  spacing, section rules instead of rails, and the `-c` short form documented.
- **Status output that tells the truth.** Recovery explains the restore instead
  of alarming; the boot spinner speaks operator vocabulary rather than module
  names; catch-up refusals name the reason instead of failing silently.
- **Lookup correctness.** A confirmed transaction is never reported unknown
  while the index rebuilds, and the supply estimate is keyed on the
  balances-height marker with a writer generation fence, so it can neither
  double-count nor go stale.
- **Steadier under stress.** One sync stall costs one reset instead of a
  self-sustaining storm, and the boot/runtime heal window no longer has a dead
  band between what boot keeps and what runtime can repair.
- **Clean shutdown.** SIGTERM terminates the node instead of being absorbed at
  the interactive prompt, and an orderly stop or in-place restart no longer
  prints a spurious error from an in-flight catch-up batch.
- **Consensus encoding pinned.** The serialization crates are pinned exactly and
  the encoding is held by golden-byte tests; size-constant relationships and
  wire variant names are guarded so a refactor cannot silently change the wire.
- **Warning-free source builds on Windows.**

## GPU mining build

The GPU backend continues to live on the `gpu-mining` branch and ships as a
separate `-gpu` artifact. The 8.0.1 GPU build mines on the GPU by default
(`--cpu` opts out) and additionally carries the compact block relay (v2), a
transport-only bandwidth reduction with no consensus impact. Build from source
with `cargo build --release --features gpu_miner` on that branch. Guide:
`docs/GPU_MINING.md` (gpu-mining branch).

## Operator action

Replace the binary and restart. Confirm the process reports version `8.0.1`.
Wallet keys, node identity, configuration, and the chain database are untouched.

## Building from source

Unchanged from 8.0.0: rustc 1.89 or newer, no system dependencies beyond the
Rust toolchain.

## Notes

There is no wallet migration, no transaction-format change, and no
network-message change. Release artifacts and their SHA-256 checksums must be
generated from the reviewed `8.0.1` tag; checksums from earlier releases do not
apply.

---

# alphanumeric v8.0.0

Storage engine release. The node's embedded database moves from `sled` to
`redb`. **No change to block validity rules** — 8.0.0 and 7.9.x nodes stay on
the same chain, follow each other, accept each other's blocks, and can be
upgraded in any order and at any pace. There is no activation height and no
deadline.

The chain data itself is unchanged. What changes is the file format it is
stored in locally, and the size of what you download to get started.

## What you get

- **Bootstrap downloads are roughly 40% smaller** — about 100 MB instead of
  about 170 MB — and extract to a single database file of about 1.1 GB instead
  of about 1.9 GB spread over 70 files.
- **Faster and steadier writes.** Commits are quicker, and the disk footprint no
  longer grows well beyond the data it holds during sustained activity.
- **Instant startup after heavy write periods**, where the previous engine could
  spend seconds reopening its files.
- The database is a single file, `chain.redb`, which makes backups, copies, and
  disk accounting straightforward.

## Operator action

Replace the binary and restart. Confirm the process reports version `8.0.0` and
that the startup banner reads `Database: redb`.

On first start, the node fetches a current bootstrap in the new format and
resumes normally; a node that prefers to sync from peers instead may do so. Your
wallet keys, node identity, and configuration are untouched — those files are
separate from the chain database and are read exactly as before.

Your data folder keeps the same name and location. `blockchain.db` remains a
directory; the new engine stores `blockchain.db/chain.redb` inside it. Set
`ALPHANUMERIC_DB_PATH` exactly as before if you use a custom location.

**The previous engine's files are left in place, untouched.** That is deliberate:
until you delete them, downgrading is nothing more than running the old binary
again. Once you are satisfied with 8.0.0, you can reclaim that space by deleting
everything in `blockchain.db` except `chain.redb`.

Operators who would rather convert an existing database in place than download a
bootstrap can build with `--features sled-convert` and run
`alphanumeric convert-sled-db <old-db-dir> <new-db-dir>`. Conversion verifies
every record it writes and leaves the source database untouched.

## Building from source

Source builds now require **rustc 1.89 or newer**. An older toolchain stops with
a clear message from cargo rather than producing a binary; run `rustup update` if
you see it. There is no new system dependency — the new engine is pure Rust, so
Linux and Windows builds still need nothing beyond the Rust toolchain.

## Block capacity

The block feed limit rises from 1 MB to 2 MB, roughly doubling sustained
transaction throughput. This is a producer-side limit on how much a node feeds
into the blocks it builds; it is not a consensus change, and blocks from any
version remain valid to every version. Fees, the fee estimator, and per-sender
mempool limits are unchanged in behaviour.

## Pool payouts without payout transactions (opt-in)

The miner can now pay each block's reward directly to the participant it is owed
to, replacing batched payout transactions entirely. Set
`ALPHANUMERIC_COINBASE_PAYOUTS` to a file of addresses and share weights; the
recipient for each block is a deterministic, auditable function of the file and
the block height. Misconfiguration refuses to mine rather than quietly paying the
wrong address.

**This is off unless you set that variable**, and with it unset the miner behaves
exactly as it always has. Full guide: `docs/POOL_PAYOUTS.md`.

## Notes

There is no wallet migration, no transaction-format change, and no
network-message change. Release artifacts and their SHA-256 checksums must be
generated from the reviewed `8.0.0` tag; checksums from earlier releases do not
apply.

---

# alphanumeric v7.9.4

Scheduled consensus compatibility release. Reward accounting V2 activates at
block `569,423`. Miners, pools, public nodes, and other validating operators must
upgrade before that height.

## Operator action

- Upgrade every block-producing or validating deployment before block `569,423`.
- Confirm the process reports version `7.9.4` after restart.
- Compare the announced consensus fingerprint across upgraded peers during the
  rollout.
- Do not run an older miner past the activation boundary.

Blocks below the activation height retain the existing rules exactly. At and
above the activation height, compatible nodes use the updated reward-accounting
rules. This release also makes mining-template fee aggregation identical to the
consensus path and advertises advisory activation metadata through peer
announcements.

There is no database migration, wallet migration, resync, transaction-format
change, or network-message change. Release artifacts and their SHA-256 checksums
must be generated from the reviewed `7.9.4` tag; checksums from earlier releases
do not apply.

---

# alphanumeric v7.9.3

Security and hardening release, following a full audit of the node. **No change
to block validity rules** — nothing about which blocks or transactions are valid
changes, so 7.9.3, 7.9.2, 7.9.1 and 7.9.0 nodes stay on the same chain and can be
upgraded in any order. macOS (Apple Silicon) prebuilt below; Linux/Windows/other
platforms build from source.

**Recommended for every node**, and the sooner the better: the headline fix
closes a way for one message to silence another, and it protects a node from the
moment that node upgrades — it does not need anyone else to upgrade first.

## The main fix: a verdict could answer for something it never saw

The node remembers whether it has already judged a block or a transaction, so a
second copy of the same thing costs nothing to dismiss. Those memories were filed
under an identifier that does not pin the contents: two different messages could
share one, and the verdict recorded for the first could then be handed back for
the second.

Both directions were wrong. A rejected copy could stand in for the legitimate
message sharing its identifier and suppress it for up to an hour — a block
stalling on that node, or a payment quietly dropped before it was ever examined.
In the other direction, an acceptance could wave through bytes nothing had
verified.

Verdicts are now filed under what they actually attest to, so an entry can only
be retrieved by the message that earned it. Repeat copies still short-circuit, so
the protection the cache exists for is unchanged.

This is local bookkeeping. It touches no hash, no merkle root, no balance and
nothing on the wire — which is why an upgraded node agrees with every older node
about exactly which blocks and transactions are valid, and why upgrading is worth
doing immediately rather than waiting for the rest of the network.

## Also fixed

- **Witnesses survive a reorg.** A height reached by adopting a branch was served
  witness-short, so peers stalled their verification floor on it. Worse: because
  reverted payments are restored from that same store, a second reorg away from
  the branch dropped those payments with only a debug line. Both block-application
  paths now retain witnesses identically.
- **A retained witness must match what the block committed.** One of the two
  sources was accepted on length alone instead of being bound to the transaction's
  committed signature hash. An unbound witness is exactly the record a peer cannot
  verify against the root. Both sources now go through one check.
- **An unreadable database is set aside, not deleted.** Every failure to open the
  chain — a lock still held by another instance, a transient I/O error, a genuinely
  corrupt page — took the same irreversible action. The directory is now renamed
  for diagnosis and the node re-bootstraps as before. At most one copy is kept, so
  a node that fails repeatedly cannot fill its own disk.
- **Orphan pruning stopped opening every block it was deciding about.** It
  deserialized up to ten thousand stored blocks to read three small fields, on a
  path that runs for every applied block, under the chain write lock.
- **A peer's peer list is capped** the way the gateway's already was — the trusted
  source was bounded and the unauthenticated one was not.
- **Header-verification eviction is amortised** and no longer runs inside the
  headers write guard, where a peer streaming long header chains charged block
  ingestion for it.
- **`info` releases the chain lock before drawing**, instead of holding it across
  several hundred lines of output.
- Assorted smaller fixes: an inbound-attempt window that rolls instead of acting
  as a silence-gated lockout; IPv4-mapped addresses grouped with their real IPv4
  subnet everywhere rather than only on some paths; temp directories from an
  interrupted bootstrap swept instead of accumulating; background notices no
  longer able to park a runtime worker on a stalled terminal; and the finalize
  stage names corrected — every non-zero one had been mislabelled by an earlier
  refactor, which matters exactly when they are read, during a stall.

## Fewer false alarms

Three things reported trouble when there was none, which is worse than saying
nothing: a warning that fires during ordinary operation teaches you to scroll
past the one that matters.

- **The lock watchdog no longer calls a busy chain a wedged one.** It decided a
  node was stuck by trying to take the chain lock with a timeout — but the lock
  is write-preferring, so any long legitimate write (a balance rebuild, a
  catch-up, a bootstrap import) starves that probe exactly the way a deadlock
  would. A node doing its first big catch-up logged a wedge it did not have, and
  then finished syncing normally. It now also asks whether work is getting done,
  via a counter it can read without the lock, and only strikes when nothing is
  progressing. A real wedge still strikes on schedule.
- **Startup recovery stopped announcing itself as an error.** A marker left by a
  previous run is the ordinary consequence of an unclean stop, and the rebuild it
  triggers is usually seconds. It was reported up front, at error level, on the
  strength of a comment calling it a multi-minute wedge — next to the passphrase
  prompt. It is now silent when it is quick, reports the real duration when it
  takes more than ten seconds, and says the chain was not damaged. The live case,
  where a running node genuinely stalls, is unchanged.
- **A mesh that fails to come up says so and retries**, instead of disabling
  itself silently for the rest of the session.

## Whispers

- **A whisper now shows its amount.** The fee band that carries a whisper is not
  exclusive: an ordinary payment at a flat fee can land in it. Such a payment was
  reported as a valueless message and left out of the received total — an inbound
  credit that looked like a novelty. The amount now travels on every whisper line
  and in every digest total.
- **Whispers can no longer flood the console.** They collapse under volume the way
  payments already did, but the digest **keeps the codes** — for a whisper the code
  is the payload, so a bare count would discard the only part worth reading. A
  single whisper still prints in full, now on one line instead of two.
- A whisper sent to yourself is no longer counted as both sent and received.

## For miners

- **A solved block is announced before it is reported.** It used to wait while the
  client assembled a console summary, including a balance query that takes a fresh
  chain read lock — which, immediately after a block is applied, queues behind any
  block already waiting to be applied. That is time a competitor's block spends
  propagating. Nothing is skipped to get there: the block is validated, has won
  the tip check, and is on disk before it is announced.
- **An external block-notify hook** for pool operators, following Bitcoin's
  `-blocknotify` contract, so a Stratum pool is told the tip moved instead of
  polling and handing out work on a dead parent. No-op unless
  `ALPHANUMERIC_BLOCKNOTIFY` is set.
- The CPU progress bar no longer flickers on an 80-column terminal.

## Interface

- The wallet ledger is a table, with colour naming the kind of money and the
  spendable and total figures in bold — the two numbers people actually read.
- `help` is two aligned columns, with aliases coloured by section.
- A bare Enter points at `help` instead of only complaining.
- `account` prints the three counterparties worth acting on IN FULL — the latest
  inbound, the latest outbound, and the one seen most often — because the table
  above them truncates every address to keep its columns. Bare `account` now
  resolves your default wallet, and it accepts a wallet name as well as an
  address. It still looks up any address; that is the point of it.
- `account`, `history` and `whisper` render in the same display language as the
  rest of the client; the whisper list is a ledger rather than a dump.
- An address on its own looks it up; `bal` works as an alias for `balance`.
- `debug` no longer advertises `diagnostics`/`diag` aliases that dispatch never
  routed, and `--status` no longer advertises one either.

## Heads-up for block 517,583 (~10 August)

Unchanged by this release — this is the already-scheduled fee-accounting
activation, repeated here because 7.9.3 is what most nodes should be running by
then.

- **Upgrade before that height.** From 517,583 a block's *total* fees must stay
  within the scheduled allowance. An upgraded miner builds a slightly smaller
  block and is never affected. A miner still on older software can build a block
  that upgraded nodes reject — that, and only that, is what would split the
  network. Every node agreeing on the rule means no split at all.
- **A whisper on a very large transfer will stop sending.** A whisper carries its
  message in the fee, and that fee includes a component proportional to the amount
  sent, so a whisper on roughly 1,290 coins or more exceeds the per-block allowance
  on its own and is declined at submission. Ordinary whispers are far below this
  and are unaffected. Splitting a large transfer, or sending it without a whisper,
  both work normally.

## Documentation

Every document shipped inside these archives was audited line by line against
the code. The corrections that matter to anyone building on this:

- **The signing test vector did not validate.** Its `sender` was not the address
  its own seed derives, and because the sender is inside the signed message, the
  message, its hex and the signature hash were wrong with it — a transaction
  built literally from the document was rejected. It is regenerated, verified,
  and pinned by a test so it cannot silently rot again.
- **The automatic fee ceiling was documented at half its value** (`0.001`) in
  three places. It is `0.002`, which is what the API has always returned.
- **The whisper note was wrong about classification.** It is a pure fee-band
  test, and the document's own example transaction sat inside the band. The note
  now states the band and how a payer stays out of it.
- **README advertised five relay environment variables that do not exist**, and
  described relay publishing and sync as opt-in and off. Both are unconditional.
- The user guide showed the prompt as `alphanumeric:` (it has been `a#:` since
  7.3.7) and asked Linux builders to install OpenSSL headers and cmake, which
  the rustls/ring pin removed.
- GPU troubleshooting stopped recommending `WGPU_BACKEND=dx12` as a first step:
  the miner already falls back to the same card on another backend by itself,
  and setting that variable *restricts* it to one backend, removing the fallback.

## Install / verify
- **Standard**: use `alphanumeric-v7.9.3-macos-arm64.zip`
- **GPU mining (opt-in)**: use `alphanumeric-v7.9.3-gpu-macos-arm64.zip`
- **Signature model / protocol** unchanged; no protocol migration.
- Upgrading is a drop-in binary replacement: no database migration, no resync.

## Artifacts
| file | sha256 |
|---|---|
| alphanumeric-v7.9.3-macos-arm64.zip | `e4dc58d02a6aecc7246c1ea69b475923aaec741430a17398c103707132b196db` |
| alphanumeric-v7.9.3-gpu-macos-arm64.zip (opt-in GPU mining) | `e27a9d05152249945dc2903cac32314ff9de88bb8eb181ba24aa82cb927b1925` |

## Notes
- Build verification source: `cargo build --release --features bootstrap_publisher`
  on `main`, and the same plus `,gpu_miner` on `gpu-mining`.
- Linux and Windows build from source; the mesh is a default feature, so a plain
  `cargo build --release` produces a mesh-capable binary.
