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

## Install / verify
- **Standard**: use `alphanumeric-v7.9.3-macos-arm64.zip`
- **GPU mining (opt-in)**: use `alphanumeric-v7.9.3-gpu-macos-arm64.zip`
- **Signature model / protocol** unchanged; no protocol migration.
- Upgrading is a drop-in binary replacement: no database migration, no resync.

## Artifacts
| file | sha256 |
|---|---|
| alphanumeric-v7.9.3-macos-arm64.zip | `__SHA_CPU__` |
| alphanumeric-v7.9.3-gpu-macos-arm64.zip (opt-in GPU mining) | `__SHA_GPU__` |

## Notes
- Build verification source: `cargo build --release --features bootstrap_publisher`
  on `main`, and the same plus `,gpu_miner` on `gpu-mining`.
- Linux and Windows build from source; the mesh is a default feature, so a plain
  `cargo build --release` produces a mesh-capable binary.
