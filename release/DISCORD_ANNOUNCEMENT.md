**Alphanumeric v7.9.3 — a verdict could answer for something it never saw**

Security and hardening release, following a full audit of the node. No change to
block validity rules, wire format, or network compatibility — 7.9.3, 7.9.2, 7.9.1
and 7.9.0 nodes stay on the same chain and can be upgraded in any order.
**Recommended for every node, and the sooner the better.**

### The main fix
The node remembers whether it has already judged a block or a transaction, so a
second copy costs nothing to dismiss. Those memories were filed under an
identifier that does not pin the contents — two different messages could share
one, and the verdict recorded for the first could be handed back for the second.

Both directions were wrong. A rejected copy could stand in for the legitimate
message sharing its identifier and suppress it for up to an hour: a block
stalling on that node, or a payment quietly dropped before it was ever looked at.
In the other direction an acceptance could wave through bytes nothing verified.

Verdicts are now filed under what they actually attest to, so an entry can only
be retrieved by the message that earned it. Repeat copies still short-circuit.

This is local bookkeeping — no hash, no merkle root, no balance, nothing on the
wire. That is why an upgraded node agrees with every older node about which
blocks and transactions are valid, and **why upgrading helps you immediately
rather than only once the network does**.

### Also fixed
- **Witnesses survive a reorg.** A height reached by adopting a branch was served
  witness-short, stalling peers' verification floor on it — and because reverted
  payments are restored from that same store, a second reorg dropped those
  payments with only a debug line.
- **A retained witness must match what the block committed.** One of the two
  sources was trusted on length alone rather than bound to the committed
  signature hash.
- **An unreadable database is set aside, not deleted.** Every failure to open the
  chain took the same irreversible action. It is renamed for diagnosis now, at
  most one copy kept, so a repeatedly-failing node can't fill its own disk.
- **Orphan pruning stopped opening every block it was deciding about** — it read
  up to ten thousand stored blocks for three small fields, under the chain write
  lock, for every applied block.
- A peer's peer list is capped the way the gateway's already was; header
  verification eviction is amortised and out of the write guard; `info` releases
  the chain lock before drawing.
- Plus: a rolling inbound-attempt window, IPv4-mapped addresses grouped with
  their real subnet everywhere, bootstrap temp dirs swept, background notices
  unable to park a runtime worker, and corrected finalize stage names.

### Whispers
- **A whisper now shows its amount.** The fee band carrying a whisper isn't
  exclusive — an ordinary payment at a flat fee can land in it, and used to be
  reported as a valueless message and left out of the received total.
- **Whispers can't flood the console.** They collapse under volume like payments,
  but the digest **keeps the codes** — the code is the payload, so a bare count
  would throw away the only part worth reading. One whisper still prints in full.
- A whisper to yourself is no longer counted as both sent and received.

### For miners
- **A solved block is announced before it's reported.** It used to wait on a
  console summary — including a balance query whose chain read lock queues behind
  any block waiting to be applied. That was time a competitor's block spent
  propagating. Nothing is skipped: the block is validated, has won the tip check,
  and is on disk before it goes out.
- **External block-notify hook** for pools (Bitcoin's `-blocknotify` contract), so
  a Stratum pool learns the tip moved instead of handing out work on a dead
  parent. No-op unless `ALPHANUMERIC_BLOCKNOTIFY` is set.

### Interface
Wallet ledger is a table with spendable/total in bold; `help` is two aligned
columns; a bare Enter points at `help`; `account`, `history` and `whisper` share
one display language and the whisper list is a ledger; an address on its own
looks it up; `bal` aliases `balance`.

### Before block 517,583 (~10 August)
Unchanged by this release — the already-scheduled fee-accounting activation.
**Upgrade before that height.** From 517,583 a block's total fees must stay within
the scheduled allowance; an upgraded miner just builds a slightly smaller block.
A miner on older software can build a block upgraded nodes reject — that, and only
that, is what would split the network.

Also from that height: a whisper on roughly 1,290 coins or more exceeds the
per-block allowance on its own and is declined at submission. Ordinary whispers
are far below this. Split the transfer, or send it without a whisper.

### Download (macOS, Apple Silicon)
Standard: `alphanumeric-v7.9.3-macos-arm64.zip`
GPU mining (opt-in): `alphanumeric-v7.9.3-gpu-macos-arm64.zip`

Linux/Windows build from source — the mesh is a default feature, so a plain
`cargo build --release` gives you a mesh-capable binary.

Drop-in replacement: no database migration, no resync.

### Artifacts + checksums
`alphanumeric-v7.9.3-macos-arm64.zip`
`e4dc58d02a6aecc7246c1ea69b475923aaec741430a17398c103707132b196db`

`alphanumeric-v7.9.3-gpu-macos-arm64.zip`
`e27a9d05152249945dc2903cac32314ff9de88bb8eb181ba24aa82cb927b1925`
