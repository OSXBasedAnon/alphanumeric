# Consensus Decisions

This file records reviewed consensus characteristics that are intentionally not
changed by local hardening. It is a decision log, not a claim that future evidence
cannot change the conclusion.

## Timestamp-driven retarget

The required work for a child block is derived partly from the child timestamp. The
timestamp is bounded by the parent and the allowed future-time window, but a miner can
still influence short-term block cadence inside those bounds.

The reviewed forward-timestamp schedule creates a bounded fast interval followed by a
compensating high-difficulty interval. The initiating miner captures its own winning
block and its probability of winning depends on hashrate; no broader claim about every
possible schedule is made here.

Disposition: accept the current rule. It does not justify a standalone hard fork. Any
future change requires a new threat model, reproducible simulation across adversarial
schedules, specification text, activation planning, and independent review. It must
not be bundled into unrelated non-consensus hardening.

## Reward accounting V2

Reward accounting V2 activates at block `569,423`. The boundary is fixed in the
node and included in its advisory consensus fingerprint. Blocks below the
activation height retain the legacy rules exactly; blocks at and above it use the
V2 rules.

Disposition: ship as a coordinated consensus release. Miners, pools, public
nodes, and other validating operators must run a compatible release before the
activation height. The change does not require a database migration, wallet
migration, resync, transaction-format change, or network-message change.

## Hex witness encoding

Transaction witnesses (`signature`, `pub_key`, `sig_hash`) are carried as lowercase
hex strings inside the canonical `Transaction` struct. This representation is
load-bearing in three consensus-adjacent places: the deterministic block weight
charges witness fields at two bytes per raw byte (`full_witness_transaction_weight`),
activated shape validation measures field lengths in hex units
(`hex_field_has_decoded_len`), and the consensus Merkle leaf is SHA-256 over the
codec serialization of the struct, hex included (`calculate_merkle_leaf_hash`). The
serialization crates are exact-pinned and the encoding is held by golden-byte tests;
a one-byte shift in either is a chain split, which is why both are treated as
consensus surfaces rather than dependencies.

Reviewed 2026-08. The hex representation costs roughly 2x on the P2P wire against a
binary encoding (measured: 14,618 versus 7,367 bytes for a full-witness transfer)
and nothing in block capacity, because the weight formula charges constants rather
than measured bytes. The review found no path to a same-network binary re-encoding:
deployed readers hard-error on a MessagePack `bin` where they expect `str`, and the
failure lands before the block index is readable, so even a height-gated switch
cannot be delivered to an un-upgraded peer. The wire cost is instead recoverable
without any fork through per-peer negotiated transports (capability-suffix pattern
already used by the transaction inventory), which hydrate received binary witnesses
back into the canonical hex struct before any hashing, leaving Merkle leaves
byte-identical.

Disposition: keep hex as the canonical and external representation indefinitely.
Hex remains correct at the JSON boundary and is published in the signing
specification. Do not change the canonical encoding as a standalone action, and do
not remove the two-bytes-per-byte factor from the weight formula independently of
it: dropping that factor doubles effective block capacity, which is a loosening and
therefore a coordinated hard fork. If a consensus-breaking release ever becomes
necessary for an unrelated reason, a canonical binary encoding and a matching
weight-formula revision may be evaluated for bundling into that release, under the
same standard as any other consensus change.

## Producer feed cap held at 2 MB

The producer's block assembly cap (`mempool::MAX_BLOCK_SIZE`, 2,000,000 bytes) is
producer policy, not consensus: validation accepts blocks up to
`MAX_BLOCK_WEIGHT_BYTES` (3,500,000), and producers with different caps coexist on
one network. Raising the cap to the validation limit would raise delivered
throughput from roughly 27 to 47 transactions per second and requires no fork at
any node.

Reviewed 2026-08. Delivered demand is a small fraction of one percent of the
current envelope, and current throughput already exceeds the settlement rate of
the largest proof-of-work networks. The staged program in `mempool.rs` already
names the promotion gates: clean full-block propagation campaigns, orphan-rate
measurement, and compact-transport reconstruction hit rate.

Disposition: hold at 2 MB deliberately. The dial moves on evidence of demand and
only after the named gates are green, not on availability of headroom. This is a
stability posture, not a technical limitation, and the change remains a
one-constant producer restart whenever the gates justify it.
