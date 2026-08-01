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
