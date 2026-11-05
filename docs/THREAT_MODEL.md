# Alphanumeric Threat Model

## Scope
This model covers consensus-critical behavior in `src/a9/blockchain.rs`, `src/a9/miner.rs`, `src/a9/bpos.rs`, `src/a9/node.rs`, and bootstrap state loading in `src/main.rs`.

## Security Goals
- Deterministic block validity across nodes.
- Deterministic fee accounting and full-witness-equivalent block limits after
  the coordinated activation height.
- Strong transaction authenticity and sender-key binding.
- Header verification resistant to small colluding sets when verifier context is available.
- Bootstrap state integrity via pinned publisher manifests, archive hash validation, and signed size metadata when available.
- Bounded resource usage under malformed peer input.
- Low-latency block announcements without making compact delivery a prerequisite
  for receiving the unchanged full block.

## Trust Boundaries
- Peer network input is untrusted.
- Bootstrap HTTP endpoints are untrusted until signature and hash checks pass.
- Local disk state may be stale/corrupted and must be validated at startup.

## Primary Threats And Controls
1. Difficulty/PoW manipulation via numeric overflow or lossy conversion.
Control: bounded integer target derivation (`pow_target_from_difficulty`) with saturation semantics.
Coverage: `pow_target_zero_difficulty_is_max_target`, `pow_target_halves_every_16_difficulty_points`, `pow_target_saturates_to_zero_for_large_difficulty`.

2. Header quorum bypass or deadlock due to incorrect threshold math.
Control: ratio-based verifier threshold over eligible validator set.
Coverage: `verifier_threshold_is_ratio_based_for_small_sets`, `verifier_threshold_is_clamped_to_valid_range`, `header_quorum_enforcement_is_disabled_for_small_networks`, `header_quorum_enforcement_is_enabled_with_three_eligible_nodes`, `conflicting_verified_header_is_detected`.

3. Memory safety risk from unsound thread-safety assumptions.
Control: removed manual `unsafe impl Send/Sync` for `HybridSwarm`; rely on compiler-enforced trait bounds.
Coverage: compile-time safety checks.

4. Bootstrap poisoning or resource exhaustion via weak manifests, malformed hashes, or oversized archives.
Control: HTTPS bootstrap URLs, pinned publisher identity, signed manifest fields, strict SHA-256 format checks, streamed download verification, signed archive size/file-count checks, and disk preflight. There is no unverified fallback: a manifest that fails signature verification aborts the bootstrap rather than proceeding under a size cap, and the download/extraction bounds come from the signed `compressed_bytes` / `extracted_bytes` / `file_count` fields, so they cannot be relaxed by an attacker or by an environment variable.
Coverage: startup path in `ensure_bootstrap_db`, manifest verification tests, and bootstrap archive size tests.

5. Balance/amount divergence from floating-point comparisons in consensus checks.
Control: integer unit-based minimum amount checks, and exact integer equality between a block's declared difficulty and the value re-derived from its parent — `block.difficulty != expected_difficulty` is rejected outright. No tolerance band is applied; the earlier 0.1% variance allowance was removed.
Coverage: validation paths in `validate_block_internal`, `prevalidate_unattached_block_strict`, and mempool admission.

6. Orphan-index corruption and orphan linkage inconsistencies.
Control: deterministic orphan index format + parse verification.
Coverage: `orphan_index_round_trip_extracts_hash`.

7. Fee-accounting behavior drifting outside the scheduled economics.
Control: activation-gated checked-integer aggregation keeps each exact
historical coinbase within the scheduled net-accounting baseline.
Coverage: fee-accounting activation, boundary, lifetime schedule, and strict
subset tests in `src/a9/blockchain.rs`.

8. Large full-witness blocks losing propagation races.
Control: activation-gated deterministic full-witness-equivalent block weight;
the WebRTC mesh sends a compact commitment first and the unchanged full block
immediately afterward on the ordered channel. Over TCP, peers that negotiate
compact v2 exchange a compact announcement with body recovery, and every failure
path falls back to the unchanged full-block message.
Coverage: shape/weight invariance, compact commitment, frame ordering, and
full-fallback dedup tests.

9. Mixed-version behavior across a coordinated consensus activation.
Control: the new predicate only narrows prior validity and preserves the exact
historical reward calculation and transaction wire format. Operators must still
upgrade before the published activation height; safe activation depends on
majority enforcement, not merely on wire compatibility.

10. Gateway unavailable, frozen, or answering with data it cannot prove.
Control: the gateway is an accelerator, not a dependency. A node follows the
signed tip beacon only while a verified read is fresh and its height is moving
(`beacon_follow_state`); otherwise the main monitor follows the chain from its
peers with a bounded, single-flight `sync_with_network` round (per-call and
per-candidate time budgets, up to eight candidates, and a sit-out with backoff
for peers that served something refused while claiming a taller chain). Every
block taken that way passes the same validation and witness checks as any other.
A beacon whose signature does not verify against a pinned publisher key cannot
produce a runtime re-bootstrap verdict, and the boot-time "too far behind" check
ignores an unsigned tip height. A verified but frozen beacon below the local tip
does not force a re-bootstrap onto its branch, and the mine-prep stale-tip guard
widens to the reorg margin only while the beacon is stuck at its maximum, so a
stuck publisher cannot stop mining while a stale cache edge still cannot launder
a ghost block.
Coverage: `beacon_follow_verdict_live_only_when_fresh_and_moving`,
`beacon_follow_state_uses_production_bounds`,
`frozen_beacon_holds_tip_only_for_a_verified_frozen_beacon_below_us`,
`unverified_beacon_never_yields_a_bootstrap`,
`client_converge_paths_all_apply_the_unverified_beacon_rule`,
`ghost_guard_tolerance_widens_only_while_the_beacon_is_stuck`,
`sync_strikes_cool_down_exponentially_and_filter_candidates`,
`sync_with_network_stays_bounded_and_wide`, and the `follow_*` pacing tests in
`src/main.rs`.

## Residual Risks
- Multi-node adversarial integration coverage is still limited compared with mature L1 test harnesses.
- Some consensus-adjacent modules still contain inactive/dead paths that increase audit surface.
- The older TCP compact v1 pull/proxy transport remains disabled pending integrated
  acknowledgement, retry, and source-failure testing (compact v2 is the one in use).
- Signed official bootstraps remain compatible with older manifests that do not yet include size metadata; those should be republished with current publisher tooling.
- Without the gateway, catch-up over peers is limited to the span peers still hold full
  transaction witnesses for; a node offline for longer, or a new node, needs a signed beacon
  or a signed snapshot. Peer-only finality also trails the local tip by the reorg margin, so
  a partition outlasting it does not heal without the beacon.
- Some boot-time and reconcile fork checks still consult gateway data that is
  consistency-checked but not publisher-signed; moving them onto signed data is
  open work.

## Test And Control Mapping
- Unit tests are embedded in consensus modules for deterministic math, thresholding behavior, and compatibility conversions.
- Compile-time checks now enforce safe concurrency traits for swarm ownership.
- Runtime startup checks enforce pinned publisher identity, signed manifest integrity, hash integrity, and archive extraction constraints before trusting chain snapshots.
