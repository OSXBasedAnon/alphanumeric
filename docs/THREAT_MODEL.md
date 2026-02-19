# Alphanumeric Threat Model

## Scope
This model covers consensus-critical behavior in `src/a9/blockchain.rs`, `src/a9/progpow.rs`, `src/a9/bpos.rs`, `src/a9/node.rs`, and bootstrap state loading in `src/main.rs`.

## Security Goals
- Deterministic block validity across nodes.
- Strong transaction authenticity and sender-key binding.
- Header verification resistant to small colluding sets when verifier context is available.
- Bootstrap state integrity via canonical source + optional manifest hash validation.
- Bounded resource usage under malformed peer input.

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

4. Bootstrap poisoning via weak manifests or malformed hashes.
Control: canonical bootstrap URL, manifest fallback, strict SHA-256 format checks, and hash enforcement when a valid manifest hash is present.
Coverage: startup path in `ensure_bootstrap_db` and `is_valid_sha256_hex`.

5. Balance/amount divergence from floating-point comparisons in consensus checks.
Control: integer unit-based minimum amount checks and integer tolerance logic for difficulty validation.
Coverage: validation paths in `validate_block_internal`, `prevalidate_unattached_block_strict`, and mempool admission.

6. Orphan-index corruption and orphan linkage inconsistencies.
Control: deterministic orphan index format + parse verification.
Coverage: `orphan_index_round_trip_extracts_hash`.

## Residual Risks
- Multi-node adversarial integration coverage is still limited compared with mature L1 test harnesses.
- Some consensus-adjacent modules still contain inactive/dead paths that increase audit surface.
- Bootstrap authenticity is integrity-checked, but publisher identity pinning is not mandatory in default runtime mode.

## Test And Control Mapping
- Unit tests are embedded in consensus modules for deterministic math, thresholding behavior, and compatibility conversions.
- Compile-time checks now enforce safe concurrency traits for swarm ownership.
- Runtime startup checks enforce canonical source and hash integrity before trusting chain snapshots.
