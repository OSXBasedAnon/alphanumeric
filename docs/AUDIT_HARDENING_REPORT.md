# Alphanumeric Hardening Report

> Historical record (pre-7.9.0): this report describes the hardening pass that
> preceded the coordinated fee-accounting and block-weight release. It is not a
> current release-safety statement; consult `README.md`, `THREAT_MODEL.md`, and
> the activation notice shipped with the current release.

## Scope
- Consensus path: `src/a9/blockchain.rs`, `src/a9/node.rs`, `src/a9/bpos.rs`, `src/a9/miner.rs`
- Compatibility path: transaction serialization/deserialization
- Bootstrap integrity path: `src/main.rs`

## Hardening Applied
1. BPoS enforcement hook added to block acceptance.
Path: `src/a9/node.rs`
- Block validation now performs optional quorum enforcement when verifier context is mature.
- Rejection conditions added:
  - conflicting verified header exists at same height
  - known header record fails quorum
- Bootstrap/single-node mode preserved by gating enforcement to networks with sufficient eligible verifiers.

2. Header quorum math and verifier semantics tightened.
Path: `src/a9/bpos.rs`
- Added explicit eligible-verifier and enforcement helpers:
  - `eligible_verifier_count`
  - `should_enforce_consensus_for_headers`
  - `has_verification_record`
  - `has_conflicting_verified_header`
- Local observation marker (`__local__`) no longer counts toward external quorum.
- Header state verification metadata is updated from verification map for consistency.

3. Transaction compatibility regression coverage expanded.
Path: `src/a9/blockchain.rs`
- Added tests validating:
  - JSON field compatibility (`amount`/`fee` field names remain stable)
  - legacy bincode transaction decode into unit-backed transaction fields

4. Targeted warning-noise cleanup in active mining/whisper/wallet paths.
Paths: `src/a9/miner.rs`, `src/a9/whisper.rs`, `src/a9/wallet.rs`
- Removed several unused-variable hotspots and dead locals in hot code paths.

5. Threat model updated to match actual runtime behavior.
Path: `docs/THREAT_MODEL.md`
- Corrected bootstrap integrity assumptions.
- Mapped added quorum hardening tests and residual risks.

6. Pending transaction and mining safety tightened.
Paths: `src/a9/blockchain.rs`, `src/a9/mgmt.rs`
- Invalid pending transactions are removed during live mempool sync instead of only being skipped.
- Candidate mining filters now skip malformed regular transactions before block construction.
- New-block prevalidation rejects invalid regular transaction amount/signature shape before finalization.
- Added regression coverage for negative fees and invalid regular transaction amounts.

7. CLI output and status display hardened.
Paths: `src/a9/wallet.rs`, `src/a9/blockchain.rs`, `src/main.rs`
- ML-DSA verification diagnostics now go through debug logging instead of writing into interactive command output.
- Chain status uses saturating timestamp math for future-skewed local blocks.
- Pending totals display actual pending values/fees instead of absolute values.

## Remaining Hardening Work
1. Add deterministic multi-node adversarial tests:
- divergent header broadcasts
- delayed parent/orphan replay
- witness withholding under tx signature checks

2. Reduce consensus-adjacent dead code and deprecated APIs:
- especially `libp2p` deprecated behaviour methods in `src/a9/node.rs`

3. Add release-gate CI checks:
- compatibility fixtures (legacy/new tx decoding)
- snapshot checksum verification path tests
- forced mixed-version simulation for PoW edge difficulty handling

## Fork Risk Statement
- The hardening covered by this historical report was designed to avoid an
  immediate fork requirement by:
  - preserving transaction wire-field compatibility
  - applying BPoS quorum enforcement only when verifier context exists
  - keeping bootstrap fallback behavior operational
