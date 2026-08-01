**Alphanumeric v7.9.4 — required upgrade before block 569,423**

Version 7.9.4 is a scheduled consensus compatibility release. Reward accounting
V2 activates at block **569,423**.

### Operator action
- Upgrade miners, pools, public nodes, and other validating deployments before
  block 569,423.
- Confirm the restarted process reports version 7.9.4.
- Do not run an older miner past the activation boundary.

Blocks below the activation height retain the existing rules. Compatible nodes
use the updated reward-accounting rules from block 569,423 onward. The release
also adds advisory consensus-fingerprint telemetry so rollout compatibility can
be monitored directly.

This is a drop-in binary replacement: no database migration, wallet migration,
resync, transaction-format change, or network-message change.

macOS release artifacts and SHA-256 checksums will be published from the reviewed
v7.9.4 tag. Linux and Windows operators can build the same tag from source.
