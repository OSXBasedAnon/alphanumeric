# Bootstrap Publisher Operations

Bootstrap publishing is maintainer infrastructure for the canonical launch network. Normal users, miners, and relay nodes do not need a publisher shell script on macOS; they should run the `alphanumeric` binary directly and let the node discover peers.

The publisher role is intentionally small:

- run a trusted headless node against the canonical network database
- expose the normal P2P port so nodes can sync from the network
- optionally expose the local stats endpoint
- publish signed bootstrap snapshots only when authorized by the gateway token

Required operator configuration:

- `ALPHANUMERIC_BOOTSTRAP_PUBLISH_TOKEN`
- `ALPHANUMERIC_DB_PATH`
- `ALPHANUMERIC_DISCOVERY_BASES`
- `ALPHANUMERIC_HEADLESS=true`

Optional publisher-only configuration:

- `ALPHANUMERIC_BIND_IP`
- `ALPHANUMERIC_PORT`
- `ALPHANUMERIC_STATS_ENABLED`
- `ALPHANUMERIC_STATS_BIND`
- `ALPHANUMERIC_STATS_PORT`
- `ALPHANUMERIC_ENABLE_HEADER_SNAPSHOTS`
- `ALPHANUMERIC_ENABLE_STATS_SNAPSHOTS`
- `ALPHANUMERIC_PEER_CACHE_PATH`

Do not commit machine-specific LaunchAgent wrappers, local absolute paths, token-file locations, or private operational scripts. Keep those in local ops config and keep the public release package focused on the client binary and user guide.
