# alphanumeric
https://www.alphanumeric.blue/

![Screenshot_2025-01-04_213726](https://github.com/user-attachments/assets/0b5c747c-53f7-4e09-82c8-0e9bfbd8cd89)

`alphanumeric` is a Rust blockchain node runtime with integrated networking, wallet management, mining, and diagnostics tooling.

## Why This Exists

This project aims to provide a single-node binary that can:

- maintain chain state locally (`sled`)
- discover and connect to peers
- propagate transactions/blocks
- mine blocks
- expose operational stats
- support wallet and message workflows from an interactive CLI

## Current Status

- Active development.
- Interfaces and internals can change between commits.
- Not a formally audited production system.

## Technical Architecture

High-level module map:

- `src/main.rs`: process entrypoint, bootstrap, CLI loop, network command handling
- `src/a9/node.rs`: P2P runtime, framing, peer management, sync, event handling
- `src/a9/blockchain.rs`: block/transaction validation and persistence
- `src/a9/mgmt.rs`: wallet management and key workflow
- `src/a9/progpow.rs`: mining manager and mining flow
- `src/a9/velocity.rs`: velocity/shred propagation support
- `src/a9/bpos.rs`: sentinel/validator-related logic
- `src/a9/whisper.rs`: whisper messaging support

Runtime shape:

1. bootstrap/load DB (`blockchain.db`)
2. initialize blockchain state
3. initialize node runtime + listeners
4. spawn background tasks:
   - peer maintenance
   - discovery/announce
   - sync
   - optional stats
5. process interactive commands and network events

## Network and Protocol Notes

- Default node TCP port: `7177` (`DEFAULT_PORT` in `src/a9/node.rs`)
- Outbound messaging uses framed transport (length-prefixed payloads)
- Message size limits are enforced (`MAX_MESSAGE_SIZE`)
- Outbound connection pooling is enabled with:
  - idle cleanup
  - LRU-style eviction
  - per-peer circuit breaker on repeated failures
- Inbound connection handling is concurrency-limited
- DNS/discovery endpoints are environment-configurable

## Consensus and Validation

The codebase includes multiple consensus/validation-related components (PoW/mining path, sentinel/validator logic, and propagation optimizations). Behavior is defined by the current code paths in `src/a9/*`.

If you are integrating against this repository, pin a commit hash and validate behavior at that exact revision.

## Build and Run

Prerequisites:

- Rust stable toolchain
- Cargo

Build:

```powershell
cargo build --release
```

Run:

```powershell
cargo run --release
```

## Bootstrap and Storage

Startup bootstrap source (default):

- `https://alphanumeric.blue/bootstrap/blockchain.db.zip`

If `blockchain.db` already exists locally, that state is used.

Primary local artifacts:

- `blockchain.db`
- `private.key`
- optional lock files (`*.lock`)

## Configuration via Environment Variables

Common variables used by the runtime include:

- `ALPHANUMERIC_BIND_IP`
- `ALPHANUMERIC_BOOTSTRAP_URL`
- `ALPHANUMERIC_BOOTSTRAP_REQUIRED`
- `ALPHANUMERIC_IGNORE_DB_LOCK`
- `ALPHANUMERIC_STATS_ENABLED`
- `ALPHANUMERIC_STATS_BIND`
- `ALPHANUMERIC_STATS_PORT`
- `ALPHANUMERIC_DNS_SEEDS`
- `ALPHANUMERIC_DISCOVERY_BASE`
- `ALPHANUMERIC_DISCOVERY_BASES`
- `ALPHANUMERIC_DISCOVERY_URL`
- `ALPHANUMERIC_ANNOUNCE_URL`
- `ALPHANUMERIC_HEADERS_URL`
- `ALPHANUMERIC_PUBLIC_IP`
- `ALPHANUMERIC_ENABLE_UPNP`
- `ALPHANUMERIC_PEER_CACHE_PATH`
- `ALPHANUMERIC_TX_WITNESS_CACHE_SIZE`

## CLI Surface

Interactive command loop examples:

- `create <sender> <recipient> <amount>`
- `whisper <address> <msg>` (amount can be provided depending on flow)
- `balance`
- `new [wallet_name]`
- `account <address>`
- `history`
- `rename <old_name> <new_name>`
- `mine <wallet_name>`
- `info`
- `diagnostics`

Process flags/network commands:

- `--status` or `-s`
- `--sync`
- `--sync --force`
- `--connect <ip:port>`
- `--getpeers`
- `--discover`

## Security Posture

This project handles key material and peer input. Treat it accordingly.

- `private.key` is sensitive. Secure the host and filesystem permissions.
- Do not commit key material to source control.
- Treat all network input as untrusted.
- Validate operational assumptions before mainnet-like usage.

## Operations Checklist

Minimum recommended setup for a reachable node:

1. open TCP port `7177` on host firewall/router
2. run node on a stable host with persistent disk
3. monitor logs and peer count
4. back up sensitive key material securely

Windows firewall example:

```powershell
New-NetFirewallRule -Name "Alphanumeric Network" -DisplayName "Alphanumeric Network (Port 7177)" -Protocol TCP -LocalPort 7177 -Direction Inbound,Outbound -Action Allow
```

## Development Workflow

Quick local checks:

```powershell
cargo check
```

When changing protocol/runtime code, prefer:

- explicit message framing
- bounded buffers and timeouts
- clear lock scopes
- deterministic error handling

## Frontend

- Official frontend: https://www.alphanumeric.blue/

## Community

- Discord: https://discord.gg/D3r7TRcj9t

## License

MIT
