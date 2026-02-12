# alphanumeric

https://www.alphanumeric.blue/

![Screenshot_2025-01-04_213726](https://github.com/user-attachments/assets/0b5c747c-53f7-4e09-82c8-0e9bfbd8cd89)

Rust-based blockchain node implementation with integrated networking, mining, wallet management, and diagnostics tooling.

## Project Status

This repository is under active development. Interfaces and internals may change between commits.

## Highlights

- Rust codebase focused on performance and memory safety
- P2P node runtime with peer discovery, sync, and propagation
- Proof-of-work mining path
- Wallet management and transaction flow
- Embedded storage via `sled`
- Optional stats and discovery integrations

## Quick Start

### Prerequisites

- Rust (stable)
- Cargo

### Run

```powershell
cargo run --release
```

On first startup, the node can bootstrap from:

- `https://alphanumeric.blue/bootstrap/blockchain.db.zip`

If a local `blockchain.db` is present, it will use local state instead.

## Network Notes

- Default node port: `7177` (TCP)
- To accept inbound peers, allow TCP `7177` on your host/firewall/router

Windows firewall example (PowerShell as Administrator):

```powershell
New-NetFirewallRule -Name "Alphanumeric Network" -DisplayName "Alphanumeric Network (Port 7177)" -Protocol TCP -LocalPort 7177 -Direction Inbound,Outbound -Action Allow
```

## Configuration (Environment)

Examples used by the runtime include:

- `ALPHANUMERIC_BIND_IP`
- `ALPHANUMERIC_BOOTSTRAP_URL`
- `ALPHANUMERIC_BOOTSTRAP_REQUIRED`
- `ALPHANUMERIC_STATS_ENABLED`
- `ALPHANUMERIC_STATS_PORT`
- `ALPHANUMERIC_DISCOVERY_BASE`

## Security Notes

- Treat `private.key` and wallet key material as sensitive secrets.
- Do not commit secrets to git.
- Use encrypted storage and hardened host access controls in production.

## Community

- Discord: https://discord.gg/D3r7TRcj9t

## License

MIT
