# Alphanumeric Client User Guide

This download contains Alphanumeric client version 7.6.0 for macOS.

## What Is Included

- `alphanumeric` - the client program
- `README.md` - this user guide

The client stores its chain database, node identity, wallets, and lock files beside the folder you run it from unless you set a custom database path.

## Recommended Setup

Create one folder for the client and always run it from that folder:

```bash
mkdir -p ~/Alphanumeric
cd ~/Alphanumeric
```

Move the `alphanumeric` file into that folder, then make it executable if needed:

```bash
chmod +x ./alphanumeric
```

Start the client:

```bash
./alphanumeric
```

On first run, the client will create or download local chain data into:

```bash
~/Alphanumeric/blockchain.db
```

It will also create local identity and wallet files in the same working folder.

## macOS First-Run Note

If macOS blocks the program because it was downloaded from the internet, open it from Finder with right-click, then Open.

If you prefer Terminal, you can remove the quarantine flag:

```bash
xattr -dr com.apple.quarantine ./alphanumeric
```

## First Run

When the client starts, it checks local chain data against the launch network. If no usable `blockchain.db` exists, or if the local DB belongs to the wrong network, it downloads the current bootstrap snapshot from the Alphanumeric gateway and verifies it before using it.

If bootstrap succeeds, the command prompt appears:

```text
alphanumeric:
```

Type commands after that prompt.

## Basic Commands

Show wallet balances:

```text
balance
```

Show network and chain status:

```text
info
```

Create a wallet:

```text
new my_wallet
```

Mine to a wallet:

```text
mine my_wallet
```

Send funds:

```text
create sender_wallet recipient_address amount
```

Example:

```text
create my_wallet 84dab431b53e6522fe2e74914eec99f17758f4e3 1.25
```

Show all commands:

```text
help
```

Exit:

```text
exit
```

## Keeping Your Data Safe

Back up these files and folders from your Alphanumeric folder:

- `private.key`
- `node_identity.key`
- `blockchain.db`

If you lose wallet key material, the client cannot recover those wallets for you.

Do not share private key files. Public wallet addresses are safe to share.

## Choosing a Custom Data Folder

By default, data is stored beside the folder where you run the client. To force a specific database path, set `ALPHANUMERIC_DB_PATH` before starting:

```bash
ALPHANUMERIC_DB_PATH="$HOME/Alphanumeric/blockchain.db" ./alphanumeric
```

Use the same path every time so the client keeps using the same chain and wallet state.

## Network Settings

The default discovery gateway is:

```text
https://alphanumeric.blue
```

If you need to set it manually:

```bash
ALPHANUMERIC_DISCOVERY_BASES=https://alphanumeric.blue ./alphanumeric
```

## Faster Sync: WebRTC Mesh (Recommended)

Most miners are behind home NAT with no open port, so by default blocks propagate through the
gateway relay, which is slower. The WebRTC mesh lets your node hole-punch **direct** peer-to-peer
links to other miners (coordinated by the gateway, no port-forwarding needed), so blocks gossip
node-to-node and catch-up is much faster. Turn it on:

```bash
ALPHANUMERIC_WEBRTC_MESH=true ./alphanumeric
```

It falls back to the normal gateway relay automatically for the minority of peers it can't reach
directly, so there's no downside to enabling it.

## Running a Public Node (Optional)

A normal client bootstraps from the gateway and connects out to peers — you do not need to
open any ports. If you run a reachable machine (a VPS, or a home box behind a Cloudflare/
Tailscale tunnel) you can optionally run a **public full-history node** that serves the whole
chain to brand-new nodes over peer-to-peer, so onboarding no longer depends only on the
gateway snapshot:

```bash
ALPHANUMERIC_PUBLIC_NODE=true \
ALPHANUMERIC_PUBLIC_IP=<your.routable.ip> \
ALPHANUMERIC_PORT=7367 \
./alphanumeric
```

To point a fresh node at a specific public node instead of (or in addition to) the gateway,
set its address as a seed:

```bash
ALPHANUMERIC_SEED_NODES=<ip:port> ./alphanumeric
```

A fresh node given a seed will reconstruct the chain directly from that peer if the gateway
snapshot is ever unavailable.

## Troubleshooting

If the client says another instance is running, make sure no other `alphanumeric` process is open.

If the client cannot connect to peers, leave it open for a minute, then run:

```text
info
```

If the chain database gets corrupted or belongs to the wrong network, the client replaces it from the signed bootstrap at startup.

If you intentionally want to force bootstrap while keeping the same folder:

```bash
ALPHANUMERIC_FORCE_BOOTSTRAP=true ./alphanumeric
```

## Support Files Created at Runtime

The client may create these local files:

- `blockchain.db` - local chain database
- `blockchain.db.lock` - runtime lock file
- `private.key` - wallet key storage
- `node_identity.key` - node identity key
- `*.bootstrap_backup_*` - temporary safety backups during bootstrap replacement

Keep the client folder together if you move it to another machine.
