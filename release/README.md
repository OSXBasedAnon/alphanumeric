# Alphanumeric Client User Guide

This is the user guide for Alphanumeric client version 7.7.3.

The prebuilt download is for **macOS (Apple Silicon)**. On **Windows** and
**Linux** you build from source — it takes a few minutes and one `cargo`
command; see the setup sections below.

The client stores its chain database, node identity, wallets, and lock files beside the folder you run it from unless you set a custom database path.

## Setup — macOS (prebuilt download)

Create one folder for the client and always run it from that folder:

```bash
mkdir -p ~/Alphanumeric
cd ~/Alphanumeric
```

Move the `alphanumeric` file into that folder, then make it executable if needed:

```bash
chmod +x ./alphanumeric
```

If macOS blocks the program because it was downloaded from the internet, open it from Finder with right-click, then Open. If you prefer Terminal, you can remove the quarantine flag:

```bash
xattr -dr com.apple.quarantine ./alphanumeric
```

Start the client:

```bash
./alphanumeric
```

## Setup — Windows (build from source)

1. Install Rust from <https://rustup.rs> (run `rustup-init.exe`, accept the
   default MSVC toolchain). If the installer asks for the Visual Studio C++
   Build Tools, let it install them — Rust needs them to link programs.
2. Install Git from <https://git-scm.com> if you do not have it.
3. In PowerShell:

```powershell
git clone https://github.com/OSXBasedAnon/alphanumeric
cd alphanumeric
cargo build --release
```

4. Run the client from its own folder so your chain data stays together:

```powershell
mkdir ~\Alphanumeric
copy target\release\alphanumeric.exe ~\Alphanumeric\
cd ~\Alphanumeric
.\alphanumeric.exe
```

Always run the **release** build as shown above. A debug build (plain
`cargo run`) is many times slower — fine for a quick look, wrong for mining.

Environment variables in PowerShell are set like this (any variable in this
guide works the same way):

```powershell
$env:ALPHANUMERIC_HEADLESS = "true"
.\alphanumeric.exe
```

## Setup — Linux (build from source)

On Debian/Ubuntu:

```bash
sudo apt install build-essential pkg-config libssl-dev cmake git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/OSXBasedAnon/alphanumeric
cd alphanumeric
cargo build --release
mkdir -p ~/Alphanumeric && cp target/release/alphanumeric ~/Alphanumeric/
cd ~/Alphanumeric && ./alphanumeric
```

Other distributions need the same things under their own package names: a C
compiler, pkg-config, OpenSSL headers, cmake, git, and Rust via rustup.

## First Run

When the client starts, it checks local chain data against the launch network. If no usable `blockchain.db` exists, or if the local DB belongs to the wrong network, it downloads the current bootstrap snapshot from the Alphanumeric gateway and verifies it before using it. On first run, the client creates local identity and wallet files in the working folder, and the chain database:

```text
blockchain.db
```

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

Look up any account (balance and full transaction history):

```text
account 84dab431b53e6522fe2e74914eec99f17758f4e3
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

## Running a Node Without Mining

Nodes never mine on their own — mining only starts if you type `mine`. To run
a light, hands-off node that just follows and verifies the chain (works fine
on modest machines and small VPSes):

```bash
ALPHANUMERIC_HEADLESS=true ./alphanumeric
```

## Run Your Own Explorer (Optional)

Any node can serve read-only chain data over local HTTP for a block-explorer
website, an exchange integration, or scripts:

```bash
ALPHANUMERIC_EXPLORER_API=127.0.0.1:8790 ALPHANUMERIC_HEADLESS=true ./alphanumeric
```

Endpoints: `/explorer/tip`, `/explorer/block/{height}`,
`/explorer/tx/{height}/{position}`, `/explorer/address/{address}`,
`/explorer/supply`, `/explorer/status`. It is off by default and costs nothing
when disabled. Keep the port on localhost and put your web server in front if
your site is public. Full guide: `EXPLORER_API.md` (included with this
download and in the repository under `docs/`).

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

## Faster Sync: WebRTC Mesh (on by default)

Most miners are behind home NAT with no open port, so blocks would otherwise propagate only through
the gateway relay, which is slower. The WebRTC mesh lets your node hole-punch **direct** peer-to-peer
links to other miners (coordinated by the gateway, no port-forwarding needed), so blocks gossip
node-to-node and catch-up is much faster. As of v7.6.1 the mesh is **on by default** — there is
nothing to configure.

It falls back to the normal gateway relay automatically for any peer it can't reach directly, and a
node with no mesh peers just runs on the relay exactly as before — so there is no downside. If you
ever want to turn it off:

```bash
ALPHANUMERIC_WEBRTC_MESH=false ./alphanumeric
```

The mesh is **internet-only**: it connects using your public internet address (discovered via
standard STUN) and never scans, advertises, or connects to devices on your local network — so it
will not trigger any "allow access to your local network" prompt.

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
