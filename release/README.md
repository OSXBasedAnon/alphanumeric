# Alphanumeric Client User Guide

This download contains Alphanumeric client version 7.3.7 for macOS.

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

When the client starts, it checks for local chain data. If no usable `blockchain.db` exists, it downloads the current bootstrap snapshot from the Alphanumeric gateway and verifies it before using it.

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

## Troubleshooting

If the client says another instance is running, make sure no other `alphanumeric` process is open.

If the client cannot connect to peers, leave it open for a minute, then run:

```text
info
```

If the chain database gets corrupted or you want to start from the latest bootstrap again, stop the client, move the old database aside, and start again:

```bash
mv blockchain.db blockchain.db.backup
./alphanumeric
```

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
