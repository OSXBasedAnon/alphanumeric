# alphanumeric
![Screenshot_2025-01-04_213726](https://github.com/user-attachments/assets/0b5c747c-53f7-4e09-82c8-0e9bfbd8cd89)

alphanumeric is an advanced, high-performance blockchain written in Rust. It incorporates cutting-edge cryptographic and consensus algorithms to provide a secure, decentralized ledger.

## Key Features

- **Rust Architecture**: Built with Rust for memory safety, concurrency, and performance 
- **SHA-256 & BLAKE3 Hashing**: Uses industry standard SHA-256 for proof-of-work and BLAKE3 for fast, secure hashing
- **CPUPoW Consensus**: Implements ProgPoW for CPU (Programmatic Proof-of-Work) ASIC resistance 
- **CRYSTALS-Dilithium Quantum DSS**: Post-quantum ready digital signature scheme for future-proof security
- **BPoS Sentinel**: Unique BFT-based Proof-of-Stake consensus layer for validator security
- **Velocity Block Propagation**: Optimized block propagation protocol using erasure coding and subnet peer selection
- **Temporal Verification**: Time-based blockchain analysis for anomaly detection and fork resolution
- **Whisper Messaging**: Built-in peer-to-peer encrypted messaging with vanity fee codes
- **Sled Database**: Utilizes sled, a modern embedded database, for efficient blockchain storage
- **Argon2 Encrypted Wallets**: Wallet private keys encrypted using memory-hard Argon2 hashing

## Command Line Interface

alphanumeric provides an interactive command line interface for blockchain management:

### Wallet Commands
- `create <sender> <recipient> <amount>`: Create a new transaction
- `whisper <address> <msg>`: Send an encrypted message (vanity fee code can be added after amount)
- `balance`: Show all wallet balances  
- `new [wallet_name]`: Create a new wallet
- `account <address>`: Show detailed account information
- `history`: Display transaction history for loaded wallets
- `rename <old_name> <new_name>`: Rename an existing wallet

### Mining Commands  
- `mine <wallet_name>`: Mine a new block with the specified miner wallet

### Network Commands
- `--status` or `-s`: Show network connection status
- `--sync`: Perform a blockchain sync with the network  
- `--sync --force`: Force a full blockchain resync
- `--connect <ip:port>`: Manually connect to a network peer
- `--getpeers`: List all currently connected peers
- `--discover`: Actively search for new network peers

### Blockchain Commands
- `info`: Display detailed blockchain status including difficulty, hashrate, and more 
- `diagnostics`: Run blockchain diagnostic checks and display metrics

## Getting Started
You will need the blockchain.db for the application to run, make sure the blockchain.db folder is in the root directory.

To allow other nodes to connect to your blockchain node, you need to open port 7177 (TCP) in your router. You have to configure your server to accept incoming and outgoing connections for port 7177.

For **local connections in your Windows Firewall. Follow these steps:

1.  Open PowerShell as an administrator (right-click on PowerShell and select "Run as administrator").
2.  Run the following command:

```powershell
New-NetFirewallRule -Name "Alphanumeric Network" -DisplayName "Alphanumeric Network (Port 7177)" -Protocol TCP -LocalPort 7177 -Direction Inbound,Outbound -Action Allow
```
### Prerequisites
- Rust (stable toolchain)
- Cargo

## Website
https://www.empiremonster.com/p/alphanumeric.html

## Discord
https://discord.gg/D3r7TRcj9t

## License
This project is licensed under the MIT License.

## Acknowledgments
- The Rust community
- Claude
- Gemini
- Microsoft
