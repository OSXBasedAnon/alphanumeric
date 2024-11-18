import os
import requests
import json
import hashlib
import base58
import logging
from dogedark.blockchain import Blockchain
from dogedark.wallet import Wallet
from dogedark.node import Node
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_wallets():
    filename = "wallet.json"
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                wallets_data = json.load(f)
                wallets = {}
                for name, data in wallets_data.items():
                    wallet = Wallet.from_dict(data)
                    wallets[name] = wallet
                    # Ensure address is generated and saved if missing
                    if not wallet.wallet_address:
                        wallet.wallet_address = wallet.get_wallet_address()
                print(f"Loaded wallets from {filename}")
            return wallets
        except Exception as e:
            print(f"Failed to load wallets from {filename}: {e}")
            return {}
    else:
        return {}

def save_wallets(wallets):
    filename = "wallet.json"
    try:
        wallets_data = {}
        for name, wallet in wallets.items():
            # Ensure address is generated using get_wallet_address() method
            wallet_data = wallet.to_dict()  
            wallets_data[name] = wallet_data
        
        with open(filename, 'w') as f:
            json.dump(wallets_data, f)
        print(f"Saved wallets to {filename}")
    except Exception as e:
        print(f"Failed to save wallets to {filename}: {e}")

class Wallet:
    def __init__(self, private_key=None):
        if private_key is None:
            self.generate_keys()
        else:
            self.private_key = private_key
            self.public_key = private_key.public_key()
        self.balance = 0
        self.wallet_address = None

    def generate_keys(self):
        """Generate private and public keys."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def get_public_key(self):
        """Return the public key in PEM format."""
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_pem.decode('utf-8')

    def get_private_key(self):
        """Return the private key in PEM format."""
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key_pem.decode('utf-8')

    def get_wallet_address(self):
        """Generate and return the wallet address based on the public key."""
        # Get the public key in DER format (binary format)
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Hash the public key using SHA256 and RIPEMD160
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

        # Base58 encode the resulting hash to generate the wallet address
        wallet_address = base58.b58encode(ripemd160_hash).decode('utf-8')
        
        return wallet_address

    def to_dict(self):
        """Convert the wallet object to a dictionary for serialization."""
        return {
            'balance': self.balance,
            'public_key': self.get_public_key(),
            'wallet_address': self.get_wallet_address(),  # This ensures the address is generated from the public key
            'private_key': self.get_private_key()
        }

    @classmethod
    def from_dict(cls, wallet_dict):
        """Load a wallet from a dictionary."""
        # Load the private key from PEM
        private_key_pem = wallet_dict.get('private_key')
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
        
        # Create wallet instance using the private key
        wallet = cls(private_key)
        
        # Set balance from the dictionary
        wallet.balance = wallet_dict.get('balance', 0)
        
        # Set wallet address. It should always be derived from the public key.
        wallet.wallet_address = wallet.get_wallet_address()  # Always regenerate the address based on the public key
        
        return wallet

def generate_wallet_address(wallet):
    """Generate a unique wallet address based on the wallet's public key."""
    public_key = wallet.get_public_key()
    sha256_hash = hashlib.sha256(public_key.encode('utf-8')).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    address = base58.b58encode(ripemd160_hash).decode('utf-8')
    wallet.wallet_address = address
    return wallet.wallet_address

def create_wallet():
    """Create a wallet with a new unique key pair and address."""
    wallet = Wallet()  # Initialize a new wallet
    generate_wallet_address(wallet)  # Generate a unique address based on the new keys
    return wallet

def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org")
        public_ip = response.text
        print(f"Public IP Address: {public_ip}")
        return public_ip
    except requests.exceptions.RequestException as e:
        print(f"Error fetching public IP: {e}")
        return "localhost"

def format_transaction_data(transaction):
    return {
        'From': transaction.get('from', 'Unknown'),
        'To': transaction.get('to', 'Unknown'),
        'Amount': transaction.get('amount', 'Unknown'),
    }

def print_blockchain_info(blockchain):
    print(f"Blockchain loaded with {len(blockchain.chain)} blocks.")

import logging

def download_blockchain_from_node(blockchain, blockchain_node):
    """
    Download blockchain from a node if not loaded locally.
    """
    if not blockchain.check_if_loaded():
        print("Blockchain not loaded locally. Attempting to download...")
        try:
            blockchain.load_blockchain_from_file()
            if not blockchain.check_if_loaded():
                # Ensure correct method call
                blockchain_data = blockchain_node.get_blockchain()  # Adjust as needed
                blockchain.load_from_dict(blockchain_data)
                blockchain.save_to_file()
            print("Blockchain downloaded and loaded successfully.")
        except Exception as e:
            print(f"Failed to download blockchain: {e}")
            logging.error(f"Error downloading blockchain: {e}")
            raise

def get_public_key(self):
    """Return the public key as a string."""
    if self.public_key is None:
        raise ValueError("Public key not generated.")
    return self.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def generate_new_address(wallets):
    """Generate a completely new address by creating a new Wallet instance."""
    new_wallet = create_wallet()  # Create a fresh wallet
    new_address = new_wallet.address  # Get the address from the newly created wallet

    # Save the new wallet to the wallets dictionary
    wallet_name = f"wallet_{len(wallets) + 1}"
    wallets[wallet_name] = new_wallet

    print(f"Generated new address: {new_address}")
    print(f"New wallet created with name: {wallet_name}")
    
    return new_address

def get_blockchain_details(chain, pending_transactions, current_block):
    """
    Gather the details about the blockchain to display.
    Args:
        chain: List of blocks in the blockchain
        pending_transactions: List of pending transactions
        current_block: Current block number
    """
    try:
        blockchain_details = {
            'block_count': len(chain),
            'total_supply': sum(block['transactions'].get('amount', 0) for block in chain if 'transactions' in block),
            'current_block_reward': get_current_block_reward(current_block),
            'pending_transactions': len(pending_transactions),
            'chain': chain
        }
        return blockchain_details
    except Exception as e:
        print(f"Error gathering blockchain details: {e}")
        return None

def get_current_block_reward(current_block):
    """
    Dynamically calculate the block reward based on the current block number.
    Args:
        current_block: Current block number
    """
    initial_reward = 50
    halving_interval = 210000
    halvings = current_block // halving_interval
    reward = initial_reward / (2 ** halvings)
    return max(reward, 1)  # Minimum reward of 1

def show_balance(wallets, blockchain):
    print("\nWallet Balances:")
    for wallet_name, wallet in wallets.items():
        try:
            # Get balance directly from wallet object
            balance = wallet.balance if hasattr(wallet, 'balance') else 0
            
            # Get address from wallet object
            address = wallet.wallet_address if hasattr(wallet, 'wallet_address') else generate_wallet_address(wallet)

            print(f"Wallet Address: {address}")
            print(f"Balance: {balance} units\n")
        except Exception as e:
            print(f"Error displaying balance for {wallet_name}: {e}\n")


def main():
    try:
        # Load wallets from file
        wallets = load_wallets()

        # Initialize predefined wallets if they don't exist
        predefined_wallets = ["sender_wallet", "recipient_wallet", "new_wallet"]
        for wallet_name in predefined_wallets:
            if wallet_name not in wallets:
                new_wallet = create_wallet()
                wallets[wallet_name] = new_wallet

        # Save wallets to ensure they are persisted
        save_wallets(wallets)

        # Display the current wallet addresses
        print(f"Sender Wallet Address: {generate_wallet_address(wallets['sender_wallet'])}")
        print(f"Recipient Wallet Address: {generate_wallet_address(wallets['recipient_wallet'])}")
        print(f"New Wallet Address: {generate_wallet_address(wallets['new_wallet'])}")

        # Initialize blockchain
        blockchain = Blockchain()
        blockchain.load_blockchain_from_file()

        # Get public IP address
        public_ip = get_public_ip()

        # Initialize blockchain node with public IP address
        blockchain_node = Node(host=public_ip, port=5000, blockchain=blockchain)

        # Download blockchain from node if not loaded locally
        download_blockchain_from_node(blockchain, blockchain_node)

        # Register wallets with the blockchain
        blockchain.register_wallet(wallets["sender_wallet"])
        blockchain.register_wallet(wallets["recipient_wallet"])
        blockchain.register_wallet(wallets["new_wallet"])

        miner_wallet = wallets["new_wallet"]

        # Display initial blockchain info
        print("Initial Blockchain:")
        print_blockchain_info(blockchain)

        while True:
            print("\nAvailable Commands:")
            print("1. Create Transaction (format: create sender recipient amount)")
            print("2. Mine Pending Transactions (format: mine miner_wallet)")
            print("3. Show Blockchain (format: show)")
            print("4. Show Balance (format: balance)")
            print("5. Create New Wallet Address (format: new)")
            print("6. Exit")

            command = input("\nEnter command: ")

            # Process commands
            if command.startswith("create"):
                try:
                    _, sender, recipient, amount = command.split()
                    amount = float(amount)

                    sender_wallet = blockchain.find_wallet_by_address(sender)
                    recipient_wallet = blockchain.find_wallet_by_address(recipient)

                    if sender_wallet and recipient_wallet:
                        transaction_success = blockchain.create_transaction(sender_wallet, recipient_wallet, amount)
                        if transaction_success:
                            print(f"Transaction created: {amount} units from {sender} to {recipient}")
                        else:
                            print(f"Failed to create transaction: {amount} units from {sender} to {recipient}")
                    else:
                        print("Invalid sender or recipient wallet address.")
                except Exception as e:
                    print(f"Error creating transaction: {e}")

            elif command.startswith("mine"):
                try:
                    _, miner = command.split()
                    miner_wallet = blockchain.find_wallet_by_address(miner)
                    if miner_wallet:
                        blockchain.mine_pending_transactions(miner_wallet.wallet_address)
                        print(f"Mining started for wallet: {miner}")
                    else:
                        print("Invalid miner wallet address.")
                except Exception as e:
                    print(f"Error mining transactions: {e}")

            elif command.startswith("show"):
                try:
                    # Fetch the latest block to use as current_block
                    current_block = blockchain.get_latest_block()

                    if current_block is None:
                        print("Blockchain is empty or invalid. Cannot show details.")
                        continue

                    # Fetch blockchain details
                    blockchain_details = blockchain.get_blockchain_details()

                    if not blockchain_details:
                        print("Error: Blockchain details could not be fetched.")
                        continue

                    # Display the most recent blocks (limit to 5 most recent)
                    num_recent_blocks = 5
                    recent_blocks = blockchain_details[-num_recent_blocks:]

                    if not recent_blocks:
                        print("No recent blocks found in the blockchain.")
                        continue

                    print("\nLatest Blocks:")
                    for block in recent_blocks:
                        print(f"Block #{block['block_id']}:")
                        print(f"  Block Hash: {block['hash']}")
                        print(f"  Previous Block Hash: {block['previous_hash']}")
                        print(f"  Timestamp: {block['timestamp']}")
                        print(f"  Transactions: {block['transactions']}")

                    # Show the user's wallet balance
                    print(f"Wallet Balance: {miner_wallet.get_balance()} units")
                except Exception as e:
                    print(f"Error showing blockchain details: {e}")

            elif command.startswith("balance"):
                try:
                    # Now calling show_balance with the full wallets dictionary and blockchain instance
                    show_balance(wallets, blockchain)  # Display balance for all wallets
                except Exception as e:
                    print(f"Error showing balance: {e}")

            elif command.startswith("new"):
                try:
                    # Create a new wallet dynamically and add it to the wallets dictionary
                    new_wallet = create_wallet()
                    new_wallet_name = f"wallet_{len(wallets) + 1}"  # Generate a new unique name
                    wallets[new_wallet_name] = new_wallet  # Add the new wallet to the dictionary
                    new_address = generate_wallet_address(new_wallet)
                    print(f"New wallet created: {new_wallet_name}")
                    print(f"New wallet address: {new_address}")

                    # Register the new wallet with the blockchain
                    blockchain.register_wallet(wallets[new_wallet_name])  # Ensure it gets registered on the blockchain
                    print(f"New wallet {new_wallet_name} registered on the blockchain.")

                    save_wallets(wallets)
                except Exception as e:
                    print(f"Error creating new wallet: {e}")

            elif command == "exit":
                try:
                    blockchain.save_to_file()
                    save_wallets(wallets)
                    print("Blockchain saved and program exited.")
                    break
                except Exception as e:
                    print(f"Error during exit: {e}")

            else:
                print("Invalid command.")

    except Exception as e:
        print(f"An error occurred during setup: {e}")


if __name__ == "__main__":
    main()
