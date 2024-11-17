import os
import requests
import json
import hashlib
import base58
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
                wallets = {name: Wallet.from_dict(data) for name, data in wallets_data.items()}
            print(f"Loaded wallets from {filename}")
            return wallets
        except Exception as e:
            print(f"Failed to load wallets from {filename}: {e}")
            return {}
    else:
        return {}

def to_dict(self):
    return {
        'balance': self.balance,
        'public_key': self.get_public_key(),
        'wallet_address': self.wallet_address,
        'private_key': self.get_private_key()
    }

@classmethod
def from_dict(cls, wallet_dict):
    private_key_pem = wallet_dict.get('private_key')
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    wallet = cls(private_key)
    wallet.balance = wallet_dict.get('balance', 0)
    wallet.wallet_address = wallet_dict.get('wallet_address')
    return wallet

def get_private_key(self):
    private_key_pem = self.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key_pem.decode('utf-8')

def save_wallets(wallets):
    filename = "wallet.json"
    try:
        wallets_data = {name: wallet.to_dict() for name, wallet in wallets.items()}
        with open(filename, 'w') as f:
            json.dump(wallets_data, f)
        print(f"Saved wallets to {filename}")
    except Exception as e:
        print(f"Failed to save wallets to {filename}: {e}")

def create_wallet():
    wallet = Wallet()
    return wallet

def generate_wallet_address(wallet):
    public_key = wallet.get_public_key()
    sha256_hash = hashlib.sha256(public_key.encode('utf-8')).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    address = base58.b58encode(ripemd160_hash).decode('utf-8')
    wallet.address = address  # Store the address in the wallet instance
    return address

def create_wallet():
    wallet = Wallet()
    wallet.generate_keys()  # Ensure unique key generation
    generate_wallet_address(wallet)  # Generate address and assign it to the wallet
    return wallet

def show_balance(wallet):
    if not hasattr(wallet, "cached_address"):
        wallet.cached_address = generate_wallet_address(wallet.get_public_key())
    print(f"Wallet Address: {wallet.cached_address}")
    print(f"Balance: {wallet.get_balance()} units")

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

def download_blockchain_from_node(blockchain, blockchain_node):
    if not blockchain.check_if_loaded():
        print("Blockchain not loaded locally. Attempting to download...")
        try:
            blockchain.load_blockchain_from_file()
            if not blockchain.check_if_loaded():
                blockchain_data = blockchain_node.get_blockchain()
                blockchain.load_from_dict(blockchain_data)
                blockchain.save_blockchain_to_file()
            print("Blockchain downloaded and loaded successfully.")
        except Exception as e:
            print(f"Failed to download blockchain: {e}")

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

def main():
    try:
        # Load wallets from file
        wallets = load_wallets()
        if "sender_wallet" not in wallets:
            wallets["sender_wallet"] = create_wallet()
        if "recipient_wallet" not in wallets:
            wallets["recipient_wallet"] = create_wallet()
        if "new_wallet" not in wallets:
            wallets["new_wallet"] = create_wallet()
        
        save_wallets(wallets)

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

            try:
                if command.startswith("create"):
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

                elif command.startswith("mine"):
                    _, miner = command.split()
                    miner_wallet = blockchain.find_wallet_by_address(miner)
                    if miner_wallet:
                        blockchain.mine_pending_transactions(miner_wallet.wallet_address)
                        print(f"Mining started for wallet: {miner}")
                    else:
                        print("Invalid miner wallet address.")

                elif command.startswith("show"):
                    print("Blockchain after mining:")
                    print_blockchain_info(blockchain)
                    print(f"Wallet Balance: {miner_wallet.get_balance()}")

                elif command.startswith("balance"):
                    print("\nWallet Balances:")
                    show_balance(wallets["sender_wallet"])  # Pass the wallet object instead of address

                elif command.startswith("new"):
                    for wallet_name, wallet in wallets.items():
                        new_address = generate_wallet_address(wallet)  # Explicitly generate the address
                        print(f"New address for wallet '{wallet_name}': {new_address}")
                    
                    # Save wallets with new addresses
                    save_wallets(wallets)

                elif command == "exit":
                    blockchain.save_blockchain_to_file()
                    save_wallets(wallets)
                    print("Blockchain saved and program exited.")
                    break

                else:
                    print("Invalid command.")

            except Exception as e:
                print(f"An error occurred while processing the command: {e}")

    except Exception as e:
        print(f"An error occurred during setup: {e}")

# Function to show wallet balances
def show_balance(wallet):
    if not hasattr(wallet, "cached_address"):
        wallet.cached_address = generate_wallet_address(wallet)  # Correctly uses the Wallet object
    print(f"Wallet Address: {wallet.cached_address}")
    print(f"Balance: {wallet.get_balance()} units")

if __name__ == "__main__":
    main()
