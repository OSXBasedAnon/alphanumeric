import hashlib
import base58
import requests
import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from dogedark.blockchain import Blockchain
from dogedark.wallet import Wallet
from dogedark.node import Node


def load_wallets(blockchain):
    """Load wallets from the blockchain by processing transactions."""
    transactions = flatten_transactions(blockchain)

    wallets = {}
    for transaction in transactions:
        sender = transaction.get('from')
        receiver = transaction.get('to')

        if sender and sender not in wallets:
            wallets[sender] = create_wallet_from_blockchain(sender, blockchain)
        if receiver and receiver not in wallets:
            wallets[receiver] = create_wallet_from_blockchain(receiver, blockchain)

    return wallets

def create_wallet_from_blockchain(address, blockchain):
    balance = get_balance_from_blockchain(address, blockchain)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    sha256_hash = hashlib.sha256(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    wallet_address = base58.b58encode(ripemd160_hash).decode('utf-8')

    # Return Wallet object instead of a dictionary
    wallet = Wallet(private_key, public_key, balance, wallet_address)
    return wallet

def generate_new_address(wallets, blockchain):
    """Generate a new wallet address and register it with the blockchain."""
    new_wallet = Wallet.create_wallet()  # Create a new wallet
    new_address = new_wallet.wallet_address
    wallet_name = f"wallet_{len(wallets) + 1}"
    
    # Register the new wallet with the blockchain
    blockchain.register_wallet(new_wallet)  # Ensure this wallet is on the blockchain
    
    wallets[wallet_name] = new_wallet  # Add to the local wallet list
    print(f"Generated new address: {new_address}")
    print(f"New wallet created with name: {wallet_name}")

    return new_address

def get_balance_from_blockchain(address, blockchain):
    balance = 0
    for block in blockchain.chain:
        for transaction in block['transactions']:
            if transaction.get('from') == address:
                balance -= transaction.get('amount', 0)
            if transaction.get('to') == address:
                balance += transaction.get('amount', 0)
    return balance

def flatten_transactions(blockchain):
    """Helper function to extract all transactions from the blockchain."""
    if not blockchain.chain:
        return []

    transactions = []
    if isinstance(blockchain.chain, dict):
        for block in blockchain.chain.values():
            transactions.extend(block.get('transactions', []))
    elif isinstance(blockchain.chain, list):
        for block in blockchain.chain:
            transactions.extend(block.get('transactions', []))
    
    return transactions

def save_wallets(wallets):
    print(f"Saving {len(wallets)} wallets to blockchain storage...")
    # You can implement actual saving logic here.


def serialize_public_key(wallet):
    public_key = wallet.public_key
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes


def generate_wallet_address(wallet):
    public_key = get_public_key(wallet)
    sha256_hash = hashlib.sha256(public_key.encode('utf-8')).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    wallet.wallet_address = base58.b58encode(ripemd160_hash).decode('utf-8')
    return wallet.wallet_address  # Return using dot notation as well

def show_balance(wallet):
    print(f"Wallet Address: {wallet.wallet_address}")
    print(f"Balance: {wallet.balance} units")

def get_public_key(wallet):
    if wallet.public_key is None:
        raise ValueError("Public key not generated.")
    return wallet.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

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
                blockchain.load_blockchain_data(blockchain_data)
                blockchain.save_blockchain_to_file()
            print("Blockchain downloaded and loaded successfully.")
        except Exception as e:
            print(f"Failed to download blockchain: {e}")

def generate_new_address(wallets):
    new_wallet = Wallet.create_wallet()
    new_address = new_wallet.wallet_address
    wallet_name = f"wallet_{len(wallets) + 1}"
    wallets[wallet_name] = new_wallet
    print(f"Generated new address: {new_address}")
    print(f"New wallet created with name: {wallet_name}")

    return new_address

def import_wallets(import_file='wallet.json'):
    # Check if the wallet file exists
    if not os.path.exists(import_file):
        print(f"{import_file} does not exist. Creating a new wallet file.")
        # Create an empty file if the wallet file doesn't exist
        with open(import_file, 'w') as f:
            json.dump([], f, indent=4)  # Empty list for now
        return {}

    with open(import_file, 'r') as f:
        wallets_data = json.load(f)

    # Debugging: Print the wallets_data to check the structure
    print("Wallet data loaded from file:", wallets_data)

    wallets = {}
    
    # Iterate through each wallet in the list (or dictionary, depending on structure)
    for wallet_data in wallets_data:
        print("Processing wallet:", wallet_data)  # Debugging each wallet entry

        # Ensure 'wallet_address' exists in each wallet
        if 'wallet_address' not in wallet_data:
            print(f"Error: Missing 'wallet_address' in wallet data: {wallet_data}")
            continue  # Skip this wallet if no wallet address is found

        wallet_name = wallet_data['wallet_address']
        private_key = serialization.load_pem_private_key(wallet_data['private_key'].encode('utf-8'), password=None)
        public_key = serialization.load_pem_public_key(wallet_data['public_key'].encode('utf-8'))

        # Recreate the Wallet object
        wallet = Wallet(private_key, public_key, wallet_data['balance'], wallet_name)
        wallets[wallet_name] = wallet

    print(f"Wallets imported from {import_file}.")
    return wallets

def export_wallets(wallets, export_file='wallet.json'):
    # Check if the file exists
    if os.path.exists(export_file):
        confirmation = input(f"Are you sure you want to overwrite {export_file}? (y/n): ")
        if confirmation.lower() != 'y':
            print("Export canceled.")
            return

    wallets_data = {}

    for wallet_name, wallet in wallets.items():
        private_key_bytes = wallet.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_key_bytes = wallet.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        wallets_data[wallet_name] = {
            'private_key': private_key_bytes,
            'public_key': public_key_bytes,
            'wallet_address': wallet.wallet_address,
            'balance': wallet.balance
        }
    with open(export_file, 'w') as f:
        json.dump(wallets_data, f, indent=4)
    
    print(f"Wallets exported to {export_file}.")

def main():
    try:
        blockchain = Blockchain()
        blockchain.load_blockchain_from_file()

        # Create the genesis block if the blockchain is empty
        if blockchain.chain == []:
            blockchain.create_genesis_block()

        # Load wallets from the file if they exist
        wallets = import_wallets()

        # If no wallets exist, create new ones and export to wallet.json
        if not wallets:
            wallets["sender_wallet"] = Wallet.create_wallet()
            wallets["recipient_wallet"] = Wallet.create_wallet()
            wallets["new_wallet"] = Wallet.create_wallet()

            # Save the newly created wallets to file
            export_wallets(wallets)  # This will save to 'wallet.json' by default

        # Register wallets with blockchain
        blockchain.register_wallet(wallets["sender_wallet"])
        blockchain.register_wallet(wallets["recipient_wallet"])
        blockchain.register_wallet(wallets["new_wallet"])

        # Print wallet addresses
        print(f"Sender Wallet Address: {wallets['sender_wallet'].wallet_address}")
        print(f"Recipient Wallet Address: {wallets['recipient_wallet'].wallet_address}")
        print(f"New Wallet Address: {wallets['new_wallet'].wallet_address}")

        # Get public IP address
        public_ip = get_public_ip()

        # Initialize blockchain node with public IP address
        blockchain_node = Node(host=public_ip, port=5000, blockchain=blockchain)

        # Download blockchain from node if not loaded locally
        download_blockchain_from_node(blockchain, blockchain_node)

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
            print("6. Export Wallets (format: export filename)")
            print("7. Import Wallets (format: import filename)")
            print("8. Exit")

            command = input("\nEnter command: ")

            try:
                if command.startswith("create"):
                    _, sender, recipient, amount = command.split()
                    amount = float(amount)

                    # Find sender and recipient wallets by address
                    sender_wallet = blockchain.find_wallet_by_address(sender)
                    recipient_wallet = blockchain.find_wallet_by_address(recipient)

                    if sender_wallet and recipient_wallet:
                        # Check sender balance and create transaction
                        if sender_wallet.balance >= amount:
                            transaction_success = blockchain.create_transaction(sender_wallet, recipient_wallet, amount)
                            if transaction_success:
                                print(f"Transaction created: {amount} units from {sender} to {recipient}")
                            else:
                                print(f"Failed to create transaction from {sender} to {recipient}")
                        else:
                            print(f"Sender wallet does not have enough balance.")
                    else:
                        print("Sender or Recipient not found.")

                elif command.startswith("mine"):
                    _, wallet_name = command.split()  # Renamed miner_wallet_name to wallet_name
                    wallet = blockchain.find_wallet_by_address(wallet_name)
                    if wallet:  # Proceed if the wallet exists
                        blockchain.mine_pending_transactions(wallet)  # Use the wallet for mining
                        print(f"Mining completed with wallet {wallet.wallet_address}")
                    else:
                        print(f"Wallet {wallet_name} not found.")

                elif command.startswith("show"):
                    print_blockchain_info(blockchain)

                elif command.startswith("balance"):
                    parts = command.split()
                    if len(parts) == 1:
                        # Show balance of all wallets
                        print("Showing all wallets and balances:")
                        for wallet_name, wallet in wallets.items():
                            show_balance(wallet)
                    elif len(parts) == 2:
                        # Show balance of a specific wallet
                        _, wallet_name = parts
                        wallet = wallets.get(wallet_name)
                        if wallet:
                            show_balance(wallet)
                        else:
                            print(f"Wallet {wallet_name} not found.")
                    else:
                        print("Invalid balance command. Use 'balance' to show all wallets or 'balance wallet_name' to show a specific wallet's balance.")

                elif command.startswith("new"):
                    new_wallet = Wallet.create_wallet()
                    wallets[f"wallet_{len(wallets)+1}"] = new_wallet
                    blockchain.register_wallet(new_wallet)  # Register new wallet with blockchain
                    print(f"New wallet address: {new_wallet.wallet_address}")

                elif command.startswith("export"):
                    _, filename = command.split()
                    export_wallets(wallets, filename)

                elif command.startswith("import"):
                    _, filename = command.split()
                    wallets = import_wallets(filename)

                elif command.startswith("exit"):
                    break
                else:
                    print("Unknown command.")
            except Exception as e:
                print(f"Error: {e}")
    except Exception as e:
        print(f"Error initializing blockchain or wallet: {e}")

if __name__ == "__main__":
    main()
