import os
from dogedark.blockchain import Blockchain
from dogedark.wallet import Wallet
from dogedark.node import Node
import threading
from cryptography.hazmat.primitives import serialization
import hashlib
import base58
import json


def check_and_load_wallet(filename, create_new=False):
    """Check if a wallet file exists, and load or create a new one"""
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            private_key = f.read()
        wallet = Wallet()
        wallet.load_wallet(private_key)
        print(f"Loaded wallet from {filename}")
    else:
        if create_new:
            wallet = Wallet()
            wallet.save_wallet(filename)
            print(f"Created and saved new wallet to {filename}")
        else:
            wallet = None
    return wallet


def save_public_key(wallet, filename):
    """Helper function to save public key in PEM format"""
    with open(filename, "wb") as f:
        public_key = wallet.get_public_key()
        f.write(public_key.encode('utf-8'))


def download_blockchain_from_node(blockchain, blockchain_node):
    """Fetch blockchain from node if it doesn't exist locally"""
    if not blockchain.check_if_loaded():  # Change is_loaded() to check_if_loaded()
        print("Downloading blockchain from the node...")
        blockchain_data = blockchain_node.get_blockchain()
        blockchain.load_blockchain_data(blockchain_data)
        print("Blockchain downloaded successfully.")


def generate_wallet_address(public_key):
    """Generate a human-readable wallet address (like Bitcoin) from the public key."""
    # Perform SHA-256 hashing
    sha256_hash = hashlib.sha256(public_key.encode('utf-8')).digest()
    # Perform RIPEMD-160 hashing
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    # Base58 encode the hash
    address = base58.b58encode(ripemd160_hash).decode('utf-8')
    return address


def show_balance(wallet):
    """Show balance and wallet ID (public key as address)"""
    wallet_address = generate_wallet_address(wallet.get_public_key())
    print(f"Wallet Address: {wallet_address}")
    print(f"Balance: {wallet.get_balance()} units")


if __name__ == "__main__":
    try:
        # Check and load wallets or create new ones if not found
        sender_wallet = check_and_load_wallet("sender_private_key.pem", create_new=True)
        recipient_wallet = check_and_load_wallet("recipient_private_key.pem", create_new=True)
        new_wallet = check_and_load_wallet("new_private_key.pem", create_new=True)

        # Save public keys
        save_public_key(sender_wallet, "sender_public_key.pem")
        save_public_key(recipient_wallet, "recipient_public_key.pem")
        save_public_key(new_wallet, "new_public_key.pem")

        # Initialize sender wallet with balance for testing
        sender_wallet.set_balance(100)

        # Print out the public keys (addresses) in PEM format
        print(f"Sender Wallet Address: {generate_wallet_address(sender_wallet.get_public_key())}")
        print(f"Recipient Wallet Address: {generate_wallet_address(recipient_wallet.get_public_key())}")
        print(f"New Wallet Address: {generate_wallet_address(new_wallet.get_public_key())}")

        # Set up blockchain and load it
        blockchain = Blockchain()
        blockchain.load_blockchain_from_file()  # This should call the correct method

        # Initialize blockchain node (assuming localhost and port 5000)
        blockchain_node = Node(host="localhost", port=5000, blockchain=blockchain)

        # Download blockchain from node if it isn't already loaded
        download_blockchain_from_node(blockchain, blockchain_node)

        # Register sender, recipient, and new wallet in the blockchain
        blockchain.register_wallet(sender_wallet)
        blockchain.register_wallet(recipient_wallet)
        blockchain.register_wallet(new_wallet)

        # Initialize miner wallet (for demonstration purposes, use the new wallet)
        miner_wallet = new_wallet

        # Display initial blockchain state
        print("Initial Blockchain:")
        for block in blockchain.chain:
            print(f"Block {block['index']}: {block['transactions']}")

        # Command-line interface for interaction
        while True:
            print("\nAvailable Commands:")
            print("1. Create Transaction (format: create sender recipient amount)")
            print("2. Mine Pending Transactions (format: mine miner_wallet)")
            print("3. Show Blockchain (format: show)")
            print("4. Show Balance (format: balance)")
            print("5. Exit")

            command = input("\nEnter command: ")

            try:
                if command.startswith("create"):
                    _, sender, recipient, amount = command.split()
                    amount = float(amount)

                    sender_wallet = blockchain.find_wallet_by_public_key(sender)
                    recipient_wallet = blockchain.find_wallet_by_public_key(recipient)

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
                    miner_wallet = blockchain.find_wallet_by_public_key(miner)
                    if miner_wallet:
                        blockchain_node.mine_pending_transactions(miner_wallet)
                        print(f"Mining started for wallet: {miner}")
                    else:
                        print("Invalid miner wallet address.")

                elif command.startswith("show"):
                    print("Blockchain after mining:")
                    for block in blockchain.chain:
                        print(f"Block {block['index']}: {block['transactions']}")
                    print(f"Miner Wallet Balance: {miner_wallet.get_balance()}")
                    print(f"Sender Wallet Balance: {sender_wallet.get_balance()}")
                    print(f"Recipient Wallet Balance: {recipient_wallet.get_balance()}")
                    print(f"New Wallet Balance: {new_wallet.get_balance()}")

                elif command.startswith("balance"):
                    print("\nWallet Balances and Addresses:")
                    show_balance(sender_wallet)
                    show_balance(recipient_wallet)
                    show_balance(new_wallet)

                elif command == "exit":
                    blockchain.save_blockchain()
                    save_public_key(sender_wallet, "sender_public_key.pem")
                    save_public_key(recipient_wallet, "recipient_public_key.pem")
                    save_public_key(new_wallet, "new_public_key.pem")
                    sender_wallet.save_wallet("sender_private_key.pem")
                    recipient_wallet.save_wallet("recipient_private_key.pem")
                    new_wallet.save_wallet("new_private_key.pem")
                    print("Blockchain saved and program exited.")
                    break

                else:
                    print("Invalid command.")

            except Exception as e:
                print(f"An error occurred while processing the command: {e}")

    except Exception as e:
        print(f"An error occurred during setup: {e}")
