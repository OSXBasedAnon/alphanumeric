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
    wallet = None
    if os.path.exists(filename):
        try:
            wallet = Wallet.load_wallet(filename)  # Load the wallet properly
            print(f"Loaded wallet from {filename}")
        except Exception as e:
            print(f"Failed to load wallet from {filename}: {e}")
    else:
        if create_new:
            wallet = Wallet()
            try:
                wallet.save_wallet(filename)
                print(f"Created and saved new wallet to {filename}")
            except Exception as e:
                print(f"Failed to save new wallet to {filename}: {e}")
    return wallet

def save_public_key(wallet, filename):
    try:
        with open(filename, "wb") as f:
            public_key = wallet.get_public_key()
            f.write(public_key.encode('utf-8'))
        print(f"Public key saved to {filename}")
    except Exception as e:
        print(f"Failed to save public key to {filename}: {e}")

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

def generate_wallet_address(public_key):
    sha256_hash = hashlib.sha256(public_key.encode('utf-8')).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    address = base58.b58encode(ripemd160_hash).decode('utf-8')
    return address

def show_balance(wallet):
    if not hasattr(wallet, "cached_address"):
        wallet.cached_address = generate_wallet_address(wallet.get_public_key())
    print(f"Wallet Address: {wallet.cached_address}")
    print(f"Balance: {wallet.get_balance()} units")

if __name__ == "__main__":
    try:
        sender_wallet = check_and_load_wallet("sender_private_key.json", create_new=True)
        recipient_wallet = check_and_load_wallet("recipient_private_key.json", create_new=True)
        new_wallet = check_and_load_wallet("new_private_key.json", create_new=True)

        save_public_key(sender_wallet, "sender_public_key.pem")
        save_public_key(recipient_wallet, "recipient_public_key.pem")
        save_public_key(new_wallet, "new_public_key.pem")

        print(f"Sender Wallet Address: {generate_wallet_address(sender_wallet.get_public_key())}")
        print(f"Recipient Wallet Address: {generate_wallet_address(recipient_wallet.get_public_key())}")
        print(f"New Wallet Address: {generate_wallet_address(new_wallet.get_public_key())}")

        blockchain = Blockchain()
        blockchain.load_blockchain_from_file()

        blockchain_node = Node(host="localhost", port=5000, blockchain=blockchain)

        download_blockchain_from_node(blockchain, blockchain_node)

        # Register wallets with the blockchain
        blockchain.register_wallet(sender_wallet)
        blockchain.register_wallet(recipient_wallet)
        blockchain.register_wallet(new_wallet)

        miner_wallet = new_wallet

        print("Initial Blockchain:")
        for block in blockchain.chain:
            print(f"Block {block.index}: {block.transactions}")

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
                    for block in blockchain.chain:
                        print(f"Block {block.index}: {block.transactions}")
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
                    blockchain.save_blockchain_to_file()
                    save_public_key(sender_wallet, "sender_public_key.pem")
                    save_public_key(recipient_wallet, "recipient_public_key.pem")
                    save_public_key(new_wallet, "new_public_key.pem")
                    sender_wallet.save_wallet("sender_private_key.json")
                    recipient_wallet.save_wallet("recipient_private_key.json")
                    new_wallet.save_wallet("new_private_key.json")
                    print("Blockchain saved and program exited.")
                    break

                else:
                    print("Invalid command.")

            except Exception as e:
                print(f"An error occurred while processing the command: {e}")

    except Exception as e:
        print(f"An error occurred during setup: {e}")
