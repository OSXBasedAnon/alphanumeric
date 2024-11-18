import hashlib
import json
import time
import random
import logging
import rsa
import threading
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric import rsa as cryptography_rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64

# Constants for Proof of Work and Tokenomics
INITIAL_DIFFICULTY = 4
BLOCK_REWARD = 50
TOTAL_SUPPLY = 21000000
DIFFICULTY_ADJUSTMENT_INTERVAL = 10
HALVING_INTERVAL = 210000
MAX_BLOCKS = 21000000
TRANSACTION_FEE = 0.01

# Generate private RSA key using cryptography package
def generate_private_key():
    return cryptography_rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

# Save the private key to a file
def save_private_key(private_key, filename="private_key.pem"):
    with open(filename, 'wb') as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

# Save the public key to a file
def save_public_key(public_key, filename="public_key.pem"):
    with open(filename, 'wb') as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

class Wallet:
    def __init__(self, private_key=None):
        if private_key:
            self.private_key = private_key
            self.public_key = private_key.public_key()
        else:
            self.private_key = self.generate_private_key()
            self.public_key = self.private_key.public_key()
        self.balance = 0

    def generate_private_key(self):
        # Use cryptography to generate an RSA private key
        return cryptography_rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def get_public_key(self):
        # Return the public key in PEM format (a readable format)
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    def update_balance(self, amount):
        # Update the wallet balance
        self.balance += amount

    def sign_transaction(self, transaction):
        transaction_copy = transaction.copy()
        transaction_copy.pop('signature', None)  # Remove signature field if it exists
        transaction_bytes = json.dumps(transaction_copy, sort_keys=True).encode()
        signature = self.private_key.sign(
            transaction_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def verify_transaction(self, transaction, signature):
        try:
            transaction_copy = transaction.copy()
            transaction_copy.pop('signature', None)  # Remove signature field if it exists
            transaction_bytes = json.dumps(transaction_copy, sort_keys=True).encode()
            decoded_signature = base64.b64decode(signature)
            self.public_key.verify(
                decoded_signature,
                transaction_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Transaction verification failed: {e}")
            return False

    def save_wallet(self, private_filename="private_key.pem", public_filename="public_key.pem"):
        save_private_key(self.private_key, private_filename)
        save_public_key(self.public_key, public_filename)

    def load_wallet(self, private_filename="private_key.pem"):
        with open(private_filename, 'rb') as private_file:
            private_key_data = private_file.read()
            self.private_key = serialization.load_pem_private_key(private_key_data, password=None, backend=default_backend())
            self.public_key = self.private_key.public_key()

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{self.transactions}"
        return progpow_algorithm(block_string, self.nonce)

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.difficulty = INITIAL_DIFFICULTY
        self.block_reward = BLOCK_REWARD
        self.lock = threading.Lock()
        self.token_supply = TOTAL_SUPPLY
        self.blocks_mined = 0
        self.wallets = {}  # Dictionary to store wallets by public key

    def create_genesis_block(self):
        return Block(0, "0", int(time.time()), [], 0)

    def add_block(self, new_block):
        with self.lock:
            self.chain.append(new_block)
            self.adjust_difficulty()
            self.update_block_reward()

    def adjust_difficulty(self):
        if len(self.chain) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0:
            expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL * 10  # Expected time in seconds
            actual_time = self.chain[-1].timestamp - self.chain[-DIFFICULTY_ADJUSTMENT_INTERVAL].timestamp
            if actual_time < expected_time / 2:
                self.difficulty += 1
            elif actual_time > expected_time * 2:
                self.difficulty -= 1

    def update_block_reward(self):
        if len(self.chain) % HALVING_INTERVAL == 0:
            self.block_reward /= 2

    def mine_pending_transactions(self, miner_wallet):
        block = Block(len(self.chain), self.chain[-1].hash, int(time.time()), self.pending_transactions)
        block.nonce = self.mine_block(block)
        self.add_block(block)
        miner_wallet.update_balance(self.block_reward)  # Reward for mining a block
        self.pending_transactions = []

    def mine_block(self, block):
        while True:
            if block.calculate_hash()[:self.difficulty] == '0' * self.difficulty:
                return block.nonce
            block.nonce += 1
            if self.blocks_mined >= MAX_BLOCKS:
                print("Max blocks reached! Token supply exhausted.")
                exit()  # Exit when the total supply is mined
            self.blocks_mined += 1

    def validate_block(self, block):
        if block.previous_hash == self.chain[-1].hash and block.hash == block.calculate_hash():
            for transaction in block.transactions:
                if not self.validate_transaction(transaction):
                    return False
            return True
        return False

    def validate_transaction(self, transaction):
        # Check transaction format
        required_fields = {'sender', 'recipient', 'amount', 'signature'}
        if not all(field in transaction for field in required_fields):
            print("Transaction format is invalid.")
            return False

        sender_wallet = self.find_wallet_by_public_key(transaction['sender'])
        if not sender_wallet:
            print(f"Sender wallet not found for public key: {transaction['sender']}")
            return False

        # Verify sender has enough balance
        if sender_wallet.balance < transaction['amount']:
            print(f"Insufficient funds in sender's wallet: {transaction['sender']}")
            return False

        # Check the signature
        if not sender_wallet.verify_transaction(transaction, transaction['signature']):
            print(f"Invalid signature for transaction: {transaction}")
            return False

        # Ensure the transaction includes the correct fee
        if transaction['amount'] < TRANSACTION_FEE:
            print("Transaction amount is less than the required fee.")
            return False

        # All checks passed
        return True

    def find_wallet_by_public_key(self, public_key):
        return self.wallets.get(public_key)  # Map to actual wallet objects

    def register_wallet(self, wallet):
        """Register a wallet in the blockchain."""
        self.wallets[wallet.get_public_key()] = wallet
        print(f"Wallet registered with public key: {wallet.get_public_key()}")

def create_wallet(self):
    private_key = generate_private_key()
    wallet = Wallet(private_key)
    self.register_wallet(wallet)
    return wallet

# Helper functions for ProgPoW (this part remains largely unchanged)
def progpow_algorithm(block_string, nonce):
    program = random_program()
    return progpow_hash(block_string, nonce, program)

def random_program():
    operations = ['+', '-', '*', '^', '|', '&']
    program = []
    for _ in range(64):
        op = random.choice(operations)
        num = random.randint(1, 10)
        program.append(f"{num}{op}")
    return program

def progpow_hash(block_string, nonce, program):
    # Example of how a hash could be computed, but this is simplified
    hash_input = f"{block_string}{nonce}{''.join(program)}"
    return hashlib.sha256(hash_input.encode()).hexdigest()

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{self.transactions}"
        return progpow_algorithm(block_string, self.nonce)

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.difficulty = INITIAL_DIFFICULTY
        self.block_reward = BLOCK_REWARD
        self.lock = threading.Lock()
        self.token_supply = TOTAL_SUPPLY
        self.blocks_mined = 0
        self.wallets = {}  # Dictionary to store wallets by public key

    def create_genesis_block(self):
        return Block(0, "0", int(time.time()), [], 0)

    def add_block(self, new_block):
        with self.lock:
            self.chain.append(new_block)
            self.adjust_difficulty()
            self.update_block_reward()

    def adjust_difficulty(self):
        if len(self.chain) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0:
            expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL * 10  # Expected time in seconds
            actual_time = self.chain[-1].timestamp - self.chain[-DIFFICULTY_ADJUSTMENT_INTERVAL].timestamp
            if actual_time < expected_time / 2:
                self.difficulty += 1
            elif actual_time > expected_time * 2:
                self.difficulty -= 1

    def update_block_reward(self):
        if len(self.chain) % HALVING_INTERVAL == 0:
            self.block_reward /= 2

    def register_wallet(self, wallet):
        """Register a wallet in the blockchain."""
        self.wallets[wallet.get_public_key()] = wallet
        print(f"Wallet registered with public key: {wallet.get_public_key()}")

    def create_transaction(self, sender_wallet, recipient_wallet, amount):
        """Create a transaction from sender to recipient."""
        if sender_wallet.balance < amount + TRANSACTION_FEE:
            print(f"Insufficient funds for transaction: {amount} units from sender to recipient")
            return False

        transaction = {
            'sender': sender_wallet.get_public_key(),
            'recipient': recipient_wallet.get_public_key(),
            'amount': amount
        }
        transaction['signature'] = sender_wallet.sign_transaction(transaction)

        # Verify the transaction is valid before adding it to the pending transactions
        if self.validate_transaction(transaction):
            self.pending_transactions.append(transaction)
            sender_wallet.update_balance(-amount - TRANSACTION_FEE)
            recipient_wallet.update_balance(amount)
            return True
        else:
            return False

    def mine_pending_transactions(self, miner_wallet):
        block = Block(len(self.chain), self.chain[-1].hash, int(time.time()), self.pending_transactions)
        block.nonce = self.mine_block(block)
        self.add_block(block)
        miner_wallet.update_balance(self.block_reward)  # Reward for mining a block
        self.pending_transactions = []

    def mine_block(self, block):
        while True:
            if block.calculate_hash()[:self.difficulty] == '0' * self.difficulty:
                return block.nonce
            block.nonce += 1
            if self.blocks_mined >= MAX_BLOCKS:
                print("Max blocks reached! Token supply exhausted.")
                exit()  # Exit when the total supply is mined
            self.blocks_mined += 1

    def validate_block(self, block):
        if block.previous_hash == self.chain[-1].hash and block.hash == block.calculate_hash():
            for transaction in block.transactions:
                if not self.validate_transaction(transaction):
                    return False
            return True
        return False

    def validate_transaction(self, transaction):
        # Check transaction format
        required_fields = {'sender', 'recipient', 'amount', 'signature'}
        if not all(field in transaction for field in required_fields):
            print("Transaction format is invalid.")
            return False

        sender_wallet = self.find_wallet_by_public_key(transaction['sender'])
        if not sender_wallet:
            print(f"Sender wallet not found for public key: {transaction['sender']}")
            return False

        # Verify sender has enough balance
        if sender_wallet.balance < transaction['amount']:
            print(f"Insufficient funds in sender's wallet: {transaction['sender']}")
            return False

        # Check the signature
        if not sender_wallet.verify_transaction(transaction, transaction['signature']):
            print(f"Invalid signature for transaction: {transaction}")
            return False

        # Ensure the transaction includes the correct fee
        if transaction['amount'] < TRANSACTION_FEE:
            print("Transaction amount is less than the required fee.")
            return False

        # All checks passed
        return True

    def find_wallet_by_public_key(self, public_key):
        return self.wallets.get(public_key)  # Map to actual wallet objects

    def save_blockchain(self, filename="blockchain.json"):
        with open(filename, 'w') as file:
            json_chain = [block.__dict__ for block in self.chain]
            json.dump(json_chain, file, indent=4)

    def load_blockchain(self, filename="blockchain.json"):
        try:
            with open(filename, 'r') as file:
                json_chain = json.load(file)
                self.chain = []
                for block_data in json_chain:
                    block = Block(
                        index=block_data['index'],
                        previous_hash=block_data['previous_hash'],
                        timestamp=block_data['timestamp'],
                        transactions=block_data['transactions'],
                        nonce=block_data['nonce']
                    )
                    block.hash = block_data['hash']
                    self.chain.append(block)
        except FileNotFoundError:
            self.chain = [self.create_genesis_block()]
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            self.chain = [self.create_genesis_block()]

class Node:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = set()
        self.server = None
        self.lock = threading.Lock()

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Node started at {self.host}:{self.port}")
        threading.Thread(target=self.accept_connections).start()

    def accept_connections(self):
        while True:
            client_socket, _ = self.server.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        request = client_socket.recv(1024).decode('utf-8')
        print(f"Received message: {request}")
        if request.startswith('GET /peers'):
            self.send_peers(client_socket)
        elif request.startswith('POST /transaction'):
            self.receive_transaction(client_socket, request)
        client_socket.close()

    def send_peers(self, client_socket):
        """Send the list of peers to a connected node."""
        with self.lock:
            peers_list = list(self.peers)
        client_socket.send(json.dumps(peers_list).encode('utf-8'))

    def receive_transaction(self, client_socket, request):
        """Receive a transaction from a connected node."""
        transaction_data = request.split("\n")[-1]  # assuming the transaction is the last line
        transaction = json.loads(transaction_data)
        print(f"Received transaction: {transaction}")

        # Here you could validate and process the transaction as necessary
        client_socket.send("Transaction received".encode('utf-8'))

    def add_peer(self, peer_address):
        """Add a peer to the network."""
        with self.lock:
            self.peers.add(peer_address)

    def remove_peer(self, peer_address):
        """Remove a peer from the network."""
        with self.lock:
            self.peers.discard(peer_address)

class BlockchainNode:
    def __init__(self, blockchain):
        self.blockchain = blockchain

    def start_mining(self, miner_wallet):
        with ThreadPoolExecutor(max_workers=4) as executor:
            executor.submit(self.blockchain.mine_pending_transactions, miner_wallet)

    def submit_transaction(self, sender_wallet, recipient_wallet, amount):
        with ThreadPoolExecutor(max_workers=4) as executor:
            executor.submit(self.blockchain.create_transaction, sender_wallet, recipient_wallet, amount)

    def run(self):
        print("Blockchain Node started...")
        while True:
            time.sleep(1)  # Simulate time passing, potentially for new transactions or blocks
            if self.blockchain.pending_transactions:
                self.start_mining(miner_wallet)

# Logging improvements for better debugging and monitoring
logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    try:
        # Create wallets for the sender, recipient, and a new wallet
        sender_wallet = Wallet()
        recipient_wallet = Wallet()
        new_wallet = Wallet()  # A new wallet to be registered in the blockchain

        # Save wallets
        sender_wallet.save_wallet("sender_private_key.pem", "sender_public_key.pem")
        recipient_wallet.save_wallet("recipient_private_key.pem", "recipient_public_key.pem")
        new_wallet.save_wallet("new_private_key.pem", "new_public_key.pem")

        # Initialize sender wallet with balance for testing
        sender_wallet.update_balance(100)  # Example balance

        # Print out the public keys (addresses) in PEM format
        print(f"Sender Wallet Address: {sender_wallet.get_public_key()}")
        print(f"Recipient Wallet Address: {recipient_wallet.get_public_key()}")
        print(f"New Wallet Address: {new_wallet.get_public_key()}")  # Print new wallet address

        # Set up blockchain and load if exists
        blockchain = Blockchain()
        blockchain.load_blockchain()

        # Register sender, recipient, and new wallet in the blockchain
        blockchain.register_wallet(sender_wallet)  
        blockchain.register_wallet(recipient_wallet)  
        blockchain.register_wallet(new_wallet)  # Register new wallet

        blockchain_node = BlockchainNode(blockchain)

        # Initialize miner wallet (for demonstration purposes, use the new wallet)
        miner_wallet = new_wallet

        # Display initial blockchain state
        print("Initial Blockchain:")
        for block in blockchain.chain:
            print(f"Block {block.index}: {block.transactions}")

        # Command-line interface for interaction
        while True:
            print("\nAvailable Commands:")
            print("1. Create Transaction (format: create sender recipient amount)")
            print("2. Mine Pending Transactions (format: mine miner_wallet)")
            print("3. Show Blockchain (format: show)")
            print("4. Exit")

            command = input("\nEnter command: ")

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
                    blockchain_node.start_mining(miner_wallet)
                    print(f"Mining started for wallet: {miner}")
                else:
                    print("Invalid miner wallet address.")

            elif command.startswith("show"):
                print("Blockchain after mining:")
                for block in blockchain.chain:
                    print(f"Block {block.index}: {block.transactions}")
                print(f"Miner Wallet Balance: {miner_wallet.balance}")
                print(f"Sender Wallet Balance: {sender_wallet.balance}")
                print(f"Recipient Wallet Balance: {recipient_wallet.balance}")
                print(f"New Wallet Balance: {new_wallet.balance}")

            elif command == "exit":
                # Save blockchain and wallets before exiting
                blockchain.save_blockchain()
                sender_wallet.save_wallet("sender_private_key.pem", "sender_public_key.pem")
                recipient_wallet.save_wallet("recipient_private_key.pem", "recipient_public_key.pem")
                new_wallet.save_wallet("new_private_key.pem", "new_public_key.pem")
                break

            else:
                print("Invalid command. Please try again.")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        print("Exiting the program.")
        # Optional: Keep the console open for a bit longer to see results
        import time
        time.sleep(5)  # Keeps the console open for 5 seconds after execution
