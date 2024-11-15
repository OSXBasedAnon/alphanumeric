import hashlib
import time
import random
import logging
import threading
import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

# Constants
INITIAL_DIFFICULTY = 4
BLOCK_REWARD = 50
TOTAL_SUPPLY = 21000000
DIFFICULTY_ADJUSTMENT_INTERVAL = 10
HALVING_INTERVAL = 210000
MAX_BLOCKS = 21000000
TRANSACTION_FEE = 0.01

# ProgPoW functions
def progpow_algorithm(block_string, nonce):
    print("progpow_algorithm function called")
    start_time = time.time()
    program = random_program()
    result = progpow_hash(block_string, nonce, program)
    end_time = time.time()
    print(f"Hash computation took: {end_time - start_time:.6f} seconds")
    return result

def random_program(length=64):
    print("random_program function called")
    operations = ['+', '-', '*', '^', '|', '&']
    program = []
    for _ in range(length):
        op = random.choice(operations)
        num = random.randint(1, 10)
        program.append(f"{num}{op}")
    return program

def progpow_hash(block_string, nonce, program):
    print("progpow_hash function called")
    hash_input = f"{block_string}{nonce}{''.join(program)}"
    hash_output = hashlib.sha256(hash_input.encode()).hexdigest()
    print(f"Program: {''.join(program)}\nHash: {hash_output}")
    return hash_output

def efficient_random_program(length=64, seed=None):
    print("efficient_random_program function called")
    if seed is not None:
        random.seed(seed)
    operations = ['+', '-', '*', '^', '|', '&']
    return [f"{random.randint(1, 10)}{random.choice(operations)}" for _ in range(length)]

def optimized_progpow_hash(block_string, nonce, program):
    print("optimized_progpow_hash function called")
    hash_input = f"{block_string}{nonce}{''.join(program)}"
    hasher = hashlib.sha256()
    hasher.update(hash_input.encode())
    return hasher.hexdigest()

class Wallet:
    def __init__(self, private_key=None):
        if private_key is None:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
        else:
            self.private_key = private_key
        self.public_key = self.private_key.public_key()
        self.balance = 0
        logging.info(f"Wallet created. Public Key Type: {type(self.public_key)}")
        
    def get_public_key_pem(self):
        """Get the public key in PEM format as bytes."""
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logging.info(f"Retrieved Public Key PEM: {public_key_pem}")
        return public_key_pem

    def get_public_key(self):
        """Get the public key in PEM format as string."""
        return self.get_public_key_pem().decode('utf-8')

    def sign_transaction(self, transaction):
        transaction_string = json.dumps(transaction, sort_keys=True)
        signature = self.private_key.sign(
            transaction_string.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_transaction(self, transaction, signature):
        try:
            transaction_string = json.dumps(transaction, sort_keys=True)
            self.public_key.verify(
                signature,
                transaction_string.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def update_balance(self, amount):
        self.balance += amount
        
def to_dict(self):
    return {
        'balance': self.balance,
        'public_key': self.get_public_key_pem().decode('utf-8')  # Ensure it's in PEM format
    }

import hashlib

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0, hash=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.hash = hash if hash else self.calculate_hash()  # Use provided hash, else calculate it

    def calculate_hash(self):
        # Calculates the hash (example using SHA-256)
        return hashlib.sha256(f"{self.index}{self.previous_hash}{self.timestamp}{self.transactions}{self.nonce}".encode('utf-8')).hexdigest()

    def __getitem__(self, key):
        # Allows subscript access to Block attributes (e.g., block['index'])
        return getattr(self, key)

    def __str__(self):
        return f"Block(index={self.index}, transactions={self.transactions}, nonce={self.nonce})"

    def to_dict(self):
        return {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'nonce': self.nonce,
            'hash': self.hash
        }

    @classmethod
    def from_dict(cls, block_dict):
        block = cls(
            block_dict['index'],
            block_dict['previous_hash'],
            block_dict['timestamp'],
            block_dict['transactions'],
            block_dict['nonce']
        )
        block.hash = block_dict['hash']
        return block

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.difficulty = INITIAL_DIFFICULTY
        self.block_reward = BLOCK_REWARD
        self.lock = threading.Lock()
        self.token_supply = TOTAL_SUPPLY
        self.blocks_mined = 0
        self.wallets = {}
        self._is_loaded = False  # Private attribute to track if blockchain is loaded

    def load_blockchain_from_file(self, filename='blockchain_state.json'):
        """Load the blockchain state from a file."""
        try:
            if not os.path.exists(filename):
                print(f"No saved state found at {filename}")
                return False

            with open(filename, 'r') as f:
                state = json.load(f)

            self.chain = [Block.from_dict(block_dict) for block_dict in state['chain']]
            self.pending_transactions = state['pending_transactions']
            self.difficulty = state['difficulty']
            self.block_reward = state['block_reward']
            self.token_supply = state['token_supply']
            self.blocks_mined = state['blocks_mined']

            print(f"Blockchain state loaded from {filename}")
            self._is_loaded = True  # Set to True after loading successfully
            return True
        except Exception as e:
            print(f"Error loading blockchain state: {e}")
            return False

    def check_if_loaded(self):
        """Check if the blockchain has been loaded."""
        return self._is_loaded

    def to_dict(self):
        """Convert blockchain to dictionary for serialization."""
        return {
            'chain': [block.to_dict() for block in self.chain],
            'pending_transactions': self.pending_transactions,
            'difficulty': self.difficulty,
            'block_reward': self.block_reward,
            'token_supply': self.token_supply,
            'blocks_mined': self.blocks_mined
        }

    def load_from_dict(self, data):
        """Load blockchain from dictionary data."""
        with self.lock:
            self.chain = [Block.from_dict(block_data) for block_data in data['chain']]
            self.pending_transactions = data['pending_transactions']
            self.difficulty = data['difficulty']
            self.block_reward = data['block_reward']
            self.token_supply = data['token_supply']
            self.blocks_mined = data['blocks_mined']

    def get_latest_block(self):
        """Get the most recent block in the chain."""
        return self.chain[-1]

    def is_valid_chain(self, chain=None):
        """Validate the entire blockchain."""
        if chain is None:
            chain = self.chain

        if len(chain) == 0:
            return False

        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]

            # Verify block hash
            if current_block.hash != current_block.calculate_hash():
                return False

            # Verify block link
            if current_block.previous_hash != previous_block.hash:
                return False

            # Verify transactions in block
            for transaction in current_block.transactions:
                if not self.validate_transaction(transaction):
                    return False

        return True

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
        miner_wallet.update_balance(self.block_reward)
        self.pending_transactions = []

    def mine_block(self, block):
        while True:
            if block.calculate_hash()[:self.difficulty] == '0' * self.difficulty:
                return block.nonce
            block.nonce += 1
            if self.blocks_mined >= MAX_BLOCKS:
                print("Max blocks reached! Token supply exhausted.")
                exit()
            self.blocks_mined += 1

    def validate_block(self, block):
        if block.previous_hash == self.chain[-1].hash and block.hash == block.calculate_hash():
            for transaction in block.transactions:
                if not self.validate_transaction(transaction):
                    return False
            return True
        return False

    def validate_transaction(self, transaction):
        required_fields = {'sender', 'recipient', 'amount', 'signature'}
        if not all(field in transaction for field in required_fields):
            print("Transaction format is invalid.")
            return False

        sender_wallet = self.find_wallet_by_public_key(transaction['sender'])
        if not sender_wallet:
            print(f"Sender wallet not found for public key: {transaction['sender']}")
            return False

        if sender_wallet.balance < transaction['amount']:
            print(f"Insufficient funds in sender's wallet: {transaction['sender']}")
            return False

        if not sender_wallet.verify_transaction(transaction, transaction['signature']):
            print(f"Invalid signature for transaction: {transaction}")
            return False

        if transaction['amount'] < TRANSACTION_FEE:
            print("Transaction amount is less than the required fee.")
            return False

        return True

    def find_wallet_by_public_key(self, public_key):
        return self.wallets.get(public_key)

    def register_wallet(self, wallet):
        # Convert the public key to its string representation in PEM format
        public_key_str = wallet.get_public_key()
        
        # Now use the PEM format as the dictionary key
        self.wallets[public_key_str] = wallet

    def create_wallet(self):
        wallet = Wallet()
        self.register_wallet(wallet)
        return wallet

    def save_blockchain(self, filename='blockchain_state.json'):
        """Save the current state of the blockchain to a file."""
        state = {
            'chain': [block.to_dict() for block in self.chain],
            'pending_transactions': self.pending_transactions,
            'difficulty': self.difficulty,
            'block_reward': self.block_reward,
            'token_supply': self.token_supply,
            'blocks_mined': self.blocks_mined,
            'wallets': {k: w.to_dict() for k, w in self.wallets.items()}
        }

        try:
            with open(filename, 'w') as f:
                json.dump(state, f, indent=4)
            print(f"Blockchain state saved to {filename}")
        except Exception as e:
            print(f"Error saving blockchain state: {e}")
