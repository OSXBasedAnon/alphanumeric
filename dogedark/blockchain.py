import hashlib
import time
import logging
import threading
import json
import os
import random
from dogedark.wallet import Wallet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature

# Constants
INITIAL_DIFFICULTY = 4
BLOCK_REWARD = 50
TOTAL_SUPPLY = 21000000
DIFFICULTY_ADJUSTMENT_INTERVAL = 10
BLOCKCHAIN_FILE_PATH = 'blockchain_state.json'

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ProgPoW functions (streamlined)
def progpow_algorithm(block_string, nonce, difficulty):
    """Simulates a ProgPoW algorithm with difficulty."""
    program = deterministic_program(block_string, nonce)
    hash_result = progpow_hash(block_string, nonce, program)
    
    # Difficulty: hash must have certain leading zeros
    target = '0' * difficulty
    while not hash_result.startswith(target):
        nonce += 1
        program = deterministic_program(block_string, nonce)
        hash_result = progpow_hash(block_string, nonce, program)
    
    return hash_result, nonce  # Return the valid hash and the nonce used

def deterministic_program(block_string, nonce, length=64):
    """Generates a deterministic sequence of operations based on block data."""
    operations = ['+', '-', '*', '^', '|', '&']
    return [f"{(hashlib.sha256((block_string + str(nonce)).encode()).hexdigest()[i % 64])}{random.choice(operations)}" for i in range(length)]

def progpow_hash(block_string, nonce, program):
    """Generates a hash using SHA-256."""
    hash_input = f"{block_string}{nonce}{''.join(program)}"
    return hashlib.sha256(hash_input.encode()).hexdigest()

class Block:
    """Represents a block in the blockchain."""
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0, hash=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.hash = hash or self.calculate_hash()

    def calculate_hash(self):
        """Calculates the hash for the block."""
        return hashlib.sha256(
            f"{self.index}{self.previous_hash}{self.timestamp}{self.transactions}{self.nonce}".encode('utf-8')
        ).hexdigest()

    def to_dict(self):
        """Convert block to dictionary."""
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
        """Create a Block object from dictionary."""
        return cls(
            block_dict['index'],
            block_dict['previous_hash'],
            block_dict['timestamp'],
            block_dict['transactions'],
            block_dict['nonce'],
            block_dict.get('hash')
        )

    def __str__(self):
        """String representation for logging and debugging."""
        return f"Block(index={self.index}, hash={self.hash}, previous_hash={self.previous_hash}, transactions={self.transactions}, nonce={self.nonce})"

class Blockchain:
    """Represents the blockchain structure with mining difficulty adjustments."""
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.difficulty = INITIAL_DIFFICULTY  # Starting difficulty
        self.block_reward = BLOCK_REWARD
        self.lock = threading.Lock()
        self.wallets = {}  # Holds wallets indexed by public key
        self.loaded = False  # Flag to track if blockchain has been loaded

    def create_genesis_block(self):
        """Generate the first block in the blockchain."""
        return Block(0, "0", int(time.time()), "Genesis Block")

    def add_block(self, new_block):
        """Add a block to the blockchain."""
        with self.lock:
            self.chain.append(new_block)
            logging.info(f"Block added: {new_block.to_dict()}")  # Use to_dict() here
            self.save_blockchain_to_file()  # Save after adding the block

    def mine_block(self, wallet_address):
        """Mine a new block, adjusting difficulty and using ProgPoW."""
        new_block = Block(
            len(self.chain),
            self.chain[-1].hash,
            int(time.time()),
            self.pending_transactions,
            nonce=0
        )
        
        # Add block reward transaction
        wallet = self.find_wallet_by_address(wallet_address)
        if not wallet:
            logging.error(f"Wallet not found for address: {wallet_address}")
            return

        reward_transaction = {"from": "Network", "to": wallet.get_public_key(), "amount": self.block_reward}
        new_block.transactions.append(reward_transaction)
        
        # Mine block with ProgPoW algorithm
        nonce = 0
        block_string = f"{new_block.index}{new_block.previous_hash}{new_block.timestamp}{new_block.transactions}{new_block.nonce}"
        hash_result, nonce = progpow_algorithm(block_string, nonce, self.difficulty)
        
        new_block.nonce = nonce
        new_block.hash = hash_result
        
        self.add_block(new_block)
        wallet.update_balance(self.block_reward)  # Update wallet balance
        self.pending_transactions = []  # Clear pending transactions
        logging.info(f"Mining completed for wallet: {wallet_address}. Reward: {self.block_reward} units.")
        self.save_blockchain_to_file()  # Save after mining

    def mine_pending_transactions(self, miner_wallet_address):
        """Mine all pending transactions, rewarding the miner."""
        logging.info(f"Starting mining for wallet: {miner_wallet_address}")
        self.mine_block(miner_wallet_address)

    def adjust_difficulty(self):
        """Adjust the difficulty periodically (e.g., after every DIFFICULTY_ADJUSTMENT_INTERVAL blocks)."""
        if len(self.chain) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0:
            last_block = self.chain[-1]
            previous_block = self.chain[-DIFFICULTY_ADJUSTMENT_INTERVAL]
            time_taken = last_block.timestamp - previous_block.timestamp
            # Adjust difficulty based on time taken
            if time_taken < 10:  # Blocks mined too quickly, increase difficulty
                self.difficulty += 1
            elif time_taken > 20:  # Blocks mined too slowly, decrease difficulty
                self.difficulty -= 1
            logging.info(f"Difficulty adjusted: {self.difficulty}")

    def create_wallet(self):
        """Create and register a new wallet directly."""
        wallet = Wallet()
        public_key = wallet.get_public_key()
        self.wallets[public_key] = wallet  # Register wallet with static address
        logging.info(f"Wallet created and registered with Public Key: {public_key}")
        return wallet

    def create_transaction(self, sender_wallet, recipient_wallet, amount):
        """Create a new transaction and add it to the pending transactions."""
        if sender_wallet.get_balance() < amount:
            logging.error(f"Transaction failed: Insufficient funds. Sender balance: {sender_wallet.get_balance()}, amount: {amount}")
            return False
        
        transaction = {
            'from': sender_wallet.get_public_key(),
            'to': recipient_wallet.get_public_key(),
            'amount': amount
        }
        sender_wallet.update_balance(-amount)  # Deduct amount from sender's balance
        recipient_wallet.update_balance(amount)  # Add amount to recipient's balance
        self.pending_transactions.append(transaction)
        logging.info(f"Transaction added: {transaction}")
        self.save_blockchain_to_file()  # Save after adding the transaction
        return True

    def find_wallet_by_address(self, wallet_address):
        """Find and return a wallet using its address."""
        for wallet in self.wallets.values():
            if wallet.get_wallet_address() == wallet_address:
                logging.info(f"Wallet found for address: {wallet_address}")
                return wallet
        logging.warning(f"Wallet not found for address: {wallet_address}")
        return None

    def register_wallet(self, wallet):
        """Register a wallet by its address."""
        self.wallets[wallet.wallet_address] = wallet
        logging.info(f"Registered Wallet: {wallet.wallet_address}")

    def to_dict(self):
        """Convert blockchain to dictionary."""
        return {
            'chain': [block.to_dict() for block in self.chain],  # Use to_dict() for each block
            'pending_transactions': self.pending_transactions,
            'difficulty': self.difficulty
        }

    def load_from_dict(self, data):
        """Load blockchain from dictionary data."""
        with self.lock:
            self.chain = [Block.from_dict(block) for block in data['chain']]
            self.pending_transactions = data['pending_transactions']
            self.difficulty = data['difficulty']
            self.loaded = True  # Set loaded flag to True after loading data

    def load_blockchain_from_file(self, file_path=BLOCKCHAIN_FILE_PATH):
        """Load blockchain from a file."""
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                data = json.load(f)
                self.load_from_dict(data)
            logging.info(f"Blockchain loaded from {file_path}")
        else:
            logging.warning(f"Blockchain file not found at {file_path}. Starting fresh.")

    def save_blockchain_to_file(self, file_path=BLOCKCHAIN_FILE_PATH):
        """Save blockchain to a file."""
        try:
            with open(file_path, 'w') as f:
                json.dump(self.to_dict(), f, indent=4)
            logging.info(f"Blockchain saved to {file_path}")
        except Exception as e:
            logging.error(f"Failed to save blockchain to {file_path}: {e}")

    def check_if_loaded(self):
        """Check if the blockchain has been loaded."""
        return self.loaded

