import hashlib
import time
import logging
import threading
import json
import os
import random
from dogedark.wallet import Wallet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # Fixed import
from cryptography.exceptions import InvalidSignature
import numpy as np

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
    """Modified ProgPoW-like algorithm with reduced difficulty and computational load"""
    # Compute deterministic program with reduced computational load
    program = deterministic_program(block_string, nonce)
    hash_result = progpow_hash(block_string, nonce, program)
    
    # Difficulty: hash must have certain leading zeros
    target = '0' * difficulty
    while not hash_result.startswith(target):
        nonce += 1
        program = deterministic_program(block_string, nonce)
        hash_result = progpow_hash(block_string, nonce, program)
    
    return hash_result, nonce

def deterministic_program(block_string, nonce, length=64):
    """Generates a simpler memory-hard program with reduced CPU and memory demands."""
    operations = ['+', '-', '*', '^', '|', '&', '%', '<<', '>>']
    
    # Reduce matrix size for faster computation
    matrix_size = 50  # Reduced matrix size to speed up multiplication
    matrix_a = np.random.randint(0, 10, size=(matrix_size, matrix_size))
    matrix_b = np.random.randint(0, 10, size=(matrix_size, matrix_size))
    
    # Simulate "real" computation by performing fewer matrix multiplications
    program = []
    for i in range(min(length, 10)):  # Reduced number of iterations to speed up processing
        # Perform matrix multiplication for complexity
        result = np.dot(matrix_a, matrix_b)
        
        # Hash part of the result to add unpredictability
        result_hash = hashlib.sha256(result.tobytes()).hexdigest()
        
        # Random cryptographic operation for added complexity (but simplified)
        operation = random.choice(operations)
        program.append(f"{result_hash[i % len(result_hash)]}{operation}")
        
        # Modify the matrices for the next iteration
        matrix_a = np.random.randint(0, 10, size=(matrix_size, matrix_size))
        matrix_b = np.random.randint(0, 10, size=(matrix_size, matrix_size))
        
    return program

def progpow_hash(block_string, nonce, program):
    """Generates a hash using a simplified computational approach with reduced memory requirements."""
    hash_input = f"{block_string}{nonce}{''.join(program)}"
    initial_hash = hashlib.sha256(hash_input.encode()).hexdigest()
    final_hash = hashlib.sha3_512(initial_hash.encode()).hexdigest()
    return final_hash

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
        self.difficulty = INITIAL_DIFFICULTY
        self.block_reward = BLOCK_REWARD
        self.lock = threading.Lock()
        self.wallets = {}  # Holds wallets indexed by public key
        self.loaded = False

    def create_genesis_block(self):
        """Generate the first block in the blockchain."""
        return Block(0, "0", int(time.time()), "Genesis Block")

    def add_block(self, new_block):
        """Add a block to the blockchain."""
        with self.lock:
            self.chain.append(new_block)
            logging.info(f"Block added: {new_block.to_dict()}")
            self.save_blockchain_to_file()

    def mine_block(self, wallet_address):
        """Mine a new block, adjusting difficulty and using ProgPoW."""
        new_block = Block(
            len(self.chain),
            self.chain[-1].hash,
            int(time.time()),
            self.pending_transactions,
            nonce=0
        )
        
        wallet = self.find_wallet_by_address(wallet_address)
        if not wallet:
            logging.error(f"Wallet not found for address: {wallet_address}")
            return

        reward_transaction = {"from": "Network", "to": wallet.get_public_key(), "amount": self.block_reward}
        new_block.transactions.append(reward_transaction)
        
        # Apply transaction fees for each transaction (Ethereum-like)
        fee_total = 0
        for txn in self.pending_transactions:
            fee_total += txn.get('fee', 0)

        miner_transaction = {
            "from": "Network", 
            "to": wallet.get_public_key(), 
            "amount": self.block_reward + fee_total
        }
        new_block.transactions.append(miner_transaction)
        
        nonce = 0
        block_string = f"{new_block.index}{new_block.previous_hash}{new_block.timestamp}{new_block.transactions}{new_block.nonce}"
        hash_result, nonce = progpow_algorithm(block_string, nonce, self.difficulty)
        
        new_block.nonce = nonce
        new_block.hash = hash_result
        
        self.add_block(new_block)
        wallet.update_balance(self.block_reward + fee_total)
        self.pending_transactions = []
        logging.info(f"Mining completed for wallet: {wallet_address}. Reward: {self.block_reward + fee_total} units.")
        self.save_blockchain_to_file()

    def mine_pending_transactions(self, miner_wallet_address):
        """Mine all pending transactions, rewarding the miner."""
        logging.info(f"Starting mining for wallet: {miner_wallet_address}")
        self.mine_block(miner_wallet_address)

    def adjust_difficulty(self):
        """Adjust the difficulty periodically."""
        if len(self.chain) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0:
            last_block = self.chain[-1]
            previous_block = self.chain[-DIFFICULTY_ADJUSTMENT_INTERVAL]
            time_taken = last_block.timestamp - previous_block.timestamp
            if time_taken < 10:  # Blocks mined too quickly
                self.difficulty += 1
            elif time_taken > 20:  # Blocks mined too slowly
                self.difficulty -= 1
            logging.info(f"Difficulty adjusted: {self.difficulty}")

    def create_wallet(self):
        """Create and register a new wallet."""
        wallet = Wallet()
        public_key = wallet.get_public_key()
        if public_key not in self.wallets:  # Ensure we don't add duplicate wallets
            self.wallets[public_key] = wallet
            logging.info(f"Wallet created and registered with Public Key: {public_key}")
        else:
            logging.info(f"Wallet with Public Key {public_key} already exists.")
        return wallet

    def register_wallet(self, wallet):
        """Register an existing wallet with the blockchain."""
        public_key = wallet.get_public_key()
        if public_key not in self.wallets:
            self.wallets[public_key] = wallet
            logging.info(f"Existing wallet registered with Public Key: {public_key}")
        else:
            logging.warning(f"Wallet with Public Key {public_key} already registered")

    def create_transaction(self, sender_wallet, recipient_wallet, amount, fee=0):
        """Create a new transaction and add it to pending transactions."""
        if sender_wallet.get_balance() < (amount + fee):
            logging.error(f"Transaction failed: Insufficient funds. Sender balance: {sender_wallet.get_balance()}, amount: {amount}, fee: {fee}")
            return False
        
        transaction_data = {
            'from': sender_wallet.get_public_key(),
            'to': recipient_wallet.get_public_key(),
            'amount': amount,
            'fee': fee
        }
        
        # Sign the transaction
        sender_private_key = sender_wallet.get_private_key()
        signature = self.sign_transaction(sender_private_key, transaction_data)
        transaction_data['signature'] = signature
        
        # Update balances immediately
        sender_wallet.update_balance(-(amount + fee))
        recipient_wallet.update_balance(amount)
        
        self.pending_transactions.append(transaction_data)
        logging.info(f"Transaction added: {transaction_data}")
        self.save_blockchain_to_file()  # Save the blockchain to file after every transaction
        return True

    def sign_transaction(self, private_key, transaction_data):
        """Sign the transaction data using the private key."""
        private_key = serialization.load_pem_private_key(private_key.encode(), password=None)
        transaction_str = json.dumps(transaction_data, sort_keys=True)
        transaction_bytes = transaction_str.encode('utf-8')
        signature = private_key.sign(
            transaction_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature.hex()

    def verify_transaction(self, transaction_data):
        """Verify the signature of the transaction."""
        public_key = transaction_data['from']
        signature = bytes.fromhex(transaction_data['signature'])
        
        try:
            sender_wallet = self.find_wallet_by_address(public_key)
            public_key = sender_wallet.get_public_key()
            public_key = serialization.load_pem_public_key(public_key.encode())
            
            transaction_str = json.dumps(transaction_data, sort_keys=True)
            transaction_bytes = transaction_str.encode('utf-8')
            
            public_key.verify(
                signature,
                transaction_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            logging.error("Transaction signature verification failed.")
            return False

    def find_wallet_by_address(self, wallet_address):
        """Find and return a wallet using its address."""
        for wallet in self.wallets.values():
            if wallet.get_wallet_address() == wallet_address:
                logging.info(f"Wallet found for address: {wallet_address}")
                return wallet
        logging.warning(f"Wallet not found for address: {wallet_address}")
        return None

    def to_dict(self):
        """Convert blockchain to dictionary."""
        return {
            'chain': [block.to_dict() for block in self.chain],
            'pending_transactions': self.pending_transactions,
            'difficulty': self.difficulty,
            'wallets': {address: wallet.to_dict() for address, wallet in self.wallets.items()}
        }

    def load_from_dict(self, data):
        """Load blockchain from dictionary data."""
        with self.lock:
            self.chain = [Block.from_dict(block) for block in data['chain']]
            self.pending_transactions = data['pending_transactions']
            self.difficulty = data['difficulty']
            self.wallets = {address: Wallet.from_dict(wallet_data) 
                          for address, wallet_data in data.get('wallets', {}).items()}
            self.loaded = True

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
        if not self.loaded:
            logging.warning("Blockchain has not been loaded properly. Skipping save.")
            return
        
        with open(file_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)
        logging.info(f"Blockchain saved to {file_path}")

    def check_if_loaded(self):
        """Check if the blockchain has been loaded successfully."""
        return self.loaded
