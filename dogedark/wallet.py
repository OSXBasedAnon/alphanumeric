import hashlib
import time
import json
import os
import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

# Constants for blockchain (example)
BLOCK_REWARD = 50  # Example reward
TOTAL_SUPPLY = 21000000  # Example total supply for a cryptocurrency

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

    def get_public_key_pem(self):
        """Get the public key in PEM format as bytes."""
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_pem

    def get_public_key(self):
        """Get the public key in PEM format as string."""
        return self.get_public_key_pem().decode('utf-8')

    def sign_transaction(self, transaction):
        """Sign a transaction with the wallet's private key."""
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
        """Verify a transaction signature."""
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

    def get_balance(self):
        """Returns the balance of the wallet."""
        return self.balance

    def set_balance(self, amount):
        """Set the balance to the given amount."""
        self.balance = amount

    def to_dict(self):
        """Convert wallet to dictionary for serialization."""
        return {
            'balance': self.balance,
            'public_key': self.get_public_key(),
            'private_key': self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
        }

    @classmethod
    def from_dict(cls, wallet_dict):
        """Create a wallet instance from a dictionary."""
        private_key_pem = wallet_dict.get('private_key')
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        wallet = cls(private_key)
        wallet.balance = wallet_dict.get('balance', 0)
        return wallet

    def save_wallet(self, filename='wallet.json'):
        """Save the wallet to a file."""
        wallet_data = self.to_dict()
        with open(filename, 'w') as f:
            json.dump(wallet_data, f)

    @classmethod
    def load_wallet(cls, filename='wallet.json'):
        """Load a wallet from a file."""
        if not os.path.exists(filename):
            print(f"No wallet file found at {filename}")
            return None

        with open(filename, 'r') as f:
            wallet_data = json.load(f)

        return cls.from_dict(wallet_data)


class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0, hash=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.hash = hash if hash else self.calculate_hash()  # Use provided hash, else calculate it

    def calculate_hash(self):
        return hashlib.sha256(
            f"{self.index}{self.previous_hash}{self.timestamp}{self.transactions}{self.nonce}".encode('utf-8')
        ).hexdigest()

    def to_dict(self):
        """Convert block to dictionary for serialization."""
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
        """Create a block instance from a dictionary."""
        block = cls(
            block_dict['index'],
            block_dict['previous_hash'],
            block_dict['timestamp'],
            block_dict['transactions'],
            block_dict['nonce'],
            block_dict['hash']
        )
        return block

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.difficulty = 4
        self.block_reward = BLOCK_REWARD
        self.token_supply = TOTAL_SUPPLY
        self.blocks_mined = 0

    def create_genesis_block(self):
        """Create the first block in the blockchain."""
        return Block(0, "0", int(time.time()), [])

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
            return True
        except Exception as e:
            print(f"Error loading blockchain state: {e}")
            return False

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

    def is_valid_chain(self, chain=None):
        """Validates the entire blockchain."""
        if chain is None:
            chain = self.chain

        if len(chain) == 0:
            return False  # If the chain is empty, it's invalid

        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]

            # Verify block hash and block link
            if current_block.hash != current_block.calculate_hash():
                print(f"Invalid hash at block {current_block.index}")
                return False  # Block's hash is invalid
            if current_block.previous_hash != previous_block.hash:
                print(f"Invalid previous hash at block {current_block.index}")
                return False  # Previous hash doesn't match

        return True

    def get_latest_block(self):
        """Get the most recent block in the chain."""
        return self.chain[-1]

# Example usage
wallet = Wallet()
wallet.set_balance(100)
wallet.save_wallet()

blockchain = Blockchain()
blockchain.load_blockchain_from_file()
