import hashlib
import time
import logging
import threading
import json
import os
import random
from dataclasses import dataclass
from typing import NamedTuple, Tuple, List, Optional
from functools import reduce
import numpy as np
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from dogedark.wallet import Wallet

# Constants
INITIAL_REWARD = 50
HALVING_INTERVAL = 100000000
MIN_REWARD = 1
INITIAL_DIFFICULTY = 4
BLOCK_REWARD = 50
SUPPLY = 210000000
DIFFICULTY_ADJUSTMENT_INTERVAL = 10
BLOCKCHAIN_FILE_PATH = 'blockchain.json'

# Instead of using a dictionary, create a tuple of constants
CONSTANTS = (
    INITIAL_REWARD,
    HALVING_INTERVAL,
    MIN_REWARD,
    INITIAL_DIFFICULTY,
    BLOCK_REWARD,
    SUPPLY,
    DIFFICULTY_ADJUSTMENT_INTERVAL
)

# Hash the constants tuple
constants_hash = hashlib.sha256(str(CONSTANTS).encode('utf-8')).hexdigest()

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def GetBlockReward(nHeight: int) -> int:
    halvings = nHeight // HALVING_INTERVAL
    reward = INITIAL_REWARD >> halvings
    return max(reward, MIN_REWARD)

def CalculateCumulativeSupply(block_height: int) -> int:
    return sum(
        GetBlockReward(height) * HALVING_INTERVAL
        for height in range(0, block_height, HALVING_INTERVAL)
    )

@dataclass(frozen=True)
class Transaction:
    sender: str
    recipient: str
    amount: float
    timestamp: int
    signature: Optional[str] = None
    
    def to_tuple(self) -> tuple:
        return (self.sender, self.recipient, self.amount, self.timestamp, self.signature)

@dataclass(frozen=True)
class BlockHeader:
    index: int
    previous_hash: str
    timestamp: int
    merkle_root: str
    nonce: int
    difficulty: int  # Ensure this is included
    
    def to_tuple(self) -> tuple:
        return (self.index, self.previous_hash, self.timestamp, 
                self.merkle_root, self.nonce, self.difficulty)

class Block:
    def __init__(self, index: int, previous_hash: str, timestamp: int,
                 transactions: Tuple[Transaction, ...], nonce: int = 0, difficulty: int = 4) -> None:
        self._header = BlockHeader(
            index=index,
            previous_hash=previous_hash,
            timestamp=timestamp,
            merkle_root=self._calculate_merkle_root(transactions),
            nonce=nonce,
            difficulty=difficulty
        )
        self._transactions = transactions
        self._hash = self.calculate_hash()

    @property
    def header(self) -> BlockHeader:
        return self._header
        
    @property
    def transactions(self) -> Tuple[Transaction, ...]:
        return self._transactions
        
    @property
    def hash(self) -> str:
        return self._hash

    def _calculate_merkle_root(self, transactions: Tuple[Transaction, ...]) -> str:
        if not transactions:
            return hashlib.sha256(b'').hexdigest()
            
        def hash_pair(hash1: str, hash2: str) -> str:
            return hashlib.sha256(f"{hash1}{hash2}".encode()).hexdigest()
            
        transaction_hashes = tuple(
            hashlib.sha256(str(tx.to_tuple()).encode()).hexdigest()
            for tx in transactions
        )
        
        while len(transaction_hashes) > 1:
            if len(transaction_hashes) % 2 != 0:
                transaction_hashes += (transaction_hashes[-1],)
            transaction_hashes = tuple(
                hash_pair(transaction_hashes[i], transaction_hashes[i + 1])
                for i in range(0, len(transaction_hashes), 2)
            )
            
        return transaction_hashes[0]

    def calculate_hash(self) -> str:
        header_tuple = self._header.to_tuple()
        header_string = ''.join(str(x) for x in header_tuple)
        return hashlib.sha256(header_string.encode()).hexdigest()

    def to_tuple(self) -> tuple:
        return (
            self._header.to_tuple(),
            tuple(tx.to_tuple() for tx in self._transactions),
            self._hash
        )

    @classmethod
    def from_tuple(cls, data: tuple) -> 'Block':
        header_data, transactions_data, block_hash = data
        header = BlockHeader(*header_data)
        transactions = tuple(
            Transaction(*tx_data) for tx_data in transactions_data
        )
        
        block = cls(
            index=header.index,
            previous_hash=header.previous_hash,
            timestamp=header.timestamp,
            transactions=transactions,
            nonce=header.nonce,
            difficulty=header.difficulty
        )
        
        if block.hash != block_hash:
            raise ValueError("Block hash mismatch during reconstruction")
            
        return block

    @staticmethod
    def progpow_algorithm(block_string: str, nonce: int, difficulty: int) -> Tuple[str, int]:
        program = deterministic_program(block_string, nonce)
        hash_result = progpow_hash(block_string, nonce, program)
        
        target = '0' * difficulty
        while not hash_result.startswith(target):
            nonce += 1
            program = deterministic_program(block_string, nonce)
            hash_result = progpow_hash(block_string, nonce, program)
        
        return hash_result, nonce

# You can also include the deterministic_program and progpow_hash functions here
# as they are part of the previous code you provided.

def deterministic_program(block_string: str, nonce: int, length: int = 64) -> Tuple[str, ...]:
    operations = ('+', '-', '*', '^', '|', '&', '%', '<<', '>>')
    matrix_size = 50
    
    # Use numpy's random with a seed based on block_string and nonce
    seed = int(hashlib.sha256(f"{block_string}{nonce}".encode()).hexdigest(), 16)
    rng = np.random.RandomState(seed)
    
    matrix_a = rng.randint(0, 10, size=(matrix_size, matrix_size))
    matrix_b = rng.randint(0, 10, size=(matrix_size, matrix_size))
    
    program = []
    for i in range(min(length, 10)):
        result = np.dot(matrix_a, matrix_b)
        result_hash = hashlib.sha256(result.tobytes()).hexdigest()
        operation = operations[i % len(operations)]
        program.append(f"{result_hash[i % len(result_hash)]}{operation}")
        
        matrix_a = rng.randint(0, 10, size=(matrix_size, matrix_size))
        matrix_b = rng.randint(0, 10, size=(matrix_size, matrix_size))
    
    return tuple(program)

def progpow_hash(block_string: str, nonce: int, program: Tuple[str, ...]) -> str:
    hash_input = f"{block_string}{nonce}{''.join(program)}"
    initial_hash = hashlib.sha256(hash_input.encode()).hexdigest()
    final_hash = hashlib.sha3_512(initial_hash.encode()).hexdigest()
    return final_hash

@dataclass(frozen=True)
class BlockchainState:
    chain: Tuple[Block, ...]
    wallets: Tuple[Wallet, ...]
    difficulty: int
    pending_transactions: Tuple[Transaction, ...]

    def calculate_block_reward(self) -> int:
        halvings = self.header.index // HALVING_INTERVAL
        reward = INITIAL_REWARD >> halvings
        return max(reward, MIN_REWARD)

class Blockchain:
    def __init__(self, key: bytes = None):
        self.chain = []
        self.pending_transactions = []
        self._wallets = []
        self.difficulty = 4
        self.mining_reward = 50
        self.transaction_fee = 0.1
        self.block_time = 10  # Example block time value
        self.last_difficulty_adjustment = 0
        self.difficulty_adjustment_interval = 100
        self._lock = threading.Lock()

        # Encryption for private keys
        self.cipher = Fernet(key) if key else None

    def check_if_loaded(self) -> bool:
        """Check if the blockchain has been loaded from file or network"""
        return self.loaded

    def load_blockchain_from_file(self, filename='blockchain.json'):
        """Load blockchain state from a file."""
        try:
            with open(filename, 'r') as f:
                # Load the data from the JSON file
                data = json.load(f)

                # Ensure that the data is a dictionary
                if not isinstance(data, dict):
                    raise ValueError(f"Expected dictionary data, but got {type(data)}")

                # Ensure 'chain' is a list and other keys are set properly
                self.chain = data.get('chain', [])
                if not isinstance(self.chain, list):
                    raise ValueError(f"Expected 'chain' to be a list, but got {type(self.chain)}")

                # Assign values from the dictionary (with defaults if keys are missing)
                self.pending_transactions = data.get('pending_transactions', [])
                if not isinstance(self.pending_transactions, list):
                    raise ValueError(f"Expected 'pending_transactions' to be a list, but got {type(self.pending_transactions)}")

                self.wallets = data.get('wallets', {})
                if not isinstance(self.wallets, dict):
                    raise ValueError(f"Expected 'wallets' to be a dictionary, but got {type(self.wallets)}")

                self.difficulty = data.get('difficulty', 0)
                self.mining_reward = data.get('mining_reward', 0)
                self.transaction_fee = data.get('transaction_fee', 0)
                self.block_time = data.get('block_time', 0)
                self.last_difficulty_adjustment = data.get('last_difficulty_adjustment', 0)
                self.difficulty_adjustment_interval = data.get('difficulty_adjustment_interval', 0)

            logging.info(f"Blockchain loaded successfully from {filename}")
        except Exception as e:
            logging.error(f"Error loading blockchain from file: {e}")
            raise
    
    def calculate_block_hash(self, header_data: tuple, transactions_data: list) -> str:
        block_data = {
            'header': header_data,
            'transactions': transactions_data
        }
        block_data_string = json.dumps(block_data, sort_keys=True).encode('utf-8')
        return hashlib.sha256(block_data_string).hexdigest()

    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data before storing it."""
        if self.cipher:
            encrypted_data = self.cipher.encrypt(data.encode())
            return encrypted_data.decode()
        return data  # If no cipher, return data unencrypted

    def save_blockchain_to_file(self, filename='blockchain.json'):
        try:
            # Initialize data structure
            data = {
                'chain': [],
                'pending_transactions': [],
                'wallets': {},
                'difficulty': self.difficulty,
                'mining_reward': self.mining_reward,
                'transaction_fee': self.transaction_fee,
                'block_time': self.block_time,
                'last_difficulty_adjustment': self.last_difficulty_adjustment,
                'difficulty_adjustment_interval': self.difficulty_adjustment_interval
            }

            # Serialize the blocks
            for block in self.chain:
                # Handle both Block objects and dictionary blocks
                if isinstance(block, Block):
                    block_data = {
                        'header': {
                            'index': block.header.index,
                            'previous_hash': block.header.previous_hash,
                            'timestamp': block.header.timestamp,
                            'merkle_root': block.header.merkle_root,
                            'nonce': block.header.nonce,
                            'difficulty': block.header.difficulty
                        },
                        'transactions': [
                            {
                                'sender': tx.sender,
                                'recipient': tx.recipient,
                                'amount': tx.amount,
                                'timestamp': tx.timestamp,
                                'signature': tx.signature
                            } for tx in block.transactions
                        ],
                        'hash': block.hash
                    }
                else:
                    # If it's already a dictionary, use it as is
                    block_data = block
                
                data['chain'].append(block_data)

            # Serialize pending transactions
            for tx in self.pending_transactions:
                if isinstance(tx, Transaction):
                    tx_data = {
                        'sender': tx.sender,
                        'recipient': tx.recipient,
                        'amount': tx.amount,
                        'timestamp': tx.timestamp,
                        'signature': tx.signature
                    }
                else:
                    tx_data = tx
                data['pending_transactions'].append(tx_data)

            # Serialize wallets
            for wallet in self._wallets:
                wallet_data = {
                    'address': wallet.wallet_address if hasattr(wallet, 'wallet_address') else str(wallet),
                    'public_key': wallet.get_public_key() if hasattr(wallet, 'get_public_key') else None
                }
                
                # Safely handle private key encryption
                if hasattr(wallet, 'get_private_key') and self.cipher:
                    private_key = wallet.get_private_key()
                    if private_key:
                        wallet_data['private_key'] = self.encrypt_data(str(private_key))
                
                data['wallets'][wallet_data['address']] = wallet_data

            # Write serialized data to a JSON file with atomic write
            temp_filename = f"{filename}.tmp"
            with open(temp_filename, 'w') as f:
                json.dump(data, f, indent=4)
            
            # Atomic replace
            os.replace(temp_filename, filename)
            
            logging.info(f"Blockchain saved successfully to {filename}")
        
        except Exception as e:
            logging.error(f"Error saving blockchain to file: {e}")
            # Clean up temp file if it exists
            if os.path.exists(temp_filename):
                os.remove(temp_filename)
            raise

    def load_blockchain_data(self, blockchain_data: bytes) -> None:
        """Load blockchain state from provided data (used when downloading from node)"""
        logging.info("Loading blockchain from provided data...")
        try:
            state = self._deserialize_state(blockchain_data)
            self._load_blockchain_data(state)
            self.loaded = True
            logging.info("Blockchain loaded successfully from provided data")
        except Exception as e:
            logging.error(f"Error loading blockchain data: {e}")
            raise

    def _get_blockchain_state(self) -> BlockchainState:
        """Get current blockchain state as immutable BlockchainState"""
        return BlockchainState(
            chain=self._chain,
            wallets=self._wallets,
            difficulty=self._difficulty,
            pending_transactions=self._pending_transactions
        )

    def _serialize_state(self, state: BlockchainState) -> bytes:
        """Serialize blockchain state to bytes"""
        chain_data = tuple(block.to_tuple() for block in state.chain)
        wallet_data = tuple(
            wallet.get_private_key().private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ) for wallet in state.wallets
        )
        transactions_data = tuple(tx.to_tuple() for tx in state.pending_transactions)
        
        state_tuple = (
            chain_data,
            wallet_data,
            state.difficulty,
            transactions_data
        )
        return self._secure_serialize(state_tuple)

    def _secure_serialize(self, data: tuple) -> bytes:
        """Securely serialize data to bytes using a consistent format"""
        return json.dumps(data).encode('utf-8')

    def _secure_deserialize(self, data: bytes) -> tuple:
        try:
            result = json.loads(data.decode('utf-8'))
            if not isinstance(result, tuple):
                # Convert list to tuple or raise custom error
                result = tuple(result)
            return result
        except Exception as e:
            logging.error(f"Error deserializing blockchain data: {e}")
            raise

    def _deserialize_state(self, data: bytes) -> BlockchainState:
        """Deserialize blockchain state from bytes"""
        state_tuple = self._secure_deserialize(data)
        chain_data, wallet_data, difficulty, transactions_data = state_tuple
        
        chain = tuple(Block.from_tuple(block_data) for block_data in chain_data)
        wallets = tuple(
            Wallet(private_key=serialization.load_pem_private_key(
                wallet_bytes,
                password=None
            )) for wallet_bytes in wallet_data
        )
        pending_transactions = tuple(
            Transaction(*tx_data) for tx_data in transactions_data
        )
        
        return BlockchainState(
            chain=chain,
            wallets=wallets,
            difficulty=difficulty,
            pending_transactions=pending_transactions
        )

    def _load_blockchain_data(self, state: BlockchainState) -> None:
        self._chain = state.chain
        self._wallets = state.wallets
        self._difficulty = state.difficulty
        self._pending_transactions = state.pending_transactions

    def add_transaction(self, transaction: Transaction) -> None:
        """Add a new transaction to pending transactions"""
        with self._lock:
            self._pending_transactions = self._pending_transactions + (transaction,)

    def get_chain(self) -> Tuple[Block, ...]:
        """Get the current chain"""
        return self._chain

    def get_pending_transactions(self) -> Tuple[Transaction, ...]:
        """Get pending transactions"""
        return self._pending_transactions

    def _create_genesis_block(self) -> Block:
        genesis_transaction = Transaction(
            sender="0",
            recipient="0",
            amount=0,
            timestamp=int(time.time())
        )
        return Block(
            index=0,
            previous_hash="0",
            timestamp=int(time.time()),
            transactions=(genesis_transaction,)
        )

    def add_block(self, new_block: Block) -> None:
        with self._lock:
            if not self._is_valid_block(new_block):
                raise ValueError("Invalid block")
            self._chain = self._chain + (new_block,)
            self._save_state()
            logging.info(f"Block added: {new_block.hash}")

    def _is_valid_block(self, block: Block) -> bool:
        if block.header.index != len(self._chain):
            return False
        if block.header.previous_hash != self._chain[-1].hash:
            return False
        if block.hash != block.calculate_hash():
            return False
        if block.header.merkle_root != block._calculate_merkle_root(block.transactions):
            return False
        return True

    def create_transaction(self, sender_wallet: Wallet, recipient_wallet: Wallet, 
                         amount: float, fee: float = 0) -> bool:
        if sender_wallet.get_balance() < (amount + fee):
            logging.error(f"Insufficient funds. Balance: {sender_wallet.get_balance()}, Amount: {amount}, Fee: {fee}")
            return False

        transaction = Transaction(
            sender=sender_wallet.get_public_key(),
            recipient=recipient_wallet.get_public_key(),
            amount=amount,
            timestamp=int(time.time()),
            signature=self._sign_transaction(sender_wallet.get_private_key(), amount, recipient_wallet.get_public_key())
        )

        sender_wallet.update_balance(-(amount + fee))
        recipient_wallet.update_balance(amount)
        
        self._pending_transactions.append(transaction)
        self._save_state()
        logging.info(f"Transaction created: {transaction.to_tuple()}")
        return True

    def _sign_transaction(self, private_key: str, amount: float, recipient: str) -> str:
        message = f"{amount}{recipient}{int(time.time())}".encode()
        signature = private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature.hex()

    def verify_transaction(self, transaction_data):
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

    def find_wallet_by_address(self, address: str) -> Wallet:
        for wallet in self._wallets:
            if wallet.wallet_address == address:
                return wallet
        raise ValueError(f"Wallet with address {address} not found.")

    def mine_pending_transactions(self, miner_address: str) -> Optional[Block]:
        logging.info(f"Starting mining for wallet: {miner_address}")
        
        with self._lock:
            try:
                # Validate miner's wallet exists
                if not self.get_wallet_by_address(miner_address):
                    logging.error(f"Invalid miner address: {miner_address}")
                    return None

                # Get current pending transactions
                current_transactions = self._pending_transactions.copy()
                
                # Validate all pending transactions before mining
                valid_transactions = []
                for tx in current_transactions:
                    if self._validate_transaction(tx):
                        valid_transactions.append(tx)
                    else:
                        logging.warning(f"Invalid transaction removed from pool: {tx}")
                
                # Create mining reward transaction
                reward_tx = Transaction(
                    sender="0",  # Mining reward comes from network
                    recipient=miner_address,
                    amount=self._calculate_block_reward(),
                    timestamp=int(time.time())
                )
                
                # Combine valid transactions with reward
                block_transactions = valid_transactions + [reward_tx]
                
                # Create new block
                previous_block = self._chain[-1]
                new_block = Block(
                    index=len(self._chain),
                    previous_hash=previous_block.hash,
                    timestamp=int(time.time()),
                    transactions=tuple(block_transactions),
                    nonce=0,
                    difficulty=self._difficulty
                )
                
                # Mine the block using ProgPOW
                logging.info("Starting ProgPOW mining process...")
                block_string = str(new_block.to_tuple())
                hash_result, nonce = Block.progpow_algorithm(block_string, 0, self._difficulty)
                
                # Update block with found nonce
                new_block = Block(
                    index=new_block.header.index,
                    previous_hash=new_block.header.previous_hash,
                    timestamp=new_block.header.timestamp,
                    transactions=new_block.transactions,
                    nonce=nonce,
                    difficulty=self._difficulty
                )
                
                # Validate the mined block
                if not self._is_valid_block(new_block):
                    logging.error("Mined block validation failed")
                    return None
                
                # Update wallet balances for all transactions
                self._update_wallet_balances(new_block.transactions)
                
                # Add block to chain
                self._chain.append(new_block)
                
                # Clear processed transactions from pending pool
                self._pending_transactions = [tx for tx in self._pending_transactions 
                                           if tx not in valid_transactions]
                
                # Adjust difficulty if needed
                self._adjust_difficulty()
                
                # Save updated blockchain state
                self.save_blockchain_to_file()
                
                logging.info(f"Successfully mined block {new_block.header.index} "
                           f"with hash {new_block.hash}")
                
                return new_block
                
            except Exception as e:
                logging.error(f"Error during mining process: {e}")
                return None

    def mine_block(self, miner_address: str) -> Optional[Block]:
        with self._lock:  # Ensure _lock is defined and used appropriately
            if not self._pending_transactions:
                return None

            reward_tx = Transaction(
                sender="0",
                recipient=miner_address,
                amount=BLOCK_REWARD,
                timestamp=int(time.time())
            )

            all_transactions = tuple(self._pending_transactions) + (reward_tx,)

            new_block = Block(
                index=len(self._chain),
                previous_hash=self._chain[-1].hash,
                timestamp=int(time.time()),
                transactions=all_transactions
            )
            
            # Mining process
            block_string = str(new_block.to_tuple())
            hash_result, nonce = progpow_algorithm(block_string, 0, self._difficulty)
            
            # Update block with mining results
            new_block = Block(
                index=new_block.header.index,
                previous_hash=new_block.header.previous_hash,
                timestamp=new_block.header.timestamp,
                transactions=new_block.transactions,
                nonce=nonce
            )
            
            self._pending_transactions = []
            self.adjust_difficulty()
            
            return new_block

    def _adjust_difficulty(self) -> None:
        """Adjust mining difficulty based on recent block times."""
        if len(self._chain) % DIFFICULTY_ADJUSTMENT_INTERVAL != 0:
            return
            
        # Calculate average block time for last interval
        prev_adjustment_block = self._chain[-DIFFICULTY_ADJUSTMENT_INTERVAL]
        time_taken = self._chain[-1].header.timestamp - prev_adjustment_block.header.timestamp
        average_block_time = time_taken / DIFFICULTY_ADJUSTMENT_INTERVAL
        
        # Adjust difficulty to target block time
        if average_block_time < self._block_time / 2:
            self._difficulty += 1
        elif average_block_time > self._block_time * 2:
            self._difficulty = max(1, self._difficulty - 1)
            
        logging.info(f"Difficulty adjusted to: {self._difficulty}")

    def create_wallet(self):
        wallet = Wallet()
        self._wallets.append(wallet)  # Append instead of concatenating
        logging.info(f"New wallet created with address: {wallet.wallet_address}")
        return wallet

    def register_wallet(self, wallet: Wallet) -> None:
        """Register a wallet to the blockchain."""
        if wallet.wallet_address not in self._wallets:
            self._wallets = self._wallets + (wallet.wallet_address,)  # Add new wallet to the internal wallet list
            logging.info(f"Wallet registered: {wallet.get_public_key()} with address {wallet.wallet_address}")
        else:
            logging.info(f"Wallet with address {wallet.wallet_address} is already registered.")

    def _save_state(self) -> None:
        chain_data = tuple(block.to_tuple() for block in self._chain)
        wallet_data = tuple(
            (wallet.get_private_key(),) for wallet in self._wallets
        )
        
        state_data = (chain_data, wallet_data, self._difficulty)
        
        temp_path = BLOCKCHAIN_FILE_PATH + '.tmp'
        try:
            with open(temp_path, 'wb') as f:
                f.write(str(state_data).encode())
            os.replace(temp_path, BLOCKCHAIN_FILE_PATH)
        except Exception as e:
            logging.error(f"Failed to save blockchain state: {e}")
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def load_state(self) -> None:
        """Load the blockchain state from file."""
        try:
            if not os.path.exists(BLOCKCHAIN_FILE_PATH):
                logging.info("No existing blockchain state found. Starting with genesis block.")
                self._chain = (self._create_genesis_block(),)
                self.loaded = True
                return

            with open(BLOCKCHAIN_FILE_PATH, 'r') as f:
                state_data = json.load(f)

            # Verify that state_data has the correct structure
            if not isinstance(state_data, list) or len(state_data) != 3:
                raise ValueError("Invalid state data structure")

            chain_data, wallet_data, difficulty = state_data

            # Reconstruct the chain
            self._chain = tuple(
                Block.from_tuple(block_data) for block_data in chain_data
            )

            # Reconstruct wallets
            self._wallets = tuple(
                Wallet(private_key=serialization.load_pem_private_key(
                    wallet_data_item[0],
                    password=None
                )) for wallet_data_item in wallet_data
            )

            # Load difficulty
            self._difficulty = difficulty

            # Load pending transactions if they exist
            self._pending_transactions = [
                Transaction(**tx_data) for tx_data in state_data.get(3, [])
            ]

            self.loaded = True
            logging.info("Blockchain state loaded successfully")

        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode blockchain state file: {e}")
            self._chain = (self._create_genesis_block(),)
            self.loaded = True
        except Exception as e:
            logging.error(f"Failed to load blockchain state: {e}")
            self._chain = (self._create_genesis_block(),)
            self.loaded = True

    def _calculate_wallet_balance(self, address: str) -> float:
        """Calculate the current balance of a wallet address."""
        balance = 0.0
        
        # Check all confirmed transactions in blockchain
        for block in self._chain:
            for tx in block.transactions:
                if tx.recipient == address:
                    balance += tx.amount
                if tx.sender == address:
                    balance -= tx.amount
                    
        # Check pending transactions
        for tx in self._pending_transactions:
            if tx.sender == address:
                balance -= tx.amount
                
        return balance

    def _update_wallet_balances(self, transactions: List[Transaction]) -> None:
        """Update wallet balances after mining a block."""
        for tx in transactions:
            if tx.sender != "0":  # Skip mining reward sender
                sender_wallet = self.get_wallet_by_address(tx.sender)
                if sender_wallet:
                    sender_wallet.update_balance(-tx.amount)
                    
            recipient_wallet = self.get_wallet_by_address(tx.recipient)
            if recipient_wallet:
                recipient_wallet.update_balance(tx.amount)

    def get_wallet_by_address(self, address: str) -> Optional[Wallet]:
        """Find a wallet by its address (works for list of wallets)."""
        for wallet in self._wallets:
            if wallet.address == address:
                return wallet
        return None

    def register_wallet(self, wallet: Wallet):
        if not self.is_wallet_valid(wallet):
            logging.warning(f"Wallet {wallet.wallet_address} is already registered.")
            return
        self._wallets.append(wallet)
        self.save_state()
        logging.info(f"Wallet {wallet.wallet_address} registered.")

    def is_wallet_valid(self, wallet: Wallet) -> bool:
        return all(w.wallet_address != wallet.wallet_address for w in self._wallets)

    def get_wallets(self) -> List[Wallet]:
        return self._wallets.copy()

    def initialize_node(self, node_id: str) -> None:
        """Initialize a new node with the given ID"""
        self.node_id = node_id
        self.load_blockchain_from_file()
        logging.info(f"Node initialized with ID: {node_id}")

    def save_state(self):
        try:
            # First load any existing blockchain state
            try:
                with open(BLOCKCHAIN_FILE_PATH, 'r') as f:
                    blockchain_data = json.load(f)
                    if not isinstance(blockchain_data, dict):
                        logging.warning(f"Expected dictionary but got {type(blockchain_data)}. Creating new blockchain state.")
                        blockchain_data = {
                            "chain": self.chain,
                            "pending_transactions": self.pending_transactions,
                            "difficulty": self.difficulty
                        }
            except FileNotFoundError:
                logging.info(f"{BLOCKCHAIN_FILE_PATH} file not found, initializing with default structure.")
                blockchain_data = {
                    "chain": self.chain,
                    "pending_transactions": self.pending_transactions,
                    "difficulty": self.difficulty
                }

            # Append the new wallet data to blockchain state
            wallet_data = [wallet.to_dict() for wallet in self._wallets]
            blockchain_data["wallet_data"] = wallet_data
            
            # Save the blockchain state back to the file
            with open(BLOCKCHAIN_FILE_PATH, 'w') as f:
                json.dump(blockchain_data, f, indent=4)
            logging.info(f"Blockchain state saved to {BLOCKCHAIN_FILE_PATH}.")
            
            # Handle saving wallet data to separate file
            try:
                with open('wallet.json', 'r') as wallet_file:
                    existing_wallet_data = json.load(wallet_file)
                    if not isinstance(existing_wallet_data, list):
                        logging.warning(f"Expected list but got {type(existing_wallet_data)}. Resetting wallet data.")
                        existing_wallet_data = []
            except FileNotFoundError:
                logging.info("wallet.json file not found, initializing with an empty list.")
                existing_wallet_data = []
            
            # Update existing wallet data with new data
            existing_wallet_data.extend(wallet_data)
            unique_wallet_data = {wallet['id']: wallet for wallet in existing_wallet_data}.values()
            
            # Save the updated wallet data back to wallet.json
            with open('wallet.json', 'w') as wallet_file:
                json.dump(list(unique_wallet_data), wallet_file, indent=4)
            logging.info("Wallet data saved to wallet.json.")
        except Exception as e:
            logging.error(f"Error saving state: {e}")

