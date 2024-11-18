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
INITIAL_REWARD = 50
HALVING_INTERVAL = 210000
MIN_REWARD = 1
INITIAL_DIFFICULTY = 4
BLOCK_REWARD = 50
SUPPLY = 210000000
DIFFICULTY_ADJUSTMENT_INTERVAL = 10
BLOCKCHAIN_FILE_PATH = 'blockchain.json'
ALGORITHM_VERSION_HASH = hashlib.sha256("Algorithm_v1.0".encode()).hexdigest()

constants_dict = {
    "INITIAL_REWARD": INITIAL_REWARD,
    "HALVING_INTERVAL": HALVING_INTERVAL,
    "MIN_REWARD": MIN_REWARD,
    "SUPPLY": SUPPLY,
    "DIFFICULTY_ADJUSTMENT_INTERVAL": DIFFICULTY_ADJUSTMENT_INTERVAL
}

constants_json = json.dumps(constants_dict, sort_keys=True).encode('utf-8')
constants_hash = hashlib.sha256(constants_json).hexdigest()

# Store this hash in the genesis block or as part of your blockchain's state
print(f"Hash of Constants: {constants_hash}")

# Logging configuration
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to get the current block reward
def GetBlockReward(nHeight):
    halvings = nHeight // HALVING_INTERVAL  # Calculate how many halvings have occurred
    reward = INITIAL_REWARD >> halvings  # Right shift by number of halvings (equivalent to halving the reward)
    
    # Ensure that reward does not go below the minimum
    if reward < MIN_REWARD:
        reward = MIN_REWARD
    
    return reward

# Function to calculate the cumulative supply (optional)
def CalculateCumulativeSupply(block_height):
    supply = 0
    for height in range(0, block_height, HALVING_INTERVAL):
        reward = GetBlockReward(height)
        supply += reward * HALVING_INTERVAL
    return supply

# Function to adjust difficulty dynamically
def adjust_difficulty(previous_difficulty, block_time, target_block_time=10):
    """Adjust difficulty based on how long it took to mine the last block."""
    if block_time < target_block_time:
        return previous_difficulty + 1  # Increase difficulty
    elif block_time > target_block_time:
        return max(previous_difficulty - 1, 1)  # Decrease difficulty, minimum is 1
    return previous_difficulty

# ProgPoW functions
def progpow_algorithm(block_string, nonce, difficulty, previous_hash=None, block_time=10):
    """Advanced ProgPoW implementation with dynamic previous hash handling."""
    import hashlib
    import struct
    import time
    from typing import List
    
    # Dynamic previous hash handling
    if previous_hash is None:
        # Generate initial hash based on block_string if no previous hash
        previous_hash = hashlib.sha3_256(block_string.encode()).hexdigest()
    elif len(previous_hash) != 64:
        # Ensure hash is proper length - extend or truncate if needed
        if len(previous_hash) < 64:
            # Extend short hash by hashing it with itself
            while len(previous_hash) < 64:
                previous_hash = hashlib.sha3_256(previous_hash.encode()).hexdigest()
        else:
            # Truncate long hash
            previous_hash = previous_hash[:64]
    
    # Validate block_time
    if not block_time or block_time <= 0:
        raise ValueError("block_time must be a positive number")
    
    # Constants for the algorithm
    DATASET_SIZE = 256 * 1024  # 256KB dataset
    MIX_LENGTH = 32
    EPOCH_LENGTH = 100
    ADJUSTMENT_FACTOR = 0.25
    
    # Initialize round constants for mixing
    round_constants = [
        int.from_bytes(hashlib.sha3_256(str(i).encode()).digest()[:8], 'big')
        for i in range(16)
    ]
    
    initial_mix = [
        int.from_bytes(hashlib.sha3_256(str(i + 100).encode()).digest()[:8], 'big')
        for i in range(MIX_LENGTH)
    ]
    
    def generate_dataset(epoch: int, prev_hash: str) -> List[bytes]:
        """Generate dataset for the current epoch using previous hash as additional entropy"""
        # Combine epoch and previous hash for dataset seed
        seed = hashlib.sha3_256(
            str(epoch).encode() + bytes.fromhex(prev_hash)
        ).digest()
        dataset = []
        
        for i in range(DATASET_SIZE // 32):
            item = hashlib.sha3_256(seed + struct.pack(">I", i)).digest()
            dataset.append(item)
        
        return dataset
    
    def compute_mix(header_bytes: bytes, dataset: List[bytes], prev_hash: bytes) -> bytes:
        """Compute the mix value using the dataset and previous hash"""
        # Initialize mix with previous hash influence
        mix = [x ^ int.from_bytes(prev_hash[i:i+8], 'big') 
               for i, x in enumerate(initial_mix) if i < len(prev_hash)//8]
        
        for i in range(64):
            # Include previous hash in mix calculation
            mix_value = (sum(mix) + int.from_bytes(prev_hash[:8], 'big')) % len(dataset)
            dataset_item = dataset[mix_value]
            round_const = round_constants[i % len(round_constants)]
            
            for j in range(len(mix)):
                mix[j] ^= int.from_bytes(dataset_item[j*4:(j+1)*4], 'big')
                mix[j] = (mix[j] + round_const) & 0xFFFFFFFF
                mix[j] = ((mix[j] << 13) | (mix[j] >> 19)) & 0xFFFFFFFF
                # Additional mixing with previous hash
                mix[j] ^= int.from_bytes(prev_hash[j%32:j%32+4], 'big')
        
        final_mix = bytearray()
        for value in mix:
            final_mix.extend(value.to_bytes(4, 'big'))
        
        return bytes(final_mix)
    
    # Adjust difficulty based on block time
    difficulty = int(difficulty * (1 + (block_time / 10 - 1) * ADJUSTMENT_FACTOR))
    difficulty = max(1, min(difficulty, 32))  # Clamp difficulty
    target = '0' * difficulty
    
    # Start mining process
    current_nonce = nonce
    epoch = current_nonce // EPOCH_LENGTH
    prev_hash_bytes = bytes.fromhex(previous_hash)
    dataset = generate_dataset(epoch, previous_hash)
    
    while True:
        # Create header bytes with previous hash influence
        header = struct.pack(">I32sQQI",
            1,  # version
            prev_hash_bytes,
            int(time.time()),
            current_nonce,
            difficulty
        )
        
        # Compute mix and final hash
        mix = compute_mix(header, dataset, prev_hash_bytes)
        hash_result = hashlib.sha3_256(header + mix + prev_hash_bytes).hexdigest()
        
        if hash_result.startswith(target):
            return hash_result, current_nonce
        
        current_nonce += 1
        
        # Check if we've moved to a new epoch
        if current_nonce // EPOCH_LENGTH != epoch:
            epoch = current_nonce // EPOCH_LENGTH
            dataset = generate_dataset(epoch, previous_hash)

def deterministic_program(block_string, nonce, previous_hash, length=64):
    # Combine block data, nonce, and previous hash
    input_data = f"{block_string}{nonce}{previous_hash}".encode()
    initial_state = hashlib.sha3_256(input_data).digest()
    
    # Create memory buffer
    memory_size = max(length * 1024, 16384)  # Minimum 16KB buffer
    memory_buffer = bytearray(memory_size)
    
    # Fill memory buffer
    for i in range(0, memory_size, 32):
        current_hash = hashlib.sha3_256(initial_state + i.to_bytes(4, byteorder='big')).digest()
        memory_buffer[i:i+32] = current_hash

    # Define operations with dynamic dependencies
    operations = ['^', '&', '|', '+', '-', '<<', '>>', '*', '%']
    program = []
    current_state = initial_state

    # Main loop
    for i in range(length):
        # Compute index based on current state
        index = int.from_bytes(current_state[:4], byteorder='big') % (memory_size - 32)
        
        # Access memory buffer
        memory_block = bytes(memory_buffer[index:index + 32])
        
        # Determine operation dynamically
        op_index = int.from_bytes(current_state[-4:], byteorder='big') % len(operations)
        operation = operations[op_index]

        # Update state with new hash
        current_state = hashlib.sha3_256(memory_block + current_state).digest()
        
        # Modify memory buffer
        new_pos = int.from_bytes(current_state[-4:], byteorder='big') % (memory_size - 32)
        memory_buffer[new_pos:new_pos + 32] = current_state

        # Append operation result to program
        result_hex = current_state.hex()
        program.append(f"{result_hex[i % len(result_hex)]}{operation}")
        
        # Mix in previous result
        if i > 0:
            current_state = hashlib.sha3_256(current_state + program[i-1].encode()).digest()
    
    return program

def progpow_hash(block_string, nonce, program):
    """Generates a secure hash for the block using SHA-3."""
    hash_input = f"{block_string}{nonce}{''.join(program)}"
    initial_hash = hashlib.sha3_256(hash_input.encode()).hexdigest()
    final_hash = hashlib.sha3_512(initial_hash.encode()).hexdigest()
    return final_hash

def validate_block(block_data, program_hash):
    if program_hash != ALGORITHM_VERSION_HASH:
        raise ValueError("Invalid mining algorithm version detected!")

    try:
        block_hash = block_data["hash"]
        previous_hash = block_data["previous_hash"]
        block_string = block_data["data"]
        nonce = block_data["nonce"]
        difficulty = block_data["difficulty"]
        timestamp = block_data["timestamp"]
    except KeyError as e:
        raise ValueError(f"Missing required block field: {e}")

    target = "0" * difficulty
    if not block_hash.startswith(target):
        raise ValueError("Block hash does not meet the required difficulty target!")

    recalculated_hash = progpow_hash(block_string, nonce, [])
    if recalculated_hash != block_hash:
        raise ValueError("Block hash is inconsistent with block data!")

    if not previous_hash:
        raise ValueError("Previous block hash is missing!")
    # Add additional logic here if chain context is available to confirm the previous hash.

    current_time = int(time.time())
    if timestamp > current_time:
        raise ValueError("Block timestamp is in the future!")
    if abs(current_time - timestamp) > 3600:  # Allowable drift of 1 hour
        raise ValueError("Block timestamp is too far in the past or future!")

    if nonce < 0 or nonce > 2**32 - 1:  # Example range, modify based on requirements
        raise ValueError("Nonce is out of acceptable range!")

    print("Block validation successful.")

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0, hash=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.constants_hash = constants_hash  # Set the constants_hash before calculating the hash
        self.reward = self.calculate_block_reward()  # Calculate reward for this block
        self.hash = hash or self.calculate_hash()  # Now that constants_hash is set, calculate the block hash

    def calculate_block_reward(self):
        """Calculate the reward for the block based on the number of halvings."""
        halvings = self.index // HALVING_INTERVAL  # Calculate how many halvings have occurred
        reward = INITIAL_REWARD >> halvings  # Right shift by number of halvings (equivalent to halving the reward)
        
        # Ensure that reward does not go below the minimum
        if reward < MIN_REWARD:
            reward = MIN_REWARD
        
        return reward

    def calculate_hash(self):
        """Calculates the hash for the block."""
        # Including constants_hash to ensure integrity
        return hashlib.sha256(
            f"{self.index}{self.previous_hash}{self.timestamp}{self.transactions}{self.nonce}{self.constants_hash}".encode('utf-8')
        ).hexdigest()

    def to_dict(self) -> dict:
        """
        Convert block to dictionary.

        Returns:
            dict: Block data with the following keys:
                - index
                - previous_hash
                - timestamp
                - transactions
                - nonce
                - hash
                - reward
                - constants_hash
        """
        return {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'nonce': self.nonce,
            'hash': self.hash,
            'reward': self.reward,
            'constants_hash': self.constants_hash
        }

    @classmethod
    def from_dict(cls, block_dict):
        """Create a Block object from dictionary."""
        block = cls(
            block_dict['index'],
            block_dict['previous_hash'],
            block_dict['timestamp'],
            block_dict['transactions'],
            block_dict['nonce'],
            block_dict.get('hash')
        )
        block.reward = block_dict.get('reward', block.calculate_block_reward())  # Handle reward in from_dict
        block.constants_hash = block_dict.get('constants_hash', constants_hash)  # Retrieve constants_hash if available
        return block

    def __str__(self):
        """String representation for logging and debugging."""
        return f"Block(index={self.index}, hash={self.hash}, previous_hash={self.previous_hash}, transactions={self.transactions}, nonce={self.nonce}, reward={self.reward}, constants_hash={self.constants_hash})"

class Blockchain:
    def __init__(self):
        """Initialize the blockchain."""
        # Initialize default values first
        self.chain = []
        self.pending_transactions = []
        self.wallets = {}  # Holds wallets indexed by public key
        self.difficulty = INITIAL_DIFFICULTY
        self.mining_reward = BLOCK_REWARD
        self.transaction_fee = 1  # Default transaction fee
        self.block_time = 600  # Target block time in seconds (10 minutes)
        self.last_difficulty_adjustment = 0
        self.difficulty_adjustment_interval = 2016  # Number of blocks between difficulty adjustments
        self.loaded = False
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Synchronization variables
        self.last_sync_time = time.time()
        self.sync_interval = 300  # 5 minutes in seconds
        self.blocks_since_sync = 0
        self.sync_every_n_blocks = 5  # Sync every 5 blocks
        
        try:
            # Try to load existing blockchain
            if os.path.exists(BLOCKCHAIN_FILE_PATH):
                self.load_blockchain_from_file()
            else:
                self.initialize_new_blockchain()
        except Exception as e:
            logging.warning(f"Could not load blockchain from file: {e}")
            self.initialize_new_blockchain()

    def load_blockchain_from_file(self, file_path=BLOCKCHAIN_FILE_PATH):
        """Load the blockchain from the file."""
        try:
            with open(file_path, 'r') as f:
                blockchain_data = json.load(f)
                self.chain = blockchain_data.get('chain', [])
                
                # Load wallets
                wallet_data = blockchain_data.get('wallets', {})
                self.wallets = {}
                for address, wallet_dict in wallet_data.items():
                    try:
                        self.wallets[address] = Wallet.from_dict(wallet_dict)
                    except Exception as e:
                        logging.error(f"Error loading wallet {address}: {e}")
                        continue
                
                self.loaded = True
                logging.info("Blockchain loaded successfully.")
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in blockchain file: {e}")
        except FileNotFoundError:
            logging.error(f"Blockchain file not found: {file_path}")
        except Exception as e:
            logging.error(f"Error loading blockchain from file: {e}")
            raise

    def save_to_file(self):
        blockchain_data = {
            'chain': [block.to_dict() for block in self.chain],
            'wallets': {address: wallet.to_dict() for address, wallet in self.wallets.items()},
            'difficulty': self.difficulty,
            'mining_reward': self.mining_reward
        }
        with open('blockchain.json', 'w') as f:
            json.dump(blockchain_data, f)

    def save_blockchain_to_file(self):
        """Save the blockchain to a file."""
        try:
            with open(BLOCKCHAIN_FILE_PATH, 'wb') as f:
                blockchain_data = {
                    'chain': self.chain,
                    'wallets': self.wallets
                }
                pickle.dump(blockchain_data, f)
                logging.info("Blockchain saved successfully.")
        except Exception as e:
            logging.error(f"Error saving blockchain to file: {e}")
            raise

    def initialize_new_blockchain(self):
        """Initialize a new blockchain with genesis block and save it."""
        try:
            with self.lock:
                genesis_block = self.create_genesis_block()
                self.chain = [genesis_block]
                self.wallets = {}  # Start with an empty wallet list
                self.loaded = True  # Mark as loaded since we're creating fresh
                self.save_blockchain_to_file()
                logging.info("New blockchain initialized with genesis block")
        except Exception as e:
            logging.error(f"Error initializing blockchain: {str(e)}")

    def create_genesis_block(self):
        """Generate the first block in the blockchain."""
        genesis_block = Block(0, "0", int(time.time()), ["Genesis Block"])
        logging.info(f"Genesis block created: {genesis_block}")
        return genesis_block

    def get(self, key):
        """Custom get method to return values by key."""
        logging.debug(f"Calling get with key: {key}")
        if hasattr(self, key):
            return getattr(self, key)
        else:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{key}'")

    def get_current_block_reward(self, current_block):
        """Calculate the block reward for the current block."""
        initial_reward = 50
        halving_interval = 210000
        halvings = current_block // halving_interval
        reward = initial_reward / (2 ** halvings)
        return max(reward, 1)  # Minimum reward of 1

    def get_blockchain_details(self, current_block):
        """Gather blockchain details."""
        try:
            total_supply = 0
            for block in self.chain:
                for transaction in block.transactions:
                    try:
                        amount = transaction['amount']
                        if isinstance(amount, str):
                            amount = float(amount)  # Convert to float if necessary
                        total_supply += amount
                    except (TypeError, ValueError) as e:
                        print(f"Error processing transaction: {e}")

            blockchain_details = {
                'block_count': len(self.chain),
                'total_supply': total_supply,
                'current_block_reward': self.get_current_block_reward(current_block),
                'pending_transactions': len(self.pending_transactions),
                'chain': self.chain
            }
            return blockchain_details
        except Exception as e:
            print(f"Error gathering blockchain details: {e}")
            return None

    def add_block(self, new_block):
        """Add a block to the chain and handle synchronization."""
        try:
            with self.lock:
                # Add block to chain
                self.chain.append(new_block)
                logging.info(f"Block added: {new_block.to_dict()}")
                # Increment blocks since last sync
                self.blocks_since_sync += 1
                # Check if sync is needed
                self.sync_if_needed()
                self.save_blockchain_to_file()
                return True
        except Exception as e:
            logging.error(f"Error adding block: {str(e)}")
            return False

    def save_wallets_to_file(self, filepath='wallet.json'):
        temp_file = f"{filepath}.temp"
        backup_file = f"{filepath}.backup"
        
        try:
            wallets_data = {}
            for wallet in self.wallets.values():
                if wallet is None:
                    continue
                
                public_key = wallet.get_public_key()
                balance = wallet.get_balance()
                
                if public_key is None or balance is None:
                    continue
                
                wallets_data[public_key] = {
                    "balance": balance,
                    "last_updated": int(time.time())
                }
            
            with open(temp_file, 'w') as file:
                json.dump(wallets_data, file, indent=4)
                
            if os.path.exists(filepath):
                try:
                    os.replace(filepath, backup_file)
                except Exception as e:
                    logging.warning(f"Failed to create backup: {e}")
            
            os.replace(temp_file, filepath)
            
            if os.path.exists(backup_file):
                try:
                    os.remove(backup_file)
                except Exception as e:
                    logging.warning(f"Failed to remove backup file: {e}")
            
            logging.info(f"Successfully saved {len(wallets_data)} wallets to {filepath}")
            return True
            
        except Exception as e:
            logging.error(f"Error saving wallets to file: {str(e)}")
            
            if os.path.exists(backup_file) and os.path.exists(filepath):
                try:
                    os.replace(backup_file, filepath)
                    logging.info("Restored wallet file from backup")
                except Exception as restore_error:
                    logging.error(f"Failed to restore backup: {restore_error}")
            
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass
                
            return False

    def sync_wallets_with_blockchain(self):
        """Sync wallets with blockchain by updating balances."""
        try:
            for wallet in self.wallets.values():
                wallet.sync_with_blockchain(self.chain)
            logging.info("Wallets synchronized with blockchain.")
            return True
        except Exception as e:
            logging.error(f"Error syncing wallets with blockchain: {str(e)}")
            return False

    def sync_if_needed(self):
        """Perform sync if conditions are met."""
        if self.check_sync_needed():
            self.sync_wallets_with_blockchain()
            self.last_sync_time = time.time()
            self.blocks_since_sync = 0
            return True
        return False

    def check_sync_needed(self):
        """Check if synchronization is needed based on time or block count."""
        current_time = time.time()
        time_since_sync = current_time - self.last_sync_time
        
        return (
            time_since_sync >= self.sync_interval or 
            self.blocks_since_sync >= self.sync_every_n_blocks
        )

    def resolve_conflicts(self, new_chain):
        """Resolve conflicts with other nodes and sync wallets."""
        try:
            if len(new_chain) > len(self.chain):
                self.chain = new_chain
                # Force sync after chain update
                self.sync_wallets_with_blockchain()
                self.last_sync_time = time.time()
                self.blocks_since_sync = 0
                return True
            return False
        except Exception as e:
            logging.error(f"Error resolving conflicts: {str(e)}")
            return False

    def mine_block(self, wallet_address):
        """Mine a new block and handle synchronization."""
        try:
            # Step 1: Validate wallet
            if not wallet_address:
                raise ValueError("Invalid wallet address")
            
            wallet = self.find_wallet_by_address(wallet_address)
            if not wallet:
                logging.error(f"Wallet not found for address: {wallet_address}")
                return None

            with self.lock:  # Thread safety for mining
                # Step 2: Create the new block
                previous_hash = self.chain[-1].hash if self.chain else "0" * 64
                new_block = Block(
                    index=len(self.chain),
                    previous_hash=previous_hash,
                    timestamp=int(time.time()),
                    transactions=[],
                    nonce=0
                )
                
                # Step 3: Calculate total fees and reward
                fee_total = sum(txn.get('fee', 0) for txn in self.pending_transactions)
                total_reward = self.block_reward + fee_total
                
                # Create reward transaction with proper wallet public key
                reward_transaction = {
                    "from": "Network",
                    "to": wallet_address,  # Use wallet_address instead of public key
                    "amount": total_reward,
                    "timestamp": int(time.time()),
                    "type": "mining_reward"
                }
                
                # Add transactions to block
                new_block.transactions = list(self.pending_transactions)
                new_block.transactions.append(reward_transaction)
                
                # Step 4: Mine the block (proof of work)
                max_nonce = 2**32
                nonce = 0
                mining_start_time = time.time()
                
                while nonce < max_nonce:
                    block_string = (
                        f"{new_block.index}"
                        f"{new_block.previous_hash}"
                        f"{new_block.timestamp}"
                        f"{new_block.transactions}"
                        f"{nonce}"
                    )
                    hash_result, nonce = progpow_algorithm(block_string, nonce, self.difficulty)
                    
                    if hash_result.startswith("0" * self.difficulty):
                        new_block.nonce = nonce
                        new_block.hash = hash_result
                        break
                else:
                    logging.error("Failed to find valid nonce")
                    return None
                
                # Step 5: Sync blockchain and wallets (if necessary)
                if self.check_sync_needed():
                    self.sync_wallets_with_blockchain()
                
                # Step 6: Add the block to the blockchain
                success = self.add_block(new_block)
                
                if success:
                    # Clear pending transactions
                    self.pending_transactions = []
                    
                    # Update wallet state through blockchain calculation
                    # Instead of directly updating wallet.balance
                    wallet_state = self.get_wallet_state(wallet_address)
                    
                    mining_time = time.time() - mining_start_time
                    logging.info(f"Block {new_block.index} mined successfully:")
                    logging.info(f"Mining time: {mining_time:.2f} seconds")
                    logging.info(f"Hash: {new_block.hash}")
                    logging.info(f"Reward: {total_reward} units")
                    
                    # Save blockchain state
                    self.save_blockchain_to_file()
                    
                return new_block if success else None
            
        except Exception as e:
            logging.error(f"Error in mining block: {str(e)}")
            return None

    def get_wallet_state(self, address):
        wallet_state = {'total_balance': 0.0, 'transaction_history': []}
        try:
            wallet = self.wallets.get(address)
            if not wallet:
                return wallet_state

            transactions = [t for block in self.chain for t in block.transactions if t['to'] == address or t['from'] == address]
            for transaction in transactions:
                if transaction['to'] == address:
                    wallet_state['total_balance'] += transaction['amount']
                elif transaction['from'] == address:
                    wallet_state['total_balance'] -= transaction['amount']
                wallet_state['transaction_history'].append({
                    'type': 'received' if transaction['to'] == address else 'sent',
                    'amount': transaction['amount'],
                    'from': transaction.get('from'),
                    'to': transaction.get('to'),
                    'block': transaction.get('block')
                })

            return wallet_state
        except Exception as e:
            logging.error(f"Error retrieving wallet state for address {address}: {e}")
            return wallet_state

    def force_sync(self):
        """Force an immediate wallet synchronization."""
        try:
            logging.info("Forcing wallet synchronization...")
            success = self.sync_wallets_with_blockchain()
            if success:
                self.last_sync_time = time.time()
                self.blocks_since_sync = 0
                logging.info("Forced synchronization completed successfully")
            return success
        except Exception as e:
            logging.error(f"Error during forced sync: {str(e)}")
            return False

    def handle_new_transaction(self, transaction):
        """Process a new transaction and handle synchronization."""
        self.pending_transactions.append(transaction)
        logging.info(f"New transaction added: {transaction}")
        
        # Check sync need periodically
        self.sync_if_needed()

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
        wallet = Wallet(self)
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

        # Update balances
        sender_wallet.update_balance(-(amount + fee))
        recipient_wallet.update_balance(amount)

        self.pending_transactions.append(transaction_data)
        logging.info(f"Transaction added: {transaction_data}")
        self.save_blockchain_to_file()  # Save blockchain after successful transaction
        self.save_wallets_to_file()     # Save updated wallet balances

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
        wallet = self.wallets.get(wallet_address)  # Use dictionary lookup for efficiency
        if wallet:
            logging.info(f"Wallet found for address: {wallet_address}")
        else:
            logging.warning(f"Wallet not found for address: {wallet_address}")
        return wallet

    def to_dict(self):
        """Convert blockchain to dictionary."""
        return {
            'chain': [block.to_dict() for block in self.chain],  # Assuming each block has a to_dict method
            'pending_transactions': self.pending_transactions,
            'difficulty': self.difficulty,
            'wallets': {address: wallet.to_dict() for address, wallet in self.wallets.items()}  # Assuming wallet has to_dict
        }

    def load_from_dict(self, data: dict) -> None:
        """Load blockchain state from a dictionary."""
        try:
            # Load blockchain parameters with defaults
            self.difficulty = self.get('difficulty') or self.difficulty
            self.mining_reward = self.get('mining_reward') or self.mining_reward
            self.transaction_fee = self.get('transaction_fee') or self.transaction_fee
            self.block_time = self.get('block_time') or self.block_time
            self.last_difficulty_adjustment = self.get('last_difficulty_adjustment') or self.last_difficulty_adjustment
            self.difficulty_adjustment_interval = self.get('difficulty_adjustment_interval') or self.difficulty_adjustment_interval

            # Load blockchain chain
            self.chain = self.get('chain') or []

            # Load pending transactions
            self.pending_transactions = self.get('pending_transactions') or []

            # Load wallets
            wallet_data = self.get('wallets') or {}
            self.wallets = {}
            for address, wallet_dict in wallet_data.items():
                try:
                    self.wallets[address] = Wallet.from_dict(wallet_dict)
                except Exception as e:
                    logging.error(f"Error loading wallet {address}: {e}")
                    continue

            # Ensure genesis block
            if not self.chain:
                self.create_genesis_block()

            logging.info("Blockchain loaded successfully from dictionary")
        except Exception as e:
            logging.error(f"Error loading blockchain from dictionary: {e}")
            raise

    def get_block_by_index(self, index):
        """Retrieve a block by index."""
        if 0 <= index < len(self.chain):  # Consistent with self.chain usage
            return self.chain[index]
        else:
            raise IndexError("Block index out of range.")

    def load_blockchain_from_file(self, filename='blockchain.json'):
        """Load blockchain state from a file."""
        try:
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    data = json.load(f)
                self.load_from_dict(data)
                self.loaded = True  # Set to True after successful load
                logging.info(f"Blockchain loaded from {filename}")
            else:
                logging.info(f"No blockchain file found at {filename}, starting fresh")
                self.initialize_new_blockchain()  # Create a new blockchain with genesis block
        except Exception as e:
            logging.error(f"Error loading blockchain from file: {e}")
            raise

    def save_blockchain_to_file(self, filename='blockchain.json'):
        """Save blockchain state to a file."""
        try:
            data = {
                'chain': [block.to_dict() for block in self.chain],
                'pending_transactions': self.pending_transactions,
                'wallets': {address: wallet.to_dict() for address, wallet in self.wallets.items()},
                'difficulty': self.difficulty,
                'mining_reward': self.mining_reward,
                'transaction_fee': self.transaction_fee,
                'block_time': self.block_time,
                'last_difficulty_adjustment': self.last_difficulty_adjustment,
                'difficulty_adjustment_interval': self.difficulty_adjustment_interval
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
            logging.info(f"Blockchain saved to {filename}")
        except Exception as e:
            logging.error(f"Error saving blockchain to file: {e}")
            raise

    def check_if_loaded(self):
        """Check if the blockchain has been loaded successfully."""
        return self.loaded

