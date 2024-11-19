import json
import logging
import hashlib
from datetime import datetime, timezone
import os

# Define a fixed timestamp for the genesis block to avoid discrepancies
GENESIS_BLOCK_TIMESTAMP = "2024-11-18 22:38:38.855183"  # Use a fixed timestamp

GENESIS_BLOCK_DATA = {
    "index": 0,
    "timestamp": GENESIS_BLOCK_TIMESTAMP,
    "data": "Genesis Block",
    "previous_hash": "0" * 64,  # No previous block, hence all zeros
    "hash": None,  # Will be computed after creating the block
    "difficulty": 1,
    "nonce": 0,
}

BLOCKCHAIN_FILE_PATH = "blockchain_state.json"  # Path to store blockchain state

class Blockchain:
    def __init__(self):
        # This will initialize the blockchain with a genesis block
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 1  # Can be adjusted
        self.create_genesis_block()

    def create_genesis_block(self):
        """Creates the genesis block as a dictionary"""
        genesis_block = {
            'index': 0,
            'previous_hash': "0" * 64,  # Genesis block has no previous hash
            'timestamp': GENESIS_BLOCK_TIMESTAMP,  # Use the fixed timestamp
            'merkle_root': "",  # Empty for genesis block
            'nonce': 0,  # Nonce for genesis block
            'difficulty': 1,  # Difficulty for genesis block
            'hash': "",  # This will be filled with the calculated hash
        }

        # Now calculate the hash for the genesis block
        genesis_block['hash'] = self.calculate_block_hash(genesis_block)

        # Log the genesis block hash for debugging
        logging.debug(f"Genesis block hash: {genesis_block['hash']}")

        # Create the full blockchain structure
        blockchain_data = {
            "chain": [genesis_block],
            "pending_transactions": [],
            "difficulty": self.difficulty,
        }

        # Add the genesis block to the blockchain
        self.chain = blockchain_data["chain"]

    def calculate_block_hash(self, block_data: dict) -> str:
        """Calculate the hash for a block using its dictionary data"""
        # Log the block data for debugging purposes
        logging.debug(f"Block data for hashing: {json.dumps(block_data, sort_keys=True)}")

        # Ensure consistent hashing by sorting keys and serializing the block data
        block_data_string = json.dumps(block_data, sort_keys=True).encode('utf-8')

        # Return SHA256 hash
        return hashlib.sha256(block_data_string).hexdigest()

    def save_blockchain_to_file(self) -> None:
        """Save the current state of the blockchain to a file"""
        # Include the full structure including pending transactions and difficulty
        blockchain_data = {
            "chain": self.chain,
            "pending_transactions": self.pending_transactions,
            "difficulty": self.difficulty,
        }
        
        with open(BLOCKCHAIN_FILE_PATH, 'w') as file:
            json.dump(blockchain_data, file, indent=4)
        logging.info(f"Blockchain saved to {BLOCKCHAIN_FILE_PATH}.")

    def reset_blockchain(self) -> None:
        """Reset the blockchain to only the genesis block"""
        self.create_genesis_block()  # Recreate the genesis block and start over
        self.save_blockchain_to_file()  # Save the new blockchain to file
        logging.info("Blockchain has been reset to a new genesis block.")

    def delete_blockchain_file(self) -> None:
        """Delete the blockchain file"""
        if os.path.exists(BLOCKCHAIN_FILE_PATH):
            os.remove(BLOCKCHAIN_FILE_PATH)
            logging.info("Blockchain file deleted.")
        else:
            logging.warning(f"{BLOCKCHAIN_FILE_PATH} does not exist.")

    def load_blockchain_from_file(self) -> None:
        """Load the blockchain from the file"""
        try:
            with open(BLOCKCHAIN_FILE_PATH, 'r') as file:
                blockchain_data = json.load(file)

            # Load blockchain and its state
            self.chain = blockchain_data.get("chain", [])
            self.pending_transactions = blockchain_data.get("pending_transactions", [])
            self.difficulty = blockchain_data.get("difficulty", 1)

            logging.info("Blockchain loaded successfully from file.")
        except Exception as e:
            logging.error(f"Error loading blockchain from file: {e}")

def main():
    logging.basicConfig(level=logging.DEBUG)  # Set logging level to DEBUG to capture detailed logs

    # Initialize a new blockchain
    blockchain = Blockchain()

    # Save the blockchain to a file
    blockchain.save_blockchain_to_file()

    # Optional: To reset the blockchain (can be called later if needed)
    # blockchain.reset_blockchain()

    # Optional: To delete the blockchain file (can be called later if needed)
    # blockchain.delete_blockchain_file()

    # Optionally load the blockchain from file
    blockchain.load_blockchain_from_file()

if __name__ == "__main__":
    main()
