import hashlib
import time
import json
import os
import base58
import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Wallet:
    def __init__(self, blockchain, private_key=None):
        """Initialize the wallet with blockchain reference.
        
        Args:
            blockchain: Reference to the blockchain instance
            private_key: Optional private key to initialize wallet
        """
        self.blockchain = blockchain
        
        # Initialize keys
        if private_key is None:
            if os.path.exists('private_key.pem'):
                try:
                    with open('private_key.pem', 'rb') as f:
                        self.private_key = serialization.load_pem_private_key(f.read(), password=None)
                        logging.info("Loaded private key from file.")
                except Exception as e:
                    logging.error(f"Error loading private key: {e}")
                    raise
            else:
                self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                try:
                    with open('private_key.pem', 'wb') as f:
                        f.write(self.private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption()
                        ))
                    logging.info("Generated new private key and saved to file.")
                except Exception as e:
                    logging.error(f"Error saving private key: {e}")
                    raise
        else:
            self.private_key = private_key

        self.public_key = self.private_key.public_key()
        self.address = self.generate_address()
        logging.info(f"Wallet initialized with address: {self.address}")

    def generate_address(self):
        """Generate deterministic wallet address from public key."""
        public_key_bytes = self.get_public_key().encode('utf-8')
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        return base58.b58encode(ripemd160.digest()).decode('utf-8')

    def get_transaction_history(self):
        """Get transaction history from blockchain."""
        try:
            history = []
            for block in self.blockchain.chain:
                for tx in block.transactions:
                    if tx.get('to') == self.address or tx.get('from') == self.address:
                        history.append({
                            'block': block.index,
                            'timestamp': block.timestamp,
                            'type': 'receive' if tx.get('to') == self.address else 'send',
                            'amount': tx.get('amount', 0),
                            'from': tx.get('from'),
                            'to': tx.get('to'),
                            'transaction_type': tx.get('type', 'transfer')
                        })
            return history
        except Exception as e:
            logging.error(f"Error getting transaction history: {e}")
            return []

    def create_transaction(self, recipient_address, amount, fee=0):
        """Create a new transaction."""
        try:
            current_balance = self.get_balance()
            if current_balance < amount + fee:
                logging.error("Insufficient balance for transaction")
                return None

            transaction = {
                'timestamp': int(time.time()),
                'from': self.address,
                'to': recipient_address,
                'amount': amount,
                'fee': fee,
                'public_key': self.get_public_key()
            }

            # Sign transaction
            signature = self.sign_transaction(transaction)
            transaction['signature'] = base58.b58encode(signature).decode('utf-8')
            
            return transaction

        except Exception as e:
            logging.error(f"Error creating transaction: {e}")
            return None

    def sign_transaction(self, transaction):
        """Sign a transaction using the private key."""
        try:
            # Create deterministic transaction string
            tx_string = json.dumps(transaction, sort_keys=True)
            signature = self.private_key.sign(
                tx_string.encode(),
                padding=PKCS1v15(),
                algorithm=hashes.SHA256()
            )
            return signature
        except Exception as e:
            logging.error(f"Error signing transaction: {e}")
            raise

    def verify_transaction(self, transaction, signature):
        """Verify a transaction's signature."""
        try:
            tx_string = json.dumps(transaction, sort_keys=True)
            decoded_signature = base58.b58decode(signature.encode('utf-8'))
            
            self.public_key.verify(
                decoded_signature,
                tx_string.encode(),
                padding=PKCS1v15(),
                algorithm=hashes.SHA256()
            )
            return True
        except InvalidSignature:
            logging.warning("Invalid transaction signature")
            return False
        except Exception as e:
            logging.error(f"Error verifying transaction: {e}")
            return False

    def get_public_key(self):
        """Get public key in PEM format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def get_private_key(self):
        """Get private key in PEM format."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

    def export_wallet(self):
        """Export wallet data for backup."""
        return {
            'address': self.address,
            'public_key': self.get_public_key(),
            'private_key': self.get_private_key()
        }

    @classmethod
    def import_wallet(cls, blockchain, wallet_data):
        """Import wallet from backup data."""
        try:
            private_key = serialization.load_pem_private_key(
                wallet_data['private_key'].encode(),
                password=None
            )
            return cls(blockchain, private_key)
        except Exception as e:
            logging.error(f"Error importing wallet: {e}")
            raise

    def get_pending_transactions(self):
        """Get pending transactions for this wallet."""
        try:
            pending = []
            for tx in self.blockchain.pending_transactions:
                if tx.get('to') == self.address or tx.get('from') == self.address:
                    pending.append(tx)
            return pending
        except Exception as e:
            logging.error(f"Error getting pending transactions: {e}")
            return []

    def save_wallet(self, filename='wallet.json'):
        """Save wallet data to a file."""
        try:
            wallet_data = self.to_dict()
            with open(filename, 'w') as f:
                json.dump(wallet_data, f)
            logging.info(f"Wallet saved to {filename}.")
        except Exception as e:
            logging.error(f"Error saving wallet: {e}")
            raise

    def to_dict(self):
        """Convert wallet instance to dictionary."""
        return {
            'balance': str(self.get_balance()),  # Ensure balance is a string
            'address': self.address,
            'public_key': self.get_public_key(),
            'private_key': self.get_private_key()
        }

    @classmethod
    def from_dict(cls, blockchain, wallet_dict):
        """Create a Wallet instance from a dictionary."""
        try:
            required_keys = ['private_key', 'address']
            if not all(key in wallet_dict for key in required_keys):
                raise ValueError("Missing required keys in wallet data")

            private_key_pem = wallet_dict['private_key']
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )

            wallet = cls(blockchain, private_key)
            wallet.address = wallet_dict['address'].strip()  # Set the address properly
            return wallet
        except ValueError as e:
            logging.warning(f"Invalid wallet data: {e}")
        except Exception as e:
            logging.error(f"Error creating wallet from dict: {e}")
            raise
            
    def get_balance(self):
        """Get current balance from blockchain."""
        try:
            # Get the wallet state (which should be a dictionary)
            wallet_state = self.blockchain.get_wallet_state(self.address)

            # If wallet_state is a dictionary and contains 'total_balance', return it
            if isinstance(wallet_state, dict):
                return wallet_state.get('total_balance', 0)

            # If wallet_state is not found or is not in expected format
            logging.warning(f"Unexpected wallet state format for address {self.address}")
            return 0
        except Exception as e:
            logging.error(f"Error getting balance: {e}")
            return 0
