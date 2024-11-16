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

# Setting up logging to capture logs
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Wallet:
    """Represents a cryptocurrency wallet with private and public keys."""

    def __init__(self, private_key=None):
        """Initialize the wallet with a private key or generate a new one."""
        if private_key is None:
            # Check if a private key file exists
            if os.path.exists('private_key.pem'):
                try:
                    with open('private_key.pem', 'rb') as f:
                        self.private_key = serialization.load_pem_private_key(f.read(), password=None)
                        logging.info("Loaded private key from file.")
                except Exception as e:
                    logging.error(f"Error loading private key: {e}")
                    raise
            else:
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                try:
                    with open('private_key.pem', 'wb') as f:
                        f.write(
                            self.private_key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.NoEncryption()
                            )
                        )
                    logging.info("Generated new private key and saved to file.")
                except Exception as e:
                    logging.error(f"Error saving private key: {e}")
                    raise
        else:
            self.private_key = private_key
            logging.info("Private key provided directly.")

        self.public_key = self.private_key.public_key()
        self.wallet_address = self.get_wallet_address()  # Generate wallet address only once

        # Load the balance from the saved file, or set it to 0 if not available
        self.balance = self.load_balance()
        logging.info(f"Wallet created. Public Key Type: {type(self.public_key)}")

    def get_private_key(self):
        """Get the private key in PEM format as a string."""
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key_pem.decode('utf-8')

    def load_balance(self):
        """Load the wallet balance from the saved file, if available."""
        if os.path.exists('wallet.json'):
            try:
                with open('wallet.json', 'r') as f:
                    wallet_data = json.load(f)
                    return wallet_data.get('balance', 0)  # Return the balance if available, else 0
            except json.JSONDecodeError as e:
                logging.error(f"Failed to decode wallet data: {e}")
            except Exception as e:
                logging.error(f"Failed to load wallet balance: {e}")
        return 0  # Default balance is 0 if no file or error occurs

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

    def get_wallet_address(self):
        """Generate the wallet address from the public key."""
        sha256_hash = hashlib.sha256(self.get_public_key_pem()).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        wallet_address = base58.b58encode(ripemd160.digest()).decode('utf-8')
        logging.info(f"Generated Wallet Address: {wallet_address}")
        return wallet_address

    def sign_transaction(self, transaction):
        """Sign a transaction with the wallet's private key."""
        try:
            transaction_string = json.dumps(transaction, sort_keys=True)
            signature = self.private_key.sign(
                transaction_string.encode(),
                padding=PKCS1v15(),
                algorithm=hashes.SHA256()
            )
            return signature
        except Exception as e:
            logging.error(f"Error signing transaction: {e}")
            raise

    def verify_transaction(self, transaction, signature):
        """Verify the signature of a transaction."""
        try:
            transaction_string = json.dumps(transaction, sort_keys=True)
            self.public_key.verify(
                signature,
                transaction_string.encode(),
                padding=PKCS1v15(),
                algorithm=hashes.SHA256()
            )
            return True
        except InvalidSignature:
            logging.warning("Invalid signature detected.")
            return False
        except Exception as e:
            logging.error(f"Error verifying transaction: {e}")
            raise

    def update_balance(self, amount):
        """Update the wallet's balance by adding the amount."""
        self.balance += amount
        self.save_wallet()  # Save the balance after each update

    def get_balance(self):
        """Get the current balance of the wallet."""
        return self.balance

    def set_balance(self, amount):
        """Set the balance to a specific amount."""
        self.balance = amount
        self.save_wallet()  # Save the balance after setting it

    def to_dict(self):
        """Convert wallet to a dictionary for serialization."""
        return {
            'balance': self.balance,
            'public_key': self.get_public_key(),
            'wallet_address': self.wallet_address,  # Ensure wallet address is saved
            'private_key': self.get_private_key()
        }

    @classmethod
    def from_dict(cls, wallet_dict):
        """Create a wallet instance from a dictionary."""
        private_key_pem = wallet_dict.get('private_key')
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        wallet = cls(private_key)
        wallet.balance = wallet_dict.get('balance', 0)
        wallet.wallet_address = wallet_dict.get('wallet_address')  # Ensure wallet address is loaded
        return wallet

    def save_wallet(self, filename='wallet.json'):
        """Save the wallet data to a file."""
        try:
            wallet_data = self.to_dict()
            with open(filename, 'w') as f:
                json.dump(wallet_data, f)
            logging.info(f"Wallet saved to {filename}.")
        except Exception as e:
            logging.error(f"Error saving wallet: {e}")
            raise

    @classmethod
    def load_wallet(cls, filename='wallet.json'):
        """Load a wallet from a file."""
        if not os.path.exists(filename):
            logging.error(f"No wallet file found at {filename}")
            return None

        try:
            with open(filename, 'r') as f:
                wallet_data = json.load(f)
            logging.info(f"Loaded wallet data from {filename}.")
            return cls.from_dict(wallet_data)
        except Exception as e:
            logging.error(f"Error loading wallet file: {e}")
            return None
