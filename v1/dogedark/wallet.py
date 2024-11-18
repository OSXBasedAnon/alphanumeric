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
    def __init__(self, private_key=None):
        """Initialize the wallet, either loading or generating keys."""
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
            logging.info("Private key provided directly.")

        self.public_key = self.private_key.public_key()
        self.wallet_address = self.get_wallet_address()
        self.balance = self.load_balance()
        logging.info(f"Wallet created. Public Key Type: {type(self.public_key)}")

    def generate_keys(self):
        """Generate a unique set of RSA keys for the wallet."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private_key = private_key
        self.public_key = private_key.public_key()

        # Convert the public key to PEM format (as a string)
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logging.info("RSA keys generated for wallet.")
        return pem

    def get_private_key(self):
        """Return private key in PEM format."""
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key_pem.decode('utf-8')

    def get_public_key(self):
        """Return the public key in PEM format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def get_wallet_address(self):
        """Generate wallet address from public key."""
        sha256_hash = hashlib.sha256(self.get_public_key().encode('utf-8')).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        wallet_address = base58.b58encode(ripemd160.digest()).decode('utf-8')
        logging.info(f"Generated Wallet Address: {wallet_address}")
        return wallet_address

    def load_balance(self):
        """Load balance from wallet data."""
        if os.path.exists('wallet.json'):
            try:
                with open('wallet.json', 'r') as f:
                    wallet_data = json.load(f)
                    balance = wallet_data.get('balance', 0)
                    logging.info(f"Loaded balance: {balance}")
                    return balance
            except json.JSONDecodeError as e:
                logging.error(f"Failed to decode wallet data: {e}")
            except Exception as e:
                logging.error(f"Failed to load wallet balance: {e}")
        else:
            logging.warning("No wallet file found. Defaulting balance to 0.")
        return 0

    def update_balance(self, amount):
        """Update the wallet balance."""
        self.balance += amount
        self.save_wallet()

    def get_balance(self):
        """Return the wallet's balance."""
        return self.balance

    def set_balance(self, amount):
        """Set the wallet's balance."""
        self.balance = amount
        self.save_wallet()

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
            'balance': self.balance,
            'public_key': self.get_public_key(),
            'wallet_address': self.wallet_address,
            'private_key': self.get_private_key()
        }

    @classmethod
    def from_dict(cls, wallet_dict):
        """Create a Wallet instance from a dictionary."""
        private_key_pem = wallet_dict.get('private_key')
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        wallet = cls(private_key)
        wallet.balance = wallet_dict.get('balance', 0)
        wallet.wallet_address = wallet_dict.get('wallet_address')
        return wallet

    def sign_transaction(self, transaction):
        """Sign a transaction using the private key."""
        try:
            transaction_string = json.dumps(transaction, sort_keys=True)
            signature = self.private_key.sign(
                transaction_string.encode(),
                padding=PKCS1v15(),
                algorithm=serialization.hazmat.primitives.hashes.SHA256()
            )
            return signature
        except Exception as e:
            logging.error(f"Error signing transaction: {e}")
            raise

    def verify_transaction(self, transaction, signature):
        """Verify a transaction's signature using the public key."""
        try:
            transaction_string = json.dumps(transaction, sort_keys=True)
            self.public_key.verify(
                signature,
                transaction_string.encode(),
                padding=PKCS1v15(),
                algorithm=serialization.hazmat.primitives.hashes.SHA256()
            )
            return True
        except InvalidSignature:
            logging.warning("Invalid signature detected.")
            return False
        except Exception as e:
            logging.error(f"Error verifying transaction: {e}")
            raise


def show_balance(wallet):
    """Display the balance of a wallet."""
    print(f"Wallet Address: {wallet.wallet_address}")
    print(f"Balance: {wallet.get_balance()} units")
