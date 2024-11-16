import hashlib
import time
import json
import os
import base58
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

class Wallet:
    """Represents a cryptocurrency wallet with private and public keys."""
    
    def __init__(self, private_key=None):
        """Initialize the wallet with a private key or generate a new one."""
        if private_key is None:
            if os.path.exists('private_key.pem'):
                with open('private_key.pem', 'rb') as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
                    logging.info("Loaded private key from file.")
            else:
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                with open('private_key.pem', 'wb') as f:
                    f.write(
                        self.private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption()
                        )
                    )
                logging.info("Generated new private key and saved to file.")
        else:
            self.private_key = private_key
            logging.info("Private key provided directly.")
        
        self.public_key = self.private_key.public_key()
        self.balance = 0
        self.wallet_address = self.get_wallet_address()  # Generate wallet address
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
        """Verify the signature of a transaction."""
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
        """Update the wallet's balance by adding the amount."""
        self.balance += amount

    def get_balance(self):
        """Get the current balance of the wallet."""
        return self.balance

    def set_balance(self, amount):
        """Set the balance to a specific amount."""
        self.balance = amount

    def to_dict(self):
        """Convert wallet to a dictionary for serialization."""
        return {
            'balance': self.balance,
            'public_key': self.get_public_key(),
            'wallet_address': self.wallet_address,  # Include wallet address in the dictionary
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
        wallet.wallet_address = wallet_dict.get('wallet_address')  # Set wallet address
        return wallet

    def save_wallet(self, filename='wallet.json'):
        """Save the wallet data to a file."""
        wallet_data = self.to_dict()
        with open(filename, 'w') as f:
            json.dump(wallet_data, f)
        logging.info(f"Wallet saved to {filename}.")

    @classmethod
    def load_wallet(cls, filename='wallet.json'):
        """Load a wallet from a file."""
        if not os.path.exists(filename):
            logging.error(f"No wallet file found at {filename}")
            return None

        with open(filename, 'r') as f:
            wallet_data = json.load(f)
            logging.info(f"Loaded wallet data from {filename}.")

        return cls.from_dict(wallet_data)

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    wallet = Wallet()
    wallet.save_wallet()

    loaded_wallet = Wallet.load_wallet()
    if loaded_wallet:
        logging.info(f"Loaded wallet balance: {loaded_wallet.get_balance()}")
        logging.info(f"Loaded wallet public key: {loaded_wallet.get_public_key()}")
        logging.info(f"Wallet Address: {loaded_wallet.get_wallet_address()}")

    logging.info(f"Wallet Address: {wallet.get_wallet_address()}")
    logging.info(f"Balance: {wallet.get_balance()} units")
