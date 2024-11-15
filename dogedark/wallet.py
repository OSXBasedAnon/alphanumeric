import json
import os
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

class Wallet:
    def __init__(self, private_key=None):
        if private_key and isinstance(private_key, rsa.RSAPrivateKey):
            self.private_key = private_key
            self.public_key = self.private_key.public_key()
        else:
            self.private_key = self.generate_private_key()
            self.public_key = self.private_key.public_key()

        self.balance = 0
        # Generate and store the wallet address once, during wallet creation
        self.wallet_address = self.get_wallet_address()

    def generate_private_key(self):
        """Generate a new RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def get_public_key_pem(self):
        """Get the public key in PEM format as bytes."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_public_key(self):
        """Get the public key in PEM format as string."""
        return self.get_public_key_pem().decode('utf-8')

    def set_balance(self, balance):
        """Set the balance for the wallet."""
        self.balance = balance

    def get_balance(self):
        """Get the balance of the wallet."""
        return self.balance

    def sign_message(self, message):
        """Sign a message with the private key."""
        signature = self.private_key.sign(
            message.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, signature, message):
        """Verify a signature with the public key."""
        try:
            self.public_key.verify(
                signature,
                message.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False

    def save_wallet(self, filename="wallet.json"):
        """Save the private key, public key, and wallet address to a JSON file."""
        wallet_data = {
            'private_key': self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8'),
            'public_key': self.get_public_key(),
            'wallet_address': self.wallet_address,
            'balance': self.balance
        }
        with open(filename, 'w') as f:
            json.dump(wallet_data, f)
        print(f"Wallet saved to {filename}")

    @staticmethod
    def load_wallet(filename="wallet.json"):
        """Load the wallet data from a JSON file and return a Wallet instance."""
        if not os.path.exists(filename):
            print("Wallet file not found!")
            return None

        with open(filename, 'r') as f:
            wallet_data = json.load(f)

        private_key = serialization.load_pem_private_key(
            wallet_data['private_key'].encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        wallet = Wallet(private_key)
        wallet.wallet_address = wallet_data['wallet_address']
        wallet.set_balance(wallet_data['balance'])
        
        print(f"Wallet loaded from {filename}")
        return wallet

    def get_wallet_address(self):
        """Generate a wallet address from the public key."""
        public_key_bytes = self.get_public_key_pem()

        # Step 1: SHA-256 hash of the public key
        sha256_hash = hashlib.sha256(public_key_bytes).digest()

        # Step 2: RIPEMD-160 hash of the SHA-256 result
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

        # Step 3: Return the wallet address (usually hex-encoded)
        return ripemd160_hash.hex()
