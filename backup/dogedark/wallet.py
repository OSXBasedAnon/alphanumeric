import logging
import hashlib
import base58
import json
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class BlockchainStateError(Exception):
    """Custom exception for blockchain state errors"""
    pass

class WalletError(Exception):
    """Custom exception for wallet-related errors"""
    pass

class Wallet:
    def __init__(self, private_key=None, blockchain_interface=None):
        if blockchain_interface is None:
            blockchain_interface = BlockchainInterface()  # Use default if not provided
        self._balance = 0
        self._last_sync = None
        self._sync_lock = asyncio.Lock()
        self._pending_transactions = []
        self._blockchain_interface = blockchain_interface

        try:
            if private_key:
                logging.info("Private key provided. Initializing wallet.")
                self.private_key = private_key
                self.public_key = private_key.public_key()
            else:
                logging.info("No private key provided. Generating new wallet keys.")
                self.private_key = self.generate_keys()
                self.public_key = self.private_key.public_key()

            self.wallet_address = self.get_wallet_address()
            logging.info(f"Wallet initialized with address: {self.wallet_address}")
        except Exception as e:
            raise WalletError(f"Failed to initialize wallet: {str(e)}")

    @property
    def balance(self):
        return self._balance

    @property
    def last_sync(self):
        return self._last_sync

    @property
    def pending_transactions_count(self):
        return len(self._pending_transactions)

    @classmethod
    def create_wallet(cls, blockchain_interface=None):
        """
        Create and return a new wallet instance.
        """
        try:
            logging.info("Creating new wallet...")
            wallet = cls(blockchain_interface=blockchain_interface)
            if blockchain_interface:
                asyncio.run(wallet.init_blockchain_state(blockchain_interface))
            return wallet
        except Exception as e:
            logging.error(f"Failed to create wallet: {e}")
            raise WalletError(f"Failed to create wallet: {str(e)}")

    async def get_wallet_info(self) -> Dict[str, Any]:
        """
        Get wallet information in a structured format.
        """
        try:
            balance = await self.get_balance()
            return {
                'address': self.wallet_address,
                'balance': balance,
                'last_sync': self._last_sync.isoformat() if self._last_sync else None,
                'pending_transactions': len(self._pending_transactions)
            }
        except Exception as e:
            raise WalletError(f"Failed to get wallet info: {str(e)}")

    async def init_blockchain_state(self, blockchain_interface):
        """
        Initialize blockchain state for the wallet.
        """
        try:
            self._blockchain_interface = blockchain_interface
            await self.sync_with_blockchain()
            logging.info("Blockchain state initialized successfully")
        except Exception as e:
            logging.error(f"Failed to initialize blockchain state: {e}")
            raise BlockchainStateError(f"Failed to initialize blockchain state: {str(e)}")

    async def sync_with_blockchain(self):
        if not self._blockchain_interface:
            raise BlockchainStateError("No blockchain interface configured")

        async with self._sync_lock:
            try:
                new_balance = await self._blockchain_interface.get_balance(self.wallet_address)
                pending_txs = await self._blockchain_interface.get_pending_transactions(self.wallet_address)

                # Update wallet state
                self._balance = new_balance
                self._pending_transactions = pending_txs
                self._last_sync = datetime.now()

                logging.info(f"Wallet synchronized. Balance: {self._balance}, "
                             f"Pending transactions: {len(self._pending_transactions)}")

                return True
            except Exception as e:
                logging.error(f"Synchronization failed: {e}")
                return False

    async def get_balance(self, force_sync=False):
        if force_sync or self._needs_sync():
            await self.sync_with_blockchain()
        return self._balance

    async def get_balance(self, force_sync=False):
        """
        Get wallet balance with optional forced synchronization.
        """
        if force_sync or self._needs_sync():
            await self.sync_with_blockchain()
        return self._balance

    def _needs_sync(self, max_age_seconds=60):
        """
        Determine if wallet needs synchronization based on last sync time.
        """
        if not self._last_sync:
            return True
        
        age = (datetime.now() - self._last_sync).total_seconds()
        return age > max_age_seconds

    async def submit_transaction(self, to_address: str, amount: float):
        """
        Submit a transaction to the blockchain with proper synchronization.
        """
        if not self._blockchain_interface:
            raise BlockchainStateError("No blockchain interface configured")

        try:
            # Ensure wallet is synchronized before transaction
            await self.sync_with_blockchain()

            if amount > self._balance:
                logging.warning(f"Transaction failed: Insufficient funds for {amount}.")
                return False  # More graceful handling of insufficient funds.

            transaction = {
                'from': self.wallet_address,
                'to': to_address,
                'amount': amount,
                'timestamp': datetime.now().isoformat(),
                'nonce': len(self._pending_transactions)
            }

            # Sign transaction
            signature = self.sign_transaction(transaction)

            # Submit to blockchain
            success = await self._blockchain_interface.submit_transaction(transaction, signature)

            if success:
                # Optimistically update balance and pending transactions
                self._pending_transactions.append(transaction)
                self._balance -= amount
                logging.info(f"Transaction submitted successfully: {amount} to {to_address}")
                return True
            else:
                logging.error(f"Transaction submission failed: Blockchain response unsuccessful.")
                return False

        except Exception as e:
            logging.error(f"Transaction submission failed: {e}")
            raise

    def generate_keys(self):
        """Generate a unique RSA key pair."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        logging.info("New RSA key pair generated.")
        return private_key

    def get_private_key(self):
        """Return private key in PEM format."""
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key_pem.decode('utf-8')

    def get_public_key(self):
        """Return public key in PEM format."""
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_pem.decode('utf-8')

    def get_wallet_address(self):
        """Generate wallet address from public key."""
        public_key_pem = self.get_public_key().encode('utf-8')
        sha256_hash = hashlib.sha256(public_key_pem).digest()
        ripemd160 = hashlib.new('ripemd160', sha256_hash)
        return base58.b58encode(ripemd160.digest()).decode('utf-8')

    def sign_transaction(self, transaction):
        """Sign a transaction using the private key."""
        try:
            # Hash transaction data first
            transaction_hash = hashlib.sha256(json.dumps(transaction, sort_keys=True).encode()).digest()
            signature = self.private_key.sign(
                transaction_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
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
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            logging.warning("Invalid signature detected.")
            return False
        except Exception as e:
            logging.error(f"Error verifying transaction: {e}")
            raise

    def to_dict(self) -> Dict[str, Any]:
        """Convert wallet to dictionary format."""
        return {
            'address': self.wallet_address,
            'balance': self._balance,
            'last_sync': self._last_sync.isoformat() if self._last_sync else None,
            'pending_transactions': len(self._pending_transactions),
            'public_key': self.get_public_key(),
            'private_key': self.get_private_key()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], blockchain_interface=None):
        """Create wallet instance from dictionary."""
        try:
            private_key_pem = data.get('private_key')
            if not private_key_pem:
                raise ValueError("Private key missing from wallet data")

            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )
            
            wallet = cls(private_key, blockchain_interface)
            wallet._balance = data.get('balance', 0)
            if data.get('last_sync'):
                wallet._last_sync = datetime.fromisoformat(data['last_sync'])
            
            return wallet

        except Exception as e:
            logging.error(f"Failed to create wallet from dictionary: {e}")
            raise

# Web3 Stuff
class BlockchainInterface:
    async def get_balance(self, address: str) -> float:
        """Get balance for address from blockchain."""
        # Implement actual blockchain communication
        logging.info(f"Fetching balance for address: {address}")
        return 0.0

    async def get_pending_transactions(self, address: str) -> list:
        """Get pending transactions for address."""
        # Implement actual blockchain communication
        logging.info(f"Fetching pending transactions for address: {address}")
        return []

    async def submit_transaction(self, transaction: dict, signature: bytes) -> bool:
        """Submit transaction to blockchain."""
        # Implement actual blockchain communication
        logging.info(f"Submitting transaction: {transaction}")
        return True

async def show_wallet_info(wallet):
    try:
        balance = await wallet.get_balance()
        
        print("\nWallet Information:")
        print(f"Address: {wallet.wallet_address}")
        print(f"Balance: {balance}")
        print(f"Last Sync: {wallet._last_sync or 'Never'}")
        print(f"Pending Transactions: {len(wallet._pending_transactions)}")
    except Exception as e:
        print(f"Error displaying wallet info: {e}")

async def main():
    try:
        # Create blockchain interface
        blockchain_interface = BlockchainInterface()
        
        # Create new wallet
        wallet = Wallet.create_wallet(blockchain_interface)
        
        # Show wallet information
        await show_wallet_info(wallet)
        
        # Example transaction
        success = await wallet.submit_transaction(
            to_address="recipient_address",
            amount=1.0
        )
        
        if success:
            print("Transaction submitted successfully")
            await show_wallet_info(wallet)
            
    except Exception as e:
        logging.error(f"Error in main execution: {str(e)}")
        raise