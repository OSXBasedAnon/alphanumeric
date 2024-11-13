import hashlib
import json
import time
import random
import struct
import rsa
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

# Constants for Proof of Work
INITIAL_DIFFICULTY = 4
DIFFICULTY_ADJUSTMENT_INTERVAL = 10  # Number of blocks after which difficulty is adjusted
BLOCK_REWARD = 50  # Initial block reward for mining
HALVING_INTERVAL = 210000  # Number of blocks after which the block reward is halved
TRANSACTION_FEE = 1  # Transaction fee

# Update tokenomics for 500,000,000 token supply
TOTAL_SUPPLY = 500_000_000  # Total supply of tokens
MAX_BLOCKS = 10_000_000  # Example: how many blocks until the token supply runs out (this could be adjusted)

# ProgPoW algorithm
def random_program():
    operations = ['+', '-', '*', '^', '|', '&']
    program = []
    for _ in range(64):
        op = random.choice(operations)
        reg = random.randint(0, 15)
        program.append((op, reg))
    return program

def progpow_hash(block_string, nonce, program):
    hash_input = f"{block_string}{nonce}".encode('utf-8')
    h = hashlib.sha256(hash_input).digest()
    state = list(struct.unpack('<8I', h))  # Convert to list

    for op, reg in program:
        if op == '+':
            state[reg % 8] += state[(reg + 1) % 8]
        elif op == '-':
            state[reg % 8] -= state[(reg + 1) % 8]
        elif op == '*':
            state[reg % 8] *= state[(reg + 1) % 8]
        elif op == '^':
            state[reg % 8] ^= state[(reg + 1) % 8]
        elif op == '|':
            state[reg % 8] |= state[(reg + 1) % 8]
        elif op == '&':
            state[reg % 8] &= state[(reg + 1) % 8]
        state[reg % 8] &= (16 * 1024 // 4) - 1

    final_state = struct.pack('<8I', *state)
    return hashlib.sha256(final_state).hexdigest()

def progpow_algorithm(block_string, nonce):
    program = random_program()
    return progpow_hash(block_string, nonce, program)

# Block and Blockchain structure
class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{self.transactions}"
        return progpow_algorithm(block_string, self.nonce)

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.difficulty = INITIAL_DIFFICULTY
        self.block_reward = BLOCK_REWARD
        self.lock = threading.Lock()
        self.token_supply = TOTAL_SUPPLY
        self.blocks_mined = 0

    def create_genesis_block(self):
        return Block(0, "0", int(time.time()), [], 0)

    def add_block(self, new_block):
        with self.lock:
            self.chain.append(new_block)
            self.adjust_difficulty()
            self.update_block_reward()

    def adjust_difficulty(self):
        if len(self.chain) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0:
            expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL * 10  # Expected time in seconds
            actual_time = self.chain[-1].timestamp - self.chain[-DIFFICULTY_ADJUSTMENT_INTERVAL].timestamp
            if actual_time < expected_time / 2:
                self.difficulty += 1
            elif actual_time > expected_time * 2:
                self.difficulty -= 1

    def update_block_reward(self):
        if len(self.chain) % HALVING_INTERVAL == 0:
            self.block_reward /= 2

    def mine_pending_transactions(self, miner_wallet):
        block = Block(len(self.chain), self.chain[-1].hash, int(time.time()), self.pending_transactions)
        block.nonce = self.mine_block(block)
        self.add_block(block)
        miner_wallet.receive_payment(self.block_reward)  # Reward for mining a block
        self.pending_transactions = []

    def mine_block(self, block):
        while True:
            if block.calculate_hash()[:self.difficulty] == '0' * self.difficulty:
                return block.nonce
            block.nonce += 1
            if self.blocks_mined >= MAX_BLOCKS:
                print("Max blocks reached! Token supply exhausted.")
                exit()  # Exit when the total supply is mined
            self.blocks_mined += 1

    def create_transaction(self, sender_wallet, recipient_wallet, amount):
        if sender_wallet.send_payment(amount, recipient_wallet):
            transaction = {"from": sender_wallet.public_key, "to": recipient_wallet.public_key, "amount": amount}
            self.pending_transactions.append(transaction)
            return True
        return False

    def validate_block(self, block):
        if block.previous_hash == self.chain[-1].hash and block.hash == block.calculate_hash():
            for transaction in block.transactions:
                if not self.validate_transaction(transaction):
                    return False
            return True
        return False

    def validate_transaction(self, transaction):
        # Placeholder for transaction validation logic
        return True

    def display_chain(self):
        for block in self.chain:
            print(f"Block #{block.index} Hash: {block.hash}\nTransactions: {block.transactions}\n")

# Wallet system with private-public keys
class Wallet:
    def __init__(self):
        self.balance = 0
        self.private_key, self.public_key = self.generate_keys()

    def generate_keys(self):
        (public_key, private_key) = rsa.newkeys(2048)  # RSA keys with 2048-bit
        return private_key, public_key

    def sign_transaction(self, transaction):
        try:
            transaction_string = json.dumps(transaction, sort_keys=True)
            return rsa.sign(transaction_string.encode('utf-8'), self.private_key, 'SHA-256')
        except Exception as e:
            print(f"Error signing transaction: {e}")
            return None

    def verify_transaction(self, transaction, signature):
        try:
            transaction_string = json.dumps(transaction, sort_keys=True)
            rsa.verify(transaction_string.encode('utf-8'), signature, self.public_key)
            return True
        except rsa.pkcs1.VerificationError:
            return False
        except Exception as e:
            print(f"Error verifying transaction: {e}")
            return False

    def receive_payment(self, amount):
        self.balance += amount

    def send_payment(self, amount, recipient_wallet):
        if self.balance >= amount + TRANSACTION_FEE:
            self.balance -= amount + TRANSACTION_FEE
            recipient_wallet.receive_payment(amount)
            return True
        return False

# Node improvements with Gossip Protocol and P2P Network
class GossipProtocol:
    def broadcast_block(self, block_data):
        # Implement gossip broadcast for blocks
        pass

    def broadcast_transaction(self, transaction_data):
        # Implement gossip broadcast for transactions
        pass

# In the Node class, add more print statements
class Node:
    def __init__(self, blockchain, is_miner=False):
        self.blockchain = blockchain
        self.peers = []  # List of peer node addresses
        self.node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.node_socket.bind(('localhost', 5003))  # Change port for secondary node
        self.node_socket.listen(5)
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.gossip_protocol = GossipProtocol()  # Placeholder for gossip implementation
        self.is_miner = is_miner  # Flag indicating if this node mines
        self.connected_peers = []  # List of connected peers

    def start(self):
        print("Node is starting...")
        threading.Thread(target=self.listen_for_clients).start()
        if self.is_miner:
            threading.Thread(target=self.mine_blocks).start()
        print("Listening for incoming connections...")

        # Add known peer addresses to the peer list
        self.peers = [
            ('localhost', 5001),  # Example peer address
            # ... other peer addresses
        ]

        # Start a thread to periodically connect to peers
        threading.Thread(target=self.connect_to_peers).start()

    def listen_for_clients(self):
        try:
            while True:
                print("Waiting for incoming connections...")
                client_socket, client_address = self.node_socket.accept()
                print(f"Connection from {client_address} has been established!")
                self.executor.submit(self.handle_client, client_socket)
        except Exception as e:
            print(f"Error in start: {e}")
        finally:
            self.executor.shutdown(wait=True)

    def handle_client(self, client_socket):
        try:
            print("Handling client...")
            data = client_socket.recv(1024).decode('utf-8')
            message = json.loads(data)
            if message["type"] == "new_block":
                self.handle_new_block(message["block"])
            elif message["type"] == "new_transaction":
                self.handle_new_transaction(message["transaction"])
            client_socket.close()
        except Exception as e:
            print(f"Error handling client: {e}")

    def mine_blocks(self):
        while True:
            if self.blockchain.pending_transactions:
                print("Mining new block...")
                self.blockchain.mine_pending_transactions(self)
                self.gossip_protocol.broadcast_block(self.blockchain.chain[-1].__dict__)
                time.sleep(5)

    def connect_to_peers(self):
        while True:
            for peer in self.peers:
                try:
                    print(f"Connecting to peer: {peer}")
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.connect(peer)
                        message = {"type": "get_blockchain"}
                        sock.send(json.dumps(message).encode('utf-8'))
                except Exception as e:
                    print(f"Error connecting to peer {peer}: {e}")
            time.sleep(60)  # Try reconnecting every 60 seconds

    def handle_new_block(self, block_data):
        try:
            print(f"Handling new block: {block_data['hash']}")
            # Add the new block to the blockchain
            new_block = Block(
                block_data["index"],
                block_data["previous_hash"],
                block_data["timestamp"],
                block_data["transactions"],
                block_data["nonce"]
            )
            if self.blockchain.validate_block(new_block):
                self.blockchain.add_block(new_block)
                print(f"Block #{block_data['index']} added successfully.")
            else:
                print("Block validation failed.")
        except Exception as e:
            print(f"Error handling new block: {e}")

    def handle_new_transaction(self, transaction_data):
        try:
            print(f"Handling new transaction: {transaction_data}")
            sender_wallet = Wallet()  # Simulate the sender's wallet (replace with real wallet handling)
            recipient_wallet = Wallet()  # Simulate the recipient's wallet
            amount = transaction_data["amount"]
            if self.blockchain.create_transaction(sender_wallet, recipient_wallet, amount):
                print(f"Transaction from {transaction_data['from']} to {transaction_data['to']} added successfully.")
            else:
                print("Transaction validation failed.")
        except Exception as e:
            print(f"Error handling new transaction: {e}")

    def broadcast_transaction(self, transaction_data):
        for peer in self.connected_peers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect(peer)
                    message = {"type": "new_transaction", "transaction": transaction_data}
                    sock.send(json.dumps(message).encode('utf-8'))
                    print(f"Transaction broadcasted to {peer}")
            except Exception as e:
                print(f"Error broadcasting transaction to {peer}: {e}")

    def broadcast_block(self, block_data):
        for peer in self.connected_peers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect(peer)
                    message = {"type": "new_block", "block": block_data}
                    sock.send(json.dumps(message).encode('utf-8'))
                    print(f"Block broadcasted to {peer}")
            except Exception as e:
                print(f"Error broadcasting block to {peer}: {e}")

    def start_mining(self):
        if not self.is_miner:
            print("This node is not a miner.")
            return
        print("Mining started...")
        self.mine_blocks()

    def connect_to_peers(self):
        while True:
            for peer in self.peers:
                try:
                    print(f"Connecting to peer: {peer}")
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.connect(peer)
                        message = {"type": "get_blockchain"}
                        sock.send(json.dumps(message).encode('utf-8'))
                except Exception as e:
                    print(f"Error connecting to peer {peer}: {e}")
            time.sleep(60)  # Try reconnecting every 60 seconds

# Example of how to run the node and blockchain system
def main():
    blockchain = Blockchain()
    node = Node(blockchain, is_miner=True)  # Create a miner node
    node.start()

    # Simulate a wallet
    miner_wallet = Wallet()

    # Simulate mining process
    node.mine_pending_transactions(miner_wallet)
    
    # Simulate transactions
    sender_wallet = Wallet()
    recipient_wallet = Wallet()
    blockchain.create_transaction(sender_wallet, recipient_wallet, 10)

    # Simulate broadcasting transactions and blocks
    transaction_data = {
        "from": sender_wallet.public_key,
        "to": recipient_wallet.public_key,
        "amount": 10
    }
    node.broadcast_transaction(transaction_data)

    block_data = blockchain.chain[-1].__dict__
    node.broadcast_block(block_data)

if __name__ == "__main__":
    main()
