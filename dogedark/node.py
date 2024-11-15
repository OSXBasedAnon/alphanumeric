import time
import logging
import socket
import threading
import json
import os
from concurrent.futures import ThreadPoolExecutor
from dogedark.blockchain import Blockchain
from dogedark.wallet import Wallet

# Set up basic logging configuration
logging.basicConfig(level=logging.INFO)

class Node:
    def __init__(self, host, port, blockchain=None, bootstrap_nodes=None):
        self.host = host
        self.port = port
        self.node_id = f"{host}:{port}"  # node_id is set here
        self.peers = set()
        self.server = None
        self.lock = threading.Lock()
        self.blockchain = blockchain if blockchain else Blockchain()
        self.wallet = None
        self.bootstrap_nodes = bootstrap_nodes or []
        self.blockchain_file = "blockchain_data.json"
        self.init_wallet()
        logging.info(f"Node initialized with ID: {self.node_id}")

    def init_wallet(self):
        self.wallet = self.blockchain.create_wallet()
        logging.info(f"Wallet created. Public Key Type in Node: {type(self.wallet.public_key)}")
        logging.info(f"Node wallet created with public key: {self.wallet.get_public_key()}")

    def start(self):
        """Start the node's server and initialize P2P connections."""
        # Start server
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        logging.info(f"Node started at {self.host}:{self.port}")

        # Start accepting connections in a separate thread
        threading.Thread(target=self.accept_connections, daemon=True).start()

        # Connect to bootstrap nodes and sync blockchain
        self.initialize_p2p_network()

    def accept_connections(self):
        """Accept incoming connections from peers."""
        logging.info("Waiting for connections...")
        while True:
            # Accept a new connection
            client_socket, client_address = self.server.accept()
            logging.info(f"Connection established with {client_address}")

            # Start a new thread to handle the client communication
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def initialize_p2p_network(self):
        """Initialize P2P network and sync blockchain with peers."""
        # Connect to bootstrap nodes
        for bootstrap_node in self.bootstrap_nodes:
            self.connect_to_peer(bootstrap_node)

        # Request blockchain from peers
        self.sync_blockchain()

    def sync_blockchain(self):
        """Synchronize blockchain with peers."""
        if not self.peers:
            self.load_local_blockchain()
            return

        longest_chain = None
        max_length = len(self.blockchain.chain)

        for peer in self.peers:
            try:
                chain_data = self.request_blockchain(peer)
                if chain_data and len(chain_data['chain']) > max_length:
                    if self.validate_chain(chain_data['chain']):
                        longest_chain = chain_data
                        max_length = len(chain_data['chain'])
            except Exception as e:
                logging.error(f"Error syncing with peer {peer}: {e}")

        if longest_chain:
            self.blockchain.load_from_dict(longest_chain)
            self.save_blockchain()
            logging.info(f"Blockchain synchronized with {max_length} blocks")

    def validate_chain(self, chain_data):
        """Validate a blockchain received from a peer."""
        try:
            # Basic validation of chain structure
            prev_hash = "0"  # Genesis block previous hash
            for block in chain_data:
                if not all(k in block for k in ['index', 'previous_hash', 'hash']):
                    return False
                if block['previous_hash'] != prev_hash:
                    return False
                prev_hash = block['hash']
            return True
        except Exception as e:
            logging.error(f"Chain validation error: {e}")
            return False

    def load_local_blockchain(self):
        """Load blockchain from local storage if available."""
        if os.path.exists(self.blockchain_file):
            try:
                with open(self.blockchain_file, 'r') as f:
                    chain_data = json.load(f)
                self.blockchain.load_from_dict(chain_data)
                logging.info("Local blockchain loaded successfully")
            except Exception as e:
                logging.error(f"Error loading local blockchain: {e}")

    def save_blockchain(self):
        """Save current blockchain to local storage."""
        try:
            chain_data = self.blockchain.to_dict()
            with open(self.blockchain_file, 'w') as f:
                json.dump(chain_data, f, indent=4)
            logging.info("Blockchain saved to local storage")
        except Exception as e:
            logging.error(f"Error saving blockchain: {e}")

    def request_blockchain(self, peer):
        """Request blockchain data from a peer."""
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect(peer)
            request = "GET /blockchain\n"
            peer_socket.send(request.encode('utf-8'))
            response = peer_socket.recv(1024*1024).decode('utf-8')  # Increased buffer size
            peer_socket.close()
            return json.loads(response)
        except Exception as e:
            logging.error(f"Error requesting blockchain from peer {peer}: {e}")
            return None

    def handle_client(self, client_socket):
        """Handle incoming client requests."""
        try:
            request = client_socket.recv(1024).decode('utf-8')
            logging.info(f"Received request: {request}")

            if request.startswith('GET /peers'):
                self.send_peers(client_socket)
            elif request.startswith('GET /blockchain'):
                self.send_blockchain(client_socket)
            elif request.startswith('POST /transaction'):
                self.receive_transaction(client_socket, request)
            elif request.startswith('POST /block'):
                self.receive_block(client_socket, request)
            else:
                client_socket.send("Unknown request".encode('utf-8'))
        except Exception as e:
            logging.error(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def send_blockchain(self, client_socket):
        """Send blockchain data to requesting peer."""
        chain_data = self.blockchain.to_dict()
        response = json.dumps(chain_data)
        client_socket.send(response.encode('utf-8'))

    def connect_to_peer(self, peer_address):
        """Connect to a new peer and add to peer list."""
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect(peer_address)
            self.add_peer(peer_address)
            logging.info(f"Connected to peer: {peer_address}")
            peer_socket.close()
        except Exception as e:
            logging.error(f"Failed to connect to peer {peer_address}: {e}")

    def broadcast_transaction(self, transaction):
        """Broadcast a transaction to all peers."""
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(self.send_message_to_peer, peer, 
                              f"POST /transaction\n{json.dumps(transaction)}")
                for peer in self.peers
            ]
            for future in futures:
                try:
                    future.result(timeout=5)
                except Exception as e:
                    logging.error(f"Broadcast error: {e}")

    def add_peer(self, peer_address):
        """Add a peer node to the network."""
        with self.lock:
            if peer_address not in self.peers and peer_address != (self.host, self.port):
                self.peers.add(peer_address)
                logging.info(f"Added peer: {peer_address}")

def main():
    # Example bootstrap nodes
    bootstrap_nodes = [
        ('localhost', 5001),
        ('localhost', 5002)
    ]

    try:
        # Create and start node
        node = Node(
            host="localhost",
            port=5000,
            bootstrap_nodes=bootstrap_nodes
        )
        node.start()

        # Keep the main thread running
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logging.info("Shutting down node...")
        node.save_blockchain()
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
    finally:
        logging.info("Node shutdown complete.")

if __name__ == "__main__":
    main()
