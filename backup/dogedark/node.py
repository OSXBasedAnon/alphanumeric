import time
import logging
import socket
import threading
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dogedark.blockchain import Blockchain, BlockchainState
from dogedark.wallet import Wallet

# Set up basic logging configuration
logging.basicConfig(level=logging.INFO)

class Node:
    def __init__(self, host, port, blockchain=None, bootstrap_nodes=None):
        self.host = host
        self.port = port
        self.node_id = f"{host}:{port}"
        self.peers = set()
        self.server = None
        self.lock = threading.Lock()
        self.blockchain = blockchain if blockchain else Blockchain()
        self.blockchain.load_state()
        self.wallet = None
        self.bootstrap_nodes = bootstrap_nodes or []
        self.blockchain_file = "blockchain_data.json"
        self.init_wallet()
        self.last_sync_time = 0
        self.peer_discovery_interval = 30
        self.sync_interval = 10
        logging.info(f"Node initialized with ID: {self.node_id}")

    def get_blockchain(self):
        state = self.blockchain.get_state()  # Get the blockchain state (assuming `get_state` exists)
        return self.blockchain._serialize_state(state)

    def send_blockchain(self, client_socket):
        blockchain_data = self.get_blockchain()  # Get the serialized blockchain state
        client_socket.send(blockchain_data)

    def init_wallet(self):
        self.wallet = self.blockchain.create_wallet()
        logging.info(f"Wallet created. Public Key Type in Node: {type(self.wallet.public_key)}")
        logging.info(f"Node wallet created with public key: {self.wallet.get_public_key()}")

    def create_wallet(self) -> Wallet:
        wallet = Wallet()
        self.wallet = wallet
        logging.info(f"New wallet created: {wallet.get_public_key()}")
        return wallet

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        logging.info(f"Node started at {self.host}:{self.port}")

        threading.Thread(target=self.accept_connections, daemon=True).start()
        threading.Thread(target=self.periodic_peer_discovery, daemon=True).start()
        threading.Thread(target=self.periodic_blockchain_sync, daemon=True).start()
        self.initialize_p2p_network()

    def accept_connections(self):
        """Accept incoming connections from peers."""
        logging.info("Waiting for connections...")
        while True:
            client_socket, client_address = self.server.accept()
            logging.info(f"Connection established with {client_address}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def initialize_p2p_network(self):
        """Initialize P2P network and sync blockchain with peers."""
        for bootstrap_node in self.bootstrap_nodes:
            self.connect_to_peer(bootstrap_node)
        self.sync_blockchain()

    def sync_blockchain(self):
        """Synchronize blockchain with peers."""
        if time.time() - self.last_sync_time < self.sync_interval:  # Avoid frequent sync requests
            return
        self.last_sync_time = time.time()

        longest_chain = None
        max_length = len(self.blockchain.chain)

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_peer = {
                executor.submit(self.request_blockchain, peer): peer for peer in self.peers
            }
            for future in as_completed(future_to_peer):
                peer = future_to_peer[future]
                try:
                    chain_data = future.result()
                    if chain_data and len(chain_data) > max_length:
                        if self.validate_chain(chain_data):
                            longest_chain = chain_data
                            max_length = len(chain_data)
                except Exception as e:
                    logging.error(f"Error syncing with peer {peer}: {e}")

        if longest_chain:
            self.blockchain._deserialize_state(longest_chain)  # Deserialize the blockchain state
            self.save_blockchain()
            logging.info(f"Blockchain synchronized with {max_length} blocks")

    def validate_chain(self, chain_data):
        try:
            prev_hash = "0"
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
        if os.path.exists(self.blockchain_file):
            try:
                with open(self.blockchain_file, 'rb') as f:
                    chain_data = f.read()
                self.blockchain._deserialize_state(chain_data)  # Deserialize the blockchain state
                logging.info("Local blockchain loaded successfully")
            except Exception as e:
                logging.error(f"Error loading local blockchain: {e}")

    def save_blockchain(self):
        try:
            chain_data = self.get_blockchain()  # Get the serialized blockchain state
            with open(self.blockchain_file, 'wb') as f:
                f.write(chain_data)
            logging.info("Blockchain saved to local storage")
        except Exception as e:
            logging.error(f"Error saving blockchain: {e}")

    def request_blockchain(self, peer):
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect(peer)
            request = "GET /blockchain\n"
            peer_socket.send(request.encode('utf-8'))
            response = peer_socket.recv(1024 * 1024)  # Read up to 1MB of data
            peer_socket.close()
            return response
        except Exception as e:
            logging.error(f"Error requesting blockchain from peer {peer}: {e}")
            return None

    def handle_client(self, client_socket):
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

    def send_peers(self, client_socket):
        """Send peer list to requesting node."""
        peer_list = list(self.peers)
        response = json.dumps({"peers": peer_list})
        client_socket.send(response.encode('utf-8'))

    def periodic_peer_discovery(self):
        while True:
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_peer = {
                    executor.submit(self.request_peer_list, peer): peer for peer in self.peers
                }
                for future in as_completed(future_to_peer):
                    peer = future_to_peer[future]
                    try:
                        new_peers = future.result()
                        if new_peers:
                            for new_peer in new_peers:
                                self.add_peer(new_peer)
                    except Exception as e:
                        logging.error(f"Peer discovery error with {peer}: {e}")
            time.sleep(self.peer_discovery_interval)

    def request_peer_list(self, peer):
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect(peer)
            peer_socket.send("GET /peers\n".encode('utf-8'))
            response = peer_socket.recv(1024).decode('utf-8')
            peer_socket.close()
            return json.loads(response).get("peers", [])
        except Exception as e:
            logging.error(f"Error requesting peers from {peer}: {e}")
            return []

    def connect_to_peer(self, peer_address):
        try:
            self.add_peer(peer_address)
            logging.info(f"Connected to peer: {peer_address}")
        except Exception as e:
            logging.error(f"Failed to connect to peer {peer_address}: {e}")

    def add_peer(self, peer_address):
        with self.lock:
            if peer_address not in self.peers:
                self.peers.add(peer_address)
                logging.info(f"Peer {peer_address} added to peer list")
