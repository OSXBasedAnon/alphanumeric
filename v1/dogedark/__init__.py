from dogedark.blockchain import Blockchain
from dogedark.wallet import Wallet
from dogedark.node import Node

version = '1.0.0'

# Initialize the blockchain object
blockchain = Blockchain()

# Initialize the node, passing the blockchain object
node = Node(
    host="localhost",
    port=5000,
    blockchain=blockchain,  # Pass the blockchain instance here
    bootstrap_nodes=[('localhost', 5001), ('localhost', 5002)]  # Example of bootstrap nodes
)

def start_server():
    """
    Function to start the server.
    This will initialize the Node, start listening, and attempt to connect to bootstrap nodes.
    """
    try:
        node.start()
        print(f"Node started at {node.host}:{node.port}")
    except Exception as e:
        print(f"Failed to start the server: {e}")

# Call the function to start the server
if __name__ == '__main__':
    start_server()
