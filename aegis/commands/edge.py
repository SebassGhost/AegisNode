from dotenv import load_dotenv
from edge_node.runner import run_edge_node

def start(args):
    load_dotenv()
    run_edge_node()
