from scripts.generate_keys import generate_node_keys

def generate(args):
    node_id = args.node
    generate_node_keys(node_id)

