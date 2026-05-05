from crypto_lib.rsa_core import build_rsa
from node import Node
import keys_config 
import json

# Build nodes and public keys from inventory data
def build_node(inventory):
   rsa = build_rsa(inventory)
   file_path = f"data/inventory_{inventory['name']}.json"
   e = rsa["e"]
   d = rsa["d"]
   n = rsa["n"]
   
   return Node(inventory["name"], e, d, n, file_path), {"e": e, "n": n}


nodes = []
public_keys = {}

for inventory in [keys_config.INVENTORY_A_KEYS,
                  keys_config.INVENTORY_B_KEYS,
                  keys_config.INVENTORY_C_KEYS,
                  keys_config.INVENTORY_D_KEYS]:
    
    node, public_key = build_node(inventory)
    nodes.append(node)
    public_keys[inventory["name"]] = public_key




def process_query(item_id, node):
    total_qty = 0

    with open(node.file_path, "r") as f:
        data = json.load(f)

    for record in data:
        if record["item_id"] == item_id:
            total_qty += record["qty"]

    return {
        "item_id": item_id,
        "total_qty": total_qty
    }