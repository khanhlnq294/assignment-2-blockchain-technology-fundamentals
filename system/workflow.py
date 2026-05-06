from crypto_lib.rsa_core import simple_hash, encrypt, decrypt, build_rsa
from system.node import Node
import keys_config 
import crypto_lib.multi_sign as multi_sign
from system.consensus import run_pbft
import json


def reset_data(nodes):
    seed_data = {
        "A": [
            {"item_id": "001", "qty": 32, "price": 12, "location": "D"},
            {"item_id": "002", "qty": 20, "price": 14, "location": "C"},
            {"item_id": "003", "qty": 22, "price": 16, "location": "B"},
            {"item_id": "004", "qty": 12, "price": 18, "location": "A"}
            ],
        "B": [
            {"item_id": "001", "qty": 32, "price": 12, "location": "D"},
            {"item_id": "002", "qty": 20, "price": 14, "location": "C"},
            {"item_id": "003", "qty": 22, "price": 16, "location": "B"},
            {"item_id": "004", "qty": 12, "price": 18, "location": "A"}
            ],
        "C": [
            {"item_id": "001", "qty": 32, "price": 12, "location": "D"},
            {"item_id": "002", "qty": 20, "price": 14, "location": "C"},
            {"item_id": "003", "qty": 22, "price": 16, "location": "B"},
            {"item_id": "004", "qty": 12, "price": 18, "location": "A"}
            ],
        "D": [
            {"item_id": "001", "qty": 32, "price": 12, "location": "D"},
            {"item_id": "002", "qty": 20, "price": 14, "location": "C"},
            {"item_id": "003", "qty": 22, "price": 16, "location": "B"},
            {"item_id": "004", "qty": 12, "price": 18, "location": "A"}
            ]
    }

    for node in nodes:
        with open(node.file_path, "w") as f:
            json.dump(seed_data[node.name], f, indent=4)





# Build nodes and public keys from inventory data
def build_node(inventory):
   rsa = build_rsa(inventory)
   file_path = f"data/inventory{inventory['name']}.json"
   e = rsa["e"]
   d = rsa["d"]
   n = rsa["n"]
   
   return Node(inventory["name"], e, d, n, file_path), {"e": e, "n": n}

def initalise_system():
   nodes = []
   public_keys = {}
   
   for inventory in [keys_config.INVENTORY_A_KEYS,
                     keys_config.INVENTORY_B_KEYS,
                     keys_config.INVENTORY_C_KEYS,
                     keys_config.INVENTORY_D_KEYS]:
         node, public_key = build_node(inventory)
         nodes.append(node)
         public_keys[inventory["name"]] = public_key

   return nodes, public_keys


def create_record_workflow(nodes, public_keys, creator_name, item_id, qty, price, location):
    creator = next(n for n in nodes if n.name == creator_name)

    packet = creator.create_record(item_id, qty, price, location)

    message = json.dumps(packet["record"])

    pbft_packet = {
        "message": message,
        "signature": packet["signature"],
        "sender": creator.name
    }

    accepted = run_pbft(pbft_packet, nodes, public_keys)

    return accepted



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


def query_workflow(nodes, item_id):
    #query 
    result = process_query(item_id, nodes[0])
    message = json.dumps(result)

    #start multi-signature process
    pkg_rsa = build_rsa(keys_config.PKG_KEYS)

    g_values = multi_sign.generate_g_values(nodes, pkg_rsa)
    t_values = multi_sign.compute_t_values(nodes, pkg_rsa)

    t = multi_sign.compute_t(t_values, pkg_rsa["n"])
    h = multi_sign.compute_h(message, t)

    s_values = multi_sign.compute_s_values(nodes, g_values, h, pkg_rsa["n"])
    S = multi_sign.compute_S(s_values, pkg_rsa["n"])

    print("\n--- Sender-side verification ---")
    valid = multi_sign.verify_signature(S, t, h, nodes, pkg_rsa)
    print("\n")

    if not valid:
        return {"status": "FAILED"}

    #prepare package
    package = {
        "message": result,
        "S": S,
        "t": t,
        "h": h
    }

    package_str = json.dumps(package)

    #encrypt package hash with procurement officer's public key for receiver-side verification
    po_rsa = build_rsa(keys_config.PROCUREMENT_OFFICER_KEYS)

    package_hash = simple_hash(package_str)
    cipher = encrypt(package_hash, po_rsa["e"], po_rsa["n"])

    return {
        "status": "SUCCESS",
        "cipher": cipher,
        "package": package
    }



def verify_received_package(cipher, package, nodes):
    po_rsa = build_rsa(keys_config.PROCUREMENT_OFFICER_KEYS)

    decrypted_hash = decrypt(cipher, po_rsa["d"], po_rsa["n"])

    package_str = json.dumps(package)

    if decrypted_hash != simple_hash(package_str):
        return False

    pkg_rsa = build_rsa(keys_config.PKG_KEYS)

    print("\n--- Receiver-side verification ---")
    return multi_sign.verify_signature(package["S"], package["t"], package["h"], nodes, pkg_rsa)
