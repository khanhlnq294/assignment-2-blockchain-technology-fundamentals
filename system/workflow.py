from crypto_lib.rsa_core import encrypt, decrypt, build_rsa
from crypto_lib.hashing import simple_hash
from nodes.inventory_node import InventoryNode
import keys_config
import crypto_lib.multi_sign as multi_sign
from system.consensus import run_pbft
import json


SEED_RECORDS = [
    {"item_id": "001", "qty": 32, "price": 12, "location": "D", "originator": "SEED"},
    {"item_id": "002", "qty": 20, "price": 14, "location": "C", "originator": "SEED"},
    {"item_id": "003", "qty": 22, "price": 16, "location": "B", "originator": "SEED"},
    {"item_id": "004", "qty": 12, "price": 18, "location": "A", "originator": "SEED"},
]


def reset_data(nodes):
    for node in nodes:
        with open(node.file_path, "w") as f:
            json.dump(SEED_RECORDS, f, indent=4)


def initalise_system():
    all_key_params = [
        keys_config.INVENTORY_A_KEYS,
        keys_config.INVENTORY_B_KEYS,
        keys_config.INVENTORY_C_KEYS,
        keys_config.INVENTORY_D_KEYS,
    ]
    nodes = []
    public_keys = {}
    for params in all_key_params:
        file_path = f"data/inventory{params['name']}.json"
        node = InventoryNode(params["name"], params, file_path)
        node.identity = keys_config.INVENTORY_IDENTITIES[params["name"]]
        node.random_r = keys_config.INVENTORY_RANDOM_R[params["name"]]
        nodes.append(node)
        public_keys[params["name"]] = {"e": node.e, "n": node.n}
    return nodes, public_keys


def create_record_workflow(nodes, public_keys, creator_name, item_id, qty, price, location):
    creator = next(n for n in nodes if n.name == creator_name)
    packet = creator.create_record(item_id, qty, price, location)
    message = json.dumps(packet["record"], sort_keys=True)
    pbft_packet = {
        "message": message,
        "signature": packet["signature"],
        "sender": creator.name
    }
    return run_pbft(pbft_packet, nodes, public_keys)


def process_query(item_id, node):
    total_qty = 0
    with open(node.file_path, "r") as f:
        data = json.load(f)
    for record in data:
        if record["item_id"] == item_id:
            total_qty += record["qty"]
    return {"item_id": item_id, "total_qty": total_qty}


def query_workflow(nodes, item_id):
    result = process_query(item_id, nodes[0])
    message = json.dumps(result, sort_keys=True)

    pkg_rsa = build_rsa(keys_config.PKG_KEYS)
    g_values = multi_sign.generate_g_values(nodes, pkg_rsa)
    t_values = multi_sign.compute_t_values(nodes, pkg_rsa)
    t = multi_sign.compute_t(t_values, pkg_rsa["n"])
    h = multi_sign.compute_h(message, t)
    s_values = multi_sign.compute_s_values(nodes, g_values, h, pkg_rsa["n"])
    S = multi_sign.compute_S(s_values, pkg_rsa["n"])

    print("\n--- Sender-side verification ---")
    valid = multi_sign.verify_signature(S, t, h, nodes, pkg_rsa)
    print()
    if not valid:
        return {"status": "FAILED"}

    package = {"message": result, "S": S, "t": t, "h": h}
    package_str = json.dumps(package, sort_keys=True)

    po_rsa = build_rsa(keys_config.PROCUREMENT_OFFICER_KEYS)
    package_hash = simple_hash(package_str) % po_rsa["n"]
    cipher = encrypt(package_hash, po_rsa["e"], po_rsa["n"])

    return {"status": "SUCCESS", "cipher": cipher, "package": package}


def verify_received_package(cipher, package, nodes):
    po_rsa = build_rsa(keys_config.PROCUREMENT_OFFICER_KEYS)
    decrypted_hash = decrypt(cipher, po_rsa["d"], po_rsa["n"])

    package_str = json.dumps(package, sort_keys=True)
    expected_hash = simple_hash(package_str) % po_rsa["n"]

    if decrypted_hash != expected_hash:
        return False

    pkg_rsa = build_rsa(keys_config.PKG_KEYS)
    print("\n--- Receiver-side verification ---")
    return multi_sign.verify_signature(
        package["S"], package["t"], package["h"], nodes, pkg_rsa
    )
