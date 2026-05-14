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
    """Reset each node's JSON database to the four starter records."""
    for node in nodes:
        with open(node.file_path, "w") as f:
            json.dump(SEED_RECORDS, f, indent=4)


def initalise_system():
    """Build the four inventory nodes and collect their public keys."""
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


# ============================================================================
# Task 1 + Task 2: Insert a new inventory record
# ============================================================================

def create_record_workflow(nodes, public_keys, creator_name,
                           item_id, qty, price, location):
    """The originator signs a new record; all nodes vote via PBFT."""
    creator = next(n for n in nodes if n.name == creator_name)

    print("\n" + "=" * 60)
    print("  TASK 1: RECORD CREATION & DIGITAL SIGNATURE")
    print("=" * 60)
    print(f"  Originator: Inventory {creator.name}")
    print(f"  RSA public key:  e = {creator.e}")
    print(f"                   n = {creator.n}")

    # Task 1: originator signs the record
    packet  = creator.create_record(item_id, qty, price, location)
    message = json.dumps(packet["record"])

    print(f"\n  Record built: {packet['record']}")
    print(f"  H(M) [SHA-256 as int]: {simple_hash(message)}")
    print(f"  RSA signature s = H(M)^d mod n: {packet['signature']}")

    pbft_packet = {
        "message":   message,
        "signature": packet["signature"],
        "sender":    creator.name,
    }

    # Task 2: PBFT consensus round
    return run_pbft(pbft_packet, nodes, public_keys)


# ============================================================================
# Query helper
# ============================================================================

def process_query(item_id, node):
    """Sum qty across all records for the given item_id."""
    total_qty = 0
    with open(node.file_path, "r") as f:
        data = json.load(f)
    for record in data:
        if record["item_id"] == item_id:
            total_qty += record["qty"]
    return {"item_id": item_id, "total_qty": total_qty}


# ============================================================================
# Task 3 part A: Query + Harn multi-signature + RSA encryption
# ============================================================================

def query_workflow(nodes, item_id):
    """Process a Procurement Officer query end-to-end.

    Steps map directly to the Harn identity-based multi-signature scheme:
       Phase 1: key extraction        g_i = ID_i^d mod n
       Phase 2: round-1 commitment    t_i = r_i^e mod n; t = prod(t_i)
       Phase 3: round-2 signature     h = H(t || m); s_i = g_i * r_i^h
                                       S = prod(s_i)
       Phase 4: verification          S^e == (prod ID_i) * t^h
    """

    print("\n" + "=" * 60)
    print("  TASK 3: QUERY WORKFLOW (Procurement Officer side)")
    print("=" * 60)

    # ---- Step 1: query node A's database ----------------------------------
    print("\n[Step 1] Query node A's local database")
    result  = process_query(item_id, nodes[0])
    message = json.dumps(result, sort_keys=True)
    print(f"  Item ID queried   : {item_id}")
    print(f"  Aggregated result : {result}")
    print(f"  Canonical message m: {message}")

    # ---- Step 2: PKG public key parameters --------------------------------
    pkg_rsa = build_rsa(keys_config.PKG_KEYS)
    print("\n[Step 2] PKG (Private Key Generator) RSA parameters")
    print(f"  e (public exponent)  = {pkg_rsa['e']}")
    print(f"  n (modulus)          = {pkg_rsa['n']}")

    # ---- Step 3: Phase 1 - key extraction ---------------------------------
    print("\n[Step 3] Phase 1 - Key extraction (g_i = ID_i^d mod n)")
    g_values = multi_sign.generate_g_values(nodes, pkg_rsa)
    for node in nodes:
        ID = keys_config.INVENTORY_IDENTITIES[node.name]
        print(f"  Node {node.name}: ID = {ID}, g_{node.name} = {g_values[node.name]}")

    # ---- Step 4: Phase 2 - round-1 commitments ----------------------------
    print("\n[Step 4] Phase 2a - Round-1 commitments (t_i = r_i^e mod n)")
    t_values = multi_sign.compute_t_values(nodes, pkg_rsa)
    for node in nodes:
        r = keys_config.INVENTORY_RANDOM_R[node.name]
        print(f"  Node {node.name}: r = {r}, t_{node.name} = {t_values[node.name]}")

    t = multi_sign.compute_t(t_values, pkg_rsa["n"])
    print(f"\n[Step 4b] Phase 2b - Aggregate t = prod(t_i) mod n")
    print(f"  t = {t}")

    # ---- Step 5: Phase 3a - challenge -------------------------------------
    h = multi_sign.compute_h(message, t)
    print(f"\n[Step 5] Phase 3a - Challenge h = H(t || m)")
    print(f"  h = {h}")

    # ---- Step 6: Phase 3b - partial signatures ----------------------------
    print("\n[Step 6] Phase 3b - Partial signatures (s_i = g_i * r_i^h mod n)")
    s_values = multi_sign.compute_s_values(nodes, g_values, h, pkg_rsa["n"])
    for node in nodes:
        print(f"  s_{node.name} = {s_values[node.name]}")

    S = multi_sign.compute_S(s_values, pkg_rsa["n"])
    print(f"\n[Step 6b] Phase 3c - Aggregate S = prod(s_i) mod n")
    print(f"  S = {S}")

    # ---- Step 7: Sender-side verification ---------------------------------
    print("\n[Step 7] Phase 4 - Sender-side verification")
    print("  Equation: S^e mod n  ==  (prod ID_i) * t^h mod n")
    valid = multi_sign.verify_signature(S, t, h, nodes, pkg_rsa)
    print(f"  Sender-side verification result: {'PASS' if valid else 'FAIL'}")

    if not valid:
        return {"status": "FAILED"}

    # ---- Step 8: Build the package ---------------------------------------
    package = {"message": result, "S": S, "t": t, "h": h}
    package_str = json.dumps(package, sort_keys=True)

    # ---- Step 9: Encrypt the package hash with Officer's RSA public key --
    po_rsa = build_rsa(keys_config.PROCUREMENT_OFFICER_KEYS)
    package_hash = simple_hash(package_str) % po_rsa["n"]
    cipher = encrypt(package_hash, po_rsa["e"], po_rsa["n"])

    print("\n[Step 8] Encrypt package hash with Procurement Officer's RSA public key")
    print(f"  Officer e = {po_rsa['e']}")
    print(f"  Officer n = {po_rsa['n']}")
    print(f"  Package hash (mod n)      = {package_hash}")
    print(f"  Encrypted cipher = h^e mod n: {cipher}")

    return {"status": "SUCCESS", "cipher": cipher, "package": package}


# ============================================================================
# Task 3 part B: Officer-side receive, decrypt, re-verify
# ============================================================================

def verify_received_package(cipher, package, nodes):
    """Officer decrypts the cipher and re-verifies the multi-signature."""
    print("\n" + "=" * 60)
    print("  TASK 3 (continued): RECEIVER-SIDE VERIFICATION")
    print("=" * 60)

    po_rsa = build_rsa(keys_config.PROCUREMENT_OFFICER_KEYS)

    # ---- Step 1: Decrypt the seal ----------------------------------------
    print("\n[Step 1] Decrypt cipher with Officer's RSA private key")
    decrypted_hash = decrypt(cipher, po_rsa["d"], po_rsa["n"])
    print(f"  decrypted_hash = cipher^d mod n: {decrypted_hash}")

    # ---- Step 2: Recompute and compare -----------------------------------
    package_str   = json.dumps(package, sort_keys=True)
    expected_hash = simple_hash(package_str) % po_rsa["n"]
    print(f"\n[Step 2] Recompute hash of received package")
    print(f"  expected_hash (mod n) = {expected_hash}")
    print(f"  Match: {'YES' if decrypted_hash == expected_hash else 'NO'}")

    if decrypted_hash != expected_hash:
        print("  HASH MISMATCH - package was tampered with.")
        return False

    # ---- Step 3: Re-verify the Harn multi-signature ----------------------
    print("\n[Step 3] Re-run Phase 4 verification of the Harn multi-signature")
    print("  Equation: S^e mod n  ==  (prod ID_i) * t^h mod n")
    pkg_rsa = build_rsa(keys_config.PKG_KEYS)
    result = multi_sign.verify_signature(
        package["S"], package["t"], package["h"], nodes, pkg_rsa
    )
    print(f"  Receiver-side verification result: {'PASS' if result else 'FAIL'}")
    return result
