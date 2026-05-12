import os
import json

from keys_config import (
    INVENTORY_A_KEYS, INVENTORY_B_KEYS,
    INVENTORY_C_KEYS, INVENTORY_D_KEYS,
    PKG_KEYS, PROCUREMENT_OFFICER_KEYS,
    INVENTORY_IDENTITIES, INVENTORY_RANDOM_R,
)
from nodes.inventory_node import InventoryNode
from nodes.pkg import PKG
from nodes.procurement import ProcurementOfficer


DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

INITIAL_RECORDS = [
    {"item_id": "001", "qty": 32, "price": 12, "location": "D", "originator": "SEED"},
    {"item_id": "002", "qty": 20, "price": 14, "location": "C", "originator": "SEED"},
    {"item_id": "003", "qty": 22, "price": 16, "location": "B", "originator": "SEED"},
    {"item_id": "004", "qty": 12, "price": 18, "location": "A", "originator": "SEED"},
]


def bootstrap_system():
    """Returns (all_nodes, pkg, officer) fully initialised."""

    # 1. Build the four inventory nodes
    entries = [
        (INVENTORY_A_KEYS, "A"),
        (INVENTORY_B_KEYS, "B"),
        (INVENTORY_C_KEYS, "C"),
        (INVENTORY_D_KEYS, "D"),
    ]
    all_nodes = []
    for params, name in entries:
        db_path = os.path.join(DATA_DIR, f"inventory{name}.json")
        node = InventoryNode(name, params, db_path)
        node.identity = INVENTORY_IDENTITIES[name]
        node.random_r = INVENTORY_RANDOM_R[name]
        all_nodes.append(node)

    # 2. Build PKG and Officer
    pkg     = PKG(PKG_KEYS)
    officer = ProcurementOfficer(PROCUREMENT_OFFICER_KEYS)

    # 3. PKG issues each node its Harn secret key g_i = ID_i^d mod n
    for node in all_nodes:
        node.harn_secret_g = pkg.issue_secret_key(node.identity)

    # 4. Seed databases if empty
    for node in all_nodes:
        if not node.records:
            for r in INITIAL_RECORDS:
                node.store(r)

    return all_nodes, pkg, officer


def reset_databases():
    """Reset all node databases to the initial seed records."""
    for name in ("A", "B", "C", "D"):
        path = os.path.join(DATA_DIR, f"inventory{name}.json")
        with open(path, "w") as f:
            json.dump(INITIAL_RECORDS, f, indent=4)
