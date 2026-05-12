import os

from keys_config import (
    INVENTORY_A_KEYS, INVENTORY_B_KEYS, INVENTORY_C_KEYS, INVENTORY_D_KEYS,
    PKG_KEYS, PROCUREMENT_OFFICER_KEYS,
    INVENTORY_IDENTITIES, INVENTORY_RANDOM_R,
)
from nodes.inventory_node import InventoryNode
from nodes.pkg            import PKG
from nodes.procurement    import ProcurementOfficer


# Pre-existing records taken from Figure 1 of the spec.
# All four inventories start synchronized with these four records.
INITIAL_RECORDS = [
    {"item_id": "001", "qty": 32, "price": 12, "location": "D",
     "originator": "SEED"},
    {"item_id": "002", "qty": 20, "price": 14, "location": "C",
     "originator": "SEED"},
    {"item_id": "003", "qty": 22, "price": 16, "location": "B",
     "originator": "SEED"},
    {"item_id": "004", "qty": 12, "price": 18, "location": "A",
     "originator": "SEED"},
]


DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


def _seed_inventory(node):
    if not node.records:
        for r in INITIAL_RECORDS:
            node.append_record(r)


def bootstrap_system():
    """Returns (all_nodes, pkg, officer)."""

    # ---- 1) Build the four Inventory nodes ------------------------------
    inv_a = InventoryNode("A", INVENTORY_A_KEYS,
                          INVENTORY_IDENTITIES["A"], INVENTORY_RANDOM_R["A"],
                          db_path=os.path.join(DATA_DIR, "inventory_A.json"))
    inv_b = InventoryNode("B", INVENTORY_B_KEYS,
                          INVENTORY_IDENTITIES["B"], INVENTORY_RANDOM_R["B"],
                          db_path=os.path.join(DATA_DIR, "inventory_B.json"))
    inv_c = InventoryNode("C", INVENTORY_C_KEYS,
                          INVENTORY_IDENTITIES["C"], INVENTORY_RANDOM_R["C"],
                          db_path=os.path.join(DATA_DIR, "inventory_C.json"))
    inv_d = InventoryNode("D", INVENTORY_D_KEYS,
                          INVENTORY_IDENTITIES["D"], INVENTORY_RANDOM_R["D"],
                          db_path=os.path.join(DATA_DIR, "inventory_D.json"))

    all_nodes = [inv_a, inv_b, inv_c, inv_d]

    # ---- 2) Build PKG and Procurement Officer ---------------------------
    pkg     = PKG(PKG_KEYS)
    officer = ProcurementOfficer(PROCUREMENT_OFFICER_KEYS)

    # ---- 3) PKG issues each Inventory its Harn secret key g_j -----------
    for n in all_nodes:
        n.harn_secret_g = pkg.issue_secret_key(n.identity)

    # ---- 4) Seed each Inventory's DB ------------------------------------
    for n in all_nodes:
        _seed_inventory(n)

    return all_nodes, pkg, officer


def reset_databases():
    """Delete inventory_*.json so the next bootstrap re-seeds clean state."""
    for fn in ("inventory_A.json", "inventory_B.json",
               "inventory_C.json", "inventory_D.json"):
        path = os.path.join(DATA_DIR, fn)
        if os.path.exists(path):
            os.remove(path)
