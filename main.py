import system.workflow as wf
from crypto_lib.rsa_core import build_rsa
import keys_config
import json


def show_database(nodes):
    """Print each node's current inventory records."""
    print("\n" + "=" * 60)
    print("  LOCAL DATABASES")
    print("=" * 60)
    for node in nodes:
        print(f"\n  Inventory {node.name}:")
        with open(node.file_path, "r") as f:
            records = json.load(f)
        if records:
            for r in records:
                print(f"    {r}")
        else:
            print("    (empty)")


def print_key_parameters():
    """Display all hardcoded key material so a marker can verify the
    from-scratch RSA key derivation (n = p*q, d = e^-1 mod phi(n))."""
    print("\n" + "=" * 60)
    print("  KEY PARAMETERS")
    print("=" * 60)

    print("\n  Inventory node RSA key pairs:")
    for params in [keys_config.INVENTORY_A_KEYS, keys_config.INVENTORY_B_KEYS,
                   keys_config.INVENTORY_C_KEYS, keys_config.INVENTORY_D_KEYS]:
        rsa = build_rsa(params)
        print(f"\n    Node {params['name']}")
        print(f"      p = {params['p']}")
        print(f"      q = {params['q']}")
        print(f"      n = p * q = {rsa['n']}")
        print(f"      e = {rsa['e']}")
        print(f"      d = e^-1 mod phi(n) = {rsa['d']}")

    print("\n  PKG (Harn multi-sig authority):")
    pkg = build_rsa(keys_config.PKG_KEYS)
    print(f"    p = {keys_config.PKG_KEYS['p']}")
    print(f"    q = {keys_config.PKG_KEYS['q']}")
    print(f"    n = {pkg['n']}")
    print(f"    e = {pkg['e']}")
    print(f"    d = {pkg['d']}")

    print("\n  Procurement Officer RSA key pair:")
    po = build_rsa(keys_config.PROCUREMENT_OFFICER_KEYS)
    print(f"    p = {keys_config.PROCUREMENT_OFFICER_KEYS['p']}")
    print(f"    q = {keys_config.PROCUREMENT_OFFICER_KEYS['q']}")
    print(f"    n = {po['n']}")
    print(f"    e = {po['e']}")
    print(f"    d = {po['d']}")

    print("\n  Harn identities and per-signer randomness:")
    for name in ("A", "B", "C", "D"):
        print(f"    Node {name}: ID = {keys_config.INVENTORY_IDENTITIES[name]}, "
              f"r = {keys_config.INVENTORY_RANDOM_R[name]}")


def prompt_new_record(nodes, public_keys):
    names = [n.name for n in nodes]
    print("\n--- Create a new inventory record ---")

    while True:
        org = input(f"Originator inventory ({'/'.join(names)}): ").strip().upper()
        if org in names:
            break
        print("  Invalid choice, try again.")

    while True:
        item_id = input("Item ID (e.g. 001)          : ").strip()
        if item_id and item_id.isdigit():
            break
        print("  Item ID must be a number (e.g. 001), try again.")

    while True:
        try:
            qty = int(input("Quantity (integer)          : ").strip())
            if qty > 0:
                break
            print("  Quantity must be greater than 0.")
        except ValueError:
            print("  Please enter a whole number.")

    while True:
        try:
            price = int(input("Price (integer)             : ").strip())
            if price >= 0:
                break
            print("  Price cannot be negative.")
        except ValueError:
            print("  Please enter a whole number.")

    while True:
        location = input("Location (A/B/C/D)          : ").strip().upper()
        if location in names:
            break
        print(f"  Location must be one of {'/'.join(names)}, try again.")

    accepted = wf.create_record_workflow(
        nodes, public_keys, org, item_id, qty, price, location)

    if accepted:
        print(f"\n  >>> Record for item {item_id} committed to all nodes.")
    else:
        print("\n  >>> Record rejected by consensus.")

def prompt_query(nodes):
    """Interactive prompt for running a Procurement Officer query."""
    item_id = input("\nEnter item ID to query (e.g. 001): ").strip()

    response = wf.query_workflow(nodes, item_id)
    if response["status"] != "SUCCESS":
        print("\n  >>> Query failed during multi-signature phase.")
        return

    ok = wf.verify_received_package(response["cipher"], response["package"], nodes)
    if ok:
        result = response["package"]["message"]
        print("\n" + "=" * 60)
        print(f"  FINAL RESULT: VALID")
        print(f"    Item ID    : {result['item_id']}")
        print(f"    Total qty  : {result['total_qty']}")
        print("=" * 60)
    else:
        print("\n  >>> Final result: INVALID -- verification failed.")


MENU = """
=============================
        MAIN MENU
=============================
    1. Insert a NEW inventory record   (Task 1 + 2)
    2. Run a query as Procurement Officer  (Task 3)
    3. Show local databases
    4. Print all key parameters
    5. Reset databases to seed state
    0. Exit
=============================
"""


def main():
    print("Initialising 4-node blockchain inventory system...")
    nodes, public_keys = wf.initalise_system()
    wf.reset_data(nodes)
    print("System ready.\n")

    while True:
        print(MENU)
        choice = input("Choose: ").strip()

        if choice == "1":
            prompt_new_record(nodes, public_keys)
        elif choice == "2":
            prompt_query(nodes)
        elif choice == "3":
            show_database(nodes)
        elif choice == "4":
            print_key_parameters()
        elif choice == "5":
            wf.reset_data(nodes)
            print("  Databases reset to seed state.")
        elif choice == "0":
            print("\nGoodbye.")
            break
        else:
            print("  Unknown option, please choose 0-5.")


if __name__ == "__main__":
    main()
