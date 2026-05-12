import system.workflow as wf
import sys
import os
import json

# SHOW DATABASE - FOR DEMONSTRATION
def show_db(nodes):
    for node in nodes:
        print(f"\n--- Inventory {node.name} ---")
        with open(node.file_path, "r") as f:
            records = json.load(f)
        if records:
            for r in records:
                print(f" {r}")
        else:
            print("Empty")


# ADD NEW RECORD (TASK 1 + 2)
def add_new_record(nodes, public_keys):
    names = [n.name for n in nodes]
    print("\n--- Create a new inventory record ---")

    #Choose originator
    while True:
        org = input(f"Originator inventory ({'/'.join(names)}): ").strip().upper()
        if org in names:
            break
        print("Invalid choice, try again.")

    item_id = input("Item ID (e.g. 005)          : ").strip()

    while True:
        try:
            qty = int(input("Quantity (integer)          : ").strip())
            break
        except ValueError:
            print("Please enter a whole number.")

    while True:
        try:
            price = int(input("Price (integer)             : ").strip())
            break
        except ValueError:
            print("Please enter a whole number.")

    location = input("Location (A/B/C/D)          : ").strip().upper() or "A"

    accepted = wf.create_record_workflow(nodes, public_keys, org, item_id, qty, price, location)
    if accepted:
        print(f"\nRecord for item {item_id} accepted and committed to all nodes.")
    else:
        print("\nRecord rejected by consensus.")


def prompt_query(nodes):
    item_id = input("\nEnter item ID to query (e.g. 001): ").strip()

    response = wf.query_workflow(nodes, item_id)
    if response["status"] != "SUCCESS":
        print("Query failed during multi-signature phase.")
        return

    ok = wf.verify_received_package(response["cipher"], response["package"], nodes)
    if ok:
        result = response["package"]["message"]
        print(f"\nFinal result: VALID")
        print(f"  Item ID   : {result['item_id']}")
        print(f"  Total Qty : {result['total_qty']}")
    else:
        print("\nFinal result: INVALID -- verification failed.")

MENU = """
Main menu
---------
    1. Insert a NEW inventory record
    2. Run a query as Procurement Officer
    3. Show local database
    0. Exit
"""

def main():
    nodes, public_keys = wf.initalise_system()
    wf.reset_data(nodes)
    print("System initialised with 4 inventory nodes (A, B, C, D).")

    while True:
        print(MENU)
        choice = input("Choose: ").strip()

        if choice == "1":
            add_new_record(nodes, public_keys)
        elif choice == "2":
            prompt_query(nodes)
        elif choice == "3":
            show_db(nodes)
        elif choice == "0":
            print("\nGoodbye.")
            break
        else:
            print("Unknown option, please choose 0-3.")


if __name__ == "__main__":
    main()
