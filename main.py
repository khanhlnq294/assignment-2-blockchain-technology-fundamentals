import system.workflow as wf
import sys
import os

# ----------------------- Main execution --------------------------
# Main execution
nodes, public_keys = wf.initalise_system()
# Reset data files for clean demonstration
wf.reset_data(nodes)
# -----------------------------------------------------------------

# Creates new record (node, public_keys, creator_name, item_id, qty, price, location)
wf.create_record_workflow(nodes, public_keys, "A", "001", 5, 10, "A")

# Query and verify package
response = wf.query_workflow(nodes, "001")
if response["status"] == "SUCCESS":
    ok = wf.verify_received_package(response["cipher"], response["package"], nodes)
    print("Final result:", "VALID\n" + str(wf.process_query("001", nodes[0])) if ok else "INVALID")

# MENU = """
# Main menu
# ---------
#     1. Insert a NEW inventory record 
#     2. Run a query as a Procurement Officier
#     3. Show local database
#     0. Exit
# """

# def promt_new_record(all_nodes):
#     print("\n--- Create a new inventory record ---")
#     names = [n.name for n in all_nodes]
#     while True:
#         org = input(f"Originator inventory ({'/'.join(names)}): ").strip().upper()
#         if org in names:
#             break
#         print("Invalid choice.")
#     item_id = input("Item ID (e.g. 005)         : ").strip()
#     while True:
#         qty_s = input ("Input quantity (integer)    :").strip()
#         try:
#             qty = int(qty_s); 
#             break
#         except ValueError:
#             print("Please enter an integer")
#     while True:
#         price_s = input("Item Price     :").strip()
#         try:
#             price = int(price_s);
#             break
#         except ValueError:
#             print("Please enter an integer.")
#     location = input("Location (A/B/C/D or other)   :").strip().upper() or "A"

#     record = {
#         "item_id": item_id,
#         "qty": qty,
#         "price": price,
#         "location": location,
#         "orginator": org
#     }

#     originator_node = next(n for n in all_nodes if n.name = org)
#     insert_record_workflow(orginator_node, all_nodes, record)


#     """def main():
#         all_nodes, pkg, officier = bootstrap_system()"""

#         while True:
#             choice = input("Choose:").strip()
#             print(MENU)
#             if choice == "1": promt_new_record(all_nodes)
#             #elif choice == "2": promt_query
#             elif choice == "0": 
#                 print("\nGoodbye.")
#                 return
#             else: print("Unknown")


