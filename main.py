import workflow as wf
# Main execution
nodes, public_keys = wf.initalise_system()

# Reset data files for clean demonstration
wf.reset_data(nodes)

# Creates new record (node, public_keys, creator_name, item_id, qty, price, location)
wf.create_record_workflow(nodes, public_keys, "A", "001", 5, 10, "A")

# Query and verify package
response = wf.query_workflow(nodes, "001")
if response["status"] == "SUCCESS":
    ok = wf.verify_received_package(response["cipher"], response["package"], nodes)
    print("Final result:", "VALID\n" + str(wf.process_query("001", nodes[0])) if ok else "INVALID")