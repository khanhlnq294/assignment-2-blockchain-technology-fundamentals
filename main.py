from crypto import mod_inverse 
from node import Node
import inventoryA, inventoryB, inventoryC, inventoryD

# Build nodes and public keys from inventory data
def build_node(inventory):
   p = inventory.p
   q = inventory.q
   e = inventory.e
   
   n = p * q
   phi = (p - 1) * (q - 1)
   d = mod_inverse(e, phi)
   
   return Node(inventory.name, e, d, n), {"e": e, "n": n}


nodes = []
public_keys = {}

for inventory in [inventoryA, inventoryB, inventoryC, inventoryD]:
    node, public_key = build_node(inventory)
    nodes.append(node)
    public_keys[inventory.name] = public_key








