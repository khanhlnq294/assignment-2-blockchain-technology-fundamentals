from crypto_lib.hashing import simple_hash
from crypto_lib.rsa_core import rsa_verify
import json


def get_threshold(n):
    """PBFT acceptance threshold: 2f + 1 where f = (n-1)//3."""
    f = (n - 1) // 3
    return 2 * f + 1


def run_pbft(packet, nodes, public_keys):
    """One PBFT-style voting round.
    Each receiver verifies the originator's signature; if at least
    threshold YES votes, every node commits the record to local storage.
    """
    message   = packet["message"]
    signature = packet["signature"]
    sender    = packet["sender"]

    print("\n" + "=" * 60)
    print("  TASK 2: PBFT CONSENSUS ROUND")
    print("=" * 60)
    print(f"  Sender (originator): Inventory {sender}")
    print(f"  Record : {message}")

    threshold = get_threshold(len(nodes))
    print(f"  n = {len(nodes)}, f = {(len(nodes) - 1) // 3}, threshold = {threshold}")

    print("\n  PREPARE phase: each receiver verifies the signature.")
    votes = []
    sender_pub = public_keys[sender]

    for node in nodes:
        if node.name == sender:
            print(f"    Node {node.name}: YES (originator -- implicit)")
            votes.append(True)
            continue

        h = simple_hash(message)
        valid = rsa_verify(h, signature, sender_pub["e"], sender_pub["n"])
        outcome = "YES" if valid else "NO"
        print(f"    Node {node.name}: verifying s^e mod n vs H(M)... {outcome}")
        votes.append(valid)

    yes_count = sum(votes)
    print(f"\n  YES votes: {yes_count} / threshold {threshold}")
    print("Signed message:", message)
    print("Hash during verify:", simple_hash(message))

    if yes_count >= threshold:
        print("  DECISION: COMMIT (record will be appended on every node)")
        record = json.loads(message)
        for node in nodes:
            node.store(record)
        return True
    else:
        print("  DECISION: REJECT (insufficient votes)")
        return False
