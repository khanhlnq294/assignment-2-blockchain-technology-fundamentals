from crypto_lib.hashing import simple_hash
from crypto_lib.rsa_core import rsa_verify
import json


def get_threshold(n):
    """BFT threshold: 2f+1 where f = (n-1)//3."""
    f = (n - 1) // 3
    return 2 * f + 1


def run_pbft(packet, nodes, public_keys):
    message   = packet["message"]
    signature = packet["signature"]
    sender    = packet["sender"]

    print("\n--- BFT CONSENSUS ROUND ---")
    print("Sender:", sender)
    print("New record:", message)

    threshold = get_threshold(len(nodes))
    print("Threshold:", threshold)

    votes = []

    for node in nodes:
        if node.name == sender:
            # Originator implicitly votes YES -- they signed the record
            print(f"{node.name} PREPARE vote: YES (originator)")
            votes.append(True)
            continue

        pub = public_keys[sender]
        h = simple_hash(message) % pub["n"]
        valid = rsa_verify(h, signature, pub["e"], pub["n"])
        print(f"{node.name} PREPARE vote:", "YES" if valid else "NO")
        votes.append(valid)

    yes_count = sum(votes)
    print("\nYES votes:", yes_count)

    if yes_count >= threshold:
        print("COMMIT: ACCEPTED\n")
        record = json.loads(message)
        for node in nodes:
            node.store(record)
        return True
    else:
        print("COMMIT: REJECTED")
        return False
