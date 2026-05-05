from crypto_lib.rsa_core import rsa_verify


def get_threshold(n):
    f = (n - 1) // 3
    return 2 * f + 1


def run_pbft(packet, nodes, public_keys):
    message = packet["message"]
    signature = packet["signature"]
    sender = packet["sender"]

    print("\n--- PBFT CONSENSUS ROUND ---")
    print("Sender:", sender)
    print("Message:", message)

    threshold = get_threshold(len(nodes))
    print("Threshold:", threshold)

    votes = []

    
    for node in nodes:
        pub = public_keys[sender]

        valid = rsa_verify(message, signature, pub["e"], pub["n"])

        print(f"{node.name} PREPARE vote:", "YES" if valid else "NO")

        votes.append(valid)

    yes_count = sum(votes)

    print("\nYES votes:", yes_count)

    
    if yes_count >= threshold:
        print("COMMIT: ACCEPTED")

        for node in nodes:
            node.store(message)

        return True
    

    else:
        print("COMMIT: REJECTED")
        return False