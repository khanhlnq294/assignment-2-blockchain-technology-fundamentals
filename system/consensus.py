"""PBFT style """

def bft_threshold(num_nodes):
    # n >= 3f + 1   <=>   f = (n - 1) // 3   ;   --> threshold = 2f + 1
    f = (num_nodes - 1) // 3
    return 2 * f + 1

def receiver_vote(signed_bundle, receiver_node):
    record = signed_bundle["record"]
    h_local = record_hash(record)
    sig_ok = rsa_verify(h_local, signed_bundle["signature"], signed_bundle["originator_pub"])
    return {"voter": receiver_node.name,
            "vote" : "YES" if sig_ok else "NO"}

def run_consensus_round(signed_bundle, all_nodes):
    receivers = [n for n in all_nodes if n.name!=signed_bundle["originatore"]]
    votes = [receiver_vote(signed_bundle, r) for r in receivers]
    yes_count = 1 + sum(1 for v in votes if v["vote"] == "YES") # +1 = originator
    threshold = bft_threshold(len(all_nodes))
    return {"yes_count": yes_count, 
            "threshold": threshold,
            "receiver_votes": votes}
