"""
selftest.py
===========
Standalone tests for the three assignment tasks.
Run from the project root:   python selftest.py
"""

import system.workflow as wf
from crypto_lib.rsa_core import build_rsa, rsa_sign, rsa_verify
from crypto_lib.hashing import simple_hash
import crypto_lib.multi_sign as multi_sign
import keys_config
import json

PASS = "[PASS]"
FAIL = "[FAIL]"

def check(label, got, want):
    status = PASS if got == want else FAIL
    print(f"  {status} {label}: got={got}, want={want}")

def run_tests():
    nodes, public_keys = wf.initalise_system()
    wf.reset_data(nodes)

    # ------------------------------------------------------------------
    print("\nTest 1: clean RSA signature verifies")
    rsa = build_rsa(keys_config.INVENTORY_A_KEYS)
    msg = "test message"
    h = simple_hash(msg) % rsa["n"]
    sig = rsa_sign(h, rsa["d"], rsa["n"])
    result = rsa_verify(h, sig, rsa["e"], rsa["n"])
    check("RSA verify(clean)", result, True)

    # ------------------------------------------------------------------
    print("\nTest 2: tampered record fails RSA verification")
    rsa = build_rsa(keys_config.INVENTORY_A_KEYS)
    msg = '{"item_id": "001", "qty": 5}'
    h = simple_hash(msg) % rsa["n"]
    sig = rsa_sign(h, rsa["d"], rsa["n"])
    tampered = '{"item_id": "001", "qty": 9999}'
    h2 = simple_hash(tampered) % rsa["n"]
    result = rsa_verify(h2, sig, rsa["e"], rsa["n"])
    check("RSA verify(tampered)", result, False)

    # ------------------------------------------------------------------
    print("\nTest 3: tampered signature fails RSA verification")
    rsa = build_rsa(keys_config.INVENTORY_A_KEYS)
    msg = "another test"
    h = simple_hash(msg) % rsa["n"]
    sig = rsa_sign(h, rsa["d"], rsa["n"])
    result = rsa_verify(h, sig + 1, rsa["e"], rsa["n"])
    check("RSA verify(tampered sig)", result, False)

    # ------------------------------------------------------------------
    print("\nTest 4: clean Harn multi-signature verifies")
    pkg_rsa = build_rsa(keys_config.PKG_KEYS)
    message = json.dumps({"item_id": "001", "total_qty": 37}, sort_keys=True)
    g_values = multi_sign.generate_g_values(nodes, pkg_rsa)
    t_values = multi_sign.compute_t_values(nodes, pkg_rsa)
    t = multi_sign.compute_t(t_values, pkg_rsa["n"])
    h = multi_sign.compute_h(message, t)
    s_values = multi_sign.compute_s_values(nodes, g_values, h, pkg_rsa["n"])
    S = multi_sign.compute_S(s_values, pkg_rsa["n"])
    result = multi_sign.verify_signature(S, t, h, nodes, pkg_rsa)
    check("Harn verify(clean)", result, True)

    # ------------------------------------------------------------------
    print("\nTest 5: tampered message fails Harn verification")
    h_bad = multi_sign.compute_h("tampered message", t)
    result = multi_sign.verify_signature(S, t, h_bad, nodes, pkg_rsa)
    check("Harn verify(tampered m)", result, False)

    # ------------------------------------------------------------------
    print("\nTest 6: tampered S fails Harn verification")
    result = multi_sign.verify_signature(S + 1, t, h, nodes, pkg_rsa)
    check("Harn verify(tampered S)", result, False)

    # ------------------------------------------------------------------
    print("\nTest 7: PBFT rejects a record signed by a different node")
    from system.consensus import run_pbft
    rsa_b = build_rsa(keys_config.INVENTORY_B_KEYS)
    record = {"item_id": "999", "qty": 1, "price": 1, "location": "A", "originator": "A"}
    msg_str = json.dumps(record, sort_keys=True)
    h_b = simple_hash(msg_str) % rsa_b["n"]
    forged_sig = rsa_sign(h_b, rsa_b["d"], rsa_b["n"])   # signed by B, claimed from A
    packet = {"message": msg_str, "signature": forged_sig, "sender": "A"}
    accepted = run_pbft(packet, nodes, public_keys)
    check("PBFT accepted(bad sig)", accepted, False)

    # ------------------------------------------------------------------
    print("\nTest 8: full end-to-end create + query + verify")
    wf.reset_data(nodes)
    wf.create_record_workflow(nodes, public_keys, "A", "001", 5, 10, "A")
    response = wf.query_workflow(nodes, "001")
    ok = wf.verify_received_package(response["cipher"], response["package"], nodes)
    check("End-to-end VALID", ok, True)
    check("Total qty", response["package"]["message"]["total_qty"], 37)

    print("\nAll tests complete.")


if __name__ == "__main__":
    run_tests()
