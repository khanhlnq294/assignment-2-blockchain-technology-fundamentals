from crypto_lib.rsa_core import build_rsa, decrypt
from crypto_lib.hashing import simple_hash
import crypto_lib.multi_sign as multi_sign
import json


class ProcurementOfficer:
    def __init__(self, key_params):
        self.rsa = build_rsa(key_params)

    def get_public_key(self):
        """Returns the Officer's public key for encrypting responses to them."""
        return {"e": self.rsa["e"], "n": self.rsa["n"]}

    def decrypt_cipher(self, cipher):
        """Decrypt the hash seal: hash = cipher^d mod n."""
        return decrypt(cipher, self.rsa["d"], self.rsa["n"])

    def verify_response(self, cipher, package, nodes, pkg_public_key):
        """Full receiver-side verification (Task 3 part B).
        Returns True only if:
          - the decrypted hash matches the package hash, AND
          - the Harn multi-signature equation holds.
        """
        # Step 1: decrypt the seal
        decrypted_hash = self.decrypt_cipher(cipher)

        # Step 2: re-hash the package and compare
        package_str = json.dumps(package, sort_keys=True)
        expected_hash = simple_hash(package_str) % self.rsa["n"]
        if decrypted_hash != expected_hash:
            return False

        # Step 3: re-run Harn verification
        print("\n--- Receiver-side verification ---")
        return multi_sign.verify_signature(
            package["S"], package["t"], package["h"],
            nodes, pkg_public_key
        )
