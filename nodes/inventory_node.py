from crypto_lib.hashing import simple_hash
from crypto_lib.rsa_core import rsa_sign, rsa_verify, build_rsa
import json
import os


class InventoryNode:
    def __init__(self, name, key_params, file_path):
        self.name = name
        rsa = build_rsa(key_params)
        self.e = rsa["e"]
        self.d = rsa["d"]
        self.n = rsa["n"]
        self.file_path = file_path

        # Create data file if it doesn't exist
        if not os.path.exists(self.file_path):
            with open(self.file_path, "w") as f:
                json.dump([], f)

    def create_record(self, item_id, qty, price, location):
        #Build and sign a new record. Includes originator field.
        record = {
            "item_id": item_id,
            "qty": qty,
            "price": price,
            "location": location,
            "originator": self.name
        }
        message = json.dumps(record)
        signature = self.sign_message(message)
        return {"record": record, "signature": signature, "Signer": self.name}

    def store(self, record):
        #Append a record to this node's JSON database.
        with open(self.file_path, "r") as f:
            data = json.load(f)
        data.append(record)
        with open(self.file_path, "w") as f:
            json.dump(data, f, indent=4)

    def sign_message(self, message):
        #Hash the message with SHA-256 and sign with RSA private key.
        h = simple_hash(message)   
        return rsa_sign(h, self.d, self.n)

    def verify_signature_from(self, message, signature, e, n):
        #Verify a signature using the sender's public key.
        h = simple_hash(message) % n
        return rsa_verify(h, signature, e, n)
