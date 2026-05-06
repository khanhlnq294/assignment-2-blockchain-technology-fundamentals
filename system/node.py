from crypto_lib.rsa_core import rsa_sign, rsa_verify, simple_hash
import json

# Node class to represent each inventory node
class Node:
    def __init__(self, name, e, d, n, file_path):
        self.name = name
        self.e = e
        self.d = d
        self.n = n
        self.records = {}
        self.file_path = file_path

    def create_record(self, item_id, qty, price, location):
        record = {
            "item_id": item_id,
            "qty": qty,
            "price": price,
            "location": location
        }

        message = json.dumps(record)
        signature = self.sign_message(message)

        return {"record": record, "signature": signature, "Signer": self.name}
    
    def store(self, record):
        with open(self.file_path, "r") as f:
            data = json.load(f)
        data.append(record)
        with open (self.file_path, "w") as f:
            json.dump(data, f, indent=4)

  
    def sign_message(self, message):
        hash_value = simple_hash(message)
        return rsa_sign(hash_value, self.d, self.n)

    def verify_signature(self, message, signature, e, n):
        hash_value = simple_hash(message)
        return rsa_verify(hash_value, signature, e, n)