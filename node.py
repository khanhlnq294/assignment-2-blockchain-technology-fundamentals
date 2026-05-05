from crypto_lib.rsa_core import rsa_sign, rsa_verify, simple_hash

# Node class to represent each inventory node
class Node:
    def __init__(self, name, e, d, n):
        self.name = name
        self.e = e
        self.d = d
        self.n = n
        self.records = []

    def create_record(self, message):
        signature = self.sign_message(message)
        return {"message": message, "signature": signature, "Signer": self.name}
    
    def store(self, message):
        self.records.append(message)

    def sign_message(self, message):
        hash_value = simple_hash(message)
        return rsa_sign(hash_value, self.d, self.n)

    def verify_signature(self, message, signature, e, n):
        hash_value = simple_hash(message)
        valid = rsa_verify(hash_value, signature, e, n)
        return valid 