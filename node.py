from crypto import sign, verify

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

    def sign_message(self, message):
        return sign(message, self.d, self.n)

    def verify_signature(self, message, signature, e, n):
        valid = verify(message, signature, e, n)
        return valid 