from crypto_lib.rsa_core import build_rsa, encrypt
from crypto_lib.multi_sign import derive_signer_secret, verify_signature


class PKG:
    def __init__(self, key_params: dict):
        self.rsa = build_rsa(
            p = key_params["p"],
            q = key_params["q"],
            e = key_params["e"]
        )
    
    # 1. Harn Secret Key
    def harn_secret_key(self, identity: int) -> int:
        return derive_signer_secret(identity, self.rsa["d"], self.rsa["n"])
    # 2. Verify multi-signature by using consensus
    def verify(self, message_int: int, t:int, s: int, identities) -> dict:
        return verify_signature(
            message_int, t, s, identities,
            self.rsa["e"], self.rsa["n"]
        )
    # 3. Encrypt the response by PO's PK
    def encrypt_response(self, plaintext_piecies, recipient_public_key):
        return tuple(
            encrypt(piece, recipient_public_key)
            for piece in plaintext_piecies
        )