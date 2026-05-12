from crypto_lib.rsa_core import build_rsa


class PKG:
    def __init__(self, key_params):
        self.rsa = build_rsa(key_params)

    def issue_secret_key(self, identity):
        """Harn key extraction (Phase 1):  g = ID^d mod n.
        Called once per signer during system setup."""
        return pow(identity, self.rsa["d"], self.rsa["n"])

    def get_public_key(self):
        """Returns the PKG public key dict used in verification."""
        return {"e": self.rsa["e"], "n": self.rsa["n"]}
