import hashlib


def simple_hash(message: str) -> int:
    digest_hex = hashlib.sha256(message.encode("utf-8")).hexdigest()
    return int(digest_hex, 16)

