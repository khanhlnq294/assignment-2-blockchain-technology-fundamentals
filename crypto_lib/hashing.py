import hashlib

def canonicalise(parts) -> str:
    return "".join(str(x) for x in parts)

def simple_hash(message: str) -> int:
    digest_hex = hashlib.sha256(message.encode("utf-8")).hexdigest()
    return int(digest_hex, 16)


def record_hash(record: dict) -> int:
    parts = [
        record["item_id"],
        record["qty"],
        record["price"],
        record["location"],
        record["originator"],
    ]
    return simple_hash(canonicalise(parts))


def harn_hash(t: int, m: int, modulus: int) -> int:
    raw = simple_hash(canonicalise([t, m]))
    return raw % modulus
