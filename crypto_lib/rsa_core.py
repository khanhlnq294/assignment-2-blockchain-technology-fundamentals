def extended_euclidean(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t       # gcd, x, y    such that a*x + b*y = gcd
 
def mod_inverse(a, m):
    g, x, _ = extended_euclidean(a, m)
    if g != 1:
        raise ValueError("No modular inverse exists.")
    return x % m

def rsa_sign(message_hash_int, private_key):
    # L3 slide 32:   s = H(M)^d mod n
    d, n = private_key
    return pow(message_hash_int, d, n)
 
def rsa_verify(message_hash_int, signature, public_key):
    # L3 slide 32:   h2 = s^e mod n; valid <=> h2 == H(M)
    e, n = public_key
    return pow(signature, e, n) == message_hash_int
