from math import gcd

# Utility function to build RSA parameters from keys
def build_rsa(keys):
    p = keys["p"]
    q = keys["q"]
    e = keys["e"]
    
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    
    return {"e": e, "d": d, "n": n}


# modular exponentiation
def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if (exp % 2) == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

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

# Simple hash function to simulate sha256 (for demonstration purposes only)
def simple_hash(message):
    hash_value = 0
    for char in message:
        hash_value += ord(char)
    return hash_value

def rsa_sign(message_hash, d, n):
    # L3 slide 32:   s = H(M)^d mod n
    return pow(message_hash, d, n)
    #return mod_exp(message_hash, d, n)
 
def rsa_verify(message_hash, signature, e, n):
    # L3 slide 32:   h2 = s^e mod n; valid <=> h2 == H(M)
    return pow(signature, e, n) == message_hash
    #return mod_exp(signature, e, n) == message_hash

def encrypt(message, e, n):
    return pow(message, e, n)
    #return mod_exp(message, e, n)

def decrypt(ciphertext, d, n):
    return pow(ciphertext, d, n)
    #return mod_exp(ciphertext, d, n)


