
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


# simple hash function
def simple_hash(message):
    hash_value = 0
    for char in message:
        hash_value += ord(char)
    return hash_value


# modular inverse using Extended Euclidean Algorithm
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1



# RSA functions
def sign(message, d, n):
    hash_value = simple_hash(message)
    return mod_exp(hash_value, d, n)

def verify(message, signature, e, n):
    hash_value = simple_hash(message)
    return mod_exp(signature, e, n) == hash_value
   
def encrypt(message, e, n):
    return mod_exp(message, e, n)

def decrypt(ciphertext, d, n):
    return mod_exp(ciphertext, d, n)