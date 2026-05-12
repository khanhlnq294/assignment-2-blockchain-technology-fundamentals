from crypto_lib.hashing import simple_hash
import keys_config

#===============================
# KEY GENERATION
#===============================
def generate_g_values(nodes, pkg_rsa):
    g_values = {}

    for node in nodes:
        ID = keys_config.INVENTORY_IDENTITIES[node.name]

        g_i = pow(ID, pkg_rsa["d"], pkg_rsa["n"])

        g_values[node.name] = g_i

    return g_values

#===============================
# Round-1 commitment (each signer):
#===============================

def compute_t_values(nodes, pkg_rsa):
    t_values = {}

    for node in nodes:
        r = keys_config.INVENTORY_RANDOM_R[node.name]

        t_i = pow(r, pkg_rsa["e"], pkg_rsa["n"])

        t_values[node.name] = t_i

    return t_values


def compute_t(t_values, n):
    t = 1
    for val in t_values.values():
        t = (t * val) % n
    return t

#===============================
# Round-2 partial signatures:
#===============================
def compute_h(message, t):
    return simple_hash(str(t) + message)

def compute_s_values(nodes, g_values, h, n):
    s_values = {}

    for node in nodes:
        r = keys_config.INVENTORY_RANDOM_R[node.name]
        g_i = g_values[node.name]

        s_i = (g_i * pow(r, h, n)) % n

        s_values[node.name] = s_i

    return s_values

def compute_S(s_values, n):
    S = 1
    for s in s_values.values():
        S = (S * s) % n
    return S

#===============================
# Verification:
#===============================
def verify_signature(S, t, h, nodes, pkg_rsa):
    n = pkg_rsa["n"]
    e = pkg_rsa["e"]

    # Left side
    left = pow(S, e, n)

    # Right side
    ID_product = 1
    for node in nodes:
        ID = keys_config.INVENTORY_IDENTITIES[node.name]
        ID_product = (ID_product * ID) % n

    right = (ID_product * pow(t, h, n)) % n

    print("Left:", left)
    print("Right:", right)

    return left == right