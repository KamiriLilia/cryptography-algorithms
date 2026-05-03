import secrets
from sympy import randprime
#pip install sympy


# =========================================================
# Génération d'un grand nombre premier
# =========================================================
def generate_large_prime(bits=512):
    lower = 2 ** (bits - 1)
    upper = 2 ** bits - 1
    return randprime(lower, upper)


# =========================================================
# Génération des clés ElGamal
# =========================================================
def generate_keys(bits=512):

    # Nombre premier p
    p = generate_large_prime(bits)

    # Générateur g
    g = secrets.randbelow(p - 3) + 2

    # Clé privée x
    x = secrets.randbelow(p - 2) + 1

    # Clé publique y = g^x mod p
    y = pow(g, x, p)

    public_key = (p, g, y)
    private_key = x

    return public_key, private_key


# =========================================================
# Chiffrement
# =========================================================
def encrypt(public_key, message):

    p, g, y = public_key

    # Vérification
    if message >= p:
        raise ValueError("Le message doit être inférieur à p")

    # Nombre aléatoire k
    k = secrets.randbelow(p - 2) + 1

    # c1 = g^k mod p
    c1 = pow(g, k, p)

    # c2 = M * y^k mod p
    c2 = (message * pow(y, k, p)) % p

    return (c1, c2)


# =========================================================
# Déchiffrement
# =========================================================
def decrypt(public_key, private_key, ciphertext):

    p, g, y = public_key
    x = private_key

    c1, c2 = ciphertext

    # s = c1^x mod p
    s = pow(c1, x, p)

    # inverse de s modulo p
    s_inv = pow(s, -1, p)

    # M = c2 * s^-1 mod p
    message = (c2 * s_inv) % p

    return message


# =========================================================
# Programme principal
# =========================================================
if __name__ == "__main__":

    print("=== Génération des clés ===")

    public_key, private_key = generate_keys(512)

    p, g, y = public_key

    print("\n--- Clé publique ---")
    print("p =", p)
    print("g =", g)
    print("y =", y)

    print("\n--- Clé privée ---")
    print("x =", private_key)

    # ==========================================
    # Message à chiffrer
    # ==========================================
    message = 12345

    print("\nMessage original :", message)

    # ==========================================
    # Chiffrement
    # ==========================================
    ciphertext = encrypt(public_key, message)

    c1, c2 = ciphertext

    print("\n=== Message chiffré ===")
    print("c1 =", c1)
    print("c2 =", c2)

    # ==========================================
    # Déchiffrement
    # ==========================================
    decrypted_message = decrypt(
        public_key,
        private_key,
        ciphertext
    )

    print("\n=== Message déchiffré ===")
    print(decrypted_message)

    # Vérification
    if decrypted_message == message:
        print("\nSuccès : le message a été correctement déchiffré.")
    else:
        print("\nErreur de déchiffrement.")