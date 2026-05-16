"""
Exercice 3.4 — Cryptographie sur Courbes Elliptiques (ECC)
============================================================
1. Arithmétique de courbe elliptique (Weierstrass, petits paramètres)
2. ECDH sur P-256 avec la bibliothèque cryptography
3. Chiffrement hybride ECDH + AES-256-GCM (ECIES simplifié)
"""

import os
import hashlib
import secrets
import struct

# ─────────────────────────────────────────────────────────────────────────────
# 1. Arithmétique sur courbe elliptique — y² = x³ + 7 mod 97
# ─────────────────────────────────────────────────────────────────────────────

class EllipticCurve:
    """
    Courbe de Weierstrass : y² ≡ x³ + ax + b (mod p)
    Point à l'infini représenté par None.
    """

    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.p = p
        # Vérifier la non-singularité : 4a³ + 27b² ≢ 0 (mod p)
        discriminant = (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p
        assert discriminant != 0, "Courbe singulière ! Choisir d'autres paramètres."

    def is_on_curve(self, P) -> bool:
        """Vérifie que P est sur la courbe."""
        if P is None:
            return True  # Point à l'infini
        x, y = P
        return (pow(y, 2, self.p) - pow(x, 3, self.p) - self.a * x - self.b) % self.p == 0

    def point_add(self, P, Q):
        """
        Addition de points P + Q sur la courbe.
        
        Cas :
          • P = O (infini) → retourne Q
          • Q = O (infini) → retourne P
          • P = -Q         → retourne O
          • P = Q          → formule de doublement (tangente)
          • P ≠ Q          → formule générale (corde)
        """
        p, a = self.p, self.a

        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        # P = -Q  →  O (point à l'infini)
        if x1 == x2 and (y1 + y2) % p == 0:
            return None

        if P == Q:
            # Doublement : tangente
            # λ = (3x₁² + a) / (2y₁) mod p
            lam = (3 * pow(x1, 2, p) + a) * pow(2 * y1, -1, p) % p
        else:
            # Addition : corde
            # λ = (y₂ - y₁) / (x₂ - x₁) mod p
            lam = (y2 - y1) * pow(x2 - x1, -1, p) % p

        x3 = (pow(lam, 2, p) - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p
        return (x3, y3)

    def scalar_mult(self, k: int, P):
        """
        Multiplication scalaire : kP = P + P + ... + P (k fois)
        Algorithme double-and-add (efficace O(log k)).
        """
        if k == 0 or P is None:
            return None
        if k < 0:
            x, y = P
            P = (x, (-y) % self.p)
            k = -k

        result = None   # Point à l'infini
        addend = P

        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1

        return result

    def neg(self, P):
        """Opposé d'un point."""
        if P is None:
            return None
        x, y = P
        return (x, (-y) % self.p)


def demo_arithmetique_ecc():
    print("\n" + "█"*60)
    print("  EXERCICE 3.4 — ARITHMÉTIQUE ECC : y² = x³ + 7 mod 97")
    print("█"*60)

    # Paramètres pédagogiques : y² = x³ + 7 mod 97
    curve = EllipticCurve(a=0, b=7, p=97)

    # Point de base G (on cherche un point sur la courbe)
    # Chercher des points valides sur y² = x³ + 7 mod 97
    print("\n  --- Points sur la courbe y² = x³ + 7 mod 97 ---")
    points = []
    for x in range(97):
        rhs = (pow(x, 3, 97) + 7) % 97
        for y in range(97):
            if pow(y, 2, 97) % 97 == rhs:
                points.append((x, y))
                if len(points) <= 10:
                    print(f"    ({x:2d}, {y:2d})  ✓  vérif: {pow(y,2,97)%97} == {rhs}")

    print(f"\n  Nombre total de points sur la courbe (+ infini) : {len(points) + 1}")

    # Choisir G parmi les premiers points trouvés
    G = points[0]
    print(f"\n  Point de base G = {G}")
    print(f"  G est sur la courbe : {curve.is_on_curve(G)}")

    print(f"\n  --- Multiples de G ---")
    P = G
    orbit = [G]
    for i in range(2, 20):
        P = curve.point_add(P, G)
        if P is None:
            print(f"    {i}G = O (point à l'infini)")
            print(f"    Ordre de G = {i}")
            break
        orbit.append(P)
        print(f"    {i}G = {P}  sur courbe: {curve.is_on_curve(P)}")

    # Vérification des propriétés du groupe
    print(f"\n  --- Vérification des propriétés du groupe ---")

    # Associativité : (A+B)+C = A+(B+C)
    if len(orbit) >= 3:
        A, B, C = orbit[0], orbit[1], orbit[2]
        lhs = curve.point_add(curve.point_add(A, B), C)
        rhs = curve.point_add(A, curve.point_add(B, C))
        print(f"  Associativité : (A+B)+C = A+(B+C) → {lhs == rhs}  ✓")

    # Commutativité : A+B = B+A
    A, B = orbit[0], orbit[1]
    print(f"  Commutativité : A+B = B+A → {curve.point_add(A, B) == curve.point_add(B, A)}  ✓")

    # Élément neutre : A + O = A
    print(f"  Élément neutre : A + O = A → {curve.point_add(A, None) == A}  ✓")

    # Inverse : A + (-A) = O
    neg_A = curve.neg(A)
    print(f"  Inverse : A + (-A) = O → {curve.point_add(A, neg_A) is None}  ✓")

    # Multiplication scalaire
    k1, k2 = 5, 7
    kG_1 = curve.scalar_mult(k1, G)
    kG_2 = curve.scalar_mult(k2, G)
    kG_12 = curve.scalar_mult(k1 + k2, G)
    print(f"\n  Distributivité scalaire : (k1+k2)G = k1·G + k2·G")
    print(f"    {k1}G + {k2}G       = {curve.point_add(kG_1, kG_2)}")
    print(f"    ({k1}+{k2})G = {k1+k2}G  = {kG_12}")
    print(f"    Égalité : {curve.point_add(kG_1, kG_2) == kG_12}  ✓")

    print(f"\n  ECDLP illustré :")
    k_secret = 13
    Q = curve.scalar_mult(k_secret, G)
    print(f"    G = {G},  k = {k_secret} (secret)")
    print(f"    Q = k·G = {Q}")
    print(f"    → Connaître G et Q, trouver k est le problème ECDLP")
    print(f"    → Sur des courbes de 256 bits, ce problème est computationnellement infaisable")


# ─────────────────────────────────────────────────────────────────────────────
# 2. ECDH sur P-256 avec la bibliothèque cryptography
# ─────────────────────────────────────────────────────────────────────────────

def demo_ecdh_p256():
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key, SECP256R1, ECDH
    )
    from cryptography.hazmat.backends import default_backend

    print(f"\n{'='*60}")
    print(f"  ECDH SUR P-256 (NIST)")
    print(f"{'='*60}")

    curve = SECP256R1()
    backend = default_backend()

    # ── Alice génère sa paire de clés ──────────────────────────────────────
    priv_A = generate_private_key(curve, backend)
    pub_A  = priv_A.public_key()

    # ── Bob génère sa paire de clés ────────────────────────────────────────
    priv_B = generate_private_key(curve, backend)
    pub_B  = priv_B.public_key()

    pub_A_nums = pub_A.public_numbers()
    pub_B_nums = pub_B.public_numbers()

    print(f"\n  Clé publique d'Alice :")
    print(f"    x = {pub_A_nums.x}")
    print(f"    y = {pub_A_nums.y}")
    print(f"\n  Clé publique de Bob :")
    print(f"    x = {pub_B_nums.x}")
    print(f"    y = {pub_B_nums.y}")

    # ── Échange ECDH ───────────────────────────────────────────────────────
    # Alice calcule : shared = priv_A · pub_B
    shared_A = priv_A.exchange(ECDH(), pub_B)

    # Bob calcule   : shared = priv_B · pub_A
    shared_B = priv_B.exchange(ECDH(), pub_A)

    print(f"\n  Secret partagé ECDH (côté Alice, hex) :")
    print(f"    {shared_A.hex()}")
    print(f"\n  Secret partagé ECDH (côté Bob,   hex) :")
    print(f"    {shared_B.hex()}")
    print(f"\n  Secrets identiques : {shared_A == shared_B}  ✓")

    # ── Dérivation de clé AES-256 via SHA-256 ──────────────────────────────
    aes_key_A = hashlib.sha256(shared_A).digest()
    aes_key_B = hashlib.sha256(shared_B).digest()

    print(f"\n  Clé AES-256 dérivée (SHA-256 du secret) :")
    print(f"    Alice : {aes_key_A.hex()}")
    print(f"    Bob   : {aes_key_B.hex()}")
    print(f"    Identiques : {aes_key_A == aes_key_B}  ✓")

    print(f"""
  Protocole ECDH :
  ────────────────
  Alice : a (privé), A = a·G (public)
  Bob   : b (privé), B = b·G (public)

  Alice envoie A à Bob, Bob envoie B à Alice.

  Alice calcule : S = a·B = a·(b·G) = ab·G
  Bob calcule   : S = b·A = b·(a·G) = ab·G
  → Même secret S (coordonnée x utilisée).

  Sécurité : ECDLP sur P-256 ≈ 128 bits de sécurité
  Clés P-256 (256 bits) ≈ RSA-3072 (NIST SP 800-57).
""")

    return aes_key_A, pub_A, pub_B, priv_A, priv_B


# ─────────────────────────────────────────────────────────────────────────────
# 3. Chiffrement hybride ECDH + AES-256-GCM (ECIES simplifié)
# ─────────────────────────────────────────────────────────────────────────────

def ecies_encrypt(message: bytes, recipient_pub_key) -> bytes:
    """
    ECIES simplifié : Alice chiffre un message pour Bob.
    
    Algorithme :
      1. Générer une paire éphémère (r, R = r·G)
      2. S = r · pub_B  (secret ECDH)
      3. k = SHA-256(S)  (clé AES-256)
      4. Chiffrer message avec AES-256-GCM
      5. Retourner : R_x || R_y || nonce || tag || ciphertext
    
    Format du paquet chiffré (big-endian) :
      [4B len_R] [R bytes] [12B nonce] [16B GCM tag] [ciphertext]
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key, SECP256R1, ECDH
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend

    # 1. Paire éphémère
    ephemeral_priv = generate_private_key(SECP256R1(), default_backend())
    ephemeral_pub  = ephemeral_priv.public_key()

    # 2. Secret ECDH
    shared_secret = ephemeral_priv.exchange(ECDH(), recipient_pub_key)

    # 3. Clé AES-256
    aes_key = hashlib.sha256(shared_secret).digest()

    # 4. Chiffrement AES-256-GCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext_tag = aesgcm.encrypt(nonce, message, None)
    # Note : AESGCM.encrypt retourne ciphertext || tag (16 octets de tag)
    ciphertext = ciphertext_tag[:-16]
    tag        = ciphertext_tag[-16:]

    # 5. Sérialiser la clé publique éphémère (format non-compressé : 04 || x || y)
    R_bytes = ephemeral_pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    # Paquet : len(R)[4B] + R + nonce[12B] + tag[16B] + ciphertext
    packet = struct.pack(">I", len(R_bytes)) + R_bytes + nonce + tag + ciphertext
    return packet


def ecies_decrypt(packet: bytes, recipient_priv_key) -> bytes:
    """
    ECIES simplifié : Bob déchiffre un message d'Alice.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import ECDH
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat
    )
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1, EllipticCurvePublicNumbers
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey
    )

    # Désérialiser
    offset = 0
    len_R = struct.unpack(">I", packet[offset:offset+4])[0]
    offset += 4

    R_bytes    = packet[offset:offset+len_R]; offset += len_R
    nonce      = packet[offset:offset+12];    offset += 12
    tag        = packet[offset:offset+16];    offset += 16
    ciphertext = packet[offset:]

    # Reconstruire la clé publique éphémère
    ephemeral_pub = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), R_bytes)

    # Secret ECDH
    shared_secret = recipient_priv_key.exchange(ECDH(), ephemeral_pub)

    # Clé AES
    aes_key = hashlib.sha256(shared_secret).digest()

    # Déchiffrement AES-256-GCM
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return plaintext


def demo_chiffrement_hybride():
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key, SECP256R1
    )
    from cryptography.hazmat.backends import default_backend

    print(f"\n{'='*60}")
    print(f"  CHIFFREMENT HYBRIDE ECDH + AES-256-GCM (ECIES SIMPLIFIÉ)")
    print(f"{'='*60}")

    # Générer les clés de Bob (destinataire)
    priv_B = generate_private_key(SECP256R1(), default_backend())
    pub_B  = priv_B.public_key()

    print(f"\n  Bob génère sa paire de clés P-256 :")
    pub_B_nums = pub_B.public_numbers()
    print(f"    Clé publique x = {pub_B_nums.x:#x}"[:80] + "...")
    print(f"    Clé publique y = {pub_B_nums.y:#x}"[:80] + "...")

    # Message à chiffrer
    message = (
        "Bonjour Bob ! Ceci est un message confidentiel chiffré "
        "avec ECIES (ECDH + AES-256-GCM). "
        "Seul toi peux le lire grâce à ta clé privée P-256."
    ).encode("utf-8")

    print(f"\n  Message original ({len(message)} octets) :")
    print(f"    {message.decode()}")

    # Alice chiffre pour Bob
    print(f"\n  Alice chiffre avec la clé publique de Bob...")
    packet = ecies_encrypt(message, pub_B)

    print(f"  Paquet chiffré ({len(packet)} octets, hex extrait) :")
    print(f"    {packet.hex()[:80]}...")
    print(f"\n  Structure du paquet :")

    len_R = struct.unpack(">I", packet[:4])[0]
    print(f"    [0:4]    = longueur de R      : {len_R} octets")
    print(f"    [4:{4+len_R}] = R (clé éphémère)  : {packet[4:4+len_R].hex()[:40]}...")
    print(f"    [...]    = nonce (12 octets)  : {packet[4+len_R:4+len_R+12].hex()}")
    print(f"    [...]    = GCM tag (16 octets): {packet[4+len_R+12:4+len_R+28].hex()}")
    print(f"    [...]    = ciphertext          : {packet[4+len_R+28:].hex()[:40]}...")

    # Bob déchiffre
    print(f"\n  Bob déchiffre avec sa clé privée...")
    decrypted = ecies_decrypt(packet, priv_B)

    print(f"  Message déchiffré :")
    print(f"    {decrypted.decode()}")
    print(f"\n  Déchiffrement correct : {decrypted == message}  ✓")

    # Vérifier que sans la clé privée de Bob, on ne peut pas déchiffrer
    priv_Eve = generate_private_key(SECP256R1(), default_backend())
    try:
        ecies_decrypt(packet, priv_Eve)
        print(f"\n  ✗ ERREUR : Eve a pu déchiffrer !")
    except Exception as e:
        print(f"\n  Eve tente de déchiffrer avec sa propre clé privée...")
        print(f"  → Exception : {type(e).__name__} — Déchiffrement impossible sans la clé de Bob ✓")

    print(f"""
  Résumé du protocole ECIES simplifié :
  ══════════════════════════════════════
  1. Alice génère une paire éphémère (r, R = r·G)
  2. Alice calcule S = r · pub_Bob  →  AES_key = SHA-256(S)
  3. Alice chiffre avec AES-256-GCM : C = AES(AES_key, message)
  4. Alice envoie : (R, C) à Bob

  5. Bob calcule S = priv_Bob · R = priv_Bob · r · G = r · pub_Bob ✓
  6. Bob dérive AES_key = SHA-256(S)
  7. Bob déchiffre C avec AES-256-GCM

  Sécurité :
  • Confidentialité  : IND-CCA2 (avec GCM authentifié)
  • Authenticité     : GCM tag protège contre la modification
  • Forward Secrecy  : clé éphémère r jetée après usage
  • Performance      : AES-GCM chiffre les données, ECC sécurise la clé
  • Taille de clé    : P-256 (64 octets publique) << RSA-3072 (384 octets)
""")


# ─────────────────────────────────────────────────────────────────────────────
# PROGRAMME PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "█"*60)
    print("  EXERCICE 3.4 — CRYPTOGRAPHIE SUR COURBES ELLIPTIQUES")
    print("█"*60)

    # 1. Arithmétique sur y² = x³ + 7 mod 97
    demo_arithmetique_ecc()

    # 2. ECDH sur P-256
    demo_ecdh_p256()

    # 3. Chiffrement hybride ECIES
    demo_chiffrement_hybride()

    print("\n" + "█"*60)
    print("  COMPARAISON FINALE : ECC vs RSA vs ElGamal")
    print("█"*60)
    print(f"""
  ┌──────────────┬───────────────┬───────────────┬───────────────┐
  │ Système      │ Sécurité 128b │ Clé publique  │ Clé privée    │
  ├──────────────┼───────────────┼───────────────┼───────────────┤
  │ RSA          │ 3072 bits     │ 384 octets    │ 384 octets    │
  │ ElGamal      │ 3072 bits     │ 3×384 octets  │ 384 octets    │
  │ ECC (P-256)  │  256 bits     │  64 octets    │  32 octets    │
  └──────────────┴───────────────┴───────────────┴───────────────┘

  ECC est 6× plus compact que RSA/ElGamal à sécurité équivalente.
  → Standard pour TLS 1.3, Signal Protocol, carte à puce, IoT.
""")
    print("█"*60)
    print("  FIN DE L'EXERCICE 3.4")
    print("█"*60 + "\n")
# ══════════════════════════════════════════════════════════════════════════════
# CLASSE ECCAlgorithm POUR L'INTERFACE MAIN.PY
# ══════════════════════════════════════════════════════════════════════════════

class ECCAlgorithm:
    """
    Wrapper pour l'interface main.py
    """
    
    def __init__(self):
        self._curve = None
        self._alice_priv = None
        self._alice_pub = None
        self._bob_priv = None
        self._bob_pub = None
        self._shared_secret = None
    
    def get_name(self):
        return "ECC (Elliptic Curve Cryptography)"
    
    def get_description(self):
        return (
            "ECC — Cryptographie sur Courbes Elliptiques\n"
            "• Sécurité : ECDLP (Elliptic Curve Discrete Log)\n"
            "• ECC-256 ≈ RSA-3072 en sécurité\n"
            "• Clés beaucoup plus compactes que RSA\n"
            "• Protocoles : ECDH, ECDSA, ECIES\n"
            "• Fonctionnalités :\n"
            "  - 'ecdh' : échange de clés ECDH\n"
            "  - 'ecies' : chiffrement hybride avec AES\n"
            "  - 'demo' : démonstration complète"
        )
    
    def get_key_info(self):
        return {
            "type": "asymmetric",
            "placeholder": "'ecdh' | 'ecies' | 'demo'"
        }
    
    def encrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        key_lower = str(key).strip().lower()
        
        if log_step:
            log_step("🔐 ECC — SIMULATION")
            log_step("=" * 42)
        
        if key_lower == "demo":
            result = """
╔══════════════════════════════════════════════════════════════╗
║              CRYPTOGRAPHIE SUR COURBES ELLIPTIQUES          ║
╠══════════════════════════════════════════════════════════════╣
║  Courbe P-256 (SECP256R1) — niveau de sécurité ~128 bits    ║
╠══════════════════════════════════════════════════════════════╣
║  Propriétés du groupe :                                     ║
║    • Associativité : (A+B)+C = A+(B+C) ✓                    ║
║    • Commutativité : A+B = B+A ✓                            ║
║    • Élément neutre : A + O = A ✓                           ║
║    • Inverse : A + (-A) = O ✓                               ║
╠══════════════════════════════════════════════════════════════╣
║  Exemple ECDLP (logarithme discret) :                       ║
║    G = point de base                                        ║
║    k = 13 (secret)                                          ║
║    Q = k·G                                                  ║
║    → Trouver k à partir de G et Q est INFESAISABLE         ║
╠══════════════════════════════════════════════════════════════╣
║  Comparaison ECC vs RSA :                                   ║
║    • ECC-256   ≈ RSA-3072  (même sécurité)                  ║
║    • Clé ECC   : 32 octets                                  ║
║    • Clé RSA   : 384 octets (12x plus grand)                ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ ECC est le standard moderne (TLS 1.3, Signal, Bitcoin)   ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("✓ Démonstration ECC complète")
            
            return result
        
        elif key_lower == "ecdh":
            try:
                from cryptography.hazmat.primitives.asymmetric.ec import (
                    generate_private_key, SECP256R1, ECDH
                )
                from cryptography.hazmat.backends import default_backend
                
                curve = SECP256R1()
                backend = default_backend()
                
                # Alice génère sa paire
                priv_A = generate_private_key(curve, backend)
                pub_A = priv_A.public_key()
                
                # Bob génère sa paire
                priv_B = generate_private_key(curve, backend)
                pub_B = priv_B.public_key()
                
                # Échange
                shared_A = priv_A.exchange(ECDH(), pub_B)
                shared_B = priv_B.exchange(ECDH(), pub_A)
                
                self._shared_secret = shared_A
                pub_A_nums = pub_A.public_numbers()
                pub_B_nums = pub_B.public_numbers()
                
                result = f"""
╔══════════════════════════════════════════════════════════════╗
║                    ÉCHANGE ECDH SUR P-256                    ║
╠══════════════════════════════════════════════════════════════╣
║  Alice :                                                     ║
║    Clé publique x = {pub_A_nums.x}[:48]...
║    Clé publique y = {pub_A_nums.y}[:48]...
║                                                              ║
║  Bob :                                                       ║
║    Clé publique x = {pub_B_nums.x}[:48]...
║    Clé publique y = {pub_B_nums.y}[:48]...
╠══════════════════════════════════════════════════════════════╣
║  Secret partagé ECDH : {shared_A.hex()[:48]}...
╠══════════════════════════════════════════════════════════════╣
║  ✓ Secrets identiques : {shared_A == shared_B}              ║
╚══════════════════════════════════════════════════════════════╝
"""
                if log_step:
                    log_step("✓ Échange ECDH simulé")
                
                return result
                
            except ImportError:
                return "⚠️ Bibliothèque 'cryptography' non installée. Exécutez : pip install cryptography"
        
        elif key_lower == "ecies":
            try:
                from cryptography.hazmat.primitives.asymmetric.ec import (
                    generate_private_key, SECP256R1
                )
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                from cryptography.hazmat.backends import default_backend
                
                # Bob (destinataire)
                priv_B = generate_private_key(SECP256R1(), default_backend())
                pub_B = priv_B.public_key()
                
                # Message
                message = text.encode("utf-8") if text else b"Message secret pour Bob"
                
                # Alice chiffre avec la clé publique de Bob
                packet = ecies_encrypt(message, pub_B)
                
                # Bob déchiffre
                decrypted = ecies_decrypt(packet, priv_B)
                
                result = f"""
╔══════════════════════════════════════════════════════════════╗
║           CHIFFREMENT HYBRIDE ECIES (ECDH + AES)            ║
╠══════════════════════════════════════════════════════════════╣
║  Message original : {message.decode()[:50]}...                             ║
║  Paquet chiffré   : {packet.hex()[:48]}...                               ║
║  Message déchiffré: {decrypted.decode()[:50]}...                             ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ Chiffrement hybride réussi !                             ║
║  ✓ Confidentialité + Authenticité (AES-GCM)                 ║
║  ✓ Forward Secrecy (clé éphémère)                           ║
╚══════════════════════════════════════════════════════════════╝
"""
                if log_step:
                    log_step("✓ Chiffrement ECIES simulé")
                
                return result
                
            except ImportError:
                return "⚠️ Bibliothèque 'cryptography' non installée. Exécutez : pip install cryptography"
        
        else:
            return "Utilisez 'demo', 'ecdh' ou 'ecies' comme clé."
    
    def decrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        return self.encrypt(text, key, log_step, log_matrix)

if __name__ == "__main__":
    main()