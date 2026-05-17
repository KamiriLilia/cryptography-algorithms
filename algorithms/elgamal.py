"""
Exercice 3.3 — Cryptosystème ElGamal
======================================
Implémentation complète : génération de clés, chiffrement/déchiffrement,
démonstration du non-déterminisme, malléabilité, et comparaison RSA vs ElGamal.
Affichage détaillé étape par étape (log_step / log_matrix) comme DES.
"""

import random
import secrets
import time
from math import gcd

# ─────────────────────────────────────────────────────────────────────────────
# Utilitaires arithmétiques
# ─────────────────────────────────────────────────────────────────────────────

def is_prime_miller_rabin(n: int, k: int = 20) -> bool:
    """Test de primalité de Miller-Rabin (probabiliste, k tours)."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))
        candidate |= 1
        if is_prime_miller_rabin(candidate):
            return candidate


def generate_safe_prime(bits: int, log_step=None):
    if log_step:
        log_step(f"  [Recherche d'un premier sûr p = 2q+1 de {bits} bits...]")
    attempts = 0
    while True:
        attempts += 1
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if is_prime_miller_rabin(p):
            if log_step:
                log_step(f"  [Trouvé en {attempts} tentative(s)]")
            return p, q


def find_generator(p: int, q: int) -> int:
    while True:
        g = random.randrange(2, p - 1)
        if pow(g, q, p) == 1 and pow(g, 2, p) != 1:
            return g


def modinv(a: int, m: int) -> int:
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Pas d'inverse modulaire pour {a} mod {m}")
    return x % m


def extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _short(n: int, max_digits: int = 30) -> str:
    """Raccourcit un grand entier pour l'affichage."""
    s = str(n)
    if len(s) <= max_digits:
        return s
    return s[:12] + "..." + s[-12:] + f"  [{len(s)} chiffres]"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Génération de clés ElGamal
# ─────────────────────────────────────────────────────────────────────────────

def elgamal_keygen(bits: int = 512, log_step=None, log_matrix=None):
    """
    Génère une paire de clés ElGamal avec affichage détaillé.

    Clé publique  : (p, g, y)  avec y = g^x mod p
    Clé privée    : x
    """
    if log_step:
        log_step("╔══════════════════════════════════════════════╗")
        log_step(f"║   ÉLGAMAL — GÉNÉRATION DE CLÉS ({bits} bits)   ║")
        log_step("╚══════════════════════════════════════════════╝")
        log_step("")
        log_step("  ── Étape 1 : Choisir un premier sûr p = 2q+1 ──")

    t0 = time.time()
    p, q = generate_safe_prime(bits, log_step)

    if log_step:
        log_step(f"  ✅ p = {_short(p)}")
        log_step(f"  ✅ q = {_short(q)}  (q = (p-1)/2)")
        log_step("")
        log_step("  ── Étape 2 : Trouver un générateur g d'ordre q ──")
        log_step("  Condition : g^q ≡ 1 (mod p)  ET  g ≠ 1")

    g = find_generator(p, q)

    if log_step:
        log_step(f"  ✅ g = {_short(g)}")
        log_step(f"  Vérif : g^q mod p = {pow(g, q, p)}  (attendu : 1) ✓")
        log_step("")
        log_step("  ── Étape 3 : Clé privée x ─────────────────────")
        log_step("  x choisi aléatoirement dans [2, q-1]")

    x = secrets.randbelow(q - 2) + 2

    if log_step:
        log_step(f"  x (privé) = {_short(x)}")
        log_step("")
        log_step("  ── Étape 4 : Clé publique y = g^x mod p ────────")

    y = pow(g, x, p)

    elapsed = time.time() - t0

    if log_step:
        log_step(f"  Calcul : g^x mod p")
        log_step(f"    g = {_short(g)}")
        log_step(f"    x = {_short(x)}")
        log_step(f"    p = {_short(p)}")
        log_step(f"  ✅ y = {_short(y)}")
        log_step("")
        log_step("  ── Résumé des clés ─────────────────────────────")
        log_step(f"  Clé publique  : (p, g, y)")
        log_step(f"    p = {_short(p)}")
        log_step(f"    g = {_short(g)}")
        log_step(f"    y = {_short(y)}")
        log_step(f"  Clé privée    : x = {_short(x)}")
        log_step(f"  Temps de génération : {elapsed:.3f}s")

    if log_matrix:
        log_matrix("CLÉ PUBLIQUE (p, g, y) — premiers octets de p",
                   list(p.to_bytes((p.bit_length() + 7) // 8, 'big')[:8]))

    return {"p": p, "q": q, "g": g, "y": y, "x": x}


# ─────────────────────────────────────────────────────────────────────────────
# 2. Chiffrement ElGamal
# ─────────────────────────────────────────────────────────────────────────────

def elgamal_encrypt(M: int, pub: dict,
                    log_step=None, log_matrix=None) -> tuple:
    """
    Chiffre le message M < p.

    Algorithme :
      1. Choisir k aléatoire dans [2, q-1]
      2. C1 = g^k mod p
      3. C2 = M · y^k mod p
    """
    p, g, y, q = pub["p"], pub["g"], pub["y"], pub["q"]
    assert 0 < M < p, "Le message M doit satisfaire 0 < M < p"

    if log_step:
        log_step("╔══════════════════════════════════════════════╗")
        log_step("║          ÉLGAMAL — CHIFFREMENT               ║")
        log_step("╚══════════════════════════════════════════════╝")
        log_step("")
        log_step("  ── Entrée ────────────────────────────────────")
        log_step(f"  Message M  = {_short(M)}")
        log_step(f"  p          = {_short(p)}")
        log_step(f"  g          = {_short(g)}")
        log_step(f"  y (pub)    = {_short(y)}")
        log_step("")
        log_step("  ── Étape 1 : Choisir l'éphémère k ───────────")
        log_step("  k aléatoire dans [2, q-1]  (différent à chaque appel)")

    k = secrets.randbelow(q - 2) + 2

    if log_step:
        log_step(f"  k = {_short(k)}")

    if log_step:
        log_step("")
        log_step("  ── Étape 2 : C1 = g^k mod p ─────────────────")
        log_step(f"  Calcul : {_short(g)}^k mod p")

    C1 = pow(g, k, p)

    if log_step:
        log_step(f"  ✅ C1 = {_short(C1)}")
        log_step("")
        log_step("  ── Étape 3 : Secret partagé s = y^k mod p ───")
        log_step(f"  y = g^x (clé publique), k éphémère")
        log_step(f"  s = y^k = g^(xk) mod p")

    s = pow(y, k, p)

    if log_step:
        log_step(f"  ✅ s = y^k mod p = {_short(s)}")
        log_step("")
        log_step("  ── Étape 4 : C2 = M · s mod p ───────────────")
        log_step(f"  M = {_short(M)}")
        log_step(f"  s = {_short(s)}")
        log_step(f"  C2 = (M × s) mod p")

    C2 = (M * s) % p

    if log_step:
        log_step(f"  ✅ C2 = {_short(C2)}")
        log_step("")
        log_step("  ── Résultat du chiffrement ───────────────────")
        log_step(f"  Chiffré = (C1, C2)")
        log_step(f"    C1 = {_short(C1)}")
        log_step(f"    C2 = {_short(C2)}")
        log_step("")
        log_step("  ➤ Non-déterminisme : k différent → (C1,C2) différents")
        log_step("    même si M est identique !")

    if log_matrix:
        nb = (p.bit_length() + 7) // 8
        log_matrix("C1 — premiers octets",
                   list(C1.to_bytes(nb, 'big')[:8]))
        log_matrix("C2 — premiers octets",
                   list(C2.to_bytes(nb, 'big')[:8]))

    return C1, C2


# ─────────────────────────────────────────────────────────────────────────────
# 3. Déchiffrement ElGamal
# ─────────────────────────────────────────────────────────────────────────────

def elgamal_decrypt(C1: int, C2: int, priv: dict,
                    log_step=None, log_matrix=None) -> int:
    """
    Déchiffre (C1, C2).

    Algorithme :
      s  = C1^x mod p   (secret partagé reconstruit)
      M  = C2 · s^(-1) mod p
    """
    p, x = priv["p"], priv["x"]

    if log_step:
        log_step("╔══════════════════════════════════════════════╗")
        log_step("║         ÉLGAMAL — DÉCHIFFREMENT              ║")
        log_step("╚══════════════════════════════════════════════╝")
        log_step("")
        log_step("  ── Entrée ────────────────────────────────────")
        log_step(f"  C1 = {_short(C1)}")
        log_step(f"  C2 = {_short(C2)}")
        log_step(f"  x  (privé) = {_short(x)}")
        log_step("")
        log_step("  ── Étape 1 : Reconstruire s = C1^x mod p ────")
        log_step("  C1 = g^k  →  C1^x = g^(kx) = (g^x)^k = y^k = s")
        log_step(f"  Calcul : {_short(C1)}^x mod p")

    s = pow(C1, x, p)

    if log_step:
        log_step(f"  ✅ s = {_short(s)}")
        log_step("")
        log_step("  ── Étape 2 : Inverse de s modulo p ──────────")
        log_step("  s_inv = s^(-1) mod p  (via algorithme d'Euclide étendu)")

    s_inv = modinv(s, p)

    if log_step:
        log_step(f"  ✅ s_inv = {_short(s_inv)}")
        log_step(f"  Vérif : (s × s_inv) mod p = {(s * s_inv) % p}  (attendu : 1) ✓")
        log_step("")
        log_step("  ── Étape 3 : M = C2 · s_inv mod p ──────────")
        log_step(f"  C2     = M · y^k  →  C2 × s_inv = M × y^k × y^(-k) = M")
        log_step(f"  C2     = {_short(C2)}")
        log_step(f"  s_inv  = {_short(s_inv)}")
        log_step(f"  M = (C2 × s_inv) mod p")

    M = (C2 * s_inv) % p

    if log_step:
        log_step(f"  ✅ M déchiffré = {_short(M)}")

    if log_matrix:
        nb = (p.bit_length() + 7) // 8
        log_matrix("M déchiffré — premiers octets",
                   list(M.to_bytes(nb, 'big')[:8]))

    return M


# ─────────────────────────────────────────────────────────────────────────────
# 4. Démonstration non-déterminisme
# ─────────────────────────────────────────────────────────────────────────────

def demo_chiffrement(keys: dict, log_step=None, log_matrix=None):
    M = 12345
    pub  = {k: keys[k] for k in ("p", "q", "g", "y")}
    priv = {"p": keys["p"], "x": keys["x"]}

    if log_step:
        log_step("╔══════════════════════════════════════════════╗")
        log_step("║     DÉMONSTRATION NON-DÉTERMINISME           ║")
        log_step("╚══════════════════════════════════════════════╝")
        log_step(f"  Message M = {M}")
        log_step("")
        log_step("  ════ Chiffrement 1 ════════════════════════")

    C1a, C2a = elgamal_encrypt(M, pub, log_step, log_matrix)
    dec_a    = elgamal_decrypt(C1a, C2a, priv, log_step, log_matrix)

    if log_step:
        log_step("")
        log_step("  ════ Chiffrement 2 (même M) ════════════════")

    C1b, C2b = elgamal_encrypt(M, pub, log_step, log_matrix)
    dec_b    = elgamal_decrypt(C1b, C2b, priv, log_step, log_matrix)

    if log_step:
        log_step("")
        log_step("  ── Comparaison ───────────────────────────────")
        log_step(f"  C1a == C1b ? {C1a == C1b}  (attendu : False)")
        log_step(f"  C2a == C2b ? {C2a == C2b}  (attendu : False)")
        log_step(f"  D(E1(M)) = {dec_a}  {'✓' if dec_a == M else '✗'}")
        log_step(f"  D(E2(M)) = {dec_b}  {'✓' if dec_b == M else '✗'}")
        log_step("")
        log_step("  ➤ Deux chiffrés différents pour le même message")
        log_step("  ➤ ElGamal est IND-CPA (sémantiquement sûr)")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Malléabilité multiplicative
# ─────────────────────────────────────────────────────────────────────────────

def demo_malleabilite(keys: dict, log_step=None, log_matrix=None):
    p    = keys["p"]
    pub  = {k: keys[k] for k in ("p", "q", "g", "y")}
    priv = {"p": keys["p"], "x": keys["x"]}

    if log_step:
        log_step("╔══════════════════════════════════════════════╗")
        log_step("║       MALLÉABILITÉ MULTIPLICATIVE            ║")
        log_step("╚══════════════════════════════════════════════╝")
        log_step("")
        log_step("  Propriété : E(M1) ⊗ E(M2) = E(M1·M2 mod p)")
        log_step("  Formule   : (C1_1·C1_2, C2_1·C2_2) mod p")

    M1, M2 = 100, 200
    M1_M2  = (M1 * M2) % p

    if log_step:
        log_step("")
        log_step(f"  M1 = {M1}   M2 = {M2}   M1·M2 mod p = {M1_M2}")
        log_step("")
        log_step("  ── Chiffrement de M1 ─────────────────────────")

    C1_1, C2_1 = elgamal_encrypt(M1, pub, log_step, log_matrix)

    if log_step:
        log_step("")
        log_step("  ── Chiffrement de M2 ─────────────────────────")

    C1_2, C2_2 = elgamal_encrypt(M2, pub, log_step, log_matrix)

    if log_step:
        log_step("")
        log_step("  ── Forge : produit des chiffrés ──────────────")
        log_step(f"  C1_prod = (C1_1 × C1_2) mod p")
        log_step(f"  C2_prod = (C2_1 × C2_2) mod p")

    C1_prod = (C1_1 * C1_2) % p
    C2_prod = (C2_1 * C2_2) % p

    if log_step:
        log_step(f"  C1_prod = {_short(C1_prod)}")
        log_step(f"  C2_prod = {_short(C2_prod)}")
        log_step("")
        log_step("  ── Déchiffrement du produit ──────────────────")

    dec_prod = elgamal_decrypt(C1_prod, C2_prod, priv, log_step, log_matrix)

    if log_step:
        log_step("")
        log_step(f"  Résultat déchiffré      = {dec_prod}")
        log_step(f"  Attendu (M1·M2 mod p)  = {M1_M2}")
        log_step(f"  {'✅ Malléabilité vérifiée !' if dec_prod == M1_M2 else '✗ Erreur !'}")
        log_step("")
        log_step("  ── Forge de E(2M) depuis E(M) ────────────────")
        log_step("  L'attaquant modifie C2 → 2·C2 sans connaître M ni x")

    M_orig = 12345

    if log_step:
        log_step(f"  M_orig = {M_orig}")

    C1, C2 = elgamal_encrypt(M_orig, pub, log_step, log_matrix)

    C2_forged = (2 * C2) % p

    if log_step:
        log_step(f"  C2 original = {_short(C2)}")
        log_step(f"  C2 forgé    = 2 × C2 mod p = {_short(C2_forged)}")
        log_step("")
        log_step("  ── Déchiffrement du chiffré forgé ────────────")

    dec_forged = elgamal_decrypt(C1, C2_forged, priv, log_step, log_matrix)

    if log_step:
        log_step("")
        log_step(f"  M attendu (2·M) = {(2 * M_orig) % p}")
        log_step(f"  M obtenu        = {dec_forged}")
        log_step(f"  {'✅ Forge réussie !' if dec_forged == (2 * M_orig) % p else '✗ Erreur !'}")
        log_step("")
        log_step("  ── Explication ───────────────────────────────")
        log_step("  E(M) = (g^k, M·y^k)  →  forgé = (g^k, 2·M·y^k)")
        log_step("  Déchiffrement : s = (g^k)^x = y^k")
        log_step("  M' = (2·M·y^k) / y^k = 2·M  ✓")
        log_step("")
        log_step("  ➤ ElGamal N'EST PAS IND-CCA2 (malléable)")
        log_step("  ➤ Solution : utiliser ECIES ou ajouter un MAC")


# ─────────────────────────────────────────────────────────────────────────────
# 6. Comparaison RSA vs ElGamal
# ─────────────────────────────────────────────────────────────────────────────

def demo_comparaison_tailles(log_step=None):
    bits  = 2048
    octets = bits // 8

    if log_step:
        log_step("╔══════════════════════════════════════════════╗")
        log_step("║   COMPARAISON TAILLES : RSA-2048 vs ElGamal  ║")
        log_step("╚══════════════════════════════════════════════╝")
        log_step("")
        log_step(f"  {'Paramètre':<25} {'RSA-2048':<20} {'ElGamal-2048'}")
        log_step(f"  {'─'*65}")
        log_step(f"  {'Clé publique':<25} {octets} octets         3×{octets}={3*octets} o  (p,g,y)")
        log_step(f"  {'Clé privée':<25} {octets} octets         {octets} octets")
        log_step(f"  {'Taille chiffré':<25} {octets} octets         2×{octets}={2*octets} o  (C1,C2)")
        log_step(f"  {'Expansion message':<25} ×1                   ×2  (overhead doublé)")
        log_step(f"  {'Déterminisme':<25} Oui (PKCS#1 v1.5)    Non (k éphémère)")
        log_step(f"  {'Sécurité sémantique':<25} Non (sans OAEP)      Oui (IND-CPA)")
        log_step(f"  {'Malléabilité':<25} Non (avec OAEP)      Oui (sans MAC)")
        log_step(f"  {'Opérations chiffr.':<25} 1 exp. mod           2 exp. mod")
        log_step(f"  {'─'*65}")
        log_step("")
        log_step("  ── Implications pratiques ────────────────────")
        log_step("  1. BANDE PASSANTE : ElGamal double la taille des données.")
        log_step("     → En pratique : chiffrement hybride (ElGamal+AES).")
        log_step("")
        log_step("  2. PERFORMANCE :")
        log_step("     • RSA chiffrement : rapide (e=65537 petit)")
        log_step("     • ElGamal chiffrement : 2 exponentiations → plus lent")
        log_step("     • Déchiffrement : comparable (1 expo chacun)")
        log_step("")
        log_step("  3. SÉCURITÉ SÉMANTIQUE :")
        log_step("     • ElGamal : IND-CPA par construction (k aléatoire)")
        log_step("     • RSA-PKCS#1 v1.5 : non sémantiquement sûr → OAEP requis")
        log_step("")
        log_step("  4. USAGE MODERNE :")
        log_step("     • ElGamal → base de DSA, Cramer-Shoup")
        log_step("     • ECC (ECDH+ECIES) remplace ElGamal :")
        log_step("       ECC-256 ≈ ElGamal-3072, mais clés 10× plus petites")


# ─────────────────────────────────────────────────────────────────────────────
# CLASSE ELGAMALALGORITHM (interface main.py)
# ─────────────────────────────────────────────────────────────────────────────

class ElGamalAlgorithm:
    def __init__(self):
        self._keys = None

    def get_name(self):
        return "ElGamal (Chiffrement)"

    def get_description(self):
        return (
            "ElGamal — Chiffrement asymétrique basé sur le logarithme discret\n"
            "• Sécurité : DLP (Logarithme Discret)\n"
            "• Clé publique : (p, g, y) | Clé privée : x\n"
            "• Propriété : non-déterministe (k éphémère aléatoire)\n"
            "• Défaut : malléable (nécessite un MAC)\n"
            "• Format clé : 'gen' pour générer | 'bits:512'"
        )

    def get_key_info(self):
        return {
            "type": "asymmetric",
            "placeholder": "'gen' ou 'bits:512'"
        }

    # ──────────────────────────────────────────────────────────────
    # ENCRYPT
    # ──────────────────────────────────────────────────────────────

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:

        key_lower = str(key).strip().lower()

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║          ÉLGAMAL — INTERFACE ENCRYPT         ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Texte clair  : '{text}'")
            log_step(f"  Clé brute    : '{key}'")

        # ── Génération de clés ──────────────────────────────────
        if key_lower == "gen" or key_lower.startswith("bits:"):
            bits = 512
            if key_lower.startswith("bits:"):
                try:
                    bits = int(key_lower.split(":")[1])
                except ValueError:
                    pass
            if log_step:
                log_step(f"  Mode         : Génération de clés ({bits} bits)")
            self._keys = elgamal_keygen(bits, log_step, log_matrix)
            pub = self._keys
            return (
                f"PUBLIC_KEY:{pub['p']},{pub['g']},{pub['y']}"
                f"|PRIVATE_KEY:{pub['x']}"
            )

        # ── Chiffrement du message ──────────────────────────────
        if self._keys is None:
            raise ValueError("Générez d'abord des clés avec 'gen'")

        data = text.encode("utf-8")

        if log_step:
            log_step(f"  Taille texte : {len(data)} octet(s)")

        if log_matrix:
            log_matrix("TEXTE CLAIR (bytes)",
                       list(data[:8].ljust(8, b'\x00')))

        pub = {k: self._keys[k] for k in ("p", "q", "g", "y")}

        # Chiffrement hybride si message > 64 octets
        if len(data) > 64:
            return self._hybrid_encrypt(text, log_step, log_matrix)

        M = int.from_bytes(data, 'big')

        if log_step:
            log_step(f"  Message (int): {_short(M)}")

        C1, C2 = elgamal_encrypt(M, pub, log_step, log_matrix)

        if log_step:
            log_step("")
            log_step("  ── Résultat final ────────────────────────────")
            log_step(f"  C1 = {_short(C1)}")
            log_step(f"  C2 = {_short(C2)}")

        return f"C1:{C1}|C2:{C2}"

    # ──────────────────────────────────────────────────────────────
    # DECRYPT
    # ──────────────────────────────────────────────────────────────

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:

        if self._keys is None:
            if "PUBLIC_KEY" in text:
                return "Veuillez d'abord générer des clés avec 'gen'"
            raise ValueError("Aucune clé disponible.")

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║         ÉLGAMAL — INTERFACE DECRYPT          ║")
            log_step("╚══════════════════════════════════════════════╝")

        priv = {"p": self._keys["p"], "x": self._keys["x"]}

        # Chiffrement hybride
        if "NONCE:" in text:
            return self._hybrid_decrypt(text, log_step)

        if "|" not in text:
            raise ValueError("Format de chiffré invalide")

        parts  = text.split("|")
        C1_str = parts[0].replace("C1:", "")
        C2_str = parts[1].replace("C2:", "")
        C1, C2 = int(C1_str), int(C2_str)

        if log_step:
            log_step(f"  C1 = {_short(C1)}")
            log_step(f"  C2 = {_short(C2)}")

        M       = elgamal_decrypt(C1, C2, priv, log_step, log_matrix)
        M_bytes = M.to_bytes((M.bit_length() + 7) // 8, 'big')

        result = M_bytes.decode("utf-8", errors="replace")

        if log_step:
            log_step("")
            log_step("  ── Résultat final ────────────────────────────")
            log_step(f"  Texte clair déchiffré : '{result}'")

        if log_matrix:
            log_matrix("MESSAGE DÉCHIFFRÉ (bytes)", list(M_bytes[:8]))

        return result

    # ──────────────────────────────────────────────────────────────
    # Chiffrement hybride ElGamal + AES-GCM
    # ──────────────────────────────────────────────────────────────

    def _hybrid_encrypt(self, text: str,
                        log_step=None, log_matrix=None) -> str:
        import os
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if log_step:
            log_step("")
            log_step("  ── Chiffrement hybride (message > 64 octets) ─")
            log_step("  1. Générer clé AES-256 aléatoire")

        aes_key = os.urandom(32)
        nonce   = os.urandom(12)

        if log_step:
            log_step(f"  AES key = {aes_key.hex()}")
            log_step(f"  nonce   = {nonce.hex()}")
            log_step("  2. Chiffrer le message avec AES-GCM")

        aesgcm     = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, text.encode("utf-8"), None)

        if log_step:
            log_step("  3. Chiffrer la clé AES avec ElGamal")

        aes_key_int = int.from_bytes(aes_key, 'big')
        pub         = {k: self._keys[k] for k in ("p", "q", "g", "y")}
        C1, C2      = elgamal_encrypt(aes_key_int, pub, log_step, log_matrix)

        return f"C1:{C1}|C2:{C2}|NONCE:{nonce.hex()}|DATA:{ciphertext.hex()}"

    def _hybrid_decrypt(self, text: str, log_step=None) -> str:
        import os
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        parts      = text.split("|")
        C1         = int(parts[0].replace("C1:", ""))
        C2         = int(parts[1].replace("C2:", ""))
        nonce      = bytes.fromhex(parts[2].replace("NONCE:", ""))
        data       = bytes.fromhex(parts[3].replace("DATA:", ""))
        priv       = {"p": self._keys["p"], "x": self._keys["x"]}

        if log_step:
            log_step("  ── Déchiffrement hybride ─────────────────────")
            log_step("  1. Déchiffrer la clé AES avec ElGamal")

        aes_key_int = elgamal_decrypt(C1, C2, priv, log_step)
        aes_key     = aes_key_int.to_bytes(32, 'big')

        if log_step:
            log_step(f"  AES key récupérée = {aes_key.hex()}")
            log_step("  2. Déchiffrer le message avec AES-GCM")

        aesgcm = AESGCM(aes_key)
        plain  = aesgcm.decrypt(nonce, data, None)
        return plain.decode("utf-8", errors="replace")


# ─────────────────────────────────────────────────────────────────────────────
# PROGRAMME PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # Adaptateur simple pour afficher les étapes dans le terminal
    def log_step(msg: str):
        print(msg)

    def log_matrix(label: str, data: list):
        print(f"\n  [MATRICE] {label}")
        print("  " + " ".join(f"{b:02X}" for b in data))
        print()

    BITS = 512
    print("\n" + "█" * 60)
    print("  EXERCICE 3.3 — CRYPTOSYSTÈME ELGAMAL (DÉTAILLÉ)")
    print("█" * 60)
    print(f"\n  Note : {BITS} bits pour la démo (production : 2048+ bits NIST)")

    keys = elgamal_keygen(BITS, log_step, log_matrix)
    demo_chiffrement(keys, log_step, log_matrix)
    demo_malleabilite(keys, log_step, log_matrix)
    demo_comparaison_tailles(log_step)

    print("\n" + "█" * 60)
    print("  FIN DE L'EXERCICE 3.3")
    print("█" * 60 + "\n")


if __name__ == "__main__":
    main()