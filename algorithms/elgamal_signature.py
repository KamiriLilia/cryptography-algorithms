"""
Exercice 5.2 — Signature ElGamal
==================================
• Implémentation from scratch (arithmétique modulaire)
• Génération de clés, signature, vérification
• Attaque par réutilisation du nonce k (récupération de la clé privée)
• Attaque par k=0 ou k=1
• Contre-mesures : HMAC-DRBG, k dérivé déterministement (RFC 6979)
"""

import secrets
import hashlib
import time

BANNER = "█" * 62


# ─────────────────────────────────────────────────────────────────────────────
# Utilitaires arithmétiques
# ─────────────────────────────────────────────────────────────────────────────

def miller_rabin(n: int, k: int = 20) -> bool:
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1; d //= 2
    import random
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if miller_rabin(p):
            return p


def gen_safe_prime(bits: int):
    """Génère p = 2q+1 (premier sûr), retourne (p, q)."""
    print(f"  [Recherche d'un premier sûr {bits} bits...]", end="", flush=True)
    att = 0
    while True:
        att += 1
        q = gen_prime(bits - 1)
        p = 2 * q + 1
        if miller_rabin(p):
            print(f" OK ({att} tentatives)")
            return p, q


def find_generator(p: int, q: int) -> int:
    """Générateur d'ordre q dans (Z/pZ)*."""
    while True:
        g = secrets.randbelow(p - 2) + 2
        if pow(g, q, p) == 1 and pow(g, 2, p) != 1:
            return g


def modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError(f"Pas d'inverse de {a} mod {m}")
    return x % m


def _egcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def H(message: bytes) -> int:
    """SHA-256 → entier."""
    return int(hashlib.sha256(message).hexdigest(), 16)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Génération de clés ElGamal pour la signature
# ─────────────────────────────────────────────────────────────────────────────

def elgamal_keygen(bits: int = 512):
    """
    Paramètres publics : (p, q, g)
    Clé privée  : x ∈ [2, q-1]
    Clé publique: y = g^x mod p
    """
    p, q = gen_safe_prime(bits)
    g = find_generator(p, q)
    x = secrets.randbelow(q - 2) + 2
    y = pow(g, x, p)
    return {"p": p, "q": q, "g": g, "x": x, "y": y}


# ─────────────────────────────────────────────────────────────────────────────
# 2. Signature ElGamal
# ─────────────────────────────────────────────────────────────────────────────

def elgamal_sign(message: bytes, keys: dict, k: int = None) -> tuple:
    p, q, g, x = keys["p"], keys["q"], keys["g"], keys["x"]
    p1 = p - 1
    h = H(message)

    if k is None:
        while True:
            k = secrets.randbelow(p1 - 2) + 2
            from math import gcd
            if gcd(k, p1) == 1:
                break

    r = pow(g, k, p)
    k_inv = modinv(k, p1)
    s = (k_inv * (h - x * r)) % p1

    if s == 0:
        raise ValueError("s = 0, régénérer k !")

    return r, s


def elgamal_verify(message: bytes, r: int, s: int, keys: dict) -> bool:
    p, g, y = keys["p"], keys["g"], keys["y"]

    if not (0 < r < p) or s == 0:
        return False

    h = H(message)
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE ElGamalSignatureAlgorithm POUR L'INTERFACE MAIN.PY
# ══════════════════════════════════════════════════════════════════════════════

class ElGamalSignatureAlgorithm:
    def __init__(self):
        self._keys = None
    
    def get_name(self):
        return "ElGamal Signature"
    
    def get_description(self):
        return (
            "ElGamal Signature — Authenticité et intégrité\n"
            "• Principe : basé sur le logarithme discret (DLP)\n"
            "• Signature : (r, s) avec r=g^k mod p, s=k⁻¹(H(M)-x·r) mod (p-1)\n"
            "• Vérification : g^H(M) == y^r · r^s mod p\n"
            "• Non-déterministe (k aléatoire)\n"
            "• ⚠️ ATTENTION : réutilisation de k → clé privée compromise\n"
            "• Format clé : 'gen' pour générer | 'sign' | 'verify' | 'demo'"
        )
    
    def get_key_info(self):
        return {
            "type": "asymmetric",
            "placeholder": "'gen' | 'sign' | 'verify' | 'demo'"
        }
    
    def encrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        key_lower = str(key).strip().lower()
        
        if log_step:
            log_step("✍️ ELGAMAL SIGNATURE — SIMULATION")
            log_step("=" * 42)
        
        if key_lower == "gen":
            return self._generate_keys(log_step)
        elif key_lower == "sign":
            return self._sign_message(text, log_step)
        elif key_lower == "verify":
            return self._verify_signature(text, log_step)
        elif key_lower == "demo":
            return self._full_demo(log_step)
        else:
            return self.get_description()
    
    def decrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        return self.encrypt(text, key, log_step, log_matrix)
    
    def _generate_keys(self, log_step=None):
        """Génère une paire de clés ElGamal signature"""
        try:
            self._keys = elgamal_keygen(512)
            
            result = f"""
╔══════════════════════════════════════════════════════════════╗
║          GÉNÉRATION DE CLÉS ELGAMAL SIGNATURE               ║
╠══════════════════════════════════════════════════════════════╣
║  Paramètres publics :                                        ║
║    p = {self._keys['p']:#x}[:48]...
║    q = {self._keys['q']:#x}[:32]...
║    g = {self._keys['g']:#x}[:32]...
╠══════════════════════════════════════════════════════════════╣
║  Clé publique : y = g^x mod p = {self._keys['y']:#x}[:48]...
║  Clé privée : x = [CONFIDENTIEL]                             ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ Clés générées avec succès !                               ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("✓ Clés ElGamal signature générées")
            
            return result
            
        except Exception as e:
            return f"Erreur lors de la génération : {str(e)}"
    
    def _sign_message(self, text: str, log_step=None):
        """Signe un message"""
        if self._keys is None:
            return "Erreur: Générez d'abord des clés avec 'gen'"
        
        try:
            message = text.encode("utf-8")
            r, s = elgamal_sign(message, self._keys)
            
            result = f"""
╔══════════════════════════════════════════════════════════════╗
║                SIGNATURE ELGAMAL GÉNÉRÉE                     ║
╠══════════════════════════════════════════════════════════════╣
║  Message : {text[:50]}{'...' if len(text) > 50 else ''}                     ║
║  H(M)     : {H(message):#x}[:48]...                          ║
╠══════════════════════════════════════════════════════════════╣
║  Signature :                                                ║
║    r = {r:#x}[:48]...                                       ║
║    s = {s:#x}[:48]...                                       ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ Signature générée avec succès !                          ║
║  ✓ Taille signature : 2×512 bits                            ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("✓ Signature ElGamal générée")
            
            return result
            
        except Exception as e:
            return f"Erreur lors de la signature : {str(e)}"
    
    def _verify_signature(self, text: str, log_step=None):
        """Vérifie une signature (format: message|r|s)"""
        if self._keys is None:
            return "Erreur: Générez d'abord des clés avec 'gen'"
        
        try:
            if "|" not in text:
                return "Format : 'message|r|s'"
            
            parts = text.split("|")
            if len(parts) < 3:
                return "Format : 'message|r|s'"
            
            msg_part = parts[0]
            r = int(parts[1])
            s = int(parts[2])
            message = msg_part.encode("utf-8")
            
            is_valid = elgamal_verify(message, r, s, self._keys)
            
            if is_valid:
                return """
╔══════════════════════════════════════════════════════════════╗
║                  VÉRIFICATION DE SIGNATURE                   ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ SIGNATURE VALIDE !                                        ║
║  ✓ Le message est authentique et n'a pas été modifié        ║
╚══════════════════════════════════════════════════════════════╝
"""
            else:
                return """
╔══════════════════════════════════════════════════════════════╗
║                  VÉRIFICATION DE SIGNATURE                   ║
╠══════════════════════════════════════════════════════════════╣
║  ✗ SIGNATURE INVALIDE !                                      ║
║  ✗ Le message a été modifié ou la signature est fausse       ║
╚══════════════════════════════════════════════════════════════╝
"""
        except Exception as e:
            return f"Erreur lors de la vérification : {str(e)}"
    
    def _full_demo(self, log_step=None):
        """Démonstration complète"""
        try:
            # Génération des clés
            self._keys = elgamal_keygen(512)
            
            # Message à signer
            message = b"Document confidentiel signe par Alice."
            r, s = elgamal_sign(message, self._keys)
            
            # Vérification
            is_valid = elgamal_verify(message, r, s, self._keys)
            
            result = f"""
╔══════════════════════════════════════════════════════════════╗
║           DÉMONSTRATION COMPLÈTE ELGAMAL SIGNATURE          ║
╠══════════════════════════════════════════════════════════════╣
║  Message : {message.decode()}                 ║
║  H(M)     : {H(message):#x}[:48]...                          ║
╠══════════════════════════════════════════════════════════════╣
║  Signature :                                                ║
║    r = {r:#x}[:48]...                                       ║
║    s = {s:#x}[:48]...                                       ║
╠══════════════════════════════════════════════════════════════╣
║  Vérification : {'✓ VALIDE' if is_valid else '✗ INVALIDE'}                    ║
╠══════════════════════════════════════════════════════════════╣
║  Attaques connues :                                          ║
║    • Réutilisation de k → clé privée compromise             ║
║    • k trivial (0 ou 1) → espace de recherche réduit        ║
╠══════════════════════════════════════════════════════════════╣
║  Contre-mesures :                                            ║
║    • RFC 6979 (k déterministe)                              ║
║    • Vérifier pgcd(k, p-1) = 1                              ║
║    • Ne jamais réutiliser k                                 ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("✓ Démonstration ElGamal Signature complète")
            
            return result
            
        except Exception as e:
            return f"Erreur lors de la démonstration : {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
# PROGRAMME PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()