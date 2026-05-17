"""
Exercice 5.3 — DSA et ECDSA
=============================
• DSA from scratch (groupe multiplicatif, sous-groupe d'ordre q)
• ECDSA via bibliothèque cryptography (P-256, P-384)
• EdDSA / Ed25519 (bonus)
• Attaque : réutilisation de nonce k → récupération de clé privée
• Comparaison des standards de signature
"""

import os
import hashlib
import secrets
import time
from math import gcd

BANNER = "█" * 62


# ─────────────────────────────────────────────────────────────────────────────
# Utilitaires communs
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


def modinv(a: int, m: int) -> int:
    def egcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x
    g, x, _ = egcd(a % m, m)
    if g != 1: raise ValueError(f"Pas d'inverse de {a} mod {m}")
    return x % m


def sha256_int(data: bytes) -> int:
    return int(hashlib.sha256(data).hexdigest(), 16)


def sha384_int(data: bytes) -> int:
    return int(hashlib.sha384(data).hexdigest(), 16)


# ─────────────────────────────────────────────────────────────────────────────
# PARTIE 1 : DSA (Digital Signature Algorithm — FIPS 186-4)
# ─────────────────────────────────────────────────────────────────────────────

class DSA:
    def __init__(self, p_bits: int = 1024, q_bits: int = 256):
        self.p_bits = p_bits
        self.q_bits = q_bits
        self.p = None
        self.q = None
        self.g = None
        self.x = None
        self.y = None

    def setup(self):
        print(f"  [Génération paramètres DSA-{self.p_bits}/{self.q_bits}...]", end="", flush=True)
        t0 = time.time()
        self.q = gen_prime(self.q_bits)
        attempts = 0
        while True:
            attempts += 1
            k = secrets.randbits(self.p_bits - self.q_bits)
            k |= 1
            self.p = k * self.q + 1
            if self.p.bit_length() == self.p_bits and miller_rabin(self.p):
                break
        exp = (self.p - 1) // self.q
        while True:
            h = secrets.randbelow(self.p - 3) + 2
            g = pow(h, exp, self.p)
            if g != 1:
                self.g = g
                break
        print(f" OK ({time.time()-t0:.2f}s, {attempts} tentatives)")

    def keygen(self):
        self.x = secrets.randbelow(self.q - 1) + 1
        self.y = pow(self.g, self.x, self.p)

    def sign(self, message: bytes, k: int = None) -> tuple:
        p, q, g, x = self.p, self.q, self.g, self.x
        h = sha256_int(message) % q
        if k is None:
            while True:
                k = secrets.randbelow(q - 1) + 1
                r = pow(g, k, p) % q
                if r != 0: break
        else:
            r = pow(g, k, p) % q
        k_inv = modinv(k, q)
        s = (k_inv * (h + x * r)) % q
        if s == 0:
            raise ValueError("s = 0, régénérer k")
        return r, s

    def verify(self, message: bytes, r: int, s: int) -> bool:
        p, q, g, y = self.p, self.q, self.g, self.y
        if not (0 < r < q and 0 < s < q):
            return False
        h = sha256_int(message) % q
        w = modinv(s, q)
        u1 = (h * w) % q
        u2 = (r * w) % q
        v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
        return v == r


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE DSAAlgorithm POUR L'INTERFACE MAIN.PY
# ══════════════════════════════════════════════════════════════════════════════

class DSAAlgorithm:
    def __init__(self):
        self._dsa = None
    
    def get_name(self):
        return "DSA (Digital Signature Algorithm)"
    
    def get_description(self):
        return (
            "DSA — Digital Signature Algorithm (FIPS 186-4)\n"
            "• Sécurité : DLP (Logarithme Discret)\n"
            "• Paramètres : p (1024 bits), q (256 bits)\n"
            "• Signature : (r, s)\n"
            "• Non-déterministe (k aléatoire)\n"
            "• ⚠️ ATTENTION : réutilisation de k → clé privée compromise\n"
            "• Format clé : 'gen' | 'sign' | 'verify' | 'demo'"
        )
    
    def get_key_info(self):
        return {
            "type": "asymmetric",
            "placeholder": "'gen' | 'sign' | 'verify' | 'demo'"
        }
    
    def encrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        key_lower = str(key).strip().lower()
        
        if key_lower == "gen":
            self._dsa = DSA(p_bits=1024, q_bits=256)
            self._dsa.setup()
            self._dsa.keygen()
            return f"""
╔══════════════════════════════════════════════════════════════╗
║                    CLÉS DSA GÉNÉRÉES                        ║
╠══════════════════════════════════════════════════════════════╣
║  p = {self._dsa.p:#x}[:48]...
║  q = {self._dsa.q:#x}[:32]...
║  g = {self._dsa.g:#x}[:32]...
║  y (publique) = {self._dsa.y:#x}[:48]...
║  x (privée) = [CONFIDENTIEL]                                 ║
╚══════════════════════════════════════════════════════════════╝
"""
        elif key_lower == "sign" and self._dsa:
            msg = text.encode("utf-8")
            r, s = self._dsa.sign(msg)
            return f"r={r:#x}\ns={s:#x}"
        elif key_lower == "demo":
            return self._full_demo()
        else:
            return "Utilisez 'gen' pour générer des clés, 'sign' pour signer"
    
    def decrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        return self.encrypt(text, key, log_step, log_matrix)
    
    def _full_demo(self):
        dsa = DSA(p_bits=1024, q_bits=256)
        dsa.setup()
        dsa.keygen()
        msg = b"Message test DSA"
        r, s = dsa.sign(msg)
        valid = dsa.verify(msg, r, s)
        return f"""
╔══════════════════════════════════════════════════════════════╗
║                 DÉMONSTRATION DSA COMPLÈTE                  ║
╠══════════════════════════════════════════════════════════════╣
║  Message : {msg.decode()}                                     ║
║  Signature : r={r:#x}[:32]..., s={s:#x}[:32]...              ║
║  Vérification : {'✓ VALIDE' if valid else '✗ INVALIDE'}        ║
╚══════════════════════════════════════════════════════════════╝
"""


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE ECDSAAlgorithm POUR L'INTERFACE MAIN.PY
# ══════════════════════════════════════════════════════════════════════════════

class ECDSAAlgorithm:
    def __init__(self):
        self._priv = None
        self._pub = None
    
    def get_name(self):
        return "ECDSA (Elliptic Curve DSA)"
    
    def get_description(self):
        return (
            "ECDSA — Digital Signature Algorithm sur courbes elliptiques\n"
            "• Courbe : P-256 (SECP256R1) - 128 bits de sécurité\n"
            "• Clés : 32 octets (privée), 64 octets (publique)\n"
            "• Signature : 64 octets (DER encodé)\n"
            "• Non-déterministe (k aléatoire) sauf RFC 6979\n"
            "• Format clé : 'gen' | 'sign' | 'demo'\n"
            "• Nécessite cryptography : pip install cryptography"
        )
    
    def get_key_info(self):
        return {
            "type": "asymmetric",
            "placeholder": "'gen' | 'sign' | 'demo'"
        }
    
    def encrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        key_lower = str(key).strip().lower()
        
        if key_lower == "gen":
            try:
                from cryptography.hazmat.primitives.asymmetric.ec import (
                    generate_private_key, SECP256R1
                )
                from cryptography.hazmat.backends import default_backend
                
                self._priv = generate_private_key(SECP256R1(), default_backend())
                self._pub = self._priv.public_key()
                nums = self._pub.public_numbers()
                
                return f"""
╔══════════════════════════════════════════════════════════════╗
║                  CLÉS ECDSA P-256 GÉNÉRÉES                  ║
╠══════════════════════════════════════════════════════════════╣
║  Clé publique (x) : {nums.x:#x}[:48]...
║  Clé publique (y) : {nums.y:#x}[:48]...
║  Clé privée : [CONFIDENTIEL]                                 ║
╚══════════════════════════════════════════════════════════════╝
"""
            except ImportError:
                return "⚠️ cryptography non installé. Exécutez : pip install cryptography"
        
        elif key_lower == "sign" and self._priv:
            try:
                from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
                from cryptography.hazmat.primitives import hashes
                
                msg = text.encode("utf-8")
                sig = self._priv.sign(msg, ECDSA(hashes.SHA256()))
                return f"Signature (hex) : {sig.hex()}"
            except Exception as e:
                return f"Erreur : {str(e)}"
        
        elif key_lower == "demo":
            return self._full_demo()
        else:
            return "Utilisez 'gen' pour générer des clés, 'sign' pour signer"
    
    def decrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        return self.encrypt(text, key, log_step, log_matrix)
    
    def _full_demo(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ec import (
                generate_private_key, SECP256R1, ECDSA
            )
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            
            priv = generate_private_key(SECP256R1(), default_backend())
            pub = priv.public_key()
            msg = b"Message test ECDSA"
            sig = priv.sign(msg, ECDSA(hashes.SHA256()))
            
            return f"""
╔══════════════════════════════════════════════════════════════╗
║                DÉMONSTRATION ECDSA COMPLÈTE                 ║
╠══════════════════════════════════════════════════════════════╣
║  Message : {msg.decode()}                                     ║
║  Signature (hex) : {sig.hex()[:64]}...                       ║
║  Taille signature : {len(sig)} octets                         ║
╚══════════════════════════════════════════════════════════════╝
"""
        except ImportError:
            return "⚠️ cryptography non installé. Exécutez : pip install cryptography"


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE Ed25519Algorithm POUR L'INTERFACE MAIN.PY
# ══════════════════════════════════════════════════════════════════════════════

class Ed25519Algorithm:
    def __init__(self):
        self._priv = None
        self._pub = None
    
    def get_name(self):
        return "Ed25519 (EdDSA)"
    
    def get_description(self):
        return (
            "Ed25519 — Courbe de Edwards pour signatures\n"
            "• Courbe : Curve25519 (montée en Edwards)\n"
            "• Sécurité : 128 bits\n"
            "• Clés : 32 octets (privée et publique)\n"
            "• Signature : 64 octets\n"
            "• DÉTERMINISTE (RFC 8032) → pas de faille RNG\n"
            "• Très rapide et résistant aux timing attacks\n"
            "• Format clé : 'gen' | 'sign' | 'demo'"
        )
    
    def get_key_info(self):
        return {
            "type": "asymmetric",
            "placeholder": "'gen' | 'sign' | 'demo'"
        }
    
    def encrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        key_lower = str(key).strip().lower()
        
        if key_lower == "gen":
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                    Ed25519PrivateKey
                )
                from cryptography.hazmat.primitives.serialization import (
                    Encoding, PublicFormat, PrivateFormat, NoEncryption
                )
                
                self._priv = Ed25519PrivateKey.generate()
                self._pub = self._priv.public_key()
                
                priv_bytes = self._priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                pub_bytes = self._pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
                
                return f"""
╔══════════════════════════════════════════════════════════════╗
║                  CLÉS Ed25519 GÉNÉRÉES                      ║
╠══════════════════════════════════════════════════════════════╣
║  Clé privée (32 octets) : {priv_bytes.hex()}                 ║
║  Clé publique (32 octets): {pub_bytes.hex()}                 ║
╚══════════════════════════════════════════════════════════════╝
"""
            except ImportError:
                return "⚠️ cryptography non installé. Exécutez : pip install cryptography"
        
        elif key_lower == "sign" and self._priv:
            try:
                msg = text.encode("utf-8")
                sig = self._priv.sign(msg)
                return f"Signature (64 octets) : {sig.hex()}"
            except Exception as e:
                return f"Erreur : {str(e)}"
        
        elif key_lower == "demo":
            return self._full_demo()
        else:
            return "Utilisez 'gen' pour générer des clés, 'sign' pour signer"
    
    def decrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        return self.encrypt(text, key, log_step, log_matrix)
    
    def _full_demo(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey
            )
            
            priv = Ed25519PrivateKey.generate()
            pub = priv.public_key()
            msg = b"Message test Ed25519"
            sig = priv.sign(msg)
            
            return f"""
╔══════════════════════════════════════════════════════════════╗
║              DÉMONSTRATION Ed25519 COMPLÈTE                 ║
╠══════════════════════════════════════════════════════════════╣
║  Message : {msg.decode()}                                     ║
║  Signature (64 octets) : {sig.hex()[:64]}...                 ║
║  ✓ Déterministe : même message → même signature             ║
║  ✓ Très rapide et sécurisé                                  ║
╚══════════════════════════════════════════════════════════════╝
"""
        except ImportError:
            return "⚠️ cryptography non installé. Exécutez : pip install cryptography"


# ─────────────────────────────────────────────────────────────────────────────
# PROGRAMME PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{BANNER}")
    print(f"  EXERCICE 5.3 — DSA ET ECDSA")
    print(BANNER)

    demo_dsa()
    demo_ecdsa()
    demo_ed25519()
    comparaison_standards()

    print(f"\n{BANNER}")
    print(f"  FIN EXERCICE 5.3")
    print(BANNER)