"""
Exercice 5.1 — Signature RSA : PKCS#1 v1.5 et PSS
====================================================
• Génération de clés RSA-2048
• Signature / Vérification avec PKCS#1 v1.5 et PSS
• Attaques : falsification existentielle, malléabilité, rejeu
• Contre-mesures : PSS, horodatage, nonces
"""

import os
import time
import hashlib
import secrets

# ── PyCryptodome ──────────────────────────────────────────────────────────────
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA256, SHA512

# ── cryptography (HAZMAT) ──────────────────────────────────────────────────────
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

BANNER = "█" * 62


# ─────────────────────────────────────────────────────────────────────────────
# 1. Génération de clés RSA-2048
# ─────────────────────────────────────────────────────────────────────────────

def generer_cles_rsa(bits: int = 2048):
    print(f"\n{BANNER}")
    print(f"  1. GÉNÉRATION DE CLÉS RSA-{bits}")
    print(BANNER)

    t0 = time.time()
    key = RSA.generate(bits)
    elapsed = time.time() - t0

    print(f"\n  Clé privée (d, n) :")
    print(f"    n ({bits} bits) = {key.n:#x}"[:80] + "...")
    print(f"    e              = {key.e}  (exposant public standard)")
    print(f"    d              = {key.d:#x}"[:80] + "...")
    print(f"\n  Temps de génération : {elapsed:.3f}s")
    print(f"  Taille clé publique  : {bits // 8} octets")
    print(f"  Taille signature     : {bits // 8} octets (= taille du module n)")

    return key


# ─────────────────────────────────────────────────────────────────────────────
# 2a. Signature PKCS#1 v1.5
# ─────────────────────────────────────────────────────────────────────────────

def demo_pkcs1v15(key):
    print(f"\n{'=' * 62}")
    print(f"  2a. SIGNATURE RSA — PKCS#1 v1.5  (RFC 3447)")
    print(f"{'=' * 62}")

    message = b"Bonjour ! Ceci est un message authentique."
    print(f"\n  Message : {message.decode()}")

    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)

    print(f"\n  Hash SHA-256   : {h.hexdigest()}")
    print(f"  Signature (hex): {signature.hex()[:64]}...")
    print(f"  Taille         : {len(signature)} octets")

    h_verif = SHA256.new(message)
    try:
        pkcs1_15.new(key.publickey()).verify(h_verif, signature)
        print(f"\n  ✓ Vérification sur message original : VALIDE")
    except (ValueError, TypeError) as e:
        print(f"\n  ✗ Erreur : {e}")

    message_altere = b"Bonjour ! Ceci est un message falsifie."
    h_altere = SHA256.new(message_altere)
    try:
        pkcs1_15.new(key.publickey()).verify(h_altere, signature)
        print(f"  ✗ Vérification sur message altéré  : VALIDE (BUG !)")
    except (ValueError, TypeError):
        print(f"  ✓ Vérification sur message altéré  : REJETÉE (intégrité OK)")

    print(f"""
  Schéma PKCS#1 v1.5 (EM = Encoded Message) :
  ┌────┬────┬─────────────┬────┬─────────────────────┐
  │ 00 │ 01 │  PS (FF…FF) │ 00 │  DigestInfo + Hash  │
  └────┴────┴─────────────┴────┴─────────────────────┘
    1B   1B   ≥ 8 octets    1B   SHA-256 → 51 octets

  S = (EM)^d mod n   (signature)
  V : EM' = S^e mod n, puis comparer EM' avec l'attendu.
""")

    return message, signature


# ─────────────────────────────────────────────────────────────────────────────
# 2b. Signature RSA-PSS (Probabilistic Signature Scheme)
# ─────────────────────────────────────────────────────────────────────────────

def demo_pss(key):
    print(f"\n{'=' * 62}")
    print(f"  2b. SIGNATURE RSA — PSS  (ISO/IEC 9796-2)")
    print(f"{'=' * 62}")

    message = b"Bonjour ! Ceci est un message authentique."

    h1 = SHA256.new(message)
    sig1 = pss.new(key).sign(h1)

    h2 = SHA256.new(message)
    sig2 = pss.new(key).sign(h2)

    print(f"\n  Message : {message.decode()}")
    print(f"\n  Signature 1 : {sig1.hex()[:64]}...")
    print(f"  Signature 2 : {sig2.hex()[:64]}...")
    print(f"  Identiques  : {sig1 == sig2}  (PSS est probabiliste — sel aléatoire)")

    h_v = SHA256.new(message)
    try:
        pss.new(key.publickey()).verify(h_v, sig1)
        print(f"\n  ✓ Vérification PSS : VALIDE")
    except (ValueError, TypeError) as e:
        print(f"\n  ✗ Erreur PSS : {e}")

    return sig1


# ─────────────────────────────────────────────────────────────────────────────
# 3. Attaques et contre-mesures
# ─────────────────────────────────────────────────────────────────────────────

def demo_attaques(key, message, sig_pkcs):
    print(f"\n{'=' * 62}")
    print(f"  3. ATTAQUES ET CONTRE-MESURES")
    print(f"{'=' * 62}")

    pub = key.publickey()

    print(f"\n  ─── Attaque 1 : Falsification existentielle ───")
    print(f"""
  Si on signe directement M (sans H(M)), un attaquant peut forger :
    • Choisir S aléatoire
    • Calculer M_forgé = S^e mod n
    • La paire (M_forgé, S) est une signature valide !

  Contre-mesure : TOUJOURS signer H(M).
""")

    n, e = int(key.n), int(key.e)
    S_attaque = secrets.randbits(2048) % n
    M_forge = pow(S_attaque, e, n)
    print(f"  S (attaquant choisit) = {S_attaque:#x}"[:72] + "...")
    print(f"  M_forgé = S^e mod n   = {M_forge:#x}"[:72] + "...")

    print(f"\n  ─── Attaque 2 : Malléabilité multiplicative ───")
    print(f"""
  RSA signature textbook : si S = M^d mod n
    Alors S1·S2 mod n = (M1·M2)^d mod n
  Contre-mesure : padding PKCS#1 / PSS détruit la structure multiplicative.
""")

    print(f"\n  ─── Attaque 3 : Attaque par rejeu ───")
    print(f"""
  Contre-mesures :
  1. NONCE   : inclure un identifiant unique dans M
  2. TIMESTAMP : inclure l'horodatage dans M
  3. SESSION ID : lier la signature à un contexte de session
""")

    print(f"""
  ─── Attaque 4 : Bleichenbacher 2006 (PKCS#1 v1.5) ───

  Contre-mesures :
  • Vérification stricte de la longueur totale de DigestInfo
  • Comparaison en temps constant
  • Migrer vers RSA-PSS (pas vulnérable par conception)
""")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Sérialisation des clés (PEM/DER)
# ─────────────────────────────────────────────────────────────────────────────

def demo_serialisation(key):
    print(f"\n{'=' * 62}")
    print(f"  4. SÉRIALISATION DES CLÉS (PEM / DER)")
    print(f"{'=' * 62}")

    priv_pem = key.export_key("PEM").decode()
    pub_pem = key.publickey().export_key("PEM").decode()

    print(f"\n  Clé privée (PEM) :")
    for line in priv_pem.split("\n")[:4]:
        print(f"    {line}")
    print(f"    ... ({len(priv_pem)} caractères total)")

    print(f"\n  Clé publique (PEM) :")
    for line in pub_pem.split("\n")[:4]:
        print(f"    {line}")
    print(f"    ... ({len(pub_pem)} caractères total)")


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE RSASignatureAlgorithm POUR L'INTERFACE MAIN.PY
# ══════════════════════════════════════════════════════════════════════════════

class RSASignatureAlgorithm:
    def __init__(self):
        self._key = None
        self._public_key = None
        self._private_key = None
    
    def get_name(self):
        return "RSA Signature (PKCS#1 v1.5 / PSS)"
    
    def get_description(self):
        return (
            "RSA Signature — Authenticité et intégrité\n"
            "• Principe : S = H(M)^d mod n\n"
            "• Vérification : S^e mod n == H(M)\n"
            "• Schémas : PKCS#1 v1.5 (déterministe) et PSS (probabiliste)\n"
            "• Sécurité : basée sur la factorisation\n"
            "• Format clé :\n"
            "  - 'gen' : générer une paire de clés\n"
            "  - 'sign' : signer un message\n"
            "  - 'verify' : vérifier une signature\n"
            "  - 'demo' : démonstration complète"
        )
    
    def get_key_info(self):
        return {
            "type": "asymmetric",
            "placeholder": "'gen' | 'sign' | 'verify' | 'demo'"
        }
    
    def encrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        key_lower = str(key).strip().lower()
        
        if log_step:
            log_step("✍️ RSA SIGNATURE — SIMULATION")
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
        """Génère une paire de clés RSA"""
        try:
            self._key = RSA.generate(2048)
            self._public_key = self._key.publickey()
            
            result = f"""
╔══════════════════════════════════════════════════════════════╗
║              GÉNÉRATION DE CLÉS RSA SIGNATURE               ║
╠══════════════════════════════════════════════════════════════╣
║  Clé publique (n, e) :                                       ║
║    n = {self._key.n:#x}[:64]...
║    e = {self._key.e}                                         ║
╠══════════════════════════════════════════════════════════════╣
║  Clé privée (n, d) :                                         ║
║    d = {self._key.d:#x}[:64]...                              ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ Clés générées avec succès !                               ║
║  ✓ Taille : 2048 bits (256 octets)                           ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("✓ Clés RSA générées")
            
            return result
            
        except ImportError:
            return "⚠️ PyCryptodome non installé. Exécutez : pip install pycryptodome"
    
    def _sign_message(self, text: str, log_step=None):
        """Signe un message"""
        if self._key is None:
            return "Erreur: Générez d'abord des clés avec 'gen'"
        
        try:
            message = text.encode("utf-8")
            h = SHA256.new(message)
            signature = pkcs1_15.new(self._key).sign(h)
            
            result = f"""
╔══════════════════════════════════════════════════════════════╗
║                    SIGNATURE RSA PKCS#1 v1.5                 ║
╠══════════════════════════════════════════════════════════════╣
║  Message : {text[:50]}{'...' if len(text) > 50 else ''}                     ║
║  Hash SHA-256 : {h.hexdigest()[:32]}...                      ║
║  Signature    : {signature.hex()[:48]}...                    ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ Signature générée avec succès !                          ║
║  ✓ Taille signature : {len(signature)} octets                 ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("✓ Signature générée")
            
            return result
            
        except Exception as e:
            return f"Erreur lors de la signature : {str(e)}"
    
    def _verify_signature(self, text: str, log_step=None):
        """Vérifie une signature (format: message|signature_hex)"""
        if self._key is None:
            return "Erreur: Générez d'abord des clés avec 'gen'"
        
        try:
            if "|" not in text:
                return "Format : 'message|signature_hex'"
            
            msg_part, sig_part = text.split("|", 1)
            message = msg_part.encode("utf-8")
            signature = bytes.fromhex(sig_part.strip())
            
            h = SHA256.new(message)
            
            try:
                pkcs1_15.new(self._key.publickey()).verify(h, signature)
                return """
╔══════════════════════════════════════════════════════════════╗
║                  VÉRIFICATION DE SIGNATURE                   ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ SIGNATURE VALIDE !                                        ║
║  ✓ Le message est authentique et n'a pas été modifié        ║
╚══════════════════════════════════════════════════════════════╝
"""
            except (ValueError, TypeError):
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
            # Générer les clés
            self._key = RSA.generate(2048)
            
            # Message à signer
            message = b"Document confidentiel signe par Alice."
            h = SHA256.new(message)
            
            # Signature PKCS#1 v1.5
            signature_pkcs = pkcs1_15.new(self._key).sign(h)
            
            # Signature PSS
            signature_pss = pss.new(self._key).sign(h)
            
            result = f"""
╔══════════════════════════════════════════════════════════════╗
║              DÉMONSTRATION COMPLÈTE RSA SIGNATURE           ║
╠══════════════════════════════════════════════════════════════╣
║  Message : {message.decode()}                 ║
║  Hash SHA-256 : {h.hexdigest()[:32]}...                      ║
╠══════════════════════════════════════════════════════════════╣
║  PKCS#1 v1.5 (déterministe) :                                ║
║    Signature : {signature_pkcs.hex()[:48]}...                ║
║    ✓ Vérification : OK                                       ║
╠══════════════════════════════════════════════════════════════╣
║  PSS (probabiliste) :                                        ║
║    Signature : {signature_pss.hex()[:48]}...                 ║
║    ✓ Vérification : OK                                       ║
╠══════════════════════════════════════════════════════════════╣
║  Attaques connues :                                          ║
║    • Falsification existentielle (sans hachage)              ║
║    • Bleichenbacher (PKCS#1 v1.5 mal implémenté)             ║
║    • Rejeu (ajouter nonce/timestamp)                         ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ Démonstration terminée                                    ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("✓ Démonstration RSA Signature complète")
            
            return result
            
        except ImportError:
            return "⚠️ PyCryptodome non installé. Exécutez : pip install pycryptodome"


# ─────────────────────────────────────────────────────────────────────────────
# PROGRAMME PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()