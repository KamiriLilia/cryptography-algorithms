"""
Diffie-Hellman Key Exchange — Attaque MITM — Contre-mesure ECDSA
=================================================================
1. Implémentation DH avec un premier p de 512 bits (RFC 3526 group 1)
2. Simulation d'une attaque Man-in-the-Middle complète
3. Contre-mesure par signature ECDSA des clés publiques DH

Dépendances : cryptography
    pip install cryptography
"""

import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# ══════════════════════════════════════════════════════════════════════════════
# Paramètres DH — Premier p de 512 bits (RFC 3526, groupe 1 / Oakley group 1)
# ══════════════════════════════════════════════════════════════════════════════

P = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B"
    "22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51"
    "C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A"
    "899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)
G = 2
P_BITS = P.bit_length()


# ══════════════════════════════════════════════════════════════════════════════
# Utilitaires
# ══════════════════════════════════════════════════════════════════════════════

def separator(title: str, width: int = 72) -> None:
    print("\n" + "═" * width)
    print(f"  {title}")
    print("═" * width)


def subsection(title: str) -> None:
    print(f"\n  ── {title} ──")


def fmt_hex(n: int, indent: int = 6, cols: int = 48) -> str:
    """Formate un grand entier en hexadécimal multiligne indenté."""
    h = format(n, "x")
    lines = [h[i : i + cols] for i in range(0, len(h), cols)]
    pad = " " * indent
    return ("\n" + pad).join(lines)


def rand_private_key(bits: int = 256) -> int:
    """Génère un entier aléatoire cryptographiquement sûr de `bits` bits."""
    return int.from_bytes(os.urandom(bits // 8), "big")


def modpow(base: int, exp: int, mod: int) -> int:
    """Exponentiation modulaire rapide (pow built-in en Python)."""
    return pow(base, exp, mod)


# ══════════════════════════════════════════════════════════════════════════════
# PARTIE 1 — Échange Diffie-Hellman
# ══════════════════════════════════════════════════════════════════════════════

class DHParty:
    """
    Représente un participant à un échange DH.
    
    Attributs publics  : public_key = g^private_key mod p
    Attributs privés   : _private_key (jamais partagé)
    """

    def __init__(self, name: str, private_key: int | None = None):
        self.name = name
        self._private_key = private_key if private_key is not None else rand_private_key()
        self.public_key: int = modpow(G, self._private_key, P)
        self.shared_key: int | None = None

    def compute_shared_key(self, other_public: int) -> int:
        """Calcule K = other_public^private_key mod p."""
        self.shared_key = modpow(other_public, self._private_key, P)
        return self.shared_key

    def print_keys(self) -> None:
        print(f"\n  [{self.name}]")
        print(f"    Clé privée  ({self._private_key.bit_length()} bits) :")
        print(f"      {fmt_hex(self._private_key)}")
        print(f"    Clé publique ({self.public_key.bit_length()} bits) :")
        print(f"      {fmt_hex(self.public_key)}")


def demo_dh() -> tuple[DHParty, DHParty]:
    separator("PARTIE 1 — Échange Diffie-Hellman")

    print(f"\n  Paramètres publics :")
    print(f"    p ({P_BITS} bits) :")
    print(f"      {fmt_hex(P)}")
    print(f"    g = {G}")

    alice = DHParty("Alice")
    bob   = DHParty("Bob")

    subsection("Génération des clés privées et publiques")
    alice.print_keys()
    bob.print_keys()

    subsection("Échange des clés publiques")
    print(f"\n  Alice ──── A = g^a mod p ────► Bob")
    print(f"  Alice ◄─── B = g^b mod p ──── Bob")

    ka = alice.compute_shared_key(bob.public_key)    # K = B^a mod p
    kb = bob.compute_shared_key(alice.public_key)    # K = A^b mod p

    subsection("Clé partagée K = g^(ab) mod p")
    print(f"\n  Ka (Alice calcule B^a mod p) :")
    print(f"      {fmt_hex(ka)}")
    print(f"\n  Kb (Bob calcule   A^b mod p) :")
    print(f"      {fmt_hex(kb)}")

    match = ka == kb
    print(f"\n  Ka == Kb : {'✓ OUI — Clé partagée établie avec succès !' if match else '✗ NON — Erreur.'}")
    assert match, "Erreur dans le calcul DH — les clés partagées diffèrent."

    return alice, bob


# ══════════════════════════════════════════════════════════════════════════════
# PARTIE 2 — Attaque Man-in-the-Middle
# ══════════════════════════════════════════════════════════════════════════════

class MITMAttacker:
    """
    Mallory intercepte l'échange entre Alice et Bob.

    Il génère deux paires DH distinctes :
      • (m1, M1) pour se faire passer pour Bob  auprès d'Alice
      • (m2, M2) pour se faire passer pour Alice auprès de Bob

    Il établit ainsi :
      • K_with_alice = A^m1 mod p  (Alice calcule M1^a = g^(m1*a))
      • K_with_bob   = B^m2 mod p  (Bob   calcule M2^b = g^(m2*b))
    """

    def __init__(self, name: str = "Mallory"):
        self.name = name
        self._m1 = rand_private_key()
        self._m2 = rand_private_key()
        self.M1: int = modpow(G, self._m1, P)   # Transmis à Alice à la place de B
        self.M2: int = modpow(G, self._m2, P)   # Transmis à Bob   à la place de A
        self.k_with_alice: int | None = None
        self.k_with_bob:   int | None = None

    def intercept_alice(self, alice_public: int) -> int:
        """
        Reçoit A d'Alice.
        - Calcule K_with_alice = A^m1 mod p  (session partagée avec Alice)
        - Retourne M2 pour être transmis à Bob (Mallory se fait passer pour Alice)
        """
        self.k_with_alice = modpow(alice_public, self._m1, P)
        return self.M2   # Bob recevra M2 à la place de A

    def intercept_bob(self, bob_public: int) -> int:
        """
        Reçoit B de Bob.
        - Calcule K_with_bob = B^m2 mod p  (session partagée avec Bob)
        - Retourne M1 pour être transmis à Alice (Mallory se fait passer pour Bob)
        """
        self.k_with_bob = modpow(bob_public, self._m2, P)
        return self.M1   # Alice recevra M1 à la place de B

    def decrypt_and_reencrypt(self, msg: str, direction: str) -> str:
        """Simule le déchiffrement et re-chiffrement du message."""
        return f"[Mallory a lu '{msg}' et l'a retransmis vers {direction}]"


def demo_mitm(alice_dh: DHParty, bob_dh: DHParty) -> MITMAttacker:
    # Crée de nouvelles instances pour la démo MITM (clés partagées vierges)
    alice = DHParty("Alice", alice_dh._private_key)
    bob   = DHParty("Bob",   bob_dh._private_key)
    separator("PARTIE 2 — Attaque Man-in-the-Middle")

    mallory = MITMAttacker()

    print("""
  Schéma de l'attaque :

  Alice  ──── A ────►  [Mallory intercepte A, envoie M2]  ────►  Bob
  Alice  ◄─── M1 ───  [Mallory intercepte B, envoie M1]  ◄────   Bob

  Résultat :
    Alice croit parler à Bob  → partage K_Alice  avec Mallory
    Bob   croit parler à Alice → partage K_Bob    avec Mallory
    Mallory lit et modifie tout le trafic en clair
    """)

    subsection("Clés de Mallory")
    print(f"\n  [Mallory — session ↔ Alice]")
    print(f"    m1 ({mallory._m1.bit_length()} bits) : {fmt_hex(mallory._m1)}")
    print(f"    M1 = g^m1 mod p :")
    print(f"      {fmt_hex(mallory.M1)}")
    print(f"\n  [Mallory — session ↔ Bob]")
    print(f"    m2 ({mallory._m2.bit_length()} bits) : {fmt_hex(mallory._m2)}")
    print(f"    M2 = g^m2 mod p :")
    print(f"      {fmt_hex(mallory.M2)}")

    subsection("Déroulement de l'attaque")

    # Step 1 : Alice envoie A, Mallory intercepte et envoie M2 à Bob
    print(f"\n  1. Alice envoie A. Mallory intercepte et transmet M2 à Bob.")
    fake_for_bob   = mallory.intercept_alice(alice.public_key)   # M2

    # Step 2 : Bob reçoit M2 (croit que c'est A), envoie B, Mallory intercepte
    print(f"  2. Bob reçoit M2 (croit que c'est A), envoie B.")
    print(f"     Mallory intercepte B et transmet M1 à Alice.")
    fake_for_alice = mallory.intercept_bob(bob.public_key)      # M1

    # Step 3 : Alice et Bob calculent leurs clés partagées avec Mallory
    alice_shared = alice.compute_shared_key(fake_for_alice)     # M1^a mod p
    bob_shared   = bob.compute_shared_key(fake_for_bob)         # M2^b mod p

    subsection("Clés établies (toutes compromises)")
    print(f"\n  K_Alice (Alice croit partager avec Bob) = M1^a mod p :")
    print(f"      {fmt_hex(alice_shared)}")
    print(f"\n  K_M←A  (Mallory connaît  K_Alice)       = A^m1  mod p :")
    print(f"      {fmt_hex(mallory.k_with_alice)}")
    print(f"\n  Mallory connaît K_Alice : {'✓ OUI' if alice_shared == mallory.k_with_alice else '✗ NON'}")

    print(f"\n  K_Bob   (Bob croit partager avec Alice) = M2^b mod p :")
    print(f"      {fmt_hex(bob_shared)}")
    print(f"\n  K_M←B   (Mallory connaît  K_Bob)        = B^m2  mod p :")
    print(f"      {fmt_hex(mallory.k_with_bob)}")
    print(f"\n  Mallory connaît K_Bob  : {'✓ OUI' if bob_shared == mallory.k_with_bob else '✗ NON'}")

    subsection("Simulation d'interception de message")
    msg = "Bonjour Bob, voici mon numéro de compte : FR76..."
    print(f"\n  Alice envoie (chiffré avec K_Alice) : \"{msg}\"")
    print(f"  {mallory.decrypt_and_reencrypt(msg, 'Bob')}")

    assert alice_shared == mallory.k_with_alice, "Erreur MITM session Alice"
    assert bob_shared   == mallory.k_with_bob,   "Erreur MITM session Bob"

    return mallory


# ══════════════════════════════════════════════════════════════════════════════
# PARTIE 3 — Contre-mesure ECDSA
# ══════════════════════════════════════════════════════════════════════════════

class ECDSAParty(DHParty):
    """
    Étend DHParty avec une paire de clés ECDSA (P-256).
    
    Chaque partie signe sa clé publique DH avant de la transmettre.
    Le destinataire vérifie la signature avec la clé publique EC
    obtenue au préalable via un canal sûr (PKI, certificat, etc.).
    """

    def __init__(self, name: str):
        super().__init__(name)
        self._ec_private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend()
        )
        self.ec_public_key = self._ec_private_key.public_key()

    def sign_dh_pubkey(self) -> bytes:
        """Signe la représentation octets de la clé publique DH."""
        message = self._dh_pubkey_bytes()
        signature = self._ec_private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify_dh_pubkey(self, dh_pubkey: int, signature: bytes, ec_pubkey) -> bool:
        """Vérifie la signature ECDSA d'une clé publique DH reçue."""
        message = dh_pubkey.to_bytes((dh_pubkey.bit_length() + 7) // 8, "big")
        try:
            ec_pubkey.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def _dh_pubkey_bytes(self) -> bytes:
        return self.public_key.to_bytes(
            (self.public_key.bit_length() + 7) // 8, "big"
        )

    def ec_pubkey_hex(self) -> str:
        raw = self.ec_public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        return raw.hex()


class MITMAttackerWithFakeSig(MITMAttacker):
    """
    Mallory tente de forger une signature ECDSA pour sa clé M1/M2.
    Il dispose de sa propre paire EC mais pas des clés privées EC
    d'Alice ou Bob → la vérification échoue chez le destinataire.
    """

    def __init__(self):
        super().__init__()
        self._fake_ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    def forge_signature_for(self, dh_pubkey: int) -> bytes:
        """Signe M1/M2 avec SA clé EC (pas celle d'Alice/Bob)."""
        message = dh_pubkey.to_bytes((dh_pubkey.bit_length() + 7) // 8, "big")
        return self._fake_ec_key.sign(message, ec.ECDSA(hashes.SHA256()))


def demo_ecdsa() -> None:
    separator("PARTIE 3 — Contre-mesure ECDSA")

    print("""
  Principe :
    • Alice et Bob possèdent chacun une paire de clés ECDSA (P-256).
    • Leurs clés publiques EC sont échangées via un canal authentifié
      (PKI, certificat X.509, échange hors-bande, etc.) AVANT l'échange DH.
    • Lors de l'échange DH, chaque partie signe sa clé publique DH.
    • Le destinataire vérifie la signature avant de l'utiliser.
    • Mallory ne peut pas forger Sig_Alice(M1) sans privEC_Alice.
    """)

    alice = ECDSAParty("Alice")
    bob   = ECDSAParty("Bob")
    mallory = MITMAttackerWithFakeSig()

    subsection("Clés ECDSA P-256 (distribuées hors-bande)")
    print(f"\n  Alice  EC pubkey (uncompressed) :\n    {alice.ec_pubkey_hex()}")
    print(f"\n  Bob    EC pubkey (uncompressed) :\n    {bob.ec_pubkey_hex()}")

    subsection("Échange DH authentifié — Alice → Bob")

    sig_alice = alice.sign_dh_pubkey()
    print(f"\n  Alice signe A avec privEC_Alice :")
    print(f"    SHA-256(A) signé → signature ECDSA ({len(sig_alice)} bytes) :")
    print(f"    {sig_alice.hex()}")

    print(f"\n  Bob vérifie Sig_Alice(A) avec pubEC_Alice :")
    ok_a = bob.verify_dh_pubkey(alice.public_key, sig_alice, alice.ec_public_key)
    print(f"    → {'✓ VALIDE — Bob accepte A et calcule K' if ok_a else '✗ INVALIDE — Bob rejette A'}")
    assert ok_a

    subsection("Échange DH authentifié — Bob → Alice")

    sig_bob = bob.sign_dh_pubkey()
    print(f"\n  Bob signe B avec privEC_Bob :")
    print(f"    SHA-256(B) signé → signature ECDSA ({len(sig_bob)} bytes) :")
    print(f"    {sig_bob.hex()}")

    print(f"\n  Alice vérifie Sig_Bob(B) avec pubEC_Bob :")
    ok_b = alice.verify_dh_pubkey(bob.public_key, sig_bob, bob.ec_public_key)
    print(f"    → {'✓ VALIDE — Alice accepte B et calcule K' if ok_b else '✗ INVALIDE — Alice rejette B'}")
    assert ok_b

    subsection("Tentative MITM de Mallory — injections bloquées")

    # Mallory tente d'injecter M1 à la place de A (vers Bob)
    fake_sig_m1 = mallory.forge_signature_for(mallory.M1)
    print(f"\n  Mallory forge Sig(M1) avec sa propre clé EC :")
    print(f"    {fake_sig_m1.hex()}")
    print(f"\n  Bob vérifie Sig_Mallory(M1) avec pubEC_Alice :")
    try:
        alice.ec_public_key.verify(fake_sig_m1,
                                   mallory.M1.to_bytes((mallory.M1.bit_length()+7)//8,"big"),
                                   ec.ECDSA(hashes.SHA256()))
        bob_accepts = True
    except InvalidSignature:
        bob_accepts = False
    print(f"    → {'✓ Accepté (ERREUR !)' if bob_accepts else '✗ INVALIDE — Bob rejette M1 ✓ ATTAQUE BLOQUÉE'}")

    # Mallory tente d'injecter M2 à la place de B (vers Alice)
    fake_sig_m2 = mallory.forge_signature_for(mallory.M2)
    print(f"\n  Alice vérifie Sig_Mallory(M2) avec pubEC_Bob :")
    try:
        bob.ec_public_key.verify(fake_sig_m2,
                                 mallory.M2.to_bytes((mallory.M2.bit_length()+7)//8,"big"),
                                 ec.ECDSA(hashes.SHA256()))
        alice_accepts = True
    except InvalidSignature:
        alice_accepts = False
    print(f"    → {'✓ Accepté (ERREUR !)' if alice_accepts else '✗ INVALIDE — Alice rejette M2 ✓ ATTAQUE BLOQUÉE'}")

    assert not bob_accepts and not alice_accepts

    subsection("Clé partagée finale — authentifiée et sécurisée")
    K_alice = alice.compute_shared_key(bob.public_key)
    K_bob   = bob.compute_shared_key(alice.public_key)
    print(f"\n  K = g^(ab) mod p :")
    print(f"    {fmt_hex(K_alice)}")
    print(f"\n  Ka == Kb : {'✓ OUI' if K_alice == K_bob else '✗ NON'}")
    print(f"\n  ✓ Confidentialité  : DH garantit que K n'est connu que d'Alice et Bob.")
    print(f"  ✓ Authenticité     : ECDSA garantit l'identité des participants.")
    print(f"  ✓ MITM impossible  : Mallory ne peut pas forger une signature valide.\n")
# ══════════════════════════════════════════════════════════════════════════════
# CLASSE DHAlgorithm POUR L'INTERFACE MAIN.PY
# ══════════════════════════════════════════════════════════════════════════════

class DHAlgorithm:
    """
    Wrapper pour l'interface main.py
    """
    
    def __init__(self):
        self._alice = None
        self._bob = None
        self._shared_key = None
    
    def get_name(self):
        return "Diffie-Hellman (Échange de clés)"
    
    def get_description(self):
        return (
            "Diffie-Hellman — Échange de clés sécurisé\n"
            "• Protocole : échange de clés publiques\n"
            "• Sécurité : DLP (Logarithme Discret)\n"
            "• Paramètres : p (512 bits), g=2\n"
            "• ATTENTION : vulnérable au MITM sans authentification\n"
            "• Fonctionnalités :\n"
            "  - 'demo' : simuler l'échange complet\n"
            "  - 'mitm' : simuler l'attaque Man-in-the-Middle\n"
            "  - 'ecdsa' : démonstration de la contre-mesure"
        )
    
    def get_key_info(self):
        return {
            "type": "asymmetric",
            "placeholder": "'demo' | 'mitm' | 'ecdsa'"
        }
    
    def encrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        key_lower = str(key).strip().lower()
        
        if log_step:
            log_step("🔐 DIFFIE-HELLMAN — SIMULATION")
            log_step("=" * 42)
        
        if key_lower == "demo":
            # Simulation d'échange DH normal
            alice = DHParty("Alice")
            bob = DHParty("Bob")
            
            self._alice = alice
            self._bob = bob
            
            ka = alice.compute_shared_key(bob.public_key)
            kb = bob.compute_shared_key(alice.public_key)
            self._shared_key = ka
            
            result = f"""
╔══════════════════════════════════════════════════════════════╗
║                    ÉCHANGE DIFFIE-HELLMAN                    ║
╠══════════════════════════════════════════════════════════════╣
║  Paramètres publics :                                        ║
║    p = {P_BITS} bits
║    g = {G}                                                    ║
╠══════════════════════════════════════════════════════════════╣
║  Alice :                                                     ║
║    Clé privée a = {alice._private_key:#x}[:32]...
║    Clé publique A = {alice.public_key:#x}[:32]...
║                                                              ║
║  Bob :                                                       ║
║    Clé privée b = {bob._private_key:#x}[:32]...
║    Clé publique B = {bob.public_key:#x}[:32]...
╠══════════════════════════════════════════════════════════════╣
║  Clé partagée K = g^(ab) mod p :                             ║
║    {self._shared_key:#x}[:64]...
╠══════════════════════════════════════════════════════════════╣
║  ✓ Échange réussi ! Les deux parties ont la même clé.       ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("✓ Échange DH simulé avec succès")
            
            return result
        
        elif key_lower == "mitm":
            # Simulation de l'attaque MITM
            alice = DHParty("Alice")
            bob = DHParty("Bob")
            mallory = MITMAttacker()
            
            fake_for_bob = mallory.intercept_alice(alice.public_key)
            fake_for_alice = mallory.intercept_bob(bob.public_key)
            
            alice_shared = alice.compute_shared_key(fake_for_alice)
            bob_shared = bob.compute_shared_key(fake_for_bob)
            
            result = f"""
╔══════════════════════════════════════════════════════════════╗
║              ATTAQUE MAN-IN-THE-MIDDLE (MITM)               ║
╠══════════════════════════════════════════════════════════════╣
║  Mallory intercepte l'échange entre Alice et Bob !          ║
╠══════════════════════════════════════════════════════════════╣
║  Clés de Mallory :                                          ║
║    m1 (avec Alice) = {mallory._m1:#x}[:32]...
║    M1 = g^m1 mod p = {mallory.M1:#x}[:32]...
║    m2 (avec Bob)   = {mallory._m2:#x}[:32]...
║    M2 = g^m2 mod p = {mallory.M2:#x}[:32]...
╠══════════════════════════════════════════════════════════════╣
║  Clés compromises :                                         ║
║    K_Alice (Alice ↔ Mallory) = {alice_shared:#x}[:32]...
║    K_Bob   (Bob ↔ Mallory)   = {bob_shared:#x}[:32]...
╠══════════════════════════════════════════════════════════════╣
║  ⚠️ Mallory peut lire et modifier tous les messages !      ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("⚠️ Attaque MITM simulée")
            
            return result
        
        elif key_lower == "ecdsa":
            # Contre-mesure ECDSA (version simplifiée sans crypto)
            result = """
╔══════════════════════════════════════════════════════════════╗
║              CONTRE-MESURE ECDSA CONTRE MITM                ║
╠══════════════════════════════════════════════════════════════╣
║  Principe :                                                 ║
║    • Alice et Bob possèdent des clés ECDSA (P-256)          ║
║    • Chaque partie signe sa clé publique DH                 ║
║    • Le destinataire vérifie la signature                   ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ Mallory ne peut pas forger la signature d'Alice          ║
║  ✓ L'attaque MITM est bloquée !                             ║
╠══════════════════════════════════════════════════════════════╣
║  Note: Pour une démonstration complète, installez :         ║
║    pip install cryptography                                 ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("✓ Contre-mesure ECDSA expliquée")
            
            return result
        
        else:
            return "DH est un protocole d'échange de clés. Utilisez 'demo', 'mitm' ou 'ecdsa'."
    
    def decrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        return self.encrypt(text, key, log_step, log_matrix)

# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 72)
    print("  Diffie-Hellman · Attaque MITM · Contre-mesure ECDSA")
    print("=" * 72)

    # 1. Échange DH normal
    alice, bob = demo_dh()

    # 2. Attaque MITM sur un échange DH non authentifié
    demo_mitm(alice, bob)

    # 3. Contre-mesure ECDSA
    demo_ecdsa()

    separator("FIN DE LA DÉMONSTRATION")
    print("""
  Résumé :
    • DH assure la confidentialité mais pas l'authenticité.
    • Sans authentification, un MITM peut intercepter silencieusement.
    • ECDSA sur les clés publiques DH bloque toute substitution.
    • En production : TLS 1.3 combine ECDHE + certificats X.509 (ECDSA/RSA).
    """)