"""
Exercice 4.1 — MD5 (Message Digest 5)
Sortie 128 bits | Construction Merkle-Damgård | 4 tours de 16 ops
"""

import hashlib
import os
import time

# ─────────────────────────────────────────────
# Utilitaires
# ─────────────────────────────────────────────

def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def hex_to_bits(hex_str: str) -> str:
    """Convertit un digest hex en chaîne de bits."""
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)

def bit_difference_rate(hex1: str, hex2: str) -> float:
    """Taux de bits différents entre deux digests hexadécimaux."""
    bits1 = hex_to_bits(hex1)
    bits2 = hex_to_bits(hex2)
    diff = sum(b1 != b2 for b1, b2 in zip(bits1, bits2))
    return diff / len(bits1)

def flip_bit(data: bytes, bit_index: int) -> bytes:
    """Inverse le bit `bit_index` dans `data`."""
    byte_index = bit_index // 8
    bit_offset = 7 - (bit_index % 8)
    ba = bytearray(data)
    ba[byte_index] ^= (1 << bit_offset)
    return bytes(ba)

def banner(title: str):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print('═' * 60)

# ─────────────────────────────────────────────
# Partie 1 — Calcul MD5 sur 5 messages
# ─────────────────────────────────────────────

def partie1():
    banner("PARTIE 1 — Hash MD5 sur 5 messages")

    messages = {
        "Chaîne vide":    b"",
        "1 octet  (0x41)": b"A",
        "1 Kio":           os.urandom(1024),
        "1 Mio":           os.urandom(1024 * 1024),
        "Fichier binaire": bytes(range(256)) * 4,   # 1 Kio de motif binaire
    }

    print(f"\n{'Message':<20} {'Hash MD5 (hex)':<34} {'Bits'}")
    print('-' * 65)

    for label, data in messages.items():
        digest = md5_hex(data)
        bits   = len(hex_to_bits(digest))
        assert bits == 128, f"Attendu 128 bits, obtenu {bits}"
        short = digest[:16] + "…" + digest[-8:]
        print(f"{label:<20} {short:<34} {bits} ✓")

    print("\n✅  Tous les digests font exactement 128 bits.")

# ─────────────────────────────────────────────
# Partie 2 — Effet avalanche
# ─────────────────────────────────────────────

def partie2():
    banner("PARTIE 2 — Effet avalanche (inversion d'un seul bit)")

    messages = {
        "Chaîne vide":    b"\x00",          # doit contenir ≥1 octet pour flipper
        "1 octet":        b"A",
        "1 Kio":          os.urandom(1024),
        "1 Mio":          os.urandom(1024 * 1024),
        "Fichier binaire": bytes(range(256)) * 4,
    }

    print(f"\n{'Message':<16} {'Hash original (tronqué)':<26} {'Hash modifié (tronqué)':<26} {'Taux diff.'}")
    print('-' * 80)

    taux_total = []
    for label, data in messages.items():
        orig      = md5_hex(data)
        modified  = md5_hex(flip_bit(data, 0))   # inverse le bit 0
        taux      = bit_difference_rate(orig, modified)
        taux_total.append(taux)

        o_short = orig[:12] + "…"
        m_short = modified[:12] + "…"
        signe   = "✅" if 0.40 <= taux <= 0.60 else "⚠️ "
        print(f"{label:<16} {o_short:<26} {m_short:<26} {taux*100:5.1f} % {signe}")

    moyenne = sum(taux_total) / len(taux_total)
    print(f"\n  Taux moyen de bits différents : {moyenne*100:.1f} %  (cible ≈ 50 %)")


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE MD5Algorithm POUR L'INTERFACE MAIN.PY
# ══════════════════════════════════════════════════════════════════════════════

class MD5Algorithm:
    def get_name(self):
        return "MD5 (Message Digest 5)"
    
    def get_description(self):
        return (
            "MD5 — Fonction de hachage (128 bits)\n"
            "• Construction : Merkle-Damgård\n"
            "• 4 tours de 16 opérations (F, G, H, I)\n"
            "• Sortie : 32 caractères hexadécimaux (128 bits)\n"
            "• ⚠️ COLLISIONS PRATIQUES TROUVÉES (Wang & Yu, 2004)\n"
            "• ❌ BANNI pour la sécurité (plus sûr depuis 2012)\n"
            "• ✓ Encore utilisé pour checksums (pas sécurité)\n"
            "• Format clé : n'importe quelle chaîne (ignorée)"
        )
    
    def get_key_info(self):
        return {
            "type": "hash",
            "placeholder": "Entrée quelconque (hash seulement)"
        }
    
    def encrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        """
        Calcule le hash MD5 du texte.
        La clé est ignorée (pas nécessaire pour le hachage).
        """
        data = text.encode("utf-8")
        digest = md5_hex(data)
        
        if log_step:
            log_step("🔐 MD5 — CALCUL DE HACHAGE")
            log_step("=" * 42)
            log_step(f"   Entrée : {text[:100]}{'...' if len(text) > 100 else ''}")
            log_step(f"   Taille : {len(data)} octets")
            log_step(f"   Hash MD5 : {digest}")
            log_step(f"   Taille hash : {len(digest) * 4} bits")
        
        # Afficher aussi l'effet avalanche si demandé (mode démo)
        if str(key).strip().lower() == "avalanche":
            modified = flip_bit(data, 0)
            digest2 = md5_hex(modified)
            taux = bit_difference_rate(digest, digest2)
            
            result = f"""
╔══════════════════════════════════════════════════════════════╗
║                    HASH MD5 - EFFET AVALANCHE               ║
╠══════════════════════════════════════════════════════════════╣
║  Hash original : {digest}                                     ║
║  Hash modifié  : {digest2}                                     ║
║  Taux différences : {taux*100:.1f} % (cible ≈ 50 %)           ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ Un seul bit modifié → ~50% du hash change                ║
║  ⚠️ MD5 est cassé : collisions trouvées (2004)              ║
║  ❌ Ne pas utiliser pour la sécurité                         ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("✓ Effet avalanche démontré")
            
            return result
        
        # Formatage du résultat
        result = f"""
╔══════════════════════════════════════════════════════════════╗
║                         HASH MD5                            ║
╠══════════════════════════════════════════════════════════════╣
║  Entrée : {text[:80]}{'...' if len(text) > 80 else ''}                     ║
║  Hash   : {digest}                                             ║
╠══════════════════════════════════════════════════════════════╣
║  Taille : 128 bits (32 caractères hexadécimaux)             ║
║  ⚠️ MD5 n'est plus sécurisé (collisions possibles)          ║
╚══════════════════════════════════════════════════════════════╝
"""
        return result
    
    def decrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        """
        MD5 est une fonction de hachage, pas un chiffrement.
        On ne peut pas déchiffrer.
        """
        return "⚠️ MD5 est une fonction de hachage à sens unique. Impossible de déchiffrer."


# ─────────────────────────────────────────────
# Point d'entrée
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════╗")
    print("║          Exercice 4.1 — MD5 (Message Digest 5)      ║")
    print("╚══════════════════════════════════════════════════════╝")
    partie1()
    partie2()
    print()