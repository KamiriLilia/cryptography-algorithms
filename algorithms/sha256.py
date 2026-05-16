"""
Exercice 4.2 — SHA-256 (Secure Hash Algorithm 2)
Sortie 256 bits | Merkle-Damgård | 64 tours | 512 bits/bloc
Implémentation from-scratch + validation hashlib + vérif. intégrité

Corrections apportées :
  1. ch() : parenthèses ajoutées pour appliquer MASK32 sur le XOR complet
  2. Commentaire corruption : "1 bit modifié" (et non "1 octet")
"""

import hashlib
import struct
import os

# ─────────────────────────────────────────────
# Constantes SHA-256
# ─────────────────────────────────────────────

# Premiers 32 bits des racines carrées des 8 premiers nombres premiers
H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# Premiers 32 bits des racines cubiques des 64 premiers nombres premiers
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

MASK32 = 0xFFFFFFFF   # masque 32 bits

# ─────────────────────────────────────────────
# Fonctions auxiliaires 32 bits
# ─────────────────────────────────────────────

def rotr(x: int, n: int) -> int:
    """Rotation à droite sur 32 bits."""
    return ((x >> n) | (x << (32 - n))) & MASK32

def ch(x, y, z):  return ((x & y) ^ (~x & z)) & MASK32
def maj(x, y, z): return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x): return rotr(x,  2) ^ rotr(x, 13) ^ rotr(x, 22)
def sigma1(x): return rotr(x,  6) ^ rotr(x, 11) ^ rotr(x, 25)
def gamma0(x): return rotr(x,  7) ^ rotr(x, 18) ^ (x >>  3)
def gamma1(x): return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

# ─────────────────────────────────────────────
# Padding Merkle-Damgård
# ─────────────────────────────────────────────

def md_padding(message: bytes) -> bytes:
    """
    Ajoute le padding SHA-256 (FIPS 180-4, §5.1.1) :
      1. Un bit '1'  → octet 0x80
      2. Des zéros   → jusqu'à longueur ≡ 56 (mod 64)
      3. Longueur du message original en bits sur 64 bits big-endian
    Garantit que le message paddé est un multiple de 512 bits (64 octets).
    """
    length_bits = len(message) * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += struct.pack('>Q', length_bits)
    assert len(message) % 64 == 0, "Padding incorrect"
    return message

# ─────────────────────────────────────────────
# Compression d'un bloc de 512 bits (64 octets)
# ─────────────────────────────────────────────

def compress_block(block: bytes, h: list) -> list:
    """
    Fonction de compression SHA-256 sur un bloc de 512 bits.
    Expansion : 16 mots de 32 bits → 64 mots (schedule).
    Compression : 64 tours avec les constantes K[i].
    """
    w = list(struct.unpack('>16I', block))
    for i in range(16, 64):
        s0 = gamma0(w[i - 15])
        s1 = gamma1(w[i -  2])
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK32)

    a, b, c, d, e, f, g, hh = h

    for i in range(64):
        S1    = sigma1(e)
        ch_   = ch(e, f, g)
        temp1 = (hh + S1 + ch_ + K[i] + w[i]) & MASK32
        S0    = sigma0(a)
        maj_  = maj(a, b, c)
        temp2 = (S0 + maj_) & MASK32

        hh = g;  g = f;  f = e
        e  = (d + temp1) & MASK32
        d  = c;  c = b;  b = a
        a  = (temp1 + temp2) & MASK32

    return [
        (h[0] + a) & MASK32, (h[1] + b) & MASK32,
        (h[2] + c) & MASK32, (h[3] + d) & MASK32,
        (h[4] + e) & MASK32, (h[5] + f) & MASK32,
        (h[6] + g) & MASK32, (h[7] + hh) & MASK32,
    ]

# ─────────────────────────────────────────────
# SHA-256 complet
# ─────────────────────────────────────────────

def sha256(message: bytes) -> str:
    """Calcule le digest SHA-256 d'un message quelconque."""
    padded = md_padding(message)
    h = H0[:]
    for i in range(0, len(padded), 64):
        h = compress_block(padded[i:i + 64], h)
    return ''.join(f'{x:08x}' for x in h)


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE SHA256Algorithm POUR L'INTERFACE MAIN.PY
# ══════════════════════════════════════════════════════════════════════════════

class SHA256Algorithm:
    def get_name(self):
        return "SHA-256 (Secure Hash Algorithm 2)"
    
    def get_description(self):
        return (
            "SHA-256 — Fonction de hachage (256 bits)\n"
            "• Construction : Merkle-Damgård\n"
            "• 64 tours | Bloc : 512 bits\n"
            "• Sortie : 64 caractères hexadécimaux (256 bits)\n"
            "• Standard : TLS, git, Bitcoin, JWT, Blockchain\n"
            "• ✓ Toujours sécurisé (pas de collision pratique)\n"
            "• Format clé : 'avalanche' pour démo effet avalanche"
        )
    
    def get_key_info(self):
        return {
            "type": "hash",
            "placeholder": "Entrée quelconque | 'avalanche'"
        }
    
    def flip_bit(self, data: bytes, bit_index: int) -> bytes:
        """Inverse le bit `bit_index` dans `data`."""
        byte_index = bit_index // 8
        bit_offset = 7 - (bit_index % 8)
        ba = bytearray(data)
        ba[byte_index] ^= (1 << bit_offset)
        return bytes(ba)
    
    def hex_to_bits(self, hex_str: str) -> str:
        """Convertit un digest hex en chaîne de bits."""
        return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)
    
    def bit_difference_rate(self, hex1: str, hex2: str) -> float:
        """Taux de bits différents entre deux digests hexadécimaux."""
        bits1 = self.hex_to_bits(hex1)
        bits2 = self.hex_to_bits(hex2)
        diff = sum(b1 != b2 for b1, b2 in zip(bits1, bits2))
        return diff / len(bits1)
    
    def encrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        """
        Calcule le hash SHA-256 du texte.
        """
        data = text.encode("utf-8")
        digest = sha256(data)
        
        if log_step:
            log_step("🔐 SHA-256 — CALCUL DE HACHAGE")
            log_step("=" * 42)
            log_step(f"   Entrée : {text[:100]}{'...' if len(text) > 100 else ''}")
            log_step(f"   Taille : {len(data)} octets")
            log_step(f"   Hash SHA-256 : {digest}")
            log_step(f"   Taille hash : {len(digest) * 4} bits")
        
        # Mode avalanche (démonstration de l'effet avalanche)
        if str(key).strip().lower() == "avalanche":
            modified = self.flip_bit(data, 0)
            digest2 = sha256(modified)
            taux = self.bit_difference_rate(digest, digest2)
            
            # Calculer le hash original via hashlib pour validation
            hash_expected = hashlib.sha256(data).hexdigest()
            validation = "✓" if digest == hash_expected else "⚠️"
            
            result = f"""
╔══════════════════════════════════════════════════════════════╗
║                 SHA-256 - EFFET AVALANCHE                   ║
╠══════════════════════════════════════════════════════════════╣
║  Validation implémentation : {validation} (vs hashlib)                   ║
╠══════════════════════════════════════════════════════════════╣
║  Hash original : {digest}                                     ║
║  Hash modifié  : {digest2}                                     ║
╠══════════════════════════════════════════════════════════════╣
║  Taux différences : {taux*100:.1f} % (cible ≈ 50 %)           ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ SHA-256 est sécurisé (pas de collision pratique)         ║
║  ✓ Utilisé dans Bitcoin, TLS, JWT, Blockchain               ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("✓ Effet avalanche démontré")
            
            return result
        
        # Formatage du résultat normal
        # Vérification avec hashlib
        hash_expected = hashlib.sha256(data).hexdigest()
        validation = "✓" if digest == hash_expected else "⚠️"
        
        result = f"""
╔══════════════════════════════════════════════════════════════╗
║                       HASH SHA-256                          ║
╠══════════════════════════════════════════════════════════════╣
║  Validation : {validation} (comparé à hashlib)                         ║
╠══════════════════════════════════════════════════════════════╣
║  Entrée : {text[:80]}{'...' if len(text) > 80 else ''}                     ║
║  Hash   : {digest}                                             ║
╠══════════════════════════════════════════════════════════════╣
║  Taille : 256 bits (64 caractères hexadécimaux)             ║
║  ✓ SHA-256 est la référence actuelle pour le hachage        ║
╚══════════════════════════════════════════════════════════════╝
"""
        return result
    
    def decrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        """
        SHA-256 est une fonction de hachage, pas un chiffrement.
        On ne peut pas déchiffrer.
        """
        return "⚠️ SHA-256 est une fonction de hachage à sens unique. Impossible de déchiffrer."


# ─────────────────────────────────────────────
# Partie 1 — Validation sur 10 vecteurs de test
# ─────────────────────────────────────────────

def partie1():
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║          Exercice 4.2 — SHA-256 from scratch         ║")
    print("╚══════════════════════════════════════════════════════╝")
    print("\n─── PARTIE 1 : Validation contre hashlib (10 vecteurs) ───\n")

    vecteurs = [
        b"",
        b"a",
        b"abc",
        b"message digest",
        b"abcdefghijklmnopqrstuvwxyz",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        b"12345678901234567890" * 4,
        b"The quick brown fox jumps over the lazy dog",
        b"The quick brown fox jumps over the lazy dog.",
        os.urandom(1000),
    ]

    ok = 0
    for i, msg in enumerate(vecteurs):
        mine     = sha256(msg)
        expected = hashlib.sha256(msg).hexdigest()
        match    = "✅ OK" if mine == expected else "❌ ERREUR"
        if mine == expected:
            ok += 1
        label = repr(msg[:20]) + ("…" if len(msg) > 20 else "")
        print(f"  [{i+1:02d}] {label:<32} {match}")

    print(f"\n  Résultat : {ok}/10 vecteurs corrects")
    if ok == 10:
        print("  🎉 Implémentation SHA-256 validée !")
    else:
        print("  ⚠️  Des vecteurs ont échoué — vérifier l'implémentation.")

# ─────────────────────────────────────────────
# Partie 2 — Vérification d'intégrité simulée
# ─────────────────────────────────────────────

def partie2():
    print("\n─── PARTIE 2 : Vérification d'intégrité (simulation) ───\n")

    archive_data  = os.urandom(512 * 1024)
    hash_officiel = hashlib.sha256(archive_data).hexdigest()

    hash_local = hashlib.sha256(archive_data).hexdigest()
    statut     = "✅  OK — fichier intact" if hash_local == hash_officiel else "❌  CORROMPU"
    print(f"  Cas 1 — Fichier intact")
    print(f"    Hash officiel  : {hash_officiel}")
    print(f"    Hash local     : {hash_local}")
    print(f"    Statut         : {statut}\n")

    ba = bytearray(archive_data)
    ba[42] ^= 0x01
    hash_corrompu = hashlib.sha256(bytes(ba)).hexdigest()
    statut2       = "✅  OK" if hash_corrompu == hash_officiel else "❌  CORROMPU — falsification détectée"

    print(f"  Cas 2 — Fichier corrompu (1 bit modifié sur {512*1024*8:,} bits)")
    print(f"    Hash officiel  : {hash_officiel}")
    print(f"    Hash corrompu  : {hash_corrompu}")
    print(f"    Statut         : {statut2}")

    bits_orig = bin(int(hash_officiel, 16))[2:].zfill(256)
    bits_corr = bin(int(hash_corrompu, 16))[2:].zfill(256)
    diff_bits = sum(b1 != b2 for b1, b2 in zip(bits_orig, bits_corr))
    print(f"\n    Bits différents dans le digest : {diff_bits}/256 ({diff_bits/256*100:.1f} %)")
    print("    → Un seul bit modifié dans le fichier suffit à invalider le hash.")
    print("    → L'effet avalanche garantit que ~50 % des bits du digest changent.")


# ══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    partie1()
    partie2()
    print()