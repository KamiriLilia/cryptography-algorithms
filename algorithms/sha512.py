"""
Exercice 4.3 — SHA-512 et comparaison générale
SHA-512 : 512 bits, 80 tours, mots 64 bits
SHA-3   : construction éponge, immune length-extension
Benchmark sur 100 Mio : débit MD5 / SHA-256 / SHA-512 / SHA3-256 / SHA3-512

Corrections apportées :
  1. Alignement des lignes rapide/lent : {name:<10} pour largeur fixe
  2. SHA-3 (sha3_256 et sha3_512) ajouté au benchmark et à la comparaison
"""

import hashlib
import os
import time

# ─────────────────────────────────────────────
# Utilitaires
# ─────────────────────────────────────────────

def hex_to_bits(hex_str: str) -> str:
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)

def bit_diff_rate(h1: str, h2: str) -> float:
    b1, b2 = hex_to_bits(h1), hex_to_bits(h2)
    return sum(a != b for a, b in zip(b1, b2)) / len(b1)

def flip_bit(data: bytes, idx: int = 0) -> bytes:
    ba = bytearray(data)
    ba[idx // 8] ^= 1 << (7 - idx % 8)
    return bytes(ba)

def banner(t):
    print(f"\n{'═'*66}\n  {t}\n{'═'*66}")

# ─────────────────────────────────────────────
# Algorithmes à comparer
# ─────────────────────────────────────────────

ALGOS = {
    "MD5"      : (hashlib.md5,       128),
    "SHA-256"  : (hashlib.sha256,    256),
    "SHA-512"  : (hashlib.sha512,    512),
    "SHA3-256" : (hashlib.sha3_256,  256),
    "SHA3-512" : (hashlib.sha3_512,  512),
}

# ─────────────────────────────────────────────
# Partie 1 — Comparaison sur un même message
# ─────────────────────────────────────────────

def partie1():
    banner("PARTIE 1 — Comparaison MD5 / SHA-256 / SHA-512 / SHA3 sur un même message")

    message = b"Cryptographie appliquee - exercice 4.3"
    modifie = flip_bit(message)

    print(f"\n  Message original  : {message.decode()}")
    print(f"  Message modifié   : 1 bit inversé (bit 0 de l'octet 0)\n")

    print(f"  {'Algorithme':<10}  {'Construction':<18}  {'Bits':>6}  "
          f"{'Temps (µs)':>11}  {'Hash (tronqué)':<22}  {'Avalanche'}")
    print("  " + "─" * 90)

    for name, (fn, bits) in ALGOS.items():
        runs = 200
        t0 = time.perf_counter()
        for _ in range(runs):
            digest = fn(message).hexdigest()
        t1 = time.perf_counter()
        micros = (t1 - t0) / runs * 1e6

        digest2 = fn(modifie).hexdigest()
        taux    = bit_diff_rate(digest, digest2)

        actual_bits = len(hex_to_bits(digest))
        assert actual_bits == bits, f"{name}: {actual_bits} bits au lieu de {bits}"

        construction = "Éponge (Keccak)" if name.startswith("SHA3") else "Merkle-Damgård"

        short = digest[:18] + "…"
        signe = "✅" if 0.40 <= taux <= 0.60 else "⚠️ "
        print(f"  {name:<10}  {construction:<18}  {bits:>6}  "
              f"{micros:>11.2f}  {short:<22}  {taux*100:5.1f} % {signe}")

    print()
    print("  Observations :")
    print("  • MD5 / SHA-256 / SHA-512 / SHA3 produisent des sorties de taille croissante")
    print("  • L'effet avalanche est ≈ 50 % pour chaque algorithme")
    print("  • SHA-512 utilise des mots de 64 bits → souvent plus rapide que SHA-256 sur x86-64")
    print("  • SHA3-256/512 (construction éponge) sont immunes à la length-extension attack")
    print("  • SHA-2 et MD5 (Merkle-Damgård) sont vulnérables à la length-extension attack")

# ─────────────────────────────────────────────
# Partie 2 — Benchmark sur 100 Mio
# ─────────────────────────────────────────────

def partie2():
    banner("PARTIE 2 — Benchmark débit sur 100 Mio de données")

    SIZE_MB = 100
    CHUNK   = 1024 * 1024
    N_CHUNK = SIZE_MB

    print(f"\n  Génération de {SIZE_MB} Mio de données aléatoires…")
    chunks = [os.urandom(CHUNK) for _ in range(N_CHUNK)]
    print("  Données prêtes.\n")

    print(f"  {'Algorithme':<10}  {'Construction':<18}  "
          f"{'Temps (s)':>10}  {'Débit (Mio/s)':>14}  {'Hash (tronqué)'}")
    print("  " + "─" * 80)

    resultats = {}
    for name, (fn, _) in ALGOS.items():
        h  = fn()
        t0 = time.perf_counter()
        for chunk in chunks:
            h.update(chunk)
        digest  = h.hexdigest()
        elapsed = time.perf_counter() - t0

        debit = SIZE_MB / elapsed
        resultats[name] = debit

        construction = "Éponge (Keccak)" if name.startswith("SHA3") else "Merkle-Damgård"
        short = digest[:14] + "…"
        print(f"  {name:<10}  {construction:<18}  "
              f"{elapsed:>10.3f}  {debit:>14.1f}  {short}")

    tri    = sorted(resultats.items(), key=lambda x: x[1], reverse=True)
    rapide = tri[0]
    lent   = tri[-1]

    print()
    print(f"  🏆 Le plus rapide : {rapide[0]:<10}  →  {rapide[1]:.1f} Mio/s")
    print(f"  🐢 Le plus lent   : {lent[0]:<10}  →  {lent[1]:.1f} Mio/s")

    print()
    print("  Classement complet :")
    for rang, (name, debit) in enumerate(tri, 1):
        print(f"    {rang}. {name:<10}  {debit:>8.1f} Mio/s")

    print()
    print("  Notes :")
    print("  • SHA-512 est généralement plus rapide que SHA-256 sur CPU 64 bits,")
    print("    car il traite 1024 bits/bloc avec des mots 64 bits natifs.")
    print("  • MD5 reste rapide mais est cryptographiquement cassé (Wang & Yu, 2004).")
    print("  • SHA3-256/512 (Keccak, construction éponge) :")
    print("    – Immunes à la length-extension attack par construction.")
    print("    – Généralement plus lents que SHA-2 sur CPU x86-64 (pas de matériel dédié).")
    print("  • SHA-256 bénéficie des extensions SHA-NI (Intel Goldmont+, AMD Zen+),")
    print("    ce qui peut le rendre plus rapide que SHA-512 sur certains CPU récents.")


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE SHA512Algorithm POUR L'INTERFACE MAIN.PY
# ══════════════════════════════════════════════════════════════════════════════

class SHA512Algorithm:
    def get_name(self):
        return "SHA-512 (Secure Hash Algorithm 2)"
    
    def get_description(self):
        return (
            "SHA-512 — Fonction de hachage (512 bits)\n"
            "• Construction : Merkle-Damgård\n"
            "• 80 tours | Mots : 64 bits | Bloc : 1024 bits\n"
            "• Sortie : 128 caractères hexadécimaux (512 bits)\n"
            "• Performance : souvent plus rapide que SHA-256 sur CPU 64 bits\n"
            "• Standard : chiffrement, signatures, blockchain\n"
            "• Format clé : 'benchmark' pour tester les performances\n"
            "  'avalanche' pour démonstration effet avalanche"
        )
    
    def get_key_info(self):
        return {
            "type": "hash",
            "placeholder": "Entrée quelconque | 'avalanche' | 'benchmark'"
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
        Calcule le hash SHA-512 du texte.
        """
        data = text.encode("utf-8")
        digest = hashlib.sha512(data).hexdigest()
        
        if log_step:
            log_step("🔐 SHA-512 — CALCUL DE HACHAGE")
            log_step("=" * 42)
            log_step(f"   Entrée : {text[:100]}{'...' if len(text) > 100 else ''}")
            log_step(f"   Taille : {len(data)} octets")
            log_step(f"   Hash SHA-512 : {digest[:64]}...")
            log_step(f"   Taille hash : {len(digest) * 4} bits")
        
        # Mode benchmark
        if str(key).strip().lower() == "benchmark":
            return self._run_benchmark(log_step)
        
        # Mode avalanche
        if str(key).strip().lower() == "avalanche":
            modified = self.flip_bit(data, 0)
            digest2 = hashlib.sha512(modified).hexdigest()
            taux = self.bit_difference_rate(digest, digest2)
            
            result = f"""
╔══════════════════════════════════════════════════════════════╗
║                 SHA-512 - EFFET AVALANCHE                   ║
╠══════════════════════════════════════════════════════════════╣
║  Hash original : {digest[:48]}...                             ║
║  Hash modifié  : {digest2[:48]}...                             ║
╠══════════════════════════════════════════════════════════════╣
║  Taux différences : {taux*100:.1f} % (cible ≈ 50 %)           ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ SHA-512 est sécurisé                                      ║
║  ✓ Plus rapide que SHA-256 sur CPU 64 bits                   ║
╚══════════════════════════════════════════════════════════════╝
"""
            if log_step:
                log_step("✓ Effet avalanche démontré")
            
            return result
        
        # Formatage du résultat normal
        result = f"""
╔══════════════════════════════════════════════════════════════╗
║                       HASH SHA-512                          ║
╠══════════════════════════════════════════════════════════════╣
║  Entrée : {text[:80]}{'...' if len(text) > 80 else ''}                     ║
║  Hash   : {digest[:64]}...                                     ║
╠══════════════════════════════════════════════════════════════╣
║  Taille : 512 bits (128 caractères hexadécimaux)            ║
║  ✓ SHA-512 est plus rapide que SHA-256 sur CPU 64 bits      ║
╚══════════════════════════════════════════════════════════════╝
"""
        return result
    
    def _run_benchmark(self, log_step=None):
        """Exécute un benchmark des algorithmes de hachage"""
        SIZE_MB = 100
        CHUNK = 1024 * 1024
        N_CHUNK = SIZE_MB
        
        if log_step:
            log_step("📊 SHA-512 — BENCHMARK SUR 100 Mio")
            log_step("=" * 42)
            log_step(f"   Génération de {SIZE_MB} Mio de données...")
        
        chunks = [os.urandom(CHUNK) for _ in range(N_CHUNK)]
        
        results = {}
        algos_to_test = {
            "MD5": hashlib.md5,
            "SHA-256": hashlib.sha256,
            "SHA-512": hashlib.sha512,
            "SHA3-256": hashlib.sha3_256,
            "SHA3-512": hashlib.sha3_512,
        }
        
        for name, fn in algos_to_test.items():
            h = fn()
            t0 = time.perf_counter()
            for chunk in chunks:
                h.update(chunk)
            elapsed = time.perf_counter() - t0
            debit = SIZE_MB / elapsed
            results[name] = debit
        
        tri = sorted(results.items(), key=lambda x: x[1], reverse=True)
        
        result = f"""
╔══════════════════════════════════════════════════════════════╗
║            BENCHMARK HACHAGE SUR {SIZE_MB} Mio                     ║
╠══════════════════════════════════════════════════════════════╣
║  Classement (débit en Mio/s) :                               ║
"""
        for rang, (name, debit) in enumerate(tri, 1):
            result += f"║    {rang}. {name:<10}  {debit:>8.1f} Mio/s{' 🏆' if rang == 1 else ''}                        ║\n"
        
        result += f"""╠══════════════════════════════════════════════════════════════╣
║  Observations :                                             ║
║  • SHA-512 est souvent plus rapide que SHA-256 sur 64 bits ║
║  • MD5 est rapide mais cassé (ne pas utiliser)             ║
║  • SHA3 est plus lent mais immune à length-extension       ║
╚══════════════════════════════════════════════════════════════╝
"""
        if log_step:
            log_step("✓ Benchmark terminé")
        
        return result
    
    def decrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        """
        SHA-512 est une fonction de hachage, pas un chiffrement.
        On ne peut pas déchiffrer.
        """
        return "⚠️ SHA-512 est une fonction de hachage à sens unique. Impossible de déchiffrer."


# ─────────────────────────────────────────────
# Point d'entrée
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║    Exercice 4.3 — SHA-512 & Comparaison générale        ║")
    print("╚══════════════════════════════════════════════════════════╝")
    partie1()
    partie2()
    print()