"""
Twofish - TP2 Exercice 2.4 (Finaliste NIST)
Implémentation pédagogique complète avec affichage
détaillé étape par étape (log_step / log_matrix) — style DES.
"""

import time
import os


class TwofishAlgorithm:
    """
    Architecture Twofish :
    - Type : Réseau de Feistel (4 branches, structure LR modifiée)
    - Bloc : 128 bits
    - Clé  : 128, 192 ou 256 bits
    - Tours : 16
    """

    Q0 = list(range(256))
    Q1 = [(i * 167 + 13) % 256 for i in range(256)]

    def __init__(self):
        self.Q0_inv = [0] * 256
        self.Q1_inv = [0] * 256
        for i, v in enumerate(self.Q0):
            self.Q0_inv[v] = i
        for i, v in enumerate(self.Q1):
            self.Q1_inv[v] = i

    # ──────────────────────────────────────────────────────────────
    # Interface
    # ──────────────────────────────────────────────────────────────

    def get_name(self):
        return "Twofish"

    def get_description(self):
        return (
            "Twofish — Finaliste NIST AES (2e place, 2000).\n"
            "• Structure : Réseau de Feistel à 4 branches (modifié)\n"
            "• Bloc : 128 bits | Clé : 128/192/256 bits | 16 tours\n"
            "• S-boxes dépendantes de la clé (key-dependent)\n"
            "• Matrice MDS 4×4 sur GF(2⁸) pour la diffusion\n"
            "• Transformation PHT (Pseudo-Hadamard)\n"
            "• Key whitening en entrée et sortie"
        )

    def get_key_info(self):
        return {
            "type": "symmetric",
            "placeholder": "Clé texte (16+ caractères recommandés)"
        }

    # ──────────────────────────────────────────────────────────────
    # Arithmétique GF(2⁸)
    # ──────────────────────────────────────────────────────────────

    def _gf_mul(self, a: int, b: int, poly: int = 0x169) -> int:
        """Multiplication dans GF(2⁸) avec polynôme 0x169."""
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            carry = a & 0x80
            a = (a << 1) & 0xFF
            if carry:
                a ^= (poly & 0xFF)
            b >>= 1
        return result

    # ──────────────────────────────────────────────────────────────
    # Key Schedule
    # ──────────────────────────────────────────────────────────────

    def _key_schedule(self, key: str, log_step=None, log_matrix=None):
        """Dérive les sous-clés depuis la clé avec log détaillé."""
        key_bytes = key.encode("utf-8")
        key_bytes = (key_bytes * 4)[:32]

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║      TWOFISH — KEY SCHEDULE (40 sous-clés)   ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Clé brute (hex) : {key_bytes.hex().upper()}")
            log_step(f"  Clé 256 bits    : {key_bytes[:16].hex().upper()}")
            log_step(f"                    {key_bytes[16:].hex().upper()}")
            log_step("")
            log_step("  ── Étape 1 : Décomposition en mots 32 bits ──")

        words = [int.from_bytes(key_bytes[i:i+4], 'little') for i in range(0, 32, 4)]
        Me = words[0::2]   # mots d'indice pair
        Mo = words[1::2]   # mots d'indice impair

        if log_step:
            log_step(f"  8 mots de 32 bits (little-endian) :")
            for idx, w in enumerate(words):
                tag = "Me" if idx % 2 == 0 else "Mo"
                log_step(f"    w[{idx}] = {w:08X}  ({tag})")
            log_step(f"  Me (pairs) = {[f'{v:08X}' for v in Me]}")
            log_step(f"  Mo (impairs)= {[f'{v:08X}' for v in Mo]}")
            log_step("")
            log_step("  ── Étape 2 : Génération des 20 paires (K2i, K2i+1) ──")
            log_step("  Formule :")
            log_step("    A    = h(2i · ρ, Me)")
            log_step("    B    = ROL8( h((2i+1) · ρ, Mo) )")
            log_step("    K2i  = (A + B)   mod 2³²")
            log_step("    K2i+1= (A + 2B)  mod 2³²")
            log_step("    ρ = 0x01010101")
            log_step("")
            log_step(f"  {'Paire':>6}  {'A':>10}  {'B':>10}  {'K2i':>10}  {'K2i+1':>10}")
            log_step(f"  {'─'*56}")

        RHO = 0x01010101
        round_keys = []

        for i in range(20):
            A = self._h(2 * i * RHO, Me)
            B = self._h((2 * i + 1) * RHO, Mo)
            B = ((B << 8) | (B >> 24)) & 0xFFFFFFFF
            K2i  = (A + B)     & 0xFFFFFFFF
            K2i1 = (A + 2 * B) & 0xFFFFFFFF
            round_keys.extend([K2i, K2i1])
            if log_step:
                log_step(
                    f"  K{2*i:02d}-{2*i+1:02d}   "
                    f"{A:08X}   {B:08X}   {K2i:08X}   {K2i1:08X}"
                )

        if log_step:
            log_step(f"  {'─'*56}")
            log_step(f"  ✅ 40 sous-clés de 32 bits générées")
            log_step(f"     K[0..3]  → whitening entrée")
            log_step(f"     K[4..7]  → whitening sortie")
            log_step(f"     K[8..39] → 16 rounds (2 clés/round)")

        if log_matrix:
            log_matrix("KEY SCHEDULE — K[0..7] (whitening + 1er round)",
                       [b for k in round_keys[:8]
                        for b in k.to_bytes(4, 'big')])

        s_key = words
        return round_keys, s_key

    # ──────────────────────────────────────────────────────────────
    # Fonction h
    # ──────────────────────────────────────────────────────────────

    def _h(self, x: int, L: list) -> int:
        """Fonction h de Twofish (sans log pour éviter verbosité excessive)."""
        b = [(x >> (i * 8)) & 0xFF for i in range(4)]
        for i, li in enumerate(L):
            lb = [(li >> (j * 8)) & 0xFF for j in range(4)]
            b = [b[j] ^ lb[j] for j in range(4)]
            b = [self.Q0[b[j]] if i % 2 == 0 else self.Q1[b[j]] for j in range(4)]
        result = 0
        mds_col = [0x01, 0xEF, 0x5B, 0x5B]
        for j in range(4):
            val = sum(self._gf_mul(b[(j + k) % 4], mds_col[k]) for k in range(4)) & 0xFF
            result |= (val << (j * 8))
        return result

    def _h_verbose(self, x: int, L: list, label: str, log_step) -> int:
        """Version verbeux de h pour les rounds affichés."""
        b = [(x >> (i * 8)) & 0xFF for i in range(4)]
        log_step(f"  │  │  h({label}) : entrée bytes = "
                 f"[{b[0]:02X},{b[1]:02X},{b[2]:02X},{b[3]:02X}]")

        for i, li in enumerate(L):
            lb = [(li >> (j * 8)) & 0xFF for j in range(4)]
            b  = [b[j] ^ lb[j] for j in range(4)]
            log_step(f"  │  │    XOR ⊕ L[{i}] = {li:08X}  → "
                     f"[{b[0]:02X},{b[1]:02X},{b[2]:02X},{b[3]:02X}]")
            b  = [self.Q0[b[j]] if i % 2 == 0 else self.Q1[b[j]] for j in range(4)]
            q  = "Q0" if i % 2 == 0 else "Q1"
            log_step(f"  │  │    {q}          → "
                     f"[{b[0]:02X},{b[1]:02X},{b[2]:02X},{b[3]:02X}]")

        result = 0
        mds_col = [0x01, 0xEF, 0x5B, 0x5B]
        out_bytes = []
        for j in range(4):
            val = sum(self._gf_mul(b[(j+k) % 4], mds_col[k]) for k in range(4)) & 0xFF
            out_bytes.append(val)
            result |= (val << (j * 8))
        log_step(f"  │  │    MDS GF(2⁸)    → "
                 f"[{out_bytes[0]:02X},{out_bytes[1]:02X},"
                 f"{out_bytes[2]:02X},{out_bytes[3]:02X}]  = {result:08X}")
        return result

    # ──────────────────────────────────────────────────────────────
    # Fonction F
    # ──────────────────────────────────────────────────────────────

    def _f_function(self, R0: int, R1: int, round_keys: list,
                    s_key: list, r: int,
                    log_step=None) -> tuple:
        """
        Fonction F de Twofish :
          T0 = h(R0, s_key)
          T1 = h(ROL8(R1), s_key)
          F0 = T0 + T1 + K_{2r+8}   (PHT)
          F1 = T0 + 2·T1 + K_{2r+9} (PHT)
        """
        if log_step:
            log_step(f"  │  ┌─ Fonction F — Round {r+1:02d}")
            log_step(f"  │  │  Entrée : R0 = {R0:08X}   R1 = {R1:08X}")
            log_step(f"  │  │")
            log_step(f"  │  │  ── T0 = h(R0, s_key) ──────────────────")
            T0 = self._h_verbose(R0, s_key, f"R0={R0:08X}", log_step)
            log_step(f"  │  │  T0 = {T0:08X}")
            log_step(f"  │  │")
            log_step(f"  │  │  ── T1 = h(ROL8(R1), s_key) ─────────────")
            R1_rot = ((R1 << 8) | (R1 >> 24)) & 0xFFFFFFFF
            log_step(f"  │  │  ROL8(R1) = ROL8({R1:08X}) = {R1_rot:08X}")
            T1 = self._h_verbose(R1_rot, s_key, f"ROL8(R1)={R1_rot:08X}", log_step)
            log_step(f"  │  │  T1 = {T1:08X}")
            log_step(f"  │  │")
            log_step(f"  │  │  ── PHT (Pseudo-Hadamard Transform) ───────")
            log_step(f"  │  │  K[{2*r+8}] = {round_keys[2*r+8]:08X}")
            log_step(f"  │  │  K[{2*r+9}] = {round_keys[2*r+9]:08X}")
            F0 = (T0 + T1 + round_keys[2*r+8]) & 0xFFFFFFFF
            F1 = (T0 + 2*T1 + round_keys[2*r+9]) & 0xFFFFFFFF
            log_step(f"  │  │  F0 = T0 + T1   + K[{2*r+8}] = "
                     f"{T0:08X} + {T1:08X} + {round_keys[2*r+8]:08X} = {F0:08X}")
            log_step(f"  │  │  F1 = T0 + 2·T1 + K[{2*r+9}] = "
                     f"{T0:08X} + {2*T1:09X} + {round_keys[2*r+9]:08X} = {F1:08X}")
            log_step(f"  │  └─ F(R0,R1) = ({F0:08X}, {F1:08X})")
        else:
            T0 = self._h(R0, s_key)
            T1 = self._h(((R1 << 8) | (R1 >> 24)) & 0xFFFFFFFF, s_key)
            F0 = (T0 + T1  + round_keys[2*r+8]) & 0xFFFFFFFF
            F1 = (T0 + 2*T1 + round_keys[2*r+9]) & 0xFFFFFFFF

        return F0, F1

    # ──────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────

    def _split_block(self, block: int):
        mask = 0xFFFFFFFF
        return (block & mask, (block >> 32) & mask,
                (block >> 64) & mask, (block >> 96) & mask)

    def _join_block(self, r0, r1, r2, r3) -> int:
        return r0 | (r1 << 32) | (r2 << 64) | (r3 << 96)

    def _rot_right(self, v: int, n: int) -> int:
        return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF

    def _rot_left(self, v: int, n: int) -> int:
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    # ──────────────────────────────────────────────────────────────
    # Chiffrement d'un bloc 128 bits
    # ──────────────────────────────────────────────────────────────

    def _encrypt_block(self, block: int, round_keys: list,
                       s_key: list, log_step=None, log_matrix=None) -> int:

        r0, r1, r2, r3 = self._split_block(block)

        if log_step:
            log_step("┌─────────────────────────────────────────────────────┐")
            log_step(f"│  TWOFISH — CHIFFREMENT D'UN BLOC 128 bits           │")
            log_step("└─────────────────────────────────────────────────────┘")
            log_step(f"  Bloc brut     : {block:032X}")
            log_step(f"  Split (little): r0={r0:08X}  r1={r1:08X}  "
                     f"r2={r2:08X}  r3={r3:08X}")
            log_step("")
            log_step("  ── Input Whitening (XOR avec K[0..3]) ─────────────")
            log_step(f"  K[0]={round_keys[0]:08X}  K[1]={round_keys[1]:08X}  "
                     f"K[2]={round_keys[2]:08X}  K[3]={round_keys[3]:08X}")
            log_step(f"  Avant : r0={r0:08X}  r1={r1:08X}  "
                     f"r2={r2:08X}  r3={r3:08X}")

        r0 ^= round_keys[0]
        r1 ^= round_keys[1]
        r2 ^= round_keys[2]
        r3 ^= round_keys[3]

        if log_step:
            log_step(f"  Après : r0={r0:08X}  r1={r1:08X}  "
                     f"r2={r2:08X}  r3={r3:08X}")
            log_step("")

        if log_matrix:
            log_matrix("APRÈS INPUT WHITENING",
                       list(self._join_block(r0,r1,r2,r3).to_bytes(16,'big')))

        for r in range(16):
            # Affiche rounds 1, 2 et 16
            show = log_step and (r < 2 or r == 15)

            if show:
                log_step(f"  ══════════════ Round {r+1:02d} / 16 ══════════════")
                log_step(f"  │  État : r0={r0:08X}  r1={r1:08X}  "
                         f"r2={r2:08X}  r3={r3:08X}")

            F0, F1 = self._f_function(
                r0, r1, round_keys, s_key, r,
                log_step=(log_step if show else None)
            )

            if show:
                log_step(f"  │")
                log_step(f"  │  ── Application du réseau Feistel ──────────")
                log_step(f"  │  r2' = ROR1(r2 ⊕ F0)")
                log_step(f"  │       = ROR1({r2:08X} ⊕ {F0:08X})")

            new_r2 = self._rot_right(r2 ^ F0, 1)

            if show:
                log_step(f"  │       = ROR1({r2 ^ F0:08X}) = {new_r2:08X}")
                log_step(f"  │  r3' = ROL1(r3) ⊕ F1")
                log_step(f"  │       = ROL1({r3:08X}) ⊕ {F1:08X}")

            new_r3 = self._rot_left(r3, 1) ^ F1

            if show:
                log_step(f"  │       = {self._rot_left(r3,1):08X} ⊕ {F1:08X} = {new_r3:08X}")
                log_step(f"  │  Swap (r0,r1,r2,r3) → (r2',r3',r0,r1)")

            r0, r1, r2, r3 = new_r2, new_r3, r0, r1

            if show:
                log_step(f"  │  → r0={r0:08X}  r1={r1:08X}  "
                         f"r2={r2:08X}  r3={r3:08X}")

            if log_step and r == 2 and r != 15:
                log_step(f"  ... (rounds 3 → 15 non affichés) ...")

        # Défaire le dernier swap
        r0, r1, r2, r3 = r2, r3, r0, r1

        if log_step:
            log_step("")
            log_step("  ── Output Whitening (XOR avec K[4..7]) ────────────")
            log_step(f"  Avant : r0={r0:08X}  r1={r1:08X}  "
                     f"r2={r2:08X}  r3={r3:08X}")
            log_step(f"  K[4]={round_keys[4]:08X}  K[5]={round_keys[5]:08X}  "
                     f"K[6]={round_keys[6]:08X}  K[7]={round_keys[7]:08X}")

        r0 ^= round_keys[4]
        r1 ^= round_keys[5]
        r2 ^= round_keys[6]
        r3 ^= round_keys[7]

        result = self._join_block(r0, r1, r2, r3)

        if log_step:
            log_step(f"  Après : r0={r0:08X}  r1={r1:08X}  "
                     f"r2={r2:08X}  r3={r3:08X}")
            log_step(f"  ✅ Bloc chiffré = {result:032X}")

        if log_matrix:
            log_matrix("BLOC CHIFFRÉ (bytes)", list(result.to_bytes(16,'big')))

        return result

    # ──────────────────────────────────────────────────────────────
    # Déchiffrement d'un bloc
    # ──────────────────────────────────────────────────────────────

    def _decrypt_block(self, block: int, round_keys: list,
                       s_key: list, log_step=None) -> int:
        r0, r1, r2, r3 = self._split_block(block)

        if log_step:
            log_step("┌─────────────────────────────────────────────────────┐")
            log_step("│  TWOFISH — DÉCHIFFREMENT D'UN BLOC 128 bits         │")
            log_step("└─────────────────────────────────────────────────────┘")
            log_step(f"  Bloc chiffré : {block:032X}")
            log_step("")
            log_step("  ── Output Whitening inverse (XOR K[4..7]) ──────────")

        r0 ^= round_keys[4]
        r1 ^= round_keys[5]
        r2 ^= round_keys[6]
        r3 ^= round_keys[7]

        if log_step:
            log_step(f"  Après : r0={r0:08X}  r1={r1:08X}  "
                     f"r2={r2:08X}  r3={r3:08X}")
            log_step("")

        for r in range(15, -1, -1):
            show = log_step and (r >= 14 or r < 2)

            r0, r1, r2, r3 = r2, r3, r0, r1
            F0, F1 = self._f_function(r0, r1, round_keys, s_key, r,
                                      log_step=(log_step if show else None))

            if show:
                log_step(f"  ══════════════ Round {r+1:02d} inverse ══════════════")

            new_r2 = self._rot_left(r2, 1) ^ F0
            new_r3 = self._rot_right(r3 ^ F1, 1)
            r0, r1, r2, r3 = r0, r1, new_r2, new_r3

            if log_step and r == 13:
                log_step("  ... (rounds intermédiaires non affichés) ...")

        r0, r1, r2, r3 = r2, r3, r0, r1

        if log_step:
            log_step("")
            log_step("  ── Input Whitening inverse (XOR K[0..3]) ───────────")

        r0 ^= round_keys[0]
        r1 ^= round_keys[1]
        r2 ^= round_keys[2]
        r3 ^= round_keys[3]

        result = self._join_block(r0, r1, r2, r3)

        if log_step:
            log_step(f"  ✅ Bloc déchiffré = {result:032X}")

        return result

    # ──────────────────────────────────────────────────────────────
    # Interface encrypt / decrypt
    # ──────────────────────────────────────────────────────────────

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:

        block_bytes = text.encode("utf-8")[:16].ljust(16, b'\x00')
        block_int   = int.from_bytes(block_bytes, 'little')

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║          TWOFISH — CHIFFREMENT               ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Texte clair  : '{text}'")
            log_step(f"  Clé brute    : '{key}'")
            log_step(f"  Taille texte : {len(text.encode())} octet(s) "
                     f"(padded à 16)")
            log_step(f"  Bloc (hex)   : {block_bytes.hex().upper()}")

        if log_matrix:
            log_matrix("TEXTE CLAIR (bytes)", list(block_bytes))

        round_keys, s_key = self._key_schedule(key, log_step, log_matrix)

        result_int   = self._encrypt_block(block_int, round_keys, s_key,
                                           log_step, log_matrix)
        result_bytes = result_int.to_bytes(16, 'little')

        if log_step:
            log_step("")
            log_step("  ── Résultat final ────────────────────────────")
            log_step(f"  Ciphertext (hex) : {result_bytes.hex().upper()}")

        if log_matrix:
            log_matrix("CIPHERTEXT FINAL (bytes)", list(result_bytes))

        return result_bytes.hex()

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:

        try:
            block_bytes = bytes.fromhex(text.strip())[:16].ljust(16, b'\x00')
        except ValueError:
            block_bytes = text.encode("utf-8")[:16].ljust(16, b'\x00')

        block_int = int.from_bytes(block_bytes, 'little')

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║         TWOFISH — DÉCHIFFREMENT              ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Chiffré (hex) : {block_bytes.hex().upper()}")

        if log_matrix:
            log_matrix("CIPHERTEXT (bytes)", list(block_bytes))

        round_keys, s_key = self._key_schedule(key, log_step, log_matrix)

        result_int   = self._decrypt_block(block_int, round_keys, s_key,
                                           log_step)
        result_bytes = result_int.to_bytes(16, 'little')
        result       = result_bytes.decode("utf-8", errors="ignore").rstrip('\x00')

        if log_step:
            log_step("")
            log_step("  ── Résultat final ────────────────────────────")
            log_step(f"  Texte clair  : '{result}'")

        if log_matrix:
            log_matrix("TEXTE DÉCHIFFRÉ (bytes)", list(result_bytes))

        return result


# ─────────────────────────────────────────────────────────────────
# PROGRAMME PRINCIPAL
# ─────────────────────────────────────────────────────────────────

def main():
    def log_step(msg): print(msg)
    def log_matrix(label, data):
        print(f"\n  [MATRICE] {label}")
        print("  " + " ".join(f"{b:02X}" for b in data))
        print()

    print("\n" + "█"*60)
    print("  EXERCICE 2.4 — TWOFISH (DÉTAILLÉ)")
    print("█"*60)

    tf   = TwofishAlgorithm()
    text = "Hello Twofish!"
    key  = "MaCleSecrete1234"

    enc = tf.encrypt(text, key, log_step, log_matrix)
    dec = tf.decrypt(enc,  key, log_step, log_matrix)

    print(f"\n  Texte original  : {text}")
    print(f"  Chiffré (hex)   : {enc}")
    print(f"  Déchiffré       : {dec}")
    print(f"  Vérif           : {'✅ OK' if dec == text else '✗ ERREUR'}")
    print("\n" + "█"*60 + "\n")


if __name__ == "__main__":
    main()