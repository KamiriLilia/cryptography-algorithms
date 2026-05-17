"""
DES (Data Encryption Standard) - TP2 Exercice 2.2
Style mixte :
  - Couleurs automatiques via classify_log_line (main.py)
  - Symbole ⊕ visible pour chaque XOR byte par byte
  - Matrices hex formatées via log_matrix
  - S-Boxes : tableau avec ligne / colonne / valeur
  - Rounds Feistel numérotés et détaillés
"""

import os
import struct


class DESAlgorithm:

    def __init__(self):
        self.IP = [
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
        ]
        self.IP_INV = [
            40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
            38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
            36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
            34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25
        ]
        self.E = [
            32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
             8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
        ]
        self.P = [
            16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,
             5, 18, 31, 10,  2,  8, 24, 14, 32, 27,  3,  9,
            19, 13, 30,  6, 22, 11,  4, 25
        ]
        self.S_BOXES = [
            [[14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7],
             [ 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8],
             [ 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0],
             [15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13]],
            [[15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10],
             [ 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5],
             [ 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15],
             [13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9]],
            [[10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1],
             [13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7],
             [ 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12]],
            [[ 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15],
             [13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9],
             [10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4],
             [ 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14]],
            [[ 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9],
             [14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6],
             [ 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14],
             [11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3]],
            [[12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11],
             [10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8],
             [ 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6],
             [ 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13]],
            [[ 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1],
             [13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6],
             [ 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2],
             [ 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12]],
            [[13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7],
             [ 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2],
             [ 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8],
             [ 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11]],
        ]
        self.PC1 = [
            57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
            10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
            14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
        ]
        self.PC2 = [
            14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
            23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
        ]
        self.SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # ================================================================
    # INTERFACE
    # ================================================================

    def get_name(self):
        return "DES (Data Encryption Standard)"

    def get_description(self):
        return (
            "DES — Chiffrement par blocs (56 bits de clé)\n"
            "• Structure : Réseau de Feistel | 16 rounds\n"
            "• Bloc : 64 bits | Clé : 56 bits effectifs\n"
            "• Modes : ECB (défaut) | cbc:clé | 3des:clé24\n"
            "• Affichage : ⊕ XOR · S-Boxes · Rounds · Permutations"
        )

    def get_key_info(self):
        return {
            "type": "symmetric",
            "placeholder": "Clé 8 car. | cbc:clé | 3des:clé24"
        }

    # ================================================================
    # HELPERS
    # ================================================================

    def _h(self, val: int, bits: int) -> str:
        """Entier → hex majuscule, bon nombre de nibbles."""
        return format(val, f'0{bits // 4}X')

    def _xor_table(self, a_int: int, b_int: int, res_int: int,
                   nb_bytes: int, label_a: str, label_b: str,
                   label_res: str, log_step):
        """
        Affiche un XOR complet en tableau byte par byte avec le symbole ⊕.
        Compatible avec le tag 'xor' du classify_log_line.
        """
        a = a_int.to_bytes(nb_bytes, 'big')
        b = b_int.to_bytes(nb_bytes, 'big')
        r = res_int.to_bytes(nb_bytes, 'big')
        log_step(f"  XOR ⊕  {label_a}  ⊕  {label_b}  =  {label_res}")
        log_step(f"  {'Pos':>4}   {label_a:>6}   ⊕   {label_b:>6}   =   {label_res:>6}")
        log_step(f"  {'─'*44}")
        for i in range(nb_bytes):
            log_step(f"  [{i+1:>2}]    {a[i]:02X}       ⊕    {b[i]:02X}       =    {r[i]:02X}")
        log_step(f"  {'─'*44}")
        log_step(f"  XOR résultat : {res_int.to_bytes(nb_bytes,'big').hex().upper()}")

    # ================================================================
    # PRIMITIVES
    # ================================================================

    def _permute(self, block: int, table: list, in_bits: int) -> int:
        out = 0
        for pos in table:
            out = (out << 1) | ((block >> (in_bits - pos)) & 1)
        return out

    def _left_rotate(self, val: int, n: int, size: int = 28) -> int:
        return ((val << n) | (val >> (size - n))) & ((1 << size) - 1)

    # ================================================================
    # KEY SCHEDULE
    # ================================================================

    def _generate_round_keys(self, key: bytes,
                             log_step=None, log_matrix=None) -> list:
        key_int = int.from_bytes(key[:8].ljust(8, b'\x00'), 'big')

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║        KEY SCHEDULE — 16 SOUS-CLÉS           ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Clé originale (64 bits) : {self._h(key_int, 64)}")

        key_56 = self._permute(key_int, self.PC1, 64)

        if log_step:
            log_step(f"  Après Permutation PC-1 (56 bits) : {self._h(key_56, 56)}")

        C = (key_56 >> 28) & 0xFFFFFFF
        D =  key_56        & 0xFFFFFFF

        if log_step:
            log_step(f"  C0 = {format(C,'07X')}   D0 = {format(D,'07X')}")
            log_step(f"  {'─'*62}")
            log_step(f"  {'Rnd':>4}  {'Rot':>4}  {'C':>10}  {'D':>10}  {'Sous-clé K (48 bits)':>16}")
            log_step(f"  {'─'*62}")

        round_keys = []
        for i, shift in enumerate(self.SHIFTS):
            C  = self._left_rotate(C, shift)
            D  = self._left_rotate(D, shift)
            CD = (C << 28) | D
            rk = self._permute(CD, self.PC2, 56)
            round_keys.append(rk)
            if log_step:
                log_step(
                    f"  K{i+1:02d}   +{shift}   "
                    f"{format(C,'07X')}   {format(D,'07X')}   "
                    f"{self._h(rk, 48)}"
                )

        if log_step:
            log_step(f"  {'─'*62}")
            log_step(f"  ✅ 16 sous-clés de 48 bits générées")

        return round_keys

    # ================================================================
    # FONCTION F (Feistel)
    # ================================================================

    def _f_function(self, R: int, K: int, round_num: int,
                    log_step=None, log_matrix=None) -> int:

        # 1. Expansion E : 32 → 48 bits
        R_exp = self._permute(R, self.E, 32)

        if log_step:
            log_step(f"  │  ┌─ Fonction F — Round {round_num:02d}")
            log_step(
                f"  │  │  Expansion E(R) : "
                f"{self._h(R, 32)} → {self._h(R_exp, 48)}  (32→48 bits)"
            )

        # 2. XOR E(R) ⊕ K
        xored = R_exp ^ K

        if log_step:
            log_step(f"  │  │")
            log_step(f"  │  │  XOR ⊕  E(R) ⊕ K{round_num:02d} :")
            log_step(f"  │  │    E(R) = {self._h(R_exp, 48)}")
            log_step(f"  │  │    K{round_num:02d}  = {self._h(K, 48)}")
            log_step(f"  │  │    ⊕")
            log_step(f"  │  │    {'─'*48}")
            a_b = R_exp.to_bytes(6, 'big')
            b_b = K.to_bytes(6, 'big')
            x_b = xored.to_bytes(6, 'big')
            for idx in range(6):
                log_step(
                    f"  │  │  [{idx+1}]  "
                    f"{a_b[idx]:08b} ⊕ {b_b[idx]:08b} = {x_b[idx]:08b}"
                    f"   ({a_b[idx]:02X} ⊕ {b_b[idx]:02X} = {x_b[idx]:02X})"
                )
            log_step(f"  │  │    {'─'*48}")
            log_step(f"  │  │    XOR = {self._h(xored, 48)}")

        # 3. S-Boxes
        result = 0
        if log_step:
            log_step(f"  │  │")
            log_step(f"  │  │  Substitution S-Boxes :")
            log_step(f"  │  │  {'S':>4}  {'Chunk':>10}  {'Ligne':>6}  {'Col':>5}  {'Sortie':>8}")
            log_step(f"  │  │  {'─'*44}")

        for i in range(8):
            chunk = (xored >> (42 - 6 * i)) & 0x3F
            row   = ((chunk >> 4) & 2) | (chunk & 1)
            col   = (chunk >> 1) & 0xF
            val   = self.S_BOXES[i][row][col]
            result = (result << 4) | val
            if log_step:
                log_step(
                    f"  │  │  S{i+1}   "
                    f"{format(chunk,'06b')}({chunk:02X})  "
                    f"   {row}     "
                    f"  {col:2d}    "
                    f"  → {val:2d} (0x{val:X})"
                )

        if log_step:
            log_step(f"  │  │  {'─'*44}")
            log_step(f"  │  │  Sortie S-Boxes (32 bits) = {self._h(result, 32)}")

        if log_matrix:
            log_matrix(f"S-Boxes sortie Round {round_num:02d}", list(result.to_bytes(4,'big')))

        # 4. Permutation P
        final = self._permute(result, self.P, 32)

        if log_step:
            log_step(f"  │  │")
            log_step(
                f"  │  │  Permutation P : "
                f"{self._h(result, 32)} → {self._h(final, 32)}"
            )
            log_step(f"  │  └─ f(R, K{round_num:02d}) = {self._h(final, 32)}")

        return final

    # ================================================================
    # CHIFFREMENT D'UN BLOC 64 bits
    # ================================================================

    def _des_block(self, block: bytes, round_keys: list,
                   log_step=None, log_matrix=None,
                   block_idx: int = 0, verbose: bool = True) -> bytes:

        b = int.from_bytes(block, 'big')

        if log_step and verbose:
            log_step(f"┌─────────────────────────────────────────────────────┐")
            log_step(f"│  BLOC #{block_idx}  —  Entrée : {self._h(b, 64)}  │")
            log_step(f"└─────────────────────────────────────────────────────┘")

        if log_matrix and verbose:
            log_matrix(f"BLOC #{block_idx} — ENTRÉE (bytes)", list(block))

        # Permutation initiale IP
        b_ip = self._permute(b, self.IP, 64)
        L    = (b_ip >> 32) & 0xFFFFFFFF
        R    =  b_ip        & 0xFFFFFFFF

        if log_step and verbose:
            log_step(
                f"  Permutation IP   : "
                f"{self._h(b, 64)} → {self._h(b_ip, 64)}"
            )
            log_step(f"  L0 = {self._h(L, 32)}   R0 = {self._h(R, 32)}")
            log_step(f"")

        for i, rk in enumerate(round_keys):
            # Affiche rounds 1, 2 et le dernier round (16)
            is_last = (i == len(round_keys) - 1)
            show    = verbose and (i < 2 or is_last)

            if log_step and show:
                log_step(f"  ══════════════ Round {i+1:02d} / 16 ══════════════")
                log_step(f"  │  L{i} = {self._h(L, 32)}   R{i} = {self._h(R, 32)}")

            f_res = self._f_function(
                R, rk, i + 1,
                log_step=(log_step if show else None),
                log_matrix=(log_matrix if show else None)
            )

            # XOR Feistel : nouveau R = L ⊕ f(R, K)
            new_r = L ^ f_res

            if log_step and show:
                log_step(f"  │")
                log_step(f"  │  XOR ⊕  L{i} ⊕ f(R{i}, K{i+1:02d}) :")
                log_step(f"  │    L{i}           = {self._h(L, 32)}")
                log_step(f"  │    f(R{i}, K{i+1:02d}) = {self._h(f_res, 32)}")
                log_step(f"  │    ⊕")
                l_b   = L.to_bytes(4, 'big')
                f_b   = f_res.to_bytes(4, 'big')
                nr_b  = new_r.to_bytes(4, 'big')
                for bi in range(4):
                    log_step(
                        f"  │    [{bi+1}]  {l_b[bi]:02X} ⊕ {f_b[bi]:02X} = {nr_b[bi]:02X}"
                    )
                log_step(f"  │    ──────────────────────────────")
                log_step(f"  │    Nouveau R{i+1} = {self._h(new_r, 32)}")

            L, R = R, new_r

            if log_step and show:
                log_step(f"  │  → L{i+1} = {self._h(L, 32)}   R{i+1} = {self._h(R, 32)}")

            # Message de saut pour les rounds intermédiaires
            if verbose and i == 2 and not is_last and log_step:
                log_step(f"  ... (rounds 3 → 15 non affichés) ...")

        # Permutation inverse IP⁻¹
        pre_ip_inv = (R << 32) | L
        combined   = self._permute(pre_ip_inv, self.IP_INV, 64)

        if log_step and verbose:
            log_step(f"")
            log_step(
                f"  Permutation IP⁻¹ : "
                f"(R16||L16) = {self._h(pre_ip_inv, 64)}"
            )
            log_step(f"  Sortie IP⁻¹      = {self._h(combined, 64)}")
            log_step(f"  ✅ Bloc #{block_idx} → {self._h(combined, 64)}")

        if log_matrix and verbose:
            log_matrix(f"BLOC #{block_idx} — SORTIE (bytes)", list(combined.to_bytes(8, 'big')))

        return combined.to_bytes(8, 'big')

    # ================================================================
    # PKCS7
    # ================================================================

    def _pkcs7_pad(self, data: bytes, bs: int = 8) -> bytes:
        pad = bs - (len(data) % bs)
        return data + bytes([pad] * pad)

    def _pkcs7_unpad(self, data: bytes) -> bytes:
        if not data:
            return data
        p = data[-1]
        return data[:-p] if 1 <= p <= 8 else data

    # ================================================================
    # DES-ECB
    # ================================================================

    def _des_ecb(self, data: bytes, key: bytes, encrypt: bool,
                 log_step=None, log_matrix=None) -> bytes:
        rk = self._generate_round_keys(key, log_step, log_matrix)
        if not encrypt:
            rk = rk[::-1]
        padded = self._pkcs7_pad(data) if encrypt else data
        n      = len(padded) // 8

        if log_step:
            log_step(f"")
            log_step(f"╔══════════════════════════════════════════════╗")
            log_step(f"║  DES-ECB  —  {n} bloc(s) de 64 bits           ║")
            log_step(f"╚══════════════════════════════════════════════╝")

        result = b""
        for i in range(0, len(padded), 8):
            idx     = i // 8
            verbose = (idx < 2)
            result += self._des_block(
                padded[i:i+8], rk,
                log_step=(log_step if verbose else None),
                log_matrix=(log_matrix if verbose else None),
                block_idx=idx, verbose=verbose
            )
            if log_step and idx == 1 and n > 2:
                log_step(f"  ... ({n-2} bloc(s) supplémentaire(s) non affiché(s)) ...")

        if log_step:
            log_step(f"  ✅ ECB terminé — {n} bloc(s) traité(s)")

        return result if encrypt else self._pkcs7_unpad(result)

    # ================================================================
    # DES-CBC
    # ================================================================

    def _des_cbc_encrypt(self, data: bytes, key: bytes, iv: bytes,
                         log_step=None, log_matrix=None) -> bytes:
        rk     = self._generate_round_keys(key, log_step, log_matrix)
        prev   = iv
        result = b""
        padded = self._pkcs7_pad(data)
        n      = len(padded) // 8

        if log_step:
            log_step(f"")
            log_step(f"╔══════════════════════════════════════════════╗")
            log_step(f"║  DES-CBC ENCRYPT  —  {n} bloc(s)              ║")
            log_step(f"╚══════════════════════════════════════════════╝")
            log_step(f"  IV = {iv.hex().upper()}")

        for i in range(0, len(padded), 8):
            idx   = i // 8
            plain = padded[i:i+8]
            xored = bytes(a ^ b for a, b in zip(plain, prev))

            if log_step and idx < 2:
                log_step(f"")
                log_step(f"  ─── Bloc #{idx} ───────────────────────────────────")
                log_step(f"  Plaintext   : {plain.hex().upper()}")
                log_step(f"  IV / Préc.  : {prev.hex().upper()}")
                log_step(f"  XOR ⊕  Plaintext ⊕ IV/Précédent :")
                log_step(f"  {'Pos':>4}  {'Plain':>6}  ⊕  {'IV':>6}  =  {'XOR':>6}")
                log_step(f"  {'─'*38}")
                for bi in range(8):
                    log_step(
                        f"  [{bi+1:>2}]   {plain[bi]:02X}      ⊕   {prev[bi]:02X}     =   {xored[bi]:02X}"
                    )
                log_step(f"  {'─'*38}")
                log_step(f"  ⊕ Résultat XOR = {xored.hex().upper()}")

            enc    = self._des_block(
                xored, rk,
                log_step=(log_step if idx < 2 else None),
                log_matrix=(log_matrix if idx < 2 else None),
                block_idx=idx, verbose=(idx < 2)
            )
            result += enc
            prev    = enc

            if log_step and idx < 2:
                log_step(f"  Chiffré DES = {enc.hex().upper()}")

            if log_step and idx == 1 and n > 2:
                log_step(f"  ... ({n-2} bloc(s) suivant(s) non affiché(s)) ...")

        if log_step:
            log_step(f"  ✅ CBC ENCRYPT terminé")

        return result

    def _des_cbc_decrypt(self, data: bytes, key: bytes, iv: bytes,
                         log_step=None, log_matrix=None) -> bytes:
        rk   = self._generate_round_keys(key)[::-1]
        prev = iv
        result = b""
        n = len(data) // 8

        if log_step:
            log_step(f"")
            log_step(f"╔══════════════════════════════════════════════╗")
            log_step(f"║  DES-CBC DECRYPT  —  {n} bloc(s)              ║")
            log_step(f"╚══════════════════════════════════════════════╝")
            log_step(f"  IV = {iv.hex().upper()}")

        for i in range(0, len(data), 8):
            idx   = i // 8
            block = data[i:i+8]
            dec   = self._des_block(block, rk, block_idx=idx)
            plain = bytes(a ^ b for a, b in zip(dec, prev))

            if log_step and idx < 2:
                log_step(f"  Bloc #{idx} chiffré : {block.hex().upper()}")
                log_step(f"  Après DES⁻¹        : {dec.hex().upper()}")
                log_step(f"  XOR ⊕  DES⁻¹ ⊕ IV/Précédent :")
                log_step(f"  {'Pos':>4}  {'DEC':>6}  ⊕  {'IV':>6}  =  {'Plain':>6}")
                log_step(f"  {'─'*38}")
                for bi in range(8):
                    log_step(
                        f"  [{bi+1:>2}]   {dec[bi]:02X}      ⊕   {prev[bi]:02X}     =   {plain[bi]:02X}"
                    )
                log_step(f"  {'─'*38}")
                log_step(f"  ⊕ Plaintext = {plain.hex().upper()}")

            result += plain
            prev    = block

        if log_step:
            log_step(f"  ✅ CBC DECRYPT terminé")

        return self._pkcs7_unpad(result)

    # ================================================================
    # TRIPLE-DES CBC
    # ================================================================

    def _3des_cbc_encrypt(self, data, k1, k2, k3, iv,
                          log_step=None, log_matrix=None):
        if log_step:
            log_step(f"")
            log_step(f"╔══════════════════════════════════════════════╗")
            log_step(f"║  TRIPLE-DES CBC  —  Schéma EDE               ║")
            log_step(f"╚══════════════════════════════════════════════╝")
            log_step(f"  K1 = {k1.hex().upper()}")
            log_step(f"  K2 = {k2.hex().upper()}")
            log_step(f"  K3 = {k3.hex().upper()}")
            log_step(f"  IV = {iv.hex().upper()}")
            log_step(f"  Schéma : Encrypt(K1) → Decrypt(K2) → Encrypt(K3)")

        rk1e = self._generate_round_keys(k1)
        rk2e = self._generate_round_keys(k2)
        rk3e = self._generate_round_keys(k3)
        rk2d = rk2e[::-1]

        padded = self._pkcs7_pad(data)
        prev   = iv
        result = b""
        n      = len(padded) // 8

        for i in range(0, len(padded), 8):
            idx   = i // 8
            plain = padded[i:i+8]
            xored = bytes(a ^ b for a, b in zip(plain, prev))

            if log_step and idx == 0:
                log_step(f"")
                log_step(f"  ─── Bloc #0 ─────────────────────────────────────")
                log_step(f"  Plaintext  : {plain.hex().upper()}")
                log_step(f"  XOR ⊕  Plaintext ⊕ IV :")
                log_step(f"  {'Pos':>4}  {'Plain':>6}  ⊕  {'IV':>6}  =  {'XOR':>6}")
                log_step(f"  {'─'*38}")
                for bi in range(8):
                    log_step(
                        f"  [{bi+1:>2}]   {plain[bi]:02X}      ⊕   {prev[bi]:02X}     =   {xored[bi]:02X}"
                    )
                log_step(f"  {'─'*38}")
                log_step(f"  ⊕ XOR = {xored.hex().upper()}")

            b = self._des_block(xored, rk1e, block_idx=idx)
            if log_step and idx == 0:
                log_step(f"  → Encrypt(K1) = {b.hex().upper()}")

            b = self._des_block(b, rk2d, block_idx=idx)
            if log_step and idx == 0:
                log_step(f"  → Decrypt(K2) = {b.hex().upper()}")

            b = self._des_block(b, rk3e, block_idx=idx)
            if log_step and idx == 0:
                log_step(f"  → Encrypt(K3) = {b.hex().upper()}")
                if n > 1:
                    log_step(f"  ... ({n-1} bloc(s) suivant(s) non affiché(s)) ...")

            result += b
            prev    = b

        if log_step:
            log_step(f"  ✅ 3DES-CBC terminé")

        return result

    def _3des_cbc_decrypt(self, data, k1, k2, k3, iv):
        rk1e = self._generate_round_keys(k1)
        rk2e = self._generate_round_keys(k2)
        rk3e = self._generate_round_keys(k3)
        prev  = iv
        result = b""
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            b = self._des_block(block, rk3e[::-1])
            b = self._des_block(b,     rk2e)
            b = self._des_block(b,     rk1e[::-1])
            result += bytes(a ^ b2 for a, b2 in zip(b, prev))
            prev = block
        return self._pkcs7_unpad(result)

    # ================================================================
    # INTERFACE ENCRYPT / DECRYPT
    # ================================================================

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:

        key_lower = str(key).strip().lower()
        data      = text.encode("utf-8")

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║          DES — CHIFFREMENT DÉTAILLÉ          ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Texte clair  : '{text}'")
            log_step(f"  Clé brute    : '{key}'")
            log_step(f"  Taille texte : {len(data)} octet(s)")

        if log_matrix:
            log_matrix("TEXTE CLAIR (bytes)", list(data[:8].ljust(8, b'\x00')))

        if key_lower.startswith("3des:"):
            raw_key     = key[5:].encode("utf-8").ljust(24, b'\x00')[:24]
            k1, k2, k3  = raw_key[:8], raw_key[8:16], raw_key[16:]
            iv           = os.urandom(8)
            if log_step:
                log_step(f"  Mode      : 3DES-CBC")
                log_step(f"  IV généré : {iv.hex().upper()}")
            cipher = self._3des_cbc_encrypt(data, k1, k2, k3, iv, log_step, log_matrix)
            result = f"IV:{iv.hex()}|{cipher.hex()}"
            if log_step:
                log_step(f"")
                log_step(f"  ✅ Résultat final : {result}")
            return result

        if key_lower.startswith("cbc:"):
            raw_key = key[4:].encode("utf-8").ljust(8, b'\x00')[:8]
            iv      = os.urandom(8)
            if log_step:
                log_step(f"  Mode      : DES-CBC")
                log_step(f"  Clé (hex) : {raw_key.hex().upper()}")
                log_step(f"  IV généré : {iv.hex().upper()}")
            cipher = self._des_cbc_encrypt(data, raw_key, iv, log_step, log_matrix)
            result = f"IV:{iv.hex()}|{cipher.hex()}"
            if log_step:
                log_step(f"")
                log_step(f"  ✅ Résultat final : {result}")
            return result

        # DES-ECB
        raw_key = key.encode("utf-8").ljust(8, b'\x00')[:8]
        if log_step:
            log_step(f"  Mode      : DES-ECB")
            log_step(f"  Clé (hex) : {raw_key.hex().upper()}")

        result_bytes = self._des_ecb(data, raw_key, True, log_step, log_matrix)
        result       = result_bytes.hex()

        if log_step:
            log_step(f"")
            log_step(f"  ✅ Résultat final (hex) : {result}")

        if log_matrix:
            log_matrix("CIPHERTEXT FINAL (bytes)", list(result_bytes[:8]))

        return result

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:

        key_lower = str(key).strip().lower()

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║         DES — DÉCHIFFREMENT DÉTAILLÉ         ║")
            log_step("╚══════════════════════════════════════════════╝")

        if key_lower.startswith("3des:"):
            if "|" not in text:
                raise ValueError("Format 3DES invalide — attendu : IV:hex|ciphertext")
            iv_hex, cipher_hex = text.split("|", 1)
            iv     = bytes.fromhex(iv_hex.replace("IV:", ""))
            cipher = bytes.fromhex(cipher_hex)
            raw_key     = key[5:].encode("utf-8").ljust(24, b'\x00')[:24]
            k1, k2, k3  = raw_key[:8], raw_key[8:16], raw_key[16:]
            if log_step:
                log_step(f"  Mode : 3DES-CBC | IV = {iv.hex().upper()}")
            plain = self._3des_cbc_decrypt(cipher, k1, k2, k3, iv)
            return plain.decode("utf-8", errors="replace")

        if key_lower.startswith("cbc:"):
            if "|" not in text:
                raise ValueError("Format CBC invalide — attendu : IV:hex|ciphertext")
            iv_hex, cipher_hex = text.split("|", 1)
            iv     = bytes.fromhex(iv_hex.replace("IV:", ""))
            cipher = bytes.fromhex(cipher_hex)
            raw_key = key[4:].encode("utf-8").ljust(8, b'\x00')[:8]
            if log_step:
                log_step(f"  Mode : DES-CBC | IV = {iv.hex().upper()}")
            plain = self._des_cbc_decrypt(cipher, raw_key, iv, log_step, log_matrix)
            return plain.decode("utf-8", errors="replace")

        # DES-ECB
        raw_key = key.encode("utf-8").ljust(8, b'\x00')[:8]
        if log_step:
            log_step(f"  Mode : DES-ECB | Clé = {raw_key.hex().upper()}")
        try:
            cipher_bytes = bytes.fromhex(text.strip())
        except ValueError:
            cipher_bytes = text.encode("utf-8")

        plain = self._des_ecb(cipher_bytes, raw_key, False, log_step, log_matrix)
        return plain.decode("utf-8", errors="replace")