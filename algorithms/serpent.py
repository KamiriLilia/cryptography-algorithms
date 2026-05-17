"""
Serpent - TP2 Exercice 2.4 (Finaliste NIST)
Implémentation pédagogique complète avec affichage
détaillé étape par étape (log_step / log_matrix) — style DES.
"""

import time


class SerpentAlgorithm:

    # 8 S-boxes officielles de Serpent (4 bits → 4 bits)
    S_BOXES = [
        [3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12],
        [15,12,2,7,9,0,5,10,1,11,14,8,6,13,3,4],
        [8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2],
        [0,15,11,8,12,9,6,3,13,1,2,4,10,7,5,14],
        [1,15,8,3,12,0,11,6,2,5,4,10,9,14,7,13],
        [15,5,2,11,4,10,9,12,0,3,14,8,13,6,7,1],
        [7,2,12,5,8,4,6,11,14,9,1,15,13,3,10,0],
        [1,13,15,0,14,8,2,11,7,4,12,10,9,3,5,6],
    ]

    def __init__(self):
        self._build_inv_sboxes()

    def _build_inv_sboxes(self):
        self.S_BOXES_INV = []
        for sb in self.S_BOXES:
            inv = [0] * 16
            for i, v in enumerate(sb):
                inv[v] = i
            self.S_BOXES_INV.append(inv)

    # ──────────────────────────────────────────────────────────────
    # Interface
    # ──────────────────────────────────────────────────────────────

    def get_name(self):
        return "Serpent"

    def get_description(self):
        return (
            "Serpent — Finaliste NIST AES (4e place, 2000).\n"
            "• Structure : SPN (Substitution-Permutation Network)\n"
            "• Bloc : 128 bits | Clé : 128/192/256 bits\n"
            "• 32 tours avec 8 S-boxes de 4 bits\n"
            "• Marge de sécurité maximale (vs 10 tours pour AES)\n"
            "• Défait vs Rijndael : performances insuffisantes"
        )

    def get_key_info(self):
        return {
            "type": "symmetric",
            "placeholder": "Clé texte (16+ caractères recommandés)"
        }

    # ──────────────────────────────────────────────────────────────
    # Key Schedule
    # ──────────────────────────────────────────────────────────────

    def _derive_subkeys(self, key: str,
                        log_step=None, log_matrix=None) -> list:
        """Dérive 33 sous-clés de 128 bits avec log détaillé."""
        key_bytes = key.encode("utf-8")
        key_bytes = (key_bytes * 4)[:32]
        key_int   = int.from_bytes(key_bytes, 'big')
        MASK128   = (1 << 128) - 1

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║    SERPENT — KEY SCHEDULE (33 sous-clés)     ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Clé brute (hex) : {key_bytes.hex().upper()}")
            log_step(f"  Clé 256 bits    : {key_int:032X}")
            log_step("")
            log_step("  ── Algorithme de dérivation ──────────────────")
            log_step("  Pour i = 0..32 :")
            log_step("    val = ROL11(val)  (rotation de 11 bits sur 128)")
            log_step("    val = val ⊕ (φ × (i+1) mod 2¹²⁸)")
            log_step("    Ki  = val")
            log_step("  avec φ = 0x9E3779B9 (fraction dorée)")
            log_step("")
            log_step(f"  {'i':>3}  {'Sous-clé Ki (128 bits, premiers 32 bits)':>44}")
            log_step(f"  {'─'*50}")

        phi = 0x9e3779b9
        val = key_int & MASK128

        subkeys = []
        for i in range(33):
            val = ((val << 11) | (val >> 117)) & MASK128
            val ^= (phi * (i + 1)) & MASK128
            subkeys.append(val)
            if log_step:
                # Affiche les 4 premiers et les 4 derniers
                if i < 4 or i >= 29:
                    top32 = (val >> 96) & 0xFFFFFFFF
                    log_step(f"  K{i:02d}  {val:032X}   (top32: {top32:08X})")
                elif i == 4:
                    log_step(f"  ... (K04 → K28 non affichées) ...")

        if log_step:
            log_step(f"  {'─'*50}")
            log_step(f"  ✅ 33 sous-clés de 128 bits générées")
            log_step(f"     K[0..31] → 32 rounds")
            log_step(f"     K[32]    → whitening final")

        if log_matrix:
            log_matrix("KEY SCHEDULE — K[0] (premiers 16 octets)",
                       list(subkeys[0].to_bytes(16, 'big')))

        return subkeys

    # ──────────────────────────────────────────────────────────────
    # S-Boxes
    # ──────────────────────────────────────────────────────────────

    def _apply_sbox(self, block: int, round_num: int,
                    inverse: bool = False,
                    log_step=None) -> int:
        """Applique la S-box du round, avec log si demandé."""
        sb_idx = round_num % 8
        sb     = self.S_BOXES_INV[sb_idx] if inverse else self.S_BOXES[sb_idx]
        result = 0

        if log_step:
            mode = "inverse" if inverse else "directe"
            log_step(f"  │  ── S-Box S{sb_idx} ({mode}) — 32 nibbles de 4 bits ──")
            log_step(f"  │  {'Nib':>4}  {'In':>4}  {'Out':>4}   "
                     f"{'Nib':>4}  {'In':>4}  {'Out':>4}   "
                     f"{'Nib':>4}  {'In':>4}  {'Out':>4}   "
                     f"{'Nib':>4}  {'In':>4}  {'Out':>4}")
            log_step(f"  │  {'─'*62}")

        nibbles_in  = []
        nibbles_out = []
        for i in range(32):
            nibble = (block >> (i * 4)) & 0xF
            val    = sb[nibble]
            result |= (val << (i * 4))
            nibbles_in.append(nibble)
            nibbles_out.append(val)

        if log_step:
            # Affiche 4 colonnes de 8 lignes
            for row in range(8):
                line = "  │  "
                for col in range(4):
                    idx = row + col * 8
                    if idx < 32:
                        line += (f"  [{idx:02d}]   {nibbles_in[idx]:X}"
                                 f" → {nibbles_out[idx]:X}   ")
                log_step(line)
            log_step(f"  │  {'─'*62}")
            log_step(f"  │  Entrée  : {block:032X}")
            log_step(f"  │  Sortie  : {result:032X}")

        return result

    # ──────────────────────────────────────────────────────────────
    # Transformation linéaire
    # ──────────────────────────────────────────────────────────────

    def _linear_transform(self, block: int,
                          log_step=None) -> int:
        """Transformation linéaire Serpent avec log."""
        mask32 = 0xFFFFFFFF

        def rot_left(v: int, n: int) -> int:
            return ((v << n) | (v >> (32 - n))) & mask32

        w0 = block & mask32
        w1 = (block >> 32) & mask32
        w2 = (block >> 64) & mask32
        w3 = (block >> 96) & mask32

        if log_step:
            log_step(f"  │  ── Transformation Linéaire (LT) ────────────")
            log_step(f"  │  Entrée : w0={w0:08X}  w1={w1:08X}  "
                     f"w2={w2:08X}  w3={w3:08X}")

        w0 = rot_left(w0, 13)
        w2 = rot_left(w2, 3)
        w1 ^= w0 ^ w2
        w3 ^= w2 ^ ((w0 << 3) & mask32)
        w1 = rot_left(w1, 1)
        w3 = rot_left(w3, 7)
        w0 ^= w1 ^ w3
        w2 ^= w3 ^ ((w1 << 7) & mask32)
        w0 = rot_left(w0, 5)
        w2 = rot_left(w2, 22)

        result = w0 | (w1 << 32) | (w2 << 64) | (w3 << 96)

        if log_step:
            log_step(f"  │  Étapes : ROL(w0,13) | ROL(w2,3)")
            log_step(f"  │           w1 ^= w0^w2 | w3 ^= w2^(w0<<3)")
            log_step(f"  │           ROL(w1,1) | ROL(w3,7)")
            log_step(f"  │           w0 ^= w1^w3 | w2 ^= w3^(w1<<7)")
            log_step(f"  │           ROL(w0,5) | ROL(w2,22)")
            log_step(f"  │  Sortie : w0={w0:08X}  w1={w1:08X}  "
                     f"w2={w2:08X}  w3={w3:08X}")

        return result

    def _linear_transform_inv(self, block: int) -> int:
        mask32 = 0xFFFFFFFF

        def rot_left(v, n):
            return ((v << n) | (v >> (32 - n))) & mask32

        def rot_right(v, n):
            return ((v >> n) | (v << (32 - n))) & mask32

        w0 = block & mask32
        w1 = (block >> 32) & mask32
        w2 = (block >> 64) & mask32
        w3 = (block >> 96) & mask32

        w2 = rot_right(w2, 22)
        w0 = rot_right(w0, 5)
        w2 ^= w3 ^ ((w1 << 7) & mask32)
        w0 ^= w1 ^ w3
        w3 = rot_right(w3, 7)
        w1 = rot_right(w1, 1)
        w3 ^= w2 ^ ((w0 << 3) & mask32)
        w1 ^= w0 ^ w2
        w2 = rot_right(w2, 3)
        w0 = rot_right(w0, 13)

        return w0 | (w1 << 32) | (w2 << 64) | (w3 << 96)

    # ──────────────────────────────────────────────────────────────
    # Chiffrement d'un bloc 128 bits
    # ──────────────────────────────────────────────────────────────

    def _encrypt_block(self, block: int, subkeys: list,
                       log_step=None, log_matrix=None) -> int:
        MASK    = (1 << 128) - 1
        current = block

        if log_step:
            log_step("┌─────────────────────────────────────────────────────┐")
            log_step("│  SERPENT — CHIFFREMENT D'UN BLOC 128 bits           │")
            log_step("└─────────────────────────────────────────────────────┘")
            log_step(f"  Bloc d'entrée : {current:032X}")
            log_step("")
            log_step("  Structure SPN : pour chaque round r ∈ [0..31] :")
            log_step("    1. XOR avec sous-clé  K[r]")
            log_step("    2. Substitution        S_{r mod 8}")
            log_step("    3. Transformation lin. LT  (sauf round 31)")
            log_step("")

        for r in range(32):
            show = log_step and (r < 2 or r == 31)

            if show:
                log_step(f"  ══════════════ Round {r+1:02d} / 32 ══════════════")
                log_step(f"  │  État avant  : {current:032X}")
                log_step(f"  │")
                log_step(f"  │  ── Étape 1 : XOR ⊕ K[{r:02d}] ─────────────────")
                log_step(f"  │  État     = {current:032X}")
                log_step(f"  │  K[{r:02d}]   = {subkeys[r]:032X}")

            before_xor = current
            current ^= subkeys[r]

            if show:
                # Affiche le XOR octet par octet (8 premiers octets)
                a = before_xor.to_bytes(16, 'big')
                b = subkeys[r].to_bytes(16, 'big')
                c = current.to_bytes(16, 'big')
                log_step(f"  │  XOR ⊕  (8 premiers octets) :")
                log_step(f"  │  {'Pos':>4}  {'État':>6}  ⊕  {'K[r]':>6}  =  {'XOR':>6}")
                log_step(f"  │  {'─'*36}")
                for bi in range(8):
                    log_step(f"  │  [{bi+1:>2}]   {a[bi]:02X}       ⊕   {b[bi]:02X}     =   {c[bi]:02X}")
                log_step(f"  │  {'─'*36}")
                log_step(f"  │  Après XOR : {current:032X}")
                log_step(f"  │")

            # S-box
            current = self._apply_sbox(
                current, r,
                log_step=(log_step if show else None)
            )

            if show and log_matrix:
                log_matrix(f"Après S-Box Round {r+1:02d}",
                           list(current.to_bytes(16, 'big')))

            # LT (sauf dernier round)
            if r < 31:
                current = self._linear_transform(
                    current,
                    log_step=(log_step if show else None)
                )
                if show:
                    log_step(f"  │  Après LT    : {current:032X}")

            if show:
                log_step(f"  │  → État fin   : {current:032X}")

            if log_step and r == 2:
                log_step(f"  ... (rounds 3 → 31 non affichés) ...")

        # Whitening final
        if log_step:
            log_step("")
            log_step("  ── Whitening final : XOR ⊕ K[32] ─────────────────")
            log_step(f"  Avant  : {current:032X}")
            log_step(f"  K[32]  : {subkeys[32]:032X}")

        current ^= subkeys[32]

        if log_step:
            log_step(f"  Après  : {current:032X}")
            log_step(f"  ✅ Bloc chiffré = {current:032X}")

        if log_matrix:
            log_matrix("BLOC CHIFFRÉ (bytes)", list(current.to_bytes(16,'big')))

        return current & MASK

    # ──────────────────────────────────────────────────────────────
    # Déchiffrement d'un bloc
    # ──────────────────────────────────────────────────────────────

    def _decrypt_block(self, block: int, subkeys: list,
                       log_step=None) -> int:
        MASK    = (1 << 128) - 1
        current = block

        if log_step:
            log_step("┌─────────────────────────────────────────────────────┐")
            log_step("│  SERPENT — DÉCHIFFREMENT D'UN BLOC 128 bits         │")
            log_step("└─────────────────────────────────────────────────────┘")
            log_step(f"  Bloc chiffré : {current:032X}")
            log_step("")
            log_step("  Ordre inverse : K[32] → round 31 → ... → round 0")
            log_step("")
            log_step("  ── Whitening final inverse : XOR ⊕ K[32] ───────────")

        current ^= subkeys[32]

        if log_step:
            log_step(f"  Après XOR K[32] : {current:032X}")

        for r in range(31, -1, -1):
            show = log_step and (r >= 30 or r < 2)

            if show:
                log_step(f"  ══════════════ Round {r+1:02d} inverse ══════════════")
                log_step(f"  │  État : {current:032X}")

            if r < 31:
                current = self._linear_transform_inv(current)
                if show:
                    log_step(f"  │  Après LT⁻¹ : {current:032X}")

            current = self._apply_sbox(current, r, inverse=True,
                                       log_step=(log_step if show else None))

            if show:
                log_step(f"  │  Après S⁻¹  : {current:032X}")

            current ^= subkeys[r]

            if show:
                log_step(f"  │  Après XOR K[{r:02d}] : {current:032X}")

            if log_step and r == 29:
                log_step(f"  ... (rounds 29 → 2 non affichés) ...")

        if log_step:
            log_step(f"  ✅ Bloc déchiffré = {current:032X}")

        return current & MASK

    # ──────────────────────────────────────────────────────────────
    # Interface encrypt / decrypt
    # ──────────────────────────────────────────────────────────────

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:

        block_bytes = text.encode("utf-8")[:16].ljust(16, b'\x00')
        block_int   = int.from_bytes(block_bytes, 'big')

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║          SERPENT — CHIFFREMENT               ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Texte clair  : '{text}'")
            log_step(f"  Clé brute    : '{key}'")
            log_step(f"  Taille texte : {len(text.encode())} octet(s) "
                     f"(padded à 16)")
            log_step(f"  Bloc (hex)   : {block_bytes.hex().upper()}")

        if log_matrix:
            log_matrix("TEXTE CLAIR (bytes)", list(block_bytes))

        subkeys = self._derive_subkeys(key, log_step, log_matrix)

        result_int = self._encrypt_block(block_int, subkeys,
                                         log_step, log_matrix)
        result_hex = format(result_int, '032x')

        if log_step:
            log_step("")
            log_step("  ── Résultat final ────────────────────────────")
            log_step(f"  Ciphertext (hex) : {result_hex.upper()}")

        if log_matrix:
            log_matrix("CIPHERTEXT FINAL (bytes)",
                       list(result_int.to_bytes(16, 'big')))

        return result_hex

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:

        try:
            block_int = int(text.strip(), 16)
        except ValueError:
            block_bytes = text.encode("utf-8")[:16].ljust(16, b'\x00')
            block_int   = int.from_bytes(block_bytes, 'big')

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║         SERPENT — DÉCHIFFREMENT              ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Chiffré (hex) : {text.strip().upper()}")

        if log_matrix:
            log_matrix("CIPHERTEXT (bytes)",
                       list(block_int.to_bytes(16, 'big')))

        subkeys = self._derive_subkeys(key, log_step, log_matrix)

        result_int   = self._decrypt_block(block_int, subkeys, log_step)
        result_bytes = result_int.to_bytes(16, 'big')
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
    print("  EXERCICE 2.4 — SERPENT (DÉTAILLÉ)")
    print("█"*60)

    sp   = SerpentAlgorithm()
    text = "Hello Serpent!!"
    key  = "MaCleSecrete1234"

    enc = sp.encrypt(text, key, log_step, log_matrix)
    dec = sp.decrypt(enc,  key, log_step, log_matrix)

    print(f"\n  Texte original  : {text}")
    print(f"  Chiffré (hex)   : {enc}")
    print(f"  Déchiffré       : {dec}")
    print(f"  Vérif           : {'✅ OK' if dec == text else '✗ ERREUR'}")
    print("\n" + "█"*60 + "\n")


if __name__ == "__main__":
    main()