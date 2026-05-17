"""
RC6 — Finaliste NIST AES (RSA Laboratories) — TP2 Exercice 2.4
Implémentation pédagogique fidèle avec :
  - Structure Feistel-like à 4 registres (A, B, C, D)
  - 20 tours complets
  - Rotations dépendantes des données (data-dependent rotations)
  - Key schedule complet (S[0..43])
  - Bloc : 128 bits | Mots : 32 bits | w=32, r=20, b=16/24/32
"""

import struct


class RC6Algorithm:

    # Paramètres RC6-32/20/b
    W = 32          # taille d'un mot en bits
    R = 20          # nombre de tours
    P32 = 0xB7E15163  # constante Pw (partie fractionnaire de e)
    Q32 = 0x9E3779B9  # constante Qw (partie fractionnaire du nombre d'or)
    MASK = 0xFFFFFFFF

    def get_name(self):
        return "RC6"

    def get_description(self):
        return (
            "RC6 — Finaliste NIST AES (RSA Laboratories)\n"
            "• Structure : Feistel-like à 4 registres (A,B,C,D)\n"
            "• Bloc : 128 bits | Tours : 20 | Mots : 32 bits\n"
            "• Originalité : rotations dépendantes des données\n"
            "  (data-dependent rotations via f(x) = x(2x+1) mod 2^w)\n"
            "• Clé : 128/192/256 bits | 44 sous-clés\n"
            "• Key whitening en entrée et en sortie"
        )

    def get_key_info(self):
        return {"type": "symmetric", "placeholder": "Clé (16+ caractères)"}

    # ------------------------------------------------------------------
    # Helpers arithmétiques
    # ------------------------------------------------------------------

    def _rotl(self, x: int, n: int) -> int:
        n = n & (self.W - 1)
        return ((x << n) | (x >> (self.W - n))) & self.MASK

    def _rotr(self, x: int, n: int) -> int:
        n = n & (self.W - 1)
        return ((x >> n) | (x << (self.W - n))) & self.MASK

    def _lg_w(self) -> int:
        """log2(w) = 5 pour w=32"""
        return 5

    # ------------------------------------------------------------------
    # Key Schedule — dérive 2(r+2) = 44 sous-clés
    # ------------------------------------------------------------------

    def _key_schedule(self, key: str) -> list:
        """
        Génère le tableau S[0..2r+3] (44 mots de 32 bits).
        Étape 1 : convertir la clé en mots L[]
        Étape 2 : initialiser S[] avec P32, Q32
        Étape 3 : mélange A/B sur 3 × max(|S|,|L|) itérations
        """
        key_bytes = key.encode("utf-8")
        # Padder / tronquer à 16 octets (128 bits)
        key_bytes = (key_bytes * (16 // len(key_bytes) + 1))[:16]

        b = len(key_bytes)
        u = self.W // 8          # octets par mot = 4
        c = (b + u - 1) // u     # nombre de mots-clés = 4

        # Charger la clé en mots 32 bits little-endian
        L = [0] * c
        for i in range(b - 1, -1, -1):
            L[i // u] = ((L[i // u] << 8) + key_bytes[i]) & self.MASK

        # Initialiser S
        t = 2 * (self.R + 2)   # = 44
        S = [0] * t
        S[0] = self.P32
        for i in range(1, t):
            S[i] = (S[i - 1] + self.Q32) & self.MASK

        # Mélange
        A = B = i = j = 0
        iterations = 3 * max(t, c)
        for _ in range(iterations):
            A = S[i] = self._rotl((S[i] + A + B) & self.MASK, 3)
            B = L[j] = self._rotl((L[j] + A + B) & self.MASK, (A + B) & self.MASK)
            i = (i + 1) % t
            j = (j + 1) % c

        return S

    # ------------------------------------------------------------------
    # Chiffrement d'un bloc 128 bits
    # ------------------------------------------------------------------

    def _encrypt_block(self, block: bytes, S: list, log_step=None) -> bytes:
        """
        Découpe le bloc en 4 mots 32 bits A,B,C,D (little-endian).
        Applique 20 tours RC6 + key whitening.
        """
        A, B, C, D = struct.unpack_from('<4I', block)
        lg = self._lg_w()

        # Pré-blanchiment
        B = (B + S[0]) & self.MASK
        D = (D + S[1]) & self.MASK

        if log_step:
            log_step(f"   Entrée A={A:08X} B={B:08X} C={C:08X} D={D:08X}")

        for i in range(1, self.R + 1):
            # f(x) = x(2x+1) mod 2^w
            f = (B * (2 * B + 1)) & self.MASK
            g = (D * (2 * D + 1)) & self.MASK
            t = self._rotl(f, lg)
            u = self._rotl(g, lg)
            A = (self._rotl(A ^ t, u) + S[2 * i]) & self.MASK
            C = (self._rotl(C ^ u, t) + S[2 * i + 1]) & self.MASK
            A, B, C, D = B, C, D, A
            if log_step and i <= 3:
                log_step(f"   Tour {i:2d}: A={A:08X} B={B:08X} C={C:08X} D={D:08X}")

        # Post-blanchiment
        A = (A + S[2 * self.R + 2]) & self.MASK
        C = (C + S[2 * self.R + 3]) & self.MASK

        if log_step:
            log_step(f"   Sortie A={A:08X} B={B:08X} C={C:08X} D={D:08X}")

        return struct.pack('<4I', A, B, C, D)

    # ------------------------------------------------------------------
    # Déchiffrement d'un bloc 128 bits
    # ------------------------------------------------------------------

    def _decrypt_block(self, block: bytes, S: list) -> bytes:
        A, B, C, D = struct.unpack_from('<4I', block)
        lg = self._lg_w()

        # Annuler le post-blanchiment
        C = (C - S[2 * self.R + 3]) & self.MASK
        A = (A - S[2 * self.R + 2]) & self.MASK

        for i in range(self.R, 0, -1):
            A, B, C, D = D, A, B, C
            g = (D * (2 * D + 1)) & self.MASK
            f = (B * (2 * B + 1)) & self.MASK
            u = self._rotl(g, lg)
            t = self._rotl(f, lg)
            C = self._rotr((C - S[2 * i + 1]) & self.MASK, t) ^ u
            A = self._rotr((A - S[2 * i]) & self.MASK, u) ^ t

        # Annuler le pré-blanchiment
        D = (D - S[1]) & self.MASK
        B = (B - S[0]) & self.MASK

        return struct.pack('<4I', A, B, C, D)

    # ------------------------------------------------------------------
    # Interface publique
    # ------------------------------------------------------------------

    def encrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        block = text.encode("utf-8")[:16].ljust(16, b'\x00')
        S = self._key_schedule(key)

        if log_step:
            log_step("🔐 RC6 — CHIFFREMENT (Finaliste AES)")
            log_step("=" * 42)
            log_step(f"   Structure : Feistel-like 4 registres (A,B,C,D)")
            log_step(f"   Bloc : 128 bits | Tours : {self.R}")
            log_step(f"   Sous-clés générées : {len(S)} mots de 32 bits")
            log_step(f"   Texte (hex) : {block.hex()}")
            log_step(f"\n   Rotation dépendante des données :")
            log_step(f"   f(x) = x(2x+1) mod 2^32  →  rotation de lg(w)=5 bits")
            log_step(f"\n   Déroulement des tours :")

        result = self._encrypt_block(block, S, log_step)

        if log_step:
            log_step(f"\n✅ Chiffré (hex) : {result.hex()}")

        return result.hex()

    def decrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        try:
            block = bytes.fromhex(text.strip())[:16].ljust(16, b'\x00')
        except ValueError:
            block = text.encode("utf-8")[:16].ljust(16, b'\x00')

        S = self._key_schedule(key)

        if log_step:
            log_step("🔓 RC6 — DÉCHIFFREMENT")
            log_step("=" * 42)

        result = self._decrypt_block(block, S)

        decoded = result.decode("utf-8", errors="ignore").rstrip('\x00')

        if log_step:
            log_step(f"✅ Texte déchiffré : {decoded}")

        return decoded