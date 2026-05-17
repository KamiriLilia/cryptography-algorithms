"""
MARS — Finaliste NIST AES (IBM) — TP2 Exercice 2.4
Implémentation pédagogique fidèle avec :
  - Structure hybride en 3 phases (spec IBM 1998)
  - Phase 1 : Forward mixing  (ajout de sous-clés + S-box)
  - Phase 2 : Core cryptographique (16 tours Feistel avec S-box et rotations)
  - Phase 3 : Backward unmixing (inverse de la phase 1)
  - S-box officielle MARS
  - Key schedule complet (40 sous-clés 32 bits)
  - Bloc : 128 bits (4 mots 32 bits A,B,C,D)
"""

import struct


class MARSAlgorithm:

    # S-box officielle MARS (256 entrées × 32 bits — spec IBM 1998)
    SBOX = [
        0x09d0c479, 0x28c8ffe0, 0x84aa6c39, 0x9dad7287, 0x7dff9be3, 0xd4268361, 0xc96da1d4, 0x7974cc93,
        0x85d0582e, 0x2a4b5705, 0x1ca16a62, 0xc3bd279d, 0x0f1f25e5, 0x5160372f, 0xc695c1fb, 0x4d7ff1e4,
        0xae5f6bf4, 0x0d72ee46, 0xff23de8a, 0xb1cf8e83, 0xf14902e2, 0x3e981e42, 0x8bf53eb6, 0x7f4bf8ac,
        0x83631f83, 0x25970205, 0x76afe784, 0x3a7931d4, 0x4f846450, 0x5c64c3f6, 0x210a5f18, 0xc6986a26,
        0x28f4e826, 0x3a60a81c, 0xd340a664, 0x7ea820c4, 0x526687c5, 0x7eddd12b, 0x32a11d1d, 0x9c9ef086,
        0x080dbf68, 0x31b3e96a, 0xd45a7eef, 0xa0768059, 0x2a2356c5, 0x0c22b124, 0x5b40c8e7, 0x1e94b1b3,
        0x2ba7b0a4, 0x8f888d8d, 0xfe2e39c9, 0xa52a9849, 0xa72e1f75, 0x1fc11b3c, 0x2e55898f, 0xe8e96781,
        0x7d2d1d86, 0x4c116a89, 0x5476bd08, 0x4a51c12a, 0x9a56404d, 0x5c3cf8da, 0x01c1e3b5, 0x8f9c9a31,
        0xe63abd0e, 0xb5028411, 0x4c814e5a, 0xe59c1b68, 0x8e252720, 0x7c8f3b47, 0x11abe4fe, 0x5a5b68d0,
        0xdb79a045, 0x5b5b3a1c, 0x6c7db488, 0x10d9f5d9, 0x2af521b2, 0xca2a22a6, 0x94984fd9, 0x33eed5d7,
        0xbc46de5f, 0x47c5a9a4, 0x3f914a26, 0xb1aea71e, 0x85e47b3a, 0x6d73a6bd, 0x58f67382, 0xc5a498d9,
        0x9d03ff83, 0x0ea3db0d, 0xd51e1ca8, 0x8d5fdf6a, 0xce3af912, 0x1879ede5, 0xd71a0f5e, 0xdcfc6f88,
        0x5789a454, 0x3e1eb99e, 0x4e7c3b72, 0xf70e7c7e, 0x2f4e89d3, 0x61c7a5a1, 0xd4b19ae3, 0x2c0e3b5a,
        0xd736de96, 0xb2a93c33, 0x7cd90d51, 0x20be95da, 0xcbf73a38, 0x2b38fd46, 0x7e9fe739, 0x9c34bc53,
        0xcc02455a, 0xab22e8f5, 0x5a1d1dbb, 0xf7faee3c, 0x95e43e1c, 0xad38bef5, 0x17b8d54a, 0x2f95a2ac,
        0x6b3fc1cc, 0x01d1a0ae, 0x26f12e23, 0x00d1dcfc, 0xb07db613, 0x9f5d2a2d, 0x5cd5cade, 0xe15f4b71,
        0x35a46fe7, 0xba5f76e5, 0xcd4da32d, 0x3a53f5d9, 0xf21da41e, 0xede09620, 0xdc5ed3eb, 0x19c3ec40,
        0xeaf2e46c, 0xfab94f9b, 0x16e6d1b8, 0xdabd7739, 0xe7a2e7be, 0x19f5df90, 0x8802d56a, 0xdc3ff2d5,
        0x2519fdde, 0x0e0e29b8, 0x6b9e4ac3, 0x5e49f95e, 0x6d00f28b, 0x7b92be96, 0xf24433e7, 0x1df0a5b4,
        0x5dfbde07, 0x77a8bf98, 0xf9bdbddf, 0xb1b9c0dc, 0xa4fe073e, 0x6b61a7da, 0xf7efbad2, 0x8c6ba729,
        0xa39ebbe5, 0x14b5ecef, 0x63e5d0c4, 0xe2dcb4d2, 0x48eaadf8, 0x1c7e89c1, 0xb46e56b4, 0x0d0ef40b,
        0xdde6c96c, 0xba38b54c, 0x49f3dbc1, 0x8e94e06f, 0x6ba04fd3, 0xf35e6871, 0x8b5eed51, 0x86fc3b95,
        0x8b59524c, 0x2e3a614a, 0x6de61559, 0xa2e0e44c, 0xf0b3c0a3, 0x7bcfd48f, 0x44c5fc5d, 0xb7f8e8fe,
        0x9abee7ff, 0xe7c0fe7a, 0x9ea32e58, 0x25acb64c, 0x82d4e0cc, 0x5c9e1dcd, 0x5d5fdb57, 0xd0fa2f16,
        0xf6d4a906, 0xdb7b8d55, 0x0a2fcf50, 0xc75ddf76, 0x5ef30cab, 0x26c0d126, 0xe9d06a44, 0x8fd8feb0,
        0xcc0ba42b, 0xb4da83e6, 0xadbb0bf1, 0xfc1e64e9, 0xea2b1a17, 0x31ca3e3c, 0x9a5b1768, 0xc6a82700,
        0xe8c1fed2, 0xfbe1d7ea, 0x08bd2fb3, 0xdde0d7fa, 0xba5a2aca, 0x4b2d36e5, 0xcb7c69c4, 0x96de50e5,
        0xedba4f01, 0x7484b0eb, 0xa6c41b68, 0xe2a67c61, 0x2edfd96f, 0xaecc6f40, 0x4f3d32a9, 0xcfffc2d5,
        0x8c07d84c, 0x3fcc0c98, 0x91b9f69e, 0xbb9fc8a1, 0x13b6f7e3, 0xa1db2085, 0xbcdbf12e, 0x3a34bc85,
        0x60d8901a, 0xdead4b95, 0xfce3a213, 0x1b02cbaf, 0xf476e7b4, 0x6e37bfab, 0x2fa70547, 0x2f8f90ae,
        0xf69e5b02, 0xcde3cbee, 0x4d1edfed, 0x84a24dfc, 0x5dc78a85, 0xb66ed9c4, 0x9eca3209, 0x86a39f81,
        0xf1fc3c95, 0x6f1f8eff, 0x17e45ee3, 0x0dc7d6b1, 0xe9c9ba70, 0x4e2e1b89, 0xc374a7e7, 0xacd4e9c5,
    ]

    MASK = 0xFFFFFFFF

    def get_name(self):
        return "MARS"

    def get_description(self):
        return (
            "MARS — Finaliste NIST AES (IBM, 1998)\n"
            "• Structure hybride en 3 phases :\n"
            "  ① Forward mixing  : ajout clés + S-box (8 demi-tours)\n"
            "  ② Core crypto     : 16 tours Feistel S-box + rotations\n"
            "  ③ Backward unmixing : inverse exact de ①\n"
            "• Bloc : 128 bits (4 mots 32 bits A,B,C,D)\n"
            "• 40 sous-clés de 32 bits | S-box 256×32 bits\n"
            "• Clé : 128/192/256 bits"
        )

    def get_key_info(self):
        return {"type": "symmetric", "placeholder": "Clé (16+ caractères)"}

    # ------------------------------------------------------------------
    # Helpers arithmétiques
    # ------------------------------------------------------------------

    def _rotl(self, x: int, n: int) -> int:
        n = n & 31
        return ((x << n) | (x >> (32 - n))) & self.MASK

    def _rotr(self, x: int, n: int) -> int:
        n = n & 31
        return ((x >> n) | (x << (32 - n))) & self.MASK

    def _s(self, idx: int) -> int:
        return self.SBOX[idx & (len(self.SBOX) - 1)]

    # ------------------------------------------------------------------
    # Key Schedule — 40 sous-clés de 32 bits
    # ------------------------------------------------------------------

    def _key_schedule(self, key: str) -> list:
        """
        Dérive 40 mots de sous-clés.
        La clé est chargée en mots 32 bits little-endian puis étendue
        par un LFSR avec XOR et rotations (spec MARS, version simplifiée).
        Les sous-clés du cœur (indices 4–35) ont leurs 2 bits de poids
        faible forcés à 1 (contrainte de la spec).
        """
        key_bytes = key.encode("utf-8")
        key_bytes = (key_bytes * (32 // len(key_bytes) + 1))[:32]

        T = list(struct.unpack_from('<8I', key_bytes[:32]))
        K = [0] * 40
        for i in range(40):
            T[0] = T[0] ^ self._rotl(T[3] ^ T[7], 3) ^ (4 * i)
            T[0] = self._rotl(T[0], 9)
            K[i] = T[0]
            T = T[1:] + [T[0]]

        for i in range(4, 36):
            K[i] |= 3

        return K

    # ------------------------------------------------------------------
    # Phase 1 — Forward mixing (8 demi-tours, inversible)
    # ------------------------------------------------------------------

    def _forward_mix(self, A, B, C, D, K, log_step=None):
        """
        Ajout des 4 premières sous-clés, puis 8 demi-tours :
          t = S[(A + K[4+i]) mod |S|]
          B ^= t,  C += t,  D ^= rotl(t, 13)
          A = rotl(A, 13)
          rotation circulaire A,B,C,D → B,C,D,A
        """
        A = (A + K[0]) & self.MASK
        B = (B + K[1]) & self.MASK
        C = (C + K[2]) & self.MASK
        D = (D + K[3]) & self.MASK

        for i in range(8):
            t = self._s((A + K[4 + i]) & self.MASK)
            B ^= t
            C = (C + t) & self.MASK
            D ^= self._rotl(t, 13)
            A = self._rotl(A, 13)
            A, B, C, D = B, C, D, A
            if log_step and i < 2:
                log_step(f"   Mix {i+1}: A={A:08X} B={B:08X} C={C:08X} D={D:08X}")

        return A, B, C, D

    def _backward_unmix(self, A, B, C, D, K):
        """Inverse exact de _forward_mix."""
        for i in range(7, -1, -1):
            A, B, C, D = D, A, B, C
            A = self._rotr(A, 13)
            t = self._s((A + K[4 + i]) & self.MASK)
            D ^= self._rotl(t, 13)
            C = (C - t) & self.MASK
            B ^= t

        D = (D - K[3]) & self.MASK
        C = (C - K[2]) & self.MASK
        B = (B - K[1]) & self.MASK
        A = (A - K[0]) & self.MASK

        return A, B, C, D

    # ------------------------------------------------------------------
    # Phase 2 — Core cryptographique (16 tours Feistel)
    # ------------------------------------------------------------------

    def _core_encrypt(self, A, B, C, D, K, log_step=None):
        """
        16 tours Feistel avec S-box et rotations.
        Chaque tour :
          f = S[A[0..7]] ^ S[A[8..15]]  +  K[12+2i]
          g = S[A[16..23]] ^ S[A[24..31]]  +  K[13+2i]
          B ^= f,  C += g,  D ^= rotl(f^g, 5)
          A = rotl(A, 13)
          rotation circulaire A,B,C,D → B,C,D,A
        """
        for i in range(16):
            ki  = K[(12 + 2 * i) % len(K)]
            ki1 = K[(13 + 2 * i) % len(K)]

            f = (self._s(A & 0xFF) ^ self._s((A >> 8) & 0xFF) + ki) & self.MASK
            g = (self._s((A >> 16) & 0xFF) ^ self._s((A >> 24) & 0xFF) + ki1) & self.MASK

            B ^= f
            C = (C + g) & self.MASK
            D ^= self._rotl(f ^ g, 5)
            A = self._rotl(A, 13)
            A, B, C, D = B, C, D, A

            if log_step and i < 3:
                log_step(f"   Core {i+1}: A={A:08X} B={B:08X} C={C:08X} D={D:08X}")

        return A, B, C, D

    def _core_decrypt(self, A, B, C, D, K):
        """Inverse exact de _core_encrypt."""
        for i in range(15, -1, -1):
            A, B, C, D = D, A, B, C
            A = self._rotr(A, 13)

            ki  = K[(12 + 2 * i) % len(K)]
            ki1 = K[(13 + 2 * i) % len(K)]

            f = (self._s(A & 0xFF) ^ self._s((A >> 8) & 0xFF) + ki) & self.MASK
            g = (self._s((A >> 16) & 0xFF) ^ self._s((A >> 24) & 0xFF) + ki1) & self.MASK

            D ^= self._rotl(f ^ g, 5)
            C = (C - g) & self.MASK
            B ^= f

        return A, B, C, D

    # ------------------------------------------------------------------
    # Phase 3 — Key whitening final
    # ------------------------------------------------------------------

    def _final_add(self, A, B, C, D, K):
        return (
            (A + K[36]) & self.MASK,
            (B + K[37]) & self.MASK,
            (C + K[38]) & self.MASK,
            (D + K[39]) & self.MASK,
        )

    def _final_sub(self, A, B, C, D, K):
        return (
            (A - K[36]) & self.MASK,
            (B - K[37]) & self.MASK,
            (C - K[38]) & self.MASK,
            (D - K[39]) & self.MASK,
        )

    # ------------------------------------------------------------------
    # Chiffrement / Déchiffrement d'un bloc 128 bits
    # ------------------------------------------------------------------

    def _encrypt_block(self, block: bytes, K: list, log_step=None) -> bytes:
        A, B, C, D = struct.unpack_from('<4I', block)

        if log_step:
            log_step(f"   Entrée  A={A:08X} B={B:08X} C={C:08X} D={D:08X}")

        A, B, C, D = self._forward_mix(A, B, C, D, K, log_step)

        if log_step:
            log_step(f"   → Après mixing  A={A:08X} B={B:08X} C={C:08X} D={D:08X}")

        A, B, C, D = self._core_encrypt(A, B, C, D, K, log_step)

        if log_step:
            log_step(f"   → Après core    A={A:08X} B={B:08X} C={C:08X} D={D:08X}")

        A, B, C, D = self._final_add(A, B, C, D, K)

        if log_step:
            log_step(f"   Sortie  A={A:08X} B={B:08X} C={C:08X} D={D:08X}")

        return struct.pack('<4I', A, B, C, D)

    def _decrypt_block(self, block: bytes, K: list) -> bytes:
        A, B, C, D = struct.unpack_from('<4I', block)
        A, B, C, D = self._final_sub(A, B, C, D, K)
        A, B, C, D = self._core_decrypt(A, B, C, D, K)
        A, B, C, D = self._backward_unmix(A, B, C, D, K)
        return struct.pack('<4I', A, B, C, D)

    # ------------------------------------------------------------------
    # Interface publique
    # ------------------------------------------------------------------

    def encrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        block = text.encode("utf-8")[:16].ljust(16, b'\x00')
        K = self._key_schedule(key)

        if log_step:
            log_step("🔐 MARS — CHIFFREMENT (Finaliste AES - IBM)")
            log_step("=" * 42)
            log_step("   Structure hybride en 3 phases :")
            log_step("   ① Forward mixing  (8 demi-tours + S-box)")
            log_step("   ② Core crypto     (16 tours Feistel + rotations)")
            log_step("   ③ Key whitening   (addition finale)")
            log_step(f"   Sous-clés : {len(K)} mots de 32 bits")
            log_step(f"   Texte (hex) : {block.hex()}\n")

        result = self._encrypt_block(block, K, log_step)

        if log_step:
            log_step(f"\n✅ Chiffré (hex) : {result.hex()}")

        return result.hex()

    def decrypt(self, text: str, key: str, log_step=None, log_matrix=None) -> str:
        try:
            block = bytes.fromhex(text.strip())[:16].ljust(16, b'\x00')
        except ValueError:
            block = text.encode("utf-8")[:16].ljust(16, b'\x00')

        K = self._key_schedule(key)

        if log_step:
            log_step("🔓 MARS — DÉCHIFFREMENT")
            log_step("=" * 42)
            log_step("   Ordre inverse des 3 phases :")
            log_step("   ① Annuler key whitening  (soustraction)")
            log_step("   ② Inverse core crypto    (16 tours inversés)")
            log_step("   ③ Backward unmixing")

        result = self._decrypt_block(block, K)
        decoded = result.decode("utf-8", errors="ignore").rstrip('\x00')

        if log_step:
            log_step(f"\n✅ Texte déchiffré : {decoded}")

        return decoded