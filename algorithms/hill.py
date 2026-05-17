"""
Hill Cipher - TP1 Exercice 1.3
Implémentation complète avec :
  - Hill 2×2 ET 3×3
  - Calcul de l'inverse modulaire de la matrice clé (det⁻¹ × adj mod 26)
  - Vérification de validité de la matrice
  - Attaque à clair connu
"""


class HillAlgorithm:

    def get_name(self):
        return "Hill Cipher"

    def get_description(self):
        return (
            "Chiffre de Hill — substitution polygraphique par blocs.\n"
            "Chiffrement : C = (P × K) mod 26\n"
            "Déchiffrement : P = (C × K⁻¹) mod 26\n"
            "Clé 2×2 : '3,3,2,5'  |  Clé 3×3 : '6,24,1,13,16,10,20,17,15'\n"
            "Attaque : 'known_plain:<clair>:<chiffre>'"
        )

    def get_key_info(self):
        return {
            "type": "symmetric",
            "placeholder": "4 entiers (2x2) ou 9 entiers (3x3) séparés par virgules"
        }

    # ------------------------------------------------------------------
    # Arithmétique modulaire
    # ------------------------------------------------------------------

    def _gcd(self, a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, a: int, m: int = 26) -> int:
        a = a % m
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        raise ValueError(f"Pas d'inverse pour {a} mod {m} "
                         f"(gcd={self._gcd(a, m)} ≠ 1)")

    # ------------------------------------------------------------------
    # Opérations matricielles mod 26
    # ------------------------------------------------------------------

    def _mat_mul(self, A: list, B: list, mod: int = 26) -> list:
        """Multiplie deux matrices carrées de même taille."""
        n = len(A)
        return [
            [(sum(A[i][k] * B[k][j] for k in range(n))) % mod
             for j in range(n)]
            for i in range(n)
        ]

    def _mat_vec(self, M: list, v: list, mod: int = 26) -> list:
        """Multiplie matrice × vecteur colonne."""
        n = len(M)
        return [(sum(M[i][j] * v[j] for j in range(n))) % mod for i in range(n)]

    # ------------------------------------------------------------------
    # Inverse modulaire d'une matrice (2×2 et 3×3)
    # ------------------------------------------------------------------

    def _det2(self, M: list) -> int:
        return (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % 26

    def _inverse_2x2(self, M: list) -> list:
        det = self._det2(M)
        if det == 0:
            raise ValueError("Déterminant nul — matrice non inversible.")
        det_inv = self._mod_inverse(det)
        a, b, c, d = M[0][0], M[0][1], M[1][0], M[1][1]
        return [
            [(d * det_inv) % 26,  (-b * det_inv) % 26],
            [(-c * det_inv) % 26, (a * det_inv) % 26],
        ]

    def _det3(self, M: list) -> int:
        return (
            M[0][0] * (M[1][1] * M[2][2] - M[1][2] * M[2][1])
            - M[0][1] * (M[1][0] * M[2][2] - M[1][2] * M[2][0])
            + M[0][2] * (M[1][0] * M[2][1] - M[1][1] * M[2][0])
        ) % 26

    def _cofactor3(self, M: list, r: int, c: int) -> int:
        """Cofacteur (r,c) d'une matrice 3×3."""
        sub = [
            [M[i][j] for j in range(3) if j != c]
            for i in range(3) if i != r
        ]
        sign = (-1) ** (r + c)
        minor = (sub[0][0] * sub[1][1] - sub[0][1] * sub[1][0]) % 26
        return (sign * minor) % 26

    def _inverse_3x3(self, M: list) -> list:
        det = self._det3(M)
        if det % 26 == 0:
            raise ValueError("Déterminant nul mod 26 — matrice non inversible.")
        det_inv = self._mod_inverse(int(det) % 26)
        # Matrice des cofacteurs transposée (adjointe)
        adj = [
            [(self._cofactor3(M, j, i) * det_inv) % 26 for j in range(3)]
            for i in range(3)
        ]
        return adj

    # ------------------------------------------------------------------
    # Parsing de la clé
    # ------------------------------------------------------------------

    def _parse_key(self, key: str) -> list:
        nums = [int(x) for x in key.replace(' ', '').split(',') if x]
        if len(nums) == 4:
            M = [[nums[0], nums[1]], [nums[2], nums[3]]]
            det = self._det2(M)
            if det == 0:
                raise ValueError("Matrice 2×2 : déterminant = 0 mod 26.")
            if self._gcd(int(det), 26) != 1:
                raise ValueError(f"Déterminant {det} non inversible mod 26 "
                                  f"(gcd={self._gcd(int(det), 26)}).")
            return M
        elif len(nums) == 9:
            M = [[nums[i * 3 + j] for j in range(3)] for i in range(3)]
            det = int(self._det3(M)) % 26
            if det == 0:
                raise ValueError("Matrice 3×3 : déterminant = 0 mod 26.")
            if self._gcd(det, 26) != 1:
                raise ValueError(f"Déterminant {det} non inversible mod 26 "
                                  f"(gcd={self._gcd(det, 26)}).")
            return M
        else:
            raise ValueError("Clé : 4 entiers (2×2) ou 9 entiers (3×3).")

    # ------------------------------------------------------------------
    # Texte → vecteurs et retour
    # ------------------------------------------------------------------

    def _text_to_vectors(self, text: str, block_size: int) -> tuple[list, str]:
        letters = "".join(c.upper() for c in text if c.isalpha())
        pad = (-len(letters)) % block_size
        letters += "X" * pad
        vectors = [
            [ord(letters[i + j]) - ord('A') for j in range(block_size)]
            for i in range(0, len(letters), block_size)
        ]
        return vectors, letters

    def _vectors_to_text(self, vectors: list) -> str:
        return "".join(chr(v + ord('A')) for vec in vectors for v in vec)

    # ------------------------------------------------------------------
    # Chiffrement (Exercice 1.3 – point 1)
    # ------------------------------------------------------------------

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        if str(key).strip().lower().startswith("known_plain"):
            return self._known_plaintext_attack(key, log_step=log_step)

        M = self._parse_key(key)
        n = len(M)

        if log_step:
            log_step(f"📐 HILL CIPHER {n}×{n} — CHIFFREMENT")
            log_step("=" * 42)
            log_step(f"Matrice clé K :")
            for row in M:
                log_step("  " + "  ".join(f"{v:3d}" for v in row))

        vectors, prepared = self._text_to_vectors(text, n)

        if log_step:
            log_step(f"\nTexte préparé ({n}-grammes) : {prepared}")
            log_step(f"Formule : C = P × K  mod 26\n")

        result_vectors = []
        for i, vec in enumerate(vectors):
            enc = self._mat_vec(M, vec)
            result_vectors.append(enc)
            if log_step:
                block_str = "".join(chr(v + ord('A')) for v in vec)
                enc_str = "".join(chr(v + ord('A')) for v in enc)
                log_step(f"  Bloc {i+1} '{block_str}' {vec} → {enc} '{enc_str}'")

        result = self._vectors_to_text(result_vectors)
        if log_step:
            log_step(f"\n✅ Texte chiffré : {result}")
        return result

    # ------------------------------------------------------------------
    # Déchiffrement (Exercice 1.3 – point 1)
    # ------------------------------------------------------------------

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        M = self._parse_key(key)
        n = len(M)
        inv_M = self._inverse_2x2(M) if n == 2 else self._inverse_3x3(M)

        if log_step:
            log_step(f"📐 HILL CIPHER {n}×{n} — DÉCHIFFREMENT")
            log_step("=" * 42)
            log_step("Matrice clé K :")
            for row in M:
                log_step("  " + "  ".join(f"{v:3d}" for v in row))
            det = self._det2(M) if n == 2 else self._det3(M)
            log_step(f"det(K) mod 26 = {int(det) % 26}")
            log_step(f"det⁻¹ mod 26  = {self._mod_inverse(int(det) % 26)}")
            log_step("\nMatrice inverse K⁻¹ = det⁻¹ × adj(K) mod 26 :")
            for row in inv_M:
                log_step("  " + "  ".join(f"{v:3d}" for v in row))
            log_step(f"\nFormule : P = C × K⁻¹  mod 26\n")

        vectors, prepared = self._text_to_vectors(text, n)
        result_vectors = []
        for i, vec in enumerate(vectors):
            dec = self._mat_vec(inv_M, vec)
            result_vectors.append(dec)
            if log_step:
                block_str = "".join(chr(v + ord('A')) for v in vec)
                dec_str = "".join(chr(v + ord('A')) for v in dec)
                log_step(f"  Bloc {i+1} '{block_str}' {vec} → {dec} '{dec_str}'")

        result = self._vectors_to_text(result_vectors)
        if log_step:
            log_step(f"\n✅ Texte déchiffré : {result}")
        return result

    # ------------------------------------------------------------------
    # Attaque à clair connu (Exercice 1.3 – point 2)
    # ------------------------------------------------------------------

    def _known_plaintext_attack(self, key_arg: str, log_step=None) -> str:
        """
        Syntaxe : 'known_plain:<plaintext>:<ciphertext>'
        Exemple  : 'known_plain:HELP:HIAT'  (Hill 2×2)
        Récupère la matrice clé K à partir de paires (clair, chiffré).
        K = P⁻¹ × C  mod 26
        """
        parts = key_arg.split(":")
        if len(parts) < 3:
            raise ValueError(
                "Format : 'known_plain:<clair>:<chiffre>' "
                "(ex: known_plain:HELP:HIAT)"
            )
        plain_text = "".join(c.upper() for c in parts[1] if c.isalpha())
        cipher_text = "".join(c.upper() for c in parts[2] if c.isalpha())

        # Détermine la taille du bloc
        if len(plain_text) >= 9 and len(cipher_text) >= 9:
           n = 3
        elif len(plain_text) >= 4 and len(cipher_text) >= 4:
           n = 2
        else:
            n = 2

        if log_step:
            log_step("⚔️  ATTAQUE À CLAIR CONNU — Hill Cipher")
            log_step("=" * 42)
            log_step(f"   Paires connues : clair='{plain_text[:n*n]}' "
                     f"chiffré='{cipher_text[:n*n]}'")
            log_step(f"   Taille de bloc : {n}×{n}")
            log_step(f"\n   Méthode : K = P⁻¹ × C  mod 26")

        # Construire les matrices P et C (n colonnes = n blocs)
        P = [[ord(plain_text[i * n + j]) - ord('A')
              for i in range(n)] for j in range(n)]
        C = [[ord(cipher_text[i * n + j]) - ord('A')
              for i in range(n)] for j in range(n)]

        if log_step:
            log_step("\n   Matrice P (clair) :")
            for row in P:
                log_step("     " + str(row))
            log_step("   Matrice C (chiffré) :")
            for row in C:
                log_step("     " + str(row))

        try:
            P_inv = self._inverse_2x2(P) if n == 2 else self._inverse_3x3(P)
            K_recovered = self._mat_mul(P_inv, C)
        except ValueError as e:
            return f"Attaque échouée : {e}"

        if log_step:
            log_step("\n   P⁻¹ mod 26 :")
            for row in P_inv:
                log_step("     " + str(row))
            log_step("\n✅ Clé K = P⁻¹ × C  mod 26 :")
            for row in K_recovered:
                log_step("     " + str(row))
            log_step(
                "\n   Réponse à la question :")
            log_step(
                "   Hill est vulnérable au clair connu car K se récupère")
            log_step(
                "   par simple inversion matricielle (K = P⁻¹ × C mod 26),")
            log_step(
                "   quelle que soit la taille de la matrice — la complexité")
            log_step(
                "   n'apporte pas de sécurité contre cette attaque.")

        flat = [str(K_recovered[i][j])
                for i in range(n) for j in range(n)]
        return "Clé récupérée K = " + ",".join(flat)