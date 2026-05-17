"""
Affine Cipher - TP1 (classique)
Correction : casse ignorée, sortie MAJUSCULES, logs enrichis
"""


class AffineAlgorithm:

    def __init__(self):
        self._inv_cache: dict[int, int] = {}

    def get_name(self):
        return "Affine Cipher"

    def get_description(self):
        return (
            "Chiffre affine : combinaison de multiplication et d'addition.\n"
            "Chiffrement : E(x) = (a·x + b) mod 26\n"
            "Déchiffrement : D(x) = a⁻¹·(x - b) mod 26\n"
            "'a' doit être copremier avec 26.\n"
            "Valeurs valides pour a : 1,3,5,7,9,11,15,17,19,21,23,25"
        )

    def get_key_info(self):
        return {
            "type": "symmetric",
            "placeholder": "'a,b' (ex: 5,8) — a copremier avec 26"
        }

    # ------------------------------------------------------------------
    # Arithmétique
    # ------------------------------------------------------------------

    def _gcd(self, a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, a: int, m: int = 26) -> int:
        a = a % m
        if a in self._inv_cache:
            return self._inv_cache[a]
        for x in range(1, m):
            if (a * x) % m == 1:
                self._inv_cache[a] = x
                return x
        raise ValueError(f"{a} n'a pas d'inverse mod {m} "
                         f"(gcd={self._gcd(a, m)} ≠ 1)")

    def _parse_key(self, key: str) -> tuple[int, int]:
        parts = key.replace(' ', '').split(',')
        if len(parts) < 2:
            raise ValueError("Format : 'a,b' (ex: 5,8)")
        a, b = int(parts[0]), int(parts[1]) % 26
        if self._gcd(a, 26) != 1:
            raise ValueError(
                f"a={a} n'est pas copremier avec 26 "
                f"(gcd={self._gcd(a,26)}). "
                "Valeurs valides : 1,3,5,7,9,11,15,17,19,21,23,25"
            )
        return a, b

    # ------------------------------------------------------------------
    # Chiffrement (casse ignorée → MAJUSCULES)
    # ------------------------------------------------------------------

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        a, b = self._parse_key(key)
        a_inv = self._mod_inverse(a)

        if log_step:
            log_step(f"📌 Chiffre Affine — Chiffrement")
            log_step(f"   E(x) = ({a}·x + {b}) mod 26")
            log_step(f"   a={a}, b={b}, a⁻¹={a_inv} (pour vérif)")
            log_step("=" * 42)

        prepared = "".join(c.upper() for c in text if c.isalpha())
        if log_step:
            log_step(f"   Texte préparé (MAJUSCULES) : {prepared}")

        result = ""
        for char in prepared:
            x = ord(char) - ord('A')
            y = (a * x + b) % 26
            new_char = chr(y + ord('A'))
            if log_step:
                log_step(f"  '{char}'(x={x}) → ({a}·{x}+{b})%26 = {y} → '{new_char}'")
            result += new_char

        if log_step:
            log_step(f"\n✅ Chiffré : {result}")
        return result

    # ------------------------------------------------------------------
    # Déchiffrement
    # ------------------------------------------------------------------

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        a, b = self._parse_key(key)
        a_inv = self._mod_inverse(a)

        if log_step:
            log_step(f"📌 Chiffre Affine — Déchiffrement")
            log_step(f"   D(x) = {a_inv}·(x - {b}) mod 26")
            log_step(f"   a⁻¹={a_inv}, b={b}")
            log_step("=" * 42)

        prepared = "".join(c.upper() for c in text if c.isalpha())

        result = ""
        for char in prepared:
            x = ord(char) - ord('A')
            y = (a_inv * (x - b)) % 26
            new_char = chr(y + ord('A'))
            if log_step:
                log_step(f"  '{char}'(x={x}) → {a_inv}·({x}-{b})%26 = {y} → '{new_char}'")
            result += new_char

        if log_step:
            log_step(f"\n✅ Déchiffré : {result}")
        return result