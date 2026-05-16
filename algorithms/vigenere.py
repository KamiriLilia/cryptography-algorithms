"""
Vigenère Cipher - TP1 Exercice 1.2
Implémentation complète avec :
  - Chiffrement / Déchiffrement (casse ignorée → majuscules)
  - Test de Kasiski (estimation de la longueur de clé)
  - Analyse par IC (retrouver les lettres de la clé)
"""

from math import gcd
from functools import reduce

IC_FRENCH = 0.074

FRENCH_FREQ = {
    'E': 14.715, 'A': 7.636, 'I': 7.529, 'S': 7.948, 'N': 7.095,
    'R': 6.553, 'T': 7.244, 'O': 5.378, 'L': 5.456, 'U': 6.311,
    'D': 3.669, 'C': 3.260, 'M': 2.968, 'P': 2.521, 'V': 1.628,
    'H': 0.737, 'G': 1.054, 'F': 1.066, 'B': 0.901, 'Q': 1.362,
    'J': 0.613, 'X': 0.427, 'Z': 0.326, 'Y': 0.128, 'K': 0.049, 'W': 0.114,
}


class VigenereAlgorithm:

    def get_name(self):
        return "Vigenère Cipher"

    def get_description(self):
        return (
            "Chiffre de Vigenère — substitution poly-alphabétique.\n"
            "Chiffrement : Ci = (Pi + Ki) mod 26\n"
            "Déchiffrement : Pi = (Ci - Ki) mod 26\n"
            "Clés spéciales : 'kasiski' ou 'ic' pour attaque automatique."
        )

    def get_key_info(self):
        return {
            "type": "symmetric",
            "placeholder": "Mot-clé (lettres) | 'kasiski' | 'ic'"
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _letters_only(self, text: str) -> str:
        return "".join(c.upper() for c in text if c.isalpha())

    def _extend_key(self, text_letters: str, key: str) -> list[int]:
        key_up = [ord(c) - ord('A') for c in key.upper() if c.isalpha()]
        if not key_up:
            raise ValueError("La clé doit contenir au moins une lettre.")
        return [key_up[i % len(key_up)] for i in range(len(text_letters))]

    # ------------------------------------------------------------------
    # 1. Chiffrement (Exercice 1.2 – point 1)
    # ------------------------------------------------------------------

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        k = str(key).strip().lower()
        if k == "kasiski":
            key_len = self.kasiski_test(text, log_step=log_step)
            return f"[Kasiski] Longueur de clé estimée : {key_len}"
        if k == "ic":
            recovered = self.ic_attack(text, log_step=log_step)
            return f"[IC] Clé récupérée : {recovered}"

        prepared = self._letters_only(text)
        key_vals = self._extend_key(prepared, key)

        if log_step:
            log_step("🔐 Chiffrement Vigenère")
            log_step(f"   Mot-clé : {key.upper()}")
            log_step(f"   Texte préparé : {prepared}")
            log_step("=" * 42)

        result = ""
        for i, char in enumerate(prepared):
            p = ord(char) - ord('A')
            k_val = key_vals[i]
            c = (p + k_val) % 26
            new_char = chr(c + ord('A'))
            if log_step:
                log_step(f"  '{char}'({p}) + '{chr(k_val+65)}'({k_val})"
                         f" = {c} → '{new_char}'")
            result += new_char

        if log_step:
            log_step(f"\n✅ Texte chiffré : {result}")
        return result

    # ------------------------------------------------------------------
    # 2. Déchiffrement (Exercice 1.2 – point 1)
    # ------------------------------------------------------------------

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        k = str(key).strip().lower()
        if k == "kasiski":
            key_len = self.kasiski_test(text, log_step=log_step)
            return f"[Kasiski] Longueur de clé estimée : {key_len}"
        if k == "ic":
            recovered = self.ic_attack(text, log_step=log_step)
            # Déchiffre avec la clé récupérée
            return self.decrypt(text, recovered, log_step=log_step)

        prepared = self._letters_only(text)
        key_vals = self._extend_key(prepared, key)

        if log_step:
            log_step("🔓 Déchiffrement Vigenère")
            log_step(f"   Mot-clé : {key.upper()}")
            log_step(f"   Texte préparé : {prepared}")
            log_step("=" * 42)

        result = ""
        for i, char in enumerate(prepared):
            c = ord(char) - ord('A')
            k_val = key_vals[i]
            p = (c - k_val) % 26
            new_char = chr(p + ord('A'))
            if log_step:
                log_step(f"  '{char}'({c}) - '{chr(k_val+65)}'({k_val})"
                         f" = {p} → '{new_char}'")
            result += new_char

        if log_step:
            log_step(f"\n✅ Texte déchiffré : {result}")
        return result

    # ------------------------------------------------------------------
    # 3. Test de Kasiski (Exercice 1.2 – point 2)
    # ------------------------------------------------------------------

    def kasiski_test(self, ciphertext: str, log_step=None) -> int:
        """
        Recherche les trigrammes répétés dans le cryptogramme.
        Calcule le PGCD des distances entre répétitions pour estimer
        la longueur probable de la clé.
        Retourne la longueur estimée (int).
        """
        prepared = self._letters_only(ciphertext)

        if log_step:
            log_step("🔍 TEST DE KASISKI — Vigenère")
            log_step(f"   Cryptogramme ({len(prepared)} lettres) : "
                     f"{prepared[:60]}...")
            log_step("=" * 42)

        # Recherche de tous les trigrammes répétés et leurs positions
        trigram_positions: dict[str, list[int]] = {}
        for i in range(len(prepared) - 2):
            trig = prepared[i:i + 3]
            trigram_positions.setdefault(trig, []).append(i)

        repeated = {t: pos for t, pos in trigram_positions.items()
                    if len(pos) > 1}

        if log_step:
            log_step(f"   Trigrammes répétés trouvés : {len(repeated)}")

        if not repeated:
            if log_step:
                log_step("   ⚠️  Aucun trigramme répété — texte trop court ?")
            return 3  # valeur par défaut

        # Distances entre répétitions
        distances = []
        for trig, positions in repeated.items():
            for i in range(len(positions) - 1):
                d = positions[i + 1] - positions[i]
                distances.append(d)
                if log_step:
                    log_step(f"   '{trig}' aux positions {positions[i]} et "
                             f"{positions[i+1]} → distance = {d}")

        # PGCD de toutes les distances
        overall_gcd = reduce(gcd, distances)

        if log_step:
            log_step(f"\n   PGCD de toutes les distances : {overall_gcd}")
            log_step(f"✅ Longueur de clé estimée : {overall_gcd}")
            log_step(f"\n   Réponse à la question :")
            log_step("   Plus la clé est longue, plus l'IC se rapproche de")
            log_step(f"   celui d'un texte aléatoire ({0.0385:.4f}).")
            log_step("   Quand |K| = |M| → One-Time Pad (Vernam) : ")
            log_step("   IC ≈ 0.0385, sécurité parfaite théorique.")

        return overall_gcd

    # ------------------------------------------------------------------
    # 4. Analyse par IC — retrouver la clé (Exercice 1.2 – point 3)
    # ------------------------------------------------------------------

    def _compute_ic(self, text: str) -> float:
        n = len(text)
        if n < 2:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

    def _best_shift_for_subsequence(self, subseq: str) -> str:
        """Trouve la lettre de clé qui maximise la corrélation de fréquences."""
        n = len(subseq)
        freq = {c: subseq.count(c) / n * 100 for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
        best_corr = -1.0
        best_k = 0
        for k in range(26):
            corr = sum(
                freq.get(chr((ord(letter) + k) % 26 + ord('A')), 0)
                * FRENCH_FREQ[letter]
                for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            )
            if corr > best_corr:
                best_corr = corr
                best_k = k
        return chr(best_k + ord('A'))

    def ic_attack(self, ciphertext: str, log_step=None,
                  max_key_len: int = 20) -> str:
        """
        Pour chaque longueur de clé k possible (1..max_key_len) :
          - Découpe le cryptogramme en k sous-séquences
          - Calcule l'IC moyen
          - La longueur dont l'IC moyen est le plus proche de IC_FRENCH est retenue
        Puis retrouve chaque lettre de la clé par analyse de fréquences.
        Retourne la clé récupérée (str).
        """
        prepared = self._letters_only(ciphertext)

        if log_step:
            log_step("📊 ATTAQUE PAR INDICE DE COÏNCIDENCE — Vigenère")
            log_step(f"   Cryptogramme ({len(prepared)} lettres)")
            log_step("=" * 42)

        best_key_len = 1
        best_ic_diff = float('inf')

        if log_step:
            log_step("   k  |  IC moyen  |  Δ avec IC français")
            log_step("   ---|------------|--------------------")

        for k in range(1, min(max_key_len + 1, len(prepared) // 2)):
            subsequences = [prepared[i::k] for i in range(k)]
            ic_avg = sum(self._compute_ic(s) for s in subsequences) / k
            diff = abs(ic_avg - IC_FRENCH)
            if log_step:
                log_step(f"   {k:2d} |  {ic_avg:.4f}    |  {diff:.4f}")
            if diff < best_ic_diff:
                best_ic_diff = diff
                best_key_len = k

        if log_step:
            log_step(f"\n✅ Longueur de clé retenue : {best_key_len}")

        # Retrouver chaque lettre de la clé
        subsequences = [prepared[i::best_key_len] for i in range(best_key_len)]
        recovered_key = ""
        for i, subseq in enumerate(subsequences):
            letter = self._best_shift_for_subsequence(subseq)
            recovered_key += letter
            if log_step:
                log_step(f"   Sous-séquence {i+1} → lettre clé : '{letter}'")

        if log_step:
            log_step(f"\n✅ Clé récupérée : {recovered_key}")

        return recovered_key

    # ------------------------------------------------------------------
    # 5. Génération de la clé étendue (utilitaire interne)
    # ------------------------------------------------------------------

    def generate_key(self, text: str, key: str) -> list:
        """Génère la liste des valeurs de clé alignées sur le texte."""
        letters = self._letters_only(text)
        return self._extend_key(letters, key)