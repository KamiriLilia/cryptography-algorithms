"""
Vigenère Cipher - TP1 Exercice 1.2
Implémentation complète avec :
  - Chiffrement / Déchiffrement (casse ignorée → majuscules)
  - Test de Kasiski (estimation de la longueur de clé)
  - Analyse par IC (retrouver les lettres de la clé)
  - Affichage coloré compatible avec classify_log_line du main.py
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

    def _extend_key(self, text_letters: str, key: str) -> list:
        key_up = [ord(c) - ord('A') for c in key.upper() if c.isalpha()]
        if not key_up:
            raise ValueError("La clé doit contenir au moins une lettre.")
        return [key_up[i % len(key_up)] for i in range(len(text_letters))]

    # ------------------------------------------------------------------
    # 1. Chiffrement
    # ------------------------------------------------------------------

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:

        k = str(key).strip().lower()

        # ── En-tête principal (tag "header" → cyan dans l'app) ────────
        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║       VIGENÈRE — CHIFFREMENT DÉTAILLÉ        ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Texte clair : '{text}'")
            log_step(f"  Clé brute   : '{key}'")

        # ── Modes spéciaux : Kasiski / IC ─────────────────────────────
        if k == "kasiski":
            if log_step:
                log_step("  Mode        : TEST DE KASISKI")
                log_step("  ─" * 22)
            key_len = self.kasiski_test(text, log_step=log_step)
            return f"[Kasiski] Longueur de clé estimée : {key_len}"

        if k == "ic":
            if log_step:
                log_step("  Mode        : ATTAQUE PAR INDICE DE COÏNCIDENCE")
                log_step("  ─" * 22)
            recovered = self.ic_attack(text, log_step=log_step)
            return f"[IC] Clé récupérée : {recovered}"

        # ── Chiffrement lettre par lettre ──────────────────────────────
        prepared = self._letters_only(text)
        key_vals = self._extend_key(prepared, key)

        if log_step:
            log_step(f"  Mode        : CHIFFREMENT VIGENÈRE")
            log_step(f"  Mot-clé     : {key.upper()}")
            log_step(f"  Texte prép. : {prepared}")
            log_step(f"  ──────────────────────────────────────────────")
            log_step(f"  {'i':>4}  {'Clair':>7}  {'Clé':>7}  "
                     f"{'Formule':>14}  {'Chiffré':>8}")
            log_step(f"  ──────────────────────────────────────────────")

        result = ""
        for i, char in enumerate(prepared):
            p        = ord(char) - ord('A')
            k_val    = key_vals[i]
            c        = (p + k_val) % 26
            new_char = chr(c + ord('A'))
            if log_step:
                log_step(
                    f"  [{i+1:>3}]  "
                    f"'{char}'({p:2d})   "
                    f"'{chr(k_val+65)}'({k_val:2d})  "
                    f"({p}+{k_val})%26={c:2d}   "
                    f"→ '{new_char}'"
                )
            result += new_char

        if log_step:
            log_step(f"  ──────────────────────────────────────────────")
            log_step(f"✅ Texte chiffré : {result}")

        return result

    # ------------------------------------------------------------------
    # 2. Déchiffrement
    # ------------------------------------------------------------------

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:

        k = str(key).strip().lower()

        # ── En-tête principal ──────────────────────────────────────────
        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║       VIGENÈRE — DÉCHIFFREMENT DÉTAILLÉ      ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Texte chiffré : '{text}'")
            log_step(f"  Clé brute     : '{key}'")

        # ── Modes spéciaux : Kasiski / IC ─────────────────────────────
        if k == "kasiski":
            if log_step:
                log_step("  Mode        : TEST DE KASISKI")
                log_step("  ─" * 22)
            key_len = self.kasiski_test(text, log_step=log_step)
            return f"[Kasiski] Longueur de clé estimée : {key_len}"

        if k == "ic":
            if log_step:
                log_step("  Mode        : ATTAQUE PAR IC → puis déchiffrement")
                log_step("  ─" * 22)
            recovered = self.ic_attack(text, log_step=log_step)
            if log_step:
                log_step(f"")
                log_step("╔══════════════════════════════════════════════╗")
                log_step("║   VIGENÈRE — DÉCHIFFREMENT AVEC CLÉ TROUVÉE ║")
                log_step("╚══════════════════════════════════════════════╝")
                log_step(f"  Clé récupérée : '{recovered}'")
            # Appel récursif SANS re-afficher l'en-tête (log_step=None)
            return self._decrypt_core(text, recovered, log_step=log_step)

        # ── Déchiffrement normal ───────────────────────────────────────
        return self._decrypt_core(text, key, log_step=log_step)

    def _decrypt_core(self, text: str, key: str, log_step=None) -> str:
        """Noyau du déchiffrement — appelé directement ou après IC."""
        prepared = self._letters_only(text)
        key_vals = self._extend_key(prepared, key)

        if log_step:
            log_step(f"  Mot-clé     : {key.upper()}")
            log_step(f"  Texte prép. : {prepared}")
            log_step(f"  ──────────────────────────────────────────────")
            log_step(f"  {'i':>4}  {'Chiffré':>8}  {'Clé':>7}  "
                     f"{'Formule':>15}  {'Clair':>7}")
            log_step(f"  ──────────────────────────────────────────────")

        result = ""
        for i, char in enumerate(prepared):
            c        = ord(char) - ord('A')
            k_val    = key_vals[i]
            p        = (c - k_val) % 26
            new_char = chr(p + ord('A'))
            if log_step:
                log_step(
                    f"  [{i+1:>3}]  "
                    f"'{char}'({c:2d})    "
                    f"'{chr(k_val+65)}'({k_val:2d})  "
                    f"({c}-{k_val})%26={p:2d}   "
                    f"→ '{new_char}'"
                )
            result += new_char

        if log_step:
            log_step(f"  ──────────────────────────────────────────────")
            log_step(f"✅ Texte déchiffré : {result}")

        return result

    # ------------------------------------------------------------------
    # 3. Test de Kasiski
    # ------------------------------------------------------------------

    def kasiski_test(self, ciphertext: str, log_step=None) -> int:
        """
        Recherche les trigrammes répétés dans le cryptogramme.
        Calcule le PGCD des distances entre répétitions pour estimer
        la longueur probable de la clé.
        """
        prepared = self._letters_only(ciphertext)

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║         TEST DE KASISKI — VIGENÈRE           ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Cryptogramme ({len(prepared)} lettres) :")
            log_step(f"  {prepared[:60]}{'...' if len(prepared)>60 else ''}")
            log_step(f"  ──────────────────────────────────────────────")

        # ── Recherche des trigrammes répétés ──────────────────────────
        trigram_positions: dict = {}
        for i in range(len(prepared) - 2):
            trig = prepared[i:i + 3]
            trigram_positions.setdefault(trig, []).append(i)

        repeated = {t: pos for t, pos in trigram_positions.items()
                    if len(pos) > 1}

        if log_step:
            log_step(f"  Trigrammes répétés trouvés : {len(repeated)}")
            log_step(f"  ──────────────────────────────────────────────")

        if not repeated:
            if log_step:
                log_step("  Aucun trigramme répété — texte trop court ?")
            return 3

        # ── Distances entre répétitions ───────────────────────────────
        distances = []
        if log_step:
            log_step(f"  {'Trigramme':>12}  {'Pos A':>6}  {'Pos B':>6}  "
                     f"{'Distance':>9}")
            log_step(f"  ──────────────────────────────────────────────")

        for trig, positions in repeated.items():
            for i in range(len(positions) - 1):
                d = positions[i + 1] - positions[i]
                distances.append(d)
                if log_step:
                    log_step(
                        f"     '{trig}'        "
                        f"{positions[i]:>6}   "
                        f"{positions[i+1]:>6}   "
                        f"→ d = {d}"
                    )

        # ── PGCD de toutes les distances ──────────────────────────────
        overall_gcd = reduce(gcd, distances)

        if log_step:
            log_step(f"  ──────────────────────────────────────────────")
            log_step(f"  PGCD de toutes les distances : {overall_gcd}")
            log_step(f"✅ Longueur de clé estimée : {overall_gcd}")
            log_step(f"  ──────────────────────────────────────────────")
            log_step(f"  Remarque théorique :")
            log_step(f"  Plus la clé est longue → IC s'approche de 0.0385")
            log_step(f"  Si |K| = |M| → One-Time Pad (Vernam) : sécurité parfaite")

        return overall_gcd

    # ------------------------------------------------------------------
    # 4. Analyse par IC — retrouver la clé
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
        freq = {c: subseq.count(c) / n * 100
                for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
        best_corr = -1.0
        best_k    = 0
        for k in range(26):
            corr = sum(
                freq.get(chr((ord(letter) + k) % 26 + ord('A')), 0)
                * FRENCH_FREQ[letter]
                for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            )
            if corr > best_corr:
                best_corr = corr
                best_k    = k
        return chr(best_k + ord('A'))

    def ic_attack(self, ciphertext: str, log_step=None,
                  max_key_len: int = 20) -> str:
        """
        Pour chaque longueur de clé k (1..max_key_len) :
          - Découpe le cryptogramme en k sous-séquences
          - Calcule l'IC moyen
          - Retient la longueur dont l'IC est le plus proche de IC_FRENCH
        Puis retrouve chaque lettre de la clé par analyse de fréquences.
        """
        prepared = self._letters_only(ciphertext)

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║  ATTAQUE PAR INDICE DE COÏNCIDENCE — VIGENÈRE║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Cryptogramme : {len(prepared)} lettres")
            log_step(f"  IC français de référence : {IC_FRENCH:.4f}")
            log_step(f"  ──────────────────────────────────────────────")
            log_step(f"  {'k':>4}  {'IC moyen':>10}  {'Δ IC':>10}  {'Meilleur':>9}")
            log_step(f"  ──────────────────────────────────────────────")

        best_key_len = 1
        best_ic_diff = float('inf')

        for k in range(1, min(max_key_len + 1, len(prepared) // 2)):
            subsequences = [prepared[i::k] for i in range(k)]
            ic_avg = sum(self._compute_ic(s) for s in subsequences) / k
            diff   = abs(ic_avg - IC_FRENCH)
            is_best = diff < best_ic_diff
            if is_best:
                best_ic_diff = diff
                best_key_len = k
            if log_step:
                marker = "  ←" if is_best else ""
                log_step(
                    f"  {k:>4}  {ic_avg:>10.4f}  {diff:>10.4f}{marker}"
                )

        if log_step:
            log_step(f"  ──────────────────────────────────────────────")
            log_step(f"✅ Longueur de clé retenue : {best_key_len}")
            log_step(f"  ──────────────────────────────────────────────")
            log_step(f"  Recherche de chaque lettre de la clé :")

        # ── Retrouver chaque lettre de la clé ─────────────────────────
        subsequences  = [prepared[i::best_key_len] for i in range(best_key_len)]
        recovered_key = ""
        for i, subseq in enumerate(subsequences):
            letter = self._best_shift_for_subsequence(subseq)
            recovered_key += letter
            if log_step:
                log_step(
                    f"  Sous-séquence {i+1:>2} "
                    f"({len(subseq):>3} lettres) "
                    f"→ lettre clé : '{letter}'"
                )

        if log_step:
            log_step(f"  ──────────────────────────────────────────────")
            log_step(f"✅ Clé récupérée : {recovered_key}")

        return recovered_key

    # ------------------------------------------------------------------
    # 5. Génération de la clé étendue (utilitaire)
    # ------------------------------------------------------------------

    def generate_key(self, text: str, key: str) -> list:
        """Génère la liste des valeurs de clé alignées sur le texte."""
        letters = self._letters_only(text)
        return self._extend_key(letters, key)