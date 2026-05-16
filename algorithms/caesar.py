"""
Caesar Cipher - TP1 Exercice 1.1
Implémentation complète avec :
  - Chiffrement / Déchiffrement (casse ignorée → majuscules)
  - Attaque par force brute + détection auto du français
  - Analyse de fréquences + Indice de Coïncidence (IC)

CORRECTIONS APPLIQUÉES :
  1. Bug formule IC : corr = Σ freq_chiffré[X] × FRENCH_FREQ[(X-k) mod 26]
     donne directement k (clé de déchiffrement), sans inversion (26-k).
  2. Force brute : conserve les espaces du texte source pour que
     split() retrouve les mots → score fiable même sur textes courts.
  3. Score normalisé (proportion) au lieu du comptage brut.
  4. Fonctions standalone chiffrer_cesar() / dechiffrer_cesar() ajoutées.
"""

# ──────────────────────────────────────────────────────────
# Mots français courants pour la détection automatique
# ──────────────────────────────────────────────────────────
FRENCH_WORDS = {
    "le", "la", "les", "de", "du", "des", "un", "une", "et", "est",
    "en", "au", "aux", "ce", "se", "sa", "son", "ses", "ou", "si",
    "je", "tu", "il", "elle", "nous", "vous", "ils", "elles", "on",
    "que", "qui", "quoi", "dont", "ou", "pas", "plus", "tres", "bien",
    "avec", "dans", "sur", "par", "pour", "comme", "mais", "donc",
    "etre", "avoir", "faire", "dire", "aller", "voir", "venir", "tout",
    "bonjour", "monde", "france", "oui", "non", "merci", "jour", "nuit",
    "homme", "femme", "enfant", "maison", "ville", "pays", "temps", "vie",
}

# ──────────────────────────────────────────────────────────
# Fréquences des lettres en français (en %)
# ──────────────────────────────────────────────────────────
FRENCH_FREQ = {
    'E': 14.715, 'A': 7.636, 'I': 7.529, 'S': 7.948, 'N': 7.095,
    'R': 6.553,  'T': 7.244, 'O': 5.378, 'L': 5.456, 'U': 6.311,
    'D': 3.669,  'C': 3.260, 'M': 2.968, 'P': 2.521, 'V': 1.628,
    'H': 0.737,  'G': 1.054, 'F': 1.066, 'B': 0.901, 'Q': 1.362,
    'J': 0.613,  'X': 0.427, 'Z': 0.326, 'Y': 0.128, 'K': 0.049,
    'W': 0.114,
}

IC_FRENCH = 0.074   # Indice de coïncidence théorique du français
IC_RANDOM = 0.0385  # Indice de coïncidence d'un texte aléatoire


# ══════════════════════════════════════════════════════════
class CaesarAlgorithm:
# ══════════════════════════════════════════════════════════

    def get_name(self):
        return "Caesar Cipher"

    def get_description(self):
        return (
            "Le chiffre de César décale chaque lettre d'un nombre fixe.\n"
            "Chiffrement : C = (P + K) mod 26\n"
            "Déchiffrement : P = (C - K) mod 26\n"
            "Attaque force brute et analyse de fréquences disponibles."
        )

    def get_key_info(self):
        return {
            "type": "symmetric",
            "placeholder": "Décalage (1-25) | 'brute' | 'ic'",
        }

    # ──────────────────────────────────────────────────────
    # Helpers internes
    # ──────────────────────────────────────────────────────

    def _letters_only(self, text: str) -> str:
        """Retourne uniquement les lettres en majuscules (espaces supprimés)."""
        return "".join(c.upper() for c in text if c.isalpha())

    def _shift_char(self, char: str, shift: int) -> str:
        """Décale un caractère alphabétique majuscule de `shift` positions."""
        return chr((ord(char) - ord('A') + shift) % 26 + ord('A'))

    def _parse_shift(self, key) -> int:
        """Valide et convertit la clé en entier 1-25."""
        try:
            shift = int(key)
            if not 1 <= shift <= 25:
                raise ValueError
            return shift
        except (ValueError, TypeError):
            raise ValueError(
                "La clé doit être un entier entre 1 et 25 "
                "(ou 'brute' / 'ic')"
            )

    # ──────────────────────────────────────────────────────
    # 1. Chiffrement
    # ──────────────────────────────────────────────────────

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        """
        Chiffre `text` avec le décalage `key`.
        Casse ignorée, espaces/ponctuation supprimés → sortie MAJUSCULES.
        Modes spéciaux : 'brute' → force brute | 'ic' → analyse IC.
        """
        if str(key).strip().lower() == "brute":
            return self.brute_force_attack(text, log_step=log_step)
        if str(key).strip().lower() == "ic":
            k, _ = self.frequency_analysis(text, log_step=log_step)
            return self._caesar_encrypt(
                self._letters_only(text), k, log_step=log_step
            )

        shift = self._parse_shift(key)
        prepared = self._letters_only(text)
        return self._caesar_encrypt(prepared, shift, log_step=log_step)

    def _caesar_encrypt(self, text_upper: str, shift: int,
                        log_step=None) -> str:
        if log_step:
            log_step(f"Chiffre de César — Décalage : {shift}")
            log_step(f"   Texte préparé : {text_upper}")
            log_step("=" * 42)

        result = ""
        for char in text_upper:
            new_char = self._shift_char(char, shift)
            if log_step:
                log_step(f"  '{char}' → '{new_char}' (+{shift} mod 26)")
            result += new_char

        if log_step:
            log_step(f"\nTexte chiffré : {result}")
        return result

    # ──────────────────────────────────────────────────────
    # 2. Déchiffrement
    # ──────────────────────────────────────────────────────

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        """
        Déchiffre `text` avec le décalage `key`.
        Modes spéciaux : 'brute' et 'ic' déduisent la clé automatiquement.
        """
        if str(key).strip().lower() == "brute":
            return self.brute_force_attack(text, log_step=log_step)
        if str(key).strip().lower() == "ic":
            k, _ = self.frequency_analysis(text, log_step=log_step)
            key = str(k)

        shift = self._parse_shift(key)
        prepared = self._letters_only(text)

        if log_step:
            log_step(f"Déchiffrement César — Décalage : {shift}")
            log_step(f"   Texte préparé : {prepared}")
            log_step("=" * 42)

        result = ""
        for char in prepared:
            new_char = self._shift_char(char, -shift)
            if log_step:
                log_step(f"  '{char}' → '{new_char}' (-{shift} mod 26)")
            result += new_char

        if log_step:
            log_step(f"\nTexte déchiffré : {result}")
        return result

    # ──────────────────────────────────────────────────────
    # 3. Attaque par force brute
    # ──────────────────────────────────────────────────────

    def brute_force_attack(self, ciphertext: str, log_step=None) -> str:
        """
        Teste les 26 décalages possibles.

        CORRECTION : le texte original (espaces conservés) est utilisé
        pour déchiffrer les candidats afin que split() retrouve les mots
        et que le score soit fiable même sur des textes courts.

        Identifie automatiquement le texte français via un dictionnaire.
        Retourne le meilleur candidat déchiffré (sans espaces, majuscules).
        """
        if not any(c.isalpha() for c in ciphertext):
            raise ValueError("Le texte chiffré ne contient aucune lettre.")

        if log_step:
            log_step("ATTAQUE PAR FORCE BRUTE — César")
            log_step(f"   Cryptogramme : {ciphertext}")
            log_step("=" * 42)

        best_score = -1.0
        best_plain = ""
        best_k = 0

        for k in range(26):
            # Déchiffrer en conservant les espaces (pour le scoring par mots)
            candidate_with_spaces = "".join(
                self._shift_char(c.upper(), -k) if c.isalpha() else c
                for c in ciphertext
            )
            score = self._french_score_normalized(candidate_with_spaces)
            candidate_clean = self._letters_only(candidate_with_spaces)

            if log_step:
                preview = candidate_clean[:40] + (
                    "..." if len(candidate_clean) > 40 else ""
                )
                log_step(f"  k={k:2d} | score={score:.3f} | {preview}")

            if score > best_score:
                best_score = score
                best_plain = candidate_clean
                best_k = k

        if log_step:
            log_step(f"\nMeilleure clé trouvée : k={best_k}  "
                     f"(score={best_score:.3f})")
            log_step(f"   Texte déchiffré : {best_plain}")

        return best_plain

    def _french_score_normalized(self, text: str) -> float:
        """
        Score normalisé : proportion de mots français reconnus.
        Robuste sur les textes courts (évite le biais de longueur).
        Retourne 0.0 si le texte ne contient aucun mot.
        """
        words = text.lower().split()
        if not words:
            return 0.0
        recognized = sum(1 for w in words if w in FRENCH_WORDS)
        return recognized / len(words)

    # ──────────────────────────────────────────────────────
    # 4. Analyse de fréquences + Indice de Coïncidence
    # ──────────────────────────────────────────────────────

    def frequency_analysis(self, ciphertext: str,
                           log_step=None) -> tuple:
        """
        Calcule l'IC du cryptogramme, compare à l'IC du français (≈0.074)
        et déduit k sans force brute par corrélation de fréquences.

        FORMULE CORRIGÉE :
          k = argmax Σ_X  freq_chiffré[X] × FRENCH_FREQ[(X - k) mod 26]

        Intuition : si C = P + k alors P = C - k.
        La lettre X du chiffré correspond à la lettre (X-k) du français.
        Le k qui maximise la corrélation est directement la clé de déchiffrement.
        Pas d'inversion (26-k) nécessaire.

        Retourne (k_déduit, ic_calculé).
        """
        prepared = self._letters_only(ciphertext)
        n = len(prepared)
        if n < 2:
            raise ValueError(
                "Texte trop court pour l'analyse de fréquences."
            )

        # ── Calcul de l'IC ──────────────────────────────────────────────
        freq = {}
        for c in prepared:
            freq[c] = freq.get(c, 0) + 1

        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

        if log_step:
            log_step("ANALYSE DE FRÉQUENCES — César")
            log_step(
                f"   Cryptogramme ({n} lettres) : "
                f"{prepared[:60]}{'...' if n > 60 else ''}"
            )
            log_step("=" * 42)
            log_step(f"   IC calculé   : {ic:.4f}")
            log_step(f"   IC français  : {IC_FRENCH:.4f}")
            log_step(f"   IC aléatoire : {IC_RANDOM:.4f}")
            if abs(ic - IC_FRENCH) < 0.01:
                log_step(
                    "   → IC proche du français : "
                    "substitution mono-alphabétique confirmée"
                )
            else:
                log_step(
                    "   → IC éloigné du français : "
                    "texte peut-être poly-alphabétique"
                )

        # ── Corrélation de fréquences (formule corrigée) ────────────────
        freq_pct = {
            c: (freq.get(c, 0) / n) * 100
            for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        }

        best_corr = -1.0
        best_k = 0
        corr_table = []

        for k in range(26):
            corr = sum(
                freq_pct.get(x, 0)
                * FRENCH_FREQ.get(
                    chr((ord(x) - ord('A') - k) % 26 + ord('A')), 0
                )
                for x in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            )
            corr_table.append((k, corr))
            if corr > best_corr:
                best_corr = corr
                best_k = k

        if log_step:
            log_step("\n   Top 5 corrélations (clé de déchiffrement) :")
            for k, corr in sorted(corr_table, key=lambda x: -x[1])[:5]:
                log_step(f"     k={k:2d} → corrélation = {corr:.2f}")
            decrypted = "".join(
                self._shift_char(c, -best_k) for c in prepared
            )
            log_step(f"\nClé déduite par IC : k = {best_k}")
            log_step(f"   Texte déchiffré : {decrypted}")

        return best_k, ic


# ══════════════════════════════════════════════════════════
# Fonctions standalone — nommage exigé par le TP
# ══════════════════════════════════════════════════════════

_algo = CaesarAlgorithm()


def chiffrer_cesar(texte: str, k: int) -> str:
    """
    Chiffre `texte` avec le décalage `k` (1–25).
    Ignore les espaces, la ponctuation et la casse.
    Retourne le texte chiffré en majuscules.
    """
    return _algo.encrypt(texte, str(k))


def dechiffrer_cesar(texte: str, k: int) -> str:
    """
    Déchiffre `texte` avec le décalage `k` (1–25).
    Retourne le texte déchiffré en majuscules.
    """
    return _algo.decrypt(texte, str(k))


# ══════════════════════════════════════════════════════════
# Tests de validation
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":

    sep = "=" * 55

    print(sep)
    print("  TESTS DE VALIDATION — Chiffre de César")
    print(sep)

    # ── Test 1 : chiffrement / déchiffrement de base ───────────────────
    print("\n[1] Chiffrement / Déchiffrement de base")

    assert chiffrer_cesar("ABC", 3)  == "DEF", "Erreur ABC→DEF"
    assert dechiffrer_cesar("DEF", 3) == "ABC", "Erreur DEF→ABC"
    assert chiffrer_cesar("XYZ", 3)  == "ABC", "Erreur wrap XYZ→ABC"
    assert dechiffrer_cesar("ABC", 3) == "XYZ", "Erreur wrap ABC→XYZ"

    texte = "le chiffre de cesar est simple mais efficace"
    letters_only = _algo._letters_only(texte)
    for k in range(1, 26):
        assert dechiffrer_cesar(chiffrer_cesar(texte, k), k) == letters_only, \
            f"Symétrie rompue pour k={k}"

    print("  OK — chiffrement / déchiffrement + wrap-around + symétrie")

    # ── Test 2 : force brute ───────────────────────────────────────────
    print("\n[2] Force brute")

    cas_brute = [
        ("bonjour le monde",               7),
        ("la vie est belle",               13),
        ("le soleil brille sur la france",  3),
    ]
    for texte_clair, k_secret in cas_brute:
        # Chiffrer en conservant les espaces
        chiffre_espaces = " ".join(
            "".join(
                _algo._shift_char(c.upper(), k_secret) if c.isalpha() else c
                for c in mot
            )
            for mot in texte_clair.split()
        )
        resultat = _algo.brute_force_attack(chiffre_espaces)
        attendu  = _algo._letters_only(texte_clair)
        assert resultat == attendu, \
            f"Force brute échouée pour '{texte_clair}' k={k_secret}: {resultat}"
        print(f"  OK — '{texte_clair}' k={k_secret}")

    # ── Test 3 : analyse de fréquences (IC) ───────────────────────────
    print("\n[3] Analyse de fréquences — IC")

    texte_long = (
        "le chiffre de cesar est une methode de chiffrement par substitution "
        "mono alphabetique il decale chaque lettre de l alphabet d un nombre "
        "fixe de positions cette technique est tres ancienne et fut utilisee "
        "par jules cesar pour ses communications militaires secretes en france "
        "et dans les pays voisins il est facile de le casser par analyse de "
        "frequences car la distribution des lettres en francais est bien connue"
    ) * 3

    for k_test in [1, 3, 7, 11, 17, 23, 25]:
        chiffre_long = chiffrer_cesar(texte_long, k_test)
        k_deduit, ic = _algo.frequency_analysis(chiffre_long)
        assert k_deduit == k_test, \
            f"IC a déduit k={k_deduit} au lieu de k={k_test}"
        print(f"  OK — k={k_test:2d} | IC={ic:.4f} | déduit={k_deduit}")

    # ── Test 4 : modes 'brute' et 'ic' via encrypt/decrypt ────────────
    print("\n[4] Modes 'brute' et 'ic'")

    texte_mode = (
        "bonjour le monde il fait beau aujourd hui "
        "le ciel est bleu et le soleil brille"
    )
    k_mode = 5
    chiffre_mode_espaces = " ".join(
        "".join(
            _algo._shift_char(c.upper(), k_mode) if c.isalpha() else c
            for c in mot
        )
        for mot in texte_mode.split()
    )
    chiffre_mode_clean = chiffrer_cesar(texte_mode, k_mode)
    attendu_mode = _algo._letters_only(texte_mode)

    assert _algo.decrypt(chiffre_mode_espaces, "brute") == attendu_mode, \
        "Mode 'brute' échoué"
    assert _algo.decrypt(chiffre_mode_clean, "ic") == attendu_mode, \
        "Mode 'ic' échoué"
    print("  OK — mode 'brute' et mode 'ic'")

    print(f"\n{sep}")
    print("  Tous les tests passent.")
    print(sep)