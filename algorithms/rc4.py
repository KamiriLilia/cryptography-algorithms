"""
RC4 (Rivest Cipher 4) - TP2 Exercice 2.1
Implémentation complète avec :
  - KSA (Key Scheduling Algorithm) — permutation de S selon la clé
  - PRGA (Pseudo-Random Generation Algorithm)
  - Vulnérabilité WEP : corrélation entre keystream et clé (IV faibles)
  - Biais statistiques RC4 (facultatif)
"""

import random


class RC4Algorithm:

    def get_name(self):
        return "RC4 (Rivest Cipher 4)"

    def get_description(self):
        return (
            "Chiffrement par flot RC4.\n"
            "Phase 1 — KSA : initialise et permute le tableau S (256 octets)\n"
            "           selon la clé.\n"
            "Phase 2 — PRGA : génère le keystream par échanges dans S.\n"
            "Clé spéciale : 'wep' → démo vulnérabilité IV faibles WEP."
        )

    def get_key_info(self):
        return {
            "type": "symmetric",
            "placeholder": "Clé texte (longueur quelconque) | 'wep'"
        }

    # ------------------------------------------------------------------
    # 1. KSA — Key Scheduling Algorithm (Exercice 2.1 – point 1)
    # ------------------------------------------------------------------

    def ksa(self, key: str | bytes, log_step=None) -> list:
        """
        Initialise le tableau S = [0..255] puis le permute selon la clé.
        Retourne le tableau S après KSA.
        """
        if isinstance(key, str):
            key_bytes = [ord(c) for c in key]
        else:
            key_bytes = list(key)

        S = list(range(256))

        if log_step:
            log_step("🔑 KSA — Key Scheduling Algorithm")
            log_step(f"   Longueur de clé : {len(key_bytes)} octets")
            log_step(f"   Clé (hex) : {bytes(key_bytes).hex()}")
            log_step("   Permutation de S :")

        j = 0
        for i in range(256):
            j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
            S[i], S[j] = S[j], S[i]
            if log_step and i < 8:
                log_step(f"     i={i:3d}, j={j:3d} → S[{i}]↔S[{j}]")

        if log_step:
            log_step(f"   ... (256 itérations au total)")
            log_step(f"   S[0..7] après KSA : {S[:8]}")

        return S

    # ------------------------------------------------------------------
    # 2. PRGA — Pseudo-Random Generation Algorithm (Exercice 2.1 – point 1)
    # ------------------------------------------------------------------

    def prga(self, S: list, length: int, log_step=None) -> list:
        """
        Génère `length` octets de keystream à partir de S.
        S est modifié en place.
        """
        keystream = []
        i = j = 0

        if log_step:
            log_step("\n🎲 PRGA — Pseudo-Random Generation Algorithm")
            log_step(f"   Génération de {length} octets de keystream :")

        for k in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            ks_byte = S[(S[i] + S[j]) % 256]
            keystream.append(ks_byte)
            if log_step and k < 8:
                log_step(f"     k={k}: i={i}, j={j}, "
                         f"keystream[{k}]=0x{ks_byte:02X}")

        if log_step and length > 8:
            log_step(f"     ... ({length-8} octets supplémentaires)")

        return keystream

    # ------------------------------------------------------------------
    # 3. Chiffrement (Exercice 2.1 – point 1)
    # ------------------------------------------------------------------

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        if str(key).strip().lower() == "wep":
            return self._wep_vulnerability(text, log_step=log_step)

        if log_step:
            log_step("🔐 RC4 — CHIFFREMENT")
            log_step("=" * 42)
            log_step(f"   Clé : '{key}'")
            log_step(f"   Message : '{text}'")

        S = self.ksa(key, log_step)
        keystream = self.prga(S[:], len(text), log_step)

        if log_step:
            log_step("\n   XOR texte clair ⊕ keystream :")

        result_bytes = []
        for i, char in enumerate(text):
            pt = ord(char)
            ks = keystream[i]
            ct = pt ^ ks
            result_bytes.append(ct)
            if log_step and i < 8:
                log_step(f"     '{char}' (0x{pt:02X}) ⊕ 0x{ks:02X} "
                         f"= 0x{ct:02X}")

        result = bytes(result_bytes).hex()
        if log_step:
            log_step(f"\n✅ Chiffré (hex) : {result}")
        return result

    # ------------------------------------------------------------------
    # 4. Déchiffrement (Exercice 2.1 – point 1)
    # ------------------------------------------------------------------

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        if log_step:
            log_step("🔓 RC4 — DÉCHIFFREMENT")
            log_step("=" * 42)

        try:
            cipher_bytes = bytes.fromhex(text.strip())
        except ValueError:
            cipher_bytes = text.encode("utf-8")

        S = self.ksa(key, log_step)
        keystream = self.prga(S[:], len(cipher_bytes), log_step)

        result_bytes = [b ^ ks for b, ks in zip(cipher_bytes, keystream)]
        result = bytes(result_bytes).decode("utf-8", errors="replace")

        if log_step:
            log_step(f"\n✅ Texte déchiffré : {result}")
        return result

    # ------------------------------------------------------------------
    # 5. Vulnérabilité WEP — IV faibles (Exercice 2.1 – point 2)
    # ------------------------------------------------------------------

    def _wep_vulnerability(self, key: str, log_step=None) -> str:
        """
        Démontre la corrélation entre le 1er octet du keystream
        et la clé secrète pour des IV faibles (0x00, 0x01, ...).
        Dans WEP, la clé RC4 = IV (3 octets) || clé_secrète.
        """
        secret = [ord(c) for c in key] if key else [0x57, 0x45, 0x50]  # "WEP"

        if log_step:
            log_step("⚠️  VULNÉRABILITÉ WEP — IV FAIBLES")
            log_step("=" * 42)
            log_step(f"   Clé secrète : {bytes(secret).hex()}")
            log_step(f"   Clé RC4 WEP = IV (3 octets) || clé_secrète")
            log_step(f"\n   Pour des IV faibles (3, 255, x) :")
            log_step(f"   Le 1er octet du keystream est fortement corrélé")
            log_step(f"   au 1er octet de la clé secrète.\n")
            log_step(f"   {'IV (hex)':<12} {'1er octet KS':>13} {'Corr. clé[0]':>14}")
            log_step(f"   {'-'*12} {'-'*13} {'-'*14}")

        correlations = []
        for x in range(16):
            iv = [3, 255, x]
            rc4_key = bytes(iv + secret)
            S = self.ksa(rc4_key)
            ks = self.prga(S, 1)
            first_byte = ks[0]
            # Corrélation FMS : le 1er KS byte ≈ S[1] + secret[0]
            expected = (S[1] + secret[0]) % 256 if len(secret) > 0 else 0
            match = "← corrélé !" if first_byte == expected else ""
            correlations.append((iv, first_byte, match))
            if log_step:
                log_step(f"   {bytes(iv).hex():<12} {first_byte:>13} "
                         f"  {match}")

        hits = sum(1 for _, _, m in correlations if m)
        result = (f"IV faibles testés : 16 | "
                  f"Corrélations FMS trouvées : {hits}/16")

        if log_step:
            log_step(f"\n✅ {hits}/16 IV montrent la corrélation FMS.")
            log_step(
                "\n   Raison du bannissement de RC4 dans TLS 1.3 :")
            log_step(
                "   Biais statistiques (RC4 bias) : le 2e octet du keystream")
            log_step(
                "   tend vers 0 avec probabilité 2/256 au lieu de 1/256.")
            log_step(
                "   Accumulés sur 10 000+ paquets WEP, ces biais permettent")
            log_step(
                "   de retrouver la clé secrète (attaque FMS/PTW).")

        return result
        # ------------------------------------------------------------------
    # 6. Biais statistiques RC4 (Exercice 2.1 – point 3)
    # ------------------------------------------------------------------

    def rc4_bias_demo(self, samples=10000, log_step=None):
        """
        Génère plusieurs keystreams RC4 avec des clés aléatoires
        et observe le biais statistique du 2e octet du keystream.

        Théorie :
        Le 2e octet du keystream RC4 vaut 0 avec une probabilité
        proche de 2/256 au lieu de 1/256.
        """

        if log_step:
            log_step("📊 BIAIS STATISTIQUE RC4")
            log_step("=" * 42)
            log_step(f"   Nombre d'échantillons : {samples}")
            log_step("   Observation du 2e octet du keystream\n")

        # histogramme des valeurs 0..255
        histogram = [0] * 256

        for _ in range(samples):

            # clé aléatoire de 16 octets
            random_key = bytes(random.randint(0, 255) for _ in range(16))

            # génération RC4
            S = self.ksa(random_key)
            keystream = self.prga(S, 2)

            # 2e octet
            second_byte = keystream[1]

            histogram[second_byte] += 1

        # probabilité observée pour 0x00
        zero_count = histogram[0]
        observed_prob = zero_count / samples

        # probabilité théorique uniforme
        uniform_prob = 1 / 256

        if log_step:
            log_step("   Valeurs les plus fréquentes :")

            top_values = sorted(
                [(i, c) for i, c in enumerate(histogram)],
                key=lambda x: x[1],
                reverse=True
            )[:10]

            for value, count in top_values:
                prob = count / samples
                log_step(
                    f"     0x{value:02X} : "
                    f"{count:5d} occurrences "
                    f"({prob:.5f})"
                )

            log_step("\n📈 Observation du biais RC4 :")
            log_step(
                f"   P(2e octet = 0x00) observée : "
                f"{observed_prob:.5f}"
            )
            log_step(
                f"   Probabilité uniforme attendue : "
                f"{uniform_prob:.5f}"
            )

            if observed_prob > uniform_prob:
                log_step(
                    "\n⚠️  Le 2e octet est biaisé vers 0x00."
                )
                log_step(
                    "   Ce biais statistique a contribué "
                    "à l'abandon de RC4 dans TLS 1.3."
                )

        return {
            "samples": samples,
            "zero_count": zero_count,
            "observed_probability": observed_prob,
            "expected_probability": uniform_prob,
            "histogram": histogram
        }