"""
One-Time Pad (Vernam) - TP1 Exercice 1.4
Implémentation complète avec :
  - Génération de clé aléatoire
  - Chiffrement / Déchiffrement XOR octet à octet
  - Démonstration de la vulnérabilité de réutilisation de clé
  - Attaque "crib dragging" (statistiques de langue)
"""

import os
import string


# Mots anglais/français courts courants pour le crib dragging
COMMON_WORDS = [
    "the", "and", "for", "are", "but", "not", "you", "all",
    "can", "has", "her", "was", "one", "our", "out", "who",
    "get", "use", "man", "new", "now", "way", "may", "say",
    "le", "la", "les", "de", "du", "et", "en", "un", "une",
    "est", "que", "qui", "pas", "sur", "par", "avec", "dans",
]

PRINTABLE = set(string.printable)


class OTPAlgorithm:

    def __init__(self):
        self._last_key: bytes | None = None  # stocke la dernière clé générée

    def get_name(self):
        return "One-Time Pad (Vernam)"

    def get_description(self):
        return (
            "One-Time Pad — sécurité parfaite théorique.\n"
            "Chiffrement : Ci = Pi XOR Ki  (octet à octet)\n"
            "Déchiffrement : Pi = Ci XOR Ki\n"
            "Clés spéciales :\n"
            "  'genkey'        → générer et afficher une clé\n"
            "  'reuse:<msg2>'  → démo vulnérabilité réutilisation\n"
            "  'crib:<msg2>'   → attaque crib dragging\n"
            "  Sinon : clé hexadécimale (ex: 4f2a...)"
        )

    def get_key_info(self):
        return {
            "type": "symmetric",
            "placeholder": "Clé hex (même longueur que le texte) | 'genkey'"
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _text_to_bytes(self, text: str) -> bytes:
        return text.encode("utf-8")

    def _bytes_to_hex(self, b: bytes) -> str:
        return b.hex()

    def _hex_to_bytes(self, h: str) -> bytes:
        return bytes.fromhex(h.strip())

    # ------------------------------------------------------------------
    # 1. Génération de clé (Exercice 1.4 – point 1)
    # ------------------------------------------------------------------

    def _generate_key(self, length: int) -> bytes:
        return os.urandom(length)

    # ------------------------------------------------------------------
    # 2. Chiffrement (Exercice 1.4 – point 1)
    # ------------------------------------------------------------------

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        k = str(key).strip().lower()

        # Mode génération de clé
        if k == "genkey":
            msg_bytes = self._text_to_bytes(text)
            otp_key = self._generate_key(len(msg_bytes))
            self._last_key = otp_key
            key_hex = self._bytes_to_hex(otp_key)
            cipher = bytes(a ^ b for a, b in zip(msg_bytes, otp_key))
            cipher_hex = self._bytes_to_hex(cipher)
            if log_step:
                log_step("🔑 ONE-TIME PAD — GÉNÉRATION DE CLÉ")
                log_step("=" * 42)
                log_step(f"   Texte ({len(msg_bytes)} octets) : {text}")
                log_step(f"   Clé OTP générée (hex) : {key_hex}")
                log_step(f"\n   Chiffrement XOR octet à octet :")
                for i in range(min(8, len(msg_bytes))):
                    log_step(f"     P[{i}]=0x{msg_bytes[i]:02X} "
                             f"XOR K[{i}]=0x{otp_key[i]:02X} "
                             f"= C[{i}]=0x{cipher[i]:02X}")
                if len(msg_bytes) > 8:
                    log_step(f"     ... ({len(msg_bytes)-8} octets supplémentaires)")
                log_step(f"\n   ⚠️  Conservez la clé pour déchiffrer !")
                log_step(f"   CLE: {key_hex}")
                log_step(f"\n✅ Chiffré (hex) : {cipher_hex}")
            return f"CLE:{key_hex}|CIPHER:{cipher_hex}"

        # Mode réutilisation de clé (vulnérabilité)
        if k.startswith("reuse:"):
            return self._reuse_demo(text, k[6:], log_step=log_step)

        # Mode crib dragging
        if k.startswith("crib:"):
            return self._crib_dragging(text, k[5:], log_step=log_step)

        # Chiffrement normal avec clé hex fournie
        msg_bytes = self._text_to_bytes(text)
        try:
            key_bytes = self._hex_to_bytes(key)
        except ValueError:
            # Clé fournie comme texte brut
            key_bytes = (key.encode() * (len(msg_bytes) // len(key) + 1))[:len(msg_bytes)]

        if len(key_bytes) < len(msg_bytes):
            raise ValueError(
                f"La clé OTP doit être au moins aussi longue que le message "
                f"({len(msg_bytes)} octets). "
                f"Clé fournie : {len(key_bytes)} octets."
            )
        key_bytes = key_bytes[:len(msg_bytes)]

        if log_step:
            log_step("🔐 ONE-TIME PAD — CHIFFREMENT")
            log_step("=" * 42)
            log_step(f"   Message   : {text}")
            log_step(f"   Clé (hex) : {self._bytes_to_hex(key_bytes)}")
            log_step(f"\n   XOR octet à octet :")
            for i in range(min(8, len(msg_bytes))):
                log_step(f"     P[{i}]=0x{msg_bytes[i]:02X} "
                         f"XOR K[{i}]=0x{key_bytes[i]:02X} "
                         f"= C[{i}]=0x{(msg_bytes[i] ^ key_bytes[i]):02X}")

        cipher = bytes(a ^ b for a, b in zip(msg_bytes, key_bytes))
        result = self._bytes_to_hex(cipher)

        if log_step:
            log_step(f"\n✅ Chiffré (hex) : {result}")
            # Vérification
            decrypted = bytes(a ^ b for a, b in zip(cipher, key_bytes))
            log_step(f"   Vérification D(E(M)) = M : "
                     f"{'✓' if decrypted == msg_bytes else '✗'}")
        return result

    # ------------------------------------------------------------------
    # 3. Déchiffrement (Exercice 1.4 – point 1)
    # ------------------------------------------------------------------

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        # Gérer le format CLE:...|CIPHER:...
        if "|CIPHER:" in text:
            parts = text.split("|CIPHER:")
            if len(parts) == 2:
                text = parts[1]

        try:
            cipher_bytes = self._hex_to_bytes(text)
        except ValueError:
            raise ValueError("Le chiffré doit être en hexadécimal.")

        # Clé au format CLE:hex
        if str(key).strip().startswith("CLE:"):
            key = key.strip()[4:]
        try:
            key_bytes = self._hex_to_bytes(key)
        except ValueError:
            key_bytes = (key.encode() * (len(cipher_bytes) // len(key) + 1))[:len(cipher_bytes)]

        if len(key_bytes) < len(cipher_bytes):
            raise ValueError("Clé trop courte pour ce chiffré.")
        key_bytes = key_bytes[:len(cipher_bytes)]

        if log_step:
            log_step("🔓 ONE-TIME PAD — DÉCHIFFREMENT")
            log_step("=" * 42)
            log_step(f"   XOR octet à octet :")
            for i in range(min(8, len(cipher_bytes))):
                log_step(f"     C[{i}]=0x{cipher_bytes[i]:02X} "
                         f"XOR K[{i}]=0x{key_bytes[i]:02X} "
                         f"= P[{i}]=0x{(cipher_bytes[i] ^ key_bytes[i]):02X}")

        plain = bytes(a ^ b for a, b in zip(cipher_bytes, key_bytes))
        try:
            result = plain.decode("utf-8")
        except UnicodeDecodeError:
            result = plain.decode("latin-1")

        if log_step:
            log_step(f"\n✅ Texte déchiffré : {result}")
        return result

    # ------------------------------------------------------------------
    # 4. Vulnérabilité de réutilisation de clé (Exercice 1.4 – point 2)
    # ------------------------------------------------------------------

    def _reuse_demo(self, msg1: str, msg2: str, log_step=None) -> str:
        """
        Chiffre M1 et M2 avec la MÊME clé K aléatoire.
        Calcule C1 XOR C2 = M1 XOR M2 et montre la fuite d'information.
        """
        m1 = self._text_to_bytes(msg1)
        m2 = self._text_to_bytes(msg2)
        min_len = min(len(m1), len(m2))
        m1, m2 = m1[:min_len], m2[:min_len]

        K = self._generate_key(min_len)
        C1 = bytes(a ^ b for a, b in zip(m1, K))
        C2 = bytes(a ^ b for a, b in zip(m2, K))
        C1_xor_C2 = bytes(a ^ b for a, b in zip(C1, C2))

        if log_step:
            log_step("⚠️  VULNÉRABILITÉ — RÉUTILISATION DE CLÉ OTP")
            log_step("=" * 42)
            log_step(f"   M1 : {msg1[:min_len]}")
            log_step(f"   M2 : {msg2[:min_len]}")
            log_step(f"   Clé K (hex) : {K.hex()} (MÊME clé !)")
            log_step(f"\n   C1 = M1 XOR K = {C1.hex()}")
            log_step(f"   C2 = M2 XOR K = {C2.hex()}")
            log_step(f"\n   C1 XOR C2 = {C1_xor_C2.hex()}")
            log_step(f"            = M1 XOR M2  (la clé K disparaît !)")
            log_step(f"\n   Un attaquant connaît M1 XOR M2 sans connaître K.")
            log_step(f"   Il peut en déduire M2 s'il connaît M1 (et vice-versa).")
            m1_xor_m2 = bytes(a ^ b for a, b in zip(m1, m2))
            log_step(f"\n   Vérification M1 XOR M2 = {m1_xor_m2.hex()}")
            log_step(f"   C1 XOR C2 == M1 XOR M2 : "
                     f"{'✓' if C1_xor_C2 == m1_xor_m2 else '✗'}")

        return (f"C1={C1.hex()} | C2={C2.hex()} | "
                f"C1^C2=M1^M2={C1_xor_C2.hex()}")

    # ------------------------------------------------------------------
    # 5. Attaque "crib dragging" (Exercice 1.4 – point 3)
    # ------------------------------------------------------------------

    def _crib_dragging(self, msg1: str, msg2: str, log_step=None) -> str:
        """
        À partir de C1 XOR C2 = M1 XOR M2, essaie de récupérer
        partiellement M1 et M2 en testant des mots courants (cribs).
        """
        m1 = self._text_to_bytes(msg1)
        m2 = self._text_to_bytes(msg2)
        min_len = min(len(m1), len(m2))
        m1b, m2b = m1[:min_len], m2[:min_len]

        K = self._generate_key(min_len)
        C1 = bytes(a ^ b for a, b in zip(m1b, K))
        C2 = bytes(a ^ b for a, b in zip(m2b, K))
        keystream_xor = bytes(a ^ b for a, b in zip(C1, C2))

        if log_step:
            log_step("🕵️  ATTAQUE CRIB DRAGGING — OTP")
            log_step("=" * 42)
            log_step(f"   C1 XOR C2 (hex) : {keystream_xor.hex()}")
            log_step(f"\n   Test de mots courants (cribs) :")

        hits = []
        for crib in COMMON_WORDS:
            crib_b = crib.upper().encode()
            for pos in range(min_len - len(crib_b) + 1):
                segment = keystream_xor[pos:pos + len(crib_b)]
                candidate = bytes(a ^ b for a, b in zip(segment, crib_b))
                if all(chr(c) in PRINTABLE and chr(c).isalpha()
                       for c in candidate):
                    hits.append((pos, crib, candidate.decode("latin-1")))

        if log_step:
            if hits:
                for pos, crib, candidate in hits[:10]:
                    log_step(f"     pos={pos:3d} | crib='{crib}' → "
                             f"M?='{candidate}'")
                log_step(f"\n   {len(hits)} candidats trouvés.")
            else:
                log_step("   Aucun crib concluant (texte trop court ?).")

            log_step(f"\n   Réponse à la question :")
            log_step("   Obstacles concrets de l'OTP :")
            log_step("   1. Distribution sécurisée de la clé (autant longue")
            log_step("      que le message) — problème du canal sécurisé.")
            log_step("   2. Clé à usage unique strict : toute réutilisation")
            log_step("      brise la sécurité parfaite (crib dragging).")
            log_step("   3. Gestion et stockage de grandes quantités de clés.")
            log_step("   4. Impossibilité de générer de vrais bits aléatoires")
            log_step("      en grande quantité (RNG matériel limité).")

        summary = f"{len(hits)} candidats par crib dragging"
        if hits:
            summary += " : " + ", ".join(
                f"pos{h[0]}→'{h[2]}'" for h in hits[:3]
            )
        return summary