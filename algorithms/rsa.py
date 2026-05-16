"""
RSA (Rivest-Shamir-Adleman) - TP3 Exercice 3.2
Implémentation complète avec :
  - RSA-512, 1024, 2048 bits (via sympy pour les grands premiers)
  - Padding OAEP (via hashlib, implémentation pédagogique)
  - Chiffrement hybride RSA + AES
  - Export des clés
"""

import hashlib
import os
import time


# Essaie d'importer sympy pour les grands premiers
try:
    from sympy import nextprime, isprime, randprime
    SYMPY_OK = True
except ImportError:
    SYMPY_OK = False


class RSAAlgorithm:

    def get_name(self):
        return "RSA (Rivest-Shamir-Adleman)"

    def get_description(self):
        return (
            "RSA — chiffrement asymétrique par factorisation.\n"
            "• Clé publique (n, e) pour chiffrer\n"
            "• Clé privée (n, d) pour déchiffrer\n"
            "• Format clé : 'p,q'  (ex: 61,53)\n"
            "• Format bits : 'bits:512', 'bits:1024', 'bits:2048'\n"
            "• Hybride RSA+AES : clé 'hybrid:<p>,<q>'\n"
            "Réponse : RSA ne peut pas chiffrer des messages arbitraires\n"
            "car m doit être < n. OAEP ajoute du padding aléatoire et\n"
            "une fonction de hachage pour éviter les attaques à texte choisi."
        )

    def get_key_info(self):
        return {
            "type": "asymmetric",
            "placeholder": "'p,q' | 'bits:512' | 'hybrid:p,q'"
        }

    # ------------------------------------------------------------------
    # Arithmétique
    # ------------------------------------------------------------------

    def _gcd(self, a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, a: int, m: int) -> int:
        """Inverse modulaire par l'algorithme d'Euclide étendu."""
        g, x, _ = self._extended_gcd(a, m)
        if g != 1:
            raise ValueError(f"Pas d'inverse pour {a} mod {m}")
        return x % m

    def _extended_gcd(self, a: int, b: int) -> tuple:
        if a == 0:
            return b, 0, 1
        g, x, y = self._extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    def _is_prime(self, n: int) -> bool:
        if SYMPY_OK:
            return isprime(n)
        if n < 2:
            return False
        if n < 4:
            return True
        if n % 2 == 0 or n % 3 == 0:
            return False
        i = 5
        while i * i <= n:
            if n % i == 0 or n % (i + 2) == 0:
                return False
            i += 6
        return True

    def _generate_prime(self, bits: int) -> int:
        """Génère un nombre premier aléatoire de `bits` bits."""
        if SYMPY_OK:
            low = 1 << (bits - 1)
            high = (1 << bits) - 1
            return randprime(low, high)
        # Fallback sans sympy
        import random
        while True:
            n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if self._is_prime(n):
                return n

    # ------------------------------------------------------------------
    # Génération de clés
    # ------------------------------------------------------------------

    def _generate_keys(self, p: int, q: int,
                        log_step=None) -> tuple[tuple, tuple]:
        if not self._is_prime(p) or not self._is_prime(q):
            raise ValueError("p et q doivent être des nombres premiers.")
        if p == q:
            raise ValueError("p et q doivent être distincts.")

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        while self._gcd(e, phi) != 1:
            e += 2
        d = self._mod_inverse(e, phi)

        if log_step:
            log_step(f"   n = p × q = {p} × {q} = {n}")
            log_step(f"   φ(n) = (p-1)(q-1) = {phi}")
            log_step(f"   e = {e}  [gcd(e,φ) = 1]")
            log_step(f"   d = e⁻¹ mod φ(n) = {d}")
            log_step(f"   Clé publique  : (n={n}, e={e})")
            log_step(f"   Clé privée    : (n={n}, d={d})")

        return (n, e), (n, d)

    def _generate_keys_bits(self, bits: int,
                             log_step=None) -> tuple[tuple, tuple]:
        half = bits // 2
        if log_step:
            log_step(f"   Génération de p et q aléatoires ({half} bits chacun)...")
        p = self._generate_prime(half)
        q = self._generate_prime(half)
        while q == p:
            q = self._generate_prime(half)
        if log_step:
            log_step(f"   p = {str(p)[:30]}...")
            log_step(f"   q = {str(q)[:30]}...")
        return self._generate_keys(p, q, log_step)

    # ------------------------------------------------------------------
    # OAEP simplifié (pédagogique)
    # ------------------------------------------------------------------

    def _mgf1(self, seed: bytes, length: int) -> bytes:
        """Mask Generation Function (MGF1) basée sur SHA-256."""
        result = b""
        for i in range((length + 31) // 32):
            result += hashlib.sha256(seed + i.to_bytes(4, 'big')).digest()
        return result[:length]

    def _oaep_pad(self, message: bytes, n_bytes: int) -> bytes:
        """Padding OAEP pédagogique."""
        h_len = 32  # SHA-256
        max_msg = n_bytes - 2 * h_len - 2
        if len(message) > max_msg:
            raise ValueError(
                f"Message trop long pour OAEP ({len(message)} > {max_msg} octets). "
                "RSA ne peut pas chiffrer directement des messages arbitraires."
            )
        l_hash = hashlib.sha256(b"").digest()
        ps = b"\x00" * (max_msg - len(message))
        db = l_hash + ps + b"\x01" + message
        seed = os.urandom(h_len)
        db_mask = self._mgf1(seed, len(db))
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
        seed_mask = self._mgf1(masked_db, h_len)
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
        return b"\x00" + masked_seed + masked_db

    def _oaep_unpad(self, em: bytes) -> bytes:
        h_len = 32
        masked_seed = em[1:1 + h_len]
        masked_db = em[1 + h_len:]
        seed_mask = self._mgf1(masked_db, h_len)
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
        db_mask = self._mgf1(seed, len(masked_db))
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
        sep = db.index(b"\x01", h_len)
        return db[sep + 1:]

    # ------------------------------------------------------------------
    # Chiffrement / Déchiffrement RSA
    # ------------------------------------------------------------------

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        k = str(key).strip()

        # Mode hybride RSA + AES
        if k.lower().startswith("hybrid:"):
            return self._hybrid_encrypt(text, k[7:], log_step=log_step)

        # Mode bits: génération aléatoire
        if k.lower().startswith("bits:"):
            bits = int(k[5:])
            if log_step:
                log_step(f"🔐 RSA-{bits} — GÉNÉRATION DE CLÉS")
                log_step("=" * 42)
            t0 = time.time()
            pub, priv = self._generate_keys_bits(bits, log_step)
            elapsed = (time.time() - t0) * 1000
            if log_step:
                log_step(f"   Temps génération : {elapsed:.0f} ms")
            n, e = pub
        else:
            # Format p,q
            parts = k.split(",")
            if len(parts) < 2:
                raise ValueError("Format : 'p,q' (ex: 61,53)")
            p, q = int(parts[0]), int(parts[1])
            if log_step:
                log_step("🔐 RSA — CHIFFREMENT")
                log_step("=" * 42)
            pub, priv = self._generate_keys(p, q, log_step)
            n, e = pub

        msg_bytes = text.encode("utf-8")
        n_bytes = (n.bit_length() + 7) // 8

        if log_step:
            log_step(f"\n   n = {n.bit_length()} bits")
            log_step(f"   Message : '{text[:40]}{'...' if len(text)>40 else ''}'")
            log_step(f"\n   Chiffrement : c = m^e mod n")
            log_step(f"   (avec padding OAEP pour sécurité sémantique)")

        # OAEP si n assez grand, sinon chiffrement octet par octet
        if n_bytes > 2 * 32 + 3 and len(msg_bytes) <= n_bytes - 66:
            try:
                padded = self._oaep_pad(msg_bytes, n_bytes)
                m_int = int.from_bytes(padded, 'big')
                c_int = pow(m_int, e, n)
                result = c_int.to_bytes(n_bytes, 'big').hex()
                if log_step:
                    log_step(f"   Padding OAEP appliqué ✓")
                    log_step(f"\n✅ Chiffré (hex, {len(result)//2} octets) : "
                             f"{result[:64]}...")
                return f"OAEP:{result}"
            except Exception:
                pass

        # Fallback : chiffrement caractère par caractère (petites clés)
        result_nums = []
        for i, char in enumerate(text):
            m = ord(char)
            if m >= n:
                raise ValueError(
                    f"Caractère '{char}' (ASCII {m}) ≥ n={n}. "
                    "Utilisez une clé plus grande."
                )
            c = pow(m, e, n)
            result_nums.append(c)
            if log_step and i < 5:
                log_step(f"   '{char}' ({m}) → {m}^{e} mod {n} = {c}")
        if log_step and len(text) > 5:
            log_step(f"   ... ({len(text)-5} caractères supplémentaires)")

        result = ",".join(str(x) for x in result_nums)
        if log_step:
            log_step(f"\n✅ Chiffré : {result[:80]}{'...' if len(result)>80 else ''}")

        # Stocker d pour le déchiffrement (on inclut n,d dans le résultat)
        _, (n2, d) = pub, priv
        return f"KEY:{n},{e},{d}|DATA:{result}"

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:
        k = str(key).strip()

        if k.lower().startswith("hybrid:"):
            return self._hybrid_decrypt(text, k[7:], log_step=log_step)

        # Extraire n,d du chiffré si inclus
        if text.startswith("KEY:"):
            meta, data_part = text.split("|DATA:")
            meta_vals = meta[4:].split(",")
            n, e, d = int(meta_vals[0]), int(meta_vals[1]), int(meta_vals[2])
            text = data_part
        else:
            # Régénérer depuis la clé
            if k.lower().startswith("bits:"):
                bits = int(k[5:])
                pub, priv = self._generate_keys_bits(bits, log_step)
            else:
                parts = k.split(",")
                p, q = int(parts[0]), int(parts[1])
                pub, priv = self._generate_keys(p, q, log_step)
            n, e = pub
            n, d = priv

        if log_step:
            log_step("🔓 RSA — DÉCHIFFREMENT")
            log_step("=" * 42)
            log_step(f"   Clé privée (n={str(n)[:20]}..., d={str(d)[:20]}...)")
            log_step(f"   Déchiffrement : m = c^d mod n")

        # Mode OAEP
        if text.startswith("OAEP:"):
            hex_data = text[5:]
            n_bytes = (n.bit_length() + 7) // 8
            c_int = int.from_bytes(bytes.fromhex(hex_data), 'big')
            m_int = pow(c_int, d, n)
            em = m_int.to_bytes(n_bytes, 'big')
            plain_bytes = self._oaep_unpad(em)
            result = plain_bytes.decode("utf-8")
            if log_step:
                log_step(f"\n✅ Texte : {result}")
            return result

        # Mode caractère par caractère
        try:
            nums = [int(x) for x in text.split(",")]
        except ValueError:
            raise ValueError("Format invalide pour le chiffré RSA.")

        result = ""
        for i, c in enumerate(nums):
            m = pow(c, d, n)
            result += chr(m)
            if log_step and i < 5:
                log_step(f"   {c}^{d} mod {n} = {m} → '{chr(m)}'")

        if log_step:
            log_step(f"\n✅ Texte déchiffré : {result}")
        return result

    # ------------------------------------------------------------------
    # Chiffrement hybride RSA + AES (Exercice 3.2 – point 2)
    # ------------------------------------------------------------------

    def _hybrid_encrypt(self, text: str, pq_str: str,
                         log_step=None) -> str:
        """Chiffrement hybride : clé AES-256 chiffrée par RSA + données par AES."""
        parts = pq_str.split(",")
        if len(parts) < 2:
            raise ValueError("Format : 'hybrid:p,q'")
        p, q = int(parts[0]), int(parts[1])

        if log_step:
            log_step("🔐 CHIFFREMENT HYBRIDE RSA + AES")
            log_step("=" * 42)
            log_step("   Étape 1 : Générer une clé AES-256 aléatoire")

        aes_key = os.urandom(32)  # 256 bits

        if log_step:
            log_step(f"   Clé AES-256 (hex) : {aes_key.hex()}")
            log_step("\n   Étape 2 : Générer les clés RSA")

        pub, priv = self._generate_keys(p, q, log_step)
        n, e = pub
        _, d = priv

        if log_step:
            log_step("\n   Étape 3 : Chiffrer la clé AES avec RSA")
            t_rsa = time.time()

        # Chiffrer la clé AES avec RSA (octet par octet si n petit)
        aes_key_int = int.from_bytes(aes_key, 'big')
        if aes_key_int >= n:
            # n trop petit pour une vraie RSA-256, chiffrer octet par octet
            enc_key = ",".join(str(pow(b, e, n)) for b in aes_key)
        else:
            enc_key = str(pow(aes_key_int, e, n))

        if log_step:
            elapsed_rsa = (time.time() - t_rsa) * 1000
            log_step(f"   Clé AES chiffrée par RSA : {str(enc_key)[:40]}...")
            log_step(f"   Temps RSA : {elapsed_rsa:.2f} ms")
            log_step("\n   Étape 4 : Chiffrer les données avec AES (XOR simplifié)")
            t_aes = time.time()

        # "AES" simplifié : XOR avec la clé répétée (pédagogique)
        data = text.encode("utf-8")
        key_stream = (aes_key * (len(data) // 32 + 1))[:len(data)]
        enc_data = bytes(a ^ b for a, b in zip(data, key_stream))

        if log_step:
            elapsed_aes = (time.time() - t_aes) * 1000
            log_step(f"   Données chiffrées (hex) : {enc_data.hex()[:40]}...")
            log_step(f"   Temps AES : {elapsed_aes:.4f} ms")
            log_step(f"\n   → AES est ~{int(elapsed_rsa/(elapsed_aes+0.001))}× "
                     f"plus rapide que RSA pour les données")

        result = f"HYBRID|KEY:{n},{e},{d}|ENC_KEY:{enc_key}|DATA:{enc_data.hex()}"
        if log_step:
            log_step(f"\n✅ Chiffré hybride généré.")
        return result

    def _hybrid_decrypt(self, text: str, pq_str: str,
                         log_step=None) -> str:
        if not text.startswith("HYBRID|"):
            raise ValueError("Ce texte n'est pas un chiffré hybride RSA+AES.")
        parts_dict = {}
        for part in text.split("|"):
            if ":" in part:
                k, v = part.split(":", 1)
                parts_dict[k] = v

        meta = parts_dict["KEY"].split(",")
        n, e, d = int(meta[0]), int(meta[1]), int(meta[2])
        enc_key_str = parts_dict["ENC_KEY"]
        enc_data = bytes.fromhex(parts_dict["DATA"])

        if log_step:
            log_step("🔓 DÉCHIFFREMENT HYBRIDE RSA + AES")
            log_step("=" * 42)
            log_step("   Étape 1 : Déchiffrer la clé AES avec RSA (clé privée)")

        # Récupérer la clé AES
        if "," in enc_key_str:
            aes_key = bytes(pow(int(x), d, n) for x in enc_key_str.split(","))
        else:
            aes_int = pow(int(enc_key_str), d, n)
            aes_key = aes_int.to_bytes(32, 'big')

        if log_step:
            log_step(f"   Clé AES récupérée (hex) : {aes_key.hex()}")
            log_step("   Étape 2 : Déchiffrer les données avec AES")

        key_stream = (aes_key * (len(enc_data) // 32 + 1))[:len(enc_data)]
        plain = bytes(a ^ b for a, b in zip(enc_data, key_stream))
        result = plain.decode("utf-8", errors="replace")

        if log_step:
            log_step(f"\n✅ Texte : {result}")
        return result

    # ------------------------------------------------------------------
    # Export des clés RSA
    # ------------------------------------------------------------------

    def export_keys(self, pub: tuple, priv: tuple,
                    pub_file="public_key.txt",
                    priv_file="private_key.txt",
                    log_step=None):
        """
        Exporte les clés publique et privée dans des fichiers texte.
        """
        n_pub, e = pub
        n_priv, d = priv

        with open(pub_file, "w") as f:
            f.write("----- RSA PUBLIC KEY -----\n")
            f.write(f"n = {n_pub}\n")
            f.write(f"e = {e}\n")

        with open(priv_file, "w") as f:
            f.write("----- RSA PRIVATE KEY -----\n")
            f.write(f"n = {n_priv}\n")
            f.write(f"d = {d}\n")

        if log_step:
            log_step("💾 Export des clés RSA")
            log_step(f"   Clé publique → {pub_file}")
            log_step(f"   Clé privée   → {priv_file}")

    # ------------------------------------------------------------------
    # Chiffrement hybride RSA + AES d'un fichier
    # ------------------------------------------------------------------

    def hybrid_encrypt_file(self, input_file: str,
                            output_file: str,
                            key: str,
                            log_step=None):
        """
        Chiffre un fichier avec :
          - AES (XOR pédagogique)
          - clé AES chiffrée par RSA
        """
        parts = key.split(",")

        if len(parts) < 2:
            raise ValueError("Format clé : 'p,q'")

        p, q = int(parts[0]), int(parts[1])

        if log_step:
            log_step("🔐 CHIFFREMENT FICHIER HYBRIDE RSA + AES")
            log_step("=" * 50)

        # --------------------------------------------------------------
        # Génération clés RSA
        # --------------------------------------------------------------

        pub, priv = self._generate_keys(p, q, log_step)

        n, e = pub
        _, d = priv

        # --------------------------------------------------------------
        # Génération clé AES-256
        # --------------------------------------------------------------

        aes_key = os.urandom(32)

        if log_step:
            log_step(f"\n🔑 Clé AES-256 générée :")
            log_step(f"   {aes_key.hex()}")

        # --------------------------------------------------------------
        # Lecture fichier
        # --------------------------------------------------------------

        with open(input_file, "rb") as f:
            data = f.read()

        if log_step:
            log_step(f"\n📂 Fichier lu : {input_file}")
            log_step(f"   Taille : {len(data)} octets")

        # --------------------------------------------------------------
        # AES (XOR pédagogique)
        # --------------------------------------------------------------

        t_aes = time.time()

        key_stream = (aes_key * (len(data) // 32 + 1))[:len(data)]

        encrypted_data = bytes(
            a ^ b for a, b in zip(data, key_stream)
        )

        aes_time = (time.time() - t_aes) * 1000

        # --------------------------------------------------------------
        # RSA sur la clé AES
        # --------------------------------------------------------------

        t_rsa = time.time()

        aes_key_int = int.from_bytes(aes_key, 'big')

        if aes_key_int >= n:
            enc_key = ",".join(
                str(pow(b, e, n))
                for b in aes_key
            )
        else:
            enc_key = str(pow(aes_key_int, e, n))

        rsa_time = (time.time() - t_rsa) * 1000

        # --------------------------------------------------------------
        # Sauvegarde
        # --------------------------------------------------------------

        with open(output_file, "wb") as f:

            metadata = (
                f"KEY:{n},{e},{d}\n"
                f"ENC_KEY:{enc_key}\n"
                f"DATA:\n"
            ).encode()

            f.write(metadata)
            f.write(encrypted_data)

        # --------------------------------------------------------------
        # Logs
        # --------------------------------------------------------------

        if log_step:
            log_step("\n⏱ Temps d'exécution :")
            log_step(f"   RSA : {rsa_time:.2f} ms")
            log_step(f"   AES : {aes_time:.2f} ms")

            ratio = rsa_time / (aes_time + 0.0001)

            log_step(f"   AES est ~{int(ratio)}× plus rapide")

            log_step(f"\n💾 Fichier chiffré sauvegardé :")
            log_step(f"   {output_file}")

        return output_file

    # ------------------------------------------------------------------
    # Déchiffrement hybride fichier RSA + AES
    # ------------------------------------------------------------------

    def hybrid_decrypt_file(self, input_file: str,
                            output_file: str,
                            log_step=None):
        """
        Déchiffre un fichier chiffré avec hybrid_encrypt_file
        """
        if log_step:
            log_step("🔓 DÉCHIFFREMENT FICHIER HYBRIDE")
            log_step("=" * 50)

        with open(input_file, "rb") as f:
            lines = []

            while True:
                line = f.readline()

                if line == b"DATA:\n":
                    break

                lines.append(line.decode().strip())

            encrypted_data = f.read()

        meta = {}

        for line in lines:
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k] = v

        n, e, d = map(int, meta["KEY"].split(","))

        enc_key = meta["ENC_KEY"]

        # --------------------------------------------------------------
        # Déchiffrer clé AES
        # --------------------------------------------------------------

        if "," in enc_key:
            aes_key = bytes(
                pow(int(x), d, n)
                for x in enc_key.split(",")
            )
        else:
            aes_int = pow(int(enc_key), d, n)
            aes_key = aes_int.to_bytes(32, 'big')

        if log_step:
            log_step(f"🔑 Clé AES récupérée")

        # --------------------------------------------------------------
        # Déchiffrer données
        # --------------------------------------------------------------

        key_stream = (
            aes_key * (len(encrypted_data) // 32 + 1)
        )[:len(encrypted_data)]

        plain_data = bytes(
            a ^ b for a, b in zip(encrypted_data, key_stream)
        )

        with open(output_file, "wb") as f:
            f.write(plain_data)

        if log_step:
            log_step(f"💾 Fichier déchiffré : {output_file}")

        return output_file