"""
Cryptosystème RSA (Rivest, Shamir, Adleman - 1977)

"""


class RSACipher:
    """
    Implémentation du cryptosysteme RSA
    """

    def __init__(self):
        self.p = None
        self.q = None
        self.n = None
        self.phi = None
        self.e = None
        self.d = None

    # ------------------------------------------------------------------ #
    #  Fonctions mathematiques                                             #
    # ------------------------------------------------------------------ #

    def _is_prime(self, n):
        """
        Verifie si n est un nombre premier.
         p et q doivent obligatoirement etre premiers.
        """
        if n < 2:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False
        for i in range(3, int(n ** 0.5) + 1, 2):
            if n % i == 0:
                return False
        return True

    def _gcd(self, a, b):
        """
        Algorithme d'Euclide pour le PGCD.
        """
        while b != 0:
            a, b = b, a % b
        return a

    def _egcd(self, a, b):
        """
        Algorithme d'Euclide etendu 
        
        """
        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        return old_r, old_s, old_t   # (gcd, x, y)

    def _mod_inverse(self, a, m):
        """
        Calcul de l'inverse modulaire: a^(-1) mod m.
        """
        g, x, _ = self._egcd(a, m)
        if g != 1:
            raise Exception("Inverse modulaire n'existe pas (pgcd ≠ 1)")
        return x % m

    def _choose_e_auto(self, phi):
        """
        Choisit e automatiquement tel que 1 < e < phi et pgcd(e, phi) = 1.
        """
        common_e = [65537, 257, 17, 11, 7, 5]   # on retire 3 (faible)

        for e in common_e:
            if e < phi and self._gcd(e, phi) == 1:
                return e

        # Dernier recours : recherche séquentielle à partir de 5
        e = 5
        while e < phi:
            if self._gcd(e, phi) == 1:
                return e
            e += 2
        raise Exception("Impossible de trouver un e valide.")

    # ------------------------------------------------------------------ #
    #  Gestion des clés                                                    #
    # ------------------------------------------------------------------ #

    def generate_keys(self, p, q, e=None):
        """
        Génère les clés publique et privée à partir de p et q.

        Paramètres:
        - p, q : nombres premiers distincts
        - e    : (optionnel) exposant de chiffrement fourni par l'utilisateur.
                 Si None, e est calculé automatiquement.
        """
        #  Vérification primalité
        if not self._is_prime(p):
            raise Exception(f"p = {p} n'est pas un nombre premier!")
        if not self._is_prime(q):
            raise Exception(f"q = {q} n'est pas un nombre premier!")

        if p == q:
            raise Exception("p et q doivent être différents!")

        self.p = p
        self.q = q
        self.n = p * q
        self.phi = (p - 1) * (q - 1)

        #  Vérification que n > 25
        if self.n <= 25:
            raise Exception(
                f"n = {self.n} est trop petit. "
                f"Il faut n > 25 (valeur max d'un caractère = 25). "
                f"Choisissez des nombres premiers plus grands."
            )

        # Gestion de e
        if e is None:
            self.e = self._choose_e_auto(self.phi)
            print(f"\n(e calculé automatiquement: {self.e})")
        else:
            if e <= 1 or e >= self.phi:
                raise Exception(f"e doit être compris entre 1 et φ(n)={self.phi}")
            if self._gcd(e, self.phi) != 1:
                raise Exception(
                    f"e = {e} invalide : pgcd({e}, {self.phi}) = "
                    f"{self._gcd(e, self.phi)} ≠ 1"
                )
            self.e = e
            print(f"\n(e fourni par l'utilisateur: {self.e} — ✓ valide)")

        self.d = self._mod_inverse(self.e, self.phi)

        return (self.n, self.e), (self.n, self.d)

    def set_public_key(self, n, e):
        """Définit la clé publique pour chiffrer."""
        self.n = n
        self.e = e

    def set_private_key(self, n, d):
        """Définit la clé privée pour déchiffrer."""
        self.n = n
        self.d = d

    def get_public_key(self):
        """Retourne la clé publique (n, e)."""
        return (self.n, self.e)

    def get_private_key(self):
        """Retourne la clé privée (n, d)."""
        return (self.n, self.d)

    def display_keys(self):
        """Affiche les clés générées."""
        print(f"\n{'='*50}")
        print("CLÉS GÉNÉRÉES")
        print(f"{'='*50}")
        print(f"p       = {self.p}")
        print(f"q       = {self.q}")
        print(f"n       = {self.n}")
        print(f"φ(n)    = {self.phi}")
        print(f"e       = {self.e}")
        print(f"d       = {self.d}")
        print(f"\nClé publique  (n, e) = ({self.n}, {self.e})")
        print(f"Clé privée    (n, d) = ({self.n}, {self.d})")
        print(f"{'='*50}")

    # ------------------------------------------------------------------ #
    #  Encodage / décodage texte ↔ nombres                                #
    # ------------------------------------------------------------------ #

    def _text_to_numbers(self, text):
        """
        Convertit un texte en nombres (A=0, B=1, ..., Z=25).
        Les caractères non-alphabétiques sont encodés par leur valeur ASCII.
        """
        text = text.upper()
        numbers = []
        for char in text:
            if 'A' <= char <= 'Z':
                numbers.append(ord(char) - ord('A'))
            else:
                numbers.append(ord(char))
        return numbers

    def _numbers_to_text(self, numbers):
        """
        Convertit des nombres en texte (0=A, 1=B, ..., 25=Z).
        """
        text = ""
        for num in numbers:
            if 0 <= num <= 25:
                text += chr(num + ord('A'))
            else:
                text += chr(num)
        return text

    # ------------------------------------------------------------------ #
    #  Chiffrement / déchiffrement                                         #
    # ------------------------------------------------------------------ #

    def encrypt(self, plaintext):
        """
        Chiffre un message avec la clé publique.
        Formule: C = M^e mod n

        Vérifie que chaque valeur M < n avant de chiffrer.
        """
        if self.n is None or self.e is None:
            raise Exception("Clé publique non définie.")

        numbers = self._text_to_numbers(plaintext)

        # Vérification M < n pour chaque caractère
        for i, num in enumerate(numbers):
            if num >= self.n:
                char = plaintext.upper()[i]
                raise Exception(
                    f"Impossible de chiffrer '{char}' (valeur={num}) : "
                    f"n={self.n} doit être > {num}. "
                    f"Choisissez des nombres premiers plus grands."
                )

        cipher_numbers = []
        for num in numbers:
            encrypted = pow(num, self.e, self.n)  # pow intégré : rapide et sûr
            cipher_numbers.append(encrypted)

        return cipher_numbers

    def decrypt(self, cipher_numbers):
        """
        Déchiffre un message avec la clé privée.
        Formule: M = C^d mod n
        """
        if self.n is None or self.d is None:
            raise Exception("Clé privée non définie.")

        plain_numbers = []
        for num in cipher_numbers:
            decrypted = pow(num, self.d, self.n)
            plain_numbers.append(decrypted)

        return self._numbers_to_text(plain_numbers)


# ------------------------------------------------------------------ #
#  Interface CLI                                                       #
# ------------------------------------------------------------------ #

def main():
    cipher = RSACipher()
    public_key = None
    private_key = None

    while True:
        print("\n" + "=" * 50)
        print("CRYPTOSYSTÈME RSA")
        print("=" * 50)
        print("1. Générer des clés (entrer p et q)")
        print("2. Chiffrer un message")
        print("3. Déchiffrer un message")
        print("4. Afficher les clés")
        print("5. Quitter")
        print("-" * 50)

        choix = input("\nVotre choix (1-5): ").strip()

        if choix == '1':
            print("\n--- GÉNÉRATION DES CLÉS ---")
            try:
                p = int(input("p (nombre premier): "))
                q = int(input("q (nombre premier): "))

                e_input = input("e (laissez vide pour calcul automatique): ").strip()
                e = int(e_input) if e_input else None

                public_key, private_key = cipher.generate_keys(p, q, e)
                cipher.display_keys()

            except ValueError:
                print("Erreur: Veuillez entrer des nombres valides.")
            except Exception as ex:
                print(f"Erreur: {ex}")

        elif choix == '2':
            print("\n--- CHIFFREMENT ---")

            if public_key is None:
                print("Aucune clé générée. Utilisez l'option 1 d'abord.")
                continue

            cipher.set_public_key(public_key[0], public_key[1])
            plaintext = input("Message à chiffrer: ")

            try:
                ciphertext = cipher.encrypt(plaintext)
                print(f"\nClair  : {plaintext.upper()}")
                print(f"Chiffré: {ciphertext}")
            except Exception as ex:
                print(f"Erreur: {ex}")

        elif choix == '3':
            print("\n--- DÉCHIFFREMENT ---")

            if private_key is None:
                print("Aucune clé générée. Utilisez l'option 1 d'abord.")
                continue

            cipher.set_private_key(private_key[0], private_key[1])
            ciphertext_str = input("Message chiffré (nombres séparés par des virgules): ")

            try:
                ciphertext = [int(x.strip()) for x in ciphertext_str.split(',')]
                plaintext = cipher.decrypt(ciphertext)
                print(f"\nChiffré: {ciphertext}")
                print(f"Clair  : {plaintext}")
            except ValueError:
                print("Erreur: Format invalide. Entrez des nombres séparés par des virgules.")
            except Exception as ex:
                print(f"Erreur: {ex}")

        elif choix == '4':
            if public_key and private_key:
                print(f"\nClé publique : ({public_key[0]}, {public_key[1]})")
                print(f"Clé privée   : ({private_key[0]}, {private_key[1]})")
            else:
                print("\nAucune clé générée.")

        elif choix == '5':
            print("\nAu revoir!")
            break

        else:
            print("\nChoix invalide. Entrez un nombre entre 1 et 5.")


if __name__ == "__main__":
    main()     