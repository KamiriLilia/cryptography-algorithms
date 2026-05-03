import hashlib
from rsa import RSACipher

class RSASignature:

    def __init__(self):
        self.rsa = RSACipher()

    def sign(self, message, private_key):
        n, d = private_key

        h = int(hashlib.md5(message.encode()).hexdigest(), 16) % n
        return pow(h, d, n)

    def verify(self, message, signature, public_key):
        n, e = public_key

        h = int(hashlib.md5(message.encode()).hexdigest(), 16) % n
        h2 = pow(signature, e, n)

        return h == h2  


"""import hashlib
from rsa import RSACipher


class RSASignature:

    def __init__(self):
        self.rsa = RSACipher()

    # =========================================================
    # Signature RSA + MD5
    # =========================================================

    def sign(self, message, private_key):

        n, d = private_key

        # MD5 du message
        digest = hashlib.md5(message.encode()).hexdigest()

        # conversion hex -> int + réduction modulo n
        h = int(digest, 16) % n

        # signature RSA
        signature = pow(h, d, n)

        return signature

    # =========================================================
    # Vérification RSA + MD5
    # =========================================================

    def verify(self, message, signature, public_key):

        n, e = public_key

        # recalcul MD5
        digest = hashlib.md5(message.encode()).hexdigest()
        h = int(digest, 16) % n

        # vérification RSA
        h_verif = pow(signature, e, n)

        return h == h_verif
    
def main():

    rsa = RSACipher()
    signer = RSASignature()

    public_key = None
    private_key = None

    while True:

        print("\n" + "=" * 50)
        print("SIGNATURES NUMÉRIQUES RSA (MD5)")
        print("=" * 50)

        print("1. Générer les clés RSA")
        print("2. Signer un message")
        print("3. Vérifier une signature")
        print("4. Quitter")

        choix = input("\nChoix : ")

        # =====================================================
        # 1. Génération des clés
        # =====================================================
        if choix == '1':

            try:
                p = int(input("p premier : "))
                q = int(input("q premier : "))

                public_key, private_key = rsa.generate_keys(p, q)

                print("\nClé publique (n, e) :")
                print(public_key)

                print("\nClé privée (n, d) :")
                print(private_key)

            except Exception as ex:
                print("Erreur :", ex)

        # =====================================================
        # 2. Signature
        # =====================================================
        elif choix == '2':

            if private_key is None:
                print("⚠️ Générez les clés d'abord.")
                continue

            message = input("Message à signer : ")

            try:
                signature = signer.sign(message, private_key)

                print("\n--- RÉSULTAT ---")
                print("Message     :", message)
                print("Signature   :", signature)

            except Exception as ex:
                print("Erreur :", ex)

        # =====================================================
        # 3. Vérification
        # =====================================================
        elif choix == '3':

            if public_key is None:
                print("⚠️ Générez les clés d'abord.")
                continue

            message = input("Message original : ")

            try:
                signature = int(input("Signature : "))

                valid = signer.verify(message, signature, public_key)

                print("\n--- VÉRIFICATION ---")

                if valid:
                    print("✔ Signature VALIDE")
                else:
                    print("✘ Signature INVALIDE")

            except Exception as ex:
                print("Erreur :", ex)

        # =====================================================
        # 4. Quitter
        # =====================================================
        elif choix == '4':
            print("\nAu revoir 👋")
            break

        else:
            print("Choix invalide.")

if __name__ == "__main__":
    main()"""