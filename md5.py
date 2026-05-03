import hashlib


# =========================================================
# Fonction MD5
# =========================================================
def md5_hash(message):

    # Création de l'objet MD5
    md5 = hashlib.md5()

    # Encodage du message en bytes
    md5.update(message.encode('utf-8'))

    # Retourne le hash hexadécimal
    return md5.hexdigest()


# =========================================================
# Programme principal
# =========================================================
if __name__ == "__main__":

    print("=== Algorithme MD5 ===")

    # Message utilisateur
    message = input("Entrez un message : ")

    # Calcul du hash
    digest = md5_hash(message)

    # Affichage
    print("\nMessage :", message)
    print("MD5 :", digest)

    # Taille du hash
    print("Taille :", len(digest) * 4, "bits")