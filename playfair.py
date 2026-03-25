def create_table(key):
    key = key.upper().replace("J", "I")
    table = []
    used = set()

    # Ajouter les lettres du mot-clé
    for char in key:
        if char.isalpha() and char not in used:
            table.append(char)
            used.add(char)

    # Compléter avec le reste de l'alphabet
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":  # J est fusionné avec I
        if char not in used:
            table.append(char)

    # Transformer en matrice 5x5
    matrix = [table[i:i+5] for i in range(0, 25, 5)]
    return matrix


def find_position(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j


def prepare_text(text):
    text = text.upper().replace("J", "I")

    #Keeps only letters + Removes spaces, numbers, punctuation
    text = "".join([c for c in text if c.isalpha()])

    prepared = ""
    i = 0
    while i < len(text):
        a = text[i]
        b = ""

        if i + 1 < len(text):
            b = text[i + 1]
            if a == b:
                b = "X"
                i += 1
            else:
                i += 2
        else:
            b = "X"
            i += 1

        prepared += a + b

    return prepared


def playfair_encrypt(matrix, text):
    text = prepare_text(text)
    result = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:  # même ligne
            result += matrix[r1][(c1 + 1) % 5]
            result += matrix[r2][(c2 + 1) % 5]

        elif c1 == c2:  # même colonne
            result += matrix[(r1 + 1) % 5][c1]
            result += matrix[(r2 + 1) % 5][c2]

        else:  # rectangle
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


def playfair_decrypt(matrix, text):
    result = ""
    text = text.upper().replace("J", "I")

    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:  # même ligne
            result += matrix[r1][(c1 - 1) % 5]
            result += matrix[r2][(c2 - 1) % 5]

        elif c1 == c2:  # même colonne
            result += matrix[(r1 - 1) % 5][c1]
            result += matrix[(r2 - 1) % 5][c2]

        else:  # rectangle
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


def print_matrix(matrix):
    print("\nTable Playfair :")
    for row in matrix:
        print(" ".join(row))


def main():
    key = input("Entrez le mot-clé : ")
    matrix = create_table(key)
    print_matrix(matrix)

    print("\n1. Chiffrer")
    print("2. Déchiffrer")
    choice = input("Choix (1/2) : ")

    text = input("Entrez le message : ")

    if choice == "1":
        encrypted = playfair_encrypt(matrix, text)
        print("Message chiffré :", encrypted)

    elif choice == "2":
        decrypted = playfair_decrypt(matrix, text)
        print("Message déchiffré :", decrypted)

    else:
        print("Choix invalide.")


if __name__ == "__main__":
    main()