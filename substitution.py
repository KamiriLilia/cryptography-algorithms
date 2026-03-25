"""
Chiffrement par substitution aléatoire (monoalphabetique)
Table utilisee: Clair    A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
                Chiffre  X W Y K R L A M B N C O D P E Q F Z G S H T I U J V
"""

class SubstitutionCipher:
    def __init__(self):
        self.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.cipher_alphabet = "XWYKRLAMBNCODPEQFZGSHTIUJV"
        
        self.encrypt_map = {}
        self.decrypt_map = {} 
        
        for i in range(26):
            self.encrypt_map[self.alphabet[i]] = self.cipher_alphabet[i]
            self.decrypt_map[self.cipher_alphabet[i]] = self.alphabet[i]
    
    def encrypt(self, plaintext):
        plaintext = plaintext.upper()
        ciphertext = ""
        
        for char in plaintext:
            if char in self.encrypt_map:
                ciphertext += self.encrypt_map[char]
            else:
                ciphertext += char
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        ciphertext = ciphertext.upper()
        plaintext = ""
        
        for char in ciphertext:
            if char in self.decrypt_map:
                plaintext += self.decrypt_map[char]
            else:
                plaintext += char
        
        return plaintext


def main():
    cipher = SubstitutionCipher()
    
    while True:
        print("\n" + "-" * 50)
        print("SUBSTITUTION ALEATOIRE")
        print("-" * 50)
        print("1. Chiffrer")
        print("2. Dechiffrer")
        print("3. Quitter")
        print("-" * 50)
        
        choix = input("\nVotre choix (1-3): ").strip()
        
        if choix == '1':
            plaintext = input("\nMessage a chiffrer: ")
            ciphertext = cipher.encrypt(plaintext)
            print(f"\nClair  : {plaintext}")
            print(f"Chiffré: {ciphertext}")
            
        elif choix == '2':
            ciphertext = input("\nMessage a dechiffrer: ")
            plaintext = cipher.decrypt(ciphertext)
            print(f"\nChiffré: {ciphertext}")
            print(f"Clair  : {plaintext}")
            
        elif choix == '3':
            print("\nAu revoir!")
            break
        else:
            print("\nChoix invalide.")


if __name__ == "__main__":
    main()