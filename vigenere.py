"""
Chiffre de Vigenere
Formules:
- Chiffrement: C = (P + K) mod 26
- Déchiffrement: P = (C - K) mod 26
Où P, C, K sont des nombres (A=0, B=1, ..., Z=25)
"""

class VigenereCipher:
    def __init__(self):
        self.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
    def _char_to_num(self, char):
        if char in self.alphabet:
            return ord(char) - ord('A')
        return -1
    
    def _num_to_char(self, num):
        return chr((num % 26) + ord('A'))
    
    def encrypt(self, plaintext, key):
        plaintext = plaintext.upper()
        key = key.upper()
        ciphertext = ""
        
        key_index = 0
        key_length = len(key)
        
        for char in plaintext:
            if char in self.alphabet:
                P = self._char_to_num(char)
                K = self._char_to_num(key[key_index % key_length])
                C = (P + K) % 26
                ciphertext += self._num_to_char(C)
                key_index += 1
            else:
                ciphertext += char
        
        return ciphertext
    
    def decrypt(self, ciphertext, key):
        ciphertext = ciphertext.upper()
        key = key.upper()
        plaintext = ""
        
        key_index = 0
        key_length = len(key)
        
        for char in ciphertext:
            if char in self.alphabet:
                C = self._char_to_num(char)
                K = self._char_to_num(key[key_index % key_length])
                P = (C - K) % 26
                plaintext += self._num_to_char(P)
                key_index += 1
            else:
                plaintext += char
        
        return plaintext


def main():
    cipher = VigenereCipher()
    
    while True:
        print("\n" + "-" * 50)
        print("CHIFFRE DE VIGENERE")
        print("-" * 50)
        print("1. Chiffrer")
        print("2. Dechiffrer")
        print("3. Quitter")
        print("-" * 50)
        
        choix = input("\nVotre choix (1-3): ").strip()
        
        if choix == '1':
            plaintext = input("\nMessage a chiffrer: ")
            key = input("Clé: ")
            ciphertext = cipher.encrypt(plaintext, key)
            print(f"\nClair  : {plaintext}")
            print(f"Clé    : {key}")
            print(f"Chiffre: {ciphertext}")
            
        elif choix == '2':
            ciphertext = input("\nMessage a dechiffrer: ")
            key = input("Clé: ")
            plaintext = cipher.decrypt(ciphertext, key)
            print(f"\nChiffre: {ciphertext}")
            print(f"Clé    : {key}")
            print(f"Clair  : {plaintext}")
            
        elif choix == '3':
            print("\nAu revoir!") 
            break
        else:
            print("\nChoix invalide.")


if __name__ == "__main__":
    main()