"""
DES (Data Encryption Standard)
- Taille du bloc: 64 bits
- Taille de la clé: 56 bits effectifs
- Nombre de rondes: 16
- Structure: Reseau de Feistel
"""

class DESCipher: 
    # Permutation initiale (IP)
    IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]
    
    # Permutation finale (IP^-1)
    IP_INV = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]
    
    # Table d'expansion (E)
    E = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    
    # S-Boxes
    S_BOXES = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]
    
    # Permutation P
    P = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ]
    
    # Table PC-1
    PC1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]
    
    # Table PC-2
    PC2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]
    
    SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode()
        if isinstance(key, bytes):
            self.key = int.from_bytes(key[:8], 'big')
        else:
            self.key = key
        
        self.subkeys = self._generate_subkeys()
    
    def _permute(self, block, table, input_size):
        result = 0
        for i, pos in enumerate(table):
            bit = (block >> (input_size - pos)) & 1
            result = (result << 1) | bit
        return result
    
    def _left_rotate(self, value, bits, size):
        return ((value << bits) | (value >> (size - bits))) & ((1 << size) - 1)
    
    def _generate_subkeys(self):
        permuted_key = self._permute(self.key, self.PC1, 64)
        
        C = (permuted_key >> 28) & 0xFFFFFFF
        D = permuted_key & 0xFFFFFFF
        
        subkeys = []
        
        for round_num in range(16):
            shift = self.SHIFT_SCHEDULE[round_num]
            C = self._left_rotate(C, shift, 28)
            D = self._left_rotate(D, shift, 28)
            
            combined = (C << 28) | D
            subkey = self._permute(combined, self.PC2, 56)
            subkeys.append(subkey)
        
        return subkeys
    
    def _expand(self, half_block):
        result = 0
        for i, pos in enumerate(self.E):
            bit = (half_block >> (32 - pos)) & 1
            result = (result << 1) | bit
        return result
    
    def _sbox_substitute(self, expanded_block):
        result = 0
        for i in range(8):
            bits = (expanded_block >> (42 - 6 * i)) & 0x3F
            
            row = ((bits & 0x20) >> 4) | (bits & 0x01)
            col = (bits >> 1) & 0x0F
            
            sbox_value = self.S_BOXES[i][row][col]
            result = (result << 4) | sbox_value
        
        return result
    
    def _permute_p(self, block):
        return self._permute(block, self.P, 32)
    
    def _feistel_function(self, right, subkey):
        expanded = self._expand(right)
        xored = expanded ^ subkey
        substituted = self._sbox_substitute(xored)
        permuted = self._permute_p(substituted)
        return permuted
    
    def encrypt_block(self, block):
        block = self._permute(block, self.IP, 64)
        
        L = (block >> 32) & 0xFFFFFFFF
        R = block & 0xFFFFFFFF
        
        for i in range(16):
            new_L = R
            new_R = L ^ self._feistel_function(R, self.subkeys[i])
            L, R = new_L, new_R
        
        block = (R << 32) | L
        block = self._permute(block, self.IP_INV, 64)
        
        return block
    
    def decrypt_block(self, block):
        block = self._permute(block, self.IP, 64)
        
        L = (block >> 32) & 0xFFFFFFFF
        R = block & 0xFFFFFFFF
        
        for i in range(15, -1, -1):
            new_L = R
            new_R = L ^ self._feistel_function(R, self.subkeys[i])
            L, R = new_L, new_R
        
        block = (R << 32) | L
        block = self._permute(block, self.IP_INV, 64)
        
        return block
    
    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        pad_len = 8 - (len(plaintext) % 8)
        plaintext += bytes([pad_len] * pad_len)
        
        ciphertext = b''
        for i in range(0, len(plaintext), 8):
            block = int.from_bytes(plaintext[i:i+8], 'big')
            encrypted = self.encrypt_block(block)
            ciphertext += encrypted.to_bytes(8, 'big')
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        plaintext = b''
        for i in range(0, len(ciphertext), 8):
            block = int.from_bytes(ciphertext[i:i+8], 'big')
            decrypted = self.decrypt_block(block)
            plaintext += decrypted.to_bytes(8, 'big')
        
        pad_len = plaintext[-1]
        if pad_len <= 8:
            plaintext = plaintext[:-pad_len]
        
        return plaintext


def main():
    key = input("\nEntrez la clé (8 caractères): ").strip()
    
    try:
        des = DESCipher(key)
        
        while True:
            print("\n" + "-" * 50)
            print("DES")
            print("-" * 50)
            print("1. Chiffrer")
            print("2. Dechiffrer")
            print("3. Quitter")
            print("-" * 50)
            
            choix = input("\nVotre choix (1-3): ").strip()
            
            if choix == '1':
                plaintext = input("\nMessage à chiffrer: ")
                ciphertext = des.encrypt(plaintext)
                print(f"\nClair  : {plaintext}")
                print(f"Chiffre: {ciphertext.hex()}")
                
            elif choix == '2':
                ciphertext_hex = input("\nMessage a dechiffrer (hex): ")
                try:
                    ciphertext = bytes.fromhex(ciphertext_hex)
                    plaintext = des.decrypt(ciphertext).decode()
                    print(f"\nChiffré: {ciphertext_hex}")
                    print(f"Clair  : {plaintext}")
                except:
                    print("Erreur: Format hexadecimal invalide.")
                    
            elif choix == '3':
                print("\nAu revoir!")
                break
            else:
                print("\nChoix invalide.")
                
    except Exception as e:
        print(f"\nErreur: {e}")


if __name__ == "__main__":
    main()