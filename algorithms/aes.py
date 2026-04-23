class AESAlgorithm:
    def __init__(self):
        self.s_box = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
        ]
    
    def get_name(self):
        return "AES (Advanced Encryption Standard)"
    
    def get_description(self):
        return """AES est un chiffrement par blocs de 128 bits.
Les transformations AES sont :
• SubBytes : substitution non-linéaire via S-Box
• ShiftRows : décalage cyclique des lignes
• MixColumns : multiplication matricielle
• AddRoundKey : XOR avec la clé de tour"""
    
    def get_key_info(self):
        return {"type": "symmetric", "placeholder": "Entrez une clé (ex: secretkey123)"}
    
    def encrypt(self, text, key, log_step, log_matrix):
        """Chiffrement AES avec étapes détaillées"""
        
        # Préparer le texte (16 bytes)
        text_bytes = text.encode('utf-8')[:16]
        state = list(text_bytes)
        while len(state) < 16:
            state.append(0)
        
        # ÉTAPE 1: État initial
        log_matrix("MATRICE INITIALE", state, 1, 7)
        log_step(f"Texte original : '{text}'")
        log_step(f"Conversion en bytes : {bytes(state).hex()}")
        
        # Génération de la clé
        key_bytes = key.encode('utf-8')
        round_key = []
        for i in range(16):
            round_key.append(key_bytes[i % len(key_bytes)])
        
        # ÉTAPE 2: AddRoundKey
        log_matrix("CLÉ DE TOUR", round_key, 2, 7)
        log_step(f"Clé utilisée : '{key}'")
        
        for i in range(16):
            old_val = state[i]
            state[i] ^= round_key[i]
            log_step(f"Byte {i+1:2d} : {old_val:02X} ⊕ {round_key[i]:02X} = {state[i]:02X}")
        
        log_matrix("APRES AddRoundKey", state)
        
        # ÉTAPE 3: SubBytes
        log_step("Substitution par S-Box :")
        for i in range(16):
            old_val = state[i]
            if old_val < len(self.s_box):
                state[i] = self.s_box[old_val]
            log_step(f"Byte {i+1:2d} : {old_val:02X} → S-Box → {state[i]:02X}")
        
        log_matrix("APRES SubBytes", state, 3, 7)
        
        # ÉTAPE 4: ShiftRows
        log_step("Décalage des lignes :")
        log_step("  • Ligne 0: aucun décalage")
        log_step("  • Ligne 1: décalage gauche de 1")
        log_step("  • Ligne 2: décalage gauche de 2")
        log_step("  • Ligne 3: décalage gauche de 3")
        
        s = state[:]
        state = [
            s[0], s[1], s[2], s[3],
            s[5], s[6], s[7], s[4],
            s[10], s[11], s[8], s[9],
            s[15], s[12], s[13], s[14]
        ]
        
        log_matrix("APRES ShiftRows", state, 4, 7)
        
        # ÉTAPE 5: MixColumns
        log_step("Multiplication matricielle (MixColumns) :")
        new_state = state[:]
        for col in range(4):
            col_values = [state[col], state[col+4], state[col+8], state[col+12]]
            log_step(f"Colonne {col+1} : [{col_values[0]:02X}, {col_values[1]:02X}, {col_values[2]:02X}, {col_values[3]:02X}]")
            
            new_state[col] = (col_values[0] * 2) % 256
            new_state[col+4] = (col_values[1] * 2) % 256
            new_state[col+8] = (col_values[2] * 2) % 256
            new_state[col+12] = (col_values[3] * 2) % 256
            log_step(f"→ Après MixColumns : [{new_state[col]:02X}, {new_state[col+4]:02X}, {new_state[col+8]:02X}, {new_state[col+12]:02X}]")
        
        state = new_state
        log_matrix("APRES MixColumns", state, 5, 7)
        
        # ÉTAPE 6: AddRoundKey final
        log_step("AddRoundKey final :")
        for i in range(16):
            old_val = state[i]
            state[i] ^= round_key[i]
            log_step(f"Byte {i+1:2d} : {old_val:02X} ⊕ {round_key[i]:02X} = {state[i]:02X}")
        
        log_matrix("CIPHERTEXT FINAL", state, 6, 7)
        
        # Résultat
        result = bytes(state).hex()
        log_step(f"✨ Résultat final (hexadécimal) : {result}")
        
        return result
    
    def decrypt(self, text, key, log_step, log_matrix):
        """Déchiffrement AES"""
        try:
            state = [int(text[i:i+2], 16) for i in range(0, len(text), 2)]
        except:
            state = [ord(c) for c in text[:16]]
        
        while len(state) < 16:
            state.append(0)
        
        log_matrix("CIPHERTEXT REÇU", state, 1, 4)
        
        key_bytes = key.encode('utf-8')
        round_key = []
        for i in range(16):
            round_key.append(key_bytes[i % len(key_bytes)])
        
        for i in range(16):
            state[i] ^= round_key[i]
        
        result = bytes(state).decode('utf-8', errors='ignore').strip('\x00')
        log_step(f"✨ Texte déchiffré : {result}")
        
        return result