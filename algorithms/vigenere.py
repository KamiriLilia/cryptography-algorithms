class VigenereAlgorithm:
    def get_name(self):
        return "Vigenère Cipher"
    
    def get_description(self):
        return """The Vigenère cipher uses a keyword for polyalphabetic substitution.
Encryption: Ci = (Pi + Ki) mod 26
Decryption: Pi = (Ci - Ki) mod 26"""
    
    def get_key_info(self):
        return {"type": "symmetric", "placeholder": "Enter keyword (letters only)"}
    
    def generate_key(self, text, key):
        key = key.upper()
        key = ''.join([c for c in key if c.isalpha()])
        if not key:
            raise ValueError("Key must contain at least one letter")
        
        key_vals = [ord(c) - ord('A') for c in key]
        result = []
        j = 0
        for char in text:
            if char.isalpha():
                result.append(key_vals[j % len(key)])
                j += 1
            else:
                result.append(None)
        return result
    
    def encrypt(self, text, key, log_step=None, log_matrix=None):
        key_vals = self.generate_key(text, key)
        
        if log_step:
            log_step(f"📌 Vigenère Encryption")
            log_step(f"Keyword: {key}")
            log_step("=" * 40)
        
        result = ""
        j = 0
        for i, char in enumerate(text):
            if char.isalpha() and key_vals[j] is not None:
                base = ord('A') if char.isupper() else ord('a')
                shift = key_vals[j]
                new_char = chr((ord(char.upper()) - ord('A') + shift) % 26 + base)
                key_letter = chr(shift + ord('A'))
                if log_step:
                    log_step(f"  '{char}' + '{key_letter}' = '{new_char}'")
                result += new_char
                j += 1
            else:
                result += char
                if char.isalpha() and log_step:
                    log_step(f"  '{char}' → unchanged")
        
        return result
    
    def decrypt(self, text, key, log_step=None, log_matrix=None):
        key_vals = self.generate_key(text, key)
        
        if log_step:
            log_step(f"📌 Vigenère Decryption")
            log_step(f"Keyword: {key}")
            log_step("=" * 40)
        
        result = ""
        j = 0
        for i, char in enumerate(text):
            if char.isalpha() and key_vals[j] is not None:
                base = ord('A') if char.isupper() else ord('a')
                shift = key_vals[j]
                new_char = chr((ord(char.upper()) - ord('A') - shift) % 26 + base)
                key_letter = chr(shift + ord('A'))
                if log_step:
                    log_step(f"  '{char}' - '{key_letter}' = '{new_char}'")
                result += new_char
                j += 1
            else:
                result += char
        
        return result