class CaesarAlgorithm:
    def get_name(self):
        return "Caesar Cipher"
    
    def get_description(self):
        return """The Caesar cipher shifts each letter by a fixed number.
Encryption: C = (P + K) mod 26
Decryption: P = (C - K) mod 26"""
    
    def get_key_info(self):
        return {"type": "symmetric", "placeholder": "Enter shift (1-25)"}
    
    def encrypt(self, text, key, log_step=None, log_matrix=None):
        try:
            shift = int(key)
            if shift < 1 or shift > 25:
                raise ValueError("Shift must be between 1 and 25")
        except ValueError:
            raise ValueError("Key must be an integer between 1 and 25")
        
        if log_step:
            log_step(f"📌 Caesar Cipher - Shift: {shift}")
            log_step("=" * 40)
        
        result = ""
        for i, char in enumerate(text):
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                new_char = chr((ord(char) - base + shift) % 26 + base)
                if log_step:
                    log_step(f"  '{char}' → '{new_char}' (shifted by {shift})")
                result += new_char
            else:
                if log_step:
                    log_step(f"  '{char}' → unchanged")
                result += char
        
        return result
    
    def decrypt(self, text, key, log_step=None, log_matrix=None):
        try:
            shift = int(key)
            if shift < 1 or shift > 25:
                raise ValueError("Shift must be between 1 and 25")
        except ValueError:
            raise ValueError("Key must be an integer between 1 and 25")
        
        if log_step:
            log_step(f"📌 Caesar Cipher Decryption - Shift: {shift}")
            log_step("=" * 40)
        
        result = ""
        for i, char in enumerate(text):
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                new_char = chr((ord(char) - base - shift) % 26 + base)
                if log_step:
                    log_step(f"  '{char}' → '{new_char}' (shifted back by {shift})")
                result += new_char
            else:
                if log_step:
                    log_step(f"  '{char}' → unchanged")
                result += char
        
        return result