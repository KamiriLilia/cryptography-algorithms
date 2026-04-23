"""
RC4 (Rivest Cipher 4) - Educational Implementation
Stream cipher with KSA and PRGA
"""

class RC4Algorithm:
    def get_name(self):
        return "RC4 (Rivest Cipher 4)"
    
    def get_description(self):
        return """RC4 is a stream cipher with:
• KSA - Key Scheduling Algorithm
• PRGA - Pseudo-Random Generation Algorithm
• XOR with keystream for encryption/decryption"""
    
    def get_key_info(self):
        return {"type": "symmetric", "placeholder": "Enter key (any length)"}
    
    def ksa(self, key, log_step=None):
        """Key Scheduling Algorithm"""
        S = list(range(256))
        key_bytes = [ord(c) for c in key]
        
        if log_step:
            log_step("KSA - Initializing S-box...")
        j = 0
        for i in range(256):
            j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
            S[i], S[j] = S[j], S[i]
            
            if log_step and i < 5:
                log_step(f"  i={i}, j={j}, swapped S[{i}] and S[{j}]")
        
        return S
    
    def prga(self, S, length, log_step=None):
        """Pseudo-Random Generation Algorithm"""
        keystream = []
        i = j = 0
        
        if log_step:
            log_step("\nPRGA - Generating keystream...")
        for k in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            
            keystream_byte = S[(S[i] + S[j]) % 256]
            keystream.append(keystream_byte)
            
            if log_step and k < 5:
                log_step(f"  Round {k+1}: i={i}, j={j}, keystream_byte={keystream_byte:02X}")
        
        return keystream
    
    def encrypt(self, text, key, log_step=None, log_matrix=None):
        """Encrypt with RC4"""
        if log_step:
            log_step("🔐 RC4 ENCRYPTION")
            log_step("=" * 40)
        
        S = self.ksa(key, log_step)
        keystream = self.prga(S[:], len(text), log_step)
        
        # XOR
        result_bytes = []
        if log_step:
            log_step("\nXOR with plaintext:")
        for i, char in enumerate(text):
            pt_byte = ord(char)
            ks_byte = keystream[i]
            ct_byte = pt_byte ^ ks_byte
            result_bytes.append(ct_byte)
            
            if log_step and i < 10:
                log_step(f"  '{char}' (0x{pt_byte:02X}) XOR 0x{ks_byte:02X} = 0x{ct_byte:02X}")
        
        result = bytes(result_bytes).hex()
        if log_step:
            log_step(f"\n✨ Ciphertext (hex): {result}")
        
        return result
    
    def decrypt(self, text, key, log_step=None, log_matrix=None):
        """Decrypt with RC4"""
        if log_step:
            log_step("🔓 RC4 DECRYPTION")
            log_step("=" * 40)
        
        # Convert hex to bytes
        try:
            cipher_bytes = bytes.fromhex(text)
        except:
            cipher_bytes = text.encode('utf-8')
        
        S = self.ksa(key, log_step)
        keystream = self.prga(S[:], len(cipher_bytes), log_step)
        
        # XOR
        result_bytes = []
        for i, byte in enumerate(cipher_bytes):
            pt_byte = byte ^ keystream[i]
            result_bytes.append(pt_byte)
        
        result = bytes(result_bytes).decode('utf-8', errors='ignore')
        if log_step:
            log_step(f"\n✨ Decrypted text: {result}")
        
        return result