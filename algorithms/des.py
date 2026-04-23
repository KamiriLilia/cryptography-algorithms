"""
DES (Data Encryption Standard) - Educational Implementation
Shows initial permutation, Feistel rounds, S-boxes, final permutation
"""

class DESAlgorithm:
    def __init__(self):
        # Simplified S-boxes for educational purposes
        self.s_box = [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10]
        ]
    
    def get_name(self):
        return "DES (Data Encryption Standard)"
    
    def get_description(self):
        return """DES is a block cipher with Feistel structure:
• 64-bit blocks
• 56-bit effective key
• 16 rounds of processing
• Initial and final permutations
• 8 S-boxes for substitution"""
    
    def get_key_info(self):
        return {"type": "symmetric", "placeholder": "Enter 8-character key (64 bits)"}
    
    def initial_permutation(self, block):
        """Simplified initial permutation (IP)"""
        return block[::-1]
    
    def final_permutation(self, block):
        """Simplified final permutation (IP⁻¹)"""
        return block[::-1]
    
    def expansion(self, right):
        """Expansion permutation (32 to 48 bits) - simplified"""
        return right + right[:4]
    
    def sbox_substitution(self, data):
        """S-box substitution (48 to 32 bits) - simplified"""
        result = 0
        for i in range(8):
            chunk = (data >> (i * 6)) & 0x3F
            row = ((chunk >> 4) & 0x2) | (chunk & 0x1)
            col = (chunk >> 1) & 0xF
            val = self.s_box[row % 2][col]
            result |= (val << (i * 4))
        return result
    
    def pbox_permutation(self, data):
        """P-box permutation - simplified"""
        return ((data & 0xAAAAAAAA) >> 1) | ((data & 0x55555555) << 1)
    
    def feistel_round(self, left, right, round_key, round_num, log_step=None):
        """Single Feistel round"""
        if log_step:
            log_step(f"\n  🔄 Round {round_num}")
            log_step(f"    Input: L={left:08X}, R={right:08X}")
        
        # Expansion
        expanded = self.expansion(format(right, '032b'))
        if log_step:
            log_step(f"    Expansion: R → {expanded[:16]}...")
        
        # XOR with round key
        xored = int(expanded, 2) ^ round_key
        if log_step:
            log_step(f"    XOR with key: {xored:012X}")
        
        # S-box substitution
        sbox_out = self.sbox_substitution(xored)
        if log_step:
            log_step(f"    S-box output: {sbox_out:08X}")
        
        # P-box permutation
        pbox_out = self.pbox_permutation(sbox_out)
        if log_step:
            log_step(f"    P-box output: {pbox_out:08X}")
        
        # XOR with left
        new_right = left ^ pbox_out
        if log_step:
            log_step(f"    New R = L XOR F = {new_right:08X}")
        
        return right, new_right
    
    def generate_round_keys(self, key):
        """Generate 16 round keys from main key (simplified)"""
        key_int = 0
        for i, c in enumerate(key[:8]):
            key_int |= (ord(c) << (56 - (i * 8)))
        
        round_keys = []
        for i in range(16):
            # Simplified key schedule
            round_key = ((key_int << i) | (key_int >> (56 - i))) & 0xFFFFFFFFFFFF
            round_keys.append(round_key & 0xFFFFFFFF)
        return round_keys
    
    def encrypt(self, text, key, log_step=None, log_matrix=None):
        """Encrypt with DES showing all rounds"""
        if len(key) < 8:
            raise ValueError("Key must be at least 8 characters")
        
        # Prepare block (8 bytes = 64 bits)
        block_bytes = text.encode('utf-8')[:8]
        while len(block_bytes) < 8:
            block_bytes += b'\x00'
        
        block_int = int.from_bytes(block_bytes, 'big')
        
        if log_step:
            log_step("🐍 DES ENCRYPTION PROCESS")
            log_step("=" * 50)
            log_step(f"Plaintext block: {block_bytes.hex()}")
            log_step(f"Plaintext (int): {block_int:016X}")
        
        # Initial permutation
        ip = self.initial_permutation(format(block_int, '064b'))
        ip_int = int(ip, 2)
        if log_step:
            log_step(f"\n📊 After Initial Permutation: {ip_int:016X}")
        
        # Split into left and right (32 bits each)
        left = (ip_int >> 32) & 0xFFFFFFFF
        right = ip_int & 0xFFFFFFFF
        
        if log_step:
            log_step(f"Split: L={left:08X}, R={right:08X}")
        
        # Generate round keys
        round_keys = self.generate_round_keys(key)
        if log_step:
            log_step(f"\n🔑 Generated 16 round keys")
        
        # 16 Feistel rounds
        for i in range(16):
            left, right = self.feistel_round(left, right, round_keys[i], i + 1, log_step)
        
        # Final swap
        final_block = (right << 32) | left
        if log_step:
            log_step(f"\n📊 After final swap: {final_block:016X}")
        
        # Final permutation
        fp = self.final_permutation(format(final_block, '064b'))
        cipher_int = int(fp, 2)
        
        cipher_bytes = cipher_int.to_bytes(8, 'big')
        result = cipher_bytes.hex()
        
        if log_step:
            log_step(f"\n✨ Final Ciphertext (hex): {result}")
        
        return result
    
    def decrypt(self, text, key, log_step=None, log_matrix=None):
        """Decrypt with DES (reverse order of rounds)"""
        try:
            cipher_bytes = bytes.fromhex(text)
            if len(cipher_bytes) < 8:
                cipher_bytes = text.encode('utf-8')[:8]
        except:
            cipher_bytes = text.encode('utf-8')[:8]
        
        while len(cipher_bytes) < 8:
            cipher_bytes += b'\x00'
        
        cipher_int = int.from_bytes(cipher_bytes, 'big')
        
        if log_step:
            log_step("🐍 DES DECRYPTION PROCESS")
            log_step("=" * 50)
            log_step(f"Ciphertext block: {cipher_bytes.hex()}")
        
        # Initial permutation
        ip = self.initial_permutation(format(cipher_int, '064b'))
        ip_int = int(ip, 2)
        
        # Split
        left = (ip_int >> 32) & 0xFFFFFFFF
        right = ip_int & 0xFFFFFFFF
        
        # Generate round keys
        round_keys = self.generate_round_keys(key)
        
        # 16 rounds in reverse order
        for i in range(15, -1, -1):
            left, right = self.feistel_round(left, right, round_keys[i], i + 1, log_step)
        
        # Final swap and permutation
        final_block = (right << 32) | left
        fp = self.final_permutation(format(final_block, '064b'))
        plain_int = int(fp, 2)
        
        plain_bytes = plain_int.to_bytes(8, 'big')
        result = plain_bytes.decode('utf-8', errors='ignore').strip('\x00')
        
        if log_step:
            log_step(f"\n✨ Decrypted Text: {result}")
        
        return result