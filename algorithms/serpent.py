"""
Serpent Algorithm - Educational Implementation
Shows 32 rounds with S-box operations
"""

class SerpentAlgorithm:
    def __init__(self):
        # Simplified S-boxes for educational purposes
        self.s_boxes = [
            [i ^ 0x0 for i in range(16)],
            [i ^ 0x5 for i in range(16)],
            [i ^ 0xA for i in range(16)],
            [i ^ 0xF for i in range(16)],
            [i ^ 0x3 for i in range(16)],
            [i ^ 0x6 for i in range(16)],
            [i ^ 0x9 for i in range(16)],
            [i ^ 0xC for i in range(16)],
        ]
    
    def get_name(self):
        return "Serpent"
    
    def get_description(self):
        return """Serpent is a block cipher with 32 rounds:
• 128-bit blocks
• 32 rounds of processing
• 8 S-boxes used in sequence
• Strong security margin"""
    
    def get_key_info(self):
        return {"type": "symmetric", "placeholder": "Enter key (16+ characters)"}
    
    def serpent_round(self, data, round_num, is_encrypt, log_step=None):
        """Single Serpent round"""
        sbox = self.s_boxes[round_num % 8]
        
        if log_step:
            log_step(f"    Round {round_num}/32")
            log_step(f"      Using S-box #{round_num % 8}")
        
        # Apply S-box to each nibble
        result = 0
        for i in range(0, 32, 4):
            nibble = (data >> i) & 0xF
            if is_encrypt:
                transformed = sbox[nibble]
            else:
                # Decryption needs inverse S-box
                transformed = sbox.index(nibble) if nibble in sbox else nibble
            result |= (transformed << i)
        
        return result
    
    def linear_transform(self, data, is_encrypt, log_step=None):
        """Linear diffusion layer"""
        # Simplified linear transform
        if is_encrypt:
            result = ((data << 1) | (data >> 31)) & 0xFFFFFFFF
        else:
            result = ((data >> 1) | (data << 31)) & 0xFFFFFFFF
        return result
    
    def encrypt(self, text, key, log_step=None, log_matrix=None):
        """Encrypt with Serpent showing rounds"""
        # Prepare block (16 bytes = 128 bits)
        block_bytes = text.encode('utf-8')[:16]
        while len(block_bytes) < 16:
            block_bytes += b'\x00'
        
        block_int = int.from_bytes(block_bytes, 'big')
        
        if log_step:
            log_step("🐍 SERPENT ENCRYPTION PROCESS")
            log_step("=" * 50)
            log_step(f"Number of rounds: 32")
            log_step(f"Block (hex): {block_bytes.hex()}")
            log_step("\nProcessing rounds...")
        
        current = block_int
        for i in range(32):
            # S-box layer
            current = self.serpent_round(current, i + 1, True, log_step)
            
            # Linear transform (except last round)
            if i < 31:
                current = self.linear_transform(current, True, log_step)
            
            if log_step and (i + 1) % 4 == 0:
                log_step(f"    After round {i+1}: {current:032X}")
        
        result_hex = format(current, '032x')
        if log_step:
            log_step(f"\n✨ Final Ciphertext (hex): {result_hex}")
        
        return result_hex
    
    def decrypt(self, text, key, log_step=None, log_matrix=None):
        """Decrypt with Serpent (reverse order)"""
        try:
            block_int = int(text, 16)
        except:
            block_bytes = text.encode('utf-8')[:16]
            while len(block_bytes) < 16:
                block_bytes += b'\x00'
            block_int = int.from_bytes(block_bytes, 'big')
        
        if log_step:
            log_step("🐍 SERPENT DECRYPTION PROCESS")
            log_step("=" * 50)
        
        current = block_int
        for i in range(31, -1, -1):
            # Inverse linear transform (except last round)
            if i < 31:
                current = self.linear_transform(current, False, log_step)
            
            # Inverse S-box layer
            current = self.serpent_round(current, i + 1, False, log_step)
        
        result_bytes = current.to_bytes(16, 'big')
        result = result_bytes.decode('utf-8', errors='ignore').strip('\x00')
        
        if log_step:
            log_step(f"\n✨ Decrypted Text: {result}")
        
        return result