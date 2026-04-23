"""
Hill Cipher Implementation
Polygraphic substitution using matrix multiplication
"""

class HillAlgorithm:
    def __init__(self):
        self.mod_inverse_cache = {}
    
    def get_name(self):
        return "Hill Cipher"
    
    def get_description(self):
        return """The Hill cipher uses matrix multiplication:
• Works on blocks of letters
• Encryption: C = (P × K) mod 26
• Decryption: P = (C × K⁻¹) mod 26
• Matrix must be invertible modulo 26"""
    
    def get_key_info(self):
        return {"type": "symmetric", "placeholder": "Enter 2x2 matrix as '3,3,2,5'"}
    
    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a
    
    def mod_inverse(self, a, m=26):
        if a in self.mod_inverse_cache:
            return self.mod_inverse_cache[a]
        
        a = a % m
        for x in range(1, m):
            if (a * x) % m == 1:
                self.mod_inverse_cache[a] = x
                return x
        raise ValueError(f"No inverse for {a} mod {m}")
    
    def matrix_mod_inverse(self, matrix):
        """Calculate 2x2 matrix inverse modulo 26"""
        a, b, c, d = matrix[0][0], matrix[0][1], matrix[1][0], matrix[1][1]
        det = (a * d - b * c) % 26
        
        if det == 0:
            raise ValueError("Matrix determinant is 0, not invertible")
        
        det_inv = self.mod_inverse(det)
        
        inv = [
            [(d * det_inv) % 26, (-b * det_inv) % 26],
            [(-c * det_inv) % 26, (a * det_inv) % 26]
        ]
        return inv
    
    def parse_key(self, key):
        """Parse key string into 2x2 matrix"""
        numbers = []
        for part in key.replace(' ', '').split(','):
            if part:
                numbers.append(int(part))
        
        if len(numbers) < 4:
            raise ValueError("Need 4 integers for 2x2 matrix")
        
        matrix = [[numbers[0], numbers[1]], [numbers[2], numbers[3]]]
        
        # Check determinant
        det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26
        if det == 0:
            raise ValueError("Matrix not invertible (determinant = 0 mod 26)")
        
        try:
            self.mod_inverse(det)
        except:
            raise ValueError("Determinant has no inverse modulo 26")
        
        return matrix
    
    def multiply_matrix_vector(self, matrix, vector):
        """Multiply 2x2 matrix by 2-element vector"""
        return [
            (matrix[0][0] * vector[0] + matrix[0][1] * vector[1]) % 26,
            (matrix[1][0] * vector[0] + matrix[1][1] * vector[1]) % 26
        ]
    
    def text_to_vectors(self, text):
        """Convert text to vectors of numbers (A=0)"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        if len(text) % 2 != 0:
            text += 'X'
        
        vectors = []
        for i in range(0, len(text), 2):
            vectors.append([ord(text[i]) - ord('A'), ord(text[i+1]) - ord('A')])
        return vectors, text
    
    def vectors_to_text(self, vectors):
        """Convert vectors back to text"""
        result = ''
        for v in vectors:
            result += chr(v[0] + ord('A')) + chr(v[1] + ord('A'))
        return result
    
    def encrypt(self, text, key, log_step=None, log_matrix=None):
        """Encrypt using Hill cipher"""
        matrix = self.parse_key(key)
        
        if log_step:
            log_step("📐 HILL CIPHER ENCRYPTION")
            log_step("=" * 40)
            log_step(f"Key Matrix:")
            log_step(f"  [{matrix[0][0]:2d} {matrix[0][1]:2d}]")
            log_step(f"  [{matrix[1][0]:2d} {matrix[1][1]:2d}]")
        
        vectors, prepared = self.text_to_vectors(text)
        if log_step:
            log_step(f"\nPrepared text: {prepared}")
            log_step(f"Vectors: {vectors}")
            log_step(f"\nEncryption: C = (P × K) mod 26")
        
        result_vectors = []
        for i, vec in enumerate(vectors):
            encrypted = self.multiply_matrix_vector(matrix, vec)
            result_vectors.append(encrypted)
            if log_step:
                log_step(f"\nBlock {i+1}:")
                log_step(f"  [{vec[0]:2d} {vec[1]:2d}] × [{matrix[0][0]} {matrix[0][1]}] = [{encrypted[0]:2d} {encrypted[1]:2d}]")
                log_step(f"                    [{matrix[1][0]} {matrix[1][1]}]")
        
        result = self.vectors_to_text(result_vectors)
        if log_step:
            log_step(f"\n✨ Encrypted text: {result}")
        
        return result
    
    def decrypt(self, text, key, log_step=None, log_matrix=None):
        """Decrypt using Hill cipher"""
        matrix = self.parse_key(key)
        inv_matrix = self.matrix_mod_inverse(matrix)
        
        if log_step:
            log_step("📐 HILL CIPHER DECRYPTION")
            log_step("=" * 40)
            log_step(f"Key Matrix:")
            log_step(f"  [{matrix[0][0]:2d} {matrix[0][1]:2d}]")
            log_step(f"  [{matrix[1][0]:2d} {matrix[1][1]:2d}]")
            log_step(f"\nInverse Matrix:")
            log_step(f"  [{inv_matrix[0][0]:2d} {inv_matrix[0][1]:2d}]")
            log_step(f"  [{inv_matrix[1][0]:2d} {inv_matrix[1][1]:2d}]")
        
        vectors, prepared = self.text_to_vectors(text)
        if log_step:
            log_step(f"\nCiphertext vectors: {vectors}")
            log_step(f"\nDecryption: P = (C × K⁻¹) mod 26")
        
        result_vectors = []
        for i, vec in enumerate(vectors):
            decrypted = self.multiply_matrix_vector(inv_matrix, vec)
            result_vectors.append(decrypted)
            if log_step:
                log_step(f"\nBlock {i+1}:")
                log_step(f"  [{vec[0]:2d} {vec[1]:2d}] → [{decrypted[0]:2d} {decrypted[1]:2d}]")
        
        result = self.vectors_to_text(result_vectors)
        if log_step:
            log_step(f"\n✨ Decrypted text: {result}")
        
        return result