class AffineAlgorithm:
    def __init__(self):
        self.mod_inverse_cache = {}
    
    def get_name(self):
        return "Affine Cipher"
    
    def get_description(self):
        return """The Affine cipher combines multiplication and addition.
Encryption: E(x) = (ax + b) mod 26
Decryption: D(x) = a⁻¹(x - b) mod 26
'a' must be coprime with 26"""
    
    def get_key_info(self):
        return {"type": "symmetric", "placeholder": "Enter 'a,b' (e.g., '5,8')"}
    
    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a
    
    def mod_inverse(self, a, m=26):
        if a in self.mod_inverse_cache:
            return self.mod_inverse_cache[a]
        
        for x in range(1, m):
            if (a * x) % m == 1:
                self.mod_inverse_cache[a] = x
                return x
        raise ValueError(f"{a} has no inverse mod {m}")
    
    def parse_key(self, key):
        parts = key.replace(' ', '').split(',')
        if len(parts) < 2:
            parts = key.split()
        
        a = int(parts[0].strip())
        b = int(parts[1].strip()) % 26
        
        if self.gcd(a, 26) != 1:
            raise ValueError(f"a={a} must be coprime with 26")
        
        return a, b
    
    def encrypt(self, text, key, log_step=None, log_matrix=None):
        a, b = self.parse_key(key)
        
        if log_step:
            log_step(f"📌 Affine Encryption: E(x) = ({a}x + {b}) mod 26")
            log_step(f"a={a}, b={b}")
            log_step("=" * 40)
        
        result = ""
        for i, char in enumerate(text):
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                x = ord(char.upper()) - ord('A')
                y = (a * x + b) % 26
                new_char = chr(y + base)
                if log_step:
                    log_step(f"  '{char}' (x={x}) → y=({a}×{x}+{b})%26={y} → '{new_char}'")
                result += new_char
            else:
                result += char
                if log_step:
                    log_step(f"  '{char}' → unchanged")
        
        return result
    
    def decrypt(self, text, key, log_step=None, log_matrix=None):
        a, b = self.parse_key(key)
        a_inv = self.mod_inverse(a)
        
        if log_step:
            log_step(f"📌 Affine Decryption: D(x) = {a_inv}(x - {b}) mod 26")
            log_step(f"a⁻¹={a_inv}, b={b}")
            log_step("=" * 40)
        
        result = ""
        for i, char in enumerate(text):
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                x = ord(char.upper()) - ord('A')
                y = (a_inv * (x - b)) % 26
                new_char = chr(y + base)
                if log_step:
                    log_step(f"  '{char}' (x={x}) → y={a_inv}×({x}-{b})%26={y} → '{new_char}'")
                result += new_char
            else:
                result += char
        
        return result