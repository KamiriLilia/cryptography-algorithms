"""
RSA Algorithm - Implementation éducative
Chiffrement asymétrique basé sur la factorisation
"""

class RSAAlgorithm:
    def __init__(self):
        self.mod_inverse_cache = {}
    
    def get_name(self):
        return "RSA (Rivest-Shamir-Adleman)"
    
    def get_description(self):
        return """RSA est un chiffrement asymétrique :
• Basé sur la difficulté de factorisation
• Clé publique (n, e) pour chiffrer
• Clé privée (n, d) pour déchiffrer
• Utilisé pour signatures et échanges de clés"""
    
    def get_key_info(self):
        return {"type": "asymmetric", "placeholder": "Enter 'p,q' (ex: 61,53)"}
    
    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a
    
    def mod_inverse(self, a, m):
        if a in self.mod_inverse_cache:
            return self.mod_inverse_cache[a]
        
        a = a % m
        for x in range(1, m):
            if (a * x) % m == 1:
                self.mod_inverse_cache[a] = x
                return x
        raise ValueError(f"No inverse for {a} mod {m}")
    
    def is_prime(self, n):
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True
    
    def generate_keys(self, p, q, log_step=None):
        """Génère les clés publique et privée à partir de p et q"""
        if not self.is_prime(p) or not self.is_prime(q):
            raise ValueError("p et q doivent être premiers")
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        if log_step:
            log_step(f"  n = {p} × {q} = {n}")
            log_step(f"  φ(n) = ({p}-1) × ({q}-1) = {phi}")
        
        # Choisir e (généralement 65537)
        e = 65537
        while self.gcd(e, phi) != 1:
            e += 2
        
        if log_step:
            log_step(f"  e = {e} (gcd({e},{phi}) = 1)")
        
        # Calculer d
        d = self.mod_inverse(e, phi)
        
        if log_step:
            log_step(f"  d = e⁻¹ mod φ(n) = {d}")
        
        return (n, e), (n, d)
    
    def encrypt(self, text, key, log_step=None, log_matrix=None):
        """Chiffrement RSA avec clé publique (n,e) ou p,q"""
        
        if log_step:
            log_step("🔐 RSA ENCRYPTION")
            log_step("=" * 40)
        
        # Parser la clé
        parts = key.replace(' ', '').split(',')
        
        if len(parts) == 2:
            # Format: p,q - générer les clés
            p = int(parts[0])
            q = int(parts[1])
            if log_step:
                log_step(f"Clés générées à partir de p={p}, q={q}")
            public_key, private_key = self.generate_keys(p, q, log_step)
            n, e = public_key
        else:
            raise ValueError("Format: 'p,q' (ex: 61,53)")
        
        if log_step:
            log_step(f"\nClé publique: (n={n}, e={e})")
            log_step(f"\nChiffrement: c = m^e mod n")
            log_step("-" * 40)
        
        # Convertir le texte en nombres
        result_numbers = []
        
        for i, char in enumerate(text):
            m = ord(char)  # Valeur ASCII du caractère
            c = pow(m, e, n)  # Chiffrement: c = m^e mod n
            result_numbers.append(c)
            if log_step and i < 10:
                log_step(f"  '{char}' (ASCII {m}) → {m}^{e} mod {n} = {c}")
        
        if log_step and len(text) > 10:
            log_step(f"  ... et {len(text)-10} autres caractères")
        
        # Convertir en string
        result = ','.join(str(x) for x in result_numbers)
        
        if log_step:
            log_step(f"\n✨ Ciphertext: {result[:100]}{'...' if len(result)>100 else ''}")
        
        return result
    
    def decrypt(self, text, key, log_step=None, log_matrix=None):
        """Déchiffrement RSA avec clé privée (n,d) ou p,q"""
        
        if log_step:
            log_step("🔓 RSA DECRYPTION")
            log_step("=" * 40)
        
        # Parser la clé
        parts = key.replace(' ', '').split(',')
        
        if len(parts) == 2:
            # Format: p,q - générer les clés
            p = int(parts[0])
            q = int(parts[1])
            if log_step:
                log_step(f"Clés générées à partir de p={p}, q={q}")
            public_key, private_key = self.generate_keys(p, q, log_step)
            n, d = private_key
        else:
            raise ValueError("Format: 'p,q' (ex: 61,53)")
        
        if log_step:
            log_step(f"\nClé privée: (n={n}, d={d})")
            log_step(f"\nDéchiffrement: m = c^d mod n")
            log_step("-" * 40)
        
        # Convertir le texte chiffré en nombres
        try:
            numbers = [int(x) for x in text.split(',')]
        except:
            raise ValueError("Le texte chiffré doit être au format 'nombre1,nombre2,...'")
        
        result = ""
        for i, c in enumerate(numbers):
            m = pow(c, d, n)  # Déchiffrement: m = c^d mod n
            result += chr(m)
            if log_step and i < 10:
                log_step(f"  {c} → {c}^{d} mod {n} = {m} → '{chr(m)}'")
        
        if log_step and len(numbers) > 10:
            log_step(f"  ... et {len(numbers)-10} autres blocs")
        
        if log_step:
            log_step(f"\n✨ Decrypted text: {result}")
        
        return result