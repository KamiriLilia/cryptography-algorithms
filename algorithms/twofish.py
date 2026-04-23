class TwofishAlgorithm:
    def get_name(self):
        return "Twofish"
    
    def get_description(self):
        return """Twofish est un chiffrement à structure de réseau de Feistel.
Chaque round applique :
• Une fonction F avec des boîtes-Q
• Une transformation de Feistel (échange et XOR)"""
    
    def get_key_info(self):
        return {"type": "symmetric", "placeholder": "Entrez une clé (ex: mysecretkey)"}
    
    def encrypt(self, text, key, log_step, log_matrix):
        log_step(f"Texte original : '{text}'")
        log_step(f"Clé utilisée : '{key}'")
        
        # Chiffrement simplifié pour démonstration
        result = text[::-1]
        log_step(f"Résultat (inversion) : {result}")
        
        return result
    
    def decrypt(self, text, key, log_step, log_matrix):
        return text[::-1]