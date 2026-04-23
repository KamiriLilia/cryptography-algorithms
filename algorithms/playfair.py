class PlayfairAlgorithm:
    def get_name(self):
        return "Playfair Cipher"
    
    def get_description(self):
        return """The Playfair cipher encrypts digraphs (pairs of letters).
Creates a 5x5 grid and applies rectangle, row, or column rules."""
    
    def get_key_info(self):
        return {"type": "symmetric", "placeholder": "Enter keyword"}
    
    def create_grid(self, key):
        key = key.upper().replace('J', 'I')
        seen = set()
        chars = []
        
        for c in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            if c not in seen and c.isalpha():
                seen.add(c)
                chars.append(c)
        
        grid = [chars[i:i+5] for i in range(0, 25, 5)]
        positions = {}
        for i, row in enumerate(grid):
            for j, c in enumerate(row):
                positions[c] = (i, j)
        
        return grid, positions
    
    def prepare(self, text):
        text = text.upper().replace('J', 'I')
        text = ''.join(c for c in text if c.isalpha())
        
        result = []
        i = 0
        while i < len(text):
            result.append(text[i])
            if i + 1 < len(text) and text[i] == text[i+1]:
                result.append('X')
            i += 1
        
        if len(result) % 2 != 0:
            result.append('X')
        
        return ''.join(result)
    
    def process_digraph(self, digraph, positions, grid, encrypt):
        p1, p2 = positions[digraph[0]], positions[digraph[1]]
        
        if p1[0] == p2[0]:  # Same row
            shift = 1 if encrypt else -1
            return grid[p1[0]][(p1[1] + shift) % 5] + grid[p2[0]][(p2[1] + shift) % 5]
        elif p1[1] == p2[1]:  # Same column
            shift = 1 if encrypt else -1
            return grid[(p1[0] + shift) % 5][p1[1]] + grid[(p2[0] + shift) % 5][p2[1]]
        else:  # Rectangle
            return grid[p1[0]][p2[1]] + grid[p2[0]][p1[1]]
    
    def encrypt(self, text, key, log_step=None, log_matrix=None):
        grid, positions = self.create_grid(key)
        
        if log_step:
            log_step("📌 Playfair Grid:")
            for row in grid:
                log_step(f"  {' '.join(row)}")
        
        prepared = self.prepare(text)
        if log_step:
            log_step(f"\nPrepared text: {prepared}")
        
        result = []
        for i in range(0, len(prepared), 2):
            digraph = prepared[i:i+2]
            encrypted = self.process_digraph(digraph, positions, grid, encrypt=True)
            result.append(encrypted)
            if log_step:
                log_step(f"  '{digraph}' → '{encrypted}'")
        
        return ''.join(result)
    
    def decrypt(self, text, key, log_step=None, log_matrix=None):
        grid, positions = self.create_grid(key)
        
        if log_step:
            log_step("📌 Playfair Grid:")
            for row in grid:
                log_step(f"  {' '.join(row)}")
        
        result = []
        for i in range(0, len(text), 2):
            digraph = text[i:i+2]
            decrypted = self.process_digraph(digraph, positions, grid, encrypt=False)
            result.append(decrypted)
            if log_step:
                log_step(f"  '{digraph}' → '{decrypted}'")
        
        return ''.join(result).replace('X', '')