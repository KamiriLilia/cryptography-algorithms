from algorithms.aes import AESAlgorithm  # ton fichier existant

class AESCipher:

    def __init__(self):
        self.aes = AESAlgorithm()

    def encrypt(self, text, key):
        return self.aes.encrypt(
            text,
            key,
            lambda x: None,
            lambda x,y,z=None,w=None: None
        )

    def decrypt(self, text, key):
        return self.aes.decrypt(
            text,
            key,
            lambda x: None,
            lambda x,y,z=None,w=None: None
        )