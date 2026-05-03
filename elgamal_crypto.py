import elgammel

class ElGamalCrypto:

    def __init__(self):
        self.public_key = None
        self.private_key = None

    def generate(self):
        self.public_key, self.private_key = elgammel.generate_keys()
        return self.public_key, self.private_key

    def encrypt_key(self, aes_key, public_key):
        return elgammel.encrypt(public_key, aes_key)

    def decrypt_key(self, ciphertext):
        return elgammel.decrypt(self.public_key, self.private_key, ciphertext)