import socket
import threading
import json
import base64

from rsa_signature import RSASignature
from elgamal_crypto import ElGamalCrypto
from aes_cipher import AESCipher


class SecureChat:

    def __init__(self, host='127.0.0.1', port=5000):
        self.host = host
        self.port = port

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.rsa = RSASignature()
        self.elgamal = ElGamalCrypto()
        self.aes = AESCipher()

        self.peer_elgamal_pub = None
        self.peer_rsa_pub = None

    # =========================
    # SERVER
    # =========================
    def start_server(self):
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)

        print("[SERVER] Waiting...")
        self.conn, _ = self.sock.accept()

        print("[SERVER] Client connected")

        self.exchange_keys(self.conn)

        threading.Thread(target=self.receive, daemon=True).start()
        self.send_loop(self.conn)

    # =========================
    # CLIENT
    # =========================
    def connect(self):
        self.sock.connect((self.host, self.port))
        self.conn = self.sock

        print("[CLIENT] Connected")

        self.exchange_keys(self.conn)

        threading.Thread(target=self.receive, daemon=True).start()
        self.send_loop(self.conn)

    # =========================
    # KEY EXCHANGE
    # =========================
    def exchange_keys(self, conn):

        # ElGamal
        pub, priv = self.elgamal.generate()

        rsa_pub = self.rsa.rsa.generate_keys(61, 53)[0]  # demo simple

        my_keys = {
            "elgamal": pub,
            "rsa": rsa_pub
        }

        conn.send(json.dumps(my_keys).encode())

        peer_keys = json.loads(conn.recv(4096).decode())

        self.peer_elgamal_pub = peer_keys["elgamal"]
        self.peer_rsa_pub = peer_keys["rsa"]

        print("[+] Keys exchanged")

    # =========================
    # SEND MESSAGE
    # =========================
    def send_loop(self, conn):

        while True:
            msg = input("You: ")

            aes_key = b"1234567890123456"

            encrypted_msg = self.aes.encrypt(msg, aes_key)

            encrypted_key = self.elgamal.encrypt_key(
                aes_key,
                self.peer_elgamal_pub
            )

            signature = self.rsa.sign(msg, self.rsa.rsa.generate_keys(61, 53)[1])

            packet = {
                "msg": encrypted_msg,
                "key": encrypted_key,
                "sig": signature
            }

            conn.send(json.dumps(packet).encode())

    # =========================
    # RECEIVE MESSAGE
    # =========================
    def receive(self):

        while True:
            data = self.conn.recv(4096)
            if not data:
                break

            packet = json.loads(data.decode())

            print("\n[ENCRYPTED MESSAGE RECEIVED]")

            print(packet)


# =========================
# MAIN
# =========================
if __name__ == "__main__":

    mode = input("server/client ? ")

    app = SecureChat()

    if mode == "server":
        app.start_server()
    else:
        app.connect()