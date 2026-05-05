import tkinter as tk
from tkinter import scrolledtext, messagebox
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ===== COLORS =====
BG = "#1e1e2e"
FG = "#ffffff"
ACCENT = "#6c5ce7"
GREEN = "#00b894"
BLUE = "#0984e3"
RED = "#d63031"
DARK = "#2d3436"

# ===== CRYPTO =====
def generate_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()

def hash_msg(msg):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(msg)
    return digest.finalize()

def sign(priv, h):
    return priv.sign(
        h,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify(pub, sig, h):
    try:
        pub.verify(
            sig, h,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def aes_encrypt(key, msg):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    enc = cipher.encryptor()
    return iv, enc.update(msg) + enc.finalize()

def aes_decrypt(key, iv, ct):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()

def encrypt_key(pub, key):
    return pub.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_key(priv, enc_key):
    return priv.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ===== USER =====
class User:
    def __init__(self, name):
        self.name = name
        self.private, self.public = generate_keys()

# ===== APP =====
class SecureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Chat")
        self.root.geometry("650x550")
        self.root.configure(bg=BG)

        self.users = {}
        self.current_user = None
        self.messages = []

        self.build_ui()
        self.dev_window()

    # ===== UI =====
    def build_ui(self):
        header = tk.Frame(self.root, bg=ACCENT)
        header.pack(fill="x")

        tk.Label(header, text="🔐 Secure Chat",
                 bg=ACCENT, fg="white",
                 font=("Arial", 18, "bold")).pack(pady=10)

        login_frame = tk.Frame(self.root, bg=BG)
        login_frame.pack(pady=10)

        self.username_entry = tk.Entry(login_frame)
        self.username_entry.grid(row=0, column=0, padx=5)

        tk.Button(login_frame, text="Login",
                  bg=ACCENT, fg="white",
                  command=self.login).grid(row=0, column=1)

        self.text_area = scrolledtext.ScrolledText(
            self.root, height=12,
            bg=DARK, fg=FG
        )
        self.text_area.pack(pady=10)

        msg_frame = tk.Frame(self.root, bg=BG)
        msg_frame.pack()

        self.msg_entry = tk.Entry(msg_frame, width=40)
        self.msg_entry.grid(row=0, column=0, padx=5)

        self.receiver_entry = tk.Entry(msg_frame, width=20)
        self.receiver_entry.grid(row=0, column=1, padx=5)

        btn_frame = tk.Frame(self.root, bg=BG)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="📤 Envoyer",
                  bg=GREEN, fg="white",
                  width=15, command=self.send).grid(row=0, column=0, padx=10)

        tk.Button(btn_frame, text="📥 Recevoir",
                  bg=BLUE, fg="white",
                  width=15, command=self.receive).grid(row=0, column=1, padx=10)

    # ===== DEV PANEL =====
    def dev_window(self):
        self.dev = tk.Toplevel(self.root)
        self.dev.title("🧑‍💻 Dev Panel")
        self.dev.geometry("700x500")
        self.dev.configure(bg=BG)

        self.log = scrolledtext.ScrolledText(self.dev, height=10, bg=DARK, fg=FG)
        self.log.pack(pady=5)

        btn_frame = tk.Frame(self.dev, bg=BG)
        btn_frame.pack()

        tk.Button(btn_frame, text="🔑 Clés",
                  bg=ACCENT, fg="white",
                  command=self.show_keys).grid(row=0, column=0, padx=5)

        tk.Button(btn_frame, text="📬 Messages",
                  bg=BLUE, fg="white",
                  command=self.show_messages).grid(row=0, column=1, padx=5)

        tk.Button(btn_frame, text="⚠️ Attaque",
                  bg=RED, fg="white",
                  command=self.attack_message).grid(row=0, column=2, padx=5)

    def log_dev(self, txt):
        self.log.insert(tk.END, txt + "\n")
        self.log.see(tk.END)

    # ===== LOGIN =====
    def login(self):
        name = self.username_entry.get()

        if name not in self.users:
            self.users[name] = User(name)
            self.log_dev(f"[KEY GEN] {name} généré")

        self.current_user = self.users[name]
        self.text_area.insert(tk.END, f"Connecté: {name}\n")

    # ===== SEND =====
    def send(self):
        if not self.current_user:
            return

        receiver_name = self.receiver_entry.get()
        if receiver_name not in self.users:
            messagebox.showerror("Erreur", "Utilisateur inconnu")
            return

        receiver = self.users[receiver_name]
        msg = self.msg_entry.get().encode()

        aes_key = os.urandom(32)
        iv, ct = aes_encrypt(aes_key, msg)
        h = hash_msg(msg)
        sig = sign(self.current_user.private, h)
        enc_key = encrypt_key(receiver.public, aes_key)

        package = {
            "ct": ct,
            "iv": iv,
            "key": enc_key,
            "sig": sig,
            "sender": self.current_user.name,
            "receiver": receiver_name
        }

        self.messages.append(package)
        self.text_area.insert(tk.END, f"📤 envoyé à {receiver_name}\n")

    # ===== RECEIVE =====
    def receive(self):
        if not self.current_user:
            return

        for i, p in enumerate(self.messages):
            if p["receiver"] == self.current_user.name:
                sender = self.users[p["sender"]]

                aes_key = decrypt_key(self.current_user.private, p["key"])
                msg = aes_decrypt(aes_key, p["iv"], p["ct"])

                valid = verify(sender.public, p["sig"], hash_msg(msg))

                self.text_area.insert(tk.END, f"📥 {msg}\n")
                self.text_area.insert(tk.END, f"✔ Signature: {valid}\n")

                if not valid:
                    self.log_dev("🚨 attaque détectée")

                self.messages.pop(i)
                return

    # ===== DEV =====
    def show_keys(self):
        win = tk.Toplevel(self.dev)
        text = scrolledtext.ScrolledText(win)
        text.pack()

        for name, u in self.users.items():
            pub = u.public.public_numbers()
            priv = u.private.private_numbers()

            text.insert(tk.END, f"{name}\n")
            text.insert(tk.END, f"(n,e)=({pub.n},{pub.e})\n")
            text.insert(tk.END, f"(n,d)=({priv.public_numbers.n},{priv.d})\n\n")

    def show_messages(self):
        self.msg_win = tk.Toplevel(self.dev)
        self.listbox = tk.Listbox(self.msg_win, width=60)
        self.listbox.pack()

        for i, m in enumerate(self.messages):
            self.listbox.insert(tk.END, f"{i}: {m['sender']} → {m['receiver']}")

    # ===== ATTACK =====
    def attack_message(self):
        if not hasattr(self, "listbox"):
            self.log_dev("⚠️ Ouvre d'abord 'Messages en attente'")
            return

        try:
            idx = self.listbox.curselection()[0]
        except:
            self.log_dev("⚠️ Aucun message sélectionné")
            return

        attack_win = tk.Toplevel(self.dev)
        attack_win.title("Choisir attaque")
        attack_win.geometry("300x250")

        tk.Label(attack_win, text="Type d'attaque :", font=("Arial", 12, "bold")).pack(pady=10)

        def do_attack(type_attack):
            msg = self.messages[idx]

            # ===== AVANT =====
            self.log_dev(f"[BEFORE ATTACK] {msg}")

            if type_attack == "msg":
                msg["ct"] = b"ATTACKED"
                self.log_dev(f"[ATTACK] Message {idx} modifié")

            elif type_attack == "sig":
                msg["sig"] = b"FAKE_SIGNATURE"
                self.log_dev(f"[ATTACK] Signature {idx} modifiée")

            elif type_attack == "key":
                msg["key"] = b"FAKE_KEY"
                self.log_dev(f"[ATTACK] Clé AES {idx} modifiée")

            elif type_attack == "replay":
                self.messages.append(msg.copy())
                self.log_dev(f"[ATTACK] Replay du message {idx}")

            # ===== APRÈS =====
            self.log_dev(f"[AFTER ATTACK] {self.messages[idx]}")

            attack_win.destroy()

        tk.Button(attack_win, text="🟥 Modifier message",
                  bg="#d63031", fg="white",
                  command=lambda: do_attack("msg")).pack(pady=5)

        tk.Button(attack_win, text="🟧 Modifier signature",
                  bg="#e17055", fg="white",
                  command=lambda: do_attack("sig")).pack(pady=5)

        tk.Button(attack_win, text="🟨 Modifier clé AES",
                  bg="#fdcb6e", fg="black",
                  command=lambda: do_attack("key")).pack(pady=5)

        tk.Button(attack_win, text="🟩 Replay attack",
                  bg="#00b894", fg="white",
                  command=lambda: do_attack("replay")).pack(pady=5)

# ===== RUN =====
root = tk.Tk()
app = SecureApp(root)
root.mainloop()