import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import os
import socket
import threading
import json
import base64
import struct
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ===== COLORS =====
BG      = "#1e1e2e"
FG      = "#cdd6f4"
ACCENT  = "#7c3aed"
ACCENT2 = "#a855f7"
GREEN   = "#00b894"
BLUE    = "#3b82f6"
RED     = "#ef4444"
ORANGE  = "#f97316"
YELLOW  = "#eab308"
DARK    = "#181825"
PANEL   = "#24273a"
BORDER  = "#313244"
GRAY    = "#6c7086"
SUBTEXT = "#a6adc8"

DEFAULT_PORT = 9999

# ============================================================
# CRYPTO
# ============================================================
def generate_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()

def pub_to_bytes(pub):
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)

def pub_from_bytes(data):
    return serialization.load_pem_public_key(data)

def hash_msg(msg):
    d = hashes.Hash(hashes.SHA256())
    d.update(msg)
    return d.finalize()

def sign_msg(priv, h):
    return priv.sign(h,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

def verify_sig(pub, sig, h):
    try:
        pub.verify(sig, h,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except:
        return False

def aes_encrypt(key, msg):
    iv = os.urandom(16)
    c = Cipher(algorithms.AES(key), modes.CFB(iv))
    e = c.encryptor()
    return iv, e.update(msg) + e.finalize()

def aes_decrypt(key, iv, ct):
    c = Cipher(algorithms.AES(key), modes.CFB(iv))
    d = c.decryptor()
    return d.update(ct) + d.finalize()

def rsa_encrypt(pub, data):
    return pub.encrypt(data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))

def rsa_decrypt(priv, data):
    return priv.decrypt(data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))

def b64e(b): return base64.b64encode(b).decode()
def b64d(s): return base64.b64decode(s)

# ============================================================
# NETWORK
# ============================================================
def send_pkt(sock, data):
    raw = json.dumps(data).encode()
    sock.sendall(struct.pack(">I", len(raw)) + raw)

def recv_pkt(sock):
    hdr = _recv_n(sock, 4)
    if not hdr: return None
    n = struct.unpack(">I", hdr)[0]
    raw = _recv_n(sock, n)
    if not raw: return None
    return json.loads(raw.decode())

def _recv_n(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: return None
        buf += chunk
    return buf

# ============================================================
# USER
# ============================================================
class User:
    def __init__(self, name):
        self.name = name
        self.private, self.public = generate_keys()

# ============================================================
# SERVER
# ============================================================
class ChatServer:
    def __init__(self, host="0.0.0.0", port=DEFAULT_PORT, log_cb=None):
        self.host = host
        self.port = port
        self.log = log_cb or print
        self.clients = {}
        self.running = False
        self.sock = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(10)
        self.running = True
        self.log(f"[SERVER] Ecoute sur {self.host}:{self.port}")
        threading.Thread(target=self._accept, daemon=True).start()

    def stop(self):
        self.running = False
        if self.sock: self.sock.close()

    def _accept(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
                self.log(f"[SERVER] Connexion de {addr[0]}:{addr[1]}")
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
            except: break

    def _handle(self, conn):
        name = None
        try:
            while True:
                pkt = recv_pkt(conn)
                if not pkt: break
                cmd = pkt.get("cmd")

                if cmd == "register":
                    name = pkt["name"]
                    self.clients[name] = {"sock": conn, "pub": b64d(pkt["pub"])}
                    self.log(f"[SERVER] {name} enregistre")
                    self._broadcast_users()
                    send_pkt(conn, {"cmd": "ok"})

                elif cmd == "get_pub":
                    t = pkt["target"]
                    if t in self.clients:
                        send_pkt(conn, {"cmd": "pub_key", "name": t,
                                        "pub": b64e(self.clients[t]["pub"])})
                    else:
                        send_pkt(conn, {"cmd": "error", "msg": "Introuvable"})

                elif cmd == "msg":
                    rcv = pkt["receiver"]
                    if rcv in self.clients:
                        send_pkt(self.clients[rcv]["sock"],
                                 {"cmd": "incoming", "package": pkt["package"]})
                        send_pkt(conn, {"cmd": "ok"})
                        self.log(f"[SERVER] {pkt['package']['sender']} -> {rcv}")
                    else:
                        send_pkt(conn, {"cmd": "error", "msg": "Hors ligne"})

        except Exception as e:
            self.log(f"[SERVER] Erreur: {e}")
        finally:
            if name and name in self.clients:
                del self.clients[name]
                self.log(f"[SERVER] {name} deconnecte")
                self._broadcast_users()
            conn.close()

    def _broadcast_users(self):
        ul = list(self.clients.keys())
        for c in self.clients.values():
            try: send_pkt(c["sock"], {"cmd": "users", "list": ul})
            except: pass

# ============================================================
# CLIENT
# ============================================================
class ChatClient:
    def __init__(self, user, host, port, on_msg_cb, on_users_cb, log_cb):
        self.user = user
        self.host = host
        self.port = port
        self.on_msg = on_msg_cb
        self.on_users = on_users_cb
        self.log = log_cb
        self.sock = None
        self.connected = False
        self._last_resp = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.connected = True
        send_pkt(self.sock, {
            "cmd": "register",
            "name": self.user.name,
            "pub": b64e(pub_to_bytes(self.user.public))
        })
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def disconnect(self):
        self.connected = False
        if self.sock: self.sock.close()

    def _recv_loop(self):
        while self.connected:
            try:
                pkt = recv_pkt(self.sock)
                if not pkt: break
                cmd = pkt.get("cmd")
                if cmd == "incoming":
                    self.on_msg(pkt["package"])
                elif cmd == "users":
                    self.on_users(pkt["list"])
                else:
                    self._last_resp = pkt
            except: break
        self.connected = False
        self.log("[NET] Deconnecte")

    def get_remote_pub(self, name):
        self._last_resp = None
        send_pkt(self.sock, {"cmd": "get_pub", "target": name})
        for _ in range(50):
            if self._last_resp and self._last_resp.get("cmd") == "pub_key":
                return pub_from_bytes(b64d(self._last_resp["pub"]))
            time.sleep(0.1)
        return None

    def send_message(self, receiver, plaintext: bytes):
        pub = self.get_remote_pub(receiver)
        if not pub:
            self.log("[NET] Cle publique introuvable")
            return False
        aes_key = os.urandom(32)
        iv, ct = aes_encrypt(aes_key, plaintext)
        h = hash_msg(plaintext)
        sig = sign_msg(self.user.private, h)
        enc_key = rsa_encrypt(pub, aes_key)
        pkg = {
            "ct": b64e(ct), "iv": b64e(iv),
            "key": b64e(enc_key), "sig": b64e(sig),
            "sender": self.user.name, "receiver": receiver
        }
        send_pkt(self.sock, {"cmd": "msg", "receiver": receiver, "package": pkg})
        return True

# ============================================================
# APP
# ============================================================
class SecureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        self.root.configure(bg=BG)
        self.root.resizable(True, True)

        self.server = None
        self.client = None
        self.current_user = None
        self.online_users = []
        self.intercepted = []

        self._build_main_window()
        self._show_connect_dialog()

    # ----------------------------------------------------------
    # MAIN WINDOW
    # ----------------------------------------------------------
    def _build_main_window(self):
        self.root.geometry("1200x700")
        self.root.minsize(900, 500)

        # TOP BAR
        topbar = tk.Frame(self.root, bg=DARK, height=44)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        tk.Label(topbar, text="Secure Chat",
                 bg=DARK, fg=FG, font=("Courier", 14, "bold")).pack(side="left", padx=16)

        self.conn_label = tk.Label(topbar, text="Non connecte",
                                   bg=DARK, fg=RED, font=("Courier", 10))
        self.conn_label.pack(side="right", padx=16)

        self.mode_label = tk.Label(topbar, text="",
                                   bg=DARK, fg=GRAY, font=("Courier", 9))
        self.mode_label.pack(side="right", padx=4)

        # PANED WINDOW
        self.paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL,
                               bg=BORDER, sashwidth=5, sashrelief="flat",
                               handlesize=0)
        self.paned.pack(fill="both", expand=True)

        self._build_chat_panel(self.paned)
        self._build_dev_panel(self.paned)

    # ----------------------------------------------------------
    # CHAT PANEL (left)
    # ----------------------------------------------------------
    def _build_chat_panel(self, parent):
        chat_frame = tk.Frame(parent, bg=BG)
        parent.add(chat_frame, minsize=400, width=680)

        # Sidebar users
        sidebar = tk.Frame(chat_frame, bg=PANEL, width=155)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="EN LIGNE",
                 bg=PANEL, fg=GRAY, font=("Courier", 8, "bold")).pack(
                     pady=(14, 4), padx=10, anchor="w")

        self.users_lb = tk.Listbox(
            sidebar, bg=PANEL, fg=GREEN,
            font=("Courier", 10), relief="flat", bd=0,
            selectbackground=ACCENT, selectforeground="white",
            activestyle="none", highlightthickness=0)
        self.users_lb.pack(fill="both", expand=True, padx=4)
        self.users_lb.bind("<Double-Button-1>", self._pick_user)

        tk.Label(sidebar, text="Double-clic pour selectionner",
                 bg=PANEL, fg=GRAY, font=("Courier", 7),
                 wraplength=140, justify="left").pack(pady=8, padx=8, anchor="w")

        # Chat area
        chat_right = tk.Frame(chat_frame, bg=BG)
        chat_right.pack(side="left", fill="both", expand=True)

        self.chat_area = scrolledtext.ScrolledText(
            chat_right, bg=DARK, fg=FG,
            font=("Courier", 10), relief="flat",
            wrap=tk.WORD, state="disabled",
            padx=12, pady=10)
        self.chat_area.pack(fill="both", expand=True)

        self.chat_area.tag_config("sent",    foreground=BLUE)
        self.chat_area.tag_config("recv",    foreground=GREEN)
        self.chat_area.tag_config("system",  foreground=GRAY)
        self.chat_area.tag_config("sig_ok",  foreground=GREEN)
        self.chat_area.tag_config("sig_bad", foreground=RED)
        self.chat_area.tag_config("error",   foreground=RED)

        # Compose bar
        compose = tk.Frame(chat_right, bg=PANEL, height=50)
        compose.pack(fill="x")
        compose.pack_propagate(False)

        tk.Label(compose, text="A :", bg=PANEL, fg=SUBTEXT,
                 font=("Courier", 10)).pack(side="left", padx=(10, 2))

        self.to_entry = tk.Entry(
            compose, width=13, bg=DARK, fg=FG,
            insertbackground=FG, font=("Courier", 10),
            relief="flat", bd=4)
        self.to_entry.pack(side="left", padx=(0, 8), pady=10)

        self.msg_entry = tk.Entry(
            compose, bg=DARK, fg=FG,
            insertbackground=FG, font=("Courier", 10),
            relief="flat", bd=4)
        self.msg_entry.pack(side="left", fill="x", expand=True, pady=10)
        self.msg_entry.bind("<Return>", lambda e: self._send())

        tk.Button(
            compose, text=" Envoyer ", bg=ACCENT, fg="white",
            font=("Courier", 10, "bold"), relief="flat", bd=0,
            activebackground=ACCENT2, activeforeground="white",
            cursor="hand2", command=self._send
        ).pack(side="left", padx=8, pady=10)

    # ----------------------------------------------------------
    # DEV PANEL (right)
    # ----------------------------------------------------------
    def _build_dev_panel(self, parent):
        dev_frame = tk.Frame(parent, bg=PANEL)
        parent.add(dev_frame, minsize=320, width=520)

        tk.Label(dev_frame, text="Dev Panel",
                 bg=PANEL, fg=ACCENT2,
                 font=("Courier", 12, "bold")).pack(pady=(10, 4), padx=12, anchor="w")

        # Notebook style
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dev.TNotebook",
                         background=PANEL, borderwidth=0, tabmargins=0)
        style.configure("Dev.TNotebook.Tab",
                         background=DARK, foreground=SUBTEXT,
                         font=("Courier", 9), padding=[10, 5])
        style.map("Dev.TNotebook.Tab",
                  background=[("selected", BORDER)],
                  foreground=[("selected", FG)])

        nb = ttk.Notebook(dev_frame, style="Dev.TNotebook")
        nb.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        # ── Tab 1: Logs ──────────────────────────────────────
        log_tab = tk.Frame(nb, bg=DARK)
        nb.add(log_tab, text="  Logs  ")

        self.log_area = scrolledtext.ScrolledText(
            log_tab, bg=DARK, fg=SUBTEXT,
            font=("Courier", 9), relief="flat",
            wrap=tk.WORD, padx=6, pady=6)
        self.log_area.pack(fill="both", expand=True)
        self.log_area.tag_config("srv",    foreground="#89b4fa")
        self.log_area.tag_config("net",    foreground="#a6e3a1")
        self.log_area.tag_config("attack", foreground=RED)
        self.log_area.tag_config("warn",   foreground=ORANGE)

        tk.Button(log_tab, text="Effacer", bg=DARK, fg=GRAY,
                  font=("Courier", 8), relief="flat",
                  command=lambda: self.log_area.delete("1.0", tk.END)
                  ).pack(anchor="e", padx=6, pady=2)

        # ── Tab 2: Interceptes ───────────────────────────────
        msg_tab = tk.Frame(nb, bg=DARK)
        nb.add(msg_tab, text="  Interceptes  ")

        self.intercept_lb = tk.Listbox(
            msg_tab, bg=DARK, fg=FG,
            font=("Courier", 9), relief="flat", bd=0,
            selectbackground=ACCENT, selectforeground="white",
            activestyle="none", highlightthickness=0)
        self.intercept_lb.pack(fill="both", expand=True, padx=6, pady=6)

        tk.Button(
            msg_tab, text="Lancer une attaque", bg=RED, fg="white",
            font=("Courier", 10, "bold"), relief="flat", bd=0,
            cursor="hand2", command=self._attack_dialog
        ).pack(fill="x", padx=6, pady=(0, 6), ipady=4)

        # ── Tab 3: Cles ──────────────────────────────────────
        keys_tab = tk.Frame(nb, bg=DARK)
        nb.add(keys_tab, text="  Cles  ")

        self.keys_area = scrolledtext.ScrolledText(
            keys_tab, bg=DARK, fg=SUBTEXT,
            font=("Courier", 8), relief="flat",
            wrap=tk.WORD, padx=6, pady=6)
        self.keys_area.pack(fill="both", expand=True)

        tk.Button(keys_tab, text="Rafraichir", bg=DARK, fg=GRAY,
                  font=("Courier", 8), relief="flat",
                  command=self._refresh_keys
                  ).pack(anchor="e", padx=6, pady=2)

        # ── Tab 4: Reseau ────────────────────────────────────
        net_tab = tk.Frame(nb, bg=DARK)
        nb.add(net_tab, text="  Reseau  ")

        self.net_area = scrolledtext.ScrolledText(
            net_tab, bg=DARK, fg=SUBTEXT,
            font=("Courier", 9), relief="flat",
            wrap=tk.WORD, padx=8, pady=8)
        self.net_area.pack(fill="both", expand=True)
        self.net_area.tag_config("title", foreground=ACCENT2,
                                  font=("Courier", 10, "bold"))
        self.net_area.tag_config("key",   foreground=BLUE)
        self.net_area.tag_config("val",   foreground=FG)

        tk.Button(net_tab, text="Rafraichir", bg=DARK, fg=GRAY,
                  font=("Courier", 8), relief="flat",
                  command=self._refresh_net
                  ).pack(anchor="e", padx=6, pady=2)

    # ----------------------------------------------------------
    # CONNECT DIALOG
    # ----------------------------------------------------------
    def _show_connect_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Connexion")
        dlg.geometry("420x340")
        dlg.configure(bg=BG)
        dlg.grab_set()
        dlg.resizable(False, False)

        dlg.update_idletasks()
        sw = dlg.winfo_screenwidth()
        sh = dlg.winfo_screenheight()
        dlg.geometry(f"+{sw//2-210}+{sh//2-170}")

        tk.Label(dlg, text="Secure Chat", bg=BG, fg=ACCENT2,
                 font=("Courier", 18, "bold")).pack(pady=(20, 4))
        tk.Label(dlg, text="Choisissez votre mode de connexion",
                 bg=BG, fg=GRAY, font=("Courier", 9)).pack(pady=(0, 16))

        mode_var = tk.StringVar(value="server")
        mode_f = tk.Frame(dlg, bg=BG)
        mode_f.pack()
        for val, txt in [("server", "Creer un serveur"), ("client", "Rejoindre")]:
            tk.Radiobutton(
                mode_f, text=txt, variable=mode_var, value=val,
                bg=BG, fg=FG, selectcolor=DARK,
                activebackground=BG, activeforeground=ACCENT2,
                font=("Courier", 10)).pack(side="left", padx=14)

        tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x", padx=20, pady=10)

        fields = tk.Frame(dlg, bg=BG)
        fields.pack(pady=4)

        def lbl(row, text):
            tk.Label(fields, text=text, bg=BG, fg=SUBTEXT,
                     font=("Courier", 10), anchor="e", width=13
                     ).grid(row=row, column=0, sticky="e", padx=6, pady=5)

        def ent(row, default=""):
            e = tk.Entry(fields, font=("Courier", 10), bg=PANEL, fg=FG,
                         insertbackground=FG, relief="flat", bd=6, width=20)
            e.insert(0, default)
            e.grid(row=row, column=1, pady=5)
            return e

        lbl(0, "Pseudo :");    e_name = ent(0)
        lbl(1, "IP Serveur :"); e_ip   = ent(1, "127.0.0.1")
        lbl(2, "Port :");       e_port = ent(2, str(DEFAULT_PORT))

        def on_ok():
            name = e_name.get().strip()
            ip   = e_ip.get().strip()
            try:
                port = int(e_port.get().strip())
            except:
                messagebox.showerror("Erreur", "Port invalide", parent=dlg)
                return
            if not name:
                messagebox.showerror("Erreur", "Entrez un pseudo", parent=dlg)
                return

            self.current_user = User(name)

            if mode_var.get() == "server":
                self.server = ChatServer(
                    host="0.0.0.0", port=port,
                    log_cb=lambda t: self.root.after(
                        0, lambda t=t: self._log(t, "srv")))
                try:
                    self.server.start()
                except Exception as ex:
                    messagebox.showerror("Erreur serveur", str(ex), parent=dlg)
                    return
                self._connect_client("127.0.0.1", port)
                self.mode_label.config(text="[SERVEUR]")
            else:
                self._connect_client(ip, port)
                self.mode_label.config(text=f"[CLIENT -> {ip}:{port}]")

            dlg.destroy()
            self.conn_label.config(text=f"Connecte: {name}", fg=GREEN)
            self.root.title(f"Secure Chat — {name}")
            self._chat_write(f"Connecte en tant que {name}\n", "system")
            self._refresh_net()

        tk.Button(
            dlg, text="  Connexion  ", bg=ACCENT, fg="white",
            font=("Courier", 12, "bold"), relief="flat", bd=0,
            activebackground=ACCENT2, cursor="hand2",
            command=on_ok).pack(pady=14)

    # ----------------------------------------------------------
    # CLIENT CONNECT
    # ----------------------------------------------------------
    def _connect_client(self, ip, port):
        self.client = ChatClient(
            user=self.current_user,
            host=ip, port=port,
            on_msg_cb=lambda pkg: self.root.after(
                0, lambda p=pkg: self._on_incoming(p)),
            on_users_cb=lambda ul: self.root.after(
                0, lambda u=ul: self._on_users(u)),
            log_cb=lambda t: self.root.after(
                0, lambda t=t: self._log(t, "net"))
        )
        try:
            self.client.connect()
        except Exception as ex:
            messagebox.showerror("Erreur connexion", str(ex))

    # ----------------------------------------------------------
    # INCOMING MESSAGE
    # ----------------------------------------------------------
    def _on_incoming(self, pkg):
        self.intercepted.append(pkg)
        self.intercept_lb.insert(
            tk.END, f"{len(self.intercepted)-1}: {pkg['sender']} -> {pkg['receiver']}")

        sender = pkg["sender"]
        self._log(f"[RECV] Paquet de {sender}", "net")
        try:
            aes_key = rsa_decrypt(self.current_user.private, b64d(pkg["key"]))
            plain   = aes_decrypt(aes_key, b64d(pkg["iv"]), b64d(pkg["ct"]))
            h       = hash_msg(plain)
            spub    = self.client.get_remote_pub(sender)
            valid   = verify_sig(spub, b64d(pkg["sig"]), h) if spub else False

            self._chat_write(f"[{sender}]: ", "recv")
            self._chat_write(plain.decode() + "\n", "recv")
            if valid:
                self._chat_write("   Signature valide\n", "sig_ok")
            else:
                self._chat_write("   Signature INVALIDE\n", "sig_bad")
                self._log("ATTAQUE DETECTEE — signature invalide!", "attack")

        except Exception as e:
            self._chat_write(f"Dechiffrement echoue: {e}\n", "error")
            self._log(f"[ERROR] {e}", "warn")

    # ----------------------------------------------------------
    # USERS UPDATE
    # ----------------------------------------------------------
    def _on_users(self, ul):
        self.online_users = ul
        self.users_lb.delete(0, tk.END)
        for u in ul:
            suffix = "  (moi)" if self.current_user and u == self.current_user.name else ""
            self.users_lb.insert(tk.END, f"  {u}{suffix}")
        self._refresh_net()

    # ----------------------------------------------------------
    # SEND
    # ----------------------------------------------------------
    def _send(self):
        if not self.client or not self.client.connected:
            messagebox.showwarning("Non connecte", "Connectez-vous d'abord")
            return
        to   = self.to_entry.get().strip()
        text = self.msg_entry.get().strip()
        if not to or not text:
            return
        if to == self.current_user.name:
            messagebox.showwarning("Erreur", "Vous ne pouvez pas vous ecrire a vous-meme")
            return
        self.msg_entry.delete(0, tk.END)

        def _do():
            ok = self.client.send_message(to, text.encode())
            if ok:
                self.root.after(0, lambda: self._chat_write(
                    f"[moi -> {to}]: {text}\n", "sent"))
            else:
                self.root.after(0, lambda: messagebox.showerror("Erreur", "Envoi echoue"))

        threading.Thread(target=_do, daemon=True).start()

    def _pick_user(self, event):
        sel = self.users_lb.curselection()
        if sel:
            name = self.users_lb.get(sel[0]).strip().split("  (moi)")[0]
            self.to_entry.delete(0, tk.END)
            self.to_entry.insert(0, name)

    # ----------------------------------------------------------
    # HELPERS
    # ----------------------------------------------------------
    def _chat_write(self, text, tag=""):
        self.chat_area.config(state="normal")
        self.chat_area.insert(tk.END, text, tag)
        self.chat_area.see(tk.END)
        self.chat_area.config(state="disabled")

    def _log(self, text, tag=""):
        self.log_area.insert(tk.END, text + "\n", tag)
        self.log_area.see(tk.END)

    def _refresh_keys(self):
        self.keys_area.delete("1.0", tk.END)
        if not self.current_user:
            self.keys_area.insert(tk.END, "Non connecte\n")
            return
        u = self.current_user
        pub  = u.public.public_numbers()
        priv = u.private.private_numbers()
        self.keys_area.insert(tk.END, f"=== {u.name} ===\n\n")
        self.keys_area.insert(tk.END, "[PUBLIC]\n")
        self.keys_area.insert(tk.END, f"  e = {pub.e}\n")
        self.keys_area.insert(tk.END, f"  n = {str(pub.n)[:80]}...\n\n")
        self.keys_area.insert(tk.END, "[PRIVE]\n")
        self.keys_area.insert(tk.END, f"  d = {str(priv.d)[:80]}...\n")

    def _refresh_net(self):
        self.net_area.delete("1.0", tk.END)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "127.0.0.1"

        def row(k, v):
            self.net_area.insert(tk.END, f"  {k:<18}", "key")
            self.net_area.insert(tk.END, f"{v}\n", "val")

        if self.server:
            self.net_area.insert(tk.END, "MODE SERVEUR\n\n", "title")
            row("IP locale :", local_ip)
            row("Port :", str(self.server.port))
            row("Clients connectes :", str(list(self.server.clients.keys())))
            self.net_area.insert(tk.END,
                "\nPartagez cette IP avec les autres\nutilisateurs.\n", "key")
        elif self.client:
            self.net_area.insert(tk.END, "MODE CLIENT\n\n", "title")
            row("Serveur :", f"{self.client.host}:{self.client.port}")
            row("Pseudo :", self.current_user.name if self.current_user else "—")
            row("Statut :", "connecte" if self.client.connected else "deconnecte")
        else:
            self.net_area.insert(tk.END, "Non connecte\n", "key")

    # ----------------------------------------------------------
    # ATTACK DIALOG
    # ----------------------------------------------------------
    def _attack_dialog(self):
        sel = self.intercept_lb.curselection()
        if not sel:
            self._log("Selectionne un message dans la liste", "warn")
            return
        idx = sel[0]
        pkg = self.intercepted[idx]

        dlg = tk.Toplevel(self.root)
        dlg.title("Attaque")
        dlg.geometry("320x290")
        dlg.configure(bg=BG)
        dlg.resizable(False, False)

        tk.Label(dlg, text=f"Message {idx}  |  {pkg['sender']} -> {pkg['receiver']}",
                 bg=BG, fg=SUBTEXT, font=("Courier", 8)).pack(pady=(12, 2))
        tk.Label(dlg, text="Choisir le type d'attaque",
                 bg=BG, fg=FG, font=("Courier", 11, "bold")).pack(pady=(0, 12))

        def attack(t):
            self._log(f"[BEFORE] {pkg['sender']}->{pkg['receiver']}  ct={pkg['ct'][:16]}...", "warn")
            if t == "msg":
                pkg["ct"] = b64e(b"ATTACKED_CONTENT_XXX")
                self._log("[ATTACK] Ciphertext modifie", "attack")
            elif t == "sig":
                pkg["sig"] = b64e(b"FAKE_SIGNATURE_XXX")
                self._log("[ATTACK] Signature falsifiee", "attack")
            elif t == "key":
                pkg["key"] = b64e(b"FAKE_AES_KEY_XXX")
                self._log("[ATTACK] Cle AES modifiee", "attack")
            elif t == "replay":
                copy = dict(pkg)
                self.intercepted.append(copy)
                self.intercept_lb.insert(tk.END,
                    f"{len(self.intercepted)-1}: [REPLAY] {copy['sender']} -> {copy['receiver']}")
                self._on_incoming(copy)
                self._log("[ATTACK] Replay injecte", "attack")
            self._log(f"[AFTER]  ct={pkg['ct'][:16]}...", "warn")
            dlg.destroy()

        btns = [
            ("Modifier le message (ct)",  "msg",    "#dc2626"),
            ("Falsifier la signature",    "sig",    "#ea580c"),
            ("Remplacer la cle AES",      "key",    "#ca8a04"),
            ("Replay attack",             "replay", "#16a34a"),
        ]
        for label, typ, color in btns:
            tk.Button(
                dlg, text=label, bg=color, fg="white",
                font=("Courier", 10), relief="flat", bd=0,
                activebackground=color, cursor="hand2",
                command=lambda t=typ: attack(t)
            ).pack(fill="x", padx=20, pady=4, ipady=6)

# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureApp(root)
    root.mainloop()  
