"""
Educational Cryptography Suite - Cyberpunk Neon Edition
Version COMPLÈTE - Avec affichage détaillé des étapes (XOR, matrices, rounds)
"""

import customtkinter as ctk
from tkinter import messagebox
import time
import threading
try:
    import winsound
    HAS_SOUND = True
except ImportError:
    HAS_SOUND = False
import random
import math
import tkinter as tk

# ============ IMPORTS DES ALGORITHMES ============
from algorithms.caesar import CaesarAlgorithm
from algorithms.vigenere import VigenereAlgorithm
from algorithms.affine import AffineAlgorithm
from algorithms.playfair import PlayfairAlgorithm
from algorithms.hill import HillAlgorithm
from algorithms.Otp import OTPAlgorithm

from algorithms.rc4 import RC4Algorithm
from algorithms.des import DESAlgorithm
from algorithms.aes import AESAlgorithm
from algorithms.twofish import TwofishAlgorithm
from algorithms.serpent import SerpentAlgorithm

from algorithms.rsa import RSAAlgorithm
from algorithms.Dh import DHAlgorithm
from algorithms.ecc import ECCAlgorithm
from algorithms.elgamal import ElGamalAlgorithm

from algorithms.rsa_signature import RSASignatureAlgorithm
from algorithms.elgamal_signature import ElGamalSignatureAlgorithm
from algorithms.dsa_ecdsa import DSAAlgorithm, ECDSAAlgorithm, Ed25519Algorithm

from algorithms.md5 import MD5Algorithm
from algorithms.sha256 import SHA256Algorithm
from algorithms.sha512 import SHA512Algorithm


# ============ STYLE CYBERPUNK NEON ============
COLORS = {
    "bg": "#0a0a0f",
    "bg_card": "#0d0d1a",
    "bg_darker": "#05050a",
    "card_hover": "#1a1a3a",
    "cyan": "#00f3ff",
    "cyan_dark": "#00b8c4",
    "magenta": "#ff00ff",
    "magenta_dark": "#cc00cc",
    "purple": "#8b00ff",
    "purple_dark": "#6600cc",
    "green": "#00ff88",
    "green_dark": "#00cc66",
    "yellow": "#ffcc00",
    "red": "#ff3366",
    "text": "#e0e0ff",
    "text_dim": "#8080aa",
    "border": "#1a1a3a",
    "orange": "#ff8800",
    "lime": "#aaff00",
    "pink": "#ff69b4",
    "gold": "#ffd700",
    "sky": "#87ceeb",
}

# Tags de couleur pour le log textbox
LOG_TAGS = {
    "header":   COLORS["cyan"],
    "round":    COLORS["magenta"],
    "xor":      COLORS["yellow"],
    "sbox":     COLORS["orange"],
    "perm":     COLORS["lime"],
    "key":      COLORS["sky"],
    "result":   COLORS["green"],
    "block":    COLORS["pink"],
    "normal":   COLORS["text"],
    "dim":      COLORS["text_dim"],
    "error":    COLORS["red"],
    "box":      COLORS["gold"],
    "kasiski":  COLORS["magenta"],
    "ic":       COLORS["orange"],
    "vigstep":  COLORS["cyan"],
}


def beep(*args):
    if not HAS_SOUND:
        return
    try:
        for freq, dur in args:
            winsound.Beep(freq, dur)
    except Exception:
        pass


def classify_log_line(line: str) -> str:
    """
    Détermine le tag de couleur d'une ligne de log.
    Couvre DES, AES, Vigenère et tous les autres algorithmes.
    """
    l = line.strip()

    # ── En-têtes encadrés (╔ ║ ╚) → cyan bold ─────────────────────────
    if any(x in l for x in ["╔", "╚", "║"]):
        return "header"

    # ── Résultats / succès ─────────────────────────────────────────────
    if any(x in l for x in ["✅", "Résultat final", "terminé",
                              "chiffré :", "déchiffré :", "COMPLETED",
                              "Clé récupérée :", "Longueur de clé estimée",
                              "Longueur de clé retenue"]):
        return "result"

    # ── XOR (DES, CBC, Vigenère formule) ──────────────────────────────
    if any(x in l for x in ["XOR", "xor", "⊕", "(P+K)", "(C-K)",
                              ")%26=", "+{k_val})", "-{k_val})"]):
        return "xor"

    # ── Vigenère : ligne lettre par lettre [  1] 'B'(1) ... ───────────
    if l.startswith("[") and "%" in l and "→" in l:
        return "vigstep"

    # ── Vigenère : Kasiski ─────────────────────────────────────────────
    if any(x in l for x in ["KASISKI", "Kasiski", "kasiski",
                              "Trigramme", "trigramme",
                              "PGCD", "distance", "Distance"]):
        return "kasiski"

    # ── Vigenère : IC ─────────────────────────────────────────────────
    if any(x in l for x in ["COÏNCIDENCE", "IC moyen", "IC français",
                              "Sous-séquence", "sous-séquence",
                              "lettre clé", "Indice de"]):
        return "ic"

    # ── Vigenère : clé étendue / texte préparé ────────────────────────
    if any(x in l for x in ["Mot-clé", "Texte prép", "Clé brute",
                              "Texte clair", "Texte chiffré"]):
        return "key"

    # ── S-Boxes (DES) ──────────────────────────────────────────────────
    if any(x in l for x in ["S1", "S2", "S3", "S4", "S5",
                              "S6", "S7", "S8", "S-Box", "S_Box",
                              "Substitution S"]):
        return "sbox"

    # ── Permutations / Expansions (DES, AES) ──────────────────────────
    if any(x in l for x in ["Permutation", "Expansion", "PC-1", "PC-2",
                              "IP", "IP⁻¹", "SubBytes", "ShiftRows",
                              "MixColumns", "AddRoundKey"]):
        return "perm"

    # ── Clés / Key Schedule ───────────────────────────────────────────
    if any(x in l for x in ["K01", "K02", "K03", "K04", "K05", "K06",
                              "K07", "K08", "K09", "K10", "K11", "K12",
                              "K13", "K14", "K15", "K16",
                              "sous-clé", "Key Schedule", "rotate",
                              "KEY SCHEDULE", "Clé (hex)", "Clé originale"]):
        return "key"

    # ── Rounds (DES, AES, Feistel) ────────────────────────────────────
    if any(x in l for x in ["Round", "round", "─── Round",
                              "══════ Round", "Feistel"]):
        return "round"

    # ── Blocs (DES ECB/CBC) ───────────────────────────────────────────
    if any(x in l for x in ["Bloc #", "BLOC #"]):
        return "block"

    # ── Boîtes / séparateurs ──────────────────────────────────────────
    if any(x in l for x in ["┌", "└", "├", "│", "─"]):
        return "box"

    # ── Erreurs ───────────────────────────────────────────────────────
    if any(x in l for x in ["❌", "⚠️", "ERREUR", "ERROR"]):
        return "error"

    return "normal"


class GlowButton(ctk.CTkButton):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<ButtonPress-1>", self.on_click)
        self.normal_color = kwargs.get("fg_color")

    def on_enter(self, e):
        if self.normal_color == COLORS["cyan"]:
            self.configure(fg_color=COLORS["cyan_dark"],
                           border_color=COLORS["cyan"], border_width=2)
        else:
            self.configure(fg_color=COLORS["magenta_dark"],
                           border_color=COLORS["magenta"], border_width=2)

    def on_leave(self, e):
        self.configure(fg_color=self.normal_color, border_width=0)

    def on_click(self, e):
        original_color = self.cget("fg_color")
        self.configure(fg_color=COLORS["yellow"])
        self.after(150, lambda: self.configure(fg_color=original_color))


class ResultCyberWindow:
    def __init__(self, parent, result, operation, algorithm_name):
        self.parent = parent
        self.result = result
        self.operation = operation
        self.algorithm_name = algorithm_name

        self.window = ctk.CTkToplevel(parent)
        self.window.title("✨ RÉSULTAT FINAL ✨")
        self.window.geometry("750x600")
        self.window.configure(fg_color=COLORS["bg_darker"])
        self.window.transient(parent)

        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (750 // 2)
        y = (self.window.winfo_screenheight() // 2) - (600 // 2)
        self.window.geometry(f"750x600+{x}+{y}")

        beep((1200, 100), (1500, 100), (1800, 200), (2000, 300))

        self.window.attributes('-alpha', 0)
        self.fade_in()
        self.setup_ui()
        self.window.after(200, self.explode_confetti)
        self.animate_glitch()

    def fade_in(self, alpha=0):
        if alpha < 1:
            alpha += 0.05
            self.window.attributes('-alpha', alpha)
            self.window.after(20, lambda: self.fade_in(alpha))

    def setup_ui(self):
        main_frame = ctk.CTkFrame(
            self.window, corner_radius=20, fg_color=COLORS["bg_card"],
            border_width=2, border_color=COLORS["cyan"]
        )
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(25, 10))

        self.success_icon = ctk.CTkLabel(
            header_frame, text="🎉", font=ctk.CTkFont(size=60))
        self.success_icon.pack()
        self.animate_icon()

        badge = ctk.CTkLabel(header_frame, text="⚡ SUCCÈS ⚡",
                             font=ctk.CTkFont(size=20, weight="bold"),
                             text_color=COLORS["cyan"])
        badge.pack(pady=(5, 0))

        operation_text = ("CHIFFREMENT" if self.operation == "encrypt"
                          else "DÉCHIFFREMENT")
        title = ctk.CTkLabel(header_frame,
                             text=f"{operation_text} COMPLET",
                             font=ctk.CTkFont(size=28, weight="bold"),
                             text_color=COLORS["magenta"])
        title.pack()

        algo_label = ctk.CTkLabel(
            header_frame,
            text=f"┌── {self.algorithm_name} ──┐",
            font=ctk.CTkFont(size=12, family="Consolas"),
            text_color=COLORS["text_dim"])
        algo_label.pack()

        result_frame = ctk.CTkFrame(
            main_frame, corner_radius=15, fg_color=COLORS["bg_darker"],
            border_width=2, border_color=COLORS["purple"])
        result_frame.pack(fill="both", expand=True, padx=25, pady=20)

        result_title = ctk.CTkLabel(
            result_frame, text="░▒▓█ RÉSULTAT FINAL █▓▒░",
            font=ctk.CTkFont(size=12, family="Consolas", weight="bold"),
            text_color=COLORS["green"])
        result_title.pack(pady=(15, 5))

        self.result_text = ctk.CTkTextbox(
            result_frame,
            font=ctk.CTkFont(size=13, family="Consolas"),
            corner_radius=8, wrap="word",
            fg_color=COLORS["bg_card"], height=150)
        self.result_text.pack(fill="both", expand=True, padx=15, pady=(5, 15))
        self.result_text.insert("1.0", self.result)
        self.result_text.configure(state="disabled")

        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(pady=(10, 25))

        copy_btn = ctk.CTkButton(
            btn_frame, text="[ 📋 COPIER ]",
            command=lambda: self.copy_result(self.result),
            fg_color="transparent", border_width=2,
            border_color=COLORS["cyan"],
            hover_color=COLORS["cyan_dark"],
            width=160, height=45,
            font=ctk.CTkFont(size=14, weight="bold"), corner_radius=10)
        copy_btn.pack(side="left", padx=15)

        close_btn = ctk.CTkButton(
            btn_frame, text="[ FERMER ]",
            command=self.window.destroy,
            fg_color="transparent", border_width=2,
            border_color=COLORS["magenta"],
            hover_color=COLORS["magenta_dark"],
            width=140, height=45,
            font=ctk.CTkFont(size=14, weight="bold"), corner_radius=10)
        close_btn.pack(side="left", padx=15)

    def animate_icon(self, count=0):
        icons = ["🎉", "✨", "🌟", "⭐", "🎊", "🏆"]
        if self.window.winfo_exists():
            self.success_icon.configure(text=icons[count % len(icons)])
            self.window.after(300, lambda: self.animate_icon(count + 1))

    def animate_glitch(self, count=0):
        if not self.window.winfo_exists():
            return
        if count % 15 == 0:
            self.window.configure(
                border_color=random.choice(
                    [COLORS["cyan"], COLORS["magenta"], COLORS["purple"]]
                )
            )
            self.window.after(
                100, lambda: self.window.configure(border_color=COLORS["cyan"])
            )
        self.window.after(500, lambda: self.animate_glitch(count + 1))

    def explode_confetti(self):
        if not self.window.winfo_exists():
            return
        colors = ["#ff00ff", "#00ffff", "#ff00ff", "#00ff88",
                  "#ffcc00", "#ff3366"]

        class Confetti:
            def __init__(self, canvas, x, y, color, angle, speed):
                self.canvas = canvas
                self.x      = x
                self.y      = y
                self.color  = color
                self.angle  = angle
                self.speed  = speed
                self.size   = random.randint(5, 12)
                self.life   = 100
                self.shape  = random.choice(["rect", "circle"])
                if self.shape == "rect":
                    self.id = canvas.create_rectangle(
                        x, y, x+self.size, y+self.size,
                        fill=color, outline="")
                else:
                    self.id = canvas.create_oval(
                        x, y, x+self.size, y+self.size,
                        fill=color, outline="")

            def update(self):
                self.x    += math.cos(self.angle) * self.speed
                self.y    += math.sin(self.angle) * self.speed + 1
                self.speed *= 0.98
                self.life  -= 2
                self.size   = max(2, self.size - 0.2)
                self.canvas.coords(
                    self.id, self.x, self.y,
                    self.x + self.size, self.y + self.size)
                if self.life <= 0 or self.y > 600:
                    self.canvas.delete(self.id)
                    return False
                return True

        canvas = tk.Canvas(self.window, bg="",
                           highlightthickness=0, bd=0)
        canvas.place(relwidth=1, relheight=1)
        canvas.lift()

        confettis = []
        for _ in range(200):
            angle = random.uniform(0, math.pi * 2)
            speed = random.uniform(5, 18)
            color = random.choice(colors)
            confettis.append(Confetti(canvas, 375, 300, color, angle, speed))

        def animate_confettis():
            still_alive = [c for c in confettis if c.update()]
            if still_alive and self.window.winfo_exists():
                self.window.after(20, animate_confettis)
            else:
                canvas.destroy()

        animate_confettis()

    def copy_result(self, text):
        self.parent.clipboard_clear()
        self.parent.clipboard_append(text)
        beep((1000, 50), (1200, 50))


# ============================================================
#   FENÊTRE DE TRAITEMENT AMÉLIORÉE — LOG COLORÉ DÉTAILLÉ
# ============================================================

class ProgressCyberWindow:
    """Fenêtre de traitement avec affichage coloré des étapes."""

    def __init__(self, parent, algorithm, operation, text, key,
                 update_result_callback):
        self.parent                 = parent
        self.algorithm              = algorithm
        self.operation              = operation
        self.text                   = text
        self.key                    = key
        self.update_result_callback = update_result_callback

        self.window = ctk.CTkToplevel(parent)
        self.window.title(
            f"[ {operation.upper()} PROCESS — DÉTAIL COMPLET ]")
        self.window.geometry("1100x820")
        self.window.minsize(900, 650)
        self.window.configure(fg_color=COLORS["bg_darker"])
        self.window.transient(parent)
        self.window.grab_set()

        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth()  // 2) - (1100 // 2)
        y = (self.window.winfo_screenheight() // 2) - (820  // 2)
        self.window.geometry(f"1100x820+{x}+{y}")

        self.window.attributes('-alpha', 0)
        self.fade_in()
        self.setup_ui()
        self.window.after(400, self.start_processing)

    def fade_in(self, alpha=0):
        if alpha < 1:
            alpha += 0.06
            self.window.attributes('-alpha', alpha)
            self.window.after(18, lambda: self.fade_in(alpha))

    def setup_ui(self):
        main_frame = ctk.CTkFrame(
            self.window, corner_radius=20, fg_color=COLORS["bg_card"],
            border_width=2, border_color=COLORS["cyan"])
        main_frame.pack(fill="both", expand=True, padx=15, pady=15)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(3, weight=1)

        # ── En-tête ──────────────────────────────────────────────────
        header_frame = ctk.CTkFrame(
            main_frame, fg_color=COLORS["bg_darker"],
            corner_radius=12, border_width=1,
            border_color=COLORS["purple"])
        header_frame.grid(row=0, column=0, sticky="ew",
                          padx=20, pady=(18, 8))

        op_text  = "ENCRYPT" if self.operation == "encrypt" else "DECRYPT"
        op_color = (COLORS["cyan"] if self.operation == "encrypt"
                    else COLORS["magenta"])

        ctk.CTkLabel(
            header_frame,
            text=f"  ⚡ {op_text}ING — {self.algorithm.get_name()}",
            font=ctk.CTkFont(size=15, weight="bold", family="Consolas"),
            text_color=op_color
        ).pack(anchor="w", padx=15, pady=(10, 3))

        text_preview = (self.text[:60] + "..."
                        if len(self.text) > 60 else self.text)
        ctk.CTkLabel(
            header_frame,
            text=f"  INPUT : {text_preview}",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=COLORS["text_dim"]
        ).pack(anchor="w", padx=15, pady=2)
        ctk.CTkLabel(
            header_frame,
            text=f"  KEY   : {self.key}",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=COLORS["text_dim"]
        ).pack(anchor="w", padx=15, pady=(2, 10))

        # ── Barre de progression ──────────────────────────────────────
        prog_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        prog_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 6))

        self.progress_bar = ctk.CTkProgressBar(
            prog_frame, height=12, corner_radius=6,
            fg_color=COLORS["bg_darker"],
            progress_color=COLORS["cyan"])
        self.progress_bar.pack(fill="x")
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(
            prog_frame, text="[>] INITIALIZING...",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=COLORS["cyan"])
        self.progress_label.pack(anchor="w", pady=(4, 0))

        # ── Légende des couleurs ──────────────────────────────────────
        legend_frame = ctk.CTkFrame(
            main_frame, fg_color=COLORS["bg_darker"],
            corner_radius=8, border_width=1,
            border_color=COLORS["border"])
        legend_frame.grid(row=2, column=0, sticky="new",
                          padx=20, pady=(0, 4))

        legend_inner = ctk.CTkFrame(legend_frame, fg_color="transparent")
        legend_inner.pack(fill="x", padx=12, pady=6)

        legend_items = [
            ("■ HEADER",   COLORS["cyan"]),
            ("■ ROUND",    COLORS["magenta"]),
            ("■ XOR",      COLORS["yellow"]),
            ("■ S-BOX",    COLORS["orange"]),
            ("■ PERMUT",   COLORS["lime"]),
            ("■ CLÉ",      COLORS["sky"]),
            ("■ RÉSULTAT", COLORS["green"]),
            ("■ KASISKI",  COLORS["magenta"]),
            ("■ IC",       COLORS["orange"]),
        ]
        for label, color in legend_items:
            ctk.CTkLabel(
                legend_inner, text=label,
                font=ctk.CTkFont(size=9, family="Consolas", weight="bold"),
                text_color=color
            ).pack(side="left", padx=5)

        # ── Zone de log principale ────────────────────────────────────
        log_outer = ctk.CTkFrame(
            main_frame, corner_radius=12, fg_color=COLORS["bg_darker"],
            border_width=1, border_color=COLORS["purple"])
        log_outer.grid(row=3, column=0, sticky="nsew", padx=20, pady=(0, 8))
        main_frame.grid_rowconfigure(3, weight=1)

        log_title_row = ctk.CTkFrame(log_outer, fg_color="transparent")
        log_title_row.pack(fill="x", padx=15, pady=(10, 4))

        ctk.CTkLabel(
            log_title_row,
            text="┌─[ DÉROULEMENT : XOR · ROUNDS · S-BOXES · VIGENÈRE ]─",
            font=ctk.CTkFont(size=12, weight="bold", family="Consolas"),
            text_color=COLORS["purple"]
        ).pack(side="left")

        ctk.CTkButton(
            log_title_row, text="[ CLEAR ]",
            command=self._clear_log,
            width=80, height=26,
            fg_color="transparent", border_width=1,
            border_color=COLORS["text_dim"],
            hover_color=COLORS["card_hover"],
            font=ctk.CTkFont(size=10, family="Consolas")
        ).pack(side="right")

        self.log_text = tk.Text(
            log_outer,
            font=("Consolas", 11),
            bg=COLORS["bg_darker"],
            fg=COLORS["text"],
            insertbackground=COLORS["cyan"],
            selectbackground=COLORS["purple"],
            relief="flat", bd=0,
            wrap="none",
            state="disabled",
        )

        scrollbar_y = tk.Scrollbar(
            log_outer, orient="vertical", command=self.log_text.yview)
        scrollbar_x = tk.Scrollbar(
            log_outer, orient="horizontal", command=self.log_text.xview)
        self.log_text.configure(
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set)

        scrollbar_y.pack(side="right",  fill="y",  padx=(0, 4))
        scrollbar_x.pack(side="bottom", fill="x",  padx=4, pady=(0, 4))
        self.log_text.pack(fill="both", expand=True, padx=(10, 0))

        # ── Configurer TOUS les tags de couleur ──────────────────────
        for tag_name, color in LOG_TAGS.items():
            self.log_text.tag_configure(tag_name, foreground=color)

        # Tags avec style gras en plus
        bold_tags = {
            "header":  (COLORS["cyan"],    "bold"),
            "xor":     (COLORS["yellow"],  "bold"),
            "round":   (COLORS["magenta"], "bold"),
            "result":  (COLORS["green"],   "bold"),
            "kasiski": (COLORS["magenta"], "bold"),
        }
        for tag_name, (color, weight) in bold_tags.items():
            self.log_text.tag_configure(
                tag_name,
                foreground=color,
                font=("Consolas", 11, weight))

        # ── Pied de page ──────────────────────────────────────────────
        footer_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        footer_frame.grid(row=4, column=0, sticky="ew",
                          padx=20, pady=(0, 12))

        self.footer_label = ctk.CTkLabel(
            footer_frame, text="[>] SYSTEM: PROCESSING...",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=COLORS["text_dim"])
        self.footer_label.pack(side="left")

        self.line_count_label = ctk.CTkLabel(
            footer_frame, text="lignes: 0",
            font=ctk.CTkFont(size=10, family="Consolas"),
            text_color=COLORS["text_dim"])
        self.line_count_label.pack(side="right")

        self._line_count = 0
        self.animate_loading()

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self._line_count = 0
        self.line_count_label.configure(text="lignes: 0")

    def animate_loading(self, count=0):
        if not hasattr(self, 'window') or not self.window.winfo_exists():
            return
        chars = ["|", "/", "-", "\\"]
        try:
            current = self.footer_label.cget("text")
            if "PROCESSING" in current or "INITIALIZING" in current:
                self.footer_label.configure(
                    text=f"[>] SYSTEM: PROCESSING {chars[count % len(chars)]}"
                )
        except Exception:
            pass
        self.window.after(180, lambda: self.animate_loading(count + 1))

    def log(self, text: str):
        """Ajoute une ligne au log avec coloration automatique."""
        if not hasattr(self, 'window') or not self.window.winfo_exists():
            return

        tag = classify_log_line(text)

        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

        self._line_count += 1
        try:
            self.line_count_label.configure(
                text=f"lignes: {self._line_count}")
            self.window.update_idletasks()
        except Exception:
            pass

    def log_matrix(self, title: str, data, step_num=None, total=None):
        """Affiche une matrice ou un tableau d'octets avec titre."""
        if not hasattr(self, 'window') or not self.window.winfo_exists():
            return

        self.log(f"┌─[ {title} ]")
        try:
            if isinstance(data, (bytes, bytearray)):
                hex_str  = data.hex().upper()
                row_size = 16
                for i in range(0, len(hex_str), row_size):
                    chunk = hex_str[i:i + row_size]
                    pairs = ' '.join(
                        chunk[j:j + 2] for j in range(0, len(chunk), 2))
                    self.log(f"│  {pairs}")
            elif isinstance(data, list):
                if data and isinstance(data[0], list):
                    for row in data:
                        row_str = "  ".join(f"{v:3}" for v in row)
                        self.log(f"│  [ {row_str} ]")
                else:
                    for i in range(0, len(data), 8):
                        self.log(f"│  {data[i:i+8]}")
            else:
                self.log(f"│  {data}")
        except Exception as e:
            self.log(f"│  (erreur affichage: {e})")
        self.log(f"└───────────────────────────────")

    def update_progress(self, current: int, total: int):
        if total > 0 and self.window.winfo_exists():
            p = current / total
            self.progress_bar.set(p)
            self.progress_label.configure(
                text=f"[>] PROGRESS: {int(p * 100)}%  "
                     f"— étape {current}/{total}"
            )

    def start_processing(self):
        def process():
            try:
                step_count  = [0]
                total_steps = 10

                def log_step(step_text, step_num=None, total=None):
                    step_count[0] += 1
                    if step_num is not None:
                        step_count[0] = step_num
                    if step_num is not None and total is not None:
                        self.update_progress(step_num, total)
                    else:
                        frac = min(step_count[0] / total_steps, 0.95)
                        self.progress_bar.set(frac)
                    self.log(step_text)

                def log_matrix_cb(title, matrix,
                                  step_num=None, total=None):
                    step_count[0] += 1
                    if step_num is not None and total is not None:
                        self.update_progress(step_num, total)
                    self.log_matrix(title, matrix, step_num, total)

                if self.operation == "encrypt":
                    result = self.algorithm.encrypt(
                        self.text, self.key, log_step, log_matrix_cb)
                else:
                    result = self.algorithm.decrypt(
                        self.text, self.key, log_step, log_matrix_cb)

                if self.window.winfo_exists():
                    self.log("")
                    self.log("=" * 62)
                    self.log("✅  PROCESS COMPLETED SUCCESSFULLY!")
                    self.log("=" * 62)
                    self.progress_bar.set(1.0)
                    self.progress_label.configure(
                        text="[>] PROGRESS: 100% — TERMINÉ")
                    self.footer_label.configure(
                        text="[>] SYSTEM: COMPLETED — OUVERTURE DU RÉSULTAT...",
                        text_color=COLORS["green"])

                final_result    = result
                final_operation = self.operation
                final_algo_name = self.algorithm.get_name()
                parent_window   = self.parent

                self.update_result_callback(final_result)

                def show_result():
                    self.window.destroy()
                    ResultCyberWindow(
                        parent_window, final_result,
                        final_operation, final_algo_name)

                self.parent.after(0, show_result)

            except ValueError as e:
                err_msg = str(e)
                if self.window.winfo_exists():
                    self.log("")
                    self.log("⚠️  PARAMÈTRE INVALIDE")
                    self.log(f"   {err_msg}")
                    self.log("   Corrigez la clé ou le texte puis réessayez.")
                    self.footer_label.configure(
                        text="[>] SYSTEM: PARAMÈTRE INVALIDE",
                        text_color=COLORS["yellow"])
                    self.window.after(2500, self.window.destroy)
                    self.parent.after(
                        2600,
                        lambda m=err_msg: messagebox.showwarning(
                            "⚠️  Paramètre invalide", m))

            except Exception as e:
                if self.window.winfo_exists():
                    self.log("")
                    self.log("❌ ERREUR")
                    self.log(f"   {str(e)}")
                    self.footer_label.configure(
                        text="[>] SYSTEM: ERREUR",
                        text_color=COLORS["red"])
                    self.window.after(2500, self.window.destroy)
                    self.parent.after(
                        2200,
                        lambda m=str(e): messagebox.showerror("Erreur", m))

        thread = threading.Thread(target=process, daemon=True)
        thread.start()


# ============================================================
#   APP PRINCIPALE
# ============================================================

class CryptoApp:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.window = ctk.CTk()
        self.window.title("⎯⎯ CRYPTO SUITE v2.0 - COMPLETE EDITION ⎯⎯")
        self.window.geometry("1400x900")
        self.window.minsize(1200, 750)
        self.window.configure(fg_color=COLORS["bg_darker"])

        self.window.grid_columnconfigure(0, weight=0)
        self.window.grid_columnconfigure(1, weight=1)
        self.window.grid_rowconfigure(0, weight=1)

        self.current_algorithm = None
        self.algorithms        = {}

        self.init_algorithms()
        self.setup_ui()

        if self.algorithms:
            self.select_algorithm(list(self.algorithms.keys())[0])

    def init_algorithms(self):
        self.algorithms = {
            "Caesar Cipher":        CaesarAlgorithm(),
            "Vigenère Cipher":      VigenereAlgorithm(),
            "Affine Cipher":        AffineAlgorithm(),
            "Playfair Cipher":      PlayfairAlgorithm(),
            "Hill Cipher":          HillAlgorithm(),
            "One-Time Pad (OTP)":   OTPAlgorithm(),
            "RC4":                  RC4Algorithm(),
            "DES / 3DES":           DESAlgorithm(),
            "AES (128/192/256)":    AESAlgorithm(),
            "Twofish":              TwofishAlgorithm(),
            "Serpent":              SerpentAlgorithm(),
            "RSA":                  RSAAlgorithm(),
            "Diffie-Hellman (DH)":  DHAlgorithm(),
            "ECC / ECDH":           ECCAlgorithm(),
            "ElGamal":              ElGamalAlgorithm(),
            "MD5":                  MD5Algorithm(),
            "SHA-256":              SHA256Algorithm(),
            "SHA-512":              SHA512Algorithm(),
            "RSA Signature":        RSASignatureAlgorithm(),
            "ElGamal Signature":    ElGamalSignatureAlgorithm(),
            "DSA / ECDSA":          ECDSAAlgorithm(),
            "Ed25519":              Ed25519Algorithm(),
        }

    def setup_ui(self):
        # ── Sidebar ───────────────────────────────────────────────────
        self.sidebar = ctk.CTkFrame(
            self.window, width=350, corner_radius=0,
            fg_color=COLORS["bg_card"],
            border_width=1, border_color=COLORS["purple"])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        header = ctk.CTkFrame(self.sidebar, fg_color="transparent",
                               height=140)
        header.pack(fill="x", pady=(25, 0))

        self.logo = ctk.CTkLabel(header, text="⚡",
                                  font=ctk.CTkFont(size=60),
                                  text_color=COLORS["cyan"])
        self.logo.pack(pady=(5, 0))
        self.animate_logo()

        ctk.CTkLabel(
            header, text="┌─[CRYPTO SUITE]─┐",
            font=ctk.CTkFont(size=18, weight="bold", family="Consolas"),
            text_color=COLORS["cyan"]
        ).pack()
        ctk.CTkLabel(
            header, text="└─[COMPLETE EDITION]─┘",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=COLORS["purple"]
        ).pack()

        ctk.CTkFrame(self.sidebar, height=2,
                     fg_color=COLORS["cyan"]).pack(fill="x", padx=20, pady=20)

        categories = [
            ("🔐 CLASSIQUE (TP1)", [
                "Caesar Cipher", "Vigenère Cipher", "Affine Cipher",
                "Playfair Cipher", "Hill Cipher", "One-Time Pad (OTP)"]),
            ("⚡ SYMÉTRIQUE (TP2)", [
                "RC4", "DES / 3DES", "AES (128/192/256)",
                "Twofish", "Serpent"]),
            ("🔑 ASYMÉTRIQUE (TP3)", [
                "RSA", "Diffie-Hellman (DH)", "ECC / ECDH", "ElGamal"]),
            ("📊 HACHAGE (TP4)", [
                "MD5", "SHA-256", "SHA-512"]),
            ("✍️ SIGNATURES (TP5)", [
                "RSA Signature", "ElGamal Signature",
                "DSA / ECDSA", "Ed25519"]),
        ]

        self.algo_frame = ctk.CTkScrollableFrame(
            self.sidebar, fg_color="transparent",
            scrollbar_button_color=COLORS["cyan"])
        self.algo_frame.pack(fill="both", expand=True, padx=15, pady=5)

        self.algo_buttons = {}
        for cat_name, algos in categories:
            ctk.CTkLabel(
                self.algo_frame,
                text=f"├─[ {cat_name} ]─┤",
                font=ctk.CTkFont(size=11, weight="bold", family="Consolas"),
                text_color=COLORS["magenta"]
            ).pack(anchor="w", pady=(10, 5))
            for algo_name in algos:
                if algo_name in self.algorithms:
                    btn = ctk.CTkButton(
                        self.algo_frame,
                        text=f"> {algo_name}",
                        command=lambda name=algo_name:
                            self.select_algorithm(name),
                        height=38, corner_radius=6,
                        font=ctk.CTkFont(size=11, family="Consolas"),
                        fg_color="transparent",
                        hover_color=COLORS["card_hover"],
                        anchor="w"
                    )
                    btn.pack(fill="x", pady=2)
                    self.algo_buttons[algo_name] = btn

        status_frame = ctk.CTkFrame(
            self.sidebar, height=55,
            fg_color=COLORS["cyan_dark"], corner_radius=0)
        status_frame.pack(fill="x", side="bottom")
        self.status_label = ctk.CTkLabel(
            status_frame, text="◇ SYSTEM: READY ◇",
            font=ctk.CTkFont(size=12, weight="bold", family="Consolas"),
            text_color=COLORS["bg_darker"])
        self.status_label.pack(pady=15)

        # ── Main content ──────────────────────────────────────────────
        self.main_frame = ctk.CTkFrame(
            self.window, corner_radius=25,
            fg_color=COLORS["bg_card"],
            border_width=2, border_color=COLORS["cyan"])
        self.main_frame.grid(row=0, column=1, sticky="nsew",
                             padx=25, pady=25)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(3, weight=1)

        info_frame = ctk.CTkFrame(
            self.main_frame, corner_radius=15,
            fg_color=COLORS["bg_darker"],
            border_width=1, border_color=COLORS["purple"])
        info_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))

        self.algo_title = ctk.CTkLabel(
            info_frame, text="[>] SELECT ALGORITHM [<]",
            font=ctk.CTkFont(size=26, weight="bold", family="Consolas"),
            text_color=COLORS["cyan"])
        self.algo_title.pack(pady=(20, 8), padx=25)

        self.algo_desc = ctk.CTkLabel(
            info_frame, text="CHOOSE A CIPHER FROM THE SIDEBAR",
            font=ctk.CTkFont(size=13, family="Consolas"),
            text_color=COLORS["text_dim"], wraplength=800)
        self.algo_desc.pack(pady=(0, 20), padx=25)

        input_card = ctk.CTkFrame(
            self.main_frame, corner_radius=15,
            fg_color=COLORS["bg_darker"],
            border_width=1, border_color=COLORS["purple"])
        input_card.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        input_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            input_card, text="┌─[ INPUT DATA ]─┐",
            font=ctk.CTkFont(size=14, weight="bold", family="Consolas"),
            text_color=COLORS["cyan"]
        ).grid(row=0, column=0, sticky="w", padx=20, pady=(15, 5))

        self.input_text = ctk.CTkTextbox(
            input_card, height=130,
            font=ctk.CTkFont(size=14, family="Consolas"),
            corner_radius=10, fg_color=COLORS["bg_card"],
            border_width=1, border_color=COLORS["purple"])
        self.input_text.grid(row=1, column=0, sticky="ew",
                             padx=20, pady=(0, 15))

        controls_card = ctk.CTkFrame(
            self.main_frame, corner_radius=15,
            fg_color=COLORS["bg_darker"],
            border_width=1, border_color=COLORS["purple"])
        controls_card.grid(row=2, column=0, sticky="ew", pady=(0, 20))
        controls_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            controls_card, text="┌─[ ENCRYPTION KEY ]─┐",
            font=ctk.CTkFont(size=13, weight="bold", family="Consolas"),
            text_color=COLORS["magenta"]
        ).grid(row=0, column=0, sticky="w", padx=20, pady=(15, 5))

        self.key_entry = ctk.CTkEntry(
            controls_card,
            placeholder_text="ENTER KEY...",
            font=ctk.CTkFont(size=14, family="Consolas"),
            height=48, corner_radius=10,
            fg_color=COLORS["bg_card"],
            border_width=1, border_color=COLORS["purple"])
        self.key_entry.grid(row=1, column=0, sticky="ew",
                            padx=20, pady=(0, 15))

        btn_frame = ctk.CTkFrame(controls_card, fg_color="transparent")
        btn_frame.grid(row=2, column=0, sticky="ew",
                       padx=20, pady=(0, 15))
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)

        self.encrypt_btn = GlowButton(
            btn_frame, text="[ ENCRYPT ]",
            command=self.encrypt_text,
            fg_color=COLORS["cyan"],
            hover_color=COLORS["cyan_dark"],
            height=55,
            font=ctk.CTkFont(size=16, weight="bold", family="Consolas"),
            corner_radius=12)
        self.encrypt_btn.grid(row=0, column=0, padx=10, sticky="ew")

        self.decrypt_btn = GlowButton(
            btn_frame, text="[ DECRYPT ]",
            command=self.decrypt_text,
            fg_color=COLORS["magenta"],
            hover_color=COLORS["magenta_dark"],
            height=55,
            font=ctk.CTkFont(size=16, weight="bold", family="Consolas"),
            corner_radius=12)
        self.decrypt_btn.grid(row=0, column=1, padx=10, sticky="ew")

        result_card = ctk.CTkFrame(
            self.main_frame, corner_radius=15,
            fg_color=COLORS["bg_darker"],
            border_width=1, border_color=COLORS["purple"])
        result_card.grid(row=3, column=0, sticky="nsew")
        result_card.grid_columnconfigure(0, weight=1)
        result_card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            result_card, text="┌─[ LAST RESULT ]─┐",
            font=ctk.CTkFont(size=13, weight="bold", family="Consolas"),
            text_color=COLORS["green"]
        ).grid(row=0, column=0, sticky="w", padx=20, pady=(15, 5))

        self.result_text = ctk.CTkTextbox(
            result_card,
            font=ctk.CTkFont(size=13, family="Consolas"),
            corner_radius=10, fg_color=COLORS["bg_card"],
            border_width=1, border_color=COLORS["purple"])
        self.result_text.grid(row=1, column=0, sticky="nsew",
                              padx=20, pady=(0, 10))

        ctk.CTkButton(
            result_card, text="[ COPY ]",
            command=self.copy_result,
            height=38, width=100,
            fg_color="transparent",
            border_width=1, border_color=COLORS["green"],
            hover_color=COLORS["green_dark"],
            font=ctk.CTkFont(size=12, family="Consolas")
        ).grid(row=2, column=0, sticky="e", padx=20, pady=(0, 15))

    def animate_logo(self, count=0):
        icons = ["⚡", "👉", "👈", "⚡", "💀"]
        self.logo.configure(text=icons[count % len(icons)])
        self.window.after(600, lambda: self.animate_logo(count + 1))

    def select_algorithm(self, algo_name):
        self.current_algorithm = self.algorithms[algo_name]
        for name, btn in self.algo_buttons.items():
            btn.configure(
                fg_color=COLORS["cyan"] if name == algo_name
                else "transparent")

        self.algo_title.configure(text=f"[>] {algo_name.upper()} [<]")
        self.algo_desc.configure(
            text=self.current_algorithm.get_description())
        key_info = self.current_algorithm.get_key_info()
        self.key_entry.configure(
            placeholder_text=key_info["placeholder"].upper())
        self.input_text.delete("1.0", "end")
        self.result_text.delete("1.0", "end")
        self.status_label.configure(
            text=f"◇ SYSTEM: {algo_name[:25].upper()} SELECTED ◇")
        self.window.after(
            2000,
            lambda: self.status_label.configure(text="◇ SYSTEM: READY ◇"))
        beep((800, 100), (1000, 100))

    def encrypt_text(self):
        if not self.current_algorithm:
            messagebox.showwarning("Error", "SELECT AN ALGORITHM FIRST")
            return
        text = self.input_text.get("1.0", "end-1c")
        key  = self.key_entry.get()
        if not text:
            messagebox.showwarning("Error", "ENTER TEXT TO ENCRYPT")
            return
        if not key and \
                self.current_algorithm.get_key_info()["type"] != "hash":
            messagebox.showwarning("Error", "ENTER A KEY")
            return
        self.status_label.configure(text="◇ SYSTEM: ENCRYPTING... ◇")
        beep((600, 50))
        ProgressCyberWindow(
            self.window, self.current_algorithm,
            "encrypt", text, key, self.update_result)

    def decrypt_text(self):
        if not self.current_algorithm:
            messagebox.showwarning("Error", "SELECT AN ALGORITHM FIRST")
            return
        text = self.input_text.get("1.0", "end-1c")
        key  = self.key_entry.get()
        if not text:
            messagebox.showwarning("Error", "ENTER TEXT TO DECRYPT")
            return
        if not key:
            messagebox.showwarning("Error", "ENTER A KEY")
            return
        self.status_label.configure(text="◇ SYSTEM: DECRYPTING... ◇")
        beep((600, 50))
        ProgressCyberWindow(
            self.window, self.current_algorithm,
            "decrypt", text, key, self.update_result)

    def update_result(self, result):
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", result)
        self.status_label.configure(
            text="◇ SYSTEM: OPERATION COMPLETE ◇")
        self.window.after(
            2500,
            lambda: self.status_label.configure(text="◇ SYSTEM: READY ◇"))

    def copy_result(self):
        result = self.result_text.get("1.0", "end-1c")
        if result:
            self.window.clipboard_clear()
            self.window.clipboard_append(result)
            self.status_label.configure(
                text="◇ SYSTEM: COPIED TO CLIPBOARD ◇")
            self.window.after(
                1500,
                lambda: self.status_label.configure(
                    text="◇ SYSTEM: READY ◇"))
            beep((800, 50), (1000, 50))

    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    app = CryptoApp()
    app.run()