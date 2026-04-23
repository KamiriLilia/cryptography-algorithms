"""
Educational Cryptography Suite - Cyberpunk Neon Edition
Version complète et corrigée
"""

import customtkinter as ctk
from tkinter import messagebox
import time
import threading
import winsound
import random
import math
import tkinter as tk

from algorithms.aes import AESAlgorithm
from algorithms.twofish import TwofishAlgorithm
from algorithms.des import DESAlgorithm
from algorithms.rsa import RSAAlgorithm 
from algorithms.serpent import SerpentAlgorithm
from algorithms.rc4 import RC4Algorithm
from algorithms.caesar import CaesarAlgorithm
from algorithms.vigenere import VigenereAlgorithm
from algorithms.affine import AffineAlgorithm
from algorithms.playfair import PlayfairAlgorithm
from algorithms.hill import HillAlgorithm

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
}


class GlowButton(ctk.CTkButton):
    """Bouton avec effet de brillance néon"""
    
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.master_window = master
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<ButtonPress-1>", self.on_click)
        self.normal_color = kwargs.get("fg_color")
    
    def on_enter(self, e):
        if self.normal_color == COLORS["cyan"]:
            self.configure(fg_color=COLORS["cyan_dark"], border_color=COLORS["cyan"], border_width=2)
        else:
            self.configure(fg_color=COLORS["magenta_dark"], border_color=COLORS["magenta"], border_width=2)
    
    def on_leave(self, e):
        self.configure(fg_color=self.normal_color, border_width=0)
    
    def on_click(self, e):
        original_color = self.cget("fg_color")
        self.configure(fg_color=COLORS["yellow"])
        self.after(150, lambda: self.configure(fg_color=original_color))


class ResultCyberWindow:
    """Fenêtre de résultat séparée avec confettis explosifs"""
    
    def __init__(self, parent, result, operation, algorithm_name):
        self.parent = parent
        self.result = result
        self.operation = operation
        self.algorithm_name = algorithm_name
        
        # Créer la fenêtre
        self.window = ctk.CTkToplevel(parent)
        self.window.title("✨ RÉSULTAT FINAL ✨")
        self.window.geometry("750x600")
        self.window.configure(fg_color=COLORS["bg_darker"])
        self.window.transient(parent)
        
        # Centrer
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (750 // 2)
        y = (self.window.winfo_screenheight() // 2) - (600 // 2)
        self.window.geometry(f"750x600+{x}+{y}")
        
        # Sons de succès
        try:
            winsound.Beep(1200, 100)
            winsound.Beep(1500, 100)
            winsound.Beep(1800, 200)
            winsound.Beep(2000, 300)
        except:
            pass
        
        # Animation d'entrée
        self.window.attributes('-alpha', 0)
        self.fade_in()
        self.setup_ui()
        
        # Lancer les confettis après l'affichage
        self.window.after(200, self.explode_confetti)
        self.animate_glitch()
    
    def fade_in(self, alpha=0):
        if alpha < 1:
            alpha += 0.05
            self.window.attributes('-alpha', alpha)
            self.window.after(20, lambda: self.fade_in(alpha))
    
    def setup_ui(self):
        # Main frame néon
        main_frame = ctk.CTkFrame(
            self.window, 
            corner_radius=20, 
            fg_color=COLORS["bg_card"],
            border_width=2,
            border_color=COLORS["cyan"]
        )
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(25, 10))
        
        # Icône animée
        self.success_icon = ctk.CTkLabel(
            header_frame,
            text="🎉",
            font=ctk.CTkFont(size=60)
        )
        self.success_icon.pack()
        self.animate_icon()
        
        # Badge de succès
        badge = ctk.CTkLabel(
            header_frame,
            text="⚡ SUCCÈS ⚡",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=COLORS["cyan"]
        )
        badge.pack(pady=(5, 0))
        
        # Titre
        operation_text = "CHIFFREMENT" if self.operation == "encrypt" else "DÉCHIFFREMENT"
        title = ctk.CTkLabel(
            header_frame,
            text=f"{operation_text} COMPLET",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=COLORS["magenta"]
        )
        title.pack()
        
        # Info algorithme
        algo_label = ctk.CTkLabel(
            header_frame,
            text=f"┌── {self.algorithm_name} ──┐",
            font=ctk.CTkFont(size=12, family="Consolas"),
            text_color=COLORS["text_dim"]
        )
        algo_label.pack()
        
        # Zone de résultat
        result_frame = ctk.CTkFrame(
            main_frame, 
            corner_radius=15, 
            fg_color=COLORS["bg_darker"],
            border_width=2,
            border_color=COLORS["purple"]
        )
        result_frame.pack(fill="both", expand=True, padx=25, pady=20)
        
        # ASCII art
        ascii_top = ctk.CTkLabel(
            result_frame,
            text="┌─────────────────────────────────────────────────────────────┐",
            font=ctk.CTkFont(size=10, family="Consolas"),
            text_color=COLORS["cyan"]
        )
        ascii_top.pack(anchor="w", padx=15, pady=(15, 0))
        
        result_title = ctk.CTkLabel(
            result_frame,
            text="│                    ░▒▓█ RÉSULTAT FINAL █▓▒░                    │",
            font=ctk.CTkFont(size=12, family="Consolas", weight="bold"),
            text_color=COLORS["green"]
        )
        result_title.pack(anchor="w", padx=15)
        
        ascii_mid = ctk.CTkLabel(
            result_frame,
            text="├─────────────────────────────────────────────────────────────┤",
            font=ctk.CTkFont(size=10, family="Consolas"),
            text_color=COLORS["cyan"]
        )
        ascii_mid.pack(anchor="w", padx=15)
        
        # Textbox pour le résultat
        self.result_text = ctk.CTkTextbox(
            result_frame,
            font=ctk.CTkFont(size=13, family="Consolas"),
            corner_radius=8,
            wrap="word",
            fg_color=COLORS["bg_card"],
            height=150
        )
        self.result_text.pack(fill="both", expand=True, padx=15, pady=(5, 5))
        self.result_text.insert("1.0", self.result)
        self.result_text.configure(state="disabled")
        
        ascii_bottom = ctk.CTkLabel(
            result_frame,
            text="└─────────────────────────────────────────────────────────────┘",
            font=ctk.CTkFont(size=10, family="Consolas"),
            text_color=COLORS["cyan"]
        )
        ascii_bottom.pack(anchor="w", padx=15, pady=(0, 15))
        
        # Boutons
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(pady=(10, 25))
        
        copy_btn = ctk.CTkButton(
            btn_frame,
            text="[ 📋 COPIER ]",
            command=lambda: self.copy_result(self.result),
            fg_color="transparent",
            border_width=2,
            border_color=COLORS["cyan"],
            hover_color=COLORS["cyan_dark"],
            width=160,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            corner_radius=10
        )
        copy_btn.pack(side="left", padx=15)
        
        close_btn = ctk.CTkButton(
            btn_frame,
            text="[ FERMER ]",
            command=self.window.destroy,
            fg_color="transparent",
            border_width=2,
            border_color=COLORS["magenta"],
            hover_color=COLORS["magenta_dark"],
            width=140,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            corner_radius=10
        )
        close_btn.pack(side="left", padx=15)
    
    def animate_icon(self, count=0):
        icons = ["🎉", "✨", "🌟", "⭐", "🎊", "🏆"]
        if self.window.winfo_exists():
            self.success_icon.configure(text=icons[count % len(icons)])
            self.window.after(300, lambda: self.animate_icon(count + 1))
    
    def animate_glitch(self, count=0):
        """Effet glitch sur le titre"""
        if not self.window.winfo_exists():
            return
        
        if count % 15 == 0:
            self.window.configure(border_color=random.choice([COLORS["cyan"], COLORS["magenta"], COLORS["purple"]]))
            self.window.after(100, lambda: self.window.configure(border_color=COLORS["cyan"]))
        
        self.window.after(500, lambda: self.animate_glitch(count + 1))
    
    def explode_confetti(self):
        """Explosion de confettis"""
        if not self.window.winfo_exists():
            return
        
        colors = ["#ff00ff", "#00ffff", "#ff00ff", "#00ff88", "#ffcc00", "#ff3366"]
        
        class Confetti:
            def __init__(self, canvas, x, y, color, angle, speed):
                self.canvas = canvas
                self.x = x
                self.y = y
                self.color = color
                self.angle = angle
                self.speed = speed
                self.size = random.randint(5, 12)
                self.life = 100
                shape = random.choice(["rect", "circle"])
                if shape == "rect":
                    self.id = canvas.create_rectangle(x, y, x+self.size, y+self.size, fill=color, outline="")
                else:
                    self.id = canvas.create_oval(x, y, x+self.size, y+self.size, fill=color, outline="")
            
            def update(self):
                self.x += math.cos(self.angle) * self.speed
                self.y += math.sin(self.angle) * self.speed + 1
                self.speed *= 0.98
                self.life -= 2
                self.size = max(2, self.size - 0.2)
                
                if "rect" in str(self.id):
                    self.canvas.coords(self.id, self.x, self.y, self.x+self.size, self.y+self.size)
                else:
                    self.canvas.coords(self.id, self.x, self.y, self.x+self.size, self.y+self.size)
                
                if self.life <= 0 or self.y > 600:
                    self.canvas.delete(self.id)
                    return False
                return True
        
        canvas = tk.Canvas(self.window, bg="",highlightthickness=0,bd=0
)
        canvas.place(relwidth=1, relheight=1)
        canvas.lift()
        canvas.configure(bg="", highlightthickness=0)
        
        confettis = []
        center_x = 375
        center_y = 300
        
        for _ in range(200):
            angle = random.uniform(0, math.pi * 2)
            speed = random.uniform(5, 18)
            color = random.choice(colors)
            confetti = Confetti(canvas, center_x, center_y, color, angle, speed)
            confettis.append(confetti)
        
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
        try:
            winsound.Beep(1000, 50)
            winsound.Beep(1200, 50)
        except:
            pass


class ProgressCyberWindow:
    """Fenêtre de traitement STYLE CYBERPUNK"""
    
    def __init__(self, parent, algorithm, operation, text, key, update_result_callback):
        self.parent = parent
        self.algorithm = algorithm
        self.operation = operation
        self.text = text
        self.key = key
        self.update_result_callback = update_result_callback
        
        # Fenêtre principale
        self.window = ctk.CTkToplevel(parent)
        self.window.title(f"[ {operation.upper()} PROCESS ]")
        self.window.geometry("1200x850")
        self.window.minsize(1000, 700)
        self.window.configure(fg_color=COLORS["bg_darker"])
        self.window.transient(parent)
        self.window.grab_set()
        
        # Centrer
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (1200 // 2)
        y = (self.window.winfo_screenheight() // 2) - (850 // 2)
        self.window.geometry(f"1200x850+{x}+{y}")
        
        # Animation d'entrée
        self.window.attributes('-alpha', 0)
        self.fade_in()
        
        self.setup_ui()
        
        # Démarrer le traitement
        self.window.after(500, self.start_processing)
    
    def fade_in(self, alpha=0):
        if alpha < 1:
            alpha += 0.05
            self.window.attributes('-alpha', alpha)
            self.window.after(20, lambda: self.fade_in(alpha))
    
    def setup_ui(self):
        # Border néon autour de la fenêtre
        main_frame = ctk.CTkFrame(
            self.window, 
            corner_radius=20, 
            fg_color=COLORS["bg_card"],
            border_width=2,
            border_color=COLORS["cyan"]
        )
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # HEADER
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=30, pady=(25, 15))
        
        # ASCII Header
        ascii_header = ctk.CTkLabel(
            header_frame,
            text="┌─────────────────────────────────────────────────────────────────┐\n│  ░▒▓█▓▒░ CRYPTO PROCESSING v2.0 ░▒▓█▓▒░  │\n└─────────────────────────────────────────────────────────────────┘",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=COLORS["cyan"]
        )
        ascii_header.pack()
        
        # Info box
        info_frame = ctk.CTkFrame(
            header_frame, 
            fg_color=COLORS["bg_darker"], 
            corner_radius=10,
            border_width=1,
            border_color=COLORS["purple"]
        )
        info_frame.pack(fill="x", pady=15)
        
        operation_text = "ENCRYPT" if self.operation == "encrypt" else "DECRYPT"
        op_color = COLORS["cyan"] if self.operation == "encrypt" else COLORS["magenta"]
        
        ctk.CTkLabel(
            info_frame,
            text=f"  [>] STATUS: {operation_text}ING..",
            font=ctk.CTkFont(size=13, family="Consolas", weight="bold"),
            text_color=op_color
        ).pack(anchor="w", padx=15, pady=(10, 3))
        
        ctk.CTkLabel(
            info_frame,
            text=f"  [>] ALGORITHM: {self.algorithm.get_name()}",
            font=ctk.CTkFont(size=12, family="Consolas"),
            text_color=COLORS["text_dim"]
        ).pack(anchor="w", padx=15, pady=3)
        
        text_preview = self.text[:50] + "..." if len(self.text) > 50 else self.text
        ctk.CTkLabel(
            info_frame,
            text=f"  [>] INPUT: {text_preview}",
            font=ctk.CTkFont(size=12, family="Consolas"),
            text_color=COLORS["text_dim"]
        ).pack(anchor="w", padx=15, pady=3)
        
        ctk.CTkLabel(
            info_frame,
            text=f"  [>] KEY: {self.key}",
            font=ctk.CTkFont(size=12, family="Consolas"),
            text_color=COLORS["text_dim"]
        ).pack(anchor="w", padx=15, pady=3)
        
        ctk.CTkLabel(
            info_frame,
            text=f"  [>] STATUS: RUNNING...",
            font=ctk.CTkFont(size=12, family="Consolas"),
            text_color=COLORS["green"]
        ).pack(anchor="w", padx=15, pady=(3, 10))
        
        # BARRE DE PROGRESSION CYBER
        progress_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        progress_frame.pack(fill="x", padx=30, pady=(15, 20))
        
        self.progress_bar = ctk.CTkProgressBar(
            progress_frame,
            height=15,
            corner_radius=7,
            fg_color=COLORS["bg_darker"],
            progress_color=COLORS["cyan"]
        )
        self.progress_bar.pack(fill="x")
        self.progress_bar.set(0)
        
        self.progress_label = ctk.CTkLabel(
            progress_frame,
            text="[>] INITIALIZING PROCESS...",
            font=ctk.CTkFont(size=12, family="Consolas"),
            text_color=COLORS["cyan"]
        )
        self.progress_label.pack(pady=(8, 0))
        
        # ZONE D'AFFICHAGE
        log_frame = ctk.CTkFrame(
            main_frame, 
            corner_radius=15, 
            fg_color=COLORS["bg_darker"],
            border_width=1,
            border_color=COLORS["purple"]
        )
        log_frame.pack(fill="both", expand=True, padx=30, pady=(0, 20))
        
        log_title = ctk.CTkLabel(
            log_frame,
            text="┌─[ DETAILED PROCESS LOG ]─┐",
            font=ctk.CTkFont(size=13, family="Consolas", weight="bold"),
            text_color=COLORS["purple"]
        )
        log_title.pack(anchor="w", padx=20, pady=(15, 5))
        
        # Textbox style terminal
        self.log_text = ctk.CTkTextbox(
            log_frame,
            font=ctk.CTkFont(size=12, family="Consolas"),
            corner_radius=10,
            wrap="word",
            fg_color=COLORS["bg_darker"],
            border_width=0
        )
        self.log_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Footer
        footer_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        footer_frame.pack(fill="x", padx=30, pady=(0, 20))
        
        self.footer_label = ctk.CTkLabel(
            footer_frame,
            text="[>] SYSTEM: PROCESSING...",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=COLORS["text_dim"]
        )
        self.footer_label.pack()
        
        # Animation cyclique
        self.animate_loading()
    
    def animate_loading(self, count=0):
        """Animation de chargement style terminal"""
        if not hasattr(self, 'window') or not self.window.winfo_exists():
            return
        
        chars = ["|", "/", "-", "\\"]
        self.footer_label.configure(text=f"[>] SYSTEM: PROCESSING {chars[count % len(chars)]}")
        self.window.after(200, lambda: self.animate_loading(count + 1))
    
    def log(self, text):
        if hasattr(self, 'window') and self.window.winfo_exists():
            self.log_text.insert("end", text + "\n")
            self.log_text.see("end")
            self.window.update_idletasks()
    
    def update_progress(self, current, total):
        if total > 0:
            progress = current / total
            self.progress_bar.set(progress)
            self.progress_label.configure(text=f"[>] PROGRESS: {int(progress * 100)}% - STEP {current}/{total}")
    
    def start_processing(self):
        def process():
            try:
                step_count = 0
                total_steps = 7
                
                def log_step(step_text, step_num=None, total=None):
                    nonlocal step_count
                    step_count += 1
                    if step_num:
                        step_count = step_num
                    if step_num and total:
                        self.update_progress(step_num, total)
                    
                    self.log(f"\n{'─' * 60}")
                    self.log(f"► STEP {step_count}/{total_steps}")
                    self.log(f"{'─' * 60}")
                    self.log(f"{step_text}")
                    time.sleep(0.1)
                
                def log_matrix(title, matrix, step_num=None, total=None):
                    nonlocal step_count
                    step_count += 1
                    if step_num:
                        step_count = step_num
                    if step_num and total:
                        self.update_progress(step_num, total)
                    
                    self.log(f"\n{'─' * 60}")
                    self.log(f"► STEP {step_count}/{total_steps} : {title}")
                    self.log(f"{'─' * 60}")
                    try:
                        self.log(f"État (hex): {bytes(matrix).hex()}")
                    except:
                        self.log(f"État: {matrix}")
                    time.sleep(0.15)
                
                # Appel de l'algorithme
                if self.operation == "encrypt":
                    result = self.algorithm.encrypt(self.text, self.key, log_step, log_matrix)
                else:
                    result = self.algorithm.decrypt(self.text, self.key, log_step, log_matrix)
                
                if hasattr(self, 'window') and self.window.winfo_exists():
                    self.log(f"\n{'=' * 60}")
                    self.log("✅ PROCESS COMPLETED SUCCESSFULLY!")
                    self.log(f"{'=' * 60}")
                    
                    self.footer_label.configure(text="[>] SYSTEM: COMPLETED - OPENING RESULT...", text_color=COLORS["green"])
                    self.progress_bar.set(1.0)
                    
                    final_result = result
                    final_operation = self.operation
                    final_algorithm_name = self.algorithm.get_name()
                    parent_window = self.parent
                    
                    self.update_result_callback(final_result)
                    
                    
                def show_result():
                    self.window.destroy()
                    ResultCyberWindow(parent_window, final_result, final_operation, final_algorithm_name)

                self.parent.after(0, show_result)
            except Exception as e:
                if hasattr(self, 'window') and self.window.winfo_exists():
                    self.log(f"\n❌ ERROR: {str(e)}")
                    import traceback
                    self.log(traceback.format_exc())
                    self.window.after(2000, self.window.destroy)
                    self.window.after(2200, lambda: messagebox.showerror("Error", str(e)))
        
        thread = threading.Thread(target=process)
        thread.daemon = True
        thread.start()


class CryptoApp:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.window = ctk.CTk()
        self.window.title("⎯⎯ CRYPTO SUITE v2.0 ⎯⎯")
        self.window.geometry("1400x850")
        self.window.minsize(1200, 700)
        self.window.configure(fg_color=COLORS["bg_darker"])
        
        self.window.grid_columnconfigure(0, weight=0)
        self.window.grid_columnconfigure(1, weight=1)
        self.window.grid_rowconfigure(0, weight=1)
        
        self.current_algorithm = None
        self.algorithms = {}
        
        self.init_algorithms()
        self.setup_ui()
        
        if self.algorithms:
            self.select_algorithm(list(self.algorithms.keys())[0])
    
    def init_algorithms(self):
        self.algorithms = {
            "AES (Advanced Encryption Standard)": AESAlgorithm(),
            "Twofish": TwofishAlgorithm(),
            "DES (Data Encryption Standard)": DESAlgorithm(),
            "RSA (Rivest-Shamir-Adleman)": RSAAlgorithm(),
            "Serpent": SerpentAlgorithm(),
            "RC4 (Rivest Cipher 4)": RC4Algorithm(),
            "Caesar Cipher": CaesarAlgorithm(),
            "Vigenère Cipher": VigenereAlgorithm(),
            "Affine Cipher": AffineAlgorithm(),
            "Playfair Cipher": PlayfairAlgorithm(),
            "Hill Cipher": HillAlgorithm(),
        }
    
    def setup_ui(self):
        # Sidebar cyberpunk
        self.sidebar = ctk.CTkFrame(
            self.window, 
            width=320, 
            corner_radius=0, 
            fg_color=COLORS["bg_card"],
            border_width=1,
            border_color=COLORS["purple"]
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        
        # Header sidebar
        header = ctk.CTkFrame(self.sidebar, fg_color="transparent", height=140)
        header.pack(fill="x", pady=(25, 0))
        
        # Logo animé
        self.logo = ctk.CTkLabel(header, text="⚡", font=ctk.CTkFont(size=60), text_color=COLORS["cyan"])
        self.logo.pack(pady=(5, 0))
        self.animate_logo()
        
        title = ctk.CTkLabel(header, text="┌─[CRYPTO SUITE]─┐", font=ctk.CTkFont(size=18, weight="bold", family="Consolas"), text_color=COLORS["cyan"])
        title.pack()
        
        subtitle = ctk.CTkLabel(header, text="└─[EDUCATIONAL EDITION]─┘", font=ctk.CTkFont(size=11, family="Consolas"), text_color=COLORS["purple"])
        subtitle.pack()
        
        sep = ctk.CTkFrame(self.sidebar, height=2, fg_color=COLORS["cyan"])
        sep.pack(fill="x", padx=20, pady=20)
        
        algo_title = ctk.CTkLabel(self.sidebar, text="├─[ ALGORITHMS ]─┤", font=ctk.CTkFont(size=12, weight="bold", family="Consolas"), text_color=COLORS["magenta"])
        algo_title.pack(anchor="w", padx=20, pady=(0, 10))
        
        self.algo_frame = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent", scrollbar_button_color=COLORS["cyan"])
        self.algo_frame.pack(fill="both", expand=True, padx=15, pady=5)
        
        self.algo_buttons = {}
        for algo_name in self.algorithms.keys():
            btn = ctk.CTkButton(
                self.algo_frame,
                text=f"> {algo_name}",
                command=lambda name=algo_name: self.select_algorithm(name),
                height=45,
                corner_radius=8,
                font=ctk.CTkFont(size=12, family="Consolas"),
                fg_color="transparent",
                hover_color=COLORS["card_hover"],
                anchor="w"
            )
            btn.pack(fill="x", pady=4)
            self.algo_buttons[algo_name] = btn
        
        # Status bar
        status_frame = ctk.CTkFrame(self.sidebar, height=55, fg_color=COLORS["cyan_dark"], corner_radius=0)
        status_frame.pack(fill="x", side="bottom")
        
        self.status_label = ctk.CTkLabel(status_frame, text="◇ SYSTEM: READY ◇", font=ctk.CTkFont(size=12, weight="bold", family="Consolas"), text_color=COLORS["bg_darker"])
        self.status_label.pack(pady=15)
        
        # MAIN CONTENT
        self.main_frame = ctk.CTkFrame(self.window, corner_radius=25, fg_color=COLORS["bg_card"], border_width=2, border_color=COLORS["cyan"])
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=25, pady=25)
        
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=0)
        self.main_frame.grid_rowconfigure(1, weight=0)
        self.main_frame.grid_rowconfigure(2, weight=0)
        self.main_frame.grid_rowconfigure(3, weight=1)
        
        # Info card
        info_frame = ctk.CTkFrame(self.main_frame, corner_radius=15, fg_color=COLORS["bg_darker"], border_width=1, border_color=COLORS["purple"])
        info_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        self.algo_title = ctk.CTkLabel(info_frame, text="[>] SELECT ALGORITHM [<]", font=ctk.CTkFont(size=26, weight="bold", family="Consolas"), text_color=COLORS["cyan"])
        self.algo_title.pack(pady=(20, 8), padx=25)
        
        self.algo_desc = ctk.CTkLabel(info_frame, text="CHOOSE A CIPHER FROM THE SIDEBAR", font=ctk.CTkFont(size=13, family="Consolas"), text_color=COLORS["text_dim"], wraplength=800)
        self.algo_desc.pack(pady=(0, 20), padx=25)
        
        # Input card
        input_card = ctk.CTkFrame(self.main_frame, corner_radius=15, fg_color=COLORS["bg_darker"], border_width=1, border_color=COLORS["purple"])
        input_card.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        input_card.grid_columnconfigure(0, weight=1)
        
        input_label = ctk.CTkLabel(input_card, text="┌─[ INPUT DATA ]─┐", font=ctk.CTkFont(size=14, weight="bold", family="Consolas"), text_color=COLORS["cyan"])
        input_label.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 5))
        
        self.input_text = ctk.CTkTextbox(input_card, height=130, font=ctk.CTkFont(size=14, family="Consolas"), corner_radius=10, fg_color=COLORS["bg_card"], border_width=1, border_color=COLORS["purple"])
        self.input_text.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 15))
        
        # Controls card
        controls_card = ctk.CTkFrame(self.main_frame, corner_radius=15, fg_color=COLORS["bg_darker"], border_width=1, border_color=COLORS["purple"])
        controls_card.grid(row=2, column=0, sticky="ew", pady=(0, 20))
        controls_card.grid_columnconfigure(0, weight=1)
        
        key_label = ctk.CTkLabel(controls_card, text="┌─[ ENCRYPTION KEY ]─┐", font=ctk.CTkFont(size=13, weight="bold", family="Consolas"), text_color=COLORS["magenta"])
        key_label.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 5))
        
        self.key_entry = ctk.CTkEntry(controls_card, placeholder_text="ENTER KEY...", font=ctk.CTkFont(size=14, family="Consolas"), height=48, corner_radius=10, fg_color=COLORS["bg_card"], border_width=1, border_color=COLORS["purple"])
        self.key_entry.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 15))
        
        btn_frame = ctk.CTkFrame(controls_card, fg_color="transparent")
        btn_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 15))
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)
        
        self.encrypt_btn = GlowButton(
            btn_frame,
            text="[ ENCRYPT ]",
            command=self.encrypt_text,
            fg_color=COLORS["cyan"],
            hover_color=COLORS["cyan_dark"],
            height=55,
            font=ctk.CTkFont(size=16, weight="bold", family="Consolas"),
            corner_radius=12        )
        self.encrypt_btn.grid(row=0, column=0, padx=10, sticky="ew")
        
        self.decrypt_btn = GlowButton(
            btn_frame,
            text="[ DECRYPT ]",
            command=self.decrypt_text,
            fg_color=COLORS["magenta"],
            hover_color=COLORS["magenta_dark"],
            height=55,
            font=ctk.CTkFont(size=16, weight="bold", family="Consolas"),
            corner_radius=12
        )
        self.decrypt_btn.grid(row=0, column=1, padx=10, sticky="ew")
        
        # Result card
        result_card = ctk.CTkFrame(self.main_frame, corner_radius=15, fg_color=COLORS["bg_darker"], border_width=1, border_color=COLORS["purple"])
        result_card.grid(row=3, column=0, sticky="nsew")
        result_card.grid_columnconfigure(0, weight=1)
        result_card.grid_rowconfigure(1, weight=1)
        
        result_label = ctk.CTkLabel(result_card, text="┌─[ LAST RESULT ]─┐", font=ctk.CTkFont(size=13, weight="bold", family="Consolas"), text_color=COLORS["green"])
        result_label.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 5))
        
        self.result_text = ctk.CTkTextbox(result_card, font=ctk.CTkFont(size=13, family="Consolas"), corner_radius=10, fg_color=COLORS["bg_card"], border_width=1, border_color=COLORS["purple"])
        self.result_text.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 10))
        
        copy_btn = ctk.CTkButton(result_card, text="[ COPY ]", command=self.copy_result, height=38, width=100, fg_color="transparent", border_width=1, border_color=COLORS["green"], hover_color=COLORS["green_dark"], font=ctk.CTkFont(size=12, family="Consolas"))
        copy_btn.grid(row=2, column=0, sticky="e", padx=20, pady=(0, 15))
    
    def animate_logo(self, count=0):
        icons = ["⚡", "👉", "👈", "⚡", "💀"]
        self.logo.configure(text=icons[count % len(icons)])
        self.window.after(600, lambda: self.animate_logo(count + 1))
    
    def select_algorithm(self, algo_name):
        self.current_algorithm = self.algorithms[algo_name]
        
        for name, btn in self.algo_buttons.items():
            if name == algo_name:
                btn.configure(fg_color=COLORS["cyan"])
            else:
                btn.configure(fg_color="transparent")
        
        self.algo_title.configure(text=f"[>] {algo_name.split('(')[0].strip().upper()} [<]")
        self.algo_desc.configure(text=self.current_algorithm.get_description())
        
        key_info = self.current_algorithm.get_key_info()
        self.key_entry.configure(placeholder_text=key_info["placeholder"].upper())
        
        self.input_text.delete("1.0", "end")
        self.result_text.delete("1.0", "end")
        
        self.status_label.configure(text=f"◇ SYSTEM: {algo_name[:20].upper()} SELECTED ◇")
        self.window.after(2000, lambda: self.status_label.configure(text="◇ SYSTEM: READY ◇"))
        
        try:
            winsound.Beep(800, 100)
            winsound.Beep(1000, 100)
        except:
            pass
    
    def encrypt_text(self):
        if not self.current_algorithm:
            messagebox.showwarning("Error", "SELECT AN ALGORITHM FIRST")
            return
        
        text = self.input_text.get("1.0", "end-1c")
        key = self.key_entry.get()
        
        if not text:
            messagebox.showwarning("Error", "ENTER TEXT TO ENCRYPT")
            return
        
        if not key:
            messagebox.showwarning("Error", "ENTER A KEY")
            return
        
        self.status_label.configure(text="◇ SYSTEM: ENCRYPTING... ◇")
        
        try:
            winsound.Beep(600, 50)
        except:
            pass
        
        ProgressCyberWindow(self.window, self.current_algorithm, "encrypt", text, key, self.update_result)
    
    def decrypt_text(self):
        if not self.current_algorithm:
            messagebox.showwarning("Error", "SELECT AN ALGORITHM FIRST")
            return
        
        text = self.input_text.get("1.0", "end-1c")
        key = self.key_entry.get()
        
        if not text:
            messagebox.showwarning("Error", "ENTER TEXT TO DECRYPT")
            return
        
        if not key:
            messagebox.showwarning("Error", "ENTER A KEY")
            return
        
        self.status_label.configure(text="◇ SYSTEM: DECRYPTING... ◇")
        
        try:
            winsound.Beep(600, 50)
        except:
            pass
        
        ProgressCyberWindow(self.window, self.current_algorithm, "decrypt", text, key, self.update_result)
    
    def update_result(self, result):
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", result)
        self.status_label.configure(text="◇ SYSTEM: OPERATION COMPLETE ◇")
        self.window.after(2500, lambda: self.status_label.configure(text="◇ SYSTEM: READY ◇"))
    
    def copy_result(self):
        result = self.result_text.get("1.0", "end-1c")
        if result:
            self.window.clipboard_clear()
            self.window.clipboard_append(result)
            self.status_label.configure(text="◇ SYSTEM: COPIED TO CLIPBOARD ◇")
            self.window.after(1500, lambda: self.status_label.configure(text="◇ SYSTEM: READY ◇"))
            try:
                winsound.Beep(800, 50)
                winsound.Beep(1000, 50)
            except:
                pass
    
    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    app = CryptoApp()
    app.run()