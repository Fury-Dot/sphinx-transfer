# ═══════════════════════════════════════════════
#  ui/panel_encrypt.py  —  Panel 01: Encrypt File
# ═══════════════════════════════════════════════

import os
import threading
import customtkinter as ctk
from tkinter import messagebox
from widgets import Widgets
from constants import *


class PanelEncrypt(Widgets):
    def __init__(self, parent, engine):
        self.engine = engine
        self.frame  = ctk.CTkFrame(parent, fg_color=DARK_BG, corner_radius=0)
        self._build()

    def _build(self):
        i = ctk.CTkFrame(self.frame, fg_color=DARK_BG, corner_radius=0)
        i.pack(fill="both", expand=True, padx=36, pady=20)

        ctk.CTkLabel(i, text="ENCRYPT FILE",
                     font=("Courier New", 18, "bold"), text_color=TXT).pack(anchor="w")
        ctk.CTkLabel(i, text="AES-CTR  ·  PBKDF2-HMAC-SHA256  ·  HMAC Integrity Tag",
                     font=FS, text_color=DIM).pack(anchor="w", pady=(2, 0))

        # Input
        self.sec(i, "INPUT")
        self._src = ctk.StringVar()
        self._out = ctk.StringVar()
        self.file_row(i, "Source File",  self._src, [("All Files", "*.*")])
        self.file_row(i, "Output .enc",  self._out, [("Encrypted", "*.enc")])

        # Password
        self.sec(i, "PASSWORD")
        self._pw  = ctk.StringVar()
        self._pw2 = ctk.StringVar()
        self.pw_row(i, "Password", self._pw)
        self.pw_row(i, "Confirm",  self._pw2)

        # Strength meter
        sr = ctk.CTkFrame(i, fg_color="transparent")
        sr.pack(fill="x", pady=3)
        ctk.CTkLabel(sr, text="Strength:", font=FS, text_color=DIM).pack(side="left")
        self._str_lbl = ctk.CTkLabel(sr, text="—", font=FS, text_color=DIM)
        self._str_lbl.pack(side="left", padx=8)
        self._pw.trace_add("write", self._update_strength)

        self._pb = self.progress_bar(i)

        # Buttons
        br = ctk.CTkFrame(i, fg_color="transparent")
        br.pack(fill="x", pady=10)
        self.action_btn(br, "◈  ENCRYPT FILE", ACCENT, self._run).pack(side="left")

        self.sec(i, "LOG")
        self._log_tb = self.log_box(i)
        self.clear_btn(br, self._log_tb).pack(side="left", padx=10)

    def _update_strength(self, *_):
        pw = self._pw.get()
        score = sum([
            len(pw) >= 8,
            len(pw) >= 14,
            any(c.isupper() for c in pw),
            any(c.isdigit() for c in pw),
            any(c in "!@#$%^&*()" for c in pw),
        ])
        labels = [
            ("VERY WEAK", DANGER), ("WEAK", DANGER),
            ("FAIR", WARNING),     ("GOOD", WARNING),
            ("STRONG", SUCCESS),   ("EXCELLENT", SUCCESS),
        ]
        text, color = labels[score]
        self._str_lbl.configure(text=text, text_color=color)

    def _run(self):
        src = self._src.get().strip()
        out = self._out.get().strip()
        pw  = self._pw.get()

        if not src or not os.path.isfile(src):
            return messagebox.showerror("Error", "Select a valid source file.")
        if pw != self._pw2.get():
            return messagebox.showerror("Error", "Passwords do not match.")
        if not pw:
            return messagebox.showerror("Error", "Password cannot be empty.")
        if not out:
            out = src + ".enc"
            self._out.set(out)

        def task():
            self.log_clear(self._log_tb)
            self.log(self._log_tb, f"Source : {src}", "dim")
            self.log(self._log_tb, f"Output : {out}", "dim")
            self.set_progress(self._pb, 0.05)

            self.log(self._log_tb, f"Size   : {os.path.getsize(src):,} bytes")
            self.log(self._log_tb, "▸ Streaming encryption (PBKDF2 + AES-CTR + HMAC)…", "info")

            try:
                T = self.engine.encrypt_stream(src, out, pw, self.set_progress_cb)
            except Exception as e:
                self.log(self._log_tb, f"✗ {e}", "error")
                self.set_progress(self._pb, 0)
                return

            self.set_progress(self._pb, 1.0)
            self.log(self._log_tb, "✔ ENCRYPTION COMPLETE", "success")
            self.log(self._log_tb, f"  PBKDF2  : {T['pbkdf2_ms']} ms")
            self.log(self._log_tb, f"  AES-CTR : {T['aes_ctr_ms']} ms")
            self.log(self._log_tb, f"  HMAC    : {T['hmac_ms']}")
            self.log(self._log_tb, f"  Output  : {os.path.getsize(out):,} bytes → {out}", "success")

        threading.Thread(target=task, daemon=True).start()

    def set_progress_cb(self, p):
        self.set_progress(self._pb, p)