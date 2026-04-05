# ═══════════════════════════════════════════════
#  ui/panel_decrypt.py  —  Panel 02: Decrypt File
# ═══════════════════════════════════════════════

import os
import threading
import customtkinter as ctk
from tkinter import messagebox
from widgets import Widgets
from constants import *


class PanelDecrypt(Widgets):
    def __init__(self, parent, engine):
        self.engine = engine
        self.frame  = ctk.CTkFrame(parent, fg_color=DARK_BG, corner_radius=0)
        self._build()

    def _build(self):
        i = ctk.CTkFrame(self.frame, fg_color=DARK_BG, corner_radius=0)
        i.pack(fill="both", expand=True, padx=36, pady=20)

        ctk.CTkLabel(i, text="DECRYPT FILE",
                     font=("Courier New", 18, "bold"), text_color=TXT).pack(anchor="w")
        ctk.CTkLabel(i, text="Extract Salt/Nonce  ·  Verify HMAC  ·  AES-CTR Decrypt",
                     font=FS, text_color=DIM).pack(anchor="w", pady=(2, 0))

        self.sec(i, "INPUT")
        self._src = ctk.StringVar()
        self._out = ctk.StringVar()
        self.file_row(i, "Encrypted File", self._src, [("Encrypted", "*.enc"), ("All", "*.*")])
        self.file_row(i, "Output File",    self._out, [("All", "*.*")])

        self.sec(i, "PASSWORD")
        self._pw = ctk.StringVar()
        self.pw_row(i, "Password", self._pw)

        self._pb = self.progress_bar(i)

        br = ctk.CTkFrame(i, fg_color="transparent")
        br.pack(fill="x", pady=10)
        self.action_btn(br, "◈  DECRYPT FILE", ACCENT2, self._run).pack(side="left")

        self.sec(i, "LOG")
        self._log_tb = self.log_box(i)
        self.clear_btn(br, self._log_tb).pack(side="left", padx=10)

    def _run(self):
        src = self._src.get().strip()
        out = self._out.get().strip()
        pw  = self._pw.get()

        if not src or not os.path.isfile(src):
            return messagebox.showerror("Error", "Select a valid .enc file.")
        if not pw:
            return messagebox.showerror("Error", "Enter the password.")
        if not out:
            out = src[:-4] if src.endswith(".enc") else src + ".dec"
            self._out.set(out)

        def task():
            self.log_clear(self._log_tb)
            self.set_progress(self._pb, 0.05)

            self.log(self._log_tb, f"Bundle : {os.path.getsize(src):,} bytes")
            self.log(self._log_tb, "▸ Streaming decryption (HMAC Verify + AES-CTR)…", "info")

            try:
                T = self.engine.decrypt_stream(src, out, pw, self.set_progress_cb)
            except ValueError as e:
                self.set_progress(self._pb, 0)
                self.log(self._log_tb, f"✗ {e}", "error")
                return
            except Exception as e:
                self.set_progress(self._pb, 0)
                self.log(self._log_tb, f"✗ Unexpected: {e}", "error")
                return

            self.set_progress(self._pb, 1.0)
            self.log(self._log_tb, "✔ DECRYPTION COMPLETE", "success")
            self.log(self._log_tb, f"  PBKDF2  : {T['pbkdf2_ms']} ms")
            self.log(self._log_tb, f"  HMAC    : {T['hmac_ms']}")
            self.log(self._log_tb, f"  AES-CTR : {T['aes_ctr_ms']} ms")
            self.log(self._log_tb, f"  Saved   : {out}", "success")

        threading.Thread(target=task, daemon=True).start()

    def set_progress_cb(self, p):
        self.set_progress(self._pb, p)