# ═══════════════════════════════════════════════
#  ui/panel_send.py  —  Panel 03: Send File
# ═══════════════════════════════════════════════

import os
import threading
import customtkinter as ctk
from tkinter import messagebox
from pathlib import Path
from widgets import Widgets
from network import send_file_tcp
from constants import *


class PanelSend(Widgets):
    def __init__(self, parent, engine, history, refresh_history_cb):
        self.engine       = engine
        self.history      = history
        self.refresh_hist = refresh_history_cb
        self.frame        = ctk.CTkFrame(parent, fg_color=DARK_BG, corner_radius=0)
        self._build()

    def _build(self):
        i = ctk.CTkFrame(self.frame, fg_color=DARK_BG, corner_radius=0)
        i.pack(fill="both", expand=True, padx=36, pady=20)

        ctk.CTkLabel(i, text="SEND FILE",
                     font=("Courier New", 18, "bold"), text_color=ACCENT3).pack(anchor="w")
        ctk.CTkLabel(i,
                     text="Encrypt locally  →  Send over TCP  →  Receiver decrypts with shared password",
                     font=FS, text_color=DIM).pack(anchor="w", pady=(2, 0))

        # Info box
        box = ctk.CTkFrame(i, fg_color=BOX_BG, corner_radius=6)
        box.pack(fill="x", pady=(10, 4))
        ctk.CTkLabel(box, justify="left", fg_color=BOX_BG, text_color=DIM, font=FS, text=(
            "HOW IT WORKS\n"
            "  1. Select a file and enter a shared password\n"
            "  2. File is encrypted locally: Salt → PBKDF2 → AES-CTR → HMAC\n"
            "  3. Encrypted bundle is sent via TCP to receiver's IP:port\n"
            "  4. Receiver opens the app → panel 04 → decrypts with same password\n"
            "  ⚠  Share the password via a separate secure channel (e.g. Signal, in-person)"
        )).pack(anchor="w", padx=14, pady=10)

        # File & destination
        self.sec(i, "FILE & DESTINATION", ACCENT3)
        self._src  = ctk.StringVar()
        self._ip   = ctk.StringVar(value="")
        self._port = ctk.StringVar(value=str(DEFAULT_PORT))
        self.file_row(i,  "File to Send",   self._src, [("All Files", "*.*")])
        self.entry_row(i, "Receiver IP",    self._ip)
        self.entry_row(i, "Receiver Port",  self._port, width=10)

        # Password
        self.sec(i, "SHARED PASSWORD", ACCENT3)
        self._pw = ctk.StringVar()
        self.pw_row(i, "Password", self._pw)

        self._pb   = self.progress_bar(i)
        self._spd  = ctk.CTkLabel(i, text="", font=FS, text_color=ACCENT3)
        self._spd.pack(anchor="w")

        # Buttons
        br = ctk.CTkFrame(i, fg_color="transparent")
        br.pack(fill="x", pady=10)
        self.action_btn(br, "◈  ENCRYPT & SEND", ACCENT3, self._run).pack(side="left")

        self.sec(i, "TRANSFER LOG", ACCENT3)
        self._log_tb = self.log_box(i, 160)
        self.clear_btn(br, self._log_tb).pack(side="left", padx=10)

    def _run(self):
        src = self._src.get().strip()
        ip  = self._ip.get().strip()
        pw  = self._pw.get()
        try:
            port = int(self._port.get().strip())
        except ValueError:
            return messagebox.showerror("Error", "Invalid port number.")

        if not src or not os.path.isfile(src):
            return messagebox.showerror("Error", "Select a valid file.")
        if not ip:
            return messagebox.showerror("Error", "Enter the receiver's IP address.")
        if not pw:
            return messagebox.showerror("Error", "Enter the shared password.")

        def task():
            self.log_clear(self._log_tb)
            self.log(self._log_tb, f"File     : {src}", "dim")
            self.log(self._log_tb, f"Receiver : {ip}:{port}", "dim")
            self.log(self._log_tb, "")

            # Step 1 — Encrypt to temp file
            self.log(self._log_tb, "▸ [1/3] Streaming encryption…", "info")
            self.set_progress(self._pb, 0.05, ACCENT3)
            
            # Use a .tmp.enc file
            tmp_bundle = src + ".tmp.enc"
            
            try:
                T = self.engine.encrypt_stream(src, tmp_bundle, pw, lambda p: self.set_progress(self._pb, 0.05 + p * 0.25, ACCENT3))
            except Exception as e:
                self.log(self._log_tb, f"✗ Encryption failed: {e}", "error")
                self.set_progress(self._pb, 0)
                return

            bundle_size = os.path.getsize(tmp_bundle)
            self.log(self._log_tb,
                     f"  ✔ Encrypted — {bundle_size:,} bytes  "
                     f"(PBKDF2 {T['pbkdf2_ms']}ms / AES {T['aes_ctr_ms']}ms / "
                     f"HMAC {T['hmac_ms']})", "success")
            self.set_progress(self._pb, 0.3, ACCENT3)

            # Step 2 — Send
            self.log(self._log_tb, f"▸ [2/3] Connecting to {ip}:{port}…", "info")

            def progress_cb(pct):
                self.set_progress(self._pb, 0.3 + pct * 0.65, ACCENT3)
                self._spd.configure(
                    text=f"Sending… {pct * 100:.0f}%  "
                         f"({int(bundle_size * pct / 1024)} KB / {bundle_size // 1024} KB)")

            try:
                elapsed = send_file_tcp(ip, port, Path(src).name, tmp_bundle, progress_cb)
            except Exception as e:
                self.log(self._log_tb, f"✗ Transfer error: {e}", "error")
                self.set_progress(self._pb, 0)
                self._spd.configure(text="")
                return
            finally:
                if os.path.exists(tmp_bundle):
                    os.remove(tmp_bundle)

            # Step 3 — Done
            self.set_progress(self._pb, 1.0, SUCCESS)
            spd = bundle_size / 1024 / elapsed if elapsed > 0 else 0
            self._spd.configure(text=f"✔ Complete — {spd:.0f} KB/s  ({elapsed:.2f}s)")
            self.log(self._log_tb, "▸ [3/3] Transfer complete!", "success")
            self.log(self._log_tb, f"  Bytes : {bundle_size:,}", "success")
            self.log(self._log_tb, f"  Time  : {elapsed:.2f}s  |  Speed: {spd:.0f} KB/s", "success")

            self.history.add("SENT", Path(src).name, bundle_size,
                             f"{ip}:{port}", "OK", elapsed)
            self.refresh_hist()

        threading.Thread(target=task, daemon=True).start()