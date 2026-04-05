import os
import threading
import customtkinter as ctk
from pathlib import Path
from tkinter import messagebox
from widgets import Widgets
from network import receive_file_tcp, get_local_ip
from constants import *


class PanelReceive(Widgets):
    def __init__(self, parent, engine, history, refresh_history_cb):
        self.engine       = engine
        self.history      = history
        self.refresh_hist = refresh_history_cb
        self._active      = False
        self.frame        = ctk.CTkFrame(parent, fg_color=DARK_BG, corner_radius=0)
        self._build()

    def _build(self):
        i = ctk.CTkFrame(self.frame, fg_color=DARK_BG, corner_radius=0)
        i.pack(fill="both", expand=True, padx=36, pady=20)

        ctk.CTkLabel(i, text="RECEIVE FILE",
                     font=("Courier New", 18, "bold"), text_color=SUCCESS).pack(anchor="w")
        ctk.CTkLabel(i, text="Listen TCP  ·  Receive bundle  ·  Verify HMAC  ·  Auto-decrypt",
                     font=FS, text_color=DIM).pack(anchor="w", pady=(2, 0))

        # Your IP display
        ip_box = ctk.CTkFrame(i, fg_color=BOX_BG, corner_radius=6)
        ip_box.pack(fill="x", pady=(10, 4))
        ctk.CTkLabel(ip_box,
                     text=f"Your IP: {get_local_ip()}   ← Share this with the sender",
                     font=FB, text_color=SUCCESS).pack(anchor="w", padx=14, pady=10)

        # Config
        self.sec(i, "LISTENER CONFIG", SUCCESS)
        self._port = ctk.StringVar(value=str(DEFAULT_PORT))
        self._dir  = ctk.StringVar(value=str(Path.home()))
        self.entry_row(i, "Listen Port",    self._port, width=10)
        self.dir_row(i,   "Save Directory", self._dir)

        # Decryption
        self.sec(i, "DECRYPTION", SUCCESS)
        self._pw   = ctk.StringVar()
        self._auto = ctk.BooleanVar(value=True)
        self.pw_row(i, "Shared Password", self._pw)
        ctk.CTkCheckBox(i, text="Auto-decrypt after receiving",
                        variable=self._auto, font=FS, text_color=DIM, fg_color=SUCCESS,
                        hover_color=SUCCESS).pack(anchor="w", pady=3)

        self._pb  = self.progress_bar(i)
        self._lbl = ctk.CTkLabel(i, text="Status: Idle", font=FS, text_color=DIM)
        self._lbl.pack(anchor="w")

        # Buttons
        br = ctk.CTkFrame(i, fg_color="transparent")
        br.pack(fill="x", pady=10)
        self._start_btn = self.action_btn(br, "◈  START LISTENING", SUCCESS, self._start)
        self._start_btn.pack(side="left")
        self._stop_btn = ctk.CTkButton(br, text="■  STOP", font=FB, text_color=DANGER, fg_color=BORDER,
                                       hover_color=HOVER_BG, corner_radius=6, height=40,
                                       command=self._stop, state="disabled")
        self._stop_btn.pack(side="left", padx=10)

        self.sec(i, "RECEIVE LOG", SUCCESS)
        self._log_tb = self.log_box(i, 200)
        self.clear_btn(br, self._log_tb).pack(side="left", padx=10)

    def _start(self):
        if self._active:
            return
        try:
            port = int(self._port.get().strip())
        except ValueError:
            return messagebox.showerror("Error", "Invalid port number.")
        save_dir = self._dir.get().strip()
        if not os.path.isdir(save_dir):
            return messagebox.showerror("Error", "Invalid save directory.")

        pw = self._pw.get()
        self._active = True
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")

        def task():
            self.log_clear(self._log_tb)
            self.log(self._log_tb, f"My IP   : {get_local_ip()}", "dim")
            self.log(self._log_tb, f"Port    : {port}", "dim")
            self.log(self._log_tb, f"Save to : {save_dir}", "dim")
            self.log(self._log_tb, "")

            def status_cb(msg):
                self._lbl.configure(text=f"Status: {msg}")
                self.log(self._log_tb, f"▸ {msg}", "info")

            def progress_cb(pct):
                self.set_progress(self._pb, pct * 0.7, SUCCESS)
                self._lbl.configure(text=f"Receiving… {pct * 100:.0f}%")

            try:
                out_path, orig, elapsed = receive_file_tcp(port, save_dir,
                                                           progress_cb, status_cb)
            except Exception as e:
                self.log(self._log_tb, f"✗ Receive failed: {e}", "error")
                self._lbl.configure(text="Status: Failed")
                self.set_progress(self._pb, 0)
                self._reset_buttons()
                return

            bsz = os.path.getsize(out_path)
            spd = bsz / 1024 / elapsed if elapsed > 0 else 0
            self.set_progress(self._pb, 0.75, SUCCESS)
            self.log(self._log_tb, f"✔ Received: {orig}", "success")
            self.log(self._log_tb, f"  Saved  : {out_path}")
            self.log(self._log_tb, f"  Size   : {bsz:,} bytes   Speed: {spd:.0f} KB/s")

            # Auto-decrypt
            if self._auto.get() and pw:
                self.log(self._log_tb, "")
                self.log(self._log_tb, "▸ Auto-decrypting…", "info")
                self.set_progress(self._pb, 0.8, SUCCESS)
                try:
                    dec = out_path[:-4] if out_path.endswith(".enc") else out_path + ".dec"
                    T = self.engine.decrypt_stream(out_path, dec, pw, lambda p: self.set_progress(self._pb, 0.8 + p * 0.2, SUCCESS))
                    
                    self.set_progress(self._pb, 1.0, SUCCESS)
                    self.log(self._log_tb, "  ✔ HMAC verified — integrity confirmed", "success")
                    self.log(self._log_tb, f"  ✔ Decrypted → {dec}", "success")
                    self.log(self._log_tb,
                             f"  PBKDF2 {T['pbkdf2_ms']}ms  |  "
                             f"HMAC {T['hmac_ms']}  |  AES {T['aes_ctr_ms']}ms")
                    self._lbl.configure(text="Status: Done ✔")
                except ValueError as e:
                    self.log(self._log_tb, f"  ✗ {e}", "error")
                    self._lbl.configure(text="Status: HMAC Mismatch ✗")
                    self.set_progress(self._pb, 0)
            else:
                self.set_progress(self._pb, 1.0, SUCCESS)
                self._lbl.configure(text="Status: Received ✔ (not auto-decrypted)")

            self.history.add("RECEIVED", orig, bsz, "sender", "OK", elapsed)
            self.refresh_hist()
            self._reset_buttons()

        threading.Thread(target=task, daemon=True).start()

    def _stop(self):
        self._active = False
        self._lbl.configure(text="Status: Stopped")
        self.log(self._log_tb, "■ Listener stopped.", "warn")
        self._reset_buttons()

    def _reset_buttons(self):
        self._active = False
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")