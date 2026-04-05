# ═══════════════════════════════════════════════
#  ui/panel_bench.py  —  Panels 06/07/08: Benchmarks
# ═══════════════════════════════════════════════

import os
import time
import hashlib
import threading
import customtkinter as ctk
from widgets import Widgets
from crypto_engine import aes_ctr_crypt
from constants import *


class PanelBench(Widgets):
    """
    Single class handles all three benchmark panels.
    mode: "perf" | "iters" | "keysize"
    """

    TITLES = {
        "perf":    ("COMPARE PERFORMANCE",
                    "Python  vs  ASM  ·  PBKDF2-HMAC-SHA256 throughput"),
        "iters":   ("COMPARE ITERATIONS",
                    "PBKDF2 key derivation time vs iteration count"),
        "keysize": ("COMPARE KEY SIZE",
                    "AES-CTR encryption speed: 128 / 192 / 256-bit keys"),
    }

    def __init__(self, parent, engine, mode: str):
        self.engine = engine
        self.mode   = mode
        self.frame  = ctk.CTkFrame(parent, fg_color=DARK_BG, corner_radius=0)
        self._build()

    def _build(self):
        i = ctk.CTkFrame(self.frame, fg_color=DARK_BG, corner_radius=0)
        i.pack(fill="both", expand=True, padx=36, pady=20)

        title, subtitle = self.TITLES[self.mode]
        ctk.CTkLabel(i, text=title,
                     font=("Courier New", 18, "bold"), text_color=TXT).pack(anchor="w")
        ctk.CTkLabel(i, text=subtitle,
                     font=FS, text_color=DIM).pack(anchor="w", pady=(2, 0))

        self.sec(i, "CONFIG")
        self._pb = self.progress_bar(i)

        # Mode-specific config widgets
        if self.mode == "perf":
            self._sv = ctk.StringVar(value="64")
            self._rv = ctk.StringVar(value="5")
            r = ctk.CTkFrame(i, fg_color="transparent")
            r.pack(fill="x", pady=4)
            ctk.CTkLabel(r, text="Data (KB):", font=FS, text_color=DIM).pack(side="left")
            ctk.CTkEntry(r, textvariable=self._sv, font=FM, fg_color=PANEL_BG,
                         text_color=TXT, border_width=0, corner_radius=4, width=64).pack(side="left", padx=10)
            ctk.CTkLabel(r, text="Repeats:", font=FS, text_color=DIM).pack(side="left", padx=(20, 0))
            ctk.CTkEntry(r, textvariable=self._rv, font=FM, fg_color=PANEL_BG,
                         text_color=TXT, border_width=0, corner_radius=4, width=40).pack(side="left", padx=10)

        elif self.mode == "iters":
            self._iv = ctk.StringVar(value="10000,50000,100000,200000,500000")
            r = ctk.CTkFrame(i, fg_color="transparent")
            r.pack(fill="x", pady=4)
            ctk.CTkLabel(r, text="Iteration counts (comma-separated):",
                         font=FS, text_color=DIM).pack(side="left")
            ctk.CTkEntry(r, textvariable=self._iv, font=FM, fg_color=PANEL_BG,
                         text_color=TXT, border_width=0, corner_radius=4, width=304).pack(side="left", padx=10)

        elif self.mode == "keysize":
            ctk.CTkLabel(i, text="Tests: 1KB / 64KB / 1MB / 10MB  ×  128-bit / 192-bit / 256-bit keys",
                         font=FS, text_color=DIM).pack(anchor="w", pady=6)

        br = ctk.CTkFrame(i, fg_color="transparent")
        br.pack(fill="x", pady=10)
        self.action_btn(br, "▶  RUN BENCHMARK", ACCENT, self._run).pack(side="left")
        self._log_tb = self.log_box(i, 260)
        self.clear_btn(br, self._log_tb).pack(side="left", padx=10)
        self.sec(i, "RESULTS")

    def _run(self):
        runners = {
            "perf":    self._run_perf,
            "iters":   self._run_iters,
            "keysize": self._run_keysize,
        }
        threading.Thread(target=runners[self.mode], daemon=True).start()

    # ── Benchmark: ASM vs Python PBKDF2 ─────────────────────────────────
    def _run_perf(self):
        try:
            reps = int(self._rv.get())
        except ValueError:
            self.log(self._log_tb, "✗ Invalid config.", "error"); return

        self.log_clear(self._log_tb)
        self.log(self._log_tb, "Benchmark: Python vs ASM PBKDF2-HMAC-SHA256", "info")
        self.log(self._log_tb,
                 f"  Iterations: {self.engine.iterations:,}  |  Repeats: {reps}", "dim")
        self.log(self._log_tb,
                 f"  {'Run':>4}  {'Python (ms)':>14}  {'ASM/Fallback (ms)':>18}", "dim")
        self.log(self._log_tb, "  " + "─" * 42, "dim")

        pw   = b"benchmark_password"
        salt = os.urandom(16)
        tpy, tasm = [], []

        for k in range(reps):
            self.set_progress(self._pb, (k + 0.5) / reps)
            # Python
            t0 = time.perf_counter()
            hashlib.pbkdf2_hmac("sha256", pw, salt, self.engine.iterations, 32)
            tpy.append((time.perf_counter() - t0) * 1000)
            # ASM (or fallback)
            _, t = self.engine.asm.pbkdf2(pw, salt, self.engine.iterations, 32)
            tasm.append(t * 1000)
            self.log(self._log_tb,
                     f"  {k+1:>4}    {tpy[-1]:>12.2f}    {tasm[-1]:>16.2f}")

        avg_py  = sum(tpy) / len(tpy)
        avg_asm = sum(tasm) / len(tasm)
        speedup = avg_py / avg_asm if avg_asm > 0 else 1.0
        label   = "ASM" if self.engine.asm.using_asm else "Fallback"

        self.log(self._log_tb, "  " + "─" * 42, "dim")
        self.log(self._log_tb, f"  Avg Python   : {avg_py:.2f} ms",  "dim")
        self.log(self._log_tb, f"  Avg {label:<9}: {avg_asm:.2f} ms", "dim")
        self.log(self._log_tb, f"  Speedup      : {speedup:.2f}×",
                 "success" if speedup > 1.05 else "dim")
        self.set_progress(self._pb, 1.0)

    # ── Benchmark: PBKDF2 time vs iteration count ────────────────────────
    def _run_iters(self):
        try:
            counts = [int(x.strip()) for x in self._iv.get().split(",")]
        except ValueError:
            self.log(self._log_tb, "✗ Invalid iteration values.", "error"); return

        self.log_clear(self._log_tb)
        self.log(self._log_tb, "Benchmark: PBKDF2 Time vs Iteration Count", "info")
        self.log(self._log_tb, f"  {'Iterations':>12}  {'Time (ms)':>12}  Graph", "dim")
        self.log(self._log_tb, "  " + "─" * 52, "dim")

        pw    = b"test_password"
        salt  = os.urandom(16)
        times = []

        for k, n in enumerate(counts):
            self.set_progress(self._pb, (k + 0.5) / len(counts))
            _, t = self.engine.asm.pbkdf2(pw, salt, n, 32)
            ms   = t * 1000
            times.append(ms)
            bar_len = int(ms / max(times) * 28) if times else 0
            self.log(self._log_tb,
                     f"  {n:>12,}  {ms:>10.2f} ms  {'█' * bar_len}")

        self.log(self._log_tb, "  " + "─" * 52, "dim")
        self.log(self._log_tb,
                 f"  Min: {min(times):.2f} ms   Max: {max(times):.2f} ms", "dim")
        self.set_progress(self._pb, 1.0)

    # ── Benchmark: AES-CTR speed vs key size ─────────────────────────────
    def _run_keysize(self):
        self.log_clear(self._log_tb)
        self.log(self._log_tb, "Benchmark: AES-CTR Speed vs Key Size", "info")
        self.log(self._log_tb,
                 f"  {'Key':>8}  {'Data':>8}  {'ms':>10}  {'MB/s':>10}", "dim")
        self.log(self._log_tb, "  " + "─" * 48, "dim")

        sizes = [1024, 65536, 1048576, 10485760]
        keys  = {"AES-128": 16, "AES-192": 24, "AES-256": 32}
        done, total = 0, len(sizes) * len(keys)

        for key_name, key_len in keys.items():
            key   = os.urandom(key_len)
            nonce = os.urandom(16)
            for sz in sizes:
                data = os.urandom(sz)
                t0   = time.perf_counter()
                aes_ctr_crypt(key, nonce, data)
                ms   = (time.perf_counter() - t0) * 1000
                mbps = (sz / 1048576) / (ms / 1000) if ms > 0 else 0
                sz_l = f"{sz // 1024}KB" if sz < 1048576 else f"{sz // 1048576}MB"
                self.log(self._log_tb,
                         f"  {key_name:>8}  {sz_l:>8}  {ms:>8.3f} ms  {mbps:>8.2f} MB/s")
                done += 1
                self.set_progress(self._pb, done / total)
            self.log(self._log_tb, "")

        self.set_progress(self._pb, 1.0)
        self.log(self._log_tb, "✔ Benchmark complete.", "success")