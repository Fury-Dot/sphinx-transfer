import customtkinter as ctk
from network import get_local_ip
from constants import *

from encrypt import PanelEncrypt
from decrypt import PanelDecrypt
from send    import PanelSend
from receive import PanelReceive
from panel_history import PanelHistory
from bench   import PanelBench


class CryptoApp:
    def __init__(self, root, engine, history):
        self.root    = root
        self.engine  = engine
        self.history = history

        root.title("*SPHINX FILE TRANSFER*")
        root.geometry("1200x820")
        root.configure(fg_color=DARK_BG)
        root.resizable(True, True)

        self._build_header()
        self._build_sidebar()
        self._build_main()
        self._show("encrypt")

    # ── Header ─────────────────────────────────────────────────────────
    def _build_header(self):
        h = ctk.CTkFrame(self.root, fg_color=BOX_BG, height=62, corner_radius=0)
        h.pack(fill="x")
        h.pack_propagate(False)
        ctk.CTkLabel(h, text="◈ AES-CTR SECURE FILE SYSTEM  ·  P2P TRANSFER",
                     font=FH, text_color=ACCENT).pack(side="left", padx=24, pady=12)
        asm_c = SUCCESS if self.engine.asm.using_asm else WARNING
        asm_t = "ASM: ACTIVE" if self.engine.asm.using_asm else "ASM: PYTHON FALLBACK"
        ctk.CTkLabel(h, text=f"● {asm_t}   IP: {get_local_ip()}",
                     font=FS, text_color=asm_c).pack(side="right", padx=24)

    # ── Sidebar ─────────────────────────────────────────────────────────
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self.root, fg_color=PANEL_BG, width=232, corner_radius=0)
        sb.pack(fill="y", side="left")
        sb.pack_propagate(False)

        ctk.CTkLabel(sb, text="MENU", font=("Courier New", 11, "bold"),
                     text_color=DIM).pack(pady=(26, 6), padx=20, anchor="w")

        self._nav = {}
        items = [
            ("encrypt", "01  ENCRYPT FILE",         ACCENT),
            ("decrypt", "02  DECRYPT FILE",          ACCENT2),
            ("send",    "03  SEND FILE  ──────►",   ACCENT3),
            ("receive", "04  ◄────── RECEIVE FILE",  SUCCESS),
            ("history", "05  TRANSFER HISTORY",      WARNING),
            ("perf",    "06  COMPARE PERFORMANCE",   ACCENT),
            ("iters",   "07  COMPARE ITERATIONS",    ACCENT),
            ("keysize", "08  COMPARE KEY SIZE",       ACCENT),
        ]
        for key, lbl, ac in items:
            b = ctk.CTkButton(sb, text=lbl, font=FS, text_color=DIM, fg_color=PANEL_BG,
                              hover_color=BORDER,
                              corner_radius=4, anchor="w",
                              cursor="hand2", command=lambda k=key: self._show(k))
            b.pack(fill="x", padx=10, pady=2)
            self._nav[key] = (b, ac)

        
        ctk.CTkFrame(sb, fg_color=BORDER, height=2).pack(fill="x", padx=16, pady=16)
        ctk.CTkLabel(sb, text="SETTINGS", font=("Courier New", 11, "bold"),
                     text_color=DIM).pack(anchor="w", padx=20)

        # PBKDF2 iterations slider
        ctk.CTkLabel(sb, text="PBKDF2 Iterations",
                     font=FS, text_color=DIM).pack(anchor="w", padx=20, pady=(10, 0))
        self._iter_var = ctk.IntVar(value=100_000)
        self._iter_lbl = ctk.CTkLabel(sb, text="100,000", font=FS, text_color=ACCENT)
        self._iter_lbl.pack(anchor="w", padx=20)

        def on_iter(v):
            n = int(float(v))
            self._iter_lbl.configure(text=f"{n:,}")
            self.engine.iterations = n

        ctk.CTkSlider(sb, from_=10_000, to=500_000,
                      variable=self._iter_var, fg_color=BORDER, progress_color=ACCENT, button_color=ACCENT,
                      command=on_iter, width=186
                      ).pack(padx=20, pady=6)

        # AES key size radio buttons
        ctk.CTkLabel(sb, text="AES Key Size",
                     font=FS, text_color=DIM).pack(anchor="w", padx=20, pady=(10, 0))
        self._ks_var = ctk.StringVar(value="256-bit")

        def on_ks():
            self.engine.key_size = {"128-bit": 16, "192-bit": 24, "256-bit": 32}[self._ks_var.get()]

        for opt in ["128-bit", "192-bit", "256-bit"]:
            ctk.CTkRadioButton(sb, text=opt, variable=self._ks_var, value=opt,
                               font=FS, text_color=DIM, fg_color=ACCENT,
                               border_color=BORDER, hover_color=BORDER,
                               command=on_ks).pack(anchor="w", padx=26, pady=4)

    # ── Main panel container ─────────────────────────────────────────────
    def _build_main(self):
        main = ctk.CTkFrame(self.root, fg_color=DARK_BG, corner_radius=0)
        main.pack(fill="both", expand=True)

        # Build all panels — each has a .frame attribute
        p_history = PanelHistory(main, self.history)

        self._panels = {
            "encrypt": PanelEncrypt(main, self.engine).frame,
            "decrypt": PanelDecrypt(main, self.engine).frame,
            "send":    PanelSend(main, self.engine, self.history,
                                  p_history.refresh).frame,
            "receive": PanelReceive(main, self.engine, self.history,
                                     p_history.refresh).frame,
            "history": p_history.frame,
            "perf":    PanelBench(main, self.engine, "perf").frame,
            "iters":   PanelBench(main, self.engine, "iters").frame,
            "keysize": PanelBench(main, self.engine, "keysize").frame,
        }

    def _show(self, key: str):
        for f in self._panels.values():
            f.pack_forget()
        self._panels[key].pack(fill="both", expand=True)

        for k, (b, ac) in self._nav.items():
            b.configure(text_color=ac if k == key else DIM,
                        fg_color=SIDE_SEL if k == key else PANEL_BG)