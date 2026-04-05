# ═══════════════════════════════════════════════
#  ui/panel_history.py  —  Panel 05: Transfer History
# ═══════════════════════════════════════════════

import customtkinter as ctk
from widgets import Widgets
from constants import *


class PanelHistory(Widgets):
    def __init__(self, parent, history):
        self.history = history
        self.frame   = ctk.CTkFrame(parent, fg_color=DARK_BG, corner_radius=0)
        self._build()

    def _build(self):
        i = ctk.CTkFrame(self.frame, fg_color=DARK_BG, corner_radius=0)
        i.pack(fill="both", expand=True, padx=36, pady=20)

        ctk.CTkLabel(i, text="TRANSFER HISTORY",
                     font=("Courier New", 18, "bold"), text_color=WARNING).pack(anchor="w")
        ctk.CTkLabel(i, text="All sent and received files — this session",
                     font=FS, text_color=DIM).pack(anchor="w", pady=(2, 0))

        # Column headers
        hdr = ctk.CTkFrame(i, fg_color=BOX_BG, corner_radius=6)
        hdr.pack(fill="x", pady=(12, 0))
        # Increase width multipliers for customtkinter
        for col, w in [("TIME", 64), ("DIR", 96), ("FILENAME", 208),
                       ("SIZE", 112), ("PEER", 144), ("STATUS", 64), ("KB/s", 64)]:
            ctk.CTkLabel(hdr, text=col, font=("Courier New", 11, "bold"),
                         text_color=WARNING, width=w, anchor="w").pack(side="left", padx=5, pady=6)

        # Scrollable rows replaces Canvas + inner frame + Scrollbar combo
        self._inner = ctk.CTkScrollableFrame(i, fg_color=DARK_BG, corner_radius=6)
        self._inner.pack(fill="both", expand=True, pady=(5, 0))

        # Clear button
        br = ctk.CTkFrame(i, fg_color="transparent")
        br.pack(fill="x", pady=8)
        ctk.CTkButton(br, text="CLEAR HISTORY", font=FS, text_color=DANGER, fg_color=BORDER,
                      hover_color=HOVER_BG, corner_radius=6, height=40, width=120,
                      command=self._clear).pack(side="left")

    def refresh(self):
        """Redraw all rows from history."""
        for w in self._inner.winfo_children():
            w.destroy()

        for idx, r in enumerate(self.history.records):
            bg  = ROW_BG if idx % 2 == 0 else "transparent"
            row = ctk.CTkFrame(self._inner, fg_color=bg, corner_radius=4)
            row.pack(fill="x", pady=2)

            dir_c = ACCENT3 if r.direction == "SENT" else SUCCESS
            st_c  = SUCCESS if r.status == "OK" else DANGER
            spd   = self.history.speed_str(r)

            for val, w, color in [
                (r.time,                 64,  DIM),
                (r.direction,            96,  dir_c),
                (r.filename[:24],        208, TXT),
                (f"{r.size:,} B",        112, DIM),
                (r.peer,                 144, DIM),
                (r.status,               64,  st_c),
                (spd,                    64,  ACCENT),
            ]:
                ctk.CTkLabel(row, text=val, font=FS, text_color=color,
                             width=w, anchor="w").pack(side="left", padx=5, pady=4)

    def _clear(self):
        self.history.clear()
        self.refresh()