# ═══════════════════════════════════════════════
#  ui/widgets.py  —  Shared UI Helpers
# ═══════════════════════════════════════════════

import customtkinter as ctk
from tkinter import filedialog
from constants import *


class Widgets:
    """
    Mixin class — provides all shared widget-building helpers.
    Inherit this into any panel or the main app class.
    """

    TAG_COLORS = {
        "success": SUCCESS,
        "error":   DANGER,
        "info":    ACCENT,
        "warn":    WARNING,
        "dim":     DIM,
        "orange":  ACCENT3,
        "plain":   TXT
    }

    # ── Section header ──────────────────────────────────────────────────
    def sec(self, parent, title, color=ACCENT):
        ctk.CTkLabel(parent, text=title, font=FB, text_color=color).pack(anchor="w", pady=(16, 3))
        ctk.CTkFrame(parent, fg_color=color, height=2, corner_radius=0).pack(fill="x")

    # ── File browse row ─────────────────────────────────────────────────
    def file_row(self, parent, label, var, filetypes):
        r = ctk.CTkFrame(parent, fg_color="transparent")
        r.pack(fill="x", pady=4)
        ctk.CTkLabel(r, text=label, font=FS, text_color=DIM,
                     width=160, anchor="w").pack(side="left")
        ctk.CTkEntry(r, textvariable=var, font=FM, fg_color=PANEL_BG,
                     text_color=TXT, border_width=0, corner_radius=4
                     ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(r, text="BROWSE", font=FS, text_color=ACCENT, fg_color=BORDER,
                      hover_color=HOVER_BG, corner_radius=4, width=60,
                      command=lambda: var.set(
                          filedialog.askopenfilename(filetypes=filetypes) or var.get())
                      ).pack(side="left")

    # ── Directory browse row ────────────────────────────────────────────
    def dir_row(self, parent, label, var):
        r = ctk.CTkFrame(parent, fg_color="transparent")
        r.pack(fill="x", pady=4)
        ctk.CTkLabel(r, text=label, font=FS, text_color=DIM,
                     width=160, anchor="w").pack(side="left")
        ctk.CTkEntry(r, textvariable=var, font=FM, fg_color=PANEL_BG,
                     text_color=TXT, border_width=0, corner_radius=4
                     ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(r, text="BROWSE", font=FS, text_color=SUCCESS, fg_color=BORDER,
                      hover_color=HOVER_BG, corner_radius=4, width=60,
                      command=lambda: var.set(filedialog.askdirectory() or var.get())
                      ).pack(side="left")

    # ── Plain text entry row ────────────────────────────────────────────
    def entry_row(self, parent, label, var, width=None):
        r = ctk.CTkFrame(parent, fg_color="transparent")
        r.pack(fill="x", pady=4)
        ctk.CTkLabel(r, text=label, font=FS, text_color=DIM,
                     width=160, anchor="w").pack(side="left")
        kw = {"width": width * 8 if width else 140}
        ctk.CTkEntry(r, textvariable=var, font=FM, fg_color=PANEL_BG,
                     text_color=TXT, border_width=0, corner_radius=4,
                     **kw).pack(side="left")

    # ── Password row with show/hide ─────────────────────────────────────
    def pw_row(self, parent, label, var):
        r = ctk.CTkFrame(parent, fg_color="transparent")
        r.pack(fill="x", pady=4)
        ctk.CTkLabel(r, text=label, font=FS, text_color=DIM,
                     width=160, anchor="w").pack(side="left")
        show = ctk.BooleanVar(value=False)
        ent  = ctk.CTkEntry(r, textvariable=var, font=FM, fg_color=PANEL_BG,
                            text_color=TXT, border_width=0, corner_radius=4, show="●")
        ent.pack(side="left", fill="x", expand=True, padx=(0, 8))

        def toggle():
            show.set(not show.get())
            ent.configure(show="" if show.get() else "●")
            btn.configure(text="HIDE" if show.get() else "SHOW")

        btn = ctk.CTkButton(r, text="SHOW", font=FS, text_color=DIM, fg_color=BORDER,
                            hover_color=HOVER_BG, corner_radius=4, width=60,
                            command=toggle)
        btn.pack(side="left")

    # ── Progress bar (CustomTkinter ProgressBar) ────────────────────────
    def progress_bar(self, parent):
        pb = ctk.CTkProgressBar(parent, height=8, fg_color=BORDER, corner_radius=4)
        pb.pack(fill="x", pady=(10, 5))
        pb.set(0)
        return pb

    def set_progress(self, pb_widget, pct, color=ACCENT):
        pb_widget.configure(progress_color=color)
        pb_widget.set(pct)

    # ── Scrollable log text box ─────────────────────────────────────────
    def log_box(self, parent, height=200):
        frame = ctk.CTkFrame(parent, fg_color=ROW_BG, corner_radius=6)
        frame.pack(fill="both", expand=True, pady=4)
        
        # We'll use CTkTextbox
        tb = ctk.CTkTextbox(frame, font=FS, fg_color=ROW_BG, text_color=TXT,
                            height=height, corner_radius=6, wrap="word")
        tb.pack(fill="both", expand=True, padx=2, pady=2)
        tb.configure(state="disabled")
        
        # Tag configs map differently in ctk, but we can do it via underlying text widget if needed
        # Or just use single color insertion? For CustomTkinter, textbox has basic tag support now!
        for tag, color in self.TAG_COLORS.items():
            tb.tag_config(tag, foreground=color)

        return tb

    def log(self, tb, msg, tag="plain"):
        tb.configure(state="normal")
        tb.insert("end", msg + "\n", tag)
        tb.see("end")
        tb.configure(state="disabled")

    def log_clear(self, tb):
        tb.configure(state="normal")
        tb.delete("1.0", "end")
        tb.configure(state="disabled")

    # ── Action button ───────────────────────────────────────────────────
    def action_btn(self, parent, text, color, command):
        return ctk.CTkButton(parent, text=text, font=FB,
                             text_color=DARK_BG, fg_color=color,
                             hover_color=DIM, corner_radius=6, height=40,
                             command=command)

    # ── Clear log button ────────────────────────────────────────────────
    def clear_btn(self, parent, log_ref):
        return ctk.CTkButton(parent, text="CLEAR", font=FS, text_color=DIM, fg_color=BORDER,
                             hover_color=HOVER_BG, corner_radius=6, height=40, width=80,
                             command=lambda: self.log_clear(log_ref))