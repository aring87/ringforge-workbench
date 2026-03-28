from __future__ import annotations

import tkinter as tk
from tkinter import ttk


def apply_app_theme(root: tk.Misc) -> ttk.Style:
    """Apply the shared ttk styling used by the GUI.

    This replacement keeps the style names expected by main_app.py and the
    child windows while staying conservative so it works across Windows builds.
    """
    style = ttk.Style(root)

    # Use a stable built-in theme when available.
    for theme_name in ("clam", "vista", "default"):
        try:
            style.theme_use(theme_name)
            break
        except tk.TclError:
            continue

    bg = "#f5f7fb"
    panel = "#ffffff"
    border = "#d7dbe3"
    text = "#1f2937"
    muted = "#5b6472"
    accent = "#1f6feb"
    accent_hover = "#1859bc"
    accent_dark = "#0f3d91"

    try:
        root.configure(bg=bg)
    except Exception:
        pass

    style.configure(".", background=bg, foreground=text)
    style.configure("TFrame", background=bg)
    style.configure("Card.TFrame", background=panel, relief="flat", borderwidth=1)
    style.configure("TLabelframe", background=bg, foreground=text)
    style.configure("TLabelframe.Label", background=bg, foreground=text, font=("Segoe UI", 10, "bold"))
    style.configure("TLabel", background=bg, foreground=text, font=("Segoe UI", 10))
    style.configure("Muted.TLabel", background=bg, foreground=muted, font=("Segoe UI", 9))
    style.configure("SectionHeader.TLabel", background=bg, foreground=accent_dark, font=("Segoe UI", 11, "bold"))
    style.configure("SummaryValue.TLabel", background=bg, foreground=text, font=("Segoe UI", 18, "bold"))
    style.configure("SummaryAccent.TLabel", background=bg, foreground=accent_dark, font=("Segoe UI", 10, "bold"))

    style.configure(
        "TButton",
        font=("Segoe UI", 10),
        padding=(10, 6),
        relief="flat",
        borderwidth=1,
    )
    style.configure(
        "Action.TButton",
        font=("Segoe UI", 10, "bold"),
        padding=(12, 7),
        foreground="white",
        background=accent,
        borderwidth=0,
        focusthickness=0,
        focuscolor=accent,
    )
    style.map(
        "Action.TButton",
        background=[("active", accent_hover), ("pressed", accent_dark), ("disabled", "#9fb6e6")],
        foreground=[("disabled", "#eef3ff")],
    )

    style.configure(
        "Side.Action.TButton",
        font=("Segoe UI", 9, "bold"),
        padding=(10, 6),
        foreground="white",
        background=accent_dark,
        borderwidth=0,
    )
    style.map(
        "Side.Action.TButton",
        background=[("active", accent), ("pressed", accent_dark), ("disabled", "#9fb6e6")],
        foreground=[("disabled", "#eef3ff")],
    )

    style.configure(
        "TEntry",
        padding=6,
        fieldbackground="white",
        foreground=text,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
    )
    style.configure(
        "TCombobox",
        padding=4,
        fieldbackground="white",
        foreground=text,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
        arrowsize=14,
    )
    style.map("TCombobox", fieldbackground=[("readonly", "white")])

    style.configure(
        "TNotebook",
        background=bg,
        borderwidth=0,
        tabmargins=(2, 2, 2, 0),
    )
    style.configure(
        "TNotebook.Tab",
        font=("Segoe UI", 10, "bold"),
        padding=(12, 8),
        background="#e8edf7",
        foreground=text,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", panel), ("active", "#dde7f7")],
        foreground=[("selected", accent_dark)],
    )

    style.configure(
        "Horizontal.TProgressbar",
        troughcolor="#e5eaf3",
        bordercolor="#e5eaf3",
        background=accent,
        lightcolor=accent,
        darkcolor=accent,
    )

    style.configure(
        "Treeview",
        background="white",
        fieldbackground="white",
        foreground=text,
        rowheight=24,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
    )
    style.configure(
        "Treeview.Heading",
        background="#eef2f8",
        foreground=text,
        font=("Segoe UI", 9, "bold"),
        relief="flat",
    )
    style.map("Treeview.Heading", background=[("active", "#e1e8f5")])

    return style
