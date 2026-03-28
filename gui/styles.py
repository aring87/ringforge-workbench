from __future__ import annotations

import tkinter as tk
from tkinter import ttk


def apply_app_theme(root: tk.Misc) -> ttk.Style:
    style = ttk.Style(root)

    # Use a theme that respects color overrides better on Windows
    for theme_name in ("clam", "vista", "default"):
        try:
            style.theme_use(theme_name)
            break
        except tk.TclError:
            continue

    # Lexus-style blue / black / white blend
    bg = "#05070B"           # near-black app background
    panel = "#0B1220"        # blue-black panel / field background
    panel_alt = "#101A2E"    # slightly lighter panel
    border = "#294C8E"       # Lexus-style blue border
    text = "#F7FAFF"         # bright white text
    muted = "#B8C7E6"        # soft blue-white
    accent = "#2F6BFF"       # primary blue
    accent_hover = "#4C82FF"
    accent_dark = "#183A7A"
    progress_trough = "#16233D"
    heading_bg = "#16233D"
    disabled_fg = "#7F8DA3"
    
    root.option_add("*TCombobox*Listbox.background", panel)
    root.option_add("*TCombobox*Listbox.foreground", text)
    root.option_add("*TCombobox*Listbox.selectBackground", accent)
    root.option_add("*TCombobox*Listbox.selectForeground", text)

    try:
        root.configure(bg=bg)
    except Exception:
        pass

    style.configure(".", background=bg, foreground=text)
    style.configure("TFrame", background=bg)
    style.configure("Card.TFrame", background=panel, relief="flat", borderwidth=1)

    style.configure(
        "TLabelframe",
        background=bg,
        foreground=text,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
    )
    style.configure(
        "TLabelframe.Label",
        background=bg,
        foreground=text,
        font=("Segoe UI", 10, "bold"),
    )

    style.configure("TLabel", background=bg, foreground=text, font=("Segoe UI", 10))
    style.configure("Muted.TLabel", background=bg, foreground=muted, font=("Segoe UI", 9))
    style.configure("SectionHeader.TLabel", background=bg, foreground=accent, font=("Segoe UI", 11, "bold"))
    style.configure("SummaryValue.TLabel", background=bg, foreground=text, font=("Segoe UI", 18, "bold"))
    style.configure("SummaryAccent.TLabel", background=bg, foreground=accent, font=("Segoe UI", 10, "bold"))

    style.configure(
        "TButton",
        font=("Segoe UI", 10),
        padding=(10, 6),
        relief="flat",
        borderwidth=1,
        background=panel_alt,
        foreground=text,
    )
    style.map(
        "TButton",
        background=[
            ("active", panel_alt),
            ("pressed", panel),
            ("disabled", panel_alt),
        ],
        foreground=[("disabled", disabled_fg)],
    )

    style.configure(
        "Action.TButton",
        font=("Segoe UI", 10, "bold"),
        padding=(12, 7),
        foreground=text,
        background=accent_dark,
        borderwidth=1,
        focusthickness=0,
        focuscolor=accent_dark,
        relief="flat",
    )
    style.map(
        "Action.TButton",
        background=[
            ("active", accent_hover),
            ("pressed", "#102A5C"),
            ("disabled", "#5E739E"),
        ],
        foreground=[("disabled", "#DCE6FA")],
    )

    style.configure(
        "Side.Action.TButton",
        font=("Segoe UI", 9, "bold"),
        padding=(10, 6),
        foreground=text,
        background=accent_dark,
        borderwidth=1,
        relief="flat",
    )
    style.map(
        "Side.Action.TButton",
        background=[
            ("active", accent),
            ("pressed", "#102A5C"),
            ("disabled", "#5E739E"),
        ],
        foreground=[("disabled", "#DCE6FA")],
    )

    style.configure(
        "TEntry",
        padding=6,
        fieldbackground=panel,
        foreground=text,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
        insertcolor=text,
    )
    style.map(
        "TEntry",
        fieldbackground=[("disabled", panel), ("!disabled", panel)],
        foreground=[("disabled", disabled_fg), ("!disabled", text)],
        bordercolor=[("focus", accent), ("!focus", border)],
        lightcolor=[("focus", accent), ("!focus", border)],
        darkcolor=[("focus", accent), ("!focus", border)],
    )

    style.configure(
        "TCombobox",
        padding=4,
        fieldbackground=panel,
        background=panel_alt,
        foreground=text,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
        arrowsize=14,
        arrowcolor=text,
    )

    style.map(
        "TCombobox",
        fieldbackground=[
            ("readonly", panel),
            ("disabled", panel),
            ("!disabled", panel),
        ],
        background=[
            ("readonly", panel_alt),
            ("active", panel_alt),
            ("!disabled", panel_alt),
        ],
        foreground=[
            ("readonly", text),
            ("disabled", "#7F8DA3"),
            ("!disabled", text),
        ],
        selectbackground=[("readonly", panel)],
        selectforeground=[("readonly", text)],
        bordercolor=[("focus", accent), ("!focus", border)],
        lightcolor=[("focus", accent), ("!focus", border)],
        darkcolor=[("focus", accent), ("!focus", border)],
        arrowcolor=[("disabled", "#7F8DA3"), ("!disabled", text)],
    )

    style.configure(
        "Dark.TSpinbox",
        padding=4,
        fieldbackground=panel,
        background=panel_alt,
        foreground=text,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
        arrowsize=14,
        arrowcolor=text,
        insertcolor=text,
    )
    style.map(
        "Dark.TSpinbox",
        fieldbackground=[
            ("readonly", panel),
            ("disabled", panel),
            ("!disabled", panel),
        ],
        foreground=[
            ("disabled", disabled_fg),
            ("readonly", text),
            ("!disabled", text),
        ],
        bordercolor=[("focus", accent), ("!focus", border)],
        lightcolor=[("focus", accent), ("!focus", border)],
        darkcolor=[("focus", accent), ("!focus", border)],
        arrowcolor=[("disabled", disabled_fg), ("!disabled", text)],
        background=[("active", panel_alt), ("!disabled", panel_alt)],
    )

    style.configure(
        "Dark.TCheckbutton",
        background=bg,
        foreground=text,
        font=("Segoe UI", 10),
        focuscolor=bg,
        indicatorcolor=panel,
        indicatormargin=2,
        indicatordiameter=12,
        padding=2,
    )
    style.map(
        "Dark.TCheckbutton",
        background=[
            ("active", bg),
            ("selected", bg),
            ("disabled", bg),
            ("!disabled", bg),
        ],
        foreground=[
            ("disabled", disabled_fg),
            ("active", text),
            ("selected", text),
            ("!disabled", text),
        ],
        indicatorbackground=[
            ("selected", accent),
            ("active", panel),
            ("!disabled", panel),
        ],
        indicatorforeground=[
            ("selected", text),
            ("!disabled", text),
        ],
        indicatormargin=[("!disabled", 2)],
    )

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
        background=heading_bg,
        foreground=text,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", panel), ("active", panel_alt)],
        foreground=[("selected", accent), ("active", text)],
    )

    style.configure(
        "Horizontal.TProgressbar",
        troughcolor=progress_trough,
        bordercolor=progress_trough,
        background=accent,
        lightcolor=accent,
        darkcolor=accent,
    )

    style.configure(
        "Treeview",
        background=panel,
        fieldbackground=panel,
        foreground=text,
        rowheight=24,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
    )
    style.map(
        "Treeview",
        background=[("selected", accent_dark)],
        foreground=[("selected", text)],
    )

    style.configure(
        "Treeview.Heading",
        background=heading_bg,
        foreground=text,
        font=("Segoe UI", 9, "bold"),
        relief="flat",
    )
    style.map("Treeview.Heading", background=[("active", panel_alt)])

    return style