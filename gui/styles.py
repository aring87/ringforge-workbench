from tkinter import ttk

def apply_app_theme(root):
    bg = "#081426"
    panel = "#0d1b33"
    panel2 = "#13284a"
    text = "#eaf2ff"
    muted = "#9bb2d1"
    accent = "#1f6fff"
    accent_hover = "#3d86ff"
    border = "#2a4365"
    disabled_bg = "#102038"
    disabled_fg = "#6f87a8"

    root.option_add("*Menu.background", "#0d1b33")
    root.option_add("*Menu.foreground", "#eaf2ff")
    root.option_add("*Menu.activeBackground", "#1f6fff")
    root.option_add("*Menu.activeForeground", "#ffffff")
    root.option_add("*Menu.borderWidth", 1)

    root.option_add("*TCombobox*Listbox.background", "#0d1b33")
    root.option_add("*TCombobox*Listbox.foreground", "#eaf2ff")
    root.option_add("*TCombobox*Listbox.selectBackground", "#1f6fff")
    root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

    root.configure(bg=bg)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure(".", background=bg, foreground=text)
    style.configure("TFrame", background=bg)
    style.configure("TLabel", background=bg, foreground=text)

    style.configure(
        "SummaryValue.TLabel",
        font=("Segoe UI", 14, "bold"),
        foreground="#f8fbff",
        background="#001833",
    )

    style.configure(
        "SummaryAccent.TLabel",
        font=("Segoe UI", 11, "bold"),
        foreground="#7fb3ff",
        background="#001833",
    )

    style.configure(
        "SectionHeader.TLabel",
        font=("Segoe UI", 10, "bold"),
        foreground="#9fc5ff",
        background="#001833",
    )

    style.configure(
        "TLabelframe",
        background=bg,
        foreground=text,
        borderwidth=1,
        relief="solid",
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
    )
    style.configure("TLabelframe.Label", background=bg, foreground="#7db3ff")

    style.configure(
        "TButton",
        background=panel2,
        foreground=text,
        borderwidth=1,
        relief="flat",
        padding=6,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
    )
    style.map(
        "TButton",
        background=[("active", accent_hover), ("pressed", accent), ("disabled", disabled_bg)],
        foreground=[("disabled", disabled_fg)],
        bordercolor=[("active", accent_hover), ("pressed", accent), ("disabled", border)],
    )

    style.configure(
        "Action.TButton",
        background=panel2,
        foreground=text,
        borderwidth=1,
        relief="raised",
        padding=(16, 10),
        font=("Segoe UI Semibold", 10),
        bordercolor=border,
        lightcolor="#27496d",
        darkcolor="#10243d",
        anchor="center",
    )
    style.map(
        "Action.TButton",
        background=[
            ("pressed", "#163a63"),
            ("active", "#1a4677"),
            ("disabled", disabled_bg),
        ],
        foreground=[
            ("disabled", disabled_fg),
            ("active", "#ffffff"),
        ],
        bordercolor=[
            ("pressed", "#35597c"),
            ("active", "#466b91"),
            ("!disabled", border),
            ("disabled", border),
        ],
        lightcolor=[
            ("pressed", "#214a7a"),
            ("active", "#315b89"),
            ("!disabled", "#27496d"),
        ],
        darkcolor=[
            ("pressed", "#0d2238"),
            ("active", "#14304f"),
            ("!disabled", "#10243d"),
        ],
        relief=[
            ("pressed", "sunken"),
            ("!pressed", "raised"),
        ],
    )

    style.configure(
        "Side.Action.TButton",
        background=panel2,
        foreground=text,
        borderwidth=1,
        relief="raised",
        padding=(10, 3),
        font=("Segoe UI Semibold", 9),
        bordercolor=border,
        lightcolor="#27496d",
        darkcolor="#10243d",
        anchor="center",
    )
    style.map(
        "Side.Action.TButton",
        background=[
            ("pressed", "#163a63"),
            ("active", "#1a4677"),
            ("disabled", disabled_bg),
        ],
        foreground=[
            ("disabled", disabled_fg),
            ("active", "#ffffff"),
        ],
        bordercolor=[
            ("pressed", "#35597c"),
            ("active", "#466b91"),
            ("!disabled", border),
            ("disabled", border),
        ],
        lightcolor=[
            ("pressed", "#214a7a"),
            ("active", "#315b89"),
            ("!disabled", "#27496d"),
        ],
        darkcolor=[
            ("pressed", "#0d2238"),
            ("active", "#14304f"),
            ("!disabled", "#10243d"),
        ],
        relief=[
            ("pressed", "sunken"),
            ("!pressed", "raised"),
        ],
    )

    style.configure(
        "TEntry",
        fieldbackground=panel,
        foreground=text,
        background=panel,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
        insertcolor=text,
        relief="flat",
        padding=4,
    )

    style.configure(
        "TCombobox",
        fieldbackground=panel,
        foreground=text,
        background=panel,
        arrowcolor=text,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
        relief="flat",
        padding=4,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", panel), ("disabled", disabled_bg)],
        foreground=[("readonly", text), ("disabled", disabled_fg)],
        background=[("readonly", panel), ("disabled", disabled_bg)],
        arrowcolor=[("disabled", disabled_fg)],
    )

    style.configure(
        "TSpinbox",
        fieldbackground=panel,
        foreground=text,
        background=panel,
        arrowcolor=text,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
        relief="flat",
        padding=2,
    )
    style.map(
        "TSpinbox",
        fieldbackground=[("disabled", disabled_bg), ("readonly", panel)],
        foreground=[("disabled", disabled_fg), ("readonly", text)],
        background=[("disabled", disabled_bg), ("readonly", panel)],
        arrowcolor=[("disabled", disabled_fg)],
    )

    style.configure(
        "TCheckbutton",
        background=bg,
        foreground=text,
        indicatorbackground=panel,
        indicatormargin=2,
    )
    style.map(
        "TCheckbutton",
        foreground=[("disabled", disabled_fg)],
        background=[("disabled", bg)],
        indicatorbackground=[("selected", accent), ("disabled", disabled_bg)],
    )

    style.configure(
        "TRadiobutton",
        background=bg,
        foreground=text,
        indicatorbackground=panel,
    )
    style.map(
        "TRadiobutton",
        foreground=[("disabled", disabled_fg)],
        indicatorbackground=[("selected", accent), ("disabled", disabled_bg)],
    )

    style.configure(
        "Treeview",
        background="#0d1b33",
        fieldbackground="#0d1b33",
        foreground="#eaf2ff",
        rowheight=28,
        bordercolor="#2a4365",
        lightcolor="#2a4365",
        darkcolor="#2a4365",
    )
    style.map(
        "Treeview",
        background=[("selected", "#1f6fff")],
        foreground=[("selected", "#ffffff")],
    )

    style.configure(
        "Treeview.Heading",
        background="#13284a",
        foreground="#eaf2ff",
        bordercolor="#365a88",
        lightcolor="#365a88",
        darkcolor="#365a88",
        relief="raised",
        padding=(12, 8),
        font=("Segoe UI", 10, "bold"),
    )
    style.map(
        "Treeview.Heading",
        background=[("active", "#13284a"), ("pressed", "#1f6fff")],
        foreground=[("active", "#eaf2ff"), ("pressed", "#ffffff")],
        relief=[("active", "raised"), ("pressed", "sunken")],
    )

    style.configure("TNotebook", background=bg, borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background=panel2,
        foreground=text,
        padding=(10, 6),
        borderwidth=0,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", accent), ("active", "#18345e")],
        foreground=[("selected", "white")],
    )

    style.configure(
        "Horizontal.TProgressbar",
        troughcolor=panel,
        background=accent,
        bordercolor=border,
        lightcolor=accent,
        darkcolor=accent,
    )

    return {
        "bg": bg,
        "panel": panel,
        "panel2": panel2,
        "text": text,
        "muted": muted,
        "accent": accent,
        "accent_hover": accent_hover,
        "border": border,
        "disabled_bg": disabled_bg,
        "disabled_fg": disabled_fg,
        "style": style,
    }