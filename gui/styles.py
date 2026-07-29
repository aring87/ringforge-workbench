"""Central ttk theme for RingForge Workbench.

Every ttk style name used anywhere in ``gui`` is declared here, once, from the
tokens in :mod:`gui.theme`. Individual windows should call
:func:`apply_app_theme` (or :func:`apply_window_theme`) and then simply use the
style names below -- they must not re-declare their own palettes.

Style vocabulary
----------------

Frames      ``TFrame`` ``App.TFrame`` ``Card.TFrame`` ``Header.TFrame``
            ``SummaryCard.TFrame`` ``Toolbar.TFrame``
Labels      ``TLabel`` ``Muted.TLabel`` ``Title.TLabel`` ``Subtitle.TLabel``
            ``SectionHeader.TLabel`` ``Eyebrow.TLabel`` ``Field.TLabel``
            plus ``Card.*`` variants for labels sitting on a card surface
Buttons     ``Action.TButton`` (primary) ``Secondary.TButton`` ``Ghost.TButton``
            ``Danger.TButton`` ``Side.Action.TButton`` ``Launcher.Action.TButton``
Progress    ``Horizontal.TProgressbar`` and ``Success`` / ``Warning`` /
            ``Danger`` prefixed variants
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from gui import theme as T


def apply_app_theme(root: tk.Misc) -> ttk.Style:
    """Install the RingForge theme on ``root`` and return the ttk style object."""
    style = ttk.Style(root)

    # clam is the only stock theme that honours colour overrides consistently
    # on Windows; the others ignore fieldbackground/bordercolor.
    for theme_name in ("clam", "alt", "default"):
        try:
            style.theme_use(theme_name)
            break
        except tk.TclError:
            continue

    T.resolve_fonts(root)

    _configure_popups(root)
    _configure_base(style)
    _configure_frames(style)
    _configure_labels(style)
    _configure_buttons(style)
    _configure_inputs(style)
    _configure_toggles(style)
    _configure_notebook(style)
    _configure_progress(style)
    _configure_tables(style)
    _configure_scrollbars(style)

    try:
        root.configure(bg=T.BG)
    except Exception:
        pass

    return style


#: Windows other than the main app call this; same theme, clearer intent.
apply_window_theme = apply_app_theme


# ---------------------------------------------------------------------------
# Popup / option database
# ---------------------------------------------------------------------------

def _configure_popups(root: tk.Misc) -> None:
    """Style the Tk widgets that ttk cannot reach (combobox dropdowns, menus)."""
    opts = {
        "*TCombobox*Listbox.background": T.SUNKEN,
        "*TCombobox*Listbox.foreground": T.TEXT,
        "*TCombobox*Listbox.selectBackground": T.ACCENT,
        "*TCombobox*Listbox.selectForeground": T.TEXT_ON_ACCENT,
        "*TCombobox*Listbox.borderWidth": 0,
        "*TCombobox*Listbox.highlightThickness": 0,
        "*Menu.background": T.SURFACE,
        "*Menu.foreground": T.TEXT,
        "*Menu.activeBackground": T.ACCENT,
        "*Menu.activeForeground": T.TEXT_ON_ACCENT,
        "*Menu.borderWidth": 0,
        "*Menu.relief": "flat",
        # Tk gives Text/Listbox a 1px focus ring in a light system colour,
        # which shows up as a white outline on every dark pane. Kill it here
        # so individual call sites do not each have to remember.
        "*Text.highlightThickness": 0,
        "*Text.borderWidth": 0,
        "*Listbox.highlightThickness": 0,
        "*Listbox.borderWidth": 0,
        "*Listbox.selectBackground": T.ACCENT_SOFT,
        "*Listbox.selectForeground": T.TEXT,
        "*Entry.highlightThickness": 0,
        # Windows draws the classic tk.Scrollbar natively and ignores colour
        # options entirely, so these only help on other platforms. Prefer
        # gui.components.ScrolledText, which uses a themeable ttk scrollbar.
        "*Scrollbar.background": T.mix(T.RAISED, T.BG, 0.25),
        "*Scrollbar.troughColor": T.BG,
        "*Scrollbar.activeBackground": T.RAISED_HOVER,
        "*Scrollbar.highlightThickness": 0,
        "*Scrollbar.borderWidth": 0,
    }
    for key, value in opts.items():
        try:
            root.option_add(key, value)
        except Exception:
            pass


def _configure_base(style: ttk.Style) -> None:
    style.configure(
        ".",
        background=T.BG,
        foreground=T.TEXT,
        font=T.f_body(),
        borderwidth=0,
        focuscolor=T.ACCENT,
        # clam defaults these to near-white and draws a 3D bevel with them on
        # any element we do not style explicitly. Dark values here mean a
        # missed widget degrades to a flat hairline instead of a white frame.
        bordercolor=T.BORDER,
        lightcolor=T.BORDER,
        darkcolor=T.BORDER,
        troughcolor=T.SUNKEN,
    )
    style.configure("TSeparator", background=T.BORDER)
    style.configure("TPanedwindow", background=T.BG)
    style.configure("Sash", sashthickness=6, gripcount=0)


# ---------------------------------------------------------------------------
# Frames and containers
# ---------------------------------------------------------------------------

def _configure_frames(style: ttk.Style) -> None:
    style.configure("TFrame", background=T.BG)
    style.configure("App.TFrame", background=T.BG)
    style.configure("Banded.TFrame", background=T.BG_ALT)

    # A card is a raised surface; anything placed on it must use a Card.* style
    # so the backgrounds match.
    style.configure("Card.TFrame", background=T.SURFACE, relief="flat", borderwidth=0)
    style.configure("CardBody.TFrame", background=T.SURFACE, relief="flat", borderwidth=0)
    style.configure("Header.TFrame", background=T.SURFACE, relief="flat", borderwidth=0)
    style.configure("SummaryCard.TFrame", background=T.RAISED, relief="flat", borderwidth=0)
    style.configure("Toolbar.TFrame", background=T.SURFACE, relief="flat", borderwidth=0)
    style.configure("Sunken.TFrame", background=T.SUNKEN, relief="flat", borderwidth=0)
    style.configure("Accent.TFrame", background=T.ACCENT)
    style.configure("Divider.TFrame", background=T.BORDER)

    for name, bg in (
        ("TLabelframe", T.BG),
        ("App.TLabelframe", T.BG),
        ("Section.TLabelframe", T.BG),
        ("Card.TLabelframe", T.SURFACE),
    ):
        style.configure(
            name,
            background=bg,
            foreground=T.TEXT,
            borderwidth=1,
            relief="solid",
            bordercolor=T.BORDER,
            lightcolor=T.BORDER,
            darkcolor=T.BORDER,
        )
        style.configure(
            f"{name}.Label",
            background=bg,
            foreground=T.TEXT_SECONDARY,
            font=T.f_subheading(),
        )


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------

def _configure_labels(style: ttk.Style) -> None:
    # (style name, foreground, font, background)
    specs = [
        ("TLabel", T.TEXT, T.f_body(), T.BG),
        ("Muted.TLabel", T.TEXT_MUTED, T.f_small(), T.BG),
        ("Secondary.TLabel", T.TEXT_SECONDARY, T.f_body(), T.BG),
        ("Display.TLabel", T.TEXT, T.f_display(), T.BG),
        ("Title.TLabel", T.TEXT, T.f_title(), T.BG),
        ("Subtitle.TLabel", T.TEXT_SECONDARY, T.f_body(), T.BG),
        ("Heading.TLabel", T.TEXT, T.f_heading(), T.BG),
        ("SectionHeader.TLabel", T.TEXT, T.f_subheading(), T.BG),
        ("Eyebrow.TLabel", T.TEXT_MUTED, T.f_eyebrow(), T.BG),
        ("Field.TLabel", T.TEXT_SECONDARY, T.f_body_strong(), T.BG),
        ("FieldLabel.TLabel", T.TEXT_MUTED, T.f_small_strong(), T.BG),
        ("FieldValue.TLabel", T.TEXT, T.f_body(), T.BG),
        ("Footer.TLabel", T.TEXT_MUTED, T.f_small(), T.BG),
        ("Accent.TLabel", T.ACCENT_TEXT, T.f_body_strong(), T.BG),
        ("Success.TLabel", T.SUCCESS, T.f_body_strong(), T.BG),
        ("Warning.TLabel", T.WARNING, T.f_body_strong(), T.BG),
        ("Danger.TLabel", T.DANGER, T.f_body_strong(), T.BG),
        ("Mono.TLabel", T.TEXT_SECONDARY, T.f_mono(9), T.BG),

        # Labels that sit on a card surface.
        ("Card.TLabel", T.TEXT, T.f_body(), T.SURFACE),
        ("CardTitle.TLabel", T.TEXT, T.f_heading(), T.SURFACE),
        ("CardHeading.TLabel", T.TEXT, T.f_subheading(), T.SURFACE),
        ("CardBody.TLabel", T.TEXT_SECONDARY, T.f_body(), T.SURFACE),
        ("CardMuted.TLabel", T.TEXT_MUTED, T.f_small(), T.SURFACE),
        ("CardEyebrow.TLabel", T.TEXT_MUTED, T.f_eyebrow(), T.SURFACE),
        ("CardAccent.TLabel", T.ACCENT_TEXT, T.f_body_strong(), T.SURFACE),

        # Banner / hero text.
        ("BannerTitle.TLabel", T.TEXT, T.f_display(), T.SURFACE),
        ("BannerSub.TLabel", T.ACCENT_TEXT, T.f_heading(), T.SURFACE),
        ("BannerBody.TLabel", T.TEXT_SECONDARY, T.f_body(), T.SURFACE),

        # Metric tiles sit on the RAISED surface.
        ("SummaryCard.TLabel", T.TEXT, T.f_body(), T.RAISED),
        ("SummaryLabel.TLabel", T.TEXT_MUTED, T.f_eyebrow(), T.RAISED),
        ("SummaryValue.TLabel", T.TEXT, T.f_metric(), T.RAISED),
        ("SummaryAccent.TLabel", T.ACCENT_TEXT, T.f_subheading(), T.RAISED),
        ("SummaryHint.TLabel", T.TEXT_MUTED, T.f_small(), T.RAISED),
    ]

    for name, fg, fnt, bg in specs:
        style.configure(name, background=bg, foreground=fg, font=fnt)
        # Keep disabled labels on-surface instead of flashing to system grey.
        style.map(name, background=[("disabled", bg)], foreground=[("disabled", T.TEXT_DISABLED)])


# ---------------------------------------------------------------------------
# Buttons
# ---------------------------------------------------------------------------

def _button(
    style: ttk.Style,
    name: str,
    *,
    bg: str,
    fg: str,
    hover: str,
    press: str,
    border: str,
    border_hover: str,
    font,
    padding=(14, 8),
) -> None:
    style.configure(
        name,
        background=bg,
        foreground=fg,
        bordercolor=border,
        lightcolor=border,
        darkcolor=border,
        focuscolor=bg,
        focusthickness=0,
        borderwidth=1,
        relief="flat",
        padding=padding,
        font=font,
        anchor="center",
    )
    style.map(
        name,
        background=[("disabled", T.mix(bg, T.BG, 0.55)), ("pressed", press), ("active", hover)],
        foreground=[("disabled", T.TEXT_DISABLED)],
        bordercolor=[
            ("disabled", T.mix(border, T.BG, 0.6)),
            ("pressed", border_hover),
            ("active", border_hover),
        ],
        lightcolor=[("pressed", border_hover), ("active", border_hover)],
        darkcolor=[("pressed", border_hover), ("active", border_hover)],
        relief=[("pressed", "flat"), ("!pressed", "flat")],
    )


def _configure_buttons(style: ttk.Style) -> None:
    # Neutral default.
    _button(
        style, "TButton",
        bg=T.RAISED, fg=T.TEXT, hover=T.RAISED_HOVER, press=T.SURFACE,
        border=T.BORDER_STRONG, border_hover=T.ACCENT_BORDER, font=T.f_body(),
    )

    # Primary call to action -- solid accent, the only saturated fill in the UI.
    _button(
        style, "Action.TButton",
        bg=T.ACCENT, fg=T.TEXT_ON_ACCENT, hover=T.ACCENT_HOVER, press=T.ACCENT_PRESS,
        border=T.ACCENT, border_hover=T.ACCENT_HOVER, font=T.f_body_strong(),
    )
    _button(
        style, "Launcher.Action.TButton",
        bg=T.ACCENT, fg=T.TEXT_ON_ACCENT, hover=T.ACCENT_HOVER, press=T.ACCENT_PRESS,
        border=T.ACCENT, border_hover=T.ACCENT_HOVER, font=T.f_body_strong(),
    )

    # Secondary -- outlined, sits on cards next to a primary.
    _button(
        style, "Secondary.TButton",
        bg=T.RAISED, fg=T.TEXT, hover=T.RAISED_HOVER, press=T.SURFACE,
        border=T.BORDER_STRONG, border_hover=T.ACCENT_BORDER, font=T.f_body_strong(),
    )
    _button(
        style, "Side.Action.TButton",
        bg=T.RAISED, fg=T.TEXT_SECONDARY, hover=T.RAISED_HOVER, press=T.SURFACE,
        border=T.BORDER_STRONG, border_hover=T.ACCENT_BORDER, font=T.f_small_strong(),
        padding=(12, 7),
    )

    # Ghost -- lowest emphasis, for tertiary actions.
    _button(
        style, "Ghost.TButton",
        bg=T.SURFACE, fg=T.TEXT_SECONDARY, hover=T.RAISED, press=T.SURFACE,
        border=T.SURFACE, border_hover=T.BORDER_STRONG, font=T.f_body(),
    )

    # Destructive.
    _button(
        style, "Danger.TButton",
        bg=T.DANGER_SOFT, fg=T.DANGER, hover=T.mix(T.DANGER_SOFT, T.DANGER, 0.22),
        press=T.DANGER_SOFT, border=T.mix(T.DANGER, T.BG, 0.5), border_hover=T.DANGER,
        font=T.f_body_strong(),
    )

    # Success (used for "run"-style confirmations where present).
    _button(
        style, "Success.TButton",
        bg=T.SUCCESS_SOFT, fg=T.SUCCESS, hover=T.mix(T.SUCCESS_SOFT, T.SUCCESS, 0.22),
        press=T.SUCCESS_SOFT, border=T.mix(T.SUCCESS, T.BG, 0.5), border_hover=T.SUCCESS,
        font=T.f_body_strong(),
    )


# ---------------------------------------------------------------------------
# Text inputs
# ---------------------------------------------------------------------------

def _configure_inputs(style: ttk.Style) -> None:
    for name in ("TEntry", "Path.TEntry"):
        style.configure(
            name,
            fieldbackground=T.SUNKEN,
            background=T.SUNKEN,
            foreground=T.TEXT,
            insertcolor=T.ACCENT,
            bordercolor=T.BORDER_STRONG,
            lightcolor=T.BORDER_STRONG,
            darkcolor=T.BORDER_STRONG,
            borderwidth=1,
            relief="flat",
            padding=(10, 8),
        )
        style.map(
            name,
            fieldbackground=[("disabled", T.mix(T.SUNKEN, T.BG, 0.5)), ("readonly", T.SUNKEN)],
            foreground=[("disabled", T.TEXT_DISABLED)],
            bordercolor=[("focus", T.ACCENT), ("hover", T.BORDER_STRONG)],
            lightcolor=[("focus", T.ACCENT), ("!focus", T.BORDER_STRONG)],
            darkcolor=[("focus", T.ACCENT), ("!focus", T.BORDER_STRONG)],
        )

    style.configure(
        "TCombobox",
        fieldbackground=T.SUNKEN,
        background=T.RAISED,
        foreground=T.TEXT,
        arrowcolor=T.TEXT_SECONDARY,
        arrowsize=14,
        bordercolor=T.BORDER_STRONG,
        lightcolor=T.BORDER_STRONG,
        darkcolor=T.BORDER_STRONG,
        borderwidth=1,
        relief="flat",
        padding=(8, 7),
        insertcolor=T.ACCENT,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", T.SUNKEN), ("disabled", T.mix(T.SUNKEN, T.BG, 0.5))],
        background=[("readonly", T.RAISED), ("active", T.RAISED_HOVER)],
        foreground=[("disabled", T.TEXT_DISABLED), ("readonly", T.TEXT)],
        selectbackground=[("readonly", T.SUNKEN)],
        selectforeground=[("readonly", T.TEXT)],
        bordercolor=[("focus", T.ACCENT), ("hover", T.ACCENT_BORDER)],
        lightcolor=[("focus", T.ACCENT), ("!focus", T.BORDER_STRONG)],
        darkcolor=[("focus", T.ACCENT), ("!focus", T.BORDER_STRONG)],
        arrowcolor=[("disabled", T.TEXT_DISABLED), ("active", T.ACCENT)],
    )

    for name in ("TSpinbox", "Dark.TSpinbox"):
        style.configure(
            name,
            fieldbackground=T.SUNKEN,
            background=T.RAISED,
            foreground=T.TEXT,
            arrowcolor=T.TEXT_SECONDARY,
            arrowsize=13,
            bordercolor=T.BORDER_STRONG,
            lightcolor=T.BORDER_STRONG,
            darkcolor=T.BORDER_STRONG,
            borderwidth=1,
            relief="flat",
            padding=(8, 6),
            insertcolor=T.ACCENT,
        )
        style.map(
            name,
            fieldbackground=[("disabled", T.mix(T.SUNKEN, T.BG, 0.5)), ("readonly", T.SUNKEN)],
            foreground=[("disabled", T.TEXT_DISABLED)],
            bordercolor=[("focus", T.ACCENT)],
            lightcolor=[("focus", T.ACCENT), ("!focus", T.BORDER_STRONG)],
            darkcolor=[("focus", T.ACCENT), ("!focus", T.BORDER_STRONG)],
            arrowcolor=[("disabled", T.TEXT_DISABLED), ("active", T.ACCENT)],
        )


# ---------------------------------------------------------------------------
# Checkbuttons / radiobuttons
# ---------------------------------------------------------------------------

def _configure_toggles(style: ttk.Style) -> None:
    for name, bg in (("TCheckbutton", T.BG), ("Dark.TCheckbutton", T.BG), ("Card.TCheckbutton", T.SURFACE)):
        style.configure(
            name,
            background=bg,
            foreground=T.TEXT_SECONDARY,
            font=T.f_body(),
            focuscolor=bg,
            # Different ttk builds read the indicator from different options,
            # so set the clam name and the generic pair together.
            indicatorcolor=T.SUNKEN,
            indicatorbackground=T.SUNKEN,
            indicatorforeground=T.TEXT_ON_ACCENT,
            indicatorrelief="flat",
            indicatormargin=(0, 0, 8, 0),
            padding=(2, 4),
        )
        style.map(
            name,
            background=[("active", bg), ("selected", bg), ("disabled", bg)],
            foreground=[
                ("disabled", T.TEXT_DISABLED),
                ("selected", T.TEXT),
                ("active", T.TEXT),
            ],
            indicatorcolor=[
                ("disabled", T.mix(T.SUNKEN, T.BG, 0.5)),
                ("selected", T.ACCENT),
                ("active", T.mix(T.SUNKEN, T.ACCENT, 0.2)),
            ],
            indicatorbackground=[
                ("disabled", T.mix(T.SUNKEN, T.BG, 0.5)),
                ("selected", T.ACCENT),
                ("active", T.mix(T.SUNKEN, T.ACCENT, 0.2)),
                ("!selected", T.SUNKEN),
            ],
            indicatorforeground=[("selected", T.TEXT_ON_ACCENT)],
            bordercolor=[("selected", T.ACCENT), ("!selected", T.BORDER_STRONG)],
            lightcolor=[("selected", T.ACCENT), ("!selected", T.BORDER_STRONG)],
            darkcolor=[("selected", T.ACCENT), ("!selected", T.BORDER_STRONG)],
        )

    for name, bg in (("TRadiobutton", T.BG), ("Card.TRadiobutton", T.SURFACE)):
        style.configure(
            name,
            background=bg,
            foreground=T.TEXT_SECONDARY,
            font=T.f_body(),
            focuscolor=bg,
            indicatorcolor=T.SUNKEN,
            padding=(2, 4),
        )
        style.map(
            name,
            background=[("active", bg), ("selected", bg)],
            foreground=[("disabled", T.TEXT_DISABLED), ("selected", T.TEXT)],
            indicatorcolor=[("selected", T.ACCENT), ("disabled", T.mix(T.SUNKEN, T.BG, 0.5))],
        )


# ---------------------------------------------------------------------------
# Notebook
# ---------------------------------------------------------------------------

def _configure_notebook(style: ttk.Style) -> None:
    for name in ("TNotebook", "Api.TNotebook", "Card.TNotebook"):
        bg = T.SURFACE if name == "Card.TNotebook" else T.BG
        style.configure(
            name,
            background=bg,
            borderwidth=0,
            tabmargins=(0, 0, 0, 0),
            bordercolor=T.BORDER,
            lightcolor=T.BORDER,
            darkcolor=T.BORDER,
        )
        style.configure(
            f"{name}.Tab",
            background=bg,
            foreground=T.TEXT_MUTED,
            font=T.f_body_strong(),
            padding=(16, 9),
            borderwidth=0,
            focuscolor=bg,
            bordercolor=T.BORDER,
            lightcolor=T.BORDER,
            darkcolor=T.BORDER,
        )
        style.map(
            f"{name}.Tab",
            background=[("selected", T.SURFACE), ("active", T.mix(bg, T.SURFACE, 0.6))],
            foreground=[("selected", T.TEXT), ("active", T.TEXT_SECONDARY)],
            expand=[("selected", (0, 0, 0, 0))],
        )


# ---------------------------------------------------------------------------
# Progress bars
# ---------------------------------------------------------------------------

def _configure_progress(style: ttk.Style) -> None:
    variants = {
        "Horizontal.TProgressbar": T.ACCENT,
        "Accent.Horizontal.TProgressbar": T.ACCENT,
        "Success.Horizontal.TProgressbar": T.SUCCESS,
        "Warning.Horizontal.TProgressbar": T.WARNING,
        "Danger.Horizontal.TProgressbar": T.DANGER,
        "Muted.Horizontal.TProgressbar": T.NEUTRAL,
    }
    for name, color in variants.items():
        style.configure(
            name,
            troughcolor=T.SUNKEN,
            bordercolor=T.SUNKEN,
            background=color,
            lightcolor=color,
            darkcolor=color,
            borderwidth=0,
            thickness=8,
        )


# ---------------------------------------------------------------------------
# Treeview
# ---------------------------------------------------------------------------

def _configure_tables(style: ttk.Style) -> None:
    for name in ("Treeview", "SavedTests.Treeview", "Card.Treeview"):
        bg = T.SURFACE if name == "Card.Treeview" else T.SUNKEN
        style.configure(
            name,
            background=bg,
            fieldbackground=bg,
            foreground=T.TEXT_SECONDARY,
            rowheight=T.ROW_HEIGHT,
            borderwidth=0,
            relief="flat",
            font=T.f_body(),
            # clam paints the Treeview.field border from these three; without
            # them a bright 3D frame shows around the table.
            bordercolor=bg,
            lightcolor=bg,
            darkcolor=bg,
        )
        style.map(
            name,
            background=[("selected", T.ACCENT_SOFT)],
            foreground=[("selected", T.TEXT)],
        )

        style.configure(
            f"{name}.Heading",
            background=T.RAISED,
            foreground=T.TEXT_MUTED,
            font=T.f_eyebrow(),
            relief="flat",
            borderwidth=0,
            padding=(10, 8),
        )
        style.map(
            f"{name}.Heading",
            background=[("active", T.RAISED_HOVER)],
            foreground=[("active", T.TEXT)],
        )

    style.layout(
        "Treeview.Item",
        [
            (
                "Treeitem.padding",
                {
                    "sticky": "nswe",
                    "children": [
                        ("Treeitem.indicator", {"side": "left", "sticky": ""}),
                        ("Treeitem.image", {"side": "left", "sticky": ""}),
                        ("Treeitem.text", {"side": "left", "sticky": ""}),
                    ],
                },
            )
        ],
    )


# ---------------------------------------------------------------------------
# Scrollbars
# ---------------------------------------------------------------------------

def _configure_scrollbars(style: ttk.Style) -> None:
    for orient in ("Vertical", "Horizontal"):
        name = f"{orient}.TScrollbar"
        style.configure(
            name,
            troughcolor=T.BG,
            background=T.mix(T.RAISED, T.BG, 0.25),
            bordercolor=T.BG,
            lightcolor=T.BG,
            darkcolor=T.BG,
            arrowcolor=T.TEXT_MUTED,
            borderwidth=0,
            relief="flat",
            arrowsize=12,
            width=12,
        )
        style.map(
            name,
            background=[("pressed", T.ACCENT), ("active", T.RAISED_HOVER)],
            arrowcolor=[("pressed", T.TEXT), ("active", T.TEXT_SECONDARY)],
        )


# ---------------------------------------------------------------------------
# Helpers for plain Tk widgets (Text, Canvas, Listbox) which ttk cannot style
# ---------------------------------------------------------------------------

def console_text_options(*, mono_size: int = 10) -> dict:
    """kwargs for a ``tk.Text`` used as a log/console pane."""
    return {
        "bg": T.SUNKEN,
        "fg": T.TEXT_SECONDARY,
        "insertbackground": T.ACCENT,
        "selectbackground": T.ACCENT_SOFT,
        "selectforeground": T.TEXT,
        "relief": "flat",
        "borderwidth": 0,
        "highlightthickness": 0,
        "font": T.f_mono(mono_size),
        "padx": T.SPACE_MD,
        "pady": T.SPACE_MD,
        "wrap": "none",
    }


def text_options(*, mono: bool = False, size: int = 10) -> dict:
    """kwargs for a general-purpose ``tk.Text`` on a card surface."""
    return {
        "bg": T.SUNKEN,
        "fg": T.TEXT,
        "insertbackground": T.ACCENT,
        "selectbackground": T.ACCENT_SOFT,
        "selectforeground": T.TEXT,
        "relief": "flat",
        "borderwidth": 0,
        "highlightthickness": 0,
        "font": T.f_mono(size) if mono else T.font(size),
        "padx": T.SPACE_MD,
        "pady": T.SPACE_MD,
    }


def tag_colors_for_console(text_widget: tk.Text) -> None:
    """Register severity tags used by log panes."""
    text_widget.tag_configure("info", foreground=T.TEXT_SECONDARY)
    text_widget.tag_configure("ok", foreground=T.SUCCESS)
    text_widget.tag_configure("warn", foreground=T.WARNING)
    text_widget.tag_configure("error", foreground=T.DANGER)
    text_widget.tag_configure("accent", foreground=T.ACCENT_TEXT)
    text_widget.tag_configure("muted", foreground=T.TEXT_MUTED)
