"""Layout for the Static Analysis window.

Each screen region is a :class:`gui.components.Card`; the widgets the
controllers reach for (``app.run_btn``, ``app.output``, ``app.steps_frame`` and
friends) are still published onto ``app`` under exactly the same names, so this
module stays purely presentational.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from gui import theme as T
from gui.components import (
    Badge,
    Card,
    Checkbox,
    RoundedButton,
    StatTile,
    card_title,
    divider,
)
from gui.gui_utils import PRESETS
from gui.styles import console_text_options


# ---------------------------------------------------------------------------
# Sample selection bar
# ---------------------------------------------------------------------------

def build_header(app, parent, outer):
    """The sample picker: path entry, browse button, and triage depth preset."""
    card = Card(parent, parent_bg=T.BG, padding=(T.SPACE_LG, T.SPACE_MD))
    card.pack(fill="x", **outer)

    row = card.body
    row.columnconfigure(1, weight=1)

    ttk.Label(row, text="Sample", style="CardEyebrow.TLabel").grid(
        row=0, column=0, sticky="w", padx=(0, T.SPACE_MD)
    )

    ttk.Entry(row, textvariable=app.sample_var).grid(
        row=0, column=1, sticky="ew", padx=(0, T.SPACE_SM)
    )

    RoundedButton(
        row, "Browse", command=app._browse_sample,
        variant="secondary", parent_bg=T.SURFACE, min_width=104,
    ).grid(row=0, column=2, padx=(0, T.SPACE_XL))

    # The combo lists preset names (Fast Triage / Deep Triage / Hash Only), so
    # labelling it "Deep Triage" restated one value instead of naming the field.
    ttk.Label(row, text="Triage Depth", style="CardEyebrow.TLabel").grid(
        row=0, column=3, sticky="e", padx=(0, T.SPACE_SM)
    )

    preset_box = ttk.Combobox(
        row,
        textvariable=app.preset_var,
        values=[p.name for p in PRESETS],
        state="readonly",
        width=16,
    )
    preset_box.grid(row=0, column=4, sticky="e")
    preset_box.bind("<<ComboboxSelected>>", app._on_preset_selected)

    return card


def build_workspace(parent, outer):
    workspace = ttk.Frame(parent, style="App.TFrame")
    workspace.pack(fill="both", expand=True, **outer)

    workspace.columnconfigure(0, weight=1, uniform="col")
    workspace.columnconfigure(1, weight=1, uniform="col")

    # Top row keeps its natural height; the middle row absorbs slack.
    workspace.rowconfigure(0, weight=0)
    workspace.rowconfigure(1, weight=1)
    workspace.rowconfigure(2, weight=0)

    return workspace


def build_top_row(app, workspace):
    left = ttk.Frame(workspace, style="App.TFrame")
    left.grid(row=0, column=0, sticky="nsew", padx=(0, T.SPACE_SM))
    left.columnconfigure(0, weight=1)

    right = ttk.Frame(workspace, style="App.TFrame")
    right.grid(row=0, column=1, sticky="nsew", padx=(T.SPACE_SM, 0))
    right.columnconfigure(0, weight=1)
    right.rowconfigure(0, weight=1)

    build_configuration_section(app, left)
    build_run_progress_section(app, right)
    return left, right


def build_middle_row(app, workspace):
    left = ttk.Frame(workspace, style="App.TFrame")
    left.grid(row=1, column=0, sticky="nsew", padx=(0, T.SPACE_SM), pady=(T.SPACE_MD, 0))
    left.columnconfigure(0, weight=1)
    left.rowconfigure(0, weight=1)

    right = ttk.Frame(workspace, style="App.TFrame")
    right.grid(row=1, column=1, sticky="nsew", padx=(T.SPACE_SM, 0), pady=(T.SPACE_MD, 0))
    right.columnconfigure(0, weight=1)
    right.rowconfigure(0, weight=1)

    build_output_section(app, left)
    build_results_section(app, right)
    return left, right


# ---------------------------------------------------------------------------
# Shared card chrome
# ---------------------------------------------------------------------------

def _path_row(parent, row, label, variable, command, *, button="Browse", show=None):
    """One labelled path field with a trailing action button."""
    ttk.Label(parent, text=label, style="CardBody.TLabel").grid(
        row=row, column=0, sticky="w", pady=(0, T.SPACE_SM)
    )

    entry_opts = {"textvariable": variable}
    if show:
        entry_opts["show"] = show

    ttk.Entry(parent, **entry_opts).grid(
        row=row, column=1, sticky="ew", padx=(T.SPACE_MD, T.SPACE_SM), pady=(0, T.SPACE_SM)
    )

    RoundedButton(
        parent, button, command=command, variant="secondary",
        parent_bg=T.SURFACE, min_width=96, pady=8,
    ).grid(row=row, column=2, sticky="e", pady=(0, T.SPACE_SM))


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def build_configuration_section(app, parent):
    card = Card(parent, parent_bg=T.BG)
    card.grid(row=0, column=0, sticky="nsew")

    body = card.body
    card_title(body, "Configuration", hint="Saved automatically")

    paths = tk.Frame(body, bg=T.SURFACE)
    paths.pack(fill="x")
    paths.columnconfigure(1, weight=1)

    ttk.Label(paths, text="Case name", style="CardBody.TLabel").grid(
        row=0, column=0, sticky="w", pady=(0, T.SPACE_SM)
    )
    ttk.Entry(paths, textvariable=app.case_var).grid(
        row=0, column=1, columnspan=2, sticky="ew",
        padx=(T.SPACE_MD, 0), pady=(0, T.SPACE_SM),
    )

    _path_row(paths, 1, "Case output root", app.case_root_var, app._browse_case_root)
    _path_row(paths, 2, "capa rules folder", app.rules_var, app._browse_rules)
    _path_row(paths, 3, "capa sigs folder", app.sigs_var, app._browse_sigs)
    _path_row(
        paths, 4, "VirusTotal API key", app.vt_api_key_var, app._clear_vt_key,
        button="Clear", show="*",
    )

    divider(body).pack(fill="x", pady=T.SPACE_MD)
    _build_advanced(app, body)
    divider(body).pack(fill="x", pady=T.SPACE_MD)
    _build_run_row(app, body)

    return card


def _build_advanced(app, body):
    header = tk.Frame(body, bg=T.SURFACE)
    header.pack(fill="x")

    Checkbox(
        header,
        "Override preset with advanced settings",
        app.adv_enabled_var,
        command=app._on_adv_toggle,
        parent_bg=T.SURFACE,
    ).pack(anchor="w")

    app.adv_body = tk.Frame(body, bg=T.SURFACE)
    app.adv_body.pack(fill="x", pady=(T.SPACE_SM, 0))
    app.adv_body.columnconfigure(4, weight=1)

    app.extract_check = Checkbox(
        app.adv_body, "Enable extraction", app.extract_var,
        command=app._save_cfg, parent_bg=T.SURFACE,
    )
    app.extract_check.grid(row=0, column=0, sticky="w")

    app.subfiles_check = Checkbox(
        app.adv_body, "Enable subfiles triage", app.subfiles_var,
        command=app._save_cfg, parent_bg=T.SURFACE,
    )
    app.subfiles_check.grid(row=0, column=1, sticky="w", padx=(T.SPACE_LG, 0))

    app.subfile_limit_label = ttk.Label(
        app.adv_body, text="Subfile limit", style="CardBody.TLabel"
    )
    app.subfile_limit_label.grid(row=0, column=2, sticky="e", padx=(T.SPACE_LG, T.SPACE_SM))

    app.subfile_limit_spin = ttk.Spinbox(
        app.adv_body, from_=0, to=999, textvariable=app.subfile_limit_var,
        width=6, command=app._save_cfg, style="Dark.TSpinbox",
    )
    app.subfile_limit_spin.grid(row=0, column=3, sticky="w")

    app.strings_lite_check = Checkbox(
        app.adv_body, "Strings lite", app.strings_lite_var,
        command=app._on_strings_mode_changed, parent_bg=T.SURFACE,
    )
    app.strings_lite_check.grid(row=1, column=0, sticky="w", pady=(T.SPACE_SM, 0))

    app.skip_strings_check = Checkbox(
        app.adv_body, "Skip strings", app.no_strings_var,
        command=app._on_strings_mode_changed, parent_bg=T.SURFACE,
    )
    app.skip_strings_check.grid(
        row=1, column=1, sticky="w", padx=(T.SPACE_LG, 0), pady=(T.SPACE_SM, 0)
    )

    # Explicit list beats introspecting winfo_children() when toggling state.
    app.adv_widgets = [
        app.extract_check,
        app.subfiles_check,
        app.subfile_limit_spin,
        app.strings_lite_check,
        app.skip_strings_check,
    ]

    app.effective_label = tk.Label(
        body, text="", bg=T.SURFACE, fg=T.TEXT_MUTED, font=T.f_mono(9),
        anchor="w", justify="left",
    )
    app.effective_label.pack(anchor="w", fill="x", pady=(T.SPACE_MD, 0))


def _build_run_row(app, body):
    row = tk.Frame(body, bg=T.SURFACE)
    row.pack(fill="x")

    app.run_btn = RoundedButton(
        row, "Run Analysis", command=app._start_analysis, variant="primary",
        icon="▶", parent_bg=T.SURFACE, min_width=168,
    )
    app.run_btn.pack(side="left")

    app.cancel_btn = RoundedButton(
        row, "Cancel", command=app._cancel_analysis, variant="danger",
        parent_bg=T.SURFACE, min_width=110, state="disabled",
    )
    app.cancel_btn.pack(side="left", padx=(T.SPACE_SM, 0))

    status = tk.Frame(row, bg=T.SURFACE)
    status.pack(side="right")

    tk.Label(
        status, textvariable=app.running_var, bg=T.SURFACE, fg=T.TEXT_SECONDARY,
        font=T.f_body_strong(), anchor="e",
    ).pack(anchor="e")

    tools_var = getattr(app, "tools_status_var", app.status_var)
    tk.Label(
        status, textvariable=tools_var, bg=T.SURFACE, fg=T.TEXT_MUTED,
        font=T.f_small(), anchor="e",
    ).pack(anchor="e", pady=(2, 0))


# ---------------------------------------------------------------------------
# Pipeline progress
# ---------------------------------------------------------------------------

def build_run_progress_section(app, parent):
    card = Card(parent, parent_bg=T.BG)
    card.grid(row=0, column=0, sticky="nsew")

    body = card.body
    card_title(body, "Pipeline")

    overall = tk.Frame(body, bg=T.SURFACE)
    overall.pack(fill="x")
    overall.columnconfigure(0, weight=1)

    app.overall_var = tk.IntVar(value=0)
    app.overall_bar = ttk.Progressbar(
        overall, orient="horizontal", mode="determinate",
        maximum=100, variable=app.overall_var,
    )
    app.overall_bar.grid(row=0, column=0, sticky="ew")

    app.overall_text = tk.Label(
        overall, text="0%", bg=T.SURFACE, fg=T.TEXT, font=T.f_body_strong(), width=5, anchor="e",
    )
    app.overall_text.grid(row=0, column=1, sticky="e", padx=(T.SPACE_MD, 0))

    divider(body).pack(fill="x", pady=T.SPACE_MD)

    app.steps_frame = tk.Frame(body, bg=T.SURFACE)
    app.steps_frame.pack(fill="both", expand=True)
    # The step name column takes the slack so the bars stay a readable width
    # and line up in a single right-hand gutter.
    app.steps_frame.columnconfigure(1, weight=1)

    return card


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

def build_output_section(app, parent):
    card = Card(parent, parent_bg=T.BG, padding=(T.SPACE_LG, T.SPACE_LG))
    card.grid(row=0, column=0, sticky="nsew")

    body = card.body
    card_title(body, "Console")

    well = tk.Frame(body, bg=T.SUNKEN)
    well.pack(fill="both", expand=True)
    well.columnconfigure(0, weight=1)
    well.rowconfigure(0, weight=1)

    app.output = tk.Text(well, **console_text_options())
    app.output.grid(row=0, column=0, sticky="nsew")

    scroll = ttk.Scrollbar(well, orient="vertical", command=app.output.yview)
    scroll.grid(row=0, column=1, sticky="ns")
    app.output.configure(yscrollcommand=scroll.set)

    return card


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

def build_results_section(app, parent):
    card = Card(parent, parent_bg=T.BG)
    card.grid(row=0, column=0, sticky="nsew")

    body = card.body
    card_title(body, "Results")

    tiles = tk.Frame(body, bg=T.SURFACE)
    tiles.pack(fill="x")
    for col in range(3):
        tiles.columnconfigure(col, weight=1, uniform="tile")

    app.score_tile = StatTile(
        tiles, "Score", textvariable=app.score_var, parent_bg=T.SURFACE, accent=T.ACCENT,
    )
    app.score_tile.grid(row=0, column=0, sticky="nsew", padx=(0, T.SPACE_SM))

    app.verdict_tile = StatTile(
        tiles, "Verdict", textvariable=app.verdict_var, parent_bg=T.SURFACE,
        value_color=T.ACCENT_TEXT,
    )
    app.verdict_tile.grid(row=0, column=1, sticky="nsew", padx=T.SPACE_XS)

    app.confidence_tile = StatTile(
        tiles, "Confidence", textvariable=app.confidence_var, parent_bg=T.SURFACE,
    )
    app.confidence_tile.grid(row=0, column=2, sticky="nsew", padx=(T.SPACE_SM, 0))

    # The verdict drives the tile colour, so a glance is enough to read it.
    #
    # **It reads `verdict_band`, not the sentence.** This passed
    # `verdict_var.get()` straight in, and `verdict_var` holds wording written
    # for a reader -- "Likely Malicious", "Needs Review", "Insufficient
    # Coverage". Measured 03 Sep: all twelve sentences `corroboration-v1` can
    # write missed `STATUS_COLORS` and took the neutral default, so the tile
    # was grey for every case written since the scoring rewrite while older
    # folders, which carry the retired one-word verdicts, still coloured.
    # `ResultController` sets `verdict_band` from the model's severity, and
    # falls back to the wording for a folder that predates the field.
    def _tint_verdict(*_args):
        band = str(getattr(app, "verdict_band", "") or "").strip()
        fg, _bg = T.status_colors(band or app.verdict_var.get())
        app.verdict_tile.set_value_color(fg)

    app.verdict_band = getattr(app, "verdict_band", "")
    app.verdict_var.trace_add("write", _tint_verdict)
    _tint_verdict()

    divider(body).pack(fill="x", pady=T.SPACE_MD)
    _build_vt_panel(app, body)

    return card


def _build_vt_panel(app, body):
    panel = Card(
        body, parent_bg=T.SURFACE, fill=T.RAISED, border=T.BORDER,
        radius=T.RADIUS_MD, padding=(T.SPACE_LG, T.SPACE_MD),
    )
    panel.pack(fill="both", expand=True)

    inner = panel.body

    head = tk.Frame(inner, bg=T.RAISED)
    head.pack(fill="x")

    tk.Label(
        head, text="VIRUSTOTAL", bg=T.RAISED, fg=T.TEXT_MUTED, font=T.f_eyebrow(),
    ).pack(side="left")

    # Anchor the action to the bottom of the panel first, so it stays pinned to
    # the corner instead of floating below the text when the card grows.
    app.vt_open_btn = RoundedButton(
        inner, "Open in VirusTotal", command=app._open_virustotal,
        variant="secondary", parent_bg=T.RAISED, state="disabled", pady=8,
    )
    app.vt_open_btn.pack(side="bottom", anchor="e", pady=(T.SPACE_MD, 0))

    for variable in (app.vt_status_var, app.vt_name_var, app.vt_counts_var):
        tk.Label(
            inner, textvariable=variable, bg=T.RAISED, fg=T.TEXT_SECONDARY,
            font=T.f_small(), anchor="w", justify="left", wraplength=430,
        ).pack(side="top", anchor="w", fill="x", pady=(T.SPACE_SM, 0))

    return panel


# ---------------------------------------------------------------------------
# Artifacts bar
# ---------------------------------------------------------------------------

def build_bottom_actions(app, workspace):
    card = Card(workspace, parent_bg=T.BG, padding=(T.SPACE_LG, T.SPACE_MD))
    card.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(T.SPACE_MD, 0))

    row = card.body

    tk.Label(
        row, text="ARTIFACTS", bg=T.SURFACE, fg=T.TEXT_MUTED, font=T.f_eyebrow(),
    ).pack(side="left", padx=(0, T.SPACE_MD))

    actions = (
        ("Open Case", app._open_case_files),
        ("Static Report", app._open_html_report),
        ("Dynamic Analysis", app._open_dynamic_window),
        ("Extension Analysis", app.open_extension_analysis_window),
    )
    for label, command in actions:
        RoundedButton(
            row, label, command=command, variant="secondary",
            parent_bg=T.SURFACE, pady=8,
        ).pack(side="left", padx=(0, T.SPACE_SM))

    app.running_badge = Badge(row, "Idle", status="idle", parent_bg=T.SURFACE)
    app.running_badge.pack(side="right")

    # Mirror the shared running string into the badge.
    def _sync_badge(*_args):
        value = app.running_var.get() or "Idle"
        app.running_badge.set(value, status=value)

    app.running_var.trace_add("write", _sync_badge)
    _sync_badge()

    return card
