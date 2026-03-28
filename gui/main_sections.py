from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from gui.gui_utils import PRESETS


def build_header(app, parent, outer):
    header = ttk.Frame(parent)
    header.pack(fill="x", **outer)
    header.columnconfigure(1, weight=1)
    header.columnconfigure(3, weight=0)

    ttk.Label(header, text="Sample:").grid(row=0, column=0, sticky="w")
    ttk.Entry(header, textvariable=app.sample_var, width=90).grid(
        row=0, column=1, sticky="ew", padx=(8, 8)
    )
    ttk.Button(
        header,
        text="Browse...",
        style="Side.Action.TButton",
        command=app._browse_sample,
    ).grid(row=0, column=2, sticky="ew")

    ttk.Label(header, text="Case name:").grid(row=1, column=0, sticky="w", pady=(8, 0))
    ttk.Entry(header, textvariable=app.case_var, width=32).grid(
        row=1, column=1, sticky="w", padx=(8, 8), pady=(8, 0)
    )

    ttk.Label(header, text="Preset:").grid(row=1, column=2, sticky="e", padx=(12, 6), pady=(8, 0))
    preset_names = [p.name for p in PRESETS]
    preset_box = ttk.Combobox(
        header,
        textvariable=app.preset_var,
        values=preset_names,
        state="readonly",
        width=18,
    )
    preset_box.grid(row=1, column=3, sticky="w", pady=(8, 0))
    preset_box.bind("<<ComboboxSelected>>", app._on_preset_selected)

    return header


def build_main_columns(parent, outer):
    body = ttk.Frame(parent)
    body.pack(fill="both", expand=False, **outer)
    body.columnconfigure(0, weight=1)
    body.columnconfigure(1, weight=1)

    left_col = ttk.Frame(body)
    left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
    left_col.columnconfigure(0, weight=1)
    left_col.rowconfigure(1, weight=1)

    right_col = ttk.Frame(body)
    right_col.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
    right_col.columnconfigure(0, weight=1)

    return body, left_col, right_col


def build_configuration_section(app, parent):
    config = ttk.LabelFrame(parent, text="Configuration")
    config.grid(row=0, column=0, sticky="ew")
    config.columnconfigure(0, weight=1)

    paths = ttk.Frame(config)
    paths.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
    paths.columnconfigure(1, weight=1)

    ttk.Label(paths, text="Case output root:").grid(row=0, column=0, sticky="w")
    ttk.Entry(paths, textvariable=app.case_root_var, width=72).grid(
        row=0, column=1, sticky="ew", padx=(8, 8)
    )
    ttk.Button(
        paths,
        text="Browse...",
        style="Side.Action.TButton",
        command=app._browse_case_root,
    ).grid(row=0, column=2, sticky="ew")

    ttk.Label(paths, text="capa rules folder:").grid(row=1, column=0, sticky="w", pady=(8, 0))
    ttk.Entry(paths, textvariable=app.rules_var, width=72).grid(
        row=1, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
    )
    ttk.Button(
        paths,
        text="Browse...",
        style="Side.Action.TButton",
        command=app._browse_rules,
    ).grid(row=1, column=2, sticky="ew", pady=(8, 0))

    ttk.Label(paths, text="capa sigs folder:").grid(row=2, column=0, sticky="w", pady=(8, 0))
    ttk.Entry(paths, textvariable=app.sigs_var, width=72).grid(
        row=2, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
    )
    ttk.Button(
        paths,
        text="Browse...",
        style="Side.Action.TButton",
        command=app._browse_sigs,
    ).grid(row=2, column=2, sticky="ew", pady=(8, 0))

    ttk.Label(paths, text="VirusTotal API key:").grid(row=3, column=0, sticky="w", pady=(8, 0))
    ttk.Entry(paths, textvariable=app.vt_api_key_var, width=72, show="*").grid(
        row=3, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
    )
    ttk.Button(
        paths,
        text="Clear",
        style="Side.Action.TButton",
        command=app._clear_vt_key,
    ).grid(row=3, column=2, sticky="ew", pady=(8, 0))

    adv = ttk.LabelFrame(config, text="Advanced Settings")
    adv.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
    adv.columnconfigure(0, weight=1)

    ttk.Checkbutton(
        adv,
        text="Override preset with advanced settings",
        variable=app.adv_enabled_var,
        command=app._on_adv_toggle,
    ).grid(row=0, column=0, sticky="w")

    app.adv_body = ttk.Frame(adv)
    app.adv_body.grid(row=1, column=0, sticky="ew", pady=(8, 0))
    app.adv_body.columnconfigure(3, weight=1)

    ttk.Checkbutton(
        app.adv_body,
        text="Enable extraction",
        variable=app.extract_var,
        command=app._save_cfg,
    ).grid(row=0, column=0, sticky="w")

    ttk.Checkbutton(
        app.adv_body,
        text="Enable subfiles triage",
        variable=app.subfiles_var,
        command=app._save_cfg,
    ).grid(row=0, column=1, sticky="w", padx=(14, 0))

    ttk.Label(app.adv_body, text="Subfile limit:").grid(row=0, column=2, sticky="e", padx=(14, 6))
    app.subfile_limit_spin = ttk.Spinbox(
        app.adv_body,
        from_=0,
        to=999,
        textvariable=app.subfile_limit_var,
        width=6,
        command=app._save_cfg,
    )
    app.subfile_limit_spin.grid(row=0, column=3, sticky="w")

    ttk.Checkbutton(
        app.adv_body,
        text="Strings lite",
        variable=app.strings_lite_var,
        command=app._on_strings_mode_changed,
    ).grid(row=1, column=0, sticky="w", pady=(8, 0))

    ttk.Checkbutton(
        app.adv_body,
        text="Skip strings",
        variable=app.no_strings_var,
        command=app._on_strings_mode_changed,
    ).grid(row=1, column=1, sticky="w", padx=(14, 0), pady=(8, 0))

    app.effective_label = ttk.Label(adv, text="")
    app.effective_label.grid(row=2, column=0, sticky="w", pady=(10, 0))

    return config


def build_progress_section(app, parent):
    prog = ttk.LabelFrame(parent, text="Progress")
    prog.grid(row=0, column=0, sticky="ew")
    prog.columnconfigure(0, weight=1)

    app.overall_var = tk.IntVar(value=0)
    app.overall_bar = ttk.Progressbar(
        prog,
        orient="horizontal",
        mode="determinate",
        maximum=100,
        variable=app.overall_var,
    )
    app.overall_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))

    app.overall_text = ttk.Label(prog, text="0%")
    app.overall_text.grid(row=0, column=1, sticky="w", padx=(10, 10), pady=(10, 0))

    app.steps_frame = ttk.Frame(prog)
    app.steps_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 10))
    app.steps_frame.columnconfigure(1, weight=1)

    return prog


def build_results_section(app, parent):
    results = ttk.LabelFrame(parent, text="Results")
    results.grid(row=1, column=0, sticky="ew", pady=(10, 0))
    results.columnconfigure(0, weight=1)

    combined_wrap = ttk.Frame(results)
    combined_wrap.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))
    combined_wrap.columnconfigure(1, weight=1)
    combined_wrap.columnconfigure(3, weight=1)

    ttk.Label(combined_wrap, text="Combined Score:").grid(row=0, column=0, sticky="w")
    ttk.Label(combined_wrap, textvariable=app.combined_score_var, style="SummaryValue.TLabel").grid(
        row=0, column=1, sticky="w", padx=(8, 20)
    )

    ttk.Label(combined_wrap, text="Severity:").grid(row=0, column=2, sticky="w")
    ttk.Label(combined_wrap, textvariable=app.combined_severity_var, style="SummaryAccent.TLabel").grid(
        row=0, column=3, sticky="w", padx=(8, 0)
    )

    ttk.Label(combined_wrap, text="Verdict:").grid(row=1, column=0, sticky="w", pady=(8, 0))
    ttk.Label(combined_wrap, textvariable=app.combined_verdict_var).grid(
        row=1, column=1, sticky="w", padx=(8, 20), pady=(8, 0)
    )

    ttk.Label(combined_wrap, text="Confidence:").grid(row=1, column=2, sticky="w", pady=(8, 0))
    ttk.Label(combined_wrap, textvariable=app.combined_confidence_var).grid(
        row=1, column=3, sticky="w", padx=(8, 0), pady=(8, 0)
    )

    ttk.Separator(results, orient="horizontal").grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))

    lower = ttk.Frame(results)
    lower.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 12))
    lower.columnconfigure(0, weight=1)
    lower.columnconfigure(1, weight=1)

    left_metrics = ttk.Frame(lower)
    left_metrics.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
    left_metrics.columnconfigure(1, weight=1)

    ttk.Label(left_metrics, text="Static", style="SectionHeader.TLabel").grid(
        row=0, column=0, columnspan=2, sticky="w", pady=(0, 6)
    )

    ttk.Label(left_metrics, text="Score:").grid(row=1, column=0, sticky="w")
    ttk.Label(left_metrics, textvariable=app.score_var).grid(row=1, column=1, sticky="w", padx=(8, 0))

    ttk.Label(left_metrics, text="Verdict:").grid(row=2, column=0, sticky="w", pady=(6, 0))
    ttk.Label(left_metrics, textvariable=app.verdict_var).grid(
        row=2, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
    )

    ttk.Label(left_metrics, text="Confidence:").grid(row=3, column=0, sticky="w", pady=(6, 0))
    ttk.Label(left_metrics, textvariable=app.confidence_var).grid(
        row=3, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
    )

    ttk.Separator(left_metrics, orient="horizontal").grid(row=4, column=0, columnspan=2, sticky="ew", pady=(8, 8))

    ttk.Label(left_metrics, text="Subscores", style="SectionHeader.TLabel").grid(
        row=5, column=0, columnspan=2, sticky="w", pady=(0, 6)
    )

    ttk.Label(left_metrics, text="Static:").grid(row=6, column=0, sticky="w")
    ttk.Label(left_metrics, textvariable=app.static_subscore_var).grid(row=6, column=1, sticky="w", padx=(8, 0))

    ttk.Label(left_metrics, text="Dynamic:").grid(row=7, column=0, sticky="w", pady=(6, 0))
    ttk.Label(left_metrics, textvariable=app.dynamic_subscore_var).grid(
        row=7, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
    )

    ttk.Label(left_metrics, text="Spec/API:").grid(row=8, column=0, sticky="w", pady=(6, 0))
    ttk.Label(left_metrics, textvariable=app.spec_subscore_var).grid(
        row=8, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
    )

    right_metrics = ttk.Frame(lower)
    right_metrics.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
    right_metrics.columnconfigure(0, weight=1)

    ttk.Label(right_metrics, text="VirusTotal", style="SectionHeader.TLabel").grid(
        row=0, column=0, sticky="w", pady=(0, 6)
    )

    ttk.Label(right_metrics, textvariable=app.vt_status_var, wraplength=280, justify="left").grid(
        row=1, column=0, sticky="w"
    )
    ttk.Label(right_metrics, textvariable=app.vt_name_var, wraplength=280, justify="left").grid(
        row=2, column=0, sticky="w", pady=(6, 0)
    )
    ttk.Label(right_metrics, textvariable=app.vt_counts_var, wraplength=280, justify="left").grid(
        row=3, column=0, sticky="w", pady=(6, 0)
    )

    app.vt_open_btn = ttk.Button(
        right_metrics,
        text="Open VirusTotal",
        command=app._open_virustotal,
        state="disabled",
        style="Action.TButton",
    )
    app.vt_open_btn.grid(row=4, column=0, sticky="e", pady=(12, 0))

    return results


def build_actions_and_output(app, parent, outer):
    actions = ttk.Frame(parent)
    actions.pack(fill="x", **outer)

    buttons_row = ttk.Frame(actions)
    buttons_row.pack(fill="x")

    app.run_btn = ttk.Button(
        buttons_row,
        text="Run Analysis",
        style="Action.TButton",
        width=18,
        command=app._start_analysis,
    )
    app.run_btn.pack(side="left", padx=(0, 10))

    ttk.Button(
        buttons_row,
        text="Open Case",
        style="Action.TButton",
        width=14,
        command=app._open_case_files,
    ).pack(side="left", padx=(0, 8))

    ttk.Button(
        buttons_row,
        text="Open Report",
        style="Action.TButton",
        width=14,
        command=app._open_html_report,
    ).pack(side="left", padx=(0, 8))

    ttk.Button(
        buttons_row,
        text="Dynamic Analysis",
        style="Action.TButton",
        width=16,
        command=app._open_dynamic_window,
    ).pack(side="left", padx=(0, 8))

    ttk.Button(
        buttons_row,
        text="API Spec Analysis",
        style="Action.TButton",
        width=16,
        command=app.open_spec_analysis_window,
    ).pack(side="left", padx=(0, 8))

    status_row = ttk.Frame(actions)
    status_row.pack(fill="x", pady=(6, 0))

    ttk.Label(status_row, textvariable=app.status_var).pack(side="left")
    ttk.Label(status_row, textvariable=app.running_var, anchor="e").pack(side="right")

    out = ttk.LabelFrame(parent, text="Output")
    out.pack(fill="both", expand=True, **outer)

    app.output = tk.Text(
        out,
        wrap="none",
        height=12,
        bg="#0d1b33",
        fg="#eaf2ff",
        insertbackground="#eaf2ff",
        selectbackground="#1f6fff",
        selectforeground="white",
        relief="flat",
        borderwidth=0,
        highlightthickness=1,
        highlightbackground="#2a4365",
        highlightcolor="#3d86ff",
        font=("Consolas", 10),
    )
    app.output.pack(fill="both", expand=True, side="left")

    yscroll = ttk.Scrollbar(out, orient="vertical", command=app.output.yview)
    yscroll.pack(side="right", fill="y")
    app.output.configure(yscrollcommand=yscroll.set)

    return actions, out