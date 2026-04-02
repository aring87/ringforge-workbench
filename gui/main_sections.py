from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from gui.gui_utils import PRESETS


def build_header(app, parent, outer):
    header = ttk.Frame(parent)
    header.pack(fill="x", **outer)

    sample_row = ttk.Frame(header)
    sample_row.pack(fill="x")
    sample_row.columnconfigure(1, weight=1)

    ttk.Label(sample_row, text="Sample:").grid(row=0, column=0, sticky="w")

    ttk.Entry(sample_row, textvariable=app.sample_var, width=90).grid(
        row=0, column=1, sticky="ew", padx=(8, 8)
    )

    ttk.Button(
        sample_row,
        text="Browse...",
        style="Side.Action.TButton",
        command=app._browse_sample,
    ).grid(row=0, column=2, sticky="w", padx=(0, 16))

    ttk.Label(sample_row, text="Deep Triage:").grid(
        row=0, column=3, sticky="w", padx=(0, 6)
    )

    preset_names = [p.name for p in PRESETS]
    preset_box = ttk.Combobox(
        sample_row,
        textvariable=app.preset_var,
        values=preset_names,
        state="readonly",
        width=16,
    )
    preset_box.grid(row=0, column=4, sticky="w")
    preset_box.bind("<<ComboboxSelected>>", app._on_preset_selected)

    return header


def build_workspace(parent, outer):
    workspace = ttk.Frame(parent)
    workspace.pack(fill="both", expand=True, **outer)
    workspace.columnconfigure(0, weight=1)
    workspace.columnconfigure(1, weight=1)
    workspace.rowconfigure(0, weight=0)
    workspace.rowconfigure(1, weight=1)
    workspace.rowconfigure(2, weight=0)
    return workspace


def build_top_row(app, workspace):
    top_row = ttk.Frame(workspace)
    top_row.grid(row=0, column=0, columnspan=2, sticky="ew")
    top_row.columnconfigure(0, weight=1)
    top_row.columnconfigure(1, weight=1)

    left_top = ttk.Frame(top_row)
    left_top.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
    left_top.columnconfigure(0, weight=1)

    right_top = ttk.Frame(top_row)
    right_top.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
    right_top.columnconfigure(0, weight=1)

    build_configuration_section(app, left_top)
    build_run_progress_section(app, right_top)

    return left_top, right_top


def build_middle_row(app, workspace):
    left_mid = ttk.Frame(workspace)
    left_mid.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(10, 0))
    left_mid.columnconfigure(0, weight=1)
    left_mid.rowconfigure(0, weight=1)

    right_mid = ttk.Frame(workspace)
    right_mid.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=(10, 0))
    right_mid.columnconfigure(0, weight=1)
    right_mid.rowconfigure(0, weight=1)

    build_output_section(app, left_mid)
    build_results_section(app, right_mid)

    return left_mid, right_mid


def build_bottom_actions(app, workspace):
    artifacts = ttk.LabelFrame(workspace, text="Artifacts")
    artifacts.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
    artifacts.columnconfigure(0, weight=1)

    row = ttk.Frame(artifacts)
    row.pack(fill="x", padx=12, pady=(10, 6))

    ttk.Button(
        row,
        text="Open Case",
        style="Action.TButton",
        width=14,
        command=app._open_case_files,
    ).pack(side="left", padx=(0, 8))

    ttk.Button(
        row,
        text="Open Static Report",
        style="Action.TButton",
        width=18,
        command=app._open_html_report,
    ).pack(side="left", padx=(0, 8))

    status_row = ttk.Frame(artifacts)
    status_row.pack(fill="x", padx=12, pady=(0, 8))
    ttk.Label(status_row, textvariable=app.status_var).pack(side="left")
    ttk.Label(status_row, textvariable=app.running_var, anchor="e").pack(side="right")

    return artifacts


def build_configuration_section(app, parent):
    config = ttk.LabelFrame(parent, text="Configuration")
    config.grid(row=0, column=0, sticky="ew")
    config.columnconfigure(0, weight=1)

    paths = ttk.Frame(config)
    paths.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
    paths.columnconfigure(1, weight=1)

    ttk.Label(paths, text="Case name:").grid(row=0, column=0, sticky="w")
    ttk.Entry(paths, textvariable=app.case_var, width=40).grid(
        row=0, column=1, sticky="w", padx=(8, 8)
    )

    ttk.Label(paths, text="Case output root:").grid(row=1, column=0, sticky="w", pady=(8, 0))
    ttk.Entry(paths, textvariable=app.case_root_var, width=72).grid(
        row=1, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
    )
    ttk.Button(
        paths,
        text="Browse...",
        style="Side.Action.TButton",
        command=app._browse_case_root,
    ).grid(row=1, column=2, sticky="ew", pady=(8, 0))

    ttk.Label(paths, text="capa rules folder:").grid(row=2, column=0, sticky="w", pady=(8, 0))
    ttk.Entry(paths, textvariable=app.rules_var, width=72).grid(
        row=2, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
    )
    ttk.Button(
        paths,
        text="Browse...",
        style="Side.Action.TButton",
        command=app._browse_rules,
    ).grid(row=2, column=2, sticky="ew", pady=(8, 0))

    ttk.Label(paths, text="capa sigs folder:").grid(row=3, column=0, sticky="w", pady=(8, 0))
    ttk.Entry(paths, textvariable=app.sigs_var, width=72).grid(
        row=3, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
    )
    ttk.Button(
        paths,
        text="Browse...",
        style="Side.Action.TButton",
        command=app._browse_sigs,
    ).grid(row=3, column=2, sticky="ew", pady=(8, 0))

    ttk.Label(paths, text="VirusTotal API key:").grid(row=4, column=0, sticky="w", pady=(8, 0))
    ttk.Entry(paths, textvariable=app.vt_api_key_var, width=72, show="*").grid(
        row=4, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
    )
    ttk.Button(
        paths,
        text="Clear",
        style="Side.Action.TButton",
        command=app._clear_vt_key,
    ).grid(row=4, column=2, sticky="ew", pady=(8, 0))

    adv = ttk.LabelFrame(config, text="Advanced Settings")
    adv.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
    adv.columnconfigure(0, weight=1)

    ttk.Checkbutton(
        adv,
        text="Override preset with advanced settings",
        variable=app.adv_enabled_var,
        command=app._on_adv_toggle,
        style="Dark.TCheckbutton",
    ).grid(row=0, column=0, sticky="w")

    app.adv_body = ttk.Frame(adv)
    app.adv_body.grid(row=1, column=0, sticky="ew", pady=(8, 0))
    app.adv_body.columnconfigure(3, weight=1)

    ttk.Checkbutton(
        app.adv_body,
        text="Enable extraction",
        variable=app.extract_var,
        command=app._save_cfg,
        style="Dark.TCheckbutton",
    ).grid(row=0, column=0, sticky="w")

    ttk.Checkbutton(
        app.adv_body,
        text="Enable subfiles triage",
        variable=app.subfiles_var,
        command=app._save_cfg,
        style="Dark.TCheckbutton",
    ).grid(row=0, column=1, sticky="w", padx=(14, 0))

    ttk.Label(app.adv_body, text="Subfile limit:").grid(row=0, column=2, sticky="e", padx=(14, 6))
    app.subfile_limit_spin = ttk.Spinbox(
        app.adv_body,
        from_=0,
        to=999,
        textvariable=app.subfile_limit_var,
        width=6,
        command=app._save_cfg,
        style="Dark.TSpinbox",
    )
    app.subfile_limit_spin.grid(row=0, column=3, sticky="w")

    ttk.Checkbutton(
        app.adv_body,
        text="Strings lite",
        variable=app.strings_lite_var,
        command=app._on_strings_mode_changed,
        style="Dark.TCheckbutton",
    ).grid(row=1, column=0, sticky="w", pady=(8, 0))

    ttk.Checkbutton(
        app.adv_body,
        text="Skip strings",
        variable=app.no_strings_var,
        command=app._on_strings_mode_changed,
        style="Dark.TCheckbutton",
    ).grid(row=1, column=1, sticky="w", padx=(14, 0), pady=(8, 0))

    app.effective_label = ttk.Label(adv, text="")
    app.effective_label.grid(row=2, column=0, sticky="w", pady=(10, 0))

    run_row = ttk.Frame(config)
    run_row.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
    run_row.columnconfigure(1, weight=1)

    app.run_btn = ttk.Button(
        run_row,
        text="Run Analysis",
        style="Action.TButton",
        width=18,
        command=app._start_analysis,
    )
    app.run_btn.grid(row=0, column=0, sticky="w")

    ttk.Button(
        run_row,
        text="Open Dynamic Analysis",
        style="Action.TButton",
        width=20,
        command=app._open_dynamic_window,
    ).grid(row=0, column=1, sticky="w", padx=(8, 0))

    ttk.Label(run_row, textvariable=app.running_var).grid(row=0, column=2, sticky="e")
    run_row.columnconfigure(2, weight=1)

    return config


def build_run_progress_section(app, parent):
    parent.rowconfigure(0, weight=1)
    parent.columnconfigure(0, weight=1)

    panel = ttk.LabelFrame(parent, text="Run Static Analysis")
    panel.grid(row=0, column=0, sticky="nsew")
    panel.columnconfigure(0, weight=1)
    panel.rowconfigure(1, weight=1)

    app.overall_var = tk.IntVar(value=0)
    app.overall_bar = ttk.Progressbar(
        panel,
        orient="horizontal",
        mode="determinate",
        maximum=100,
        variable=app.overall_var,
    )
    app.overall_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))

    app.overall_text = ttk.Label(panel, text="0%")
    app.overall_text.grid(row=0, column=1, sticky="w", padx=(10, 10), pady=(10, 0))

    app.steps_frame = ttk.Frame(panel)
    app.steps_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=10, pady=(10, 10))
    app.steps_frame.columnconfigure(1, weight=1)

    return panel


def build_results_section(app, parent):
    results = ttk.LabelFrame(parent, text="Results")
    results.grid(row=0, column=0, sticky="nsew")
    results.columnconfigure(0, weight=1)
    results.rowconfigure(2, weight=1)

    combined_wrap = ttk.Frame(results)
    combined_wrap.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))
    combined_wrap.columnconfigure(1, weight=1)
    combined_wrap.columnconfigure(3, weight=1)

    ttk.Label(combined_wrap, text="Combined Score:").grid(row=0, column=0, sticky="w")
    ttk.Label(
        combined_wrap,
        textvariable=app.combined_score_var,
        style="SummaryValue.TLabel",
    ).grid(row=0, column=1, sticky="w", padx=(8, 20))

    ttk.Label(combined_wrap, text="Severity:").grid(row=0, column=2, sticky="w")
    ttk.Label(
        combined_wrap,
        textvariable=app.combined_severity_var,
        style="SummaryAccent.TLabel",
    ).grid(row=0, column=3, sticky="w", padx=(8, 0))

    ttk.Label(combined_wrap, text="Verdict:").grid(row=1, column=0, sticky="w", pady=(8, 0))
    ttk.Label(combined_wrap, textvariable=app.combined_verdict_var).grid(
        row=1, column=1, sticky="w", padx=(8, 20), pady=(8, 0)
    )

    ttk.Label(combined_wrap, text="Confidence:").grid(row=1, column=2, sticky="w", pady=(8, 0))
    ttk.Label(combined_wrap, textvariable=app.combined_confidence_var).grid(
        row=1, column=3, sticky="w", padx=(8, 0), pady=(8, 0)
    )

    ttk.Separator(results, orient="horizontal").grid(
        row=1, column=0, sticky="ew", padx=12, pady=(0, 8)
    )

    lower = ttk.Frame(results)
    lower.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))
    lower.columnconfigure(0, weight=1)
    lower.columnconfigure(1, weight=1)
    lower.rowconfigure(0, weight=1)

    static_panel = ttk.LabelFrame(lower, text="Static Summary")
    static_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
    static_panel.columnconfigure(1, weight=1)

    ttk.Label(static_panel, text="Score:").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))
    ttk.Label(static_panel, textvariable=app.score_var).grid(
        row=0, column=1, sticky="w", padx=(8, 10), pady=(10, 0)
    )

    ttk.Label(static_panel, text="Verdict:").grid(row=1, column=0, sticky="w", padx=10, pady=(6, 0))
    ttk.Label(static_panel, textvariable=app.verdict_var).grid(
        row=1, column=1, sticky="w", padx=(8, 10), pady=(6, 0)
    )

    ttk.Label(static_panel, text="Confidence:").grid(row=2, column=0, sticky="w", padx=10, pady=(6, 0))
    ttk.Label(static_panel, textvariable=app.confidence_var).grid(
        row=2, column=1, sticky="w", padx=(8, 10), pady=(6, 0)
    )

    ttk.Separator(static_panel, orient="horizontal").grid(
        row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 8)
    )

    ttk.Label(static_panel, text="Subscores", style="SectionHeader.TLabel").grid(
        row=4, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 6)
    )

    ttk.Label(static_panel, text="Static:").grid(row=5, column=0, sticky="w", padx=10)
    ttk.Label(static_panel, textvariable=app.static_subscore_var).grid(
        row=5, column=1, sticky="w", padx=(8, 10)
    )

    ttk.Label(static_panel, text="Dynamic:").grid(row=6, column=0, sticky="w", padx=10, pady=(6, 0))
    ttk.Label(static_panel, textvariable=app.dynamic_subscore_var).grid(
        row=6, column=1, sticky="w", padx=(8, 10), pady=(6, 0)
    )

    ttk.Label(static_panel, text="Spec/API:").grid(row=7, column=0, sticky="w", padx=10, pady=(6, 10))
    ttk.Label(static_panel, textvariable=app.spec_subscore_var).grid(
        row=7, column=1, sticky="w", padx=(8, 10), pady=(6, 10)
    )

    vt_panel = ttk.LabelFrame(lower, text="VirusTotal")
    vt_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
    vt_panel.columnconfigure(0, weight=1)

    ttk.Label(
        vt_panel,
        textvariable=app.vt_status_var,
        wraplength=320,
        justify="left",
    ).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))

    ttk.Label(
        vt_panel,
        textvariable=app.vt_name_var,
        wraplength=320,
        justify="left",
    ).grid(row=1, column=0, sticky="w", padx=10, pady=(6, 0))

    ttk.Label(
        vt_panel,
        textvariable=app.vt_counts_var,
        wraplength=320,
        justify="left",
    ).grid(row=2, column=0, sticky="w", padx=10, pady=(6, 0))

    app.vt_open_btn = ttk.Button(
        vt_panel,
        text="Open VirusTotal",
        command=app._open_virustotal,
        state="disabled",
        style="Action.TButton",
    )
    app.vt_open_btn.grid(row=3, column=0, sticky="e", padx=10, pady=(12, 10))

    return results


def build_output_section(app, parent):
    out = ttk.LabelFrame(parent, text="Output")
    out.grid(row=0, column=0, sticky="nsew")
    out.columnconfigure(0, weight=1)
    out.rowconfigure(0, weight=1)

    app.output = tk.Text(
        out,
        wrap="none",
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
    app.output.grid(row=0, column=0, sticky="nsew")

    yscroll = ttk.Scrollbar(out, orient="vertical", command=app.output.yview)
    yscroll.grid(row=0, column=1, sticky="ns")
    app.output.configure(yscrollcommand=yscroll.set)

    return out