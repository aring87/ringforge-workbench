import html
import json
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser

from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Dict, Optional

from PIL import Image, ImageTk

from dynamic_analysis.html_report import write_dynamic_html_report
from dynamic_analysis.orchestrator import run_dynamic_analysis
from static_triage_engine.scoring import combined_score_from_case_dir


class DynamicAnalysisWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("RingForge Workbench - Dynamic Analysis")
        self.geometry("1360x1040")
        self.minsize(1120, 920)
        self.configure(bg="#05070B")

        cfg = getattr(app, "cfg", {}) or {}

        app_case_var = getattr(app, "case_var", None)
        app_sample_var = getattr(app, "sample_var", None)
        app_case_root_var = getattr(app, "case_root_var", None)
        app_case_dir_detected = getattr(app, "case_dir_detected", None)

        main_sample = ""
        if app_sample_var is not None:
            try:
                main_sample = app_sample_var.get().strip()
            except Exception:
                main_sample = ""

        main_case_name = ""
        if app_case_var is not None:
            try:
                main_case_name = app_case_var.get().strip()
            except Exception:
                main_case_name = ""

        case_root_value = ""
        if app_case_root_var is not None:
            try:
                case_root_value = app_case_root_var.get().strip()
            except Exception:
                case_root_value = ""

        default_case_name = main_case_name or Path(main_sample or "sample").stem or "dynamic_case"
        default_case_root = Path(case_root_value) if case_root_value else (Path.cwd() / "cases")
        default_case_path = Path(app_case_dir_detected) if app_case_dir_detected else (default_case_root / default_case_name)

        self.sample_var = tk.StringVar(value=main_sample)
        self.case_dir_var = tk.StringVar(value=cfg.get("dynamic_case_dir", str(default_case_path)))
        self.timeout_var = tk.IntVar(value=int(cfg.get("dynamic_timeout_seconds", 30)))
        self.procmon_enabled_var = tk.BooleanVar(value=bool(cfg.get("dynamic_procmon_enabled", True)))

        project_root = Path(__file__).resolve().parents[1]
        self.procmon_path_var = tk.StringVar(
            value=cfg.get("dynamic_procmon_path", str(project_root / "tools" / "Procmon64.exe"))
        )
        self.procmon_config_var = tk.StringVar(
            value=cfg.get(
                "dynamic_procmon_config_path",
                str(project_root / "tools" / "procmon-configs" / "dynamic_default.pmc"),
            )
        )

        self.status_var = tk.StringVar(value="Idle")
        self.summary_status_var = tk.StringVar(value="Ready")
        self.summary_sample_var = tk.StringVar(value=Path(main_sample).name if main_sample else "-")
        self.summary_case_var = tk.StringVar(value=Path(self.case_dir_var.get()).name if self.case_dir_var.get().strip() else "-")
        self.summary_procmon_var = tk.StringVar(value="Enabled" if self.procmon_enabled_var.get() else "Disabled")
        self.summary_timeout_var = tk.StringVar(value=str(self.timeout_var.get()))
        self.summary_report_var = tk.StringVar(value="-")

        self.metric_process_var = tk.StringVar(value="-")
        self.metric_network_var = tk.StringVar(value="-")
        self.metric_filewrite_var = tk.StringVar(value="-")
        self.metric_suspicious_var = tk.StringVar(value="-")
        self.metric_persistence_var = tk.StringVar(value="-")

        self.progress_var = tk.IntVar(value=0)
        self.step_vars = {}

        self.brand_logo_img = None
        self.last_api_dir: Optional[Path] = None
        self.last_html_report: Optional[Path] = None
        self.last_json_report: Optional[Path] = None
        self.last_response_payload: Optional[dict] = None

        self.output_q: "queue.Queue[str]" = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None

        self._build_ui()
        self._reset_progress()
        self._refresh_summary_from_inputs()
        self.after(150, self._drain_output)

        self.transient(app)
        self.grab_set()

    def _build_ui(self):
        outer = {"padx": 12, "pady": 8}

        self._build_top_banner(outer)

        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, **outer)
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(0, weight=0)
        frm.rowconfigure(1, weight=1)

        header = ttk.LabelFrame(frm, text="Dynamic Analysis Setup")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        ttk.Label(header, text="Sample:").grid(row=0, column=0, sticky="w", padx=(10, 0), pady=(10, 0))
        ttk.Entry(header, textvariable=self.sample_var, width=100).grid(
            row=0, column=1, sticky="ew", padx=8, pady=(10, 0)
        )
        ttk.Button(
            header,
            text="Use Main Sample",
            style="Side.Action.TButton",
            command=self._use_main_sample,
        ).grid(row=0, column=2, sticky="ew", padx=(0, 10), pady=(10, 0))

        ttk.Label(header, text="Dynamic case folder:").grid(row=1, column=0, sticky="w", padx=(10, 0), pady=(8, 0))
        ttk.Entry(header, textvariable=self.case_dir_var, width=100).grid(
            row=1, column=1, sticky="ew", padx=8, pady=(8, 0)
        )
        ttk.Button(
            header,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_case_dir,
        ).grid(row=1, column=2, sticky="ew", padx=(0, 10), pady=(8, 0))

        ttk.Label(header, text="Timeout (seconds):").grid(row=2, column=0, sticky="w", padx=(10, 0), pady=(8, 10))

        runtime_row = ttk.Frame(header)
        runtime_row.grid(row=2, column=1, columnspan=2, sticky="w", padx=8, pady=(8, 10))

        ttk.Spinbox(
            runtime_row,
            from_=5,
            to=7200,
            textvariable=self.timeout_var,
            width=10,
            style="Dark.TSpinbox",
        ).pack(side="left")

        ttk.Checkbutton(
            runtime_row,
            text="Enable Procmon Capture",
            variable=self.procmon_enabled_var,
            style="Dark.TCheckbutton",
            command=self._refresh_summary_from_inputs,
        ).pack(side="left", padx=(14, 0))

        workspace = ttk.Frame(frm)
        workspace.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        workspace.columnconfigure(0, weight=1)
        workspace.columnconfigure(1, weight=1)
        workspace.rowconfigure(0, weight=0)
        workspace.rowconfigure(1, weight=1)

        left_top = ttk.Frame(workspace)
        left_top.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left_top.columnconfigure(0, weight=1)

        right_top = ttk.Frame(workspace)
        right_top.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right_top.columnconfigure(0, weight=1)

        self._build_settings_section(left_top)
        self._build_run_status_section(right_top)

        left_bottom = ttk.Frame(workspace)
        left_bottom.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(10, 0))
        left_bottom.columnconfigure(0, weight=1)
        left_bottom.rowconfigure(0, weight=1)

        right_bottom = ttk.Frame(workspace)
        right_bottom.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=(10, 0))
        right_bottom.columnconfigure(0, weight=1)
        right_bottom.rowconfigure(0, weight=1)

        self._build_output_section(left_bottom)
        self._build_findings_summary_section(right_bottom)

    def _build_top_banner(self, outer):
        panel_bg = "#0B1220"
        border = "#294C8E"
        accent = "#2F6BFF"
        text_main = "#F7FAFF"
        text_soft = "#B8C7E6"

        banner_wrap = ttk.Frame(self)
        banner_wrap.pack(fill="x", **outer)

        banner = tk.Frame(
            banner_wrap,
            bg=panel_bg,
            highlightthickness=1,
            highlightbackground=border,
            highlightcolor=border,
        )
        banner.pack(fill="x")
        banner.columnconfigure(1, weight=1)

        logo_path = Path(__file__).resolve().parents[1] / "assets" / "anvil.png"
        if logo_path.exists():
            logo_img = Image.open(logo_path).convert("RGBA")
            logo_img = logo_img.resize((96, 96), Image.LANCZOS)
            self.brand_logo_img = ImageTk.PhotoImage(logo_img)

            tk.Label(
                banner,
                image=self.brand_logo_img,
                bg=panel_bg,
                bd=0,
                highlightthickness=0,
            ).grid(row=0, column=0, rowspan=3, sticky="w", padx=(16, 18), pady=14)
        else:
            tk.Label(
                banner,
                text="[anvil.png missing]",
                bg=panel_bg,
                fg=accent,
                font=("Segoe UI", 10, "bold"),
                bd=0,
                highlightthickness=0,
            ).grid(row=0, column=0, rowspan=3, sticky="w", padx=(16, 18), pady=14)

        tk.Label(
            banner,
            text="RingForge Workbench",
            bg=panel_bg,
            fg=text_main,
            font=("Segoe UI", 24, "bold"),
            anchor="w",
        ).grid(row=0, column=1, sticky="sw", pady=(16, 0))

        tk.Label(
            banner,
            text="Dynamic Analysis",
            bg=panel_bg,
            fg=accent,
            font=("Segoe UI", 18, "bold"),
            anchor="w",
        ).grid(row=1, column=1, sticky="nw")

        tk.Label(
            banner,
            text="Runtime behavior capture, persistence tracking, dropped-file review, and post-execution triage.",
            bg=panel_bg,
            fg=text_soft,
            font=("Segoe UI", 10),
            anchor="w",
            justify="left",
            wraplength=980,
        ).grid(row=2, column=1, sticky="w", pady=(4, 16))

    def _build_settings_section(self, parent):
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
    
        settings = ttk.LabelFrame(parent, text="Dynamic Settings")
        settings.grid(row=0, column=0, sticky="nsew")
        settings.columnconfigure(1, weight=1)
        settings.rowconfigure(2, weight=1)

        ttk.Label(settings, text="Procmon path:").grid(row=0, column=0, sticky="w", padx=(10, 0), pady=(10, 0))
        ttk.Entry(settings, textvariable=self.procmon_path_var, width=100).grid(
            row=0, column=1, sticky="ew", padx=8, pady=(10, 0)
        )
        ttk.Button(
            settings,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_procmon,
        ).grid(row=0, column=2, sticky="ew", padx=(0, 10), pady=(10, 0))

        ttk.Label(settings, text="Procmon config:").grid(row=1, column=0, sticky="w", padx=(10, 0), pady=(8, 0))
        ttk.Entry(settings, textvariable=self.procmon_config_var, width=100).grid(
            row=1, column=1, sticky="ew", padx=8, pady=(8, 0)
        )
        ttk.Button(
            settings,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_procmon_config,
        ).grid(row=1, column=2, sticky="ew", padx=(0, 10), pady=(8, 0))

        notes = ttk.LabelFrame(settings, text="Analyst Notes")
        notes.grid(row=2, column=0, columnspan=3, sticky="ew", padx=10, pady=(10, 10))
        notes.columnconfigure(0, weight=1)

        note_text = (
            "• Use a VM snapshot before execution.\n"
            "• Run elevated when Procmon capture requires it.\n"
            "• Prefer isolated networking for unknown samples.\n"
            "• Signed installers may produce noisy but expected writes."
        )
        ttk.Label(notes, text=note_text, justify="left").grid(row=0, column=0, sticky="w", padx=10, pady=10)

        actions = ttk.Frame(settings)
        actions.grid(row=3, column=0, columnspan=3, sticky="ew", padx=10, pady=(0, 10))
        actions.columnconfigure(4, weight=1)

        self.run_btn = ttk.Button(
            actions,
            text="Run Dynamic Analysis",
            style="Action.TButton",
            width=20,
            command=self._start_dynamic_analysis,
        )
        self.run_btn.grid(row=0, column=0, sticky="w")

        ttk.Button(
            actions,
            text="Open Case Folder",
            style="Action.TButton",
            width=17,
            command=self._open_case_folder,
        ).grid(row=0, column=1, sticky="w", padx=(8, 0))

        ttk.Button(
            actions,
            text="Open Latest Report",
            style="Action.TButton",
            width=17,
            command=self._open_latest_dynamic_html,
        ).grid(row=0, column=2, sticky="w", padx=(8, 0))

        ttk.Button(
            actions,
            text="Export HTML",
            style="Action.TButton",
            width=14,
            command=self._export_dynamic_report,
        ).grid(row=0, column=3, sticky="w", padx=(8, 0))

        ttk.Label(actions, textvariable=self.status_var, anchor="e").grid(row=0, column=4, sticky="e", padx=(12, 0))

    def _build_run_status_section(self, parent):
        panel = ttk.LabelFrame(parent, text="Run Status")
        panel.grid(row=0, column=0, sticky="nsew")
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(2, weight=1)

        progress_wrap = ttk.Frame(panel)
        progress_wrap.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 8))
        progress_wrap.columnconfigure(0, weight=1)

        self.overall_bar = ttk.Progressbar(
            progress_wrap,
            orient="horizontal",
            mode="determinate",
            maximum=100,
            variable=self.progress_var,
        )
        self.overall_bar.grid(row=0, column=0, sticky="ew")

        self.overall_text = ttk.Label(progress_wrap, text="0%")
        self.overall_text.grid(row=0, column=1, sticky="w", padx=(10, 0))

        summary = ttk.LabelFrame(panel, text="Quick Status")
        summary.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        summary.columnconfigure(1, weight=1)

        rows = [
            ("Status:", self.summary_status_var),
            ("Sample:", self.summary_sample_var),
            ("Case:", self.summary_case_var),
            ("Procmon:", self.summary_procmon_var),
            ("Timeout:", self.summary_timeout_var),
            ("Latest Report:", self.summary_report_var),
        ]

        for idx, (label, var) in enumerate(rows):
            ttk.Label(summary, text=label).grid(row=idx, column=0, sticky="w", pady=(0 if idx == 0 else 6, 0))
            ttk.Label(summary, textvariable=var, wraplength=420, justify="left").grid(
                row=idx, column=1, sticky="w", padx=(8, 0), pady=(0 if idx == 0 else 6, 0)
            )

        steps_panel = ttk.LabelFrame(panel, text="Execution Steps")
        steps_panel.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))
        steps_panel.columnconfigure(1, weight=1)

        self.steps_frame = ttk.Frame(steps_panel)
        self.steps_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.steps_frame.columnconfigure(1, weight=1)

    def _build_output_section(self, parent):
        outwrap = ttk.LabelFrame(parent, text="Output")
        outwrap.grid(row=0, column=0, sticky="nsew")
        outwrap.columnconfigure(0, weight=1)
        outwrap.rowconfigure(0, weight=1)

        self.output = tk.Text(
            outwrap,
            wrap="word",
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
        self.output.grid(row=0, column=0, sticky="nsew")

        ysb = ttk.Scrollbar(outwrap, orient="vertical", command=self.output.yview)
        ysb.grid(row=0, column=1, sticky="ns")
        self.output.configure(yscrollcommand=ysb.set)

    def _build_findings_summary_section(self, parent):
        panel = ttk.LabelFrame(parent, text="Findings Summary")
        panel.grid(row=0, column=0, sticky="nsew")
        panel.columnconfigure(1, weight=1)
        panel.rowconfigure(len(metrics), weight=0)
        panel.rowconfigure(len(metrics) + 1, weight=1)

        metrics = [
            ("Processes:", self.metric_process_var),
            ("Network Events:", self.metric_network_var),
            ("File Writes:", self.metric_filewrite_var),
            ("Suspicious Paths:", self.metric_suspicious_var),
            ("Persistence Hits:", self.metric_persistence_var),
        ]

        for idx, (label, var) in enumerate(metrics):
            ttk.Label(panel, text=label).grid(row=idx, column=0, sticky="w", padx=(10, 0), pady=(10 if idx == 0 else 6, 0))
            ttk.Label(panel, textvariable=var).grid(row=idx, column=1, sticky="w", padx=(8, 10), pady=(10 if idx == 0 else 6, 0))

        report_actions = ttk.LabelFrame(panel, text="Report Actions")
        report_actions.grid(row=len(metrics), column=0, columnspan=2, sticky="ew", padx=10, pady=(14, 10))
        report_actions.columnconfigure(0, weight=1)

        ttk.Button(
            report_actions,
            text="Open Case Folder",
            style="Action.TButton",
            command=self._open_case_folder,
        ).grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))

        ttk.Button(
            report_actions,
            text="Open Latest Report",
            style="Action.TButton",
            command=self._open_latest_dynamic_html,
        ).grid(row=1, column=0, sticky="ew", padx=10, pady=6)

        ttk.Button(
            report_actions,
            text="Export HTML",
            style="Action.TButton",
            command=self._export_dynamic_report,
        ).grid(row=2, column=0, sticky="ew", padx=10, pady=6)

    def _reset_progress(self):
        for w in self.steps_frame.winfo_children():
            w.destroy()
        self.step_vars.clear()

        steps = [
            "Pre-checks",
            "Procmon start",
            "Sample execution",
            "Procmon stop",
            "Event parsing",
            "Persistence diff",
            "Findings summary",
            "Report generation",
        ]

        for idx, step in enumerate(steps):
            ttk.Label(self.steps_frame, text=f"{step}:").grid(row=idx, column=0, sticky="w")
            bar_var = tk.IntVar(value=0)
            ttk.Progressbar(
                self.steps_frame,
                orient="horizontal",
                mode="determinate",
                maximum=100,
                variable=bar_var,
            ).grid(row=idx, column=1, sticky="ew", padx=8)
            status = ttk.Label(self.steps_frame, text="idle")
            status.grid(row=idx, column=2, sticky="w")
            self.step_vars[step] = {"var": bar_var, "status": status}

        self.progress_var.set(0)
        self.overall_text.configure(text="0%")

    def _set_step(self, step: str, pct: int, status: str):
        item = self.step_vars.get(step)
        if not item:
            return
        item["var"].set(max(0, min(100, pct)))
        item["status"].configure(text=status)
        self._recalc_progress()

    def _recalc_progress(self):
        total = len(self.step_vars)
        if total == 0:
            self.progress_var.set(0)
            self.overall_text.configure(text="0%")
            return

        complete_statuses = {"done", "completed", "skipped", "n/a"}
        completed = 0
        for item in self.step_vars.values():
            st = item["status"].cget("text").strip().lower()
            if st in complete_statuses:
                completed += 1

        pct = int(round((completed / total) * 100))
        self.progress_var.set(pct)
        self.overall_text.configure(text=f"{pct}%")

    def _refresh_summary_from_inputs(self):
        sample_text = self.sample_var.get().strip()
        case_text = self.case_dir_var.get().strip()

        self.summary_sample_var.set(Path(sample_text).name if sample_text else "-")
        self.summary_case_var.set(Path(case_text).name if case_text else "-")
        self.summary_procmon_var.set("Enabled" if self.procmon_enabled_var.get() else "Disabled")
        self.summary_timeout_var.set(f"{self.timeout_var.get()} sec")

    def _save_cfg(self):
        if not hasattr(self.app, "cfg") or not isinstance(self.app.cfg, dict):
            self.app.cfg = {}

        self.app.cfg["dynamic_case_dir"] = self.case_dir_var.get().strip()
        self.app.cfg["dynamic_timeout_seconds"] = int(self.timeout_var.get())
        self.app.cfg["dynamic_procmon_enabled"] = bool(self.procmon_enabled_var.get())
        self.app.cfg["dynamic_procmon_path"] = self.procmon_path_var.get().strip()
        self.app.cfg["dynamic_procmon_config_path"] = self.procmon_config_var.get().strip()

        project_root = Path(__file__).resolve().parents[1]
        config_path = project_root / "config.json"
        config_path.write_text(json.dumps(self.app.cfg, indent=2), encoding="utf-8")

    def _use_main_sample(self):
        main_sample = ""
        app_sample_var = getattr(self.app, "sample_var", None)
        if app_sample_var is not None:
            try:
                main_sample = app_sample_var.get().strip()
            except Exception:
                main_sample = ""

        self.sample_var.set(main_sample)

        detected = getattr(self.app, "case_dir_detected", None)
        if detected:
            self.case_dir_var.set(str(Path(detected)))
        else:
            app_case_var = getattr(self.app, "case_var", None)
            app_case_root_var = getattr(self.app, "case_root_var", None)

            case_name = ""
            if app_case_var is not None:
                try:
                    case_name = app_case_var.get().strip()
                except Exception:
                    case_name = ""

            case_root = ""
            if app_case_root_var is not None:
                try:
                    case_root = app_case_root_var.get().strip()
                except Exception:
                    case_root = ""

            case_name = case_name or Path(main_sample or "sample").stem or "dynamic_case"
            case_root_path = Path(case_root) if case_root else (Path.cwd() / "cases")
            self.case_dir_var.set(str(case_root_path / case_name))

        self._refresh_summary_from_inputs()
        self._save_cfg()

    def _browse_case_dir(self):
        app_case_root_var = getattr(self.app, "case_root_var", None)

        case_root_value = ""
        if app_case_root_var is not None:
            try:
                case_root_value = app_case_root_var.get().strip()
            except Exception:
                case_root_value = ""

        default_case_root = Path(case_root_value) if case_root_value else (Path.cwd() / "cases")
        start = Path(self.case_dir_var.get()) if self.case_dir_var.get().strip() else default_case_root

        chosen = filedialog.askdirectory(title="Select dynamic case folder", initialdir=str(start))
        if chosen:
            self.case_dir_var.set(str(Path(chosen)))
            self._refresh_summary_from_inputs()
            self._save_cfg()

    def _browse_procmon(self):
        project_root = Path(__file__).resolve().parents[1]
        start = Path(self.procmon_path_var.get()).parent if self.procmon_path_var.get().strip() else (project_root / "tools")
        chosen = filedialog.askopenfilename(
            title="Select Procmon executable",
            initialdir=str(start),
            filetypes=[("Executable", "*.exe"), ("All Files", "*.*")],
        )
        if chosen:
            self.procmon_path_var.set(str(Path(chosen)))
            self._save_cfg()

    def _browse_procmon_config(self):
        project_root = Path(__file__).resolve().parents[1]
        raw = self.procmon_config_var.get().strip()
        start = Path(raw).parent if raw else (project_root / "tools" / "procmon-configs")
        chosen = filedialog.askopenfilename(
            title="Select Procmon config (.pmc)",
            initialdir=str(start),
            filetypes=[("Procmon Config", "*.pmc"), ("All Files", "*.*")],
        )
        if chosen:
            self.procmon_config_var.set(str(Path(chosen)))
            self._save_cfg()

    def _open_case_folder(self):
        case_dir = Path(self.case_dir_var.get().strip())
        if not case_dir.exists():
            messagebox.showwarning("Open Case Folder", f"Folder not found:\n{case_dir}", parent=self)
            return
        try:
            if os.name == "nt":
                os.startfile(str(case_dir))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(case_dir)])
            else:
                subprocess.Popen(["xdg-open", str(case_dir)])
        except Exception as e:
            messagebox.showerror("Open Case Folder", str(e), parent=self)

    def _export_dynamic_report(self):
        try:
            case_dir = Path(self.case_dir_var.get().strip())
            if not case_dir.exists():
                messagebox.showerror("Export Report", f"Case folder does not exist:\n{case_dir}", parent=self)
                return

            reports_dir = case_dir / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)

            summary_candidates = [
                reports_dir / "dynamic_run_summary.json",
                reports_dir / "run_summary.json",
                case_dir / "dynamic_run_summary.json",
                case_dir / "run_summary.json",
                case_dir / "metadata" / "run_summary.json",
            ]
            findings_candidates = [
                reports_dir / "dynamic_findings.json",
                case_dir / "dynamic_findings.json",
            ]

            summary_path = next((p for p in summary_candidates if p.exists()), None)
            findings_path = next((p for p in findings_candidates if p.exists()), None)
            output_html = reports_dir / "dynamic_report.html"

            if summary_path:
                write_dynamic_html_report(summary_path, output_html)
            elif findings_path:
                data = json.loads(findings_path.read_text(encoding="utf-8", errors="replace"))

                def esc(x):
                    return html.escape(str(x if x is not None else ""))

                highlights = data.get("highlights", []) or []
                counts = data.get("counts", {}) or {}
                sample = data.get("sample", {}) or {}
                html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Dynamic Report</title>
<style>
body {{ font-family: Segoe UI, Arial, sans-serif; background: #0b1220; color: #e5eefc; margin: 0; padding: 24px; }}
.card {{ background: #101a2f; border: 1px solid #223455; border-radius: 14px; padding: 18px; margin-bottom: 16px; }}
h1, h2 {{ margin-top: 0; color: #9cc4ff; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ border-bottom: 1px solid #223455; text-align: left; padding: 8px; vertical-align: top; }}
ul {{ margin-top: 8px; }} .muted {{ color: #9fb3d9; }}
</style></head><body>
<div class="card"><h1>Dynamic Analysis Report</h1><p class="muted">Case: {esc(case_dir.name)}</p><p><b>Sample:</b> {esc(sample.get("sample_name", ""))}</p><p><b>Path:</b> {esc(sample.get("sample_path", ""))}</p><p><b>SHA256:</b> {esc(sample.get("sha256", ""))}</p></div>
<div class="card"><h2>Highlights</h2>{"<ul>" + "".join(f"<li>{esc(x)}</li>" for x in highlights) + "</ul>" if highlights else "<p class='muted'>None</p>"}</div>
<div class="card"><h2>Findings Counts</h2><table>
<tr><th>Interesting Events</th><td>{esc(counts.get("interesting_events", 0))}</td></tr>
<tr><th>Process Creates</th><td>{esc(counts.get("process_creates", 0))}</td></tr>
<tr><th>Network Events</th><td>{esc(counts.get("network_events", 0))}</td></tr>
<tr><th>File Write Events</th><td>{esc(counts.get("file_write_events", 0))}</td></tr>
<tr><th>Suspicious Path Hits</th><td>{esc(counts.get("suspicious_path_hits", 0))}</td></tr>
<tr><th>Persistence Hits</th><td>{esc(counts.get("persistence_hits", 0))}</td></tr>
</table></div>
</body></html>"""
                output_html.write_text(html_doc, encoding="utf-8", errors="replace")
            else:
                checked = [str(p) for p in summary_candidates + findings_candidates]
                messagebox.showerror("Export Report", "No dynamic source file found.\n\nChecked:\n" + "\n".join(checked), parent=self)
                return

            self.summary_report_var.set(str(output_html))
            webbrowser.open(output_html.resolve().as_uri())
        except Exception as e:
            messagebox.showerror("Export Report", str(e), parent=self)

    def _open_latest_dynamic_html(self):
        try:
            case_dir = Path(self.case_dir_var.get().strip())
            if not case_dir.exists():
                messagebox.showerror("Open Report", f"Case folder does not exist:\n{case_dir}", parent=self)
                return
            html_path = case_dir / "reports" / "dynamic_report.html"
            if not html_path.exists():
                self._export_dynamic_report()
            if not html_path.exists():
                messagebox.showerror("Open Report", f"HTML report not found:\n{html_path}", parent=self)
                return
            self.summary_report_var.set(str(html_path))
            webbrowser.open(html_path.resolve().as_uri())
        except Exception as e:
            messagebox.showerror("Open Report", str(e), parent=self)

    def _start_dynamic_analysis(self):
        if self.worker_thread and self.worker_thread.is_alive():
            return

        sample = Path(self.sample_var.get().strip())
        if not sample.exists():
            messagebox.showerror("Dynamic Analysis failed", f"Sample not found:\n{sample}", parent=self)
            return

        case_dir = Path(self.case_dir_var.get().strip())
        case_dir.mkdir(parents=True, exist_ok=True)

        procmon_path = Path(self.procmon_path_var.get().strip())
        if self.procmon_enabled_var.get() and not procmon_path.exists():
            messagebox.showerror("Dynamic Analysis failed", f"Procmon not found:\n{procmon_path}", parent=self)
            return

        timeout_seconds = int(self.timeout_var.get())
        procmon_config = self.procmon_config_var.get().strip()
        config = {
            "sample_path": str(sample),
            "case_dir": str(case_dir),
            "timeout_seconds": timeout_seconds,
            "procmon_enabled": bool(self.procmon_enabled_var.get()),
            "procmon_path": str(procmon_path),
            "procmon_config_path": procmon_config,
        }

        self._save_cfg()
        self._reset_progress()
        self._refresh_summary_from_inputs()
        self.summary_status_var.set("Running")
        self.status_var.set("Running dynamic...")
        self.run_btn.configure(state="disabled")

        self._set_step("Pre-checks", 100, "done")
        self._set_step("Procmon start", 25, "running")

        self.output.delete("1.0", "end")
        self.output.insert("end", "Starting dynamic analysis:\n")
        self.output.insert("end", f"  sample={sample}\n")
        self.output.insert("end", f"  case_dir={case_dir}\n")
        self.output.insert("end", f"  timeout_seconds={timeout_seconds}\n")
        self.output.insert("end", f"  procmon_enabled={config['procmon_enabled']}\n\n")
        self.output.see("end")

        def worker():
            try:
                summary = run_dynamic_analysis(
                    config,
                    status_cb=lambda msg: self.output_q.put(f"[status] {msg}\n"),
                )

                findings = summary.get("findings", {})
                highlights = findings.get("highlights", [])

                if highlights:
                    self.output_q.put("Highlights:\n")
                    for item in highlights:
                        self.output_q.put(f"  - {item}\n")
                    self.output_q.put("\n")

                task_counts = summary.get("task_diff_summary", {})
                if task_counts:
                    self.output_q.put("Scheduled task diff:\n")
                    self.output_q.put(f"  - New tasks: {task_counts.get('new_tasks', 0)}\n")
                    self.output_q.put(f"  - Modified tasks: {task_counts.get('modified_tasks', 0)}\n")
                    self.output_q.put(f"  - Removed tasks: {task_counts.get('removed_tasks', 0)}\n")
                    self.output_q.put(f"  - Suspicious new/modified: {task_counts.get('suspicious_new_or_modified', 0)}\n\n")

                service_counts = summary.get("service_diff_summary", {})
                if service_counts:
                    self.output_q.put("Service diff:\n")
                    self.output_q.put(f"  - New services: {service_counts.get('new_services', 0)}\n")
                    self.output_q.put(f"  - Modified services: {service_counts.get('modified_services', 0)}\n")
                    self.output_q.put(f"  - Removed services: {service_counts.get('removed_services', 0)}\n")
                    self.output_q.put(f"  - Suspicious new/modified: {service_counts.get('suspicious_new_or_modified', 0)}\n\n")

                top_written = findings.get("top_written_paths", [])
                if top_written:
                    self.output_q.put("Top written paths:\n")
                    for row in top_written[:5]:
                        self.output_q.put(f"  - {row.get('count', 0)}x  {row.get('path', '')}\n")
                    self.output_q.put("\n")

                top_net = findings.get("top_network_processes", [])
                if top_net:
                    self.output_q.put("Top network processes:\n")
                    for row in top_net[:5]:
                        self.output_q.put(f"  - {row.get('process_name', '')}: {row.get('count', 0)}\n")
                    self.output_q.put("\n")

                self.output_q.put(json.dumps(summary, indent=2))
                self.after(0, lambda s=summary: self._on_done(s))
            except Exception as e:
                self.output_q.put(f"[error] {e}\n")
                self.after(0, lambda err=str(e): self._on_error(err))

        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()

    def _on_done(self, summary: Dict):
        self.app.latest_dynamic_result = summary if isinstance(summary, dict) else {}

        self._set_step("Procmon start", 100, "done")
        self._set_step("Sample execution", 100, "done")
        self._set_step("Procmon stop", 100, "done")
        self._set_step("Event parsing", 100, "done")
        self._set_step("Persistence diff", 100, "done")
        self._set_step("Findings summary", 100, "done")
        self._set_step("Report generation", 100, "done")

        findings = summary.get("findings", {}) if isinstance(summary, dict) else {}
        counts = findings.get("counts", {}) if isinstance(findings, dict) else {}

        self.metric_process_var.set(str(counts.get("process_creates", 0)))
        self.metric_network_var.set(str(counts.get("network_events", 0)))
        self.metric_filewrite_var.set(str(counts.get("file_write_events", 0)))
        self.metric_suspicious_var.set(str(counts.get("suspicious_path_hits", 0)))
        self.metric_persistence_var.set(str(counts.get("persistence_hits", 0)))

        self.run_btn.configure(state="normal")
        self.status_var.set("Idle")
        self.summary_status_var.set("Completed")

        def finalize_refresh():
            case_dir = None

            if getattr(self.app, "case_dir_detected", None):
                case_dir = Path(self.app.case_dir_detected)
            else:
                case_dir = Path(self.case_dir_var.get().strip())

            if case_dir and case_dir.exists():
                self.app.case_dir_detected = case_dir
                html_path = case_dir / "reports" / "dynamic_report.html"
                self.summary_report_var.set(str(html_path) if html_path.exists() else str(case_dir / "reports"))

                combined_score_from_case_dir(
                    case_dir,
                    dynamic_result=None,
                    spec_result=None,
                    write_output=True,
                )

                if hasattr(self.app, "refresh_combined_score"):
                    self.app.refresh_combined_score(case_dir)
            else:
                if hasattr(self.app, "refresh_combined_score"):
                    self.app.refresh_combined_score()

            exit_code = summary.get("exit_code")
            if exit_code == 0:
                messagebox.showinfo("Completed", "Dynamic analysis completed successfully.", parent=self)
            else:
                messagebox.showwarning(
                    "Completed",
                    f"Dynamic analysis completed. Sample exited with code {exit_code}.",
                    parent=self,
                )

        self.after(300, finalize_refresh)

    def _on_error(self, err: str):
        self.run_btn.configure(state="normal")
        self.status_var.set("Idle")
        self.summary_status_var.set("Error")
        self._set_step("Procmon start", 100, "done")
        messagebox.showerror("Dynamic Analysis failed", err, parent=self)

    def _drain_output(self):
        try:
            while True:
                line = self.output_q.get_nowait()
                self.output.insert("end", line)
                self.output.see("end")
        except queue.Empty:
            pass
        self.after(150, self._drain_output)