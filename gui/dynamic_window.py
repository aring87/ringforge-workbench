import html
import json
import os
import queue
import re
import subprocess
import ctypes
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
    r"""
    RingForge Dynamic Analysis window.

    Folder model used by this window:

    cases\<case_name>\
        static_analysis\
        dynamic_analysis\
            dynamic_runs\
                <run_id>\
                    metadata\
                        dynamic_run_summary.json
            reports\
                dynamic_report.html

    The main case folder remains:
        cases\<case_name>

    The dynamic engine receives:
        cases\<case_name>\dynamic_analysis

    This keeps static, dynamic, spec, API, and extension outputs cleaner.
    """

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("RingForge Workbench - Dynamic Analysis")
        self.configure(bg="#05070B")
        self.resizable(True, True)
        self._autosize_window()

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
        default_case_name = self._safe_case_name(default_case_name)

        default_case_root = Path(case_root_value) if case_root_value else (Path.cwd() / "cases")

        if app_case_dir_detected:
            default_case_home = Path(app_case_dir_detected)
        else:
            default_case_home = default_case_root / default_case_name

        default_dynamic_output = default_case_home / "dynamic_analysis"

        self.sample_var = tk.StringVar(value=main_sample)

        # Main case folder / home folder.
        self.case_dir_var = tk.StringVar(
            value=cfg.get("dynamic_case_dir", str(default_case_home))
        )

        # Dynamic-only output folder under the case home folder.
        self.dynamic_output_dir_var = tk.StringVar(
            value=cfg.get("dynamic_output_dir", str(default_dynamic_output))
        )

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
        self.summary_case_var = tk.StringVar(value=Path(self.case_dir_var.get()).name)
        self.summary_output_var = tk.StringVar(value=str(self.dynamic_output_dir_var.get()))
        self.summary_procmon_var = tk.StringVar(value="Enabled" if self.procmon_enabled_var.get() else "Disabled")
        self.summary_timeout_var = tk.StringVar(value=f"{self.timeout_var.get()} sec")
        self.summary_report_var = tk.StringVar(value="-")

        self.metric_score_var = tk.StringVar(value="-")
        self.metric_process_var = tk.StringVar(value="-")
        self.metric_network_var = tk.StringVar(value="-")
        self.metric_filewrite_var = tk.StringVar(value="-")
        self.metric_suspicious_var = tk.StringVar(value="-")
        self.metric_persistence_var = tk.StringVar(value="-")

        self.progress_var = tk.IntVar(value=0)
        self.step_vars = {}

        self.brand_logo_img = None
        self.output_q: "queue.Queue[str]" = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None
        self.cancel_event = threading.Event()

        self._build_ui()
        self._reset_progress()
        self._refresh_summary_from_inputs()
        self.after(150, self._drain_output)

        self.grab_set()


    def _get_work_area(self) -> tuple[int, int, int, int]:
        """
        Return the usable desktop work area as (left, top, width, height).

        On Windows this excludes the taskbar, which prevents the bottom of the
        Dynamic Analysis window from being hidden behind the taskbar in VMs or
        high-DPI displays. Other platforms fall back to Tk screen dimensions.
        """
        screen_w = int(self.winfo_screenwidth())
        screen_h = int(self.winfo_screenheight())

        if os.name == "nt":
            try:
                class RECT(ctypes.Structure):
                    _fields_ = [
                        ("left", ctypes.c_long),
                        ("top", ctypes.c_long),
                        ("right", ctypes.c_long),
                        ("bottom", ctypes.c_long),
                    ]

                rect = RECT()
                SPI_GETWORKAREA = 0x0030
                if ctypes.windll.user32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(rect), 0):
                    return (
                        int(rect.left),
                        int(rect.top),
                        int(rect.right - rect.left),
                        int(rect.bottom - rect.top),
                    )
            except Exception:
                pass

        return 0, 0, screen_w, screen_h

    def _autosize_window(self):
        """
        Size the Dynamic Analysis window based on the usable screen area.

        The previous approach maximized the window on Windows. That can still
        cause clipping on VMware consoles, taskbar-heavy desktops, or scaled
        displays. This version uses the work area, leaves a small safety margin,
        and enables compact layout rules when vertical space is limited.
        """
        try:
            self.update_idletasks()

            work_x, work_y, work_w, work_h = self._get_work_area()

            # Compact mode reduces banner, padding, and text-area height on
            # smaller VM/laptop displays.
            self._compact_ui = work_h < 980

            width_pct = 0.97
            height_pct = 0.96 if self._compact_ui else 0.94
            safety_x = 20
            safety_y = 36 if os.name == "nt" else 28

            width = min(int(work_w * width_pct), max(900, work_w - safety_x))
            height = min(int(work_h * height_pct), max(640, work_h - safety_y))

            min_w = min(1120, max(940, work_w - 80))
            min_h = min(720, max(620, work_h - 100))

            width = max(width, min_w)
            height = max(height, min_h)

            x = work_x + max((work_w - width) // 2, 0)
            y = work_y + max((work_h - height) // 2, 0)

            self.geometry(f"{width}x{height}+{x}+{y}")
            self.minsize(min_w, min_h)

            # Do not force zoomed/maximized here. Keeping the window inside the
            # calculated work area avoids clipping behind the Windows taskbar.
            # Users can still maximize manually if desired.

        except Exception:
            self._compact_ui = True
            self.geometry("1280x780")
            self.minsize(1040, 660)


    # -------------------------------------------------------------------------
    # Path helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _safe_case_name(value: str) -> str:
        value = (value or "dynamic_case").strip()
        value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
        value = value.strip("._-")
        return value or "dynamic_case"

    def _project_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    def _get_case_home_dir(self) -> Path:
        raw = self.case_dir_var.get().strip()
        if raw:
            return Path(raw)

        sample = self.sample_var.get().strip()
        case_name = self._safe_case_name(Path(sample).stem if sample else "dynamic_case")
        return self._project_root() / "cases" / case_name

    def _get_dynamic_output_dir(self) -> Path:
        raw = self.dynamic_output_dir_var.get().strip()
        if raw:
            return Path(raw)

        return self._get_case_home_dir() / "dynamic_analysis"

    def _ensure_case_layout(self) -> tuple[Path, Path]:
        """
        Creates the cleaner case folder layout.

        Returns:
            (case_home_dir, dynamic_output_dir)
        """
        case_home = self._get_case_home_dir()
        dynamic_output = self._get_dynamic_output_dir()

        case_home.mkdir(parents=True, exist_ok=True)

        # Create module folders.
        (case_home / "static_analysis").mkdir(parents=True, exist_ok=True)
        dynamic_output.mkdir(parents=True, exist_ok=True)
        (dynamic_output / "reports").mkdir(parents=True, exist_ok=True)
        (dynamic_output / "metadata").mkdir(parents=True, exist_ok=True)

        self.case_dir_var.set(str(case_home))
        self.dynamic_output_dir_var.set(str(dynamic_output))

        return case_home, dynamic_output

    def _sync_dynamic_output_to_case(self):
        """
        Updates the dynamic output folder to:
            <case_home>/dynamic_analysis

        This is used when the selected sample or case folder changes.
        """
        case_home = self._get_case_home_dir()
        self.dynamic_output_dir_var.set(str(case_home / "dynamic_analysis"))

    def _latest_existing(self, paths):
        existing = [p for p in paths if p.exists()]
        if not existing:
            return None
        return sorted(existing, key=lambda p: p.stat().st_mtime, reverse=True)[0]

    def _find_latest_dynamic_summary(self, case_home: Path, dynamic_output: Optional[Path] = None) -> tuple[Optional[Path], list[Path]]:
        """
        Finds the newest dynamic_run_summary.json using both the new layout and
        older compatibility paths.
        """
        dynamic_output = dynamic_output or (case_home / "dynamic_analysis")
        reports_dir = dynamic_output / "reports"

        candidates = []

        dynamic_run_roots = [
            dynamic_output / "dynamic_runs",
            case_home / "dynamic_analysis" / "dynamic_runs",
            case_home / "dynamic_runs",
        ]

        for root in dynamic_run_roots:
            if root.exists():
                candidates.extend(root.glob("*/metadata/dynamic_run_summary.json"))
                candidates.extend(root.glob("*/dynamic_run_summary.json"))

        candidates.extend(
            [
                dynamic_output / "metadata" / "dynamic_run_summary.json",
                dynamic_output / "reports" / "dynamic_run_summary.json",
                dynamic_output / "dynamic_run_summary.json",
                case_home / "metadata" / "dynamic_run_summary.json",
                case_home / "reports" / "dynamic_run_summary.json",
                case_home / "dynamic_run_summary.json",
                reports_dir / "dynamic_run_summary.json",
            ]
        )

        found = self._latest_existing(candidates)
        return found, candidates

    def _find_latest_dynamic_findings(self, case_home: Path, dynamic_output: Optional[Path] = None) -> tuple[Optional[Path], list[Path]]:
        dynamic_output = dynamic_output or (case_home / "dynamic_analysis")
        candidates = []

        dynamic_run_roots = [
            dynamic_output / "dynamic_runs",
            case_home / "dynamic_analysis" / "dynamic_runs",
            case_home / "dynamic_runs",
        ]

        for root in dynamic_run_roots:
            if root.exists():
                candidates.extend(root.glob("*/dynamic_findings.json"))
                candidates.extend(root.glob("*/metadata/dynamic_findings.json"))

        candidates.extend(
            [
                dynamic_output / "dynamic_findings.json",
                dynamic_output / "metadata" / "dynamic_findings.json",
                dynamic_output / "reports" / "dynamic_findings.json",
                case_home / "dynamic_findings.json",
                case_home / "metadata" / "dynamic_findings.json",
                case_home / "reports" / "dynamic_findings.json",
            ]
        )

        found = self._latest_existing(candidates)
        return found, candidates

    def _write_case_metadata(self, case_home: Path, dynamic_output: Path, sample: Path):
        metadata = {
            "case_name": case_home.name,
            "case_home": str(case_home),
            "dynamic_analysis_dir": str(dynamic_output),
            "static_analysis_dir": str(case_home / "static_analysis"),
            "sample_path": str(sample),
            "sample_name": sample.name,
            "layout_version": "ringforge-case-layout-1.0",
        }
        (case_home / "case_metadata.json").write_text(
            json.dumps(metadata, indent=2),
            encoding="utf-8",
        )

    # -------------------------------------------------------------------------
    # UI
    # -------------------------------------------------------------------------

    def _build_ui(self):
        compact = bool(getattr(self, "_compact_ui", False))
        outer = {"padx": 6 if compact else 10, "pady": 3 if compact else 6}

        self._build_top_banner(outer)

        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, **outer)
        frm.columnconfigure(0, weight=1)

        # Header should keep its requested height. The workspace/output area
        # gets the extra space instead.
        frm.rowconfigure(0, weight=0)
        frm.rowconfigure(1, weight=1)

        header = ttk.LabelFrame(frm, text="Dynamic Analysis Setup")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        ttk.Label(header, text="Sample:").grid(row=0, column=0, sticky="w", padx=(10, 0), pady=(10, 0))
        ttk.Entry(header, textvariable=self.sample_var, width=100).grid(
            row=0, column=1, sticky="ew", padx=8, pady=(10, 0)
        )

        sample_btns = ttk.Frame(header)
        sample_btns.grid(row=0, column=2, sticky="ew", padx=(0, 10), pady=(10, 0))
        sample_btns.columnconfigure(0, weight=1)
        sample_btns.columnconfigure(1, weight=1)

        ttk.Button(
            sample_btns,
            text="Use Main Sample",
            style="Side.Action.TButton",
            command=self._use_main_sample,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 6))

        ttk.Button(
            sample_btns,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_sample,
        ).grid(row=0, column=1, sticky="ew")

        ttk.Label(header, text="Timeout (seconds):").grid(row=1, column=0, sticky="w", padx=(10, 0), pady=(8, 10))

        runtime_row = ttk.Frame(header)
        runtime_row.grid(row=1, column=1, columnspan=2, sticky="w", padx=8, pady=(8, 10))

        ttk.Spinbox(
            runtime_row,
            from_=5,
            to=7200,
            textvariable=self.timeout_var,
            width=10,
            style="Dark.TSpinbox",
            command=self._refresh_summary_from_inputs,
        ).pack(side="left")

        ttk.Checkbutton(
            runtime_row,
            text="Enable Procmon Capture",
            variable=self.procmon_enabled_var,
            style="Dark.TCheckbutton",
            command=self._refresh_summary_from_inputs,
        ).pack(side="left", padx=(14, 0))

        workspace = ttk.Frame(frm)
        workspace.grid(row=1, column=0, sticky="nsew", pady=(6 if compact else 8, 0))
        workspace.columnconfigure(0, weight=4)
        workspace.columnconfigure(1, weight=2)

        # Top row contains settings/status. Bottom row contains output/actions.
        workspace.rowconfigure(0, weight=0)
        workspace.rowconfigure(1, weight=1)

        left_top = ttk.Frame(workspace)
        left_top.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left_top.columnconfigure(0, weight=1)

        right_top = ttk.Frame(workspace)
        right_top.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right_top.columnconfigure(0, weight=1)
        right_top.rowconfigure(0, weight=1)

        self._build_settings_section(left_top)
        self._build_run_status_section(right_top)

        left_bottom = ttk.Frame(workspace)
        left_bottom.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(6 if compact else 8, 0))
        left_bottom.columnconfigure(0, weight=1)
        left_bottom.rowconfigure(0, weight=1)

        right_bottom = ttk.Frame(workspace)
        right_bottom.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=(6 if compact else 8, 0))
        right_bottom.columnconfigure(0, weight=1)
        right_bottom.rowconfigure(0, weight=1)

        self._build_output_section(left_bottom)
        self._build_findings_summary_section(right_bottom)

    def _build_top_banner(self, outer):
        compact = bool(getattr(self, "_compact_ui", False))
        panel_bg = "#0B1220"
        border = "#294C8E"
        accent = "#2F6BFF"
        text_main = "#F7FAFF"
        text_soft = "#B8C7E6"

        logo_size = 52 if compact else 82
        title_font = 17 if compact else 22
        module_font = 13 if compact else 17
        logo_pad_y = 4 if compact else 10
        banner_title_pad = 6 if compact else 12
        banner_bottom_pad = 6 if compact else 12

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

        logo_path = self._project_root() / "assets" / "anvil.png"
        if logo_path.exists():
            logo_img = Image.open(logo_path).convert("RGBA")
            logo_img = logo_img.resize((logo_size, logo_size), Image.LANCZOS)
            self.brand_logo_img = ImageTk.PhotoImage(logo_img)

            tk.Label(
                banner,
                image=self.brand_logo_img,
                bg=panel_bg,
                bd=0,
                highlightthickness=0,
            ).grid(row=0, column=0, rowspan=3, sticky="w", padx=(14, 16), pady=logo_pad_y)
        else:
            tk.Label(
                banner,
                text="[anvil.png missing]",
                bg=panel_bg,
                fg=accent,
                font=("Segoe UI", 10, "bold"),
                bd=0,
                highlightthickness=0,
            ).grid(row=0, column=0, rowspan=3, sticky="w", padx=(14, 16), pady=logo_pad_y)

        tk.Label(
            banner,
            text="RingForge Workbench",
            bg=panel_bg,
            fg=text_main,
            font=("Segoe UI", title_font, "bold"),
            anchor="w",
        ).grid(row=0, column=1, sticky="sw", pady=(banner_title_pad, 0))

        tk.Label(
            banner,
            text="Dynamic Analysis",
            bg=panel_bg,
            fg=accent,
            font=("Segoe UI", module_font, "bold"),
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
        ).grid(row=2, column=1, sticky="w", pady=(3, banner_bottom_pad))

    def _build_settings_section(self, parent):
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        settings = ttk.LabelFrame(parent, text="Dynamic Settings")
        settings.grid(row=0, column=0, sticky="nsew")
        settings.columnconfigure(1, weight=1)
        settings.rowconfigure(3, weight=0)
        settings.rowconfigure(4, weight=0)

        ttk.Label(settings, text="Case output folder:").grid(
            row=0, column=0, sticky="w", padx=(10, 0), pady=(10, 0)
        )
        ttk.Entry(settings, textvariable=self.dynamic_output_dir_var, width=100).grid(
            row=0, column=1, sticky="ew", padx=8, pady=(10, 0)
        )
        ttk.Button(
            settings,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_dynamic_output_dir,
        ).grid(row=0, column=2, sticky="ew", padx=(0, 10), pady=(10, 0))

        ttk.Label(settings, text="Procmon path:").grid(
            row=1, column=0, sticky="w", padx=(10, 0), pady=(8, 0)
        )
        ttk.Entry(settings, textvariable=self.procmon_path_var, width=100).grid(
            row=1, column=1, sticky="ew", padx=8, pady=(8, 0)
        )
        ttk.Button(
            settings,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_procmon,
        ).grid(row=1, column=2, sticky="ew", padx=(0, 10), pady=(8, 0))

        ttk.Label(settings, text="Procmon config:").grid(
            row=2, column=0, sticky="w", padx=(10, 0), pady=(8, 0)
        )
        ttk.Entry(settings, textvariable=self.procmon_config_var, width=100).grid(
            row=2, column=1, sticky="ew", padx=8, pady=(8, 0)
        )
        ttk.Button(
            settings,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_procmon_config,
        ).grid(row=2, column=2, sticky="ew", padx=(0, 10), pady=(8, 0))

        notes = ttk.LabelFrame(settings, text="Analyst Notes")
        notes.grid(row=3, column=0, columnspan=3, sticky="ew", padx=10, pady=(8, 8))
        notes.columnconfigure(0, weight=1)

        compact = bool(getattr(self, "_compact_ui", False))
        if compact:
            note_text = (
                "• Snapshot VM before execution.  "
                "• Run elevated for best Procmon/Autoruns capture.  "
                "• Use isolated networking for unknown samples."
            )
        else:
            note_text = (
                "• Use a VM snapshot before execution.\n"
                "• Run elevated when Procmon capture requires it.\n"
                "• Prefer isolated networking for unknown samples.\n"
                "• Output is stored under the case home folder in dynamic_analysis."
            )
        ttk.Label(notes, text=note_text, justify="left", wraplength=980).grid(row=0, column=0, sticky="w", padx=8, pady=(4 if compact else 6))

        actions = ttk.Frame(settings)
        actions.grid(row=4, column=0, columnspan=3, sticky="ew", padx=10, pady=(0, 10))
        actions.columnconfigure(2, weight=1)

        self.run_btn = ttk.Button(
            actions,
            text="Run Dynamic Analysis",
            style="Action.TButton",
            width=20,
            command=self._start_dynamic_analysis,
        )
        self.run_btn.grid(row=0, column=0, sticky="w")

        self.cancel_btn = ttk.Button(
            actions,
            text="Cancel Analysis",
            style="Side.Action.TButton",
            command=self._cancel_dynamic_analysis,
            state="disabled",
        )
        self.cancel_btn.grid(row=0, column=1, sticky="w", padx=(10, 0))

        ttk.Label(
            actions,
            textvariable=self.status_var,
            anchor="e",
        ).grid(row=0, column=2, sticky="e", padx=(12, 0))

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
            ("Output:", self.summary_output_var),
            ("Procmon:", self.summary_procmon_var),
            ("Timeout:", self.summary_timeout_var),
            ("Latest Report:", self.summary_report_var),
        ]

        for idx, (label, var) in enumerate(rows):
            ttk.Label(summary, text=label).grid(row=idx, column=0, sticky="w", pady=(0 if idx == 0 else 6, 0))
            ttk.Label(summary, textvariable=var, wraplength=260 if getattr(self, "_compact_ui", False) else 340, justify="left").grid(
                row=idx, column=1, sticky="w", padx=(8, 0), pady=(0 if idx == 0 else 6, 0)
            )

        steps_panel = ttk.LabelFrame(panel, text="Execution Steps")
        steps_panel.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))
        steps_panel.columnconfigure(0, weight=1)
        steps_panel.rowconfigure(0, weight=1)

        self.steps_frame = ttk.Frame(steps_panel)
        self.steps_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.steps_frame.columnconfigure(1, weight=1)

    def _build_output_section(self, parent):
        outwrap = ttk.LabelFrame(parent, text="Output")
        outwrap.grid(row=0, column=0, sticky="nsew", pady=(2, 0))
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
        panel.rowconfigure(8, weight=1)

        metrics = [
            ("Score:", self.metric_score_var),
            ("Processes:", self.metric_process_var),
            ("Network Events:", self.metric_network_var),
            ("File Writes:", self.metric_filewrite_var),
            ("Suspicious Paths:", self.metric_suspicious_var),
            ("Persistence Hits:", self.metric_persistence_var),
        ]

        for idx, (label, var) in enumerate(metrics):
            ttk.Label(panel, text=label).grid(
                row=idx,
                column=0,
                sticky="w",
                padx=(10, 0),
                pady=(8 if idx == 0 else 5, 0),
            )
            ttk.Label(panel, textvariable=var).grid(
                row=idx,
                column=1,
                sticky="w",
                padx=(8, 10),
                pady=(8 if idx == 0 else 5, 0),
            )

        ttk.Separator(panel, orient="horizontal").grid(
            row=6,
            column=0,
            columnspan=2,
            sticky="ew",
            padx=10,
            pady=(10, 8),
        )

        report_actions = ttk.LabelFrame(panel, text="Report Actions")
        report_actions.grid(row=7, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))
        report_actions.columnconfigure(0, weight=1)

        ttk.Button(
            report_actions,
            text="Open Case Folder",
            style="Action.TButton",
            command=self._open_case_folder,
        ).grid(row=0, column=0, sticky="ew", padx=8, pady=(6 if getattr(self, "_compact_ui", False) else 10, 4), ipady=1)

        ttk.Button(
            report_actions,
            text="Open Dynamic Output Folder",
            style="Action.TButton",
            command=self._open_dynamic_output_folder,
        ).grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 4), ipady=1)

        ttk.Button(
            report_actions,
            text="Open Latest Report",
            style="Action.TButton",
            command=self._open_latest_dynamic_html,
        ).grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 6 if getattr(self, "_compact_ui", False) else 10), ipady=1)

    # -------------------------------------------------------------------------
    # Progress
    # -------------------------------------------------------------------------

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
            ttk.Label(self.steps_frame, text=f"{step}:").grid(row=idx, column=0, sticky="w", pady=1)
            bar_var = tk.IntVar(value=0)
            ttk.Progressbar(
                self.steps_frame,
                orient="horizontal",
                mode="determinate",
                maximum=100,
                variable=bar_var,
            ).grid(row=idx, column=1, sticky="ew", padx=8, pady=1)
            status = ttk.Label(self.steps_frame, text="idle")
            status.grid(row=idx, column=2, sticky="w", pady=1)
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

    # -------------------------------------------------------------------------
    # Input/config
    # -------------------------------------------------------------------------

    def _refresh_summary_from_inputs(self):
        sample_text = self.sample_var.get().strip()
        case_home = self._get_case_home_dir()
        dynamic_output = self._get_dynamic_output_dir()

        self.summary_sample_var.set(Path(sample_text).name if sample_text else "-")
        self.summary_case_var.set(case_home.name if str(case_home).strip() else "-")
        self.summary_output_var.set(str(dynamic_output))
        self.summary_procmon_var.set("Enabled" if self.procmon_enabled_var.get() else "Disabled")
        self.summary_timeout_var.set(f"{self.timeout_var.get()} sec")

    def _save_cfg(self):
        if not hasattr(self.app, "cfg") or not isinstance(self.app.cfg, dict):
            self.app.cfg = {}

        self.app.cfg["dynamic_case_dir"] = self.case_dir_var.get().strip()
        self.app.cfg["dynamic_output_dir"] = self.dynamic_output_dir_var.get().strip()
        self.app.cfg["dynamic_timeout_seconds"] = int(self.timeout_var.get())
        self.app.cfg["dynamic_procmon_enabled"] = bool(self.procmon_enabled_var.get())
        self.app.cfg["dynamic_procmon_path"] = self.procmon_path_var.get().strip()
        self.app.cfg["dynamic_procmon_config_path"] = self.procmon_config_var.get().strip()

        config_path = self._project_root() / "config.json"
        config_path.write_text(json.dumps(self.app.cfg, indent=2), encoding="utf-8")

    def _browse_sample(self):
        current = self.sample_var.get().strip()
        start_dir = Path(current).parent if current else Path.cwd()

        chosen = filedialog.askopenfilename(
            title="Select sample for dynamic analysis",
            initialdir=str(start_dir),
            filetypes=[
                ("Executable Files", "*.exe *.dll *.msi *.bat *.cmd *.ps1 *.vbs"),
                ("All Files", "*.*"),
            ],
        )
        if chosen:
            sample = Path(chosen)
            self.sample_var.set(str(sample))

            # If case folder is still generic/default, update it based on sample name.
            case_home = self._get_case_home_dir()
            if case_home.name in {"sample", "dynamic_case"}:
                new_case_home = self._project_root() / "cases" / self._safe_case_name(sample.stem)
                self.case_dir_var.set(str(new_case_home))

            self._sync_dynamic_output_to_case()
            self._refresh_summary_from_inputs()
            self._save_cfg()

    def _use_main_sample(self):
        main_sample = ""
        selected_ctx = None

        app_sample_var = getattr(self.app, "sample_var", None)
        if app_sample_var is not None:
            try:
                main_sample = app_sample_var.get().strip()
            except Exception:
                main_sample = ""

        launcher = getattr(self.app, "launcher_frame", None)
        if launcher is not None:
            if not main_sample:
                for attr_name in ("sample_var", "selected_sample_var", "main_sample_var"):
                    launcher_var = getattr(launcher, attr_name, None)
                    if launcher_var is not None:
                        try:
                            main_sample = launcher_var.get().strip()
                            if main_sample:
                                break
                        except Exception:
                            pass

            if hasattr(launcher, "get_selected_saved_test_context"):
                try:
                    selected_ctx = launcher.get_selected_saved_test_context()
                except Exception:
                    selected_ctx = None

            if not main_sample and selected_ctx:
                main_sample = (selected_ctx.get("sample_path") or "").strip()

        if not main_sample:
            messagebox.showwarning(
                "Use Main Sample",
                "No main sample is currently selected. Select a saved test in the launcher first, or use Browse to choose one manually.",
                parent=self,
            )
            return

        self.sample_var.set(main_sample)

        detected = selected_ctx.get("case_dir") if selected_ctx else None
        if not detected:
            detected = getattr(self.app, "case_dir_detected", None)

        if detected:
            case_home = Path(detected)

            # If the detected path is already inside dynamic_analysis, move back to the case home.
            if case_home.name == "dynamic_analysis":
                case_home = case_home.parent

            self.case_dir_var.set(str(case_home))
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

            case_name = self._safe_case_name(case_name or Path(main_sample).stem or "dynamic_case")
            case_root_path = Path(case_root) if case_root else (Path.cwd() / "cases")
            self.case_dir_var.set(str(case_root_path / case_name))

        self._sync_dynamic_output_to_case()
        self._refresh_summary_from_inputs()
        self._save_cfg()

    def _browse_dynamic_output_dir(self):
        case_home = self._get_case_home_dir()
        start = self._get_dynamic_output_dir()
        initial = start if start.exists() else case_home

        chosen = filedialog.askdirectory(
            title="Select Dynamic Analysis Output Folder",
            initialdir=str(initial),
            parent=self,
        )
        if chosen:
            self.dynamic_output_dir_var.set(str(Path(chosen)))
            self._refresh_summary_from_inputs()
            self._save_cfg()

    def _browse_procmon(self):
        start = Path(self.procmon_path_var.get()).parent if self.procmon_path_var.get().strip() else (
            self._project_root() / "tools"
        )
        chosen = filedialog.askopenfilename(
            title="Select Procmon executable",
            initialdir=str(start),
            filetypes=[("Executable", "*.exe"), ("All Files", "*.*")],
        )
        if chosen:
            self.procmon_path_var.set(str(Path(chosen)))
            self._save_cfg()

    def _browse_procmon_config(self):
        raw = self.procmon_config_var.get().strip()
        start = Path(raw).parent if raw else (self._project_root() / "tools" / "procmon-configs")
        chosen = filedialog.askopenfilename(
            title="Select Procmon config (.pmc)",
            initialdir=str(start),
            filetypes=[("Procmon Config", "*.pmc"), ("All Files", "*.*")],
        )
        if chosen:
            self.procmon_config_var.set(str(Path(chosen)))
            self._save_cfg()

    # -------------------------------------------------------------------------
    # Folder/report actions
    # -------------------------------------------------------------------------

    def _open_folder(self, folder: Path, title: str):
        if not folder.exists():
            messagebox.showwarning(title, f"Folder not found:\n{folder}", parent=self)
            return

        try:
            if os.name == "nt":
                os.startfile(str(folder))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(folder)])
            else:
                subprocess.Popen(["xdg-open", str(folder)])
        except Exception as e:
            messagebox.showerror(title, str(e), parent=self)

    def _open_case_folder(self):
        self._open_folder(self._get_case_home_dir(), "Open Case Folder")

    def _open_dynamic_output_folder(self):
        self._open_folder(self._get_dynamic_output_dir(), "Open Dynamic Output Folder")

    def _export_dynamic_report(self, open_after: bool = True) -> Optional[Path]:
        try:
            case_home = self._get_case_home_dir()
            dynamic_output = self._get_dynamic_output_dir()

            if not case_home.exists():
                messagebox.showerror("Export Report", f"Case folder does not exist:\n{case_home}", parent=self)
                return None

            reports_dir = dynamic_output / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)

            summary_path, summary_candidates = self._find_latest_dynamic_summary(case_home, dynamic_output)
            findings_path, findings_candidates = self._find_latest_dynamic_findings(case_home, dynamic_output)

            output_html = reports_dir / "dynamic_report.html"

            if summary_path:
                write_dynamic_html_report(summary_path, output_html)
            elif findings_path:
                data = json.loads(findings_path.read_text(encoding="utf-8", errors="replace"))
                self._write_fallback_dynamic_html(data, output_html, case_home)
            else:
                checked = [str(p) for p in summary_candidates + findings_candidates]
                messagebox.showerror(
                    "Export Report",
                    "No dynamic source file found.\n\nChecked:\n" + "\n".join(checked),
                    parent=self,
                )
                return None

            self.summary_report_var.set(str(output_html))
            if open_after:
                webbrowser.open(output_html.resolve().as_uri())

            return output_html
        except Exception as e:
            messagebox.showerror("Export Report", str(e), parent=self)
            return None

    def _write_fallback_dynamic_html(self, data: Dict, output_html: Path, case_home: Path):
        def esc(x):
            return html.escape(str(x if x is not None else ""))

        findings = data.get("findings", data) if isinstance(data, dict) else {}
        highlights = findings.get("highlights", []) or data.get("highlights", []) or []
        counts = findings.get("counts", {}) or data.get("counts", {}) or {}
        sample = data.get("sample", {}) or {}

        html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Dynamic Report</title>
<style>
body {{ font-family: Segoe UI, Arial, sans-serif; background: #0b1220; color: #e5eefc; margin: 0; padding: 24px; }}
.card {{ background: #101a2f; border: 1px solid #223455; border-radius: 14px; padding: 18px; margin-bottom: 16px; }}
h1, h2 {{ margin-top: 0; color: #9cc4ff; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ border-bottom: 1px solid #223455; text-align: left; padding: 8px; vertical-align: top; }}
ul {{ margin-top: 8px; }}
.muted {{ color: #9fb3d9; }}
</style></head><body>
<div class="card">
<h1>Dynamic Analysis Report</h1>
<p class="muted">Case: {esc(case_home.name)}</p>
<p><b>Sample:</b> {esc(sample.get("sample_name", ""))}</p>
<p><b>Path:</b> {esc(sample.get("sample_path", ""))}</p>
<p><b>SHA256:</b> {esc(sample.get("sha256", ""))}</p>
</div>
<div class="card">
<h2>Highlights</h2>
{"<ul>" + "".join(f"<li>{esc(x)}</li>" for x in highlights) + "</ul>" if highlights else "<p class='muted'>None</p>"}
</div>
<div class="card">
<h2>Findings Counts</h2>
<table>
<tr><th>Interesting Events</th><td>{esc(counts.get("interesting_events", 0))}</td></tr>
<tr><th>Process Creates</th><td>{esc(counts.get("process_creates", 0))}</td></tr>
<tr><th>Network Events</th><td>{esc(counts.get("network_events", 0))}</td></tr>
<tr><th>File Write Events</th><td>{esc(counts.get("file_write_events", 0))}</td></tr>
<tr><th>Suspicious Path Hits</th><td>{esc(counts.get("suspicious_path_hits", 0))}</td></tr>
<tr><th>Persistence Hits</th><td>{esc(counts.get("persistence_hits", 0))}</td></tr>
</table>
</div>
</body></html>"""

        output_html.write_text(html_doc, encoding="utf-8", errors="replace")

    def _open_latest_dynamic_html(self):
        try:
            case_home = self._get_case_home_dir()
            dynamic_output = self._get_dynamic_output_dir()

            if not case_home.exists():
                messagebox.showerror("Open Report", f"Case folder does not exist:\n{case_home}", parent=self)
                return

            html_path = self._export_dynamic_report(open_after=False)
            if not html_path:
                return

            if not html_path.exists():
                messagebox.showerror("Open Report", f"HTML report not found:\n{html_path}", parent=self)
                return

            self.summary_report_var.set(str(html_path))
            webbrowser.open(html_path.resolve().as_uri())
        except Exception as e:
            messagebox.showerror("Open Report", str(e), parent=self)


    # -------------------------------------------------------------------------
    # Dynamic preflight checks
    # -------------------------------------------------------------------------

    def _is_running_as_admin(self) -> bool:
        """
        Return True when RingForge is running with Administrator privileges.

        Procmon, service snapshots, scheduled task snapshots, and Autoruns
        collection are more reliable when the GUI is elevated.
        """
        if os.name != "nt":
            return False

        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _find_autorunsc_path(self) -> Optional[Path]:
        """
        Locate Autorunsc in the local tools folder.

        Autorunsc is optional for Dynamic Analysis, so this is a warning-only
        preflight item. The orchestrator can still run without Autoruns support.
        """
        tools_dir = self._project_root() / "tools"
        candidates = [
            tools_dir / "autorunsc64.exe",
            tools_dir / "Autorunsc64.exe",
            tools_dir / "autorunsc.exe",
            tools_dir / "Autorunsc.exe",
        ]

        for candidate in candidates:
            if candidate.exists():
                return candidate

        return None

    def _check_case_folder_writable(self, folder: Path) -> tuple[bool, str]:
        """
        Confirm that the selected case/output folder can be created and written.
        """
        try:
            folder.mkdir(parents=True, exist_ok=True)
            test_file = folder / ".ringforge_write_test"
            test_file.write_text("ringforge write test", encoding="utf-8")
            test_file.unlink(missing_ok=True)
            return True, ""
        except Exception as error:
            return False, str(error)

    def _run_dynamic_preflight_checks(
        self,
        sample: Path,
        case_home: Path,
        dynamic_output: Path,
        procmon_path: Path,
        procmon_config: str,
    ) -> bool:
        """
        Professional preflight validation before starting Dynamic Analysis.

        Blocking issues stop the run. Warnings allow the analyst to continue.
        """
        issues: list[str] = []
        warnings: list[str] = []

        if not sample.exists():
            issues.append(f"Sample file not found:\n{sample}")

        if sample.exists() and not sample.is_file():
            issues.append(f"Selected sample path is not a file:\n{sample}")

        case_ok, case_error = self._check_case_folder_writable(case_home)
        if not case_ok:
            issues.append(f"Case folder is not writable:\n{case_home}\n\n{case_error}")

        dynamic_ok, dynamic_error = self._check_case_folder_writable(dynamic_output)
        if not dynamic_ok:
            issues.append(f"Dynamic output folder is not writable:\n{dynamic_output}\n\n{dynamic_error}")

        if self.procmon_enabled_var.get():
            if not procmon_path.exists():
                issues.append(f"Procmon is enabled but the executable was not found:\n{procmon_path}")
            elif not procmon_path.is_file():
                issues.append(f"Procmon path is not a file:\n{procmon_path}")

        if procmon_config:
            procmon_config_path = Path(procmon_config)
            if not procmon_config_path.exists():
                warnings.append(
                    "Procmon config file was not found. RingForge will continue, "
                    "but Procmon may run with default capture behavior:\n"
                    f"{procmon_config_path}"
                )

        autorunsc_path = self._find_autorunsc_path()
        if autorunsc_path is None:
            warnings.append(
                "Autorunsc was not found in the local tools folder. "
                "Autoruns persistence diffing may be skipped.\n\n"
                "Expected one of:\n"
                f"{self._project_root() / 'tools' / 'autorunsc64.exe'}\n"
                f"{self._project_root() / 'tools' / 'autorunsc.exe'}"
            )

        if os.name == "nt" and not self._is_running_as_admin():
            warnings.append(
                "RingForge is not running as Administrator. Procmon capture, "
                "service snapshots, scheduled task snapshots, and Autoruns collection "
                "may be incomplete."
            )

        if issues:
            messagebox.showerror(
                "Dynamic Preflight Failed",
                "Dynamic Analysis cannot start until these issues are fixed:\n\n"
                + "\n\n".join(issues),
                parent=self,
            )
            self._set_step("Pre-checks", 100, "failed")
            return False

        if warnings:
            proceed = messagebox.askyesno(
                "Dynamic Preflight Warnings",
                "Dynamic Analysis can start, but these warnings were found:\n\n"
                + "\n\n".join(warnings)
                + "\n\nContinue anyway?",
                parent=self,
            )
            if not proceed:
                self._set_step("Pre-checks", 100, "cancelled")
                return False

        return True

    def _cancel_dynamic_analysis(self):
        if not self.worker_thread or not self.worker_thread.is_alive():
            return

        self.cancel_event.set()
        self.status_var.set("Cancelling...")
        self.summary_status_var.set("Cancelling")

        if self.cancel_btn is not None:
            self.cancel_btn.configure(state="disabled")

        self.output_q.put(
            "\n[cancel] Cancellation requested by analyst. Waiting for cleanup...\n"
        )
    # -------------------------------------------------------------------------
    # Run dynamic analysis
    # -------------------------------------------------------------------------

    def _start_dynamic_analysis(self):
        if self.worker_thread and self.worker_thread.is_alive():
            return

        sample = Path(self.sample_var.get().strip())
        case_home, dynamic_output = self._ensure_case_layout()
        procmon_path = Path(self.procmon_path_var.get().strip())
        timeout_seconds = int(self.timeout_var.get())
        procmon_config = self.procmon_config_var.get().strip()

        self._reset_progress()
        self._set_step("Pre-checks", 50, "checking")

        if not self._run_dynamic_preflight_checks(
            sample=sample,
            case_home=case_home,
            dynamic_output=dynamic_output,
            procmon_path=procmon_path,
            procmon_config=procmon_config,
        ):
            return

        self._write_case_metadata(case_home, dynamic_output, sample)

        # Important:
        # The orchestrator receives dynamic_output as its case_dir.
        # That means dynamic_runs will now be created under:
        # cases\<case>\dynamic_analysis\dynamic_runs\
        config = {
            "sample_path": str(sample),
            "case_dir": str(dynamic_output),
            "case_home_dir": str(case_home),
            "timeout_seconds": timeout_seconds,
            "minimum_observation_seconds": 30,
            "post_exit_observation_seconds": 120,
            "installer_observation_mode": True,
            "procmon_enabled": bool(self.procmon_enabled_var.get()),
            "procmon_path": str(procmon_path),
            "procmon_config_path": procmon_config,
        }

        self._save_cfg()
        self._refresh_summary_from_inputs()
        self.summary_status_var.set("Running")
        self.cancel_event.clear()
        self.status_var.set("Running dynamic...")
        self.run_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.update_idletasks()

        self._set_step("Pre-checks", 100, "done")
        self._set_step("Procmon start", 25, "running")

        self.output.delete("1.0", "end")
        self.output.insert("end", "Starting dynamic analysis:\n")
        self.output.insert("end", f"  sample={sample}\n")
        self.output.insert("end", f"  case_home={case_home}\n")
        self.output.insert("end", f"  dynamic_output={dynamic_output}\n")
        self.output.insert("end", f"  timeout_seconds={timeout_seconds}\n")
        self.output.insert("end", f"  procmon_enabled={config['procmon_enabled']}\n")
        self.output.insert("end", f"  procmon_path={procmon_path}\n")
        self.output.insert("end", f"  procmon_config={procmon_config or '-'}\n")
        self.output.insert("end", f"  autorunsc_path={self._find_autorunsc_path() or 'not found'}\n")
        self.output.insert("end", f"  admin={self._is_running_as_admin()}\n\n")
        self.output.see("end")

        def worker():
            try:
                summary = run_dynamic_analysis(
                    config,
                    status_cb=lambda msg: self.output_q.put(f"[status] {msg}\n"),
                    cancel_event=self.cancel_event,
                )

                findings = summary.get("findings", {}) if isinstance(summary, dict) else {}
                highlights = findings.get("highlights", []) if isinstance(findings, dict) else []

                if highlights:
                    self.output_q.put("Highlights:\n")
                    for item in highlights:
                        self.output_q.put(f"  - {item}\n")
                    self.output_q.put("\n")

                task_counts = summary.get("task_diff_summary", {}) if isinstance(summary, dict) else {}
                if task_counts:
                    self.output_q.put("Scheduled task diff:\n")
                    self.output_q.put(f"  - New tasks: {task_counts.get('new_tasks', 0)}\n")
                    self.output_q.put(f"  - Modified tasks: {task_counts.get('modified_tasks', 0)}\n")
                    self.output_q.put(f"  - Removed tasks: {task_counts.get('removed_tasks', 0)}\n")
                    self.output_q.put(
                        f"  - Suspicious new/modified: {task_counts.get('suspicious_new_or_modified', 0)}\n\n"
                    )

                service_counts = summary.get("service_diff_summary", {}) if isinstance(summary, dict) else {}
                if service_counts:
                    self.output_q.put("Service diff:\n")
                    self.output_q.put(f"  - New services: {service_counts.get('new_services', 0)}\n")
                    self.output_q.put(f"  - Modified services: {service_counts.get('modified_services', 0)}\n")
                    self.output_q.put(f"  - Removed services: {service_counts.get('removed_services', 0)}\n")
                    self.output_q.put(
                        f"  - Suspicious new/modified: {service_counts.get('suspicious_new_or_modified', 0)}\n\n"
                    )

                top_written = findings.get("top_written_paths", []) if isinstance(findings, dict) else []
                if top_written:
                    self.output_q.put("Top written paths:\n")
                    for row in top_written[:5]:
                        self.output_q.put(f"  - {row.get('count', 0)}x  {row.get('path', '')}\n")
                    self.output_q.put("\n")

                top_net = findings.get("top_network_processes", []) if isinstance(findings, dict) else []
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

        score = summary.get("score", summary.get("dynamic_score", 0)) if isinstance(summary, dict) else 0
        self.metric_score_var.set(str(score))
        self.metric_process_var.set(str(counts.get("process_creates", 0)))
        self.metric_network_var.set(str(counts.get("network_events", 0)))
        self.metric_filewrite_var.set(str(counts.get("file_write_events", 0)))
        self.metric_suspicious_var.set(str(counts.get("suspicious_path_hits", 0)))
        self.metric_persistence_var.set(str(counts.get("persistence_hits", 0)))

        self.run_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")
        self.status_var.set("Idle")
        if isinstance(summary, dict) and summary.get("cancelled"):
            self.summary_status_var.set("Cancelled")
        else:
            self.summary_status_var.set("Completed")

        def finalize_refresh():
            case_home = self._get_case_home_dir()
            dynamic_output = self._get_dynamic_output_dir()

            if case_home and case_home.exists():
                self.app.case_dir_detected = case_home

                html_path = self._export_dynamic_report(open_after=False)
                self.summary_report_var.set(str(html_path) if html_path and html_path.exists() else "-")

                try:
                    combined_score_from_case_dir(
                        case_home,
                        dynamic_result=summary,
                        spec_result=None,
                        write_output=True,
                    )
                except Exception as e:
                    self.output_q.put(f"\n[warning] Combined score refresh failed: {e}\n")

                if hasattr(self.app, "refresh_combined_score"):
                    self.app.refresh_combined_score(case_home)
            else:
                if hasattr(self.app, "refresh_combined_score"):
                    self.app.refresh_combined_score()

            exit_code = summary.get("exit_code") if isinstance(summary, dict) else None

            if isinstance(summary, dict) and summary.get("cancelled"):
                messagebox.showwarning(
                    "Cancelled",
                    summary.get("cancellation_reason", "Dynamic analysis cancelled by analyst."),
                    parent=self,
                )
            elif exit_code == 0:
                messagebox.showinfo(
                    "Completed",
                    "Dynamic analysis completed successfully.",
                    parent=self,
                )
            else:
                messagebox.showwarning(
                    "Completed",
                    f"Dynamic analysis completed. Sample exited with code {exit_code}.",
                    parent=self,
                )

        self.after(300, finalize_refresh)

    def _on_error(self, err: str):
        self.run_btn.configure(state="normal")
        if self.cancel_btn is not None:
            self.cancel_btn.configure(state="disabled")
        self.status_var.set("Idle")
        self.summary_status_var.set("Error")
        self._set_step("Procmon start", 100, "failed")
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