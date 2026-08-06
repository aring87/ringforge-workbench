import html
import json
import os
import re
import shutil
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
from dynamic_analysis.memory_dump import (
    DEFAULT_MAX_PROCESSES,
    DEFAULT_SPAWN_REDUMP_SECONDS,
)
from dynamic_analysis.orchestrator import ContainmentError, run_dynamic_analysis
from static_triage_engine.scoring import combined_score_from_case_dir
from gui import theme as T
from gui.components import Checkbox, HeaderBar


def isolation_signature(status: dict) -> tuple:
    """The parts of a containment probe that change what the window shows.

    The watch polls every few seconds and must only redraw when something an
    analyst would act on has changed -- re-packing the armed banner on every
    tick flickers and steals focus. Everything the strip and the banner read is
    in here, so two statuses with the same signature render identically.

    ``egress`` is included by adapter and gateway rather than wholesale, because
    the banner names the paths and a second adapter appearing must not be
    mistaken for the same state.
    """
    if not isinstance(status, dict):
        return ("unknown",)

    return (
        status.get("level"),
        bool(status.get("isolated")),
        status.get("egress_count"),
        status.get("note", ""),
        tuple(
            (e.get("adapter"), e.get("gateway"), e.get("reaches"))
            for e in (status.get("egress", []) or [])
            if isinstance(e, dict)
        ),
    )


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
        self.configure(bg=T.BG)
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

        # The case folder follows the selected sample until the analyst chooses
        # one explicitly. Without this, a case folder left over from the previous
        # run silently collects the next sample's results, which is what the
        # mismatch warning exists to catch -- better to get it right than to warn
        # about it.
        self._case_dir_manual = bool(cfg.get("dynamic_case_dir_manual", False))

        self.timeout_var = tk.IntVar(value=int(cfg.get("dynamic_timeout_seconds", 30)))
        self.procmon_enabled_var = tk.BooleanVar(value=bool(cfg.get("dynamic_procmon_enabled", True)))
        
        self.minimum_observation_var = tk.IntVar(
            value=int(cfg.get("dynamic_minimum_observation_seconds", 30))
        )
        self.post_exit_observation_var = tk.IntVar(
            value=int(cfg.get("dynamic_post_exit_observation_seconds", 120))
        )
        self.installer_observation_mode_var = tk.BooleanVar(
            value=bool(cfg.get("dynamic_installer_observation_mode", True))
        )
        # The timeout above is a guess about how long a sample stays dormant,
        # and dormancy varies run to run for the same binary. These let the
        # window follow the sample instead: keep waiting while it is still
        # running and has not been seen to do anything.
        self.adaptive_observation_var = tk.BooleanVar(
            value=bool(cfg.get("dynamic_adaptive_observation", True))
        )
        self.max_observation_var = tk.IntVar(
            value=int(cfg.get("dynamic_max_observation_seconds", 600))
        )
        # Seconds after launch at which the whole tree is dumped. Blank uses the
        # profile default. No set of offsets suits every family: Formbook
        # spawned its hollowing target at +20s and exited, so the standard
        # [5, 25] captured the sample once at +5s -- before it had unpacked --
        # and never again.
        self.dump_offsets_var = tk.StringVar(
            value=str(cfg.get("dynamic_memory_dump_offsets", ""))
        )
        # The chain, not the tool, decides how many processes are worth
        # dumping. A six-process loader chain hit the old cap of 5 exactly on
        # the process most likely to hold the payload.
        self.dump_max_processes_var = tk.IntVar(
            value=int(
                cfg.get("dynamic_memory_dump_max_processes", DEFAULT_MAX_PROCESSES)
            )
        )
        # A child is dumped the moment it appears, which for a hollowing loader
        # is before anything has been written into it -- the target is created
        # suspended, then unmapped and written. This is how long to wait before
        # taking the second image that has the payload in it. 0 turns it off.
        self.dump_redump_var = tk.IntVar(
            value=int(
                cfg.get(
                    "dynamic_memory_dump_spawn_redump_seconds",
                    DEFAULT_SPAWN_REDUMP_SECONDS,
                )
            )
        )

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

        # --- Tier 1 telemetry -------------------------------------------------
        # Sysmon and packet capture are on by default because they degrade
        # cleanly when the tools are absent. Simulated internet is off by
        # default: it installs a traffic diverter, so it stays opt-in.
        self.sysmon_enabled_var = tk.BooleanVar(
            value=bool(cfg.get("dynamic_sysmon_enabled", True))
        )
        self.pcap_enabled_var = tk.BooleanVar(
            value=bool(cfg.get("dynamic_pcap_enabled", True))
        )
        self.fakenet_enabled_var = tk.BooleanVar(
            value=bool(cfg.get("dynamic_fakenet_enabled", False))
        )
        self.memory_dump_enabled_var = tk.BooleanVar(
            value=bool(cfg.get("dynamic_memory_dump_enabled", True))
        )
        self.memory_yara_enabled_var = tk.BooleanVar(
            value=bool(cfg.get("dynamic_memory_yara_enabled", True))
        )
        self.fakenet_path_var = tk.StringVar(
            value=cfg.get("dynamic_fakenet_path", str(project_root / "tools" / "fakenet" / "fakenet.exe"))
        )
        self.summary_telemetry_var = tk.StringVar(value="-")

        self.status_var = tk.StringVar(value="Idle")
        self.summary_status_var = tk.StringVar(value="Ready")
        self.summary_sample_var = tk.StringVar(value=Path(main_sample).name if main_sample else "-")
        self.summary_case_var = tk.StringVar(value=Path(self.case_dir_var.get()).name)
        self.summary_output_var = tk.StringVar(
            value=self._short_display_path(self.dynamic_output_dir_var.get(), keep_parts=2)
        )
        self.summary_procmon_var = tk.StringVar(value="Enabled" if self.procmon_enabled_var.get() else "Disabled")
        self.summary_timeout_var = tk.StringVar(value=f"{self.timeout_var.get()} sec")
        self.summary_report_var = tk.StringVar(value="-")
        self.summary_observation_var = tk.StringVar(
            value=(
                f"Min {self.minimum_observation_var.get()} sec | "
                f"Post-exit {self.post_exit_observation_var.get()} sec | "
                f"{'Installer mode' if self.installer_observation_mode_var.get() else 'Standard mode'} | "
                + (
                    f"Extend to {self.max_observation_var.get()} sec"
                    if self.adaptive_observation_var.get()
                    else "Fixed window"
                )
            )
        )

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

        self._isolation_poll_job = None
        self._isolation_probe_active = False
        self._isolation_signature = None

        self._build_ui()
        self._reset_progress()
        self._refresh_summary_from_inputs()
        self._enable_case_auto_follow()
        self.after(150, self._drain_output)
        self._start_isolation_watch()

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

    #: Longest sample-derived case name. See the orchestrator's matching cap.
    #:
    #: The case name appears twice in every artifact path -- once as the case
    #: folder and again inside the run directory name -- so a sample named as
    #: its full SHA-256 costs roughly 155 characters before anything else.
    #: MalwareBazaar names every sample that way, and the first live one failed
    #: with "The filename or extension is too long".
    _MAX_CASE_NAME = 24

    @staticmethod
    def _safe_case_name(value: str) -> str:
        value = (value or "dynamic_case").strip()
        value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
        value = value.strip("._-")
        if len(value) > DynamicAnalysisWindow._MAX_CASE_NAME:
            value = value[:DynamicAnalysisWindow._MAX_CASE_NAME].rstrip("._-")
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

        # If the dynamic output folder points to a case's dynamic_analysis folder,
        # infer the case home from that output path. This prevents mismatches like:
        #   case_home = cases/notepad
        #   dynamic_output = cases/wireshark/dynamic_analysis
        if dynamic_output.name.lower() == "dynamic_analysis":
            inferred_case_home = dynamic_output.parent
            if inferred_case_home.name:
                case_home = inferred_case_home

        # Keep dynamic output aligned under the resolved case home.
        expected_dynamic_output = case_home / "dynamic_analysis"
        if dynamic_output != expected_dynamic_output:
            dynamic_output = expected_dynamic_output

        case_home.mkdir(parents=True, exist_ok=True)

        # Create module folders.
        (case_home / "static_analysis").mkdir(parents=True, exist_ok=True)
        dynamic_output.mkdir(parents=True, exist_ok=True)
        (dynamic_output / "reports").mkdir(parents=True, exist_ok=True)
        (dynamic_output / "metadata").mkdir(parents=True, exist_ok=True)

        self.case_dir_var.set(str(case_home))
        self.dynamic_output_dir_var.set(str(dynamic_output))

        return case_home, dynamic_output

    def _enable_case_auto_follow(self) -> None:
        """Keep the case folder pointed at the selected sample.

        Registered after the UI exists, so the trace never fires against
        half-built widgets. It watches the variable rather than hooking the
        Browse button because a path is just as often typed or pasted in, and
        that is exactly the route that used to leave the previous run's case
        folder selected.
        """
        try:
            self.sample_var.trace_add("write", self._on_sample_changed)
        except Exception:
            # Tk 8.5 and earlier. Auto-follow is a convenience, so losing it is
            # not worth failing the window over.
            pass

        # Reconcile the restored settings once. The trace only fires on change,
        # so a saved sample paired with the previous run's case folder would
        # otherwise stay mismatched until the sample was edited again.
        self._sync_case_dir_to_sample()

    def _on_sample_changed(self, *_args) -> None:
        self._sync_case_dir_to_sample()

    def _sync_case_dir_to_sample(self, force: bool = False) -> None:
        """Point the case folder at cases/<sample name>.

        Does nothing once the analyst has picked a folder by hand: an explicit
        choice outranks the convention, including the case where several samples
        genuinely belong to one case.
        """
        if self._case_dir_manual and not force:
            return

        sample = self.sample_var.get().strip()
        if not sample:
            return

        case_name = self._safe_case_name(Path(sample).stem)
        new_case_home = self._project_root() / "cases" / case_name

        if str(new_case_home) == self.case_dir_var.get().strip():
            return

        self.case_dir_var.set(str(new_case_home))
        self._sync_dynamic_output_to_case()

        try:
            self._refresh_summary_from_inputs()
        except Exception:
            pass

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

        # Containment banner. Hidden unless the guest is armed, and impossible
        # to miss when it is not: a run was detonated with a live network path
        # and the only sign was a muted grey line further down the header,
        # which had also gone stale.
        #
        # A tk.Label rather than ttk, because a solid fill across the full
        # width is the point and ttk styling makes that fight the theme.
        self.armed_banner = tk.Label(
            self,
            text="",
            bg="#7f1d1d",
            fg="#ffffff",
            font=("Segoe UI", 11, "bold"),
            anchor="w",
            padx=12,
            pady=7,
        )

        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, **outer)
        frm.columnconfigure(0, weight=1)
        # Kept so the banner can be packed above it on demand: re-packing a
        # forgotten widget appends it to the end otherwise, and a warning
        # underneath the output pane is a warning nobody reads.
        self._main_frame = frm

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
        
        ttk.Label(header, text="Observation:").grid(
            row=2,
            column=0,
            sticky="w",
            padx=(10, 0),
            pady=(0, 10),
        )

        observation_row = ttk.Frame(header)
        observation_row.grid(
            row=2,
            column=1,
            columnspan=2,
            sticky="w",
            padx=8,
            pady=(0, 10),
        )

        ttk.Label(observation_row, text="Min:").pack(side="left")

        ttk.Spinbox(
            observation_row,
            from_=0,
            to=7200,
            textvariable=self.minimum_observation_var,
            width=8,
            style="Dark.TSpinbox",
            command=self._refresh_summary_from_inputs,
        ).pack(side="left", padx=(6, 14))

        ttk.Label(observation_row, text="Post-exit:").pack(side="left")

        ttk.Spinbox(
            observation_row,
            from_=0,
            to=7200,
            textvariable=self.post_exit_observation_var,
            width=8,
            style="Dark.TSpinbox",
            command=self._refresh_summary_from_inputs,
        ).pack(side="left", padx=(6, 14))

        Checkbox(
            observation_row,
            "Installer mode",
            self.installer_observation_mode_var,
            command=self._refresh_summary_from_inputs,
            parent_bg=T.BG,
        ).pack(side="left", padx=(0, 14))

        Checkbox(
            observation_row,
            "Extend if dormant",
            self.adaptive_observation_var,
            command=self._refresh_summary_from_inputs,
            parent_bg=T.BG,
        ).pack(side="left")

        ttk.Label(observation_row, text="up to:").pack(side="left", padx=(6, 0))

        ttk.Spinbox(
            observation_row,
            from_=0,
            to=7200,
            textvariable=self.max_observation_var,
            width=8,
            style="Dark.TSpinbox",
            command=self._refresh_summary_from_inputs,
        ).pack(side="left", padx=(6, 0))

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

        Checkbox(
            runtime_row,
            "Enable Procmon Capture",
            self.procmon_enabled_var,
            command=self._refresh_summary_from_inputs,
            parent_bg=T.BG,
        ).pack(side="left", padx=(14, 0))

        self._build_telemetry_row(header)
        self._build_memory_row(header)

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

    def _build_top_banner(self, outer) -> None:
        """Branded page header, shared with every other workbench window."""
        logo_path = Path(__file__).resolve().parents[1] / "assets" / "anvil.png"

        header = HeaderBar(
            self,
            "RingForge",
            subtitle="Dynamic Analysis",
            description=(
                "Runtime behavior capture, persistence tracking, dropped-file "
                "review, and post-execution triage."
            ),
            logo_path=logo_path if logo_path.exists() else None,
            logo_size=52 if getattr(self, '_compact_ui', False) else 72,
            parent_bg=T.BG,
        )
        header.pack(fill="x", **outer)
        self._banner_logo_img = getattr(header, "_logo_image", None)
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
            ("Observation:", self.summary_observation_var),
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
            bg=T.SUNKEN,
            fg=T.TEXT,
            insertbackground=T.TEXT,
            selectbackground=T.ACCENT_SOFT,
            selectforeground="white",
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=T.BORDER_STRONG,
            highlightcolor=T.ACCENT,
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
            style="Secondary.TButton",
            command=self._open_case_folder,
        ).grid(row=0, column=0, sticky="ew", padx=8, pady=(6 if getattr(self, "_compact_ui", False) else 10, 4), ipady=1)

        ttk.Button(
            report_actions,
            text="Open Dynamic Output Folder",
            style="Secondary.TButton",
            command=self._open_dynamic_output_folder,
        ).grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 4), ipady=1)

        ttk.Button(
            report_actions,
            text="Open Latest Report",
            style="Secondary.TButton",
            command=self._open_latest_dynamic_html,
        ).grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 6 if getattr(self, "_compact_ui", False) else 10), ipady=1)

    # -------------------------------------------------------------------------
    # Progress
    # -------------------------------------------------------------------------

    def _apply_telemetry_steps(self, summary: Dict):
        """Reflect what telemetry actually ran, rather than assuming success.

        A tool that was switched off, or that is not installed, reports "n/a"
        instead of "done" so the pipeline never overstates coverage.
        """
        requested = any(
            (
                summary.get("sysmon_enabled"),
                summary.get("pcap_enabled"),
                summary.get("fakenet_enabled"),
                summary.get("memory_dump_enabled"),
            )
        )
        if not requested:
            self._set_step("Telemetry start", 100, "n/a")
            self._set_step("Telemetry collect", 100, "n/a")
            return

        started = any(
            (
                summary.get("sysmon_enabled") and summary.get("sysmon_preflight", {}).get("available"),
                summary.get("pcap_enabled") and summary.get("pcap_capture", {}).get("pcap_exists"),
                summary.get("fakenet_enabled") and summary.get("fakenet_summary", {}).get("parsed"),
                summary.get("memory_dump_enabled") and summary.get("memory_dump_start", {}).get("started"),
            )
        )
        self._set_step("Telemetry start", 100, "done" if started else "missing tool")

        collected = any(
            (
                summary.get("sysmon_collection", {}).get("success"),
                summary.get("network_summary", {}).get("parsed"),
                summary.get("fakenet_summary", {}).get("parsed"),
                summary.get("memory_summary", {}).get("collected"),
                summary.get("memory_yara_summary", {}).get("scanned"),
            )
        )
        self._set_step("Telemetry collect", 100, "done" if collected else "n/a")

        self._log_telemetry_outcome(summary)

    def _log_telemetry_outcome(self, summary: Dict):
        """Write a short telemetry recap into the output pane."""
        lines = []

        sysmon = summary.get("sysmon_summary") or {}
        if sysmon.get("total_events"):
            lines.append(
                f"  Sysmon: {sysmon.get('total_events', 0)} events, "
                f"{sysmon.get('high_severity_count', 0)} high-severity, "
                f"{len(sysmon.get('injection_events', []))} injection"
            )
            for highlight in (sysmon.get("highlights") or [])[:5]:
                lines.append(f"    [{highlight['severity']}] {highlight['title']}: {highlight['detail']}")

        network = summary.get("network_summary") or {}
        if network.get("parsed"):
            counts = network.get("counts", {})
            lines.append(
                f"  Network: {counts.get('dns_queries', 0)} DNS, "
                f"{counts.get('tls_sni', 0)} SNI, {counts.get('http_requests', 0)} HTTP, "
                f"{counts.get('unusual_ports', 0)} unusual ports"
            )

        iocs = summary.get("network_iocs") or {}
        for label, key in (("domains", "domains"), ("IPs", "ips")):
            values = iocs.get(key) or []
            if values:
                lines.append(f"    {label}: {', '.join(values[:8])}")

        fakenet = summary.get("fakenet_summary") or {}
        if fakenet.get("parsed"):
            counts = fakenet.get("counts", {})
            lines.append(
                f"  Simulated internet: {counts.get('dns_requests', 0)} DNS, "
                f"{counts.get('http_requests', 0)} HTTP served"
            )

        memory = summary.get("memory_summary") or {}
        memory_counts = memory.get("counts", {})
        if memory_counts.get("processes_observed"):
            lines.append(
                f"  Memory: {memory_counts.get('dumps_succeeded', 0)} dump(s) from "
                f"{memory_counts.get('processes_observed', 0)} process(es), "
                f"{memory_counts.get('total_mb', 0)} MB"
            )
            for dump in (memory.get("dumps") or [])[:5]:
                lines.append(
                    f"    pid {dump.get('pid')} {dump.get('name', '?')} "
                    f"+{dump.get('offset_seconds')}s -> {dump.get('size_mb', 0)} MB"
                )
            for failure in (memory.get("failures") or [])[:3]:
                lines.append(
                    f"    [failed] pid {failure.get('pid')}: {failure.get('error', '')[:120]}"
                )

        memory_yara = summary.get("memory_yara_summary") or {}
        if memory_yara.get("scanned"):
            yara_counts = memory_yara.get("counts", {})
            lines.append(
                f"  Memory YARA: {yara_counts.get('total_matches', 0)} match(es) across "
                f"{yara_counts.get('dumps_scanned', 0)} dump(s), "
                f"{yara_counts.get('memory_only_rules', 0)} memory-only rule(s)"
            )
            # Led with because it is the finding the dumps exist to produce.
            for rule in (memory_yara.get("memory_only_rules") or [])[:8]:
                lines.append(f"    [memory-only] {rule}")
        elif memory_yara.get("error"):
            lines.append(f"  Memory YARA: not scanned - {memory_yara['error']}")

        if not lines:
            return

        try:
            self.output.insert("end", "\nTelemetry summary:\n" + "\n".join(lines) + "\n")
            self.output.see("end")
        except Exception:
            pass

    def _build_memory_row(self, header):
        """Dump offsets and the process cap.

        Both are properties of the sample being analysed rather than of the
        tool, and both went wrong on the same Formbook run: the standard
        offsets bracketed the window in which it unpacked, and the cap of five
        fell on the sixth process in its chain -- the one most likely to hold
        the payload.
        """
        ttk.Label(header, text="Memory dumps:").grid(
            row=4, column=0, sticky="w", padx=(10, 0), pady=(0, 10)
        )

        row = ttk.Frame(header)
        row.grid(row=4, column=1, columnspan=2, sticky="w", padx=8, pady=(0, 10))

        ttk.Label(row, text="Offsets (s):").pack(side="left")

        ttk.Entry(
            row,
            textvariable=self.dump_offsets_var,
            width=18,
            style="Dark.TEntry",
        ).pack(side="left", padx=(6, 4))

        ttk.Label(row, text="blank = profile default (5, 25)").pack(side="left", padx=(0, 16))

        ttk.Label(row, text="Max processes:").pack(side="left")

        ttk.Spinbox(
            row,
            from_=1,
            to=64,
            textvariable=self.dump_max_processes_var,
            width=6,
            style="Dark.TSpinbox",
            command=self._refresh_summary_from_inputs,
        ).pack(side="left", padx=(6, 16))

        ttk.Label(row, text="Re-dump children after (s):").pack(side="left")

        ttk.Spinbox(
            row,
            from_=0,
            to=120,
            textvariable=self.dump_redump_var,
            width=6,
            style="Dark.TSpinbox",
            command=self._refresh_summary_from_inputs,
        ).pack(side="left", padx=(6, 4))

        ttk.Label(row, text="0 = off").pack(side="left")

    def _build_telemetry_row(self, header):
        """Toggles for the tier-1 telemetry sources, with live availability."""
        ttk.Label(header, text="Telemetry:").grid(
            row=3, column=0, sticky="w", padx=(10, 0), pady=(0, 10)
        )

        row = ttk.Frame(header)
        row.grid(row=3, column=1, columnspan=2, sticky="w", padx=8, pady=(0, 10))

        Checkbox(
            row,
            "Sysmon",
            self.sysmon_enabled_var,
            command=self._refresh_summary_from_inputs,
            parent_bg=T.BG,
        ).pack(side="left")

        Checkbox(
            row,
            "Packet capture",
            self.pcap_enabled_var,
            command=self._refresh_summary_from_inputs,
            parent_bg=T.BG,
        ).pack(side="left", padx=(14, 0))

        Checkbox(
            row,
            "Simulated internet",
            self.fakenet_enabled_var,
            command=self._refresh_summary_from_inputs,
            parent_bg=T.BG,
        ).pack(side="left", padx=(14, 0))

        Checkbox(
            row,
            "Memory dump",
            self.memory_dump_enabled_var,
            command=self._refresh_summary_from_inputs,
            parent_bg=T.BG,
        ).pack(side="left", padx=(14, 0))

        Checkbox(
            row,
            "Memory YARA",
            self.memory_yara_enabled_var,
            command=self._refresh_summary_from_inputs,
            parent_bg=T.BG,
        ).pack(side="left", padx=(14, 0))

        self.telemetry_status_label = ttk.Label(
            row, text="", style="Muted.TLabel"
        )
        self.telemetry_status_label.pack(side="left", padx=(16, 0))

        # Row 5: row 4 is the memory-dump controls.
        self.isolation_label = ttk.Label(header, text="", style="Muted.TLabel")
        self.isolation_label.grid(
            row=5, column=1, columnspan=2, sticky="w", padx=8, pady=(0, 10)
        )

        self._refresh_telemetry_availability()

    #: How often the containment strip re-reads the network, in milliseconds.
    #:
    #: Arming and disarming happens on the host while this window sits open, and
    #: the strip used to keep whatever it read at build time until the window was
    #: closed and reopened. A stale "Single egress path" is the most dangerous
    #: thing this GUI can display, because it is reassuring and wrong.
    #:
    #: 4s is chosen to be faster than a person can arm the guest and click Run.
    ISOLATION_POLL_MS = 4000

    def _start_isolation_watch(self):
        """Begin re-reading containment for as long as the window is open."""
        self._schedule_isolation_poll()

    def _schedule_isolation_poll(self):
        try:
            self._isolation_poll_job = self.after(
                self.ISOLATION_POLL_MS, self._poll_isolation
            )
        except Exception:
            # The window is going away; nothing left to schedule against.
            self._isolation_poll_job = None

    def _poll_isolation(self):
        """One tick of the containment watch.

        The probe shells out, so it runs on a worker thread rather than blocking
        the UI, and only one is ever in flight.

        Paused while a detonation is running, deliberately. Procmon is capturing
        everything the machine does, and a subprocess every four seconds would
        put the analyzer's own network queries into the sample's evidence. The
        run re-reads containment at launch and the summary is the authority
        during it, so nothing is lost by going quiet.
        """
        self._isolation_poll_job = None

        if self._isolation_probe_active or self._run_in_progress():
            self._schedule_isolation_poll()
            return

        self._isolation_probe_active = True

        def probe():
            try:
                from dynamic_analysis.network_capture import network_isolation_status

                status = network_isolation_status()
            except Exception as error:
                status = {"level": "unknown", "note": str(error), "egress_count": 0}
            try:
                self.after(0, lambda s=status: self._apply_isolation(s))
            except Exception:
                pass

        threading.Thread(target=probe, name="ringforge-isolation-watch", daemon=True).start()

    def _run_in_progress(self) -> bool:
        thread = getattr(self, "worker_thread", None)
        return bool(thread is not None and thread.is_alive())

    def _apply_isolation(self, status: dict) -> None:
        """Adopt a probe result on the UI thread, redrawing only on a change.

        Comparing a signature rather than redrawing every tick keeps the banner
        from being re-packed four times a minute forever, which flickers and
        steals focus from whatever the analyst is typing into.
        """
        self._isolation_probe_active = False

        signature = isolation_signature(status)
        if signature != self._isolation_signature:
            self._isolation_signature = signature
            self._isolation = status
            try:
                self._render_isolation_label()
            except Exception:
                pass

        self._schedule_isolation_poll()

    def destroy(self):
        """Stop the containment watch before the widgets go away."""
        job = getattr(self, "_isolation_poll_job", None)
        if job is not None:
            try:
                self.after_cancel(job)
            except Exception:
                pass
            self._isolation_poll_job = None
        super().destroy()

    def _refresh_isolation(self):
        """Re-read containment only. Cheap enough to run before every launch.

        The strip used to be computed once when the window was built, so a
        guest armed afterwards still showed its pre-arm state -- reassuring and
        wrong, which is why WORKFLOW says to trust the run summary over this
        line. Refreshing before the run makes the line agree with the check
        that actually gates the detonation.
        """
        try:
            from dynamic_analysis.network_capture import network_isolation_status

            self._isolation = network_isolation_status()
        except Exception as error:
            self._isolation = {"level": "unknown", "note": str(error), "egress_count": 0}
        # Kept in step with the watch so the next poll does not redraw an
        # identical state just because this path set it.
        self._isolation_signature = isolation_signature(self._isolation)
        self._refresh_telemetry_availability(isolation_only=True)

    def _refresh_telemetry_availability(self, isolation_only: bool = False):
        """Show which tier-1 tools are actually installed, before a run starts.

        Checked once at build time rather than per keystroke: each probe shells
        out to wevtutil/sc/dumpcap. ``isolation_only`` re-renders from the
        cached probes, for when only containment has been re-read.
        """
        if isolation_only:
            self._render_isolation_label()
            return

        try:
            from dynamic_analysis.sysmon_collector import sysmon_status
            from dynamic_analysis.network_capture import capture_status, network_isolation_status
            from dynamic_analysis.fakenet_runner import fakenet_status
            from dynamic_analysis.memory_dump import memory_dump_status
            from dynamic_analysis.memory_yara import memory_yara_status

            self._sysmon_preflight = sysmon_status()
            self._pcap_preflight = capture_status()
            self._fakenet_preflight = fakenet_status(self.fakenet_path_var.get().strip() or None)
            self._memory_preflight = memory_dump_status()
            self._memory_yara_preflight = memory_yara_status()
            self._isolation = network_isolation_status()
        except Exception as error:
            self._sysmon_preflight = {"available": False, "note": str(error)}
            self._pcap_preflight = {"available": False, "note": ""}
            self._fakenet_preflight = {"available": False, "note": ""}
            self._memory_preflight = {"available": False, "note": ""}
            self._memory_yara_preflight = {"available": False, "note": ""}
            self._isolation = {"level": "unknown", "note": "", "egress_count": 0}

        def mark(label, status):
            return f"{label}: {'ready' if status.get('available') else 'not installed'}"

        parts = [
            mark("Sysmon", self._sysmon_preflight),
            mark("Capture", self._pcap_preflight),
            mark("FakeNet", self._fakenet_preflight),
            mark("Memory", self._memory_preflight),
            mark("Mem YARA", self._memory_yara_preflight),
        ]
        if not self._is_running_as_admin():
            parts.append("(capture needs admin)")

        try:
            self.telemetry_status_label.configure(text="  |  ".join(parts))
        except Exception:
            pass

        self._render_isolation_label()

    def _render_armed_banner(self):
        """Show or hide the containment banner.

        Packed and unpacked rather than recoloured, so a contained run has no
        red on screen at all and the banner never becomes wallpaper.
        """
        try:
            if self._isolation.get("level") == "uncontained":
                paths = [
                    f"{e.get('adapter') or e.get('interface_ip')} -> {e.get('gateway')}"
                    for e in (self._isolation.get("egress", []) or [])
                    if e.get("reaches") in ("internet", "unexpected")
                ]
                detail = f"  ({', '.join(paths)})" if paths else ""
                self.armed_banner.configure(
                    text=(
                        "*** VM IS STILL ARMED - the guest can reach the internet."
                        f"{detail}    Detonation is blocked. "
                        "Disarm with:  .\\scripts\\vm_net.ps1 -Disarm ***"
                    )
                )
                self.armed_banner.pack(fill="x", side="top", before=self._main_frame)
            else:
                self.armed_banner.pack_forget()
        except Exception:
            pass

    def _render_isolation_label(self):
        self._render_armed_banner()

        # Containment is a separate, louder line: a second adapter lets a
        # sample bypass the simulated internet and reach real infrastructure.
        try:
            level = self._isolation.get("level")
            if level == "uncontained":
                self.isolation_label.configure(
                    text=f"ARMED - WILL NOT DETONATE: {self._isolation.get('note', '')}",
                    foreground=T.DANGER,
                )
            elif level == "warning":
                count = self._isolation.get("egress_count", 0)
                if count > 1:
                    detail = f"{count} network egress paths - disable all but one adapter"
                else:
                    # Single adapter but still not contained, e.g. an IPv6
                    # default route. Use the specific reason: telling someone
                    # to remove adapters they do not have is worse than silence.
                    detail = self._isolation.get("note", "traffic can leave this machine")
                self.isolation_label.configure(
                    text=f"NOT CONTAINED: {detail}",
                    foreground=T.DANGER,
                )
            elif self._isolation.get("isolated"):
                self.isolation_label.configure(
                    text="Contained: no default route", foreground=T.SUCCESS
                )
            elif level == "ok":
                self.isolation_label.configure(
                    text=self._isolation.get("note", ""), foreground=T.TEXT_MUTED
                )
            else:
                self.isolation_label.configure(text="", foreground=T.TEXT_MUTED)
        except Exception:
            pass

    def _reset_progress(self):
        for w in self.steps_frame.winfo_children():
            w.destroy()
        self.step_vars.clear()

        steps = [
            "Pre-checks",
            "Telemetry start",
            "Procmon start",
            "Sample execution",
            "Procmon stop",
            "Telemetry collect",
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
        self.summary_output_var.set(self._short_display_path(dynamic_output, keep_parts=2))
        self.summary_procmon_var.set("Enabled" if self.procmon_enabled_var.get() else "Disabled")
        self.summary_timeout_var.set(f"{self.timeout_var.get()} sec")
        self.summary_observation_var.set(
            f"Min {self.minimum_observation_var.get()}s | "
            f"Post {self.post_exit_observation_var.get()}s | "
            f"{'Installer' if self.installer_observation_mode_var.get() else 'Standard'} | "
            + (
                f"Extend to {self.max_observation_var.get()}s"
                if self.adaptive_observation_var.get()
                else "Fixed"
            )
        )

        enabled = [
            name
            for name, var in (
                ("Sysmon", self.sysmon_enabled_var),
                ("PCAP", self.pcap_enabled_var),
                ("FakeNet", self.fakenet_enabled_var),
                ("Memory", self.memory_dump_enabled_var),
                ("MemYARA", self.memory_yara_enabled_var),
            )
            if var.get()
        ]
        self.summary_telemetry_var.set(" + ".join(enabled) if enabled else "Procmon only")

    def _save_cfg(self):
        if not hasattr(self.app, "cfg") or not isinstance(self.app.cfg, dict):
            self.app.cfg = {}

        self.app.cfg["dynamic_case_dir"] = self.case_dir_var.get().strip()
        self.app.cfg["dynamic_case_dir_manual"] = bool(self._case_dir_manual)
        self.app.cfg["dynamic_output_dir"] = self.dynamic_output_dir_var.get().strip()
        self.app.cfg["dynamic_timeout_seconds"] = int(self.timeout_var.get())
        self.app.cfg["dynamic_procmon_enabled"] = bool(self.procmon_enabled_var.get())
        self.app.cfg["dynamic_procmon_path"] = self.procmon_path_var.get().strip()
        self.app.cfg["dynamic_procmon_config_path"] = self.procmon_config_var.get().strip()
        self.app.cfg["dynamic_minimum_observation_seconds"] = int(self.minimum_observation_var.get())
        self.app.cfg["dynamic_post_exit_observation_seconds"] = int(self.post_exit_observation_var.get())
        self.app.cfg["dynamic_installer_observation_mode"] = bool(self.installer_observation_mode_var.get())
        self.app.cfg["dynamic_adaptive_observation"] = bool(self.adaptive_observation_var.get())
        self.app.cfg["dynamic_max_observation_seconds"] = int(self.max_observation_var.get())
        self.app.cfg["dynamic_sysmon_enabled"] = bool(self.sysmon_enabled_var.get())
        self.app.cfg["dynamic_pcap_enabled"] = bool(self.pcap_enabled_var.get())
        self.app.cfg["dynamic_fakenet_enabled"] = bool(self.fakenet_enabled_var.get())
        self.app.cfg["dynamic_fakenet_path"] = self.fakenet_path_var.get().strip()
        self.app.cfg["dynamic_memory_dump_enabled"] = bool(self.memory_dump_enabled_var.get())
        self.app.cfg["dynamic_memory_dump_offsets"] = self.dump_offsets_var.get().strip()
        self.app.cfg["dynamic_memory_dump_max_processes"] = int(self.dump_max_processes_var.get())
        self.app.cfg["dynamic_memory_dump_spawn_redump_seconds"] = int(self.dump_redump_var.get())
        self.app.cfg["dynamic_memory_yara_enabled"] = bool(self.memory_yara_enabled_var.get())

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
            parent=self,
        )
        if chosen:
            sample = Path(chosen)
            # Setting this fires the auto-follow trace, which repoints the case
            # folder unless the analyst has chosen one by hand.
            self.sample_var.set(str(sample))

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

            # A case carried over from the launcher is an explicit association,
            # so it outranks the sample-name convention.
            self._case_dir_manual = True
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
            # An explicit choice stops the case folder tracking the sample name.
            self._case_dir_manual = True
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
            parent=self,
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
            parent=self,
        )
        if chosen:
            self.procmon_config_var.set(str(Path(chosen)))
            self._save_cfg()
            
    def _safe_report_stem(self, sample_name: str) -> str:
        stem = Path(sample_name or "").stem
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem)
        stem = stem.strip("._-")
        return stem or "sample"
    
    def _short_display_path(self, path_value, keep_parts: int = 2) -> str:
        if not path_value:
            return "-"

        try:
            p = Path(path_value)
            parts = p.parts

            if len(parts) <= keep_parts:
                return str(p)

            tail = Path(*parts[-keep_parts:])
            return f"...\\{tail}"
        except Exception:
            text = str(path_value)
            return text if len(text) <= 80 else f"...{text[-77:]}"

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

            sample_name = Path(self.sample_var.get().strip()).name
            sample_stem = self._safe_report_stem(sample_name)

            output_html = reports_dir / f"{sample_stem}_dynamic_report.html"
            compat_html = reports_dir / "dynamic_report.html"

            if summary_path:
                write_dynamic_html_report(summary_path, output_html)

                # Compatibility copy for existing buttons/workflows that expect dynamic_report.html.
                if output_html.exists():
                    shutil.copy2(output_html, compat_html)

            elif findings_path:
                data = json.loads(findings_path.read_text(encoding="utf-8", errors="replace"))
                self._write_fallback_dynamic_html(data, output_html, case_home)

                # Compatibility copy for existing buttons/workflows that expect dynamic_report.html.
                if output_html.exists():
                    shutil.copy2(output_html, compat_html)

            else:
                checked = [str(p) for p in summary_candidates + findings_candidates]
                messagebox.showerror(
                    "Export Report",
                    "No dynamic source file found.\n\nChecked:\n" + "\n".join(checked),
                    parent=self,
                )
                return None
            

            self.summary_report_var.set(self._short_display_path(output_html, keep_parts=2))
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

            self.summary_report_var.set(self._short_display_path(html_path, keep_parts=2))
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
            
    def _confirm_case_sample_match(self, sample: Path, case_home: Path) -> bool:
        sample_stem = self._safe_case_name(sample.stem).lower()
        case_name = self._safe_case_name(case_home.name).lower()

        if not sample_stem or not case_name:
            return True

        if case_name == sample_stem:
            return True

        if sample_stem in case_name or case_name in sample_stem:
            return True

        proceed = messagebox.askyesno(
            "Case Folder Mismatch",
            "The selected sample name does not appear to match the selected case folder.\n\n"
            f"Sample:\n{sample.name}\n\n"
            f"Case folder:\n{case_home}\n\n"
            "This may mix dynamic results into the wrong case.\n\n"
            "Continue anyway?",
            parent=self,
        )

        return bool(proceed)

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
        
    def _warn_if_observation_settings_conflict(
        self,
        timeout_seconds: int,
        minimum_observation_seconds: int,
        post_exit_observation_seconds: int,
    ) -> bool:
        """
        Warn when the configured post-exit observation target cannot fully fit
        inside the hard sample observation timeout.

        This is allowed, especially for quick baseline tests like Notepad, but the
        analyst should know the timeout will win.
        """
        if timeout_seconds <= 0:
            return True

        if post_exit_observation_seconds <= 0:
            return True

        if post_exit_observation_seconds >= timeout_seconds:
            return messagebox.askyesno(
                "Observation Settings Notice",
                "Post-exit observation is longer than or equal to the sample observation timeout.\n\n"
                f"Sample observation timeout: {timeout_seconds} seconds\n"
                f"Minimum observation: {minimum_observation_seconds} seconds\n"
                f"Post-exit observation target: {post_exit_observation_seconds} seconds\n\n"
                "The run can still continue, but RingForge will stop at the timeout before the full "
                "post-exit observation window completes.\n\n"
                "This is usually fine for quick baseline tests like Notepad. For larger installers, "
                "increase the timeout.\n\n"
                "Continue anyway?",
                parent=self,
            )

        remaining_after_minimum = timeout_seconds - minimum_observation_seconds

        if remaining_after_minimum > 0 and post_exit_observation_seconds > remaining_after_minimum:
            return messagebox.askyesno(
                "Observation Settings Notice",
                "Post-exit observation may not fully fit after the minimum observation window.\n\n"
                f"Sample observation timeout: {timeout_seconds} seconds\n"
                f"Minimum observation: {minimum_observation_seconds} seconds\n"
                f"Post-exit observation target: {post_exit_observation_seconds} seconds\n"
                f"Maximum possible post-exit time after minimum observation: {remaining_after_minimum} seconds\n\n"
                "The run can still continue, but RingForge may stop at the timeout before the full "
                "post-exit observation window completes.\n\n"
                "Continue anyway?",
                parent=self,
            )

        return True
    
    # -------------------------------------------------------------------------
    # Run dynamic analysis
    # -------------------------------------------------------------------------

    def _start_dynamic_analysis(self):
        if self.worker_thread and self.worker_thread.is_alive():
            return

        # Re-read containment now rather than trusting what was true when the
        # window opened. A guest armed since then showed its pre-arm state,
        # which is how a sample got detonated with a live network path and
        # nothing said so.
        self._refresh_isolation()
        if self._isolation.get("level") == "uncontained":
            messagebox.showerror(
                "Not contained",
                f"{self._isolation.get('note', '')}\n\n"
                "The run has not been started. Disarm the guest with\n"
                "    .\\scripts\\vm_net.ps1 -Disarm\n"
                "and try again.",
            )
            self._set_step("Pre-checks", 100, "blocked")
            self.status_var.set("Idle")
            self.summary_status_var.set("Not contained")
            return

        sample = Path(self.sample_var.get().strip())
        case_home, dynamic_output = self._ensure_case_layout()
        
        if not self._confirm_case_sample_match(sample, case_home):
            self._set_step("Pre-checks", 100, "cancelled")
            self.status_var.set("Idle")
            self.summary_status_var.set("Ready")
            return
    
        procmon_path = Path(self.procmon_path_var.get().strip())
        timeout_seconds = int(self.timeout_var.get())
        procmon_config = self.procmon_config_var.get().strip()
        
        minimum_observation_seconds = int(self.minimum_observation_var.get())
        post_exit_observation_seconds = int(self.post_exit_observation_var.get())
        installer_observation_mode = bool(self.installer_observation_mode_var.get())

        if not self._warn_if_observation_settings_conflict(
            timeout_seconds=timeout_seconds,
            minimum_observation_seconds=minimum_observation_seconds,
            post_exit_observation_seconds=post_exit_observation_seconds,
        ):
            self._set_step("Pre-checks", 100, "cancelled")
            self.status_var.set("Idle")
            self.summary_status_var.set("Ready")
            return

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
            "minimum_observation_seconds": minimum_observation_seconds,
            "post_exit_observation_seconds": post_exit_observation_seconds,
            "installer_observation_mode": installer_observation_mode,
            "adaptive_observation": bool(self.adaptive_observation_var.get()),
            "max_observation_seconds": int(self.max_observation_var.get()),
            "procmon_enabled": bool(self.procmon_enabled_var.get()),
            "procmon_path": str(procmon_path),
            "procmon_config_path": procmon_config,
            "sysmon_enabled": bool(self.sysmon_enabled_var.get()),
            "pcap_enabled": bool(self.pcap_enabled_var.get()),
            "fakenet_enabled": bool(self.fakenet_enabled_var.get()),
            "fakenet_path": self.fakenet_path_var.get().strip(),
            "memory_dump_enabled": bool(self.memory_dump_enabled_var.get()),
            "memory_yara_enabled": bool(self.memory_yara_enabled_var.get()),
            # Blank offsets fall back to the run profile's defaults in the
            # orchestrator, which parses the text.
            "memory_dump_offsets": self.dump_offsets_var.get().strip(),
            "memory_dump_max_processes": int(self.dump_max_processes_var.get()),
            "memory_dump_spawn_redump_seconds": int(self.dump_redump_var.get()),
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
        self._set_step("Telemetry start", 25, "running")
        self._set_step("Procmon start", 25, "running")

        self.output.delete("1.0", "end")
        self.output.insert("end", "Starting dynamic analysis:\n")
        self.output.insert("end", f"  sample={sample}\n")
        self.output.insert("end", f"  case_home={case_home}\n")
        self.output.insert("end", f"  dynamic_output={dynamic_output}\n")
        self.output.insert("end", f"  timeout_seconds={timeout_seconds}\n")
        self.output.insert(
            "end",
            f"  adaptive_observation={config['adaptive_observation']} "
            f"max_observation_seconds={config['max_observation_seconds']}\n",
        )
        self.output.insert(
            "end",
            f"  memory_dump_offsets={config['memory_dump_offsets'] or 'profile default'} "
            f"max_processes={config['memory_dump_max_processes']} "
            f"spawn_redump={config['memory_dump_spawn_redump_seconds'] or 'off'}\n",
        )
        self.output.insert("end", f"  procmon_enabled={config['procmon_enabled']}\n")
        self.output.insert("end", f"  procmon_path={procmon_path}\n")
        self.output.insert("end", f"  procmon_config={procmon_config or '-'}\n")
        self.output.insert("end", f"  autorunsc_path={self._find_autorunsc_path() or 'not found'}\n")
        self.output.insert(
            "end",
            f"  sysmon={config['sysmon_enabled']} "
            f"pcap={config['pcap_enabled']} "
            f"fakenet={config['fakenet_enabled']} "
            f"memory_dump={config['memory_dump_enabled']} "
            f"memory_yara={config['memory_yara_enabled']}\n",
        )
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
            except ContainmentError as e:
                # The control working, not a failure. Said differently from a
                # crash so nobody reads it as one and reaches for the override.
                self.output_q.put(f"\n[BLOCKED] {e}\n")
                self.after(
                    0,
                    lambda err=str(e): (
                        messagebox.showerror("Not contained - run blocked", err),
                        self._on_error("blocked: not contained"),
                    ),
                )
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

        self._apply_telemetry_steps(summary if isinstance(summary, dict) else {})

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
                self.summary_report_var.set(
                    self._short_display_path(html_path, keep_parts=2) if html_path and html_path.exists() else "-"
                )

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