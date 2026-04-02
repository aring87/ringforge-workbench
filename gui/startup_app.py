from __future__ import annotations

import subprocess
import sys
from pathlib import Path
import tkinter as tk
from tkinter import messagebox
import traceback

from gui.gui_utils import load_config, DEFAULT_CASE_ROOT

from gui.api_window import APIAnalysisWindow
from gui.dynamic_window import DynamicAnalysisWindow
from gui.spec_window import SpecAnalysisWindow
from gui.launcher import LauncherWindow
from gui.splash import SplashScreen
from gui.styles import apply_app_theme
from gui.extension_window import ExtensionAnalysisWindow
from gui.unified_report_window import UnifiedReportWindow


class StartupApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.project_root = Path(__file__).resolve().parents[1]
        self.assets_dir = self.project_root / "assets"
        self.anvil_path = self.assets_dir / "anvil.png"

        if getattr(sys, "frozen", False):
            self.launch_target = Path(sys.executable)
        else:
            self.launch_target = self.project_root / "scripts" / "static_triage_gui.py"

        apply_app_theme(self)

        self.title("RingForge Workbench")
        self.geometry("1280x920+80+40")
        self.minsize(1180, 820)
        self.configure(bg="#05070B")

        self.dynamic_window = None
        self.spec_window = None
        self.api_window = None
        self.launcher_frame = None
        self.extension_window = None
        self.unified_report_window = None
        self.splash_window = None

        self.cfg = load_config()
        self.case_root_var = tk.StringVar(
            value=self.cfg.get("case_root_dir", str(DEFAULT_CASE_ROOT))
        )

        # Compatibility fields so launcher-opened analysis windows can reuse
        # the same context expectations as the main static app.
        self.sample_var = tk.StringVar(value="")
        self.case_var = tk.StringVar(value="")
        self.case_dir_detected = None
        self.latest_dynamic_result = None

        self.withdraw()
        self.after(50, self._show_splash)

    def _show_splash(self):
        try:
            print("[DEBUG] Showing splash")
            self.splash_window = SplashScreen(
                self,
                image_path=self.anvil_path,
                on_close=self._show_launcher,
                duration_ms=2600,
            )
        except Exception:
            traceback.print_exc()
            print("[DEBUG] Splash failed, falling back to launcher")
            self._show_launcher()

    def _show_launcher(self):
        try:
            print("[DEBUG] Showing launcher")
            self.deiconify()
            self.lift()
            self.focus_force()
            self.configure(bg="#05070B")

            if self.launcher_frame is not None and self.launcher_frame.winfo_exists():
                self.launcher_frame.destroy()

            self.launcher_frame = LauncherWindow(self, app=self)
            self.launcher_frame.pack(fill="both", expand=True)

            self.update_idletasks()
            print("[DEBUG] Launcher shown successfully")
        except Exception as e:
            traceback.print_exc()
            self.deiconify()
            messagebox.showerror("RingForge Startup Error", f"Failed to build launcher:\n{e}")

    def open_static_analysis(self):
        try:
            if getattr(sys, "frozen", False):
                subprocess.Popen([str(self.launch_target), "--static-analysis"])
            else:
                subprocess.Popen([sys.executable, str(self.launch_target), "--static-analysis"])
        except Exception as e:
            messagebox.showerror("RingForge", f"Could not launch Static Analysis:\n{e}")

    def open_dynamic_analysis(self):
        ctx = None
        if self.launcher_frame is not None and self.launcher_frame.winfo_exists():
            try:
                ctx = self.launcher_frame.get_selected_saved_test_context()
            except Exception:
                ctx = None

        if ctx:
            sample_path = (ctx.get("sample_path") or "").strip()
            test_name = (ctx.get("test_name") or "").strip()
            case_dir = ctx.get("case_dir")

            if sample_path:
                self.sample_var.set(sample_path)

            if test_name:
                self.case_var.set(test_name)

            if case_dir:
                self.case_dir_detected = Path(case_dir)

        if self.dynamic_window is not None and self.dynamic_window.winfo_exists():
            self.dynamic_window.lift()
            self.dynamic_window.focus_force()
            return

        self.dynamic_window = DynamicAnalysisWindow(self)
        self.dynamic_window.protocol(
            "WM_DELETE_WINDOW",
            lambda win=self.dynamic_window: (win.destroy(), setattr(self, "dynamic_window", None)),
        )

    def open_api_analysis(self):
        if self.api_window is not None and self.api_window.winfo_exists():
            self.api_window.lift()
            self.api_window.focus_force()
            return

        self.api_window = APIAnalysisWindow(self)
        self.api_window.protocol(
            "WM_DELETE_WINDOW",
            lambda win=self.api_window: (win.destroy(), setattr(self, "api_window", None)),
        )

    def open_spec_analysis(self):
        if self.spec_window is not None and self.spec_window.winfo_exists():
            self.spec_window.lift()
            self.spec_window.focus_force()
            return

        self.spec_window = SpecAnalysisWindow(self)
        self.spec_window.protocol(
            "WM_DELETE_WINDOW",
            lambda win=self.spec_window: (win.destroy(), setattr(self, "spec_window", None)),
        )

    def open_extension_analysis(self):
        if self.extension_window is not None and self.extension_window.winfo_exists():
            self.extension_window.lift()
            self.extension_window.focus_force()
            return

        self.extension_window = ExtensionAnalysisWindow(self)
        self.extension_window.protocol(
            "WM_DELETE_WINDOW",
            lambda win=self.extension_window: (win.destroy(), setattr(self, "extension_window", None)),
        )

    def open_unified_report(self):
        if self.unified_report_window is not None and self.unified_report_window.winfo_exists():
            self.unified_report_window.lift()
            self.unified_report_window.focus_force()
            return

        self.unified_report_window = UnifiedReportWindow(self)
        self.unified_report_window.protocol(
            "WM_DELETE_WINDOW",
            lambda win=self.unified_report_window: (win.destroy(), setattr(self, "unified_report_window", None)),
        )