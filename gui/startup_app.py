from __future__ import annotations

import subprocess
import sys
from pathlib import Path
import tkinter as tk
from tkinter import messagebox

from gui.api_window import APIAnalysisWindow
from gui.dynamic_window import DynamicAnalysisWindow
from gui.spec_window import SpecAnalysisWindow
from gui.launcher import LauncherWindow
from gui.splash import SplashScreen
from gui.styles import apply_app_theme
from gui.extension_window import ExtensionAnalysisWindow


class StartupApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.project_root = Path(__file__).resolve().parents[1]
        self.static_script = self.project_root / "scripts" / "static_analysis_gui.py"
        self.assets_dir = self.project_root / "assets"
        self.anvil_path = self.assets_dir / "anvil.png"

        apply_app_theme(self)

        self.withdraw()
        self.title("RingForge Workbench")
        self.geometry("980x720+120+100")
        self.minsize(900, 640)

        self.dynamic_window = None
        self.spec_window = None
        self.api_window = None
        self.launcher_frame = None
        self.extension_window = None

        self.after(50, self._show_splash)

    def _show_splash(self):
        SplashScreen(
            self,
            image_path=self.anvil_path,
            on_close=self._show_launcher,
            duration_ms=2600,
        )

    def _show_launcher(self):
        self.deiconify()
        self.configure(bg="#05070B")

        if self.launcher_frame is not None:
            self.launcher_frame.destroy()

        self.launcher_frame = LauncherWindow(self, app=self)
        self.launcher_frame.pack(fill="both", expand=True)

    def open_static_analysis(self):
        if not self.static_script.exists():
            messagebox.showerror(
                "RingForge",
                f"Static Analysis launcher not found:\n{self.static_script}",
            )
            return

        try:
            subprocess.Popen([sys.executable, str(self.static_script)])
        except Exception as e:
            messagebox.showerror("RingForge", f"Could not launch Static Analysis:\n{e}")

    def open_dynamic_analysis(self):
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