from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from tkinter import messagebox


class PathActionsController:
    def __init__(self, app):
        self.app = app

    def open_path(self, path):
        if not path:
            return

        try:
            p = Path(path)
        except Exception:
            return

        if not p.exists():
            messagebox.showerror("Not Found", f"Path not found:\n{p}")
            return

        try:
            if sys.platform.startswith("win"):
                os.startfile(str(p))
            elif sys.platform == "darwin":
                subprocess.run(["open", str(p)], check=False)
            else:
                subprocess.run(["xdg-open", str(p)], check=False)
        except Exception as e:
            messagebox.showerror("Open Failed", f"Could not open:\n{p}\n\n{e}")

    def ensure_case_dir(self):
        app = self.app

        case_dir_detected = getattr(app, "case_dir_detected", None)
        if case_dir_detected:
            try:
                detected = Path(case_dir_detected)
                if detected.exists():
                    return detected
            except Exception:
                pass

        case_root_var = getattr(app, "case_root_var", None)
        case_var = getattr(app, "case_var", None)
        case_name_var = getattr(app, "case_name_var", None)

        case_root_text = ""
        if case_root_var is not None:
            try:
                case_root_text = case_root_var.get().strip()
            except Exception:
                case_root_text = ""

        case_name = ""
        if case_var is not None:
            try:
                case_name = case_var.get().strip()
            except Exception:
                case_name = ""

        if not case_name and case_name_var is not None:
            try:
                case_name = case_name_var.get().strip()
            except Exception:
                case_name = ""

        if not case_name:
            return None

        case_root = Path(case_root_text) if case_root_text else (Path.cwd() / "cases")
        candidate = case_root / case_name
        if candidate.exists():
            return candidate

        return None

    def open_case_files(self):
        case_dir = self.ensure_case_dir()
        if not case_dir:
            messagebox.showwarning("Case Not Found", "No case directory is available yet.")
            return
        self.open_path(case_dir)

    def open_html_report(self):
        case_dir = self.ensure_case_dir()
        if not case_dir:
            messagebox.showwarning("Report Not Found", "No case directory is available yet.")
            return

        report = case_dir / "report.html"
        if not report.exists():
            messagebox.showwarning("Report Not Found", f"Could not find:\n{report}")
            return

        self.open_path(report)

    def open_pdf_report(self):
        case_dir = self.ensure_case_dir()
        if not case_dir:
            messagebox.showwarning("Report Not Found", "No case directory is available yet.")
            return

        report = case_dir / "report.pdf"
        if not report.exists():
            messagebox.showwarning("Report Not Found", f"Could not find:\n{report}")
            return

        self.open_path(report)

    def open_api_folder(self):
        app = self.app
        folder = getattr(app, "latest_api_output_dir", None)
        if not folder:
            messagebox.showwarning("API Output Not Found", "No API analysis output folder is available yet.")
            return

        folder = Path(folder)
        if not folder.exists():
            messagebox.showwarning("API Output Not Found", f"Could not find:\n{folder}")
            return

        self.open_path(folder)

    def open_api_html_report(self):
        app = self.app
        folder = getattr(app, "latest_api_output_dir", None)
        if not folder:
            messagebox.showwarning("API Report Not Found", "No API analysis output folder is available yet.")
            return

        report = Path(folder) / "api_report.html"
        if not report.exists():
            messagebox.showwarning("API Report Not Found", f"Could not find:\n{report}")
            return

        self.open_path(report)