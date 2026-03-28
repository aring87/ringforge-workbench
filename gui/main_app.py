from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk

from gui.controllers import StaticAnalysisController, ResultController, PathActionsController
from gui.api_window import APIAnalysisWindow
from gui.dynamic_window import DynamicAnalysisWindow
from gui.spec_window import SpecAnalysisWindow
from gui.styles import apply_app_theme
from gui.gui_utils import (
    ROOT, DEFAULT_CASE_ROOT, DEFAULT_RULES_DIR, DEFAULT_SIGS_DIR, CLI_SCRIPT,
    STEP_DISPLAY_ORDER, STEP_LABELS,
    PRESETS, norm_path_str, normalize_rules_dir,
    looks_like_rules_dir, looks_like_sigs_dir,
    load_config, save_config,
)
from gui.main_sections import (
    build_actions_and_output,
    build_configuration_section,
    build_header,
    build_main_columns,
    build_progress_section,
    build_results_section,
)

class App(tk.Tk):
    def __init__(self):
        super().__init__()

        try:
            apply_app_theme(self)

            self.title("Static Triage GUI (v10)")
            self.geometry("1280x980+100+100")
            self.minsize(1180, 900)
            self.rowconfigure(0, weight=1)
            self.columnconfigure(0, weight=1)

            self.combined_verdict_var = tk.StringVar(value="-")
            self.combined_confidence_var = tk.StringVar(value="-")

            self.cfg = load_config()

            self.sample_var = tk.StringVar(value=self.cfg.get("sample_path", ""))
            self.case_var = tk.StringVar(value=self.cfg.get("case_name", ""))
            self.preset_var = tk.StringVar(value=self.cfg.get("preset", PRESETS[1].name))

            self.case_root_var = tk.StringVar(value=self.cfg.get("case_root_dir", str(DEFAULT_CASE_ROOT)))
            self.rules_var = tk.StringVar(value=self.cfg.get("capa_rules_dir", str(DEFAULT_RULES_DIR)))
            self.sigs_var = tk.StringVar(value=self.cfg.get("capa_sigs_dir", str(DEFAULT_SIGS_DIR)))
            self.vt_api_key_var = tk.StringVar(value=self.cfg.get("vt_api_key", ""))

            self.adv_enabled_var = tk.BooleanVar(value=self.cfg.get("adv_enabled", False))
            self.extract_var = tk.BooleanVar(value=self.cfg.get("extract", True))
            self.subfiles_var = tk.BooleanVar(value=self.cfg.get("subfiles", True))
            self.subfile_limit_var = tk.IntVar(value=int(self.cfg.get("subfile_limit", 25)))
            self.strings_lite_var = tk.BooleanVar(value=self.cfg.get("strings_lite", False))
            self.no_strings_var = tk.BooleanVar(value=self.cfg.get("no_strings", False))

            self.status_var = tk.StringVar(value="")
            self.running_var = tk.StringVar(value="Idle")

            self.score_var = tk.StringVar(value="-")
            self.verdict_var = tk.StringVar(value="-")
            self.confidence_var = tk.StringVar(value="-")
            self.combined_score_var = tk.StringVar(value="-")
            self.combined_severity_var = tk.StringVar(value="-")
            self.static_subscore_var = tk.StringVar(value="-")
            self.dynamic_subscore_var = tk.StringVar(value="-")
            self.spec_subscore_var = tk.StringVar(value="-")
            self.vt_status_var = tk.StringVar(value="VirusTotal: disabled")
            self.vt_name_var = tk.StringVar(value="VT Name: -")
            self.vt_counts_var = tk.StringVar(value="Counts: mal=0 | susp=0 | harmless=0 | undetected=0")
            self.vt_link = ""
            self.brand_logo_img = None

            self.open_case_btn = None
            self.open_html_btn = None
            self.open_pdf_btn = None
            self.dynamic_window = None
            self.spec_window = None
            self.api_window = None
            self.latest_static_result = {}
            self.latest_dynamic_result = {}
            self.latest_spec_result = {}
            self.latest_combined_score = None

            self.output_q = queue.Queue()
            self.worker_thread = None
            self.log_tail_thread = None
            self.stop_tail = threading.Event()
            self.current_log_path = None

            self.case_dir_detected = None
            self.step_widgets = {}

            self.static_controller = StaticAnalysisController(self)
            self.result_controller = ResultController(self)
            self.path_actions = PathActionsController(self)
            self.CLI_SCRIPT = CLI_SCRIPT

            print("[DEBUG] Building UI...")
            self._build_ui()
            print("[DEBUG] UI built")

            self._apply_preset_if_needed()
            self._refresh_path_status()
            self.vt_api_key_var.trace_add("write", lambda *_: self._refresh_path_status())
            self._reset_progress()
            self._reset_result_summary()

            self.update_idletasks()
            self.deiconify()
            self.state("normal")
            self.lift()
            self.focus_force()

            self.after(100, self._drain_output)
            print("[DEBUG] App initialized successfully")

        except Exception:
            import traceback
            traceback.print_exc()
            raise

    def _build_ui(self):
        outer = {"padx": 12, "pady": 8}

        build_header(self, self, outer)
        _, left_col, right_col = build_main_columns(self, outer)

        build_configuration_section(self, left_col)
        self._build_brand_panel(left_col)

        build_progress_section(self, right_col)
        build_results_section(self, right_col)

        build_actions_and_output(self, self, outer)

        self._sync_adv_state()
        self._update_effective_label()
    
    def _build_brand_panel(self, parent):
        brand = ttk.LabelFrame(parent, text="RingForge")
        brand.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        brand.columnconfigure(0, weight=1)
        brand.rowconfigure(0, weight=1)

        brand_inner = tk.Frame(
            brand,
            bg="#001833",
            highlightthickness=1,
            highlightbackground="#2a4365",
        )
        brand_inner.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        brand_inner.columnconfigure(1, weight=1)

        logo_path = ROOT / "assets" / "anvil.png"

        if logo_path.exists():
            logo_img = Image.open(logo_path).convert("RGBA")
            logo_img = logo_img.resize((220, 220), Image.LANCZOS)
            self.brand_logo_img = ImageTk.PhotoImage(logo_img)

            logo_label = tk.Label(
                brand_inner,
                image=self.brand_logo_img,
                bg="#001833",
                bd=0,
                highlightthickness=0,
            )
            logo_label.grid(row=0, column=0, rowspan=6, sticky="w", padx=(18, 24), pady=18)
        else:
            logo_label = tk.Label(
                brand_inner,
                text="[assets/anvil.png not found]",
                bg="#001833",
                fg="#7fb3ff",
                font=("Segoe UI", 11, "bold"),
            )
            logo_label.grid(row=0, column=0, rowspan=6, sticky="w", padx=(18, 24), pady=18)

        tk.Label(
            brand_inner,
            text="RingForge",
            bg="#001833",
            fg="#f8fbff",
            font=("Segoe UI", 24, "bold"),
            anchor="w",
        ).grid(row=0, column=1, sticky="sw", pady=(28, 0))

        tk.Label(
            brand_inner,
            text="Workbench",
            bg="#001833",
            fg="#7fb3ff",
            font=("Segoe UI", 20, "bold"),
            anchor="w",
        ).grid(row=1, column=1, sticky="nw")

        tk.Frame(
            brand_inner,
            bg="#1f6fff",
            height=2,
            width=220,
        ).grid(row=2, column=1, sticky="w", pady=(8, 12))

        tk.Label(
            brand_inner,
            text="Static, Dynamic & Spec Analysis Platform",
            bg="#001833",
            fg="#c7dbff",
            font=("Segoe UI", 11),
            anchor="w",
        ).grid(row=3, column=1, sticky="w")

        tk.Label(
            brand_inner,
            text="Triage  •  Scoring  •  Reporting  •  Review",
            bg="#001833",
            fg="#86a9df",
            font=("Segoe UI", 10),
            anchor="w",
        ).grid(row=4, column=1, sticky="w", pady=(6, 0))

        tk.Label(
            brand_inner,
            text="v1.5",
            bg="#001833",
            fg="#5f86c5",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        ).grid(row=5, column=1, sticky="w", pady=(14, 18))

        return brand
        

    def open_spec_analysis_window(self):
        if self.spec_window is not None and self.spec_window.winfo_exists():
            self.spec_window.lift()
            self.spec_window.focus_force()
            return
        self.spec_window = SpecAnalysisWindow(self)
        self.spec_window.protocol(
            "WM_DELETE_WINDOW",
            lambda win=self.spec_window: (win.destroy(), setattr(self, "spec_window", None)),
        )

    def open_api_analysis_window(self):
        if self.api_window is not None and self.api_window.winfo_exists():
            self.api_window.lift()
            self.api_window.focus_force()
            return
        self.api_window = APIAnalysisWindow(self)
        self.api_window.protocol(
            "WM_DELETE_WINDOW",
            lambda win=self.api_window: (win.destroy(), setattr(self, "api_window", None)),
        )

    def reload_combined_score_from_disk(self):
        self.result_controller.reload_combined_score_from_disk()

    def _reset_result_summary(self):
        self.result_controller.reset_result_summary()

    def refresh_combined_score(self, case_dir: Optional[Path] = None):
        self.result_controller.refresh_combined_score(case_dir)

    def _clear_vt_key(self):
        self.vt_api_key_var.set("")
        self._save_cfg()
        self._refresh_path_status()

    def _open_virustotal(self):
        if self.vt_link:
            try:
                webbrowser.open(self.vt_link)
            except Exception as e:
                messagebox.showerror("VirusTotal", f"Could not open link:\n{e}")

    def _open_path(self, path):
        self.path_actions.open_path(path)

    def _ensure_case_dir(self):
        return self.path_actions.ensure_case_dir()

    def _open_api_html_report(self):
        self.path_actions.open_api_html_report()

    def _open_api_folder(self):
        self.path_actions.open_api_folder()

    def _open_case_files(self):
        self.path_actions.open_case_files()

    def _open_html_report(self):
        self.path_actions.open_html_report()

    def _open_pdf_report(self):
        self.path_actions.open_pdf_report()

    def _update_result_summary_from_case(self, case_dir: Path):
        self.result_controller.update_result_summary_from_case(case_dir)

    def _save_cfg(self):
        self.cfg["sample_path"] = self.sample_var.get().strip()
        self.cfg["case_name"] = self.case_var.get().strip()
        self.cfg["preset"] = self.preset_var.get().strip()
        self.cfg["case_root_dir"] = self.case_root_var.get().strip()
        self.cfg["capa_rules_dir"] = self.rules_var.get().strip()
        self.cfg["capa_sigs_dir"] = self.sigs_var.get().strip()
        self.cfg["vt_api_key"] = self.vt_api_key_var.get().strip()
        self.cfg["adv_enabled"] = bool(self.adv_enabled_var.get())
        self.cfg["extract"] = bool(self.extract_var.get())
        self.cfg["subfiles"] = bool(self.subfiles_var.get())
        self.cfg["subfile_limit"] = int(self.subfile_limit_var.get())
        self.cfg["strings_lite"] = bool(self.strings_lite_var.get())
        self.cfg["no_strings"] = bool(self.no_strings_var.get())
        save_config(self.cfg)
        self._update_effective_label()

    def _browse_sample(self):
        start = Path(self.sample_var.get()).parent if self.sample_var.get() else ROOT
        path = filedialog.askopenfilename(title="Select sample file", initialdir=str(start))
        if not path:
            return
        self.sample_var.set(norm_path_str(path))
        if not self.case_var.get().strip():
            self.case_var.set(Path(path).stem[:64])
        self._save_cfg()

    def _browse_case_root(self):
        start = Path(self.case_root_var.get()) if self.case_root_var.get() else ROOT
        chosen = filedialog.askdirectory(title="Select case output folder", initialdir=str(start))
        if not chosen:
            return
        self.case_root_var.set(norm_path_str(chosen))
        self._save_cfg()

    def _browse_rules(self):
        start = Path(self.rules_var.get()) if self.rules_var.get() else ROOT
        chosen = filedialog.askdirectory(title="Select capa rules folder", initialdir=str(start))
        if not chosen:
            return
        self.rules_var.set(norm_path_str(chosen))
        self._save_cfg()
        self._refresh_path_status()

    def _browse_sigs(self):
        start = Path(self.sigs_var.get()) if self.sigs_var.get() else ROOT
        chosen = filedialog.askdirectory(title="Select capa sigs folder", initialdir=str(start))
        if not chosen:
            return
        self.sigs_var.set(norm_path_str(chosen))
        self._save_cfg()
        self._refresh_path_status()

    def _on_preset_changed(self):
        self._apply_preset_if_needed()
        self._save_cfg()

    def _on_preset_selected(self, event=None):
        self._on_preset_changed()
        try:
            event.widget.selection_clear()
        except Exception:
            pass
        self.after(50, lambda: self.focus_set())

    def _on_adv_toggle(self):
        self._sync_adv_state()
        self._save_cfg()

    def _sync_adv_state(self):
        advanced_on = self.adv_enabled_var.get()
        for child in self.adv_body.winfo_children():
            try:
                if isinstance(child, ttk.Label):
                    child.configure(state="normal")
                elif child is getattr(self, "subfile_limit_spin", None):
                    child.configure(state="normal" if advanced_on else "readonly")
                else:
                    child.configure(state="normal" if advanced_on else "disabled")
            except tk.TclError:
                pass
        self._update_effective_label()

    def _on_strings_mode_changed(self):
        if self.no_strings_var.get():
            self.strings_lite_var.set(False)
        self._save_cfg()

    def _selected_preset(self) -> "Preset":
        name = self.preset_var.get().strip()
        return next((p for p in PRESETS if p.name == name), PRESETS[1])

    def _apply_preset_if_needed(self):
        if self.adv_enabled_var.get():
            return
        p = self._selected_preset()
        self.extract_var.set(p.extract)
        self.subfiles_var.set(p.subfiles)
        self.subfile_limit_var.set(p.subfile_limit)
        self.no_strings_var.set(p.strings_mode.upper() == "SKIP")
        self.strings_lite_var.set(p.strings_mode.upper() == "LITE")
        self._update_effective_label()

    def _effective_settings(self) -> Tuple[bool, bool, int, str]:
        if self.adv_enabled_var.get():
            extract = bool(self.extract_var.get())
            subfiles = bool(self.subfiles_var.get())
            limit = int(self.subfile_limit_var.get())
            if self.no_strings_var.get():
                sm = "SKIP"
            elif self.strings_lite_var.get():
                sm = "LITE"
            else:
                sm = "FULL"
            return extract, subfiles, limit, sm
        p = self._selected_preset()
        return p.extract, p.subfiles, p.subfile_limit, p.strings_mode

    def _update_effective_label(self):
        extract, subfiles, limit, sm = self._effective_settings()
        self.effective_label.configure(
            text=f"Effective: extract={extract} | subfiles={subfiles} | subfile_limit={limit} | strings={sm}"
        )

    def _refresh_path_status(self):
        rules_ok = looks_like_rules_dir(Path(self.rules_var.get().strip()))
        sigs_ok = looks_like_sigs_dir(Path(self.sigs_var.get().strip()))
        vt_set = bool(self.vt_api_key_var.get().strip())
        self.status_var.set(
            f"Rules: {'OK' if rules_ok else 'MISSING/INVALID'} | "
            f"Sigs: {'OK' if sigs_ok else 'MISSING/INVALID'} | "
            f"VirusTotal API key: {'SET' if vt_set else 'MISSING'}"
        )

    def _validate_inputs(self) -> Tuple[Path, str, Path, Path, Path]:
        sample = Path(self.sample_var.get().strip())
        if not sample.exists():
            raise FileNotFoundError(f"Sample not found:\n{sample}")
        case = self.case_var.get().strip() or sample.stem[:64]
        case_root = Path(self.case_root_var.get().strip())
        case_root.mkdir(parents=True, exist_ok=True)
        rules_raw = Path(self.rules_var.get().strip())
        sigs = Path(self.sigs_var.get().strip())
        if not looks_like_rules_dir(rules_raw):
            raise FileNotFoundError(f"capa rules folder invalid:\n{rules_raw}")
        rules = normalize_rules_dir(rules_raw)
        if not looks_like_sigs_dir(sigs):
            raise FileNotFoundError(f"capa sigs folder invalid:\n{sigs}")
        return sample, case, case_root, rules, sigs

    def _reset_progress(self):
        for w in self.steps_frame.winfo_children():
            w.destroy()
        self.step_widgets.clear()

        for i, step_key in enumerate(STEP_DISPLAY_ORDER):
            label = STEP_LABELS.get(step_key, step_key)
            ttk.Label(self.steps_frame, text=f"{label}:").grid(row=i, column=0, sticky="w")
            bar_var = tk.IntVar(value=0)
            ttk.Progressbar(
                self.steps_frame, orient="horizontal", mode="determinate",
                maximum=100, variable=bar_var
            ).grid(row=i, column=1, sticky="we", padx=8)
            status = ttk.Label(self.steps_frame, text="idle")
            status.grid(row=i, column=2, sticky="w")
            self.step_widgets[step_key] = {"var": bar_var, "status": status}

        self.overall_var.set(0)
        self.overall_text.configure(text="0%")
        self._recalc_overall()

    def _set_step(self, step_key: str, pct: int, status: str):
        w = self.step_widgets.get(step_key)
        if not w:
            return
        w["var"].set(max(0, min(100, pct)))
        color_map = {
            "done": "#22c55e",
            "running": "#3d86ff",
            "queued": "#9bb2d1",
            "n/a": "#6f87a8",
            "missing tool": "#f59e0b",
            "failed": "#ef4444",
            "idle": "#9bb2d1",
        }
        fg = color_map.get(status.lower(), "#eaf2ff")
        w["status"].configure(text=status, foreground=fg)

    def _recalc_overall(self):
        completed = 0
        resolved_statuses = {"done", "failed", "error", "skipped", "n/a"}
        for step_key in STEP_DISPLAY_ORDER:
            st = self.step_widgets[step_key]["status"].cget("text").strip().lower()
            if st in resolved_statuses:
                completed += 1
        pct = int(round((completed / max(1, len(STEP_DISPLAY_ORDER))) * 100))
        self.overall_var.set(pct)
        self.overall_text.configure(text=f"{pct}%")

    def _start_log_tail(self, case_dir: Path):
        self.static_controller.start_log_tail(case_dir)

    def _tail_analysis_log(self, log_path: Path):
        self.static_controller.tail_analysis_log(log_path)

    def _maybe_detect_case_dir_from_stdout(self, line: str):
        return self.static_controller.maybe_detect_case_dir_from_stdout(line)

    def _open_dynamic_window(self):
        if self.dynamic_window is not None and self.dynamic_window.winfo_exists():
            self.dynamic_window.lift()
            self.dynamic_window.focus_force()
            return
        self.dynamic_window = DynamicAnalysisWindow(self)
        self.dynamic_window.protocol(
            "WM_DELETE_WINDOW",
            lambda win=self.dynamic_window: (win.destroy(), setattr(self, "dynamic_window", None)),
        )

    def _start_analysis(self):
        self.static_controller.start_analysis()

    def _on_done(self, rc: int):
        self.static_controller.on_done(rc)

    def _drain_output(self):
        self.static_controller.drain_output()
