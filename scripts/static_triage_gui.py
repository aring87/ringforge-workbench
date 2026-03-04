#!/usr/bin/env python3
from __future__ import annotations

"""
scripts/static_triage_gui.py

Tkinter GUI for the static triage pipeline.

- Calls: static_triage_engine.engine.run_case(...)
- Uses on_event(event_type, step_name, payload) to update per-step progress bars

Features:
- Preset dropdown:
    - Fast Triage: strings-lite, subfile-limit=5, extraction on
    - Deep Triage: full strings, subfile-limit=25, extraction+recursion on
    - Hash Only: no strings, no extract, no subfiles
- Advanced toggle:
    - Show/hide advanced controls to override preset values
- Warning when "Skip strings" is enabled (IOC extraction depends on strings.txt)
"""

import sys
import threading
import time
import subprocess
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Ensure project root is on sys.path when running "python3 scripts/static_triage_gui.py"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import static_triage_engine.engine as static_triage  # noqa: E402

STEP_ORDER = [
    ("md5", "MD5"),
    ("sha1", "SHA1"),
    ("sha256", "SHA256"),
    ("extract", "Payload Extraction"),
    ("pe_meta", "PE Metadata"),
    ("lief_meta", "LIEF Metadata"),
    ("file", "file(1)"),
    ("strings", "strings"),
    ("capa", "capa"),
    ("iocs", "IOC Extraction"),
    ("report", "Report Generation"),
    ("case", "Finalize"),
]

PRESETS = ["Fast Triage", "Deep Triage", "Hash Only"]


class StaticTriageGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Static Malware Triage")
        self.geometry("980x800")

        self.sample_path = tk.StringVar(value="")
        self.case_name = tk.StringVar(value="")
        self.status_text = tk.StringVar(value="Ready.")
        self.running = False

        self.current_case_dir: Path | None = None
        self._step_vars: dict[str, tk.DoubleVar] = {}
        self._step_labels: dict[str, ttk.Label] = {}
        self._step_bars: dict[str, ttk.Progressbar] = {}

        # Preset + effective settings
        self.preset = tk.StringVar(value="Fast Triage")
        self.effective_settings = tk.StringVar(value="")

        # Settings (preset-driven, can be overridden via Advanced)
        self.enable_extract = tk.BooleanVar(value=True)
        self.enable_subfiles = tk.BooleanVar(value=True)
        self.subfile_limit = tk.IntVar(value=5)
        self.skip_strings = tk.BooleanVar(value=False)
        self.strings_lite = tk.BooleanVar(value=True)
        self.recursive_rounds = tk.IntVar(value=3)

        # Advanced toggle + warning
        self.advanced_visible = tk.BooleanVar(value=False)
        self._advanced_frame: ttk.Frame | None = None
        self._advanced_btn: ttk.Button | None = None
        self.advanced_warning = tk.StringVar(value="")

        self._build_ui()

        # Keep Effective line updated when advanced vars change
        for v in [
            self.enable_extract,
            self.enable_subfiles,
            self.subfile_limit,
            self.skip_strings,
            self.strings_lite,
            self.recursive_rounds,
        ]:
            v.trace_add("write", lambda *_: self._apply_effective_line_only())

        # Warning updates (Skip strings affects IOC extraction)
        self.skip_strings.trace_add("write", lambda *_: self._update_strings_warning())
        self.strings_lite.trace_add("write", lambda *_: self._update_strings_warning())

        self._apply_preset()
        self._update_strings_warning()

    # ----------------------------
    # UI
    # ----------------------------
    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)

        top = ttk.LabelFrame(root, text="Input", padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Sample:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.sample_path).grid(row=0, column=1, sticky="we", padx=(8, 8))
        ttk.Button(top, text="Browse…", command=self.browse_sample).grid(row=0, column=2, sticky="e")

        ttk.Label(top, text="Case name (optional):").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(top, textvariable=self.case_name).grid(row=1, column=1, sticky="we", padx=(8, 8), pady=(8, 0))
        ttk.Button(top, text="Run Analysis", command=self.run_analysis).grid(row=1, column=2, sticky="e", pady=(8, 0))

        ttk.Label(top, text="Preset:").grid(row=2, column=0, sticky="w", pady=(10, 0))
        preset_box = ttk.Combobox(top, textvariable=self.preset, values=PRESETS, state="readonly")
        preset_box.grid(row=2, column=1, sticky="w", padx=(8, 8), pady=(10, 0))
        preset_box.bind("<<ComboboxSelected>>", lambda _e: self._apply_preset())

        self._advanced_btn = ttk.Button(top, text="Advanced ▾", command=self._toggle_advanced)
        self._advanced_btn.grid(row=2, column=2, sticky="e", pady=(10, 0))

        ttk.Label(top, textvariable=self.effective_settings, foreground="#444").grid(
            row=3, column=1, sticky="w", padx=(8, 8), pady=(6, 0)
        )

        # Advanced panel (hidden by default)
        self._advanced_frame = ttk.LabelFrame(top, text="Advanced Settings", padding=10)
        af = self._advanced_frame

        ttk.Checkbutton(af, text="Enable extraction", variable=self.enable_extract).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(af, text="Enable subfiles triage", variable=self.enable_subfiles).grid(
            row=0, column=1, sticky="w", padx=(12, 0)
        )

        ttk.Label(af, text="Subfile limit:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Spinbox(af, from_=0, to=200, textvariable=self.subfile_limit, width=8).grid(
            row=1, column=1, sticky="w", padx=(12, 0), pady=(8, 0)
        )

        ttk.Checkbutton(af, text="Skip strings", variable=self.skip_strings).grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Checkbutton(af, text="Strings lite", variable=self.strings_lite).grid(
            row=2, column=1, sticky="w", padx=(12, 0), pady=(8, 0)
        )

        ttk.Label(af, text="Recursive rounds:").grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Spinbox(af, from_=0, to=10, textvariable=self.recursive_rounds, width=8).grid(
            row=3, column=1, sticky="w", padx=(12, 0), pady=(8, 0)
        )

        ttk.Label(af, textvariable=self.advanced_warning, foreground="#b45309").grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(10, 0)
        )

        af.columnconfigure(0, weight=1)
        af.columnconfigure(1, weight=1)

        top.columnconfigure(1, weight=1)

        # Progress
        prog = ttk.LabelFrame(root, text="Progress", padding=10)
        prog.pack(fill="x", pady=(12, 0))

        for i, (step_key, step_label) in enumerate(STEP_ORDER):
            var = tk.DoubleVar(value=0.0)
            self._step_vars[step_key] = var

            lbl = ttk.Label(prog, text=f"{step_label}: idle")
            lbl.grid(row=i, column=0, sticky="w", pady=2)
            self._step_labels[step_key] = lbl

            bar = ttk.Progressbar(prog, orient="horizontal", mode="determinate", maximum=100, variable=var)
            bar.grid(row=i, column=1, sticky="we", padx=(10, 0), pady=2)
            self._step_bars[step_key] = bar

        prog.columnconfigure(1, weight=1)

        # Actions
        actions = ttk.LabelFrame(root, text="Actions", padding=10)
        actions.pack(fill="x", pady=(12, 0))

        ttk.Button(actions, text="Open Case Folder", command=self.open_case_folder).pack(side="left")
        ttk.Button(actions, text="Open HTML Report", command=self.open_html_report).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Open PDF Report", command=self.open_pdf_report).pack(side="left", padx=(8, 0))
        ttk.Label(actions, textvariable=self.status_text).pack(side="right")

        # Log output
        logs = ttk.LabelFrame(root, text="Log Output", padding=10)
        logs.pack(fill="both", expand=True, pady=(12, 0))

        self.log_box = tk.Text(logs, height=18, wrap="word")
        self.log_box.pack(fill="both", expand=True)
        self.log_box.configure(state="disabled")

    # ----------------------------
    # Advanced toggle
    # ----------------------------
    def _toggle_advanced(self) -> None:
        if not self._advanced_frame or not self._advanced_btn:
            return

        show = not self.advanced_visible.get()
        self.advanced_visible.set(show)

        if show:
            self._advanced_frame.grid(row=4, column=1, columnspan=2, sticky="we", padx=(8, 0), pady=(10, 0))
            self._advanced_btn.configure(text="Advanced ▴")
        else:
            self._advanced_frame.grid_forget()
            self._advanced_btn.configure(text="Advanced ▾")

        self._apply_effective_line_only()
        self._update_strings_warning()

    # ----------------------------
    # Presets
    # ----------------------------
    def _apply_preset(self) -> None:
        p = self.preset.get().strip()

        if p == "Fast Triage":
            self.enable_extract.set(True)
            self.enable_subfiles.set(True)
            self.subfile_limit.set(5)
            self.skip_strings.set(False)
            self.strings_lite.set(True)
            self.recursive_rounds.set(3)

        elif p == "Deep Triage":
            self.enable_extract.set(True)
            self.enable_subfiles.set(True)
            self.subfile_limit.set(25)
            self.skip_strings.set(False)
            self.strings_lite.set(False)
            self.recursive_rounds.set(3)

        elif p == "Hash Only":
            self.enable_extract.set(False)
            self.enable_subfiles.set(False)
            self.subfile_limit.set(0)
            self.skip_strings.set(True)
            self.strings_lite.set(False)
            self.recursive_rounds.set(0)

        self._apply_effective_line_only()
        self._update_strings_warning()

    def _apply_effective_line_only(self) -> None:
        self.effective_settings.set(
            f"Effective: extract={self.enable_extract.get()} | subfiles={self.enable_subfiles.get()} "
            f"| subfile_limit={self.subfile_limit.get()} | strings={'SKIP' if self.skip_strings.get() else ('LITE' if self.strings_lite.get() else 'FULL')} "
            f"| recursion_rounds={self.recursive_rounds.get()}"
        )

    def _update_strings_warning(self) -> None:
        if self.skip_strings.get():
            if self.strings_lite.get():
                self.strings_lite.set(False)
            self.advanced_warning.set("⚠ Skip strings is ON: IOC extraction will be limited (strings.txt not generated).")
        else:
            self.advanced_warning.set("")

    # ----------------------------
    # Helpers
    # ----------------------------
    def log(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"
        self.log_box.configure(state="normal")
        self.log_box.insert("end", line)
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def reset_progress(self) -> None:
        label_map = {k: v for k, v in STEP_ORDER}
        for step_key, _ in STEP_ORDER:
            self._step_vars[step_key].set(0.0)
            self._step_labels[step_key].configure(text=f"{label_map[step_key]}: idle")

    def set_step_state(self, step: str, state: str, pct: float | None = None) -> None:
        label_map = {k: v for k, v in STEP_ORDER}
        if step not in label_map:
            return
        if pct is not None:
            self._step_vars[step].set(max(0.0, min(100.0, float(pct))))
        self._step_labels[step].configure(text=f"{label_map[step]}: {state}")

    # ----------------------------
    # Button actions
    # ----------------------------
    def browse_sample(self) -> None:
        p = filedialog.askopenfilename(
            title="Choose an EXE/DLL",
            filetypes=[("Windows executables", "*.exe *.dll"), ("All files", "*.*")],
        )
        if p:
            self.sample_path.set(p)
            if not self.case_name.get().strip():
                self.case_name.set(Path(p).stem)

    def run_analysis(self) -> None:
        if self.running:
            messagebox.showinfo("Running", "Analysis is already running.")
            return

        sample = self.sample_path.get().strip()
        if not sample:
            messagebox.showwarning("Missing sample", "Choose a sample file first.")
            return
        if not Path(sample).exists():
            messagebox.showerror("Not found", f"File does not exist:\n{sample}")
            return

        case = self.case_name.get().strip() or None

        self.running = True
        self.current_case_dir = None
        self.reset_progress()
        self.status_text.set("Running…")
        self.log(
            f"Starting analysis: sample={sample} case={case or '(auto)'} preset={self.preset.get()} "
            f"(extract={self.enable_extract.get()} subfiles={self.enable_subfiles.get()} "
            f"limit={self.subfile_limit.get()} skip_strings={self.skip_strings.get()} "
            f"lite={self.strings_lite.get()} rounds={self.recursive_rounds.get()})"
        )

        t = threading.Thread(target=self._run_worker, args=(sample, case), daemon=True)
        t.start()

    def open_case_folder(self) -> None:
        if not self.current_case_dir:
            messagebox.showwarning("No case", "Run an analysis first.")
            return
        try:
            subprocess.Popen(["xdg-open", str(self.current_case_dir)])
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def open_html_report(self) -> None:
        if not self.current_case_dir:
            messagebox.showwarning("No case", "Run an analysis first.")
            return
        html_path = self.current_case_dir / "report.html"
        if not html_path.exists():
            messagebox.showerror("Missing report", f"Not found:\n{html_path}")
            return
        try:
            subprocess.Popen(["xdg-open", str(html_path)])
        except Exception:
            webbrowser.open(f"file://{html_path}")

    def open_pdf_report(self) -> None:
        if not self.current_case_dir:
            messagebox.showwarning("No case", "Run an analysis first.")
            return

        pdf_path = self.current_case_dir / "report.pdf"
        html_path = self.current_case_dir / "report.html"

        try:
            if pdf_path.exists():
                subprocess.Popen(["xdg-open", str(pdf_path)])
            elif html_path.exists():
                subprocess.Popen(["xdg-open", str(html_path)])
            else:
                messagebox.showerror("Missing report", "No report.pdf or report.html found in the case folder.")
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    # ----------------------------
    # Engine worker + callback
    # ----------------------------
    def _on_event(self, event_type: str, step: str, payload: dict) -> None:
        def apply() -> None:
            if event_type == "start":
                self.set_step_state(step, "running", 10.0)
            elif event_type == "done":
                self.set_step_state(step, "done", 100.0)
                if step == "case":
                    cd = payload.get("case_dir")
                    if cd:
                        self.current_case_dir = Path(cd)
            elif event_type == "error":
                self.set_step_state(step, "error", 100.0)
            elif event_type == "info":
                if step == "case":
                    cd = payload.get("case_dir")
                    if cd:
                        self.current_case_dir = Path(cd)

            if event_type in ("start", "done", "error"):
                extra = ""
                if isinstance(payload, dict):
                    if "returncode" in payload:
                        extra += f" rc={payload.get('returncode')}"
                    if "stderr" in payload and payload.get("stderr"):
                        extra += f" err={str(payload.get('stderr'))[:120]}"
                self.log(f"{event_type.upper():5} step={step}{extra}")

        self.after(0, apply)

    def _run_worker(self, sample: str, case: str | None) -> None:
        try:
            result = static_triage.run_case(
                sample,
                case_name=case,
                show_progress=False,
                on_event=self._on_event,
                enable_payload_extraction=bool(self.enable_extract.get()),
                triage_extracted_pes=bool(self.enable_subfiles.get()),
                subfile_limit=int(self.subfile_limit.get()),
                recursive_rounds=int(self.recursive_rounds.get()),
                skip_strings=bool(self.skip_strings.get()),
                strings_lite=bool(self.strings_lite.get()),
            )
            cd = result.get("case_dir")
            if cd:
                self.current_case_dir = Path(cd)

            verdict = result.get("verdict")
            score = result.get("risk_score")
            pdf = result.get("report_pdf")

            self.after(
                0,
                lambda: self.status_text.set(f"Done. Verdict={verdict} Score={score} PDF={'yes' if pdf else 'no'}"),
            )
            self.after(0, lambda: self.log(f"Completed: verdict={verdict} score={score} case_dir={cd}"))
        except Exception as e:
            self.after(0, lambda: self.status_text.set("Failed."))
            self.after(0, lambda: self.log(f"[!] ERROR: {e}"))
            self.after(0, lambda: messagebox.showerror("Analysis failed", str(e)))
        finally:
            self.running = False


def main() -> None:
    app = StaticTriageGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
