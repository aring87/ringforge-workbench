"""
Static Triage GUI (v10) — Fix progress parsing for timestamped analysis.log lines

Your analysis.log lines look like:
  2026-03-05T23:57:18Z STEP_START md5
  2026-03-05T23:57:18Z STEP_DONE md5 rc=0 dur=0.028
So we cannot use line.startswith("STEP_START ").
v8 parses STEP_* markers anywhere in the line via regex.

Keeps everything from v7:
- Fixed classic progress bars
- Reads analysis.log from start
- Case_dir auto-detect from stdout + fallback tailer
- Case output selector + tool selectors + advanced settings
- UTF-8 safe streaming
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from html import escape
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from dynamic_analysis.orchestrator import run_dynamic_analysis
from dynamic_analysis.html_report import write_dynamic_html_report


def app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


ROOT = app_root()
CONFIG_PATH = ROOT / "config.json"

DEFAULT_CASE_ROOT = ROOT / "cases"
DEFAULT_RULES_DIR = ROOT / "tools" / "capa-rules" / "rules"
DEFAULT_SIGS_DIR = ROOT / "tools" / "capa" / "sigs"

CLI_SCRIPT = ROOT / "scripts" / "static_triage.py"


STEP_DISPLAY_ORDER: List[str] = [
    "md5",
    "sha1",
    "sha256",
    "extract",
    "pe_meta",
    "lief_meta",
    "file",
    "strings",
    "capa",
    "iocs",
    "report",
    "finalize",
]

STEP_LABELS: Dict[str, str] = {
    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256",
    "extract": "Payload Extraction",
    "pe_meta": "PE Metadata",
    "lief_meta": "LIEF Analysis",
    "file": "File Type (Linux tool / optional on Windows)",
    "strings": "Strings (Linux tool / optional on Windows)",
    "capa": "CAPA",
    "iocs": "IOC Extraction",
    "report": "Report Generation (PDF optional on Windows)",
    "finalize": "Finalize",
}

STEP_NAME_MAP: Dict[str, str] = {
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "extract": "extract",
    "pe_meta": "pe_meta",
    "lief_meta": "lief_meta",
    "file": "file",
    "file1": "file",
    "strings": "strings",
    "capa": "capa",
    "iocs": "iocs",
    "report": "report",
    "finalize": "finalize",
}

# Parse timestamped log lines
# Example: "2026-03-05T23:57:18Z STEP_DONE sha256 rc=0 dur=0.014"
STEP_START_RE = re.compile(r"\bSTEP_START\b\s+(?P<step>\S+)")
STEP_DONE_RE  = re.compile(r"\bSTEP_DONE\b\s+(?P<step>\S+)")
STEP_FAIL_RE  = re.compile(r"\bSTEP_FAIL\b\s+(?P<step>\S+)")

# Case dir detection from stdout (optional)
CASE_DIR_RE = re.compile(r'(?:\bcase_dir\b\s*[=:]\s*)(?P<p>[^"\'\r\n]+)', re.IGNORECASE)
CASE_LINE_RE = re.compile(r"^\s*\[\+\]\s*Case:\s*(?P<p>.+?)\s*$", re.IGNORECASE)
REPORT_STDOUT_MDHTML_RE = re.compile(r"\breport\.(md|html)\s*:\s*(?P<p>.+)$", re.IGNORECASE)
REPORT_STDOUT_PDF_RE = re.compile(r"\breport\.pdf\s*:\s*(?P<p>.+)$", re.IGNORECASE)


def norm_path_str(p: str) -> str:
    try:
        return str(Path(p))
    except Exception:
        return p


def normalize_rules_dir(p: Path) -> Path:
    if (p / "rules").is_dir():
        return p / "rules"
    return p


def looks_like_rules_dir(p: Path) -> bool:
    p2 = normalize_rules_dir(p)
    return p2.is_dir() and (any(p2.rglob("*.yml")) or any(p2.rglob("*.yaml")))


def looks_like_sigs_dir(p: Path) -> bool:
    return p.is_dir() and any(p.glob("*.sig"))


def load_config() -> Dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_config(cfg: Dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


@dataclass
class Preset:
    name: str
    extract: bool
    subfiles: bool
    subfile_limit: int
    strings_mode: str  # FULL | LITE | SKIP


PRESETS: List[Preset] = [
    Preset("Fast Triage", extract=True, subfiles=True, subfile_limit=5, strings_mode="LITE"),
    Preset("Deep Triage", extract=True, subfiles=True, subfile_limit=25, strings_mode="FULL"),
    Preset("Hash Only", extract=False, subfiles=False, subfile_limit=0, strings_mode="SKIP"),
]


def build_cli_args(sample_path: Path, case_name: str, extract: bool, subfiles: bool, subfile_limit: int, strings_mode: str) -> List[str]:
    args = [str(CLI_SCRIPT), str(sample_path), "--case", case_name, "--no-progress"]
    if not extract:
        args.append("--no-extract")
    if not subfiles:
        args.append("--no-subfiles")
    if subfiles and subfile_limit:
        args += ["--subfile-limit", str(subfile_limit)]
    sm = strings_mode.upper()
    if sm == "LITE":
        args.append("--strings-lite")
    elif sm == "SKIP":
        args.append("--no-strings")
    return args


def choose_python_exe() -> Path:
    if os.name == "nt":
        venv_py = ROOT / ".venv" / "Scripts" / "python.exe"
    else:
        venv_py = ROOT / ".venv" / "bin" / "python"
    if venv_py.exists():
        return venv_py
    return Path(sys.executable)


def run_cli_streaming(python_exe: Path, args: List[str], env_overrides: Dict[str, str], output_q: "queue.Queue[str]") -> int:
    env = os.environ.copy()
    env.update(env_overrides)
    env.setdefault("PYTHONIOENCODING", "utf-8")

    proc = subprocess.Popen(
        [str(python_exe)] + args,
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        output_q.put(line.rstrip("\n"))
    return proc.wait()




class DynamicAnalysisWindow(tk.Toplevel):
    def __init__(self, app: "App"):
        super().__init__(app)
        self.app = app
        self.title("Dynamic Analysis")
        self.geometry("980x720")
        self.minsize(840, 620)

        cfg = app.cfg
        default_case = str(DEFAULT_CASE_ROOT / "dynamic_case")
        self.sample_var = tk.StringVar(value=app.sample_var.get().strip())
        self.case_dir_var = tk.StringVar(value=cfg.get("dynamic_case_dir", default_case))
        self.timeout_var = tk.IntVar(value=int(cfg.get("dynamic_timeout_seconds", 30)))
        self.procmon_enabled_var = tk.BooleanVar(value=bool(cfg.get("dynamic_procmon_enabled", True)))
        self.procmon_path_var = tk.StringVar(value=cfg.get("dynamic_procmon_path", str(ROOT / "tools" / "Procmon64.exe")))
        self.procmon_config_var = tk.StringVar(value=cfg.get("dynamic_procmon_config_path", str(ROOT / "tools" / "procmon-configs" / "dynamic_default.pmc")))
        self.status_var = tk.StringVar(value="Idle")
        self.last_api_dir: Optional[Path] = None
        self.last_html_report: Optional[Path] = None
        self.last_json_report: Optional[Path] = None
        self.last_response_payload: Optional[dict] = None

        self.output_q: "queue.Queue[str]" = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None

        self._build_ui()
        self.after(150, self._drain_output)

        self.transient(app)
        self.grab_set()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 8}

        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, **pad)
        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(6, weight=1)

        ttk.Label(frm, text="Sample:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.sample_var, width=100).grid(row=0, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Use Main Sample", command=self._use_main_sample).grid(row=0, column=2, sticky="e")

        ttk.Label(frm, text="Dynamic case folder:").grid(row=1, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.case_dir_var, width=100).grid(row=1, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Browse…", command=self._browse_case_dir).grid(row=1, column=2, sticky="e")

        ttk.Label(frm, text="Timeout (seconds):").grid(row=2, column=0, sticky="w")
        ttk.Spinbox(frm, from_=5, to=7200, textvariable=self.timeout_var, width=10).grid(row=2, column=1, sticky="w", padx=6)
        ttk.Checkbutton(frm, text="Enable Procmon Capture", variable=self.procmon_enabled_var).grid(row=2, column=2, sticky="e")

        ttk.Label(frm, text="Procmon path:").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.procmon_path_var, width=100).grid(row=3, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Browse…", command=self._browse_procmon).grid(row=3, column=2, sticky="e")

        ttk.Label(frm, text="Procmon config:").grid(row=4, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.procmon_config_var, width=100).grid(row=4, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Browse…", command=self._browse_procmon_config).grid(row=4, column=2, sticky="e")

        actions = ttk.Frame(frm)
        actions.grid(row=5, column=0, columnspan=3, sticky="we", pady=(6, 0))
        self.run_btn = ttk.Button(actions, text="Run Dynamic Analysis", command=self._start_dynamic_analysis)
        self.run_btn.pack(side="left")
        ttk.Button(actions, text="Open Case Folder", command=self._open_case_folder).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="Export HTML/PDF Report", command=self._export_dynamic_report).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="Open Latest HTML", command=self._open_latest_dynamic_html).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="API Analysis", command=self.app.open_api_analysis_window).pack(side="left", padx=(10, 0))
        ttk.Label(actions, textvariable=self.status_var).pack(side="right")

        outwrap = ttk.LabelFrame(frm, text="Output")
        outwrap.grid(row=6, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
        outwrap.columnconfigure(0, weight=1)
        outwrap.rowconfigure(0, weight=1)

        self.output = tk.Text(
            outwrap,
            wrap="word",
            height=22,
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
        )
        self.output.grid(row=0, column=0, sticky="nsew")
        ysb = ttk.Scrollbar(outwrap, orient="vertical", command=self.output.yview)
        ysb.grid(row=0, column=1, sticky="ns")
        self.output.configure(yscrollcommand=ysb.set)

    def _save_cfg(self):
        self.app.cfg["dynamic_case_dir"] = self.case_dir_var.get().strip()
        self.app.cfg["dynamic_timeout_seconds"] = int(self.timeout_var.get())
        self.app.cfg["dynamic_procmon_enabled"] = bool(self.procmon_enabled_var.get())
        self.app.cfg["dynamic_procmon_path"] = self.procmon_path_var.get().strip()
        self.app.cfg["dynamic_procmon_config_path"] = self.procmon_config_var.get().strip()
        save_config(self.app.cfg)

    def _use_main_sample(self):
        self.sample_var.set(self.app.sample_var.get().strip())

    def _browse_case_dir(self):
        start = Path(self.case_dir_var.get()) if self.case_dir_var.get().strip() else DEFAULT_CASE_ROOT
        chosen = filedialog.askdirectory(title="Select dynamic case folder", initialdir=str(start))
        if chosen:
            self.case_dir_var.set(norm_path_str(chosen))
            self._save_cfg()

    def _browse_procmon(self):
        start = Path(self.procmon_path_var.get()).parent if self.procmon_path_var.get().strip() else (ROOT / "tools")
        chosen = filedialog.askopenfilename(
            title="Select Procmon executable",
            initialdir=str(start),
            filetypes=[("Executable", "*.exe"), ("All Files", "*.*")],
        )
        if chosen:
            self.procmon_path_var.set(norm_path_str(chosen))
            self._save_cfg()

    def _browse_procmon_config(self):
        raw = self.procmon_config_var.get().strip()
        start = Path(raw).parent if raw else (ROOT / "tools" / "procmon-configs")
        chosen = filedialog.askopenfilename(
            title="Select Procmon config (.pmc)",
            initialdir=str(start),
            filetypes=[("Procmon Config", "*.pmc"), ("All Files", "*.*")],
        )
        if chosen:
            self.procmon_config_var.set(norm_path_str(chosen))
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
            candidate_paths = [
                reports_dir / "dynamic_run_summary.json",
                reports_dir / "run_summary.json",
                case_dir / "dynamic_run_summary.json",
                case_dir / "run_summary.json",
                case_dir / "metadata" / "run_summary.json",
            ]
            summary_path = next((p for p in candidate_paths if p.exists()), None)
            if not summary_path:
                messagebox.showerror(
                    "Export Report",
                    "Summary file not found.\n\nChecked:\n" + "\n".join(str(p) for p in candidate_paths),
                    parent=self,
                )
                return

            reports_dir.mkdir(parents=True, exist_ok=True)
            output_html = reports_dir / "dynamic_report.html"
            write_dynamic_html_report(summary_path, output_html)

            pdf_created = False
            pdf_path = reports_dir / "dynamic_report.pdf"
            try:
                from weasyprint import HTML
                HTML(filename=str(output_html)).write_pdf(str(pdf_path))
                pdf_created = True
            except Exception as e:
                pdf_created = False
                messagebox.showwarning(
                    "PDF Export",
                    "HTML report was created successfully, but PDF export is unavailable on this system.\n\n"
                    f"WeasyPrint error:\n{e}\n\n"
                    "You can open the HTML report and print it to PDF from your browser.",
                    parent=self,
                )

            webbrowser.open(output_html.resolve().as_uri())
            if pdf_created:
                messagebox.showinfo(
                    "Export Report",
                    f"HTML and PDF report created:\n\nHTML: {output_html}\nPDF: {pdf_path}",
                    parent=self,
                )
            else:
                messagebox.showinfo(
                    "Export Report",
                    f"HTML report created:\n\n{output_html}\n\nPDF was not created. Install weasyprint for PDF export.",
                    parent=self,
                )
        except Exception as e:
            messagebox.showerror("Export Report", str(e), parent=self)

    def _open_latest_dynamic_html(self):
        try:
            case_dir = Path(self.case_dir_var.get().strip())
            html_path = case_dir / "reports" / "dynamic_report.html"
            if not html_path.exists():
                messagebox.showerror("Open Report", f"HTML report not found:\n{html_path}", parent=self)
                return
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
        self.output.delete("1.0", "end")
        self.output.insert("end", "Starting dynamic analysis:\n")
        self.output.insert("end", f"  sample={sample}\n")
        self.output.insert("end", f"  case_dir={case_dir}\n")
        self.output.insert("end", f"  timeout_seconds={timeout_seconds}\n")
        self.output.insert("end", f"  procmon_enabled={config['procmon_enabled']}\n\n")
        self.output.see("end")

        self.status_var.set("Running dynamic…")
        self.run_btn.configure(state="disabled")

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
                self.output_q.put(f"[error] {e}")
                self.after(0, lambda err=str(e): self._on_error(err))
                
        # Start the background worker thread for dynamic analysis
        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()
        
    def _on_done(self, summary: Dict):
        self.run_btn.configure(state="normal")
        self.status_var.set("Idle")
        exit_code = summary.get("exit_code")
        if exit_code == 0:
            messagebox.showinfo("Completed", "Dynamic analysis completed successfully.", parent=self)
        else:
            messagebox.showwarning(
                "Completed",
                f"Dynamic analysis completed. Sample exited with code {exit_code}.",
                parent=self,
            )

    def _on_error(self, err: str):
        self.run_btn.configure(state="normal")
        self.status_var.set("Idle")
        messagebox.showerror("Dynamic Analysis failed", err, parent=self)

    def _drain_output(self):
        try:
            while True:
                line = self.output_q.get_nowait()
                self.output.insert("end", line + "\n")
                self.output.see("end")
        except queue.Empty:
            pass
        self.after(150, self._drain_output)


class APIAnalysisWindow(tk.Toplevel):
    PRESET_NAMES = [
        "Custom",
        "HTTPBin GET Test",
        "HTTPBin POST Test",
        "VirusTotal File Lookup",
        "VirusTotal File Upload",
        "AbuseIPDB Check IP",
        "urlscan Search",
        "Shodan Host Lookup",
    ]

    def __init__(self, app: "App"):
        super().__init__(app)
        self.app = app
        self.title("API Analysis")
        self.geometry("1120x860")
        self.minsize(940, 720)

        self.preset_var = tk.StringVar(value="HTTPBin GET Test")
        self.method_var = tk.StringVar(value="GET")
        self.url_var = tk.StringVar(value="")
        self.timeout_var = tk.IntVar(value=60)
        self.file_path_var = tk.StringVar(value="")
        self.file_field_var = tk.StringVar(value="file")
        self.status_var = tk.StringVar(value="Idle")
        self.last_api_dir: Optional[Path] = None
        self.last_html_report: Optional[Path] = None
        self.last_json_report: Optional[Path] = None
        self.last_response_payload: Optional[dict] = None

        self.output_q: "queue.Queue[str]" = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None

        self._build_ui()
        self._apply_preset(initial=True)
        self.after(150, self._drain_output)

        self.transient(app)
        self.grab_set()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 8}
        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, **pad)
        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(7, weight=1)

        ttk.Label(frm, text="Preset:").grid(row=0, column=0, sticky="w")
        ttk.Combobox(frm, textvariable=self.preset_var, values=self.PRESET_NAMES, state="readonly", width=28).grid(row=0, column=1, sticky="w", padx=6)
        ttk.Button(frm, text="Load Preset", command=self._apply_preset).grid(row=0, column=2, sticky="w")

        ttk.Label(frm, text="Method:").grid(row=1, column=0, sticky="w")
        ttk.Combobox(frm, textvariable=self.method_var, values=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"], state="readonly", width=12).grid(row=1, column=1, sticky="w", padx=6)
        ttk.Label(frm, text="Timeout (sec):").grid(row=1, column=2, sticky="e")
        ttk.Spinbox(frm, from_=1, to=300, textvariable=self.timeout_var, width=8).grid(row=1, column=3, sticky="w", padx=6)

        ttk.Label(frm, text="URL:").grid(row=2, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.url_var, width=112).grid(row=2, column=1, columnspan=3, sticky="we", padx=6)

        ttk.Label(frm, text="Upload file:").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.file_path_var, width=92).grid(row=3, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Browse…", command=self._browse_upload_file).grid(row=3, column=2, sticky="w")
        field_wrap = ttk.Frame(frm)
        field_wrap.grid(row=3, column=3, sticky="w")
        ttk.Label(field_wrap, text="Field:").pack(side="left")
        ttk.Entry(field_wrap, textvariable=self.file_field_var, width=10).pack(side="left", padx=(6, 0))

        hints = ttk.LabelFrame(frm, text="Preset Notes")
        hints.grid(row=4, column=0, columnspan=4, sticky="we", pady=(8, 0))
        hints.columnconfigure(0, weight=1)
        self.notes_var = tk.StringVar(value="")
        ttk.Label(hints, textvariable=self.notes_var, wraplength=1000, justify="left").grid(row=0, column=0, sticky="w", padx=8, pady=8)

        req_wrap = ttk.LabelFrame(frm, text="Request")
        req_wrap.grid(row=5, column=0, columnspan=4, sticky="nsew", pady=(8, 0))
        req_wrap.columnconfigure(0, weight=1)
        req_wrap.columnconfigure(1, weight=1)
        req_wrap.rowconfigure(1, weight=1)
        ttk.Label(req_wrap, text="Headers (JSON):").grid(row=0, column=0, sticky="w", padx=8, pady=(8, 4))
        ttk.Label(req_wrap, text="Body / form fields (JSON or raw text):").grid(row=0, column=1, sticky="w", padx=8, pady=(8, 4))
        text_kwargs = dict(wrap="word", height=12, bg="#0d1b33", fg="#eaf2ff", insertbackground="#eaf2ff", selectbackground="#1f6fff", selectforeground="white", relief="flat", borderwidth=0, highlightthickness=1, highlightbackground="#2a4365", highlightcolor="#3d86ff", font=("Consolas", 10))
        self.headers_text = tk.Text(req_wrap, **text_kwargs)
        self.headers_text.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=(0, 8))
        self.body_text = tk.Text(req_wrap, **text_kwargs)
        self.body_text.grid(row=1, column=1, sticky="nsew", padx=(4, 8), pady=(0, 8))

        actions = ttk.Frame(frm)
        actions.grid(row=6, column=0, columnspan=4, sticky="we", pady=(8, 0))
        self.send_btn = ttk.Button(actions, text="Send Request", command=self._start_request)
        self.send_btn.pack(side="left")
        ttk.Button(actions, text="Clear", command=self._clear_fields).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="Save HTML Report", command=self._save_current_html_report).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="Open HTML Report", command=self._open_latest_html).pack(side="left", padx=(10, 0))
        ttk.Label(actions, textvariable=self.status_var).pack(side="right")

        out_wrap = ttk.LabelFrame(frm, text="Response")
        out_wrap.grid(row=7, column=0, columnspan=4, sticky="nsew", pady=(8, 0))
        out_wrap.columnconfigure(0, weight=1)
        out_wrap.rowconfigure(0, weight=1)
        self.output = tk.Text(out_wrap, wrap="none", height=20, bg="#0d1b33", fg="#eaf2ff", insertbackground="#eaf2ff", selectbackground="#1f6fff", selectforeground="white", relief="flat", borderwidth=0, highlightthickness=1, highlightbackground="#2a4365", highlightcolor="#3d86ff", font=("Consolas", 10))
        self.output.grid(row=0, column=0, sticky="nsew")
        ysb = ttk.Scrollbar(out_wrap, orient="vertical", command=self.output.yview)
        ysb.grid(row=0, column=1, sticky="ns")
        self.output.configure(yscrollcommand=ysb.set)

    def _default_headers(self) -> dict:
        return {"User-Agent": "RingForge-Analyzer/1.0"}

    def _app_vt_key(self) -> str:
        return self.app.vt_api_key_var.get().strip() if hasattr(self.app, "vt_api_key_var") else ""

    def _preset_map(self) -> dict:
        vt_key = self._app_vt_key()
        return {
            "Custom": {"method": "GET", "url": "", "headers": self._default_headers(), "body": "", "notes": "Custom request. Enter any URL, headers, body, and optional file upload."},
            "HTTPBin GET Test": {"method": "GET", "url": "https://httpbin.org/get", "headers": self._default_headers(), "body": "", "notes": "Best first test. This should return HTTP 200 with a JSON echo of your request.", "file_path": "", "file_field": "file"},
            "HTTPBin POST Test": {"method": "POST", "url": "https://httpbin.org/post", "headers": {**self._default_headers(), "Content-Type": "application/json"}, "body": {"sample": "whoami.exe", "test": True}, "notes": "Simple POST validation. Useful to confirm JSON body handling works.", "file_path": "", "file_field": "file"},
            "VirusTotal File Lookup": {"method": "GET", "url": "https://www.virustotal.com/api/v3/files/<sha256>", "headers": {**self._default_headers(), "x-apikey": vt_key or "<YOUR_VT_API_KEY>"}, "body": "", "notes": "Replace <sha256> with a real SHA256. This uses your main GUI VirusTotal key if you already entered one.", "file_path": "", "file_field": "file"},
            "VirusTotal File Upload": {"method": "POST", "url": "https://www.virustotal.com/api/v3/files", "headers": {**self._default_headers(), "x-apikey": vt_key or "<YOUR_VT_API_KEY>"}, "body": {}, "notes": "Choose an executable or similar file to upload. This sends multipart/form-data to VirusTotal.", "file_path": "", "file_field": "file"},
            "AbuseIPDB Check IP": {"method": "GET", "url": "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90&verbose", "headers": {**self._default_headers(), "Key": "<YOUR_ABUSEIPDB_KEY>", "Accept": "application/json"}, "body": "", "notes": "Replace the IP and key. Good for checking whether your headers and querystring handling work.", "file_path": "", "file_field": "file"},
            "urlscan Search": {"method": "GET", "url": "https://urlscan.io/api/v1/search/?q=domain:example.com", "headers": self._default_headers(), "body": "", "notes": "Replace example.com. Useful for testing a search-style API request.", "file_path": "", "file_field": "file"},
            "Shodan Host Lookup": {"method": "GET", "url": "https://api.shodan.io/shodan/host/8.8.8.8?key=<YOUR_SHODAN_KEY>", "headers": self._default_headers(), "body": "", "notes": "Replace the IP and API key. Good for quick host lookup testing.", "file_path": "", "file_field": "file"},
        }

    def _apply_preset(self, initial: bool = False):
        preset = self.preset_var.get().strip() or "Custom"
        presets = self._preset_map()
        data = presets.get(preset, presets["Custom"])
        self.method_var.set(data["method"])
        self.url_var.set(data["url"])
        self.file_path_var.set(data.get("file_path", ""))
        self.file_field_var.set(data.get("file_field", "file"))
        self.headers_text.delete("1.0", "end")
        self.body_text.delete("1.0", "end")
        self.headers_text.insert("1.0", json.dumps(data["headers"], indent=2))
        if isinstance(data["body"], (dict, list)):
            self.body_text.insert("1.0", json.dumps(data["body"], indent=2))
        else:
            self.body_text.insert("1.0", str(data["body"]))
        self.notes_var.set(data["notes"])
        if not initial:
            self.status_var.set(f"Loaded preset: {preset}")

    def _browse_upload_file(self):
        start = Path(self.file_path_var.get()).parent if self.file_path_var.get().strip() else ROOT
        chosen = filedialog.askopenfilename(title="Select file to upload", initialdir=str(start))
        if chosen:
            self.file_path_var.set(norm_path_str(chosen))

    def _clear_fields(self):
        self.url_var.set("")
        self.file_path_var.set("")
        self.file_field_var.set("file")
        self.headers_text.delete("1.0", "end")
        self.body_text.delete("1.0", "end")
        self.output.delete("1.0", "end")
        self.headers_text.insert("1.0", json.dumps(self._default_headers(), indent=2))
        self.notes_var.set("")
        self.status_var.set("Idle")

    def _parse_headers_and_body(self):
        headers_raw = self.headers_text.get("1.0", "end").strip()
        body_raw = self.body_text.get("1.0", "end").strip()
        try:
            headers = json.loads(headers_raw) if headers_raw else {}
            if not isinstance(headers, dict):
                raise ValueError("Headers must be a JSON object.")
        except Exception as e:
            raise ValueError(f"Invalid headers JSON:\n{e}")
        body_data = ""
        if body_raw:
            try:
                body_data = json.loads(body_raw)
            except Exception:
                body_data = body_raw
        return headers, body_data

    def _current_case_name(self) -> str:
        case_name = self.app.case_var.get().strip() if hasattr(self.app, "case_var") else ""
        if case_name:
            return case_name
        sample = self.app.sample_var.get().strip() if hasattr(self.app, "sample_var") else ""
        if sample:
            return Path(sample).stem[:64]
        return "api_case"

    def _ensure_api_dir(self) -> Path:
        case_root = Path(self.app.case_root_var.get().strip()) if hasattr(self.app, "case_root_var") else (ROOT / "cases")
        case_root.mkdir(parents=True, exist_ok=True)
        case_dir = case_root / self._current_case_name()
        case_dir.mkdir(parents=True, exist_ok=True)
        api_dir = case_dir / "api"
        api_dir.mkdir(parents=True, exist_ok=True)
        self.last_api_dir = api_dir
        return api_dir

    def _render_api_html(self, payload: dict) -> str:
        response = payload.get("response", {})
        headers_html = "".join(
            f"<tr><td>{escape(str(k))}</td><td>{escape(str(v))}</td></tr>"
            for k, v in response.get("headers", {}).items()
        ) or "<tr><td colspan='2'>No headers</td></tr>"
        request_headers_html = "".join(
            f"<tr><td>{escape(str(k))}</td><td>{escape(str(v))}</td></tr>"
            for k, v in payload.get("request", {}).get("headers", {}).items()
        ) or "<tr><td colspan='2'>No headers</td></tr>"
        body_text = payload.get("response", {}).get("body_text", "")
        return f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<title>API Test Report</title>
<style>
body {{ background:#081426; color:#eaf2ff; font-family:Segoe UI,Arial,sans-serif; margin:24px; }}
h1,h2 {{ color:#7db3ff; }}
.card {{ background:#0d1b33; border:1px solid #2a4365; border-radius:10px; padding:16px; margin-bottom:18px; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ border:1px solid #2a4365; padding:8px; text-align:left; vertical-align:top; }}
th {{ background:#13284a; }}
pre {{ white-space:pre-wrap; word-wrap:break-word; background:#0b1730; border:1px solid #2a4365; padding:12px; border-radius:8px; }}
.kv {{ margin:4px 0; }}
</style>
</head>
<body>
<h1>API Test Report</h1>
<div class='card'>
<div class='kv'><strong>Saved:</strong> {escape(str(payload.get("saved_at", "")))}</div>
<div class='kv'><strong>Preset:</strong> {escape(str(payload.get("preset", "")))}</div>
<div class='kv'><strong>Method:</strong> {escape(str(payload.get("request", {}).get("method", "")))}</div>
<div class='kv'><strong>URL:</strong> {escape(str(payload.get("request", {}).get("url", "")))}</div>
<div class='kv'><strong>Upload file:</strong> {escape(str(payload.get("request", {}).get("upload_file", "none")))}</div>
<div class='kv'><strong>Status:</strong> {escape(str(response.get("status_code", "")))} {escape(str(response.get("reason", "")))}</div>
</div>
<div class='card'>
<h2>Request Headers</h2>
<table><tr><th>Header</th><th>Value</th></tr>{request_headers_html}</table>
</div>
<div class='card'>
<h2>Response Headers</h2>
<table><tr><th>Header</th><th>Value</th></tr>{headers_html}</table>
</div>
<div class='card'>
<h2>Response Body</h2>
<pre>{escape(body_text)}</pre>
</div>
</body>
</html>"""

    def _save_api_artifacts(self, payload: dict) -> tuple[Path, Path]:
        api_dir = self._ensure_api_dir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = api_dir / f"api_response_{timestamp}.json"
        html_path = api_dir / f"api_response_{timestamp}.html"
        latest_json = api_dir / "api_response_latest.json"
        latest_html = api_dir / "api_response_latest.html"

        json_text = json.dumps(payload, indent=2, ensure_ascii=False)
        html_text = self._render_api_html(payload)

        json_path.write_text(json_text, encoding="utf-8")
        html_path.write_text(html_text, encoding="utf-8")
        latest_json.write_text(json_text, encoding="utf-8")
        latest_html.write_text(html_text, encoding="utf-8")

        self.last_json_report = latest_json
        self.last_html_report = latest_html
        return latest_json, latest_html

    def _save_current_html_report(self):
        payload = self.last_response_payload
        if not payload:
            response_text = self.output.get("1.0", "end").strip()
            if response_text:
                payload = {
                    "saved_at": datetime.now().isoformat(timespec="seconds"),
                    "preset": self.preset_var.get().strip(),
                    "request": {
                        "method": self.method_var.get().strip().upper(),
                        "url": self.url_var.get().strip(),
                        "headers": {},
                        "body": self.body_text.get("1.0", "end").strip(),
                        "upload_file": self.file_path_var.get().strip() or "none",
                        "file_field": self.file_field_var.get().strip() or "file",
                    },
                    "response": {
                        "status_code": "",
                        "reason": "",
                        "headers": {},
                        "body_text": response_text,
                    },
                }
            else:
                messagebox.showinfo("Save HTML Report", "Run an API test first so there is a response to save.", parent=self)
                return
        _, html_path = self._save_api_artifacts(payload)
        self.status_var.set(f"Saved HTML report: {html_path.name}")
        messagebox.showinfo("Save HTML Report", f"Saved API HTML report:\n{html_path}", parent=self)

    def _open_api_folder(self):
        api_dir = self.last_api_dir
        if api_dir is None or not api_dir.exists():
            api_dir = self._ensure_api_dir()
        self.app._open_path(api_dir)

    def _open_latest_html(self):
        html_path = self.last_html_report
        if html_path is None:
            api_dir = self._ensure_api_dir()
            candidate = api_dir / "api_response_latest.html"
            html_path = candidate if candidate.exists() else None
        if html_path is None or not html_path.exists():
            messagebox.showinfo("Open HTML Report", "No saved API HTML report was found yet.", parent=self)
            return
        webbrowser.open(html_path.resolve().as_uri())

    def _build_multipart_body(self, form_data, file_path: Path, file_field: str):
        boundary = "----RingForgeBoundary7MA4YWxkTrZu0gW"
        chunks = []
        def add_bytes(b):
            chunks.append(b if isinstance(b, bytes) else str(b).encode("utf-8"))
        if isinstance(form_data, dict):
            for key, value in form_data.items():
                add_bytes(f"--{boundary}\r\n")
                add_bytes(f'Content-Disposition: form-data; name="{key}"\r\n\r\n')
                if isinstance(value, (dict, list)):
                    add_bytes(json.dumps(value))
                else:
                    add_bytes(str(value))
                add_bytes("\r\n")
        elif form_data not in ("", None):
            add_bytes(f"--{boundary}\r\n")
            add_bytes('Content-Disposition: form-data; name="payload"\r\n\r\n')
            add_bytes(str(form_data))
            add_bytes("\r\n")
        filename = file_path.name
        add_bytes(f"--{boundary}\r\n")
        add_bytes(f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n')
        add_bytes("Content-Type: application/octet-stream\r\n\r\n")
        chunks.append(file_path.read_bytes())
        add_bytes("\r\n")
        add_bytes(f"--{boundary}--\r\n")
        return boundary, b"".join(chunks)

    def _start_request(self):
        if self.worker_thread and self.worker_thread.is_alive():
            return
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("API Analysis", "Please enter a URL.", parent=self)
            return
        method = self.method_var.get().strip().upper()
        timeout = int(self.timeout_var.get())
        try:
            headers, body_data = self._parse_headers_and_body()
        except Exception as e:
            messagebox.showerror("API Analysis", str(e), parent=self)
            return
        file_path_raw = self.file_path_var.get().strip()
        file_field = self.file_field_var.get().strip() or "file"
        body_bytes = None
        if file_path_raw:
            file_path = Path(file_path_raw)
            if not file_path.exists():
                messagebox.showerror("API Analysis", f"Upload file not found:\n{file_path}", parent=self)
                return
            boundary, body_bytes = self._build_multipart_body(body_data, file_path, file_field)
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        elif body_data not in ("", None):
            if isinstance(body_data, (dict, list)):
                body_bytes = json.dumps(body_data, indent=2).encode("utf-8")
                headers.setdefault("Content-Type", "application/json")
            else:
                body_bytes = str(body_data).encode("utf-8")
        self.output.delete("1.0", "end")
        self.status_var.set("Sending...")
        self.send_btn.configure(state="disabled")
        def worker():
            try:
                req = urllib.request.Request(url=url, data=body_bytes, headers=headers, method=method)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status_code = getattr(resp, "status", None) or resp.getcode()
                    reason = getattr(resp, "reason", "")
                    resp_headers = dict(resp.getheaders())
                    raw = resp.read()
                try:
                    response_body_text = raw.decode("utf-8")
                except Exception:
                    response_body_text = raw.decode("utf-8", errors="replace")
                parts = [
                    f"> Preset: {self.preset_var.get().strip()}\n",
                    f"> Method: {method}\n",
                    f"> URL: {url}\n",
                    f"> Upload file: {file_path_raw or 'none'}\n\n",
                    f"HTTP {status_code} {reason}\n",
                    "=== Response Headers ===\n",
                ]
                for k, v in resp_headers.items():
                    parts.append(f"{k}: {v}\n")
                parts.append("\n=== Response Body ===\n")
                try:
                    parsed_body = json.loads(response_body_text)
                    pretty_body = json.dumps(parsed_body, indent=2)
                    parts.append(pretty_body)
                except Exception:
                    pretty_body = response_body_text
                    parts.append(response_body_text)

                self.last_response_payload = {
                    "saved_at": datetime.now().isoformat(timespec="seconds"),
                    "preset": self.preset_var.get().strip(),
                    "request": {
                        "method": method,
                        "url": url,
                        "headers": headers,
                        "body": body_data,
                        "upload_file": file_path_raw or "none",
                        "file_field": file_field,
                    },
                    "response": {
                        "status_code": status_code,
                        "reason": str(reason),
                        "headers": resp_headers,
                        "body_text": pretty_body,
                    },
                }

                self.output_q.put("".join(parts))
                self.after(0, self._on_request_done)
            except urllib.error.HTTPError as e:
                try:
                    err_body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    err_body = "<unable to decode error body>"

                self.last_response_payload = {
                    "saved_at": datetime.now().isoformat(timespec="seconds"),
                    "preset": self.preset_var.get().strip(),
                    "request": {
                        "method": method,
                        "url": url,
                        "headers": headers,
                        "body": body_data,
                        "upload_file": file_path_raw or "none",
                        "file_field": file_field,
                    },
                    "response": {
                        "status_code": e.code,
                        "reason": str(e.reason),
                        "headers": {},
                        "body_text": err_body,
                    },
                }

                self.output_q.put(
                    f"> Preset: {self.preset_var.get().strip()}\n"
                    f"> Method: {method}\n"
                    f"> URL: {url}\n"
                    f"> Upload file: {file_path_raw or 'none'}\n\n"
                    f"HTTP Error: {e.code} {e.reason}\n\n=== Response Body ===\n{err_body}"
                )
                self.after(0, self._on_request_done)
            except Exception as e:
                self.last_response_payload = {
                    "saved_at": datetime.now().isoformat(timespec="seconds"),
                    "preset": self.preset_var.get().strip(),
                    "request": {
                        "method": method,
                        "url": url,
                        "headers": headers,
                        "body": body_data,
                        "upload_file": file_path_raw or "none",
                        "file_field": file_field,
                    },
                    "response": {
                        "status_code": "",
                        "reason": "Request failed",
                        "headers": {},
                        "body_text": str(e),
                    },
                }

                self.output_q.put(
                    f"> Preset: {self.preset_var.get().strip()}\n"
                    f"> Method: {method}\n"
                    f"> URL: {url}\n"
                    f"> Upload file: {file_path_raw or 'none'}\n\nRequest failed:\n{e}"
                )
                self.after(0, self._on_request_done)
        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()

    def _on_request_done(self):
        self.send_btn.configure(state="normal")
        self.status_var.set("Idle")

    def _drain_output(self):
        try:
            while True:
                msg = self.output_q.get_nowait()
                self.output.insert("end", msg + "\n")
                self.output.see("end")
        except queue.Empty:
            pass
        self.after(150, self._drain_output)

class App(tk.Tk):
    def _apply_theme(self):
        bg = "#081426"
        panel = "#0d1b33"
        panel2 = "#13284a"
        text = "#eaf2ff"
        muted = "#9bb2d1"
        accent = "#1f6fff"
        accent_hover = "#3d86ff"
        border = "#2a4365"
        disabled_bg = "#102038"
        disabled_fg = "#6f87a8"

        self.configure(bg=bg)

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(".", background=bg, foreground=text)
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=text)

        style.configure(
            "TLabelframe",
            background=bg,
            foreground=text,
            borderwidth=1,
            relief="solid",
            bordercolor=border,
            lightcolor=border,
            darkcolor=border,
        )
        style.configure(
            "TLabelframe.Label",
            background=bg,
            foreground="#7db3ff",
        )

        style.configure(
            "TButton",
            background=panel2,
            foreground=text,
            borderwidth=1,
            relief="flat",
            padding=6,
            bordercolor=border,
            lightcolor=border,
            darkcolor=border,
        )
        style.map(
            "TButton",
            background=[("active", accent_hover), ("pressed", accent), ("disabled", disabled_bg)],
            foreground=[("disabled", disabled_fg)],
            bordercolor=[("active", accent_hover), ("pressed", accent), ("disabled", border)],
        )

        style.configure(
            "TEntry",
            fieldbackground=panel,
            foreground=text,
            background=panel,
            bordercolor=border,
            lightcolor=border,
            darkcolor=border,
            insertcolor=text,
            relief="flat",
            padding=4,
        )

        style.configure(
            "TCombobox",
            fieldbackground=panel,
            foreground=text,
            background=panel,
            arrowcolor=text,
            bordercolor=border,
            lightcolor=border,
            darkcolor=border,
            relief="flat",
            padding=4,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", panel), ("disabled", disabled_bg)],
            foreground=[("readonly", text), ("disabled", disabled_fg)],
            background=[("readonly", panel), ("disabled", disabled_bg)],
            arrowcolor=[("disabled", disabled_fg)],
        )

        style.configure(
            "TCheckbutton",
            background=bg,
            foreground=text,
            indicatorbackground=panel,
            indicatormargin=2,
        )
        style.map(
            "TCheckbutton",
            foreground=[("disabled", disabled_fg)],
            background=[("disabled", bg)],
            indicatorbackground=[("selected", accent), ("disabled", disabled_bg)],
        )

        style.configure(
            "TRadiobutton",
            background=bg,
            foreground=text,
            indicatorbackground=panel,
        )
        style.map(
            "TRadiobutton",
            foreground=[("disabled", disabled_fg)],
            indicatorbackground=[("selected", accent), ("disabled", disabled_bg)],
        )

        style.configure(
            "Treeview",
            background=panel,
            fieldbackground=panel,
            foreground=text,
            bordercolor=border,
            lightcolor=border,
            darkcolor=border,
        )
        style.configure(
            "Treeview.Heading",
            background=panel2,
            foreground="#cfe2ff",
            relief="flat",
        )

        style.configure("TNotebook", background=bg, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=panel2,
            foreground=text,
            padding=(10, 6),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", accent), ("active", "#18345e")],
            foreground=[("selected", "white")],
        )

        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=panel,
            background=accent,
            bordercolor=border,
            lightcolor=accent,
            darkcolor=accent,
        )
    def __init__(self):
        super().__init__()
        self._apply_theme()

        self.title("Static Triage GUI (v10)")
        self.geometry("1220x860")
        self.minsize(1050, 760)

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

        self.score_var = tk.StringVar(value="—")
        self.verdict_var = tk.StringVar(value="—")
        self.confidence_var = tk.StringVar(value="—")
        self.vt_status_var = tk.StringVar(value="VirusTotal: disabled")
        self.vt_name_var = tk.StringVar(value="VT Name: —")
        self.vt_counts_var = tk.StringVar(value="Counts: mal=0 | susp=0 | harmless=0 | undetected=0")
        self.vt_link: str = ""

        self.open_case_btn: Optional[ttk.Button] = None
        self.open_html_btn: Optional[ttk.Button] = None
        self.open_pdf_btn: Optional[ttk.Button] = None
        self.dynamic_window: Optional[DynamicAnalysisWindow] = None
        self.api_window: Optional[APIAnalysisWindow] = None

        self.output_q: "queue.Queue[str]" = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None
        self.log_tail_thread: Optional[threading.Thread] = None
        self.stop_tail = threading.Event()

        self.case_dir_detected: Optional[Path] = None
        self.step_widgets: Dict[str, Dict[str, object]] = {}

        self._build_ui()
        self._apply_preset_if_needed()
        self._refresh_path_status()
        self.vt_api_key_var.trace_add("write", lambda *_: self._refresh_path_status())
        self._reset_progress()
        self._reset_result_summary()
        self.after(100, self._drain_output)

    def _build_ui(self):
        pad = {"padx": 10, "pady": 8}

        top = ttk.Frame(self)
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Sample:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.sample_var, width=105).grid(row=0, column=1, sticky="we", padx=6)
        ttk.Button(top, text="Browse…", command=self._browse_sample).grid(row=0, column=2, sticky="e")

        ttk.Label(top, text="Case name (optional):").grid(row=1, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.case_var, width=50).grid(row=1, column=1, sticky="w", padx=6)

        ttk.Label(top, text="Preset:").grid(row=1, column=1, sticky="e", padx=(0, 220))
        preset_names = [p.name for p in PRESETS]
        ttk.OptionMenu(top, self.preset_var, self.preset_var.get(), *preset_names, command=lambda *_: self._on_preset_changed()).grid(row=1, column=2, sticky="e")

        top.columnconfigure(1, weight=1)

        paths = ttk.LabelFrame(self, text="Paths")
        paths.pack(fill="x", **pad)

        ttk.Label(paths, text=r"Case output folder (CASE_ROOT_DIR):").grid(row=0, column=0, sticky="w")
        ttk.Entry(paths, textvariable=self.case_root_var, width=105).grid(row=0, column=1, sticky="we", padx=6)
        ttk.Button(paths, text="Browse…", command=self._browse_case_root).grid(row=0, column=2)

        ttk.Label(paths, text=r"capa rules folder (…\tools\capa-rules OR …\tools\capa-rules\rules):").grid(row=1, column=0, sticky="w")
        ttk.Entry(paths, textvariable=self.rules_var, width=105).grid(row=1, column=1, sticky="we", padx=6)
        ttk.Button(paths, text="Browse…", command=self._browse_rules).grid(row=1, column=2)

        ttk.Label(paths, text=r"capa sigs folder (…\tools\capa\sigs):").grid(row=2, column=0, sticky="w")
        ttk.Entry(paths, textvariable=self.sigs_var, width=105).grid(row=2, column=1, sticky="we", padx=6)
        ttk.Button(paths, text="Browse…", command=self._browse_sigs).grid(row=2, column=2)

        ttk.Label(paths, text="VirusTotal API key (optional):").grid(row=3, column=0, sticky="w")
        ttk.Entry(paths, textvariable=self.vt_api_key_var, width=105, show="*").grid(row=3, column=1, sticky="we", padx=6)
        ttk.Button(paths, text="Clear", command=self._clear_vt_key).grid(row=3, column=2)

        ttk.Label(paths, textvariable=self.status_var).grid(row=4, column=1, sticky="w", pady=(6, 0))
        paths.columnconfigure(1, weight=1)

        adv = ttk.LabelFrame(self, text="Advanced Settings")
        adv.pack(fill="x", **pad)

        ttk.Checkbutton(adv, text="Override preset with advanced settings", variable=self.adv_enabled_var, command=self._on_adv_toggle).grid(row=0, column=0, sticky="w")

        self.adv_body = ttk.Frame(adv)
        self.adv_body.grid(row=1, column=0, sticky="we", pady=(6, 0))
        adv.columnconfigure(0, weight=1)
        self.adv_body.columnconfigure(3, weight=1)

        ttk.Checkbutton(self.adv_body, text="Enable extraction", variable=self.extract_var, command=self._save_cfg).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(self.adv_body, text="Enable subfiles triage", variable=self.subfiles_var, command=self._save_cfg).grid(row=0, column=1, sticky="w", padx=(14, 0))

        ttk.Label(self.adv_body, text="Subfile limit:").grid(row=0, column=2, sticky="e", padx=(14, 6))
        ttk.Spinbox(self.adv_body, from_=0, to=999, textvariable=self.subfile_limit_var, width=6, command=self._save_cfg).grid(row=0, column=3, sticky="w")

        ttk.Checkbutton(self.adv_body, text="Strings lite", variable=self.strings_lite_var, command=self._on_strings_mode_changed).grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Checkbutton(self.adv_body, text="Skip strings", variable=self.no_strings_var, command=self._on_strings_mode_changed).grid(row=1, column=1, sticky="w", pady=(6, 0), padx=(14, 0))

        self.effective_label = ttk.Label(adv, text="")
        self.effective_label.grid(row=2, column=0, sticky="w", pady=(8, 0))

        prog = ttk.LabelFrame(self, text="Progress")
        prog.pack(fill="x", **pad)

        self.overall_var = tk.IntVar(value=0)
        self.overall_bar = ttk.Progressbar(prog, orient="horizontal", mode="determinate", maximum=100, variable=self.overall_var)
        self.overall_bar.grid(row=0, column=0, sticky="we")
        self.overall_text = ttk.Label(prog, text="0%")
        self.overall_text.grid(row=0, column=1, sticky="w", padx=(10, 0))
        prog.columnconfigure(0, weight=1)

        self.steps_frame = ttk.Frame(prog)
        self.steps_frame.grid(row=1, column=0, columnspan=2, sticky="we", pady=(10, 0))
        self.steps_frame.columnconfigure(1, weight=1)

        actions = ttk.Frame(self)
        actions.pack(fill="x", **pad)
        self.run_btn = ttk.Button(actions, text="Run Analysis", command=self._start_analysis)
        self.run_btn.pack(side="left")
        ttk.Button(actions, text="Open Case Files", command=self._open_case_files).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="Open HTML Report", command=self._open_html_report).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="Dynamic Analysis...", command=self._open_dynamic_window).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="API Analysis", command=self.open_api_analysis_window).pack(side="left", padx=(10, 0))

        ttk.Label(actions, textvariable=self.running_var).pack(side="right")

        summary = ttk.LabelFrame(self, text="Result Summary")
        summary.pack(fill="x", **pad)
        summary.columnconfigure(1, weight=1)
        summary.columnconfigure(3, weight=1)

        ttk.Label(summary, text="Score:").grid(row=0, column=0, sticky="w")
        ttk.Label(summary, textvariable=self.score_var).grid(row=0, column=1, sticky="w", padx=(6, 24))
        ttk.Label(summary, text="Verdict:").grid(row=0, column=2, sticky="w")
        ttk.Label(summary, textvariable=self.verdict_var).grid(row=0, column=3, sticky="w", padx=(6, 24))
        ttk.Label(summary, text="Confidence:").grid(row=0, column=4, sticky="w")
        ttk.Label(summary, textvariable=self.confidence_var).grid(row=0, column=5, sticky="w", padx=(6, 0))

        ttk.Label(summary, textvariable=self.vt_status_var).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(summary, textvariable=self.vt_name_var).grid(row=1, column=2, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(summary, textvariable=self.vt_counts_var).grid(row=1, column=4, sticky="w", pady=(6, 0))
        self.vt_open_btn = ttk.Button(summary, text="Open VirusTotal", command=self._open_virustotal, state="disabled")
        self.vt_open_btn.grid(row=1, column=5, sticky="e", pady=(6, 0))

        out = ttk.LabelFrame(self, text="Output")
        out.pack(fill="both", expand=True, **pad)

        self.output = tk.Text(out, wrap="none", height=16)
        self.output.pack(fill="both", expand=True, side="left")
        self.output.configure(font=("Consolas", 10))

        yscroll = ttk.Scrollbar(out, orient="vertical", command=self.output.yview)
        yscroll.pack(side="right", fill="y")
        self.output.configure(yscrollcommand=yscroll.set)

        self._sync_adv_state()
        self._update_effective_label()


    def _reset_result_summary(self):
        self.score_var.set("—")
        self.verdict_var.set("—")
        self.confidence_var.set("—")
        self.vt_status_var.set("VirusTotal: disabled")
        self.vt_name_var.set("VT Name: —")
        self.vt_counts_var.set("Counts: mal=0 | susp=0 | harmless=0 | undetected=0")
        self.vt_link = ""
        self.vt_open_btn.configure(state="disabled")

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

    def _open_path(self, path: Path):
        try:
            if os.name == "nt":
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as e:
            messagebox.showerror("Open Path", f"Could not open:\n{path}\n\n{e}")

    def _ensure_case_dir(self) -> Optional[Path]:
        if self.case_dir_detected and self.case_dir_detected.exists():
            return self.case_dir_detected

        case_name = self.case_var.get().strip()
        if not case_name:
            sample = self.sample_var.get().strip()
            if sample:
                case_name = Path(sample).stem[:64]

        if not case_name:
            messagebox.showinfo("Open Case Files", "No case has been selected yet.")
            return None

        case_dir = Path(self.case_root_var.get().strip()) / case_name
        if case_dir.exists():
            self.case_dir_detected = case_dir
            return case_dir

        messagebox.showinfo("Open Case Files", f"Case folder not found:\n{case_dir}")
        return None
    
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

    def _open_api_html_report(self):
        case_dir = self._ensure_case_dir()
        if not case_dir:
            return
        html_path = case_dir / "api" / "api_response_latest.html"
        if html_path.exists():
            self._open_path(html_path)
        else:
            messagebox.showinfo("API HTML Form", f"API HTML report not found:\n{html_path}\n\nRun an API test first.")

    def _open_api_folder(self):
        case_dir = self._ensure_case_dir()
        if not case_dir:
            return
        api_dir = case_dir / "api"
        api_dir.mkdir(parents=True, exist_ok=True)
        self._open_path(api_dir)

    def _open_case_files(self):
        case_dir = self._ensure_case_dir()
        if case_dir:
            self._open_path(case_dir)

    def _open_html_report(self):
        case_dir = self._ensure_case_dir()
        if not case_dir:
            return
        report_html = case_dir / "report.html"
        if report_html.exists():
            self._open_path(report_html)
        else:
            messagebox.showinfo("Open HTML Report", f"HTML report not found:\n{report_html}")

    def _open_pdf_report(self):
        case_dir = self._ensure_case_dir()
        if not case_dir:
            return
        report_pdf = case_dir / "report.pdf"
        if report_pdf.exists():
            self._open_path(report_pdf)
        else:
            messagebox.showinfo("Open PDF Report", f"PDF report not found:\n{report_pdf}")

    def _update_result_summary_from_case(self, case_dir: Optional[Path]):
        if not case_dir:
            return

        summary_path = case_dir / "summary.json"
        vt_path = case_dir / "virustotal.json"

        summary = {}
        vt = {}
        try:
            if summary_path.exists():
                loaded = json.loads(summary_path.read_text(encoding="utf-8", errors="replace"))
                if isinstance(loaded, dict):
                    summary = loaded
        except Exception:
            summary = {}

        try:
            if vt_path.exists():
                loaded = json.loads(vt_path.read_text(encoding="utf-8", errors="replace"))
                if isinstance(loaded, dict):
                    vt = loaded
        except Exception:
            vt = {}

        # fall back to summary["virustotal"] when present
        if not vt:
            maybe_vt = summary.get("virustotal")
            if isinstance(maybe_vt, dict):
                vt = maybe_vt

        self.score_var.set(str(summary.get("risk_score", "—")))
        self.verdict_var.set(str(summary.get("verdict", "—")))
        self.confidence_var.set(str(summary.get("confidence", "—")))

        enabled = bool(vt.get("enabled", False))
        found = bool(vt.get("found", False))
        permalink = str(vt.get("permalink", "") or "")
        meaningful_name = str(vt.get("meaningful_name", "") or "")
        error = str(vt.get("error", "") or "")

        mal = int(vt.get("malicious", 0) or 0)
        susp = int(vt.get("suspicious", 0) or 0)
        harmless = int(vt.get("harmless", 0) or 0)
        undetected = int(vt.get("undetected", 0) or 0)

        if not vt:
            self.vt_status_var.set("VirusTotal: disabled")
        elif not enabled:
            self.vt_status_var.set("VirusTotal: disabled")
        elif found:
            self.vt_status_var.set("VirusTotal: found")
        elif error:
            self.vt_status_var.set(f"VirusTotal: {error}")
        else:
            self.vt_status_var.set("VirusTotal: no result")

        self.vt_name_var.set(f"VT Name: {meaningful_name or '—'}")
        self.vt_counts_var.set(
            f"Counts: mal={mal} | susp={susp} | harmless={harmless} | undetected={undetected}"
        )

        self.vt_link = permalink
        self.vt_open_btn.configure(state=("normal" if permalink else "disabled"))

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

    def _on_adv_toggle(self):
        self._sync_adv_state()
        self._save_cfg()

    def _sync_adv_state(self):
        state = "normal" if self.adv_enabled_var.get() else "disabled"
        for child in self.adv_body.winfo_children():
            try:
                child.configure(state=state)
            except tk.TclError:
                pass
        self._update_effective_label()

    def _on_strings_mode_changed(self):
        if self.no_strings_var.get():
            self.strings_lite_var.set(False)
        self._save_cfg()

    def _selected_preset(self) -> Preset:
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
        self.effective_label.configure(text=f"Effective: extract={extract} | subfiles={subfiles} | subfile_limit={limit} | strings={sm}")

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
            ttk.Progressbar(self.steps_frame, orient="horizontal", mode="determinate", maximum=100, variable=bar_var).grid(row=i, column=1, sticky="we", padx=8)

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
        for step_key in STEP_DISPLAY_ORDER:
            st = self.step_widgets[step_key]["status"].cget("text")
            if st in ("done", "error", "skipped"):
                completed += 1
        pct = int(round((completed / max(1, len(STEP_DISPLAY_ORDER))) * 100))
        self.overall_var.set(pct)
        self.overall_text.configure(text=f"{pct}%")

    def _start_log_tail(self, case_dir: Path):
        self.stop_tail.set()
        self.stop_tail.clear()
        log_path = case_dir / "analysis.log"
        self.output_q.put(f"[info] Progress: tailing {log_path}")
        self.log_tail_thread = threading.Thread(target=self._tail_analysis_log, args=(log_path,), daemon=True)
        self.log_tail_thread.start()

    def _tail_analysis_log(self, log_path: Path):
        deadline = time.time() + 60
        while not log_path.exists() and time.time() < deadline and not self.stop_tail.is_set():
            time.sleep(0.25)
        if not log_path.exists():
            self.output_q.put(f"[warn] analysis.log not found at: {log_path}")
            return

        with log_path.open("r", encoding="utf-8", errors="replace") as f:
            while not self.stop_tail.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.25)
                    continue
                line = line.strip()
                if not line:
                    continue

                m = STEP_START_RE.search(line)
                if m:
                    raw = m.group("step")
                    step_key = STEP_NAME_MAP.get(raw, raw)
                    self.after(0, lambda s=step_key: (self._set_step(s, 15, "running"), self._recalc_overall()))
                    continue

                m = STEP_DONE_RE.search(line)
                if m:
                    raw = m.group("step")
                    step_key = STEP_NAME_MAP.get(raw, raw)
                    self.after(0, lambda s=step_key: (self._set_step(s, 100, "done"), self._recalc_overall()))
                    continue

                m = STEP_FAIL_RE.search(line)
                if m:
                    raw = m.group("step")
                    step_key = STEP_NAME_MAP.get(raw, raw)

                    if os.name == "nt" and step_key in ("filetype", "strings"):
                        fail_label = "n/a"
                    else:
                        fail_label = "failed"

                    self.after(0, lambda s=step_key, lbl=fail_label: (self._set_step(s, 100, lbl), self._recalc_overall()))
                    continue
                
    def _maybe_detect_case_dir_from_stdout(self, line: str) -> Optional[Path]:
        m = CASE_LINE_RE.match(line)
        if m:
            p = m.group("p").strip().strip('"')
            pp = Path(p)
            if pp.is_dir():
                return pp
        m2 = CASE_DIR_RE.search(line)
        if m2:
            p = m2.group("p").strip().strip('"').strip("'")
            pp = Path(p)
            if pp.is_dir():
                return pp
        return None

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
        if self.worker_thread and self.worker_thread.is_alive():
            return

        try:
            sample, case, case_root, rules, sigs = self._validate_inputs()
        except Exception as e:
            messagebox.showerror("Analysis failed", str(e))
            return

        if not CLI_SCRIPT.exists():
            messagebox.showerror("Missing CLI", f"Could not find CLI script:\n{CLI_SCRIPT}")
            return

        extract, subfiles, limit, sm = self._effective_settings()
        args = build_cli_args(sample, case, extract, subfiles, limit, sm)

        vt_api_key = self.vt_api_key_var.get().strip()
        env_overrides = {
            "CASE_ROOT_DIR": str(case_root),
            "CAPA_RULES_DIR": str(rules),
            "CAPA_SIGS_DIR": str(sigs),
            "PYTHONIOENCODING": "utf-8",
        }
        if vt_api_key:
            env_overrides["VT_API_KEY"] = vt_api_key

        py_exe = choose_python_exe()

        self.case_dir_detected = None
        self.stop_tail.set()
        self.stop_tail.clear()

        self._reset_progress()
        self._reset_result_summary()
        self.output.delete("1.0", "end")
        self.output.insert("end", "Starting analysis:\n")
        self.output.insert("end", f"  sample={sample}\n  case={case}\n")
        self.output.insert("end", f"  case_root={case_root}\n")
        self.output.insert("end", f"  rules={rules}\n  sigs={sigs}\n")
        self.output.insert("end", f"  {self.effective_label.cget('text')}\n\n")
        self.output.insert("end", f"[cmd] {py_exe} " + " ".join(args) + "\n\n")
        self.output.see("end")

        self._start_log_tail(case_root / case)

        self.run_btn.configure(state="disabled")
        self.running_var.set("Running…")

        def worker():
            rc = 1
            try:
                rc = run_cli_streaming(py_exe, args, env_overrides, self.output_q)
            except Exception as e:
                self.output_q.put(f"[error] {e}")
                rc = 1
            finally:
                self.output_q.put(f"\n[done] exit_code={rc}")
                self.after(0, lambda: self._on_done(rc))

        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()

    def _on_done(self, rc: int):
        self.stop_tail.set()

        if rc == 0:
            if self.case_dir_detected:
                report_md = self.case_dir_detected / "report.md"
                report_html = self.case_dir_detected / "report.html"
                report_pdf = self.case_dir_detected / "report.pdf"
                if report_md.exists() or report_html.exists() or report_pdf.exists():
                    self._set_step("report", 100, "done")
                self._update_result_summary_from_case(self.case_dir_detected)

            self._set_step("finalize", 100, "done")

            for step_key in STEP_DISPLAY_ORDER:
                st_lbl = self.step_widgets.get(step_key, {}).get("status")
                if st_lbl is not None and st_lbl.cget("text") in ("idle", "running"):
                    self._set_step(step_key, 100, "done")

            self._recalc_overall()
            self.overall_var.set(100)
            self.overall_text.configure(text="100%")
        else:
            if self.case_dir_detected:
                self._update_result_summary_from_case(self.case_dir_detected)
            self._recalc_overall()

        self.run_btn.configure(state="normal")
        self.running_var.set("Idle")

        if rc == 0:
            messagebox.showinfo("Completed", "Analysis completed successfully.")
        else:
            messagebox.showwarning("Completed", f"Analysis finished with exit code {rc}.\nCheck output for details.")

    def _drain_output(self):
        try:
            while True:
                line = self.output_q.get_nowait()
                if self.case_dir_detected is None:
                    cd = self._maybe_detect_case_dir_from_stdout(line)
                    if cd is not None:
                        self.case_dir_detected = cd
                        self.output.insert("end", f"[info] Detected case_dir: {cd}\n")
                        self._start_log_tail(cd)
                        self._update_result_summary_from_case(cd)
                
                # Report generation completion from stdout (works even if analysis.log doesn't include report lines)
                mrep = REPORT_STDOUT_MDHTML_RE.search(line)
                if mrep:
                    self._set_step("report", 100, "done")
                    self._recalc_overall()
                mpdf = REPORT_STDOUT_PDF_RE.search(line)
                if mpdf:
                    val = (mpdf.group("p") or "").strip()
                    if val.lower() != "none":
                        self._set_step("report", 100, "done")
                        self._recalc_overall()
                self.output.insert("end", line + "\n")
                self.output.see("end")
                if line.startswith("[done]") and self.case_dir_detected:
                    self._update_result_summary_from_case(self.case_dir_detected)
        except queue.Empty:
            pass
        self.after(100, self._drain_output)


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
