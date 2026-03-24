"""
Static Triage GUI (v10) - Fix progress parsing for timestamped analysis.log lines

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
import shutil
from datetime import datetime
from html import escape
import urllib.request
import urllib.error
import ssl
from PIL import Image, ImageTk
from urllib.parse import urlparse
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from static_triage_engine.api_spec_analysis import analyze_api_spec as engine_analyze_api_spec

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from dynamic_analysis.orchestrator import run_dynamic_analysis
from dynamic_analysis.html_report import write_dynamic_html_report
from static_triage_engine.scoring import combined_score_from_case_dir, calculate_combined_score

try:
    import certifi  # type: ignore
except Exception:
    certifi = None

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


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
        default_case_name = app.case_var.get().strip() or Path(app.sample_var.get().strip() or "sample").stem or "dynamic_case"
        default_case_path = app.case_dir_detected or (DEFAULT_CASE_ROOT / default_case_name)
        self.sample_var = tk.StringVar(value=app.sample_var.get().strip())
        self.case_dir_var = tk.StringVar(value=cfg.get("dynamic_case_dir", str(default_case_path)))
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
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(2, weight=1)

        settings = ttk.LabelFrame(frm, text="Dynamic Analysis Settings")
        settings.grid(row=0, column=0, sticky="nsew")
        settings.columnconfigure(1, weight=1)
        
        ttk.Label(settings, text="Sample:").grid(row=0, column=0, sticky="w")
        ttk.Entry(settings, textvariable=self.sample_var, width=100).grid(row=0, column=1, sticky="we", padx=6)
        ttk.Button(settings, text="Use Main Sample", style="Side.Action.TButton", command=self._use_main_sample).grid(row=0, column=2, sticky="ew", padx=(6, 0), pady=2)

        ttk.Label(settings, text="Dynamic case folder:").grid(row=1, column=0, sticky="w")
        ttk.Entry(settings, textvariable=self.case_dir_var, width=100).grid(row=1, column=1, sticky="we", padx=6)
        ttk.Button(settings, text="Browse...", style="Side.Action.TButton", command=self._browse_case_dir).grid(row=1, column=2, sticky="ew", padx=(6, 0), pady=2)

        ttk.Label(settings, text="Timeout (seconds):").grid(row=2, column=0, sticky="w")

        timeout_row = ttk.Frame(settings)
        timeout_row.grid(row=2, column=1, columnspan=2, sticky="w", padx=6)

        ttk.Spinbox(timeout_row, from_=5, to=7200, textvariable=self.timeout_var, width=10).pack(side="left")
        ttk.Checkbutton(timeout_row, text="Enable Procmon Capture", variable=self.procmon_enabled_var).pack(side="left", padx=(12, 0))

        ttk.Label(settings, text="Procmon path:").grid(row=3, column=0, sticky="w")
        ttk.Entry(settings, textvariable=self.procmon_path_var, width=100).grid(row=3, column=1, sticky="we", padx=6)
        ttk.Button(settings, text="Browse...", style="Side.Action.TButton", command=self._browse_procmon).grid(row=3, column=2, sticky="ew", padx=(6, 0), pady=2)

        ttk.Label(settings, text="Procmon config:").grid(row=4, column=0, sticky="w")
        ttk.Entry(settings, textvariable=self.procmon_config_var, width=100).grid(row=4, column=1, sticky="we", padx=6)
        ttk.Button(settings, text="Browse...", style="Side.Action.TButton", command=self._browse_procmon_config).grid(row=4, column=2, sticky="ew", padx=(6, 0), pady=2)

        actions = ttk.Frame(frm)
        actions.grid(row=1, column=0, sticky="we", pady=(10, 2))

        self.run_btn = ttk.Button(actions, text="Run Dynamic Analysis", style="Action.TButton", width=20, command=self._start_dynamic_analysis)
        self.run_btn.pack(side="left", padx=(0, 6), pady=4)

        ttk.Button(actions, text="Open Case Folder", style="Action.TButton", width=17, command=self._open_case_folder).pack(side="left", padx=6, pady=4)
        ttk.Button(actions, text="Open Latest Report", style="Action.TButton", width=17, command=self._open_latest_dynamic_html).pack(side="left", padx=6, pady=4)

        ttk.Label(actions, textvariable=self.status_var, anchor="e").pack(side="right", padx=(12, 0), pady=6)

        outwrap = ttk.LabelFrame(frm, text="Output")
        outwrap.grid(row=2, column=0, sticky="nsew", pady=(8, 0))
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
        if getattr(self.app, "case_dir_detected", None):
            self.case_dir_var.set(str(Path(self.app.case_dir_detected)))
        else:
            case_name = self.app.case_var.get().strip() or Path(self.app.sample_var.get().strip() or "sample").stem or "dynamic_case"
            self.case_dir_var.set(str(Path(self.app.case_root_var.get().strip()) / case_name))
        self._save_cfg()

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

        self.status_var.set("Running dynamic...")
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
        self.app.latest_dynamic_result = summary if isinstance(summary, dict) else {}

        self.run_btn.configure(state="normal")
        self.status_var.set("Idle")

        def finalize_refresh():
            case_dir = None

            if getattr(self.app, "case_dir_detected", None):
                case_dir = Path(self.app.case_dir_detected)
            else:
                case_dir = Path(self.case_dir_var.get().strip())

            if case_dir and case_dir.exists():
                self.app.case_dir_detected = case_dir
                combined_score_from_case_dir(
                    case_dir,
                    dynamic_result=None,
                    spec_result=None,
                    write_output=True,
                )
                self.app.refresh_combined_score(case_dir)
            else:
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


SENSITIVE_PARAM_HINTS = {
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "access_token", "refresh_token", "authorization", "auth", "session",
    "cookie", "ssn", "dob", "email", "phone", "creditcard", "card", "cvv",
}

ADMIN_ROUTE_HINTS = {"admin", "manage", "config", "settings", "internal", "debug", "health", "metrics", "actuator"}
DESTRUCTIVE_METHODS = {"DELETE", "PATCH", "PUT"}
AUTH_HINT_KEYS = {"authorization", "x-api-key", "api-key", "apikey", "bearer", "oauth", "token", "jwt", "basic"}


def _safe_json_write(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def _safe_text_read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _load_spec_file(path: Path) -> tuple[dict[str, Any], str]:
    text = _safe_text_read(path)
    suffix = path.suffix.lower()
    if suffix == ".json":
        return json.loads(text), "json"
    if suffix in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is not installed")
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}, "yaml"
    try:
        return json.loads(text), "json"
    except Exception:
        if yaml is None:
            raise RuntimeError("Unknown spec format and PyYAML is not installed")
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}, "yaml"


def _normalize_method(m: str) -> str:
    return str(m or "").upper().strip()


def _looks_sensitive(name: str) -> bool:
    n = re.sub(r"[^a-z0-9_]+", "", name.lower())
    return any(h in n for h in SENSITIVE_PARAM_HINTS)


def _looks_admin_route(path: str) -> bool:
    p = path.lower()
    return any(f"/{h}" in p or p.endswith(f"/{h}") for h in ADMIN_ROUTE_HINTS)


def _extract_server_hosts(spec: dict[str, Any]) -> list[str]:
    hosts: list[str] = []
    servers = spec.get("servers", [])
    if isinstance(servers, list):
        for item in servers:
            if isinstance(item, dict):
                url = str(item.get("url", "") or "").strip()
                if url:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        hosts.append(parsed.netloc.lower())
    host = spec.get("host")
    if isinstance(host, str) and host.strip():
        hosts.append(host.strip().lower())
    return sorted(set(hosts))


def _extract_security_schemes(spec: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    components = spec.get("components", {})
    if isinstance(components, dict):
        schemes = components.get("securitySchemes", {})
        if isinstance(schemes, dict):
            for name, item in schemes.items():
                if isinstance(item, dict):
                    out.append({"name": str(name), "type": str(item.get("type", "") or ""), "scheme": str(item.get("scheme", "") or ""), "in": str(item.get("in", "") or ""), "header_name": str(item.get("name", "") or "")})
    sec_defs = spec.get("securityDefinitions", {})
    if isinstance(sec_defs, dict):
        for name, item in sec_defs.items():
            if isinstance(item, dict):
                out.append({"name": str(name), "type": str(item.get("type", "") or ""), "scheme": str(item.get("scheme", "") or ""), "in": str(item.get("in", "") or ""), "header_name": str(item.get("name", "") or "")})
    return out


def _extract_parameters(op: dict[str, Any], path_item: dict[str, Any]) -> list[dict[str, str]]:
    params: list[dict[str, str]] = []
    for source in (path_item.get("parameters", []), op.get("parameters", [])):
        if isinstance(source, list):
            for p in source:
                if isinstance(p, dict):
                    params.append({"name": str(p.get("name", "") or ""), "in": str(p.get("in", "") or "")})
    request_body = op.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content", {})
        if isinstance(content, dict):
            for ctype, body in content.items():
                if isinstance(body, dict):
                    schema = body.get("schema", {})
                    if isinstance(schema, dict):
                        props = schema.get("properties", {})
                        if isinstance(props, dict):
                            for name in props.keys():
                                params.append({"name": str(name), "in": f"body:{ctype}"})
    return params


def _canonical_auth_name(name: str) -> str:
    n = str(name or "").strip().lower().replace("_", "-").replace(" ", "").replace("/", "-")

    if n in {
        "apikey", "api-key", "apikeyauth", "x-api-key", "xapikey", "api-key-auth"
    }:
        return "api-key"

    if n in {
        "bearer", "jwt", "bearerauth", "bearer-auth"
    }:
        return "bearer"

    if n in {
        "basic", "basicauth", "basic-auth"
    }:
        return "basic"

    if n in {"oauth", "oauth2"}:
        return "oauth2"

    if n in {"openidconnect", "openid-connect"}:
        return "openid-connect"

    if not n:
        return "none"

    return n


def _summarize_auth(security_schemes: list[dict[str, Any]], spec_text: str) -> list[str]:
    found: list[str] = []

    for item in security_schemes:
        t = (item.get("type", "") or "").lower()
        scheme = (item.get("scheme", "") or "").lower()
        header_name = (item.get("header_name", "") or "").lower()
        scheme_name = (item.get("name", "") or "").lower()

        if t == "apikey":
            found.append("api-key")
        elif t == "http" and scheme == "bearer":
            found.append("bearer")
        elif t == "http" and scheme == "basic":
            found.append("basic")
        elif t == "oauth2":
            found.append("oauth2")
        elif t == "openidconnect":
            found.append("openid-connect")

        if header_name in {"x-api-key", "api-key", "apikey"}:
            found.append("api-key")
        if scheme_name:
            found.append(_canonical_auth_name(scheme_name))

    # only use loose text hints when no explicit schemes were found
    if not found:
        text_l = spec_text.lower()
        for hint in AUTH_HINT_KEYS:
            if hint in text_l:
                found.append(_canonical_auth_name(hint))

    out: list[str] = []
    for item in found:
        canon = _canonical_auth_name(item)
        if canon != "none" and canon not in out:
            out.append(canon)
    return out
    
def _security_requirement_names(sec: Any) -> list[str]:
    names: list[str] = []
    if isinstance(sec, list):
        for item in sec:
            if isinstance(item, dict):
                for key in item.keys():
                    canon = _canonical_auth_name(str(key))
                    if canon != "none" and canon not in names:
                        names.append(canon)
    return names


def _effective_endpoint_auth(op: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    # endpoint-specific security overrides global security
    if "security" in op:
        names = _security_requirement_names(op.get("security"))
        return names if names else []

    names = _security_requirement_names(spec.get("security"))
    return names


# Legacy in-GUI spec analyzer kept for compatibility; SpecAnalysisWindow now calls the backend analyzer.
def analyze_api_spec(spec_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    spec_path = Path(spec_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "returncode": 0, "error": "", "input_file": str(spec_path), "format": "", "spec_type": "", "title": "", "version": "",
        "servers": [], "auth_summary": [], "security_schemes": [], "endpoints": [], "risk_notes": [],
        "summary": {"endpoint_count": 0, "get_count": 0, "post_count": 0, "put_count": 0, "patch_count": 0, "delete_count": 0, "admin_like_route_count": 0, "sensitive_param_count": 0, "auth_scheme_count": 0},
    }
    try:
        spec, fmt = _load_spec_file(spec_path)
        if not isinstance(spec, dict):
            raise RuntimeError("Spec root is not an object")
        spec_text = _safe_text_read(spec_path)
        info = spec.get("info", {}) if isinstance(spec.get("info"), dict) else {}
        paths = spec.get("paths", {}) if isinstance(spec.get("paths"), dict) else {}
        result["format"] = fmt
        if "openapi" in spec:
            result["spec_type"] = "openapi"
        elif "swagger" in spec:
            result["spec_type"] = "swagger2"
        else:
            result["spec_type"] = "unknown"
        result["title"] = str(info.get("title", "") or "")
        result["version"] = str(info.get("version", "") or "")
        result["servers"] = _extract_server_hosts(spec)
        security_schemes = _extract_security_schemes(spec)
        result["security_schemes"] = security_schemes
        result["auth_summary"] = _summarize_auth(security_schemes, spec_text)
        endpoints: list[dict[str, Any]] = []
        method_counts = {"GET": 0, "POST": 0, "PUT": 0, "PATCH": 0, "DELETE": 0}
        admin_like_route_count = 0
        sensitive_param_count = 0
        valid_methods = {"get", "post", "put", "patch", "delete", "head", "options"}
        for route, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            if _looks_admin_route(str(route)):
                admin_like_route_count += 1
            for method, op in path_item.items():
                if method.lower() not in valid_methods or not isinstance(op, dict):
                    continue
                m = _normalize_method(method)
                if m in method_counts:
                    method_counts[m] += 1
                params = _extract_parameters(op, path_item)
                sensitive_params = [p for p in params if _looks_sensitive(p.get("name", ""))]
                sensitive_param_count += len(sensitive_params)
                endpoint_auth = _effective_endpoint_auth(op, spec)
                endpoints.append({
                    "path": str(route),
                    "method": m,
                    "operation_id": str(op.get("operationId", "") or ""),
                    "summary": str(op.get("summary", "") or ""),
                    "description": str(op.get("description", "") or "")[:500],
                    "admin_like_route": _looks_admin_route(str(route)),
                    "destructive_method": m in DESTRUCTIVE_METHODS,
                    "parameters": params,
                    "sensitive_parameters": sensitive_params,
                    "auth_summary": endpoint_auth,
                })
        result["endpoints"] = endpoints
        result["summary"] = {
            "endpoint_count": len(endpoints), "get_count": method_counts["GET"], "post_count": method_counts["POST"], "put_count": method_counts["PUT"],
            "patch_count": method_counts["PATCH"], "delete_count": method_counts["DELETE"], "admin_like_route_count": admin_like_route_count,
            "sensitive_param_count": sensitive_param_count, "auth_scheme_count": len(result["auth_summary"]),
        }
        risk_notes: list[str] = []
        if not result["servers"]:
            risk_notes.append("No server/base URL definitions found in API spec")
        if method_counts["DELETE"] > 0 or method_counts["PATCH"] > 0:
            risk_notes.append("Spec exposes destructive or update-oriented methods (DELETE/PATCH)")
        if admin_like_route_count > 0:
            risk_notes.append(f"Admin/config/internal-like routes detected ({admin_like_route_count})")
        if sensitive_param_count > 0:
            risk_notes.append(f"Sensitive-looking parameters detected ({sensitive_param_count})")
        if not result["auth_summary"]:
            risk_notes.append("No obvious authentication scheme detected in spec")
        result["risk_notes"] = risk_notes
    except Exception as e:
        result["returncode"] = 1
        result["error"] = f"{type(e).__name__}: {e}"
    _safe_json_write(output_dir / "api_spec_analysis.json", result)
    return result


class SpecAnalysisWindow(tk.Toplevel):
    def __init__(self, app: "App"):
        super().__init__(app)
        self.app = app
        self.title("API Spec Analysis")
        self.geometry("2030x1100")
        self.minsize(1650, 900)
        self.spec_path_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Idle")
        self.summary_var = tk.StringVar(value="Load an OpenAPI or Swagger spec to analyze endpoints, authentication, and API risk indicators.")
        self.last_spec_dir: Optional[Path] = None
        self.last_html_report: Optional[Path] = None
        self.last_json_report: Optional[Path] = None
        self.last_result: Optional[dict[str, Any]] = None
        self._build_ui()
        self.transient(app)
        self.grab_set()

    def _current_case_name(self) -> str:
        case_name = self.app.case_var.get().strip() if hasattr(self.app, "case_var") else ""
        if case_name:
            return case_name
        sample = self.app.sample_var.get().strip() if hasattr(self.app, "sample_var") else ""
        if sample:
            return Path(sample).stem[:64]
        return "spec_case"

    def _ensure_spec_dir(self) -> Path:
        case_root = Path(self.app.case_root_var.get().strip()) if hasattr(self.app, "case_root_var") else (ROOT / "cases")
        case_root.mkdir(parents=True, exist_ok=True)
        case_dir = case_root / self._current_case_name()
        case_dir.mkdir(parents=True, exist_ok=True)
        spec_dir = case_dir / "spec"
        spec_dir.mkdir(parents=True, exist_ok=True)
        self.last_spec_dir = spec_dir
        return spec_dir

    def _build_ui(self):
        pad = {"padx": 12, "pady": 10}

        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, **pad)
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(2, weight=1)

        # ---------- Top command bar ----------
        top = ttk.LabelFrame(frm, text="API Spec Analysis")
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="API Spec:").grid(row=0, column=0, sticky="w", padx=(8, 0), pady=10)

        ttk.Entry(top, textvariable=self.spec_path_var, width=100).grid(
            row=0, column=1, sticky="ew", padx=8, pady=10
        )

        btns = ttk.Frame(top)
        btns.grid(row=0, column=2, sticky="e", padx=(0, 8), pady=8)

        ttk.Button(
            btns,
            text="Browse",
            style="Side.Action.TButton",
            command=self._browse_spec,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            btns,
            text="Analyze Spec",
            style="Action.TButton",
            command=self._parse_spec,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            btns,
            text="Open HTML Report",
            style="Action.TButton",
            command=self._open_html_report,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            btns,
            text="Open Case Files",
            style="Action.TButton",
            command=self._open_case_files,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            btns,
            text="Manual API Tester",
            style="Action.TButton",
            command=self._open_manual_api_tester,
        ).pack(side="left")

        # ---------- Quick metrics strip ----------
        metrics = ttk.LabelFrame(frm, text="Overview")
        metrics.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        for i in range(4):
            metrics.columnconfigure(i, weight=1)

        self.spec_format_var = tk.StringVar(value="-")
        self.spec_version_var = tk.StringVar(value="-")
        self.spec_endpoint_count_var = tk.StringVar(value="-")
        self.spec_auth_var = tk.StringVar(value="-")

        def metric_cell(parent, col, title, var):
            box = ttk.Frame(parent)
            box.grid(row=0, column=col, sticky="ew", padx=10, pady=10)
            ttk.Label(box, text=title, style="SectionHeader.TLabel").pack(anchor="w")
            ttk.Label(box, textvariable=var, style="SummaryValue.TLabel").pack(anchor="w", pady=(4, 0))

        metric_cell(metrics, 0, "Format", self.spec_format_var)
        metric_cell(metrics, 1, "Version", self.spec_version_var)
        metric_cell(metrics, 2, "Endpoints", self.spec_endpoint_count_var)
        metric_cell(metrics, 3, "Auth", self.spec_auth_var)

        # ---------- Main workspace ----------
        body = ttk.Frame(frm)
        body.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        body.columnconfigure(0, weight=0, minsize=500)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # Left pane
        left = ttk.Frame(body)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)

        # Give the left-side content real vertical space
        left.rowconfigure(0, weight=0)  # Summary
        left.rowconfigure(1, weight=1)  # Risk Notes
        left.rowconfigure(2, weight=1)  # Top Risky Endpoints
        left.rowconfigure(3, weight=1)  # Recommended Tests
        left.rowconfigure(4, weight=0)  # Getting Started

        summary = ttk.LabelFrame(left, text="Summary")
        summary.grid(row=0, column=0, sticky="ew")
        summary.columnconfigure(0, weight=1)

        self.summary_label = ttk.Label(
            summary,
            textvariable=self.summary_var,
            wraplength=360,
            justify="left",
        )
        self.summary_label.grid(row=0, column=0, sticky="w", padx=10, pady=10)

        notes = ttk.LabelFrame(left, text="Risk Notes")
        notes.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        notes.columnconfigure(0, weight=1)

        self.notes_text = tk.Text(
            notes,
            height=10,
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
        self.notes_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        top_risky = ttk.LabelFrame(left, text="Top Risky Endpoints")
        top_risky.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        top_risky.columnconfigure(0, weight=1)
        top_risky.rowconfigure(0, weight=1)

        self.top_risky_text = tk.Text(
            top_risky,
            height=12,
            wrap="word",
            bg="#071b34",
            fg="#eaf2ff",
            insertbackground="#eaf2ff",
            selectbackground="#1f61ff",
            selectforeground="white",
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#2a4365",
            highlightcolor="#3d86ff",
            font=("Consolas", 10),
        )
        self.top_risky_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        recommended = ttk.LabelFrame(left, text="Recommended Tests")
        recommended.grid(row=3, column=0, sticky="nsew", pady=(10, 0))
        recommended.columnconfigure(0, weight=1)
        recommended.rowconfigure(0, weight=1)

        self.recommended_tests_text = tk.Text(
            recommended,
            height=10,
            wrap="word",
            bg="#071b34",
            fg="#eaf2ff",
            insertbackground="#eaf2ff",
            selectbackground="#1f61ff",
            selectforeground="white",
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#2a4365",
            highlightcolor="#3d86ff",
            font=("Consolas", 10),
        )
        self.recommended_tests_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        empty = ttk.LabelFrame(left, text="Getting Started")
        empty.grid(row=4, column=0, sticky="nsew", pady=(10, 0))
        empty.columnconfigure(0, weight=1)

        ttk.Label(
            empty,
            text="API Spec Analysis",
            style="SectionHeader.TLabel",
        ).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))

        ttk.Label(
            empty,
            text="Load an OpenAPI or Swagger definition to build endpoint inventory, summarize authentication, generate risk notes, and create an HTML report.",
            wraplength=360,
            justify="left",
        ).grid(row=1, column=0, sticky="w", padx=10)

        ttk.Label(
            empty,
            text="Supported formats: JSON, YAML, YML"
        ).grid(row=2, column=0, sticky="w", padx=10, pady=(8, 10))

        # Right pane
        right = ttk.LabelFrame(body, text="Endpoint Inventory")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)
        right.rowconfigure(1, weight=0)

        # table wrapper
        table_wrap = ttk.Frame(right)
        table_wrap.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        table_wrap.columnconfigure(0, weight=1)
        table_wrap.columnconfigure(1, weight=0)
        table_wrap.rowconfigure(0, weight=1)

        cols = ("method", "path", "summary", "auth", "auth_source", "risk_level", "params", "flags")
        self.tree = ttk.Treeview(table_wrap, columns=cols, show="headings", height=22)

        headings = {
            "method": "Method",
            "path": "Path",
            "summary": "Summary",
            "auth": "Auth",
            "auth_source": "Auth_Source",
            "risk_level": "Risk",
            "params": "Params",
            "flags": "Flags",
        }

        widths = {
            "method": 100,
            "path": 250,
            "summary": 360,
            "auth": 220,
            "auth_source": 110,
            "risk_level": 80,
            "params": 90,
            "flags": 220,
        }

        for col in cols:
            self.tree.heading(col, text=headings[col], anchor="w")
            self.tree.column(
                col,
                width=widths[col],
                minwidth=widths[col],
                anchor="w",
                stretch=(col == "summary"),
            )

        self.tree.grid(row=0, column=0, sticky="nsew")

        ysb = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        ysb.grid(row=0, column=1, sticky="ns", padx=(0, 6))

        xsb = ttk.Scrollbar(right, orient="horizontal", command=self.tree.xview)
        xsb.grid(row=1, column=0, sticky="ew", padx=4, pady=(0, 4))

        self.tree.configure(
            yscrollcommand=ysb.set,
            xscrollcommand=xsb.set,
        )

        # ---------- Status row ----------
        status_row = ttk.Frame(frm)
        status_row.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(status_row, textvariable=self.status_var).pack(side="right", padx=(12, 0), pady=2)

    def _browse_spec(self):
        start = Path(self.spec_path_var.get()).parent if self.spec_path_var.get().strip() else ROOT
        chosen = filedialog.askopenfilename(title="Select API spec", initialdir=str(start), filetypes=[("API Specs", "*.json *.yaml *.yml"), ("All Files", "*.*")])
        if chosen:
            self.spec_path_var.set(norm_path_str(chosen))
    
    def _normalize_auth_name(self, name: str) -> str:
        n = (name or "").strip().lower().replace("_", "-")

        if n in {"apikey", "api-key", "x-api-key", "api key"}:
            return "api-key"
        if n in {"bearer", "jwt", "bearerauth"}:
            return "bearer"
        if n in {"basic", "basicauth"}:
            return "basic"
        if n in {"oauth2", "oauth"}:
            return "oauth2"
        if n in {"none", ""}:
            return "none"

        return n


    def _format_endpoint_auth(self, ep: dict[str, Any]) -> str:
        raw = ep.get("auth_summary") or ep.get("auth") or []
        if isinstance(raw, str):
            raw = [raw]

        normalized = []
        for item in raw:
            val = self._normalize_auth_name(str(item))
            if val and val != "none" and val not in normalized:
                normalized.append(val)

        return ", ".join(normalized) if normalized else "none"

    def _populate_result(self, result: dict[str, Any]):
        for item in self.tree.get_children():
            self.tree.delete(item)

        summary = result.get("summary", {})
        title = result.get("title") or Path(result.get("input_file", "spec")).name

        raw_auth_summary = result.get("auth_summary", [])
        normalized_auth_summary = []
        for item in raw_auth_summary:
            canon = _canonical_auth_name(str(item))
            if canon != "none" and canon not in normalized_auth_summary:
                normalized_auth_summary.append(canon)

        self.spec_format_var.set(result.get("format", "") or "-")
        self.spec_version_var.set(result.get("version", "") or "-")
        self.spec_endpoint_count_var.set(str(summary.get("endpoint_count", 0)))
        self.spec_auth_var.set(", ".join(normalized_auth_summary) if normalized_auth_summary else "none")

        self.summary_var.set(
            f"Title: {title}\n"
            f"Format: {result.get('format', '-')}\n"
            f"Type: {result.get('spec_type', '-')}\n"
            f"Servers: {', '.join(result.get('servers', [])) or 'none'}\n"
            f"Methods: GET {summary.get('get_count',0)} | POST {summary.get('post_count',0)} | "
            f"PUT {summary.get('put_count',0)} | PATCH {summary.get('patch_count',0)} | "
            f"DELETE {summary.get('delete_count',0)}"
        )

        self.notes_text.delete("1.0", "end")

        notes = result.get("risk_notes", []) or []
        parser_warnings = result.get("parser_warnings", []) or []
        unresolved_refs = result.get("unresolved_refs", []) or []

        sections = []

        if notes:
            sections.append("Risk Notes\n" + "\n".join(f"- {x}" for x in notes))
        else:
            sections.append("Risk Notes\n- No risk notes generated.")

        if parser_warnings:
            sections.append("Parser Warnings\n" + "\n".join(f"- {x}" for x in parser_warnings))

        if unresolved_refs:
            preview = unresolved_refs[:10]
            sections.append(
                "Unresolved Refs\n"
                + "\n".join(f"- {x}" for x in preview)
                + (f"\n- ... and {len(unresolved_refs) - len(preview)} more" if len(unresolved_refs) > 10 else "")
            )

        self.notes_text.delete("1.0", "end")
        self.notes_text.insert("1.0", "\n\n".join(sections))
        
        if hasattr(self, "top_risky_text"):
            self.top_risky_text.delete("1.0", "end")
            top_risky = result.get("top_risky_endpoints", []) or []

            if not top_risky:
                endpoints = result.get("endpoints", []) or []
                top_risky = sorted(
                    [ep for ep in endpoints if ep.get("risk_level") == "high" or int(ep.get("risk_score", 0)) > 0],
                    key=lambda ep: (-int(ep.get("risk_score", 0)), str(ep.get("path", "")), str(ep.get("method", "")))
                )[:10]

            if top_risky:
                lines = []
                for item in top_risky[:10]:
                    method = item.get("method", "")
                    path = item.get("path", "")
                    level = item.get("risk_level", "")
                    score = item.get("risk_score", 0)
                    reasons = item.get("risk_reasons", []) or []
                    if isinstance(reasons, str):
                        reasons = [reasons]

                    lines.append(f"{method} {path} [{level} | score={score}]")
                    for reason in reasons[:4]:
                        lines.append(f"  - {reason}")
                    lines.append("")

                self.top_risky_text.insert("1.0", "\n".join(lines).strip())
            else:
                self.top_risky_text.insert("1.0", "No high-risk endpoints identified.")
                
        if hasattr(self, "recommended_tests_text"):
            self.recommended_tests_text.delete("1.0", "end")
            recs = result.get("recommended_tests", []) or []

            if recs:
                lines = []
                for item in recs[:10]:
                    method = item.get("method", "")
                    path = item.get("path", "")
                    level = item.get("risk_level", "")
                    score = item.get("risk_score", 0)
                    tests = item.get("tests", []) or []
                    if isinstance(tests, str):
                        tests = [tests]
                    lines.append(f"{method} {path} [{level} | score={score}]")
                    for test in tests[:5]:
                        lines.append(f"  - {test}")
                    lines.append("")
                self.recommended_tests_text.insert("1.0", "\n".join(lines).strip())
            else:
                self.recommended_tests_text.insert("1.0", "No recommended tests generated.")

        for ep in result.get("endpoints", []):
            params = ep.get("parameters", [])
            flags = []

            if ep.get("admin_like_route"):
                flags.append("admin-like")
            if ep.get("destructive_method"):
                flags.append("destructive")
            if ep.get("sensitive_parameters"):
                flags.append("sensitive-params")

            ep_auth = ep.get("auth_schemes_applied", []) or []
            if isinstance(ep_auth, str):
                ep_auth = [ep_auth]

            normalized_ep_auth = []
            for item in ep_auth:
                canon = _canonical_auth_name(str(item))
                if canon != "none" and canon not in normalized_ep_auth:
                    normalized_ep_auth.append(canon)

            if normalized_ep_auth:
                auth_txt = ", ".join(normalized_ep_auth)
            elif ep.get("auth_required"):
                auth_txt = "required"
            else:
                auth_txt = "none"
                
            auth_source_txt = str(ep.get("auth_source", "") or "")
            if auth_source_txt == "explicit_none":
                auth_source_txt = "public"

            self.tree.insert(
                "",
                "end",
                values=(
                    ep.get("method", ""),
                    ep.get("path", ""),
                    ep.get("summary", ""),
                    auth_txt,
                    auth_source_txt,
                    ep.get("risk_level", ""),
                    len(params),
                    ", ".join(flags),
                ),
            )

    def _render_html(self, result: dict[str, Any]) -> str:
        from html import escape

        summary = result.get("summary", {}) or {}
        title = result.get("title") or Path(result.get("input_file", "spec")).name
        version = result.get("version") or "-"
        spec_type = result.get("spec_type") or "-"
        fmt = result.get("format") or "-"
        confidence = result.get("confidence") or "-"
        servers = result.get("servers", []) or []
        auth_summary = result.get("auth_summary", []) or []
        endpoints = result.get("endpoints", []) or []
        risk_notes = result.get("risk_notes", []) or []
        parser_warnings = result.get("parser_warnings", []) or []
        unresolved_refs = result.get("unresolved_refs", []) or []
        top_risky = result.get("top_risky_endpoints", []) or []
        recommended_tests = result.get("recommended_tests", []) or []

        auth_txt = ", ".join(str(x) for x in auth_summary) if auth_summary else "none"
        servers_txt = ", ".join(str(x) for x in servers) if servers else "none"

        risk_notes_html = "".join(f"<li>{escape(str(x))}</li>" for x in risk_notes) or "<li>None</li>"
        parser_warnings_html = "".join(f"<li>{escape(str(x))}</li>" for x in parser_warnings) or "<li>None</li>"
        unresolved_refs_html = "".join(f"<li>{escape(str(x))}</li>" for x in unresolved_refs[:20]) or "<li>None</li>"

        top_risky_html = ""
        for item in top_risky:
            method = escape(str(item.get("method", "")))
            path = escape(str(item.get("path", "")))
            level = escape(str(item.get("risk_level", "")))
            score = escape(str(item.get("risk_score", 0)))
            reasons = item.get("risk_reasons", []) or []
            if isinstance(reasons, str):
                reasons = [reasons]
            reasons_html = "".join(f"<li>{escape(str(r))}</li>" for r in reasons[:6]) or "<li>No reasons captured.</li>"
            top_risky_html += f"""
            <div class="endpoint-card">
                <div class="endpoint-title">{method} {path}</div>
                <div class="muted">Risk: {level} | Score: {score}</div>
                <ul>{reasons_html}</ul>
            </div>
            """
        if not top_risky_html:
            top_risky_html = "<p class='muted'>No high-risk endpoints identified.</p>"

        recommended_html = ""
        for item in recommended_tests:
            method = escape(str(item.get("method", "")))
            path = escape(str(item.get("path", "")))
            level = escape(str(item.get("risk_level", "")))
            score = escape(str(item.get("risk_score", 0)))
            tests = item.get("tests", []) or []
            if isinstance(tests, str):
                tests = [tests]
            tests_html = "".join(f"<li>{escape(str(t))}</li>" for t in tests[:8]) or "<li>No tests generated.</li>"
            recommended_html += f"""
            <div class="endpoint-card">
                <div class="endpoint-title">{method} {path}</div>
                <div class="muted">Risk: {level} | Score: {score}</div>
                <ul>{tests_html}</ul>
            </div>
            """
        if not recommended_html:
            recommended_html = "<p class='muted'>No recommended tests generated.</p>"

        rows = []
        for ep in endpoints:
            params = ep.get("parameters", []) or []
            flags = []
            if ep.get("admin_like_route"):
                flags.append("admin-like")
            if ep.get("destructive_method"):
                flags.append("destructive")
            if ep.get("sensitive_parameters"):
                flags.append("sensitive-params")
            if ep.get("file_upload"):
                flags.append("upload")

            ep_auth = ep.get("auth_schemes_applied", []) or []
            if isinstance(ep_auth, str):
                ep_auth = [ep_auth]
            auth_txt_ep = ", ".join(str(x) for x in ep_auth) if ep_auth else ("required" if ep.get("auth_required") else "none")

            auth_source_txt = str(ep.get("auth_source", "") or "")
            if auth_source_txt == "explicit_none":
                auth_source_txt = "public"

            rows.append(
                "<tr>"
                f"<td>{escape(str(ep.get('method', '')))}</td>"
                f"<td>{escape(str(ep.get('path', '')))}</td>"
                f"<td>{escape(str(ep.get('summary', '')))}</td>"
                f"<td>{escape(auth_txt_ep)}</td>"
                f"<td>{escape(auth_source_txt)}</td>"
                f"<td>{escape(str(ep.get('risk_level', '')))}</td>"
                f"<td>{len(params)}</td>"
                f"<td>{escape(', '.join(flags))}</td>"
                "</tr>"
            )

        return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="utf-8">
    <title>API Spec Analysis - {escape(str(title))}</title>
    <style>
    body {{
        margin: 0;
        font-family: Arial, sans-serif;
        background: #071b34;
        color: #eaf2ff;
    }}
    .container {{
        max-width: 1600px;
        margin: 0 auto;
        padding: 24px;
    }}
    h1 {{
        margin: 0 0 8px 0;
        font-size: 28px;
    }}
    h2 {{
        margin: 0 0 10px 0;
        font-size: 18px;
    }}
    .muted {{
        color: #b7c9e8;
        font-size: 13px;
    }}
    .grid {{
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 12px;
        margin: 18px 0;
    }}
    .card {{
        background: #0c2344;
        border: 1px solid #2a4365;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 16px;
    }}
    .two-col {{
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 16px;
    }}
    .endpoint-card {{
        background: #0a1d39;
        border: 1px solid #2a4365;
        border-radius: 8px;
        padding: 12px;
        margin-bottom: 10px;
    }}
    .endpoint-title {{
        font-weight: bold;
        margin-bottom: 4px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 8px;
        font-size: 13px;
    }}
    th, td {{
        border: 1px solid #2a4365;
        padding: 8px;
        text-align: left;
        vertical-align: top;
    }}
    th {{
        background: #17345f;
    }}
    ul {{
        margin: 8px 0 0 18px;
    }}
    .footer {{
        margin-top: 20px;
        color: #b7c9e8;
        font-size: 12px;
    }}
    </style>
    </head>
    <body>
    <div class="container">
        <h1>API Spec Analysis</h1>
        <div class="muted">{escape(str(title))}</div>

        <div class="grid">
            <div class="card"><h2>Format</h2><div>{escape(fmt)}</div></div>
            <div class="card"><h2>Version</h2><div>{escape(version)}</div></div>
            <div class="card"><h2>Endpoints</h2><div>{summary.get("endpoint_count", 0)}</div></div>
            <div class="card"><h2>Auth</h2><div>{escape(auth_txt)}</div></div>
        </div>

        <div class="card">
            <h2>Summary</h2>
            <div><strong>Type:</strong> {escape(spec_type)}</div>
            <div><strong>Confidence:</strong> {escape(str(confidence))}</div>
            <div><strong>Servers:</strong> {escape(servers_txt)}</div>
            <div><strong>Top Risky Endpoints:</strong> {summary.get("top_risky_endpoint_count", 0)}</div>
            <div><strong>Unresolved Refs:</strong> {result.get("unresolved_refs_count", 0)}</div>
            <div><strong>Methods:</strong> GET {summary.get("get_count",0)} | POST {summary.get("post_count",0)} | PUT {summary.get("put_count",0)} | PATCH {summary.get("patch_count",0)} | DELETE {summary.get("delete_count",0)}</div>
        </div>

        <div class="two-col">
            <div class="card">
                <h2>Risk Notes</h2>
                <ul>{risk_notes_html}</ul>
            </div>
            <div class="card">
                <h2>Parser Warnings</h2>
                <ul>{parser_warnings_html}</ul>
            </div>
        </div>

        <div class="card">
            <h2>Unresolved Refs</h2>
            <ul>{unresolved_refs_html}</ul>
        </div>

        <div class="two-col">
            <div class="card">
                <h2>Top Risky Endpoints</h2>
                {top_risky_html}
            </div>
            <div class="card">
                <h2>Recommended Tests</h2>
                {recommended_html}
            </div>
        </div>

        <div class="card">
            <h2>Endpoint Inventory</h2>
            <table>
                <tr>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Summary</th>
                    <th>Auth</th>
                    <th>Auth Source</th>
                    <th>Risk</th>
                    <th>Params</th>
                    <th>Flags</th>
                </tr>
                {''.join(rows)}
            </table>
        </div>

        <div class="footer">Generated by RingForge Workbench</div>
    </div>
    </body>
    </html>"""

    def _save_report_files(self, result: dict[str, Any]) -> tuple[Path, Path]:
        spec_dir = self._ensure_spec_dir()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        src = Path(self.spec_path_var.get().strip())
        spec_name = src.stem if src.exists() else "spec"
        safe_spec_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in spec_name)
        safe_spec_name = safe_spec_name.strip("_") or "spec"

        json_path = spec_dir / f"spec_inventory_{safe_spec_name}_{timestamp}.json"
        html_path = spec_dir / f"spec_inventory_{safe_spec_name}_{timestamp}.html"

        latest_json = spec_dir / f"spec_inventory_latest_{safe_spec_name}.json"
        latest_html = spec_dir / f"spec_inventory_latest_{safe_spec_name}.html"

        generic_latest_json = spec_dir / "spec_inventory_latest.json"
        generic_latest_html = spec_dir / "spec_inventory_latest.html"

        _safe_json_write(json_path, result)
        _safe_json_write(latest_json, result)
        _safe_json_write(generic_latest_json, result)

        html_text = self._render_html(result)
        html_path.write_text(html_text, encoding="utf-8")
        latest_html.write_text(html_text, encoding="utf-8")
        generic_latest_html.write_text(html_text, encoding="utf-8")

        if src.exists():
            try:
                shutil.copy2(src, spec_dir / f"original_{safe_spec_name}{src.suffix.lower()}")
            except Exception:
                pass

        # point buttons to the most recent named report for this spec
        self.last_json_report = latest_json
        self.last_html_report = latest_html

        return latest_json, latest_html

    def _parse_spec(self):
        spec_path = Path(self.spec_path_var.get().strip())
        if spec_path.suffix.lower() not in {".json", ".yaml", ".yml"}:
            messagebox.showerror(
                "Spec Analysis",
                "API Spec Analysis only accepts .json, .yaml, or .yml files.",
                parent=self,
            )
            self.status_var.set("Invalid spec file type")
            return
        result = engine_analyze_api_spec(spec_path, self._ensure_spec_dir())
        if result.get('returncode') != 0:
            messagebox.showerror('Spec Analysis', result.get('error', 'Unknown error'), parent=self)
            self.status_var.set('Parse failed')
            return
        self.last_result = result
        self.app.latest_spec_result = result if isinstance(result, dict) else {}
        self._populate_result(result)
        self._save_report_files(result)
        case_root = Path(self.app.case_root_var.get().strip()) if hasattr(self.app, "case_root_var") else DEFAULT_CASE_ROOT
        case_dir = case_root / self._current_case_name()
        self.app.case_dir_detected = case_dir

        combined_score_from_case_dir(
            case_dir,
            dynamic_result=None,
            spec_result=None,
            write_output=True,
        )
        self.app.refresh_combined_score(case_dir)

        self.status_var.set(f"Parsed {result.get('summary', {}).get('endpoint_count', 0)} endpoints")

    def _save_html_report(self):
        if not self.last_result:
            messagebox.showinfo('Save HTML Report', 'Parse a spec first so there is a report to save.', parent=self)
            return
        _, html_path = self._save_report_files(self.last_result)
        self.status_var.set(f'Saved HTML report: {html_path.name}')
        messagebox.showinfo('Save HTML Report', f'Saved spec HTML report:{html_path}', parent=self)

    def _open_html_report(self):
        report_path = None

        # first choice: the last report generated in this window
        if getattr(self, "last_html_report", None):
            candidate = Path(self.last_html_report)
            if candidate.exists():
                report_path = candidate

        # second choice: derive the spec-specific latest report from the current spec path
        if report_path is None:
            spec_dir = self._ensure_spec_dir()
            src = Path(self.spec_path_var.get().strip())
            if src.exists():
                spec_name = src.stem
                safe_spec_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in spec_name)
                safe_spec_name = safe_spec_name.strip("_") or "spec"

                candidate = spec_dir / f"spec_inventory_latest_{safe_spec_name}.html"
                if candidate.exists():
                    report_path = candidate

        # fallback: generic latest
        if report_path is None:
            spec_dir = self._ensure_spec_dir()
            candidate = spec_dir / "spec_inventory_latest.html"
            if candidate.exists():
                report_path = candidate

        if report_path and report_path.exists():
            webbrowser.open(report_path.resolve().as_uri())
            self.status_var.set(f"Opened HTML report: {report_path.name}")
        else:
            messagebox.showinfo("Open HTML Report", "No saved HTML report found yet.", parent=self)

    def _open_case_files(self):
        spec_dir = self.last_spec_dir
        if spec_dir is None:
            candidate = self._ensure_spec_dir()
            spec_dir = candidate if candidate.exists() else None
        if spec_dir is None or not spec_dir.exists():
            messagebox.showinfo('Open Case Files', 'No spec case folder was found yet.', parent=self)
            return
        self.app._open_path(spec_dir)

    def _open_manual_api_tester(self):
        APIAnalysisWindow(self.app)


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
        self.title("Manual API Tester")
        self.geometry("1400x980")
        self.minsize(1200, 820)

        self.preset_var = tk.StringVar(value="HTTPBin GET Test")
        self.method_var = tk.StringVar(value="GET")
        self.url_var = tk.StringVar(value="")
        self.timeout_var = tk.IntVar(value=60)
        self.verify_ssl_var = tk.BooleanVar(value=True)
        self.file_path_var = tk.StringVar(value="")
        self.file_field_var = tk.StringVar(value="file")
        self.status_var = tk.StringVar(value="Idle")
        self.last_api_dir: Optional[Path] = None
        self.last_html_report: Optional[Path] = None
        self.last_json_report: Optional[Path] = None
        self.last_response_payload: Optional[dict] = None

        self.output_q: "queue.Queue[str]" = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None
        self.log_tail_thread: Optional[threading.Thread] = None
        self.stop_tail = threading.Event()
        self.current_log_path: Optional[Path] = None

        self.case_dir_detected: Optional[Path] = None
        self.step_widgets: Dict[str, Dict[str, object]] = {}
        
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
        options_wrap = ttk.Frame(frm)
        options_wrap.grid(row=1, column=2, columnspan=2, sticky="e")
        ttk.Checkbutton(options_wrap, text="Verify SSL", variable=self.verify_ssl_var).pack(side="left", padx=(0, 12))
        ttk.Label(options_wrap, text="Timeout (sec):").pack(side="left")
        ttk.Spinbox(options_wrap, from_=1, to=300, textvariable=self.timeout_var, width=8, style="TSpinbox").pack(side="left", padx=(6, 0))

        ttk.Label(frm, text="URL:").grid(row=2, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.url_var, width=112).grid(row=2, column=1, columnspan=3, sticky="we", padx=6)

        ttk.Label(frm, text="Upload file:").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.file_path_var, width=92).grid(row=3, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Browse...", command=self._browse_upload_file).grid(row=3, column=2, sticky="w")
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
        return {"User-Agent": "RingForge-Workbench/1.2"}

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

    def _build_ssl_context(self):
        if not self.verify_ssl_var.get():
            return ssl._create_unverified_context()
        try:
            if certifi is not None:
                return ssl.create_default_context(cafile=certifi.where())
        except Exception:
            pass
        return ssl.create_default_context()

    def _format_request_exception(self, err: Exception) -> str:
        msg = str(err)
        lowered = msg.lower()
        if "certificate_verify_failed" in lowered or "unable to get local issuer certificate" in lowered:
            return (
                f"{err}\n\n"
                "Tip: your Python environment could not validate the HTTPS certificate chain. "
                "Try enabling or disabling 'Verify SSL' in this window depending on your test needs."
            )
        return msg

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
                ssl_context = self._build_ssl_context()
                with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as resp:
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
                        "body_text": self._format_request_exception(e),
                    },
                }

                self.output_q.put(
                    f"> Preset: {self.preset_var.get().strip()}\n"
                    f"> Method: {method}\n"
                    f"> URL: {url}\n"
                    f"> Upload file: {file_path_raw or 'none'}\n\nRequest failed:\n{self._format_request_exception(e)}"
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

        self.option_add("*Menu.background", "#0d1b33")
        self.option_add("*Menu.foreground", "#eaf2ff")
        self.option_add("*Menu.activeBackground", "#1f6fff")
        self.option_add("*Menu.activeForeground", "#ffffff")
        self.option_add("*Menu.borderWidth", 1)
        
        self.option_add("*TCombobox*Listbox.background", "#0d1b33")
        self.option_add("*TCombobox*Listbox.foreground", "#eaf2ff")
        self.option_add("*TCombobox*Listbox.selectBackground", "#1f6fff")
        self.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        
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
            "SummaryValue.TLabel",
            font=("Segoe UI", 14, "bold"),
            foreground="#f8fbff",
            background="#001833",
        )

        style.configure(
            "SummaryAccent.TLabel",
            font=("Segoe UI", 11, "bold"),
            foreground="#7fb3ff",
            background="#001833",
        )

        style.configure(
            "SectionHeader.TLabel",
            font=("Segoe UI", 10, "bold"),
            foreground="#9fc5ff",
            background="#001833",
        )

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
            "Action.TButton",
            background=panel2,
            foreground=text,
            borderwidth=1,
            relief="raised",
            padding=(16, 10),
            font=("Segoe UI Semibold", 10),
            bordercolor=border,
            lightcolor="#27496d",
            darkcolor="#10243d",
            anchor="center",
        )
        style.map(
            "Action.TButton",
            background=[
                ("pressed", "#163a63"),
                ("active", "#1a4677"),
                ("disabled", disabled_bg),
            ],
            foreground=[
                ("disabled", disabled_fg),
                ("active", "#ffffff"),
            ],
            bordercolor=[
                ("pressed", "#35597c"),
                ("active", "#466b91"),
                ("!disabled", border),
                ("disabled", border),
            ],
            lightcolor=[
                ("pressed", "#214a7a"),
                ("active", "#315b89"),
                ("!disabled", "#27496d"),
            ],
            darkcolor=[
                ("pressed", "#0d2238"),
                ("active", "#14304f"),
                ("!disabled", "#10243d"),
            ],
            relief=[
                ("pressed", "sunken"),
                ("!pressed", "raised"),
            ],
        )
        style.configure(
            "Side.Action.TButton",
            background=panel2,
            foreground=text,
            borderwidth=1,
            relief="raised",
            padding=(10, 3),
            font=("Segoe UI Semibold", 9),
            bordercolor=border,
            lightcolor="#27496d",
            darkcolor="#10243d",
            anchor="center",
        )
        style.map(
            "Side.Action.TButton",
            background=[
                ("pressed", "#163a63"),
                ("active", "#1a4677"),
                ("disabled", disabled_bg),
            ],
            foreground=[
                ("disabled", disabled_fg),
                ("active", "#ffffff"),
            ],
            bordercolor=[
                ("pressed", "#35597c"),
                ("active", "#466b91"),
                ("!disabled", border),
                ("disabled", border),
            ],
            lightcolor=[
                ("pressed", "#214a7a"),
                ("active", "#315b89"),
                ("!disabled", "#27496d"),
            ],
            darkcolor=[
                ("pressed", "#0d2238"),
                ("active", "#14304f"),
                ("!disabled", "#10243d"),
            ],
            relief=[
                ("pressed", "sunken"),
                ("!pressed", "raised"),
            ],
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
            "TSpinbox",
            fieldbackground=panel,
            foreground=text,
            background=panel,
            arrowcolor=text,
            bordercolor=border,
            lightcolor=border,
            darkcolor=border,
            relief="flat",
            padding=2,
        )
        style.map(
            "TSpinbox",
            fieldbackground=[("disabled", disabled_bg), ("readonly", panel)],
            foreground=[("disabled", disabled_fg), ("readonly", text)],
            background=[("disabled", disabled_bg), ("readonly", panel)],
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
            background="#13284a",
            foreground="#eaf2ff",
            bordercolor="#2a4365",
            lightcolor="#2a4365",
            darkcolor="#2a4365",
            relief="flat",
            padding=(14, 8),
            font=("Segoe UI", 10, "bold"),
        )

        style.map(
            "Treeview.Heading",
            background=[("active", "#13284a"), ("pressed", "#1f6fff")],
            foreground=[("active", "#eaf2ff"), ("pressed", "#ffffff")],
            relief=[("pressed", "flat"), ("active", "flat")],
        )
        
        style.configure(
            "Treeview",
            background="#0d1b33",
            fieldbackground="#0d1b33",
            foreground="#eaf2ff",
            rowheight=28,
            bordercolor="#2a4365",
            lightcolor="#2a4365",
            darkcolor="#2a4365",
        )

        style.map(
            "Treeview",
            background=[("selected", "#1f6fff")],
            foreground=[("selected", "#ffffff")],
        )

        style.configure(
            "Treeview.Heading",
            background="#13284a",
            foreground="#eaf2ff",
            bordercolor="#365a88",
            lightcolor="#365a88",
            darkcolor="#365a88",
            relief="raised",
            padding=(12, 8),
            font=("Segoe UI", 10, "bold"),
        )

        style.map(
            "Treeview.Heading",
            background=[("active", "#13284a"), ("pressed", "#1f6fff")],
            foreground=[("active", "#eaf2ff"), ("pressed", "#ffffff")],
            relief=[("active", "raised"), ("pressed", "sunken")],
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
        self.geometry("1280x980")
        self.minsize(1180, 900)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

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
        self.vt_link: str = ""
        self.brand_logo_img = None

        self.open_case_btn: Optional[ttk.Button] = None
        self.open_html_btn: Optional[ttk.Button] = None
        self.open_pdf_btn: Optional[ttk.Button] = None
        self.dynamic_window: Optional[DynamicAnalysisWindow] = None
        self.spec_window: Optional[SpecAnalysisWindow] = None
        self.api_window: Optional[APIAnalysisWindow] = None
        self.latest_static_result: dict[str, Any] = {}
        self.latest_dynamic_result: dict[str, Any] = {}
        self.latest_spec_result: dict[str, Any] = {}
        self.latest_combined_score: Optional[dict[str, Any]] = None

        self.output_q: "queue.Queue[str]" = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None
        self.log_tail_thread: Optional[threading.Thread] = None
        self.stop_tail = threading.Event()
        self.current_log_path: Optional[Path] = None

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
        outer = {"padx": 12, "pady": 8}

        # ---------- Header ----------
        header = ttk.Frame(self)
        header.pack(fill="x", **outer)
        header.columnconfigure(1, weight=1)
        header.columnconfigure(3, weight=0)

        ttk.Label(header, text="Sample:").grid(row=0, column=0, sticky="w")
        ttk.Entry(header, textvariable=self.sample_var, width=90).grid(
            row=0, column=1, sticky="ew", padx=(8, 8)
        )
        ttk.Button(
            header,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_sample,
        ).grid(row=0, column=2, sticky="ew")

        ttk.Label(header, text="Case name:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(header, textvariable=self.case_var, width=32).grid(
            row=1, column=1, sticky="w", padx=(8, 8), pady=(8, 0)
        )

        ttk.Label(header, text="Preset:").grid(row=1, column=2, sticky="e", padx=(12, 6), pady=(8, 0))
        preset_names = [p.name for p in PRESETS]
        preset_box = ttk.Combobox(
            header,
            textvariable=self.preset_var,
            values=preset_names,
            state="readonly",
            width=18,
        )
        preset_box.grid(row=1, column=3, sticky="w", pady=(8, 0))
        preset_box.bind("<<ComboboxSelected>>", self._on_preset_selected)

        # ---------- Main 2-column body ----------
        body = ttk.Frame(self)
        body.pack(fill="both", expand=False, **outer)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)

        left_col = ttk.Frame(body)
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left_col.columnconfigure(0, weight=1)
        left_col.rowconfigure(1, weight=1)

        right_col = ttk.Frame(body)
        right_col.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right_col.columnconfigure(0, weight=1)

        # ---------- Configuration ----------
        config = ttk.LabelFrame(left_col, text="Configuration")
        config.grid(row=0, column=0, sticky="ew")
        config.columnconfigure(0, weight=1)
        
        # ---------- Brand panel ----------
        brand = ttk.LabelFrame(left_col, text="RingForge")
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
            text="v1.2",
            bg="#001833",
            fg="#5f86c5",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        ).grid(row=5, column=1, sticky="w", pady=(14, 18))

        # Paths subsection
        paths = ttk.LabelFrame(config, text="Paths")
        paths.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        paths.columnconfigure(1, weight=1)

        ttk.Label(paths, text="Case output folder:").grid(row=0, column=0, sticky="w")
        ttk.Entry(paths, textvariable=self.case_root_var, width=72).grid(
            row=0, column=1, sticky="ew", padx=(8, 8)
        )
        ttk.Button(
            paths,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_case_root,
        ).grid(row=0, column=2, sticky="ew")

        ttk.Label(paths, text="capa rules folder:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(paths, textvariable=self.rules_var, width=72).grid(
            row=1, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
        )
        ttk.Button(
            paths,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_rules,
        ).grid(row=1, column=2, sticky="ew", pady=(8, 0))

        ttk.Label(paths, text="capa sigs folder:").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(paths, textvariable=self.sigs_var, width=72).grid(
            row=2, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
        )
        ttk.Button(
            paths,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_sigs,
        ).grid(row=2, column=2, sticky="ew", pady=(8, 0))

        ttk.Label(paths, text="VirusTotal API key:").grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(paths, textvariable=self.vt_api_key_var, width=72, show="*").grid(
            row=3, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
        )
        ttk.Button(
            paths,
            text="Clear",
            style="Side.Action.TButton",
            command=self._clear_vt_key,
        ).grid(row=3, column=2, sticky="ew", pady=(8, 0))

        # Advanced subsection
        adv = ttk.LabelFrame(config, text="Advanced Settings")
        adv.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        adv.columnconfigure(0, weight=1)

        ttk.Checkbutton(
            adv,
            text="Override preset with advanced settings",
            variable=self.adv_enabled_var,
            command=self._on_adv_toggle,
        ).grid(row=0, column=0, sticky="w")

        self.adv_body = ttk.Frame(adv)
        self.adv_body.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        self.adv_body.columnconfigure(3, weight=1)

        ttk.Checkbutton(
            self.adv_body,
            text="Enable extraction",
            variable=self.extract_var,
            command=self._save_cfg,
        ).grid(row=0, column=0, sticky="w")

        ttk.Checkbutton(
            self.adv_body,
            text="Enable subfiles triage",
            variable=self.subfiles_var,
            command=self._save_cfg,
        ).grid(row=0, column=1, sticky="w", padx=(14, 0))

        ttk.Label(self.adv_body, text="Subfile limit:").grid(
            row=0, column=2, sticky="e", padx=(14, 6)
        )
        self.subfile_limit_spin = ttk.Spinbox(
            self.adv_body,
            from_=0,
            to=999,
            textvariable=self.subfile_limit_var,
            width=6,
            command=self._save_cfg,
        )
        self.subfile_limit_spin.grid(row=0, column=3, sticky="w")

        ttk.Checkbutton(
            self.adv_body,
            text="Strings lite",
            variable=self.strings_lite_var,
            command=self._on_strings_mode_changed,
        ).grid(row=1, column=0, sticky="w", pady=(8, 0))

        ttk.Checkbutton(
            self.adv_body,
            text="Skip strings",
            variable=self.no_strings_var,
            command=self._on_strings_mode_changed,
        ).grid(row=1, column=1, sticky="w", padx=(14, 0), pady=(8, 0))

        self.effective_label = ttk.Label(adv, text="")
        self.effective_label.grid(row=2, column=0, sticky="w", pady=(10, 0))

        # ---------- Right column: Progress ----------
        prog = ttk.LabelFrame(right_col, text="Progress")
        prog.grid(row=0, column=0, sticky="ew")
        prog.columnconfigure(0, weight=1)

        self.overall_var = tk.IntVar(value=0)
        self.overall_bar = ttk.Progressbar(
            prog,
            orient="horizontal",
            mode="determinate",
            maximum=100,
            variable=self.overall_var,
        )
        self.overall_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))

        self.overall_text = ttk.Label(prog, text="0%")
        self.overall_text.grid(row=0, column=1, sticky="w", padx=(10, 10), pady=(10, 0))

        self.steps_frame = ttk.Frame(prog)
        self.steps_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 10))
        self.steps_frame.columnconfigure(1, weight=1)
        
        # ---------- Results ----------
        self.combined_verdict_var = tk.StringVar(value="-")
        self.combined_confidence_var = tk.StringVar(value="-")

        results = ttk.LabelFrame(right_col, text="Results")
        results.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        results.columnconfigure(0, weight=1)

        # Combined headline section
        combined_wrap = ttk.Frame(results)
        combined_wrap.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))
        combined_wrap.columnconfigure(1, weight=1)
        combined_wrap.columnconfigure(3, weight=1)

        ttk.Label(combined_wrap, text="Combined Score:").grid(row=0, column=0, sticky="w")
        ttk.Label(
            combined_wrap,
            textvariable=self.combined_score_var,
            style="SummaryValue.TLabel",
        ).grid(row=0, column=1, sticky="w", padx=(8, 20))

        ttk.Label(combined_wrap, text="Severity:").grid(row=0, column=2, sticky="w")
        ttk.Label(
            combined_wrap,
            textvariable=self.combined_severity_var,
            style="SummaryAccent.TLabel",
        ).grid(row=0, column=3, sticky="w", padx=(8, 0))

        ttk.Label(combined_wrap, text="Verdict:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Label(combined_wrap, textvariable=self.combined_verdict_var).grid(
            row=1, column=1, sticky="w", padx=(8, 20), pady=(8, 0)
        )

        ttk.Label(combined_wrap, text="Confidence:").grid(row=1, column=2, sticky="w", pady=(8, 0))
        ttk.Label(combined_wrap, textvariable=self.combined_confidence_var).grid(
            row=1, column=3, sticky="w", padx=(8, 0), pady=(8, 0)
        )

        # Divider
        ttk.Separator(results, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=12, pady=(0, 8)
        )

        # Lower two-column summary area
        lower = ttk.Frame(results)
        lower.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 12))
        lower.columnconfigure(0, weight=1)
        lower.columnconfigure(1, weight=1)

        # Left side: Static + Subscores
        left_metrics = ttk.Frame(lower)
        left_metrics.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left_metrics.columnconfigure(1, weight=1)

        ttk.Label(left_metrics, text="Static", style="SectionHeader.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 6)
        )

        ttk.Label(left_metrics, text="Score:").grid(row=1, column=0, sticky="w")
        ttk.Label(left_metrics, textvariable=self.score_var).grid(
            row=1, column=1, sticky="w", padx=(8, 0)
        )

        ttk.Label(left_metrics, text="Verdict:").grid(row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Label(left_metrics, textvariable=self.verdict_var).grid(
            row=2, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
        )

        ttk.Label(left_metrics, text="Confidence:").grid(row=3, column=0, sticky="w", pady=(6, 0))
        ttk.Label(left_metrics, textvariable=self.confidence_var).grid(
            row=3, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
        )

        ttk.Separator(left_metrics, orient="horizontal").grid(
            row=4, column=0, columnspan=2, sticky="ew", pady=(10, 8)
        )

        ttk.Label(left_metrics, text="Subscores", style="SectionHeader.TLabel").grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(0, 6)
        )

        ttk.Label(left_metrics, text="Static:").grid(row=6, column=0, sticky="w")
        ttk.Label(left_metrics, textvariable=self.static_subscore_var).grid(
            row=6, column=1, sticky="w", padx=(8, 0)
        )

        ttk.Label(left_metrics, text="Dynamic:").grid(row=7, column=0, sticky="w", pady=(6, 0))
        ttk.Label(left_metrics, textvariable=self.dynamic_subscore_var).grid(
        row=7, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
        )

        ttk.Label(left_metrics, text="Spec/API:").grid(row=8, column=0, sticky="w", pady=(6, 0))
        ttk.Label(left_metrics, textvariable=self.spec_subscore_var).grid(
            row=8, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
        )

        # Right side: VirusTotal
        right_metrics = ttk.Frame(lower)
        right_metrics.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right_metrics.columnconfigure(0, weight=1)

        ttk.Label(right_metrics, text="VirusTotal", style="SectionHeader.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 6)
        )

        ttk.Label(right_metrics, textvariable=self.vt_status_var, wraplength=280, justify="left").grid(
            row=1, column=0, sticky="w"
        )
        ttk.Label(right_metrics, textvariable=self.vt_name_var, wraplength=280, justify="left").grid(
            row=2, column=0, sticky="w", pady=(6, 0)
        )
        ttk.Label(right_metrics, textvariable=self.vt_counts_var, wraplength=280, justify="left").grid(
            row=3, column=0, sticky="w", pady=(6, 0)
        )

        self.vt_open_btn = ttk.Button(
            right_metrics,
            text="Open VirusTotal",
            command=self._open_virustotal,
            state="disabled",
            style="Action.TButton",
        )
        self.vt_open_btn.grid(row=4, column=0, sticky="e", pady=(12, 0))

            
        # ---------- Command bar ----------
        actions = ttk.Frame(self)
        actions.pack(fill="x", **outer)

        buttons_row = ttk.Frame(actions)
        buttons_row.pack(fill="x")

        self.run_btn = ttk.Button(
            buttons_row,
            text="Run Analysis",
            style="Action.TButton",
            width=18,
            command=self._start_analysis,
        )
        self.run_btn.pack(side="left", padx=(0, 10))

        ttk.Button(
            buttons_row,
            text="Open Case",
            style="Action.TButton",
            width=14,
            command=self._open_case_files,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            buttons_row,
            text="Open Report",
            style="Action.TButton",
            width=14,
            command=self._open_html_report,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            buttons_row,
            text="Dynamic Analysis",
            style="Action.TButton",
            width=16,
            command=self.open_dynamic_window,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            buttons_row,
            text="API Spec Analysis",
            style="Action.TButton",
            width=16,
            command=self.open_spec_analysis_window,
        ).pack(side="left", padx=(0, 8))

        status_row = ttk.Frame(actions)
        status_row.pack(fill="x", pady=(6, 0))

        ttk.Label(status_row, textvariable=self.status_var).pack(side="left")
        ttk.Label(status_row, textvariable=self.running_var, anchor="e").pack(side="right")

        # ---------- Output ----------
        out = ttk.LabelFrame(self, text="Output")
        out.pack(fill="both", expand=True, **outer)

        self.output = tk.Text(
            out,
            wrap="none",
            height=12,
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
        self.output.pack(fill="both", expand=True, side="left")

        yscroll = ttk.Scrollbar(out, orient="vertical", command=self.output.yview)
        yscroll.pack(side="right", fill="y")
        self.output.configure(yscrollcommand=yscroll.set)

        self._sync_adv_state()
        self._update_effective_label()
        
    def open_dynamic_window(self):
        DynamicAnalysisWindow(self)

    def open_api_analysis_window(self):
        APIAnalysisWindow(self)

    def open_spec_analysis_window(self):
        SpecAnalysisWindow(self)   
    
    def reload_combined_score_from_disk(self):
        print("DEBUG reload_combined_score_from_disk called")
        print("DEBUG case_dir_detected =", self.case_dir_detected)

        if not self.case_dir_detected:
            return

        self.refresh_combined_score(Path(self.case_dir_detected))

        print("DEBUG combined_score_var =", self.combined_score_var.get())
        print("DEBUG static_subscore_var =", self.static_subscore_var.get())
        print("DEBUG dynamic_subscore_var =", self.dynamic_subscore_var.get())
        print("DEBUG spec_subscore_var =", self.spec_subscore_var.get())

        self.update_idletasks()


    def _reset_result_summary(self):
        self.score_var.set("-")
        self.verdict_var.set("-")
        self.confidence_var.set("-")
        self.combined_score_var.set("-")
        self.combined_severity_var.set("-")
        self.static_subscore_var.set("-")
        self.dynamic_subscore_var.set("-")
        self.spec_subscore_var.set("-")
        self.combined_verdict_var.set("-")
        self.combined_confidence_var.set("-")
        self.vt_status_var.set("VirusTotal: disabled")
        self.vt_name_var.set("VT Name: -")
        self.vt_counts_var.set("Counts: mal=0 | susp=0 | harmless=0 | undetected=0")
        self.vt_link = ""
        self.vt_open_btn.configure(state="disabled")

    def refresh_combined_score(self, case_dir: Optional[Path] = None):
        combined = None
        try:
            if case_dir:
                case_dir = Path(case_dir)

            if case_dir and case_dir.exists():
                combined = combined_score_from_case_dir(
                    case_dir,
                    dynamic_result=None,
                    spec_result=None,
                    write_output=True,
                )
            else:
                static_result = self.latest_static_result or None
                dynamic_result = self.latest_dynamic_result or None
                spec_result = self.latest_spec_result or None

                combined = calculate_combined_score(
                    static_result=static_result,
                    dynamic_result=dynamic_result,
                    spec_result=spec_result,
                )

        except Exception as e:
            print(f"DEBUG refresh_combined_score failed: {e}")
            combined = None

        if not combined:
            self.combined_score_var.set("-")
            self.combined_severity_var.set("-")
            self.static_subscore_var.set("-")
            self.dynamic_subscore_var.set("-")
            self.spec_subscore_var.set("-")
            self.combined_verdict_var.set("-")
            self.combined_confidence_var.set("-")
            self.latest_combined_score = None
            return

        self.latest_combined_score = combined
        self.combined_verdict_var.set(str(combined.get("verdict", "-")))
        self.combined_confidence_var.set(str(combined.get("confidence", "-")))
        self.combined_score_var.set(str(combined.get("total_score", "-")))
        self.combined_severity_var.set(str(combined.get("severity", "-")))

        subs = combined.get("subscores", {}) if isinstance(combined.get("subscores"), dict) else {}
        present = combined.get("present", {}) if isinstance(combined.get("present"), dict) else {}

        self.static_subscore_var.set(str(subs.get("static", 0)) if present.get("static") else "-")
        self.dynamic_subscore_var.set(str(subs.get("dynamic", 0)) if present.get("dynamic") else "-")
        self.spec_subscore_var.set(str(subs.get("spec", 0)) if present.get("spec") else "-")

        self.update_idletasks()

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

        self.score_var.set(str(summary.get("risk_score", "-")))
        self.verdict_var.set(str(summary.get("verdict", "-")))
        self.confidence_var.set(str(summary.get("confidence", "-")))

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

        self.vt_name_var.set(f"VT Name: {meaningful_name or '-'}")
        self.vt_counts_var.set(
            f"Counts: mal={mal} | susp={susp} | harmless={harmless} | undetected={undetected}"
        )

        self.vt_link = permalink
        self.vt_open_btn.configure(state=("normal" if permalink else "disabled"))

        self.latest_static_result = {
            "summary": summary,
            "iocs": json.loads((case_dir / "iocs.json").read_text(encoding="utf-8", errors="replace")) if (case_dir / "iocs.json").exists() else {},
            "pe_meta": json.loads((case_dir / "pe_metadata.json").read_text(encoding="utf-8", errors="replace")) if (case_dir / "pe_metadata.json").exists() else {},
            "lief_meta": json.loads((case_dir / "lief_metadata.json").read_text(encoding="utf-8", errors="replace")) if (case_dir / "lief_metadata.json").exists() else {},
            "api_analysis": json.loads((case_dir / "api_analysis.json").read_text(encoding="utf-8", errors="replace")) if (case_dir / "api_analysis.json").exists() else {},
        }
        self.refresh_combined_score(case_dir)

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
                # Keep labels visually normal
                if isinstance(child, ttk.Label):
                    child.configure(state="normal")
                # Keep the spinbox dark/readable when advanced settings are off
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
        resolved_statuses = {"done", "failed", "error", "skipped", "n/a"}

        for step_key in STEP_DISPLAY_ORDER:
            st = self.step_widgets[step_key]["status"].cget("text").strip().lower()
            if st in resolved_statuses:
                completed += 1

        pct = int(round((completed / max(1, len(STEP_DISPLAY_ORDER))) * 100))
        self.overall_var.set(pct)
        self.overall_text.configure(text=f"{pct}%")

    def _start_log_tail(self, case_dir: Path):
        log_path = case_dir / "analysis.log"

        if self.current_log_path == log_path and self.log_tail_thread and self.log_tail_thread.is_alive():
            return

        self.stop_tail.set()

        if self.log_tail_thread and self.log_tail_thread.is_alive():
            self.log_tail_thread.join(timeout=1.0)

        self.stop_tail.clear()
        self.current_log_path = log_path

        self.output_q.put(f"[info] Progress: tailing {log_path}")
        self.log_tail_thread = threading.Thread(
            target=self._tail_analysis_log,
            args=(log_path,),
            daemon=True,
        )
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
                    line_lower = line.lower()

                    optional_na_steps = {"extract", "file", "filetype", "strings", "capa"}

                    if (
                        os.name == "nt"
                        and step_key in optional_na_steps
                        and (
                            "winerror 2" in line_lower
                            or "cannot find the file specified" in line_lower
                            or "rc=127" in line_lower
                            or "tool not found" in line_lower
                        )
                    ):
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
        self.running_var.set("Running...")

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
        self.current_log_path = None

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
                        if self.current_log_path != (cd / "analysis.log"):
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
                self.output.insert("end", line)
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

