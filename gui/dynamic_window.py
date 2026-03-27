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

from dynamic_analysis.html_report import write_dynamic_html_report
from dynamic_analysis.orchestrator import run_dynamic_analysis
from static_triage_engine.scoring import combined_score_from_case_dir


class DynamicAnalysisWindow(tk.Toplevel):
    def __init__(self, app: "App"):
        super().__init__(app)
        self.app = app
        self.title("Dynamic Analysis")
        self.geometry("980x720")
        self.minsize(840, 620)

        cfg = app.cfg
        default_case_name = app.case_var.get().strip() or Path(app.sample_var.get().strip() or "sample").stem or "dynamic_case"
        default_case_root = Path(app.case_root_var.get().strip()) if app.case_root_var.get().strip() else Path.cwd() / "cases"
        default_case_path = app.case_dir_detected or (default_case_root / default_case_name)
        self.sample_var = tk.StringVar(value=app.sample_var.get().strip())
        self.case_dir_var = tk.StringVar(value=cfg.get("dynamic_case_dir", str(default_case_path)))
        self.timeout_var = tk.IntVar(value=int(cfg.get("dynamic_timeout_seconds", 30)))
        self.procmon_enabled_var = tk.BooleanVar(value=bool(cfg.get("dynamic_procmon_enabled", True)))
        project_root = Path(__file__).resolve().parents[1]
        self.procmon_path_var = tk.StringVar(value=cfg.get("dynamic_procmon_path", str(project_root / "tools" / "Procmon64.exe")))
        self.procmon_config_var = tk.StringVar(value=cfg.get("dynamic_procmon_config_path", str(project_root / "tools" / "procmon-configs" / "dynamic_default.pmc")))
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

        project_root = Path(__file__).resolve().parents[1]
        config_path = project_root / "config.json"
        config_path.write_text(json.dumps(self.app.cfg, indent=2), encoding="utf-8")

    def _use_main_sample(self):
        self.sample_var.set(self.app.sample_var.get().strip())
        if getattr(self.app, "case_dir_detected", None):
            self.case_dir_var.set(str(Path(self.app.case_dir_detected)))
        else:
            case_name = self.app.case_var.get().strip() or Path(self.app.sample_var.get().strip() or "sample").stem or "dynamic_case"
            self.case_dir_var.set(str(Path(self.app.case_root_var.get().strip()) / case_name))
        self._save_cfg()

    def _browse_case_dir(self):
        default_case_root = Path(self.app.case_root_var.get().strip()) if self.app.case_root_var.get().strip() else Path.cwd() / "cases"
        start = Path(self.case_dir_var.get()) if self.case_dir_var.get().strip() else default_case_root
        chosen = filedialog.askdirectory(title="Select dynamic case folder", initialdir=str(start))
        if chosen:
            self.case_dir_var.set(str(Path(chosen)))
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
