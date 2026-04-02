from __future__ import annotations

import json
import html
import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import tkinter.scrolledtext as scrolledtext
except Exception:
    scrolledtext = None


class UnifiedReportWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

        self.title("Unified RingForge Report")
        self.geometry("1180x820+150+100")
        self.minsize(980, 720)
        self.configure(bg="#05070B")
        self.transient(parent)

        self.case_dir = None
        self.output_report_path = None
        self.detected_artifacts = {}

        self.case_path_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready")
        self.case_name_var = tk.StringVar(value="-")
        self.modules_var = tk.StringVar(value="-")
        self.report_path_var = tk.StringVar(value="-")
        self.overall_verdict_var = tk.StringVar(value="-")

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _build_ui(self):
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)

        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(2, weight=1)

        header = ttk.LabelFrame(outer, text="Case Source")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header.columnconfigure(1, weight=1)

        ttk.Label(header, text="Path:").grid(row=0, column=0, sticky="w", padx=8, pady=(8, 6))
        ttk.Entry(header, textvariable=self.case_path_var).grid(row=0, column=1, sticky="ew", padx=8, pady=(8, 6))

        btns = ttk.Frame(header)
        btns.grid(row=0, column=2, sticky="e", padx=8, pady=(8, 6))

        ttk.Button(btns, text="Browse", style="Action.TButton", command=self._browse_case_dir).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Scan", style="Action.TButton", command=self._scan_case_dir).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Generate Report", style="Action.TButton", command=self._generate_report).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Open Report Folder", style="Action.TButton", command=self._open_report_folder).pack(side="left")

        summary = ttk.LabelFrame(outer, text="Summary")
        summary.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        for col in range(4):
            summary.columnconfigure(col, weight=1)

        self._summary_row(summary, 0, "Case Name", self.case_name_var, "Modules Found", self.modules_var)
        self._summary_row(summary, 1, "Overall Verdict", self.overall_verdict_var, "Report Path", self.report_path_var)

        lower = ttk.Panedwindow(outer, orient="horizontal")
        lower.grid(row=2, column=0, sticky="nsew")

        left_panel = ttk.Frame(lower, padding=6)
        middle_panel = ttk.Frame(lower, padding=6)
        right_panel = ttk.Frame(lower, padding=6)

        lower.add(left_panel, weight=2)
        lower.add(middle_panel, weight=3)
        lower.add(right_panel, weight=4)

        for panel in (left_panel, middle_panel, right_panel):
            panel.columnconfigure(0, weight=1)
            panel.rowconfigure(1, weight=1)

        ttk.Label(left_panel, text="Detected Artifacts", style="SectionHeader.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.artifacts_text = self._make_text(left_panel)
        self.artifacts_text.grid(row=1, column=0, sticky="nsew")
        self._set_text(self.artifacts_text, "No case scanned yet.")

        ttk.Label(middle_panel, text="Findings Summary", style="SectionHeader.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.summary_text = self._make_text(middle_panel)
        self.summary_text.grid(row=1, column=0, sticky="nsew")
        self._set_text(self.summary_text, "Run a scan to summarize what is available.")

        ttk.Label(right_panel, text="Generated Report Preview", style="SectionHeader.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.preview_text = self._make_text(right_panel)
        self.preview_text.grid(row=1, column=0, sticky="nsew")
        self._set_text(self.preview_text, "Generate a report to preview the result.")

        footer = ttk.Frame(outer)
        footer.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        footer.columnconfigure(0, weight=1)

        ttk.Label(footer, textvariable=self.status_var, style="Muted.TLabel").grid(row=0, column=0, sticky="w")

    def _summary_row(self, parent, row, label1, var1, label2, var2):
        ttk.Label(parent, text=f"{label1}:").grid(row=row, column=0, sticky="w", padx=8, pady=4)
        ttk.Label(parent, textvariable=var1, wraplength=360, justify="left").grid(row=row, column=1, sticky="ew", padx=8, pady=4)
        ttk.Label(parent, text=f"{label2}:").grid(row=row, column=2, sticky="w", padx=8, pady=4)
        ttk.Label(parent, textvariable=var2, wraplength=360, justify="left").grid(row=row, column=3, sticky="ew", padx=8, pady=4)

    def _make_text(self, parent):
        if scrolledtext is not None:
            return scrolledtext.ScrolledText(
                parent,
                wrap="word",
                height=18,
                bg="#0B1220",
                fg="#F7FAFF",
                insertbackground="#F7FAFF",
                relief="flat",
                borderwidth=1,
                padx=10,
                pady=10,
                font=("Consolas", 10),
            )

        return tk.Text(
            parent,
            wrap="word",
            height=18,
            bg="#0B1220",
            fg="#F7FAFF",
            insertbackground="#F7FAFF",
            relief="flat",
            borderwidth=1,
            padx=10,
            pady=10,
            font=("Consolas", 10),
        )

    def _set_text(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _browse_case_dir(self):
        path = filedialog.askdirectory(title="Select case or report folder", parent=self)
        if path:
            self.case_path_var.set(path)
        self._bring_to_front()

    def _bring_to_front(self):
        try:
            self.lift()
            self.focus_force()
            self.after(50, self.lift)
        except Exception:
            pass

    def _load_json_if_exists(self, path_str: str):
        try:
            path = Path(path_str)
            if path.exists() and path.is_file():
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return None

    def _detect_artifacts(self, case_dir: Path) -> dict:
        checks = {
            "Static Analysis": [
                case_dir / "report.json",
                case_dir / "summary.json",
                case_dir / "metadata" / "run_summary.json",
                case_dir / "yara_results.json",
                case_dir / "reports" / "report.html",
                case_dir / "reports" / "static_report.html",
            ],
            "Dynamic Analysis": [
                case_dir / "metadata" / "dynamic_run_summary.json",
                case_dir / "reports" / "dynamic_findings.json",
                case_dir / "files" / "dropped_files_summary.json",
                case_dir / "reports" / "dynamic_report.html",
            ],
            "Manual API Tester": [
                case_dir / "api" / "manual_api_latest.json",
                case_dir / "api" / "manual_api_latest.html",
            ],
            "Spec Analysis": [
                case_dir / "spec" / "spec_inventory_latest.json",
                case_dir / "spec" / "spec_inventory_latest.html",
                case_dir / "spec" / "api_spec_analysis.json",
                case_dir / "api_spec_analysis.json",
                case_dir / "reports" / "api_spec_analysis.json",
            ],
            "Browser Extension Analysis": [
                case_dir / "ringforge_extension_reports",
                case_dir / "extension_analysis.json",
                case_dir / "reports" / "extension_analysis.json",
            ],
        }

        results = {}
        for module_name, candidates in checks.items():
            found_paths = [str(p) for p in candidates if p.exists()]
            results[module_name] = {
                "found": bool(found_paths),
                "paths": found_paths,
            }
        return results

    def _build_detailed_findings(self) -> dict:
        findings = {
            "static": [],
            "dynamic": [],
            "api": [],
            "spec": [],
            "extension": [],
        }

        static_paths = self.detected_artifacts.get("Static Analysis", {}).get("paths", [])
        dynamic_paths = self.detected_artifacts.get("Dynamic Analysis", {}).get("paths", [])
        api_paths = self.detected_artifacts.get("Manual API Tester", {}).get("paths", [])
        spec_paths = self.detected_artifacts.get("Spec Analysis", {}).get("paths", [])
        extension_paths = self.detected_artifacts.get("Browser Extension Analysis", {}).get("paths", [])

        for p in static_paths:
            data = self._load_json_if_exists(p)
            if not isinstance(data, dict):
                continue

            if "score" in data:
                findings["static"].append(f"Score: {data['score']}")
            if "verdict" in data:
                findings["static"].append(f"Verdict: {data['verdict']}")
            if "confidence" in data:
                findings["static"].append(f"Confidence: {data['confidence']}")

            if "sample_path" in data:
                findings["static"].append(f"Sample: {Path(str(data['sample_path'])).name}")

            if "engine" in data:
                findings["static"].append(f"YARA engine: {data['engine']}")

            if "match_count" in data:
                findings["static"].append(f"YARA match count: {data['match_count']}")

            if "rule_file_count" in data:
                findings["static"].append(f"YARA rule files loaded: {data['rule_file_count']}")

            if data.get("matched") is True:
                findings["static"].append("YARA produced one or more matches")
            elif data.get("matched") is False:
                findings["static"].append("YARA produced no matches")

            matches = data.get("matches", [])
            if isinstance(matches, list) and matches:
                matched_rules = []
                for m in matches[:10]:
                    if isinstance(m, dict):
                        matched_rules.append(str(m.get("rule", "unknown")))
                    else:
                        matched_rules.append(str(m))
                findings["static"].append("Matched rules: " + ", ".join(matched_rules))

            if data.get("error"):
                findings["static"].append(f"YARA error: {data['error']}")

        for p in dynamic_paths:
            data = self._load_json_if_exists(p)
            if not isinstance(data, dict):
                continue

            if "score" in data:
                findings["dynamic"].append(f"Score: {data['score']}")
            if "severity" in data:
                findings["dynamic"].append(f"Severity: {data['severity']}")
            if "verdict" in data:
                findings["dynamic"].append(f"Verdict: {data['verdict']}")

            source = data.get("findings", data)
            if not any(k in source for k in ("highlights", "spawned_processes", "counts")):
                continue

            spawned = source.get("spawned_processes", [])
            spawned_count = len(spawned) if isinstance(spawned, list) else 0

            highlights = source.get("highlights", [])
            if isinstance(highlights, list):
                for x in highlights[:10]:
                    text = str(x).strip()
                    if spawned_count and text.lower() == f"spawned processes observed: {spawned_count}".lower():
                        continue
                    findings["dynamic"].append(text)

            if isinstance(spawned, list):
                findings["dynamic"].append(f"Spawned processes: {spawned_count}")

                preview = []
                seen_names = set()
                for item in spawned[:10]:
                    if isinstance(item, dict):
                        proc_name = item.get("path") or item.get("process_name") or "unknown"
                        name_only = Path(str(proc_name)).name
                        if name_only not in seen_names:
                            seen_names.add(name_only)
                            preview.append(name_only)

                if preview:
                    findings["dynamic"].append("Spawned process names: " + ", ".join(preview))

            counts = source.get("counts", {})
            if isinstance(counts, dict):
                if "interesting_events" in counts:
                    findings["dynamic"].append(f"Interesting events: {counts['interesting_events']}")
                if "process_creates" in counts:
                    findings["dynamic"].append(f"Process creates: {counts['process_creates']}")
                if "network_events" in counts:
                    findings["dynamic"].append(f"Network events: {counts['network_events']}")
                if "file_write_events" in counts:
                    findings["dynamic"].append(f"File write events: {counts['file_write_events']}")
                if "persistence_hits" in counts:
                    findings["dynamic"].append(f"Persistence hits: {counts['persistence_hits']}")

            break

        for p in api_paths:
            data = self._load_json_if_exists(p)
            if not isinstance(data, dict):
                continue

            req = data.get("request", {}) if isinstance(data.get("request"), dict) else {}
            resp = data.get("response", {}) if isinstance(data.get("response"), dict) else {}

            if "method" in req:
                findings["api"].append(f"Method: {req['method']}")
            if "url" in req:
                findings["api"].append(f"URL: {req['url']}")
            if "status_code" in resp:
                findings["api"].append(f"HTTP status: {resp['status_code']}")
            if "reason" in resp and resp.get("reason"):
                findings["api"].append(f"Reason: {resp['reason']}")
            break

        for p in spec_paths:
            data = self._load_json_if_exists(p)
            if not isinstance(data, dict):
                continue

            if "score" in data:
                findings["spec"].append(f"Score: {data['score']}")
            if "verdict" in data:
                findings["spec"].append(f"Verdict: {data['verdict']}")
            if "confidence" in data:
                findings["spec"].append(f"Confidence: {data['confidence']}")

            summary = data.get("summary", {})
            if isinstance(summary, dict) and "endpoint_count" in summary:
                findings["spec"].append(f"Endpoints: {summary['endpoint_count']}")

            if "auth_summary" in data:
                findings["spec"].append("Authentication summary present")

            detections = data.get("detections", [])
            if isinstance(detections, list):
                findings["spec"].append(f"Spec detections: {len(detections)}")
            break

        for p in extension_paths:
            path = Path(p)

            if path.is_dir():
                json_candidates = list(path.glob("*_extension_analysis.json"))
                for candidate in json_candidates:
                    data = self._load_json_if_exists(str(candidate))
                    if not isinstance(data, dict):
                        continue

                    summary = data.get("summary", {})
                    if isinstance(summary, dict):
                        findings["extension"].append(f"Extension verdict: {summary.get('risk_verdict', '-')}")
                        findings["extension"].append(f"Extension risk score: {summary.get('risk_score', '0')}")
                        findings["extension"].append(f"Files found: {summary.get('files_found', '0')}")
                        break
            else:
                data = self._load_json_if_exists(str(path))
                if isinstance(data, dict):
                    summary = data.get("summary", {})
                    if isinstance(summary, dict):
                        findings["extension"].append(f"Extension verdict: {summary.get('risk_verdict', '-')}")
                        findings["extension"].append(f"Extension risk score: {summary.get('risk_score', '0')}")
                        findings["extension"].append(f"Files found: {summary.get('files_found', '0')}")

        for key in findings:
            deduped = []
            seen = set()
            for item in findings[key]:
                if item not in seen:
                    seen.add(item)
                    deduped.append(item)
            findings[key] = deduped or ["No detailed findings extracted."]

        return findings

    def _derive_overall_verdict(self, artifacts: dict) -> str:
        dynamic_summary = self._load_json_if_exists(str(self.case_dir / "metadata" / "dynamic_run_summary.json")) if self.case_dir else None
        static_summary = self._load_json_if_exists(str(self.case_dir / "report.json")) if self.case_dir else None
        if not isinstance(static_summary, dict) and self.case_dir:
            static_summary = self._load_json_if_exists(str(self.case_dir / "summary.json"))

        if isinstance(dynamic_summary, dict) and dynamic_summary.get("verdict"):
            return str(dynamic_summary.get("verdict"))

        if isinstance(static_summary, dict) and static_summary.get("verdict"):
            return str(static_summary.get("verdict"))

        findings = self._build_detailed_findings()
        joined = " ".join(" ".join(items).lower() for items in findings.values() if isinstance(items, list))

        if "elevated attention" in joined or "high risk" in joined:
            return "High Risk"
        if "needs review" in joined or "moderate risk" in joined or "persistence" in joined:
            return "Moderate Risk"
        if "benign / clean baseline" in joined or "low suspicion" in joined:
            return "Low Risk"

        count = sum(1 for meta in artifacts.values() if meta.get("found"))
        if count >= 2:
            return "Moderate Activity"
        if count >= 1:
            return "Limited Activity"
        return "No Results"

    def _scan_case_dir(self):
        raw = self.case_path_var.get().strip()
        if not raw:
            messagebox.showwarning("Unified Report", "Select a case folder first.")
            return

        case_dir = Path(raw)
        if not case_dir.exists() or not case_dir.is_dir():
            messagebox.showerror("Unified Report", f"Folder not found:\n{case_dir}")
            return

        self.case_dir = case_dir
        self.case_name_var.set(case_dir.name)

        artifacts = self._detect_artifacts(case_dir)
        self.detected_artifacts = artifacts

        found_modules = [name for name, meta in artifacts.items() if meta.get("found")]
        self.modules_var.set(", ".join(found_modules) if found_modules else "None")
        self.overall_verdict_var.set(self._derive_overall_verdict(artifacts))

        artifact_lines = []
        findings = self._build_detailed_findings()
        summary_lines = []

        for module_name, meta in artifacts.items():
            found = meta.get("found", False)
            label = "FOUND" if found else "NOT FOUND"
            artifact_lines.append(f"[{label}] {module_name}")
            for p in meta.get("paths", []):
                artifact_lines.append(f"  - {p}")

        module_map = {
            "Static Analysis": "static",
            "Dynamic Analysis": "dynamic",
            "Manual API Tester": "api",
            "Spec Analysis": "spec",
            "Browser Extension Analysis": "extension",
        }

        for module_name, key in module_map.items():
            summary_lines.append(f"{module_name}:")
            for item in findings.get(key, []):
                summary_lines.append(f"  - {item}")
            summary_lines.append("")

        if not artifact_lines:
            artifact_lines.append("No artifacts detected.")
        if not summary_lines:
            summary_lines.append("Nothing found yet.")

        self._set_text(self.artifacts_text, "\n".join(artifact_lines))
        self._set_text(self.summary_text, "\n".join(summary_lines))
        self.status_var.set(f"Scanned case folder: {case_dir}")
        self._bring_to_front()

    def _generate_report(self):
        if self.case_dir is None:
            self._scan_case_dir()
            if self.case_dir is None:
                return

        findings = self._build_detailed_findings()

        static_summary = self._load_json_if_exists(str(self.case_dir / "report.json"))
        if not isinstance(static_summary, dict):
            static_summary = self._load_json_if_exists(str(self.case_dir / "summary.json"))

        dynamic_summary = self._load_json_if_exists(str(self.case_dir / "metadata" / "dynamic_run_summary.json"))

        spec_summary = self._load_json_if_exists(str(self.case_dir / "spec" / "spec_inventory_latest.json"))
        if not isinstance(spec_summary, dict):
            spec_summary = self._load_json_if_exists(str(self.case_dir / "api_spec_analysis.json"))

        static_score = static_summary.get("score") if isinstance(static_summary, dict) else None
        dynamic_score = dynamic_summary.get("score") if isinstance(dynamic_summary, dict) else None
        spec_score = spec_summary.get("score") if isinstance(spec_summary, dict) else None

        data = {
            "case_name": self.case_dir.name,
            "case_path": str(self.case_dir),
            "overall_verdict": self._derive_overall_verdict(self.detected_artifacts),
            "static_score": static_score,
            "dynamic_score": dynamic_score,
            "spec_score": spec_score,
            "modules": self.detected_artifacts,
            "findings": findings,
        }

        report_dir = self.case_dir / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)

        json_path = report_dir / "unified_report.json"
        html_path = report_dir / "unified_report.html"

        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            html_text = self._build_html_report(data)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_text)

            self.output_report_path = html_path
            self.report_path_var.set(str(html_path))
            preview = html_text[:12000]
            if len(html_text) > 12000:
                preview += "\n\n[Preview truncated]"
            self._set_text(self.preview_text, preview)
            self.status_var.set(f"Unified report created: {html_path}")
            self._bring_to_front()
        except Exception as e:
            messagebox.showerror("Unified Report", f"Could not generate report:\n{e}")
            self._bring_to_front()

    def _build_html_report(self, data: dict) -> str:
        case_name = html.escape(str(data.get("case_name", "-")))
        case_path = html.escape(str(data.get("case_path", "-")))
        overall_verdict = html.escape(str(data.get("overall_verdict", "-")))
        static_score = data.get("static_score")
        dynamic_score = data.get("dynamic_score")
        spec_score = data.get("spec_score")
        modules = data.get("modules", {}) or {}
        findings = data.get("findings", {}) or {}

        def fmt_score(value):
            return "-" if value is None else html.escape(str(value))

        def list_section(title: str, items: list[str]) -> str:
            body = "<ul>" + "".join(f"<li>{html.escape(str(x))}</li>" for x in items) + "</ul>" if items else "<p>-</p>"
            return f"""
  <section class="card">
    <h2>{html.escape(title)}</h2>
    {body}
  </section>
"""

        rows = []
        for module_name, meta in modules.items():
            found = "Yes" if meta.get("found") else "No"
            paths = "<br>".join(html.escape(str(p)) for p in meta.get("paths", [])) or "-"
            rows.append(
                f"<tr><th>{html.escape(module_name)}</th><td>{found}</td><td>{paths}</td></tr>"
            )

        rows_html = "\n".join(rows) if rows else "<tr><td colspan='3'>No module data found.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Unified RingForge Report</title>
<style>
:root {{
  --bg: #0A0A0A;
  --panel: #101726;
  --border: #22314F;
  --text: #F3F6FB;
  --muted: #A9B7D0;
  --blue: #6EA8FF;
}}
* {{ box-sizing: border-box; }}
body {{
  font-family: Segoe UI, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  margin: 0;
  padding: 24px;
}}
.container {{
  max-width: 1200px;
  margin: 0 auto;
}}
.banner {{
  background: linear-gradient(135deg, #0A0A0A, #0F1C3F 45%, #1E4ED8 100%);
  border: 1px solid #22314F;
  border-radius: 18px;
  padding: 22px;
  margin-bottom: 20px;
}}
h1 {{
  margin: 0 0 8px 0;
  font-size: 30px;
  color: var(--blue);
}}
h2 {{
  color: var(--text);
  margin-top: 0;
}}
.subtitle {{
  color: var(--muted);
  margin-top: 6px;
  font-size: 14px;
}}
.card {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 18px;
  margin-bottom: 18px;
}}
table {{
  width: 100%;
  border-collapse: collapse;
}}
th, td {{
  text-align: left;
  padding: 10px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  word-break: break-word;
}}
th {{
  width: 24%;
  color: #cbd5e1;
}}
ul {{
  margin: 0;
  padding-left: 20px;
}}
li {{
  margin-bottom: 6px;
}}
.footer {{
  margin-top: 20px;
  color: var(--muted);
  font-size: 12px;
  text-align: right;
}}
</style>
</head>
<body>
<div class="container">
  <div class="banner">
    <h1>Unified RingForge Report</h1>
    <div class="subtitle">Generated by RingForge Workbench</div>
  </div>

  <section class="card">
    <h2>Case Overview</h2>
    <table>
      <tr><th>Case Name</th><td>{case_name}</td></tr>
      <tr><th>Case Path</th><td>{case_path}</td></tr>
      <tr><th>Static Score</th><td>{fmt_score(static_score)}</td></tr>
      <tr><th>Dynamic Score</th><td>{fmt_score(dynamic_score)}</td></tr>
      <tr><th>Spec Score</th><td>{fmt_score(spec_score)}</td></tr>
      <tr><th>Overall Verdict</th><td>{overall_verdict}</td></tr>
    </table>
  </section>

  <section class="card">
    <h2>Detected Modules</h2>
    <table>
      <tr>
        <th>Module</th>
        <th>Found</th>
        <th>Artifacts</th>
      </tr>
      {rows_html}
    </table>
  </section>

  {list_section("Static Analysis Summary", findings.get("static", []))}
  {list_section("Dynamic Analysis Summary", findings.get("dynamic", []))}
  {list_section("Manual API Tester Summary", findings.get("api", []))}
  {list_section("Spec Analysis Summary", findings.get("spec", []))}
  {list_section("Browser Extension Analysis Summary", findings.get("extension", []))}

  <div class="footer">Generated by RingForge Workbench • Unified Report</div>
</div>
</body>
</html>"""

    def _open_report_folder(self):
        if self.case_dir is None:
            messagebox.showinfo("Unified Report", "No case folder selected yet.")
            return

        report_dir = self.case_dir / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)

        try:
            if os.name == "nt":
                os.startfile(str(report_dir))
            else:
                messagebox.showinfo("Open Report Folder", f"Report folder:\n{report_dir}")
            self.status_var.set(f"Opened report folder: {report_dir}")
        except Exception as e:
            messagebox.showerror("Open Report Folder", f"Could not open report folder:\n{e}")