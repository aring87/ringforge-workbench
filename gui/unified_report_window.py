from __future__ import annotations

import json
import html
import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from static_triage_engine.verdict_report import render_verdict_report
from gui import theme as T
from gui.components import HeaderBar, ScrolledText
from gui.styles import apply_window_theme

try:
    import tkinter.scrolledtext as scrolledtext
except Exception:
    scrolledtext = None


class UnifiedReportWindow(tk.Toplevel):
    r"""
    Unified RingForge report window with the cleaned case-home layout.

    Preferred layout:

        cases\<case>\
            case_metadata.json
            combined_verdict.json
            metadata\
                static_run_summary.json
                combined_verdict.json

            static_analysis\
                summary.json
                iocs.json
                pe_metadata.json
                lief_metadata.json
                report.html
                report.md
                metadata\
                    static_run_summary.json

            dynamic_analysis\
                dynamic_runs\
                    <run_id>\
                        metadata\
                            dynamic_run_summary.json
                        procmon\
                        persistence\
                        files\
                        reports\
                            dynamic_findings.json
                reports\
                    dynamic_report.html

            unified_report\
                unified_report.json
                unified_report.html

    Legacy paths are still supported.
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

        self.title("Unified RingForge Report")
        self.geometry("1180x820+150+100")
        self.minsize(980, 720)
        self.configure(bg=T.BG)
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

    # ---------------------------------------------------------------------
    # UI
    # ---------------------------------------------------------------------

    def _build_ui(self):
        apply_window_theme(self)

        outer = ttk.Frame(self, style="App.TFrame", padding=12)
        outer.pack(fill="both", expand=True)

        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(3, weight=1)

        self._build_top_banner(outer)

        header = ttk.LabelFrame(outer, text="Case Source")
        header.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        header.columnconfigure(1, weight=1)

        ttk.Label(header, text="Path:").grid(row=0, column=0, sticky="w", padx=8, pady=(8, 6))
        ttk.Entry(header, textvariable=self.case_path_var).grid(row=0, column=1, sticky="ew", padx=8, pady=(8, 6))

        btns = ttk.Frame(header)
        btns.grid(row=0, column=2, sticky="e", padx=8, pady=(8, 6))

        # "Generate Report" is the primary action here; the rest support it.
        ttk.Button(btns, text="Browse", style="Secondary.TButton", command=self._browse_case_dir).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Scan", style="Secondary.TButton", command=self._scan_case_dir).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Generate Report", style="Action.TButton", command=self._generate_report).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Open Report Folder", style="Secondary.TButton", command=self._open_report_folder).pack(side="left")

        summary = ttk.LabelFrame(outer, text="Summary")
        summary.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        for col in range(4):
            summary.columnconfigure(col, weight=1)

        self._summary_row(summary, 0, "Case Name", self.case_name_var, "Modules Found", self.modules_var)
        self._summary_row(summary, 1, "Overall Verdict", self.overall_verdict_var, "Report Path", self.report_path_var)

        lower = ttk.Panedwindow(outer, orient="horizontal")
        lower.grid(row=3, column=0, sticky="nsew")

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
        footer.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        footer.columnconfigure(0, weight=1)

        ttk.Label(footer, textvariable=self.status_var, style="Muted.TLabel").grid(row=0, column=0, sticky="w")

    def _build_top_banner(self, parent):
        """Branded page header, shared with every other workbench window."""
        logo_path = Path(__file__).resolve().parents[1] / "assets" / "anvil.png"

        header = HeaderBar(
            parent,
            "RingForge",
            subtitle="Unified Report",
            description=(
                "Combine artifacts from any completed analysis modules into one "
                "consolidated report."
            ),
            logo_path=logo_path if logo_path.exists() else None,
            logo_size=72,
            parent_bg=T.BG,
        )
        header.grid(row=0, column=0, sticky="ew", pady=(0, T.SPACE_MD))
        self._banner_logo_img = getattr(header, "_logo_image", None)

    def _summary_row(self, parent, row, label1, var1, label2, var2):
        ttk.Label(parent, text=f"{label1}:").grid(row=row, column=0, sticky="w", padx=8, pady=4)
        ttk.Label(parent, textvariable=var1, wraplength=360, justify="left").grid(row=row, column=1, sticky="ew", padx=8, pady=4)
        ttk.Label(parent, text=f"{label2}:").grid(row=row, column=2, sticky="w", padx=8, pady=4)
        ttk.Label(parent, textvariable=var2, wraplength=360, justify="left").grid(row=row, column=3, sticky="ew", padx=8, pady=4)

    def _make_text(self, parent):
        return ScrolledText(
            parent,
            wrap="word",
            height=18,
            bg=T.SUNKEN,
            fg=T.TEXT_SECONDARY,
            insertbackground=T.ACCENT,
            selectbackground=T.ACCENT_SOFT,
            selectforeground=T.TEXT,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
            padx=10,
            pady=10,
            font=T.f_mono(10),
        )

    def _set_text(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _browse_case_dir(self):
        path = filedialog.askdirectory(
            title="Select case folder",
            parent=self,
        )
        if path:
            p = self._normalize_case_dir(Path(path))
            self.case_path_var.set(str(p))

    def _bring_to_front(self):
        try:
            self.lift()
            self.focus_force()
            self.after(50, self.lift)
        except Exception:
            pass

    # ---------------------------------------------------------------------
    # Path/data helpers
    # ---------------------------------------------------------------------

    def _normalize_case_dir(self, path: Path) -> Path:
        """
        If user browses directly into static_analysis or dynamic_analysis,
        normalize back to the shared case-home folder.
        """
        if path.name in {"static_analysis", "dynamic_analysis", "spec_analysis", "api_analysis", "extension_analysis"}:
            return path.parent

        # If user picks a specific dynamic run folder, walk back to case home:
        # cases\<case>\dynamic_analysis\dynamic_runs\<run_id>
        parts = [p.lower() for p in path.parts]
        if "dynamic_runs" in parts and "dynamic_analysis" in parts:
            try:
                idx = parts.index("dynamic_analysis")
                return Path(*path.parts[:idx])
            except Exception:
                pass

        return path

    def _load_json_if_exists(self, path_str: str | Path):
        try:
            path = Path(path_str)
            if path.exists() and path.is_file():
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    return json.load(f)
        except Exception:
            pass
        return None

    def _existing_paths(self, paths: list[Path]) -> list[str]:
        found = []
        seen = set()
        for p in paths:
            key = str(p).lower()
            if key in seen:
                continue
            seen.add(key)
            try:
                if p.exists():
                    found.append(str(p))
            except Exception:
                pass
        return found

    def _latest_path(self, paths: list[Path]) -> Path | None:
        existing = [p for p in paths if p.exists()]
        if not existing:
            return None
        return sorted(existing, key=lambda p: p.stat().st_mtime, reverse=True)[0]
        
    def _latest_child_dir(self, parent_dir: Path) -> Path | None:
        try:
            if not parent_dir.exists() or not parent_dir.is_dir():
                return None

            dirs = [p for p in parent_dir.iterdir() if p.is_dir()]
            if not dirs:
                return None

            return sorted(dirs, key=lambda p: p.stat().st_mtime, reverse=True)[0]
        except Exception:
            return None

    def _dynamic_summary_candidates(self, case_dir: Path) -> list[Path]:
        candidates = []

        dynamic_runs_dir = case_dir / "dynamic_analysis" / "dynamic_runs"
        if dynamic_runs_dir.exists():
            try:
                candidates.extend(
                    sorted(
                        dynamic_runs_dir.glob("*/metadata/dynamic_run_summary.json"),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True,
                    )
                )
            except Exception:
                pass

        # Legacy and compatibility paths.
        candidates.extend([
            case_dir / "metadata" / "dynamic_run_summary.json",
            case_dir / "dynamic_analysis" / "metadata" / "dynamic_run_summary.json",
            case_dir / "dynamic_analysis" / "dynamic_run_summary.json",
            case_dir / "reports" / "dynamic_run_summary.json",
            case_dir / "dynamic_run_summary.json",
        ])
        return candidates

    def _dynamic_findings_candidates(self, case_dir: Path) -> list[Path]:
        candidates = []

        dynamic_runs_dir = case_dir / "dynamic_analysis" / "dynamic_runs"
        if dynamic_runs_dir.exists():
            try:
                candidates.extend(
                    sorted(
                        dynamic_runs_dir.glob("*/reports/dynamic_findings.json"),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True,
                    )
                )
                candidates.extend(
                    sorted(
                        dynamic_runs_dir.glob("*/dynamic_findings.json"),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True,
                    )
                )
            except Exception:
                pass

        candidates.extend([
            case_dir / "dynamic_analysis" / "reports" / "dynamic_findings.json",
            case_dir / "dynamic_analysis" / "dynamic_findings.json",
            case_dir / "reports" / "dynamic_findings.json",
            case_dir / "dynamic_findings.json",
        ])
        return candidates

    def _detect_artifacts(self, case_dir: Path) -> dict:
        static_candidates = [
            case_dir / "static_analysis" / "summary.json",
            case_dir / "static_analysis" / "report.html",
            case_dir / "static_analysis" / "report.md",
            case_dir / "static_analysis" / "iocs.json",
            case_dir / "static_analysis" / "pe_metadata.json",
            case_dir / "static_analysis" / "lief_metadata.json",
            case_dir / "static_analysis" / "metadata" / "static_run_summary.json",
            case_dir / "metadata" / "static_run_summary.json",
            # legacy
            case_dir / "report.json",
            case_dir / "summary.json",
            case_dir / "metadata" / "run_summary.json",
            case_dir / "yara_results.json",
            case_dir / "reports" / "report.html",
            case_dir / "reports" / "static_report.html",
        ]

        dynamic_candidates = [
            *self._dynamic_summary_candidates(case_dir),
            *self._dynamic_findings_candidates(case_dir),
            case_dir / "dynamic_analysis" / "reports" / "dynamic_report.html",
        ]
        
        extension_runs_dir = case_dir / "browser_extension_analysis" / "runs"
        latest_extension_run_dir = self._latest_child_dir(extension_runs_dir)

        extension_run_candidates = []
        if latest_extension_run_dir is not None:
            extension_run_candidates.append(latest_extension_run_dir)
        
        checks = {
            "Static Analysis": static_candidates,
            "Dynamic Analysis": dynamic_candidates,
            "Manual API Tester": [
                case_dir / "api_analysis" / "manual_api_latest.json",
                case_dir / "api_analysis" / "manual_api_latest.html",
                case_dir / "api" / "manual_api_latest.json",
                case_dir / "api" / "manual_api_latest.html",
            ],
            "Spec Analysis": [
                case_dir / "spec_analysis" / "api_spec_analysis.json",
                case_dir / "spec_analysis" / "metadata" / "api_spec_analysis.json",
                case_dir / "spec_analysis" / "spec_inventory_latest.json",
                case_dir / "spec_analysis" / "spec_inventory_latest.html",
                case_dir / "spec" / "spec_inventory_latest.json",
                case_dir / "spec" / "spec_inventory_latest.html",
                case_dir / "spec" / "api_spec_analysis.json",
                case_dir / "api_spec_analysis.json",
                case_dir / "reports" / "api_spec_analysis.json",
            ],
            "Browser Extension Analysis": [
                case_dir / "browser_extension_analysis" / "browser_extension_analysis.json",
                case_dir / "browser_extension_analysis" / "browser_extension_report.html",
                case_dir / "browser_extension_analysis" / "metadata" / "browser_extension_analysis.json",

                *extension_run_candidates,

                # Legacy compatibility paths
                case_dir / "extension_analysis" / "extension_analysis.json",
                case_dir / "extension_analysis" / "reports" / "extension_analysis.json",
                case_dir / "ringforge_extension_reports",
                case_dir / "extension_analysis.json",
                case_dir / "reports" / "extension_analysis.json",
            ],
            "Case Verdict": [
                case_dir / "combined_verdict.json",
                case_dir / "metadata" / "combined_verdict.json",
            ],
        }

        results = {}
        for module_name, candidates in checks.items():
            found_paths = self._existing_paths(candidates)
            results[module_name] = {
                "found": bool(found_paths),
                "paths": found_paths,
            }
        return results

    # ---------------------------------------------------------------------
    # Findings extraction
    # ---------------------------------------------------------------------

    def _build_detailed_findings(self) -> dict:
        findings = {
            "static": [],
            "dynamic": [],
            "api": [],
            "spec": [],
            "extension": [],
            "combined": [],
        }

        static_paths = self.detected_artifacts.get("Static Analysis", {}).get("paths", [])
        dynamic_paths = self.detected_artifacts.get("Dynamic Analysis", {}).get("paths", [])
        api_paths = self.detected_artifacts.get("Manual API Tester", {}).get("paths", [])
        spec_paths = self.detected_artifacts.get("Spec Analysis", {}).get("paths", [])
        extension_paths = self.detected_artifacts.get("Browser Extension Analysis", {}).get("paths", [])
        combined_paths = self.detected_artifacts.get("Combined Score", {}).get("paths", [])

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

            sample_obj = data.get("sample", {})
            if "sample_path" in data:
                findings["static"].append(f"Sample: {Path(str(data['sample_path'])).name}")
            elif isinstance(sample_obj, dict):
                sample_path = sample_obj.get("sample_path") or sample_obj.get("path") or sample_obj.get("target_path")
                if sample_path:
                    findings["static"].append(f"Sample: {Path(str(sample_path)).name}")

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
            if not isinstance(source, dict):
                continue

            spawned = source.get("spawned_processes", [])
            spawned_count = len(spawned) if isinstance(spawned, list) else 0

            highlights = source.get("highlights", [])
            if isinstance(highlights, list):
                for x in highlights[:10]:
                    text = str(x).strip()
                    if text:
                        findings["dynamic"].append(text)

            if isinstance(spawned, list) and spawned:
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
                for key, label in [
                    ("interesting_events", "Interesting events"),
                    ("process_creates", "Process creates"),
                    ("network_events", "Network events"),
                    ("file_write_events", "File write events"),
                    ("persistence_hits", "Persistence hits"),
                ]:
                    if key in counts:
                        findings["dynamic"].append(f"{label}: {counts[key]}")

            # Stop after first JSON dynamic source. Usually newest run summary.
            if "dynamic_run_summary.json" in str(p).lower() or "dynamic_findings.json" in str(p).lower():
                break

        for p in api_paths:
            data = self._load_json_if_exists(p)
            if not isinstance(data, dict):
                continue

            req = data.get("request", {}) if isinstance(data.get("request"), dict) else {}
            resp = data.get("response", {}) if isinstance(data.get("response"), dict) else {}

            module_name = data.get("module") or data.get("tool")
            if module_name:
                findings["api"].append(f"Tool: {module_name}")

            saved_at = data.get("saved_at")
            if saved_at:
                findings["api"].append(f"Saved at: {saved_at}")

            redaction = data.get("redaction")
            if redaction:
                findings["api"].append(f"Redaction: {redaction}")

            if "method" in req:
                findings["api"].append(f"Method: {req['method']}")

            if "url" in req:
                findings["api"].append(f"URL: {req['url']}")

            if "verify_ssl" in req:
                findings["api"].append(f"Verify SSL: {req['verify_ssl']}")

            if "timeout_seconds" in req:
                findings["api"].append(f"Timeout: {req['timeout_seconds']} seconds")

            # Support both old and new Manual API Tester schemas.
            status_value = resp.get("status", resp.get("status_code"))
            if status_value not in (None, ""):
                findings["api"].append(f"HTTP status: {status_value}")

            if "reason" in resp and resp.get("reason"):
                findings["api"].append(f"Reason: {resp['reason']}")

            content_type = resp.get("content_type")
            if content_type:
                findings["api"].append(f"Content-Type: {content_type}")

            elapsed = resp.get("elapsed")
            if elapsed:
                findings["api"].append(f"Elapsed: {elapsed}")

            size = resp.get("size")
            if size:
                findings["api"].append(f"Response size: {size}")

            analysis = data.get("analysis")
            if isinstance(analysis, str) and analysis.strip():
                analysis_lines = []
                for line in analysis.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("[") or line.lower().startswith("note:"):
                        analysis_lines.append(line)

                if analysis_lines:
                    findings["api"].append("Analysis findings:")
                    for line in analysis_lines[:12]:
                        findings["api"].append(f"  {line}")

            html_report = data.get("html_report")
            if html_report:
                findings["api"].append(f"Latest HTML: {html_report}")

            user_saved_html = data.get("user_saved_html_report")
            if user_saved_html:
                findings["api"].append(f"Exported HTML: {user_saved_html}")

            break
            
        for p in spec_paths:
            data = self._load_json_if_exists(p)
            if not isinstance(data, dict):
                continue

            title = data.get("title")
            version = data.get("version")
            spec_type = data.get("spec_type")
            fmt = data.get("format")
            confidence = data.get("confidence")

            if title:
                findings["spec"].append(f"Spec title: {title}")
            if version:
                findings["spec"].append(f"Spec version: {version}")
            if spec_type:
                findings["spec"].append(f"Spec type: {spec_type}")
            if fmt:
                findings["spec"].append(f"Format: {fmt}")
            if confidence:
                findings["spec"].append(f"Parser confidence: {confidence}")

            summary = data.get("summary", {}) if isinstance(data.get("summary"), dict) else {}
            scoring = data.get("scoring", {}) if isinstance(data.get("scoring"), dict) else {}

            if summary:
                findings["spec"].append(f"Endpoints: {summary.get('endpoint_count', 0)}")
                findings["spec"].append(f"Unauthenticated endpoints: {summary.get('unauthenticated_endpoint_count', 0)}")
                findings["spec"].append(f"Sensitive unauthenticated endpoints: {summary.get('sensitive_unauthenticated_endpoint_count', 0)}")
                findings["spec"].append(f"High-risk endpoints: {summary.get('high_risk_endpoint_count', 0)}")
                findings["spec"].append(f"Medium-risk endpoints: {summary.get('medium_risk_endpoint_count', 0)}")
                findings["spec"].append(f"Schema issue endpoints: {summary.get('schema_issue_endpoint_count', 0)}")

            if scoring:
                findings["spec"].append(f"HTTP server detected: {scoring.get('http_server_detected', False)}")
                findings["spec"].append(f"File upload endpoints: {scoring.get('file_upload_endpoints', 0)}")
                findings["spec"].append(f"Auth gap count: {scoring.get('auth_gap_count', 0)}")

            auth_summary = data.get("auth_summary", [])
            if isinstance(auth_summary, list):
                findings["spec"].append("Auth schemes: " + (", ".join(str(x) for x in auth_summary) if auth_summary else "none"))

            risk_notes = data.get("risk_notes", [])
            if isinstance(risk_notes, list) and risk_notes:
                findings["spec"].append("Risk notes:")
                for note in risk_notes[:10]:
                    findings["spec"].append(f"  - {note}")

            top_risky = data.get("top_risky_endpoints", [])
            if isinstance(top_risky, list) and top_risky:
                findings["spec"].append("Notable endpoints:")
                for ep in top_risky[:8]:
                    if isinstance(ep, dict):
                        findings["spec"].append(
                            f"  - {ep.get('method', '')} {ep.get('path', '')} "
                            f"[{ep.get('risk_level', '')} | score={ep.get('risk_score', 0)}]"
                        )

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
                        findings["extension"].append(f"Extension name: {summary.get('name', '-')}")
                        findings["extension"].append(f"Extension version: {summary.get('version', '-')}")
                        findings["extension"].append(f"Manifest version: {summary.get('manifest_version', '-')}")
                        findings["extension"].append(f"Extension verdict: {summary.get('risk_verdict', '-')}")
                        findings["extension"].append(f"Extension risk score: {summary.get('risk_score', '0')}")
                        findings["extension"].append(f"Files found: {summary.get('files_found', '0')}")
                        findings["extension"].append(f"Permissions: {summary.get('permissions', '-')}")
                        findings["extension"].append(f"Host permissions: {summary.get('host_permissions', '-')}")
                        findings["extension"].append(f"Background: {summary.get('background', '-')}")
                        findings["extension"].append(f"Content scripts: {summary.get('content_scripts', '-')}")
                        findings["extension"].append(f"Web resources: {summary.get('web_resources', '-')}")
                        findings["extension"].append(f"Externally connectable: {summary.get('externally_connectable', '-')}")
                        findings["extension"].append(f"Update URL: {summary.get('update_url', '-')}")
                        findings["extension"].append(f"CSP: {summary.get('csp', '-')}")
                        
                        risk_notes = data.get("risk_notes", [])
                        if isinstance(risk_notes, list) and risk_notes:
                            findings["extension"].append("Risk notes:")
                            for note in risk_notes[:12]:
                                findings["extension"].append(f"  {note}")
            else:
                data = self._load_json_if_exists(str(path))
                if isinstance(data, dict):
                    summary = data.get("summary", {})
                    if isinstance(summary, dict):
                        findings["extension"].append(f"Extension name: {summary.get('name', '-')}")
                        findings["extension"].append(f"Extension version: {summary.get('version', '-')}")
                        findings["extension"].append(f"Manifest version: {summary.get('manifest_version', '-')}")
                        findings["extension"].append(f"Extension verdict: {summary.get('risk_verdict', '-')}")
                        findings["extension"].append(f"Extension risk score: {summary.get('risk_score', '0')}")
                        findings["extension"].append(f"Files found: {summary.get('files_found', '0')}")
                        findings["extension"].append(f"Permissions: {summary.get('permissions', '-')}")
                        findings["extension"].append(f"Host permissions: {summary.get('host_permissions', '-')}")
                        findings["extension"].append(f"Background: {summary.get('background', '-')}")
                        findings["extension"].append(f"Content scripts: {summary.get('content_scripts', '-')}")
                        findings["extension"].append(f"Web resources: {summary.get('web_resources', '-')}")
                        findings["extension"].append(f"Externally connectable: {summary.get('externally_connectable', '-')}")
                        findings["extension"].append(f"Update URL: {summary.get('update_url', '-')}")
                        findings["extension"].append(f"CSP: {summary.get('csp', '-')}")

                    risk_notes = data.get("risk_notes", [])
                    if isinstance(risk_notes, list) and risk_notes:
                        findings["extension"].append("Risk notes:")
                        for note in risk_notes[:12]:
                            findings["extension"].append(f"  {note}")

                    break

        for p in combined_paths:
            data = self._load_json_if_exists(p)
            if not isinstance(data, dict):
                continue

            total = data.get("total_score", data.get("score"))
            severity = data.get("severity")
            verdict = data.get("verdict")

            if total is not None:
                findings["combined"].append(f"Total score: {total}")
            if severity:
                findings["combined"].append(f"Severity: {severity}")
            if verdict:
                findings["combined"].append(f"Verdict: {verdict}")

            subscores = data.get("subscores", {})
            if isinstance(subscores, dict):
                static_score = subscores.get("static")
                dynamic_score = subscores.get("dynamic")
                spec_score = subscores.get("spec")
            else:
                static_score = data.get("static_score")
                dynamic_score = data.get("dynamic_score")
                spec_score = data.get("spec_score")

            if static_score is not None:
                findings["combined"].append(f"Static score: {static_score}")
            if dynamic_score is not None:
                findings["combined"].append(f"Dynamic score: {dynamic_score}")
            if spec_score is not None:
                findings["combined"].append(f"Spec score: {spec_score}")

            break

        for key in findings:
            deduped = []
            seen = set()
            for item in findings[key]:
                if item not in seen:
                    seen.add(item)
                    deduped.append(item)
            findings[key] = deduped

        return findings

    def _latest_static_summary(self) -> dict | None:
        if not self.case_dir:
            return None
        candidates = [
            self.case_dir / "static_analysis" / "summary.json",
            self.case_dir / "static_analysis" / "metadata" / "static_run_summary.json",
            self.case_dir / "metadata" / "static_run_summary.json",
            self.case_dir / "summary.json",
            self.case_dir / "report.json",
        ]
        p = self._latest_path(candidates)
        data = self._load_json_if_exists(p) if p else None
        return data if isinstance(data, dict) else None

    def _latest_dynamic_summary(self) -> dict | None:
        if not self.case_dir:
            return None
        p = self._latest_path(self._dynamic_summary_candidates(self.case_dir))
        data = self._load_json_if_exists(p) if p else None
        return data if isinstance(data, dict) else None

    def _latest_spec_summary(self) -> dict | None:
        if not self.case_dir:
            return None
        candidates = [
            self.case_dir / "spec_analysis" / "api_spec_analysis.json",
            self.case_dir / "spec_analysis" / "metadata" / "api_spec_analysis.json",
            self.case_dir / "spec" / "spec_inventory_latest.json",
            self.case_dir / "api_spec_analysis.json",
        ]
        p = self._latest_path(candidates)
        data = self._load_json_if_exists(p) if p else None
        return data if isinstance(data, dict) else None
        
    def _latest_extension_summary(self) -> dict | None:
        if not self.case_dir:
            return None

        candidates = [
            self.case_dir / "browser_extension_analysis" / "browser_extension_analysis.json",
            self.case_dir / "browser_extension_analysis" / "metadata" / "browser_extension_analysis.json",
            self.case_dir / "extension_analysis" / "extension_analysis.json",
            self.case_dir / "extension_analysis.json",
        ]

        runs_dir = self.case_dir / "browser_extension_analysis" / "runs"
        if runs_dir.exists():
            try:
                candidates.extend(
                    sorted(
                        runs_dir.glob("*/browser_extension_analysis.json"),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True,
                    )
                )
            except Exception:
                pass

        p = self._latest_path(candidates)
        data = self._load_json_if_exists(p) if p else None
        return data if isinstance(data, dict) else None

    def _combined_summary(self) -> dict | None:
        if not self.case_dir:
            return None
        p = self._latest_path([
            self.case_dir / "combined_verdict.json",
            self.case_dir / "metadata" / "combined_verdict.json",
        ])
        data = self._load_json_if_exists(p) if p else None
        return data if isinstance(data, dict) else None
        
    def _derive_spec_score_and_verdict(self, spec_summary: dict | None) -> tuple[int | None, str | None]:
        """
        Derive a display score/verdict for spec-only or spec-heavy cases.

        This is intentionally separate from malware/static/dynamic scoring so API
        spec risk does not sound like endpoint malware behavior.
        """
        if not isinstance(spec_summary, dict):
            return None, None

        summary = spec_summary.get("summary", {}) if isinstance(spec_summary.get("summary"), dict) else {}
        scoring = spec_summary.get("scoring", {}) if isinstance(spec_summary.get("scoring"), dict) else {}

        high_count = int(summary.get("high_risk_endpoint_count", 0) or 0)
        medium_count = int(summary.get("medium_risk_endpoint_count", 0) or 0)
        sensitive_unauth = int(summary.get("sensitive_unauthenticated_endpoint_count", 0) or 0)
        auth_gap_count = int(summary.get("auth_gap_count", scoring.get("auth_gap_count", 0)) or 0)
        schema_issue_count = int(summary.get("schema_issue_endpoint_count", scoring.get("schema_issue_endpoint_count", 0)) or 0)
        file_upload_count = int(summary.get("file_upload_endpoint_count", scoring.get("file_upload_endpoints", 0)) or 0)

        http_server = bool(scoring.get("http_server_detected", False))

        score = 0
        score += min(30, high_count * 10)
        score += min(18, medium_count * 3)
        score += min(12, sensitive_unauth * 3)
        score += min(8, auth_gap_count)
        score += min(6, schema_issue_count)
        score += min(6, file_upload_count * 3)

        if http_server:
            score += 5

        score = max(0, min(100, score))

        if score >= 60:
            verdict = "High API Spec Risk"
        elif score >= 35:
            verdict = "Medium API Spec Risk"
        elif score >= 15:
            verdict = "Low API Spec Risk"
        else:
            verdict = "Informational API Spec Review"

        return score, verdict
        
    def _derive_extension_score_and_verdict(self, extension_summary: dict | None) -> tuple[int | None, str | None]:
        """
        Derive a display score/verdict for browser-extension-only cases.
        This keeps extension risk separate from static/dynamic malware scoring.
        """
        if not isinstance(extension_summary, dict):
            return None, None

        summary = extension_summary.get("summary", {})
        if not isinstance(summary, dict):
            return None, None

        raw_score = summary.get("risk_score")
        raw_verdict = str(summary.get("risk_verdict", "") or "").strip().lower()

        try:
            score = int(raw_score)
        except Exception:
            score = None

        if raw_verdict == "high":
            return score, "High Browser Extension Risk"
        if raw_verdict == "medium":
            return score, "Medium Browser Extension Risk"
        if raw_verdict == "low":
            return score, "Low Browser Extension Risk"

        if score is not None:
            if score >= 7:
                return score, "High Browser Extension Risk"
            if score >= 3:
                return score, "Medium Browser Extension Risk"
            return score, "Low Browser Extension Risk"

        return None, None

    def _derive_overall_verdict(self, artifacts: dict) -> str:
        combined = self._combined_summary()
        if isinstance(combined, dict):
            for key in ("verdict", "severity"):
                if combined.get(key):
                    return str(combined.get(key))

        dynamic_summary = self._latest_dynamic_summary()
        static_summary = self._latest_static_summary()

        if isinstance(dynamic_summary, dict) and dynamic_summary.get("verdict"):
            return str(dynamic_summary.get("verdict"))

        if isinstance(static_summary, dict) and static_summary.get("verdict"):
            return str(static_summary.get("verdict"))

        findings = self._build_detailed_findings()
        joined = " ".join(" ".join(items).lower() for items in findings.values() if isinstance(items, list))

        if "critical" in joined or "high risk" in joined:
            return "High Risk"
        if "needs review" in joined or "moderate risk" in joined or "persistence" in joined:
            return "Moderate Risk"
        if "benign" in joined or "low suspicion" in joined or "low risk" in joined:
            return "Low Risk"

        spec_found = artifacts.get("Spec Analysis", {}).get("found", False)
        extension_found = artifacts.get("Browser Extension Analysis", {}).get("found", False)

        other_modules_for_spec = any(
            artifacts.get(name, {}).get("found", False)
            for name in [
                "Static Analysis",
                "Dynamic Analysis",
                "Manual API Tester",
                "Browser Extension Analysis",
                "Combined Score",
            ]
        )

        other_modules_for_extension = any(
            artifacts.get(name, {}).get("found", False)
            for name in [
                "Static Analysis",
                "Dynamic Analysis",
                "Manual API Tester",
                "Spec Analysis",
                "Combined Score",
            ]
        )

        if spec_found and not other_modules_for_spec:
            spec_score, spec_verdict = self._derive_spec_score_and_verdict(self._latest_spec_summary())
            if spec_verdict:
                return spec_verdict

        if extension_found and not other_modules_for_extension:
            extension_score, extension_verdict = self._derive_extension_score_and_verdict(self._latest_extension_summary())
            if extension_verdict:
                return extension_verdict

        count = sum(1 for meta in artifacts.values() if meta.get("found"))
        if count >= 2:
            return "Moderate Activity"
        if count >= 1:
            return "Limited Activity"
        return "No Results"

    # ---------------------------------------------------------------------
    # Scan/report generation
    # ---------------------------------------------------------------------

    def _scan_case_dir(self):
        raw = self.case_path_var.get().strip()
        if not raw:
            messagebox.showwarning("Unified Report", "Select a case folder first.")
            return

        case_dir = self._normalize_case_dir(Path(raw))
        if not case_dir.exists() or not case_dir.is_dir():
            messagebox.showerror("Unified Report", f"Folder not found:\n{case_dir}")
            return

        self.case_dir = case_dir
        self.case_path_var.set(str(case_dir))
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
            "Combined Score": "combined",
        }

        for module_name, key in module_map.items():
            items = [
                str(item).strip()
                for item in findings.get(key, [])
                if str(item).strip()
            ]

            if not items:
                continue

            summary_lines.append(f"{module_name}:")
            for item in items:
                lower_item = item.lower().rstrip(":")

                if lower_item in {"analysis findings", "severity summary", "risk notes", "top findings", "evidence"}:
                    summary_lines.append(f"  {item}")
                elif item.startswith("Note:"):
                    summary_lines.append(f"    {item}")
                elif item.startswith("["):
                    summary_lines.append(f"    - {item}")
                else:
                    summary_lines.append(f"  - {item}")

            summary_lines.append("")

        self._set_text(self.artifacts_text, "\n".join(artifact_lines) if artifact_lines else "No artifacts detected.")
        self._set_text(self.summary_text, "\n".join(summary_lines) if summary_lines else "Nothing found yet.")
        self.status_var.set(f"Scanned case folder: {case_dir}")
        self._bring_to_front()

    def _generate_report(self):
        if self.case_dir is None:
            self._scan_case_dir()
            if self.case_dir is None:
                return

        findings = self._build_detailed_findings()

        static_summary = self._latest_static_summary()
        dynamic_summary = self._latest_dynamic_summary()
        spec_summary = self._latest_spec_summary()
        combined_summary = self._combined_summary()

        static_score = None
        dynamic_score = None
        api_score = None
        spec_score = None
        extension_score = None
        combined_score = None

        combined_verdict = None
        combined_severity = None
        combined_categories = None
        combined_coverage = None

        if isinstance(combined_summary, dict):
            # `score` under `corroboration-v1`; `total_score` in case folders
            # written before the change. It is descriptive volume either way and
            # the verdict below is what the reader should be looking at.
            combined_score = combined_summary.get("score", combined_summary.get("total_score"))
            combined_verdict = combined_summary.get("verdict")
            combined_severity = combined_summary.get("severity")
            counts = combined_summary.get("counts", {})
            if isinstance(counts, dict) and counts:
                combined_categories = (
                    f"{counts.get('categories_present', 0)} present, "
                    f"{counts.get('categories_strong', 0)} emphatic, "
                    f"{counts.get('categories_unknown', 0)} not collected")
            if "coverage_complete" in combined_summary:
                combined_coverage = (
                    "complete" if combined_summary.get("coverage_complete")
                    else "INCOMPLETE -- a collector did not run")

            subscores = combined_summary.get("subscores", {})
            if isinstance(subscores, dict):
                static_score = subscores.get("static")
                dynamic_score = subscores.get("dynamic")
                spec_score = subscores.get("spec")
            else:
                static_score = combined_summary.get("static_score")
                dynamic_score = combined_summary.get("dynamic_score")
                spec_score = combined_summary.get("spec_score")

        if static_score is None and isinstance(static_summary, dict):
            static_score = static_summary.get("score") or static_summary.get("static_score")

        if dynamic_score is None and isinstance(dynamic_summary, dict):
            dynamic_score = dynamic_summary.get("score") or dynamic_summary.get("dynamic_score")

        if spec_score is None and isinstance(spec_summary, dict):
            spec_score = spec_summary.get("score") or spec_summary.get("spec_score")

            if spec_score is None:
                derived_spec_score, _derived_spec_verdict = self._derive_spec_score_and_verdict(spec_summary)
                spec_score = derived_spec_score
        
        api_findings = findings.get("api", [])
        if api_findings:
            api_score = "Present"

        extension_summary = self._latest_extension_summary()

        if isinstance(extension_summary, dict):
            derived_extension_score, _derived_extension_verdict = self._derive_extension_score_and_verdict(extension_summary)
            extension_score = derived_extension_score if derived_extension_score is not None else "Present"
        else:
            extension_findings = findings.get("extension", [])
            if extension_findings:
                extension_score = "Present"

        data = {
            "case_name": self.case_dir.name,
            "case_path": str(self.case_dir),
            "overall_verdict": self._derive_overall_verdict(self.detected_artifacts),
            "combined_score": combined_score,
            # The whole verdict document, for the renderer. The flattened
            # fields above stay because the Tk view reads individual values.
            "verdict_json": combined_summary if isinstance(combined_summary, dict) else None,
            "combined_verdict": combined_verdict,
            "combined_severity": combined_severity,
            "combined_categories": combined_categories,
            "combined_coverage": combined_coverage,
            "static_score": static_score,
            "dynamic_score": dynamic_score,
            "api_score": api_score,
            "spec_score": spec_score,
            "extension_score": extension_score,
            "modules": self.detected_artifacts,
            "findings": findings,
        }

        report_dir = self.case_dir / "unified_report"
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
        """Render the case verdict page.

        **This used to be the page.** It opened with a twelve-row key/value
        table in which the verdict sat between the case path and five
        per-module subscores from the retired additive model, and the evidence
        -- the prose each category carries -- appeared nowhere. See
        `static_triage_engine/verdict_report.py` for the order the page uses now
        and why that order is the argument.
        """
        verdict = data.get("verdict_json")
        if not isinstance(verdict, dict) or not verdict:
            # **Not an empty report.** A case with no verdict document has not
            # been scored, and saying so is different from rendering a page of
            # blanks that reads like a clean result.
            return render_verdict_report(
                {
                    "band": "Nothing Collected",
                    "domain": "malware",
                    "verdict": "Insufficient Coverage",
                    "severity": "Unknown",
                    "counts": {},
                    "coverage_complete": False,
                    "modules_run": [],
                    "modules_absent": ["static", "dynamic", "spec", "api",
                                       "extension"],
                    "uncollected_categories": [],
                    "coverage": {},
                    "evidence": [],
                    "score_model": "",
                    "score": 0,
                },
                case_name=str(data.get("case_name", "")),
                case_path=str(data.get("case_path", "")),
            )

        return render_verdict_report(
            verdict,
            case_name=str(data.get("case_name", "")),
            case_path=str(data.get("case_path", "")),
            module_artifacts=data.get("modules") or {},
        )

    def _open_report_folder(self):
        if self.case_dir is None:
            messagebox.showinfo("Unified Report", "No case folder selected yet.")
            return

        report_dir = self.case_dir / "unified_report"
        report_dir.mkdir(parents=True, exist_ok=True)

        try:
            if os.name == "nt":
                os.startfile(str(report_dir))
            else:
                messagebox.showinfo("Open Report Folder", f"Report folder:\n{report_dir}")
            self.status_var.set(f"Opened report folder: {report_dir}")
        except Exception as e:
            messagebox.showerror("Open Report Folder", f"Could not open report folder:\n{e}")
