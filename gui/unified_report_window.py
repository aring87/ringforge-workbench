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


from verdict.case_artifacts import (
    MODULES,
    build_findings,
    detect_artifacts,
    load_json,
    load_summary,
)
from verdict.case_summary import (
    extension_score_and_verdict,
    overall_verdict,
    spec_score_and_verdict,
)


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

    # Artifact detection, candidate ordering and finding extraction all live
    # in `verdict.case_artifacts` now -- about 500 widget-free lines that
    # could not be imported without a display, and were carrying two defects
    # that a case page shows rather than reports. `_load_json_if_exists` and
    # `_existing_paths` went with them; nothing here called either any more.
    def _load_json_if_exists(self, path_str: str | Path):
        return load_json(path_str)

    def _detect_artifacts(self, case_dir: Path) -> dict:
        return detect_artifacts(case_dir)

    def _build_detailed_findings(self) -> dict:
        return build_findings(self.detected_artifacts)


    # Each of these took a candidate list written canonical-first and handed
    # it to a helper that sorted by modification time, so a legacy file that
    # had merely been touched more recently spoke for the case. First existing
    # candidate wins now; the ordering is in `verdict.case_artifacts`.
    def _latest_static_summary(self) -> dict | None:
        return load_summary(self.case_dir, "Static Analysis")

    def _latest_dynamic_summary(self) -> dict | None:
        return load_summary(self.case_dir, "Dynamic Analysis")

    def _latest_spec_summary(self) -> dict | None:
        return load_summary(self.case_dir, "Spec Analysis")

    def _latest_extension_summary(self) -> dict | None:
        return load_summary(self.case_dir, "Browser Extension Analysis")

    def _combined_summary(self) -> dict | None:
        return load_summary(self.case_dir, "Case Verdict")


    # These three moved to `verdict/case_summary.py`, where they can be
    # tested. None of them ever touched a widget; they were data functions
    # living in a Toplevel, which is why the defect below went unnoticed for a
    # release. See that module for what changed and what deliberately did not.
    def _derive_spec_score_and_verdict(self, spec_summary: dict | None) -> tuple[int | None, str | None]:
        return spec_score_and_verdict(spec_summary)

    def _derive_extension_score_and_verdict(self, extension_summary: dict | None) -> tuple[int | None, str | None]:
        return extension_score_and_verdict(extension_summary)

    def _derive_overall_verdict(self, artifacts: dict) -> str:
        return overall_verdict(
            artifacts=artifacts,
            combined=self._combined_summary(),
            dynamic_summary=self._latest_dynamic_summary(),
            static_summary=self._latest_static_summary(),
            spec_summary=self._latest_spec_summary(),
            extension_summary=self._latest_extension_summary(),
        )

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

        # `MODULES` is the one place these names live. This dict was a second
        # copy and it named the last row `Combined Score`, which is what the
        # module was called before `combined_score.json` became
        # `combined_verdict.json` -- so the case verdict's findings never
        # rendered, on any case that had one.
        for module_name, key in MODULES.items():
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
