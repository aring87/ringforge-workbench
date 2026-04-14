from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from tkinter import ttk


class LauncherWindow(ttk.Frame):
    def __init__(self, parent, app, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.app = app
        self.configure(padding=18)

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(4, weight=1)

        self.test_tree = None
        self._build()

    def _build(self):
        header = ttk.Frame(self)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 14))
        header.columnconfigure(0, weight=1)

        ttk.Label(
            header,
            text="RingForge Workbench",
            style="SectionHeader.TLabel",
            font=("Segoe UI", 20, "bold"),
        ).grid(row=0, column=0, sticky="w")

        ttk.Label(
            header,
            text="Choose the analysis workflow you want to launch.",
            style="Muted.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(6, 0))

        self._card(
            1, 0,
            "Static Analysis",
            "Run the current full static triage interface.",
            self.app.open_static_analysis,
        )
        self._card(
            1, 1,
            "Dynamic Analysis",
            "Launch runtime behavior capture and review.",
            self.app.open_dynamic_analysis,
        )
        self._card(
            2, 0,
            "API Analysis",
            "Run manual API testing and inspect responses.",
            self.app.open_api_analysis,
        )
        self._card(
            2, 1,
            "Spec Analysis",
            "Review OpenAPI or Swagger specs and risky endpoints.",
            self.app.open_spec_analysis,
        )
        self._card(
            3, 0,
            "Browser Extension Analysis",
            "Review Chrome/Edge browser extensions, manifests, permissions, and risk indicators.",
            self.app.open_extension_analysis,
        )
        self._card(
            3, 1,
            "Unified Report",
            "Generate one combined RingForge report from any completed case artifacts, regardless of which analysis modules were run.",
            self.app.open_unified_report,
        )

        self._build_recent_tests_panel()

        footer = ttk.Frame(self)
        footer.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(16, 0))
        footer.columnconfigure(0, weight=1)

        ttk.Button(
            footer,
            text="Refresh Saved Tests",
            style="Action.TButton",
            command=self._refresh_saved_tests_no_focus,
            takefocus=False,
        ).grid(row=0, column=0, sticky="w")

        ttk.Button(
            footer,
            text="Exit",
            style="Action.TButton",
            command=self.app.destroy,
            takefocus=False,
        ).grid(row=0, column=1, sticky="e")

    def _card(self, row, col, title, desc, command):
        card = ttk.Frame(self, style="Card.TFrame", padding=16)
        card.grid(row=row, column=col, sticky="nsew", padx=8, pady=8)
        self.rowconfigure(row, weight=0)

        ttk.Label(
            card,
            text=title,
            style="TLabel",
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w")

        ttk.Label(
            card,
            text=desc,
            style="Muted.TLabel",
            wraplength=320,
            justify="left",
        ).pack(anchor="w", pady=(8, 14))

        def launch():
            self.focus_set()
            self.after(50, self.focus_set)
            command()

        ttk.Button(
            card,
            text=f"Open {title}",
            style="Launcher.Action.TButton",
            command=launch,
            takefocus=False,
        ).pack(anchor="w")
    
    def _refresh_saved_tests_no_focus(self):
        self.focus_set()
        self.after(50, self.focus_set)
        self.refresh_saved_tests()

    def _build_recent_tests_panel(self):
        panel = ttk.LabelFrame(self, text="Saved Tests and Scores")
        panel.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=8, pady=(12, 0))
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(0, weight=1)

        style = ttk.Style()
        style.configure(
            "SavedTests.Treeview",
            background="#0d1b33",
            fieldbackground="#0d1b33",
            foreground="#eaf2ff",
            rowheight=24,
        )
        style.map(
            "SavedTests.Treeview",
            background=[("selected", "#1f6fff")],
            foreground=[("selected", "white")],
        )

        columns = ("test_name", "analysis_type", "score", "status", "completed_at", "sample_path")
        self.test_tree = ttk.Treeview(
            panel,
            columns=columns,
            show="headings",
            height=10,
            style="SavedTests.Treeview",
        )

        self.test_tree.heading("test_name", text="Test")
        self.test_tree.heading("analysis_type", text="Type")
        self.test_tree.heading("score", text="Score")
        self.test_tree.heading("status", text="Status")
        self.test_tree.heading("completed_at", text="Completed")
        self.test_tree.heading("sample_path", text="Sample")

        self.test_tree.column("test_name", width=140, anchor="w")
        self.test_tree.column("analysis_type", width=80, anchor="center")
        self.test_tree.column("score", width=70, anchor="center")
        self.test_tree.column("status", width=90, anchor="center")
        self.test_tree.column("completed_at", width=170, anchor="w")
        self.test_tree.column("sample_path", width=520, anchor="w")

        self.test_tree.grid(row=0, column=0, sticky="nsew")

        ysb = ttk.Scrollbar(panel, orient="vertical", command=self.test_tree.yview)
        ysb.grid(row=0, column=1, sticky="ns")
        self.test_tree.configure(yscrollcommand=ysb.set)

        self.refresh_saved_tests()

    def _infer_type_from_summary_path(self, summary_path: Path, data: dict | None = None) -> str:
        name = summary_path.name.lower()
        if "dynamic" in name:
            return "dynamic"

        if isinstance(data, dict):
            if "findings" in data or "procmon_summary" in data or "procmon_enabled" in data:
                return "dynamic"
            if "virustotal" in data or "capa" in data or "api_analysis" in data:
                return "static"

        return "static"

    def _get_case_roots(self):
        roots = []

        app_case_root_var = getattr(self.app, "case_root_var", None)
        if app_case_root_var is not None:
            try:
                value = app_case_root_var.get().strip()
                if value:
                    roots.append(Path(value))
            except Exception:
                pass

        project_root = getattr(self.app, "project_root", Path.cwd())
        default_cases = Path(project_root) / "cases"
        if default_cases not in roots:
            roots.append(default_cases)

        unique_roots = []
        seen = set()
        for root in roots:
            key = str(root).lower()
            if key not in seen:
                seen.add(key)
                unique_roots.append(root)

        return unique_roots

    def _build_row_from_summary(self, case_dir: Path, summary_path: Path, data: dict):
        analysis_type = data.get("analysis_type") or self._infer_type_from_summary_path(summary_path, data)

        sample_obj = data.get("sample", {})
        findings = data.get("findings", {}) if isinstance(data.get("findings"), dict) else {}
        counts = findings.get("counts", {}) if isinstance(findings.get("counts"), dict) else {}

        score = (
            data.get("score")
            or data.get("combined_score")
            or data.get("static_score")
            or data.get("dynamic_score")
            or "-"
        )

        if score == "-" and analysis_type == "dynamic":
            score = counts.get("interesting_events", "-")

        completed_at = (
            data.get("completed_at")
            or data.get("ended_at_utc")
            or data.get("started_at_utc")
            or ""
        )

        sample_path = ""

        if isinstance(sample_obj, dict):
            sample_path = (
                data.get("sample_path")
                or sample_obj.get("sample_path")
                or sample_obj.get("path")
                or sample_obj.get("target_path")
                or ""
            )
        elif isinstance(sample_obj, str):
            sample_path = data.get("sample_path") or sample_obj
        else:
            sample_path = data.get("sample_path") or ""

        if not sample_path:
            # fallback: use common executable names found in case folder metadata if available
            possible = [
                case_dir / "metadata" / "sample_path.txt",
                case_dir / "sample_path.txt",
            ]
            for p in possible:
                try:
                    if p.exists():
                        sample_path = p.read_text(encoding="utf-8", errors="replace").strip()
                        if sample_path:
                            break
                except Exception:
                    pass

        status = data.get("status")
        if not status:
            if data.get("exit_code") == 0:
                status = "completed"
            elif data.get("exit_code") is not None:
                status = f"exit {data.get('exit_code')}"
            else:
                status = "completed"

        return {
            "test_name": data.get("test_name", case_dir.name),
            "analysis_type": analysis_type,
            "score": score,
            "status": status,
            "completed_at": completed_at,
            "sample_path": sample_path,
            "case_dir": str(case_dir),
        }

    def _load_saved_tests(self):
        results = []
        seen_rows = set()

        for case_root in self._get_case_roots():
            if not case_root.exists():
                continue

            try:
                case_dirs = sorted(
                    [p for p in case_root.iterdir() if p.is_dir()],
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
            except Exception:
                continue

            for case_dir in case_dirs:
                preferred_paths = [
                    case_dir / "metadata" / "static_run_summary.json",
                    case_dir / "metadata" / "dynamic_run_summary.json",
                ]

                legacy_paths = [
                    case_dir / "reports" / "static_run_summary.json",
                    case_dir / "reports" / "dynamic_run_summary.json",
                    case_dir / "reports" / "run_summary.json",
                    case_dir / "static_run_summary.json",
                    case_dir / "dynamic_run_summary.json",
                    case_dir / "run_summary.json",
                    case_dir / "runlog.json",
                ]

                existing_preferred = [p for p in preferred_paths if p.exists()]

                if existing_preferred:
                    existing_paths = existing_preferred
                else:
                    existing_paths = [p for p in legacy_paths if p.exists()]

                for summary_path in existing_paths:
                    try:
                        data = json.loads(summary_path.read_text(encoding="utf-8", errors="replace"))
                    except Exception:
                        continue

                    try:
                        row = self._build_row_from_summary(case_dir, summary_path, data)
                    except Exception:
                        continue

                    row_key = (
                        str(case_dir).lower(),
                        str(row.get("analysis_type", "")).lower(),
                        str(row.get("completed_at", "")),
                    )
                    if row_key in seen_rows:
                        continue
                    seen_rows.add(row_key)

                    results.append(row)

        return results

    def refresh_saved_tests(self):
        if self.test_tree is None:
            return

        for item in self.test_tree.get_children():
            self.test_tree.delete(item)

        rows = self._load_saved_tests()

        self.test_tree.tag_configure(
            "visible_row",
            background="#0d1b33",
            foreground="#eaf2ff",
        )

        for row in rows:
            self.test_tree.insert(
                "",
                "end",
                values=(
                    row["test_name"],
                    row["analysis_type"],
                    row["score"],
                    row["status"],
                    row["completed_at"],
                    row["sample_path"],
                ),
                tags=("visible_row",),
            )

    def get_selected_saved_test_context(self):
        if self.test_tree is None:
            return None

        selected = self.test_tree.selection()
        if not selected:
            return None

        item_id = selected[0]
        item = self.test_tree.item(item_id)
        values = item.get("values", [])
        if len(values) < 6:
            return None

        test_name, analysis_type, score, status, completed_at, sample_path = values

        case_dir = None

        # First try to resolve by test name
        for case_root in self._get_case_roots():
            candidate = case_root / str(test_name)
            if candidate.exists():
                case_dir = candidate
                break

        # Fallback: search summaries for matching row values
        if case_dir is None:
            for case_root in self._get_case_roots():
                if not case_root.exists():
                    continue
                try:
                    for candidate in case_root.iterdir():
                        if not candidate.is_dir():
                            continue
                        if candidate.name == str(test_name):
                            case_dir = candidate
                            break
                    if case_dir is not None:
                        break
                except Exception:
                    pass

        return {
            "test_name": str(test_name),
            "analysis_type": str(analysis_type),
            "sample_path": str(sample_path).strip(),
            "case_dir": case_dir,
        }