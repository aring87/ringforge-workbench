from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from tkinter import ttk

from gui import theme as T
from gui.components import Badge, Card, EmptyState, HeaderBar, RoundedButton, SectionTitle

#: The six analysis workflows, in launch order.
#: (attribute on app, title, glyph, category accent, description)
MODULES = [
    (
        "open_static_analysis",
        "Static Analysis",
        "◈",
        "ultrasonic",
        "Hash, PE metadata, capa capabilities, and VirusTotal enrichment for an executable.",
    ),
    (
        "open_dynamic_analysis",
        "Dynamic Analysis",
        "▶",
        "cyan",
        "Capture runtime process, file, and registry behaviour inside an instrumented VM.",
    ),
    (
        "open_api_analysis",
        "API Analysis",
        "⇄",
        "sky",
        "Send manual endpoint requests and score the responses for risk indicators.",
    ),
    (
        "open_spec_analysis",
        "Spec Analysis",
        "▤",
        "periwinkle",
        "Review OpenAPI or Swagger definitions and surface risky or undocumented endpoints.",
    ),
    (
        "open_extension_analysis",
        "Browser Extension Analysis",
        "◧",
        "azure",
        "Inspect Chrome and Edge extension manifests, permissions, and risk indicators.",
    ),
    (
        "open_unified_report",
        "Unified Report",
        "▦",
        "teal",
        "Combine artifacts from any completed modules into one consolidated analyst report.",
    ),
]

#: Column layout for the saved-tests table.
TEST_COLUMNS = [
    ("test_name", "Case", 200, "w"),
    ("analysis_type", "Module", 110, "center"),
    ("score", "Score", 90, "center"),
    ("status", "Status", 120, "center"),
    ("completed_at", "Completed", 190, "w"),
    ("sample_path", "Sample", 460, "w"),
]


class LauncherWindow(ttk.Frame):
    def __init__(self, parent, app, *args, **kwargs):
        super().__init__(parent, style="App.TFrame", *args, **kwargs)
        self.app = app
        self.configure(padding=T.SPACE_XL)

        for col in range(3):
            self.columnconfigure(col, weight=1, uniform="module")
        self.rowconfigure(4, weight=1)

        self.test_tree = None
        self.empty_state = None
        self.count_badge = None
        self._build()

    # -- layout -----------------------------------------------------------

    def _build(self):
        self._build_header()

        SectionTitle(
            self,
            "Analysis Modules",
            eyebrow="Workflows",
            subtitle="Pick a module to open it. Select a saved case below first to carry its context across.",
            parent_bg=T.BG,
        ).grid(row=1, column=0, columnspan=3, sticky="ew", pady=(T.SPACE_XL, T.SPACE_MD))

        for index, (attr, title, glyph, category, desc) in enumerate(MODULES):
            self._module_card(
                row=2 + index // 3,
                col=index % 3,
                title=title,
                glyph=glyph,
                accent=T.CATEGORY[category],
                desc=desc,
                command=getattr(self.app, attr),
            )

        self._build_recent_tests_panel()
        self._build_footer()

    def _build_header(self):
        logo = Path(getattr(self.app, "project_root", Path.cwd())) / "assets" / "anvil.png"

        header = HeaderBar(
            self,
            "RingForge",
            subtitle="Workbench",
            description=(
                "Unified software triage: static, dynamic, and behavioural analysis "
                "with scoring and consolidated reporting."
            ),
            logo_path=logo if logo.exists() else None,
            logo_size=72,
            parent_bg=T.BG,
        )
        header.grid(row=0, column=0, columnspan=3, sticky="ew")

        RoundedButton(
            header.actions,
            "Exit",
            command=self.app.destroy,
            variant="ghost",
            parent_bg=T.SURFACE,
        ).pack(side="right")

    def _module_card(self, row, col, title, glyph, accent, desc, command):
        def launch():
            self.focus_set()
            self.after(50, self.focus_set)
            command()

        card = Card(
            self,
            accent=accent,
            hover=True,
            parent_bg=T.BG,
            padding=(T.SPACE_LG + 4, T.SPACE_LG),
        )
        card.grid(row=row, column=col, sticky="nsew", padx=T.SPACE_SM, pady=T.SPACE_SM)
        self.rowconfigure(row, weight=0)

        body = card.body

        title_row = tk.Frame(body, bg=T.SURFACE)
        title_row.pack(fill="x")

        # The glyph sits on a chip tinted with the module's own accent, which
        # gives each card a spot of colour instead of a lone grey mark.
        chip_fill = T.mix(T.SURFACE, accent, 0.14)
        chip = Card(
            title_row,
            fill=chip_fill,
            border=T.mix(T.SURFACE, accent, 0.42),
            radius=T.RADIUS_SM,
            padding=(T.SPACE_SM, T.SPACE_XS),
            parent_bg=T.SURFACE,
            highlight=False,
        )
        chip.pack(side="left", padx=(0, T.SPACE_MD))
        tk.Label(
            chip.body, text=glyph, bg=chip_fill, fg=accent, font=T.font(14),
        ).pack()

        tk.Label(
            title_row, text=title, bg=T.SURFACE, fg=T.TEXT,
            font=T.f_subheading(), anchor="w", justify="left",
        ).pack(side="left", pady=(4, 0))

        desc_label = tk.Label(
            body, text=desc, bg=T.SURFACE, fg=T.TEXT_MUTED, font=T.f_small(),
            anchor="w", justify="left", wraplength=290,
        )
        desc_label.pack(anchor="w", fill="x", pady=(T.SPACE_MD, T.SPACE_LG))

        # Wrap to the card's real width instead of a fixed 290px. The cards are
        # a third of the window each, so on any reasonably sized window the fixed
        # value broke the copy into a narrow column with a wide empty gutter
        # beside it, and made every card taller than its content needed.
        def rewrap(event, label=desc_label):
            width = event.width - 2 * (T.SPACE_LG + 4) - T.SPACE_SM
            if width > 80:
                label.configure(wraplength=width)

        card.bind("<Configure>", rewrap, add="+")

        RoundedButton(
            body,
            "Open",
            command=launch,
            variant="accent",
            parent_bg=T.SURFACE,
            min_width=110,
        ).pack(anchor="w")

        # The whole card is a click target, not just the button.
        card.bind_click(launch)

    def _build_footer(self):
        footer = tk.Frame(self, bg=T.BG)
        footer.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(T.SPACE_LG, 0))

        RoundedButton(
            footer,
            "Refresh",
            command=self._refresh_saved_tests_no_focus,
            variant="secondary",
            icon="↻",
            parent_bg=T.BG,
        ).pack(side="left")

        tk.Label(
            footer,
            text="Cases are read from the configured case output root.",
            bg=T.BG, fg=T.TEXT_MUTED, font=T.f_small(),
        ).pack(side="left", padx=(T.SPACE_MD, 0))

    def _refresh_saved_tests_no_focus(self):
        self.focus_set()
        self.after(50, self.focus_set)
        self.refresh_saved_tests()

    def _build_recent_tests_panel(self):
        panel = Card(self, parent_bg=T.BG, padding=(T.SPACE_LG, T.SPACE_LG))
        panel.grid(
            row=4, column=0, columnspan=3, sticky="nsew",
            padx=T.SPACE_SM, pady=(T.SPACE_XL, 0),
        )

        body = panel.body
        body.columnconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)

        head = tk.Frame(body, bg=T.SURFACE)
        head.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, T.SPACE_MD))

        tk.Label(
            head, text="Saved Tests and Scores", bg=T.SURFACE, fg=T.TEXT,
            font=T.f_subheading(),
        ).pack(side="left")

        self.count_badge = Badge(head, "0 cases", status="idle", parent_bg=T.SURFACE)
        self.count_badge.pack(side="left", padx=(T.SPACE_SM, 0))

        # The table sits directly on the card surface rather than in a sunken
        # well, so its square corners never fight the card's rounded ones.
        table_wrap = tk.Frame(body, bg=T.SURFACE)
        table_wrap.grid(row=1, column=0, columnspan=2, sticky="nsew")
        table_wrap.columnconfigure(0, weight=1)
        table_wrap.rowconfigure(0, weight=1)

        self.test_tree = ttk.Treeview(
            table_wrap,
            columns=[c[0] for c in TEST_COLUMNS],
            show="headings",
            height=9,
            style="Card.Treeview",
            selectmode="browse",
        )

        for key, heading, width, anchor in TEST_COLUMNS:
            # Heading alignment follows its column so the two never disagree.
            self.test_tree.heading(key, text=heading, anchor=anchor)
            self.test_tree.column(key, width=width, anchor=anchor, stretch=(key == "sample_path"))

        self.test_tree.grid(row=0, column=0, sticky="nsew")

        ysb = ttk.Scrollbar(table_wrap, orient="vertical", command=self.test_tree.yview)
        ysb.grid(row=0, column=1, sticky="ns")
        self.test_tree.configure(yscrollcommand=ysb.set)

        self.empty_state = EmptyState(
            table_wrap,
            "No saved cases yet",
            detail="Run any analysis module and completed cases will appear here.",
            glyph="◎",
            parent_bg=T.SURFACE,
        )

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
        """
        Load saved test rows from the RingForge case-home layout without duplicate
        static/combined rows.

        New layout:
            cases\\<case>\\metadata\\static_run_summary.json
            cases\\<case>\\static_analysis\\metadata\\static_run_summary.json
            cases\\<case>\\dynamic_analysis\\dynamic_runs\\<run>\\metadata\\dynamic_run_summary.json
            cases\\<case>\\combined_score.json

        Legacy layout is still supported.
        """
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
                summary_paths = []

                # Static: choose only one static summary per case.
                static_candidates = [
                    case_dir / "metadata" / "static_run_summary.json",
                    case_dir / "static_analysis" / "metadata" / "static_run_summary.json",
                    case_dir / "reports" / "static_run_summary.json",
                    case_dir / "static_run_summary.json",
                ]
                for p in static_candidates:
                    if p.exists():
                        summary_paths.append(p)
                        break

                # Dynamic: show each dynamic run summary, newest first.
                dynamic_runs_dir = case_dir / "dynamic_analysis" / "dynamic_runs"
                dynamic_run_found = False
                if dynamic_runs_dir.exists():
                    try:
                        dynamic_run_summaries = sorted(
                            dynamic_runs_dir.glob("*/metadata/dynamic_run_summary.json"),
                            key=lambda p: p.stat().st_mtime,
                            reverse=True,
                        )
                        if dynamic_run_summaries:
                            summary_paths.extend(dynamic_run_summaries)
                            dynamic_run_found = True
                    except Exception:
                        pass

                # Dynamic compatibility fallback only if no dynamic run summaries exist.
                if not dynamic_run_found:
                    dynamic_candidates = [
                        case_dir / "metadata" / "dynamic_run_summary.json",
                        case_dir / "dynamic_analysis" / "metadata" / "dynamic_run_summary.json",
                        case_dir / "dynamic_analysis" / "dynamic_run_summary.json",
                        case_dir / "reports" / "dynamic_run_summary.json",
                        case_dir / "dynamic_run_summary.json",
                        case_dir / "dynamic_findings.json",
                        case_dir / "reports" / "dynamic_findings.json",
                    ]
                    for p in dynamic_candidates:
                        if p.exists():
                            summary_paths.append(p)
                            break

                # Combined: choose only one combined score per case.
                combined_candidates = [
                    case_dir / "combined_score.json",
                    case_dir / "metadata" / "combined_score.json",
                ]
                for p in combined_candidates:
                    if p.exists():
                        summary_paths.append(p)
                        break

                # Legacy generic run summary, only if no better summaries were found.
                if not summary_paths:
                    for p in [
                        case_dir / "reports" / "run_summary.json",
                        case_dir / "run_summary.json",
                        case_dir / "runlog.json",
                    ]:
                        if p.exists():
                            summary_paths.append(p)
                            break

                for summary_path in summary_paths:
                    try:
                        data = json.loads(summary_path.read_text(encoding="utf-8", errors="replace"))
                    except Exception:
                        continue

                    try:
                        row = self._build_row_from_summary(case_dir, summary_path, data)
                    except Exception:
                        continue

                    if summary_path.name.lower() == "combined_score.json":
                        row["analysis_type"] = "combined"
                        row["test_name"] = case_dir.name
                        row["score"] = data.get("total_score", data.get("score", "-"))
                        row["status"] = "completed"
                        row["completed_at"] = data.get("completed_at", "")
                        if not row.get("sample_path"):
                            row["sample_path"] = self._sample_path_from_case(case_dir) or ""

                    # De-dupe by logical row, not by file path. This prevents the
                    # case-home copy and module copy from displaying twice.
                    row_key = (
                        str(case_dir).lower(),
                        str(row.get("analysis_type", "")).lower(),
                        str(row.get("completed_at", "")),
                        str(row.get("score", "")),
                    )
                    if row_key in seen_rows:
                        continue
                    seen_rows.add(row_key)

                    results.append(row)

        def sort_key(row):
            return str(row.get("completed_at") or "")

        results.sort(key=sort_key, reverse=True)
        return results

    def _sample_path_from_case(self, case_dir: Path) -> str:
        """
        Best-effort sample path lookup for combined rows or older summaries.
        """
        candidates = [
            case_dir / "case_metadata.json",
            case_dir / "metadata" / "static_run_summary.json",
            case_dir / "static_analysis" / "metadata" / "static_run_summary.json",
            case_dir / "metadata" / "dynamic_run_summary.json",
        ]

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

        for p in candidates:
            try:
                if not p.exists():
                    continue
                data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
                sample_obj = data.get("sample", {})
                if isinstance(sample_obj, dict):
                    value = (
                        data.get("sample_path")
                        or sample_obj.get("sample_path")
                        or sample_obj.get("path")
                        or sample_obj.get("target_path")
                        or ""
                    )
                else:
                    value = data.get("sample_path") or sample_obj or ""

                value = str(value).strip()
                if value:
                    return value
            except Exception:
                pass

        return ""

    def refresh_saved_tests(self):
        if self.test_tree is None:
            return

        for item in self.test_tree.get_children():
            self.test_tree.delete(item)

        rows = self._load_saved_tests()

        # Zebra striping plus a severity tint for rows that did not complete.
        # The stripe tags deliberately set background only -- if they also set a
        # foreground it competes with the "failed" tag and the tint is lost.
        self.test_tree.tag_configure("even", background=T.SURFACE)
        self.test_tree.tag_configure("odd", background=T.mix(T.SURFACE, T.RAISED, 0.55))
        self.test_tree.tag_configure("failed", foreground=T.DANGER)

        for index, row in enumerate(rows):
            tags = ["even" if index % 2 == 0 else "odd"]
            status = str(row.get("status", "")).strip().lower()
            if status and status not in ("completed", "done", "ok"):
                tags.append("failed")

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
                tags=tuple(tags),
            )

        self._update_table_chrome(len(rows))

    def _update_table_chrome(self, count: int) -> None:
        """Toggle the empty-state overlay and refresh the case counter."""
        if self.count_badge is not None:
            label = "1 case" if count == 1 else f"{count} cases"
            self.count_badge.set(label, status="info" if count else "idle")

        if self.empty_state is None:
            return

        if count:
            self.empty_state.place_forget()
        else:
            self.empty_state.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.empty_state.lift()

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

        for case_root in self._get_case_roots():
            candidate = case_root / str(test_name)
            if candidate.exists():
                case_dir = candidate
                break

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

                        sample_guess = self._sample_path_from_case(candidate)
                        if sample_guess and sample_guess == str(sample_path).strip():
                            case_dir = candidate
                            break

                    if case_dir is not None:
                        break
                except Exception:
                    pass

        return {
            "test_name": str(test_name),
            "analysis_type": str(analysis_type),
            "score": str(score),
            "status": str(status),
            "completed_at": str(completed_at),
            "sample_path": str(sample_path).strip(),
            "case_dir": case_dir,
        }
