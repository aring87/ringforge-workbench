from __future__ import annotations
import re
import urllib.request
import urllib.parse
import json
import shutil
import tkinter as tk
import webbrowser
import os
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from gui import theme as T
from gui.components import HeaderBar
from gui.styles import apply_window_theme
from typing import Any, Optional

try:
    from PIL import Image, ImageTk
except Exception:
    Image = None
    ImageTk = None

from gui.api_window import APIAnalysisWindow
from static_triage_engine.api_spec_analysis import analyze_api_spec as engine_analyze_api_spec


def _safe_json_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


class SpecAnalysisWindow(tk.Toplevel):
    def __init__(self, app: "App"):
        super().__init__(app)
        self.app = app
        self.title("API Spec Analysis")
        self.geometry("1880x1080")
        self.minsize(1600, 900)
        self.configure(bg=T.BG)

        self.spec_path_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Idle")
        self.summary_var = tk.StringVar(
            value="Load an OpenAPI or Swagger spec to analyze endpoints, authentication, and API risk indicators."
        )

        self.spec_format_var = tk.StringVar(value="-")
        self.spec_version_var = tk.StringVar(value="-")
        self.spec_endpoint_count_var = tk.StringVar(value="-")
        self.spec_auth_var = tk.StringVar(value="-")
        self.spec_confidence_var = tk.StringVar(value="-")

        self.last_spec_dir: Optional[Path] = None
        self.last_html_report: Optional[Path] = None
        self.last_json_report: Optional[Path] = None
        self.last_result: Optional[dict[str, Any]] = None

        self.brand_logo_img = None

        self._configure_styles()
        self._build_ui()
        self.transient(app)
        self.grab_set()

    # -------------------------------------------------------------------------
    # STYLES
    # -------------------------------------------------------------------------

    def _configure_styles(self) -> None:
        # One shared theme for the whole workbench; see gui/styles.py.
        apply_window_theme(self)

        # Kept for the plain Tk widgets in this window, which ttk cannot style.
        self.colors = {
            "bg": T.BG,
            "panel": T.SURFACE,
            "panel_alt": T.RAISED,
            "border": T.BORDER,
            "text": T.TEXT,
            "muted": T.TEXT_MUTED,
            "accent": T.ACCENT,
            "entry_bg": T.SUNKEN,
            "tab_bg": T.RAISED,
        }

    # -------------------------------------------------------------------------
    # CASE HELPERS
    # -------------------------------------------------------------------------

    def _current_case_name(self) -> str:
        case_name = self.app.case_var.get().strip() if hasattr(self.app, "case_var") else ""
        if case_name:
            return case_name

        sample = self.app.sample_var.get().strip() if hasattr(self.app, "sample_var") else ""
        if sample:
            return Path(sample).stem[:64]

        return "spec_case"

    def _ensure_spec_dir(self) -> Path:
        project_root = Path(__file__).resolve().parents[1]
        case_root = (
            Path(self.app.case_root_var.get().strip())
            if hasattr(self.app, "case_root_var") and self.app.case_root_var.get().strip()
            else (project_root / "cases")
        )
        case_root.mkdir(parents=True, exist_ok=True)

        case_dir = case_root / self._current_case_name()
        case_dir.mkdir(parents=True, exist_ok=True)

        spec_dir = case_dir / "spec_analysis"
        spec_dir.mkdir(parents=True, exist_ok=True)

        self.last_spec_dir = spec_dir
        return spec_dir

    # -------------------------------------------------------------------------
    # UI
    # -------------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self._build_top_banner({"padx": 10, "pady": (8, 10)})

        content = ttk.Frame(self, style="App.TFrame")
        content.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=0)
        content.rowconfigure(1, weight=0)
        content.rowconfigure(2, weight=1)
        content.rowconfigure(3, weight=0)

        self._build_spec_controls(content)
        self._build_overview_cards(content)
        self._build_main_body(content)
        self._build_status_bar(content)

    def _build_top_banner(self, outer: dict[str, Any]) -> None:
        """Branded page header, shared with every other workbench window."""
        logo_path = Path(__file__).resolve().parents[1] / "assets" / "anvil.png"

        header = HeaderBar(
            self,
            "RingForge",
            subtitle="Spec Analysis",
            description=(
                "Review OpenAPI and Swagger definitions and surface risky or "
                "undocumented endpoints."
            ),
            logo_path=logo_path if logo_path.exists() else None,
            logo_size=72,
            parent_bg=T.BG,
        )
        header.grid(row=0, column=0, sticky="ew", padx=outer.get("padx", 10), pady=outer.get("pady", (8, 10)))
        self._banner_logo_img = getattr(header, "_logo_image", None)

    def _build_spec_controls(self, parent):
        top = ttk.LabelFrame(parent, text="Spec Input", style="Section.TLabelframe")
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="API Spec", style="Field.TLabel").grid(
            row=0, column=0, sticky="w", padx=(12, 8), pady=10
        )

        ttk.Entry(top, textvariable=self.spec_path_var).grid(
            row=0, column=1, sticky="ew", padx=(0, 10), pady=10
        )

        btns = ttk.Frame(top, style="App.TFrame")
        btns.grid(row=0, column=2, sticky="e", padx=(0, 10), pady=8)

        ttk.Button(
            btns,
            text="Browse",
            style="Secondary.TButton",
            command=self._browse_spec,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            btns,
            text="Analyze Spec",
            style="Secondary.TButton",
            command=self._parse_spec,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            btns,
            text="Open Latest Report",
            style="Secondary.TButton",
            command=self._open_html_report,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            btns,
            text="Open Case Files",
            style="Secondary.TButton",
            command=self._open_case_files,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            btns,
            text="Manual API Tester",
            style="Secondary.TButton",
            command=self._open_manual_api_tester,
        ).pack(side="left")

    def _build_overview_cards(self, parent: tk.Misc) -> None:
        metrics = ttk.LabelFrame(parent, text="Overview", style="Section.TLabelframe")
        metrics.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        for i in range(5):
            metrics.columnconfigure(i, weight=1)

        self._build_metric_card(metrics, 0, "Format", self.spec_format_var)
        self._build_metric_card(metrics, 1, "Version", self.spec_version_var)
        self._build_metric_card(metrics, 2, "Endpoints", self.spec_endpoint_count_var)
        self._build_metric_card(metrics, 3, "Auth", self.spec_auth_var)
        self._build_metric_card(metrics, 4, "Confidence", self.spec_confidence_var)

    def _build_metric_card(self, parent: tk.Misc, col: int, title: str, var: tk.StringVar) -> None:
        card = ttk.Frame(parent, style="SummaryCard.TFrame")
        card.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 8, 0), pady=10)
        card.columnconfigure(0, weight=1)
        ttk.Label(card, text=title, style="SummaryLabel.TLabel").grid(row=0, column=0, sticky="w", padx=12, pady=(10, 2))
        ttk.Label(card, textvariable=var, style="SummaryValue.TLabel").grid(row=1, column=0, sticky="w", padx=12, pady=(0, 10))

    def _build_main_body(self, parent: tk.Misc) -> None:
        body = ttk.Frame(parent, style="App.TFrame")
        body.grid(row=2, column=0, sticky="nsew", pady=(0, 8))
        body.columnconfigure(0, weight=0, minsize=520)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_left_sidebar(body)
        self._build_endpoint_inventory(body)

    def _build_left_sidebar(self, parent: tk.Misc) -> None:
        left = ttk.Frame(parent, style="App.TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=0)
        left.rowconfigure(1, weight=1)
        left.rowconfigure(2, weight=1)
        left.rowconfigure(3, weight=1)
        left.rowconfigure(4, weight=0)

        summary = ttk.LabelFrame(left, text="Summary", style="Section.TLabelframe")
        summary.grid(row=0, column=0, sticky="ew")
        summary.columnconfigure(0, weight=1)

        self.summary_label = ttk.Label(
            summary,
            textvariable=self.summary_var,
            wraplength=420,
            justify="left",
        )
        self.summary_label.grid(row=0, column=0, sticky="w", padx=12, pady=12)

        self.notes_text = self._build_sidebar_box(left, 1, "Risk Notes", height=11)
        self.top_risky_text = self._build_sidebar_box(left, 2, "Top Risky Endpoints", height=12)
        self.recommended_tests_text = self._build_sidebar_box(left, 3, "Recommended Tests", height=11)

        getting_started = ttk.LabelFrame(left, text="Getting Started", style="Section.TLabelframe")
        getting_started.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        getting_started.columnconfigure(0, weight=1)

        ttk.Label(getting_started, text="API Spec Analysis", style="SectionHeader.TLabel").grid(
            row=0, column=0, sticky="w", padx=12, pady=(10, 4)
        )
        ttk.Label(
            getting_started,
            text="Load an OpenAPI or Swagger definition to build endpoint inventory, summarize authentication, generate risk notes, and create an HTML report.",
            wraplength=420,
            justify="left",
        ).grid(row=1, column=0, sticky="w", padx=12)
        ttk.Label(
            getting_started,
            text="Supported formats: JSON, YAML, YML",
            style="Muted.TLabel",
        ).grid(row=2, column=0, sticky="w", padx=12, pady=(8, 10))

    def _build_sidebar_box(self, parent: tk.Misc, row: int, title: str, height: int) -> tk.Text:
        section = ttk.LabelFrame(parent, text=title, style="Section.TLabelframe")
        section.grid(row=row, column=0, sticky="nsew", pady=(10, 0))
        section.columnconfigure(0, weight=1)
        section.rowconfigure(0, weight=1)

        text = tk.Text(
            section,
            height=height,
            wrap="word",
            bg=self.colors["entry_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            selectbackground=self.colors["accent"],
            selectforeground=T.TEXT_ON_ACCENT,
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=self.colors["border"],
            highlightcolor=self.colors["border"],
            padx=10,
            pady=8,
            font=("Consolas", 10),
        )
        text.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)

        return text

    def _build_endpoint_inventory(self, parent: tk.Misc) -> None:
        right = ttk.LabelFrame(parent, text="Endpoint Inventory", style="Section.TLabelframe")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)
        right.rowconfigure(1, weight=0)

        table_wrap = ttk.Frame(right, style="App.TFrame")
        table_wrap.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
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
            "auth_source": "Auth Source",
            "risk_level": "Risk",
            "params": "Params",
            "flags": "Flags",
        }
        widths = {
            "method": 100,
            "path": 340,
            "summary": 420,
            "auth": 180,
            "auth_source": 110,
            "risk_level": 80,
            "params": 80,
            "flags": 220,
        }

        for col in cols:
            self.tree.heading(col, text=headings[col], anchor="w")
            self.tree.column(col, width=widths[col], minwidth=widths[col], anchor="w", stretch=(col in {"path", "summary"}))

        self.tree.grid(row=0, column=0, sticky="nsew")

        ysb = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        ysb.grid(row=0, column=1, sticky="ns")
        xsb = ttk.Scrollbar(right, orient="horizontal", command=self.tree.xview)
        xsb.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 8))

        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)

    def _build_status_bar(self, parent: tk.Misc) -> None:
        status_row = ttk.Frame(parent, style="App.TFrame")
        status_row.grid(row=3, column=0, sticky="ew")
        status_row.columnconfigure(0, weight=1)

        ttk.Label(status_row, textvariable=self.status_var, style="Muted.TLabel").grid(
            row=0, column=1, sticky="e", padx=(12, 0), pady=2
        )

    # -------------------------------------------------------------------------
    # INPUT HELPERS
    # -------------------------------------------------------------------------

    def _browse_spec(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        start = Path(self.spec_path_var.get()).parent if self.spec_path_var.get().strip() else project_root
        chosen = filedialog.askopenfilename(
            title="Select API spec",
            initialdir=str(start),
            filetypes=[("API Specs", "*.json *.yaml *.yml"), ("All Files", "*.*")],
            parent=self,
        )
        if chosen:
            self.spec_path_var.set(str(Path(chosen)))

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

    # -------------------------------------------------------------------------
    # RESULT POPULATION
    # -------------------------------------------------------------------------

    def _populate_result(self, result: dict[str, Any]) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        summary = result.get("summary", {})
        title = result.get("title") or Path(result.get("input_file", "spec")).name

        raw_auth_summary = result.get("auth_summary", [])
        normalized_auth_summary = []
        for item in raw_auth_summary:
            canon = self._normalize_auth_name(str(item))
            if canon != "none" and canon not in normalized_auth_summary:
                normalized_auth_summary.append(canon)

        self.spec_format_var.set(result.get("format", "") or "-")
        self.spec_version_var.set(result.get("version", "") or "-")
        self.spec_endpoint_count_var.set(str(summary.get("endpoint_count", 0)))
        self.spec_auth_var.set(", ".join(normalized_auth_summary) if normalized_auth_summary else "none")
        self.spec_confidence_var.set(str(result.get("confidence", "-")))

        self.summary_var.set(
            f"Title: {title}\n"
            f"Format: {result.get('format', '-')}\n"
            f"Type: {result.get('spec_type', '-')}\n"
            f"Servers: {', '.join(result.get('servers', [])) or 'none'}\n"
            f"Methods: GET {summary.get('get_count',0)} | POST {summary.get('post_count',0)} | "
            f"PUT {summary.get('put_count',0)} | PATCH {summary.get('patch_count',0)} | "
            f"DELETE {summary.get('delete_count',0)}"
        )

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

        self.top_risky_text.delete("1.0", "end")
        top_risky = result.get("top_risky_endpoints", []) or []

        if not top_risky:
            endpoints = result.get("endpoints", []) or []
            top_risky = sorted(
                [ep for ep in endpoints if ep.get("risk_level") == "high" or int(ep.get("risk_score", 0)) > 0],
                key=lambda ep: (-int(ep.get("risk_score", 0)), str(ep.get("path", "")), str(ep.get("method", ""))),
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
                canon = self._normalize_auth_name(str(item))
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

    # -------------------------------------------------------------------------
    # HTML RENDERING / REPORTS
    # -------------------------------------------------------------------------

    def _render_html(self, result: dict[str, Any]) -> str:
        from html import escape
        from dynamic_analysis.report_theme import report_page

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
            <div class="card" style="margin-bottom:10px;">
                <div style="font-weight:bold;margin-bottom:4px;">{method} {path}</div>
                <div class="muted" style="margin-bottom:6px;">Risk: {level} | Score: {score}</div>
                <ul>{reasons_html}</ul>
            </div>"""
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
            <div class="card" style="margin-bottom:10px;">
                <div style="font-weight:bold;margin-bottom:4px;">{method} {path}</div>
                <div class="muted" style="margin-bottom:6px;">Risk: {level} | Score: {score}</div>
                <ul>{tests_html}</ul>
            </div>"""
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

        body_html = f"""
        <div class="tile-grid">
            <div class="tile"><div class="tile-label">Format</div><div class="tile-value" style="font-size:18px;">{escape(fmt)}</div></div>
            <div class="tile"><div class="tile-label">Spec Type</div><div class="tile-value" style="font-size:18px;">{escape(spec_type)}</div></div>
            <div class="tile"><div class="tile-label">Version</div><div class="tile-value" style="font-size:18px;">{escape(version)}</div></div>
            <div class="tile"><div class="tile-label">Endpoints</div><div class="tile-value">{summary.get("endpoint_count", 0)}</div></div>
            <div class="tile"><div class="tile-label">Auth</div><div class="tile-value" style="font-size:18px;">{escape(auth_txt)}</div></div>
            <div class="tile"><div class="tile-label">Notable</div><div class="tile-value">{summary.get("top_risky_endpoint_count", 0)}</div></div>
            <div class="tile"><div class="tile-label">Confidence</div><div class="tile-value" style="font-size:18px;">{escape(str(confidence))}</div></div>
            <div class="tile"><div class="tile-label">Unresolved Refs</div><div class="tile-value">{result.get("unresolved_refs_count", 0)}</div></div>
        </div>

        <div class="card">
            <div class="section-head"><h2>Summary</h2></div>
            <table class="kv">
                <tr><th>Servers</th><td>{escape(servers_txt)}</td></tr>
                <tr><th>Methods</th><td>GET {summary.get("get_count",0)} | POST {summary.get("post_count",0)} | PUT {summary.get("put_count",0)} | PATCH {summary.get("patch_count",0)} | DELETE {summary.get("delete_count",0)}</td></tr>
                <tr><th>Admin-like Routes</th><td>{summary.get("admin_like_route_count", 0)}</td></tr>
                <tr><th>Sensitive Parameters</th><td>{summary.get("sensitive_param_count", 0)}</td></tr>
            </table>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;">
            <div class="card">
                <div class="section-head"><h2>Risk Notes</h2></div>
                <ul>{risk_notes_html}</ul>
            </div>
            <div class="card">
                <div class="section-head"><h2>Parser Warnings</h2></div>
                <ul>{parser_warnings_html}</ul>
            </div>
        </div>

        <div class="card">
            <div class="section-head"><h2>Unresolved Refs</h2></div>
            <ul>{unresolved_refs_html}</ul>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;">
            <div class="card">
                <div class="section-head"><h2>Notable Endpoints</h2></div>
                {top_risky_html}
            </div>
            <div class="card">
                <div class="section-head"><h2>Recommended Tests</h2></div>
                {recommended_html}
            </div>
        </div>

        <div class="card">
            <div class="section-head"><h2>Endpoint Inventory</h2></div>
            <div class="table-wrap">
                <table>
                    <thead><tr>
                        <th>Method</th><th>Path</th><th>Summary</th>
                        <th>Auth</th><th>Auth Source</th><th>Risk</th>
                        <th>Params</th><th>Flags</th>
                    </tr></thead>
                    <tbody>{''.join(rows)}</tbody>
                </table>
            </div>
        </div>
        """

        verdict_label = str(confidence).upper() if confidence and confidence != "-" else spec_type.upper()
        verdict_class = "verdict sev-none" if str(confidence).lower() in ("high", "very high") else "verdict sev-low"

        return report_page(
            title="API Spec Analysis",
            subtitle=escape(str(title)),
            verdict=verdict_label,
            verdict_class=verdict_class,
            body_html=body_html,
        )
    
    def _is_url(self, value: str) -> bool:
        text = (value or "").strip().lower()
        return text.startswith("http://") or text.startswith("https://")


    def _download_spec_url(self, url: str, spec_dir: Path) -> Path:
        """
        Download an OpenAPI/Swagger spec URL into the current spec_analysis folder
        and return the local file path.
        """
        spec_dir.mkdir(parents=True, exist_ok=True)

        parsed = urllib.parse.urlparse(url)
        name = Path(parsed.path).name or "downloaded_openapi_spec.json"

        # Preserve a useful extension when possible.
        if not Path(name).suffix:
            name = f"{name}.json"

        # Keep filename safe for Windows.
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._-")
        if not safe_name:
            safe_name = "downloaded_openapi_spec.json"

        output_dir = spec_dir / "downloaded_specs"
        output_dir.mkdir(parents=True, exist_ok=True)

        output_path = output_dir / safe_name

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "RingForge-Workbench/1.0",
                "Accept": "application/json, application/yaml, text/yaml, */*",
            },
        )

        with urllib.request.urlopen(request, timeout=30) as response:
            content = response.read()

        if not content:
            raise ValueError("Downloaded spec was empty.")

        output_path.write_bytes(content)
        return output_path
    
    def _save_report_files(self, result: dict[str, Any]) -> tuple[Path, Path]:
        spec_dir = self._ensure_spec_dir()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        src = Path(self.spec_path_var.get().strip())
        spec_name = src.stem if src.exists() else "spec"
        safe_spec_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in spec_name)
        safe_spec_name = safe_spec_name.strip("_") or "spec"

        html_text = self._render_html(result)

        # ------------------------------------------------------------------
        # Canonical latest outputs used by Spec window, Unified Report, scoring,
        # and other readers.
        # ------------------------------------------------------------------
        api_spec_json = spec_dir / "api_spec_analysis.json"
        latest_json = spec_dir / "spec_inventory_latest.json"
        latest_html = spec_dir / "spec_inventory_latest.html"

        _safe_json_write(api_spec_json, result)
        _safe_json_write(latest_json, result)
        latest_html.write_text(html_text, encoding="utf-8")

        # Optional latest-by-spec-name outputs. These are useful when testing
        # multiple specs in one case but still avoid timestamp clutter.
        named_latest_json = spec_dir / f"spec_inventory_latest_{safe_spec_name}.json"
        named_latest_html = spec_dir / f"spec_inventory_latest_{safe_spec_name}.html"

        _safe_json_write(named_latest_json, result)
        named_latest_html.write_text(html_text, encoding="utf-8")

        # ------------------------------------------------------------------
        # Metadata copy for compatibility with Unified Report/module detection.
        # ------------------------------------------------------------------
        metadata_dir = spec_dir / "metadata"
        metadata_dir.mkdir(parents=True, exist_ok=True)
        _safe_json_write(metadata_dir / "api_spec_analysis.json", result)

        # ------------------------------------------------------------------
        # Historical run folder. This keeps old runs without cluttering root.
        # ------------------------------------------------------------------
        runs_dir = spec_dir / "runs"
        run_dir = runs_dir / f"{timestamp}_{safe_spec_name}"
        run_dir.mkdir(parents=True, exist_ok=True)

        run_json = run_dir / "api_spec_analysis.json"
        run_inventory_json = run_dir / "spec_inventory.json"
        run_inventory_html = run_dir / "spec_inventory.html"

        _safe_json_write(run_json, result)
        _safe_json_write(run_inventory_json, result)
        run_inventory_html.write_text(html_text, encoding="utf-8")

        # ------------------------------------------------------------------
        # Preserve source spec.
        # Keep latest original in spec_analysis\originals and per-run copy in runs.
        # ------------------------------------------------------------------
        if src.exists():
            try:
                originals_dir = spec_dir / "originals"
                originals_dir.mkdir(parents=True, exist_ok=True)

                original_name = f"original_{safe_spec_name}{src.suffix.lower()}"
                shutil.copy2(src, originals_dir / original_name)
                shutil.copy2(src, run_dir / original_name)
            except Exception:
                pass

        # ------------------------------------------------------------------
        # Legacy compatibility copies.
        # Keep only latest files here so old readers/releases still work.
        # ------------------------------------------------------------------
        case_dir = spec_dir.parent
        legacy_spec_dir = case_dir / "spec"
        legacy_spec_dir.mkdir(parents=True, exist_ok=True)

        _safe_json_write(legacy_spec_dir / "api_spec_analysis.json", result)
        _safe_json_write(legacy_spec_dir / "spec_inventory_latest.json", result)
        (legacy_spec_dir / "spec_inventory_latest.html").write_text(html_text, encoding="utf-8")

        _safe_json_write(case_dir / "api_spec_analysis.json", result)

        self.last_json_report = latest_json
        self.last_html_report = latest_html
        return latest_json, latest_html

    # -------------------------------------------------------------------------
    # ACTIONS
    # -------------------------------------------------------------------------

    def _parse_spec(self) -> None:
        raw_input = self.spec_path_var.get().strip()

        if not raw_input:
            messagebox.showwarning(
                "Spec Analysis",
                "Select or enter an API spec file first.",
                parent=self,
            )
            self.status_var.set("No spec selected")
            return

        try:
            spec_dir = self._ensure_spec_dir()

            if self._is_url(raw_input):
                self.status_var.set("Downloading API spec URL...")
                self.update_idletasks()

                spec_path = self._download_spec_url(raw_input, spec_dir)
                self.spec_path_var.set(str(spec_path))
            else:
                spec_path = Path(raw_input)

            if spec_path.suffix.lower() not in {".json", ".yaml", ".yml"}:
                messagebox.showerror(
                    "Spec Analysis",
                    "API Spec Analysis only accepts .json, .yaml, or .yml files.",
                    parent=self,
                )
                self.status_var.set("Invalid spec file type")
                return

            if not spec_path.exists():
                messagebox.showerror(
                    "Spec Analysis",
                    f"Spec file not found:\n{spec_path}",
                    parent=self,
                )
                self.status_var.set("Spec file not found")
                return

            self.status_var.set("Analyzing spec...")
            self.update_idletasks()

            result = engine_analyze_api_spec(spec_path, spec_dir)

            if result.get("returncode") != 0:
                messagebox.showerror(
                    "Spec Analysis",
                    result.get("error", "Unknown error"),
                    parent=self,
                )
                self.status_var.set("Parse failed")
                return

            self.last_result = result
            self.app.latest_spec_result = result if isinstance(result, dict) else {}
            self._populate_result(result)
            self._save_report_files(result)

            project_root = Path(__file__).resolve().parents[1]
            case_root = (
                Path(self.app.case_root_var.get().strip())
                if hasattr(self.app, "case_root_var") and self.app.case_root_var.get().strip()
                else (project_root / "cases")
            )
            case_dir = case_root / self._current_case_name()
            self.app.case_dir_detected = case_dir

            self.status_var.set(f"Parsed {result.get('summary', {}).get('endpoint_count', 0)} endpoints")

        except Exception as e:
            messagebox.showerror(
                "Spec Analysis",
                f"Could not analyze spec:\n{e}",
                parent=self,
            )
            self.status_var.set("Spec analysis failed")

    def _save_html_report(self) -> None:
        if not self.last_result:
            messagebox.showinfo(
                "Save HTML Report",
                "Parse a spec first so there is a report to save.",
                parent=self,
            )
            return

        _, html_path = self._save_report_files(self.last_result)
        self.status_var.set(f"Saved HTML report: {html_path.name}")
        messagebox.showinfo(
            "Save HTML Report",
            f"Saved spec HTML report:\n{html_path}",
            parent=self,
        )

    def _open_html_report(self) -> None:
        """
        Open the latest canonical Spec Analysis HTML report.

        Historical reports are stored under:
            spec_analysis/runs/<timestamp>_<spec_name>/spec_inventory.html

        The button should always open:
            spec_analysis/spec_inventory_latest.html
        """
        spec_dir = self.last_spec_dir

        if spec_dir is None:
            spec_dir = self._ensure_spec_dir()

        latest_html = Path(spec_dir) / "spec_inventory_latest.html"

        if self.last_html_report and Path(self.last_html_report).exists():
            latest_html = Path(self.last_html_report)

        if not latest_html.exists():
            messagebox.showinfo(
                "Open HTML Report",
                "No Spec Analysis HTML report was found yet. Run Analyze Spec first.",
                parent=self,
            )
            self.status_var.set("No HTML report found")
            return

        try:
            webbrowser.open(latest_html.resolve().as_uri())
            self.status_var.set(f"Opened HTML report: {latest_html}")
        except Exception as e:
            messagebox.showerror(
                "Open HTML Report",
                f"Could not open HTML report:\n{latest_html}\n\n{e}",
                parent=self,
            )
            self.status_var.set("Could not open HTML report")

    def _open_case_files(self) -> None:
        spec_dir = self.last_spec_dir
        if spec_dir is None:
            candidate = self._ensure_spec_dir()
            spec_dir = candidate if candidate.exists() else None

        if spec_dir is None or not spec_dir.exists():
            messagebox.showinfo("Open Case Files", "No spec case folder was found yet.", parent=self)
            return

        try:
            if hasattr(self.app, "_open_path"):
                self.app._open_path(spec_dir)
            elif os.name == "nt":
                os.startfile(str(spec_dir))
            else:
                webbrowser.open(spec_dir.resolve().as_uri())

            self.status_var.set(f"Opened case files: {spec_dir}")

        except Exception as e:
            messagebox.showerror(
                "Open Case Files",
                f"Could not open spec case folder:\n{spec_dir}\n\n{e}",
                parent=self,
            )

    def _open_manual_api_tester(self) -> None:
        APIAnalysisWindow(self.app)


SpecWindow = SpecAnalysisWindow
