from __future__ import annotations

import json
import shutil
import tkinter as tk
import webbrowser

from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
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
        self.configure(bg="#05070B")

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
        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except Exception:
            pass

        bg = "#05070B"
        panel = "#0B1220"
        panel_alt = "#101A2E"
        border = "#294C8E"
        text = "#F7FAFF"
        muted = "#B8C7E6"
        accent = "#2F6BFF"
        accent_active = "#3F7BFF"
        entry_bg = "#0D1A33"
        tab_bg = "#14213B"

        style.configure(".", background=bg, foreground=text)
        style.configure("App.TFrame", background=bg)
        style.configure("Card.TFrame", background=panel, relief="flat", borderwidth=0)
        style.configure("SummaryCard.TFrame", background=panel_alt, relief="flat", borderwidth=0)

        style.configure("Section.TLabelframe", background=bg, foreground=text, borderwidth=1, relief="solid")
        style.configure("Section.TLabelframe.Label", background=bg, foreground=text, font=("Segoe UI", 10, "bold"))

        style.configure("Title.TLabel", background=panel, foreground=text, font=("Segoe UI", 18, "bold"))
        style.configure("Subtitle.TLabel", background=panel, foreground=muted, font=("Segoe UI", 10))
        style.configure("Field.TLabel", background=bg, foreground="#DCE6FF", font=("Segoe UI", 10, "bold"))
        style.configure("Muted.TLabel", background=bg, foreground=muted, font=("Segoe UI", 9))
        style.configure("SectionHeader.TLabel", background=bg, foreground=accent, font=("Segoe UI", 11, "bold"))
        style.configure("SummaryLabel.TLabel", background=panel_alt, foreground=muted, font=("Segoe UI", 9, "bold"))
        style.configure("SummaryValue.TLabel", background=panel_alt, foreground=text, font=("Segoe UI", 13, "bold"))

        style.configure(
            "Action.TButton",
            background=accent,
            foreground="#FFFFFF",
            bordercolor=accent,
            focusthickness=0,
            focuscolor=accent,
            padding=(12, 7),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Action.TButton",
            background=[("active", accent_active), ("pressed", accent_active)],
            foreground=[("disabled", "#A6B4D0"), ("!disabled", "#FFFFFF")],
        )

        style.configure(
            "Secondary.TButton",
            background=panel_alt,
            foreground=text,
            bordercolor=border,
            focusthickness=0,
            focuscolor=panel_alt,
            padding=(10, 7),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Secondary.TButton",
            background=[("active", "#16284A"), ("pressed", "#16284A")],
            foreground=[("disabled", "#A6B4D0"), ("!disabled", text)],
        )

        style.configure(
            "TEntry",
            fieldbackground=entry_bg,
            foreground=text,
            insertcolor=text,
            bordercolor=border,
            lightcolor=border,
            darkcolor=border,
            padding=6,
        )

        style.configure(
            "Treeview",
            background=entry_bg,
            fieldbackground=entry_bg,
            foreground=text,
            bordercolor=border,
            rowheight=28,
            font=("Segoe UI", 10),
        )
        style.map("Treeview", background=[("selected", "#1D3F86")], foreground=[("selected", "#FFFFFF")])
        style.configure(
            "Treeview.Heading",
            background=panel_alt,
            foreground=text,
            bordercolor=border,
            font=("Segoe UI", 10, "bold"),
            padding=(8, 8),
        )

        self.colors = {
            "bg": bg,
            "panel": panel,
            "panel_alt": panel_alt,
            "border": border,
            "text": text,
            "muted": muted,
            "accent": accent,
            "entry_bg": entry_bg,
            "tab_bg": tab_bg,
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

        spec_dir = case_dir / "spec"
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
        panel_bg = self.colors["panel"]
        border = self.colors["border"]
        accent = self.colors["accent"]
        text_main = self.colors["text"]
        text_soft = self.colors["muted"]

        banner_wrap = ttk.Frame(self, style="App.TFrame")
        banner_wrap.grid(row=0, column=0, sticky="ew", padx=outer.get("padx", 10), pady=outer.get("pady", (8, 10)))
        banner_wrap.columnconfigure(0, weight=1)

        banner = tk.Frame(
            banner_wrap,
            bg=panel_bg,
            highlightthickness=1,
            highlightbackground=border,
            highlightcolor=border,
        )
        banner.grid(row=0, column=0, sticky="ew")
        banner.columnconfigure(1, weight=1)

        logo_path = Path(__file__).resolve().parents[1] / "assets" / "anvil.png"
        if logo_path.exists() and Image is not None and ImageTk is not None:
            try:
                logo_img = Image.open(logo_path).convert("RGBA")
                logo_img = logo_img.resize((96, 96), Image.LANCZOS)
                self.brand_logo_img = ImageTk.PhotoImage(logo_img)
                tk.Label(
                    banner,
                    image=self.brand_logo_img,
                    bg=panel_bg,
                    bd=0,
                    highlightthickness=0,
                ).grid(row=0, column=0, rowspan=3, sticky="w", padx=(16, 18), pady=14)
            except Exception:
                self._build_banner_fallback(banner, panel_bg, accent)
        else:
            self._build_banner_fallback(banner, panel_bg, accent)

        tk.Label(
            banner,
            text="RingForge Workbench",
            bg=panel_bg,
            fg=text_main,
            font=("Segoe UI", 24, "bold"),
            anchor="w",
        ).grid(row=0, column=1, sticky="sw", pady=(16, 0))

        tk.Label(
            banner,
            text="API Spec Analysis",
            bg=panel_bg,
            fg=accent,
            font=("Segoe UI", 18, "bold"),
            anchor="w",
        ).grid(row=1, column=1, sticky="nw")

        tk.Label(
            banner,
            text="Analyze OpenAPI and Swagger definitions, inspect endpoint inventory, review auth models, and export analyst-ready HTML reports.",
            bg=panel_bg,
            fg=text_soft,
            font=("Segoe UI", 10),
            anchor="w",
            justify="left",
            wraplength=1100,
        ).grid(row=2, column=1, sticky="w", pady=(4, 16))

    def _build_banner_fallback(self, banner: tk.Misc, panel_bg: str, accent: str) -> None:
        tk.Label(
            banner,
            text="[anvil.png missing]",
            bg=panel_bg,
            fg=accent,
            font=("Segoe UI", 10, "bold"),
            bd=0,
            highlightthickness=0,
        ).grid(row=0, column=0, rowspan=3, sticky="w", padx=(16, 18), pady=14)

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
            text="Open HTML Report",
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
            selectforeground="#FFFFFF",
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
            <div class="tile"><div class="tile-label">Top Risky</div><div class="tile-value">{summary.get("top_risky_endpoint_count", 0)}</div></div>
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
                <div class="section-head"><h2>Top Risky Endpoints</h2></div>
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

        self.last_json_report = latest_json
        self.last_html_report = latest_html
        return latest_json, latest_html

    # -------------------------------------------------------------------------
    # ACTIONS
    # -------------------------------------------------------------------------

    def _parse_spec(self) -> None:
        spec_path = Path(self.spec_path_var.get().strip())
        if spec_path.suffix.lower() not in {".json", ".yaml", ".yml"}:
            messagebox.showerror(
                "Spec Analysis",
                "API Spec Analysis only accepts .json, .yaml, or .yml files.",
                parent=self,
            )
            self.status_var.set("Invalid spec file type")
            return

        self.status_var.set("Analyzing spec...")
        self.update_idletasks()

        result = engine_analyze_api_spec(spec_path, self._ensure_spec_dir())
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
        report_path = None

        if self.last_html_report:
            candidate = Path(self.last_html_report)
            if candidate.exists():
                report_path = candidate

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

    def _open_case_files(self) -> None:
        spec_dir = self.last_spec_dir
        if spec_dir is None:
            candidate = self._ensure_spec_dir()
            spec_dir = candidate if candidate.exists() else None

        if spec_dir is None or not spec_dir.exists():
            messagebox.showinfo("Open Case Files", "No spec case folder was found yet.", parent=self)
            return

        self.app._open_path(spec_dir)

    def _open_manual_api_tester(self) -> None:
        APIAnalysisWindow(self.app)


SpecWindow = SpecAnalysisWindow
