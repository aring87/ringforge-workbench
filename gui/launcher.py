from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class LauncherWindow(ttk.Frame):
    def __init__(self, parent, app, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.app = app
        self.configure(padding=18)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
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

        footer = ttk.Frame(self)
        footer.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(16, 0))
        footer.columnconfigure(0, weight=1)

        ttk.Button(
            footer,
            text="Exit",
            style="Action.TButton",
            command=self.app.destroy,
        ).grid(row=0, column=1, sticky="e")

    def _card(self, row, col, title, desc, command):
        card = ttk.Frame(self, style="Card.TFrame", padding=16)
        card.grid(row=row, column=col, sticky="nsew", padx=8, pady=8)
        self.rowconfigure(row, weight=1)

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

        ttk.Button(
            card,
            text=f"Open {title}",
            style="Action.TButton",
            command=command,
        ).pack(anchor="w")