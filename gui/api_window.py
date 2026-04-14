from __future__ import annotations

import json
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from PIL import Image, ImageTk
except Exception:
    Image = None
    ImageTk = None

try:
    import requests
except Exception:
    requests = None


class APIAnalysisWindow(tk.Toplevel):
    PRESETS = {
        "HTTPBin GET Test": {
            "method": "GET",
            "url": "https://httpbin.org/get",
            "headers": {"User-Agent": "RingForge-Workbench/1.2"},
            "body": "",
            "notes": "Returns HTTP 200 with JSON showing your request details.",
            "verify_ssl": True,
            "timeout": 60,
            "upload_file": "",
            "file_field": "file",
        },
        "HTTPBin POST JSON": {
            "method": "POST",
            "url": "https://httpbin.org/post",
            "headers": {
                "Content-Type": "application/json",
                "User-Agent": "RingForge-Workbench/1.2",
            },
            "body": {"sample": "value"},
            "notes": "Posts JSON to HTTPBin and returns the reflected payload and request metadata.",
            "verify_ssl": True,
            "timeout": 60,
            "upload_file": "",
            "file_field": "file",
        },
        "HTTPBin PUT Test": {
            "method": "PUT",
            "url": "https://httpbin.org/put",
            "headers": {
                "Content-Type": "application/json",
                "User-Agent": "RingForge-Workbench/1.2",
            },
            "body": {"sample": "value"},
            "notes": "Sends a PUT request to HTTPBin and returns the reflected payload.",
            "verify_ssl": True,
            "timeout": 60,
            "upload_file": "",
            "file_field": "file",
        },
        "HTTPBin PATCH Test": {
            "method": "PATCH",
            "url": "https://httpbin.org/patch",
            "headers": {
                "Content-Type": "application/json",
                "User-Agent": "RingForge-Workbench/1.2",
            },
            "body": {"sample": "value"},
            "notes": "Sends a PATCH request to HTTPBin and returns the reflected payload.",
            "verify_ssl": True,
            "timeout": 60,
            "upload_file": "",
            "file_field": "file",
        },
        "HTTPBin DELETE Test": {
            "method": "DELETE",
            "url": "https://httpbin.org/delete",
            "headers": {"User-Agent": "RingForge-Workbench/1.2"},
            "body": "",
            "notes": "Sends a DELETE request to HTTPBin and returns request details.",
            "verify_ssl": True,
            "timeout": 60,
            "upload_file": "",
            "file_field": "file",
        },
        "HTTPBin HEAD Test": {
            "method": "HEAD",
            "url": "https://httpbin.org/get",
            "headers": {"User-Agent": "RingForge-Workbench/1.2"},
            "body": "",
            "notes": "Sends a HEAD request and returns headers only.",
            "verify_ssl": True,
            "timeout": 60,
            "upload_file": "",
            "file_field": "file",
        },
        "HTTPBin OPTIONS Test": {
            "method": "OPTIONS",
            "url": "https://httpbin.org/get",
            "headers": {"User-Agent": "RingForge-Workbench/1.2"},
            "body": "",
            "notes": "Sends an OPTIONS request to inspect supported methods.",
            "verify_ssl": True,
            "timeout": 60,
            "upload_file": "",
            "file_field": "file",
        },
        "VirusTotal File Lookup": {
            "method": "GET",
            "url": "https://www.virustotal.com/api/v3/files/<sha256>",
            "headers": {
                "x-apikey": "<your_api_key_here>",
                "User-Agent": "RingForge-Workbench/1.2",
            },
            "body": "",
            "notes": "Looks up a file hash in VirusTotal. Replace <sha256> and provide your API key.",
            "verify_ssl": True,
            "timeout": 60,
            "upload_file": "",
            "file_field": "file",
        },
        "Generic Multipart Upload": {
            "method": "POST",
            "url": "https://httpbin.org/post",
            "headers": {"User-Agent": "RingForge-Workbench/1.2"},
            "body": {"note": "test-upload"},
            "notes": "Sends a multipart form request. Select a file and adjust the form field name if needed.",
            "verify_ssl": True,
            "timeout": 60,
            "upload_file": "",
            "file_field": "file",
        },
    }

    HTTPBIN_METHOD_URLS = {
        "GET": "https://httpbin.org/get",
        "POST": "https://httpbin.org/post",
        "PUT": "https://httpbin.org/put",
        "PATCH": "https://httpbin.org/patch",
        "DELETE": "https://httpbin.org/delete",
        "HEAD": "https://httpbin.org/get",
        "OPTIONS": "https://httpbin.org/get",
    }

    def __init__(self, master: tk.Misc | None = None) -> None:
        super().__init__(master)
        self.title("Manual API Tester")
        self.geometry("1560x1080")
        self.minsize(1360, 920)
        self.configure(bg="#05070B")

        self.latest_report_path: Path | None = None
        self.brand_logo_img = None
        self._request_thread: threading.Thread | None = None

        self.method_var = tk.StringVar(value="GET")
        self.url_var = tk.StringVar(value="")
        self.upload_file_var = tk.StringVar(value="")
        self.file_field_var = tk.StringVar(value="file")
        self.verify_ssl_var = tk.BooleanVar(value=True)
        self.timeout_var = tk.IntVar(value=60)
        self.preset_var = tk.StringVar(value="HTTPBin GET Test")

        self._configure_styles()
        self._build_ui()
        self._load_preset()

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

        self.option_add("*TCombobox*Listbox*Background", entry_bg)
        self.option_add("*TCombobox*Listbox*Foreground", text)
        self.option_add("*TCombobox*Listbox*selectBackground", accent)
        self.option_add("*TCombobox*Listbox*selectForeground", "#FFFFFF")

        style.configure(".", background=bg, foreground=text)
        style.configure("App.TFrame", background=bg)
        style.configure("Header.TFrame", background=panel)
        style.configure("Card.TFrame", background=panel, relief="flat", borderwidth=0)
        style.configure("SummaryCard.TFrame", background=panel_alt, relief="flat", borderwidth=0)

        style.configure("Section.TLabelframe", background=bg, foreground=text, borderwidth=1, relief="solid")
        style.configure("Section.TLabelframe.Label", background=bg, foreground=text, font=("Segoe UI", 10, "bold"))

        style.configure("Field.TLabel", background=bg, foreground="#DCE6FF", font=("Segoe UI", 10, "bold"))
        style.configure("Muted.TLabel", background=bg, foreground=muted, font=("Segoe UI", 9))
        style.configure("SummaryLabel.TLabel", background=panel_alt, foreground=muted, font=("Segoe UI", 9, "bold"))
        style.configure("SummaryValue.TLabel", background=panel_alt, foreground=text, font=("Segoe UI", 11, "bold"))

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
            "TSpinbox",
            fieldbackground=entry_bg,
            foreground=text,
            arrowsize=12,
            insertcolor=text,
            bordercolor=border,
            lightcolor=border,
            darkcolor=border,
            padding=4,
        )
        style.configure(
            "TCombobox",
            fieldbackground=entry_bg,
            background=entry_bg,
            foreground=text,
            arrowcolor=text,
            bordercolor=border,
            lightcolor=border,
            darkcolor=border,
            padding=4,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", entry_bg)],
            foreground=[("readonly", text)],
            background=[("readonly", entry_bg)],
        )

        style.configure("TCheckbutton", background=bg, foreground=text, font=("Segoe UI", 10))
        style.map("TCheckbutton", background=[("active", bg)], foreground=[("active", text)])

        style.configure("TNotebook", background=bg, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure(
            "TNotebook.Tab",
            background=tab_bg,
            foreground=text,
            padding=(16, 9),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", accent), ("active", "#1D3F86")],
            foreground=[("selected", "#FFFFFF"), ("active", "#FFFFFF")],
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
        }

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self._build_top_banner({"padx": 10, "pady": (8, 10)})

        content = ttk.Frame(self, style="App.TFrame")
        content.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=0)
        content.rowconfigure(1, weight=0)
        content.rowconfigure(2, weight=0)
        content.rowconfigure(3, weight=1)

        self._build_request_setup(content)
        self._build_request_editors(content)
        self._build_action_bar(content)
        self._build_response_section(content)

    def _build_top_banner(self, outer: dict[str, Any]) -> None:
        panel_bg = "#0B1220"
        border = "#294C8E"
        accent = "#2F6BFF"
        text_main = "#F7FAFF"
        text_soft = "#B8C7E6"

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
                tk.Label(banner, image=self.brand_logo_img, bg=panel_bg, bd=0, highlightthickness=0).grid(
                    row=0, column=0, rowspan=3, sticky="w", padx=(16, 18), pady=14
                )
            except Exception:
                tk.Label(banner, text="[anvil.png error]", bg=panel_bg, fg=accent, font=("Segoe UI", 10, "bold"), bd=0, highlightthickness=0).grid(
                    row=0, column=0, rowspan=3, sticky="w", padx=(16, 18), pady=14
                )
        else:
            tk.Label(banner, text="[anvil.png missing]", bg=panel_bg, fg=accent, font=("Segoe UI", 10, "bold"), bd=0, highlightthickness=0).grid(
                row=0, column=0, rowspan=3, sticky="w", padx=(16, 18), pady=14
            )

        tk.Label(banner, text="RingForge Workbench", bg=panel_bg, fg=text_main, font=("Segoe UI", 24, "bold"), anchor="w").grid(
            row=0, column=1, sticky="sw", pady=(16, 0)
        )
        tk.Label(banner, text="Manual API Tester", bg=panel_bg, fg=accent, font=("Segoe UI", 18, "bold"), anchor="w").grid(
            row=1, column=1, sticky="nw"
        )
        tk.Label(
            banner,
            text="Build requests, test endpoints, inspect responses, and export analyst-ready HTML reports.",
            bg=panel_bg,
            fg=text_soft,
            font=("Segoe UI", 10),
            anchor="w",
            justify="left",
            wraplength=980,
        ).grid(row=2, column=1, sticky="w", pady=(4, 16))

    def _build_request_setup(self, parent: tk.Misc) -> None:
        frame = ttk.LabelFrame(parent, text="Request Setup", style="Section.TLabelframe")
        frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        frame.columnconfigure(0, weight=0, minsize=120)
        frame.columnconfigure(1, weight=1)

        label_padx = (12, 10)
        field_padx = (0, 12)

        ttk.Label(frame, text="Preset", style="Field.TLabel").grid(row=0, column=0, sticky="w", padx=label_padx, pady=(10, 6))
        preset_row = ttk.Frame(frame)
        preset_row.grid(row=0, column=1, sticky="w", padx=field_padx, pady=(10, 6))

        self.preset_combo = ttk.Combobox(
            preset_row,
            textvariable=self.preset_var,
            state="readonly",
            values=list(self.PRESETS.keys()),
            width=28,
        )
        self.preset_combo.grid(row=0, column=0, sticky="w")
        self.preset_combo.bind("<<ComboboxSelected>>", lambda e: self._load_preset())

        self.load_preset_btn = ttk.Button(preset_row, text="Load Preset", style="Action.TButton", command=self._load_preset, width=12)
        self.load_preset_btn.grid(row=0, column=1, sticky="w", padx=(10, 0))

        ttk.Label(frame, text="Method", style="Field.TLabel").grid(row=1, column=0, sticky="w", padx=label_padx, pady=6)
        self.method_combo = ttk.Combobox(
            frame,
            textvariable=self.method_var,
            state="readonly",
            values=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
            width=10,
        )
        self.method_combo.grid(row=1, column=1, sticky="w", padx=field_padx, pady=6)
        self.method_combo.bind("<<ComboboxSelected>>", self._on_method_changed)

        ttk.Label(frame, text="URL", style="Field.TLabel").grid(row=2, column=0, sticky="w", padx=label_padx, pady=6)
        url_row = ttk.Frame(frame)
        url_row.grid(row=2, column=1, sticky="ew", padx=field_padx, pady=6)
        url_row.columnconfigure(0, weight=1)

        self.url_entry = ttk.Entry(url_row, textvariable=self.url_var)
        self.url_entry.grid(row=0, column=0, sticky="ew")
        self.verify_ssl_check = ttk.Checkbutton(url_row, text="Verify SSL", variable=self.verify_ssl_var)
        self.verify_ssl_check.grid(row=0, column=1, sticky="w", padx=(10, 8))
        self.timeout_spin = ttk.Spinbox(url_row, from_=1, to=600, textvariable=self.timeout_var, width=5)
        self.timeout_spin.grid(row=0, column=2, sticky="w", padx=(0, 4))
        ttk.Label(url_row, text="sec", style="Muted.TLabel").grid(row=0, column=3, sticky="w")

        ttk.Label(frame, text="File Upload", style="Field.TLabel").grid(row=3, column=0, sticky="w", padx=label_padx, pady=6)
        upload_row = ttk.Frame(frame)
        upload_row.grid(row=3, column=1, sticky="ew", padx=field_padx, pady=6)
        upload_row.columnconfigure(0, weight=1)

        self.upload_entry = ttk.Entry(upload_row, textvariable=self.upload_file_var)
        self.upload_entry.grid(row=0, column=0, sticky="ew")
        self.browse_btn = ttk.Button(upload_row, text="Browse...", style="Secondary.TButton", command=self._browse_file, width=11)
        self.browse_btn.grid(row=0, column=1, sticky="w", padx=(10, 18))
        ttk.Label(upload_row, text="Form Field", style="Field.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 8))
        self.file_field_entry = ttk.Entry(upload_row, textvariable=self.file_field_var, width=12)
        self.file_field_entry.grid(row=0, column=3, sticky="w")

        ttk.Label(frame, text="Preset Description", style="Field.TLabel").grid(row=4, column=0, sticky="nw", padx=label_padx, pady=(6, 10))
        self.preset_notes = tk.Text(
            frame,
            height=2,
            wrap="word",
            bg=self.colors["entry_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.colors["border"],
            highlightcolor=self.colors["border"],
            bd=0,
            padx=10,
            pady=7,
            font=("Segoe UI", 10),
            cursor="arrow",
        )
        self.preset_notes.grid(row=4, column=1, sticky="ew", padx=field_padx, pady=(6, 10))
        self.preset_notes.configure(state="disabled")

    def _build_request_editors(self, parent: tk.Misc) -> None:
        frame = ttk.LabelFrame(parent, text="Request", style="Section.TLabelframe")
        frame.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(1, weight=1)

        ttk.Label(frame, text="Headers (JSON)", style="Field.TLabel").grid(row=0, column=0, sticky="w", padx=12, pady=(12, 6))
        ttk.Label(frame, text="Body / Payload (JSON or raw text)", style="Field.TLabel").grid(row=0, column=1, sticky="w", padx=12, pady=(12, 6))

        self.headers_text = self._build_textbox(frame, row=1, column=0)
        self.body_text = self._build_textbox(frame, row=1, column=1)

    def _build_action_bar(self, parent: tk.Misc) -> None:
        bar = ttk.Frame(parent, style="App.TFrame")
        bar.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        bar.columnconfigure(0, weight=1)
        bar.columnconfigure(1, weight=0)

        left = ttk.Frame(bar, style="App.TFrame")
        left.grid(row=0, column=0, sticky="w")
        ttk.Button(left, text="Send Request", style="Action.TButton", command=self.send_request).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(left, text="Clear", style="Secondary.TButton", command=self.clear_form).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(left, text="Copy Response", style="Secondary.TButton", command=self.copy_response).grid(row=0, column=2, padx=(0, 6))

        right = ttk.Frame(bar, style="App.TFrame")
        right.grid(row=0, column=1, sticky="e")
        ttk.Button(right, text="Save HTML Report", style="Secondary.TButton", command=self.save_html_report).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(right, text="Open HTML Report", style="Secondary.TButton", command=self.open_html_report).grid(row=0, column=1)

    def _build_response_section(self, parent: tk.Misc) -> None:
        outer = ttk.LabelFrame(parent, text="Response", style="Section.TLabelframe")
        outer.grid(row=3, column=0, sticky="nsew")
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)

        summary = ttk.Frame(outer, style="App.TFrame")
        summary.grid(row=0, column=0, sticky="ew", padx=10, pady=(14, 10))
        for idx in range(4):
            summary.columnconfigure(idx, weight=1)

        self.status_card = self._build_summary_card(summary, 0, "Status", "Waiting")
        self.time_card = self._build_summary_card(summary, 1, "Time", "—")
        self.type_card = self._build_summary_card(summary, 2, "Type", "—")
        self.size_card = self._build_summary_card(summary, 3, "Size", "—")

        self.status_value = self.status_card[1]
        self.time_value = self.time_card[1]
        self.type_value = self.type_card[1]
        self.size_value = self.size_card[1]

        self.response_notebook = ttk.Notebook(outer)
        self.response_notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        self.body_tab = ttk.Frame(self.response_notebook, style="App.TFrame")
        self.headers_tab = ttk.Frame(self.response_notebook, style="App.TFrame")
        self.raw_tab = ttk.Frame(self.response_notebook, style="App.TFrame")
        self.response_notebook.add(self.body_tab, text="Body")
        self.response_notebook.add(self.headers_tab, text="Headers")
        self.response_notebook.add(self.raw_tab, text="Raw")

        self.response_body_text = self._build_textbox(self.body_tab, row=0, column=0, outer_pad=0)
        self.response_headers_text = self._build_textbox(self.headers_tab, row=0, column=0, outer_pad=0)
        self.response_raw_text = self._build_textbox(self.raw_tab, row=0, column=0, outer_pad=0)

        for tab in (self.body_tab, self.headers_tab, self.raw_tab):
            tab.columnconfigure(0, weight=1)
            tab.rowconfigure(0, weight=1)

    def _build_summary_card(self, parent: tk.Misc, column: int, label: str, value: str) -> tuple[ttk.Frame, ttk.Label]:
        card = ttk.Frame(parent, style="SummaryCard.TFrame")
        card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0))
        card.columnconfigure(0, weight=1)

        ttk.Label(card, text=label, style="SummaryLabel.TLabel").grid(row=0, column=0, sticky="w", padx=12, pady=(10, 2))
        value_label = ttk.Label(card, text=value, style="SummaryValue.TLabel")
        value_label.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 10))
        return card, value_label

    def _build_textbox(self, parent: tk.Misc, row: int, column: int, outer_pad: int = 12) -> tk.Text:
        wrapper = ttk.Frame(parent, style="App.TFrame")
        wrapper.grid(row=row, column=column, sticky="nsew", padx=outer_pad, pady=(0, 8))
        wrapper.columnconfigure(0, weight=1)
        wrapper.rowconfigure(0, weight=1)

        text = tk.Text(
            wrapper,
            wrap="word",
            undo=True,
            height=12,
            bg=self.colors["entry_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.colors["border"],
            highlightcolor=self.colors["border"],
            padx=10,
            pady=8,
            font=("Consolas", 10),
        )
        text.grid(row=0, column=0, sticky="nsew")
        y_scroll = ttk.Scrollbar(wrapper, orient="vertical", command=text.yview)
        y_scroll.grid(row=0, column=1, sticky="ns")
        text.configure(yscrollcommand=y_scroll.set)
        return text

    def _browse_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file to upload")
        if path:
            self.upload_file_var.set(path)

    def _load_preset(self) -> None:
        preset = self.PRESETS.get(self.preset_var.get())
        if not preset:
            return

        self.method_var.set(preset.get("method", "GET"))
        self.url_var.set(preset.get("url", ""))
        self.verify_ssl_var.set(bool(preset.get("verify_ssl", True)))
        self.timeout_var.set(int(preset.get("timeout", 60)))
        self.upload_file_var.set(preset.get("upload_file", ""))
        self.file_field_var.set(preset.get("file_field", "file"))

        self._set_text(self.headers_text, self._pretty_json_or_string(preset.get("headers", "")))
        self._set_text(self.body_text, self._pretty_json_or_string(preset.get("body", "")))

        self.preset_notes.configure(state="normal")
        self._set_text(self.preset_notes, str(preset.get("notes", "")))
        self.preset_notes.configure(state="disabled")
        self.preset_notes.configure(cursor="arrow")
    
    def _sync_httpbin_preset_from_method(self) -> None:
        method = self.method_var.get().strip().upper()
        current_url = self.url_var.get().strip()

        if "httpbin.org" not in current_url:
            return

        preset_map = {
            "GET": "HTTPBin GET Test",
            "POST": "HTTPBin POST JSON",
            "PUT": "HTTPBin PUT Test",
            "PATCH": "HTTPBin PATCH Test",
            "DELETE": "HTTPBin DELETE Test",
            "HEAD": "HTTPBin HEAD Test",
            "OPTIONS": "HTTPBin OPTIONS Test",
        }

        preset_name = preset_map.get(method)
        if preset_name and preset_name in self.PRESETS:
            self.preset_var.set(preset_name)

    def _on_method_changed(self, event=None) -> None:
        method = self.method_var.get().strip().upper()
        current_url = self.url_var.get().strip()

        if "httpbin.org" not in current_url:
            return

        preset_map = {
            "GET": "HTTPBin GET Test",
            "POST": "HTTPBin POST JSON",
            "PUT": "HTTPBin PUT Test",
            "PATCH": "HTTPBin PATCH Test",
            "DELETE": "HTTPBin DELETE Test",
            "HEAD": "HTTPBin HEAD Test",
            "OPTIONS": "HTTPBin OPTIONS Test",
        }

        preset_name = preset_map.get(method)
        if preset_name and preset_name in self.PRESETS:
            self.preset_var.set(preset_name)
            self._load_preset()

    def _set_text(self, widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)

    def _get_text(self, widget: tk.Text) -> str:
        return widget.get("1.0", "end").strip()

    def _pretty_json_or_string(self, value: Any) -> str:
        if isinstance(value, (dict, list)):
            return json.dumps(value, indent=2)
        return "" if value is None else str(value)

    def _safe_parse_json(self, text: str, field_name: str) -> Any:
        text = text.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{field_name} is not valid JSON.\n{exc}") from exc

    def _normalize_headers(self, raw: Any) -> dict[str, str]:
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            raise ValueError("Headers JSON must be an object/dictionary.")
        return {str(k): "" if v is None else str(v) for k, v in raw.items()}

    def _format_bytes(self, size: int | None) -> str:
        if size is None:
            return "—"
        units = ["B", "KB", "MB", "GB"]
        value = float(size)
        for unit in units:
            if value < 1024 or unit == units[-1]:
                return f"{int(value)} {unit}" if unit == "B" else f"{value:.2f} {unit}"
            value /= 1024
        return f"{size} B"

    def _escape_html(self, value: str) -> str:
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def clear_form(self) -> None:
        self.preset_var.set("HTTPBin GET Test")
        self.method_var.set("GET")
        self.url_var.set("")
        self.upload_file_var.set("")
        self.file_field_var.set("file")
        self.verify_ssl_var.set(True)
        self.timeout_var.set(60)

        self._set_text(self.headers_text, "")
        self._set_text(self.body_text, "")
        self._set_text(self.response_body_text, "")
        self._set_text(self.response_headers_text, "")
        self._set_text(self.response_raw_text, "")

        self.preset_notes.configure(state="normal")
        self._set_text(self.preset_notes, "")
        self.preset_notes.configure(state="disabled")

        self._update_response_ui("Waiting", "—", "—", "—", "", "", "", False)

    def copy_response(self) -> None:
        current_tab = self.response_notebook.select()
        widget = {
            str(self.body_tab): self.response_body_text,
            str(self.headers_tab): self.response_headers_text,
            str(self.raw_tab): self.response_raw_text,
        }.get(current_tab, self.response_body_text)

        text = self._get_text(widget)
        if not text:
            messagebox.showinfo("Copy Response", "There is no response content to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)

    def send_request(self) -> None:
        if requests is None:
            messagebox.showerror("Missing Dependency", "The 'requests' package is not installed in this environment.")
            return
        if self._request_thread and self._request_thread.is_alive():
            messagebox.showinfo("Request In Progress", "A request is already running.")
            return

        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Missing URL", "Please enter a URL.")
            return

        try:
            self._normalize_headers(self._safe_parse_json(self._get_text(self.headers_text), "Headers"))
        except ValueError as exc:
            messagebox.showerror("Invalid Input", str(exc))
            return

        self._update_response_ui("Sending...", "—", "—", "—", "", "", "", False)
        self._request_thread = threading.Thread(target=self._request_worker, daemon=True)
        self._request_thread.start()

    def _request_worker(self) -> None:
        file_handle = None
        try:
            method = self.method_var.get().strip().upper()
            url = self.url_var.get().strip()
            timeout = int(self.timeout_var.get() or 60)
            verify_ssl = bool(self.verify_ssl_var.get())

            headers = self._normalize_headers(self._safe_parse_json(self._get_text(self.headers_text), "Headers"))
            body_text = self._get_text(self.body_text)

            json_payload = None
            data_payload = None
            files_payload = None

            if self.upload_file_var.get().strip():
                upload_path = self.upload_file_var.get().strip()
                field_name = self.file_field_var.get().strip() or "file"
                file_handle = open(upload_path, "rb")
                files_payload = {field_name: file_handle}

                if body_text.strip():
                    stripped = body_text.strip()
                    if stripped.startswith("{") or stripped.startswith("["):
                        parsed = self._safe_parse_json(body_text, "Body")
                        data_payload = {str(k): "" if v is None else str(v) for k, v in parsed.items()} if isinstance(parsed, dict) else body_text
                    else:
                        data_payload = body_text
            elif body_text.strip():
                content_type = str(headers.get("Content-Type", "")).lower()
                if "application/json" in content_type:
                    json_payload = self._safe_parse_json(body_text, "Body")
                else:
                    stripped = body_text.strip()
                    if stripped.startswith("{") or stripped.startswith("["):
                        try:
                            json_payload = self._safe_parse_json(body_text, "Body")
                        except ValueError:
                            data_payload = body_text
                    else:
                        data_payload = body_text

            started = time.perf_counter()
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json_payload if files_payload is None else None,
                data=data_payload,
                files=files_payload,
                timeout=timeout,
                verify=verify_ssl,
            )
            elapsed = time.perf_counter() - started

            response_headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
            response_body = "" if method == "HEAD" else response.text
            raw_response = f"HTTP {response.status_code} {response.reason}\n{response_headers}\n\n{response_body}"
            content_type = response.headers.get("Content-Type", "")
            size_text = self._format_bytes(len(response.content) if response.content is not None else 0)

            self.after(0, lambda: self._apply_response_success(
                response.status_code,
                elapsed,
                content_type,
                size_text,
                response_body,
                response_headers,
                raw_response,
            ))
        except Exception as exc:
            self.after(0, lambda: self._apply_response_error(str(exc)))
        finally:
            if file_handle is not None:
                try:
                    file_handle.close()
                except Exception:
                    pass

    def _apply_response_success(self, status_code: int, elapsed: float, content_type: str, size_text: str, body_text: str, headers_text: str, raw_text: str) -> None:
        self._update_response_ui(
            status=str(status_code),
            elapsed=f"{elapsed:.2f}s",
            content_type=content_type or "—",
            size=size_text,
            body=body_text,
            headers=headers_text,
            raw=raw_text,
            ok=True,
        )

    def _apply_response_error(self, message: str) -> None:
        self._update_response_ui(
            status="Error",
            elapsed="—",
            content_type="—",
            size="—",
            body=message,
            headers="",
            raw=message,
            ok=False,
        )

    def _update_response_ui(self, status: str, elapsed: str, content_type: str, size: str, body: str, headers: str, raw: str, ok: bool) -> None:
        self.status_value.configure(text=status)
        self.time_value.configure(text=elapsed)
        self.type_value.configure(text=content_type)
        self.size_value.configure(text=size)
        self._set_text(self.response_body_text, body)
        self._set_text(self.response_headers_text, headers)
        self._set_text(self.response_raw_text, raw)
        self.response_notebook.select(self.body_tab)

    def save_html_report(self) -> None:
        method = self.method_var.get().strip()
        url = self.url_var.get().strip()
        status = self.status_value.cget("text")
        elapsed = self.time_value.cget("text")
        content_type = self.type_value.cget("text")
        size = self.size_value.cget("text")
        headers = self._get_text(self.response_headers_text)
        body = self._get_text(self.response_body_text)
        raw = self._get_text(self.response_raw_text)

        if not body and not raw:
            messagebox.showinfo("Save HTML Report", "There is no response to save yet.")
            return

        path = filedialog.asksaveasfilename(
            title="Save HTML Report",
            defaultextension=".html",
            initialfile="api_test_report.html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
        )
        if not path:
            return

        html = f"""<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<title>RingForge API Test Report</title>
<style>
body {{ background: #05070B; color: #F7FAFF; font-family: \"Segoe UI\", Arial, sans-serif; margin: 24px; }}
.card {{ background: #0B1220; border: 1px solid #294C8E; border-radius: 12px; padding: 16px; margin-bottom: 16px; }}
h1, h2 {{ margin-top: 0; }}
.grid {{ display: grid; grid-template-columns: 140px 1fr; gap: 8px 12px; }}
.label {{ color: #B8C7E6; font-weight: 700; }}
pre {{ white-space: pre-wrap; word-break: break-word; background: #0D1A33; border: 1px solid #294C8E; border-radius: 10px; padding: 12px; overflow-x: auto; }}
</style>
</head>
<body>
<div class=\"card\">
    <h1>RingForge Manual API Tester Report</h1>
    <div class=\"grid\">
        <div class=\"label\">Method</div><div>{self._escape_html(method)}</div>
        <div class=\"label\">URL</div><div>{self._escape_html(url)}</div>
        <div class=\"label\">Status</div><div>{self._escape_html(status)}</div>
        <div class=\"label\">Time</div><div>{self._escape_html(elapsed)}</div>
        <div class=\"label\">Type</div><div>{self._escape_html(content_type)}</div>
        <div class=\"label\">Size</div><div>{self._escape_html(size)}</div>
    </div>
</div>
<div class=\"card\"><h2>Response Body</h2><pre>{self._escape_html(body)}</pre></div>
<div class=\"card\"><h2>Response Headers</h2><pre>{self._escape_html(headers)}</pre></div>
<div class=\"card\"><h2>Raw Output</h2><pre>{self._escape_html(raw)}</pre></div>
</body>
</html>
"""
        out_path = Path(path)
        out_path.write_text(html, encoding="utf-8")
        self.latest_report_path = out_path
        messagebox.showinfo("Save HTML Report", f"Saved report to:\n{out_path}")

    def open_html_report(self) -> None:
        if self.latest_report_path and self.latest_report_path.exists():
            webbrowser.open(self.latest_report_path.resolve().as_uri())
            return
        messagebox.showinfo("Open HTML Report", "No saved HTML report is available yet.")


ApiWindow = APIAnalysisWindow

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    window = APIAnalysisWindow(root)
    window.mainloop()
