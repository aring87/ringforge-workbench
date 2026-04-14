from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import tkinter.scrolledtext as scrolledtext
except Exception:
    scrolledtext = None


class ExtensionAnalysisWindow(tk.Toplevel):
    BG = "#05070B"
    PANEL = "#0B1220"
    PANEL_ALT = "#101A2E"
    PANEL_SOFT = "#0D1730"
    BORDER = "#294C8E"
    BORDER_SOFT = "#1C3566"
    ACCENT = "#2F6BFF"
    ACCENT_HOVER = "#3D7BFF"
    TEXT = "#F7FAFF"
    MUTED = "#9FB0D3"
    SUCCESS = "#22C55E"
    WARNING = "#F59E0B"
    DANGER = "#EF4444"

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.current_file_inventory = []

        self.title("Extension Analysis")
        self.geometry("1280x900+120+80")
        self.minsize(1120, 780)
        self.configure(bg=self.BG)
        self.transient(parent)

        self._temp_dir = None
        self.current_source = None
        self.current_working_dir = None
        self.current_manifest_path = None
        self.current_manifest = None

        self.source_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready")
        self.loaded_name_var = tk.StringVar(value="RingForge Workbench - Extension Analysis")
        self.name_var = tk.StringVar(value="-")
        self.version_var = tk.StringVar(value="-")
        self.description_var = tk.StringVar(value="-")
        self.manifest_version_var = tk.StringVar(value="-")
        self.permissions_var = tk.StringVar(value="-")
        self.host_permissions_var = tk.StringVar(value="-")
        self.background_var = tk.StringVar(value="-")
        self.content_scripts_var = tk.StringVar(value="-")
        self.web_resources_var = tk.StringVar(value="-")
        self.externally_connectable_var = tk.StringVar(value="-")
        self.update_url_var = tk.StringVar(value="-")
        self.csp_var = tk.StringVar(value="-")
        self.commands_var = tk.StringVar(value="-")
        self.risk_score_var = tk.StringVar(value="0")
        self.file_count_var = tk.StringVar(value="0")
        self.risk_verdict_var = tk.StringVar(value="-")

        self.risk_verdict_badge = None
        self.risk_verdict_text = None
        self.score_value_label = None
        self.score_card = None
        self._file_listbox_widget = None

        self._configure_styles()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("App.TFrame", background=self.BG)
        style.configure("Card.TFrame", background=self.PANEL, relief="flat")
        style.configure("App.TLabelframe",
                        background=self.PANEL,
                        foreground=self.TEXT,
                        bordercolor=self.BORDER,
                        lightcolor=self.BORDER,
                        darkcolor=self.BORDER,
                        relief="solid",
                        borderwidth=1)
        style.configure("App.TLabelframe.Label",
                        background=self.PANEL,
                        foreground=self.TEXT,
                        font=("Segoe UI", 10, "bold"))

        style.configure("BannerTitle.TLabel",
                        background=self.PANEL,
                        foreground=self.TEXT,
                        font=("Segoe UI", 16, "bold"))
        style.configure("BannerSub.TLabel",
                        background=self.PANEL,
                        foreground=self.MUTED,
                        font=("Segoe UI", 10))

        style.configure("SectionHeader.TLabel",
                        background=self.BG,
                        foreground=self.ACCENT,
                        font=("Segoe UI", 10, "bold"))

        style.configure("FieldLabel.TLabel",
                        background=self.PANEL,
                        foreground=self.MUTED,
                        font=("Segoe UI", 9, "bold"))
        style.configure("FieldValue.TLabel",
                        background=self.PANEL,
                        foreground=self.TEXT,
                        font=("Segoe UI", 10))
        style.configure("Footer.TLabel",
                        background=self.BG,
                        foreground=self.MUTED,
                        font=("Segoe UI", 9))

        style.configure("Path.TEntry",
                        fieldbackground=self.PANEL_ALT,
                        background=self.PANEL_ALT,
                        foreground=self.TEXT,
                        bordercolor=self.BORDER,
                        lightcolor=self.BORDER,
                        darkcolor=self.BORDER,
                        padding=(8, 7))

        style.configure("Action.TButton",
                        background=self.ACCENT,
                        foreground=self.TEXT,
                        bordercolor=self.ACCENT,
                        focusthickness=0,
                        focuscolor=self.ACCENT,
                        padding=(12, 8),
                        font=("Segoe UI", 10, "bold"))
        style.map("Action.TButton",
                  background=[("active", self.ACCENT_HOVER), ("pressed", self.ACCENT)])

        style.configure("Secondary.TButton",
                        background=self.PANEL_ALT,
                        foreground=self.TEXT,
                        bordercolor=self.BORDER_SOFT,
                        focusthickness=0,
                        focuscolor=self.BORDER_SOFT,
                        padding=(12, 8),
                        font=("Segoe UI", 10, "bold"))
        style.map("Secondary.TButton",
                  background=[("active", "#132346"), ("pressed", "#10203E")])

        style.configure("TNotebook",
                        background=self.BG,
                        borderwidth=0,
                        tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab",
                        background=self.PANEL_ALT,
                        foreground=self.TEXT,
                        padding=(12, 7),
                        font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", self.ACCENT), ("active", "#1B335F")],
                  foreground=[("selected", self.TEXT)])

    def _build_ui(self):
        outer = ttk.Frame(self, style="App.TFrame", padding=10)
        outer.pack(fill="both", expand=True)

        outer.columnconfigure(0, weight=1)

        # Give the workspace more dominance
        outer.rowconfigure(0, weight=0)  # banner
        outer.rowconfigure(1, weight=0)  # source
        outer.rowconfigure(2, weight=0)  # summary
        outer.rowconfigure(3, weight=1)  # workspace
        outer.rowconfigure(4, weight=0)  # footer

        self._build_banner(outer)
        self._build_source_card(outer)
        self._build_summary_card(outer)
        self._build_workspace(outer)
        self._build_footer(outer)

    def _build_banner(self, parent):
        from pathlib import Path
        try:
            from PIL import Image, ImageTk
        except Exception:
            Image = None
            ImageTk = None

        panel_bg = "#0B1220"
        border = "#294C8E"
        accent = "#2F6BFF"
        text_main = "#F7FAFF"
        text_soft = "#B8C7E6"

        banner_wrap = ttk.Frame(parent, style="App.TFrame")
        banner_wrap.grid(row=0, column=0, sticky="ew", pady=(0, 8))
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

        if Image is not None and ImageTk is not None and logo_path.exists():
            try:
                logo_img = Image.open(logo_path).convert("RGBA")
                logo_img = logo_img.resize((96, 96), Image.LANCZOS)
                self._banner_logo_img = ImageTk.PhotoImage(logo_img)

                tk.Label(
                    banner,
                    image=self._banner_logo_img,
                    bg=panel_bg,
                    bd=0,
                    highlightthickness=0,
                ).grid(row=0, column=0, rowspan=3, sticky="w", padx=(16, 18), pady=14)
            except Exception:
                tk.Label(
                    banner,
                    text="RF",
                    bg=panel_bg,
                    fg=accent,
                    font=("Segoe UI", 18, "bold"),
                    bd=0,
                    highlightthickness=0,
                ).grid(row=0, column=0, rowspan=3, sticky="w", padx=(16, 18), pady=14)
        else:
            tk.Label(
                banner,
                text="RF",
                bg=panel_bg,
                fg=accent,
                font=("Segoe UI", 18, "bold"),
                bd=0,
                highlightthickness=0,
            ).grid(row=0, column=0, rowspan=3, sticky="w", padx=(16, 18), pady=14)

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
            text="Extension Analysis",
            bg=panel_bg,
            fg=accent,
            font=("Segoe UI", 18, "bold"),
            anchor="w",
        ).grid(row=1, column=1, sticky="nw")

        tk.Label(
            banner,
            text="Inspect Chrome and Edge extension packages for permissions, scripts, remote access, and risky behaviors.",
            bg=panel_bg,
            fg=text_soft,
            font=("Segoe UI", 10),
            anchor="w",
            justify="left",
            wraplength=980,
        ).grid(row=2, column=1, sticky="w", pady=(4, 16))

    def _build_source_card(self, parent):
        header = ttk.LabelFrame(parent, text="Extension Source", style="App.TLabelframe")
        header.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        header.columnconfigure(0, weight=1)

        top = ttk.Frame(header, style="Card.TFrame")
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 4))
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="Path", style="FieldLabel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(top, textvariable=self.source_var, style="Path.TEntry").grid(row=0, column=1, sticky="ew")

        browse_btns = ttk.Frame(top, style="Card.TFrame")
        browse_btns.grid(row=0, column=2, sticky="e", padx=(10, 0))

        ttk.Button(browse_btns, text="Open Folder", style="Secondary.TButton", command=self._browse_folder).pack(side="left", padx=(0, 4))
        ttk.Button(browse_btns, text="Open ZIP", style="Secondary.TButton", command=self._browse_zip).pack(side="left", padx=(0, 4))
        ttk.Button(browse_btns, text="Open CRX", style="Secondary.TButton", command=self._browse_crx).pack(side="left", padx=(0, 4))
        ttk.Button(browse_btns, text="Analyze", style="Action.TButton", command=self._analyze_selected).pack(side="left")

        bottom = ttk.Frame(header, style="Card.TFrame")
        bottom.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))
        bottom.columnconfigure(0, weight=1)

        save_btns = ttk.Frame(bottom, style="Card.TFrame")
        save_btns.grid(row=0, column=1, sticky="e")

        ttk.Button(save_btns, text="Save JSON", style="Secondary.TButton", command=self._export_json_as).pack(side="left", padx=(0, 4))
        ttk.Button(save_btns, text="Save HTML", style="Secondary.TButton", command=self._export_html_as).pack(side="left", padx=(0, 4))
        ttk.Button(save_btns, text="Open Reports", style="Secondary.TButton", command=self._open_report_folder).pack(side="left")

    def _build_summary_card(self, parent):
        summary = ttk.LabelFrame(parent, text="Summary", style="App.TLabelframe")
        summary.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        summary.columnconfigure(0, weight=7)
        summary.columnconfigure(1, weight=3)

        left = ttk.Frame(summary, style="Card.TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(10, 8), pady=8)
        left.columnconfigure(0, weight=1)
        left.columnconfigure(1, weight=1)

        self._build_details_grid(left)

        right = ttk.Frame(summary, style="Card.TFrame")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 10), pady=8)
        right.columnconfigure(0, weight=1)

        ttk.Label(right, text="Assessment", style="FieldLabel.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 4))

        self.score_card = tk.Frame(
            right,
            bg=self.PANEL_SOFT,
            highlightthickness=1,
            highlightbackground=self.BORDER_SOFT,
            highlightcolor=self.BORDER_SOFT,
            padx=12,
            pady=8,
        )
        self.score_card.grid(row=1, column=0, sticky="ew", pady=(0, 4))
        self.score_card.columnconfigure(0, weight=1)
        self.score_card.columnconfigure(1, weight=1)

        tk.Label(
            self.score_card,
            text="Risk Score",
            bg=self.PANEL_SOFT,
            fg=self.MUTED,
            font=("Segoe UI", 8, "bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        self.score_value_label = tk.Label(
            self.score_card,
            textvariable=self.risk_score_var,
            bg=self.PANEL_SOFT,
            fg=self.TEXT,
            font=("Segoe UI", 20, "bold"),
            anchor="w",
        )
        self.score_value_label.grid(row=1, column=0, sticky="w", pady=(2, 0))

        tk.Label(
            self.score_card,
            text="Files Found",
            bg=self.PANEL_SOFT,
            fg=self.MUTED,
            font=("Segoe UI", 8, "bold"),
            anchor="w",
        ).grid(row=0, column=1, sticky="w")

        tk.Label(
            self.score_card,
            textvariable=self.file_count_var,
            bg=self.PANEL_SOFT,
            fg=self.TEXT,
            font=("Segoe UI", 14, "bold"),
            anchor="w",
        ).grid(row=1, column=1, sticky="w", pady=(5, 0))

        ttk.Label(right, text="Verdict", style="FieldLabel.TLabel").grid(row=2, column=0, sticky="w", pady=(0, 4))

        self.risk_verdict_badge = tk.Frame(
            right,
            bg=self.PANEL_SOFT,
            highlightthickness=1,
            highlightbackground=self.BORDER_SOFT,
            highlightcolor=self.BORDER_SOFT,
            padx=10,
            pady=7,
        )
        self.risk_verdict_badge.grid(row=3, column=0, sticky="ew", pady=(0, 4))

        self.risk_verdict_text = tk.Label(
            self.risk_verdict_badge,
            textvariable=self.risk_verdict_var,
            bg=self.PANEL_SOFT,
            fg=self.TEXT,
            font=("Segoe UI", 11, "bold"),
            anchor="center",
        )
        self.risk_verdict_text.pack(fill="x")

        ttk.Label(right, text="Loaded Extension", style="FieldLabel.TLabel").grid(row=4, column=0, sticky="w", pady=(2, 2))
        ttk.Label(
            right,
            textvariable=self.loaded_name_var,
            style="FieldValue.TLabel",
            wraplength=250,
            justify="left",
        ).grid(row=5, column=0, sticky="ew")
        
        right.rowconfigure(6, weight=1)

    def _build_details_grid(self, parent):
        sections = [
            ("Identity", [
                ("Name", self.name_var),
                ("Version", self.version_var),
                ("Manifest Version", self.manifest_version_var),
                ("Description", self.description_var),
            ]),
            ("Behavior / Exposure", [
                ("Permissions", self.permissions_var),
                ("Host Permissions", self.host_permissions_var),
                ("Background", self.background_var),
                ("Content Scripts", self.content_scripts_var),
                ("Web Resources", self.web_resources_var),
                ("Externally Connectable", self.externally_connectable_var),
                ("Commands", self.commands_var),
                ("CSP", self.csp_var),
            ]),
        ]

        row = 0
        for section_title, fields in sections:
            title = tk.Label(
                parent,
                text=section_title,
                bg=self.PANEL,
                fg=self.ACCENT,
                font=("Segoe UI", 9, "bold"),
                anchor="w",
            )
            title.grid(row=row, column=0, columnspan=2, sticky="w", pady=(0 if row == 0 else 6, 3))
            row += 1

            for i in range(0, len(fields), 2):
                left_field = fields[i]
                right_field = fields[i + 1] if i + 1 < len(fields) else None

                left_card = self._make_field_card(parent, left_field[0], left_field[1])
                left_card.grid(row=row, column=0, sticky="ew", padx=(0, 6), pady=2)

                if right_field:
                    right_card = self._make_field_card(parent, right_field[0], right_field[1])
                    right_card.grid(row=row, column=1, sticky="ew", padx=(6, 0), pady=2)

                row += 1

        full = self._make_field_card(parent, "Update URL", self.update_url_var, compact=True, wraplength=760)
        full.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(4, 0))

        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)
        
    def _make_field_card(self, parent, label_text, variable, compact=False, wraplength=330):
        card = tk.Frame(
            parent,
            bg=self.PANEL_SOFT,
            highlightthickness=1,
            highlightbackground=self.BORDER_SOFT,
            highlightcolor=self.BORDER_SOFT,
            padx=9,
            pady=4 if compact else 5,
        )
        card.columnconfigure(0, weight=1)

        tk.Label(
            card,
            text=label_text,
            bg=self.PANEL_SOFT,
            fg=self.MUTED,
            font=("Segoe UI", 8, "bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        tk.Label(
            card,
            textvariable=variable,
            bg=self.PANEL_SOFT,
            fg=self.TEXT,
            font=("Segoe UI", 9),
            justify="left",
            wraplength=wraplength,
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", pady=(0, 0))

        return card

    def _build_workspace(self, parent):
        workspace = ttk.Frame(parent, style="App.TFrame")
        workspace.grid(row=3, column=0, sticky="nsew")
        workspace.columnconfigure(0, weight=2)
        workspace.columnconfigure(1, weight=6)
        workspace.columnconfigure(2, weight=4)
        workspace.rowconfigure(0, weight=1)

        files_panel = ttk.Frame(workspace, style="App.TFrame")
        files_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        files_panel.columnconfigure(0, weight=1)
        files_panel.rowconfigure(1, weight=1)

        ttk.Label(files_panel, text="File Inventory", style="SectionHeader.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.file_list = self._make_listbox(files_panel)
        self.file_list.grid(row=1, column=0, sticky="nsew")
        self._file_listbox_widget.bind("<<ListboxSelect>>", self._on_file_selected)

        center_panel = ttk.Frame(workspace, style="App.TFrame")
        center_panel.grid(row=0, column=1, sticky="nsew", padx=8)
        center_panel.columnconfigure(0, weight=1)
        center_panel.rowconfigure(1, weight=1)

        ttk.Label(center_panel, text="Preview", style="SectionHeader.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 4))

        notebook = ttk.Notebook(center_panel)
        notebook.grid(row=1, column=0, sticky="nsew")

        preview_tab = ttk.Frame(notebook, style="Card.TFrame")
        preview_tab.columnconfigure(0, weight=1)
        preview_tab.rowconfigure(0, weight=1)

        manifest_tab = ttk.Frame(notebook, style="Card.TFrame")
        manifest_tab.columnconfigure(0, weight=1)
        manifest_tab.rowconfigure(0, weight=1)

        notebook.add(preview_tab, text="File Preview")
        notebook.add(manifest_tab, text="Manifest JSON")

        self.preview_text = self._make_text(preview_tab)
        self.preview_text.grid(row=0, column=0, sticky="nsew")
        self._set_text(self.preview_text, "Select a file on the left to preview its contents.")

        self.manifest_text = self._make_text(manifest_tab)
        self.manifest_text.grid(row=0, column=0, sticky="nsew")
        self._set_text(self.manifest_text, "Manifest contents will appear here after loading an extension.")

        notes_panel = ttk.Frame(workspace, style="App.TFrame")
        notes_panel.grid(row=0, column=2, sticky="nsew", padx=(8, 0))
        notes_panel.columnconfigure(0, weight=1)
        notes_panel.rowconfigure(1, weight=1)

        ttk.Label(notes_panel, text="Findings", style="SectionHeader.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.risk_text = self._make_text(notes_panel)
        self.risk_text.grid(row=1, column=0, sticky="nsew")
        self._set_text(self.risk_text, "Findings and risk notes will appear here after analysis.")

    def _build_footer(self, parent):
        footer = ttk.Frame(parent, style="App.TFrame")
        footer.grid(row=4, column=0, sticky="ew", pady=(4, 0))
        footer.columnconfigure(0, weight=1)
        footer.columnconfigure(1, weight=0)
        footer.columnconfigure(2, weight=0)

        ttk.Label(footer, textvariable=self.status_var, style="Footer.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(footer, textvariable=self.loaded_name_var, style="Footer.TLabel").grid(row=0, column=1, sticky="e", padx=(12, 12))
        ttk.Label(footer, textvariable=self.risk_verdict_var, style="Footer.TLabel").grid(row=0, column=2, sticky="e")

    def _make_listbox(self, parent):
        frame = tk.Frame(
            parent,
            bg=self.PANEL,
            highlightthickness=1,
            highlightbackground=self.BORDER_SOFT,
            highlightcolor=self.BORDER_SOFT,
        )
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        listbox = tk.Listbox(
            frame,
            bg=self.PANEL,
            fg=self.TEXT,
            selectbackground="#183A7A",
            selectforeground=self.TEXT,
            relief="flat",
            borderwidth=0,
            font=("Consolas", 10),
            width=36,
            activestyle="none",
        )

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)

        listbox.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        self._file_listbox_widget = listbox
        self._set_file_list(["No files loaded yet."])
        return frame

    def _make_text(self, parent):
        common_kwargs = {
            "wrap": "word",
            "height": 18,
            "bg": self.PANEL,
            "fg": self.TEXT,
            "insertbackground": self.TEXT,
            "relief": "flat",
            "borderwidth": 0,
            "padx": 10,
            "pady": 10,
            "font": ("Consolas", 10),
        }

        if scrolledtext is not None:
            return scrolledtext.ScrolledText(parent, **common_kwargs)
        return tk.Text(parent, **common_kwargs)

    def _set_text(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _set_file_list(self, items):
        lb = self._file_listbox_widget
        if lb is None:
            return
        lb.delete(0, "end")
        for item in items:
            lb.insert("end", item)

    def _browse_folder(self):
        path = filedialog.askdirectory(title="Select unpacked extension folder", parent=self)
        if path:
            self.source_var.set(path)
        self._bring_to_front()

    def _browse_zip(self):
        path = filedialog.askopenfilename(
            title="Select extension ZIP",
            filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")],
            parent=self,
        )
        if path:
            self.source_var.set(path)
        self._bring_to_front()

    def _browse_crx(self):
        path = filedialog.askopenfilename(
            title="Select extension CRX",
            filetypes=[("CRX files", "*.crx"), ("All files", "*.*")],
            parent=self,
        )
        if path:
            self.source_var.set(path)
        self._bring_to_front()

    def _analyze_selected(self):
        source = self.source_var.get().strip()
        if not source:
            messagebox.showwarning("Extension Analysis", "Select a folder, ZIP, or CRX first.")
            return

        source_path = Path(source)
        if not source_path.exists():
            messagebox.showerror("Extension Analysis", f"Path not found:\n{source_path}")
            return

        try:
            self._cleanup_temp()

            if source_path.is_dir():
                working_dir = source_path
            else:
                suffix = source_path.suffix.lower()
                if suffix == ".zip":
                    working_dir = self._extract_zip(source_path)
                elif suffix == ".crx":
                    working_dir = self._extract_crx(source_path)
                else:
                    raise ValueError("Unsupported file type. Use a folder, .zip, or .crx")

            manifest_path = self._find_manifest(working_dir)
            if manifest_path is None:
                raise FileNotFoundError("manifest.json was not found in the selected extension source.")

            with manifest_path.open("r", encoding="utf-8") as f:
                manifest = json.load(f)

            self.current_source = source_path
            self.current_working_dir = working_dir
            self.current_manifest_path = manifest_path
            self.current_manifest = manifest

            self.risk_score_var.set("0")
            self.risk_verdict_var.set("-")
            self.file_count_var.set("0")
            self.loaded_name_var.set(source_path.name)

            self._set_text(self.preview_text, "Select a file on the left to preview its contents.")
            self._set_text(self.risk_text, "Findings and risk notes will appear here after analysis.")
            self._set_text(self.manifest_text, "Manifest contents will appear here after loading an extension.")

            self._populate_summary(manifest)
            self._populate_file_inventory(working_dir)
            self._populate_risk_notes(manifest, working_dir)
            self._populate_manifest_text(manifest)

            self.status_var.set(f"Analyzed: {source_path}")
            self._bring_to_front()
        except Exception as e:
            messagebox.showerror("Extension Analysis", f"Analysis failed:\n{e}")
            self.status_var.set("Analysis failed")
            self._bring_to_front()

    def _extract_zip(self, zip_path: Path) -> Path:
        temp_dir = Path(tempfile.mkdtemp(prefix="ringforge_ext_"))
        self._temp_dir = temp_dir
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(temp_dir)
        return temp_dir

    def _extract_crx(self, crx_path: Path) -> Path:
        temp_dir = Path(tempfile.mkdtemp(prefix="ringforge_ext_"))
        self._temp_dir = temp_dir

        data = crx_path.read_bytes()
        if len(data) < 16 or data[:4] != b"Cr24":
            raise ValueError("Invalid CRX file header.")

        version = int.from_bytes(data[4:8], "little")

        if version == 2:
            pub_len = int.from_bytes(data[8:12], "little")
            sig_len = int.from_bytes(data[12:16], "little")
            zip_start = 16 + pub_len + sig_len
        elif version == 3:
            header_len = int.from_bytes(data[8:12], "little")
            zip_start = 12 + header_len
        else:
            raise ValueError(f"Unsupported CRX version: {version}")

        zip_bytes = data[zip_start:]
        zip_path = temp_dir / "extension.zip"
        zip_path.write_bytes(zip_bytes)

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(temp_dir)

        return temp_dir

    def _find_manifest(self, root: Path):
        direct = root / "manifest.json"
        if direct.exists():
            return direct
        for path in root.rglob("manifest.json"):
            return path
        return None

    def _populate_summary(self, manifest: dict):
        name = manifest.get("name", "-")
        version = manifest.get("version", "-")
        description = manifest.get("description", "-")
        manifest_version = manifest.get("manifest_version", "-")

        permissions = manifest.get("permissions", [])
        host_permissions = manifest.get("host_permissions", [])
        background = manifest.get("background", {})
        content_scripts = manifest.get("content_scripts", [])
        web_resources = manifest.get("web_accessible_resources", [])
        externally_connectable = manifest.get("externally_connectable", None)
        update_url = manifest.get("update_url", "-")
        commands = manifest.get("commands", {})
        csp = manifest.get("content_security_policy", "-")

        self.name_var.set(str(name))
        self.version_var.set(str(version))
        self.description_var.set(str(description))
        self.manifest_version_var.set(str(manifest_version))
        self.permissions_var.set(self._summarize_list(permissions))
        self.host_permissions_var.set(self._summarize_list(host_permissions))
        self.background_var.set(self._summarize_background(background))
        self.content_scripts_var.set(self._summarize_content_scripts(content_scripts))
        self.web_resources_var.set(self._summarize_web_resources(web_resources))
        self.externally_connectable_var.set("Present" if externally_connectable else "Not set")
        self.update_url_var.set(str(update_url))
        self.commands_var.set(", ".join(commands.keys()) if isinstance(commands, dict) and commands else "-")
        self.csp_var.set(self._summarize_csp(csp))
        self.loaded_name_var.set(str(name) if str(name).strip() else "Unnamed extension")

    def _populate_file_inventory(self, working_dir: Path):
        files = []
        for path in sorted(working_dir.rglob("*")):
            if path.is_file():
                try:
                    rel = path.relative_to(working_dir).as_posix()
                except Exception:
                    rel = path.name
                files.append(rel)

        def sort_key(name: str):
            lower = name.lower()
            priority = 99
            if lower == "manifest.json":
                priority = 0
            elif lower.endswith(".js"):
                priority = 1
            elif lower.endswith(".html") or lower.endswith(".htm"):
                priority = 2
            elif lower.endswith(".json"):
                priority = 3
            return (priority, lower)

        files = sorted(files, key=sort_key)
        self.current_file_inventory = files
        self.file_count_var.set(str(len(files)))
        self._set_file_list(files if files else ["No files loaded yet."])

        lb = self._file_listbox_widget
        if lb is not None and files:
            try:
                default_index = 0
                for i, name in enumerate(files):
                    if name.lower() == "manifest.json":
                        default_index = i
                        break
                lb.selection_clear(0, "end")
                lb.selection_set(default_index)
                lb.activate(default_index)
                self._preview_file(files[default_index])
            except Exception:
                pass

    def _populate_manifest_text(self, manifest: dict):
        pretty = json.dumps(manifest, indent=2, ensure_ascii=False)
        self._set_text(self.manifest_text, pretty)

    def _populate_risk_notes(self, manifest: dict, working_dir: Path):
        notes = []
        score = 0

        permissions = manifest.get("permissions", []) or []
        host_permissions = manifest.get("host_permissions", []) or []
        background = manifest.get("background", {}) or {}
        externally_connectable = manifest.get("externally_connectable")
        update_url = manifest.get("update_url")
        content_scripts = manifest.get("content_scripts", []) or []
        web_resources = manifest.get("web_accessible_resources", []) or []

        high_risk_perms = {
            "tabs", "cookies", "history", "webRequest", "webRequestBlocking",
            "debugger", "downloads", "nativeMessaging", "management", "proxy",
            "scripting", "declarativeNetRequest", "declarativeNetRequestWithHostAccess",
            "clipboardRead", "clipboardWrite", "desktopCapture",
        }

        found_high = sorted([p for p in permissions if p in high_risk_perms])
        if found_high:
            notes.append(f"- Elevated/sensitive permissions present: {', '.join(found_high)}")
            score += min(len(found_high) * 2, 10)

        if "<all_urls>" in host_permissions:
            notes.append("- Host permissions include <all_urls>, which is broad access across websites.")
            score += 4

        if any(isinstance(item, str) and "://" in item and "*" in item for item in host_permissions):
            notes.append("- Host permissions include wildcard URL patterns.")
            score += 2

        if background:
            notes.append("- Background execution is enabled via background page or service worker.")
            score += 1

        if content_scripts:
            notes.append("- Content scripts are present and can interact with page content.")
            score += 2

        if web_resources:
            notes.append("- Web-accessible resources are exposed to web pages or other extension contexts.")
            score += 1

        if externally_connectable:
            notes.append("- externally_connectable is configured, allowing outside pages or apps to communicate with the extension.")
            score += 2

        if update_url:
            notes.append("- update_url is defined. Review whether updates are expected from a trusted source.")
            score += 1

        csp = manifest.get("content_security_policy")
        if isinstance(csp, str) and "unsafe-eval" in csp:
            notes.append("- CSP contains unsafe-eval.")
            score += 3
        elif isinstance(csp, dict):
            csp_text = json.dumps(csp)
            if "unsafe-eval" in csp_text:
                notes.append("- CSP contains unsafe-eval.")
                score += 3

        code_hits, code_score = self._scan_source_files(working_dir)
        notes.extend(code_hits)
        score += code_score

        if not notes:
            notes.append("- No obvious high-risk indicators were found from the manifest or quick file scan.")
            notes.append("- This does not prove the extension is safe; it only means no obvious red flags were identified in this pass.")

        self.risk_score_var.set(str(score))
        verdict = self._get_risk_verdict(score)
        self.risk_verdict_var.set(verdict)
        self._update_risk_visuals(verdict)
        self._set_text(self.risk_text, "\n".join(notes))

    def _scan_source_files(self, working_dir: Path):
        notes = []
        score = 0

        patterns = [
            ("eval(", "Use of eval() found", 3),
            ("new Function(", "Use of new Function() found", 3),
            ("XMLHttpRequest", "Use of XMLHttpRequest found", 1),
            ("fetch(", "Use of fetch() found", 1),
            ("document.cookie", "Access to document.cookie found", 3),
            ("chrome.cookies", "Use of chrome.cookies API found", 3),
            ("chrome.tabs", "Use of chrome.tabs API found", 1),
            ("chrome.scripting", "Use of chrome.scripting API found", 2),
            ("chrome.webRequest", "Use of chrome.webRequest API found", 3),
            ("chrome.runtime.sendMessage", "Runtime messaging found", 1),
            ("http://", "Plain HTTP URL found", 4),
            ("https://", "Remote HTTPS URL found", 1),
        ]

        matched_messages = set()

        for path in working_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".js", ".html", ".json", ".htm"}:
                continue

            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            rel = path.relative_to(working_dir).as_posix()

            for needle, message, value in patterns:
                if needle in text:
                    key = f"{message}::{rel}"
                    if key not in matched_messages:
                        matched_messages.add(key)
                        notes.append(f"- {message}: {rel}")
                        score += value

        return notes, score

    def _preview_file(self, relative_path: str):
        if not self.current_working_dir:
            return

        file_path = self.current_working_dir / relative_path
        if not file_path.exists() or not file_path.is_file():
            self._set_text(self.preview_text, f"File not found:\n{relative_path}")
            return

        preview = self._read_file_preview(file_path)
        header = f"File: {relative_path}\n{'=' * 80}\n"
        self._set_text(self.preview_text, header + preview)

    def _read_file_preview(self, file_path: Path, max_chars: int = 12000):
        ext = file_path.suffix.lower()
        text_like = {
            ".js", ".json", ".html", ".htm", ".css", ".txt", ".md", ".xml",
            ".yml", ".yaml", ".csv"
        }

        if ext not in text_like:
            return f"[Preview not shown]\nBinary or unsupported file type: {file_path.name}"

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            return f"[Could not read file]\n{e}"

        if not content.strip():
            return "[Empty file]"

        if len(content) > max_chars:
            return content[:max_chars] + "\n\n[Preview truncated]"
        return content

    def _on_file_selected(self, event=None):
        lb = self._file_listbox_widget
        if lb is None:
            return

        selection = lb.curselection()
        if not selection:
            return

        selected_rel = lb.get(selection[0])
        if selected_rel == "No files loaded yet.":
            return

        self._preview_file(selected_rel)

    def _build_export_data(self):
        manifest_text = ""
        risk_notes_text = ""
        preview_text = ""

        try:
            manifest_text = self.manifest_text.get("1.0", "end").strip()
        except Exception:
            pass

        try:
            risk_notes_text = self.risk_text.get("1.0", "end").strip()
        except Exception:
            pass

        try:
            preview_text = self.preview_text.get("1.0", "end").strip()
        except Exception:
            pass

        return {
            "source_path": str(self.current_source) if self.current_source else "",
            "working_directory": str(self.current_working_dir) if self.current_working_dir else "",
            "manifest_path": str(self.current_manifest_path) if self.current_manifest_path else "",
            "summary": {
                "name": self.name_var.get(),
                "version": self.version_var.get(),
                "description": self.description_var.get(),
                "manifest_version": self.manifest_version_var.get(),
                "permissions": self.permissions_var.get(),
                "host_permissions": self.host_permissions_var.get(),
                "background": self.background_var.get(),
                "content_scripts": self.content_scripts_var.get(),
                "web_resources": self.web_resources_var.get(),
                "externally_connectable": self.externally_connectable_var.get(),
                "update_url": self.update_url_var.get(),
                "commands": self.commands_var.get(),
                "csp": self.csp_var.get(),
                "risk_score": self.risk_score_var.get(),
                "risk_verdict": self.risk_verdict_var.get(),
                "files_found": self.file_count_var.get(),
            },
            "risk_notes": risk_notes_text.splitlines() if risk_notes_text else [],
            "file_inventory": list(self.current_file_inventory or []),
            "manifest": self.current_manifest if isinstance(self.current_manifest, dict) else {},
            "preview_text": preview_text,
            "manifest_text": manifest_text,
        }

    def _export_json_as(self):
        if not self.current_manifest:
            messagebox.showwarning("Save JSON", "Analyze an extension first.")
            return

        default_name = f"{self._get_report_basename()}_extension_analysis.json"
        path = filedialog.asksaveasfilename(
            title="Save Extension Analysis JSON",
            defaultextension=".json",
            initialfile=default_name,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=str(self._get_report_dir()),
            parent=self,
        )
        if not path:
            return

        try:
            data = self._build_export_data()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.status_var.set(f"Saved JSON: {path}")
            self._bring_to_front()
        except Exception as e:
            messagebox.showerror("Save JSON", f"Could not save JSON:\n{e}")
            self._bring_to_front()

    def _quick_export_json(self):
        if not self.current_manifest:
            messagebox.showwarning("Save JSON", "Analyze an extension first.")
            return

        path = self._get_report_dir() / f"{self._get_report_basename()}_extension_analysis.json"

        try:
            data = self._build_export_data()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.status_var.set(f"Saved JSON: {path}")
            self._bring_to_front()
        except Exception as e:
            messagebox.showerror("Save JSON", f"Could not save JSON:\n{e}")
            self._bring_to_front()

    def _export_html_as(self):
        if not self.current_manifest:
            messagebox.showwarning("Save HTML", "Analyze an extension first.")
            return

        default_name = f"{self._get_report_basename()}_extension_analysis.html"
        path = filedialog.asksaveasfilename(
            title="Save Extension Analysis HTML",
            defaultextension=".html",
            initialfile=default_name,
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialdir=str(self._get_report_dir()),
            parent=self,
        )
        if not path:
            return

        try:
            data = self._build_export_data()
            html_text = self._build_html_report(data)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_text)
            self.status_var.set(f"Saved HTML: {path}")
            self._bring_to_front()
        except Exception as e:
            messagebox.showerror("Save HTML", f"Could not save HTML:\n{e}")
            self._bring_to_front()

    def _quick_export_html(self):
        if not self.current_manifest:
            messagebox.showwarning("Save HTML", "Analyze an extension first.")
            return

        path = self._get_report_dir() / f"{self._get_report_basename()}_extension_analysis.html"

        try:
            data = self._build_export_data()
            html_text = self._build_html_report(data)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_text)
            self.status_var.set(f"Saved HTML: {path}")
            self._bring_to_front()
        except Exception as e:
            messagebox.showerror("Save HTML", f"Could not save HTML:\n{e}")
            self._bring_to_front()

    def _build_html_report(self, data: dict) -> str:
        import html

        summary = data.get("summary", {}) or {}
        risk_notes = data.get("risk_notes", []) or []
        file_inventory = data.get("file_inventory", []) or []
        manifest = data.get("manifest", {}) or {}

        def esc(value):
            return html.escape("" if value is None else str(value))

        verdict = str(summary.get("risk_verdict", "-")).strip().upper()
        verdict_class = "sev-none"
        if verdict == "HIGH":
            verdict_class = "sev-high"
        elif verdict == "MEDIUM":
            verdict_class = "sev-med"
        elif verdict == "LOW":
            verdict_class = "sev-low"

        def list_section(title: str, items: list[str], emphasize: bool = False) -> str:
            section_class = "card card-alert" if emphasize and items else "card"
            body = "<p class='muted'>None</p>" if not items else "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in items) + "</ul>"
            return f"""
            <section class="{section_class}">
              <div class="section-head">
                <h2>{esc(title)}</h2>
                <span class="badge sev-low">Count: {len(items)}</span>
              </div>
              {body}
            </section>
            """

        def kv_table(title: str, rows: dict[str, object], badge_fragment: str = "") -> str:
            rendered = "".join(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in rows.items())
            return f"""
            <section class="card">
              <div class="section-head">
                <h2>{esc(title)}</h2>
                {badge_fragment}
              </div>
              <table class="kv">{rendered}</table>
            </section>
            """

        tile_html = f"""
        <section class="tile-grid">
          <div class="tile"><div class="tile-label">Risk Verdict</div><div class="tile-value">{esc(summary.get("risk_verdict", "-"))}</div></div>
          <div class="tile"><div class="tile-label">Risk Score</div><div class="tile-value">{esc(summary.get("risk_score", "0"))}</div></div>
          <div class="tile"><div class="tile-label">Files Found</div><div class="tile-value">{esc(summary.get("files_found", "0"))}</div></div>
          <div class="tile"><div class="tile-label">Manifest Version</div><div class="tile-value">{esc(summary.get("manifest_version", "-"))}</div></div>
          <div class="tile"><div class="tile-label">Permissions</div><div class="tile-value">{esc(summary.get("permissions", "-"))}</div></div>
          <div class="tile"><div class="tile-label">Host Permissions</div><div class="tile-value">{esc(summary.get("host_permissions", "-"))}</div></div>
        </section>
        """

        summary_rows = {
            "Name": summary.get("name", ""),
            "Version": summary.get("version", ""),
            "Description": summary.get("description", ""),
            "Manifest Version": summary.get("manifest_version", ""),
            "Permissions": summary.get("permissions", ""),
            "Host Permissions": summary.get("host_permissions", ""),
            "Background": summary.get("background", ""),
            "Content Scripts": summary.get("content_scripts", ""),
            "Web Resources": summary.get("web_resources", ""),
            "Externally Connectable": summary.get("externally_connectable", ""),
            "Update URL": summary.get("update_url", ""),
            "Commands": summary.get("commands", ""),
            "CSP": summary.get("csp", ""),
        }

        source_rows = {
            "Source Path": data.get("source_path", ""),
            "Working Directory": data.get("working_directory", ""),
            "Manifest Path": data.get("manifest_path", ""),
        }

        manifest_pre = html.escape(json.dumps(manifest, indent=2, ensure_ascii=False))
        file_items = [str(x) for x in file_inventory]
        risk_items = [str(x) for x in risk_notes]

        body_html = f"""
    {tile_html}
    <div class="grid">
      {kv_table("Extension Source", source_rows)}
      {kv_table("Extension Summary", summary_rows, f'<span class="badge {verdict_class}">Verdict: {esc(summary.get("risk_verdict", "-"))}</span>')}
    </div>
    {list_section("Risk Notes", risk_items, emphasize=True)}
    {list_section("File Inventory", file_items)}
    <section class="card">
      <div class="section-head">
        <h2>Manifest JSON</h2>
        <span class="badge sev-low">Entries: {len(manifest) if isinstance(manifest, dict) else 0}</span>
      </div>
      <pre>{manifest_pre}</pre>
    </section>
    """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Browser Extension Analysis Report</title>
<style>
:root {{
  --bg: #0A0A0A;
  --panel: #101726;
  --border: #22314F;
  --text: #F3F6FB;
  --muted: #A9B7D0;
  --blue: #6EA8FF;
  --shadow: 0 10px 30px rgba(0,0,0,0.35);
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
  max-width: 1280px;
  margin: 0 auto;
}}
h1 {{
  margin: 0 0 8px 0;
  font-size: 32px;
  color: var(--blue);
}}
h2 {{
  margin: 0;
  font-size: 18px;
  color: #bfdbfe;
}}
.subtitle {{
  color: var(--muted);
  margin-top: 6px;
  font-size: 14px;
}}
.banner {{
  background: linear-gradient(135deg, #0A0A0A, #0F1C3F 45%, #1E4ED8 100%);
  border: 1px solid #22314F;
  border-radius: 18px;
  padding: 22px;
  margin-bottom: 20px;
  box-shadow: var(--shadow);
}}
.verdict {{
  display: inline-block;
  margin-top: 14px;
  padding: 8px 12px;
  border-radius: 999px;
  font-weight: 600;
  border: 1px solid transparent;
}}
.grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 18px;
}}
.tile-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 18px;
}}
.tile {{
  background: var(--panel);
  border: 1px solid #22314F;
  border-radius: 14px;
  padding: 14px;
  box-shadow: var(--shadow);
}}
.tile-label {{
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  margin-bottom: 6px;
}}
.tile-value {{
  font-size: 24px;
  font-weight: 700;
  color: var(--text);
}}
.card {{
  background: var(--panel);
  border: 1px solid #22314F;
  border-radius: 14px;
  padding: 18px;
  margin-bottom: 18px;
  box-shadow: var(--shadow);
}}
.card-alert {{
  border-color: rgba(245, 158, 11, 0.55);
  box-shadow: 0 10px 30px rgba(245, 158, 11, 0.08);
}}
.section-head {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}}
table {{
  width: 100%;
  border-collapse: collapse;
}}
th, td {{
  text-align: left;
  padding: 9px 10px;
  border-bottom: 1px solid #22314F;
  vertical-align: top;
  word-break: break-word;
  font-size: 14px;
}}
th {{
  color: #cbd5e1;
  width: 35%;
  background: rgba(255,255,255,0.01);
}}
.kv th {{
  width: 42%;
}}
.muted {{
  color: var(--muted);
}}
ul {{
  margin: 0;
  padding-left: 20px;
}}
li {{
  margin-bottom: 6px;
}}
.badge {{
  display: inline-block;
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  border: 1px solid transparent;
  white-space: nowrap;
}}
.sev-none {{
  background: rgba(16,185,129,0.12);
  color: #a7f3d0;
  border-color: rgba(16,185,129,0.35);
}}
.sev-low {{
  background: rgba(59,130,246,0.12);
  color: #bfdbfe;
  border-color: rgba(59,130,246,0.35);
}}
.sev-med {{
  background: rgba(245,158,11,0.12);
  color: #fde68a;
  border-color: rgba(245,158,11,0.35);
}}
.sev-high {{
  background: rgba(239,68,68,0.12);
  color: #fecaca;
  border-color: rgba(239,68,68,0.35);
}}
pre {{
  margin: 0;
  padding: 14px;
  background: #08101D;
  border: 1px solid #22314F;
  color: var(--text);
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: Consolas, "Courier New", monospace;
  font-size: 13px;
  line-height: 1.4;
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
    <h1>Browser Extension Analysis Report</h1>
    <div class="subtitle">Generated by RingForge Workbench</div>
    <div class="verdict {verdict_class}">{esc(summary.get("risk_verdict", "-"))}</div>
  </div>
  {body_html}
  <div class="footer">Generated by RingForge Workbench • Browser Extension Analysis</div>
</div>
</body>
</html>"""

    def _get_report_dir(self) -> Path:
        base = None
        if self.current_source:
            source_path = Path(self.current_source)
            base = source_path if source_path.is_dir() else source_path.parent
        if base is None and self.current_working_dir:
            base = Path(self.current_working_dir)
        if base is None:
            base = Path.cwd()

        report_dir = base / "ringforge_extension_reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        return report_dir

    def _get_report_basename(self) -> str:
        if self.current_source:
            name = Path(self.current_source).stem
        elif self.name_var.get().strip() and self.name_var.get().strip() != "-":
            name = self.name_var.get().strip()
        else:
            name = "extension_analysis"

        safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in name)
        return safe.strip("_") or "extension_analysis"

    def _open_report_folder(self):
        report_dir = self._get_report_dir()
        try:
            import os
            if os.name == "nt":
                os.startfile(str(report_dir))
            else:
                messagebox.showinfo("Open Reports", f"Report folder:\n{report_dir}")
            self.status_var.set(f"Opened report folder: {report_dir}")
        except Exception as e:
            messagebox.showerror("Open Reports", f"Could not open report folder:\n{e}")

    def _get_risk_verdict(self, score: int) -> str:
        if score >= 7:
            return "High"
        if score >= 3:
            return "Medium"
        return "Low"

    def _update_risk_visuals(self, verdict: str):
        verdict_l = (verdict or "").strip().lower()

        badge_bg = self.PANEL_SOFT
        badge_border = self.BORDER_SOFT
        text_color = self.TEXT

        if verdict_l == "high":
            badge_bg = "#3A1218"
            badge_border = self.DANGER
            text_color = "#FECACA"
        elif verdict_l == "medium":
            badge_bg = "#3A2A0C"
            badge_border = self.WARNING
            text_color = "#FDE68A"
        elif verdict_l == "low":
            badge_bg = "#13301C"
            badge_border = self.SUCCESS
            text_color = "#BBF7D0"

        if self.risk_verdict_badge is not None:
            self.risk_verdict_badge.configure(
                bg=badge_bg,
                highlightbackground=badge_border,
                highlightcolor=badge_border,
            )

        if self.risk_verdict_text is not None:
            self.risk_verdict_text.configure(bg=badge_bg, fg=text_color)

        if self.score_value_label is not None:
            self.score_value_label.configure(fg=text_color if verdict_l in {"high", "medium", "low"} else self.TEXT)

        if self.score_card is not None:
            self.score_card.configure(
                bg=self.PANEL_SOFT,
                highlightbackground=self.BORDER_SOFT,
                highlightcolor=self.BORDER_SOFT,
            )

    def _bring_to_front(self):
        try:
            self.lift()
            self.focus_force()
            self.after(50, self.lift)
        except Exception:
            pass

    def _summarize_list(self, value):
        if not value:
            return "-"
        if isinstance(value, list):
            return ", ".join(str(x) for x in value[:8]) + (" ..." if len(value) > 8 else "")
        return str(value)

    def _summarize_background(self, background):
        if not background:
            return "-"
        if isinstance(background, dict):
            service_worker = background.get("service_worker")
            page = background.get("page")
            scripts = background.get("scripts")
            if service_worker:
                return f"service_worker: {service_worker}"
            if page:
                return f"page: {page}"
            if scripts:
                return f"scripts: {', '.join(scripts)}"
        return str(background)

    def _summarize_content_scripts(self, content_scripts):
        if not content_scripts:
            return "-"
        if isinstance(content_scripts, list):
            return f"{len(content_scripts)} entry(s)"
        return str(content_scripts)

    def _summarize_web_resources(self, web_resources):
        if not web_resources:
            return "-"
        if isinstance(web_resources, list):
            return f"{len(web_resources)} entry(s)"
        return str(web_resources)

    def _summarize_csp(self, csp):
        if not csp:
            return "-"
        if isinstance(csp, dict):
            return json.dumps(csp, ensure_ascii=False)
        return str(csp)

    def _cleanup_temp(self):
        if self._temp_dir and self._temp_dir.exists():
            try:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
            except Exception:
                pass
        self._temp_dir = None

    def _on_close(self):
        self._cleanup_temp()
        self.destroy()