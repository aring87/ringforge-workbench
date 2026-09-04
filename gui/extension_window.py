from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from static_triage_engine.extension_analysis import analyze_extension
from static_triage_engine.extension_report import build_extension_report
from gui import theme as T
from gui.components import Card, HeaderBar, RoundedButton, ScrolledText, StatTile, card_title
from gui.styles import apply_window_theme

try:
    import tkinter.scrolledtext as scrolledtext
except Exception:
    scrolledtext = None


class ExtensionAnalysisWindow(tk.Toplevel):
    # Aliases onto the shared design tokens. They stay as class attributes
    # because the plain Tk widgets in this window reference them directly.
    BG = T.BG
    PANEL = T.SURFACE
    PANEL_ALT = T.RAISED
    PANEL_SOFT = T.BG_ALT
    BORDER = T.BORDER
    BORDER_SOFT = T.BORDER_MUTED
    ACCENT = T.ACCENT
    ACCENT_HOVER = T.ACCENT_HOVER
    TEXT = T.TEXT
    MUTED = T.TEXT_MUTED
    SUCCESS = T.SUCCESS
    WARNING = T.WARNING
    DANGER = T.DANGER

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.current_file_inventory = []

        self.title("Browser Extension Analysis")
        self.geometry("1500x1050+80+40")
        self.minsize(1350, 940)
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
        # The model's own band, kept beside the sentence rather than re-read
        # out of it. `risk_verdict` is written for a reader and its wording
        # follows the domain; anything that needs to *act* on the result -- the
        # report's verdict chip, the case summary -- reads this.
        self.risk_severity_var = tk.StringVar(value="")

        self.risk_verdict_badge = None
        self.risk_verdict_text = None
        self.score_value_label = None
        self.score_card = None
        self._file_listbox_widget = None
        
        self.preview_text = None
        self.manifest_text = None
        self.risk_text = None

        self._configure_styles()
        self._build_ui()

        self.update_idletasks()
        self._autosize_to_screen()
        self.lift()
        self.focus_force()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_styles(self):
        # One shared theme for the whole workbench; see gui/styles.py.
        apply_window_theme(self)

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

    def _build_banner(self, parent) -> None:
        """Branded page header, shared with every other workbench window."""
        logo_path = Path(__file__).resolve().parents[1] / "assets" / "anvil.png"

        header = HeaderBar(
            parent,
            "RingForge",
            subtitle="Browser Extension Analysis",
            description=(
                "Inspect Chrome and Edge extension packages for permissions, "
                "scripts, remote access, and risky behaviors."
            ),
            logo_path=logo_path if logo_path.exists() else None,
            logo_size=72,
            parent_bg=T.BG,
        )
        header.grid(row=0, column=0, sticky="ew", pady=(0, T.SPACE_MD))
        self._banner_logo_img = getattr(header, "_logo_image", None)

    def _build_source_card(self, parent):
        header_card = Card(parent, parent_bg=T.BG)
        header_card.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        card_title(header_card.body, "Extension Source")
        header = tk.Frame(header_card.body, bg=T.SURFACE)
        header.pack(fill="both", expand=True)
        header.columnconfigure(0, weight=1)

        top = ttk.Frame(header, style="Card.TFrame")
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 4))
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="Path", style="CardBody.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(top, textvariable=self.source_var, style="Path.TEntry").grid(row=0, column=1, sticky="ew")

        browse_btns = ttk.Frame(top, style="Card.TFrame")
        browse_btns.grid(row=0, column=2, sticky="e", padx=(10, 0))

        RoundedButton(browse_btns, text="Open Folder", command=self._browse_folder, variant="secondary").pack(side="left", padx=(0, 4))
        RoundedButton(browse_btns, text="Open ZIP", command=self._browse_zip, variant="secondary").pack(side="left", padx=(0, 4))
        RoundedButton(browse_btns, text="Open CRX", command=self._browse_crx, variant="secondary").pack(side="left", padx=(0, 4))
        RoundedButton(browse_btns, text="Analyze", command=self._analyze_selected, variant="primary").pack(side="left")

        bottom = ttk.Frame(header, style="Card.TFrame")
        bottom.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))
        bottom.columnconfigure(0, weight=1)

        save_btns = ttk.Frame(bottom, style="Card.TFrame")
        save_btns.grid(row=0, column=1, sticky="e")

        RoundedButton(save_btns, text="Save JSON As", command=self._export_json_as, variant="secondary").pack(side="left", padx=(0, 4))
        RoundedButton(save_btns, text="Save HTML As", command=self._export_html_as, variant="secondary").pack(side="left", padx=(0, 4))
        RoundedButton(save_btns, text="Open Latest Report", command=self._open_latest_report, variant="secondary").pack(side="left", padx=(0, 4))
        RoundedButton(save_btns, text="Open Case Files", command=self._open_report_folder, variant="secondary").pack(side="left")

    def _build_summary_card(self, parent):
        summary_card = Card(parent, parent_bg=T.BG)
        summary_card.grid(row=2, column=0, sticky="ew", pady=(0, 6))
        card_title(summary_card.body, "Summary")
        summary = tk.Frame(summary_card.body, bg=T.SURFACE)
        summary.pack(fill="both", expand=True)
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

        ttk.Label(right, text="Assessment", style="CardBody.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 4))

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

        ttk.Label(right, text="Verdict", style="CardBody.TLabel").grid(row=2, column=0, sticky="w", pady=(0, 4))

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

        ttk.Label(right, text="Loaded Extension", style="CardBody.TLabel").grid(row=4, column=0, sticky="w", pady=(2, 2))
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
        workspace.grid(row=3, column=0, sticky="nsew", pady=(0, 4))
        workspace.columnconfigure(0, weight=2)
        workspace.columnconfigure(1, weight=6)
        workspace.columnconfigure(2, weight=4)
        workspace.rowconfigure(0, weight=1)

        # ------------------------------------------------------------------
        # Left: File inventory
        # ------------------------------------------------------------------
        files_panel = ttk.Frame(workspace, style="App.TFrame")
        files_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        files_panel.columnconfigure(0, weight=1)
        files_panel.rowconfigure(1, weight=1)

        ttk.Label(
            files_panel,
            text="File Inventory",
            style="SectionHeader.TLabel",
        ).grid(row=0, column=0, sticky="w", pady=(0, 4))

        self.file_list = self._make_listbox(files_panel)
        self.file_list.grid(row=1, column=0, sticky="nsew")

        if self._file_listbox_widget is not None:
            self._file_listbox_widget.bind("<<ListboxSelect>>", self._on_file_selected)

        # ------------------------------------------------------------------
        # Center: Preview notebook
        # ------------------------------------------------------------------
        center_panel = ttk.Frame(workspace, style="App.TFrame")
        center_panel.grid(row=0, column=1, sticky="nsew", padx=8)
        center_panel.columnconfigure(0, weight=1)
        center_panel.rowconfigure(1, weight=1)

        ttk.Label(
            center_panel,
            text="Preview",
            style="SectionHeader.TLabel",
        ).grid(row=0, column=0, sticky="w", pady=(0, 4))

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
        self._set_text(
            self.preview_text,
            "Select a file on the left to preview its contents.",
        )

        self.manifest_text = self._make_text(manifest_tab)
        self.manifest_text.grid(row=0, column=0, sticky="nsew")
        self._set_text(
            self.manifest_text,
            "Manifest contents will appear here after loading an extension.",
        )

        # ------------------------------------------------------------------
        # Right: Findings
        # ------------------------------------------------------------------
        notes_panel = ttk.Frame(workspace, style="App.TFrame")
        notes_panel.grid(row=0, column=2, sticky="nsew", padx=(8, 0))
        notes_panel.columnconfigure(0, weight=1)
        notes_panel.rowconfigure(1, weight=1)

        ttk.Label(
            notes_panel,
            text="Findings",
            style="SectionHeader.TLabel",
        ).grid(row=0, column=0, sticky="w", pady=(0, 4))

        self.risk_text = self._make_text(notes_panel)
        self.risk_text.grid(row=1, column=0, sticky="nsew")
        self._set_text(
            self.risk_text,
            "Findings and risk notes will appear here after analysis.",
        )

    def _build_footer(self, parent):
        footer = ttk.Frame(parent, style="App.TFrame")
        footer.grid(row=4, column=0, sticky="ew", pady=(4, 0))
        footer.columnconfigure(0, weight=1)
        footer.columnconfigure(1, weight=0)
        footer.columnconfigure(2, weight=0)

        ttk.Label(footer, textvariable=self.status_var, style="Footer.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(footer, textvariable=self.loaded_name_var, style="Footer.TLabel").grid(row=0, column=1, sticky="e", padx=(12, 12))
        ttk.Label(footer, textvariable=self.risk_verdict_var, style="Footer.TLabel").grid(row=0, column=2, sticky="e")
        
    def _autosize_to_screen(self):
        """
        Open large enough to show all major browser extension analysis sections.
        Prefer maximized window state; fallback to near-fullscreen geometry.
        """
        try:
            self.state("zoomed")
            return
        except Exception:
            pass

        try:
            self.attributes("-zoomed", True)
            return
        except Exception:
            pass

        try:
            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
            target_w = max(self.minsize()[0], min(screen_w - 40, 1900))
            target_h = max(self.minsize()[1], min(screen_h - 80, 1180))
            self.geometry(f"{target_w}x{target_h}+20+20")
        except Exception:
            pass


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
            selectbackground=T.ACCENT_SOFT,
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
            "bg": T.SUNKEN,
            "fg": T.TEXT_SECONDARY,
            "insertbackground": T.ACCENT,
            "selectbackground": T.ACCENT_SOFT,
            "selectforeground": T.TEXT,
            "relief": "flat",
            "borderwidth": 0,
            "highlightthickness": 0,
            "padx": 10,
            "pady": 10,
            "font": T.f_mono(10),
        }

        return ScrolledText(parent, **common_kwargs)

    def _set_text(self, widget, text):
        if widget is None:
            return

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

            # If the user selected a parent folder and we found a manifest deeper inside,
            # treat the manifest's parent as the actual extension root. This keeps reports,
            # file inventory, and source scanning focused on the extension itself.
            if source_path.is_dir() and manifest_path.parent != working_dir:
                working_dir = manifest_path.parent

            with manifest_path.open("r", encoding="utf-8") as f:
                manifest = json.load(f)

            self.current_source = working_dir if source_path.is_dir() else source_path
            self.current_working_dir = working_dir
            self.current_manifest_path = manifest_path
            self.current_manifest = manifest

            self.risk_score_var.set("0")
            self.risk_verdict_var.set("-")
            self.risk_severity_var.set("")
            self.file_count_var.set("0")
            self.loaded_name_var.set(source_path.name)

            if self.preview_text is not None:
                self._set_text(self.preview_text, "Select a file on the left to preview its contents.")

            if self.risk_text is not None:
                self._set_text(self.risk_text, "Findings and risk notes will appear here after analysis.")

            if self.manifest_text is not None:
                self._set_text(self.manifest_text, "Manifest contents will appear here after loading an extension.")

            self._populate_summary(manifest)
            self._populate_file_inventory(working_dir)
            self._populate_risk_notes(manifest, working_dir)
            self._populate_manifest_text(manifest)
            self._save_latest_to_case()

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

        matches = sorted(root.rglob("manifest.json"))

        if not matches:
            return None

        if len(matches) == 1:
            return matches[0]

        # Prefer the shallowest manifest if multiple are found.
        # This avoids randomly picking a deeply nested test/helper manifest.
        matches.sort(key=lambda p: (len(p.relative_to(root).parts), str(p).lower()))
        return matches[0]

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
        """Render what `static_triage_engine.extension_analysis` decided.

        **This method used to be the analysis** -- 190 lines of weighted
        permissions and per-file pattern scoring, inside a Tkinter window, with
        no test able to reach it. It summed toward 100 and banded `Critical` at
        80, and its source scan added points once per *file*, so a vendor bundle
        reached the ceiling on `fetch(` and `https://` alone. Nine ordinary
        files scored 67 before the manifest terms were counted.

        The engine emits `corroboration-v1` categories now, and this draws them.
        """
        result = analyze_extension(working_dir, manifest)

        self.risk_score_var.set(str(result["score"]))
        self.risk_verdict_var.set(result["verdict"])
        self.risk_severity_var.set(str(result["severity"]))
        self._update_risk_visuals(result["severity"])
        self._set_text(
            self.risk_text,
            "\n".join(f"- {note}" for note in result["notes"]))

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
        
    def _save_latest_to_case(self):
        if not self.current_manifest:
            return

        report_dir = self._get_report_dir()
        data = self._build_export_data()
        html_text = self._build_html_report(data)

        latest_json = report_dir / "browser_extension_analysis.json"
        latest_html = report_dir / "browser_extension_report.html"

        with open(latest_json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        latest_html.write_text(html_text, encoding="utf-8")

        metadata_dir = report_dir / "metadata"
        metadata_dir.mkdir(parents=True, exist_ok=True)

        with open(metadata_dir / "browser_extension_analysis.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = report_dir / "runs" / f"{timestamp}_{self._get_report_basename()}"
        run_dir.mkdir(parents=True, exist_ok=True)

        with open(run_dir / "browser_extension_analysis.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        (run_dir / "browser_extension_report.html").write_text(html_text, encoding="utf-8")

        try:
            self.parent.latest_extension_result = data
        except Exception:
            pass

        return latest_json, latest_html
        
    def _open_latest_report(self):
        html_path = self._get_report_dir() / "browser_extension_report.html"

        if not html_path.exists():
            messagebox.showinfo(
                "Open Latest Report",
                "No browser extension HTML report was found yet. Analyze an extension first.",
                parent=self,
            )
            return

        try:
            import webbrowser
            webbrowser.open(html_path.resolve().as_uri())
            self.status_var.set(f"Opened latest report: {html_path}")
        except Exception as e:
            messagebox.showerror(
                "Open Latest Report",
                f"Could not open report:\n{html_path}\n\n{e}",
                parent=self,
            )

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
                "risk_severity": self.risk_severity_var.get(),
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

        path = self._get_report_dir() / "browser_extension_analysis.json"

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

        path = self._get_report_dir() / "browser_extension_report.html"

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
        """Thin delegation. The page is
        `static_triage_engine.extension_report`."""
        return build_extension_report(data)

    def _current_case_name(self) -> str:
        case_name = self.parent.case_var.get().strip() if hasattr(self.parent, "case_var") else ""
        if case_name:
            return case_name

        sample = self.parent.sample_var.get().strip() if hasattr(self.parent, "sample_var") else ""
        if sample:
            return Path(sample).stem[:64]

        if self.current_source:
            return Path(self.current_source).stem[:64]

        return "extension_case"


    def _get_case_dir(self) -> Path:
        project_root = Path(__file__).resolve().parents[1]

        case_root = (
            Path(self.parent.case_root_var.get().strip())
            if hasattr(self.parent, "case_root_var") and self.parent.case_root_var.get().strip()
            else project_root / "cases"
        )

        case_root.mkdir(parents=True, exist_ok=True)

        case_dir = case_root / self._current_case_name()
        case_dir.mkdir(parents=True, exist_ok=True)

        try:
            self.parent.case_dir_detected = case_dir
        except Exception:
            pass

        return case_dir


    def _get_report_dir(self) -> Path:
        report_dir = self._get_case_dir() / "browser_extension_analysis"
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

    def _update_risk_visuals(self, verdict: str):
        verdict_l = (verdict or "").strip().lower()

        badge_bg = self.PANEL_SOFT
        badge_border = self.BORDER_SOFT
        text_color = self.TEXT

        # Severity colours come from the shared semantic map so this badge
        # always matches verdicts rendered elsewhere in the workbench.
        if verdict_l in T.STATUS_COLORS:
            text_color, badge_bg = T.status_colors(verdict_l)
            badge_border = text_color

        if self.risk_verdict_badge is not None:
            self.risk_verdict_badge.configure(
                bg=badge_bg,
                highlightbackground=badge_border,
                highlightcolor=badge_border,
            )

        if self.risk_verdict_text is not None:
            self.risk_verdict_text.configure(bg=badge_bg, fg=text_color)

        if self.score_value_label is not None:
            self.score_value_label.configure(fg=text_color if verdict_l in {"critical", "high", "medium", "low"} else self.TEXT)

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