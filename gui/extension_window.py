from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
import html
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import tkinter.scrolledtext as scrolledtext
except Exception:
    scrolledtext = None


class ExtensionAnalysisWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.current_file_inventory = []

        self.title("Extension Analysis")
        self.geometry("1180x840+140+100")
        self.minsize(1040, 760)
        self.configure(bg="#05070B")
        self.transient(parent)

        self._temp_dir = None
        self.current_source = None
        self.current_working_dir = None
        self.current_manifest_path = None
        self.current_manifest = None

        self.source_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready")
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
        self.preview_path_var = tk.StringVar(value="")
        self.risk_verdict_var = tk.StringVar(value="-")
        self.risk_verdict_label = None

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)

        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(2, weight=1)

        header = ttk.LabelFrame(outer, text="Extension Source")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header.columnconfigure(1, weight=1)

        ttk.Label(header, text="Path:").grid(row=0, column=0, sticky="w", padx=8, pady=(8, 6))
        ttk.Entry(header, textvariable=self.source_var).grid(row=0, column=1, sticky="ew", padx=8, pady=(8, 6))

        source_btns = ttk.Frame(header)
        source_btns.grid(row=0, column=2, sticky="e", padx=8, pady=(8, 6))

        ttk.Button(source_btns, text="Open Folder", style="Action.TButton", command=self._browse_folder).pack(side="left", padx=(0, 6))
        ttk.Button(source_btns, text="Open ZIP", style="Action.TButton", command=self._browse_zip).pack(side="left", padx=(0, 6))
        ttk.Button(source_btns, text="Open CRX", style="Action.TButton", command=self._browse_crx).pack(side="left", padx=(0, 6))
        ttk.Button(source_btns, text="Analyze", style="Action.TButton", command=self._analyze_selected).pack(side="left")

        export_btns = ttk.Frame(header)
        export_btns.grid(row=1, column=1, columnspan=2, sticky="e", padx=8, pady=(0, 8))

        ttk.Button(export_btns, text="Quick Save JSON", style="Action.TButton", command=self._quick_export_json).pack(side="left", padx=(0, 6))
        ttk.Button(export_btns, text="Quick Save HTML", style="Action.TButton", command=self._quick_export_html).pack(side="left", padx=(0, 6))
        ttk.Button(export_btns, text="Open Report Folder", style="Action.TButton", command=self._open_report_folder).pack(side="left")

        summary = ttk.LabelFrame(outer, text="Summary")
        summary.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        for col in range(4):
            summary.columnconfigure(col, weight=1)

        self._summary_row(summary, 0, "Name", self.name_var, "Version", self.version_var)
        self._summary_row(summary, 1, "Description", self.description_var, "Manifest Version", self.manifest_version_var)
        self._summary_row(summary, 2, "Permissions", self.permissions_var, "Host Permissions", self.host_permissions_var)
        self._summary_row(summary, 3, "Background", self.background_var, "Content Scripts", self.content_scripts_var)
        self._summary_row(summary, 4, "Web Resources", self.web_resources_var, "Externally Connectable", self.externally_connectable_var)
        self._summary_row(summary, 5, "Update URL", self.update_url_var, "Commands", self.commands_var)
        ttk.Label(summary, text="Risk Score:").grid(row=6, column=0, sticky="w", padx=8, pady=4)
        ttk.Label(summary, textvariable=self.risk_score_var, wraplength=360, justify="left").grid(row=6, column=1, sticky="ew", padx=8, pady=4)

        ttk.Label(summary, text="Risk Verdict:").grid(row=6, column=2, sticky="w", padx=8, pady=4)
        self.risk_verdict_label = tk.Label(
            summary,
            textvariable=self.risk_verdict_var,
            bg="#05070B",
            fg="#F7FAFF",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        )
        self.risk_verdict_label.grid(row=6, column=3, sticky="w", padx=8, pady=4)
        self._summary_row(summary, 7, "Files Found", self.file_count_var, "CSP", self.csp_var)

        lower = ttk.Panedwindow(outer, orient="horizontal")
        lower.grid(row=2, column=0, sticky="nsew")

        files_panel = ttk.Frame(lower, padding=6)
        preview_panel = ttk.Frame(lower, padding=6)
        notes_panel = ttk.Frame(lower, padding=6)
        manifest_panel = ttk.Frame(lower, padding=6)

        lower.add(files_panel, weight=2)
        lower.add(preview_panel, weight=4)
        lower.add(notes_panel, weight=3)
        lower.add(manifest_panel, weight=4)

        files_panel.columnconfigure(0, weight=1)
        files_panel.rowconfigure(1, weight=1)

        preview_panel.columnconfigure(0, weight=1)
        preview_panel.rowconfigure(1, weight=1)

        notes_panel.columnconfigure(0, weight=1)
        notes_panel.rowconfigure(1, weight=1)

        manifest_panel.columnconfigure(0, weight=1)
        manifest_panel.rowconfigure(1, weight=1)

        ttk.Label(files_panel, text="File Inventory", style="SectionHeader.TLabel").grid(row=0, column=0, sticky="w", padx=(2, 0), pady=(0, 6))
        self.file_list = self._make_listbox(files_panel)
        self.file_list.grid(row=1, column=0, sticky="nsew")
        self._file_listbox_widget.bind("<<ListboxSelect>>", self._on_file_selected)

        ttk.Label(preview_panel, text="File Preview", style="SectionHeader.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.preview_text = self._make_text(preview_panel)
        self.preview_text.grid(row=1, column=0, sticky="nsew")
        self._set_text(self.preview_text, "Select a file from File Inventory to preview its contents.")

        ttk.Label(notes_panel, text="Risk Notes", style="SectionHeader.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.risk_text = self._make_text(notes_panel)
        self.risk_text.grid(row=1, column=0, sticky="nsew")

        ttk.Label(manifest_panel, text="Manifest JSON", style="SectionHeader.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.manifest_text = self._make_text(manifest_panel)
        self.manifest_text.grid(row=1, column=0, sticky="nsew")

        footer = ttk.Frame(outer)
        footer.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        footer.columnconfigure(0, weight=1)

        ttk.Label(footer, textvariable=self.status_var, style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        
    def _build_html_report(self, data: dict) -> str:
        import html
        import json

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

        def badge_html(label: str, value):
            return f'<span class="badge {verdict_class if label == "Verdict" else "sev-low"}">{esc(label)}: {esc(value)}</span>'

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
            rendered = "".join(
                f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>"
                for k, v in rows.items()
            )
            return f"""
            <section class="card">
              <div class="section-head">
                <h2>{esc(title)}</h2>
                {badge_fragment}
              </div>
              <table class="kv">
                {rendered}
              </table>
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
      --panel-2: #0B1220;
      --border: #22314F;
      --text: #F3F6FB;
      --muted: #A9B7D0;
      --blue: #6EA8FF;
      --blue-strong: #1E4ED8;
      --good: #19C37D;
      --warn: #F5B942;
      --bad: #E45757;
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
      border: 1px solid var(--border);
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
      border: 1px solid var(--border);
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
      border-bottom: 1px solid var(--border);
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
      border: 1px solid var(--border);
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
            if source_path.is_dir():
                base = source_path
            else:
                base = source_path.parent

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
                messagebox.showinfo("Open Report Folder", f"Report folder:\n{report_dir}")
            self.status_var.set(f"Opened report folder: {report_dir}")
        except Exception as e:
            messagebox.showerror("Open Report Folder", f"Could not open report folder:\n{e}")
     
    def _update_risk_verdict_color(self, verdict: str):
        if not self.risk_verdict_label:
            return

        verdict = (verdict or "").strip().lower()

        if verdict == "high":
            color = "#EF4444"
        elif verdict == "medium":
            color = "#F59E0B"
        elif verdict == "low":
            color = "#22C55E"
        else:
            color = "#F7FAFF"

        self.risk_verdict_label.configure(fg=color)
    
    def _get_risk_verdict(self, score: int) -> str:
        if score >= 7:
            return "High"
        if score >= 3:
            return "Medium"
        return "Low"
        
    def _bring_to_front(self):
        try:
            self.lift()
            self.focus_force()
            self.after(50, self.lift)
        except Exception:
            pass
    
    def _make_listbox(self, parent):
        frame = tk.Frame(parent, bg="#05070B")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        listbox = tk.Listbox(
            frame,
            bg="#0B1220",
            fg="#F7FAFF",
            selectbackground="#183A7A",
            selectforeground="#F7FAFF",
            relief="flat",
            borderwidth=1,
            font=("Consolas", 10),
            width=32,
        )

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)

        listbox.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        self._file_listbox_widget = listbox
        return frame
        
    def _set_file_list(self, items):
        lb = getattr(self, "_file_listbox_widget", None)
        if lb is None:
            return

        lb.delete(0, "end")
        for item in items:
            lb.insert("end", item)
    
    def _on_file_selected(self, event=None):
        lb = getattr(self, "_file_listbox_widget", None)
        if lb is None:
            return

        selection = lb.curselection()
        if not selection:
            return

        selected_rel = lb.get(selection[0])
        self._preview_file(selected_rel)
        
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

    def _make_text(self, parent):
        if scrolledtext is not None:
            widget = scrolledtext.ScrolledText(
                parent,
                wrap="word",
                height=18,
                bg="#0B1220",
                fg="#F7FAFF",
                insertbackground="#F7FAFF",
                relief="flat",
                borderwidth=1,
                padx=10,
                pady=10,
                font=("Consolas", 10),
            )
            return widget

        text = tk.Text(
            parent,
            wrap="word",
            height=18,
            bg="#0B1220",
            fg="#F7FAFF",
            insertbackground="#F7FAFF",
            relief="flat",
            borderwidth=1,
            padx=10,
            pady=10,
            font=("Consolas", 10),
        )
        return text

    def _summary_row(self, parent, row, label1, var1, label2, var2):
        ttk.Label(parent, text=f"{label1}:").grid(row=row, column=0, sticky="w", padx=8, pady=4)
        ttk.Label(parent, textvariable=var1, wraplength=360, justify="left").grid(row=row, column=1, sticky="ew", padx=8, pady=4)
        ttk.Label(parent, text=f"{label2}:").grid(row=row, column=2, sticky="w", padx=8, pady=4)
        ttk.Label(parent, textvariable=var2, wraplength=360, justify="left").grid(row=row, column=3, sticky="ew", padx=8, pady=4)

    def _browse_folder(self):
        path = filedialog.askdirectory(
            title="Select unpacked extension folder",
            parent=self,
        )
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

            working_dir = None
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
                
            self.risk_score_var.set("0")
            self.risk_verdict_var.set("-")
            self.file_count_var.set("0")
            self._update_risk_verdict_color("-")

            self.current_source = source_path
            self.current_working_dir = working_dir
            self.current_manifest_path = manifest_path
            self.current_manifest = manifest
            self._set_text(self.preview_text, "Select a file from File Inventory to preview its contents.")

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
            "tabs",
            "cookies",
            "history",
            "webRequest",
            "webRequestBlocking",
            "debugger",
            "downloads",
            "nativeMessaging",
            "management",
            "proxy",
            "scripting",
            "declarativeNetRequest",
            "declarativeNetRequestWithHostAccess",
            "clipboardRead",
            "clipboardWrite",
            "desktopCapture",
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
            notes.append("- Background execution is enabled via background page/service worker.")
            score += 1

        if content_scripts:
            notes.append("- Content scripts are present and can interact with page content.")
            score += 2

        if web_resources:
            notes.append("- Web-accessible resources are exposed to web pages or other extension contexts.")
            score += 1

        if externally_connectable:
            notes.append("- externally_connectable is configured, allowing outside pages/apps to communicate with the extension.")
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
        self._update_risk_verdict_color(verdict)
        text = "\n".join(notes)
        self._set_text(self.risk_text, text)
    
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
    
    def _build_export_data(self):
        manifest_text = ""
        try:
            manifest_text = self.manifest_text.get("1.0", "end").strip()
        except Exception:
            manifest_text = ""

        risk_notes_text = ""
        try:
            risk_notes_text = self.risk_text.get("1.0", "end").strip()
        except Exception:
            risk_notes_text = ""

        preview_text = ""
        try:
            preview_text = self.preview_text.get("1.0", "end").strip()
        except Exception:
            preview_text = ""

        data = {
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
        return data
        
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
            self.status_var.set(f"Exported JSON: {path}")
            self._bring_to_front()
        except Exception as e:
            messagebox.showerror("Export JSON", f"Could not export JSON:\n{e}")
            self._bring_to_front()
            
    def _quick_export_json(self):
        if not self.current_manifest:
            messagebox.showwarning("Quick Export JSON", "Analyze an extension first.")
            return

        path = self._get_report_dir() / f"{self._get_report_basename()}_extension_analysis.json"

        try:
            data = self._build_export_data()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.status_var.set(f"Quick-saved JSON: {path}")
            self._bring_to_front()
        except Exception as e:
            messagebox.showerror("Quick Export JSON", f"Could not quick-save JSON:\n{e}")
            self._bring_to_front()

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
            self.status_var.set(f"Exported HTML: {path}")
            self._bring_to_front()
        except Exception as e:
            messagebox.showerror("Export HTML", f"Could not export HTML:\n{e}")
            self._bring_to_front()
            
    def _quick_export_html(self):
        if not self.current_manifest:
            messagebox.showwarning("Quick Export HTML", "Analyze an extension first.")
            return

        path = self._get_report_dir() / f"{self._get_report_basename()}_extension_analysis.html"

        try:
            data = self._build_export_data()
            html_text = self._build_html_report(data)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_text)
            self.status_var.set(f"Quick-saved HTML: {path}")
            self._bring_to_front()
        except Exception as e:
            messagebox.showerror("Quick Export HTML", f"Could not quick-save HTML:\n{e}")
            self._bring_to_front()
    
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
        self._set_file_list(files)
        lb = getattr(self, "_file_listbox_widget", None)
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

    def _set_text(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

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