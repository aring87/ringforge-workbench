import html
import json
import mimetypes
import queue
import ssl
import threading
import time
import tkinter as tk
import urllib.error
import urllib.request
import uuid
import webbrowser

from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional
from dynamic_analysis.report_theme import report_page

class APIAnalysisWindow(tk.Toplevel):
    def __init__(self, app: "App"):
        super().__init__(app)
        self.app = app
        self.title("Manual API Tester")
        self.geometry("1400x980")
        self.minsize(1200, 820)

        self.preset_var = tk.StringVar(value="HTTPBin GET Test")
        self.method_var = tk.StringVar(value="GET")
        self.url_var = tk.StringVar(value="")
        self.timeout_var = tk.IntVar(value=60)
        self.verify_ssl_var = tk.BooleanVar(value=True)
        self.file_path_var = tk.StringVar(value="")
        self.file_field_var = tk.StringVar(value="file")
        self.status_var = tk.StringVar(value="Idle")
        self.api_status_var = tk.StringVar(value="Status: Waiting")
        self.api_time_var = tk.StringVar(value="Time: —")
        self.api_type_var = tk.StringVar(value="Type: —")
        self.api_size_var = tk.StringVar(value="Size: —")
        self.notes_var = tk.StringVar(value="")

        self.last_api_dir: Optional[Path] = None
        self.last_html_report: Optional[Path] = None
        self.last_json_report: Optional[Path] = None
        self.last_response_payload: Optional[dict] = None

        self.output_q: "queue.Queue[object]" = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None

        self.PRESET_NAMES = list(self._preset_map().keys())

        self._build_ui()
        self._apply_preset(initial=True)
        self.after(150, self._drain_output)

        self.transient(app)
        self.grab_set()

    def _app_vt_key(self) -> str:
        try:
            return (self.app.vt_api_key_var.get() or "").strip()
        except Exception:
            return ""

    def _default_headers(self) -> dict:
        return {"User-Agent": "RingForge-Workbench/1.2"}

    def _preset_map(self) -> dict:
        vt_key = self._app_vt_key()
        return {
            "Custom": {
                "method": "GET",
                "url": "",
                "headers": self._default_headers(),
                "body": "",
                "notes": "Custom request. Enter any URL, headers, body, and optional file upload.",
                "file_path": "",
                "file_field": "file",
            },
            "HTTPBin GET Test": {
                "method": "GET",
                "url": "https://httpbin.org/get",
                "headers": self._default_headers(),
                "body": "",
                "notes": "Returns HTTP 200 with JSON showing your request details.",
                "file_path": "",
                "file_field": "file",
            },
            "HTTPBin POST Test": {
                "method": "POST",
                "url": "https://httpbin.org/post",
                "headers": {**self._default_headers(), "Content-Type": "application/json"},
                "body": {"sample": "whoami.exe", "test": True},
                "notes": "Simple POST validation. Useful to confirm JSON body handling works.",
                "file_path": "",
                "file_field": "file",
            },
            "JSONPlaceholder GET Test": {
                "method": "GET",
                "url": "https://jsonplaceholder.typicode.com/posts/1",
                "headers": self._default_headers(),
                "body": "",
                "notes": "Returns a sample JSON object for validating GET requests.",
                "file_path": "",
                "file_field": "file",
            },
            "JSONPlaceholder POST Test": {
                "method": "POST",
                "url": "https://jsonplaceholder.typicode.com/posts",
                "headers": {**self._default_headers(), "Content-Type": "application/json; charset=UTF-8"},
                "body": {
                    "title": "RingForge test",
                    "body": "Manual API tester validation",
                    "userId": 1,
                },
                "notes": "Sends a sample JSON POST request and returns a created test object.",
                "file_path": "",
                "file_field": "file",
            },
            "Example.com Test": {
                "method": "GET",
                "url": "https://example.com",
                "headers": self._default_headers(),
                "body": "",
                "notes": "Simple HTML page test for basic connectivity and response handling.",
                "file_path": "",
                "file_field": "file",
            },
            "VirusTotal File Lookup": {
                "method": "GET",
                "url": "https://www.virustotal.com/api/v3/files/<sha256>",
                "headers": {**self._default_headers(), "x-apikey": vt_key or "<YOUR_VT_API_KEY>"},
                "body": "",
                "notes": "Replace <sha256> with a real SHA256. Uses your main GUI VirusTotal key if available.",
                "file_path": "",
                "file_field": "file",
            },
            "VirusTotal File Upload": {
                "method": "POST",
                "url": "https://www.virustotal.com/api/v3/files",
                "headers": {**self._default_headers(), "x-apikey": vt_key or "<YOUR_VT_API_KEY>"},
                "body": {},
                "notes": "Choose a file to upload. Sends multipart/form-data to VirusTotal.",
                "file_path": "",
                "file_field": "file",
            },
            "AbuseIPDB Check IP": {
                "method": "GET",
                "url": "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90&verbose",
                "headers": {**self._default_headers(), "Key": "<YOUR_ABUSEIPDB_KEY>", "Accept": "application/json"},
                "body": "",
                "notes": "Replace the IP and API key. Good for header and querystring testing.",
                "file_path": "",
                "file_field": "file",
            },
            "urlscan Search": {
                "method": "GET",
                "url": "https://urlscan.io/api/v1/search/?q=domain:example.com",
                "headers": self._default_headers(),
                "body": "",
                "notes": "Replace example.com. Useful for testing a search-style API request.",
                "file_path": "",
                "file_field": "file",
            },
            "Shodan Host Lookup": {
                "method": "GET",
                "url": "https://api.shodan.io/shodan/host/8.8.8.8?key=<YOUR_SHODAN_KEY>",
                "headers": self._default_headers(),
                "body": "",
                "notes": "Replace the IP and API key. Good for quick host lookup testing.",
                "file_path": "",
                "file_field": "file",
            },
        }

    def _build_ui(self):
        pad = {"padx": 10, "pady": 8}

        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, **pad)

        frm.columnconfigure(1, weight=1)
        frm.columnconfigure(3, weight=0)
        frm.rowconfigure(7, weight=1)

        ttk.Label(frm, text="Preset:").grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            frm,
            textvariable=self.preset_var,
            values=self.PRESET_NAMES,
            state="readonly",
            width=28,
        ).grid(row=0, column=1, sticky="w", padx=6)

        ttk.Button(
            frm,
            text="Load Preset",
            style="Side.Action.TButton",
            command=self._apply_preset,
        ).grid(row=0, column=2, sticky="e", padx=(6, 0))

        ttk.Label(frm, text="Method:").grid(row=1, column=0, sticky="w")
        ttk.Combobox(
            frm,
            textvariable=self.method_var,
            values=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
            state="readonly",
            width=12,
        ).grid(row=1, column=1, sticky="w", padx=6)

        options_wrap = ttk.Frame(frm)
        options_wrap.grid(row=1, column=2, columnspan=2, sticky="e")
        ttk.Checkbutton(
            options_wrap,
            text="Verify SSL",
            variable=self.verify_ssl_var,
            style="Dark.TCheckbutton",
        ).pack(side="left", padx=(0, 12))

        ttk.Spinbox(
            options_wrap,
            from_=1,
            to=300,
            textvariable=self.timeout_var,
            width=8,
            style="Dark.TSpinbox",
        ).pack(side="left", padx=(6, 0))

        ttk.Label(frm, text="URL:").grid(row=2, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.url_var, width=112).grid(row=2, column=1, columnspan=3, sticky="we", padx=6)

        ttk.Label(frm, text="Upload file:").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.file_path_var, width=92).grid(row=3, column=1, sticky="we", padx=6)
        ttk.Button(
            frm,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_upload_file,
        ).grid(row=3, column=2, sticky="w", padx=(6, 0))

        field_wrap = ttk.Frame(frm)
        field_wrap.grid(row=3, column=3, sticky="w")
        ttk.Label(field_wrap, text="Field:").pack(side="left")
        ttk.Entry(field_wrap, textvariable=self.file_field_var, width=10).pack(side="left", padx=(6, 0))

        hints = ttk.LabelFrame(frm, text="Preset Notes")
        hints.grid(row=4, column=0, columnspan=4, sticky="we", pady=(8, 0))
        hints.columnconfigure(0, weight=1)
        ttk.Label(hints, textvariable=self.notes_var, wraplength=1200, justify="left").grid(row=0, column=0, sticky="w", padx=8, pady=8)

        req_wrap = ttk.LabelFrame(frm, text="Request")
        req_wrap.grid(row=5, column=0, columnspan=4, sticky="nsew", pady=(8, 0))
        req_wrap.columnconfigure(0, weight=1)
        req_wrap.columnconfigure(1, weight=1)
        req_wrap.rowconfigure(1, weight=1)

        ttk.Label(req_wrap, text="Headers (JSON):").grid(row=0, column=0, sticky="w", padx=8, pady=(8, 4))
        ttk.Label(req_wrap, text="Body / form fields (JSON or raw text):").grid(row=0, column=1, sticky="w", padx=8, pady=(8, 4))

        self.headers_text = tk.Text(
            req_wrap, wrap="none", height=10,
            bg="#0d1b33", fg="#eaf2ff", insertbackground="#eaf2ff",
            selectbackground="#1f6fff", selectforeground="white",
            relief="flat", borderwidth=0, highlightthickness=1,
            highlightbackground="#2a4365", highlightcolor="#3d86ff",
            font=("Consolas", 10),
        )
        self.headers_text.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=(0, 8))

        self.body_text = tk.Text(
            req_wrap, wrap="none", height=10,
            bg="#0d1b33", fg="#eaf2ff", insertbackground="#eaf2ff",
            selectbackground="#1f6fff", selectforeground="white",
            relief="flat", borderwidth=0, highlightthickness=1,
            highlightbackground="#2a4365", highlightcolor="#3d86ff",
            font=("Consolas", 10),
        )
        self.body_text.grid(row=1, column=1, sticky="nsew", padx=(4, 8), pady=(0, 8))

        actions = ttk.Frame(frm)
        actions.grid(row=6, column=0, columnspan=4, sticky="we", pady=(8, 0))

        self.send_btn = ttk.Button(actions, text="Send Request", style="Action.TButton", width=14, command=self._start_request)
        self.send_btn.pack(side="left", padx=(0, 8), pady=4)

        ttk.Button(actions, text="Clear", style="Action.TButton", width=10, command=self._clear_fields).pack(side="left", padx=6, pady=4)
        ttk.Button(actions, text="Save HTML Report", style="Action.TButton", width=16, command=self._save_current_html_report).pack(side="left", padx=6, pady=4)
        ttk.Button(actions, text="Open HTML Report", style="Action.TButton", width=16, command=self._open_latest_html).pack(side="left", padx=6, pady=4)
        self.copy_btn = ttk.Button(actions, text="Copy Response", style="Action.TButton", width=14, command=self._copy_response)
        self.copy_btn.pack(side="left", padx=6, pady=4)
        ttk.Label(actions, textvariable=self.status_var).pack(side="right")

        out_wrap = ttk.LabelFrame(frm, text="Response")
        out_wrap.grid(row=7, column=0, columnspan=4, sticky="nsew", pady=(8, 0))
        out_wrap.columnconfigure(0, weight=1)
        out_wrap.rowconfigure(1, weight=1)

        summary_frame = ttk.Frame(out_wrap)
        summary_frame.grid(row=0, column=0, sticky="we", padx=8, pady=(8, 6))
        ttk.Label(summary_frame, textvariable=self.api_status_var).pack(side="left", padx=(0, 16))
        ttk.Label(summary_frame, textvariable=self.api_time_var).pack(side="left", padx=(0, 16))
        ttk.Label(summary_frame, textvariable=self.api_type_var).pack(side="left", padx=(0, 16))
        ttk.Label(summary_frame, textvariable=self.api_size_var).pack(side="left", padx=(0, 16))

        self.response_tabs = ttk.Notebook(out_wrap)
        self.response_tabs.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))

        body_tab = ttk.Frame(self.response_tabs)
        headers_tab = ttk.Frame(self.response_tabs)
        raw_tab = ttk.Frame(self.response_tabs)

        for tab in (body_tab, headers_tab, raw_tab):
            tab.columnconfigure(0, weight=1)
            tab.rowconfigure(0, weight=1)

        self.response_tabs.add(body_tab, text="Body")
        self.response_tabs.add(headers_tab, text="Headers")
        self.response_tabs.add(raw_tab, text="Raw")

        self.body_output = tk.Text(
            body_tab, wrap="none",
            bg="#0d1b33", fg="#eaf2ff", insertbackground="#eaf2ff",
            selectbackground="#1f6fff", selectforeground="white",
            relief="flat", borderwidth=0, highlightthickness=1,
            highlightbackground="#2a4365", highlightcolor="#3d86ff",
            font=("Consolas", 10),
        )
        self.body_output.grid(row=0, column=0, sticky="nsew")
        self.body_output.configure(state="disabled")

        self.headers_output = tk.Text(
            headers_tab, wrap="none",
            bg="#0d1b33", fg="#eaf2ff", insertbackground="#eaf2ff",
            selectbackground="#1f6fff", selectforeground="white",
            relief="flat", borderwidth=0, highlightthickness=1,
            highlightbackground="#2a4365", highlightcolor="#3d86ff",
            font=("Consolas", 10),
        )
        self.headers_output.grid(row=0, column=0, sticky="nsew")
        self.headers_output.configure(state="disabled")

        self.raw_output = tk.Text(
            raw_tab, wrap="none",
            bg="#0d1b33", fg="#eaf2ff", insertbackground="#eaf2ff",
            selectbackground="#1f6fff", selectforeground="white",
            relief="flat", borderwidth=0, highlightthickness=1,
            highlightbackground="#2a4365", highlightcolor="#3d86ff",
            font=("Consolas", 10),
        )
        self.raw_output.grid(row=0, column=0, sticky="nsew")
        self.raw_output.configure(state="disabled")

    def _apply_preset(self, initial: bool = False):
        preset = self.preset_var.get().strip() or "Custom"
        presets = self._preset_map()
        data = presets.get(preset, presets["Custom"])
        self.method_var.set(data["method"])
        self.url_var.set(data["url"])
        self.file_path_var.set(data.get("file_path", ""))
        self.file_field_var.set(data.get("file_field", "file"))
        self.headers_text.delete("1.0", "end")
        self.body_text.delete("1.0", "end")
        self.headers_text.insert("1.0", json.dumps(data["headers"], indent=2))
        if isinstance(data["body"], (dict, list)):
            self.body_text.insert("1.0", json.dumps(data["body"], indent=2))
        else:
            self.body_text.insert("1.0", str(data["body"]))
        self.notes_var.set(data["notes"])
        if not initial:
            self.status_var.set(f"Loaded preset: {preset}")

    def _browse_upload_file(self):
        path = filedialog.askopenfilename(parent=self, title="Select file to upload")
        if path:
            self.file_path_var.set(path)

    def _set_text_widget(self, widget, text: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.see("1.0")
        widget.configure(state="disabled")

    def _parse_headers_and_body(self):
        headers_raw = self.headers_text.get("1.0", "end").strip()
        body_raw = self.body_text.get("1.0", "end").strip()

        headers = {}
        if headers_raw:
            try:
                headers = json.loads(headers_raw)
            except Exception as e:
                raise ValueError(f"Headers must be valid JSON.\n\n{e}")
            if not isinstance(headers, dict):
                raise ValueError("Headers JSON must be an object/dictionary.")

        body_data = ""
        if body_raw:
            try:
                body_data = json.loads(body_raw)
            except Exception:
                body_data = body_raw

        return headers, body_data

    def _build_ssl_context(self):
        if self.verify_ssl_var.get():
            return ssl.create_default_context()
        return ssl._create_unverified_context()

    def _build_multipart_body(self, fields, file_path: Path, file_field: str):
        boundary = f"----RingForgeBoundary{uuid.uuid4().hex}"
        parts = []

        if isinstance(fields, dict):
            for key, value in fields.items():
                parts.append(f"--{boundary}\r\n".encode("utf-8"))
                parts.append(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"))
                parts.append(str(value).encode("utf-8"))
                parts.append(b"\r\n")

        mime_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        file_bytes = file_path.read_bytes()

        parts.append(f"--{boundary}\r\n".encode("utf-8"))
        parts.append(
            f'Content-Disposition: form-data; name="{file_field}"; filename="{file_path.name}"\r\n'.encode("utf-8")
        )
        parts.append(f"Content-Type: {mime_type}\r\n\r\n".encode("utf-8"))
        parts.append(file_bytes)
        parts.append(b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode("utf-8"))

        return boundary, b"".join(parts)

    def _format_request_exception(self, e: Exception) -> str:
        return f"{type(e).__name__}: {e}"

    def _drain_output(self):
        try:
            while True:
                msg = self.output_q.get_nowait()
                if isinstance(msg, dict):
                    self._set_text_widget(self.body_output, msg.get("body", ""))
                    self._set_text_widget(self.headers_output, msg.get("headers", ""))
                    self._set_text_widget(self.raw_output, msg.get("raw", ""))
                else:
                    self._set_text_widget(self.raw_output, str(msg))
        except queue.Empty:
            pass
        self.after(150, self._drain_output)

    def _copy_response(self):
        current_tab = self.response_tabs.select()
        tab_text = self.response_tabs.tab(current_tab, "text")

        if tab_text == "Body":
            text = self.body_output.get("1.0", "end-1c")
        elif tab_text == "Headers":
            text = self.headers_output.get("1.0", "end-1c")
        else:
            text = self.raw_output.get("1.0", "end-1c")

        if not text.strip():
            self.status_var.set("Nothing to copy")
            self.after(1500, lambda: self.status_var.set("Idle"))
            return

        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_var.set(f"{tab_text} copied")
        self.after(1500, lambda: self.status_var.set("Idle"))

    def _clear_fields(self):
        self.url_var.set("")
        self.file_path_var.set("")
        self.file_field_var.set("file")
        self.headers_text.delete("1.0", "end")
        self.body_text.delete("1.0", "end")
        self.notes_var.set("")
        self._set_text_widget(self.body_output, "")
        self._set_text_widget(self.headers_output, "")
        self._set_text_widget(self.raw_output, "")
        self.status_var.set("Idle")
        self.api_status_var.set("Status: Waiting")
        self.api_time_var.set("Time: —")
        self.api_type_var.set("Type: —")
        self.api_size_var.set("Size: —")
        self.last_response_payload = None

    def _on_request_done(self):
        self.send_btn.configure(state="normal")
        self.status_var.set("Idle")
        self.worker_thread = None

    def _start_request(self):
        if self.worker_thread and self.worker_thread.is_alive():
            return

        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("API Analysis", "Please enter a URL.", parent=self)
            return

        method = self.method_var.get().strip().upper()
        timeout = int(self.timeout_var.get())

        try:
            headers, body_data = self._parse_headers_and_body()
        except Exception as e:
            messagebox.showerror("API Analysis", str(e), parent=self)
            return

        file_path_raw = self.file_path_var.get().strip()
        file_field = self.file_field_var.get().strip() or "file"
        body_bytes = None

        if file_path_raw:
            file_path = Path(file_path_raw)
            if not file_path.exists():
                messagebox.showerror("API Analysis", f"Upload file not found:\n{file_path}", parent=self)
                return
            boundary, body_bytes = self._build_multipart_body(body_data, file_path, file_field)
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        elif body_data not in ("", None):
            if isinstance(body_data, (dict, list)):
                body_bytes = json.dumps(body_data, indent=2).encode("utf-8")
                headers.setdefault("Content-Type", "application/json")
            else:
                body_bytes = str(body_data).encode("utf-8")

        self._set_text_widget(self.body_output, "")
        self._set_text_widget(self.headers_output, "")
        self._set_text_widget(self.raw_output, "")
        self.status_var.set("Sending...")
        self.send_btn.configure(state="disabled")

        def worker():
            start_time = time.perf_counter()
            try:
                req = urllib.request.Request(url=url, data=body_bytes, headers=headers, method=method)
                ssl_context = self._build_ssl_context()

                with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as resp:
                    status_code = getattr(resp, "status", None) or resp.getcode()
                    reason = getattr(resp, "reason", "")
                    resp_headers = dict(resp.getheaders())
                    raw = resp.read()
                    content_type = resp_headers.get("Content-Type", "Unknown")
                    size_bytes = len(raw or b"")

                elapsed_ms = int((time.perf_counter() - start_time) * 1000)

                try:
                    response_body_text = raw.decode("utf-8")
                except Exception:
                    response_body_text = raw.decode("utf-8", errors="replace")

                parts = [
                    f"> Preset: {self.preset_var.get().strip()}\n",
                    f"> Method: {method}\n",
                    f"> URL: {url}\n",
                    f"> Upload file: {file_path_raw or 'none'}\n\n",
                    f"HTTP {status_code} {reason}\n",
                    "=== Response Headers ===\n",
                ]

                for k, v in resp_headers.items():
                    parts.append(f"{k}: {v}\n")

                parts.append("\n=== Response Body ===\n")

                display_body = response_body_text
                content_type_lower = content_type.lower()

                if "application/json" in content_type_lower:
                    try:
                        parsed_body = json.loads(response_body_text)
                        display_body = json.dumps(parsed_body, indent=2)
                    except Exception:
                        display_body = response_body_text
                elif "text/html" in content_type_lower:
                    display_body = response_body_text.replace("><", ">\n<")
                elif content_type_lower.startswith("text/"):
                    display_body = response_body_text

                parts.append(display_body)

                headers_text = "\n".join(f"{k}: {v}" for k, v in resp_headers.items())
                raw_text = "".join(parts)

                self.last_response_payload = {
                    "saved_at": datetime.now().isoformat(timespec="seconds"),
                    "preset": self.preset_var.get().strip(),
                    "request": {
                        "method": method,
                        "url": url,
                        "headers": headers,
                        "body": body_data,
                        "upload_file": file_path_raw or "none",
                        "file_field": file_field,
                    },
                    "response": {
                        "status_code": status_code,
                        "reason": str(reason),
                        "headers": resp_headers,
                        "headers_text": headers_text,
                        "body_text": response_body_text,
                        "display_body": display_body,
                        "raw_text": raw_text,
                    },
                }

                self.output_q.put({
                    "body": display_body,
                    "headers": headers_text,
                    "raw": raw_text,
                })
                self.after(0, lambda: self.api_status_var.set(f"Status: {status_code} {reason}"))
                self.after(0, lambda: self.api_time_var.set(f"Time: {elapsed_ms} ms"))
                self.after(0, lambda: self.api_type_var.set(f"Type: {content_type}"))
                self.after(0, lambda: self.api_size_var.set(f"Size: {size_bytes} bytes"))
                self.after(0, self._on_request_done)

            except urllib.error.HTTPError as e:
                elapsed_ms = int((time.perf_counter() - start_time) * 1000)
                try:
                    err_body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    err_body = "<unable to decode error body>"

                err_headers = dict(e.headers.items()) if getattr(e, "headers", None) else {}
                err_type = err_headers.get("Content-Type", "Error")
                err_size = len(err_body.encode("utf-8", errors="ignore"))

                self.last_response_payload = {
                    "saved_at": datetime.now().isoformat(timespec="seconds"),
                    "preset": self.preset_var.get().strip(),
                    "request": {
                        "method": method,
                        "url": url,
                        "headers": headers,
                        "body": body_data,
                        "upload_file": file_path_raw or "none",
                        "file_field": file_field,
                    },
                    "response": {
                        "status_code": e.code,
                        "reason": str(e.reason),
                        "headers": err_headers,
                        "body_text": err_body,
                    },
                }

                err_headers_text = "\n".join(f"{k}: {v}" for k, v in err_headers.items())
                err_raw_text = (
                    f"> Preset: {self.preset_var.get().strip()}\n"
                    f"> Method: {method}\n"
                    f"> URL: {url}\n"
                    f"> Upload file: {file_path_raw or 'none'}\n\n"
                    f"HTTP Error: {e.code} {e.reason}\n\n"
                    f"{err_body}"
                )

                self.output_q.put({
                    "body": err_body,
                    "headers": err_headers_text,
                    "raw": err_raw_text,
                })
                self.after(0, lambda: self.api_status_var.set(f"Status: {e.code} {e.reason}"))
                self.after(0, lambda: self.api_time_var.set(f"Time: {elapsed_ms} ms"))
                self.after(0, lambda: self.api_type_var.set(f"Type: {err_type}"))
                self.after(0, lambda: self.api_size_var.set(f"Size: {err_size} bytes"))
                self.after(0, self._on_request_done)

            except Exception as e:
                elapsed_ms = int((time.perf_counter() - start_time) * 1000)
                err_text = self._format_request_exception(e)
                err_size = len(err_text.encode("utf-8", errors="ignore"))

                self.last_response_payload = {
                    "saved_at": datetime.now().isoformat(timespec="seconds"),
                    "preset": self.preset_var.get().strip(),
                    "request": {
                        "method": method,
                        "url": url,
                        "headers": headers,
                        "body": body_data,
                        "upload_file": file_path_raw or "none",
                        "file_field": file_field,
                    },
                    "response": {
                        "status_code": "",
                        "reason": "Request failed",
                        "headers": {},
                        "body_text": err_text,
                    },
                }

                err_raw_text = (
                    f"> Preset: {self.preset_var.get().strip()}\n"
                    f"> Method: {method}\n"
                    f"> URL: {url}\n"
                    f"> Upload file: {file_path_raw or 'none'}\n\n"
                    f"Request failed:\n{err_text}"
                )

                self.output_q.put({
                    "body": err_text,
                    "headers": "",
                    "raw": err_raw_text,
                })
                self.after(0, lambda: self.api_status_var.set("Status: Request failed"))
                self.after(0, lambda: self.api_time_var.set(f"Time: {elapsed_ms} ms"))
                self.after(0, lambda: self.api_type_var.set("Type: —"))
                self.after(0, lambda: self.api_size_var.set(f"Size: {err_size} bytes"))
                self.after(0, self._on_request_done)

        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()

    def _manual_report_dir(self) -> Path:
        base = Path.cwd() / "reports" / "manual_api"
        base.mkdir(parents=True, exist_ok=True)
        self.last_api_dir = base
        return base

    def _save_current_html_report(self):
        if not self.last_response_payload:
            messagebox.showinfo("Manual API Tester", "Run a request first.", parent=self)
            return

        report_dir = self._manual_report_dir()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = report_dir / f"manual_api_report_{ts}.html"
        json_path = report_dir / f"manual_api_report_{ts}.json"

        payload = self.last_response_payload
        req = payload.get("request", {}) if isinstance(payload.get("request"), dict) else {}
        resp = payload.get("response", {}) if isinstance(payload.get("response"), dict) else {}
        headers = resp.get("headers", {}) if isinstance(resp.get("headers"), dict) else {}
        body_text = resp.get("display_body") or resp.get("body_text", "") or ""
        
        pretty_body = body_text
        try:
            pretty_body = json.dumps(json.loads(body_text), indent=2)
        except Exception:
            pretty_body = body_text
            
        status_code = str(resp.get("status_code", "") or "")
        reason = str(resp.get("reason", "") or "")
        saved_at = str(payload.get("saved_at", "") or "")
        preset = str(payload.get("preset", "") or "")
        method = str(req.get("method", "") or "")
        url = str(req.get("url", "") or "")
        upload_file = str(req.get("upload_file", "") or "none")
        file_field = str(req.get("file_field", "") or "file")

        content_type = str(headers.get("Content-Type", "Unknown") or "Unknown")
        size_bytes = len(str(body_text).encode("utf-8", errors="replace"))
        header_count = len(headers)

        def esc(x):
            return html.escape(str(x))

        def severity_class_for_status(code_text: str) -> str:
            try:
                code = int(code_text)
            except Exception:
                return "verdict sev-med"
            if 200 <= code <= 299:
                return "verdict sev-none"
            if 300 <= code <= 399:
                return "verdict sev-low"
            if 400 <= code <= 499:
                return "verdict sev-med"
            return "verdict sev-high"

        verdict = f"{status_code} {reason}".strip() or "REQUEST FAILED"
        verdict_class = severity_class_for_status(status_code)

        headers_html = "".join(
            f"<li><strong>{esc(k)}:</strong> {esc(v)}</li>"
            for k, v in headers.items()
        ) or "<li>None</li>"

        body_html = f"""
        <section class="tile-grid">
          <div class="tile"><div class="tile-label">Method</div><div class="tile-value">{esc(method)}</div></div>
          <div class="tile"><div class="tile-label">Status</div><div class="tile-value">{esc(status_code or '-')}</div></div>
          <div class="tile"><div class="tile-label">Content Type</div><div class="tile-value" style="font-size:18px;">{esc(content_type)}</div></div>
          <div class="tile"><div class="tile-label">Headers</div><div class="tile-value">{header_count}</div></div>
          <div class="tile"><div class="tile-label">Body Size</div><div class="tile-value">{size_bytes}</div></div>
          <div class="tile"><div class="tile-label">Preset</div><div class="tile-value" style="font-size:18px;">{esc(preset or '-')}</div></div>
        </section>

        <div class="grid">
          <section class="card">
            <div class="section-head">
              <h2>Request</h2>
            </div>
            <table class="kv">
              <tr><th>Preset</th><td>{esc(preset)}</td></tr>
              <tr><th>Method</th><td>{esc(method)}</td></tr>
              <tr><th>URL</th><td>{esc(url)}</td></tr>
              <tr><th>Upload File</th><td>{esc(upload_file)}</td></tr>
              <tr><th>File Field</th><td>{esc(file_field)}</td></tr>
            </table>
          </section>

          <section class="card">
            <div class="section-head">
              <h2>Response</h2>
            </div>
            <table class="kv">
              <tr><th>Status</th><td>{esc(verdict)}</td></tr>
              <tr><th>Saved At</th><td>{esc(saved_at)}</td></tr>
              <tr><th>Content Type</th><td>{esc(content_type)}</td></tr>
              <tr><th>Body Size</th><td>{size_bytes} bytes</td></tr>
            </table>
          </section>
        </div>

        <section class="card">
          <div class="section-head">
            <h2>Response Headers</h2>
          </div>
          <ul>{headers_html}</ul>
        </section>

        <section class="card">
          <div class="section-head">
            <h2>Response Body</h2>
          </div>
          <div class="table-wrap">
            <pre style="white-space:pre-wrap;word-break:break-word;background:#0b1220;border:1px solid #1f2937;padding:14px;border-radius:12px;overflow:auto;">{esc(pretty_body)}</pre>
          </div>
        </section>
        """

        html_doc = report_page(
            title="Manual API Report",
            subtitle=esc(url or "Manual API Tester"),
            verdict=verdict,
            verdict_class=verdict_class,
            body_html=body_html,
        )

        html_path.write_text(html_doc, encoding="utf-8")
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        self.last_html_report = html_path
        self.last_json_report = json_path
        self.status_var.set(f"Saved report: {html_path.name}")
        messagebox.showinfo("Manual API Tester", f"Report saved:\n\n{html_path}", parent=self)

    def _open_latest_html(self):
        if not self.last_response_payload:
            messagebox.showinfo("Manual API Tester", "Run a request first.", parent=self)
            return

        if not self.last_html_report or not self.last_html_report.exists():
            try:
                self._save_current_html_report()
            except Exception as e:
                messagebox.showerror("Manual API Tester", f"Unable to generate HTML report.\n\n{e}", parent=self)
                return

        try:
            webbrowser.open(self.last_html_report.resolve().as_uri())
            self.status_var.set(f"Opened report: {self.last_html_report.name}")
        except Exception as e:
            messagebox.showerror("Manual API Tester", f"Unable to open report.\n\n{e}", parent=self)