"""
Static Triage GUI (v10) - Fix progress parsing for timestamped analysis.log lines

Your analysis.log lines look like:
  2026-03-05T23:57:18Z STEP_START md5
  2026-03-05T23:57:18Z STEP_DONE md5 rc=0 dur=0.028
So we cannot use line.startswith("STEP_START ").
v8 parses STEP_* markers anywhere in the line via regex.

Keeps everything from v7:
- Fixed classic progress bars
- Reads analysis.log from start
- Case_dir auto-detect from stdout + fallback tailer
- Case output selector + tool selectors + advanced settings
- UTF-8 safe streaming
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import webbrowser
import shutil
import html
from datetime import datetime
from html import escape
import urllib.request
import urllib.error
import ssl
from PIL import Image, ImageTk
from urllib.parse import urlparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
    
from gui.api_window import APIAnalysisWindow
from gui.styles import apply_app_theme

from gui.dynamic_window import DynamicAnalysisWindow
from gui.spec_window import SpecAnalysisWindow

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple




from static_triage_engine.api_spec_analysis import analyze_api_spec as engine_analyze_api_spec

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from dynamic_analysis.orchestrator import run_dynamic_analysis
from dynamic_analysis.html_report import write_dynamic_html_report
from static_triage_engine.scoring import combined_score_from_case_dir, calculate_combined_score

try:
    import certifi  # type: ignore
except Exception:
    certifi = None

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


def app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


ROOT = app_root()
CONFIG_PATH = ROOT / "config.json"

DEFAULT_CASE_ROOT = ROOT / "cases"
DEFAULT_RULES_DIR = ROOT / "tools" / "capa-rules" / "rules"
DEFAULT_SIGS_DIR = ROOT / "tools" / "capa" / "sigs"

CLI_SCRIPT = ROOT / "scripts" / "static_triage.py"


STEP_DISPLAY_ORDER: List[str] = [
    "md5",
    "sha1",
    "sha256",
    "extract",
    "pe_meta",
    "lief_meta",
    "file",
    "strings",
    "capa",
    "iocs",
    "report",
    "finalize",
]

STEP_LABELS: Dict[str, str] = {
    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256",
    "extract": "Payload Extraction",
    "pe_meta": "PE Metadata",
    "lief_meta": "LIEF Analysis",
    "file": "File Type (Linux tool / optional on Windows)",
    "strings": "Strings (Linux tool / optional on Windows)",
    "capa": "CAPA",
    "iocs": "IOC Extraction",
    "report": "Report Generation (PDF optional on Windows)",
    "finalize": "Finalize",
}

STEP_NAME_MAP: Dict[str, str] = {
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "extract": "extract",
    "pe_meta": "pe_meta",
    "lief_meta": "lief_meta",
    "file": "file",
    "file1": "file",
    "strings": "strings",
    "capa": "capa",
    "iocs": "iocs",
    "report": "report",
    "finalize": "finalize",
}

# Parse timestamped log lines
# Example: "2026-03-05T23:57:18Z STEP_DONE sha256 rc=0 dur=0.014"
STEP_START_RE = re.compile(r"\bSTEP_START\b\s+(?P<step>\S+)")
STEP_DONE_RE  = re.compile(r"\bSTEP_DONE\b\s+(?P<step>\S+)")
STEP_FAIL_RE  = re.compile(r"\bSTEP_FAIL\b\s+(?P<step>\S+)")

# Case dir detection from stdout (optional)
CASE_DIR_RE = re.compile(r'(?:\bcase_dir\b\s*[=:]\s*)(?P<p>[^"\'\r\n]+)', re.IGNORECASE)
CASE_LINE_RE = re.compile(r"^\s*\[\+\]\s*Case:\s*(?P<p>.+?)\s*$", re.IGNORECASE)
REPORT_STDOUT_MDHTML_RE = re.compile(r"\breport\.(md|html)\s*:\s*(?P<p>.+)$", re.IGNORECASE)
REPORT_STDOUT_PDF_RE = re.compile(r"\breport\.pdf\s*:\s*(?P<p>.+)$", re.IGNORECASE)


def norm_path_str(p: str) -> str:
    try:
        return str(Path(p))
    except Exception:
        return p


def normalize_rules_dir(p: Path) -> Path:
    if (p / "rules").is_dir():
        return p / "rules"
    return p


def looks_like_rules_dir(p: Path) -> bool:
    p2 = normalize_rules_dir(p)
    return p2.is_dir() and (any(p2.rglob("*.yml")) or any(p2.rglob("*.yaml")))


def looks_like_sigs_dir(p: Path) -> bool:
    return p.is_dir() and any(p.glob("*.sig"))


def load_config() -> Dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_config(cfg: Dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


@dataclass
class Preset:
    name: str
    extract: bool
    subfiles: bool
    subfile_limit: int
    strings_mode: str  # FULL | LITE | SKIP


PRESETS: List[Preset] = [
    Preset("Fast Triage", extract=True, subfiles=True, subfile_limit=5, strings_mode="LITE"),
    Preset("Deep Triage", extract=True, subfiles=True, subfile_limit=25, strings_mode="FULL"),
    Preset("Hash Only", extract=False, subfiles=False, subfile_limit=0, strings_mode="SKIP"),
]


def build_cli_args(sample_path: Path, case_name: str, extract: bool, subfiles: bool, subfile_limit: int, strings_mode: str) -> List[str]:
    args = [str(CLI_SCRIPT), str(sample_path), "--case", case_name, "--no-progress"]
    if not extract:
        args.append("--no-extract")
    if not subfiles:
        args.append("--no-subfiles")
    if subfiles and subfile_limit:
        args += ["--subfile-limit", str(subfile_limit)]
    sm = strings_mode.upper()
    if sm == "LITE":
        args.append("--strings-lite")
    elif sm == "SKIP":
        args.append("--no-strings")
    return args


def choose_python_exe() -> Path:
    if os.name == "nt":
        venv_py = ROOT / ".venv" / "Scripts" / "python.exe"
    else:
        venv_py = ROOT / ".venv" / "bin" / "python"
    if venv_py.exists():
        return venv_py
    return Path(sys.executable)


def run_cli_streaming(python_exe: Path, args: List[str], env_overrides: Dict[str, str], output_q: "queue.Queue[str]") -> int:
    env = os.environ.copy()
    env.update(env_overrides)
    env.setdefault("PYTHONIOENCODING", "utf-8")

    proc = subprocess.Popen(
        [str(python_exe)] + args,
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        output_q.put(line.rstrip("\n"))
    return proc.wait()


SENSITIVE_PARAM_HINTS = {
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "access_token", "refresh_token", "authorization", "auth", "session",
    "cookie", "ssn", "dob", "email", "phone", "creditcard", "card", "cvv",
}

ADMIN_ROUTE_HINTS = {"admin", "manage", "config", "settings", "internal", "debug", "health", "metrics", "actuator"}
DESTRUCTIVE_METHODS = {"DELETE", "PATCH", "PUT"}
AUTH_HINT_KEYS = {"authorization", "x-api-key", "api-key", "apikey", "bearer", "oauth", "token", "jwt", "basic"}


def _safe_json_write(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def _safe_text_read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _load_spec_file(path: Path) -> tuple[dict[str, Any], str]:
    text = _safe_text_read(path)
    suffix = path.suffix.lower()
    if suffix == ".json":
        return json.loads(text), "json"
    if suffix in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is not installed")
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}, "yaml"
    try:
        return json.loads(text), "json"
    except Exception:
        if yaml is None:
            raise RuntimeError("Unknown spec format and PyYAML is not installed")
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}, "yaml"


def _normalize_method(m: str) -> str:
    return str(m or "").upper().strip()


def _looks_sensitive(name: str) -> bool:
    n = re.sub(r"[^a-z0-9_]+", "", name.lower())
    return any(h in n for h in SENSITIVE_PARAM_HINTS)


def _looks_admin_route(path: str) -> bool:
    p = path.lower()
    return any(f"/{h}" in p or p.endswith(f"/{h}") for h in ADMIN_ROUTE_HINTS)


def _extract_server_hosts(spec: dict[str, Any]) -> list[str]:
    hosts: list[str] = []
    servers = spec.get("servers", [])
    if isinstance(servers, list):
        for item in servers:
            if isinstance(item, dict):
                url = str(item.get("url", "") or "").strip()
                if url:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        hosts.append(parsed.netloc.lower())
    host = spec.get("host")
    if isinstance(host, str) and host.strip():
        hosts.append(host.strip().lower())
    return sorted(set(hosts))


def _extract_security_schemes(spec: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    components = spec.get("components", {})
    if isinstance(components, dict):
        schemes = components.get("securitySchemes", {})
        if isinstance(schemes, dict):
            for name, item in schemes.items():
                if isinstance(item, dict):
                    out.append({"name": str(name), "type": str(item.get("type", "") or ""), "scheme": str(item.get("scheme", "") or ""), "in": str(item.get("in", "") or ""), "header_name": str(item.get("name", "") or "")})
    sec_defs = spec.get("securityDefinitions", {})
    if isinstance(sec_defs, dict):
        for name, item in sec_defs.items():
            if isinstance(item, dict):
                out.append({"name": str(name), "type": str(item.get("type", "") or ""), "scheme": str(item.get("scheme", "") or ""), "in": str(item.get("in", "") or ""), "header_name": str(item.get("name", "") or "")})
    return out


def _extract_parameters(op: dict[str, Any], path_item: dict[str, Any]) -> list[dict[str, str]]:
    params: list[dict[str, str]] = []
    for source in (path_item.get("parameters", []), op.get("parameters", [])):
        if isinstance(source, list):
            for p in source:
                if isinstance(p, dict):
                    params.append({"name": str(p.get("name", "") or ""), "in": str(p.get("in", "") or "")})
    request_body = op.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content", {})
        if isinstance(content, dict):
            for ctype, body in content.items():
                if isinstance(body, dict):
                    schema = body.get("schema", {})
                    if isinstance(schema, dict):
                        props = schema.get("properties", {})
                        if isinstance(props, dict):
                            for name in props.keys():
                                params.append({"name": str(name), "in": f"body:{ctype}"})
    return params


def _canonical_auth_name(name: str) -> str:
    n = str(name or "").strip().lower().replace("_", "-").replace(" ", "").replace("/", "-")

    if n in {
        "apikey", "api-key", "apikeyauth", "x-api-key", "xapikey", "api-key-auth"
    }:
        return "api-key"

    if n in {
        "bearer", "jwt", "bearerauth", "bearer-auth"
    }:
        return "bearer"

    if n in {
        "basic", "basicauth", "basic-auth"
    }:
        return "basic"

    if n in {"oauth", "oauth2"}:
        return "oauth2"

    if n in {"openidconnect", "openid-connect"}:
        return "openid-connect"

    if not n:
        return "none"

    return n


def _summarize_auth(security_schemes: list[dict[str, Any]], spec_text: str) -> list[str]:
    found: list[str] = []

    for item in security_schemes:
        t = (item.get("type", "") or "").lower()
        scheme = (item.get("scheme", "") or "").lower()
        header_name = (item.get("header_name", "") or "").lower()
        scheme_name = (item.get("name", "") or "").lower()

        if t == "apikey":
            found.append("api-key")
        elif t == "http" and scheme == "bearer":
            found.append("bearer")
        elif t == "http" and scheme == "basic":
            found.append("basic")
        elif t == "oauth2":
            found.append("oauth2")
        elif t == "openidconnect":
            found.append("openid-connect")

        if header_name in {"x-api-key", "api-key", "apikey"}:
            found.append("api-key")
        if scheme_name:
            found.append(_canonical_auth_name(scheme_name))

    # only use loose text hints when no explicit schemes were found
    if not found:
        text_l = spec_text.lower()
        for hint in AUTH_HINT_KEYS:
            if hint in text_l:
                found.append(_canonical_auth_name(hint))

    out: list[str] = []
    for item in found:
        canon = _canonical_auth_name(item)
        if canon != "none" and canon not in out:
            out.append(canon)
    return out
    
def _security_requirement_names(sec: Any) -> list[str]:
    names: list[str] = []
    if isinstance(sec, list):
        for item in sec:
            if isinstance(item, dict):
                for key in item.keys():
                    canon = _canonical_auth_name(str(key))
                    if canon != "none" and canon not in names:
                        names.append(canon)
    return names


def _effective_endpoint_auth(op: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    # endpoint-specific security overrides global security
    if "security" in op:
        names = _security_requirement_names(op.get("security"))
        return names if names else []

    names = _security_requirement_names(spec.get("security"))
    return names


# Legacy in-GUI spec analyzer kept for compatibility; SpecAnalysisWindow now calls the backend analyzer.
def analyze_api_spec(spec_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    spec_path = Path(spec_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "returncode": 0, "error": "", "input_file": str(spec_path), "format": "", "spec_type": "", "title": "", "version": "",
        "servers": [], "auth_summary": [], "security_schemes": [], "endpoints": [], "risk_notes": [],
        "summary": {"endpoint_count": 0, "get_count": 0, "post_count": 0, "put_count": 0, "patch_count": 0, "delete_count": 0, "admin_like_route_count": 0, "sensitive_param_count": 0, "auth_scheme_count": 0},
    }
    try:
        spec, fmt = _load_spec_file(spec_path)
        if not isinstance(spec, dict):
            raise RuntimeError("Spec root is not an object")
        spec_text = _safe_text_read(spec_path)
        info = spec.get("info", {}) if isinstance(spec.get("info"), dict) else {}
        paths = spec.get("paths", {}) if isinstance(spec.get("paths"), dict) else {}
        result["format"] = fmt
        if "openapi" in spec:
            result["spec_type"] = "openapi"
        elif "swagger" in spec:
            result["spec_type"] = "swagger2"
        else:
            result["spec_type"] = "unknown"
        result["title"] = str(info.get("title", "") or "")
        result["version"] = str(info.get("version", "") or "")
        result["servers"] = _extract_server_hosts(spec)
        security_schemes = _extract_security_schemes(spec)
        result["security_schemes"] = security_schemes
        result["auth_summary"] = _summarize_auth(security_schemes, spec_text)
        endpoints: list[dict[str, Any]] = []
        method_counts = {"GET": 0, "POST": 0, "PUT": 0, "PATCH": 0, "DELETE": 0}
        admin_like_route_count = 0
        sensitive_param_count = 0
        valid_methods = {"get", "post", "put", "patch", "delete", "head", "options"}
        for route, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            if _looks_admin_route(str(route)):
                admin_like_route_count += 1
            for method, op in path_item.items():
                if method.lower() not in valid_methods or not isinstance(op, dict):
                    continue
                m = _normalize_method(method)
                if m in method_counts:
                    method_counts[m] += 1
                params = _extract_parameters(op, path_item)
                sensitive_params = [p for p in params if _looks_sensitive(p.get("name", ""))]
                sensitive_param_count += len(sensitive_params)
                endpoint_auth = _effective_endpoint_auth(op, spec)
                endpoints.append({
                    "path": str(route),
                    "method": m,
                    "operation_id": str(op.get("operationId", "") or ""),
                    "summary": str(op.get("summary", "") or ""),
                    "description": str(op.get("description", "") or "")[:500],
                    "admin_like_route": _looks_admin_route(str(route)),
                    "destructive_method": m in DESTRUCTIVE_METHODS,
                    "parameters": params,
                    "sensitive_parameters": sensitive_params,
                    "auth_summary": endpoint_auth,
                })
        result["endpoints"] = endpoints
        result["summary"] = {
            "endpoint_count": len(endpoints), "get_count": method_counts["GET"], "post_count": method_counts["POST"], "put_count": method_counts["PUT"],
            "patch_count": method_counts["PATCH"], "delete_count": method_counts["DELETE"], "admin_like_route_count": admin_like_route_count,
            "sensitive_param_count": sensitive_param_count, "auth_scheme_count": len(result["auth_summary"]),
        }
        risk_notes: list[str] = []
        if not result["servers"]:
            risk_notes.append("No server/base URL definitions found in API spec")
        if method_counts["DELETE"] > 0 or method_counts["PATCH"] > 0:
            risk_notes.append("Spec exposes destructive or update-oriented methods (DELETE/PATCH)")
        if admin_like_route_count > 0:
            risk_notes.append(f"Admin/config/internal-like routes detected ({admin_like_route_count})")
        if sensitive_param_count > 0:
            risk_notes.append(f"Sensitive-looking parameters detected ({sensitive_param_count})")
        if not result["auth_summary"]:
            risk_notes.append("No obvious authentication scheme detected in spec")
        result["risk_notes"] = risk_notes
    except Exception as e:
        result["returncode"] = 1
        result["error"] = f"{type(e).__name__}: {e}"
    _safe_json_write(output_dir / "api_spec_analysis.json", result)
    return result


class App(tk.Tk):
    def _apply_theme(self):
        self.theme = apply_app_theme(self)
        
    def __init__(self):
        super().__init__()
        self._apply_theme()

        self.title("Static Triage GUI (v10)")
        self.geometry("1280x980")
        self.minsize(1180, 900)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.cfg = load_config()

        self.sample_var = tk.StringVar(value=self.cfg.get("sample_path", ""))
        self.case_var = tk.StringVar(value=self.cfg.get("case_name", ""))

        self.preset_var = tk.StringVar(value=self.cfg.get("preset", PRESETS[1].name))

        self.case_root_var = tk.StringVar(value=self.cfg.get("case_root_dir", str(DEFAULT_CASE_ROOT)))
        self.rules_var = tk.StringVar(value=self.cfg.get("capa_rules_dir", str(DEFAULT_RULES_DIR)))
        self.sigs_var = tk.StringVar(value=self.cfg.get("capa_sigs_dir", str(DEFAULT_SIGS_DIR)))
        self.vt_api_key_var = tk.StringVar(value=self.cfg.get("vt_api_key", ""))

        self.adv_enabled_var = tk.BooleanVar(value=self.cfg.get("adv_enabled", False))
        self.extract_var = tk.BooleanVar(value=self.cfg.get("extract", True))
        self.subfiles_var = tk.BooleanVar(value=self.cfg.get("subfiles", True))
        self.subfile_limit_var = tk.IntVar(value=int(self.cfg.get("subfile_limit", 25)))
        self.strings_lite_var = tk.BooleanVar(value=self.cfg.get("strings_lite", False))
        self.no_strings_var = tk.BooleanVar(value=self.cfg.get("no_strings", False))

        self.status_var = tk.StringVar(value="")
        self.running_var = tk.StringVar(value="Idle")

        self.score_var = tk.StringVar(value="-")
        self.verdict_var = tk.StringVar(value="-")
        self.confidence_var = tk.StringVar(value="-")
        self.combined_score_var = tk.StringVar(value="-")
        self.combined_severity_var = tk.StringVar(value="-")
        self.static_subscore_var = tk.StringVar(value="-")
        self.dynamic_subscore_var = tk.StringVar(value="-")
        self.spec_subscore_var = tk.StringVar(value="-")
        self.vt_status_var = tk.StringVar(value="VirusTotal: disabled")
        self.vt_name_var = tk.StringVar(value="VT Name: -")
        self.vt_counts_var = tk.StringVar(value="Counts: mal=0 | susp=0 | harmless=0 | undetected=0")
        self.vt_link: str = ""
        self.brand_logo_img = None

        self.open_case_btn: Optional[ttk.Button] = None
        self.open_html_btn: Optional[ttk.Button] = None
        self.open_pdf_btn: Optional[ttk.Button] = None
        self.dynamic_window: Optional[DynamicAnalysisWindow] = None
        self.spec_window: Optional[SpecAnalysisWindow] = None
        self.api_window: Optional[APIAnalysisWindow] = None
        self.latest_static_result: dict[str, Any] = {}
        self.latest_dynamic_result: dict[str, Any] = {}
        self.latest_spec_result: dict[str, Any] = {}
        self.latest_combined_score: Optional[dict[str, Any]] = None

        self.output_q: "queue.Queue[str]" = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None
        self.log_tail_thread: Optional[threading.Thread] = None
        self.stop_tail = threading.Event()
        self.current_log_path: Optional[Path] = None

        self.case_dir_detected: Optional[Path] = None
        self.step_widgets: Dict[str, Dict[str, object]] = {}

        self._build_ui()
        self._apply_preset_if_needed()
        self._refresh_path_status()
        self.vt_api_key_var.trace_add("write", lambda *_: self._refresh_path_status())
        self._reset_progress()
        self._reset_result_summary()
        self.after(100, self._drain_output)

    def _build_ui(self):
        outer = {"padx": 12, "pady": 8}

        # ---------- Header ----------
        header = ttk.Frame(self)
        header.pack(fill="x", **outer)
        header.columnconfigure(1, weight=1)
        header.columnconfigure(3, weight=0)

        ttk.Label(header, text="Sample:").grid(row=0, column=0, sticky="w")
        ttk.Entry(header, textvariable=self.sample_var, width=90).grid(
            row=0, column=1, sticky="ew", padx=(8, 8)
        )
        ttk.Button(
            header,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_sample,
        ).grid(row=0, column=2, sticky="ew")

        ttk.Label(header, text="Case name:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(header, textvariable=self.case_var, width=32).grid(
            row=1, column=1, sticky="w", padx=(8, 8), pady=(8, 0)
        )

        ttk.Label(header, text="Preset:").grid(row=1, column=2, sticky="e", padx=(12, 6), pady=(8, 0))
        preset_names = [p.name for p in PRESETS]
        preset_box = ttk.Combobox(
            header,
            textvariable=self.preset_var,
            values=preset_names,
            state="readonly",
            width=18,
        )
        preset_box.grid(row=1, column=3, sticky="w", pady=(8, 0))
        preset_box.bind("<<ComboboxSelected>>", self._on_preset_selected)

        # ---------- Main 2-column body ----------
        body = ttk.Frame(self)
        body.pack(fill="both", expand=False, **outer)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)

        left_col = ttk.Frame(body)
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left_col.columnconfigure(0, weight=1)
        left_col.rowconfigure(1, weight=1)

        right_col = ttk.Frame(body)
        right_col.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right_col.columnconfigure(0, weight=1)

        # ---------- Configuration ----------
        config = ttk.LabelFrame(left_col, text="Configuration")
        config.grid(row=0, column=0, sticky="ew")
        config.columnconfigure(0, weight=1)
        
        # ---------- Brand panel ----------
        brand = ttk.LabelFrame(left_col, text="RingForge")
        brand.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        brand.columnconfigure(0, weight=1)
        brand.rowconfigure(0, weight=1)

        brand_inner = tk.Frame(
            brand,
            bg="#001833",
            highlightthickness=1,
            highlightbackground="#2a4365",
        )
        brand_inner.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        brand_inner.columnconfigure(1, weight=1)

        logo_path = ROOT / "assets" / "anvil.png"

        if logo_path.exists():
            logo_img = Image.open(logo_path).convert("RGBA")
            logo_img = logo_img.resize((220, 220), Image.LANCZOS)
            self.brand_logo_img = ImageTk.PhotoImage(logo_img)

            logo_label = tk.Label(
                brand_inner,
                image=self.brand_logo_img,
                bg="#001833",
                bd=0,
                highlightthickness=0,
            )
            logo_label.grid(row=0, column=0, rowspan=6, sticky="w", padx=(18, 24), pady=18)
        else:
            logo_label = tk.Label(
                brand_inner,
                text="[assets/anvil.png not found]",
                bg="#001833",
                fg="#7fb3ff",
                font=("Segoe UI", 11, "bold"),
            )
            logo_label.grid(row=0, column=0, rowspan=6, sticky="w", padx=(18, 24), pady=18)

        tk.Label(
            brand_inner,
            text="RingForge",
            bg="#001833",
            fg="#f8fbff",
            font=("Segoe UI", 24, "bold"),
            anchor="w",
        ).grid(row=0, column=1, sticky="sw", pady=(28, 0))

        tk.Label(
            brand_inner,
            text="Workbench",
            bg="#001833",
            fg="#7fb3ff",
            font=("Segoe UI", 20, "bold"),
            anchor="w",
        ).grid(row=1, column=1, sticky="nw")

        tk.Frame(
            brand_inner,
            bg="#1f6fff",
            height=2,
            width=220,
        ).grid(row=2, column=1, sticky="w", pady=(8, 12))

        tk.Label(
            brand_inner,
            text="Static, Dynamic & Spec Analysis Platform",
            bg="#001833",
            fg="#c7dbff",
            font=("Segoe UI", 11),
            anchor="w",
        ).grid(row=3, column=1, sticky="w")

        tk.Label(
            brand_inner,
            text="Triage  •  Scoring  •  Reporting  •  Review",
            bg="#001833",
            fg="#86a9df",
            font=("Segoe UI", 10),
            anchor="w",
        ).grid(row=4, column=1, sticky="w", pady=(6, 0))

        tk.Label(
            brand_inner,
            text="v1.2",
            bg="#001833",
            fg="#5f86c5",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        ).grid(row=5, column=1, sticky="w", pady=(14, 18))

        # Paths subsection
        paths = ttk.LabelFrame(config, text="Paths")
        paths.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        paths.columnconfigure(1, weight=1)

        ttk.Label(paths, text="Case output folder:").grid(row=0, column=0, sticky="w")
        ttk.Entry(paths, textvariable=self.case_root_var, width=72).grid(
            row=0, column=1, sticky="ew", padx=(8, 8)
        )
        ttk.Button(
            paths,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_case_root,
        ).grid(row=0, column=2, sticky="ew")

        ttk.Label(paths, text="capa rules folder:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(paths, textvariable=self.rules_var, width=72).grid(
            row=1, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
        )
        ttk.Button(
            paths,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_rules,
        ).grid(row=1, column=2, sticky="ew", pady=(8, 0))

        ttk.Label(paths, text="capa sigs folder:").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(paths, textvariable=self.sigs_var, width=72).grid(
            row=2, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
        )
        ttk.Button(
            paths,
            text="Browse...",
            style="Side.Action.TButton",
            command=self._browse_sigs,
        ).grid(row=2, column=2, sticky="ew", pady=(8, 0))

        ttk.Label(paths, text="VirusTotal API key:").grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(paths, textvariable=self.vt_api_key_var, width=72, show="*").grid(
            row=3, column=1, sticky="ew", padx=(8, 8), pady=(8, 0)
        )
        ttk.Button(
            paths,
            text="Clear",
            style="Side.Action.TButton",
            command=self._clear_vt_key,
        ).grid(row=3, column=2, sticky="ew", pady=(8, 0))

        # Advanced subsection
        adv = ttk.LabelFrame(config, text="Advanced Settings")
        adv.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        adv.columnconfigure(0, weight=1)

        ttk.Checkbutton(
            adv,
            text="Override preset with advanced settings",
            variable=self.adv_enabled_var,
            command=self._on_adv_toggle,
        ).grid(row=0, column=0, sticky="w")

        self.adv_body = ttk.Frame(adv)
        self.adv_body.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        self.adv_body.columnconfigure(3, weight=1)

        ttk.Checkbutton(
            self.adv_body,
            text="Enable extraction",
            variable=self.extract_var,
            command=self._save_cfg,
        ).grid(row=0, column=0, sticky="w")

        ttk.Checkbutton(
            self.adv_body,
            text="Enable subfiles triage",
            variable=self.subfiles_var,
            command=self._save_cfg,
        ).grid(row=0, column=1, sticky="w", padx=(14, 0))

        ttk.Label(self.adv_body, text="Subfile limit:").grid(
            row=0, column=2, sticky="e", padx=(14, 6)
        )
        self.subfile_limit_spin = ttk.Spinbox(
            self.adv_body,
            from_=0,
            to=999,
            textvariable=self.subfile_limit_var,
            width=6,
            command=self._save_cfg,
        )
        self.subfile_limit_spin.grid(row=0, column=3, sticky="w")

        ttk.Checkbutton(
            self.adv_body,
            text="Strings lite",
            variable=self.strings_lite_var,
            command=self._on_strings_mode_changed,
        ).grid(row=1, column=0, sticky="w", pady=(8, 0))

        ttk.Checkbutton(
            self.adv_body,
            text="Skip strings",
            variable=self.no_strings_var,
            command=self._on_strings_mode_changed,
        ).grid(row=1, column=1, sticky="w", padx=(14, 0), pady=(8, 0))

        self.effective_label = ttk.Label(adv, text="")
        self.effective_label.grid(row=2, column=0, sticky="w", pady=(10, 0))

        # ---------- Right column: Progress ----------
        prog = ttk.LabelFrame(right_col, text="Progress")
        prog.grid(row=0, column=0, sticky="ew")
        prog.columnconfigure(0, weight=1)

        self.overall_var = tk.IntVar(value=0)
        self.overall_bar = ttk.Progressbar(
            prog,
            orient="horizontal",
            mode="determinate",
            maximum=100,
            variable=self.overall_var,
        )
        self.overall_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))

        self.overall_text = ttk.Label(prog, text="0%")
        self.overall_text.grid(row=0, column=1, sticky="w", padx=(10, 10), pady=(10, 0))

        self.steps_frame = ttk.Frame(prog)
        self.steps_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 10))
        self.steps_frame.columnconfigure(1, weight=1)
        
        # ---------- Results ----------
        self.combined_verdict_var = tk.StringVar(value="-")
        self.combined_confidence_var = tk.StringVar(value="-")

        results = ttk.LabelFrame(right_col, text="Results")
        results.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        results.columnconfigure(0, weight=1)

        # Combined headline section
        combined_wrap = ttk.Frame(results)
        combined_wrap.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))
        combined_wrap.columnconfigure(1, weight=1)
        combined_wrap.columnconfigure(3, weight=1)

        ttk.Label(combined_wrap, text="Combined Score:").grid(row=0, column=0, sticky="w")
        ttk.Label(
            combined_wrap,
            textvariable=self.combined_score_var,
            style="SummaryValue.TLabel",
        ).grid(row=0, column=1, sticky="w", padx=(8, 20))

        ttk.Label(combined_wrap, text="Severity:").grid(row=0, column=2, sticky="w")
        ttk.Label(
            combined_wrap,
            textvariable=self.combined_severity_var,
            style="SummaryAccent.TLabel",
        ).grid(row=0, column=3, sticky="w", padx=(8, 0))

        ttk.Label(combined_wrap, text="Verdict:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Label(combined_wrap, textvariable=self.combined_verdict_var).grid(
            row=1, column=1, sticky="w", padx=(8, 20), pady=(8, 0)
        )

        ttk.Label(combined_wrap, text="Confidence:").grid(row=1, column=2, sticky="w", pady=(8, 0))
        ttk.Label(combined_wrap, textvariable=self.combined_confidence_var).grid(
            row=1, column=3, sticky="w", padx=(8, 0), pady=(8, 0)
        )

        # Divider
        ttk.Separator(results, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=12, pady=(0, 8)
        )

        # Lower two-column summary area
        lower = ttk.Frame(results)
        lower.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 12))
        lower.columnconfigure(0, weight=1)
        lower.columnconfigure(1, weight=1)

        # Left side: Static + Subscores
        left_metrics = ttk.Frame(lower)
        left_metrics.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left_metrics.columnconfigure(1, weight=1)

        ttk.Label(left_metrics, text="Static", style="SectionHeader.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 6)
        )

        ttk.Label(left_metrics, text="Score:").grid(row=1, column=0, sticky="w")
        ttk.Label(left_metrics, textvariable=self.score_var).grid(
            row=1, column=1, sticky="w", padx=(8, 0)
        )

        ttk.Label(left_metrics, text="Verdict:").grid(row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Label(left_metrics, textvariable=self.verdict_var).grid(
            row=2, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
        )

        ttk.Label(left_metrics, text="Confidence:").grid(row=3, column=0, sticky="w", pady=(6, 0))
        ttk.Label(left_metrics, textvariable=self.confidence_var).grid(
            row=3, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
        )

        ttk.Separator(left_metrics, orient="horizontal").grid(
            row=4, column=0, columnspan=2, sticky="ew", pady=(10, 8)
        )

        ttk.Label(left_metrics, text="Subscores", style="SectionHeader.TLabel").grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(0, 6)
        )

        ttk.Label(left_metrics, text="Static:").grid(row=6, column=0, sticky="w")
        ttk.Label(left_metrics, textvariable=self.static_subscore_var).grid(
            row=6, column=1, sticky="w", padx=(8, 0)
        )

        ttk.Label(left_metrics, text="Dynamic:").grid(row=7, column=0, sticky="w", pady=(6, 0))
        ttk.Label(left_metrics, textvariable=self.dynamic_subscore_var).grid(
        row=7, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
        )

        ttk.Label(left_metrics, text="Spec/API:").grid(row=8, column=0, sticky="w", pady=(6, 0))
        ttk.Label(left_metrics, textvariable=self.spec_subscore_var).grid(
            row=8, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
        )

        # Right side: VirusTotal
        right_metrics = ttk.Frame(lower)
        right_metrics.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right_metrics.columnconfigure(0, weight=1)

        ttk.Label(right_metrics, text="VirusTotal", style="SectionHeader.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 6)
        )

        ttk.Label(right_metrics, textvariable=self.vt_status_var, wraplength=280, justify="left").grid(
            row=1, column=0, sticky="w"
        )
        ttk.Label(right_metrics, textvariable=self.vt_name_var, wraplength=280, justify="left").grid(
            row=2, column=0, sticky="w", pady=(6, 0)
        )
        ttk.Label(right_metrics, textvariable=self.vt_counts_var, wraplength=280, justify="left").grid(
            row=3, column=0, sticky="w", pady=(6, 0)
        )

        self.vt_open_btn = ttk.Button(
            right_metrics,
            text="Open VirusTotal",
            command=self._open_virustotal,
            state="disabled",
            style="Action.TButton",
        )
        self.vt_open_btn.grid(row=4, column=0, sticky="e", pady=(12, 0))

            
        # ---------- Command bar ----------
        actions = ttk.Frame(self)
        actions.pack(fill="x", **outer)

        buttons_row = ttk.Frame(actions)
        buttons_row.pack(fill="x")

        self.run_btn = ttk.Button(
            buttons_row,
            text="Run Analysis",
            style="Action.TButton",
            width=18,
            command=self._start_analysis,
        )
        self.run_btn.pack(side="left", padx=(0, 10))

        ttk.Button(
            buttons_row,
            text="Open Case",
            style="Action.TButton",
            width=14,
            command=self._open_case_files,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            buttons_row,
            text="Open Report",
            style="Action.TButton",
            width=14,
            command=self._open_html_report,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            buttons_row,
            text="Dynamic Analysis",
            style="Action.TButton",
            width=16,
            command=self.open_dynamic_window,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            buttons_row,
            text="API Spec Analysis",
            style="Action.TButton",
            width=16,
            command=self.open_spec_analysis_window,
        ).pack(side="left", padx=(0, 8))

        status_row = ttk.Frame(actions)
        status_row.pack(fill="x", pady=(6, 0))

        ttk.Label(status_row, textvariable=self.status_var).pack(side="left")
        ttk.Label(status_row, textvariable=self.running_var, anchor="e").pack(side="right")

        # ---------- Output ----------
        out = ttk.LabelFrame(self, text="Output")
        out.pack(fill="both", expand=True, **outer)

        self.output = tk.Text(
            out,
            wrap="none",
            height=12,
            bg="#0d1b33",
            fg="#eaf2ff",
            insertbackground="#eaf2ff",
            selectbackground="#1f6fff",
            selectforeground="white",
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#2a4365",
            highlightcolor="#3d86ff",
            font=("Consolas", 10),
        )
        self.output.pack(fill="both", expand=True, side="left")

        yscroll = ttk.Scrollbar(out, orient="vertical", command=self.output.yview)
        yscroll.pack(side="right", fill="y")
        self.output.configure(yscrollcommand=yscroll.set)

        self._sync_adv_state()
        self._update_effective_label()
        
    def open_dynamic_window(self):
        DynamicAnalysisWindow(self)

    def open_api_analysis_window(self):
        APIAnalysisWindow(self)

    def open_spec_analysis_window(self):
        SpecAnalysisWindow(self)   
    
    def reload_combined_score_from_disk(self):
        print("DEBUG reload_combined_score_from_disk called")
        print("DEBUG case_dir_detected =", self.case_dir_detected)

        if not self.case_dir_detected:
            return

        self.refresh_combined_score(Path(self.case_dir_detected))

        print("DEBUG combined_score_var =", self.combined_score_var.get())
        print("DEBUG static_subscore_var =", self.static_subscore_var.get())
        print("DEBUG dynamic_subscore_var =", self.dynamic_subscore_var.get())
        print("DEBUG spec_subscore_var =", self.spec_subscore_var.get())

        self.update_idletasks()


    def _reset_result_summary(self):
        self.score_var.set("-")
        self.verdict_var.set("-")
        self.confidence_var.set("-")
        self.combined_score_var.set("-")
        self.combined_severity_var.set("-")
        self.static_subscore_var.set("-")
        self.dynamic_subscore_var.set("-")
        self.spec_subscore_var.set("-")
        self.combined_verdict_var.set("-")
        self.combined_confidence_var.set("-")
        self.vt_status_var.set("VirusTotal: disabled")
        self.vt_name_var.set("VT Name: -")
        self.vt_counts_var.set("Counts: mal=0 | susp=0 | harmless=0 | undetected=0")
        self.vt_link = ""
        self.vt_open_btn.configure(state="disabled")

    def refresh_combined_score(self, case_dir: Optional[Path] = None):
        combined = None
        try:
            if case_dir:
                case_dir = Path(case_dir)

            if case_dir and case_dir.exists():
                combined = combined_score_from_case_dir(
                    case_dir,
                    dynamic_result=None,
                    spec_result=None,
                    write_output=True,
                )
            else:
                static_result = self.latest_static_result or None
                dynamic_result = self.latest_dynamic_result or None
                spec_result = self.latest_spec_result or None

                combined = calculate_combined_score(
                    static_result=static_result,
                    dynamic_result=dynamic_result,
                    spec_result=spec_result,
                )

        except Exception as e:
            print(f"DEBUG refresh_combined_score failed: {e}")
            combined = None

        if not combined:
            self.combined_score_var.set("-")
            self.combined_severity_var.set("-")
            self.static_subscore_var.set("-")
            self.dynamic_subscore_var.set("-")
            self.spec_subscore_var.set("-")
            self.combined_verdict_var.set("-")
            self.combined_confidence_var.set("-")
            self.latest_combined_score = None
            return

        self.latest_combined_score = combined
        self.combined_verdict_var.set(str(combined.get("verdict", "-")))
        self.combined_confidence_var.set(str(combined.get("confidence", "-")))
        self.combined_score_var.set(str(combined.get("total_score", "-")))
        self.combined_severity_var.set(str(combined.get("severity", "-")))

        subs = combined.get("subscores", {}) if isinstance(combined.get("subscores"), dict) else {}
        present = combined.get("present", {}) if isinstance(combined.get("present"), dict) else {}

        self.static_subscore_var.set(str(subs.get("static", 0)) if present.get("static") else "-")
        self.dynamic_subscore_var.set(str(subs.get("dynamic", 0)) if present.get("dynamic") else "-")
        self.spec_subscore_var.set(str(subs.get("spec", 0)) if present.get("spec") else "-")

        self.update_idletasks()

    def _clear_vt_key(self):
        self.vt_api_key_var.set("")
        self._save_cfg()
        self._refresh_path_status()

    def _open_virustotal(self):
        if self.vt_link:
            try:
                webbrowser.open(self.vt_link)
            except Exception as e:
                messagebox.showerror("VirusTotal", f"Could not open link:\n{e}")

    def _open_path(self, path: Path):
        try:
            if os.name == "nt":
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as e:
            messagebox.showerror("Open Path", f"Could not open:\n{path}\n\n{e}")

    def _ensure_case_dir(self) -> Optional[Path]:
        if self.case_dir_detected and self.case_dir_detected.exists():
            return self.case_dir_detected

        case_name = self.case_var.get().strip()
        if not case_name:
            sample = self.sample_var.get().strip()
            if sample:
                case_name = Path(sample).stem[:64]

        if not case_name:
            messagebox.showinfo("Open Case Files", "No case has been selected yet.")
            return None

        case_dir = Path(self.case_root_var.get().strip()) / case_name
        if case_dir.exists():
            self.case_dir_detected = case_dir
            return case_dir

        messagebox.showinfo("Open Case Files", f"Case folder not found:\n{case_dir}")
        return None
    
    def open_spec_analysis_window(self):
        if self.spec_window is not None and self.spec_window.winfo_exists():
            self.spec_window.lift()
            self.spec_window.focus_force()
            return
        self.spec_window = SpecAnalysisWindow(self)
        self.spec_window.protocol(
            "WM_DELETE_WINDOW",
            lambda win=self.spec_window: (win.destroy(), setattr(self, "spec_window", None)),
        )

    def open_api_analysis_window(self):
        if self.api_window is not None and self.api_window.winfo_exists():
            self.api_window.lift()
            self.api_window.focus_force()
            return

        self.api_window = APIAnalysisWindow(self)
        self.api_window.protocol(
            "WM_DELETE_WINDOW",
            lambda win=self.api_window: (win.destroy(), setattr(self, "api_window", None)),
        )

    def _open_api_html_report(self):
        case_dir = self._ensure_case_dir()
        if not case_dir:
            return
        html_path = case_dir / "api" / "api_response_latest.html"
        if html_path.exists():
            self._open_path(html_path)
        else:
            messagebox.showinfo("API HTML Form", f"API HTML report not found:\n{html_path}\n\nRun an API test first.")

    def _open_api_folder(self):
        case_dir = self._ensure_case_dir()
        if not case_dir:
            return
        api_dir = case_dir / "api"
        api_dir.mkdir(parents=True, exist_ok=True)
        self._open_path(api_dir)

    def _open_case_files(self):
        case_dir = self._ensure_case_dir()
        if case_dir:
            self._open_path(case_dir)

    def _open_html_report(self):
        case_dir = self._ensure_case_dir()
        if not case_dir:
            return
        report_html = case_dir / "report.html"
        if report_html.exists():
            self._open_path(report_html)
        else:
            messagebox.showinfo("Open HTML Report", f"HTML report not found:\n{report_html}")

    def _open_pdf_report(self):
        case_dir = self._ensure_case_dir()
        if not case_dir:
            return
        report_pdf = case_dir / "report.pdf"
        if report_pdf.exists():
            self._open_path(report_pdf)
        else:
            messagebox.showinfo("Open PDF Report", f"PDF report not found:\n{report_pdf}")

    def _update_result_summary_from_case(self, case_dir: Optional[Path]):
        if not case_dir:
            return

        summary_path = case_dir / "summary.json"
        vt_path = case_dir / "virustotal.json"

        summary = {}
        vt = {}
        try:
            if summary_path.exists():
                loaded = json.loads(summary_path.read_text(encoding="utf-8", errors="replace"))
                if isinstance(loaded, dict):
                    summary = loaded
        except Exception:
            summary = {}

        try:
            if vt_path.exists():
                loaded = json.loads(vt_path.read_text(encoding="utf-8", errors="replace"))
                if isinstance(loaded, dict):
                    vt = loaded
        except Exception:
            vt = {}

        # fall back to summary["virustotal"] when present
        if not vt:
            maybe_vt = summary.get("virustotal")
            if isinstance(maybe_vt, dict):
                vt = maybe_vt

        self.score_var.set(str(summary.get("risk_score", "-")))
        self.verdict_var.set(str(summary.get("verdict", "-")))
        self.confidence_var.set(str(summary.get("confidence", "-")))

        enabled = bool(vt.get("enabled", False))
        found = bool(vt.get("found", False))
        permalink = str(vt.get("permalink", "") or "")
        meaningful_name = str(vt.get("meaningful_name", "") or "")
        error = str(vt.get("error", "") or "")

        mal = int(vt.get("malicious", 0) or 0)
        susp = int(vt.get("suspicious", 0) or 0)
        harmless = int(vt.get("harmless", 0) or 0)
        undetected = int(vt.get("undetected", 0) or 0)

        if not vt:
            self.vt_status_var.set("VirusTotal: disabled")
        elif not enabled:
            self.vt_status_var.set("VirusTotal: disabled")
        elif found:
            self.vt_status_var.set("VirusTotal: found")
        elif error:
            self.vt_status_var.set(f"VirusTotal: {error}")
        else:
            self.vt_status_var.set("VirusTotal: no result")

        self.vt_name_var.set(f"VT Name: {meaningful_name or '-'}")
        self.vt_counts_var.set(
            f"Counts: mal={mal} | susp={susp} | harmless={harmless} | undetected={undetected}"
        )

        self.vt_link = permalink
        self.vt_open_btn.configure(state=("normal" if permalink else "disabled"))

        self.latest_static_result = {
            "summary": summary,
            "iocs": json.loads((case_dir / "iocs.json").read_text(encoding="utf-8", errors="replace")) if (case_dir / "iocs.json").exists() else {},
            "pe_meta": json.loads((case_dir / "pe_metadata.json").read_text(encoding="utf-8", errors="replace")) if (case_dir / "pe_metadata.json").exists() else {},
            "lief_meta": json.loads((case_dir / "lief_metadata.json").read_text(encoding="utf-8", errors="replace")) if (case_dir / "lief_metadata.json").exists() else {},
            "api_analysis": json.loads((case_dir / "api_analysis.json").read_text(encoding="utf-8", errors="replace")) if (case_dir / "api_analysis.json").exists() else {},
        }
        self.refresh_combined_score(case_dir)

    def _save_cfg(self):
        self.cfg["sample_path"] = self.sample_var.get().strip()
        self.cfg["case_name"] = self.case_var.get().strip()
        self.cfg["preset"] = self.preset_var.get().strip()
        self.cfg["case_root_dir"] = self.case_root_var.get().strip()
        self.cfg["capa_rules_dir"] = self.rules_var.get().strip()
        self.cfg["capa_sigs_dir"] = self.sigs_var.get().strip()
        self.cfg["vt_api_key"] = self.vt_api_key_var.get().strip()
        self.cfg["adv_enabled"] = bool(self.adv_enabled_var.get())
        self.cfg["extract"] = bool(self.extract_var.get())
        self.cfg["subfiles"] = bool(self.subfiles_var.get())
        self.cfg["subfile_limit"] = int(self.subfile_limit_var.get())
        self.cfg["strings_lite"] = bool(self.strings_lite_var.get())
        self.cfg["no_strings"] = bool(self.no_strings_var.get())
        save_config(self.cfg)
        self._update_effective_label()

    def _browse_sample(self):
        start = Path(self.sample_var.get()).parent if self.sample_var.get() else ROOT
        path = filedialog.askopenfilename(title="Select sample file", initialdir=str(start))
        if not path:
            return
        self.sample_var.set(norm_path_str(path))
        if not self.case_var.get().strip():
            self.case_var.set(Path(path).stem[:64])
        self._save_cfg()

    def _browse_case_root(self):
        start = Path(self.case_root_var.get()) if self.case_root_var.get() else ROOT
        chosen = filedialog.askdirectory(title="Select case output folder", initialdir=str(start))
        if not chosen:
            return
        self.case_root_var.set(norm_path_str(chosen))
        self._save_cfg()

    def _browse_rules(self):
        start = Path(self.rules_var.get()) if self.rules_var.get() else ROOT
        chosen = filedialog.askdirectory(title="Select capa rules folder", initialdir=str(start))
        if not chosen:
            return
        self.rules_var.set(norm_path_str(chosen))
        self._save_cfg()
        self._refresh_path_status()

    def _browse_sigs(self):
        start = Path(self.sigs_var.get()) if self.sigs_var.get() else ROOT
        chosen = filedialog.askdirectory(title="Select capa sigs folder", initialdir=str(start))
        if not chosen:
            return
        self.sigs_var.set(norm_path_str(chosen))
        self._save_cfg()
        self._refresh_path_status()

    def _on_preset_changed(self):
        self._apply_preset_if_needed()
        self._save_cfg()
    
    def _on_preset_selected(self, event=None):
        self._on_preset_changed()
        try:
            event.widget.selection_clear()
        except Exception:
            pass
        self.after(50, lambda: self.focus_set())

    def _on_adv_toggle(self):
        self._sync_adv_state()
        self._save_cfg()

    def _sync_adv_state(self):
        advanced_on = self.adv_enabled_var.get()

        for child in self.adv_body.winfo_children():
            try:
                # Keep labels visually normal
                if isinstance(child, ttk.Label):
                    child.configure(state="normal")
                # Keep the spinbox dark/readable when advanced settings are off
                elif child is getattr(self, "subfile_limit_spin", None):
                    child.configure(state="normal" if advanced_on else "readonly")
                else:
                    child.configure(state="normal" if advanced_on else "disabled")
            except tk.TclError:
                pass

        self._update_effective_label()

    def _on_strings_mode_changed(self):
        if self.no_strings_var.get():
            self.strings_lite_var.set(False)
        self._save_cfg()

    def _selected_preset(self) -> Preset:
        name = self.preset_var.get().strip()
        return next((p for p in PRESETS if p.name == name), PRESETS[1])

    def _apply_preset_if_needed(self):
        if self.adv_enabled_var.get():
            return
        p = self._selected_preset()
        self.extract_var.set(p.extract)
        self.subfiles_var.set(p.subfiles)
        self.subfile_limit_var.set(p.subfile_limit)
        self.no_strings_var.set(p.strings_mode.upper() == "SKIP")
        self.strings_lite_var.set(p.strings_mode.upper() == "LITE")
        self._update_effective_label()

    def _effective_settings(self) -> Tuple[bool, bool, int, str]:
        if self.adv_enabled_var.get():
            extract = bool(self.extract_var.get())
            subfiles = bool(self.subfiles_var.get())
            limit = int(self.subfile_limit_var.get())
            if self.no_strings_var.get():
                sm = "SKIP"
            elif self.strings_lite_var.get():
                sm = "LITE"
            else:
                sm = "FULL"
            return extract, subfiles, limit, sm
        p = self._selected_preset()
        return p.extract, p.subfiles, p.subfile_limit, p.strings_mode

    def _update_effective_label(self):
        extract, subfiles, limit, sm = self._effective_settings()
        self.effective_label.configure(text=f"Effective: extract={extract} | subfiles={subfiles} | subfile_limit={limit} | strings={sm}")

    def _refresh_path_status(self):
        rules_ok = looks_like_rules_dir(Path(self.rules_var.get().strip()))
        sigs_ok = looks_like_sigs_dir(Path(self.sigs_var.get().strip()))
        vt_set = bool(self.vt_api_key_var.get().strip())
        self.status_var.set(
            f"Rules: {'OK' if rules_ok else 'MISSING/INVALID'} | "
            f"Sigs: {'OK' if sigs_ok else 'MISSING/INVALID'} | "
            f"VirusTotal API key: {'SET' if vt_set else 'MISSING'}"
        )

    def _validate_inputs(self) -> Tuple[Path, str, Path, Path, Path]:
        sample = Path(self.sample_var.get().strip())
        if not sample.exists():
            raise FileNotFoundError(f"Sample not found:\n{sample}")
        case = self.case_var.get().strip() or sample.stem[:64]
        case_root = Path(self.case_root_var.get().strip())
        case_root.mkdir(parents=True, exist_ok=True)
        rules_raw = Path(self.rules_var.get().strip())
        sigs = Path(self.sigs_var.get().strip())
        if not looks_like_rules_dir(rules_raw):
            raise FileNotFoundError(f"capa rules folder invalid:\n{rules_raw}")
        rules = normalize_rules_dir(rules_raw)
        if not looks_like_sigs_dir(sigs):
            raise FileNotFoundError(f"capa sigs folder invalid:\n{sigs}")
        return sample, case, case_root, rules, sigs

    def _reset_progress(self):
        for w in self.steps_frame.winfo_children():
            w.destroy()
        self.step_widgets.clear()

        for i, step_key in enumerate(STEP_DISPLAY_ORDER):
            label = STEP_LABELS.get(step_key, step_key)
            ttk.Label(self.steps_frame, text=f"{label}:").grid(row=i, column=0, sticky="w")

            bar_var = tk.IntVar(value=0)
            ttk.Progressbar(self.steps_frame, orient="horizontal", mode="determinate", maximum=100, variable=bar_var).grid(row=i, column=1, sticky="we", padx=8)

            status = ttk.Label(self.steps_frame, text="idle")
            status.grid(row=i, column=2, sticky="w")

            self.step_widgets[step_key] = {"var": bar_var, "status": status}

        self.overall_var.set(0)
        self.overall_text.configure(text="0%")
        self._recalc_overall()

    def _set_step(self, step_key: str, pct: int, status: str):
        w = self.step_widgets.get(step_key)
        if not w:
            return

        w["var"].set(max(0, min(100, pct)))

        color_map = {
            "done": "#22c55e",
            "running": "#3d86ff",
            "queued": "#9bb2d1",
            "n/a": "#6f87a8",
            "missing tool": "#f59e0b",
            "failed": "#ef4444",
            "idle": "#9bb2d1",
        }
        fg = color_map.get(status.lower(), "#eaf2ff")
        w["status"].configure(text=status, foreground=fg)

    def _recalc_overall(self):
        completed = 0
        resolved_statuses = {"done", "failed", "error", "skipped", "n/a"}

        for step_key in STEP_DISPLAY_ORDER:
            st = self.step_widgets[step_key]["status"].cget("text").strip().lower()
            if st in resolved_statuses:
                completed += 1

        pct = int(round((completed / max(1, len(STEP_DISPLAY_ORDER))) * 100))
        self.overall_var.set(pct)
        self.overall_text.configure(text=f"{pct}%")

    def _start_log_tail(self, case_dir: Path):
        log_path = case_dir / "analysis.log"

        if self.current_log_path == log_path and self.log_tail_thread and self.log_tail_thread.is_alive():
            return

        self.stop_tail.set()

        if self.log_tail_thread and self.log_tail_thread.is_alive():
            self.log_tail_thread.join(timeout=1.0)

        self.stop_tail.clear()
        self.current_log_path = log_path

        self.output_q.put(f"[info] Progress: tailing {log_path}")
        self.log_tail_thread = threading.Thread(
            target=self._tail_analysis_log,
            args=(log_path,),
            daemon=True,
        )
        self.log_tail_thread.start()

    def _tail_analysis_log(self, log_path: Path):
        deadline = time.time() + 60
        while not log_path.exists() and time.time() < deadline and not self.stop_tail.is_set():
            time.sleep(0.25)
        if not log_path.exists():
            self.output_q.put(f"[warn] analysis.log not found at: {log_path}")
            return

        with log_path.open("r", encoding="utf-8", errors="replace") as f:
            while not self.stop_tail.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.25)
                    continue
                line = line.strip()
                if not line:
                    continue

                m = STEP_START_RE.search(line)
                if m:
                    raw = m.group("step")
                    step_key = STEP_NAME_MAP.get(raw, raw)
                    self.after(0, lambda s=step_key: (self._set_step(s, 15, "running"), self._recalc_overall()))
                    continue
                
                m = STEP_DONE_RE.search(line)
                if m:
                    raw = m.group("step")
                    step_key = STEP_NAME_MAP.get(raw, raw)
                    self.after(0, lambda s=step_key: (self._set_step(s, 100, "done"), self._recalc_overall()))
                    continue
                
                m = STEP_FAIL_RE.search(line)
                if m:
                    raw = m.group("step")
                    step_key = STEP_NAME_MAP.get(raw, raw)
                    line_lower = line.lower()

                    optional_na_steps = {"extract", "file", "filetype", "strings", "capa"}

                    if (
                        os.name == "nt"
                        and step_key in optional_na_steps
                        and (
                            "winerror 2" in line_lower
                            or "cannot find the file specified" in line_lower
                            or "rc=127" in line_lower
                            or "tool not found" in line_lower
                        )
                    ):
                        fail_label = "n/a"
                    else:
                        fail_label = "failed"

                    self.after(0, lambda s=step_key, lbl=fail_label: (self._set_step(s, 100, lbl), self._recalc_overall()))
                    continue
                                
    def _maybe_detect_case_dir_from_stdout(self, line: str) -> Optional[Path]:
        m = CASE_LINE_RE.match(line)
        if m:
            p = m.group("p").strip().strip('"')
            pp = Path(p)
            if pp.is_dir():
                return pp
        m2 = CASE_DIR_RE.search(line)
        if m2:
            p = m2.group("p").strip().strip('"').strip("'")
            pp = Path(p)
            if pp.is_dir():
                return pp
        return None

    def _open_dynamic_window(self):
        if self.dynamic_window is not None and self.dynamic_window.winfo_exists():
            self.dynamic_window.lift()
            self.dynamic_window.focus_force()
            return
        self.dynamic_window = DynamicAnalysisWindow(self)
        self.dynamic_window.protocol(
            "WM_DELETE_WINDOW",
            lambda win=self.dynamic_window: (win.destroy(), setattr(self, "dynamic_window", None)),
        )

    def _start_analysis(self):
        if self.worker_thread and self.worker_thread.is_alive():
            return

        try:
            sample, case, case_root, rules, sigs = self._validate_inputs()
        except Exception as e:
            messagebox.showerror("Analysis failed", str(e))
            return

        if not CLI_SCRIPT.exists():
            messagebox.showerror("Missing CLI", f"Could not find CLI script:\n{CLI_SCRIPT}")
            return

        extract, subfiles, limit, sm = self._effective_settings()
        args = build_cli_args(sample, case, extract, subfiles, limit, sm)

        vt_api_key = self.vt_api_key_var.get().strip()
        env_overrides = {
            "CASE_ROOT_DIR": str(case_root),
            "CAPA_RULES_DIR": str(rules),
            "CAPA_SIGS_DIR": str(sigs),
            "PYTHONIOENCODING": "utf-8",
        }
        if vt_api_key:
            env_overrides["VT_API_KEY"] = vt_api_key

        py_exe = choose_python_exe()

        self.case_dir_detected = None
        self.stop_tail.set()
        self.stop_tail.clear()

        self._reset_progress()
        self._reset_result_summary()
        self.output.delete("1.0", "end")
        self.output.insert("end", "Starting analysis:\n")
        self.output.insert("end", f"  sample={sample}\n  case={case}\n")
        self.output.insert("end", f"  case_root={case_root}\n")
        self.output.insert("end", f"  rules={rules}\n  sigs={sigs}\n")
        self.output.insert("end", f"  {self.effective_label.cget('text')}\n\n")
        self.output.insert("end", f"[cmd] {py_exe} " + " ".join(args) + "\n\n")
        self.output.see("end")

        self._start_log_tail(case_root / case)

        self.run_btn.configure(state="disabled")
        self.running_var.set("Running...")

        def worker():
            rc = 1
            try:
                rc = run_cli_streaming(py_exe, args, env_overrides, self.output_q)
            except Exception as e:
                self.output_q.put(f"[error] {e}")
                rc = 1
            finally:
                self.output_q.put(f"\n[done] exit_code={rc}")
                self.after(0, lambda: self._on_done(rc))

        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()

    def _on_done(self, rc: int):
        self.stop_tail.set()
        self.current_log_path = None

        if rc == 0:
            if self.case_dir_detected:
                report_md = self.case_dir_detected / "report.md"
                report_html = self.case_dir_detected / "report.html"
                report_pdf = self.case_dir_detected / "report.pdf"
                if report_md.exists() or report_html.exists() or report_pdf.exists():
                    self._set_step("report", 100, "done")
                self._update_result_summary_from_case(self.case_dir_detected)

            self._set_step("finalize", 100, "done")

            for step_key in STEP_DISPLAY_ORDER:
                st_lbl = self.step_widgets.get(step_key, {}).get("status")
                if st_lbl is not None and st_lbl.cget("text") in ("idle", "running"):
                    self._set_step(step_key, 100, "done")

            self._recalc_overall()
            self.overall_var.set(100)
            self.overall_text.configure(text="100%")
        else:
            if self.case_dir_detected:
                self._update_result_summary_from_case(self.case_dir_detected)
            self._recalc_overall()

        self.run_btn.configure(state="normal")
        self.running_var.set("Idle")

        if rc == 0:
            messagebox.showinfo("Completed", "Analysis completed successfully.")
        else:
            messagebox.showwarning("Completed", f"Analysis finished with exit code {rc}.\nCheck output for details.")

    def _drain_output(self):
        try:
            while True:
                line = self.output_q.get_nowait()
                if self.case_dir_detected is None:
                    cd = self._maybe_detect_case_dir_from_stdout(line)
                    if cd is not None:
                        self.case_dir_detected = cd
                        self.output.insert("end", f"[info] Detected case_dir: {cd}\n")
                        if self.current_log_path != (cd / "analysis.log"):
                            self._start_log_tail(cd)
                        self._update_result_summary_from_case(cd)
                
                # Report generation completion from stdout (works even if analysis.log doesn't include report lines)
                mrep = REPORT_STDOUT_MDHTML_RE.search(line)
                if mrep:
                    self._set_step("report", 100, "done")
                    self._recalc_overall()
                mpdf = REPORT_STDOUT_PDF_RE.search(line)
                if mpdf:
                    val = (mpdf.group("p") or "").strip()
                    if val.lower() != "none":
                        self._set_step("report", 100, "done")
                        self._recalc_overall()
                self.output.insert("end", line)
                self.output.see("end")
                if line.startswith("[done]") and self.case_dir_detected:
                    self._update_result_summary_from_case(self.case_dir_detected)
        except queue.Empty:
            pass
        self.after(100, self._drain_output)


def main():
    App().mainloop()


if __name__ == "__main__":
    main()

