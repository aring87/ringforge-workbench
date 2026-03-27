from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


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

STEP_START_RE = re.compile(r"\bSTEP_START\b\s+(?P<step>\S+)")
STEP_DONE_RE  = re.compile(r"\bSTEP_DONE\b\s+(?P<step>\S+)")
STEP_FAIL_RE  = re.compile(r"\bSTEP_FAIL\b\s+(?P<step>\S+)")

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


def build_cli_args(
    sample_path: Path,
    case_name: str,
    extract: bool,
    subfiles: bool,
    subfile_limit: int,
    strings_mode: str,
) -> List[str]:
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


def run_cli_streaming(
    python_exe: Path,
    args: List[str],
    env_overrides: Dict[str, str],
    output_q: "queue.Queue[str]",
) -> int:
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
