from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


def get_app_root() -> Path:
    """
    Return the project/app root.

    Source run:
      repo_root/static_triage_engine/config.py -> parent.parent

    PyInstaller/frozen run:
      directory containing the executable
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _base_dir_default() -> Path:
    """Default analysis base directory.

    Override with:
      - TRIAGE_BASE_DIR
      - ANALYSIS_BASE_DIR

    Otherwise use the application root, not the user's home folder.
    """
    v = os.getenv("TRIAGE_BASE_DIR") or os.getenv("ANALYSIS_BASE_DIR")
    if v:
        return Path(v).expanduser().resolve()
    return get_app_root()


def _cases_dir_default(base_dir: Path) -> Path:
    """Default cases directory.

    Override with:
      - CASE_ROOT_DIR
    """
    v = os.getenv("CASE_ROOT_DIR")
    if v:
        return Path(v).expanduser().resolve()
    return base_dir / "cases"


def _logs_dir_default(base_dir: Path) -> Path:
    """Default logs directory.

    Override with:
      - LOGS_DIR
    """
    v = os.getenv("LOGS_DIR")
    if v:
        return Path(v).expanduser().resolve()
    return base_dir / "logs"


def _tools_dir_default(base_dir: Path) -> Path:
    """Default tools directory.

    Override with:
      - TOOLS_DIR
    """
    v = os.getenv("TOOLS_DIR")
    if v:
        return Path(v).expanduser().resolve()
    return base_dir / "tools"


def _normalize_capa_rules_dir(path: Path) -> Path:
    """
    Accept either:
      .../capa-rules
      .../capa-rules/rules

    Prefer the nested rules directory if it exists.
    """
    path = path.expanduser().resolve()

    candidates = [
        path / "rules",
        path,
    ]

    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate

    return path


def _normalize_capa_sigs_dir(path: Path) -> Path:
    """
    Accept either:
      .../capa/sigs
      .../capa/signatures
    """
    path = path.expanduser().resolve()

    candidates = [
        path,
        path.parent / "signatures",
    ]

    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate

    return path


@dataclass(frozen=True)
class TriageConfig:
    """Central configuration for the static triage pipeline."""

    base_dir: Path = field(default_factory=_base_dir_default)

    tools_dir: Path = field(init=False)
    cases_dir: Path = field(init=False)
    logs_dir: Path = field(init=False)

    capa_rules: Path = field(init=False)
    capa_sigs: Path = field(init=False)

    ledger_file: Path = field(init=False)
    yara_rules_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        base = self.base_dir.resolve()

        tools_dir = _tools_dir_default(base)
        cases_dir = _cases_dir_default(base)
        logs_dir = _logs_dir_default(base)

        yr = os.getenv("YARA_RULES_DIR")
        yara_rules_dir = (
            Path(yr).expanduser().resolve()
            if yr
            else (tools_dir / "yara" / "rules").resolve()
        )

        cr = os.getenv("CAPA_RULES_DIR")
        cs = os.getenv("CAPA_SIGS_DIR")

        raw_capa_rules = Path(cr).expanduser().resolve() if cr else (tools_dir / "capa-rules").resolve()
        raw_capa_sigs = Path(cs).expanduser().resolve() if cs else (tools_dir / "capa" / "sigs").resolve()

        capa_rules = _normalize_capa_rules_dir(raw_capa_rules)
        capa_sigs = _normalize_capa_sigs_dir(raw_capa_sigs)

        ledger_file = logs_dir / "triage_ledger.jsonl"

        object.__setattr__(self, "base_dir", base)
        object.__setattr__(self, "tools_dir", tools_dir)
        object.__setattr__(self, "cases_dir", cases_dir)
        object.__setattr__(self, "logs_dir", logs_dir)

        object.__setattr__(self, "capa_rules", capa_rules)
        object.__setattr__(self, "capa_sigs", capa_sigs)

        object.__setattr__(self, "ledger_file", ledger_file)
        object.__setattr__(self, "yara_rules_dir", yara_rules_dir)