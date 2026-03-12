from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _base_dir_default() -> Path:
    """Default analysis base directory.

    Override with:
      - TRIAGE_BASE_DIR
      - ANALYSIS_BASE_DIR
    """
    v = os.getenv("TRIAGE_BASE_DIR") or os.getenv("ANALYSIS_BASE_DIR")
    if v:
        return Path(v).expanduser()
    return Path.home() / "analysis"


def _cases_dir_default(base_dir: Path) -> Path:
    """Default cases directory.

    Override with:
      - CASE_ROOT_DIR  (preferred)
    """
    v = os.getenv("CASE_ROOT_DIR")
    if v:
        return Path(v).expanduser()
    return base_dir / "cases"


def _logs_dir_default(base_dir: Path) -> Path:
    """Default logs directory.

    Override with:
      - LOGS_DIR
    """
    v = os.getenv("LOGS_DIR")
    if v:
        return Path(v).expanduser()
    return base_dir / "logs"


def _tools_dir_default(base_dir: Path) -> Path:
    """Default tools directory.

    Override with:
      - TOOLS_DIR
    """
    v = os.getenv("TOOLS_DIR")
    if v:
        return Path(v).expanduser()
    return base_dir / "tools"


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

    def __post_init__(self) -> None:
        base = self.base_dir

        tools_dir = _tools_dir_default(base)
        cases_dir = _cases_dir_default(base)
        logs_dir = _logs_dir_default(base)

        # Optional direct overrides:
        # CAPA_RULES_DIR may be either ...\capa-rules OR ...\capa-rules\rules (normalized later)
        cr = os.getenv("CAPA_RULES_DIR")
        cs = os.getenv("CAPA_SIGS_DIR")
        capa_rules = Path(cr).expanduser() if cr else (tools_dir / "capa-rules")
        capa_sigs = Path(cs).expanduser() if cs else (tools_dir / "capa" / "sigs")

        ledger_file = logs_dir / "triage_ledger.jsonl"

        object.__setattr__(self, "tools_dir", tools_dir)
        object.__setattr__(self, "cases_dir", cases_dir)
        object.__setattr__(self, "logs_dir", logs_dir)

        object.__setattr__(self, "capa_rules", capa_rules)
        object.__setattr__(self, "capa_sigs", capa_sigs)

        object.__setattr__(self, "ledger_file", ledger_file)
