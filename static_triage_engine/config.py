from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class TriageConfig:
    base_dir: Path = Path.home() / "analysis"
    tools_dir: Path = base_dir / "tools"
    cases_dir: Path = base_dir / "cases"
    logs_dir: Path = base_dir / "logs"
    capa_rules: Path = tools_dir / "capa-rules"
    capa_sigs: Path = tools_dir / "capa" / "sigs"
    ledger_file: Path = logs_dir / "triage_ledger.jsonl"
