from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class DynamicRunConfig:
    sample_path: str
    case_dir: str
    timeout_seconds: int = 180
    procmon_enabled: bool = True
    procmon_path: str = ""
    procmon_config_path: str = ""


@dataclass
class SampleInfo:
    sample_path: str
    sample_name: str
    size: int
    md5: str
    sha1: str
    sha256: str


@dataclass
class ProcmonEvent:
    timestamp: str
    process_name: str
    pid: Optional[int]
    operation: str
    path: str
    result: str
    detail: str
    category: str


@dataclass
class DynamicRunSummary:
    sample: dict[str, Any]
    started_at_utc: str
    ended_at_utc: str
    exit_code: Optional[int]
    procmon_enabled: bool
    procmon_summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)