import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

EventCallback = Callable[[str, str, dict[str, Any]], None]

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def emit(cb: Optional[EventCallback], event_type: str, step: str, payload: dict[str, Any] | None = None) -> None:
    if cb:
        cb(event_type, step, payload or {})

def log_line(case_dir: Path, msg: str) -> None:
    try:
        with (case_dir / "analysis.log").open("a", encoding="utf-8", errors="replace") as f:
            f.write(f"{_ts()} {msg}\n")
    except Exception:
        pass

def ledger_append(ledger_file: Path, logs_dir: Path, entry: dict[str, Any]) -> None:
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
        with ledger_file.open("a", encoding="utf-8", errors="replace") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass
