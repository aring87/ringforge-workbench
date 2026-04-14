from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass
class FlossRunResult:
    enabled: bool
    available: bool
    success: bool
    command: list[str]
    return_code: int | None
    timed_out: bool
    error: str | None
    json_path: str | None
    text_path: str | None
    decoded_count: int
    tool_path: str | None


def _safe_load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _count_decoded_strings(data: dict[str, Any]) -> int:
    """
    FLOSS JSON shape may evolve, so parse defensively.
    """
    possible_keys = [
        "decoded_strings",
        "strings",
        "results",
    ]

    for key in possible_keys:
        value = data.get(key)
        if isinstance(value, list):
            return len(value)

    # Sometimes nested structures may exist
    if isinstance(data.get("analysis"), dict):
        analysis = data["analysis"]
        value = analysis.get("decoded_strings")
        if isinstance(value, list):
            return len(value)

    return 0


def find_floss(tool_dir: Path | None = None) -> str | None:
    """
    Resolve FLOSS path from PATH first, then from a known tools directory.
    """
    found = shutil.which("floss") or shutil.which("floss.exe")
    if found:
        return found

    if tool_dir:
        candidates = [
            tool_dir / "floss" / "floss.exe",
            tool_dir / "floss.exe",
            tool_dir / "FLOSS" / "floss.exe",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)

    return None


def run_floss(
    sample_path: Path,
    case_dir: Path,
    tool_dir: Path | None = None,
    timeout_seconds: int = 180,
    enabled: bool = True,
) -> FlossRunResult:
    """
    Run FLOSS and save raw JSON/text artifacts into the case directory.
    """
    json_path = case_dir / "floss_results.json"
    text_path = case_dir / "floss_results.txt"

    if not enabled:
        return FlossRunResult(
            enabled=False,
            available=False,
            success=False,
            command=[],
            return_code=None,
            timed_out=False,
            error="FLOSS disabled",
            json_path=None,
            text_path=None,
            decoded_count=0,
            tool_path=None,
        )

    floss_path = find_floss(tool_dir)
    if not floss_path:
        return FlossRunResult(
            enabled=True,
            available=False,
            success=False,
            command=[],
            return_code=None,
            timed_out=False,
            error="FLOSS executable not found",
            json_path=None,
            text_path=None,
            decoded_count=0,
            tool_path=None,
        )

    cmd = [floss_path, "-j", "--only", "decoded", "--", str(sample_path)]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return FlossRunResult(
            enabled=True,
            available=True,
            success=False,
            command=cmd,
            return_code=None,
            timed_out=True,
            error=f"FLOSS timed out after {timeout_seconds}s",
            json_path=None,
            text_path=None,
            decoded_count=0,
            tool_path=floss_path,
        )
    except Exception as exc:
        return FlossRunResult(
            enabled=True,
            available=True,
            success=False,
            command=cmd,
            return_code=None,
            timed_out=False,
            error=f"FLOSS execution failed: {exc}",
            json_path=None,
            text_path=None,
            decoded_count=0,
            tool_path=floss_path,
        )

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""

    if completed.returncode != 0:
        text_path.write_text(stderr or stdout, encoding="utf-8", errors="replace")
        return FlossRunResult(
            enabled=True,
            available=True,
            success=False,
            command=cmd,
            return_code=completed.returncode,
            timed_out=False,
            error=(stderr.strip() or stdout.strip() or "Unknown FLOSS error"),
            json_path=None,
            text_path=str(text_path),
            decoded_count=0,
            tool_path=floss_path,
        )

    json_path.write_text(stdout, encoding="utf-8", errors="replace")
    text_path.write_text(stdout, encoding="utf-8", errors="replace")

    parsed = _safe_load_json(json_path)
    decoded_count = _count_decoded_strings(parsed)

    return FlossRunResult(
        enabled=True,
        available=True,
        success=True,
        command=cmd,
        return_code=completed.returncode,
        timed_out=False,
        error=None,
        json_path=str(json_path),
        text_path=str(text_path),
        decoded_count=decoded_count,
        tool_path=floss_path,
    )


def floss_result_to_dict(result: FlossRunResult) -> dict[str, Any]:
    return asdict(result)