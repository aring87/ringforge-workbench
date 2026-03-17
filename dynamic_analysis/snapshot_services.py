from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


SERVICE_SNAPSHOT_PS_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$outFile = "{out_file}"

$services = Get-CimInstance Win32_Service | ForEach-Object {{
    [PSCustomObject]@{{
        Name = $_.Name
        DisplayName = $_.DisplayName
        State = $_.State
        StartMode = $_.StartMode
        PathName = $_.PathName
        StartName = $_.StartName
        ServiceType = $_.ServiceType
        Description = $_.Description
        ProcessId = $_.ProcessId
    }}
}}

$services | ConvertTo-Json -Depth 4 | Set-Content -Path $outFile -Encoding UTF8
Write-Output $outFile
"""


def _run_powershell_json_to_file() -> Any:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp_path = Path(tmp.name)

    script = SERVICE_SNAPSHOT_PS_TEMPLATE.format(
        out_file=str(tmp_path).replace("\\", "\\\\")
    )

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"PowerShell service snapshot failed. rc={result.returncode} stderr={result.stderr.strip()}"
        )

    if not tmp_path.exists():
        raise RuntimeError("Service snapshot JSON file was not created.")

    raw = tmp_path.read_text(encoding="utf-8-sig").strip()
    tmp_path.unlink(missing_ok=True)

    if not raw:
        return []

    data = json.loads(raw)
    if isinstance(data, dict):
        return [data]
    return data


def normalize_service_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "service_name": str(item.get("Name", "") or ""),
        "display_name": str(item.get("DisplayName", "") or ""),
        "state": str(item.get("State", "") or ""),
        "start_mode": str(item.get("StartMode", "") or ""),
        "path_name": str(item.get("PathName", "") or ""),
        "start_name": str(item.get("StartName", "") or ""),
        "service_type": str(item.get("ServiceType", "") or ""),
        "description": str(item.get("Description", "") or ""),
        "process_id": item.get("ProcessId"),
    }


def snapshot_services() -> list[dict[str, Any]]:
    raw = _run_powershell_json_to_file()
    normalized = [normalize_service_item(item) for item in raw]
    normalized.sort(key=lambda x: x.get("service_name", ""))
    return normalized


def service_identity(service: dict[str, Any]) -> str:
    return str(service.get("service_name", "")).strip().lower()