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


def _snapshot_via_sc() -> list[dict[str, Any]]:
    """Fallback snapshot using sc.exe, which does not depend on WMI/CIM."""
    result = subprocess.run(
        ["sc.exe", "queryex", "type=", "service", "state=", "all"],
        capture_output=True,
        text=True,
        timeout=180,
        errors="replace",
    )
    if result.returncode not in (0, 1060):
        raise RuntimeError(
            f"sc query failed. rc={result.returncode} stderr={(result.stderr or '').strip()}"
        )

    services: list[dict[str, Any]] = []
    current: dict[str, Any] = {}

    for line in (result.stdout or "").splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("SERVICE_NAME:"):
            if current.get("service_name"):
                services.append(current)
            current = {
                "service_name": stripped.split(":", 1)[1].strip(),
                "display_name": "",
                "state": "",
                "start_mode": "",
                "path_name": "",
                "service_account": "",
            }
        elif stripped.upper().startswith("DISPLAY_NAME:") and current:
            current["display_name"] = stripped.split(":", 1)[1].strip()
        elif "STATE" in stripped.upper() and ":" in stripped and current:
            # e.g. "STATE              : 4  RUNNING"
            parts = stripped.split(":", 1)[1].split()
            current["state"] = parts[-1] if parts else ""

    if current.get("service_name"):
        services.append(current)

    return services


def snapshot_services_with_status() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Snapshot services, reporting which collection method succeeded."""
    status: dict[str, Any] = {"success": False, "method": "", "error": "", "fallback_used": False}
    errors: list[str] = []

    try:
        raw = _run_powershell_json_to_file()
        services = [normalize_service_item(item) for item in raw]
        services.sort(key=lambda x: x.get("service_name", ""))
        status.update({"success": True, "method": "Win32_Service"})
        return services, status
    except Exception as error:
        errors.append(f"Win32_Service: {error}")

    try:
        services = _snapshot_via_sc()
        services.sort(key=lambda x: x.get("service_name", ""))
        status.update(
            {
                "success": True,
                "method": "sc.exe",
                "fallback_used": True,
                "error": errors[0] if errors else "",
            }
        )
        return services, status
    except Exception as error:
        errors.append(f"sc.exe: {error}")

    status["error"] = " | ".join(errors)
    return [], status


def snapshot_services() -> list[dict[str, Any]]:
    """Backwards-compatible wrapper returning just the service list."""
    services, _status = snapshot_services_with_status()
    return services


def service_identity(service: dict[str, Any]) -> str:
    return str(service.get("service_name", "")).strip().lower()