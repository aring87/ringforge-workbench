from __future__ import annotations

from pathlib import Path
from typing import Any

from dynamic_analysis.snapshot_services import service_identity


SUSPICIOUS_PATH_HINTS = [
    r"\appdata\\",
    r"\temp\\",
    r"\programdata\\",
    r"\users\public\\",
    r"\startup\\",
]

SUSPICIOUS_SERVICE_NAME_HINTS = [
    "update",
    "helper",
    "host",
    "service",
]


def _norm(s: Any) -> str:
    return str(s or "").strip()


def _path_is_suspicious(path_value: str) -> bool:
    p = path_value.lower()
    return any(h in p for h in SUSPICIOUS_PATH_HINTS)


def _extract_executable_path(path_name: str) -> str:
    s = _norm(path_name)
    if not s:
        return ""

    if s.startswith('"'):
        parts = s.split('"')
        if len(parts) >= 2:
            return parts[1]

    return s.split(" ")[0]


def _basename(path_value: str) -> str:
    try:
        return Path(path_value).name.lower()
    except Exception:
        return path_value.lower()


def _service_is_suspicious(service: dict[str, Any]) -> list[str]:
    reasons: list[str] = []

    service_name = _norm(service.get("service_name", "")).lower()
    display_name = _norm(service.get("display_name", "")).lower()
    start_mode = _norm(service.get("start_mode", "")).lower()
    path_name = _norm(service.get("path_name", ""))
    exe_path = _extract_executable_path(path_name)

    if start_mode == "auto":
        reasons.append("auto_start")

    if exe_path and _path_is_suspicious(exe_path):
        reasons.append("binary_in_suspicious_path")

    if exe_path:
        base = _basename(exe_path)
        if base in {"cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe"}:
            reasons.append(f"lolbin_service_binary:{base}")

    if any(hint in service_name for hint in SUSPICIOUS_SERVICE_NAME_HINTS):
        reasons.append("generic_or_blend_in_service_name")

    if any(hint in display_name for hint in SUSPICIOUS_SERVICE_NAME_HINTS):
        reasons.append("generic_or_blend_in_display_name")

    deduped: list[str] = []
    seen = set()
    for r in reasons:
        if r not in seen:
            seen.add(r)
            deduped.append(r)

    return deduped


def diff_services(
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> dict[str, Any]:
    before_map = {service_identity(s): s for s in before}
    after_map = {service_identity(s): s for s in after}

    before_keys = set(before_map.keys())
    after_keys = set(after_map.keys())

    new_keys = sorted(after_keys - before_keys)
    removed_keys = sorted(before_keys - after_keys)
    common_keys = sorted(before_keys & after_keys)

    new_services: list[dict[str, Any]] = []
    removed_services: list[dict[str, Any]] = []
    modified_services: list[dict[str, Any]] = []

    for key in new_keys:
        service = after_map[key]
        reasons = _service_is_suspicious(service)
        new_services.append(
            {
                "identity": key,
                "service_name": service.get("service_name", ""),
                "display_name": service.get("display_name", ""),
                "start_mode": service.get("start_mode", ""),
                "path_name": service.get("path_name", ""),
                "start_name": service.get("start_name", ""),
                "state": service.get("state", ""),
                "suspicious": len(reasons) > 0,
                "reasons": reasons,
            }
        )

    for key in removed_keys:
        service = before_map[key]
        removed_services.append(
            {
                "identity": key,
                "service_name": service.get("service_name", ""),
                "display_name": service.get("display_name", ""),
            }
        )

    for key in common_keys:
        b = before_map[key]
        a = after_map[key]

        if b != a:
            reasons = _service_is_suspicious(a)
            modified_services.append(
                {
                    "identity": key,
                    "service_name": a.get("service_name", ""),
                    "display_name": a.get("display_name", ""),
                    "before": b,
                    "after": a,
                    "suspicious": len(reasons) > 0,
                    "reasons": reasons,
                }
            )

    summary = {
        "new_services": new_services,
        "removed_services": removed_services,
        "modified_services": modified_services,
        "counts": {
            "new_services": len(new_services),
            "removed_services": len(removed_services),
            "modified_services": len(modified_services),
            "suspicious_new_or_modified": sum(
                1 for s in (new_services + modified_services) if s.get("suspicious")
            ),
        },
    }

    return summary