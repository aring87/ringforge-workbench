from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any


SUSPICIOUS_PATH_HINTS = [
    r"\appdata\\",
    r"\temp\\",
    r"\programdata\\",
    r"\startup\\",
    r"\users\public\\",
    r"currentversion\run",
    r"currentversion\runonce",
]

LOLBIN_HINTS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wscript.exe",
    "cscript.exe",
    "schtasks.exe",
    "sc.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "installutil.exe",
}


def _path_is_suspicious(path_value: str) -> bool:
    p = path_value.lower()
    return any(h in p for h in SUSPICIOUS_PATH_HINTS)


def _basename(path_value: str) -> str:
    try:
        return Path(path_value).name.lower()
    except Exception:
        return path_value.lower()


def _is_self_generated_snapshot_activity(event: dict[str, Any]) -> bool:
    process_name = str(event.get("process_name", "")).lower()
    path_value = str(event.get("path", "")).lower()
    detail = str(event.get("detail", "")).lower()

    # Our launcher process spawning helper tools
    if process_name == "python.exe":
        if "get-scheduledtask" in detail or "get-ciminstance win32_service" in detail:
            return True
        if "powershell.exe -noprofile -executionpolicy bypass" in detail:
            return True

    # Temp JSON files written by our snapshot modules
    if path_value.endswith(".json") and r"\appdata\local\temp\tmp" in path_value:
        return True

    if "get-scheduledtask" in detail:
        return True

    if "get-ciminstance win32_service" in detail:
        return True

    return False


def summarize_dynamic_findings(
    events: list[dict[str, Any]],
    interesting_events: list[dict[str, Any]],
) -> dict[str, Any]:
    findings: dict[str, Any] = {
        "highlights": [],
        "top_written_paths": [],
        "top_network_processes": [],
        "spawned_processes": [],
        "suspicious_path_hits": [],
        "persistence_hits": [],
        "counts": {},
    }

    filtered_events = [ev for ev in interesting_events if not _is_self_generated_snapshot_activity(ev)]

    file_write_counter: Counter[str] = Counter()
    network_counter: Counter[str] = Counter()
    process_creates: list[dict[str, Any]] = []
    suspicious_path_hits: list[dict[str, Any]] = []
    persistence_hits: list[dict[str, Any]] = []

    for ev in filtered_events:
        category = str(ev.get("category", ""))
        path_value = str(ev.get("path", ""))
        proc_name = str(ev.get("process_name", ""))

        if category == "file_write" and path_value:
            file_write_counter[path_value] += 1

        if category == "network":
            network_counter[proc_name or "<unknown>"] += 1

        if category == "process_create":
            process_creates.append(
                {
                    "timestamp": str(ev.get("timestamp", "")),
                    "process_name": proc_name,
                    "pid": ev.get("pid"),
                    "path": path_value,
                    "detail": str(ev.get("detail", "")),
                    "is_lolbin": _basename(path_value) in LOLBIN_HINTS or _basename(proc_name) in LOLBIN_HINTS,
                }
            )

        if path_value and _path_is_suspicious(path_value):
            suspicious_path_hits.append(
                {
                    "timestamp": str(ev.get("timestamp", "")),
                    "category": category,
                    "process_name": proc_name,
                    "path": path_value,
                    "detail": str(ev.get("detail", "")),
                }
            )

        low_path = path_value.lower()
        if "currentversion\\run" in low_path or "currentversion\\runonce" in low_path:
            persistence_hits.append(
                {
                    "timestamp": str(ev.get("timestamp", "")),
                    "category": category,
                    "process_name": proc_name,
                    "path": path_value,
                    "detail": str(ev.get("detail", "")),
                }
            )

    findings["top_written_paths"] = [
        {"path": path, "count": count}
        for path, count in file_write_counter.most_common(10)
    ]
    findings["top_network_processes"] = [
        {"process_name": name, "count": count}
        for name, count in network_counter.most_common(10)
    ]
    findings["spawned_processes"] = process_creates[:25]
    findings["suspicious_path_hits"] = suspicious_path_hits[:50]
    findings["persistence_hits"] = persistence_hits[:25]

    counts = {
        "interesting_events": len(filtered_events),
        "process_creates": len(process_creates),
        "network_events": sum(network_counter.values()),
        "file_write_events": sum(file_write_counter.values()),
        "suspicious_path_hits": len(suspicious_path_hits),
        "persistence_hits": len(persistence_hits),
        "lolbin_processes": sum(1 for p in process_creates if p.get("is_lolbin")),
    }
    findings["counts"] = counts

    highlights: list[str] = []
    if counts["process_creates"]:
        highlights.append(f"Spawned processes observed: {counts['process_creates']}")
    if counts["lolbin_processes"]:
        highlights.append(f"Potential LOLBin launches observed: {counts['lolbin_processes']}")
    if counts["network_events"]:
        highlights.append(f"Network events observed: {counts['network_events']}")
    if counts["file_write_events"]:
        highlights.append(f"File writes observed: {counts['file_write_events']}")
    if counts["suspicious_path_hits"]:
        highlights.append(f"Suspicious/user-writable path hits: {counts['suspicious_path_hits']}")
    if counts["persistence_hits"]:
        highlights.append(f"Potential autorun persistence hits: {counts['persistence_hits']}")

    findings["highlights"] = highlights
    return findings