from __future__ import annotations

import csv
from pathlib import Path, PureWindowsPath
from typing import Any


INTERESTING_OPS = {
    "Process Create": "process_create",
    "CreateFile": "file_create",
    "WriteFile": "file_write",
    "SetDispositionInformationFile": "file_delete_or_disposition",
    "SetRenameInformationFile": "file_write",
    "RegCreateKey": "registry_create",
    "RegSetValue": "registry_set",
    "RegDeleteValue": "registry_delete",
    "RegDeleteKey": "registry_delete",
    "Load Image": "image_load",
    "TCP Connect": "network",
    "TCP Receive": "network",
    "TCP Send": "network",
    "UDP Send": "network",
    "UDP Receive": "network",
}

SUSPICIOUS_PATH_KEYWORDS = [
    r"\appdata\roaming\microsoft\windows\start menu\programs\startup",
    r"\windows\system32\tasks",
    r"\windows\tasks",
    r"currentversion\run",
    r"currentversion\runonce",
    r"\currentcontrolset\services\\",
]

USER_WRITABLE_MARKERS = [
    r"\users\\",
    r"\programdata\\",
    r"\appdata\\",
    r"\temp\\",
    r"\users\public\\",
]

EXECUTION_RELATED_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".ps1",
    ".bat",
    ".cmd",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".hta",
    ".scr",
    ".com",
    ".pif",
    ".jar",
    ".msi",
}

NOISE_PATH_SUBSTRINGS = (
    r"\programdata\microsoft\windows defender\\",
    r"\programdata\microsoft\windows defender advanced threat protection\\",
    r"\windows\system32\wbem\\",
    r"\windows\debug\wia\\",
    r"\appdata\local\temp\tmp",
    r"\cases\\",
    r"\procmon\\",
    r"\metadata\\",
    r"\files\\",
    r"\persistence\\",
)

NOISE_PROCESSES = {
    "msmpeng.exe",
    "nisserv.exe",
    "wmiprvse.exe",
    "consent.exe",
    "ctfmon.exe",
    "dllhost.exe",
    "backgroundtaskhost.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "runtimebroker.exe",
}

HIGH_VALUE_CATEGORIES = {
    "process_create",
    "network",
    "registry_set",
    "registry_delete",
}


def normalize_procmon_row(row: dict[str, str]) -> dict[str, Any]:
    operation = row.get("Operation", "").strip()
    category = INTERESTING_OPS.get(operation, "other")

    pid_raw = row.get("PID", "").strip()
    try:
        pid = int(pid_raw)
    except ValueError:
        pid = None

    return {
        "timestamp": row.get("Time of Day", "").strip(),
        "process_name": row.get("Process Name", "").strip(),
        "pid": pid,
        "operation": operation,
        "path": row.get("Path", "").strip(),
        "result": row.get("Result", "").strip(),
        "detail": row.get("Detail", "").strip(),
        "category": category,
    }


def parse_procmon_csv(csv_path: str | Path) -> list[dict[str, Any]]:
    csv_file = Path(csv_path)
    events: list[dict[str, Any]] = []

    with csv_file.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(normalize_procmon_row(row))

    return events


def summarize_procmon_events(events: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for event in events:
        category = str(event.get("category", "other"))
        summary[category] = summary.get(category, 0) + 1
    return summary


def filter_events_by_category(events: list[dict[str, Any]], category: str) -> list[dict[str, Any]]:
    return [e for e in events if e.get("category") == category]


def filter_events_by_path_keyword(events: list[dict[str, Any]], keyword: str) -> list[dict[str, Any]]:
    k = keyword.lower()
    return [e for e in events if k in str(e.get("path", "")).lower()]


def _normalize_lower(value: object) -> str:
    return str(value or "").strip().lower()


def _path_suffix(path_value: object) -> str:
    try:
        return PureWindowsPath(str(path_value or "").strip()).suffix.lower()
    except Exception:
        return ""


def _is_noise_process(process_name: str) -> bool:
    return _normalize_lower(process_name) in NOISE_PROCESSES


def _is_noise_path(path: str) -> bool:
    lowered = _normalize_lower(path)
    return any(part in lowered for part in NOISE_PATH_SUBSTRINGS)


def is_suspicious_path(path: str) -> bool:
    p = path.lower()
    return any(keyword in p for keyword in SUSPICIOUS_PATH_KEYWORDS)


def _path_is_user_writable(path: str) -> bool:
    p = path.lower()
    return any(keyword in p for keyword in USER_WRITABLE_MARKERS)


def _path_is_executable_or_script(path: str) -> bool:
    return _path_suffix(path) in EXECUTION_RELATED_EXTENSIONS


def _is_high_signal_event(event: dict[str, Any]) -> bool:
    category = str(event.get("category", "other"))
    operation = _normalize_lower(event.get("operation"))
    path = str(event.get("path", "") or "")
    process_name = str(event.get("process_name", "") or "")

    if _is_noise_process(process_name) or _is_noise_path(path):
        return False

    if category == "process_create":
        return True

    if category == "network":
        return operation == "tcp connect"

    if category in {"registry_set", "registry_delete"}:
        return is_suspicious_path(path)

    if category == "file_write":
        return is_suspicious_path(path) or (_path_is_user_writable(path) and _path_is_executable_or_script(path))

    if category == "image_load":
        return is_suspicious_path(path) or (_path_is_user_writable(path) and _path_is_executable_or_script(path))

    if category == "file_create":
        return _path_is_user_writable(path) and _path_is_executable_or_script(path)

    if path and is_suspicious_path(path):
        return True

    return False


def find_interesting_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event for event in events if _is_high_signal_event(event)]


def summarize_interesting_events(events: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for event in events:
        category = str(event.get("category", "other"))
        summary[category] = summary.get(category, 0) + 1
    return summary
