from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


INTERESTING_OPS = {
    "Process Create": "process_create",
    "CreateFile": "file_create",
    "WriteFile": "file_write",
    "SetDispositionInformationFile": "file_delete_or_disposition",
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
    r"\appdata\\",
    r"\temp\\",
    r"\programdata\\",
    r"\startup\\",
    r"\users\public\\",
    r"currentversion\run",
    r"currentversion\runonce",
]


HIGH_VALUE_CATEGORIES = {
    "process_create",
    "image_load",
    "network",
    "registry_set",
    "registry_delete",
    "file_write",
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


def filter_events_by_category(
    events: list[dict[str, Any]],
    category: str,
) -> list[dict[str, Any]]:
    return [e for e in events if e.get("category") == category]


def filter_events_by_path_keyword(
    events: list[dict[str, Any]],
    keyword: str,
) -> list[dict[str, Any]]:
    k = keyword.lower()
    return [e for e in events if k in str(e.get("path", "")).lower()]


def is_suspicious_path(path: str) -> bool:
    p = path.lower()
    return any(keyword in p for keyword in SUSPICIOUS_PATH_KEYWORDS)


def find_interesting_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    interesting: list[dict[str, Any]] = []

    for event in events:
        category = str(event.get("category", "other"))
        path = str(event.get("path", ""))

        if category in HIGH_VALUE_CATEGORIES:
            interesting.append(event)
            continue

        if path and is_suspicious_path(path):
            interesting.append(event)
            continue

    return interesting


def summarize_interesting_events(events: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for event in events:
        category = str(event.get("category", "other"))
        summary[category] = summary.get(category, 0) + 1
    return summary