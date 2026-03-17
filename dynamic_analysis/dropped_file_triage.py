from __future__ import annotations

from pathlib import Path
from typing import Any

from dynamic_analysis.utils import file_size, md5_file, sha1_file, sha256_file


DROPPED_FILE_EXTENSIONS = {
    ".exe": "executable",
    ".dll": "library",
    ".sys": "driver",
    ".ps1": "powershell_script",
    ".bat": "batch_script",
    ".cmd": "batch_script",
    ".js": "javascript",
    ".jse": "javascript",
    ".vbs": "vbscript",
    ".vbe": "vbscript",
    ".hta": "html_application",
    ".scr": "screensaver_executable",
    ".com": "executable",
    ".pif": "program_information_file",
    ".jar": "java_archive",
    ".msi": "windows_installer",
}

SUSPICIOUS_PATH_KEYWORDS = [
    r"\appdata\\",
    r"\temp\\",
    r"\programdata\\",
    r"\startup\\",
    r"\users\public\\",
]

EXCLUDED_PATH_PREFIXES = [
    r"c:\windows\system32\\",
    r"c:\windows\winsxs\\",
    r"c:\windows\servicing\\",
    r"c:\windows\installer\\",
    r"c:\program files\\",
    r"c:\program files (x86)\\",
]

ALLOWED_EVENT_CATEGORIES = {
    "file_create",
    "file_write",
}


def normalize_windows_path(path_value: str) -> str:
    return str(Path(path_value))


def looks_like_candidate_file(path_value: str) -> bool:
    p = str(path_value).strip()
    if not p:
        return False

    ext = Path(p).suffix.lower()
    return ext in DROPPED_FILE_EXTENSIONS


def path_is_in_suspicious_location(path_value: str) -> bool:
    p = path_value.lower()
    return any(keyword in p for keyword in SUSPICIOUS_PATH_KEYWORDS)


def path_is_excluded(path_value: str) -> bool:
    p = path_value.lower()
    return any(p.startswith(prefix) for prefix in EXCLUDED_PATH_PREFIXES)


def classify_path(path_value: str) -> str:
    ext = Path(path_value).suffix.lower()
    return DROPPED_FILE_EXTENSIONS.get(ext, "unknown")


def collect_dropped_file_candidates(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    candidates: list[dict[str, Any]] = []

    for event in events:
        category = str(event.get("category", ""))
        path_value = str(event.get("path", "")).strip()

        if category not in ALLOWED_EVENT_CATEGORIES:
            continue

        if not looks_like_candidate_file(path_value):
            continue

        norm = normalize_windows_path(path_value)
        norm_key = norm.lower()

        if path_is_excluded(norm):
            continue

        suspicious_location = path_is_in_suspicious_location(norm)

        # Keep only clearly suspicious/user-writable style locations for v1.
        if not suspicious_location:
            continue

        if norm_key in seen:
            continue

        seen.add(norm_key)

        candidates.append(
            {
                "path": norm,
                "extension": Path(norm).suffix.lower(),
                "classification": classify_path(norm),
                "source_category": category,
                "source_process_name": str(event.get("process_name", "")),
                "source_pid": event.get("pid"),
                "timestamp": str(event.get("timestamp", "")),
                "suspicious_path": suspicious_location,
            }
        )

    return candidates


def enrich_dropped_files(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []

    for item in candidates:
        path_str = str(item["path"])
        p = Path(path_str)

        exists = p.exists()
        record = dict(item)
        record["exists_on_disk"] = exists

        if exists and p.is_file():
            try:
                record["size"] = file_size(p)
                record["md5"] = md5_file(p)
                record["sha1"] = sha1_file(p)
                record["sha256"] = sha256_file(p)
            except Exception as e:
                record["hash_error"] = str(e)
                record["size"] = None
                record["md5"] = None
                record["sha1"] = None
                record["sha256"] = None
        else:
            record["size"] = None
            record["md5"] = None
            record["sha1"] = None
            record["sha256"] = None

        reasons: list[str] = []
        if record.get("suspicious_path"):
            reasons.append("path_in_suspicious_location")

        classification = str(record.get("classification", ""))
        if classification in {
            "executable",
            "library",
            "driver",
            "powershell_script",
            "batch_script",
            "javascript",
            "vbscript",
            "html_application",
            "screensaver_executable",
        }:
            reasons.append(f"classification:{classification}")

        record["reasons"] = reasons
        record["suspicious"] = len(reasons) > 0

        enriched.append(record)

    return enriched


def summarize_dropped_files(items: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "total_candidates": len(items),
        "existing_on_disk": 0,
        "missing_on_disk": 0,
        "suspicious": 0,
    }

    for item in items:
        if item.get("exists_on_disk"):
            summary["existing_on_disk"] += 1
        else:
            summary["missing_on_disk"] += 1

        if item.get("suspicious"):
            summary["suspicious"] += 1

    return summary