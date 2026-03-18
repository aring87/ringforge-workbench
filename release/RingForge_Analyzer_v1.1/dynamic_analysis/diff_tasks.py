from __future__ import annotations

from pathlib import Path
from typing import Any

from dynamic_analysis.snapshot_tasks import task_identity


SUSPICIOUS_EXECUTABLE_HINTS = {
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
}

SUSPICIOUS_PATH_HINTS = [
    r"\appdata\\",
    r"\temp\\",
    r"\programdata\\",
    r"\users\public\\",
    r"\startup\\",
]


def _norm(s: Any) -> str:
    return str(s or "").strip()


def _basename(path_value: str) -> str:
    try:
        return Path(path_value).name.lower()
    except Exception:
        return path_value.lower()


def _path_is_suspicious(path_value: str) -> bool:
    p = path_value.lower()
    return any(h in p for h in SUSPICIOUS_PATH_HINTS)


def _task_is_suspicious(task: dict[str, Any]) -> list[str]:
    reasons: list[str] = []

    if task.get("hidden"):
        reasons.append("hidden_task")

    triggers = task.get("triggers", [])
    for trig in triggers:
        trig_type = _norm(trig.get("trigger_type"))
        if trig_type:
            low = trig_type.lower()
            if "logon" in low:
                reasons.append("logon_trigger")
            if "boot" in low:
                reasons.append("boot_trigger")

    actions = task.get("actions", [])
    for act in actions:
        execute = _norm(act.get("execute"))
        arguments = _norm(act.get("arguments"))
        working_directory = _norm(act.get("working_directory"))

        base = _basename(execute)
        if base in SUSPICIOUS_EXECUTABLE_HINTS:
            reasons.append(f"lolbin:{base}")

        if execute and _path_is_suspicious(execute):
            reasons.append("execute_in_suspicious_path")

        if arguments and _path_is_suspicious(arguments):
            reasons.append("arguments_reference_suspicious_path")

        if working_directory and _path_is_suspicious(working_directory):
            reasons.append("working_directory_in_suspicious_path")

    # Deduplicate while keeping order
    deduped: list[str] = []
    seen = set()
    for r in reasons:
        if r not in seen:
            seen.add(r)
            deduped.append(r)

    return deduped


def diff_scheduled_tasks(
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> dict[str, Any]:
    before_map = {task_identity(t): t for t in before}
    after_map = {task_identity(t): t for t in after}

    before_keys = set(before_map.keys())
    after_keys = set(after_map.keys())

    new_keys = sorted(after_keys - before_keys)
    removed_keys = sorted(before_keys - after_keys)
    common_keys = sorted(before_keys & after_keys)

    new_tasks: list[dict[str, Any]] = []
    removed_tasks: list[dict[str, Any]] = []
    modified_tasks: list[dict[str, Any]] = []

    for key in new_keys:
        task = after_map[key]
        reasons = _task_is_suspicious(task)
        new_tasks.append(
            {
                "identity": key,
                "task_name": task.get("task_name", ""),
                "task_path": task.get("task_path", ""),
                "hidden": task.get("hidden", False),
                "enabled": task.get("enabled", False),
                "actions": task.get("actions", []),
                "triggers": task.get("triggers", []),
                "suspicious": len(reasons) > 0,
                "reasons": reasons,
            }
        )

    for key in removed_keys:
        task = before_map[key]
        removed_tasks.append(
            {
                "identity": key,
                "task_name": task.get("task_name", ""),
                "task_path": task.get("task_path", ""),
            }
        )

    for key in common_keys:
        b = before_map[key]
        a = after_map[key]

        if b != a:
            reasons = _task_is_suspicious(a)
            modified_tasks.append(
                {
                    "identity": key,
                    "task_name": a.get("task_name", ""),
                    "task_path": a.get("task_path", ""),
                    "before": b,
                    "after": a,
                    "suspicious": len(reasons) > 0,
                    "reasons": reasons,
                }
            )

    summary = {
        "new_tasks": new_tasks,
        "removed_tasks": removed_tasks,
        "modified_tasks": modified_tasks,
        "counts": {
            "new_tasks": len(new_tasks),
            "removed_tasks": len(removed_tasks),
            "modified_tasks": len(modified_tasks),
            "suspicious_new_or_modified": sum(
                1 for t in (new_tasks + modified_tasks) if t.get("suspicious")
            ),
        },
    }

    return summary