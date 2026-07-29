"""Scheduled task snapshots for persistence diffing.

Two collection paths are supported:

``Get-ScheduledTask``
    Rich output including triggers and principals. Requires the
    ``Root\\Microsoft\\Windows\\TaskScheduler`` CIM namespace.
``schtasks.exe /query``
    Coarser, but depends only on the Task Scheduler service. Debloated or
    stripped Windows images -- common as analysis VM bases -- frequently lack
    the CIM namespace, and there the classic tool still works.

Neither path raises. A failed snapshot degrades to an empty list with a
recorded reason, because losing task telemetry must not abort a detonation
that is also collecting Procmon, Sysmon and network data.
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


TASK_SNAPSHOT_PS_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$outFile = "{out_file}"

$tasks = Get-ScheduledTask | ForEach-Object {{
    $task = $_

    $actions = @()
    foreach ($a in ($task.Actions | Where-Object {{ $_ -ne $null }})) {{
        $actions += [PSCustomObject]@{{
            Execute = $a.Execute
            Arguments = $a.Arguments
            WorkingDirectory = $a.WorkingDirectory
        }}
    }}

    $triggers = @()
    foreach ($t in ($task.Triggers | Where-Object {{ $_ -ne $null }})) {{
        $repInterval = $null
        $repDuration = $null
        if ($t.Repetition) {{
            $repInterval = $t.Repetition.Interval
            $repDuration = $t.Repetition.Duration
        }}

        $triggers += [PSCustomObject]@{{
            Enabled = $t.Enabled
            StartBoundary = $t.StartBoundary
            EndBoundary = $t.EndBoundary
            ExecutionTimeLimit = $t.ExecutionTimeLimit
            RepetitionInterval = $repInterval
            RepetitionDuration = $repDuration
            TriggerType = $t.CimClass.CimClassName
        }}
    }}

    [PSCustomObject]@{{
        TaskName = $task.TaskName
        TaskPath = $task.TaskPath
        State = [string]$task.State
        Author = $task.Author
        Description = $task.Description
        URI = $task.URI
        PrincipalUserId = $task.Principal.UserId
        RunLevel = [string]$task.Principal.RunLevel
        LogonType = [string]$task.Principal.LogonType
        Hidden = [bool]$task.Settings.Hidden
        Enabled = [bool]$task.Settings.Enabled
        MultipleInstances = [string]$task.Settings.MultipleInstances
        Actions = $actions
        Triggers = $triggers
    }}
}}

$tasks | ConvertTo-Json -Depth 8 | Set-Content -Path $outFile -Encoding UTF8
Write-Output $outFile
"""


def _run_powershell_json_to_file() -> Any:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp_path = Path(tmp.name)

    script = TASK_SNAPSHOT_PS_TEMPLATE.format(
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
            f"PowerShell task snapshot failed. rc={result.returncode} stderr={result.stderr.strip()}"
        )

    if not tmp_path.exists():
        raise RuntimeError("Scheduled task snapshot JSON file was not created.")

    raw = tmp_path.read_text(encoding="utf-8-sig").strip()
    tmp_path.unlink(missing_ok=True)

    if not raw:
        return []

    data = json.loads(raw)
    if isinstance(data, dict):
        return [data]
    return data


def normalize_task_item(item: dict[str, Any]) -> dict[str, Any]:
    actions = item.get("Actions") or []
    triggers = item.get("Triggers") or []

    return {
        "task_name": str(item.get("TaskName", "") or ""),
        "task_path": str(item.get("TaskPath", "") or ""),
        "state": str(item.get("State", "") or ""),
        "author": str(item.get("Author", "") or ""),
        "description": str(item.get("Description", "") or ""),
        "uri": str(item.get("URI", "") or ""),
        "principal_user_id": str(item.get("PrincipalUserId", "") or ""),
        "run_level": str(item.get("RunLevel", "") or ""),
        "logon_type": str(item.get("LogonType", "") or ""),
        "hidden": bool(item.get("Hidden", False)),
        "enabled": bool(item.get("Enabled", False)),
        "multiple_instances": str(item.get("MultipleInstances", "") or ""),
        "actions": [
            {
                "execute": str(a.get("Execute", "") or ""),
                "arguments": str(a.get("Arguments", "") or ""),
                "working_directory": str(a.get("WorkingDirectory", "") or ""),
            }
            for a in actions
        ],
        "triggers": [
            {
                "enabled": bool(t.get("Enabled", False)),
                "start_boundary": str(t.get("StartBoundary", "") or ""),
                "end_boundary": str(t.get("EndBoundary", "") or ""),
                "execution_time_limit": str(t.get("ExecutionTimeLimit", "") or ""),
                "repetition_interval": str(t.get("RepetitionInterval", "") or ""),
                "repetition_duration": str(t.get("RepetitionDuration", "") or ""),
                "trigger_type": str(t.get("TriggerType", "") or ""),
            }
            for t in triggers
        ],
    }


def _split_task_path(full_name: str) -> tuple[str, str]:
    """Split ``\\Microsoft\\Windows\\Foo\\Bar`` into path and leaf name."""
    value = (full_name or "").strip()
    if not value:
        return "", ""
    if not value.startswith("\\"):
        value = "\\" + value
    head, _, leaf = value.rpartition("\\")
    return (head + "\\") if head else "\\", leaf


def _snapshot_via_schtasks() -> list[dict[str, Any]]:
    """Fallback snapshot using schtasks.exe, which does not touch CIM."""
    result = subprocess.run(
        ["schtasks.exe", "/query", "/fo", "CSV", "/v"],
        capture_output=True,
        text=True,
        timeout=180,
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"schtasks query failed. rc={result.returncode} stderr={(result.stderr or '').strip()}"
        )

    text = (result.stdout or "").strip()
    if not text:
        return []

    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return []

    header = [h.strip().lower() for h in rows[0]]

    def column(row: list[str], *names: str) -> str:
        for name in names:
            if name in header:
                index = header.index(name)
                if index < len(row):
                    return (row[index] or "").strip()
        return ""

    tasks: list[dict[str, Any]] = []
    for row in rows[1:]:
        if not row:
            continue
        # schtasks repeats its header between folders; skip those rows.
        if [c.strip().lower() for c in row] == header:
            continue

        full_name = column(row, "taskname")
        if not full_name and len(row) > 1:
            full_name = (row[1] or "").strip()
        if not full_name or full_name.lower() == "taskname":
            continue

        task_path, task_name = _split_task_path(full_name)
        run_command = column(row, "task to run")

        tasks.append(
            {
                "task_name": task_name,
                "task_path": task_path,
                "state": column(row, "scheduled task state", "status"),
                "author": column(row, "author"),
                "description": column(row, "comment"),
                "uri": full_name,
                "principal_user_id": column(row, "run as user"),
                "run_level": "",
                "logon_type": column(row, "logon mode"),
                "hidden": False,
                "enabled": column(row, "scheduled task state").lower() != "disabled",
                "multiple_instances": "",
                "actions": (
                    [{"execute": run_command, "arguments": "", "working_directory": column(row, "start in")}]
                    if run_command
                    else []
                ),
                "triggers": (
                    [
                        {
                            "enabled": True,
                            "start_boundary": column(row, "start time"),
                            "end_boundary": column(row, "end date"),
                            "execution_time_limit": "",
                            "repetition_interval": column(row, "repeat: every"),
                            "repetition_duration": column(row, "repeat: until: duration"),
                            "trigger_type": column(row, "schedule type"),
                        }
                    ]
                    if column(row, "schedule type")
                    else []
                ),
            }
        )

    return tasks


def snapshot_scheduled_tasks_with_status() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Snapshot scheduled tasks, reporting which method succeeded.

    Returns ``(tasks, status)``. ``status`` names the method used and carries
    any errors, so a degraded snapshot is visible in the report rather than
    silently looking like "no scheduled tasks changed".
    """
    status: dict[str, Any] = {"success": False, "method": "", "error": "", "fallback_used": False}
    errors: list[str] = []

    try:
        raw = _run_powershell_json_to_file()
        tasks = [normalize_task_item(item) for item in raw]
        tasks.sort(key=lambda x: (x.get("task_path", ""), x.get("task_name", "")))
        status.update({"success": True, "method": "Get-ScheduledTask"})
        return tasks, status
    except Exception as error:
        errors.append(f"Get-ScheduledTask: {error}")

    try:
        tasks = _snapshot_via_schtasks()
        tasks.sort(key=lambda x: (x.get("task_path", ""), x.get("task_name", "")))
        status.update(
            {
                "success": True,
                "method": "schtasks.exe",
                "fallback_used": True,
                "error": errors[0] if errors else "",
            }
        )
        return tasks, status
    except Exception as error:
        errors.append(f"schtasks.exe: {error}")

    status["error"] = " | ".join(errors)
    return [], status


def snapshot_scheduled_tasks() -> list[dict[str, Any]]:
    """Backwards-compatible wrapper returning just the task list."""
    tasks, _status = snapshot_scheduled_tasks_with_status()
    return tasks


def task_identity(task: dict[str, Any]) -> str:
    return f"{task.get('task_path', '')}{task.get('task_name', '')}"