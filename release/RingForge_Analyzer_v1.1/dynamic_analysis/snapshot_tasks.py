from __future__ import annotations

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


def snapshot_scheduled_tasks() -> list[dict[str, Any]]:
    raw = _run_powershell_json_to_file()
    normalized = [normalize_task_item(item) for item in raw]
    normalized.sort(key=lambda x: (x.get("task_path", ""), x.get("task_name", "")))
    return normalized


def task_identity(task: dict[str, Any]) -> str:
    return f"{task.get('task_path', '')}{task.get('task_name', '')}"