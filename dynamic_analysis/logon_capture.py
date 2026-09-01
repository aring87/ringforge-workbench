"""A filtered Procmon capture that is already running when the user logs on.

**The pipeline cannot currently see what a persisted payload does.** Measured
31 Aug on `ce0d08be...`: the detonation watched the sample drop 23 files, install
an `ONLOGON` scheduled task and exit eight seconds in, and scored it *Likely
Malicious, 140, High* on that alone. Everything the RAT actually is -- resident,
beaconing, stealing -- happens in the copy that task launches, and no run has
ever watched it. Every dynamic detector observes one boot, and a payload behind
`ONLOGON`, a logon script or a scheduled trigger is outside all of them.

Boot logging proves such a stage exists and is the wrong instrument for watching
it: the same run produced 4.2 GB of `.pmb` in 65 minutes, a 1.67 GB `.pml` and a
703 MB CSV *with the registry-read filter applied at export*, because boot
logging has no capture-time filter. 65 MB per minute is not a collector, it is a
one-off.

Three decisions here, each of them the reason this works at all.

**The task is `ONSTART`, not `ONLOGON`.** Racing the sample's own `ONLOGON` task
would be a coin toss, and losing it means missing the first seconds -- which is
exactly where `ce0d08be...` did its work both times. `ONSTART` runs as SYSTEM at
boot, before any user session exists, so the capture is already running when the
logon fires. There is no ordering to get right.

**The filter is the run's filter.** `DEFAULT_PROCMON_CONFIG_NAME` --
`dynamic_registry_reads.pmc` -- so a logon capture sees registry reads by
default, the same way a detonation does. The manifest records
`captures_registry_reads` from the file rather than the filename, because a
capture that could not have seen a thing must never read as having seen nothing.

**The Procmon binary is a parameter, and should not be named `procmon`.**
`ce0d08be...` carries a process-name blocklist holding `procmon`, `procexp`,
`processhacker` and `perfmon`; the 31 Aug runs succeeded under a renamed copy.
A payload stage that survives a logon has every opportunity to look.

**Arming is visible to the task diffs, so mind the ordering.** This registers a
real scheduled task and nothing excludes analyzer-owned tasks from
`diff_tasks`. Arm *outside* the window between a run's before and after
snapshots -- after a detonation completes, or before one starts -- and it never
shows as a new task. Arm in the middle and it is reported as persistence, by us.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from dynamic_analysis.procmon_config import describe_procmon_filter

#: The task's name, and the name to look for when something unexplained appears
#: in a task diff. Deliberately not disguised: an analyzer artifact that hides
#: from the analyzer is how a contaminated run becomes an unexplainable one.
TASK_NAME = "RingForgeLogonCapture"

#: Seconds of capture after boot. The payload stage of `ce0d08be...` started
#: 2 seconds after the logon and had installed its persistence 12 seconds later,
#: so the interesting window is short; the default is long enough to also catch
#: a first beacon on the ~18-second interval that sample used.
DEFAULT_WINDOW_SECONDS = 300

#: Guards a window long enough to fill a disk. A filtered capture is far cheaper
#: than boot logging but it is not free.
MAX_WINDOW_SECONDS = 3600


def build_capture_argv(
    python_exe: str | Path,
    script_path: str | Path,
    out_dir: str | Path,
    procmon_path: str | Path,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    config_path: str | Path | None = None,
) -> list[str]:
    """The command the scheduled task runs. Pure, so the tests can read it."""
    argv = [
        str(python_exe),
        str(script_path),
        "--capture",
        "--out", str(out_dir),
        "--procmon", str(procmon_path),
        "--window", str(int(window_seconds)),
    ]
    if config_path:
        argv.extend(["--config", str(config_path)])
    return argv


#: `schtasks` rejects a `/tr` longer than this, and the real command is well
#: over it: an interpreter path, a script path, an output directory, a Procmon
#: path and a `.pmc` path are five absolute paths in one string. Measured at 297
#: characters on the first attempt.
MAX_TR_LENGTH = 261


def write_capture_shim(out_dir: str | Path, capture_argv: list[str]) -> Path:
    """A `.cmd` holding the capture command, so `/tr` stays short.

    The alternative was shortening the command, and every way of doing that
    moves an argument somewhere less visible -- a defaults file, an environment
    variable, a hardcoded path. The shim keeps the whole invocation written down
    in one readable place next to the output it produces, which is also where
    someone debugging a capture that did not run will look first.
    """
    shim = Path(out_dir) / "run_capture.cmd"
    shim.parent.mkdir(parents=True, exist_ok=True)
    shim.write_text(
        "@echo off\r\n" + subprocess.list2cmdline(capture_argv) + "\r\n",
        encoding="utf-8",
    )
    return shim


def build_arm_argv(command: str, task_name: str = TASK_NAME) -> list[str]:
    """`schtasks /create` for an ONSTART task running as SYSTEM.

    `/rl HIGHEST` because Procmon needs administrator to load its driver, and
    `/ru SYSTEM` because the capture has to exist before any user session does.
    `/f` so re-arming replaces rather than failing, which is what an operator
    re-running this actually means.
    """
    return [
        "schtasks", "/create",
        "/tn", task_name,
        "/sc", "ONSTART",
        "/ru", "SYSTEM",
        "/rl", "HIGHEST",
        "/f",
        "/tr", command,
    ]


def build_disarm_argv(task_name: str = TASK_NAME) -> list[str]:
    return ["schtasks", "/delete", "/tn", task_name, "/f"]


def build_status_argv(task_name: str = TASK_NAME) -> list[str]:
    return ["schtasks", "/query", "/tn", task_name, "/v", "/fo", "LIST"]


def empty_manifest(reason: str) -> dict[str, Any]:
    """The shape a capture that never happened still reports.

    `completed: False` with a reason, never an empty event list that reads like
    a quiet boot. The distinction this module exists to preserve at the run
    level is the same one it has to preserve about itself.
    """
    return {
        "completed": False,
        "reason": reason,
        "task_name": TASK_NAME,
        "window_seconds": 0,
        "started_at": "",
        "ended_at": "",
        "backing_file": "",
        "csv_path": "",
        "csv_bytes": 0,
        "procmon_filter": describe_procmon_filter(None),
    }


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def run_capture(
    out_dir: str | Path,
    procmon_path: str | Path,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    config_path: str | Path | None = None,
    sleep=time.sleep,
) -> dict[str, Any]:
    """Start Procmon, hold it open for the window, then stop and export.

    This is what the task runs, so it is also the only part that must not raise:
    a scheduled task that dies leaves no manifest, and a missing manifest is
    indistinguishable from a boot where nothing happened. Every failure is
    caught and written down instead.
    """
    from dynamic_analysis.procmon_runner import (
        export_procmon_csv,
        start_procmon_capture,
        terminate_procmon_capture,
    )

    window = max(1, min(int(window_seconds), MAX_WINDOW_SECONDS))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    backing = out / "logon_capture.pml"
    csv_path = out / "logon_capture.csv"
    manifest_path = out / "logon_capture.json"

    manifest = empty_manifest("capture did not start")
    manifest["window_seconds"] = window
    manifest["backing_file"] = str(backing)
    manifest["csv_path"] = str(csv_path)
    manifest["procmon_filter"] = describe_procmon_filter(config_path)

    try:
        manifest["started_at"] = _now()
        start_procmon_capture(procmon_path, backing, config_path=config_path)
        sleep(window)
        terminate_procmon_capture(procmon_path)
        export_procmon_csv(procmon_path, backing, csv_path)
        manifest["completed"] = True
        manifest["reason"] = ""
        manifest["csv_bytes"] = csv_path.stat().st_size if csv_path.exists() else 0
    except Exception as error:  # noqa: BLE001 -- see the docstring
        manifest["reason"] = f"{type(error).__name__}: {error}"
    finally:
        manifest["ended_at"] = _now()
        try:
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        except OSError:
            pass

    return manifest


def _run(argv: list[str]) -> dict[str, Any]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    except Exception as error:  # noqa: BLE001
        return {"ok": False, "returncode": None, "stdout": "", "stderr": str(error)}
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "stdout": (result.stdout or "").strip(),
        "stderr": (result.stderr or "").strip(),
    }


def arm(
    out_dir: str | Path,
    procmon_path: str | Path,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    config_path: str | Path | None = None,
    python_exe: str | Path | None = None,
    script_path: str | Path | None = None,
) -> dict[str, Any]:
    capture_argv = build_capture_argv(
        python_exe or sys.executable,
        script_path or Path(__file__).resolve().parent.parent / "scripts" / "logon_capture.py",
        out_dir,
        procmon_path,
        window_seconds,
        config_path,
    )
    shim = write_capture_shim(out_dir, capture_argv)
    result = _run(build_arm_argv(str(shim)))
    result["command"] = subprocess.list2cmdline(capture_argv)
    result["shim"] = str(shim)
    result["task_name"] = TASK_NAME
    return result


def disarm() -> dict[str, Any]:
    return _run(build_disarm_argv())


def status() -> dict[str, Any]:
    result = _run(build_status_argv())
    result["armed"] = result["ok"]
    return result
