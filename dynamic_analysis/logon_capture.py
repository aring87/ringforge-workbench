"""A filtered Procmon capture, started early enough to see a persisted payload.

**The pipeline cannot currently see what a persisted payload does.** Measured
31 Aug on `ce0d08be...`: the detonation watched the sample drop 23 files, install
an `ONLOGON` scheduled task and exit eight seconds in, and scored it *Likely
Malicious, 140, High* on that alone. Everything the RAT actually is -- resident,
beaconing, stealing -- happens in the copy that task launches, and no run has
ever watched it. Every dynamic detector observes one boot, and a payload behind
`ONLOGON`, a logon script or a scheduled trigger is outside all of them.

Boot logging proves such a stage exists and is the wrong instrument for watching
it: the same run produced 4.2 GB of `.pmb` in 65 minutes, because boot logging
has no capture-time filter. 65 MB per minute is not a collector, it is a one-off.

**The first proving run failed, and what it falsified is recorded here rather
than fixed quietly.** `ONSTART` was chosen over `ONLOGON` on the reasoning that
it "runs as SYSTEM at boot, before any user session exists, so there is no
ordering to get right". That is wrong in practice. Measured 31 Aug:

    21:32:55   the sample's ONLOGON payload started
    21:36:46   this capture started

Task Scheduler delays and throttles boot-triggered tasks, and ours landed almost
four minutes late -- against a payload that is up 2 seconds after the logon and
finished persisting 12 seconds later. `ONSTART` is *earlier* than `ONLOGON`, it
is not *early*. `seconds_after_boot` is now in every manifest so the margin is
measured on each run instead of assumed.

**The trigger is no longer the answer, because the race is gone.** The two
candidates that followed from the failure -- a boot-start service, or a filtered
boot log -- are both attempts to *win* the race, and either would leave a margin
that has to be re-proven on every sample. The gate removes it instead:
`set_autologon(False)` before the boot, so the guest stops at the sign-in screen
and no logon session exists for the sample's `ONLOGON` task to trigger on. The
capture starts whenever Task Scheduler gets round to it, confirms its own
backing file, and sets `READY_PROPERTY`; `scripts/vm_gated_logon.ps1` on the
host waits for that and types the credentials. Being late stops mattering.
Being first does not, and it is now guaranteed rather than hoped for.

The claim that replaces "ONSTART runs early" is checkable after every run:
`ready_seconds_after_boot` here, against `payload.seconds_after_boot` from
`sysmon_since_boot.py`. The second must be the larger. If it is not, the run
says nothing about the payload's first seconds whatever it recorded.

**Still unproven, and not to be assumed twice: Procmon has never been watched
capturing from session 0.** Both modals that blocked the first attempt are
cleared before launch now, but "the modals were the only problem" is a
hypothesis of exactly the shape that cost the last run. Prove it on the clean
baseline with `vm_gated_logon.ps1 -ProveChannel` before arming anything. If
session 0 is a wall, the gate still holds -- a second local account lets
Procmon run interactively in an operator session while the target user's logon,
and only that logon, starts the payload.

**Procmon asks questions nobody in session 0 can answer.** Two modals blocked
the first run, and `/Quiet` suppresses neither: a leftover `%WINDIR%\\Procmon.pmb`
("save the collected data?") and an existing backing file ("okay to
overwrite?"). Both are checked before launch. The backing file is ours and is
removed; the boot log is not ours, so it is reported as a refusal with the
remedy rather than deleted out from under whoever armed it.

**And the collector has to verify itself.** `start_procmon_capture` sleeps three
seconds and checks nothing, so both dialogs presented as a capture that reported
success and recorded a 300-second silence -- the exact failure this package
exists to prevent, committed by the thing meant to prevent it. The backing file
is now checked after launch, which turns five minutes of nothing into an
accurate failure in a few seconds.
"""

from __future__ import annotations

import ctypes
import json
import os
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

#: Seconds of capture after the task fires. The payload stage of `ce0d08be...`
#: started 2 seconds after the logon and had installed its persistence 12
#: seconds later, so the interesting window is short; the default is long enough
#: to also catch a first beacon on the ~18-second interval that sample used.
DEFAULT_WINDOW_SECONDS = 300

#: Guards a window long enough to fill a disk. A filtered capture is far cheaper
#: than boot logging but it is not free.
MAX_WINDOW_SECONDS = 3600

#: `schtasks` rejects a `/tr` longer than this, and the real command is well
#: over it: an interpreter path, a script path, an output directory, a Procmon
#: path and a `.pmc` path are five absolute paths in one string. Measured at 297
#: characters on the first attempt.
MAX_TR_LENGTH = 261

#: Procmon's boot log. Its presence raises a modal on *any* Procmon start.
BOOT_LOG = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Procmon.pmb"

#: How long to wait for Procmon to preallocate its backing file. It reserves
#: 256 MB up front, so the file appears almost immediately when Procmon is
#: actually running -- and never when it is sitting on a dialog.
BACKING_FILE_TIMEOUT_SECONDS = 15


def seconds_since_boot() -> int | None:
    """Uptime, so a manifest can say how late the capture was.

    The whole `ONSTART` premise is a claim about this number and nothing was
    measuring it. ``None`` off Windows, where the counter does not exist.
    """
    try:
        return int(ctypes.windll.kernel32.GetTickCount64() // 1000)
    except (AttributeError, OSError):
        return None


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
    `/ru SYSTEM` because the capture should exist before a user session does.
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


def check_blocking_prompts(backing_file: str | Path, boot_log: Path = BOOT_LOG) -> dict[str, Any]:
    """Clear what we own, refuse on what we do not.

    Both modals stop an unattended capture dead, and `/Quiet` suppresses
    neither. The backing file is this run's own output and is removed. The boot
    log belongs to whoever armed boot logging, may be the only copy of a boot
    nobody can repeat, and is worth more than one capture -- so it is refused
    with the remedy rather than deleted.
    """
    result: dict[str, Any] = {"removed_backing_file": False, "blocked_by": "", "remedy": ""}

    backing = Path(backing_file)
    if backing.exists():
        try:
            backing.unlink()
            result["removed_backing_file"] = True
        except OSError as error:
            result["blocked_by"] = f"existing backing file that could not be removed: {error}"
            result["remedy"] = f"delete {backing}"
            return result

    if boot_log.exists():
        result["blocked_by"] = (
            f"a Procmon boot log at {boot_log}, which raises a modal on every "
            "Procmon start and cannot be answered from a scheduled task"
        )
        result["remedy"] = (
            f"convert it in the Procmon GUI, or delete {boot_log} if it is not wanted"
        )

    return result


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------
#
# The first proving run tried to make the capture *early*. It cannot be: Task
# Scheduler delays boot-triggered tasks, ours landed 3m51s after boot, and the
# payload was up 2 seconds after the logon. Nothing about the trigger fixes
# that, because the trigger is not the problem -- the race is.
#
# So there is no race. `AutoAdminLogon` is turned off before the boot, which
# means no logon happens, which means the sample's `ONLOGON` task does not
# fire. The capture starts whenever Task Scheduler gets round to it, verifies
# its own backing file, and only then signals the host, which types the
# credentials at the sign-in screen. The payload starts inside a capture that
# is already known to be running.
#
# The capture being late stops mattering. What replaces it is a number that can
# be checked: the payload's start minus the capture's ready, measured on every
# run, positive by construction or the run is void.
#
# **What is still unproven, and must not be assumed a second time.** Nobody has
# yet seen Procmon capture successfully from session 0. The first attempt died
# on two modals, both of which are now cleared before launch -- but "the modals
# were the only problem" is a hypothesis, and it is exactly the shape of the
# `ONSTART` claim that cost the last run. Prove it on the clean baseline before
# arming anything. If session 0 turns out to be the wall, the gate still holds:
# a second local account lets Procmon run interactively in an operator session
# while the target user's logon -- and only that logon -- fires the payload.

#: The host reads this to learn that the capture is up. A guest property rather
#: than a file: it works from session 0, needs no shared folder mounted in a
#: session that does not exist, and carries no code in either direction.
READY_PROPERTY = "/RingForge/CaptureReady"

#: Where Guest Additions puts VBoxControl. Checked in order.
VBOXCONTROL_PATHS = (
    r"C:\Windows\System32\VBoxControl.exe",
    r"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxControl.exe",
)

#: `HKLM\...\Winlogon`, where automatic logon lives. `vm_hygiene.ps1` writes
#: these; this only flips the switch and puts it back.
WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


def find_vboxcontrol() -> str:
    """Locate VBoxControl, or return an empty string.

    Guest Additions is already required by this bench -- the shared folder that
    carries files in depends on it -- so this is expected to be present. It is
    still looked for rather than assumed, because a ready signal that silently
    fails to send is a capture the host will never trigger, and the host would
    wait out its timeout reporting nothing more useful than "no signal".
    """
    import shutil

    for path in VBOXCONTROL_PATHS:
        if Path(path).is_file():
            return path
    found = shutil.which("VBoxControl.exe")
    return found or ""


def signal_ready(value: str, property_name: str = READY_PROPERTY) -> dict[str, Any]:
    """Tell the host the capture is up, and say plainly if it could not.

    ``TRANSIENT`` so the value cannot outlive the VM's power state. The host
    also deletes the property before it starts the machine, because a stale
    readiness left over from a previous boot would be read as this boot's --
    and the host would type the credentials into a machine with no capture
    running at all, producing a run that looks perfect and proves nothing.
    """
    result: dict[str, Any] = {
        "signalled": False, "property": property_name, "value": value,
        "vboxcontrol": "", "error": "",
    }

    vboxcontrol = find_vboxcontrol()
    result["vboxcontrol"] = vboxcontrol
    if not vboxcontrol:
        result["error"] = (
            "VBoxControl.exe not found, so the host cannot be told the capture "
            "is up. Guest Additions is required for the gated run."
        )
        return result

    argv = [
        vboxcontrol, "guestproperty", "set", property_name, value,
        "--flags", "TRANSIENT",
    ]
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except Exception as error:  # noqa: BLE001 -- the capture must not die here
        result["error"] = f"{type(error).__name__}: {error}"
        return result

    if completed.returncode != 0:
        result["error"] = (
            (completed.stderr or completed.stdout or "").strip()
            or f"VBoxControl returned {completed.returncode}"
        )
        return result

    result["signalled"] = True
    return result


def read_autologon() -> dict[str, Any]:
    """What `AutoAdminLogon` is set to now, without changing it."""
    result: dict[str, Any] = {"readable": False, "auto_admin_logon": "", "error": ""}
    try:
        import winreg
    except ImportError as error:  # not Windows
        result["error"] = str(error)
        return result

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINLOGON_KEY) as key:
            value, _ = winreg.QueryValueEx(key, "AutoAdminLogon")
        result["readable"] = True
        result["auto_admin_logon"] = str(value)
    except FileNotFoundError:
        result["readable"] = True
        result["auto_admin_logon"] = ""
    except OSError as error:
        result["error"] = str(error)

    return result



def _write_autologon(value: str) -> str:
    """The one call that touches HKLM. Returns an error string, or empty.

    Split out so the surrounding logic -- what it was before, whether the
    change is reported as made -- can be tested without a test suite that
    writes to the host's own Winlogon key. A test that has to be run elevated
    to pass is a test that gets skipped.
    """
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, WINLOGON_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, "AutoAdminLogon", 0, winreg.REG_SZ, value)
    except OSError as error:
        return f"{error}. Writing HKLM needs Administrator; run this elevated."
    except ImportError as error:
        return str(error)
    return ""


def set_autologon(enabled: bool) -> dict[str, Any]:
    """Open or close the gate, reporting what it was before.

    Only `AutoAdminLogon` is touched. `DefaultUserName` and `DefaultPassword`
    are left exactly as `vm_hygiene.ps1` wrote them, so re-enabling is a
    one-character change and nothing has to be re-entered -- and so a gated run
    that is abandoned halfway leaves a machine that logs itself in again as
    soon as the flag goes back.
    """
    result: dict[str, Any] = {
        "changed": False, "previous": "", "now": "1" if enabled else "0", "error": "",
    }

    before = read_autologon()
    result["previous"] = before["auto_admin_logon"]
    if before["error"]:
        result["error"] = before["error"]
        return result

    error = _write_autologon("1" if enabled else "0")
    if error:
        result["error"] = error
        return result

    result["changed"] = True
    return result


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
        "seconds_after_boot": None,
        "started_at": "",
        "ready_at": "",
        "ready_seconds_after_boot": None,
        "ready_signal": {},
        "ended_at": "",
        "backing_file": "",
        "backing_file_bytes": 0,
        "csv_path": "",
        "csv_bytes": 0,
        "preflight": {},
        "procmon_filter": describe_procmon_filter(None),
    }


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _wait_for_backing_file(backing: Path, timeout: int, sleep) -> bool:
    """Did Procmon actually start, or is it sitting on a dialog?

    It preallocates 256 MB, so the file appears within a second or two of a real
    start. Waiting for it is the difference between an accurate failure in three
    seconds and a silent one in three hundred.
    """
    waited = 0
    while waited < timeout:
        if backing.exists() and backing.stat().st_size > 0:
            return True
        sleep(1)
        waited += 1
    return backing.exists() and backing.stat().st_size > 0


def run_capture(
    out_dir: str | Path,
    procmon_path: str | Path,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    config_path: str | Path | None = None,
    sleep=time.sleep,
    boot_log: Path = BOOT_LOG,
) -> dict[str, Any]:
    """Start Procmon, hold it open for the window, then stop and export.

    This is what the task runs, so it is also the only part that must not raise:
    a scheduled task that dies leaves no manifest, and a missing manifest is
    indistinguishable from a boot where nothing happened.

    ``stage`` exists because the first version could lie. Its manifest opened
    with `reason: "capture did not start"` and only overwrote that on success or
    on a caught `Exception` -- so a killed process wrote out the *initial* reason
    as though it were a finding. `finally` now reports where it actually got to.
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
    manifest["seconds_after_boot"] = seconds_since_boot()
    manifest["backing_file"] = str(backing)
    manifest["csv_path"] = str(csv_path)
    manifest["procmon_filter"] = describe_procmon_filter(config_path)

    stage = "preflight"
    reason_recorded = False

    try:
        preflight = check_blocking_prompts(backing, boot_log=boot_log)
        manifest["preflight"] = preflight
        if preflight["blocked_by"]:
            manifest["reason"] = f"blocked by {preflight['blocked_by']}. Remedy: {preflight['remedy']}"
            reason_recorded = True
            return manifest

        stage = "starting Procmon"
        manifest["started_at"] = _now()
        start_procmon_capture(procmon_path, backing, config_path=config_path)

        stage = "waiting for the backing file"
        if not _wait_for_backing_file(backing, BACKING_FILE_TIMEOUT_SECONDS, sleep):
            manifest["reason"] = (
                f"Procmon wrote no backing file within {BACKING_FILE_TIMEOUT_SECONDS}s. "
                "It is running but not capturing -- almost always a modal dialog "
                "that cannot be answered from a scheduled task."
            )
            reason_recorded = True
            try:
                terminate_procmon_capture(procmon_path)
            except Exception:  # noqa: BLE001 -- already failing; do not mask the reason
                pass
            return manifest

        # The host is waiting on this, and it is sent only after the backing
        # file has been seen growing. Signalling on "Procmon was launched"
        # would be signalling on the exact thing that was false last time.
        stage = "signalling the host"
        manifest["ready_at"] = _now()
        manifest["ready_seconds_after_boot"] = seconds_since_boot()
        ready_value = "|".join([
            "1",
            str(manifest["ready_seconds_after_boot"]),
            manifest["ready_at"],
        ])
        manifest["ready_signal"] = signal_ready(ready_value)
        try:
            (out / "logon_capture.ready").write_text(ready_value, encoding="utf-8")
        except OSError as error:
            manifest["ready_signal"]["marker_error"] = str(error)

        stage = "capturing"
        sleep(window)

        stage = "terminating Procmon"
        terminate_procmon_capture(procmon_path)

        stage = "exporting the CSV"
        export_procmon_csv(procmon_path, backing, csv_path)

        manifest["completed"] = True
        manifest["reason"] = ""
        reason_recorded = True
    except Exception as error:  # noqa: BLE001 -- see the docstring
        manifest["reason"] = f"{type(error).__name__} while {stage}: {error}"
        reason_recorded = True
    finally:
        manifest["ended_at"] = _now()
        if not reason_recorded:
            # Killed, not raised. `except Exception` never sees a
            # KeyboardInterrupt or a terminated process, and the old code wrote
            # its opening placeholder out as if it were the answer.
            manifest["reason"] = f"interrupted while {stage}"
        manifest["backing_file_bytes"] = backing.stat().st_size if backing.exists() else 0
        manifest["csv_bytes"] = csv_path.stat().st_size if csv_path.exists() else 0
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
    gate_logon: bool = False,
) -> dict[str, Any]:
    """Register the task, and optionally close the gate behind it.

    The gate is closed *after* the task is registered and only if it
    registered. The other order can leave a machine that neither captures nor
    logs anybody in, which on a VM with no console access is a reinstall.
    """
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
    result["gate"] = set_autologon(False) if (gate_logon and result["ok"]) else {}
    return result


def disarm() -> dict[str, Any]:
    return _run(build_disarm_argv())


def status() -> dict[str, Any]:
    result = _run(build_status_argv())
    result["armed"] = result["ok"]
    return result
