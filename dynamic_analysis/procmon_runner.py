from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Optional
from static_triage_engine.proc import no_window


class ProcmonError(Exception):
    pass


def ensure_procmon_exists(procmon_path: str | Path) -> Path:
    p = Path(procmon_path)
    if not p.exists():
        raise ProcmonError(f"Procmon not found: {p}")
    return p


def start_procmon_capture(
    procmon_path: str | Path,
    backing_file: str | Path,
    config_path: Optional[str | Path] = None,
    accept_eula: bool = True,
) -> None:
    procmon = ensure_procmon_exists(procmon_path)
    backing = Path(backing_file)
    backing.parent.mkdir(parents=True, exist_ok=True)

    cmd = [str(procmon)]

    if accept_eula:
        cmd.append("/AcceptEula")

    if config_path:
        cmd.extend(["/LoadConfig", str(config_path)])

    cmd.extend([
        "/Quiet",
        "/Minimized",
        "/BackingFile", str(backing),
    ])

    # Use Popen so we do not block waiting on the GUI app.
    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            close_fds=True, creationflags=no_window(),
        )
    except Exception as e:
        raise ProcmonError(f"Failed to start Procmon: {e}") from e

    # **`Popen` succeeding does not mean Procmon is capturing.** It is a GUI
    # app: it forks, and the parent exits immediately whether or not the child
    # ever began. With stdout and stderr on DEVNULL above, a Procmon that quit
    # on startup left no trace at all -- measured 17 Sep, where a `/LoadConfig`
    # pointing at a filter that had been moved into the package by v1.12.0
    # made Procmon exit on launch. Nothing noticed for twenty-five minutes,
    # until the export failed on a backing file that was never created and took
    # the whole run down with it.
    #
    # Procmon creates the backing file as soon as it starts logging, so its
    # appearance is the cheap proof that the capture is real. Polled rather
    # than slept-then-checked, so a healthy start still costs about a second.
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        if backing.exists():
            return
        time.sleep(0.5)

    raise ProcmonError(
        f"Procmon produced no backing file at {backing} within 15s, so it is "
        f"not capturing. It exits silently on a bad /LoadConfig -- check "
        f"{config_path!r} exists."
        if config_path else
        f"Procmon produced no backing file at {backing} within 15s, so it is "
        f"not capturing."
    )


def terminate_procmon_capture(procmon_path: str | Path) -> None:
    procmon = ensure_procmon_exists(procmon_path)

    cmd = [str(procmon), "/AcceptEula", "/Terminate"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, creationflags=no_window())

    if result.returncode not in (0, None):
        raise ProcmonError(
            f"Failed to terminate Procmon. rc={result.returncode} stderr={result.stderr.strip()}"
        )

    time.sleep(3)


#: How long `/SaveAs` may take. **Measured, 28 Sep, over 195 exports in the
#: benign and malware corpora:** it was 120 s, and 19 malware exports hit it
#: while the slowest twelve that finished took 99-118 s -- six of them benign,
#: so both corpora ran at the edge. Time does not follow capture size (504 MB
#: timed out where 2,112 MB finished; 0.7 to 27 MB/s), so no size-scaled
#: limit is defensible and this is a fixed ceiling well clear of anything
#: seen. Its worst case costs 15 minutes of a 7,200 s run budget, and a run
#: that reaches it still survives -- see the `TimeoutExpired` handling below.
EXPORT_TIMEOUT_SECONDS = 900


def export_procmon_csv(
    procmon_path: str | Path,
    backing_file: str | Path,
    csv_path: str | Path,
    timeout: float = EXPORT_TIMEOUT_SECONDS,
) -> Path:
    procmon = ensure_procmon_exists(procmon_path)
    backing = Path(backing_file)
    csv_out = Path(csv_path)
    csv_out.parent.mkdir(parents=True, exist_ok=True)

    if not backing.exists():
        raise ProcmonError(f"Backing file not found: {backing}")

    cmd = [
        str(procmon),
        "/AcceptEula",
        "/Quiet",
        "/OpenLog", str(backing),
        "/SaveAs", str(csv_out),
    ]

    # **A timeout is a ProcmonError, and that is the fix, not the limit.** The
    # orchestrator catches ProcmonError from this call and carries on without
    # Procmon, precisely so one collector cannot take the others' evidence
    # down with it. `subprocess.TimeoutExpired` is not a ProcmonError, so it
    # walked straight past that handler and killed the whole dynamic module:
    # 17 of mal-112b's 109 usable runs came home static-only this way, their
    # memory dumps, Sysmon, network and persistence diffs discarded for want
    # of one CSV. `run` has already killed Procmon by the time this raises.
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, creationflags=no_window())
    except subprocess.TimeoutExpired as error:
        # A half-written CSV must not survive to be parsed as a whole one.
        # The caller gates on success, but a file on disk outlives the gate.
        try:
            csv_out.unlink(missing_ok=True)
        except OSError:
            pass
        raise ProcmonError(
            f"Procmon CSV export did not finish within {timeout:.0f}s "
            f"(backing file {backing}); continuing without Procmon"
        ) from error

    if result.returncode not in (0, None):
        raise ProcmonError(
            f"Failed to export Procmon CSV. rc={result.returncode} stderr={result.stderr.strip()}"
        )

    if not csv_out.exists():
        raise ProcmonError(f"Expected CSV was not created: {csv_out}")

    return csv_out