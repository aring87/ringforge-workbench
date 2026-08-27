"""Run a child process with a timeout that actually ends it.

**`subprocess.run(timeout=...)` does not, and the corpus runs proved it.** A
FLOSS process was found alive for 74 minutes and 4,433 CPU seconds against a
180-second timeout, with the calling worker frozen behind it and the case log
stopped after `CASE_START`.

The mechanism is not that the timeout failed to fire. It fired, `subprocess.run`
killed the process it had started, and then blocked forever in `communicate()`:

- `floss.exe` and `capa.exe` are PyInstaller launchers. They extract and spawn a
  *grandchild*, which inherits the stdout and stderr pipe handles.
- Killing the launcher leaves the grandchild running and holding those handles.
- `communicate()` reads until end-of-file. The pipe never reaches it, because a
  live process still has the write end open.

So the timeout produced a hang instead of preventing one, and an orphan kept a
core busy for as long as the machine was up. Three separate "the run is stuck"
investigations were this, and each looked like a different problem.

The fix is to kill the whole tree before draining. `psutil` walks the children;
`taskkill /T /F` is the fallback when it is unavailable.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Sequence


def kill_tree(pid: int, grace: float = 5.0) -> int:
    """Kill a process and every descendant. Returns how many were killed.

    Children first, then the parent: killing the parent first can reparent the
    children and lose the handle to them.
    """
    killed = 0
    try:
        import psutil
    except ImportError:
        psutil = None

    if psutil is not None:
        try:
            parent = psutil.Process(pid)
        except Exception:
            return 0
        try:
            victims = parent.children(recursive=True)
        except Exception:
            victims = []
        for proc in victims + [parent]:
            try:
                proc.kill()
                killed += 1
            except Exception:
                pass
        try:
            psutil.wait_procs(victims + [parent], timeout=grace)
        except Exception:
            pass
        return killed

    # No psutil: Windows can still do the whole tree in one call.
    try:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       capture_output=True, timeout=grace + 5)
        killed = 1
    except Exception:
        pass
    return killed


def run_bounded(
    cmd: Sequence[str],
    timeout: float,
    cwd: Path | str | None = None,
    drain_grace: float = 20.0,
) -> dict:
    """Run `cmd`, and be certain it is over when this returns.

    Returns `{returncode, stdout, stderr, timed_out, duration_sec, killed}`.
    `returncode` is `None` when the command was killed for running too long --
    a timeout is a fact to record, not an error to raise, because the category
    contract wants `unknown` rather than a false zero.
    """
    started = time.time()
    try:
        proc = subprocess.Popen(
            list(cmd),
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, ValueError) as error:
        return {"returncode": -1, "stdout": "", "stderr": str(error),
                "timed_out": False, "killed": 0,
                "duration_sec": round(time.time() - started, 3)}

    try:
        out, err = proc.communicate(timeout=timeout)
        return {"returncode": proc.returncode, "stdout": out or "",
                "stderr": err or "", "timed_out": False, "killed": 0,
                "duration_sec": round(time.time() - started, 3)}
    except subprocess.TimeoutExpired:
        pass

    # **Tree first, then drain.** Draining before the grandchildren are gone is
    # the deadlock this module exists for.
    killed = kill_tree(proc.pid)
    try:
        out, err = proc.communicate(timeout=drain_grace)
    except subprocess.TimeoutExpired:
        # Something still holds the pipe. Give up on the output rather than on
        # the run -- the process tree is dead either way, which is the part
        # that matters.
        proc.kill()
        out, err = "", ""
    except Exception:
        out, err = "", ""

    return {"returncode": None, "stdout": out or "", "stderr": err or "",
            "timed_out": True, "killed": killed,
            "duration_sec": round(time.time() - started, 3)}
