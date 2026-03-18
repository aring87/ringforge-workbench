from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Optional


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
            close_fds=True,
        )
    except Exception as e:
        raise ProcmonError(f"Failed to start Procmon: {e}") from e

    time.sleep(3)


def terminate_procmon_capture(procmon_path: str | Path) -> None:
    procmon = ensure_procmon_exists(procmon_path)

    cmd = [str(procmon), "/AcceptEula", "/Terminate"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    if result.returncode not in (0, None):
        raise ProcmonError(
            f"Failed to terminate Procmon. rc={result.returncode} stderr={result.stderr.strip()}"
        )

    time.sleep(3)


def export_procmon_csv(
    procmon_path: str | Path,
    backing_file: str | Path,
    csv_path: str | Path,
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

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    if result.returncode not in (0, None):
        raise ProcmonError(
            f"Failed to export Procmon CSV. rc={result.returncode} stderr={result.stderr.strip()}"
        )

    if not csv_out.exists():
        raise ProcmonError(f"Expected CSV was not created: {csv_out}")

    return csv_out