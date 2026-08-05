"""Crashes as evidence, and the images Windows writes when they happen.

Two things a crashing sample gives you for free, both of which this pipeline
was throwing away.

**A crash inside unmapped memory is proof of injection.** Windows records
Application Error 1000 with the faulting module, and when execution was in
privately allocated memory rather than a loaded image, that field reads
`unknown`. A Formbook sample hollowed `RegSvcs.exe` and died inside its own
injected region:

    Faulting application name: RegSvcs.exe, version: 4.8.9221.0
    Faulting module name: unknown, version: 0.0.0.0
    Exception code: 0xc0000005
    Fault offset: 0x0150521d

Legitimate `RegSvcs.exe` never executes from anonymous memory. That one line is
the whole finding, and the run that produced it scored 35 / Needs Review with
`sysmon_injection_events: 0`.

The reason Sysmon saw nothing is that Event 8 is `CreateRemoteThread`, and
process hollowing does not use it -- it is `NtUnmapViewOfSection`,
`WriteProcessMemory` and `SetThreadContext`, none of which raise Event 8. So
injection detection had a hole exactly the shape of the most common loader
technique, and "injection has never fired on real malware" was partly a
statement about the detector rather than about the samples.

**A crash dump is an image taken at the one moment that matters.** The dump
watcher works on a schedule, and a hollowed process that lives four seconds
falls between offsets: two runs of that sample produced nine dumps and no image
of `RegSvcs` after the payload was written into it. Windows will write a full
dump at the instant of the fault -- after the write, during execution -- if
`LocalDumps` is configured. It is not on by default, which is what
``wer_local_dump_status`` exists to say out loud.

Collected dumps are shaped like the watcher's records so the same YARA pass
scans them.

Nothing here raises into a run. Every entry point degrades to a status dict.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any, Optional

from dynamic_analysis.sysmon_collector import _run, parse_rendered_xml
from dynamic_analysis.utils import sha256_file

APPLICATION_CHANNEL = "Application"

#: "Application Error". The faulting-module field is the one that matters.
APPLICATION_ERROR_EVENT_ID = 1000

#: Application Error is a legacy provider: its EventData carries unnamed
#: positional <Data> elements rather than named ones, so the order *is* the
#: schema. Everything past index 11 is report and packaging metadata.
_FIELD_ORDER = (
    "app_name",
    "app_version",
    "app_timestamp",
    "module_name",
    "module_version",
    "module_timestamp",
    "exception_code",
    "fault_offset",
    "process_id",
    "app_start_time",
    "app_path",
    "module_path",
)

#: What the faulting-module field says when execution was not in any loaded
#: image. Windows writes "unknown"; some builds leave it empty.
_UNMAPPED_MODULE_VALUES = {"", "unknown"}

#: Registry location that makes Windows write a dump on every crash.
_LOCAL_DUMPS_KEY = (
    r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
)

#: Where LocalDumps writes when the key exists but names no folder.
_DEFAULT_DUMP_FOLDER = r"%LOCALAPPDATA%\CrashDumps"

#: Full memory. DumpType 1 is a minidump and may not contain the injected
#: region, which is the only part worth having here.
FULL_DUMP_TYPE = 2

#: A full dump of a hollowed process is tens of megabytes; a full dump of a
#: browser is not. Anything larger is recorded and left where Windows put it.
MAX_CRASH_DUMP_BYTES = 2 * 1024 * 1024 * 1024


# ---------------------------------------------------------------------------
# Crash events
# ---------------------------------------------------------------------------

def _elapsed_ms_since(since_utc: str) -> int:
    from dynamic_analysis.sysmon_collector import _elapsed_ms_since as elapsed

    return elapsed(since_utc)


def query_crash_events(since_utc: str, max_events: int = 200) -> list[dict[str, Any]]:
    """Raw Application Error 1000 events recorded since ``since_utc``."""
    elapsed_ms = _elapsed_ms_since(since_utc)
    xpath = (
        f"*[System[EventID={APPLICATION_ERROR_EVENT_ID} and "
        f"TimeCreated[timediff(@SystemTime) <= {int(elapsed_ms)}]]]"
    )

    cmd = [
        "wevtutil", "qe", APPLICATION_CHANNEL,
        f"/q:{xpath}",
        "/f:RenderedXml",
        f"/c:{int(max_events)}",
        "/rd:true",
    ]

    try:
        result = _run(cmd, timeout=120)
    except Exception:
        return []
    if result.returncode != 0:
        return []

    events = parse_rendered_xml(result.stdout or "")
    return [e for e in events if e.get("event_id") == APPLICATION_ERROR_EVENT_ID]


def _safe_pid(value: object) -> Optional[int]:
    """A PID from Application Error, which writes it as hex on some builds."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def parse_crash_event(event: dict[str, Any]) -> dict[str, Any]:
    """Turn one Application Error 1000 into named fields."""
    values = list(event.get("data_values", []) or [])
    record: dict[str, Any] = {name: "" for name in _FIELD_ORDER}
    for index, name in enumerate(_FIELD_ORDER):
        if index < len(values):
            record[name] = str(values[index] or "").strip()

    record["timestamp"] = str(event.get("timestamp", "") or "")
    record["pid"] = _safe_pid(record.get("process_id"))
    record["executed_from_unmapped_memory"] = (
        record["module_name"].strip().lower() in _UNMAPPED_MODULE_VALUES
    )
    return record


def _image_name(value: object) -> str:
    return str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].strip().lower()


def summarize_crashes(
    events: list[dict[str, Any]],
    sample_pids: set[int] | None = None,
    sample_names: set[str] | None = None,
) -> dict[str, Any]:
    """Reduce crash events to the shape the run summary carries.

    Attribution works on the PID first and falls back to the image name,
    because the PID is absent on some builds and a hollowed process is
    identified perfectly well by being the sample's own child.

    Crashes belonging to other processes are counted rather than dropped: a
    run where Windows crashed something of its own has to be tellable from one
    where nothing crashed.
    """
    names = {n.lower() for n in (sample_names or set())}

    crashes: list[dict[str, Any]] = []
    other = 0
    for event in events:
        record = parse_crash_event(event)

        if sample_pids is not None or names:
            pid = record.get("pid")
            by_pid = sample_pids is not None and pid is not None and pid in sample_pids
            by_name = _image_name(record.get("app_name")) in names
            if not (by_pid or by_name):
                other += 1
                continue

        crashes.append(record)

    unmapped = [c for c in crashes if c["executed_from_unmapped_memory"]]

    return {
        "collected": True,
        "note": "",
        "attributed_by_lineage": sample_pids is not None or bool(names),
        "counts": {
            "crashes": len(crashes),
            "crashes_in_unmapped_memory": len(unmapped),
            "other_process_crashes_excluded": other,
        },
        "crashes": crashes[:50],
        # The finding, separated out because it is a different claim from
        # "something crashed": code was running where no image is mapped.
        "unmapped_memory_crashes": [
            {
                "process": c["app_name"],
                "pid": c["pid"],
                "exception_code": c["exception_code"],
                "fault_offset": c["fault_offset"],
                "path": c["app_path"],
                "timestamp": c["timestamp"],
            }
            for c in unmapped[:20]
        ],
    }


def empty_crash_summary(note: str = "") -> dict[str, Any]:
    return {
        "collected": False,
        "note": note,
        "attributed_by_lineage": False,
        "counts": {
            "crashes": 0,
            "crashes_in_unmapped_memory": 0,
            "other_process_crashes_excluded": 0,
        },
        "crashes": [],
        "unmapped_memory_crashes": [],
    }


def collect_crashes(
    since_utc: str,
    sample_pids: set[int] | None = None,
    sample_names: set[str] | None = None,
    max_events: int = 200,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Collect and summarise crash events for a completed run."""
    events = query_crash_events(since_utc, max_events=max_events)
    records = [parse_crash_event(e) for e in events]
    summary = summarize_crashes(events, sample_pids=sample_pids, sample_names=sample_names)
    return records, summary


# ---------------------------------------------------------------------------
# Crash dumps
# ---------------------------------------------------------------------------

def _reg_query(key: str, value: str) -> str:
    try:
        result = _run(["reg", "query", key, "/v", value], timeout=20)
    except Exception:
        return ""
    if result.returncode != 0:
        return ""
    match = re.search(
        rf"{re.escape(value)}\s+REG_(?:SZ|EXPAND_SZ|DWORD)\s+(\S.*?)\s*$",
        result.stdout or "",
        re.MULTILINE,
    )
    return match.group(1).strip() if match else ""


def wer_local_dump_status() -> dict[str, Any]:
    """Whether Windows will write a dump when a process crashes.

    Off by default, and its absence looks exactly like a run where nothing
    crashed -- which is the distinction this whole module exists to make. A
    Formbook run produced an Application Error for a hollowed process and no
    image to go with it, because only ``Report.wer`` was written.
    """
    folder = _reg_query(_LOCAL_DUMPS_KEY, "DumpFolder")
    dump_type = _reg_query(_LOCAL_DUMPS_KEY, "DumpType")
    configured = bool(folder or dump_type)

    resolved = ""
    if configured:
        import os

        resolved = os.path.expandvars(folder or _DEFAULT_DUMP_FOLDER)

    parsed_type: Optional[int] = None
    if dump_type:
        try:
            parsed_type = int(dump_type, 16) if dump_type.lower().startswith("0x") else int(dump_type)
        except ValueError:
            parsed_type = None

    if not configured:
        note = (
            "Windows Error Reporting local dumps are not configured, so a "
            "process that crashes leaves metadata and no memory image. A "
            "hollowed process often lives only seconds and falls between the "
            "scheduled dump offsets, which makes the crash dump the only image "
            f"of it. Set {_LOCAL_DUMPS_KEY} with DumpType={FULL_DUMP_TYPE}."
        )
    elif parsed_type is not None and parsed_type != FULL_DUMP_TYPE:
        note = (
            f"Local dumps are configured with DumpType={parsed_type}. Only "
            f"DumpType={FULL_DUMP_TYPE} captures full memory; a minidump may "
            "omit the injected region, which is the part worth having."
        )
    else:
        note = f"Crash dumps will be written to {resolved}."

    return {
        "available": configured,
        "dump_folder": resolved,
        "dump_type": parsed_type,
        "full_memory": parsed_type == FULL_DUMP_TYPE,
        "note": note,
    }


def _snapshot(folder: Path) -> set[str]:
    try:
        return {str(p) for p in folder.rglob("*") if p.is_file()}
    except Exception:
        return set()


class CrashDumpCollector:
    """Collects the dumps Windows wrote during a run.

    Snapshotted before launch for the same reason FakeNet's listener roots are:
    the folder is shared with everything else on the machine, and after the
    fact there is no way to tell this run's dumps from last week's.
    """

    def __init__(self, output_dir: str | Path, dump_folder: str | Path | None = None):
        self.output_dir = Path(output_dir)
        status = wer_local_dump_status()
        self.dump_folder = Path(dump_folder) if dump_folder else (
            Path(status["dump_folder"]) if status.get("dump_folder") else None
        )
        self.available = self.dump_folder is not None
        self._before: set[str] = set()

    def snapshot(self) -> None:
        """Record what was already there. Call before the sample launches."""
        if self.dump_folder is not None:
            self._before = _snapshot(self.dump_folder)

    def collect(self, sample_names: set[str] | None = None) -> dict[str, Any]:
        """Copy this run's dumps into the case directory.

        Records are shaped like the memory watcher's so the same YARA pass
        scans them: a crash dump of a hollowed process is exactly the image the
        scheduled offsets keep missing.
        """
        result: dict[str, Any] = {
            "collected": False,
            "note": "",
            "dump_folder": str(self.dump_folder) if self.dump_folder else "",
            "output_dir": str(self.output_dir),
            "dumps": [],
            "counts": {"dumps": 0, "attributed": 0, "not_copied": 0},
        }

        if self.dump_folder is None:
            result["note"] = (
                "Windows Error Reporting local dumps are not configured, so no "
                "crash image could be collected."
            )
            return result

        names = {n.lower() for n in (sample_names or set())}
        new_files = sorted(_snapshot(self.dump_folder) - self._before)

        dumps: list[dict[str, Any]] = []
        for path_text in new_files:
            source = Path(path_text)
            # WER names them <image>.<pid>.dmp.
            stem = source.name.split(".")
            process_name = stem[0].lower() + ".exe" if stem else ""
            pid = _safe_pid(stem[1]) if len(stem) > 2 else None

            attributed = (not names) or process_name in names
            try:
                size = source.stat().st_size
            except OSError:
                continue

            record: dict[str, Any] = {
                "pid": pid,
                "name": source.name.split(".")[0],
                "process_name": source.name.split(".")[0],
                "image": "",
                "offset_seconds": 0,
                "trigger": "crash",
                "source_path": str(source),
                "path": "",
                "size": size,
                "size_mb": round(size / (1024 * 1024)),
                "sha256": "",
                "success": False,
                "attributed_to_sample": attributed,
                "error": "",
            }

            if size > MAX_CRASH_DUMP_BYTES:
                record["error"] = (
                    f"left in place: {size} bytes exceeds the "
                    f"{MAX_CRASH_DUMP_BYTES} byte collection limit"
                )
                dumps.append(record)
                continue

            try:
                self.output_dir.mkdir(parents=True, exist_ok=True)
                destination = self.output_dir / source.name
                shutil.copy2(source, destination)
                record["path"] = str(destination)
                record["success"] = True
                record["sha256"] = sha256_file(destination)
            except Exception as error:
                record["error"] = f"could not collect: {error}"

            dumps.append(record)

        result["collected"] = True
        result["dumps"] = dumps
        result["counts"] = {
            "dumps": len(dumps),
            "attributed": sum(1 for d in dumps if d["attributed_to_sample"]),
            "not_copied": sum(1 for d in dumps if not d["success"]),
        }
        if not dumps:
            result["note"] = (
                f"{self.dump_folder} watched; nothing crashed during the run."
            )
        return result
