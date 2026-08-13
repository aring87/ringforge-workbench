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

#: Signed Microsoft binaries that loaders hollow, because they are present on
#: every machine, run without arguments, and attract no attention.
#:
#: The distinction matters because "faulting module: unknown" is weaker than it
#: first appears. In a *managed* process, JIT-compiled code also lives in
#: private allocations with no module mapped, so an ordinary .NET application
#: that faults in its own JITted code produces the same record as one running
#: injected code. A crash in one of these, spawned by the sample, is a
#: different claim: nothing legitimate starts RegSvcs.exe and has it fault in
#: anonymous memory.
HOLLOWING_TARGETS = {
    "regsvcs.exe", "regasm.exe", "installutil.exe", "msbuild.exe",
    "aspnet_compiler.exe", "addinprocess.exe", "addinprocess32.exe",
    "addinutil.exe", "ngen.exe", "jsc.exe", "csc.exe", "vbc.exe",
    "cvtres.exe", "ilasm.exe", "regsvr32.exe", "rundll32.exe",
    "svchost.exe", "explorer.exe", "wuauclt.exe", "notepad.exe",
}


def is_hollowing_target(image_name: object) -> bool:
    """True for a binary loaders commonly hollow."""
    return _image_name(image_name) in HOLLOWING_TARGETS

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


#: Extensions WER keeps in the dump's file name before the PID.
_WER_IMAGE_EXTENSIONS = {"exe", "com", "scr", "dll"}


def _parse_wer_dump_name(filename: str) -> tuple[str, Optional[int]]:
    """`(image name, pid)` from a WER local-dump file name.

    **WER writes two shapes and this only handled one.** The comment here used
    to say "<image>.<pid>.dmp" and the code read the PID from index 1, which is
    right for `RegSvcs.10784.dmp` and wrong for `RegSvcs.exe.9132.dmp` -- there
    index 1 is `"exe"`, so the PID parsed as `None`. Both forms occur; the
    second is what the guest produced on run `d7cc5044`.

    The PID is therefore taken as the *last* all-digit component before the
    extension rather than by position, which is stable across both shapes and
    across an image whose own name contains digits.
    """
    parts = filename.split(".")
    if len(parts) < 2:
        return filename.strip().lower(), None

    body = parts[:-1]                       # drop ".dmp"

    pid = None
    pid_index = None
    for index in range(len(body) - 1, 0, -1):
        if body[index].isdigit():
            pid = _safe_pid(body[index])
            pid_index = index
            break

    # The image name is everything before the PID, and keeps its extension when
    # WER included one -- the bare stem "RegSvcs" is not in HOLLOWING_TARGETS,
    # which once scored a crash-dump image `present` where the same image from a
    # live dump scored `strong`.
    name_parts = body[:pid_index] if pid_index else body
    if not name_parts:
        name_parts = body[:1]
    name = ".".join(name_parts).lower()
    if len(name_parts) == 1 or name_parts[-1].lower() not in _WER_IMAGE_EXTENSIONS:
        name += ".exe"
    return name, pid


# ---------------------------------------------------------------------------
# The image Windows was running vs the file it was started from
# ---------------------------------------------------------------------------
#
# `app_timestamp` is the `TimeDateStamp` of the image that was *executing*, not
# of the file on disk. For an ordinary process those are the same number. For a
# hollowed one they are not: the payload carries its own header, and Windows
# faithfully reports the payload's.
#
# On run `3f70058b` Windows recorded `5ff2b99b` for `RegSvcs.exe`, while the
# `RegSvcs.exe` on that guest is `68531ee1`. That is process hollowing, visible
# in the event log alone, on a run where the pipeline scored the injection from
# a memory dump instead.
#
# Two reasons it earns its place next to the dump-based passes rather than
# duplicating them:
#
# * **It does not need the payload to crash inside the injected region.**
#   `executed_from_unmapped_memory` only fires when the fault address is in
#   private memory; a hollowed process that dies inside `ntdll` looks ordinary
#   to it and still has the wrong timestamp here.
# * **It does not need a dump at all.** `module_integrity` answers the same
#   question far better, but only for processes something managed to dump. This
#   works off one event-log field.
#
# The standing caution about comparing against a reference applies exactly as it
# does in `module_integrity`: **this belongs on the guest**, where the file the
# process was started from is the file being read. Off-guest the binary is a
# different build and every comparison is meaningless, so a missing or unreadable
# file is reported as `no_reference` and never as agreement.

_TIMESTAMP_VERDICTS = ("mismatch", "identical", "no_reference", "unparsable")


def _parse_recorded_timestamp(value: object) -> Optional[int]:
    """`app_timestamp` as written by WER: hex, occasionally 0x-prefixed."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def read_pe_timestamp(path: str | Path) -> Optional[int]:
    """`TimeDateStamp` from a PE on disk, or None if it cannot be read.

    Read structurally rather than with `pefile`: it is two bounded seeks, it
    cannot raise on a malformed image the way a full parse can, and this runs
    against whatever path an event log happened to name.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(0x40)
            if len(head) < 0x40 or head[:2] != b"MZ":
                return None
            e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
            if not 0 < e_lfanew < (1 << 28):
                return None
            handle.seek(e_lfanew)
            header = handle.read(12)          # 'PE\0\0' + Machine + Sections + TDS
            if len(header) < 12 or header[:4] != b"PE\0\0":
                return None
            return int.from_bytes(header[8:12], "little")
    except OSError:
        return None


def check_image_timestamp(
    record: dict[str, Any],
    read_timestamp=read_pe_timestamp,
) -> dict[str, Any]:
    """Compare one crash's recorded image timestamp against the file on disk."""
    recorded = _parse_recorded_timestamp(record.get("app_timestamp"))
    path = str(record.get("app_path") or "").strip()
    process = record.get("app_name") or _image_name(path)

    entry: dict[str, Any] = {
        "process": process,
        "pid": record.get("pid"),
        "path": path,
        "recorded": f"{recorded:#010x}" if recorded is not None else "",
        "on_disk": "",
        "hollowing_target": is_hollowing_target(process),
        "verdict": "unparsable",
    }
    if recorded is None:
        return entry

    on_disk = read_timestamp(path) if path else None
    if on_disk is None:
        # Not "it matched". The file was not there to compare against, which is
        # the distinction `collection_available` exists to preserve everywhere
        # else in this pipeline.
        entry["verdict"] = "no_reference"
        return entry

    entry["on_disk"] = f"{on_disk:#010x}"
    entry["verdict"] = "identical" if on_disk == recorded else "mismatch"
    return entry


def summarize_image_timestamps(
    crashes: list[dict[str, Any]],
    read_timestamp=read_pe_timestamp,
) -> dict[str, Any]:
    """Roll the per-crash timestamp checks into the shape the summary carries.

    `available` is false when nothing could be compared, so a run that read no
    files reports *could not tell* rather than a silent zero.
    """
    checks = [check_image_timestamp(c, read_timestamp) for c in crashes]
    comparable = [c for c in checks if c["verdict"] in ("mismatch", "identical")]
    mismatches = [c for c in checks if c["verdict"] == "mismatch"]
    in_target = [c for c in mismatches if c["hollowing_target"]]

    return {
        "available": bool(comparable),
        "counts": {
            "checked": len(checks),
            "comparable": len(comparable),
            "mismatch": len(mismatches),
            # The emphatic subset, by the same rule the rest of this module
            # uses: nothing legitimate runs RegSvcs.exe off a different image
            # than the one on disk.
            "mismatch_in_hollowing_target": len(in_target),
            "no_reference": sum(1 for c in checks if c["verdict"] == "no_reference"),
            "unparsable": sum(1 for c in checks if c["verdict"] == "unparsable"),
        },
        # Named, not merely counted -- the module_integrity lesson: on its first
        # live finding the unnamed skip *was* the entire answer.
        "mismatches": mismatches[:20],
        "no_reference_processes": [
            c["process"] for c in checks if c["verdict"] == "no_reference"
        ][:20],
    }


def summarize_crashes(
    events: list[dict[str, Any]],
    sample_pids: set[int] | None = None,
    sample_names: set[str] | None = None,
    read_timestamp=read_pe_timestamp,
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
    in_target = [c for c in unmapped if is_hollowing_target(c.get("app_name"))]
    timestamps = summarize_image_timestamps(crashes, read_timestamp)

    return {
        "collected": True,
        "note": "",
        "attributed_by_lineage": sample_pids is not None or bool(names),
        "image_timestamps": timestamps,
        "counts": {
            "crashes": len(crashes),
            "crashes_in_unmapped_memory": len(unmapped),
            # A hollowed process reports the *payload's* TimeDateStamp, so this
            # fires without needing the fault to land in the injected region.
            "timestamp_mismatch_in_hollowing_target":
                timestamps["counts"]["mismatch_in_hollowing_target"],
            # The subset that is emphatic rather than merely unexplained. See
            # HOLLOWING_TARGETS: a managed process faulting in JITted code
            # looks identical to one faulting in injected code, so the identity
            # of the process is what separates them.
            "crashes_in_hollowing_target": len(in_target),
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
                "hollowing_target": is_hollowing_target(c.get("app_name")),
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
            "timestamp_mismatch_in_hollowing_target": 0,
            "crashes_in_hollowing_target": 0,
            "other_process_crashes_excluded": 0,
        },
        "crashes": [],
        "unmapped_memory_crashes": [],
        "image_timestamps": {
            "available": False,
            "counts": {
                "checked": 0, "comparable": 0, "mismatch": 0,
                "mismatch_in_hollowing_target": 0,
                "no_reference": 0, "unparsable": 0,
            },
            "mismatches": [],
            "no_reference_processes": [],
        },
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
# Abnormal termination (gap 4: a bail looks like a broken payload from outside)
# ---------------------------------------------------------------------------

#: WerFault's `-p <pid>` names the process that crashed. Both spawn forms carry
#: it: `WerFault.exe -u -p 3564 -s 220` and `WerFault.exe -pss -s 408 -p 3564
#: -ip 3564`.
_WERFAULT_TARGET = re.compile(r"-p\s+(\d+)")


def _werfault_target_pid(text: object) -> Optional[int]:
    """The PID WerFault says crashed, from its command line, or ``None``."""
    match = _WERFAULT_TARGET.search(str(text or ""))
    return int(match.group(1)) if match else None


#: A process-create event's detail carries the PID of the process being
#: *created* -- Procmon writes `PID: 7976, Command line: ...`. The record's own
#: `pid` field is the process doing the creating, which is a different thing.
_SPAWNED_PID = re.compile(r"\bpid:\s*(\d+)", re.IGNORECASE)


def _spawned_pid(text: object) -> Optional[int]:
    """The PID of the process a spawn record created, or ``None``."""
    match = _SPAWNED_PID.search(str(text or ""))
    return int(match.group(1)) if match else None


def werfault_witnesses(
    process_records: list[dict[str, Any]],
    descendant_pids: set[int] | None,
) -> list[dict[str, Any]]:
    """WerFault instances naming a crashed process in the sample's tree.

    Windows spawns ``WerFault.exe`` when a process faults, and its ``-p <pid>``
    argument names the process that died. On the loader this appears as
    ``RegSvcs.exe -> WerFault.exe``. It is a witness independent of the
    Application Error 1000 event, which some Windows builds fail to write and
    which a wevtutil query can miss -- so a crash can be real and leave only
    this trace.

    Attribution is by the crashed PID against the sample's tree. ``None`` for
    ``descendant_pids`` means lineage could not be resolved, and every WerFault
    is kept rather than dropped, the same degrade the findings already use.
    """
    witnesses: list[dict[str, Any]] = []
    for record in process_records or []:
        name = _image_name(
            record.get("child_process_name")
            or record.get("process_name")
            or record.get("name")
        )
        if name != "werfault.exe":
            continue

        detail = " ".join(
            str(record.get(key, "") or "")
            for key in ("detail", "command_line", "command", "path")
        )
        target = _werfault_target_pid(detail)
        if target is None:
            continue
        if descendant_pids is not None and target not in descendant_pids:
            continue

        witnesses.append(
            {
                "crashed_pid": target,
                # WerFault's own PID, read from the spawn detail rather than from
                # the record's `pid` -- which is the process that *started*
                # WerFault. On the loader's tree those are the same process, so
                # the field reported the crashed PID twice and looked right: the
                # 06 Aug run recorded `crashed_pid: 4264, werfault_pid: 4264`
                # while WerFault was really 7976. A `-pss` spawn comes from
                # WerSvc's svchost instead, where the same mistake would have
                # named a process with nothing to do with the crash.
                "werfault_pid": _spawned_pid(detail),
                # Kept because it answers a different question -- who was
                # holding the crashed process when Windows stepped in.
                "spawned_by_pid": record.get("pid"),
                "timestamp": record.get("timestamp", ""),
            }
        )
    return witnesses


def summarize_abnormal_termination(
    crash_summary: dict[str, Any] | None,
    process_records: list[dict[str, Any]] | None = None,
    descendant_pids: set[int] | None = None,
) -> dict[str, Any]:
    """Whether the sample's chain ended by crash rather than by clean exit.

    This is gap 4's honest core. From outside the guest a sample that detects
    analysis and bails looks exactly like one whose payload is broken: both
    leave a crashed process in the tree and an otherwise quiet run. The pipeline
    cannot tell them apart, and pretending otherwise would be a guess.

    What it *can* do is refuse to let a crashed chain read as a clean one. This
    is not scored -- a crash is not evidence of malice, and benign software
    crashes -- but it is a false-negative guard: where a run is otherwise empty
    and a sample process crashed, the result is inconclusive, not benign.

    Two witnesses, unioned. The Application Error 1000 events already attributed
    to the sample, and any WerFault naming a sample-tree PID. Either alone is
    enough; together they survive one of the two being missing.
    """
    crash = crash_summary if isinstance(crash_summary, dict) else {}
    counts = crash.get("counts", {}) or {}
    event_crashes = int(counts.get("crashes", 0) or 0)

    witnesses = werfault_witnesses(process_records or [], descendant_pids)
    witness_pids = {w["crashed_pid"] for w in witnesses}

    crashed = event_crashes > 0 or bool(witnesses)

    # The PIDs and names of the crashed sample processes, from the crash events.
    crashed_processes = [
        {"process": c.get("app_name", ""), "pid": c.get("pid")}
        for c in (crash.get("crashes", []) or [])
    ]

    return {
        "chain_crashed": crashed,
        "event_crashes": event_crashes,
        "werfault_witnesses": witnesses,
        # A crash seen only via WerFault, with no Application Error event to go
        # with it -- the case this second witness exists for.
        "witnessed_only_by_werfault": bool(witness_pids) and event_crashes == 0,
        "crashed_processes": crashed_processes,
        "note": (
            "A process in the sample's tree terminated by crash. From outside "
            "the guest a deliberate anti-analysis bail is indistinguishable "
            "from a broken payload: both leave a crashed process and a quiet "
            "run. Where this run is otherwise empty, read it as inconclusive "
            "rather than clean."
            if crashed
            else ""
        ),
    }


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

    def collect(
        self,
        sample_names: set[str] | None = None,
        sample_pids: set[int] | None = None,
    ) -> dict[str, Any]:
        """Copy this run's dumps into the case directory.

        Records are shaped like the memory watcher's so the same YARA pass
        scans them: a crash dump of a hollowed process is exactly the image the
        scheduled offsets keep missing.

        **Attribution is by PID first and image name second**, the same contract
        `summarize_crashes` keeps, and for the same reason: a crash dump of the
        sample's *child* is the interesting case and its name is not the
        sample's. Run `d7cc5044` is the demonstration -- `RegSvcs.exe.9132.dmp`
        reported `attributed_to_sample: false` while pid 9132 sat in
        `missed_descendants` with the sample as its parent. The tree was known;
        this collector was the only thing not being told about it.
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
            process_name, pid = _parse_wer_dump_name(source.name)

            # PID first. `names` is seeded from the sample's own image and the
            # processes the memory watcher *observed*, so a child it never got
            # to see -- which is exactly the short-lived hollowing target this
            # dump exists to capture -- is absent from it by construction.
            by_pid = (
                sample_pids is not None and pid is not None and pid in sample_pids
            )
            by_name = bool(names) and process_name in names
            if sample_pids is None and not names:
                attributed = True          # no lineage at all: attribute nothing away
            else:
                attributed = by_pid or by_name
            try:
                size = source.stat().st_size
            except OSError:
                continue

            record: dict[str, Any] = {
                "pid": pid,
                # The reconstructed name, with its extension, not the bare stem.
                # WER writes `RegSvcs.10784.dmp`, and the stem alone is
                # "RegSvcs" -- which is not in HOLLOWING_TARGETS, so a carved
                # image from a crash dump reported hollowing_target: false and
                # scored `present` where the same image from a live dump scored
                # `strong`. The extension was already being computed here for
                # the attribution test and then discarded.
                "name": process_name,
                "process_name": process_name,
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
