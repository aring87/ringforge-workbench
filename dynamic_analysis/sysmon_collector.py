"""Sysmon telemetry collection for dynamic analysis runs.

Procmon shows filesystem, registry and process IO, but it cannot see process
injection, image-load provenance, named-pipe IPC, WMI persistence or DNS
resolution. Sysmon covers exactly those gaps, so the two are complementary
rather than redundant.

Collection is read-only and non-destructive: the Sysmon channel is never
cleared. The run start time is recorded, and afterwards only events newer than
that timestamp are queried, so a shared analysis VM keeps its history intact.

Requires Sysmon to be installed and running in the guest, e.g.::

    sysmon64.exe -accepteula -i sysmonconfig.xml

Nothing here raises if Sysmon is absent; every entry point degrades to a
disabled/unavailable status dict so a run can proceed without it.
"""

from __future__ import annotations

import ctypes
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from dynamic_analysis.findings import KNOWN_NOISE_PROCESSES
from dynamic_analysis.utils import is_analyzer_image

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

#: Sysmon event IDs we normalise. Anything not listed is still collected, just
#: reported under its numeric ID.
EVENT_NAMES = {
    1: "ProcessCreate",
    2: "FileCreateTime",
    3: "NetworkConnect",
    4: "SysmonServiceStateChange",
    5: "ProcessTerminate",
    6: "DriverLoad",
    7: "ImageLoad",
    8: "CreateRemoteThread",
    9: "RawAccessRead",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryCreateDelete",
    13: "RegistrySetValue",
    14: "RegistryRename",
    15: "FileCreateStreamHash",
    16: "SysmonConfigChange",
    17: "PipeCreated",
    18: "PipeConnected",
    19: "WmiEventFilter",
    20: "WmiEventConsumer",
    21: "WmiEventConsumerToFilter",
    22: "DnsQuery",
    23: "FileDelete",
    24: "ClipboardChange",
    25: "ProcessTampering",
    26: "FileDeleteDetected",
    27: "FileBlockExecutable",
    28: "FileBlockShredding",
    29: "FileExecutableDetected",
}

#: Event IDs that are worth surfacing on their own, with a severity weight.
#: These are the behaviours Procmon structurally cannot report.
HIGH_SIGNAL_EVENTS = {
    8: ("Process injection (CreateRemoteThread)", "high"),
    25: ("Process tampering / hollowing", "high"),
    10: ("Process memory access", "medium"),
    19: ("WMI event filter registered", "high"),
    20: ("WMI event consumer registered", "high"),
    21: ("WMI filter-to-consumer binding", "high"),
    6: ("Driver load", "medium"),
    9: ("Raw disk access", "medium"),
    17: ("Named pipe created", "low"),
    22: ("DNS query", "low"),
}

#: Access masks that indicate credential-theft style handles to LSASS.
_LSASS_ACCESS_FLAGS = ("0x1010", "0x1410", "0x1438", "0x143a", "0x1f3fff", "0x1fffff")

#: wevtutil emits attributes single-quoted (xmlns='...'), so both quote styles
#: must be handled. Matching only double quotes left the namespace in place,
#: after which every findall("Event") missed and 8 MB of telemetry parsed to
#: nothing.
_XMLNS_RE = re.compile(r"""\sxmlns(?::\w+)?\s*=\s*(?:"[^"]*"|'[^']*')""")


class SysmonError(Exception):
    pass


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        errors="replace",
    )


def default_sysmon_path() -> Path:
    """Where a bundled Sysmon binary is expected to live."""
    return Path(__file__).resolve().parents[1] / "tools" / "sysmon64.exe"


def find_sysmon(configured_path: str | Path | None = None) -> Optional[Path]:
    """Locate a Sysmon binary. Returns ``None`` when not found."""
    candidates: list[Path] = []

    if configured_path:
        candidates.append(Path(configured_path))

    tools = Path(__file__).resolve().parents[1] / "tools"
    candidates.extend([tools / "sysmon64.exe", tools / "sysmon.exe"])

    for name in ("sysmon64.exe", "sysmon.exe"):
        candidates.append(Path(name))  # resolved via PATH by shutil below

    import shutil

    for candidate in candidates:
        if candidate.is_absolute() or candidate.parent != Path("."):
            if candidate.exists():
                return candidate
        else:
            found = shutil.which(str(candidate))
            if found:
                return Path(found)

    return None


def channel_available() -> bool:
    """True when the Sysmon Operational channel is registered on this host."""
    try:
        result = _run(["wevtutil", "gl", SYSMON_CHANNEL], timeout=20)
        return result.returncode == 0
    except Exception:
        return False


def channel_record_count() -> int:
    """Total records currently in the Sysmon channel, or -1 if unreadable.

    This distinguishes the two ways a collection can come back empty: a channel
    that genuinely holds nothing (Sysmon is installed but not logging) versus a
    query or permission problem hiding events that are really there. Without
    it, both look like "the sample did nothing".
    """
    try:
        result = _run(["wevtutil", "gli", SYSMON_CHANNEL], timeout=30)
    except Exception:
        return -1

    if result.returncode != 0:
        return -1

    for line in (result.stdout or "").splitlines():
        if "numberOfLogRecords" in line:
            _, _, value = line.partition(":")
            try:
                return int(value.strip())
            except ValueError:
                return -1
    return -1


def service_running() -> bool:
    """True when a Sysmon service is in the RUNNING state."""
    for service in ("Sysmon64", "Sysmon"):
        try:
            result = _run(["sc", "query", service], timeout=20)
        except Exception:
            continue
        if result.returncode == 0 and "RUNNING" in (result.stdout or "").upper():
            return True
    return False


def sysmon_status(configured_path: str | Path | None = None) -> dict[str, Any]:
    """Preflight summary describing whether Sysmon telemetry can be collected."""
    binary = find_sysmon(configured_path)
    channel = channel_available()
    running = service_running()

    available = channel and running
    if available:
        note = "Sysmon is running and its event channel is available."
    elif channel and not running:
        note = "Sysmon channel exists but the service is not running."
    elif binary is not None:
        note = (
            "Sysmon binary found but not installed. Install it in the guest with: "
            f"{binary.name} -accepteula -i sysmonconfig.xml"
        )
    else:
        note = (
            "Sysmon not found. Install Sysmon in the analysis VM and place "
            "sysmon64.exe under tools/ to enable injection, WMI and DNS telemetry."
        )

    return {
        "available": bool(available),
        "binary_path": str(binary) if binary else "",
        "channel_available": bool(channel),
        "service_running": bool(running),
        "note": note,
    }


# ---------------------------------------------------------------------------
# Capture window
# ---------------------------------------------------------------------------

def mark_start() -> str:
    """Timestamp marking the start of a run, for later event filtering.

    Returned in the UTC form the Windows event XPath engine expects.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _since_query(since_utc: str) -> str:
    return f"*[System[TimeCreated[@SystemTime>='{since_utc}']]]"


def _timediff_query(elapsed_ms: int) -> str:
    """Events recorded within the last ``elapsed_ms`` milliseconds.

    ``timediff`` is the reliably supported way to bound an event query by time.
    Comparing @SystemTime against a literal parses without error but silently
    matches nothing on some builds, which looks identical to "Sysmon recorded
    no events" -- the worst possible failure for this collector.
    """
    return f"*[System[TimeCreated[timediff(@SystemTime) <= {int(elapsed_ms)}]]]"


def _parse_event_time(value: str) -> Optional[datetime]:
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1]
    # Event log timestamps carry 100ns precision; Python accepts 6 digits.
    if "." in text:
        head, _, frac = text.partition(".")
        text = f"{head}.{frac[:6]}"
    try:
        return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _elapsed_ms_since(since_utc: str) -> int:
    started = _parse_event_time(since_utc)
    if started is None:
        return 3600 * 1000
    delta = datetime.now(timezone.utc) - started
    # A small margin absorbs clock granularity at the boundary.
    return max(1000, int(delta.total_seconds() * 1000) + 5000)


def export_evtx(output_path: str | Path, since_utc: str) -> dict[str, Any]:
    """Archive the raw events for this run window to an .evtx file."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()

    try:
        result = _run(
            [
                "wevtutil", "epl", SYSMON_CHANNEL, str(out),
                f"/q:{_since_query(since_utc)}",
            ],
            timeout=180,
        )
    except Exception as error:
        return {"success": False, "error": str(error), "path": str(out)}

    if result.returncode != 0:
        return {
            "success": False,
            "error": (result.stderr or result.stdout or "").strip() or f"rc={result.returncode}",
            "path": str(out),
        }

    return {"success": True, "error": "", "path": str(out)}


def _query(
    xpath: str,
    max_events: int,
    reverse: bool = False,
    stats: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    cmd = [
        "wevtutil", "qe", SYSMON_CHANNEL,
        f"/q:{xpath}",
        "/f:RenderedXml",
        f"/c:{int(max_events)}",
    ]
    if reverse:
        cmd.append("/rd:true")

    try:
        result = _run(cmd, timeout=300)
    except Exception as error:
        raise SysmonError(f"Failed to query Sysmon events: {error}") from error

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise SysmonError(f"wevtutil qe failed: {detail or result.returncode}")

    raw = result.stdout or ""
    events = parse_rendered_xml(raw)

    # Record how much wevtutil actually returned. Without this, a query that
    # matched nothing and a query whose output failed to parse both present as
    # "zero events", and they need opposite fixes.
    if stats is not None:
        stats["stdout_bytes"] = len(raw)
        stats["stderr"] = (result.stderr or "").strip()[:300]
        stats["parsed_events"] = len(events)
        # Hitting the cap on a newest-first read means the *oldest* matches
        # were dropped. For a run window that has just ended this is harmless;
        # for a boot window it silently removes the payload's first seconds,
        # so the caller is told rather than left to infer it from a round
        # number.
        stats["capped"] = len(events) >= int(max_events)

    return events


def query_events(
    since_utc: str,
    max_events: int = 20000,
    attempts_out: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return normalised Sysmon events recorded since ``since_utc``.

    Tries progressively less selective queries. Each attempt is isolated: an
    error in one must not abort the rest, or a single failing strategy takes
    the whole collection down with it and the channel looks empty.

    ``attempts_out`` receives a record of every strategy tried, so an empty
    result can be explained rather than guessed at.
    """
    elapsed_ms = _elapsed_ms_since(since_utc)
    started = _parse_event_time(since_utc)

    # Every strategy reads newest-first.
    #
    # wevtutil returns oldest-first by default, and /c: caps the result. On a
    # channel holding weeks of history -- 53k records was the case that exposed
    # this -- a capped read returns events from days ago and never reaches the
    # detonation window, which presents as "Sysmon recorded nothing". For a
    # window that just ended, the most recent matches are the ones wanted.
    strategies = [
        ("timediff", _timediff_query(elapsed_ms), max_events),
        ("absolute-timestamp", _since_query(since_utc), max_events),
        # Unfiltered is a diagnostic last resort. Keep the count modest: each
        # rendered event is roughly a kilobyte of XML through a pipe, and a
        # huge request times out, which is how this path failed before.
        ("unfiltered-recent", "*", min(max_events, 3000)),
    ]

    last_error = ""
    for name, xpath, count in strategies:
        record: dict[str, Any] = {
            "strategy": name, "events": 0, "error": "",
            "stdout_bytes": 0, "parsed_events": 0, "stderr": "", "capped": False,
        }
        try:
            events = _query(xpath, count, reverse=True, stats=record)
        except SysmonError as error:
            record["error"] = str(error)
            last_error = str(error)
            if attempts_out is not None:
                attempts_out.append(record)
            continue

        # Results arrive newest-first. Bound them to the run window -- the
        # unfiltered strategy applies no time filter at all -- then restore
        # chronological order.
        if started is not None and events:
            events = [
                event for event in events
                if (_parse_event_time(event.get("timestamp", "")) or started) >= started
            ]
        events.reverse()

        record["events"] = len(events)
        if attempts_out is not None:
            attempts_out.append(record)

        if events:
            return events

    if last_error:
        raise SysmonError(last_error)
    return []


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_rendered_xml(text: str) -> list[dict[str, Any]]:
    """Parse concatenated ``<Event>`` fragments from ``wevtutil qe``.

    The tool emits one fragment per event with no enclosing root element, so
    they are wrapped before parsing. Namespaces are stripped first because the
    rendered output mixes default and prefixed namespaces.
    """
    if not text.strip():
        return []

    cleaned = _XMLNS_RE.sub("", text)
    try:
        root = ET.fromstring(f"<Events>{cleaned}</Events>")
    except ET.ParseError:
        # Salvage whatever complete fragments we can rather than losing the run.
        events: list[dict[str, Any]] = []
        for fragment in re.findall(r"<Event\b.*?</Event>", cleaned, re.DOTALL):
            try:
                node = ET.fromstring(fragment)
            except ET.ParseError:
                continue
            _strip_namespaces(node)
            events.append(_event_to_dict(node))
        return [e for e in events if e]

    # Second line of defence: if any namespace survived the textual strip, tags
    # arrive as "{uri}Event" and every lookup below silently misses.
    _strip_namespaces(root)
    return [e for e in (_event_to_dict(node) for node in root.findall("Event")) if e]


def _strip_namespaces(element: ET.Element) -> None:
    """Remove XML namespace prefixes from an element tree, in place."""
    for node in element.iter():
        if isinstance(node.tag, str) and "}" in node.tag:
            node.tag = node.tag.split("}", 1)[1]


def _event_to_dict(node: ET.Element) -> dict[str, Any]:
    system = node.find("System")
    if system is None:
        return {}

    event_id_node = system.find("EventID")
    try:
        event_id = int((event_id_node.text or "0").strip()) if event_id_node is not None else 0
    except ValueError:
        event_id = 0

    time_node = system.find("TimeCreated")
    timestamp = time_node.get("SystemTime", "") if time_node is not None else ""

    # The PID that *emitted* the event, from the System block.
    #
    # Kept separate from the EventData "ProcessId" below, which for Sysmon is
    # the process the event is *about*. For PowerShell 4104 there is no
    # EventData ProcessId at all, and this attribute is the only thing tying a
    # script block to the process that ran it -- which is what stops Windows'
    # own scheduled PowerShell from being reported as the sample's.
    execution_node = system.find("Execution")
    execution_pid = (
        execution_node.get("ProcessID", "") if execution_node is not None else ""
    )

    data: dict[str, str] = {}
    # Legacy providers -- Application Error is one -- write unnamed <Data>
    # elements, where the order *is* the schema. Collecting only named ones
    # returned an empty dict for every 1000 event, and the faulting-module
    # field lives at index 3.
    values: list[str] = []
    event_data = node.find("EventData")
    if event_data is not None:
        for item in event_data.findall("Data"):
            text = (item.text or "").strip()
            values.append(text)
            name = item.get("Name")
            if name:
                data[name] = text

    return {
        "event_id": event_id,
        "event_name": EVENT_NAMES.get(event_id, f"Event{event_id}"),
        "timestamp": timestamp,
        "process_id": data.get("ProcessId", ""),
        "execution_process_id": execution_pid,
        "data_values": values,
        "image": data.get("Image", ""),
        "user": data.get("User", ""),
        "data": data,
    }


# ---------------------------------------------------------------------------
# Summarising
# ---------------------------------------------------------------------------

def _short(value: str, limit: int = 220) -> str:
    value = (value or "").strip()
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _is_lsass_access(event: dict[str, Any]) -> bool:
    if event.get("event_id") != 10:
        return False
    target = (event["data"].get("TargetImage", "") or "").lower()
    if "lsass.exe" not in target:
        return False
    granted = (event["data"].get("GrantedAccess", "") or "").lower()
    return any(flag in granted for flag in _LSASS_ACCESS_FLAGS)


#: CreateRemoteThread pairs Windows performs on itself, as
#: (source image, target image) basenames.
#:
#: Injection is a primary malware technique, so this is an allowlist of exact
#: pairs rather than anything broader, and both images have to be the genuine
#: System32 binaries -- a copy of dwm.exe elsewhere injecting into a copy of
#: csrss.exe is the masquerade this must never wave through.
#:
#: dwm.exe -> csrss.exe is the Desktop Window Manager talking to its session's
#: client/server runtime. It fired during a mimikatz detonation and was the
#: only high-severity finding in the whole report, which then mapped it to
#: T1055 as though the sample had injected. On a credential dumper that reads
#: as entirely plausible, which is what makes it worth filtering rather than
#: leaving for the reader to recognise.
_OS_INJECTION_PAIRS = {
    ("dwm.exe", "csrss.exe"),
}


def _image_basename(value: object) -> str:
    return str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _is_system32_image(value: object) -> bool:
    return "\\windows\\system32\\" in str(value or "").replace("/", "\\").lower()


def _is_os_baseline_event(event: dict[str, Any]) -> bool:
    """True when the event is Windows acting on itself, not the sample.

    Deliberately narrow: this only covers CreateRemoteThread, and only for the
    exact pairs above running from System32. Everything else Sysmon reports as
    injection stays a finding.
    """
    if event.get("event_id") != 8:
        return False

    data = event.get("data", {}) or {}
    source = data.get("SourceImage", "")
    target = data.get("TargetImage", "")

    pair = (_image_basename(source), _image_basename(target))
    if pair not in _OS_INJECTION_PAIRS:
        return False

    return _is_system32_image(source) and _is_system32_image(target)


def _actor_pid(event: dict[str, Any]) -> Optional[int]:
    """The PID of the process that *did* the thing this event describes.

    Which field that is depends on the event. `CreateRemoteThread` and
    `ProcessAccess` name the acting process in `SourceProcessId` and the victim
    in `ProcessId`, so reading `ProcessId` for those would attribute an injection
    to the process injected *into*. Everything else acts through `ProcessId`, and
    `Execution ProcessID` from the System block is the fallback for providers
    that carry no EventData PID at all.
    """
    data = event.get("data", {}) or {}

    if event.get("event_id") in (8, 10):
        candidates = (data.get("SourceProcessId"), data.get("ProcessId"))
    else:
        candidates = (data.get("ProcessId"), event.get("execution_process_id"))

    for value in candidates:
        try:
            pid = int(str(value).strip())
        except (TypeError, ValueError):
            continue
        if pid > 0:
            return pid
    return None


def _is_analyzer_event(event: dict[str, Any]) -> bool:
    """True when the event describes the workbench's own tooling.

    Every image-bearing field is checked rather than just Image, because the
    field that names the tooling varies by event: a driver load carries it in
    ImageLoaded, a process access in SourceImage.
    """
    data = event.get("data", {}) or {}
    for key in ("Image", "ImageLoaded", "SourceImage", "TargetImage", "TargetFilename"):
        if is_analyzer_image(data.get(key)):
            return True
    return False


def _highlight(event: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Turn a high-signal event into an analyst-facing finding."""
    event_id = event.get("event_id")
    data = event.get("data", {})

    if _is_lsass_access(event):
        return {
            "severity": "high",
            "event_id": event_id,
            "title": "LSASS memory access (possible credential theft)",
            "detail": _short(
                f"{data.get('SourceImage', '?')} -> {data.get('TargetImage', '?')} "
                f"access={data.get('GrantedAccess', '?')}"
            ),
        }

    if event_id not in HIGH_SIGNAL_EVENTS:
        return None

    title, severity = HIGH_SIGNAL_EVENTS[event_id]

    if event_id == 8:
        detail = f"{data.get('SourceImage', '?')} -> {data.get('TargetImage', '?')}"
    elif event_id == 25:
        detail = f"{data.get('Image', '?')} type={data.get('Type', '?')}"
    elif event_id == 10:
        detail = (
            f"{data.get('SourceImage', '?')} -> {data.get('TargetImage', '?')} "
            f"access={data.get('GrantedAccess', '?')}"
        )
    elif event_id in (19, 20, 21):
        detail = _short(data.get("Query") or data.get("Destination") or data.get("Name", ""))
    elif event_id == 6:
        detail = f"{data.get('ImageLoaded', '?')} signed={data.get('Signed', '?')}"
    elif event_id == 22:
        detail = f"{data.get('QueryName', '?')} -> {_short(data.get('QueryResults', ''), 120)}"
    elif event_id == 17:
        detail = f"{data.get('PipeName', '?')} by {data.get('Image', '?')}"
    else:
        detail = _short(data.get("Image", ""))

    return {
        "severity": severity,
        "event_id": event_id,
        "title": title,
        "detail": _short(detail),
    }


def summarize_sysmon_events(
    events: list[dict[str, Any]],
    descendant_pids: set[int] | None = None,
) -> dict[str, Any]:
    """Aggregate raw Sysmon events into counts, indicators and highlights.

    ``descendant_pids`` is the sample's process tree. Without it this pass had no
    attribution at all: it tested for the analyzer's own tooling, for two exact
    OS injection pairs and for noise DNS, and everything that fell through those
    three lists became a finding *about the sample*.

    That cost a verdict band on 07 Aug. `dwm.exe` raised a `CreateRemoteThread`
    whose `TargetImage` Sysmon could not resolve, so the pair allowlist -- which
    holds `dwm.exe -> csrss.exe` for exactly this case -- could not match
    `("dwm.exe", "")`. The event became the run's only high-severity highlight,
    `high_severity_count: 1` made `credential_access_or_tampering` present in its
    own right, and the score went 70 to 90, Elevated Attention to Likely
    Malicious, on the Desktop Window Manager.

    A name list cannot be the attribution -- it has to be extended forever and an
    unresolved field defeats it. The lists stay, as suppression aids that run
    *before* attribution; lineage is what decides whose behaviour this was. Fourth
    time this pipeline has needed that fix in the same shape, after the network
    records, the PowerShell blocks and the dropped files.

    ``None`` means lineage could not be resolved and everything is counted, the
    same degrade the other passes use. An empty set would claim the sample
    provably did nothing.
    """
    counts: dict[str, int] = {}
    dns_queries: list[str] = []
    network_targets: list[str] = []
    pipes: list[str] = []
    injections: list[dict[str, str]] = []
    highlights: list[dict[str, Any]] = []
    analyzer_highlights: list[dict[str, Any]] = []
    os_baseline_highlights: list[dict[str, Any]] = []
    other_process_highlights: list[dict[str, Any]] = []
    noise_dns_queries: list[str] = []
    seen_highlights: set[tuple] = set()
    analyzer_events = 0
    os_baseline_events = 0
    noise_dns_events = 0
    other_process_events = 0

    for event in events:
        name = event.get("event_name", "unknown")
        counts[name] = counts.get(name, 0) + 1
        data = event.get("data", {})
        event_id = event.get("event_id")

        # Decided once, per event, and applied to indicators as well as
        # highlights. Sysmon observes the workbench's own tooling exactly as it
        # observes the sample -- FakeNet's WinDivert driver load, and its DNS
        # lookups of the guest hostname, being the recurring cases. The
        # observation is correct; the attribution is not.
        is_analyzer = _is_analyzer_event(event)
        if is_analyzer:
            analyzer_events += 1

        # Windows acting on itself, which is neither the sample nor the
        # tooling. Same treatment as an analyzer event for the same reason:
        # the observation is correct, the attribution is not.
        is_os_baseline = _is_os_baseline_event(event)
        if is_os_baseline:
            os_baseline_events += 1

        # Event 22 records the process that asked, which is the only thing that
        # says whose lookup it was. Office and OneDrive resolving their own
        # endpoints is not the sample's behaviour: one run recorded seven
        # queries, six of them Office's, and the unanswered-lookup warning
        # reported "the sample resolving 7 name(s)".
        #
        # Judged on the requesting image rather than on the domain, because a
        # suffix list has to be extended forever and still misses
        # microsoft.microsoftofficehub.
        is_noise_dns = event_id == 22 and (
            _image_basename(data.get("Image")) in KNOWN_NOISE_PROCESSES
        )
        if is_noise_dns:
            noise_dns_events += 1

        # Whose behaviour this was, asked of the acting PID rather than of a
        # list of everything the sample is not. Applied after the suppression
        # lists above so their counts still describe what they removed.
        belongs_to_sample = (
            descendant_pids is None or _actor_pid(event) in descendant_pids
        )
        if not belongs_to_sample and not is_analyzer and not is_os_baseline and not is_noise_dns:
            other_process_events += 1

        attributable = (
            not is_analyzer
            and not is_os_baseline
            and not is_noise_dns
            and belongs_to_sample
        )

        # Analyzer events stay in total_events and counts, because Sysmon really
        # did see them, but they are kept out of the indicator lists -- those are
        # read as things the sample did.
        if is_noise_dns:
            # Recorded rather than dropped, so a reader can tell "the sample
            # resolved nothing" from "its resolution was filtered".
            query = data.get("QueryName", "").strip()
            if query and query not in noise_dns_queries:
                noise_dns_queries.append(query)

        if attributable:
            if event_id == 22:
                query = data.get("QueryName", "").strip()
                if query and query not in dns_queries:
                    dns_queries.append(query)

            elif event_id == 3:
                host = data.get("DestinationHostname") or data.get("DestinationIp", "")
                port = data.get("DestinationPort", "")
                target = f"{host}:{port}".strip(":")
                if target and target not in network_targets:
                    network_targets.append(target)

            elif event_id in (17, 18):
                pipe = data.get("PipeName", "").strip()
                if pipe and pipe not in pipes:
                    pipes.append(pipe)

            elif event_id == 8:
                injections.append(
                    {
                        "source": data.get("SourceImage", ""),
                        "target": data.get("TargetImage", ""),
                    }
                )

        found = _highlight(event)
        if found:
            key = (found["event_id"], found["detail"])
            if key not in seen_highlights:
                seen_highlights.add(key)
                if is_analyzer:
                    found["analyzer_activity"] = True
                    analyzer_highlights.append(found)
                elif is_os_baseline:
                    found["windows_baseline"] = True
                    os_baseline_highlights.append(found)
                elif is_noise_dns:
                    # Kept out of the findings and out of the count, for the
                    # same reason the analyzer's own lookups are.
                    found["noise_process"] = True
                    os_baseline_highlights.append(found)
                elif not belongs_to_sample:
                    # Real, and not the sample's. Listed rather than dropped, so
                    # "Sysmon saw nothing" and "Sysmon saw it and it was somebody
                    # else's" stay distinguishable -- and because the dwm.exe
                    # event that cost a band would have been visible here.
                    found["other_process"] = True
                    found["actor_pid"] = _actor_pid(event)
                    other_process_highlights.append(found)
                else:
                    highlights.append(found)

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    highlights.sort(key=lambda h: severity_rank.get(h["severity"], 3))
    analyzer_highlights.sort(key=lambda h: severity_rank.get(h["severity"], 3))

    return {
        "total_events": len(events),
        "counts": counts,
        "dns_queries": dns_queries[:200],
        "network_targets": network_targets[:200],
        "named_pipes": pipes[:100],
        "injection_events": injections[:100],
        "highlights": highlights[:100],
        # Kept, not dropped -- same treatment the autoruns diff gives analyzer
        # entries, so the tooling can still be confirmed to have loaded.
        "analyzer_highlights": analyzer_highlights[:50],
        "analyzer_highlights_excluded": len(analyzer_highlights),
        # Same bargain as the analyzer lists above: kept so that "Windows was
        # quiet" and "Windows was filtered" stay distinguishable.
        "os_baseline_highlights": os_baseline_highlights[:50],
        "os_baseline_events_excluded": os_baseline_events,
        # Events by processes outside the sample's tree. The count is the point:
        # a run where this is 0 and a run where lineage could not be resolved are
        # different runs, and `lineage_resolved` says which.
        "other_process_highlights": other_process_highlights[:50],
        "other_process_events_excluded": other_process_events,
        "lineage_resolved": descendant_pids is not None,
        # Lookups made by software that was running anyway. Listed so that
        # "the sample resolved nothing" and "its resolution was filtered"
        # stay distinguishable.
        "noise_dns_queries": noise_dns_queries[:200],
        "noise_dns_excluded": noise_dns_events,
        # Every event attributed to the tooling, not just those that would have
        # become highlights. Without this the difference between "the tooling was
        # quiet" and "the tooling was filtered" is invisible.
        "analyzer_events_excluded": analyzer_events,
        "high_severity_count": sum(1 for h in highlights if h["severity"] == "high"),
    }


def collect(
    since_utc: str,
    evtx_path: str | Path,
    max_events: int = 20000,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Export, query and summarise Sysmon events for a completed run.

    Returns ``(events, summary, status)``. ``status`` records whether the export
    and query succeeded so a partial failure never aborts the wider run.
    """
    status: dict[str, Any] = {"success": False, "error": "", "evtx": {}, "diagnosis": ""}

    status["evtx"] = export_evtx(evtx_path, since_utc)
    status["channel_records"] = channel_record_count()
    status["elevated"] = is_elevated()

    attempts: list[dict[str, Any]] = []
    status["attempts"] = attempts

    try:
        events = query_events(since_utc, max_events=max_events, attempts_out=attempts)
    except SysmonError as error:
        status["error"] = str(error)
        status["diagnosis"] = _diagnose_empty(
            status["channel_records"], failed=True, attempts=attempts,
            elevated=status["elevated"],
        )
        return [], summarize_sysmon_events([]), status

    status["success"] = True
    if not events:
        status["diagnosis"] = _diagnose_empty(
            status["channel_records"], failed=False, attempts=attempts,
            elevated=status["elevated"],
        )

    return events, summarize_sysmon_events(events), status


def is_elevated() -> bool:
    """True when the current process has Administrator rights."""
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _diagnose_empty(
    channel_records: int,
    failed: bool,
    attempts: list[dict[str, Any]] | None = None,
    elevated: bool = True,
) -> str:
    """Explain an empty collection so it is actionable rather than mysterious."""
    attempts = attempts or []
    errors = [a for a in attempts if a.get("error")]

    if not elevated:
        return (
            "The workbench is not running as Administrator. The Sysmon "
            "Operational channel is readable only by administrators, so no "
            "events can be collected. Relaunch the workbench elevated."
        )

    if channel_records == -1:
        return (
            "The Sysmon event channel could not be read, though the service "
            "appears installed. Confirm with "
            "'wevtutil gli Microsoft-Windows-Sysmon/Operational'."
        )
    if channel_records == 0:
        return (
            "The Sysmon channel is empty: the service is installed but is not "
            "writing events. Reapply the configuration in the VM with "
            "'sysmon64.exe -c sysmonconfig.xml'."
        )

    if errors:
        detail = "; ".join(f"{a['strategy']}: {a['error'][:160]}" for a in errors)
        return (
            f"The channel holds {channel_records} records, but every query "
            f"failed. {detail}"
        )

    # Distinguish "wevtutil returned nothing" from "wevtutil returned data we
    # failed to parse". These look identical in the output but need opposite
    # fixes, so the raw byte counts decide it.
    returned_bytes = max((int(a.get("stdout_bytes", 0) or 0) for a in attempts), default=0)
    if returned_bytes > 0:
        return (
            f"The channel holds {channel_records} records and wevtutil returned "
            f"{returned_bytes} bytes, but none of it parsed into events. This is "
            "a parsing fault in the workbench, not a problem with Sysmon."
        )

    return (
        f"The channel holds {channel_records} records, but wevtutil returned no "
        "output for this run's window, including an unfiltered query. Verify "
        "with: wevtutil qe Microsoft-Windows-Sysmon/Operational /c:3 /f:RenderedXml"
    )


# ---------------------------------------------------------------------------
# The boot window
# ---------------------------------------------------------------------------
#
# A payload behind an ONLOGON task runs before anything in this pipeline is
# started, so every collector that opens at run start is looking at the wrong
# window. `logon_capture.py` answers that for Procmon by arming a capture ahead
# of the boot, and the trigger for it is still being built.
#
# Sysmon needs none of that. Its driver is boot-start and its service
# auto-start, so it was already recording before the logon that launched the
# payload -- on every run this project has ever done. The events are sitting in
# the channel; nothing here starts a collector, it reads one that never
# stopped. What Sysmon cannot give is reads: there is no registry-read or
# file-read event in any configuration, so an absence here is not evidence
# about reads, and the manifest says so rather than leaving a reader to assume.


#: Beyond this, the two boot-time sources are treated as disagreeing rather
#: than as clock granularity. Both derive from the same tick on a machine that
#: booted cold; they part company after a save/restore, which a snapshot-driven
#: bench does routinely.
BOOT_TIME_TOLERANCE_SECONDS = 120


def _boot_time_from_ticks() -> Optional[datetime]:
    """Boot time as ``now - GetTickCount64()``.

    Cheap and always available, and it *excludes time spent suspended*. A guest
    restored from a saved state therefore reports an uptime shorter than the
    wall-clock window, which places the boot too late and would crop the
    beginning of the window -- the part the payload starts in.
    """
    try:
        uptime_seconds = int(ctypes.windll.kernel32.GetTickCount64() // 1000)
    except (AttributeError, OSError):
        return None
    return datetime.now(timezone.utc) - timedelta(seconds=uptime_seconds)


def _boot_time_from_cim() -> Optional[datetime]:
    """Boot time as Windows records it, via ``Win32_OperatingSystem``."""
    command = (
        "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime."
        "ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')"
    )
    try:
        result = _run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            timeout=60,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return _parse_event_time((result.stdout or "").strip())


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


#: `None` is a meaningful answer from a boot-time source -- it did not answer --
#: so it cannot double as "not supplied". Injecting `None` for one source used
#: to fall through to querying the live machine, which made the
#: one-source-only case untestable and, worse, silently cross-checked against
#: whatever the bench happened to say.
_UNSET = object()


def resolve_boot_time(
    ticks: Any = _UNSET,
    cim: Any = _UNSET,
) -> dict[str, Any]:
    """When this boot began, from two sources that can disagree.

    Returns the window start in the form `query_events` expects, plus both
    candidates and the gap between them, because a single number here cannot be
    checked by the reader and this one decides what the collection can see.

    **The earlier candidate wins.** The two failure directions are not
    symmetrical: a boot time that is too early collects extra background, which
    lineage then attributes away, while a boot time that is too late drops the
    payload's first seconds and reports the remainder as though it were the
    whole story. One costs noise, the other costs the finding.

    Both sources are injectable so the disagreement can be tested; neither is
    reachable off Windows.
    """
    if ticks is _UNSET:
        ticks = _boot_time_from_ticks()
    if cim is _UNSET:
        cim = _boot_time_from_cim()

    candidates = [value for value in (ticks, cim) if value is not None]
    result: dict[str, Any] = {
        "since_utc": "",
        "source": "",
        "from_ticks": _format_utc(ticks) if ticks else "",
        "from_cim": _format_utc(cim) if cim else "",
        "disagreement_seconds": 0,
        "uptime_seconds": 0,
        "note": "",
    }

    if not candidates:
        result["note"] = (
            "Neither GetTickCount64 nor Win32_OperatingSystem could be read, so "
            "the boot time is unknown and a boot window cannot be bounded."
        )
        return result

    chosen = min(candidates)
    result["since_utc"] = _format_utc(chosen)
    result["uptime_seconds"] = int(
        (datetime.now(timezone.utc) - chosen).total_seconds()
    )

    if ticks is not None and cim is not None:
        gap = int(abs((ticks - cim).total_seconds()))
        result["disagreement_seconds"] = gap
        result["source"] = "ticks" if chosen is ticks else "cim"
        if gap > BOOT_TIME_TOLERANCE_SECONDS:
            result["note"] = (
                f"GetTickCount64 and Win32_OperatingSystem disagree by {gap}s "
                "about when this boot began. The earlier of the two is used, so "
                "the window cannot be short; a gap this size usually means the "
                "guest was restored from a saved state rather than booted."
            )
    else:
        result["source"] = "ticks" if ticks is not None else "cim"
        result["note"] = (
            "Only one boot-time source answered, so nothing cross-checks it."
        )

    return result


def _as_pid(value: object) -> Optional[int]:
    try:
        pid = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return pid or None


def descendants_from_sysmon(
    events: list[dict[str, Any]],
    image_name: str,
) -> Optional[set[int]]:
    """The payload's process tree, built from Sysmon's own process creates.

    A logon-triggered payload has no launched PID -- Task Scheduler started it,
    and `svchost.exe` is its parent -- so the only handle on it is its image
    name, exactly as `_mark_sample_lineage` handles a dropper relaunching
    itself. Seed on every process running that image, then walk
    ``ParentProcessId`` to a fixed point.

    ``None`` means the image never appears in the window, and that is a result
    rather than an empty one: either the persistence did not fire this boot, or
    Sysmon was not recording when it did. Returning an empty set instead would
    read as "the payload ran and did nothing", which is the confusion this
    package exists to prevent.

    PIDs are reused, and within a single boot window that is a real if small
    risk. It is the same exposure the Procmon lineage carries, accepted for the
    same reason.
    """
    target = _image_basename(image_name)
    if not target:
        return None

    creates = [event for event in events if event.get("event_id") == 1]

    pids: set[int] = set()
    for event in creates:
        data = event.get("data", {})
        pid = _as_pid(data.get("ProcessId"))
        if pid and _image_basename(data.get("Image")) == target:
            pids.add(pid)

    if not pids:
        return None

    # Fixed point, for the reason the Procmon walk needs one: a grandchild can
    # be recorded before the child that connects it.
    changed = True
    while changed:
        changed = False
        for event in creates:
            data = event.get("data", {})
            pid = _as_pid(data.get("ProcessId"))
            parent = _as_pid(data.get("ParentProcessId"))
            if pid and pid not in pids and parent in pids:
                pids.add(pid)
                changed = True

    return pids


def payload_appearance(
    events: list[dict[str, Any]],
    image_name: str,
    boot_since_utc: str,
) -> dict[str, Any]:
    """When the persisted payload started, measured rather than assumed.

    This is the number the whole logon-capture problem turns on. `ONSTART` was
    chosen over `ONLOGON` on an *assumption* about ordering that nobody had
    measured, and it was wrong by nearly four minutes. Every boot window read
    here reports the payload's own offset from boot, so the margin a capture
    has to beat is on record before the capture is built.
    """
    target = _image_basename(image_name)
    result: dict[str, Any] = {
        "image": target,
        "seen": False,
        "first_seen": "",
        "seconds_after_boot": None,
        "process_creates": 0,
        "pids": [],
    }
    if not target:
        return result

    boot = _parse_event_time(boot_since_utc)
    first: Optional[datetime] = None

    for event in events:
        if event.get("event_id") != 1:
            continue
        data = event.get("data", {})
        if _image_basename(data.get("Image")) != target:
            continue
        result["process_creates"] += 1
        pid = _as_pid(data.get("ProcessId"))
        if pid:
            result["pids"].append(pid)
        stamp = _parse_event_time(event.get("timestamp", ""))
        if stamp and (first is None or stamp < first):
            first = stamp

    if first is not None:
        result["seen"] = True
        result["first_seen"] = _format_utc(first)
        if boot is not None:
            result["seconds_after_boot"] = int((first - boot).total_seconds())

    return result


def recording_coverage(
    events: list[dict[str, Any]],
    boot_since_utc: str,
) -> dict[str, Any]:
    """When Sysmon actually started recording, against when the boot began.

    The premise of this whole module is that Sysmon's driver is boot-start, so
    the channel covers the payload's first seconds without anything having to
    be armed. Measured on the guest 01 Sep, that premise holds but not for the
    reason stated: boot at 14:25:07, first event at 14:27:58, **a 171-second
    hole at the start of the window**. The payload started at 292s and was
    caught with about two minutes to spare -- margin that came from a slow boot
    rather than from coverage.

    So the gap is reported on every run. A payload that starts inside it would
    be missed exactly the way the Procmon capture missed one, and the manifest
    would otherwise say `since-boot` and look complete.
    """
    boot = _parse_event_time(boot_since_utc)
    result: dict[str, Any] = {
        "first_event": "",
        "first_event_id": 0,
        "first_event_name": "",
        "gap_seconds": None,
        "note": "",
    }
    if not events:
        result["note"] = "No events in the window, so coverage cannot be established."
        return result

    first = events[0]
    result["first_event"] = first.get("timestamp", "")
    result["first_event_id"] = first.get("event_id", 0)
    result["first_event_name"] = first.get("event_name", "")

    stamp = _parse_event_time(result["first_event"])
    if boot is None or stamp is None:
        return result

    gap = int((stamp - boot).total_seconds())
    result["gap_seconds"] = gap
    if gap <= 0:
        return result

    explained = " Its first event is Sysmon's own service-state change, so it was starting, not idle." \
        if first.get("event_id") == 4 else ""
    result["note"] = (
        f"Sysmon recorded nothing for the first {gap}s of this boot.{explained} "
        "Anything the payload did inside that window is not here and is not "
        "absent -- it was never recorded."
    )
    return result


def payload_activity(
    events: list[dict[str, Any]],
    descendant_pids: Optional[set[int]],
) -> dict[str, Any]:
    """What the payload itself did, as opposed to what the machine did.

    `summarize_sysmon_events` filters *highlights* by lineage but counts every
    event on the box, which is the right shape for a detonation -- the run's
    own window is mostly the sample. A boot window is mostly Windows. On the
    01 Sep guest read that produced `ProcessCreate=351, RegistrySetValue=171`
    for a payload that had made exactly one process create, and a reader
    skimming the counts would have credited all of it to the sample.

    So this splits the same events by actor. `_actor_pid` decides who acted,
    which matters for `CreateRemoteThread` and `ProcessAccess`, where reading
    `ProcessId` would credit an injection to its victim.

    ``None`` for the lineage means it could not be resolved, and every list
    here comes back empty rather than full -- the same degrade the rest of the
    module uses, for the same reason.
    """
    result: dict[str, Any] = {
        "attributed": descendant_pids is not None,
        "counts": {},
        "event_total": 0,
        "registry_values_set": [],
        "registry_keys_touched": [],
        "files_created": [],
        "dns_queries": [],
        "network_targets": [],
        "named_pipes": [],
        "processes_created": [],
        "images_loaded": [],
    }
    if not descendant_pids:
        return result

    for event in events:
        actor = _actor_pid(event)
        if actor is None or actor not in descendant_pids:
            continue

        name = event.get("event_name", str(event.get("event_id", "?")))
        result["counts"][name] = result["counts"].get(name, 0) + 1
        result["event_total"] += 1

        data = event.get("data", {}) or {}
        event_id = event.get("event_id")

        if event_id == 13:
            detail = _short(f"{data.get('TargetObject', '?')} = {data.get('Details', '')}")
            if detail not in result["registry_values_set"]:
                result["registry_values_set"].append(detail)
        elif event_id in (12, 14):
            target = _short(data.get("TargetObject", ""))
            if target and target not in result["registry_keys_touched"]:
                result["registry_keys_touched"].append(target)
        elif event_id == 11:
            target = _short(data.get("TargetFilename", ""))
            if target and target not in result["files_created"]:
                result["files_created"].append(target)
        elif event_id == 22:
            query = f"{data.get('QueryName', '?')} -> {_short(data.get('QueryResults', ''), 90)}"
            if query not in result["dns_queries"]:
                result["dns_queries"].append(query)
        elif event_id == 3:
            host = data.get("DestinationHostname") or data.get("DestinationIp", "")
            target = f"{host}:{data.get('DestinationPort', '')}".strip(":")
            if target and target not in result["network_targets"]:
                result["network_targets"].append(target)
        elif event_id in (17, 18):
            pipe = data.get("PipeName", "").strip()
            if pipe and pipe not in result["named_pipes"]:
                result["named_pipes"].append(pipe)
        elif event_id == 1:
            line = _short(f"{data.get('Image', '?')} {data.get('CommandLine', '')}")
            if line not in result["processes_created"]:
                result["processes_created"].append(line)
        elif event_id == 7:
            loaded = _image_basename(data.get("ImageLoaded", ""))
            if loaded and loaded not in result["images_loaded"]:
                result["images_loaded"].append(loaded)

    for key in ("registry_values_set", "registry_keys_touched", "files_created",
                "dns_queries", "network_targets", "named_pipes",
                "processes_created", "images_loaded"):
        result[key] = result[key][:200]

    return result


def collect_since_boot(
    evtx_path: str | Path,
    image_name: str = "",
    max_events: int = 20000,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Read everything Sysmon recorded this boot, and attribute it.

    The counterpart to `collect` for a stage no run was watching. Same export,
    same query, same summary -- the window is the difference, and so is the
    attribution: there is no launched PID to seed from, so ``image_name`` is
    what makes the events anyone's in particular.

    Without it the summary counts the machine's whole boot, which on this bench
    is a known quantity of nothing in particular: an ordinary boot makes ~450
    VM-artifact registry reads and starts dozens of processes, none of them a
    sample. `lineage_resolved: false` says so, and every count in the summary
    should be distrusted when it appears.
    """
    status: dict[str, Any] = {"success": False, "error": "", "evtx": {}, "diagnosis": ""}

    boot = resolve_boot_time()
    status["boot_time"] = boot
    status["window"] = "since-boot"
    status["reads_covered"] = False
    status["reads_note"] = (
        "Sysmon has no registry-read or file-read event. Nothing here is "
        "evidence about what the payload read, only about what it created, "
        "wrote, loaded, connected to or resolved."
    )

    since_utc = boot["since_utc"]
    if not since_utc:
        status["error"] = "boot time could not be resolved"
        status["diagnosis"] = boot["note"]
        return [], summarize_sysmon_events([]), status

    status["evtx"] = export_evtx(evtx_path, since_utc)
    status["channel_records"] = channel_record_count()
    status["elevated"] = is_elevated()

    attempts: list[dict[str, Any]] = []
    status["attempts"] = attempts

    try:
        events = query_events(since_utc, max_events=max_events, attempts_out=attempts)
    except SysmonError as error:
        status["error"] = str(error)
        status["diagnosis"] = _diagnose_empty(
            status["channel_records"], failed=True, attempts=attempts,
            elevated=status["elevated"],
        )
        return [], summarize_sysmon_events([]), status

    status["success"] = True
    status["event_count"] = len(events)
    status["first_event"] = events[0].get("timestamp", "") if events else ""
    status["last_event"] = events[-1].get("timestamp", "") if events else ""

    # A capped read is newest-first, so what it drops is the *oldest* part of
    # the window -- the boot, the logon, and the payload's first seconds. That
    # is the one part of a boot window nobody can afford to lose quietly.
    capped = any(attempt.get("capped") for attempt in attempts if attempt.get("events"))
    status["truncated"] = bool(capped)
    if capped:
        status["truncation_note"] = (
            f"The query returned its cap of {max_events} events, newest first, "
            "so the oldest events in this boot window were dropped -- including "
            "the payload's first seconds. Coverage begins at "
            f"{status['first_event']}, not at boot. Re-read with a higher "
            "--max-events before drawing any conclusion from an absence."
        )

    status["coverage"] = recording_coverage(events, since_utc)

    descendants = descendants_from_sysmon(events, image_name) if image_name else None
    status["lineage_resolved"] = descendants is not None
    status["payload"] = payload_appearance(events, image_name, since_utc)
    status["payload_activity"] = payload_activity(events, descendants)

    if not image_name:
        status["lineage_note"] = (
            "No payload image was given, so nothing is attributed and every "
            "count in the summary is the whole machine's boot."
        )
    elif descendants is None:
        status["lineage_note"] = (
            f"No process running {_image_basename(image_name)} appears in this "
            "boot window. Either the persistence did not fire, or Sysmon was "
            "not recording when it did -- check `channel_records` and the "
            "persistence entry before concluding the payload is inert."
        )

    if not events:
        status["diagnosis"] = _diagnose_empty(
            status["channel_records"], failed=False, attempts=attempts,
            elevated=status["elevated"],
        )

    return events, summarize_sysmon_events(events, descendant_pids=descendants), status
