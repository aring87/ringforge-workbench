"""PowerShell ScriptBlock logging (Event ID 4104).

The reason this is worth collecting is the same reason the memory dumps are:
it sees past obfuscation. PowerShell logs a script block *after* the engine has
decoded it, so a `-EncodedCommand` blob, a `FromBase64String` payload or a
string-concatenation maze is recorded as the plain script that actually ran.
Reading the command line gives you the wrapper; reading 4104 gives you the
contents.

Three properties of 4104 shape everything here.

Long scripts arrive in fragments. A block over roughly 20 KB is split across
several events carrying MessageNumber and MessageTotal against a shared
ScriptBlockId, and the split lands mid-token. Matching patterns per event would
miss anything straddling a boundary, so fragments are reassembled before
anything looks at them.

The channel is noisy in a specific way that matters here: RingForge itself
drives PowerShell for the scheduled-task and service snapshots. Without
filtering, every run reports the analyzer's own `Get-ScheduledTask` and
`ConvertTo-Json` scripts as the sample's behaviour -- the same self-attribution
that inflated the LOLBin counts before it was fixed.

Logging must be enabled *before* the run. Unlike Sysmon, whose channel exists
once installed, ScriptBlock logging is a policy toggle and a disabled channel
looks exactly like a sample that ran no PowerShell. That distinction is what the
preflight exists to make.

Nothing here raises into a run. Every entry point degrades to a status dict.
"""

from __future__ import annotations

import re
from typing import Any, Optional

# Generic Windows Event Log plumbing, not Sysmon-specific: the rendered-XML
# parser absorbs wevtutil's namespace quirks and the timediff query is the one
# time bound that works reliably across builds. A second copy would drift.
from dynamic_analysis.sysmon_collector import (
    _elapsed_ms_since,
    _run,
    _timediff_query,
    parse_rendered_xml,
)

POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"

#: Script block execution. 4103 (pipeline/module logging) is deliberately not
#: collected: it is far noisier and says what was invoked rather than what the
#: code was, which is the question this module exists to answer.
SCRIPTBLOCK_EVENT_ID = 4104

#: Group Policy location the toggle lives at. The analysis VM is missing several
#: CIM namespaces, so the registry is the only route that reliably works there.
_POLICY_KEY = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
_POLICY_VALUE = "EnableScriptBlockLogging"

#: Scripts the workbench runs itself. Matched against the recorded script text.
_ANALYZER_SCRIPT_MARKERS = (
    "get-scheduledtask",
    "get-ciminstance win32_service",
    "schtasks",
    "autorunsc",
    "procmon",
    "procdump",
    "ringforge",
    "dynamic_analysis",
    "tasks_before",
    "tasks_after",
    "services_before",
    "services_after",
    "__psscriptpolicytest",
)

#: Behaviours worth surfacing, with the weight each carries. Deliberately about
#: what a script *does* rather than how it is written: obfuscation alone is
#: suspicious but common in legitimate tooling, whereas downloading and
#: executing is the thing being looked for.
_SUSPICIOUS_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"\bfrombase64string\b", "Base64 decoding", "high"),
    (r"\b(?:iex|invoke-expression)\b", "Dynamic code execution", "high"),
    (r"\bdownloadstring\b|\bdownloadfile\b|\bdownloaddata\b", "Remote content download", "high"),
    (r"\bnet\.webclient\b|\binvoke-webrequest\b|\bstart-bitstransfer\b", "Web client use", "medium"),
    (r"\bvirtualalloc\b|\bwriteprocessmemory\b|\bcreateremotethread\b", "Shellcode / injection APIs", "high"),
    (r"\[reflection\.assembly\]::load|\bassembly\]::load\b", "In-memory assembly load", "high"),
    (r"\bamsiutils\b|\bamsiinitfailed\b|\bamsiscanbuffer\b", "AMSI tampering", "high"),
    (r"-encodedcommand\b|\s-enc\s", "Encoded command", "high"),
    (r"\bset-mppreference\b|\badd-mppreference\b", "Defender modification", "high"),
    (r"\bnew-object\s+system\.net\b", "Raw network object", "medium"),
    (r"\bhidden\b.*\bwindowstyle\b|\bwindowstyle\b.*\bhidden\b", "Hidden window", "medium"),
    (r"\bbypass\b.*\bexecutionpolicy\b|\bexecutionpolicy\b.*\bbypass\b", "Execution policy bypass", "medium"),
    (r"\bnew-scheduledtask\b|\bregister-scheduledtask\b", "Scheduled task creation", "high"),
    (r"\bstart-process\b", "Process launch", "low"),
)

_COMPILED_PATTERNS = tuple(
    (re.compile(pattern, re.IGNORECASE), label, severity)
    for pattern, label, severity in _SUSPICIOUS_PATTERNS
)

_SEVERITY_POINTS = {"high": 3, "medium": 2, "low": 1}


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

def scriptblock_logging_enabled() -> bool:
    """True when the Group Policy toggle is set."""
    try:
        result = _run(["reg", "query", _POLICY_KEY, "/v", _POLICY_VALUE], timeout=20)
    except Exception:
        return False
    if result.returncode != 0:
        return False
    match = re.search(r"REG_DWORD\s+0x([0-9a-fA-F]+)", result.stdout or "")
    return bool(match and int(match.group(1), 16) == 1)


def channel_available() -> bool:
    try:
        result = _run(["wevtutil", "gl", POWERSHELL_CHANNEL], timeout=20)
        return result.returncode == 0
    except Exception:
        return False


def powershell_logging_status() -> dict[str, Any]:
    """Preflight summary describing whether script text can be captured."""
    enabled = scriptblock_logging_enabled()
    channel = channel_available()

    if enabled and channel:
        note = "ScriptBlock logging is enabled; script text will be captured."
    elif not channel:
        note = (
            f"The {POWERSHELL_CHANNEL} channel is unavailable. PowerShell "
            "activity cannot be recorded on this host."
        )
    else:
        note = (
            "ScriptBlock logging is DISABLED. PowerShell will run without its "
            "script text being recorded, and an empty result will be "
            "indistinguishable from a sample that used no PowerShell. Enable it "
            "with scripts\\bootstrap_tools.ps1 -EnableScriptBlockLogging."
        )

    return {
        "available": bool(enabled and channel),
        "logging_enabled": enabled,
        "channel_available": channel,
        "policy_key": _POLICY_KEY,
        "note": note,
    }


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def query_scriptblocks(since_utc: str, max_events: int = 5000) -> list[dict[str, Any]]:
    """Return raw 4104 events recorded since ``since_utc``."""
    elapsed_ms = _elapsed_ms_since(since_utc)
    xpath = (
        f"*[System[EventID={SCRIPTBLOCK_EVENT_ID} and "
        f"TimeCreated[timediff(@SystemTime) <= {int(elapsed_ms)}]]]"
    )

    cmd = [
        "wevtutil", "qe", POWERSHELL_CHANNEL,
        f"/q:{xpath}",
        "/f:RenderedXml",
        f"/c:{int(max_events)}",
        "/rd:true",
    ]

    try:
        result = _run(cmd, timeout=300)
    except Exception:
        return []
    if result.returncode != 0:
        # A disabled channel or an absent one both land here, and the preflight
        # already explains which.
        return []

    events = parse_rendered_xml(result.stdout or "")
    return [e for e in events if e.get("event_id") == SCRIPTBLOCK_EVENT_ID]


def reassemble(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Join multi-part script blocks back into whole scripts.

    PowerShell splits a long block across events at a fixed byte size, with no
    regard for token boundaries. Scanning the fragments individually misses any
    pattern that happens to straddle a split, which is precisely what a long
    obfuscated payload produces.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []

    for event in events:
        data = event.get("data", {}) or {}
        block_id = str(data.get("ScriptBlockId", "") or "")
        # Events without an id cannot be grouped; give each its own bucket
        # rather than merging unrelated scripts under a shared empty key.
        key = block_id or f"_anon_{len(order)}_{id(event)}"
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(event)

    blocks: list[dict[str, Any]] = []
    for key in order:
        parts = grouped[key]

        def part_number(entry: dict[str, Any]) -> int:
            try:
                return int((entry.get("data", {}) or {}).get("MessageNumber", 1) or 1)
            except (TypeError, ValueError):
                return 1

        parts.sort(key=part_number)
        first = parts[0]
        data = first.get("data", {}) or {}

        text = "".join(
            str((p.get("data", {}) or {}).get("ScriptBlockText", "") or "") for p in parts
        )

        try:
            expected = int(data.get("MessageTotal", len(parts)) or len(parts))
        except (TypeError, ValueError):
            expected = len(parts)

        blocks.append({
            "script_block_id": str(data.get("ScriptBlockId", "") or ""),
            "path": str(data.get("Path", "") or ""),
            "timestamp": first.get("timestamp", ""),
            # Which powershell.exe ran it. 4104 carries no EventData ProcessId,
            # so this comes from the System block's Execution element.
            "process_id": str(first.get("execution_process_id", "") or ""),
            "text": text,
            "parts": len(parts),
            "parts_expected": expected,
            # A block whose fragments did not all arrive is still worth
            # reporting, but the gap has to be visible: a missing middle can
            # hide the interesting line.
            "complete": len(parts) >= expected,
            "length": len(text),
        })

    return blocks


def _is_analyzer_script(text: str, path: str = "") -> bool:
    """True for PowerShell the workbench ran itself."""
    haystack = f"{text} {path}".lower()
    return any(marker in haystack for marker in _ANALYZER_SCRIPT_MARKERS)


def classify_script(text: str) -> list[dict[str, str]]:
    """Behaviours matched in a script block."""
    findings: list[dict[str, str]] = []
    for pattern, label, severity in _COMPILED_PATTERNS:
        if pattern.search(text):
            findings.append({"label": label, "severity": severity})
    return findings


def summarize_scriptblocks(
    blocks: list[dict[str, Any]],
    sample_pids: set[int] | None = None,
) -> dict[str, Any]:
    """Reduce reassembled blocks to the shape the run summary carries.

    ``sample_pids`` is the sample's process tree. Without it every block in the
    window counts as the sample's, which is how a mimikatz control run --
    a sample that spawned nothing at all -- reported 24 blocks from the sample
    and one suspicious: Windows Troubleshooting had run
    ``C:\\WINDOWS\\TEMP\\SDIAG_*\\TS_DiagnosticHistory.ps1`` during the window,
    and it raised a scripted_execution finding against a process the sample
    never touched.

    Passing an empty set is not the same as passing none. None means lineage
    could not be resolved and everything is counted, the way the findings
    degrade; an empty set would mean the sample provably ran nothing.
    """
    sample_blocks: list[dict[str, Any]] = []
    analyzer_count = 0
    other_process_count = 0
    seen_text: set[str] = set()

    for block in blocks:
        if _is_analyzer_script(block.get("text", ""), block.get("path", "")):
            analyzer_count += 1
            continue

        if sample_pids is not None:
            try:
                pid = int(str(block.get("process_id", "")).strip())
            except (TypeError, ValueError):
                pid = -1
            if pid not in sample_pids:
                # Recorded, not discarded: a run where the host was busy and
                # the sample quiet has to look different from a quiet run.
                other_process_count += 1
                continue

        text = block.get("text", "")
        # PowerShell re-logs a block every time it is compiled, so a loop or a
        # repeated call floods the channel with identical text.
        fingerprint = text.strip()
        if fingerprint in seen_text:
            continue
        seen_text.add(fingerprint)

        matched = classify_script(text)
        sample_blocks.append({
            "script_block_id": block.get("script_block_id", ""),
            "path": block.get("path", ""),
            "timestamp": block.get("timestamp", ""),
            "length": block.get("length", 0),
            "complete": block.get("complete", True),
            "behaviours": [m["label"] for m in matched],
            "severity": _highest_severity(matched),
            "score": sum(_SEVERITY_POINTS.get(m["severity"], 0) for m in matched),
            # Truncated: the full text lives in the case directory. An event
            # summary that embeds whole scripts becomes unreadable, and this
            # content is attacker-controlled.
            "preview": _preview(text),
        })

    sample_blocks.sort(key=lambda b: b["score"], reverse=True)
    suspicious = [b for b in sample_blocks if b["score"] > 0]

    return {
        "collected": True,
        "attributed_by_lineage": sample_pids is not None,
        "counts": {
            "blocks_total": len(blocks),
            "blocks_from_sample": len(sample_blocks),
            "blocks_suspicious": len(suspicious),
            "analyzer_blocks_excluded": analyzer_count,
            "other_process_blocks_excluded": other_process_count,
            "incomplete_blocks": sum(1 for b in sample_blocks if not b["complete"]),
        },
        "behaviours": sorted({b for block in sample_blocks for b in block["behaviours"]}),
        "score": sum(b["score"] for b in sample_blocks),
        "blocks": sample_blocks[:50],
    }


def _highest_severity(matched: list[dict[str, str]]) -> str:
    for level in ("high", "medium", "low"):
        if any(m["severity"] == level for m in matched):
            return level
    return "none"


def _preview(text: str, limit: int = 400) -> str:
    collapsed = re.sub(r"\s+", " ", (text or "").strip())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + " ..."


def empty_summary(note: str = "") -> dict[str, Any]:
    return {
        "collected": False,
        "note": note,
        "counts": {},
        "behaviours": [],
        "score": 0,
        "blocks": [],
    }


def collect(
    since_utc: str,
    max_events: int = 5000,
    sample_pids: set[int] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Collect and summarise script blocks for a completed run.

    ``sample_pids`` restricts the result to PowerShell the sample's own tree
    ran. Without it the window is the only filter, and anything Windows
    scheduled during the run counts as the sample's behaviour.
    """
    status = powershell_logging_status()
    if not status["available"]:
        return [], empty_summary(status["note"])

    events = query_scriptblocks(since_utc, max_events=max_events)
    blocks = reassemble(events)
    summary = summarize_scriptblocks(blocks, sample_pids=sample_pids)
    summary["note"] = status["note"]
    return blocks, summary
