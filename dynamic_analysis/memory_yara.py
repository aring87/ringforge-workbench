"""YARA over process memory dumps.

A dump is only worth taking if something reads it. The signal this exists for is
narrow and specific: rules that match a process's memory but *not* the sample on
disk. That difference is a packed or encrypted payload becoming visible -- the
one thing static analysis structurally cannot reach -- and it is far stronger
evidence than any raw count of matches.

To make that comparison honest, the sample on disk and every dump are scanned in
the same pass with the same compiled ruleset. Diffing against a separate static
run would compare results produced by whatever rules happened to be installed at
the time, which is not the same question.

Two properties of scanning a minidump are worth stating plainly, because both
are easy to misread:

- Rules built on PE structure (anything using the ``pe`` module) cannot match a
  raw dump. Their absence from the results means nothing at all.
- Match offsets are byte offsets into the dump file, not virtual addresses in
  the process. They are reported as ``dump_file_offset`` so nobody treats them
  as a VA.

Nothing here raises into the run. A missing yara-python, an absent rules
directory, a rule that fails to compile, or a dump that takes too long all
degrade to a status dict.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any, Callable, Optional

# Reusing the static engine's match parser rather than reimplementing it. It
# absorbs the differences between yara-python versions -- StringMatch objects
# with .instances in newer builds, (offset, identifier, data) tuples in older
# ones -- and a second copy of that logic would drift.
from static_triage_engine.yara_scan import _collect_rule_files, _parse_match

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None

StatusCallback = Optional[Callable[[str], None]]

#: A full dump is hundreds of megabytes, so the static path's 60-second default
#: is far too short. This is per file, not per run.
DEFAULT_TIMEOUT_SECONDS = 300

#: Externals declared by many public rulesets. Compiling without them fails the
#: whole ruleset on an undefined identifier, which reads as "no rules" rather
#: than "your rules need these", so they are supplied empty.
_COMMON_EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "owner": "",
    "md5": "",
}


# ---------------------------------------------------------------------------
# Rules discovery
# ---------------------------------------------------------------------------

def resolve_rules_dir(configured: str | Path | None = None) -> Optional[Path]:
    """Locate the YARA rules directory.

    Delegates to the static engine's resolver so a dynamic run scans with
    exactly the rules a static run would use. The memory-versus-disk comparison
    is only meaningful if both sides came from the same ruleset.
    """
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_dir():
            return candidate

    try:
        from static_triage_engine.config import TriageConfig
        from static_triage_engine.steps import _resolve_yara_rules_dir

        return _resolve_yara_rules_dir(TriageConfig())
    except Exception:
        return None


#: Where hand-written rules are authored, relative to the repository root.
#:
#: This directory is tracked by git. `tools\\yara\\rules\\` is not -- it is deleted
#: and rebuilt by `bootstrap_yara_rules.ps1`, which copies this one into it as
#: its last step. So a rule can be written, reviewed, committed and pulled, and
#: still never reach the scanner.
LOCAL_RULES_RELATIVE = Path("tools") / "yara" / "local"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def local_rule_drift(rules_dir: Path | None,
                     canonical_dir: Path | None = None) -> dict[str, Any]:
    """Compare the authored local rules against the copies being scanned.

    **`rules_dir` is reported by every run; its freshness never was.** Run
    `4bb6b0d5` scanned ten dumps against a `local\\` subdirectory dated 16 Aug
    that did not contain `ringforge_etherhiding.yar` at all -- four days older
    than the rule, and written up as "no matches" because a rule that is absent
    and a rule that does not fire produce the same number. That number is the
    one people read. This is the smallest thing that tells them apart *before*
    the run rather than after it.

    Missing and stale are separated because they are different mistakes: stale
    means the bootstrap ran before the last edit, missing means it has not run
    since the rule was created.
    """
    result: dict[str, Any] = {
        "checked": False, "missing": [], "stale": [], "current": [],
        "canonical_dir": "", "scanned_dir": "", "note": "",
    }

    canonical = (Path(canonical_dir) if canonical_dir
                 else Path(__file__).resolve().parents[1] / LOCAL_RULES_RELATIVE)
    result["canonical_dir"] = str(canonical)
    if rules_dir is None or not canonical.is_dir():
        result["note"] = (
            "No authored rules directory to compare against; freshness unknown."
        )
        return result

    scanned = Path(rules_dir) / "local"
    result["scanned_dir"] = str(scanned)
    result["checked"] = True

    for source in sorted(canonical.glob("*.yar")) + sorted(canonical.glob("*.yara")):
        target = scanned / source.name
        try:
            if not target.is_file():
                result["missing"].append(source.name)
            elif _digest(source) != _digest(target):
                result["stale"].append(source.name)
            else:
                result["current"].append(source.name)
        except OSError:
            # Unreadable counts as stale: the safe direction is to warn.
            result["stale"].append(source.name)

    missing, stale = result["missing"], result["stale"]
    if missing or stale:
        parts = []
        if missing:
            parts.append(f"{len(missing)} missing ({', '.join(missing)})")
        if stale:
            parts.append(f"{len(stale)} stale ({', '.join(stale)})")
        result["note"] = (
            f"Authored rules in {canonical} differ from the scanned copies in "
            f"{scanned}: {'; '.join(parts)}. Run "
            f"scripts\\bootstrap_yara_rules.ps1, or copy tools\\yara\\local\\*.yar "
            f"into it -- until then those rules cannot match, and a run will "
            f"report zero rather than an error."
        )
    else:
        result["note"] = (
            f"{len(result['current'])} authored rule file(s) match the scanned copies."
        )
    return result


def memory_yara_status(configured_rules_dir: str | Path | None = None) -> dict[str, Any]:
    """Preflight summary describing whether dumps can be scanned."""
    rules_dir = resolve_rules_dir(configured_rules_dir)
    rule_files = _collect_rule_files(rules_dir) if rules_dir else {}
    drift = local_rule_drift(rules_dir)

    if yara is None:
        available = False
        note = (
            "yara-python is not installed. Install it in the analysis VM "
            "(pip install -r requirements.txt) to scan process memory."
        )
    elif rules_dir is None:
        available = False
        note = (
            "No YARA rules directory found. Run scripts\\bootstrap_yara_rules.ps1, "
            "or set YARA_RULES_DIR, or place rules under tools\\yara\\rules."
        )
    elif not rule_files:
        available = False
        note = (
            f"The rules directory {rules_dir} contains no .yar or .yara files. "
            "Memory dumps will be written but not scanned."
        )
    else:
        available = True
        note = f"{len(rule_files)} YARA rule file(s) available for scanning process memory."

    # **Drift does not make the scan unavailable, and must not be silent
    # either.** The ruleset still compiles and still matches; it is simply not
    # the ruleset the operator believes they are running. `warning` is rendered
    # beside "ready" in the preflight strip, which is the only place anyone
    # looks before starting a run.
    warning = ""
    if drift.get("missing") or drift.get("stale"):
        counts = []
        if drift["missing"]:
            counts.append(f"{len(drift['missing'])} local rule(s) MISSING")
        if drift["stale"]:
            counts.append(f"{len(drift['stale'])} STALE")
        warning = ", ".join(counts)
        note = f"{note} {drift['note']}"

    return {
        "available": bool(available),
        "engine": "yara-python",
        "yara_available": yara is not None,
        "rules_dir": str(rules_dir) if rules_dir else "",
        "rule_file_count": len(rule_files),
        "local_rules": drift,
        "warning": warning,
        "note": note,
    }


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _relabel_offsets(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rename string offsets so they cannot be mistaken for virtual addresses."""
    for match in matches:
        for entry in match.get("strings", []) or []:
            if "offset" in entry:
                entry["dump_file_offset"] = entry.pop("offset")
    return matches


def _scan_one(
    compiled: Any,
    path: Path,
    timeout: int,
    relabel: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path),
        "file": path.name,
        "size": 0,
        "rules": [],
        "matches": [],
        "duration_seconds": 0,
        "error": "",
    }

    if not path.exists():
        result["error"] = "file not found"
        return result

    try:
        result["size"] = path.stat().st_size
    except Exception:
        pass

    started = time.monotonic()
    try:
        raw = compiled.match(str(path), timeout=timeout)
    except Exception as error:
        # yara.TimeoutError on a large dump is the expected failure here, but a
        # scan error of any kind must cost only this file.
        result["error"] = f"{type(error).__name__}: {error}"
        result["duration_seconds"] = int(time.monotonic() - started)
        return result

    result["duration_seconds"] = int(time.monotonic() - started)
    matches = [_parse_match(m) for m in raw]
    if relabel:
        matches = _relabel_offsets(matches)

    result["matches"] = matches
    result["rules"] = sorted({m.get("rule", "") for m in matches if m.get("rule")})
    return result


def scan_memory_dumps(
    dump_records: list[dict[str, Any]],
    sample_path: str | Path,
    rules_dir: str | Path | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    status_cb: StatusCallback = None,
) -> dict[str, Any]:
    """Scan the sample and every dump with one compiled ruleset.

    ``dump_records`` are the successful entries from a MemoryDumpSession, so each
    scan result keeps the pid, offset and trigger that produced it -- a match is
    much easier to act on when it says which process it came from and when.
    """
    def emit(message: str) -> None:
        if status_cb:
            status_cb(message)

    resolved = resolve_rules_dir(rules_dir)
    result: dict[str, Any] = {
        "scanned": False,
        "engine": "yara-python",
        "rules_dir": str(resolved) if resolved else "",
        "rule_file_count": 0,
        "timeout_seconds": int(timeout),
        "disk": {},
        "dumps": [],
        "memory_only_rules": [],
        "counts": {},
        "error": "",
        "note": (
            "Match offsets are byte offsets into the dump file, not virtual "
            "addresses. Rules that depend on PE structure cannot match a raw "
            "dump, so their absence is not evidence."
        ),
    }

    if yara is None:
        result["error"] = "yara-python is not installed"
        return result

    if resolved is None:
        result["error"] = "no YARA rules directory found"
        return result

    filepaths = _collect_rule_files(resolved)
    result["rule_file_count"] = len(filepaths)
    if not filepaths:
        result["error"] = f"no .yar or .yara files under {resolved}"
        return result

    # Compiled once and reused. Compiling per file would repeat the most
    # expensive part of the pass for every dump.
    emit(f"Compiling {len(filepaths)} YARA rule file(s)...")
    try:
        compiled = yara.compile(filepaths=filepaths, externals=dict(_COMMON_EXTERNALS))
    except Exception as error:
        result["error"] = f"rule compilation failed: {error}"
        return result

    sample = Path(sample_path)
    emit(f"Scanning the sample on disk: {sample.name}")
    disk = _scan_one(compiled, sample, timeout, relabel=False)
    result["disk"] = disk
    if disk.get("error"):
        emit(f"  disk scan warning: {disk['error']}")

    disk_rules = set(disk.get("rules", []))
    memory_rules: set[str] = set()

    for record in dump_records:
        path = Path(str(record.get("path", "")))
        emit(f"Scanning {path.name} ({int(record.get('size', 0) or 0) // (1024 * 1024)} MB)...")

        scan = _scan_one(compiled, path, timeout, relabel=True)
        scan.update(
            {
                "pid": record.get("pid"),
                "process_name": record.get("name", ""),
                "offset_seconds": record.get("offset_seconds"),
                "trigger": record.get("trigger", ""),
            }
        )
        result["dumps"].append(scan)
        memory_rules.update(scan.get("rules", []))

        if scan.get("error"):
            emit(f"  scan failed: {scan['error']}")
        elif scan.get("rules"):
            emit(f"  {len(scan['rules'])} rule(s) matched in {scan['duration_seconds']}s")
        else:
            emit(f"  no matches ({scan['duration_seconds']}s)")

    memory_only = sorted(memory_rules - disk_rules)

    result["scanned"] = True
    result["memory_only_rules"] = memory_only
    result["counts"] = {
        "dumps_scanned": len(result["dumps"]),
        "dumps_with_matches": sum(1 for d in result["dumps"] if d.get("rules")),
        "dumps_failed": sum(1 for d in result["dumps"] if d.get("error")),
        "disk_rules": len(disk_rules),
        "memory_rules": len(memory_rules),
        "memory_only_rules": len(memory_only),
        "total_matches": sum(len(d.get("matches", [])) for d in result["dumps"]),
    }

    if memory_only:
        emit(
            f"{len(memory_only)} rule(s) matched in memory but not on disk: "
            f"{', '.join(memory_only[:6])}"
        )

    return result


# ---------------------------------------------------------------------------
# Summarising
# ---------------------------------------------------------------------------

def summarize_memory_yara(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Reduce a scan to the shape the run summary and report carry."""
    if not isinstance(scan_result, dict) or not scan_result.get("scanned"):
        return {
            "scanned": False,
            "error": (scan_result or {}).get("error", "") if isinstance(scan_result, dict) else "",
            "counts": {},
            "memory_only_rules": [],
            "per_dump": [],
        }

    counts = scan_result.get("counts", {}) or {}
    disk = scan_result.get("disk", {}) or {}

    return {
        "scanned": True,
        "error": scan_result.get("error", ""),
        "rules_dir": scan_result.get("rules_dir", ""),
        "rule_file_count": scan_result.get("rule_file_count", 0),
        "counts": counts,
        "disk_rules": disk.get("rules", []),
        # The headline finding: visible in memory, invisible on disk.
        "memory_only_rules": scan_result.get("memory_only_rules", []),
        "per_dump": [
            {
                "pid": dump.get("pid"),
                "process_name": dump.get("process_name", ""),
                "offset_seconds": dump.get("offset_seconds"),
                "trigger": dump.get("trigger", ""),
                "file": dump.get("file", ""),
                "rules_matched": len(dump.get("rules", [])),
                "rules": ", ".join(dump.get("rules", [])[:8]),
                "duration_seconds": dump.get("duration_seconds", 0),
                "error": dump.get("error", ""),
            }
            for dump in scan_result.get("dumps", []) or []
        ],
        "note": scan_result.get("note", ""),
    }
