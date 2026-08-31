"""Run the existing passes over a logon capture, so it produces a result.

`logon_capture.py` collects; this reads what it collected. Deliberately a
**driver and not new analysis** -- it calls `summarize_procmon_events`,
`find_interesting_events`, `summarize_dynamic_findings`,
`collect_vm_artifact_reads` and `correlate_vm_check_with_silence` in the order
`orchestrator.run` calls them, so a logon capture and a detonation are judged by
the same code and cannot drift into disagreeing.

**Lineage was the thing that looked like it needed building, and did not.**
A logon-triggered payload has no launched PID -- nothing in the run started it,
the Task Scheduler did -- so the obvious reading is that attribution is
impossible here and something new is required. It is already handled:
`_mark_sample_lineage` seeds on the sample's *image name* as well as its PID,
because "a dropper relaunching itself is the shape this exists for". Passing
`sample_pid=None` and a name is enough, and the transitive walk over Procmon's
process-create records does the rest.

So the one thing a caller must supply is **which image is the sample**. On
`ce0d08be...` that is the persisted copy under `%APPDATA%\\PlatformRuntime`, and
a detonation names it in its dropped-files output. Without it nothing here can
attribute anything, and this says so rather than reporting the whole machine's
boot as the sample's behaviour.

**Read `logon_capture.json` first.** A capture that did not complete, or one
whose filter could not see registry reads, produces an analysis that is honest
about the events it has and silent about the ones it never could have had.
`analyse_logon_capture` carries both flags through so a reader cannot lose them
between the two files.
"""

from __future__ import annotations

from typing import Any

from dynamic_analysis.findings import summarize_dynamic_findings
from dynamic_analysis.procmon_parser import (
    find_interesting_events,
    summarize_interesting_events,
    summarize_procmon_events,
)
from dynamic_analysis.vm_artifact_reads import (
    collect_vm_artifact_reads,
    correlate_vm_check_with_silence,
)


def analyse_logon_capture(
    events: list[dict[str, Any]],
    sample_name: str,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Everything the detonation passes say about a logon capture.

    ``sample_name`` is the image of the persisted payload. ``manifest`` is the
    `logon_capture.json` the capture wrote, carried through so the collection
    caveats travel with the result rather than being left in another file.
    """
    manifest = manifest or {}
    procmon_filter = manifest.get("procmon_filter") or {}

    interesting = find_interesting_events(events)
    findings = summarize_dynamic_findings(
        events, interesting, sample_pid=None, sample_name=sample_name
    )

    resolved = findings.get("descendant_pids")
    descendant_pids = set(resolved) if resolved is not None else None

    vm_reads = collect_vm_artifact_reads(events, descendant_pids=descendant_pids)
    vm_check = correlate_vm_check_with_silence(
        vm_reads, events, descendant_pids=descendant_pids
    )

    return {
        # The two collection caveats, first, because everything below is only
        # as good as they are.
        "capture_completed": bool(manifest.get("completed", False)) if manifest else None,
        "captures_registry_reads": bool(procmon_filter.get("captures_registry_reads", False)),
        "sample_name": sample_name,
        "lineage_resolved": bool(findings.get("lineage_resolved")),
        "descendant_pids": sorted(descendant_pids) if descendant_pids else [],
        "event_count": len(events),
        "procmon_summary": summarize_procmon_events(events),
        "interesting_summary": summarize_interesting_events(interesting),
        "findings": findings,
        "vm_artifact_reads": vm_reads,
        "vm_check_and_bail": vm_check,
        "note": _note(findings, manifest, procmon_filter),
    }


def _note(
    findings: dict[str, Any],
    manifest: dict[str, Any],
    procmon_filter: dict[str, Any],
) -> str:
    if manifest and not manifest.get("completed", False):
        reason = manifest.get("reason") or "no reason recorded"
        return (
            f"The capture did not complete ({reason}), so anything absent below "
            "is absent from a collection that failed, not from the payload."
        )
    if not findings.get("lineage_resolved"):
        return (
            "No process ran the named image, so nothing could be attributed to "
            "the payload. Either the persisted task did not fire, or the name "
            "given is not the one it runs. This is not a statement that the "
            "payload did nothing."
        )
    if not procmon_filter.get("captures_registry_reads", False):
        return (
            "The Procmon filter captured no registry reads, so the VM-artifact "
            "pass could not have seen one whatever it reports."
        )
    return ""
