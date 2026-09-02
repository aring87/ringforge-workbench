"""A run that installs persistence has a stage it will never watch.

**The measured case.** `ce0d08be...` dropped 23 files, installed an `ONLOGON`
scheduled task, and exited eight seconds in. The run scored it *Likely
Malicious, 140, High* on that alone -- a correct verdict about the installer.
Everything the sample actually is happened in the copy that task launches:
resident, beaconing every 17.03 s to a hardcoded C2, reporting the machine's
hardware and clipboard to an operator, carrying a ransom capability. None of it
was in the run, and nothing in the report said so.

That is the gap this module names. It does not close it -- see below -- but a
summary that stays quiet about an unobserved stage is the same failure as a
collector that reports clean when it could not see: **the reader cannot tell
"nothing happened" from "nobody looked".**

**Why the orchestrator cannot simply run it.** The gated capture spans a
reboot. `AutoAdminLogon` goes to 0, the guest boots to a sign-in screen and
stops, an `ONSTART` task starts a filtered Procmon capture, that capture
confirms its own backing file and signals the host over a guest property, and
only then does the host drive a logon. `run_dynamic_analysis` executes inside
the guest, within one boot, and is gone before any of that. The host half is
`scripts/vm_gated_logon.ps1`.

So this reports rather than acts, and says exactly what to do next. That is a
deliberate boundary, not an unfinished feature: a function that claimed to
observe the deferred stage and could not would be worse than one that declines
and hands over the procedure.

**What counts as deferred.** A persistence entry added during the run whose
trigger fires at a *future* logon or boot -- `diff_tasks` already classifies
those as `logon_trigger` and `boot_trigger` -- or an autoruns entry, which is
by definition a start-up hook. A service is not counted here: services start
within a boot the run may still observe, and treating them the same would
report a gap that is not there.
"""

from __future__ import annotations

from typing import Any

#: Trigger reasons from `diff_tasks._task_is_suspicious` that mean "later".
DEFERRED_TRIGGER_REASONS = ("logon_trigger", "boot_trigger")


def _tasks_with_deferred_triggers(task_diff_summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Added tasks that fire at a future logon or boot."""
    if not isinstance(task_diff_summary, dict):
        return []

    found: list[dict[str, Any]] = []
    for key in ("added_tasks", "suspicious_added_tasks", "added", "suspicious_tasks"):
        entries = task_diff_summary.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            reasons = entry.get("reasons") or entry.get("suspicious_reasons") or []
            if not isinstance(reasons, (list, tuple)):
                reasons = [reasons]
            matched = [r for r in reasons if str(r) in DEFERRED_TRIGGER_REASONS]
            if not matched:
                continue
            record = {
                "kind": "scheduled_task",
                "name": entry.get("name") or entry.get("task_name") or "",
                "triggers": matched,
                "action": _first_action(entry),
            }
            if record not in found:
                found.append(record)
        if found:
            break
    return found


def _first_action(entry: dict[str, Any]) -> str:
    actions = entry.get("actions")
    if isinstance(actions, list) and actions:
        first = actions[0]
        if isinstance(first, dict):
            execute = str(first.get("execute") or "").strip()
            arguments = str(first.get("arguments") or "").strip()
            return f"{execute} {arguments}".strip()
        return str(first)
    return str(entry.get("action") or "")


def _autorun_entries(autoruns_diff_summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Suspicious autoruns entries added or modified during the run.

    Every autoruns entry is a start-up hook by definition, so any of them is
    deferred. Only the suspicious ones are listed: the analyzer's own
    registrations are already split out upstream, and an unremarkable new entry
    is not worth sending someone through a gated run for.
    """
    if not isinstance(autoruns_diff_summary, dict):
        return []

    found: list[dict[str, Any]] = []
    for key in ("suspicious_new_entries", "suspicious_modified_entries"):
        for entry in autoruns_diff_summary.get(key) or []:
            if not isinstance(entry, dict):
                continue
            record = {
                "kind": "autorun",
                "name": entry.get("entry") or entry.get("Entry") or entry.get("name") or "",
                "location": entry.get("entry_location") or entry.get("Entry Location") or "",
                "action": entry.get("image_path") or entry.get("Image Path") or "",
            }
            if record not in found:
                found.append(record)
    return found


def assess_deferred_stage(
    task_diff_summary: dict[str, Any] | None = None,
    autoruns_diff_summary: dict[str, Any] | None = None,
    sample_name: str = "",
) -> dict[str, Any]:
    """Did this run install something it will never see run?

    Returns a block for the run summary. ``present`` is the finding;
    ``observed`` is always False and is stated rather than implied, because the
    whole point is that the pipeline observes one boot.
    """
    entries = _tasks_with_deferred_triggers(task_diff_summary or {})
    entries += _autorun_entries(autoruns_diff_summary or {})

    result: dict[str, Any] = {
        "present": bool(entries),
        "observed": False,
        "entries": entries[:50],
        "entry_count": len(entries),
        "note": "",
        "procedure": [],
    }

    if not entries:
        result["note"] = (
            "No persistence with a future logon or boot trigger was added "
            "during this run, so there is no deferred stage to watch. This is "
            "a statement about what was installed, not about what the sample "
            "is capable of installing elsewhere."
        )
        return result

    kinds = ", ".join(sorted({e["kind"] for e in entries}))
    result["note"] = (
        f"{len(entries)} persistence entr(y/ies) ({kinds}) fire at a future "
        "logon or boot. **This run did not observe what they launch.** Every "
        "dynamic detector here watches one boot, so the verdict above "
        "describes the installer stage only. On the one sample where this was "
        "measured, the installer scored Likely Malicious at 140 while the "
        "resident stage it launched -- beaconing, reporting the machine, "
        "carrying a ransom capability -- was never in a run at all."
    )

    image = sample_name or "<the persisted image>"
    result["procedure"] = [
        "Arm the capture and close the gate, in the guest, elevated: "
        "scripts\\logon_capture.py --arm --gate-logon --out C:\\logon-capture "
        "--procmon <renamed procmon> --window 600",
        "Snapshot the armed state so the run is repeatable.",
        "From the host: scripts\\vm_gated_logon.ps1 -Snapshot <that snapshot> "
        "-ProveChannel, which waits for the capture to confirm its own backing "
        "file before any logon exists.",
        "Log on when it says Channel proven. The payload starts inside a "
        "capture already known to be recording.",
        f"Afterwards: scripts\\sysmon_since_boot.py --out <dir> --image {image} "
        "for the boot window, and logon_capture.py --analyse for the capture.",
        "Check ready_seconds_after_boot against the payload's "
        "seconds_after_boot. The second must be larger or the run says nothing "
        "about the payload's first seconds.",
    ]
    return result


def describe_for_status(assessment: dict[str, Any]) -> str:
    """One status line, or empty when there is nothing to say."""
    if not assessment.get("present"):
        return ""
    count = assessment.get("entry_count", 0)
    return (
        f"DEFERRED STAGE: {count} persistence entr(y/ies) fire at a future "
        "logon or boot and this run did not observe what they launch. "
        "See deferred_stage.procedure in the run summary."
    )
