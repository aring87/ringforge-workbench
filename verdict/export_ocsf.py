"""The verdict as an OCSF Detection Finding, for a SIEM.

**Why OCSF and not a vendor client.** Splunk, AWS Security Lake, Panther and
Sumo all ingest OCSF natively, so one mapping reaches all of them. Writing a
Splunk SDK integration instead would put this project in the business of
maintaining somebody else's client library, and would not be testable without
a Splunk.

**Why NDJSON to a spool directory.** A pure function to a line of text is
testable offline, survives the SIEM being down, and lets the customer's
existing forwarder do the shipping -- which it is already configured,
monitored and permissioned to do. Nothing here opens a socket.

**The field that makes this worth shipping.** Almost every tool sends a
severity and a score. This sends *coverage*: which modules ran, which were
absent, which categories could not be checked, and whether the band rests on
complete collection. That is what lets a detection engineer write "alert on
Corroborated, and separately alert on Unknown where coverage was incomplete" --
distinguishing a clean sample from one nobody actually looked at. The
distinction this whole model exists to draw does not survive a mapping that
flattens `Unknown` into `Informational`, so it does not.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

#: The OCSF schema release these events are shaped for. Consumers pin it, and
#: it is not the same number as `schema_version` on the verdict document.
OCSF_VERSION = "1.3.0"

#: Detection Finding, in the Findings category.
CLASS_UID = 2004
CATEGORY_UID = 2
#: Create. `type_uid` is `class_uid * 100 + activity_id`, per the spec.
ACTIVITY_ID = 1
TYPE_UID = CLASS_UID * 100 + ACTIVITY_ID

#: **`Unknown` maps to Unknown, never to Informational.** OCSF has a severity
#: for "could not be determined" and using it is the whole point: a case where
#: nothing was collected must not arrive looking like a quiet, clean one.
SEVERITY_ID = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "moderate": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "unknown": 0,
}

#: Bands that assert something happened. Everything else is exported too --
#: suppressing the quiet ones would hide coverage gaps, which are the thing
#: this exporter exists to carry.
_ACTIVE_BANDS = {"Corroborated", "Strongly Corroborated", "Single Observation"}


def _epoch_millis(stamp: str | None) -> int:
    if stamp:
        try:
            text = str(stamp).replace("Z", "+00:00")
            return int(datetime.fromisoformat(text).timestamp() * 1000)
        except Exception:
            pass
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def severity_id(severity: Any) -> int:
    return SEVERITY_ID.get(str(severity or "").strip().lower(), 0)


def _evidences(verdict: Mapping[str, Any]) -> list[dict[str, Any]]:
    """One entry per category that fired, keeping the module that saw it."""
    out = []
    for item in verdict.get("evidence") or []:
        if not isinstance(item, Mapping) or not item.get("reason"):
            continue
        out.append({
            "name": item.get("name"),
            "type": "category",
            "data": {
                "module": item.get("module"),
                "strong": bool(item.get("strong")),
                "reason": item.get("reason"),
                "detail": item.get("detail") or "",
            },
        })
    return out


def _coverage(verdict: Mapping[str, Any]) -> dict[str, Any]:
    """What was and was not looked at.

    Carried as an enrichment rather than buried in `unmapped`, because this is
    the half a detection rule needs and `unmapped` reads as leftovers.
    """
    return {
        "name": "ringforge_coverage",
        "provider": "ringforge-workbench",
        "type": "coverage",
        "data": {
            "complete": bool(verdict.get("coverage_complete")),
            "modules_run": list(verdict.get("modules_run") or []),
            "modules_absent": list(verdict.get("modules_absent") or []),
            "uncollected_categories":
                list(verdict.get("uncollected_categories") or []),
            "band": verdict.get("band"),
            "score_model": verdict.get("score_model"),
        },
    }


def _describe(verdict: Mapping[str, Any]) -> str:
    """The sentence an analyst reads in the SIEM, coverage included."""
    parts = [str(verdict.get("verdict") or "No verdict")]
    band = verdict.get("band")
    if band:
        parts.append(f"band {band}")
    run = verdict.get("modules_run") or []
    parts.append(f"modules run: {', '.join(run) if run else 'none'}")
    absent = verdict.get("modules_absent") or []
    if absent:
        parts.append(f"absent: {', '.join(absent)}")
    if not verdict.get("coverage_complete", True):
        parts.append("COVERAGE INCOMPLETE -- read the band accordingly")
    return ". ".join(parts) + "."


def to_ocsf(verdict: Mapping[str, Any]) -> dict[str, Any]:
    """One `combined_verdict.json` as one Detection Finding."""
    verdict = verdict or {}
    sample = verdict.get("sample") or {}
    provenance = verdict.get("provenance") or {}
    analyzer = provenance.get("analyzer") or {}
    time_ms = _epoch_millis(verdict.get("generated_utc"))
    band = str(verdict.get("band") or "")
    sentence = str(verdict.get("verdict") or "No verdict")
    case_name = str(verdict.get("case_name") or "unnamed case")

    finding: dict[str, Any] = {
        "activity_id": ACTIVITY_ID,
        "activity_name": "Create",
        "category_uid": CATEGORY_UID,
        "category_name": "Findings",
        "class_uid": CLASS_UID,
        "class_name": "Detection Finding",
        "type_uid": TYPE_UID,
        "time": time_ms,
        "severity_id": severity_id(verdict.get("severity")),
        "severity": str(verdict.get("severity") or "Unknown"),
        # New every time; a re-analysis supersedes rather than amends.
        "status_id": 1,
        "status": "New",
        "message": sentence,
        "finding_info": {
            # The sample hash, so a re-run updates the finding instead of
            # duplicating it.
            "uid": str(verdict.get("case_id") or case_name),
            "title": f"{sentence} ({case_name})",
            "desc": _describe(verdict),
            "types": [band] if band else [],
            "created_time": time_ms,
            "analytic": {
                "name": verdict.get("score_model") or "",
                "type_id": 1,
                "type": "Rule",
            },
        },
        "metadata": {
            "version": OCSF_VERSION,
            "logged_time": _epoch_millis(None),
            "product": {
                "name": analyzer.get("name") or "ringforge-workbench",
                "vendor_name": "RingForge",
                "version": analyzer.get("version") or "",
            },
        },
        "enrichments": [_coverage(verdict)],
        "evidences": _evidences(verdict),
        # Not a lossy mapping: everything the model produced that OCSF has no
        # field for is kept verbatim, so a consumer can always recover it.
        "unmapped": {
            "schema_version": verdict.get("schema_version"),
            "score": verdict.get("score"),
            "context_score": verdict.get("context_score"),
            "subscores": verdict.get("subscores"),
            "counts": verdict.get("counts"),
            "domain": verdict.get("domain"),
            "coverage": verdict.get("coverage"),
            "provenance": provenance,
        },
    }

    if sample:
        finding["resources"] = [{
            "type": "file",
            "uid": sample.get("sha256") or "",
            "name": sample.get("filename") or "",
            "data": {
                "hashes": {k: sample[k] for k in ("md5", "sha1", "sha256")
                           if sample.get(k)},
                "size": sample.get("size_bytes"),
            },
        }]
    return finding


def is_actionable(verdict: Mapping[str, Any]) -> bool:
    """Whether the band asserts something, as opposed to reporting coverage.

    Offered so a caller can route rather than filter. Nothing here drops an
    event: a case nobody could look at is exactly what a coverage rule needs
    to see.
    """
    return str((verdict or {}).get("band") or "") in _ACTIVE_BANDS


def write_ndjson(verdicts: Mapping[str, Any] | Iterable[Mapping[str, Any]],
                 spool: str | Path,
                 filename: str = "findings.ndjson") -> Path:
    """Append findings to a spool file for a forwarder to ship.

    Append, never overwrite: the forwarder owns the read cursor and truncating
    under it loses events. One JSON object per line, no trailing separators.
    """
    if isinstance(verdicts, Mapping):
        verdicts = [verdicts]
    spool = Path(spool)
    spool.mkdir(parents=True, exist_ok=True)
    path = spool / filename
    with path.open("a", encoding="utf-8") as handle:
        for verdict in verdicts:
            handle.write(json.dumps(to_ocsf(verdict), ensure_ascii=False,
                                    default=str) + "\n")
    return path
