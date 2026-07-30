"""Reduce a static triage summary to one SIEM event.

A `run_case` summary is the wrong shape to index. It is large, deeply nested,
carries thousands of extracted file paths, and embeds decoded strings lifted
verbatim out of the sample. Indexing it raw produces an index that is expensive
to search and, worse, one that quietly accumulates attacker-controlled content
in a system analysts trust.

So this builds a deliberate subset. The rule applied throughout is that an
event carries *findings and identifiers*, never *payload*. Hashes, rule names,
counts and verdicts are safe to store forever. Decoded strings and extracted
file contents are not, and are excluded even though they are the most
interesting thing in the case directory -- the case directory is where they
stay, and `case_dir` on the event is the pivot back to them.

Every list is capped. An event that grows with the sample is an event that
eventually exceeds the HEC payload limit, and the failure lands on the noisiest
samples, which are the ones most worth having.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

#: Schema version. Bump when a field changes meaning, so saved searches written
#: against an older shape can be found and fixed rather than silently drifting.
SCHEMA_VERSION = 1

#: Per-list caps. Generous enough to be useful, small enough that no single
#: event can blow the HEC payload limit.
_MAX_RULES = 25
_MAX_IOCS = 50
_MAX_REASONS = 20
_MAX_CAPABILITIES = 40


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _cap(values: Any, limit: int) -> list[str]:
    """Coerce to a capped list of non-empty strings."""
    out: list[str] = []
    for item in _as_list(values):
        text = str(item).strip() if not isinstance(item, dict) else str(item.get("rule", "") or item.get("value", "")).strip()
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _epoch(iso_timestamp: str) -> Optional[float]:
    """Convert the summary's ISO timestamp to epoch seconds for HEC."""
    if not iso_timestamp:
        return None
    try:
        text = iso_timestamp.strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:
        return None


def severity_for(score: Any) -> str:
    """Severity label for a static score.

    Delegates to the engine's own thresholds so a verdict never disagrees with
    the report it came from. Falls back only if that import is unavailable.
    """
    try:
        from static_triage_engine.scoring import severity_from_score

        return severity_from_score(score)
    except Exception:
        try:
            numeric = float(score)
        except Exception:
            return "unknown"
        if numeric >= 80:
            return "critical"
        if numeric >= 60:
            return "high"
        if numeric >= 35:
            return "medium"
        if numeric >= 10:
            return "low"
        return "informational"


def build_static_event(
    summary: dict[str, Any],
    case_dir: str = "",
    analyzer_host: str = "",
) -> dict[str, Any]:
    """Build the indexed event from a `run_case` summary."""
    summary = _as_dict(summary)
    sample = _as_dict(summary.get("sample"))
    signing = _as_dict(summary.get("signing"))
    virustotal = _as_dict(summary.get("virustotal"))
    yara = _as_dict(summary.get("yara"))
    extraction = _as_dict(summary.get("payload_extraction"))
    iocs = _as_dict(summary.get("ioc_summary"))
    subfiles = _as_dict(summary.get("subfiles_rollup"))
    reasons = _as_dict(summary.get("reason_breakdown"))

    sha256 = str(sample.get("sha256", "") or "")
    score = summary.get("risk_score", 0)

    event: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "analysis_type": "static",
        "analyzer": "ringforge",
        "analyzer_host": analyzer_host,
        # Stable identity for the run. Re-analysing the same bytes produces the
        # same key, which is what makes dedupe possible on the search side as
        # well as in the shipper.
        "dedupe_key": sha256,
        "case_dir": str(case_dir or summary.get("case_dir", "") or ""),
        "analysis_timestamp": str(sample.get("timestamp_utc", "") or ""),
        "runtime_seconds": summary.get("runtime_sec_total", 0),

        # --- identity -------------------------------------------------------
        "file_name": str(sample.get("filename", "") or ""),
        "file_size": sample.get("size_bytes", 0),
        "file_path": str(sample.get("path_original", "") or ""),
        "md5": str(sample.get("md5", "") or ""),
        "sha1": str(sample.get("sha1", "") or ""),
        "sha256": sha256,

        # --- verdict --------------------------------------------------------
        "verdict": str(summary.get("verdict", "") or ""),
        "risk_score": score,
        "severity": severity_for(score),
        "confidence": summary.get("confidence", ""),
        "reasons_suspicious": _cap(reasons.get("suspicious"), _MAX_REASONS),
        "reasons_benign": _cap(reasons.get("benign"), _MAX_REASONS),

        # --- signing --------------------------------------------------------
        "signature_present": bool(signing.get("signature_present", False)),
        "signature_verified": bool(signing.get("verify_ok", False)),
        "signature_status": str(signing.get("verification_status", "") or ""),
        "signer": str(signing.get("subject", "") or ""),
        "signer_issuer": str(signing.get("issuer", "") or ""),

        # --- detection ------------------------------------------------------
        "yara_matched": bool(yara.get("matched", False)),
        "yara_match_count": yara.get("match_count", 0),
        "yara_rules": _cap(yara.get("top_rules"), _MAX_RULES),
        "yara_rule_file_count": yara.get("rule_file_count", 0),

        # --- reputation -----------------------------------------------------
        # Kept as counts rather than a verdict of their own. A VT ratio is
        # context for an analyst, not a decision the index should imply.
        "vt_enabled": bool(virustotal.get("enabled", False)),
        "vt_found": bool(virustotal.get("found", False)),
        "vt_malicious": virustotal.get("malicious", 0),
        "vt_suspicious": virustotal.get("suspicious", 0),
        "vt_harmless": virustotal.get("harmless", 0),
        "vt_times_submitted": virustotal.get("times_submitted", 0),
        "vt_type_description": str(virustotal.get("type_description", "") or ""),

        # --- structure ------------------------------------------------------
        "extraction_attempted": bool(extraction.get("attempted", False)),
        "extraction_success": bool(extraction.get("success", False)),
        "extracted_file_count": extraction.get("extracted_file_count", 0),
        "extracted_pe_count": extraction.get("extracted_pe_count", 0),
        "subfile_count": subfiles.get("count", 0),

        # --- indicators -----------------------------------------------------
        # The one place sample-derived content is carried, because an IOC with
        # no value is not an IOC. Capped, and deliberately not accompanied by
        # the surrounding strings.
        "ioc_urls": _cap(iocs.get("urls"), _MAX_IOCS),
        "ioc_domains": _cap(iocs.get("domains"), _MAX_IOCS),
        "ioc_ips": _cap(iocs.get("ips"), _MAX_IOCS),
    }

    capabilities = _as_dict(summary.get("api_analysis")).get("capabilities")
    if capabilities:
        event["capabilities"] = _cap(capabilities, _MAX_CAPABILITIES)

    return {
        "event": event,
        "time": _epoch(event["analysis_timestamp"]),
        "sha256": sha256,
    }
