"""What the Unified Report says a case amounts to, out of the window.

These four functions decided the verdict shown on the case page and lived
inside `gui.UnifiedReportWindow`, where none of them referenced a single widget
and none of them could be tested without a display. That is how the defect
below survived: a scoring path with no test, in a class nobody imports.

**`v1.11.0` replaced five scoring systems with one and these were not among
them.** They are the retired additive model, still running, in the module whose
job is to present the one verdict. Two of them add points against per-endpoint
counts; the third picks a verdict by cascading through whatever it can find.

What is fixed here, and what is deliberately left alone:

* **The prose grep is gone.** The old fallback joined every finding's text and
  looked for substrings -- the word `persistence` appearing anywhere in any
  module's findings produced *"Moderate Risk"*. A verdict derived from a
  substring of a sentence is not a verdict, and the canonical model exists so
  it does not have to be one. Where no module produced a verdict, this now says
  so in the canonical coverage wording instead of guessing.
* **The per-domain scores stay.** `spec_score_and_verdict` and
  `extension_score_and_verdict` keep their arithmetic exactly as it was.
  Whether an API-spec case should band on the corroboration model is a product
  decision, not a refactor, and changing the numbers under the same names would
  move verdicts silently. They are moved and tested, not rewritten.
"""

from __future__ import annotations

from typing import Any, Mapping

#: Canonical wording for "modules ran, nothing scored". Both are bands the
#: report theme already colours; the strings this replaced -- "Moderate
#: Activity", "Limited Activity", "No Results" -- were known to nothing and
#: rendered grey.
INSUFFICIENT = "Insufficient Coverage"
NOTHING = "Nothing Collected"

#: The module names `_detect_artifacts` reports, used to decide whether a case
#: is spec-only or extension-only.
_SPEC_PEERS = ("Static Analysis", "Dynamic Analysis", "Manual API Tester",
               "Browser Extension Analysis", "Combined Score")
_EXTENSION_PEERS = ("Static Analysis", "Dynamic Analysis", "Manual API Tester",
                    "Spec Analysis", "Combined Score")


def _found(artifacts: Mapping[str, Any], name: str) -> bool:
    entry = artifacts.get(name)
    return bool(isinstance(entry, Mapping) and entry.get("found"))


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def spec_score_and_verdict(spec_summary: Any) -> tuple[int | None, str | None]:
    """A display score for spec-only or spec-heavy cases.

    Deliberately separate from malware scoring so API-spec risk does not sound
    like endpoint malware behaviour. The arithmetic is unchanged from the
    version that lived in the window.
    """
    if not isinstance(spec_summary, Mapping):
        return None, None

    summary = spec_summary.get("summary")
    summary = summary if isinstance(summary, Mapping) else {}
    scoring = spec_summary.get("scoring")
    scoring = scoring if isinstance(scoring, Mapping) else {}

    high_count = _int(summary.get("high_risk_endpoint_count"))
    medium_count = _int(summary.get("medium_risk_endpoint_count"))
    sensitive_unauth = _int(summary.get("sensitive_unauthenticated_endpoint_count"))
    auth_gap_count = _int(summary.get("auth_gap_count",
                                      scoring.get("auth_gap_count", 0)))
    schema_issue_count = _int(summary.get(
        "schema_issue_endpoint_count", scoring.get("schema_issue_endpoint_count", 0)))
    file_upload_count = _int(summary.get(
        "file_upload_endpoint_count", scoring.get("file_upload_endpoints", 0)))

    score = 0
    score += min(30, high_count * 10)
    score += min(18, medium_count * 3)
    score += min(12, sensitive_unauth * 3)
    score += min(8, auth_gap_count)
    score += min(6, schema_issue_count)
    score += min(6, file_upload_count * 3)
    if bool(scoring.get("http_server_detected", False)):
        score += 5
    score = max(0, min(100, score))

    if score >= 60:
        return score, "High API Spec Risk"
    if score >= 35:
        return score, "Medium API Spec Risk"
    if score >= 15:
        return score, "Low API Spec Risk"
    return score, "Informational API Spec Review"


def extension_score_and_verdict(extension_summary: Any) -> tuple[int | None, str | None]:
    """A display score for browser-extension-only cases.

    Prefers the extension module's own verdict and only bands on the raw score
    when it did not give one -- unchanged from the window version.
    """
    if not isinstance(extension_summary, Mapping):
        return None, None
    summary = extension_summary.get("summary")
    if not isinstance(summary, Mapping):
        return None, None

    raw_verdict = str(summary.get("risk_verdict", "") or "").strip().lower()
    try:
        score = int(summary.get("risk_score"))
    except (TypeError, ValueError):
        score = None

    if raw_verdict == "high":
        return score, "High Browser Extension Risk"
    if raw_verdict == "medium":
        return score, "Medium Browser Extension Risk"
    if raw_verdict == "low":
        return score, "Low Browser Extension Risk"

    if score is not None:
        if score >= 7:
            return score, "High Browser Extension Risk"
        if score >= 3:
            return score, "Medium Browser Extension Risk"
        return score, "Low Browser Extension Risk"
    return None, None


def overall_verdict(
    *,
    artifacts: Mapping[str, Any],
    combined: Any = None,
    dynamic_summary: Any = None,
    static_summary: Any = None,
    spec_summary: Any = None,
    extension_summary: Any = None,
) -> str:
    """The case verdict, taken from whichever module actually produced one.

    The order is a preference, not a computation: a combined verdict wins,
    then dynamic, then static, then a per-domain score where the case is
    *only* that domain. **Nothing here invents a band from evidence text.**
    """
    if isinstance(combined, Mapping):
        for key in ("verdict", "severity"):
            if combined.get(key):
                return str(combined.get(key))

    if isinstance(dynamic_summary, Mapping) and dynamic_summary.get("verdict"):
        return str(dynamic_summary.get("verdict"))
    if isinstance(static_summary, Mapping) and static_summary.get("verdict"):
        return str(static_summary.get("verdict"))

    if (_found(artifacts, "Spec Analysis")
            and not any(_found(artifacts, n) for n in _SPEC_PEERS)):
        _, verdict = spec_score_and_verdict(spec_summary)
        if verdict:
            return verdict

    if (_found(artifacts, "Browser Extension Analysis")
            and not any(_found(artifacts, n) for n in _EXTENSION_PEERS)):
        _, verdict = extension_score_and_verdict(extension_summary)
        if verdict:
            return verdict

    # **No module scored this case.** The old code reached for the findings
    # text here and matched substrings; what it produced was a guess wearing a
    # verdict's clothes. Coverage is the honest answer, and it is wording the
    # report theme already knows how to colour.
    found = sum(1 for meta in artifacts.values()
                if isinstance(meta, Mapping) and meta.get("found"))
    return INSUFFICIENT if found else NOTHING
