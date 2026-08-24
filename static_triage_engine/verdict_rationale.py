"""Why the static verdict says what it says, in words a reader can check.

Rewritten for `corroboration-v1` -- see `docs/SCORING.md`. It got shorter,
because most of what it used to do is now done better upstream: each evidence
category carries a `reason` written to be read aloud, so the rationale assembles
those instead of re-deriving a parallel set of sentences from raw counts that
could disagree with the verdict beside them.

**Three of its premises were retired with the additive model**, and keeping them
would have left the rationale arguing for a verdict the scorer no longer
reaches:

- *"File is unsigned or signature validation failed"* was listed as a reason the
  score went up. Most malware is unsigned and so is most small legitimate
  tooling; absence of exculpatory evidence is not incriminating evidence. A
  signature that is present and does not verify is a different claim and has its
  own category.
- *"VirusTotal did not report malicious verdicts"* was listed as a reason the
  score went down. Letting a third-party opinion lower a verdict is the same
  error as letting it raise one. VirusTotal now appears under its own heading,
  as somebody else's conclusion rather than as local evidence.
- The next-step advice branched on `BENIGN` / `LOW_RISK` / `SUSPICIOUS` /
  `MALICIOUS`, none of which are produced any more.
"""

from __future__ import annotations

from typing import Any, Sequence

#: What to do next, per band. Keyed on the verdict rather than the severity
#: because two verdicts share a severity and want different advice: a case at
#: `Insufficient Coverage` and one at `Needs Review` are both Medium, and only
#: one of them is a statement about the sample.
_NEXT_STEP = {
    "Likely Malicious": (
        "Contain first. Several independent kinds of evidence agree, which is "
        "the strongest statement this model makes. Pivot on the hash and the "
        "observables, and treat any host that ran this as suspect."),
    "Elevated Attention": (
        "Detonate. There is real evidence here and not yet enough of it to be "
        "sure what the sample does -- a run is the cheapest way to find out."),
    "Needs Review": (
        "One observation with nothing corroborating it. Look at the evidence "
        "below and decide whether it is explained; if it is not, a detonation "
        "is what would corroborate or dismiss it."),
    "Insufficient Coverage": (
        "This is a statement about the bench, not the sample. Nothing was "
        "collected, so nothing can be concluded -- fix the collectors and run "
        "it again before reading anything into the result."),
    "No Findings, Coverage Incomplete": (
        "Nothing fired, but at least one collector never ran, so 'clean' is not "
        "available. Re-run the missing collector before filing this."),
    "No Indicators Found": (
        "Static analysis found nothing. That is not the same as the sample "
        "doing nothing, and only a detonation can tell the two apart."),
    "Low Suspicion": (
        "Nothing reached a category. The activity volume is worth a glance, "
        "then treat as unremarkable unless provenance says otherwise."),
    "Benign / Clean Baseline": (
        "Collected in full, watched running, and nothing fired. File it."),
}

_DEFAULT_NEXT_STEP = (
    "Read the full report and decide whether a detonation is warranted.")


def build_static_verdict_rationale(
    *,
    static_score: int | float | None,
    verdict: str | None = None,
    confidence: str | None = None,
    severity: str | None = None,
    evidence: Sequence[dict[str, Any]] | None = None,
    coverage_complete: bool = True,
    uncollected: Sequence[str] | None = None,
    capa_hits: int = 0,
    vt_found: bool = False,
    vt_malicious: int = 0,
    vt_suspicious: int = 0,
) -> dict[str, Any]:
    """Assemble the rationale from what the categories already said."""
    evidence = list(evidence or [])
    uncollected = list(uncollected or [])

    # The categories, emphatic ones first -- the same order the report shows.
    findings = [
        (f"{item.get('reason', '')} "
         f"({item.get('module', '?')}/{item.get('name', '?')}"
         f"{', emphatic' if item.get('strong') else ''})").strip()
        for item in evidence if item.get("reason")
    ]

    coverage: list[str] = []
    if not coverage_complete:
        coverage.append(
            "Coverage is incomplete: "
            + ", ".join(uncollected)
            + " could not be checked. An absence here is not a finding.")
    else:
        coverage.append("Every static collector ran.")

    notes: list[str] = []
    if capa_hits:
        notes.append(
            f"capa identified {capa_hits} capability finding(s). Capability is "
            f"what the file can do, not what it did, and it contributes volume "
            f"rather than a category on its own.")
    if not findings:
        notes.append(
            "No evidence category fired. Under this model that is the absence "
            "of a claim, not a claim of absence.")

    # **Third-party, and labelled as such.** Not folded into the findings above,
    # because corroboration means independent kinds of evidence agreeing, and
    # another scanner's verdict on the same file is not independent of ours.
    third_party: list[str] = []
    if vt_found:
        if vt_malicious or vt_suspicious:
            third_party.append(
                f"VirusTotal reports {vt_malicious} malicious and "
                f"{vt_suspicious} suspicious engine verdict(s). This did not "
                f"contribute to the verdict; where our collectors did not "
                f"reproduce it, it can raise the band no higher than Needs "
                f"Review.")
        else:
            third_party.append(
                "VirusTotal reports no malicious or suspicious verdicts. This "
                "did not lower the verdict either -- it is one more opinion, "
                "not a local observation.")

    return {
        "score": static_score,
        "score_is_descriptive": True,
        "verdict": verdict or "",
        "severity": severity or "",
        "confidence": confidence or "N/A",
        "findings": findings[:8],
        "coverage": coverage,
        "third_party": third_party,
        "notes": notes[:5],
        "recommended_next_step": _NEXT_STEP.get(
            str(verdict or "").strip(), _DEFAULT_NEXT_STEP),
    }
