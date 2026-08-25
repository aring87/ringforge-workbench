"""The case verdict, laid out for someone who has to act on it.

Phase 4b left the unified report *rewired* onto one verdict and never
*designed*. It opened with a twelve-row key/value table in which the verdict sat
between "Case Path" and five per-module subscores from the retired additive
model -- and the evidence, the prose each category carries explaining what was
observed, appeared nowhere at all.

**The order here is the argument.** A reader meets, in this sequence:

1. **What we concluded** -- the band, and the sentence for the domain.
2. **Why** -- every category that fired, emphatic ones first, each in the words
   its module wrote to be read aloud.
3. **What we could not see** -- modules that never ran, collectors that failed.
   Before any per-module detail, because it qualifies everything after it.
4. **What somebody else thinks** -- VirusTotal, under its own heading, marked as
   not having contributed.
5. **How much happened** -- the context score, last and labelled descriptive.

That is close to the reverse of what the page did, and the reversal is the
point. A number at the top is read as the finding; prose at the bottom is read
as supporting material. The model's whole claim is that the corroboration *is*
the finding and the number describes it, so the page has to say that first.

**Pure and testable.** It takes the `combined_verdict.json` shape and returns
HTML. It reads no files and knows nothing about Tkinter, which is what the two
analyses lifted out of windows in Phase 3b were missing.
"""

from __future__ import annotations

import html
from typing import Any, Mapping, Sequence

from dynamic_analysis.report_theme import report_css, severity_class_for_label

#: What each band means, in one sentence, per domain. Printed beneath the
#: verdict so a reader never has to know the vocabulary to use the page.
_BAND_MEANING = {
    "malware": {
        "Strongly Corroborated":
            "Three or more independent kinds of evidence agree, or two of them "
            "are emphatic enough to stand alone.",
        "Corroborated":
            "Two independent kinds of evidence agree, or one is emphatic enough "
            "to stand alone.",
        "Single Observation":
            "One kind of evidence, with nothing corroborating it.",
        "No Evidence":
            "No category fired. That is the absence of a claim, not a claim of "
            "absence.",
        "Nothing Collected":
            "No collector produced anything. This is a statement about the "
            "bench, not about the sample.",
    },
    # Not a band -- a verdict that overrides one. Keyed here so the sentence
    # beneath the verdict is never blank.
    "_verdict": {
        "Findings Not Scored":
            "Observations were made, and every module that made them is held "
            "context-only by decision -- reported, but not yet shown to "
            "separate a real population. Nothing here has been weighed.",
    },
    "posture": {
        "Strongly Corroborated":
            "Three or more independent weaknesses, or two serious enough to "
            "stand alone.",
        "Corroborated":
            "Two independent weaknesses, or one serious enough to stand alone.",
        "Single Observation":
            "One weakness, with nothing corroborating it.",
        "No Evidence":
            "No category fired. This is a documentation and header review; it "
            "says nothing about the implementation behind them.",
        "Nothing Collected":
            "Nothing was read. A specification that failed to parse is not a "
            "specification without problems.",
    },
}

_ALL_MODULES = ("static", "dynamic", "spec", "api", "extension")


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _verdict_block(verdict: Mapping[str, Any]) -> str:
    band = str(verdict.get("band", ""))
    domain = str(verdict.get("domain", "malware"))
    severity = str(verdict.get("severity", ""))
    counts = verdict.get("counts", {}) or {}
    meaning = (_BAND_MEANING["_verdict"].get(str(verdict.get("verdict", "")))
               or _BAND_MEANING.get(domain, {}).get(band, ""))

    # The badge colour comes from the shared mapper, so the desktop window and
    # this page cannot disagree about what High looks like.
    sev_class = severity_class_for_label(severity or band)

    floors = []
    if verdict.get("severity_floor_applied"):
        floors.append(
            "<p class='muted'>Held at this band by a single observation: "
            + _e(verdict.get("severity_floor_reason", "")) + "</p>")
    if verdict.get("dissent_floor_applied"):
        floors.append(
            "<p class='muted'><strong>Raised by third-party dissent, not by "
            "local evidence.</strong> " + _e(verdict.get("dissent_floor_reason", ""))
            + "</p>")

    return f"""
      <section class="card">
        <div class="verdict {sev_class}">{_e(verdict.get('verdict', 'No verdict'))}</div>
        <table class="data-table">
          <tr><th>Band</th><td>{_e(band)}</td></tr>
          <tr><th>Severity</th><td>{_e(severity)}</td></tr>
          <tr><th>Assessing</th><td>{_e('whether this is hostile' if domain == 'malware' else 'whether this is exposed')}</td></tr>
          <tr><th>Evidence</th><td>{_e(counts.get('categories_present', 0))} categories, {_e(counts.get('categories_strong', 0))} emphatic</td></tr>
        </table>
        <p>{_e(meaning)}</p>
        {''.join(floors)}
      </section>"""


def _evidence_block(verdict: Mapping[str, Any]) -> str:
    """Every category that fired, in the words its module wrote.

    **This is the part the old page did not have.** A verdict without the
    reasoning beside it is a number with a label on it, which is the thing the
    additive model was retired for.
    """
    evidence: Sequence[Mapping[str, Any]] = verdict.get("evidence", []) or []
    if not evidence:
        return """
      <section class="card">
        <h2>Evidence</h2>
        <p class="muted">No category fired. Read the coverage below before
        reading that as a clean result.</p>
      </section>"""

    rows = []
    for item in evidence:
        emphatic = ('<span class="badge sev-high">emphatic</span>'
                    if item.get("strong") else "")
        detail = (f"<p class='muted'>{_e(item.get('detail'))}</p>"
                  if item.get("detail") else "")
        rows.append(f"""
          <div class="card-alert">
            <div class="section-head">{_e(item.get('name'))} {emphatic}
              <span class="label">{_e(item.get('module'))}</span></div>
            <p>{_e(item.get('reason'))}</p>
            {detail}
          </div>""")

    return f"""
      <section class="card">
        <h2>Evidence</h2>
        <p class="muted">Emphatic categories first. Each is one claim, and it
        fires once however many events back it.</p>
        {''.join(rows)}
      </section>"""


def _coverage_block(verdict: Mapping[str, Any]) -> str:
    """What could not be seen, before any detail that assumes it could.

    Placed above the per-module summaries deliberately: a gap here qualifies
    everything below it, and a reader who meets the detail first has already
    formed a view by the time they learn what was missing.
    """
    ran = list(verdict.get("modules_run", []) or [])
    absent = list(verdict.get("modules_absent", []) or [])
    uncollected = list(verdict.get("uncollected_categories", []) or [])
    coverage = verdict.get("coverage", {}) or {}
    complete = bool(verdict.get("coverage_complete", True))

    rows = []
    for module in _ALL_MODULES:
        if module in coverage:
            entry = coverage[module]
            missing = entry.get("uncollected") or []
            state = ("complete" if entry.get("complete")
                     else f"INCOMPLETE — {', '.join(_e(m) for m in missing)}")
            cls = "sev-none" if entry.get("complete") else "sev-med"
        else:
            state, cls = "did not run", "sev-low"
        rows.append(f"<tr><th>{_e(module)}</th>"
                    f"<td><span class='badge {cls}'>{state}</span></td></tr>")

    warning = ""
    if not complete:
        warning = (
            "<p><strong>A collector did not run.</strong> The categories it "
            "covers are reported as <em>unknown</em>, never as absent: "
            + ", ".join(_e(u) for u in uncollected) + ".</p>")
    elif absent and not ran:
        warning = "<p><strong>Nothing ran.</strong> Nothing can be concluded.</p>"
    elif "dynamic" in absent:
        warning = (
            "<p>The sample was not detonated. Static analysis can establish "
            "that nothing was found; only watching it run can establish that "
            "nothing happens.</p>")

    return f"""
      <section class="card">
        <h2>What was looked at</h2>
        {warning}
        <table class="data-table">{''.join(rows)}</table>
      </section>"""


def _context_only_block(verdict: Mapping[str, Any]) -> str:
    """Findings from modules that are reported but not counted.

    **The section exists so the mechanism cannot hide anything.** A module held
    context-only still observes things, and a page that quietly drops its
    findings would be worse than one that over-counted them -- at least the
    over-counting was visible.

    The reason each module is uncounted is printed with it, because "why does
    this not affect the verdict" is the first question a reader will have and
    the answer is a decision somebody made, not a property of the file.
    """
    modules = list(verdict.get("modules_context_only", []) or [])
    if not modules:
        return ""

    block = verdict.get("context_only", {}) or {}
    names = list(block.get("names", []) or [])
    reasons = block.get("reasons", {}) or {}

    found = (f"<p><strong>{len(names)} finding(s) reported and not counted:</strong> "
             + ", ".join(_e(n) for n in names) + ".</p>") if names else             ("<p class='muted'>These modules ran and reported nothing.</p>")

    why = "".join(
        f"<div class='card-alert'><div class='section-head'>{_e(m)}</div>"
        f"<p class='muted'>{_e(reasons.get(m, 'held context-only by decision'))}</p></div>"
        for m in modules)

    return f"""
      <section class="card">
        <h2>Reported, not counted</h2>
        {found}
        <p class="muted">These modules are held <em>context-only by decision</em>
        -- built, running, and not yet shown to separate a real population. They
        cannot move the band. Removing that hold is a claim that the module has
        been measured, not that it looks right.</p>
        {why}
      </section>"""


def _third_party_block(third_party: Sequence[str] | None) -> str:
    if not third_party:
        return ""
    items = "".join(f"<li>{_e(line)}</li>" for line in third_party)
    return f"""
      <section class="card">
        <h2>Third party</h2>
        <p class="muted">Somebody else's conclusion about the same artifact.
        It did not contribute to the verdict: corroboration means independent
        kinds of evidence agreeing, and another scanner reading the same file is
        not independent of us.</p>
        <ul>{items}</ul>
      </section>"""


def render_verdict_report(
    verdict: Mapping[str, Any],
    case_name: str = "",
    case_path: str = "",
    third_party: Sequence[str] | None = None,
    module_artifacts: Mapping[str, Any] | None = None,
) -> str:
    """One page, from the `combined_verdict.json` shape."""
    artifact_rows = []
    for module, meta in (module_artifacts or {}).items():
        found = "yes" if (meta or {}).get("found") else "no"
        paths = "<br>".join(_e(p) for p in (meta or {}).get("paths", [])) or "-"
        artifact_rows.append(
            f"<tr><th>{_e(module)}</th><td>{found}</td><td>{paths}</td></tr>")
    artifacts = f"""
      <section class="card">
        <h2>Artifacts</h2>
        <table class="data-table">
          <tr><th>Module</th><th>Found</th><th>Paths</th></tr>
          {''.join(artifact_rows)}
        </table>
      </section>""" if artifact_rows else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>RingForge Case Verdict</title>
<style>{report_css()}</style>
</head>
<body>
<div class="container">
  <div class="banner">
    <h1>Case Verdict</h1>
    <div class="subtitle">{_e(case_name) or 'RingForge Workbench'}</div>
  </div>

  {_verdict_block(verdict)}
  {_evidence_block(verdict)}
  {_coverage_block(verdict)}
  {_context_only_block(verdict)}
  {_third_party_block(third_party)}
  {artifacts}

  <section class="card">
    <h2>Context</h2>
    <table class="data-table">
      <tr><th>Case path</th><td>{_e(case_path)}</td></tr>
      <tr><th>Model</th><td>{_e(verdict.get('score_model'))}</td></tr>
      <tr><th>Context score</th><td>{_e(verdict.get('score', 0))}
        <span class="muted">— descriptive volume. Nothing bands on it, and two
        cases in the same band can differ here without differing in
        finding.</span></td></tr>
    </table>
  </section>

  <div class="footer">RingForge Workbench &bull; compare cases on the band, not the verdict wording</div>
</div>
</body>
</html>"""
