"""The Manual API Tester's report, as a page rather than a text dump.

**Why this is a module and not a method on the window.** The dynamic module
keeps its analysis in `orchestrator`, its report in `html_report` and its screen
in `gui/dynamic_window`, so the report can be built and tested without a
display. The API tester had its report inline in `gui/api_window.py`, which made
it untestable and let it drift: it hand-rolled its own `<!DOCTYPE html>` around
`report_css()` instead of using `report_page`, so it had no banner, no verdict,
no footer and no generated-at stamp while every other report did.

**What that cost, beyond looking different.** `analyze_response` returns
structured findings -- `{"severity": ..., "message": ...}` with counts per band
-- and the report flattened them into one `<pre>` of plain text. Every other
module in this workbench renders findings as rows with severity badges, so the
one module whose whole purpose is scoring a response was the one that showed its
scoring as an unstyled blob.

**The redaction notice is deliberately loud.** This is the only report here that
routinely contains bearer tokens, cookies and API keys, and whether they were
removed is the most important fact about the document -- more important than any
finding in it. A saved page that is *not* redacted says so in a `card-alert` at
the top, not in a table row three lines down.

**Findings are heuristics and the page says so, in the page.** The text version
carried that sentence and it survives here rather than being lost in the
restyling: these indicate things worth an analyst's attention, and none of them
proves a vulnerability on its own.
"""

from __future__ import annotations

import html
from typing import Any, Iterable, Mapping

from dynamic_analysis.report_theme import (
    label_badge,
    report_page,
    severity_class_for_label,
)

#: Findings order, worst first. `analyze_response` emits these four.
SEVERITY_ORDER = ("High", "Medium", "Low", "Info")

#: Status families, for a response line that reads at a glance. A 500 and a 200
#: are not the same event and should not be the same colour.
_STATUS_CLASS = {"2": "sev-none", "3": "sev-low", "4": "sev-med", "5": "sev-high"}


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _status_class(status: str) -> str:
    text = str(status or "").strip()
    return _STATUS_CLASS.get(text[:1], "sev-none")


def verdict_for(counts: Mapping[str, int]) -> tuple[str, str]:
    """The banner's verdict, and never more than the counts support.

    The worst band present, named plainly. **No findings is stated rather than
    implied** -- an empty page and a clean result are different outcomes, and
    the reader of an exported file cannot tell them apart from silence.
    """
    for level in SEVERITY_ORDER:
        if int(counts.get(level, 0) or 0) > 0:
            total = sum(int(counts.get(k, 0) or 0) for k in SEVERITY_ORDER)
            return f"{level} &middot; {total} finding(s)", severity_class_for_label(level)
    return "No findings", "sev-none"


def _kv_rows(pairs: Iterable[tuple[str, Any]]) -> str:
    return "".join(
        f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in pairs
    )


def _header_table(title: str, raw: str) -> str:
    """Headers as a table. They are key/value data and were rendered as prose.

    A line that does not split on a colon is kept and shown whole rather than
    dropped -- a malformed header is a finding in itself, and discarding it to
    keep the table tidy would hide it.
    """
    lines = [line for line in str(raw or "").splitlines() if line.strip()]
    if not lines:
        return f"""
    <section class="card">
      <div class="section-head"><h2>{_esc(title)}</h2></div>
      <p class="muted">None recorded.</p>
    </section>"""

    rows = []
    for line in lines:
        name, sep, value = line.partition(":")
        if sep:
            rows.append(f"<tr><th>{_esc(name.strip())}</th>"
                        f"<td>{_esc(value.strip())}</td></tr>")
        else:
            rows.append(f'<tr><th class="muted">malformed</th>'
                        f"<td>{_esc(line)}</td></tr>")
    return f"""
    <section class="card">
      <div class="section-head">
        <h2>{_esc(title)}</h2>
        {label_badge("Headers", len(lines))}
      </div>
      <table class="kv">{"".join(rows)}</table>
    </section>"""


def _pre_section(title: str, body: str, empty: str = "Empty.") -> str:
    if not str(body or "").strip():
        return f"""
    <section class="card">
      <div class="section-head"><h2>{_esc(title)}</h2></div>
      <p class="muted">{_esc(empty)}</p>
    </section>"""
    return f"""
    <section class="card">
      <div class="section-head"><h2>{_esc(title)}</h2></div>
      <pre>{_esc(body)}</pre>
    </section>"""


def _redaction_section(redacted: bool, replaced: int | None) -> str:
    """The most important thing about this document, at the top of it."""
    if redacted:
        counted = (f" {replaced} value(s) were replaced with <code>[REDACTED]</code>."
                   if replaced is not None else "")
        return f"""
    <section class="card">
      <div class="section-head">
        <h2>Redaction &mdash; On</h2>
        {label_badge("Redacted", replaced if replaced is not None else "yes")}
      </div>
      <p class="muted">
        Authorization headers, API keys, cookies and common secret-shaped JSON
        fields were removed before this page was written.{counted}
        <b>Redaction is pattern-based</b>, so treat it as a reduction in
        exposure rather than a guarantee: a secret in an unusual field name or
        an unstructured body can survive it.
      </p>
    </section>"""
    return """
    <section class="card card-alert">
      <div class="section-head">
        <h2>Redaction &mdash; OFF</h2>
        <span class="badge sev-high">Unredacted</span>
      </div>
      <p class="muted">
        This page was saved with redaction disabled and <b>may contain bearer
        tokens, API keys, cookies, passwords or session identifiers in full</b>.
        Treat the file as sensitive: it is as confidential as the credentials
        used to make the request.
      </p>
    </section>"""


def _findings_section(analysis: Mapping[str, Any]) -> str:
    """Findings as rows with severity badges, ordered worst first."""
    findings = list(analysis.get("findings") or [])
    counts = analysis.get("counts") or {}

    summary = " ".join(
        label_badge(level, int(counts.get(level, 0) or 0))
        for level in SEVERITY_ORDER
    )

    if not findings:
        return f"""
    <section class="card">
      <div class="section-head">
        <h2>Response Findings</h2>
        {summary}
      </div>
      <p class="muted">
        No findings were raised for this response. That is a statement about
        the checks this module runs, not a clearance: it looks at status,
        headers and body shape, and a response can be unsafe in ways none of
        those reach.
      </p>
    </section>"""

    rank = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    ordered = sorted(
        findings,
        key=lambda f: rank.get(str(f.get("severity", "")).title(), len(rank)),
    )
    rows = "".join(
        f'<tr><td class="nowrap">'
        f'<span class="badge {severity_class_for_label(f.get("severity"))}">'
        f'{_esc(f.get("severity", "-"))}</span></td>'
        f"<td>{_esc(f.get('message', ''))}</td></tr>"
        for f in ordered
    )
    return f"""
    <section class="card">
      <div class="section-head">
        <h2>Response Findings</h2>
        {summary}
      </div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Severity</th><th>Finding</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
      <p class="muted">
        <b>These are heuristic indicators for analyst review.</b> None of them
        proves a vulnerability on its own, and the absence of one proves
        nothing at all.
      </p>
    </section>"""


def build_api_report(
    *,
    method: str,
    url: str,
    status: str,
    elapsed: str,
    content_type: str,
    size: str,
    request_headers: str,
    request_body: str,
    response_headers: str,
    response_body: str,
    response_raw: str,
    analysis: Mapping[str, Any] | None = None,
    redacted: bool = True,
    redactions: int | None = None,
) -> str:
    """One exported page for one request/response pair."""
    analysis = analysis or {"findings": [], "counts": {}}
    verdict, verdict_class = verdict_for(analysis.get("counts") or {})

    exchange = f"""
    <section class="card">
      <div class="section-head">
        <h2>The Exchange</h2>
        <span class="badge {_status_class(status)}">Status: {_esc(status or '-')}</span>
      </div>
      <table class="kv">{_kv_rows([
          ("Method", method or "-"),
          ("URL", url or "-"),
          ("Status", status or "-"),
          ("Elapsed", elapsed or "-"),
          ("Content-Type", content_type or "-"),
          ("Size", size or "-"),
      ])}</table>
    </section>"""

    body_html = "\n".join([
        _redaction_section(redacted, redactions),
        exchange,
        _findings_section(analysis),
        _header_table("Request Headers", request_headers),
        _pre_section("Request Body", request_body, "No request body was sent."),
        _header_table("Response Headers", response_headers),
        _pre_section("Response Body", response_body, "The response had no body."),
        _pre_section("Raw Exchange", response_raw, "No raw capture was recorded."),
    ])

    subtitle = f"{_esc(method or '-')} {_esc(url or '-')}"
    return report_page(
        title="Manual API Test Report",
        subtitle=subtitle,
        verdict=verdict,
        verdict_class=verdict_class,
        body_html=body_html,
        footer_note="RingForge Workbench &bull; Manual API Tester",
    )
