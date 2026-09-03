"""The API Spec module's report, and the vocabulary its window shares with it.

**Why this is a module and not a method on the window.** `_render_html` sat in
`gui/spec_window.py` referencing no widget, importable only with a display, and
therefore never tested -- the third module through this pass and the third to be
hiding something there.

**What it was showing in the verdict slot.** Not a verdict. `analyze_api_spec`
sets `confidence` to describe *how well the parser understood the document*
-- it starts at `"high"` and is downgraded to `"medium"` at three parser
warnings and `"low"` at five. The report put that word, uppercased, in the same
banner slot where the dynamic report writes "Likely Malicious" and the API
tester writes "High &middot; 4 finding(s)". A reader holding the page saw
**HIGH** on a document about API risk.

It was also coloured backwards -- confident parses took `sev-none`, the chip
that elsewhere means nothing was found -- and `confidence` defaults to `"high"`
*before parsing begins*, so a spec that failed to load entirely rendered a
banner reading HIGH. Where confidence was blank it fell back to the spec type,
putting **OPENAPI** in the verdict slot.

The band comes from `spec_categories` now -- the corroboration model, which
`combine_case` was already running over this same result to feed the Combined
Score while the module's own page ignored it. Confidence is still shown, as
coverage, saying what it measures.

**The shared vocabulary is here for the same reason.** `_populate_result`
canonicalised auth scheme names for the screen and `_render_html` did not, so
the window said `bearer` where the exported page said `bearerAuth`; and the
window's endpoint table was built with three flags where the report had four,
so `upload` appeared on the page and never on screen. Both now call one
implementation.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from dynamic_analysis.report_theme import report_page, severity_class_for_label
from verdict.case_summary import spec_score_and_verdict

#: Scheme names as authors write them -> the name this workbench prints. The
#: spec's own identifiers are free-form (`bearerAuth`, `BearerAuth`, `jwt`),
#: and a report that echoes them cannot be compared across two specs.
_AUTH_ALIASES = {
    ("apikey", "api-key", "x-api-key", "api key"): "api-key",
    ("bearer", "jwt", "bearerauth"): "bearer",
    ("basic", "basicauth"): "basic",
    ("oauth2", "oauth"): "oauth2",
    ("none", ""): "none",
}

#: Coverage reads inverted from risk: a *low*-confidence parse is the one
#: needing attention, so it takes the warmer chip.
_COVERAGE_CLASS = {"high": "low", "medium": "medium", "low": "high"}

#: Endpoint properties worth a word in a table cell, in a fixed order so two
#: rows are comparable. `upload` was in the report and missing from the window.
_FLAGS = (
    ("admin_like_route", "admin-like"),
    ("destructive_method", "destructive"),
    ("sensitive_parameters", "sensitive-params"),
    ("file_upload", "upload"),
)


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def normalize_auth_name(name: Any) -> str:
    """One spelling per scheme, so two specs can be compared."""
    text = str(name or "").strip().lower().replace("_", "-")
    for aliases, canonical in _AUTH_ALIASES.items():
        if text in aliases:
            return canonical
    return text


def auth_names(values: Any) -> list[str]:
    """Canonical scheme names, deduplicated, order preserved, `none` dropped."""
    if isinstance(values, str):
        values = [values]
    names: list[str] = []
    for item in values or []:
        canonical = normalize_auth_name(item)
        if canonical and canonical != "none" and canonical not in names:
            names.append(canonical)
    return names


def auth_line(values: Any) -> str:
    """The spec's schemes as one cell. `none` is stated, never left blank."""
    return ", ".join(auth_names(values)) or "none"


def endpoint_auth(ep: Mapping[str, Any]) -> str:
    """What one operation requires.

    `required` and a named scheme are different facts: the first says the spec
    demands authentication without saying which, and that gap is the thing
    `auth_gap_count` counts.
    """
    names = auth_names(ep.get("auth_schemes_applied"))
    if names:
        return ", ".join(names)
    return "required" if ep.get("auth_required") else "none"


def endpoint_auth_source(ep: Mapping[str, Any]) -> str:
    """`explicit_none` is the spec saying *public*, and should read that way."""
    source = str(ep.get("auth_source", "") or "")
    return "public" if source == "explicit_none" else source


def endpoint_flags(ep: Mapping[str, Any]) -> list[str]:
    return [label for key, label in _FLAGS if ep.get(key)]


def spec_verdict(result: Mapping[str, Any]) -> tuple[str, str]:
    """The banner's band, and never the parser's opinion of itself.

    **Two bands were available and the report used neither.**
    `combine_case` already runs `spec_categories` over this exact result to
    feed the Combined Score, and `verdict/case_summary` computes an additive
    display score for spec-only cases in the Unified Report. They disagree --
    the reference `petstore3` spec is "No Weaknesses Found" under one and
    "Medium API Spec Risk &middot; 47/100" under the other -- which is the
    product question `case_summary` records as still open.

    The banner takes the **corroboration band**: it is the model, it is
    computed from this result already, and every other report in this
    workbench banners it. The additive score is shown in the body beside it so
    the disagreement is on the page rather than only between two pages.

    A spec that did not parse bands as `Insufficient Coverage` rather than as
    clean -- `spec_categories` refuses to read missing data as a finding, and
    that is the whole reason it exists.

    The class comes from the model's `severity`, not from the sentence. The
    wording follows the domain; the band does not.
    """
    from static_triage_engine.categories import spec_categories
    from verdict import band

    categories, context = spec_categories(dict(result) if result else None)
    decided = band(categories, context_score=context)
    return decided.verdict, severity_class_for_label(decided.severity)


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bullets(items: Iterable[Any], empty: str = "None", limit: int | None = None) -> str:
    values = list(items or [])
    if limit is not None:
        values = values[:limit]
    if not values:
        return f"<li>{_esc(empty)}</li>"
    return "".join(f"<li>{_esc(x)}</li>" for x in values)


def _endpoint_cards(items: Sequence[Mapping[str, Any]], detail_key: str,
                    detail_limit: int, empty: str, empty_detail: str) -> str:
    cards = []
    for item in items or []:
        details = item.get(detail_key) or []
        if isinstance(details, str):
            details = [details]
        cards.append(f"""
            <div class="card" style="margin-bottom:10px;">
                <div style="font-weight:bold;margin-bottom:4px;">{_esc(item.get("method", ""))} {_esc(item.get("path", ""))}</div>
                <div class="muted" style="margin-bottom:6px;">Risk: {_esc(item.get("risk_level", ""))} | Score: {_esc(item.get("risk_score", 0))}</div>
                <ul>{_bullets(details, empty_detail, detail_limit)}</ul>
            </div>""")
    return "".join(cards) or f"<p class='muted'>{_esc(empty)}</p>"


def _parse_failure_section(result: Mapping[str, Any]) -> str:
    """A spec that did not parse says so first, and loudly.

    Every count below it is a zero produced by nothing having been read, and a
    page of zeros reads as a clean spec.
    """
    if _int(result.get("returncode")) == 0:
        return ""
    return f"""
        <div class="card card-alert">
            <div class="section-head">
                <h2>The spec was not parsed</h2>
                <span class="badge sev-high">No result</span>
            </div>
            <p class="muted">
                <b>{_esc(result.get("error") or "The parser did not complete.")}</b>
                Every count on this page is zero because nothing was read, not
                because nothing was found, and there is no verdict for the same
                reason.
            </p>
        </div>"""


def _coverage_section(result: Mapping[str, Any]) -> str:
    """Parser confidence, named as what it is.

    It used to be the banner verdict. It says how much of the document the
    parser understood -- three warnings drop it to medium, five to low -- and
    it is a statement about this tool, not about the API.
    """
    confidence = str(result.get("confidence", "") or "-")
    warnings = list(result.get("parser_warnings") or [])
    unresolved = _int(result.get("unresolved_refs_count"))
    return f"""
        <div class="card">
            <div class="section-head">
                <h2>Parser Coverage</h2>
                <span class="badge {severity_class_for_label(_COVERAGE_CLASS.get(confidence.lower(), ""))}">Confidence: {_esc(confidence)}</span>
            </div>
            <p class="muted">
                <b>This describes how much of the document was read, not how
                risky the API is.</b> {len(warnings)} parser warning(s) and
                {unresolved} unresolved ref(s); confidence drops to medium at
                three warnings and low at five. A low-confidence parse means
                the counts below understate what the spec contains.
            </p>
            <ul>{_bullets(warnings, "No parser warnings.")}</ul>
        </div>"""


def _display_score_section(result: Mapping[str, Any]) -> str:
    """The other number this case has, named and placed beside the band.

    The Unified Report bands a spec-only case with `spec_score_and_verdict`,
    an additive score kept from before `corroboration-v1`. It does not always
    agree with the banner above: the reference `petstore3` spec is "No
    Weaknesses Found" to the model and 47/100 "Medium API Spec Risk" here.
    Two numbers that disagree are worth showing together; the confusing
    version is finding one on each of two pages.
    """
    score, verdict = spec_score_and_verdict(result)
    if verdict is None:
        return ""
    return f"""
        <div class="card">
            <div class="section-head">
                <h2>Unified Report Display Score</h2>
                <span class="badge {severity_class_for_label(verdict)}">{_esc(verdict)}: {_int(score)}/100</span>
            </div>
            <p class="muted">
                <b>Not the band in the banner.</b> This is the additive
                per-endpoint score the case page shows for a spec-only case,
                kept from before the corroboration model and counted from the
                same summary. Where the two disagree, the banner is the model
                and this is a volume measure.
            </p>
        </div>"""


def _endpoint_rows(endpoints: Sequence[Mapping[str, Any]]) -> str:
    return "".join(
        "<tr>"
        f"<td>{_esc(ep.get('method', ''))}</td>"
        f"<td>{_esc(ep.get('path', ''))}</td>"
        f"<td>{_esc(ep.get('summary', ''))}</td>"
        f"<td>{_esc(endpoint_auth(ep))}</td>"
        f"<td>{_esc(endpoint_auth_source(ep))}</td>"
        f"<td>{_esc(ep.get('risk_level', ''))}</td>"
        f"<td>{len(ep.get('parameters') or [])}</td>"
        f"<td>{_esc(', '.join(endpoint_flags(ep)))}</td>"
        "</tr>"
        for ep in endpoints or []
    )


def build_spec_report(result: Mapping[str, Any]) -> str:
    """One exported page for one analysed spec."""
    summary = result.get("summary") or {}
    title = result.get("title") or Path(str(result.get("input_file", "spec"))).name
    verdict, verdict_class = spec_verdict(result)

    body_html = f"""
        {_parse_failure_section(result)}
        <div class="tile-grid">
            <div class="tile"><div class="tile-label">Format</div><div class="tile-value" style="font-size:18px;">{_esc(result.get("format") or "-")}</div></div>
            <div class="tile"><div class="tile-label">Spec Type</div><div class="tile-value" style="font-size:18px;">{_esc(result.get("spec_type") or "-")}</div></div>
            <div class="tile"><div class="tile-label">Version</div><div class="tile-value" style="font-size:18px;">{_esc(result.get("version") or "-")}</div></div>
            <div class="tile"><div class="tile-label">Endpoints</div><div class="tile-value">{_int(summary.get("endpoint_count"))}</div></div>
            <div class="tile"><div class="tile-label">Auth</div><div class="tile-value" style="font-size:18px;">{_esc(auth_line(result.get("auth_summary")))}</div></div>
            <div class="tile"><div class="tile-label">Notable</div><div class="tile-value">{_int(summary.get("top_risky_endpoint_count"))}</div></div>
            <div class="tile"><div class="tile-label">High Risk</div><div class="tile-value">{_int(summary.get("high_risk_endpoint_count"))}</div></div>
            <div class="tile"><div class="tile-label">Unresolved Refs</div><div class="tile-value">{_int(result.get("unresolved_refs_count"))}</div></div>
        </div>

        <div class="card">
            <div class="section-head"><h2>Summary</h2></div>
            <table class="kv">
                <tr><th>Servers</th><td>{_esc(", ".join(str(x) for x in result.get("servers") or []) or "none")}</td></tr>
                <tr><th>Methods</th><td>GET {_int(summary.get("get_count"))} | POST {_int(summary.get("post_count"))} | PUT {_int(summary.get("put_count"))} | PATCH {_int(summary.get("patch_count"))} | DELETE {_int(summary.get("delete_count"))}</td></tr>
                <tr><th>Admin-like Routes</th><td>{_int(summary.get("admin_like_route_count"))}</td></tr>
                <tr><th>Sensitive Parameters</th><td>{_int(summary.get("sensitive_param_count"))}</td></tr>
                <tr><th>Endpoints With No Declared Auth</th><td>{_int(summary.get("auth_gap_count"))}</td></tr>
                <tr><th>Sensitive And Unauthenticated</th><td>{_int(summary.get("sensitive_unauthenticated_endpoint_count"))}</td></tr>
            </table>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;">
            <div class="card">
                <div class="section-head"><h2>Risk Notes</h2></div>
                <ul>{_bullets(result.get("risk_notes"), "No risk notes generated.")}</ul>
            </div>
            {_coverage_section(result)}
        </div>

        {_display_score_section(result)}

        <div class="card">
            <div class="section-head"><h2>Unresolved Refs</h2></div>
            <ul>{_bullets(result.get("unresolved_refs"), "None", 20)}</ul>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;">
            <div class="card">
                <div class="section-head"><h2>Notable Endpoints</h2></div>
                {_endpoint_cards(result.get("top_risky_endpoints") or [], "risk_reasons", 6,
                                 "No high-risk endpoints identified.", "No reasons captured.")}
            </div>
            <div class="card">
                <div class="section-head"><h2>Recommended Tests</h2></div>
                {_endpoint_cards(result.get("recommended_tests") or [], "tests", 8,
                                 "No recommended tests generated.", "No tests generated.")}
            </div>
        </div>

        <div class="card">
            <div class="section-head"><h2>Endpoint Inventory</h2></div>
            <div class="table-wrap">
                <table>
                    <thead><tr>
                        <th>Method</th><th>Path</th><th>Summary</th>
                        <th>Auth</th><th>Auth Source</th><th>Risk</th>
                        <th>Params</th><th>Flags</th>
                    </tr></thead>
                    <tbody>{_endpoint_rows(result.get("endpoints") or [])}</tbody>
                </table>
            </div>
        </div>
        """

    return report_page(
        title="API Spec Analysis Report",
        subtitle=_esc(title),
        verdict=verdict,
        verdict_class=verdict_class,
        body_html=body_html,
        footer_note="RingForge Workbench &bull; API Spec Analysis",
    )
