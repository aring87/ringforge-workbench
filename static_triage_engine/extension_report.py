"""The Browser Extension module's report, beside the analysis it renders.

**Why this is a module and not a method on the window.** `analyze_extension`
already lives here; its report did not. It sat in `gui/extension_window.py` as
`_build_html_report`, referencing no widget, importable only with a display, and
therefore never once tested. That is the same shape that hid a wrong verdict
colour in the Unified Report and a prose-grepped band in its fallback, and it
hid one here too -- see `verdict_class_for`.

`api_report.py` sits beside `api_response_analysis.py` for this reason; this
sits beside `extension_analysis.py` for the same one.

**What moved and what did not.** The body is the page it always was: tiles, a
source table, a summary table, risk notes, the file inventory and the raw
manifest. `_build_export_data` stays on the window because it reads the form.
"""

from __future__ import annotations

import html
import json
from typing import Any, Mapping, Sequence

from dynamic_analysis.report_theme import report_page, severity_class_for_label


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def verdict_class_for(summary: Mapping[str, Any]) -> str:
    """The verdict chip's colour, from the analysis rather than from its prose.

    **This is where the report was wrong.** It uppercased `risk_verdict` and
    matched it against `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` -- the additive
    vocabulary the extension module stopped emitting. Under `corroboration-v1`
    the sentence is one of "Likely Malicious", "Elevated Attention", "Needs
    Review", "Insufficient Coverage", "Low Suspicion" and the rest, so *every*
    ladder rung missed and every exported extension report rendered its verdict
    in the neutral grey chip that also means "No Results".

    The band is not read out of the sentence now. `analyze_extension` returns a
    `severity` -- the model's own output, `High` / `Medium` / `Low` / `Unknown`
    -- and the window carries it into the export as `risk_severity`; that is
    what colours the chip. The wording is only consulted for case folders
    written before the field existed, and `severity_class_for_label` knows both
    vocabularies for exactly that reason.
    """
    severity = str(summary.get("risk_severity", "") or "").strip()
    if severity:
        return severity_class_for_label(severity)
    return severity_class_for_label(summary.get("risk_verdict"))


def _list_section(title: str, items: Sequence[str], emphasize: bool = False) -> str:
    section_class = "card card-alert" if emphasize and items else "card"
    body = ("<p class='muted'>None</p>" if not items
            else "<ul>" + "".join(f"<li>{_esc(x)}</li>" for x in items) + "</ul>")
    return f"""
            <section class="{section_class}">
              <div class="section-head">
                <h2>{_esc(title)}</h2>
                <span class="badge sev-low">Count: {len(items)}</span>
              </div>
              {body}
            </section>
            """


def _kv_table(title: str, rows: Mapping[str, Any], badge_fragment: str = "") -> str:
    rendered = "".join(
        f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in rows.items()
    )
    return f"""
            <section class="card">
              <div class="section-head">
                <h2>{_esc(title)}</h2>
                {badge_fragment}
              </div>
              <table class="kv">{rendered}</table>
            </section>
            """


def build_extension_report(data: Mapping[str, Any]) -> str:
    """One exported page for one analysed extension."""
    summary = data.get("summary") or {}
    risk_notes = data.get("risk_notes") or []
    file_inventory = data.get("file_inventory") or []
    manifest = data.get("manifest") or {}

    verdict_class = verdict_class_for(summary)
    verdict_text = _esc(summary.get("risk_verdict", "-"))

    tile_html = f"""
        <section class="tile-grid">
          <div class="tile"><div class="tile-label">Risk Verdict</div><div class="tile-value">{verdict_text}</div></div>
          <div class="tile"><div class="tile-label">Risk Score</div><div class="tile-value">{_esc(summary.get("risk_score", "0"))}</div></div>
          <div class="tile"><div class="tile-label">Files Found</div><div class="tile-value">{_esc(summary.get("files_found", "0"))}</div></div>
          <div class="tile"><div class="tile-label">Manifest Version</div><div class="tile-value">{_esc(summary.get("manifest_version", "-"))}</div></div>
          <div class="tile"><div class="tile-label">Permissions</div><div class="tile-value">{_esc(summary.get("permissions", "-"))}</div></div>
          <div class="tile"><div class="tile-label">Host Permissions</div><div class="tile-value">{_esc(summary.get("host_permissions", "-"))}</div></div>
        </section>
        """

    summary_rows = {
        "Name": summary.get("name", ""),
        "Version": summary.get("version", ""),
        "Description": summary.get("description", ""),
        "Manifest Version": summary.get("manifest_version", ""),
        "Permissions": summary.get("permissions", ""),
        "Host Permissions": summary.get("host_permissions", ""),
        "Background": summary.get("background", ""),
        "Content Scripts": summary.get("content_scripts", ""),
        "Web Resources": summary.get("web_resources", ""),
        "Externally Connectable": summary.get("externally_connectable", ""),
        "Update URL": summary.get("update_url", ""),
        "Commands": summary.get("commands", ""),
        "CSP": summary.get("csp", ""),
    }

    source_rows = {
        "Source Path": data.get("source_path", ""),
        "Working Directory": data.get("working_directory", ""),
        "Manifest Path": data.get("manifest_path", ""),
    }

    manifest_pre = _esc(json.dumps(manifest, indent=2, ensure_ascii=False))
    file_items = [str(x) for x in file_inventory]
    risk_items = [str(x) for x in risk_notes]

    body_html = f"""
    {tile_html}
    <div class="grid">
      {_kv_table("Extension Source", source_rows)}
      {_kv_table("Extension Summary", summary_rows,
                 f'<span class="badge {verdict_class}">Verdict: {verdict_text}</span>')}
    </div>
    {_list_section("Risk Notes", risk_items, emphasize=True)}
    {_list_section("File Inventory", file_items)}
    <section class="card">
      <div class="section-head">
        <h2>Manifest JSON</h2>
        <span class="badge sev-low">Entries: {len(manifest) if isinstance(manifest, Mapping) else 0}</span>
      </div>
      <pre>{manifest_pre}</pre>
    </section>
    """

    # Was a byte-for-byte re-implementation of `report_page`: same container,
    # banner, title, subtitle, verdict and footer, differing only in the
    # footer's wording. Sharing the builder means a change to the page shell
    # reaches this report too, which is the whole reason there is a builder.
    return report_page(
        title="Browser Extension Analysis Report",
        subtitle="Generated by RingForge Workbench",
        verdict=verdict_text,
        verdict_class=verdict_class,
        body_html=body_html,
        footer_note="RingForge Workbench &bull; Browser Extension Analysis",
    )
