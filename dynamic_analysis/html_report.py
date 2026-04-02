from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from dynamic_analysis.report_theme import badge, report_page

def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _pretty_key(value: str) -> str:
    return value.replace("_", " ").strip().title()


def _severity_class_for_count(value: Any) -> str:
    try:
        n = int(value)
    except Exception:
        return "sev-none"
    if n <= 0:
        return "sev-none"
    if n <= 2:
        return "sev-low"
    if n <= 10:
        return "sev-med"
    return "sev-high"


def _section_badge(label: str, value: Any) -> str:
    cls = _severity_class_for_count(value)
    return f'<span class="badge {cls}">{_esc(label)}: {_esc(value)}</span>'


def _kv_table(title: str, data: dict[str, Any], badge_html: str = "") -> str:
    rows = []
    for k, v in data.items():
        rows.append(f"<tr><th>{_esc(_pretty_key(str(k)))}</th><td>{_esc(v)}</td></tr>")
    return f"""
    <section class="card">
      <div class="section-head">
        <h2>{_esc(title)}</h2>
        {badge_html}
      </div>
      <table class="kv">
        {''.join(rows) if rows else "<tr><td class='muted'>None</td></tr>"}
      </table>
    </section>
    """


def _list_section(title: str, items: list[Any], emphasize: bool = False) -> str:
    section_class = "card card-alert" if emphasize and items else "card"
    if not items:
        body = "<p class='muted'>None</p>"
    else:
        lis = "".join(f"<li>{_esc(item)}</li>" for item in items)
        body = f"<ul>{lis}</ul>"
    return f"""
    <section class="{section_class}">
      <div class="section-head">
        <h2>{_esc(title)}</h2>
        {_section_badge("Count", len(items))}
      </div>
      {body}
    </section>
    """


def _ordered_headers(items: list[dict[str, Any]]) -> list[str]:
    preferred = [
        "timestamp",
        "process_name",
        "pid",
        "path",
        "operation",
        "detail",
        "count",
        "is_lolbin",
        "is_analyzer_activity",
    ]
    seen: list[str] = []
    for key in preferred:
        if any(key in item for item in items):
            seen.append(key)
    for item in items:
        for key in item.keys():
            if key not in seen:
                seen.append(key)
    return seen


def _dict_list_table(title: str, items: list[dict[str, Any]], emphasize: bool = False) -> str:
    section_class = "card card-alert" if emphasize and items else "card"
    if not items:
        return f"""
        <section class="{section_class}">
          <div class="section-head">
            <h2>{_esc(title)}</h2>
            {_section_badge("Count", 0)}
          </div>
          <p class="muted">None</p>
        </section>
        """
    headers = _ordered_headers(items)
    thead = "".join(f"<th>{_esc(_pretty_key(h))}</th>" for h in headers)
    rows = []
    for item in items:
        row = "".join(f"<td>{_esc(item.get(h, ''))}</td>" for h in headers)
        rows.append(f"<tr>{row}</tr>")
    return f"""
    <section class="{section_class}">
      <div class="section-head">
        <h2>{_esc(title)}</h2>
        {_section_badge("Count", len(items))}
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr>{thead}</tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </section>
    """


def _summary_tiles(summary: dict[str, Any]) -> str:
    findings = summary.get("findings", {}) or {}
    counts = findings.get("counts", {}) or {}

    score = summary.get("score", summary.get("dynamic_score", 0))
    severity = summary.get("severity", "")
    verdict = summary.get("verdict", "")

    tiles = [
        ("Exit Code", summary.get("exit_code", "")),
        ("Dynamic Score", score),
        ("Severity", severity),
        ("Interesting Events", counts.get("interesting_events", 0)),
        ("Process Creates", counts.get("process_creates", 0)),
        ("Network Events", counts.get("network_events", 0)),
        ("File Writes", counts.get("file_write_events", 0)),
        ("Suspicious Paths", counts.get("suspicious_path_hits", 0)),
        ("Persistence Hits", counts.get("persistence_hits", 0)),
        ("LOLBin Processes", counts.get("lolbin_processes", 0)),
    ]

    blocks = []
    for label, value in tiles:
        blocks.append(
            f"""
            <div class="tile">
              <div class="tile-label">{_esc(label)}</div>
              <div class="tile-value">{_esc(value)}</div>
            </div>
            """
        )
    return f'<section class="tile-grid">{"".join(blocks)}</section>'


def build_dynamic_html_report(summary: dict[str, Any]) -> str:
    sample = summary.get("sample", {}) or {}
    findings = summary.get("findings", {}) or {}
    counts = findings.get("counts", {}) or {}
    task_diff = summary.get("task_diff_summary", {}) or {}
    service_diff = summary.get("service_diff_summary", {}) or {}
    dropped = summary.get("dropped_files_summary", {}) or {}
    procmon = summary.get("procmon_summary", {}) or {}
    procmon_interesting = summary.get("procmon_interesting_summary", {}) or {}

    suspicious_count = counts.get("suspicious_path_hits", 0)
    persistence_count = counts.get("persistence_hits", 0)
    dropped_count = dropped.get("suspicious", 0)

    verdict = "Benign / Clean Baseline"
    verdict_class = "sev-none"
    if suspicious_count or persistence_count or dropped_count:
        verdict = "Needs Review"
        verdict_class = "sev-med"
    if persistence_count or dropped_count:
        verdict = "Elevated Attention"
        verdict_class = "sev-high"

    title = f"Dynamic Analysis Report - {sample.get('sample_name', 'Unknown Sample')}"
    subtitle = (
        f"Started: {_esc(summary.get('started_at_utc', ''))} | "
        f"Ended: {_esc(summary.get('ended_at_utc', ''))} | "
        f"Exit Code: {_esc(summary.get('exit_code', ''))}"
    )

    findings_counts = {
        "score": summary.get("score", summary.get("dynamic_score", 0)),
        "severity": summary.get("severity", ""),
        "verdict": summary.get("verdict", verdict),
        **counts,
    }

    body_html = f"""
{_summary_tiles(summary)}

<div class="grid">
  {_kv_table("Sample Metadata", sample)}
  {_kv_table("Procmon Summary", procmon)}
  {_kv_table("Interesting Procmon Summary", procmon_interesting)}
  {_kv_table("Findings Counts", findings_counts)}
  {_kv_table("Scheduled Task Diff", task_diff, badge("Suspicious", task_diff.get("suspicious_new_or_modified", 0)))}
  {_kv_table("Service Diff", service_diff, badge("Suspicious", service_diff.get("suspicious_new_or_modified", 0)))}
  {_kv_table("Dropped Files Summary", dropped, badge("Suspicious", dropped.get("suspicious", 0)))}
</div>

{_list_section("Highlights", findings.get("highlights", []), emphasize=True)}
{_dict_list_table("Top Written Paths", findings.get("top_written_paths", []))}
{_dict_list_table("Top Network Processes", findings.get("top_network_processes", []))}
{_dict_list_table("Spawned Processes", findings.get("spawned_processes", []))}
{_dict_list_table("Suspicious Path Hits", findings.get("suspicious_path_hits", []), emphasize=True)}
{_dict_list_table("Persistence Hits", findings.get("persistence_hits", []), emphasize=True)}
"""

    return report_page(title, subtitle, verdict, verdict_class, body_html)

def write_dynamic_html_report(summary_path: Path, output_html: Path) -> Path:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    html_text = build_dynamic_html_report(summary)
    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(html_text, encoding="utf-8")
    return output_html