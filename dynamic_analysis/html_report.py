from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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

    tiles = [
        ("Exit Code", summary.get("exit_code", "")),
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

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    title = f"Dynamic Analysis Report - {sample.get('sample_name', 'Unknown Sample')}"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_esc(title)}</title>
<style>
  :root {{
    --bg: #0f172a;
    --panel: #111827;
    --panel-2: #0b1220;
    --border: #1f2937;
    --text: #e5e7eb;
    --muted: #94a3b8;
    --blue: #93c5fd;
    --blue-strong: #2563eb;
    --good: #10b981;
    --warn: #f59e0b;
    --bad: #ef4444;
    --shadow: 0 10px 30px rgba(0,0,0,0.28);
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: Segoe UI, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 24px;
  }}
  .container {{
    max-width: 1280px;
    margin: 0 auto;
  }}
  h1 {{
    margin: 0 0 8px 0;
    font-size: 32px;
    color: var(--blue);
  }}
  h2 {{
    margin: 0;
    font-size: 18px;
    color: #bfdbfe;
  }}
  .subtitle {{
    color: var(--muted);
    margin-top: 6px;
    font-size: 14px;
  }}
  .banner {{
    background: linear-gradient(135deg, #0b1220, #1d4ed8);
    border: 1px solid #1d4ed8;
    border-radius: 18px;
    padding: 22px;
    margin-bottom: 20px;
    box-shadow: var(--shadow);
  }}
  .verdict {{
    display: inline-block;
    margin-top: 14px;
    padding: 8px 12px;
    border-radius: 999px;
    font-weight: 600;
    border: 1px solid transparent;
  }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 18px;
  }}
  .tile-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
    margin-bottom: 18px;
  }}
  .tile {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 14px;
    box-shadow: var(--shadow);
  }}
  .tile-label {{
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-bottom: 6px;
  }}
  .tile-value {{
    font-size: 24px;
    font-weight: 700;
    color: var(--text);
  }}
  .card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px;
    margin-bottom: 18px;
    box-shadow: var(--shadow);
  }}
  .card-alert {{
    border-color: rgba(245, 158, 11, 0.55);
    box-shadow: 0 10px 30px rgba(245, 158, 11, 0.08);
  }}
  .section-head {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    margin-bottom: 14px;
    flex-wrap: wrap;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
  }}
  th, td {{
    text-align: left;
    padding: 9px 10px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    word-break: break-word;
    font-size: 14px;
  }}
  th {{
    color: #cbd5e1;
    width: 35%;
    background: rgba(255,255,255,0.01);
  }}
  .kv th {{
    width: 42%;
  }}
  .muted {{
    color: var(--muted);
  }}
  ul {{
    margin: 0;
    padding-left: 20px;
  }}
  li {{
    margin-bottom: 6px;
  }}
  .table-wrap {{
    overflow-x: auto;
  }}
  .badge {{
    display: inline-block;
    padding: 6px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    border: 1px solid transparent;
    white-space: nowrap;
  }}
  .sev-none {{
    background: rgba(16,185,129,0.12);
    color: #a7f3d0;
    border-color: rgba(16,185,129,0.35);
  }}
  .sev-low {{
    background: rgba(59,130,246,0.12);
    color: #bfdbfe;
    border-color: rgba(59,130,246,0.35);
  }}
  .sev-med {{
    background: rgba(245,158,11,0.12);
    color: #fde68a;
    border-color: rgba(245,158,11,0.35);
  }}
  .sev-high {{
    background: rgba(239,68,68,0.12);
    color: #fecaca;
    border-color: rgba(239,68,68,0.35);
  }}
  .footer {{
    margin-top: 20px;
    color: var(--muted);
    font-size: 12px;
    text-align: right;
  }}
  @media print {{
    body {{
      background: white;
      color: black;
      padding: 0;
    }}
    .banner, .card, .tile {{
      box-shadow: none;
    }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="banner">
    <h1>{_esc(title)}</h1>
    <div class="subtitle">
      Started: {_esc(summary.get("started_at_utc", ""))} |
      Ended: {_esc(summary.get("ended_at_utc", ""))} |
      Generated: {_esc(generated_at)}
    </div>
    <div class="verdict {verdict_class}">{_esc(verdict)}</div>
  </div>

  {_summary_tiles(summary)}

  <div class="grid">
    {_kv_table("Sample Metadata", sample)}
    {_kv_table("Procmon Summary", procmon)}
    {_kv_table("Interesting Procmon Summary", procmon_interesting)}
    {_kv_table("Findings Counts", counts)}
    {_kv_table("Scheduled Task Diff", task_diff, _section_badge("Suspicious", task_diff.get("suspicious_new_or_modified", 0)))}
    {_kv_table("Service Diff", service_diff, _section_badge("Suspicious", service_diff.get("suspicious_new_or_modified", 0)))}
    {_kv_table("Dropped Files Summary", dropped, _section_badge("Suspicious", dropped.get("suspicious", 0)))}
  </div>

  {_list_section("Highlights", findings.get("highlights", []), emphasize=True)}
  {_dict_list_table("Top Written Paths", findings.get("top_written_paths", []))}
  {_dict_list_table("Top Network Processes", findings.get("top_network_processes", []))}
  {_dict_list_table("Spawned Processes", findings.get("spawned_processes", []))}
  {_dict_list_table("Suspicious Path Hits", findings.get("suspicious_path_hits", []), emphasize=True)}
  {_dict_list_table("Persistence Hits", findings.get("persistence_hits", []), emphasize=True)}

  <div class="footer">
    Report generated from dynamic_run_summary.json
  </div>
</div>
</body>
</html>
"""


def write_dynamic_html_report(summary_path: Path, output_html: Path) -> Path:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    html_text = build_dynamic_html_report(summary)
    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(html_text, encoding="utf-8")
    return output_html