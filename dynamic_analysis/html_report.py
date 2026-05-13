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


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _severity_class_for_count(value: Any) -> str:
    n = _to_int(value, 0)
    if n <= 0:
        return "sev-none"
    if n <= 2:
        return "sev-low"
    if n <= 10:
        return "sev-med"
    return "sev-high"


def _severity_class_for_score(score: Any, severity: Any = "") -> str:
    sev = str(severity or "").strip().lower()
    score_i = _to_int(score, 0)

    if sev in {"critical", "high"} or score_i >= 60:
        return "sev-high"
    if sev in {"medium", "moderate"} or score_i >= 25:
        return "sev-med"
    if sev in {"low"} or score_i >= 6:
        return "sev-low"
    return "sev-none"


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


def _list_section(title: str, items: list[Any], emphasize: bool = False, empty_text: str = "None") -> str:
    section_class = "card card-alert" if emphasize and items else "card"
    if not items:
        body = f"<p class='muted'>{_esc(empty_text)}</p>"
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


def _dict_list_table(
    title: str,
    items: list[dict[str, Any]],
    emphasize: bool = False,
    empty_text: str = "None",
    limit: int = 100,
) -> str:
    section_class = "card card-alert" if emphasize and items else "card"
    if not items:
        return f"""
        <section class="{section_class}">
          <div class="section-head">
            <h2>{_esc(title)}</h2>
            {_section_badge("Count", 0)}
          </div>
          <p class="muted">{_esc(empty_text)}</p>
        </section>
        """

    visible = items[:limit]
    headers = _ordered_headers(visible)
    thead = "".join(f"<th>{_esc(_pretty_key(h))}</th>" for h in headers)
    rows = []
    for item in visible:
        row = "".join(f"<td>{_esc(item.get(h, ''))}</td>" for h in headers)
        rows.append(f"<tr>{row}</tr>")

    truncated = ""
    if len(items) > limit:
        truncated = f"<p class='muted'>Showing first {limit} of {len(items)} rows.</p>"

    return f"""
    <section class="{section_class}">
      <div class="section-head">
        <h2>{_esc(title)}</h2>
        {_section_badge("Count", len(items))}
      </div>
      {truncated}
      <div class="table-wrap">
        <table>
          <thead><tr>{thead}</tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </section>
    """


def _autoruns_counts(summary: dict[str, Any]) -> dict[str, Any]:
    # Newer orchestrator writes a full autoruns_diff object plus compact counts.
    diff = summary.get("autoruns_diff", {}) or {}
    if isinstance(diff, dict) and isinstance(diff.get("counts"), dict):
        return diff.get("counts", {}) or {}

    counts = summary.get("autoruns_diff_summary", {}) or {}
    return counts if isinstance(counts, dict) else {}


def _autoruns_table(summary: dict[str, Any]) -> str:
    counts = _autoruns_counts(summary)
    before_status = summary.get("autoruns_before_status", {}) or {}
    after_status = summary.get("autoruns_after_status", {}) or {}

    enabled = summary.get("autoruns_enabled", False)
    deep = summary.get("autoruns_deep_scan", False)

    data = {
        "enabled": enabled,
        "deep_scan": deep,
        "before_snapshot_success": before_status.get("success", False) if isinstance(before_status, dict) else False,
        "after_snapshot_success": after_status.get("success", False) if isinstance(after_status, dict) else False,
        "before_total": counts.get("before_total", 0),
        "after_total": counts.get("after_total", 0),
        "new_entries": counts.get("new_entries", 0),
        "removed_entries": counts.get("removed_entries", 0),
        "modified_entries": counts.get("modified_entries", 0),
        "suspicious_new_entries": counts.get("suspicious_new_entries", 0),
        "suspicious_modified_entries": counts.get("suspicious_modified_entries", 0),
        "suspicious_new_or_modified": counts.get("suspicious_new_or_modified", 0),
    }

    suspicious = _to_int(data["suspicious_new_or_modified"], 0)
    badge_html = badge("Suspicious", suspicious)

    return _kv_table("Autoruns Persistence Diff", data, badge_html)


def _autoruns_suspicious_sections(summary: dict[str, Any]) -> str:
    diff = summary.get("autoruns_diff", {}) or {}
    if not isinstance(diff, dict):
        return ""

    suspicious_new = diff.get("suspicious_new_entries", []) or []
    suspicious_modified = diff.get("suspicious_modified_entries", []) or []

    html_parts = []

    if suspicious_new:
        html_parts.append(
            _dict_list_table(
                "Suspicious New Autoruns Entries",
                suspicious_new if isinstance(suspicious_new, list) else [],
                emphasize=True,
                limit=50,
            )
        )

    if suspicious_modified:
        # Flatten before/after pairs into display rows.
        rows = []
        if isinstance(suspicious_modified, list):
            for item in suspicious_modified:
                if not isinstance(item, dict):
                    continue
                after = item.get("after", {}) if isinstance(item.get("after", {}), dict) else {}
                before = item.get("before", {}) if isinstance(item.get("before", {}), dict) else {}
                rows.append(
                    {
                        "entry": after.get("entry", before.get("entry", "")),
                        "category": after.get("category", before.get("category", "")),
                        "entry_location": after.get("entry_location", before.get("entry_location", "")),
                        "before_image_path": before.get("image_path", ""),
                        "after_image_path": after.get("image_path", ""),
                        "after_signer": after.get("signer", ""),
                    }
                )

        html_parts.append(
            _dict_list_table(
                "Suspicious Modified Autoruns Entries",
                rows,
                emphasize=True,
                limit=50,
            )
        )

    return "\n".join(html_parts)


def _derive_report_verdict(summary: dict[str, Any]) -> tuple[str, str]:
    """
    Use the orchestrator's actual score/severity/verdict as the source of truth.

    The older report derived a top banner from only suspicious-path/persistence
    counts, which caused mismatches like:
        banner: Benign / Clean Baseline
        score section: Medium / Needs Review
    """
    score = summary.get("score", summary.get("dynamic_score", 0))
    severity = str(summary.get("severity", "") or "").strip()
    verdict = str(summary.get("verdict", "") or "").strip()

    if verdict:
        label = verdict
        if severity and severity.lower() not in verdict.lower():
            label = f"{verdict} / {severity}"
        return label, _severity_class_for_score(score, severity)

    score_i = _to_int(score, 0)
    if score_i >= 60:
        return "High Suspicion", "sev-high"
    if score_i >= 25:
        return "Needs Review", "sev-med"
    if score_i >= 6:
        return "Low Suspicion", "sev-low"
    return "Benign / Clean Baseline", "sev-none"


def _clean_baseline_notes(summary: dict[str, Any]) -> list[str]:
    findings = summary.get("findings", {}) or {}
    counts = findings.get("counts", {}) or {}
    task_diff = summary.get("task_diff_summary", {}) or {}
    service_diff = summary.get("service_diff_summary", {}) or {}
    dropped = summary.get("dropped_files_summary", {}) or {}
    autoruns = _autoruns_counts(summary)

    notes = []

    if _to_int(task_diff.get("suspicious_new_or_modified", 0)) == 0:
        notes.append("No suspicious scheduled task changes were observed.")

    if _to_int(service_diff.get("suspicious_new_or_modified", 0)) == 0:
        notes.append("No suspicious service changes were observed.")

    if _to_int(autoruns.get("suspicious_new_or_modified", 0)) == 0:
        if _to_int(autoruns.get("before_total", 0)) or _to_int(autoruns.get("after_total", 0)):
            notes.append("Autoruns baseline comparison completed with no suspicious new or modified entries.")

    if _to_int(dropped.get("suspicious", 0)) == 0:
        notes.append("No suspicious dropped files were identified.")

    if _to_int(counts.get("persistence_hits", 0)) == 0:
        notes.append("No high-confidence persistence hits were detected in parsed Procmon events.")

    return notes


def _analyst_notes(summary: dict[str, Any]) -> list[str]:
    score = _to_int(summary.get("score", summary.get("dynamic_score", 0)), 0)
    severity = str(summary.get("severity", "") or "").strip()
    verdict = str(summary.get("verdict", "") or "").strip()
    notes = []

    notes.append(f"Dynamic score is {score}; reported verdict is {verdict or 'not provided'} and severity is {severity or 'not provided'}.")

    clean_notes = _clean_baseline_notes(summary)
    notes.extend(clean_notes)

    autoruns = _autoruns_counts(summary)
    if _to_int(autoruns.get("new_entries", 0)) > 0 or _to_int(autoruns.get("modified_entries", 0)) > 0:
        notes.append("Autoruns detected new or modified startup entries; review the Autoruns Persistence Diff section.")

    return notes


def _summary_tiles(summary: dict[str, Any]) -> str:
    findings = summary.get("findings", {}) or {}
    counts = findings.get("counts", {}) or {}
    autoruns = _autoruns_counts(summary)

    score = summary.get("score", summary.get("dynamic_score", 0))
    severity = summary.get("severity", "")
    verdict = summary.get("verdict", "")

    tiles = [
        ("Exit Code", summary.get("exit_code", "")),
        ("Dynamic Score", score),
        ("Severity", severity),
        ("Verdict", verdict),
        ("Interesting Events", counts.get("interesting_events", 0)),
        ("Process Creates", counts.get("process_creates", 0)),
        ("Network Events", counts.get("network_events", 0)),
        ("File Writes", counts.get("file_write_events", 0)),
        ("Suspicious Paths", counts.get("suspicious_path_hits", 0)),
        ("Persistence Hits", counts.get("persistence_hits", 0)),
        ("Autoruns Suspicious", autoruns.get("suspicious_new_or_modified", 0)),
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

    verdict, verdict_class = _derive_report_verdict(summary)

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

    autoruns_counts = _autoruns_counts(summary)

    body_html = f"""
{_summary_tiles(summary)}

<div class="grid">
  {_kv_table("Sample Metadata", sample)}
  {_kv_table("Procmon Summary", procmon)}
  {_kv_table("Interesting Procmon Summary", procmon_interesting)}
  {_kv_table("Findings Counts", findings_counts)}
  {_kv_table("Scheduled Task Diff", task_diff, badge("Suspicious", task_diff.get("suspicious_new_or_modified", 0)))}
  {_kv_table("Service Diff", service_diff, badge("Suspicious", service_diff.get("suspicious_new_or_modified", 0)))}
  {_autoruns_table(summary)}
  {_kv_table("Dropped Files Summary", dropped, badge("Suspicious", dropped.get("suspicious", 0)))}
</div>

{_list_section("Analyst Notes", _analyst_notes(summary), emphasize=False)}
{_list_section("Clean Baseline Checks", _clean_baseline_notes(summary), emphasize=False, empty_text="No clean-baseline checks were available.")}
{_list_section("Highlights", findings.get("highlights", []), emphasize=True, empty_text="No high-priority highlights were generated.")}
{_autoruns_suspicious_sections(summary)}
{_dict_list_table("Top Written Paths", findings.get("top_written_paths", []))}
{_dict_list_table("Top Network Processes", findings.get("top_network_processes", []))}
{_dict_list_table("Spawned Processes", findings.get("spawned_processes", []), empty_text="No non-noise spawned processes were attributed to the sample.")}
{_dict_list_table("Suspicious Path Hits", findings.get("suspicious_path_hits", []), emphasize=True, empty_text="No suspicious path hits were identified.")}
{_dict_list_table("Persistence Hits", findings.get("persistence_hits", []), emphasize=True, empty_text="No persistence hits were identified.")}
"""

    return report_page(title, subtitle, verdict, verdict_class, body_html)


def write_dynamic_html_report(summary_path: Path, output_html: Path) -> Path:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    html_text = build_dynamic_html_report(summary)
    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(html_text, encoding="utf-8")
    return output_html
