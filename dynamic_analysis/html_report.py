from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from dynamic_analysis.network_capture import is_baseline_domain
from dynamic_analysis.report_theme import badge, report_page


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _pretty_key(value: str) -> str:
    labels = {
        "total_run_duration_seconds": "Total Run Duration",
        "sample_observation_timeout_seconds": "Sample Observation Timeout",
        "minimum_observation_seconds": "Minimum Observation",
        "post_exit_observation_seconds": "Post-Exit Observation",
        "installer_observation_mode": "Installer Observation Mode",
        "procmon_enabled": "Procmon Enabled",
        "procmon_capture_quality": "Procmon Capture Quality",
        "procmon_capture_score": "Procmon Capture Score",
        "procmon_total_events": "Procmon Total Events",
        "autoruns_enabled": "Autoruns Enabled",
        "autoruns_deep_scan": "Autoruns Deep Scan",
        "autoruns_before_success": "Autoruns Before Success",
        "autoruns_before_error": "Autoruns Before Error",
        "autoruns_after_success": "Autoruns After Success",
        "autoruns_after_error": "Autoruns After Error",
    }
    key = str(value or "").strip()
    return labels.get(key, key.replace("_", " ").strip().title())


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

    # Trust explicit orchestrator severity first.
    if sev in {"critical", "high"}:
        return "sev-high"
    if sev in {"medium", "moderate"}:
        return "sev-med"
    if sev in {"low"}:
        return "sev-low"
    if sev in {"info", "none", "benign"}:
        return "sev-none"

    # Fallback only when severity is missing.
    if score_i >= 120:
        return "sev-high"
    if score_i >= 45:
        return "sev-med"
    if score_i >= 10:
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


def _list_section(
    title: str,
    items: list[Any],
    emphasize: bool = False,
    empty_text: str = "None",
    context: bool = False,
) -> str:
    """Render a titled list with a count badge.

    ``context`` marks a section whose length carries no severity, and the badge
    then stays neutral however long the list is. Scaling colour by count is only
    meaningful when more entries means more concern, and several sections here
    are the opposite: "Clean Baseline Checks" turned amber at five *passing*
    checks, and "Windows Baseline Traffic (context, not findings)" contradicted
    its own title.
    """
    section_class = "card card-alert" if emphasize and items else "card"
    if not items:
        body = f"<p class='muted'>{_esc(empty_text)}</p>"
    else:
        lis = "".join(f"<li>{_esc(item)}</li>" for item in items)
        body = f"<ul>{lis}</ul>"

    badge_html = (
        f'<span class="badge sev-none">Count: {_esc(len(items))}</span>'
        if context
        else _section_badge("Count", len(items))
    )

    return f"""
    <section class="{section_class}">
      <div class="section-head">
        <h2>{_esc(title)}</h2>
        {badge_html}
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

    # Short, atomic values (addresses, ports, PIDs, protocols) read badly when
    # broken mid-token, so they are kept on one line.
    nowrap_fields = {
        "pid", "protocol", "port", "destination", "dst", "src", "source",
        "process", "method", "event_id", "severity", "state", "count",
    }

    rows = []
    for item in visible:
        cells = []
        for header in headers:
            value = _esc(item.get(header, ""))
            css = " class=\"nowrap\"" if header.lower() in nowrap_fields else ""
            cells.append(f"<td{css}>{value}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")

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
        <table class="data-table">
          <thead><tr>{thead}</tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </section>
    """


def _attack_sections(summary: dict[str, Any]) -> str:
    """ATT&CK techniques, each shown with what evidenced it.

    The evidence column is the point. A bare list of technique IDs is a claim;
    the same list with the observation that produced each one is a finding
    somebody can check.
    """
    mapping = summary.get("attack_mapping", {}) or {}
    if not mapping.get("mapped"):
        return ""

    techniques = mapping.get("techniques", []) or []
    if not techniques:
        return _list_section(
            "MITRE ATT&CK",
            [],
            empty_text="No techniques were evidenced by this run.",
            context=True,
        )

    rows = [
        {
            "technique": f"{t.get('id', '')} {t.get('name', '')}".strip(),
            "tactic": t.get("tactic", ""),
            "evidence": "; ".join(t.get("evidence", [])[:2]),
        }
        for t in techniques
    ]

    counts = mapping.get("counts", {}) or {}
    return f"""
    <section class="card">
      <div class="section-head">
        <h2>MITRE ATT&amp;CK ({_esc(mapping.get("attack_version", ""))})</h2>
        {_section_badge("Techniques", counts.get("techniques", 0))}
      </div>
      <p class="muted">{_esc(mapping.get("note", ""))}</p>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Technique</th><th>Tactic</th><th>Evidence</th></tr></thead>
          <tbody>{''.join(
              f"<tr><td class='nowrap'>{_esc(r['technique'])}</td>"
              f"<td class='nowrap'>{_esc(r['tactic'])}</td>"
              f"<td>{_esc(r['evidence'])}</td></tr>" for r in rows
          )}</tbody>
        </table>
      </div>
    </section>
    """


def _powershell_sections(summary: dict[str, Any]) -> str:
    """Recorded script blocks, which are the deobfuscated text of what ran."""
    powershell = summary.get("powershell_summary", {}) or {}
    preflight = summary.get("powershell_preflight", {}) or {}

    if not powershell.get("collected"):
        note = powershell.get("note") or preflight.get("note") or "Not collected."
        return f"""
    <section class="card">
      <div class="section-head"><h2>PowerShell Script Blocks</h2></div>
      <p class="muted">{_esc(note)}</p>
    </section>
    """

    counts = powershell.get("counts", {}) or {}
    overview = {
        "Blocks from the sample": counts.get("blocks_from_sample", 0),
        "Suspicious blocks": counts.get("blocks_suspicious", 0),
        "Incomplete blocks": counts.get("incomplete_blocks", 0),
        "Analyzer blocks excluded": counts.get("analyzer_blocks_excluded", 0),
    }

    rows = [
        {
            "time": block.get("timestamp", ""),
            "severity": block.get("severity", ""),
            "behaviours": ", ".join(block.get("behaviours", [])) or "none",
            "length": block.get("length", 0),
            "preview": block.get("preview", ""),
        }
        for block in (powershell.get("blocks", []) or [])
    ]

    return f"""
{_kv_table("PowerShell Script Blocks", overview,
           _section_badge("Suspicious", counts.get("blocks_suspicious", 0)))}
{_list_section("PowerShell Behaviours Observed", powershell.get("behaviours", []) or [],
               emphasize=True,
               empty_text="No suspicious behaviours were matched in the recorded script blocks.")}
{_dict_list_table("Recorded Script Blocks", rows,
                  empty_text="No script blocks were attributed to the sample.")}
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
        # Shown so excluded tooling entries are visible rather than unexplained.
        "analyzer_entries_excluded": counts.get("analyzer_entries", 0),
        "before_error": before_status.get("error", "") if isinstance(before_status, dict) else "",
        "after_error": after_status.get("error", "") if isinstance(after_status, dict) else "",
    }

    suspicious = _to_int(data["suspicious_new_or_modified"], 0)
    badge_html = badge("Suspicious", suspicious)

    return _kv_table("Autoruns Persistence Diff", data, badge_html)
    
def _capture_configuration_table(summary: dict[str, Any]) -> str:
    capture_quality = summary.get("capture_quality", {}) or {}
    before_status = summary.get("autoruns_before_status", {}) or {}
    after_status = summary.get("autoruns_after_status", {}) or {}

    run_config = summary.get("run_config", {}) or {}
    procmon_filter = summary.get("procmon_filter", {}) or {}

    data = {
        "run_profile": summary.get("run_profile", ""),
        "cancelled": summary.get("cancelled", False),
        "total_run_duration_seconds": summary.get("duration_seconds", ""),
        "sample_observation_timeout_seconds": summary.get("timeout_seconds", ""),
        "procmon_enabled": summary.get("procmon_enabled", False),
        # Which filter ran. Without it, a pass reporting nothing collected and a
        # pass whose config was wrong are the same report.
        "procmon_config": procmon_filter.get("config_path", ""),
        "procmon_operations_captured": len(procmon_filter.get("operations", []) or []) or "",
        "procmon_captures_registry_reads": procmon_filter.get("captures_registry_reads", False),
        "procmon_capture_quality": capture_quality.get("status", ""),
        "procmon_capture_score": capture_quality.get("score", ""),
        "procmon_total_events": capture_quality.get("procmon_total_events", ""),
        "capture_note": capture_quality.get("note", ""),
        "autoruns_enabled": summary.get("autoruns_enabled", False),
        "autoruns_deep_scan": summary.get("autoruns_deep_scan", False),
        "autoruns_before_success": before_status.get("success", False) if isinstance(before_status, dict) else False,
        "autoruns_before_error": before_status.get("error", "") if isinstance(before_status, dict) else "",
        "autoruns_after_success": after_status.get("success", False) if isinstance(after_status, dict) else False,
        "autoruns_after_error": after_status.get("error", "") if isinstance(after_status, dict) else "",
        "installer_observation_mode": run_config.get("installer_observation_mode", summary.get("installer_observation_mode", "")),
        "minimum_observation_seconds": run_config.get("minimum_observation_seconds", summary.get("minimum_observation_seconds", "")),
        "post_exit_observation_seconds": run_config.get("post_exit_observation_seconds", summary.get("post_exit_observation_seconds", "")),
    }

    return _kv_table("Capture Configuration / Tool Status", data)
    
def _autoruns_entry_table(
    title: str,
    items: list[dict[str, Any]],
    emphasize: bool = True,
    empty_text: str = "None",
    limit: int = 50,
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
    rows = []

    for item in visible:
        rows.append(
            "<tr>"
            f"<td>{_esc(item.get('time', ''))}</td>"
            f"<td>{_esc(item.get('category', ''))}</td>"
            # Without the location, two entries of the same name in different
            # hives render as identical rows. Remcos wrote TRY150-6P1GV6 to both
            # HKCU\\...\\Run and HKLM\\...\\Wow6432Node\\...\\Run, and the report
            # showed what looked like one entry duplicated.
            f"<td>{_esc(item.get('entry_location', ''))}</td>"
            f"<td>{_esc(item.get('entry', ''))}</td>"
            f"<td>{_esc(item.get('company', ''))}</td>"
            f"<td>{_esc(item.get('image_path', ''))}</td>"
            f"<td>{_esc(item.get('launch_string', ''))}</td>"
            "</tr>"
        )

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
        <table class="autoruns-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Category</th>
              <th>Location</th>
              <th>Entry</th>
              <th>Company</th>
              <th>Image Path</th>
              <th>Launch String</th>
            </tr>
          </thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </section>
    """


def _autoruns_analyzer_section(summary: dict[str, Any]) -> str:
    """Autorun entries the analysis tooling created, excluded from findings."""
    diff = summary.get("autoruns_diff", {}) or {}
    entries = diff.get("analyzer_entries", []) or []
    if not entries:
        return ""

    return f"""
    <section class="card">
      <div class="section-head">
        <h2>Autoruns Entries From The Analysis Tooling</h2>
        {_section_badge("Excluded", len(entries))}
      </div>
      <p class="muted">
        Created by RingForge's own instrumentation rather than by the sample --
        FakeNet-NG's WinDivert diverter registers as a driver on first run, for
        example. Excluded from the findings and the score, and listed here so the
        tooling registering correctly stays verifiable.
      </p>
      {_autoruns_entry_table("", entries)}
    </section>
    """


def _autoruns_suspicious_sections(summary: dict[str, Any]) -> str:
    diff = summary.get("autoruns_diff", {}) or {}
    if not isinstance(diff, dict):
        return ""

    suspicious_new = diff.get("suspicious_new_entries", []) or []
    suspicious_modified = diff.get("suspicious_modified_entries", []) or []

    html_parts = []

    if suspicious_new:
        html_parts.append(
            _autoruns_entry_table(
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
    
def _spawned_empty_text(findings: dict[str, Any]) -> str:
    """Empty-state wording for the spawned table, which has two empty states.

    "The sample started nothing" and "we could not work out what the sample
    started" are the same empty list, and only the first is a result.
    """
    if not findings.get("lineage_resolved", True):
        return (
            "The sample's process could not be identified, so nothing here is "
            "attributed by lineage. Every process create observed during the "
            "run is listed as a finding rather than as background."
        )
    return "No spawned processes descended from the sample."


def _background_network_section(findings: dict[str, Any]) -> str:
    """Connections made during the window by processes that were not the sample.

    Once FakeNet could actually intercept, every resident service on the guest
    began reaching the simulated internet -- svchost, Defender, OneDrive,
    Copilot -- and each one counted as the sample's network activity. Judged by
    lineage now, the same as process creates, and reported here rather than
    dropped for the same reason.
    """
    rows = findings.get("background_network_processes", []) or []
    if not rows:
        return ""

    return f"""
    <section class="card">
      <div class="section-head">
        <h2>Background Network Activity (context, not findings)</h2>
        <span class="badge sev-none">Count: {_esc(sum(int(r.get("count", 0) or 0) for r in rows))}</span>
      </div>
      <p class="muted">
        These connected during the observation window but did not descend from
        the sample, so they are not counted or scored. A simulated internet
        answers everything, so every service that would normally fail to reach
        the network now succeeds against it.
      </p>
      {_dict_list_table("", rows)}
    </section>
    """


def _background_processes_section(findings: dict[str, Any]) -> str:
    """Process creates that ran during the window but not from the sample.

    Context rather than findings. Windows does its own work during any
    five-minute observation -- Defender scans, Intune check-ins, OneDrive
    starting -- and attributing that to the sample is how a benign control run
    reported six spawned processes and scored 92.

    Listed rather than discarded, because a sample can cause a process it does
    not parent: through injection, COM, a service, or WMI. Dropping these
    outright would destroy that evidence with the same filter that removes the
    housekeeping.
    """
    rows = findings.get("background_processes", []) or []
    if not rows:
        return ""

    return f"""
    <section class="card">
      <div class="section-head">
        <h2>Background Processes (context, not findings)</h2>
        <span class="badge sev-none">Count: {_esc(len(rows))}</span>
      </div>
      <p class="muted">
        These ran during the observation window but did not descend from the
        sample, so they are not counted or scored. Windows does its own work
        during any run. Worth a glance all the same: a sample can cause a
        process it does not parent, through injection, COM, a service or WMI.
      </p>
      {_spawned_processes_table("", rows, empty_text="None")}
    </section>
    """


def _spawned_processes_table(
    title: str,
    items: list[dict[str, Any]],
    emphasize: bool = False,
    empty_text: str = "No non-noise spawned processes were attributed to the sample.",
    limit: int = 50,
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
    rows = []

    for item in visible:
        rows.append(
            "<tr>"
            f"<td>{_esc(item.get('timestamp', ''))}</td>"
            f"<td>{_esc(item.get('process_name', ''))}</td>"
            f"<td>{_esc(item.get('child_process_name', ''))}</td>"
            f"<td>{_esc(item.get('pid', ''))}</td>"
            f"<td>{_esc(item.get('path', ''))}</td>"
            f"<td>{_esc(item.get('detail', ''))}</td>"
            f"<td>{_esc(item.get('is_lolbin', ''))}</td>"
            "</tr>"
        )

    truncated = ""
    if len(items) > limit:
        truncated = f"<p class='muted'>Showing first {limit} of {len(items)} rows.</p>"

    return f"""
    <section class="{section_class}">
      <div class="section-head">
        <h2>{_esc(title)}</h2>
        <span class="badge sev-low">Count: {_esc(len(items))}</span>
      </div>
      {truncated}
      <div class="table-wrap">
        <table class="process-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Parent Process</th>
              <th>Child Process</th>
              <th>PID</th>
              <th>Path</th>
              <th>Command / Detail</th>
              <th>LOLBin</th>
            </tr>
          </thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </section>
    """
def _event_hits_table(
    title: str,
    items: list[dict[str, Any]],
    emphasize: bool = True,
    empty_text: str = "None",
    limit: int = 50,
) -> str:
    section_class = "card card-alert" if emphasize and items else "card"

    if not items:
        return f"""
        <section class="{section_class}">
          <div class="section-head">
            <h2>{_esc(title)}</h2>
            <span class="badge sev-none">Count: 0</span>
          </div>
          <p class="muted">{_esc(empty_text)}</p>
        </section>
        """

    visible = items[:limit]
    rows = []

    for item in visible:
        rows.append(
            "<tr>"
            f"<td>{_esc(item.get('timestamp', ''))}</td>"
            f"<td>{_esc(item.get('process_name', ''))}</td>"
            f"<td>{_esc(item.get('operation', ''))}</td>"
            f"<td>{_esc(item.get('path', ''))}</td>"
            f"<td>{_esc(item.get('detail', ''))}</td>"
            "</tr>"
        )

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
        <table class="event-hits-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Process</th>
              <th>Operation</th>
              <th>Path</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </section>
    """

def _telemetry_coverage_table(summary: dict[str, Any]) -> str:
    """State plainly which telemetry sources were active for this run.

    Absence of evidence is not evidence of absence: if Sysmon was not running,
    the report must not read as though no injection occurred.
    """
    def describe(enabled_key: str, preflight_key: str, ran: bool) -> str:
        if not summary.get(enabled_key):
            return "Disabled for this run"
        preflight = summary.get(preflight_key, {}) or {}
        if not preflight.get("available"):
            return f"Not available - {preflight.get('note', 'tool not installed')}"
        return "Collected" if ran else "Enabled but produced no data"

    # "Collected" must mean data actually arrived. A successful query that
    # returned nothing is reported as such, because a silent zero looks
    # identical to "the sample did nothing".
    sysmon_ran = (
        bool((summary.get("sysmon_collection", {}) or {}).get("success"))
        and int((summary.get("sysmon_summary", {}) or {}).get("total_events", 0) or 0) > 0
    )
    pcap_ran = bool((summary.get("pcap_capture", {}) or {}).get("pcap_exists"))
    fakenet_ran = bool((summary.get("fakenet_summary", {}) or {}).get("parsed"))
    memory_ran = bool((summary.get("memory_summary", {}) or {}).get("collected"))

    data = {
        "Procmon": "Collected" if summary.get("procmon_enabled") else "Disabled for this run",
        "Sysmon": describe("sysmon_enabled", "sysmon_preflight", sysmon_ran),
        "Packet capture": describe("pcap_enabled", "pcap_preflight", pcap_ran),
        "Simulated internet": describe("fakenet_enabled", "fakenet_preflight", fakenet_ran),
        "Process memory": describe("memory_dump_enabled", "memory_preflight", memory_ran),
        "Memory YARA": describe(
            "memory_yara_enabled",
            "memory_yara_preflight",
            bool((summary.get("memory_yara_summary", {}) or {}).get("scanned")),
        ),
    }

    isolation = summary.get("network_isolation", {}) or {}
    if isolation:
        egress = isolation.get("egress_count", 0)
        if isolation.get("isolated"):
            data["Network isolation"] = "Isolated (no default route)"
        elif isolation.get("level") == "ok":
            data["Network isolation"] = f"Single egress path ({egress})"
        else:
            data["Network isolation"] = f"NOT CONTAINED - {egress} egress paths"

    active = sum(1 for v in data.values() if v == "Collected")
    return _kv_table("Telemetry Coverage", data, _section_badge("Active", active))


def _degraded_collection_section(summary: dict[str, Any]) -> str:
    """Report collectors that only succeeded via their fallback path.

    The task and service snapshots try WMI/CIM first and fall back to
    schtasks.exe and sc.exe. The fallback produces a usable snapshot, so the
    status is recorded as a success and the run carries on -- which is right,
    but it means a broken WMI repository leaves no mark anywhere in the report.

    That silence is the problem. WMI is itself a persistence and execution
    surface, and a guest whose `root\\cimv2` namespace is unreadable may also be
    failing to record the WMI events Sysmon is configured to watch. "This
    snapshot came the long way round" is the only warning the reader gets.
    """
    collectors = (
        ("Scheduled tasks", summary.get("tasks_snapshot_status", {}) or {}),
        ("Services", summary.get("services_snapshot_status", {}) or {}),
    )

    rows = [
        {
            "collector": label,
            "collected_via": status.get("method", "") or "fallback",
            # First line only: these carry a full PowerShell stack trace, and
            # the namespace error on line one is the part that identifies it.
            "primary_path_error": " ".join(
                str(status.get("error", "") or "").splitlines()[:1]
            ).strip()[:300],
        }
        for label, status in collectors
        if status.get("fallback_used")
    ]

    if not rows:
        return ""

    return f"""
    <section class="card card-alert">
      <div class="section-head">
        <h2>Degraded Collection</h2>
        {_section_badge("Collectors", len(rows))}
      </div>
      <p class="muted">
        These collectors failed on their primary path and succeeded only via a
        fallback. The snapshot itself is usable, so the diffs above are valid --
        but the underlying failure is not, and an unreadable WMI namespace can
        also mean WMI-based persistence and execution go unrecorded elsewhere in
        this run. Worth repairing in the guest rather than reading past.
      </p>
      {_dict_list_table("Collectors That Fell Back", rows)}
    </section>
    """


def _fakenet_cannot_intercept_section(summary: dict[str, Any]) -> str:
    """Warn when there is no route for FakeNet to intercept traffic on.

    FakeNet's diverter works on packets. With no default route, Windows rejects
    a send to any off-link address before a packet exists, so there is nothing
    to divert: the listeners are up and unreachable, and the simulated internet
    answers nothing however well it is configured.

    Observed on an AgentTesla run -- twelve listeners enabled, zero DNS
    requests served, zero diverted connections -- on a guest whose route table
    held only loopback, the on-link /24, multicast and broadcast. The sample's
    lookup was recorded by Sysmon and never became a packet. The pcap caught
    only multicast, which is the traffic that did have a route.

    Not the same warning as an unanswered lookup. That one says this sample
    went unserved; this one says no sample could be.
    """
    if not summary.get("fakenet_enabled"):
        return ""

    fakenet = summary.get("fakenet_summary", {}) or {}
    if not fakenet.get("parsed"):
        return ""

    isolation = summary.get("network_isolation", {}) or {}
    if not isolation or isolation.get("egress_count", 0):
        return ""

    listeners = len(fakenet.get("listeners_configured", []) or [])

    return f"""
    <section class="card card-alert">
      <div class="section-head">
        <h2>Simulated Internet Cannot Be Reached</h2>
        {_section_badge("Listeners idle", listeners)}
      </div>
      <p class="muted">
        This guest holds no default route, so Windows rejects a send to any
        off-link address before a packet exists. FakeNet diverts packets, so
        there is nothing for it to intercept -- {_esc(listeners)} listener(s)
        are configured and unreachable, and any sample that tries to resolve or
        connect fails locally. Nothing in this run's network results should be
        read as evidence about what the sample would do with a working network.
      </p>
      <p class="muted">
        A single default route via the host-only gateway is enough to fix it,
        and keeps containment intact: the isolation check treats one egress path
        as contained, because what it guards against is a second adapter
        letting a sample bypass the redirect.
      </p>
    </section>
    """


def _sample_dns_queries(summary: dict[str, Any]) -> list[str]:
    """Names the sample resolved, as Sysmon saw them.

    Sysmon's indicator lists already exclude the analyzer's own lookups, so
    anything left here is the sample's.
    """
    sysmon = summary.get("sysmon_summary", {}) or {}
    return [q for q in (sysmon.get("dns_queries", []) or []) if q]


def _normalize_domain(name: object) -> str:
    return str(name or "").strip().lower().rstrip(".")


def _fakenet_domains(summary: dict[str, Any]) -> tuple[list[str], list[str]]:
    """FakeNet's served lookups, split into the sample's and the host's own.

    Once the guest had a default route, Windows started reaching the simulated
    internet on its own -- NCSI connectivity checks to msftconnecttest.com on
    every run. Rendered unsplit, and in an alert-styled card, that is a warning
    about Windows checking whether it has internet.
    """
    fakenet = summary.get("fakenet_summary", {}) or {}
    notable: list[str] = []
    baseline: list[str] = []
    for name in fakenet.get("dns_requests", []) or []:
        (baseline if is_baseline_domain(name) else notable).append(name)
    return notable, baseline


def _unserved_sample_domains(summary: dict[str, Any]) -> list[str]:
    """The sample's lookups that FakeNet did not answer.

    Compared name by name, not by whether FakeNet served anything at all. The
    first version asked the latter, and Windows' own connectivity checks made
    "FakeNet served something" true on every run the moment interception
    started working -- so the check would have gone quiet exactly when it began
    to matter.
    """
    fakenet = summary.get("fakenet_summary", {}) or {}
    served = {
        _normalize_domain(d) for d in (fakenet.get("dns_requests", []) or []) if d
    }
    return [
        q for q in _sample_dns_queries(summary) if _normalize_domain(q) not in served
    ]


def _unserved_dns_section(summary: dict[str, Any]) -> str:
    """Warn when the sample resolved a name the simulated internet never answered.

    FakeNet exists so a sample proceeds through its real logic instead of dying
    at its first lookup. When Sysmon records a query and FakeNet records none,
    the sample asked and got nothing -- so whatever it would have done with an
    answer never ran.

    From a real AgentTesla run: the sample resolved ftp.cyberflor.co, Sysmon
    logged it, FakeNet logged zero DNS requests, and the network sections of the
    report said nothing was attributable to the sample. Every one of those
    statements was locally true and the conclusion they invited was wrong.
    """
    if not summary.get("fakenet_enabled"):
        return ""

    fakenet = summary.get("fakenet_summary", {}) or {}
    if not fakenet.get("parsed"):
        return ""

    queries = _unserved_sample_domains(summary)
    if not queries:
        return ""

    return f"""
    <section class="card card-alert">
      <div class="section-head">
        <h2>Name Resolution Was Not Served</h2>
        {_section_badge("Unanswered", len(queries))}
      </div>
      <p class="muted">
        Sysmon recorded the sample resolving {_esc(len(queries))} name(s) that
        the simulated internet never answered -- FakeNet logged no DNS requests
        at all. The sample asked and got nothing back, so whatever it would have
        done with an answer did not run. Treat the absence of C2 traffic in this
        run as unobserved, not as absent.
      </p>
      <ul>{''.join(f'<li>{_esc(q)}</li>' for q in queries[:25])}</ul>
    </section>
    """


def _fakenet_dns_empty_text(summary: dict[str, Any]) -> str:
    """Empty-state wording for FakeNet's requested-domains list.

    The reassuring reading -- "expected for a sample that does not use the
    network" -- is only available when the sample did not in fact try.
    """
    if _unserved_sample_domains(summary):
        return (
            "Nothing the sample asked for reached the simulated internet, though "
            "Sysmon recorded it resolving. That is a gap in what was observed, "
            "not a quiet sample -- see the warning above."
        )
    return (
        "No domains were requested. With no default route the guest generates "
        "little background traffic, so this is expected for a sample that does "
        "not use the network."
    )


def _evidence_section(summary: dict[str, Any]) -> str:
    """The independent kinds of evidence the verdict was built from.

    The verdict used to be a band on a total, and the total could not separate
    a benign canary (24) from live AgentTesla (60) from packed mimikatz (69) --
    all three read Needs Review / Medium. It now comes from how many unrelated
    kinds of evidence agree, which is only a defensible answer if the reader
    can see which ones did.
    """
    detail = summary.get("score_detail", {}) or {}
    categories = detail.get("evidence_categories", []) or []
    if not detail:
        return ""

    rows = [
        {
            "evidence": _pretty_key(str(entry.get("name", ""))),
            "weight": "strong" if entry.get("strong") else "present",
            "observed": entry.get("detail", ""),
        }
        for entry in categories
    ]

    counts = detail.get("evidence_counts", {}) or {}
    empty_text = (
        "No decisive evidence category was observed. That means none was "
        "recorded, not that none occurred -- check telemetry coverage above "
        "before reading this as a clean result."
    )

    return f"""
    <section class="{'card card-alert' if rows else 'card'}">
      <div class="section-head">
        <h2>Evidence Behind The Verdict</h2>
        {_section_badge("Agreeing", _to_int(counts.get("categories_present", 0)))}
      </div>
      <p class="muted">
        The verdict comes from how many independent kinds of evidence agree,
        not from the score. One on its own is Needs Review; one strong, or two
        of any kind, is High. Activity volume is capped so background noise
        cannot move the band.
      </p>
      {_dict_list_table("Categories Observed", rows, empty_text=empty_text)}
    </section>
    """


def _crash_evidence_section(summary: dict[str, Any]) -> str:
    """Crashes in the sample's tree, and what they say about injection.

    A fault at an address with no module mapped there means code was executing
    in privately allocated memory. Formbook hollowed RegSvcs.exe and died
    inside its own injected region; Sysmon saw nothing, because Event 8 is
    CreateRemoteThread and hollowing does not use it.
    """
    crashes = summary.get("crash_summary", {}) or {}
    preflight = summary.get("crash_dump_preflight", {}) or {}
    dumps = summary.get("crash_dumps", {}) or {}
    if not crashes and not preflight:
        return ""

    counts = crashes.get("counts", {}) or {}
    unmapped = crashes.get("unmapped_memory_crashes", []) or []

    rows = [
        {
            "Process": entry.get("process", ""),
            "PID": entry.get("pid", ""),
            "Exception": entry.get("exception_code", ""),
            "Fault offset": entry.get("fault_offset", ""),
            "Image": entry.get("path", ""),
        }
        for entry in unmapped
    ]

    dump_note = ""
    if not preflight.get("available"):
        dump_note = f"<p class='muted'>{_esc(preflight.get('note', ''))}</p>"
    elif (dumps.get("counts", {}) or {}).get("dumps"):
        dump_note = (
            f"<p class='muted'>{_to_int((dumps.get('counts') or {}).get('dumps', 0))} "
            f"crash dump(s) collected into {_esc(dumps.get('output_dir', ''))} and "
            "scanned with the memory ruleset.</p>"
        )

    return f"""
    <section class="{'card card-alert' if rows else 'card'}">
      <div class="section-head">
        <h2>Crashes In The Sample's Tree</h2>
        {_section_badge("In unmapped memory", _to_int(counts.get("crashes_in_unmapped_memory", 0)))}
      </div>
      <p class="muted">
        A fault at an address where no module is mapped means the process was
        executing privately allocated memory -- injected code. Sysmon's
        injection event is CreateRemoteThread, which process hollowing does not
        use, so this is often the only record that it happened.
        {_to_int(counts.get("crashes", 0))} crash(es) in the sample's tree,
        {_to_int(counts.get("other_process_crashes_excluded", 0))} elsewhere on
        the host excluded.
      </p>
      {_dict_list_table("Executed From Unmapped Memory", rows, emphasize=True,
                        empty_text="No crash in the sample's tree faulted outside a loaded module.")}
      {dump_note}
    </section>
    """


def _dropped_files_section(summary: dict[str, Any]) -> str:
    """What the dropped-file count is actually made of.

    The report carried the counts and not the list, and `payload_dropped` can
    reach strong off that count. A Remcos run reported 13 suspicious drops of
    which 11 did not exist -- a process walking the DLL search order in its own
    directory -- and nothing on the page said so.

    ``On disk`` is the column that would have shown it, which is why it is here
    rather than in the JSON only.
    """
    files = summary.get("dropped_files", []) or []
    if not files:
        return ""

    rows = [
        {
            "Path": entry.get("path", ""),
            "Kind": entry.get("classification", ""),
            "On disk": "yes" if entry.get("exists_on_disk") else "no",
            "Size": entry.get("size") if entry.get("size") is not None else "",
            "Written by": entry.get("source_process_name", ""),
            "SHA256": (entry.get("sha256") or "")[:16],
        }
        for entry in files
        if isinstance(entry, dict) and entry.get("suspicious")
    ]

    return _dict_list_table(
        "Suspicious Dropped Files",
        rows,
        emphasize=True,
        limit=50,
        empty_text="No dropped file triaged as suspicious.",
    )


def _unmapped_pe_section(summary: dict[str, Any]) -> str:
    """Executables found in memory that the process's loader never mapped.

    The structural counterpart to the YARA pass, and independent of it: a rule
    has to have been written for the family, while a module list is the
    process's own record of what Windows put there. The 05 Aug payload matched
    nothing in the ruleset -- an obfuscated managed assembly with no plaintext
    indicators at all -- and was conclusive from its headers.

    The two timestamps are shown side by side because that pairing is the
    finding: an image years newer than the process hosting it did not ship with
    it.
    """
    carve = summary.get("pe_carve_summary", {}) or {}
    if not carve.get("carved"):
        return ""

    counts = carve.get("counts", {}) or {}
    images = carve.get("images", []) or []
    unmapped = [i for i in images if i.get("classification") == "unmapped"]

    rows = [
        {
            "Process": image.get("process", ""),
            "PID": image.get("pid", ""),
            "Address": image.get("virtual_address", ""),
            "Size": image.get("size_of_image", 0),
            "Arch": ("{} .NET".format(image.get("machine", ""))
                     if image.get("dotnet") else image.get("machine", "")),
            "Compiled": image.get("compiled", ""),
            # Rendered as a comparison because that is what the finding is. One
            # side as a date and the other as hex leaves the reader converting
            # between them to see the thing they are meant to see.
            "Timestamp vs host": (
                f"{image.get('timestamp_hex', '')} vs "
                f"{image.get('host_image_timestamp_hex', '') or '?'}"
            ),
            "Carved": image.get("carved_file", "") or image.get("error", ""),
            "From": image.get("dump_file", ""),
        }
        for image in unmapped
    ]

    inside = _to_int(counts.get("inside_module_images", 0))
    inside_note = (
        f"<p class='muted'>{inside} further PE image(s) sat inside a module's "
        "range but not at its base. Ordinary loaders produce that occasionally "
        "-- an executable held in a resource section -- so they are recorded "
        "and not treated as evidence.</p>"
        if inside
        else ""
    )

    known_modules = _to_int(counts.get("known_module_images", 0))
    known_note = (
        f"<p class='muted'>{known_modules} further unmapped PE image(s) were "
        "system DLLs that another dump in this run enumerated as loaded modules. "
        "A process created suspended -- which is what hollowing does -- has "
        "ntdll mapped before its module list is populated, so the DLL is really "
        "there and really absent from that dump's list. Matched on build rather "
        "than on name.</p>"
        if known_modules
        else ""
    )

    resource_only = _to_int(counts.get("resource_only_images", 0))
    resource_note = (
        f"<p class='muted'>{resource_only} further unmapped PE image(s) carried "
        "no code at all and were set aside. Windows maps localised resource "
        "files as data without registering them with the loader, so every "
        "process on the machine holds a handful; an image with nothing "
        "executable in it is not a payload.</p>"
        if resource_only
        else ""
    )

    failures = _to_int(counts.get("dumps_failed", 0))
    failure_note = (
        f"<p class='muted'>{failures} dump(s) could not be parsed and were not "
        "searched. A dump written without memory (DumpType=1) carries metadata "
        "only.</p>"
        if failures
        else ""
    )

    return f"""
    <section class="{'card card-alert' if rows else 'card'}">
      <div class="section-head">
        <h2>Executables The Loader Never Mapped</h2>
        {_section_badge("Unmapped PE images", _to_int(counts.get("unmapped_images", 0)))}
      </div>
      <p class="muted">
        Every dump carries the process's own module list: what Windows mapped,
        and where. A PE header at an address no module covers was put there by
        something else, which is what process hollowing and reflective loading
        leave behind. This needs no signature, so it works on a payload no rule
        matches. {_to_int(counts.get("dumps_analyzed", 0))} dump(s) searched,
        {_to_int(counts.get("carved", 0))} image(s) written out for analysis.
      </p>
      {_dict_list_table("Unmapped PE Images", rows, emphasize=True,
                        empty_text="No PE image was found outside the mapped modules.")}
      {known_note}
      {resource_note}
      {inside_note}
      {_carve_per_dump_table(carve)}
      {failure_note}
    </section>
    """


def _carve_per_dump_table(carve: dict[str, Any]) -> str:
    """Which dump each set-aside image was in, dump by dump.

    The run totals cannot answer the question they get asked. A run reporting
    `unmapped: 0` on every image of a hollowed process and nine known-module
    images *somewhere* leaves "was a payload suppressed in that process, or was
    there no payload" arguable from the design and unreadable from the report --
    and on 06 Aug that argument decided whether a whole gap's premise was wrong.

    Only dumps that had something set aside are listed. A dump with nothing in
    any column says nothing worth a row, and eleven rows of zeroes would bury
    the two that matter.
    """
    per_dump = carve.get("per_dump", []) or []
    interesting_columns = ("unmapped", "known_module", "resource_only", "inside_module", "rejected")

    listed = [
        d for d in per_dump
        if any(_to_int(d.get(column, 0)) for column in interesting_columns) or d.get("error")
    ]
    if not listed:
        return ""

    rows = [
        {
            "Dump": d.get("file", ""),
            "Process": f"{d.get('process_name', '')} (pid {d.get('pid')})",
            "Trigger": d.get("trigger", ""),
            "Modules": d.get("modules", 0),
            "Regions": d.get("regions", 0),
            "Unmapped": d.get("unmapped", 0),
            "Known module": d.get("known_module", 0),
            "Resource only": d.get("resource_only", 0),
            "Inside module": d.get("inside_module", 0),
            "Rejected": d.get("rejected", 0),
            "Error": d.get("error", ""),
        }
        for d in listed
    ]

    quiet = len(per_dump) - len(listed)
    quiet_note = (
        f"<p class='muted'>{quiet} further dump(s) had nothing set aside in any "
        "category.</p>"
        if quiet > 0
        else ""
    )

    return f"""
      {_dict_list_table("What Each Dump Held", rows)}
      <p class="muted">
        Read the <b>Known module</b> column against a process the loader hollows.
        A system DLL a suspended process has not enumerated yet is set aside
        there legitimately; a payload-sized image would not be, and the run total
        alone cannot tell you which dump either was in.
      </p>
      {quiet_note}
    """


def _observation_window_section(summary: dict[str, Any]) -> str:
    """Warn when the run stopped watching a sample that had not yet acted.

    The window was fixed at 180 seconds while the same AgentTesla binary sat
    dormant for between 21 and 83 seconds across six runs. Nothing said what
    would happen at 200. A sample that sleeps out the window produces a report
    identical to one that ran and did nothing -- and the second reading is the
    one an analyst reaches for.

    Silent when the window closed on a sample that had exited or had already
    been seen to act: those runs observed what there was to observe.
    """
    observation = summary.get("observation", {}) or {}
    ended_because = str(observation.get("ended_because", "") or "")
    if ended_because != "extension_cap_reached":
        return ""

    elapsed = _to_int(observation.get("elapsed_seconds", 0))
    base = _to_int(observation.get("base_window_seconds", 0))
    cap = _to_int(observation.get("max_observation_seconds", 0))
    extensions = _to_int(observation.get("extensions", 0))

    return f"""
    <section class="card card-alert">
      <div class="section-head">
        <h2>Observation May Be Incomplete</h2>
        {_section_badge("Observed for", f"{elapsed}s")}
      </div>
      <p class="muted">
        The sample was still running and had not been seen to spawn anything
        when observation stopped at the {cap}s cap
        (base window {base}s, extended {extensions} time(s)). Everything below
        describes a sample that may simply not have started yet: a dormancy
        longer than the cap, a sandbox-evasion sleep, or a wait on something the
        contained guest never provided. Treat an empty result here as
        unobserved rather than clean, and re-run with a longer
        <code>max_observation_seconds</code> before concluding anything.
      </p>
    </section>
    """


def _abnormal_termination_section(summary: dict[str, Any]) -> str:
    """Warn when the sample's chain ended by crash rather than by clean exit.

    Gap 4. From outside the guest a sample that detects analysis and bails is
    indistinguishable from one whose payload is broken -- both leave a crashed
    process and an otherwise quiet run. The pipeline cannot tell them apart, so
    this does not score; it exists so a crashed chain is never read as a clean
    one.

    Silent when nothing in the sample's tree crashed.
    """
    abn = summary.get("abnormal_termination", {}) or {}
    if not abn.get("chain_crashed"):
        return ""

    crashed = abn.get("crashed_processes", []) or []
    witnesses = abn.get("werfault_witnesses", []) or []

    who = ", ".join(
        f"{c.get('process') or '?'} (pid {c.get('pid')})" for c in crashed[:6]
    )
    if not who and witnesses:
        who = ", ".join(f"pid {w.get('crashed_pid')}" for w in witnesses[:6])

    werfault_note = ""
    if abn.get("witnessed_only_by_werfault"):
        werfault_note = (
            "<p class='muted'>Seen only through WerFault, with no Application "
            "Error event to accompany it -- the crash is real but the event log "
            "did not record it, which some Windows builds do.</p>"
        )

    return f"""
    <section class="card card-alert">
      <div class="section-head">
        <h2>Chain Terminated By Crash — Result May Be Inconclusive</h2>
        {_section_badge("Crashed", _to_int(abn.get("event_crashes", 0)) or len(witnesses))}
      </div>
      <p class="muted">
        A process in the sample's tree terminated by crash{f': {_esc(who)}' if who else ''}.
        From outside the guest a deliberate anti-analysis bail is
        indistinguishable from a broken payload -- both leave a crashed process
        and an otherwise quiet run, and the pipeline cannot tell which happened.
        Where this run is otherwise empty, read it as <b>inconclusive rather
        than clean</b>: the sample may have detected the environment and left.
      </p>
      {werfault_note}
    </section>
    """


def _vm_artifact_reads_section(summary: dict[str, Any]) -> str:
    """What the sample read about the machine it was running on.

    Gap 4's second half, and collection only. A sample that enumerates the
    hypervisor and then goes quiet is the case the chain-crashed warning cannot
    reach, and until this pass existed nothing recorded the enumeration at all --
    the Procmon filter dropped every registry read at capture time.

    Not scored, and the wording is careful about why: ordinary software reads
    hardware identity. `SystemBiosVersion` is where a VM check looks for "VBOX"
    and also where an inventory agent looks for a BIOS version. What earns its
    place in a report is the pairing with a quiet run.

    Renders even when nothing was found, unlike most sections here, because the
    two zeroes mean opposite things: no artifacts read on a run that collected
    reads is a statement about the sample, and the same zero on a run that
    collected none is a statement about the config.
    """
    reads = summary.get("vm_artifact_reads", {}) or {}
    if not reads:
        return ""

    counts = reads.get("counts", {}) or {}
    hits = reads.get("hits", []) or []
    available = bool(reads.get("collection_available"))

    if not available:
        # Naming the config that ran is what makes this self-diagnosing. The
        # 06 Aug 21:15 run reported exactly this card, and "the field was on the
        # default" and "the generated config was ignored by Procmon" were
        # indistinguishable from the report -- two very different problems.
        procmon_filter = summary.get("procmon_filter", {}) or {}
        config_note = ""
        if procmon_filter.get("config_path"):
            config_note = (
                f"<p class='muted'>Filter in force: "
                f"<code>{_esc(procmon_filter.get('config_path', ''))}</code> — "
                f"{_esc(procmon_filter.get('note', ''))}</p>"
            )
        return f"""
    <section class="card">
      <div class="section-head">
        <h2>Registry Reads — Not Collected</h2>
        {_section_badge("VM artifact reads", "n/a")}
      </div>
      <p class="muted">{_esc(reads.get("note", ""))}</p>
      {config_note}
    </section>
    """

    rows = [
        {
            "Time": hit.get("timestamp", ""),
            "Process": f"{hit.get('process_name', '')} (pid {hit.get('pid')})",
            "Operation": hit.get("operation", ""),
            "Artifact": hit.get("artifact", ""),
            "Family": hit.get("family", ""),
            "Only on a VM": "yes" if hit.get("specificity") == "vm_specific" else "no",
            # The result is half the finding. SUCCESS on a guest-additions key
            # means the sample was told it is in a VM; NAME NOT FOUND means the
            # guest's hygiene held and the check came back clean.
            "Artifact present": (
                "yes"
                if hit.get("artifact_found") is True
                else "no" if hit.get("artifact_found") is False else "?"
            ),
            "Result": hit.get("result", ""),
            "Path": hit.get("path", ""),
        }
        for hit in hits
    ]

    background = _to_int(counts.get("background_artifact_reads", 0))
    background_note = (
        f"<p class='muted'>{background} read(s) of the same artifacts came from "
        "processes outside the sample's tree and are not listed. Windows reads "
        "most of these keys itself -- the Service Control Manager enumerates "
        "every service key, including the guest additions' -- which is why this "
        "pass is attributed by lineage and why the count is shown rather than "
        "dropped.</p>"
        if background
        else ""
    )

    lineage_note = (
        "<p class='muted'>The sample's process tree could not be resolved, so "
        "every process on the machine was counted. Read the rows above as "
        "unattributed rather than as the sample's.</p>"
        if not reads.get("lineage_resolved")
        else ""
    )

    # Inside the tree, and still not the sample's behaviour. Counted because the
    # 07 Aug 14:53 run reported nine artifacts read and every one was Windows:
    # five WerFault collecting crash-report identity, four PowerShell walking a
    # network-provider registration that happens to live under a VBox key.
    wer = _to_int(counts.get("windows_response_reads", 0))
    routine = _to_int(counts.get("routine_subpath_reads", 0))
    suppressed_note = ""
    if wer or routine:
        parts = []
        if wer:
            parts.append(
                f"{wer} read(s) came from Windows Error Reporting, which the sample's "
                "crash brought into the tree — WER collects machine identity for its "
                "report, so those are Windows reacting to the sample rather than the "
                "sample acting"
            )
        if routine:
            parts.append(
                f"{routine} read(s) were of a VM-specific key that Windows enumerates "
                "itself, such as the VBoxSF network-provider registration that any UNC "
                "path lookup walks"
            )
        suppressed_note = f"<p class='muted'>{'; and '.join(parts)}. Both are set aside and counted.</p>"

    return f"""
    <section class="{'card card-alert' if counts.get('vm_specific') else 'card'}">
      <div class="section-head">
        <h2>Virtual-Machine Artifacts The Sample Read</h2>
        {_section_badge("Artifacts read", _to_int(counts.get("artifacts_read", 0)))}
      </div>
      <p class="muted">
        {_esc(reads.get("note", ""))}
        {_to_int(reads.get("sample_reads", 0))} registry read(s) by the sample's
        own processes were examined, out of
        {_to_int(reads.get("reads_in_stream", 0))} captured in the run.
      </p>
      {_dict_list_table("VM Artifact Reads", rows, emphasize=bool(counts.get("vm_specific")),
                        empty_text="The sample's processes read none of the known VM artifacts.")}
      {background_note}
      {suppressed_note}
      {lineage_note}
    </section>
    """


def _fakenet_received_section(summary: dict[str, Any]) -> str:
    """Files the sample uploaded to the simulated internet.

    Emphasised because it is the strongest artifact a run can produce: not
    evidence that the sample exfiltrated, but the exfiltrated data itself.
    """
    fakenet = summary.get("fakenet_summary", {}) or {}
    received = fakenet.get("received_files", {}) or {}
    if not received:
        return ""

    files = received.get("files", []) or []
    rows = [
        {
            "File": entry.get("name", ""),
            "Size": entry.get("size", 0),
            "State": (
                "overwrote a served file"
                if entry.get("state") == "overwritten"
                else "new"
            ),
            "SHA256": entry.get("sha256", "") or "not hashed",
            "Collected to": entry.get("saved_as", "") or entry.get("error", "not collected"),
            "Uploaded to": entry.get("source_path", ""),
        }
        for entry in files
    ]

    if received.get("collected"):
        empty_text = received.get("note") or "Nothing was uploaded to the simulated internet."
    else:
        empty_text = received.get("note") or (
            "Uploads were not collected for this run, so a file the sample sent "
            "would not appear here."
        )

    return _dict_list_table(
        "Files Received By The Simulated Internet",
        rows,
        emphasize=True,
        empty_text=empty_text,
    )


def _containment_section(summary: dict[str, Any]) -> str:
    """Warn prominently when the sample could have bypassed the simulated internet.

    Whoever reads the report is often not whoever ran it, so a containment
    failure has to travel with the results rather than living only in the log.
    """
    isolation = summary.get("network_isolation", {}) or {}
    if not isolation or isolation.get("level") == "ok":
        return ""

    rows = [
        {
            "adapter": path.get("adapter", ""),
            "interface_ip": path.get("interface_ip", ""),
            "gateway": path.get("gateway", ""),
            "private": path.get("private", ""),
        }
        for path in (isolation.get("egress", []) or [])
    ]

    return f"""
    <section class="card card-alert">
      <div class="section-head">
        <h2>Containment Warning</h2>
        {badge("Egress paths", isolation.get("egress_count", 0))}
      </div>
      <p>{_esc(isolation.get("note", ""))}</p>
      <p class="muted">
        Network indicators below may reflect traffic that reached real
        infrastructure rather than the simulated internet.
      </p>
      {_dict_list_table("Egress Paths", rows)}
    </section>
    """


def _memory_dump_rows(memory: dict[str, Any]) -> list[dict[str, Any]]:
    """Dump rows trimmed for display.

    The full dump path repeats the same long case directory on every row and
    pushes the table into horizontal scrolling for no benefit -- the filename is
    the part an analyst carries over to a scanner. The complete path stays in
    memory_dumps.json.

    ``suspended`` becomes a "Capture" column in words. It is the field that says
    how far the image can be trusted, and a bare "False" states the mechanism
    while hiding the consequence -- the reader has to already know that an
    unfrozen dump is a smear to see that the row is qualified.

    Only rewritten when the key is actually present. A memory_dumps.json written
    before dumps were suspended has no such field, and defaulting it would print
    a confident "Live (smeared)" about a capture whose state was never recorded.
    """
    rows: list[dict[str, Any]] = []
    for dump in memory.get("dumps", []) or []:
        capture = (
            ("Frozen" if dump.get("suspended") else "Live (smeared)")
            if "suspended" in dump
            else ""
        )

        # Every other key is passed through untouched, so a field added to the
        # dump record later shows up in the table without a change here.
        row: dict[str, Any] = {}
        for key, value in dump.items():
            if key in ("path", "suspended"):
                continue
            row[key] = value
            # Placed next to the trigger rather than at the end: the two
            # together are how the image was captured, and separating them by
            # size and hash buries the one that qualifies the result.
            if key == "trigger" and capture:
                row["capture"] = capture

        if capture and "capture" not in row:
            row["capture"] = capture
        row["file"] = Path(str(dump.get("path", ""))).name
        rows.append(row)
    return rows


def _smeared_dumps(memory: dict[str, Any]) -> list[dict[str, Any]]:
    """Successful dumps that were read while the process kept running."""
    return [
        dump
        for dump in (memory.get("dumps", []) or [])
        if "suspended" in dump and not dump.get("suspended")
    ]


def _memory_skipped_rows(memory: dict[str, Any]) -> list[dict[str, Any]]:
    """Skipped-dump records, trimmed for display."""
    return [
        {
            "PID": entry.get("pid", ""),
            "Process": entry.get("name", "") or "?",
            "At": f"+{_to_int(entry.get('offset_seconds', 0))}s",
            "Reason": entry.get("reason", ""),
        }
        for entry in (memory.get("skipped", []) or [])
        if isinstance(entry, dict)
    ]


def _memory_sections(summary: dict[str, Any]) -> str:
    """Which process images were captured, and what remains scannable.

    Until the YARA pass lands these dumps carry no verdict of their own, so the
    section describes coverage: what was dumped, what was skipped, and why.
    Reporting a skipped process is the point -- a dump that never happened is
    otherwise indistinguishable from one that found nothing.
    """
    memory = summary.get("memory_summary", {}) or {}
    if not memory:
        return ""

    counts = memory.get("counts", {}) or {}
    preflight = summary.get("memory_preflight", {}) or {}

    if not counts.get("dumps_attempted"):
        if not summary.get("memory_dump_enabled"):
            return ""
        note = preflight.get("note", "") or (
            "No process from the sample tree was alive when a dump was due. "
            "Short-lived samples exit before the configured offset; lower it, "
            "or use the deep profile, which dumps earlier."
        )
        # The skipped list is the whole explanation for a run with no dumps, and
        # this branch used to drop it and print the preflight note instead --
        # "ProcDump is available; process memory will be dumped during the run",
        # about a run in which nothing was. The record existed in the JSON and
        # appeared nowhere a reader would look.
        skipped = _dict_list_table(
            "Why No Dump Was Taken",
            _memory_skipped_rows(memory),
            emphasize=True,
            empty_text="No reason was recorded, which is itself unexpected.",
        )
        return f"""
    <section class="card">
      <div class="section-head">
        <h2>Process Memory</h2>
        {_section_badge("Dumps", 0)}
      </div>
      <p class="muted">{_esc(note)}</p>
      {skipped}
    </section>
    """

    sections = [
        _kv_table(
            "Process Memory Dumps",
            {
                "Processes observed": counts.get("processes_observed", 0),
                "Dumps attempted": counts.get("dumps_attempted", 0),
                "Dumps succeeded": counts.get("dumps_succeeded", 0),
                "Dumps skipped": counts.get("dumps_skipped", 0),
                "Total size (MB)": counts.get("total_mb", 0),
                "Dump offsets (s)": ", ".join(
                    str(o) for o in (summary.get("memory_dump_offsets", []) or [])
                ),
                # A run that collected no re-dumps reads differently at 10s than
                # at 0, so the delay belongs next to the offsets rather than
                # only in the JSON.
                "Child re-dump (s)": (
                    summary.get("memory_dump_spawn_redump_seconds", 0) or "off"
                ),
            },
            _section_badge("Written", counts.get("dumps_succeeded", 0)),
        ),
        _dict_list_table("Captured Process Images", _memory_dump_rows(memory)),
    ]

    # A smeared image is not a failure, so it does not belong in "Failed Dumps",
    # but it does change how a result from it should be read -- and that is
    # invisible if the only trace is one word in one column of a wide table.
    smeared = _smeared_dumps(memory)
    if smeared:
        sections.append(f"""
    <section class="card">
      <div class="section-head">
        <h2>Images Captured While Running</h2>
        {_section_badge("Dumps", len(smeared))}
      </div>
      <p class="muted">
        {_esc(len(smeared))} of {_esc(counts.get("dumps_succeeded", 0))} dump(s)
        were read while the process kept running, because it could not be
        suspended -- typically access denied on a protected process, or it
        exited between being noticed and being frozen. ProcDump reads such a
        process over hundreds of megabytes while it is still writing, so the
        image is not a snapshot of a single instant and may be internally
        inconsistent. Treat a YARA miss against one of these as weaker evidence
        than a miss against a frozen image.
      </p>
    </section>
    """)

    # Sysmon saw the whole tree; the watcher saw what it could catch at two
    # polls a second. Anything in the gap ran and was never examined.
    missed = memory.get("missed_descendants", []) or []
    if missed:
        rows = [
            {
                "pid": record.get("pid"),
                "image": record.get("image", ""),
                "parent_pid": record.get("parent_pid"),
                "first_seen": record.get("timestamp", ""),
            }
            for record in missed
        ]
        sections.append(f"""
    <section class="card card-alert">
      <div class="section-head">
        <h2>Descended From The Sample But Never Dumped</h2>
        {_section_badge("Processes", len(rows))}
      </div>
      <p class="muted">
        Sysmon recorded these as descendants of the sample. The dump watcher
        polls the process tree twice a second, so a process has to outlive one
        interval to be seen at all -- these did not, and no memory of them was
        captured. Shortening the interval only moves the threshold; a process
        that lives milliseconds cannot be dumped by anything that polls.
      </p>
      <p class="muted">
        Worth reading rather than ignoring. A payload staged into a process
        this short-lived leaves no dump and no YARA result, so the run's memory
        evidence is silent about whatever ran here. The command line below is
        Sysmon's, and it is the only record of it.
      </p>
      {_dict_list_table("Missed Descendants", rows)}
    </section>
    """)

    if memory.get("skipped"):
        sections.append(
            _dict_list_table("Processes Not Dumped", _memory_skipped_rows(memory))
        )

    if memory.get("failures"):
        sections.append(
            _dict_list_table(
                "Failed Dumps", memory.get("failures", []) or [], emphasize=True
            )
        )

    sections.append(_memory_yara_sections(summary))
    return "\n".join(section for section in sections if section)


def _memory_yara_sections(summary: dict[str, Any]) -> str:
    """YARA results over the dumps, led by the memory-versus-disk difference."""
    scan = summary.get("memory_yara_summary", {}) or {}

    if not scan.get("scanned"):
        if not summary.get("memory_yara_enabled"):
            return ""
        preflight = summary.get("memory_yara_preflight", {}) or {}
        note = scan.get("error") or preflight.get("note", "")
        if not note:
            return ""
        return f"""
    <section class="card">
      <div class="section-head">
        <h2>Memory YARA</h2>
        {_section_badge("Scanned", 0)}
      </div>
      <p class="muted">{_esc(note)}</p>
      <p class="muted">
        The dumps were kept and can be scanned manually.
      </p>
    </section>
    """

    counts = scan.get("counts", {}) or {}
    memory_only = scan.get("memory_only_rules", []) or []

    sections = []

    # Led with, and flagged, because it is the finding the whole tier exists to
    # produce: a rule that fires against memory and not against the file means
    # the payload was packed or encrypted at rest.
    if memory_only:
        sections.append(f"""
    <section class="card card-alert">
      <div class="section-head">
        <h2>Matched In Memory But Not On Disk</h2>
        {_section_badge("Rules", len(memory_only))}
      </div>
      <p>
        These rules matched a process's memory while the sample on disk did not
        match them. That difference is a payload that was packed, encrypted or
        downloaded, and became readable only once the process was running.
      </p>
      <ul>{''.join(f'<li>{_esc(rule)}</li>' for rule in memory_only)}</ul>
    </section>
    """)

    sections.append(
        _kv_table(
            "Memory YARA Summary",
            {
                "Dumps scanned": counts.get("dumps_scanned", 0),
                "Dumps with matches": counts.get("dumps_with_matches", 0),
                "Dumps failed to scan": counts.get("dumps_failed", 0),
                "Total matches": counts.get("total_matches", 0),
                "Distinct rules in memory": counts.get("memory_rules", 0),
                "Distinct rules on disk": counts.get("disk_rules", 0),
                "Rules only in memory": counts.get("memory_only_rules", 0),
                "Rule files": scan.get("rule_file_count", 0),
            },
            _section_badge("Memory-only", len(memory_only)),
        )
    )

    sections.append(_dict_list_table("Per-Dump YARA Results", scan.get("per_dump", []) or []))

    if scan.get("disk_rules"):
        sections.append(
            _list_section(
                "Rules Also Matching The Sample On Disk",
                list(scan.get("disk_rules", []) or []),
                empty_text="None",
            )
        )

    if scan.get("note"):
        sections.append(f"""
    <section class="card">
      <div class="section-head"><h2>Reading These Results</h2></div>
      <p class="muted">{_esc(scan["note"])}</p>
    </section>
    """)

    return "\n".join(sections)


def _sysmon_sections(summary: dict[str, Any]) -> str:
    """Sysmon findings: the behaviours Procmon cannot observe."""
    sysmon = summary.get("sysmon_summary", {}) or {}
    if not sysmon:
        return ""

    # An empty collection is a gap in coverage, not a clean result. Say why,
    # and say what it means, rather than showing a wall of zeroes.
    collection = summary.get("sysmon_collection", {}) or {}
    if int(sysmon.get("total_events", 0) or 0) == 0:
        reason = collection.get("diagnosis") or collection.get("error") or (
            "No events were returned for this run's time window."
        )
        return f"""
    <section class="card card-alert">
      <div class="section-head">
        <h2>Sysmon: No Telemetry Collected</h2>
        {_section_badge("Events", 0)}
      </div>
      <p>{_esc(reason)}</p>
      <p class="muted">
        Process injection, credential access and WMI persistence are only
        visible through Sysmon. Their absence from this report reflects missing
        telemetry, not evidence that the sample avoided them.
      </p>
    </section>
    """

    highlights = sysmon.get("highlights", []) or []
    counts = sysmon.get("counts", {}) or {}

    overview = {
        "Total events": sysmon.get("total_events", 0),
        "High severity": sysmon.get("high_severity_count", 0),
        "Injection events": len(sysmon.get("injection_events", []) or []),
        "DNS queries": len(sysmon.get("dns_queries", []) or []),
        "Named pipes": len(sysmon.get("named_pipes", []) or []),
        # Reported rather than hidden, matching the autoruns diff: a reader
        # should be able to tell the difference between "the tooling produced no
        # noise" and "the noise was filtered". The events figure covers the
        # indicator lists too, of which the highlights are a subset.
        "Analyzer events excluded": sysmon.get("analyzer_events_excluded", 0),
        "Analyzer highlights excluded": sysmon.get("analyzer_highlights_excluded", 0),
        # Windows acting on itself -- dwm.exe injecting into csrss.exe being the
        # recurring one. Counted here for the same reason as the analyzer rows.
        "Windows baseline events excluded": sysmon.get("os_baseline_events_excluded", 0),
        # Lookups by software that was running anyway -- Office and OneDrive
        # resolving their own endpoints. Counted for the same reason.
        "Noise-process lookups excluded": sysmon.get("noise_dns_excluded", 0),
        # Events by processes outside the sample's tree. The row that would have
        # shown the dwm.exe injection for what it was before it took a verdict
        # from Elevated Attention to Likely Malicious.
        "Other-process events excluded": sysmon.get("other_process_events_excluded", 0),
        # And which kind of zero the row above is: with lineage unresolved every
        # event in the window is counted and the attribution is unproven.
        "Lineage resolved": sysmon.get("lineage_resolved", ""),
    }

    injections = [
        {"source": entry.get("source", ""), "target": entry.get("target", "")}
        for entry in (sysmon.get("injection_events", []) or [])
    ]

    return f"""
<div class="grid">
  {_kv_table("Sysmon Overview", overview, badge("High", sysmon.get("high_severity_count", 0)))}
  {_kv_table("Sysmon Event Counts", counts)}
</div>

{_dict_list_table("Sysmon Highlights", highlights)}
{_dict_list_table("Process Injection (CreateRemoteThread)", injections)}
{_sysmon_other_process_section(sysmon)}
{_crash_evidence_section(summary)}
{_list_section("Sysmon DNS Queries", sysmon.get("dns_queries", []) or [], empty_text="No DNS queries were recorded by Sysmon.")}
{_list_section("Named Pipes", sysmon.get("named_pipes", []) or [], empty_text="No named pipes were recorded.")}
"""


def _sysmon_other_process_section(sysmon: dict[str, Any]) -> str:
    """High-signal Sysmon events that belonged to something other than the sample.

    Listed rather than dropped, and listed *separately*, because the two readings
    are different findings. Windows compositing the screen raised a
    `CreateRemoteThread` on 07 Aug that Sysmon could not resolve a target for; it
    became the run's only high-severity highlight and moved the verdict a band.
    Attributed by lineage now, and shown here so the event is still findable --
    "Sysmon saw nothing" and "Sysmon saw it and it was somebody else's" must not
    look the same.
    """
    listed = sysmon.get("other_process_highlights", []) or []
    if not listed:
        return ""

    rows = [
        {
            "Severity": entry.get("severity", ""),
            "Event": entry.get("event_id", ""),
            "Title": entry.get("title", ""),
            "Acting PID": entry.get("actor_pid", ""),
            "Detail": entry.get("detail", ""),
        }
        for entry in listed
    ]

    return f"""
    <section class="card">
      <div class="section-head">
        <h2>Sysmon Events From Other Processes</h2>
        {_section_badge("Not the sample's", len(listed))}
      </div>
      <p class="muted">
        Real events, raised by processes outside the sample's tree, and therefore
        not evidence about this sample. Kept visible because a filtered event and
        an event that never happened must not read alike — and because one of
        these once carried a whole category on its own.
      </p>
      {_dict_list_table("Other-Process Events", rows)}
    </section>
    """


def _network_sections(summary: dict[str, Any]) -> str:
    """Packet capture and simulated-internet findings."""
    network = summary.get("network_summary", {}) or {}
    fakenet = summary.get("fakenet_summary", {}) or {}
    iocs = summary.get("network_iocs", {}) or {}

    if not network and not fakenet:
        return ""

    blocks = []

    if network:
        capture = network.get("capture", {}) or {}
        overview = {
            "Parsed": network.get("parsed", False),
            "Backend": capture.get("backend", ""),
            "Capture size (bytes)": capture.get("pcap_bytes", 0),
            **(network.get("counts", {}) or {}),
        }
        if network.get("note"):
            overview["Note"] = network["note"]

        blocks.append(
            f"""
<div class="grid">
  {_kv_table("Packet Capture", overview, badge("Unusual ports", (network.get("counts", {}) or {}).get("unusual_ports", 0)))}
  {_kv_table("Network Indicators", {
      "Domains (notable)": len(iocs.get("notable_domains", []) or []),
      "Domains (Windows baseline)": len(iocs.get("baseline_domains", []) or []),
      "Domains (local discovery)": len(iocs.get("local_discovery_domains", []) or []),
      "External IP addresses": len(iocs.get("external_ips", []) or []),
      "Non-routable addresses": len(iocs.get("non_routable_ips", []) or []),
      "URLs (notable)": len(iocs.get("notable_urls", []) or []),
      "URLs (total)": len(iocs.get("urls", []) or []),
  }, badge("Notable", len(iocs.get("notable_domains", []) or [])))}
</div>

{_list_section("Resolved Domains (excluding Windows baseline)", iocs.get("notable_domains", []) or [], emphasize=True, empty_text="Only routine Windows background traffic was resolved. Nothing here is attributable to the sample.")}
{_list_section("Requested URLs (excluding Windows baseline)", iocs.get("notable_urls", []) or [], emphasize=True, empty_text="No notable plaintext URLs were observed.")}
{_list_section("Contacted External IP Addresses", iocs.get("external_ips", []) or [], empty_text="No external IP addresses were contacted.")}
{_list_section("Windows Baseline Traffic (context, not findings)", iocs.get("baseline_domains", []) or [], empty_text="No Windows background traffic was recorded.", context=True)}
{_list_section("Local Network Discovery (context, not findings)", iocs.get("local_discovery_domains", []) or [], empty_text="No mDNS or local name lookups were recorded.", context=True)}
{_list_section("Non-Routable Addresses (context, not findings)", iocs.get("non_routable_ips", []) or [], empty_text="No multicast or broadcast traffic was recorded.", context=True)}
{_list_section("TLS Server Names (SNI)", network.get("tls_sni", []) or [], empty_text="No TLS SNI values were observed.")}
{_dict_list_table("HTTP Requests", network.get("http_requests", []) or [])}
{_dict_list_table("Connections On Unusual Ports", network.get("unusual_ports", []) or [])}
"""
        )

    if fakenet:
        counts = fakenet.get("counts", {}) or {}
        overview = {"Parsed": fakenet.get("parsed", False), **counts}
        if fakenet.get("dns_adapter"):
            overview["Adapter redirected"] = fakenet["dns_adapter"]
            overview["DNS server set to"] = fakenet.get("dns_server", "")

        blocks.append(
            f"""
{_fakenet_cannot_intercept_section(summary)}
{_unserved_dns_section(summary)}
{_kv_table("Simulated Internet (FakeNet-NG)", overview)}
{_fakenet_received_section(summary)}
{_dict_list_table("Connection Attempts By Process", fakenet.get("process_requests", []) or [])}
{_list_section("Domains Requested Against Simulated Internet", _fakenet_domains(summary)[0], emphasize=True, empty_text=_fakenet_dns_empty_text(summary))}
{_list_section("Windows Baseline Traffic Served (context, not findings)", _fakenet_domains(summary)[1], empty_text="None.", context=True)}
{_dict_list_table("Requests Served", fakenet.get("http_requests", []) or [])}
{_list_section("Listeners Configured", fakenet.get("listeners_configured", []) or [], empty_text="No listeners were configured.", context=True)}
"""
        )

    return "\n".join(blocks)


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

def _installer_context_notes(summary: dict[str, Any]) -> list[str]:
    """
    Add analyst-friendly context for behavior that is common in legitimate
    installers but still worth review.

    This does not suppress findings. It explains why the final verdict may be
    Needs Review instead of High.
    """
    sample = summary.get("sample", {}) or {}
    sample_name = str(sample.get("sample_name", "") or "").lower()

    findings = summary.get("findings", {}) or {}
    counts = findings.get("counts", {}) or {}

    task_diff = summary.get("task_diff_summary", {}) or {}
    service_diff = summary.get("service_diff_summary", {}) or {}
    autoruns = _autoruns_counts(summary)
    autoruns_diff = summary.get("autoruns_diff", {}) or {}

    notes: list[str] = []

    suspicious_tasks = _to_int(task_diff.get("suspicious_new_or_modified", 0))
    suspicious_services = _to_int(service_diff.get("suspicious_new_or_modified", 0))
    suspicious_autoruns = _to_int(autoruns.get("suspicious_new_or_modified", 0))
    lolbins = _to_int(counts.get("lolbin_processes", 0))
    persistence_hits = _to_int(counts.get("persistence_hits", 0))

    if suspicious_tasks or suspicious_services or suspicious_autoruns:
        notes.append(
            "Installer-style persistence activity was observed. This can be expected for software that installs drivers, services, scheduled tasks, auto-updaters, or packet-capture components, but it should still be reviewed."
        )

    if "wireshark" in sample_name:
        notes.append(
            "Wireshark commonly installs Npcap, which may create driver/service/task persistence. Treat Npcap-related entries as expected installer behavior when publisher, path, and source provenance are trusted."
        )

    # Generic Npcap context even if the sample name is not Wireshark.
    suspicious_new = []
    if isinstance(autoruns_diff, dict):
        suspicious_new = autoruns_diff.get("suspicious_new_entries", []) or []

    for row in suspicious_new:
        if not isinstance(row, dict):
            continue
        combined = " ".join(
            str(row.get(k, "") or "").lower()
            for k in ("entry", "description", "company", "image_path", "launch_string")
        )
        if "npcap" in combined or "nmap software" in combined:
            notes.append(
                "Npcap-related Autoruns activity was detected. Npcap is expected for packet capture tools, but driver installation should be validated against vendor source, signature, and business need."
            )
            break

    if lolbins:
        notes.append(
            f"LOLBin/helper process activity was observed ({lolbins} events). For installers, some use of PowerShell, cmd, conhost, msiexec, or setup helpers can be normal; review command lines for encoded commands, downloads, or unusual script execution."
        )

    if persistence_hits and suspicious_tasks == 0 and suspicious_services == 0 and suspicious_autoruns == 0:
        notes.append(
            "Procmon persistence-like events were observed, but no suspicious scheduled task, service, or Autoruns diff was confirmed. Treat these as lower-confidence persistence indicators."
        )

    # De-duplicate while preserving order.
    deduped: list[str] = []
    seen: set[str] = set()
    for note in notes:
        if note not in seen:
            deduped.append(note)
            seen.add(note)

    return deduped


def _analyst_notes(summary: dict[str, Any]) -> list[str]:
    score = _to_int(summary.get("score", summary.get("dynamic_score", 0)), 0)
    severity = str(summary.get("severity", "") or "").strip()
    verdict = str(summary.get("verdict", "") or "").strip()
    notes = []

    notes.append(f"Dynamic score is {score}; reported verdict is {verdict or 'not provided'} and severity is {severity or 'not provided'}.")

    clean_notes = _clean_baseline_notes(summary)
    notes.extend(clean_notes)
    
    notes.extend(_installer_context_notes(summary))

    autoruns = _autoruns_counts(summary)
    if _to_int(autoruns.get("new_entries", 0)) > 0 or _to_int(autoruns.get("modified_entries", 0)) > 0:
        notes.append("Autoruns detected new or modified startup entries; review the Autoruns Persistence Diff section.")

    if (summary.get("abnormal_termination", {}) or {}).get("chain_crashed"):
        notes.append(
            "A process in the sample's tree terminated by crash. A deliberate "
            "anti-analysis bail is indistinguishable from a broken payload here, "
            "so an otherwise quiet result is inconclusive rather than clean."
        )

    reads = summary.get("vm_artifact_reads", {}) or {}
    read_counts = reads.get("counts", {}) or {}
    if reads and not reads.get("collection_available"):
        notes.append(
            "Registry reads were not captured by this run's Procmon filter, so "
            "whether the sample checked for a virtual machine is unobserved "
            "rather than answered."
        )
    elif _to_int(read_counts.get("vm_specific", 0)) > 0:
        notes.append(
            f"The sample read {_to_int(read_counts.get('vm_specific', 0))} "
            "registry artifact(s) that exist only on a virtual machine. Not "
            "scored, but a quiet run from a sample that enumerated the "
            "hypervisor first is not the same as a quiet run."
        )

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
{_containment_section(summary)}
{_observation_window_section(summary)}
{_abnormal_termination_section(summary)}
{_evidence_section(summary)}

<div class="grid">
  {_kv_table("Sample Metadata", sample)}
  {_capture_configuration_table(summary)}
  {_telemetry_coverage_table(summary)}
  {_degraded_collection_section(summary)}
  {_kv_table("Procmon Summary", procmon)}
  {_kv_table("Interesting Procmon Summary", procmon_interesting)}
  {_kv_table("Findings Counts", findings_counts)}
  {_kv_table("Scheduled Task Diff", task_diff, badge("Suspicious", task_diff.get("suspicious_new_or_modified", 0)))}
  {_kv_table("Service Diff", service_diff, badge("Suspicious", service_diff.get("suspicious_new_or_modified", 0)))}
  {_autoruns_table(summary)}
  {_kv_table("Dropped Files Summary", dropped, badge("Suspicious", dropped.get("suspicious", 0)))}
</div>

{_dropped_files_section(summary)}
{_list_section("Analyst Notes", _analyst_notes(summary), emphasize=False, context=True)}
{_list_section("Installer Context / Expected Behavior", _installer_context_notes(summary), emphasize=False, empty_text="No installer-specific context was identified.", context=True)}
{_list_section("Clean Baseline Checks", _clean_baseline_notes(summary), emphasize=False, empty_text="No clean-baseline checks were available.", context=True)}
{_list_section("Highlights", findings.get("highlights", []), emphasize=True, empty_text="No high-priority highlights were generated.")}
{_attack_sections(summary)}
{_sysmon_sections(summary)}
{_powershell_sections(summary)}
{_network_sections(summary)}
{_memory_sections(summary)}
{_unmapped_pe_section(summary)}
{_vm_artifact_reads_section(summary)}
{_autoruns_suspicious_sections(summary)}
{_autoruns_analyzer_section(summary)}
{_dict_list_table("Top Written Paths", findings.get("top_written_paths", []))}
{_dict_list_table("Top Network Processes", findings.get("top_network_processes", []))}
{_background_network_section(findings)}
{_spawned_processes_table("Spawned Processes", findings.get("spawned_processes", []), empty_text=_spawned_empty_text(findings))}
{_background_processes_section(findings)}
{_event_hits_table("Suspicious Path Hits", findings.get("suspicious_path_hits", []), emphasize=True, empty_text="No suspicious path hits were identified.")}
{_event_hits_table("Persistence Hits", findings.get("persistence_hits", []), emphasize=True, empty_text="No persistence hits were identified.")}
"""

    return report_page(title, subtitle, verdict, verdict_class, body_html)


def write_dynamic_html_report(summary_path: Path, output_html: Path) -> Path:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    html_text = build_dynamic_html_report(summary)
    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(html_text, encoding="utf-8")
    return output_html
