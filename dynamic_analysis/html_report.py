from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

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

    data = {
        "run_profile": summary.get("run_profile", ""),
        "cancelled": summary.get("cancelled", False),
        "total_run_duration_seconds": summary.get("duration_seconds", ""),
        "sample_observation_timeout_seconds": summary.get("timeout_seconds", ""),
        "procmon_enabled": summary.get("procmon_enabled", False),
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
    """
    rows: list[dict[str, Any]] = []
    for dump in memory.get("dumps", []) or []:
        row = {key: value for key, value in dump.items() if key != "path"}
        row["file"] = Path(str(dump.get("path", ""))).name
        rows.append(row)
    return rows


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
        return f"""
    <section class="card">
      <div class="section-head">
        <h2>Process Memory</h2>
        {_section_badge("Dumps", 0)}
      </div>
      <p class="muted">{_esc(note)}</p>
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
            },
            _section_badge("Written", counts.get("dumps_succeeded", 0)),
        ),
        _dict_list_table("Captured Process Images", _memory_dump_rows(memory)),
    ]

    if memory.get("skipped"):
        sections.append(
            _dict_list_table("Processes Not Dumped", memory.get("skipped", []) or [])
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
        # noise" and "the noise was filtered".
        "Analyzer highlights excluded": sysmon.get("analyzer_highlights_excluded", 0),
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
{_list_section("Sysmon DNS Queries", sysmon.get("dns_queries", []) or [], empty_text="No DNS queries were recorded by Sysmon.")}
{_list_section("Named Pipes", sysmon.get("named_pipes", []) or [], empty_text="No named pipes were recorded.")}
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
      "External IP addresses": len(iocs.get("external_ips", []) or []),
      "Non-routable addresses": len(iocs.get("non_routable_ips", []) or []),
      "URLs (notable)": len(iocs.get("notable_urls", []) or []),
      "URLs (total)": len(iocs.get("urls", []) or []),
  }, badge("Notable", len(iocs.get("notable_domains", []) or [])))}
</div>

{_list_section("Resolved Domains (excluding Windows baseline)", iocs.get("notable_domains", []) or [], emphasize=True, empty_text="Only routine Windows background traffic was resolved. Nothing here is attributable to the sample.")}
{_list_section("Requested URLs (excluding Windows baseline)", iocs.get("notable_urls", []) or [], emphasize=True, empty_text="No notable plaintext URLs were observed.")}
{_list_section("Contacted External IP Addresses", iocs.get("external_ips", []) or [], empty_text="No external IP addresses were contacted.")}
{_list_section("Windows Baseline Traffic (context, not findings)", iocs.get("baseline_domains", []) or [], empty_text="No baseline traffic was recorded.")}
{_list_section("Non-Routable Addresses (context, not findings)", iocs.get("non_routable_ips", []) or [], empty_text="No multicast or broadcast traffic was recorded.")}
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
{_kv_table("Simulated Internet (FakeNet-NG)", overview)}
{_dict_list_table("Connection Attempts By Process", fakenet.get("process_requests", []) or [])}
{_list_section("Domains Requested Against Simulated Internet", fakenet.get("dns_requests", []) or [], emphasize=True, empty_text="No domains were requested. With no default route the guest generates little background traffic, so this is expected for a sample that does not use the network.")}
{_dict_list_table("Requests Served", fakenet.get("http_requests", []) or [])}
{_list_section("Listeners Configured", fakenet.get("listeners_configured", []) or [], empty_text="No listeners were configured.")}
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

<div class="grid">
  {_kv_table("Sample Metadata", sample)}
  {_capture_configuration_table(summary)}
  {_telemetry_coverage_table(summary)}
  {_kv_table("Procmon Summary", procmon)}
  {_kv_table("Interesting Procmon Summary", procmon_interesting)}
  {_kv_table("Findings Counts", findings_counts)}
  {_kv_table("Scheduled Task Diff", task_diff, badge("Suspicious", task_diff.get("suspicious_new_or_modified", 0)))}
  {_kv_table("Service Diff", service_diff, badge("Suspicious", service_diff.get("suspicious_new_or_modified", 0)))}
  {_autoruns_table(summary)}
  {_kv_table("Dropped Files Summary", dropped, badge("Suspicious", dropped.get("suspicious", 0)))}
</div>

{_list_section("Analyst Notes", _analyst_notes(summary), emphasize=False)}
{_list_section("Installer Context / Expected Behavior", _installer_context_notes(summary), emphasize=False, empty_text="No installer-specific context was identified.")}
{_list_section("Clean Baseline Checks", _clean_baseline_notes(summary), emphasize=False, empty_text="No clean-baseline checks were available.")}
{_list_section("Highlights", findings.get("highlights", []), emphasize=True, empty_text="No high-priority highlights were generated.")}
{_sysmon_sections(summary)}
{_network_sections(summary)}
{_memory_sections(summary)}
{_autoruns_suspicious_sections(summary)}
{_autoruns_analyzer_section(summary)}
{_dict_list_table("Top Written Paths", findings.get("top_written_paths", []))}
{_dict_list_table("Top Network Processes", findings.get("top_network_processes", []))}
{_spawned_processes_table("Spawned Processes", findings.get("spawned_processes", []), empty_text="No non-noise spawned processes were attributed to the sample.")}
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
