from __future__ import annotations

import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from dynamic_analysis.diff_services import diff_services
from dynamic_analysis.diff_tasks import diff_scheduled_tasks
from dynamic_analysis.dropped_file_triage import (
    collect_dropped_file_candidates,
    enrich_dropped_files,
    summarize_dropped_files,
)
from dynamic_analysis.findings import summarize_dynamic_findings
from dynamic_analysis.procmon_runner import (
    export_procmon_csv,
    start_procmon_capture,
    terminate_procmon_capture,
)
from dynamic_analysis.procmon_parser import (
    find_interesting_events,
    parse_procmon_csv,
    summarize_interesting_events,
    summarize_procmon_events,
)
from dynamic_analysis.snapshot_services import snapshot_services
from dynamic_analysis.snapshot_tasks import snapshot_scheduled_tasks
from dynamic_analysis.utils import (
    ensure_dir,
    file_size,
    md5_file,
    sha1_file,
    sha256_file,
    utc_now_iso,
    write_json,
)


StatusCallback = Optional[Callable[[str], None]]


def build_case_paths(case_dir: str | Path) -> dict[str, Path]:
    base = Path(case_dir)

    paths = {
        "base": base,
        "metadata": base / "metadata",
        "procmon": base / "procmon",
        "persistence": base / "persistence",
        "files": base / "files",
        "reports": base / "reports",
    }

    for p in paths.values():
        ensure_dir(p)

    return paths


def collect_sample_info(sample_path: str | Path) -> dict[str, Any]:
    sample = Path(sample_path)

    return {
        "sample_path": str(sample),
        "sample_name": sample.name,
        "size": file_size(sample),
        "md5": md5_file(sample),
        "sha1": sha1_file(sample),
        "sha256": sha256_file(sample),
    }


def run_sample(sample_path: str | Path, timeout_seconds: int) -> int:
    proc = subprocess.run([str(sample_path)], timeout=timeout_seconds)
    return int(proc.returncode)


def _emit(status_cb: StatusCallback, message: str) -> None:
    if status_cb:
        status_cb(message)


def _seconds_between(started_at: str, ended_at: str) -> int:
    start_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))
    duration = int((end_dt - start_dt).total_seconds())
    return max(duration, 0)


def _build_capture_quality(
    *,
    procmon_enabled: bool,
    procmon_started: bool,
    sample_launch_attempted: bool,
    exit_code: int | None,
    procmon_summary: dict[str, Any],
) -> dict[str, Any]:
    total_events = int(procmon_summary.get("total_events", 0) or 0)
    checks = [
        {
            "name": "sample_launch_attempted",
            "passed": sample_launch_attempted,
            "detail": "Sample launch was attempted." if sample_launch_attempted else "Sample launch was not attempted.",
        },
        {
            "name": "sample_exit_captured",
            "passed": exit_code is not None,
            "detail": f"Sample exit code captured: {exit_code}" if exit_code is not None else "Sample exit code not captured.",
        },
    ]

    if procmon_enabled:
        checks.extend(
            [
                {
                    "name": "procmon_started",
                    "passed": procmon_started,
                    "detail": "Procmon capture started." if procmon_started else "Procmon did not start.",
                },
                {
                    "name": "procmon_events_parsed",
                    "passed": total_events > 0,
                    "detail": f"Parsed {total_events} Procmon events."
                    if total_events > 0
                    else "No Procmon events were parsed.",
                },
            ]
        )

    passed_count = sum(1 for check in checks if check.get("passed"))
    score = int((passed_count / len(checks)) * 100) if checks else 0

    if score >= 90:
        status = "good"
    elif score >= 60:
        status = "partial"
    else:
        status = "poor"

    return {
        "score": score,
        "status": status,
        "checks": checks,
    }


def _build_behavior_summary(
    findings_summary: dict[str, Any],
    task_diff_summary: dict[str, Any],
    service_diff_summary: dict[str, Any],
) -> dict[str, int]:
    counts = findings_summary.get("counts", {}) if isinstance(findings_summary, dict) else {}
    task_counts = task_diff_summary.get("counts", {}) if isinstance(task_diff_summary, dict) else {}
    service_counts = service_diff_summary.get("counts", {}) if isinstance(service_diff_summary, dict) else {}

    return {
        "interesting_events": int(counts.get("interesting_events", 0) or 0),
        "process_creates": int(counts.get("process_creates", 0) or 0),
        "network_events": int(counts.get("network_events", 0) or 0),
        "file_write_events": int(counts.get("file_write_events", 0) or 0),
        "persistence_hits": int(counts.get("persistence_hits", 0) or 0),
        "suspicious_new_or_modified_tasks": int(task_counts.get("suspicious_new_or_modified", 0) or 0),
        "suspicious_new_or_modified_services": int(service_counts.get("suspicious_new_or_modified", 0) or 0),
    }


def calculate_dynamic_score(
    findings_summary: dict[str, Any],
    task_diff_summary: dict[str, Any],
    service_diff_summary: dict[str, Any],
    dropped_files_summary: dict[str, Any],
) -> dict[str, Any]:
    counts = findings_summary.get("counts", {}) if isinstance(findings_summary, dict) else {}
    task_counts = task_diff_summary.get("counts", {}) if isinstance(task_diff_summary, dict) else {}
    service_counts = service_diff_summary.get("counts", {}) if isinstance(service_diff_summary, dict) else {}
    dropped = dropped_files_summary if isinstance(dropped_files_summary, dict) else {}

    interesting_events = int(counts.get("interesting_events", 0) or 0)
    process_creates = int(counts.get("process_creates", 0) or 0)
    network_events = int(counts.get("network_events", 0) or 0)
    file_write_events = int(counts.get("file_write_events", 0) or 0)
    suspicious_path_hits = int(counts.get("suspicious_path_hits", 0) or 0)
    persistence_hits = int(counts.get("persistence_hits", 0) or 0)
    lolbin_processes = int(counts.get("lolbin_processes", 0) or 0)

    suspicious_tasks = int(task_counts.get("suspicious_new_or_modified", 0) or 0)
    suspicious_services = int(service_counts.get("suspicious_new_or_modified", 0) or 0)
    suspicious_dropped = int(dropped.get("suspicious", 0) or 0)

    score = 0
    score += min(interesting_events, 10)
    score += min(process_creates, 5)
    score += min(network_events * 2, 10)
    score += min(file_write_events, 5)
    score += suspicious_path_hits * 4
    score += persistence_hits * 8
    score += lolbin_processes * 5
    score += suspicious_tasks * 8
    score += suspicious_services * 8
    score += suspicious_dropped * 6

    if score <= 5:
        severity = "Low"
        verdict = "Benign / Clean Baseline"
    elif score <= 15:
        severity = "Low"
        verdict = "Low Suspicion"
    elif score <= 30:
        severity = "Medium"
        verdict = "Needs Review"
    else:
        severity = "High"
        verdict = "Elevated Attention"

    return {
        "score": score,
        "severity": severity,
        "verdict": verdict,
    }


def run_dynamic_analysis(
    config: dict[str, Any],
    status_cb: StatusCallback = None,
) -> dict[str, Any]:
    sample_path = Path(config["sample_path"])
    case_dir = Path(config["case_dir"])
    timeout_seconds = int(config.get("timeout_seconds", 180))

    run_profile = str(config.get("run_profile", "standard") or "standard").strip().lower()
    if run_profile not in {"quick", "standard", "deep"}:
        run_profile = "standard"
    run_id = str(config.get("run_id") or uuid.uuid4())

    _emit(status_cb, "Preparing case folders...")
    paths = build_case_paths(case_dir)

    run_config_path = paths["metadata"] / "run_config.json"
    sample_info_path = paths["metadata"] / "sample_info.json"
    run_summary_path = paths["metadata"] / "dynamic_run_summary.json"

    procmon_enabled = bool(config.get("procmon_enabled", False))
    procmon_path = config.get("procmon_path")
    procmon_config_path = config.get("procmon_config_path")

    procmon_backing = paths["procmon"] / "raw.pml"
    procmon_csv = paths["procmon"] / "export.csv"
    procmon_json = paths["procmon"] / "parsed_events.json"
    procmon_interesting_json = paths["procmon"] / "interesting_events.json"

    tasks_before_json = paths["persistence"] / "tasks_before.json"
    tasks_after_json = paths["persistence"] / "tasks_after.json"
    task_diffs_json = paths["persistence"] / "task_diffs.json"

    services_before_json = paths["persistence"] / "services_before.json"
    services_after_json = paths["persistence"] / "services_after.json"
    service_diffs_json = paths["persistence"] / "service_diffs.json"

    dropped_files_json = paths["files"] / "dropped_files.json"
    dropped_files_summary_json = paths["files"] / "dropped_files_summary.json"
    findings_json = paths["reports"] / "dynamic_findings.json"

    _emit(status_cb, "Writing run configuration...")
    write_json(run_config_path, config)

    _emit(status_cb, "Collecting sample hashes and metadata...")
    sample_info = collect_sample_info(sample_path)
    write_json(sample_info_path, sample_info)

    _emit(status_cb, "Snapshotting scheduled tasks (before)...")
    tasks_before = snapshot_scheduled_tasks()
    write_json(tasks_before_json, tasks_before)

    _emit(status_cb, "Snapshotting services (before)...")
    services_before = snapshot_services()
    write_json(services_before_json, services_before)

    started_at = utc_now_iso()
    exit_code: int | None = None
    procmon_summary: dict[str, int] = {}
    procmon_interesting_summary: dict[str, int] = {}
    dropped_files_summary: dict[str, int] = {}
    findings_summary: dict[str, Any] = {}
    task_diff_summary: dict[str, Any] = {}
    service_diff_summary: dict[str, Any] = {}
    procmon_started = False
    sample_launch_attempted = False

    try:
        if procmon_enabled:
            _emit(status_cb, "Starting Procmon capture...")
            start_procmon_capture(
                procmon_path=procmon_path,
                backing_file=procmon_backing,
                config_path=procmon_config_path if procmon_config_path else None,
            )
            procmon_started = True

        _emit(status_cb, f"Launching sample and waiting up to {timeout_seconds} seconds...")
        sample_launch_attempted = True
        exit_code = run_sample(sample_path, timeout_seconds)
        _emit(status_cb, f"Sample exited with code {exit_code}.")

    finally:
        _emit(status_cb, "Snapshotting scheduled tasks (after)...")
        tasks_after = snapshot_scheduled_tasks()
        write_json(tasks_after_json, tasks_after)

        _emit(status_cb, "Diffing scheduled tasks...")
        task_diff_summary = diff_scheduled_tasks(tasks_before, tasks_after)
        write_json(task_diffs_json, task_diff_summary)

        _emit(status_cb, "Snapshotting services (after)...")
        services_after = snapshot_services()
        write_json(services_after_json, services_after)

        _emit(status_cb, "Diffing services...")
        service_diff_summary = diff_services(services_before, services_after)
        write_json(service_diffs_json, service_diff_summary)

        if procmon_enabled and procmon_started:
            _emit(status_cb, "Stopping Procmon capture...")
            terminate_procmon_capture(procmon_path)

            _emit(status_cb, "Exporting Procmon CSV...")
            export_procmon_csv(
                procmon_path=procmon_path,
                backing_file=procmon_backing,
                csv_path=procmon_csv,
            )

            _emit(status_cb, "Parsing Procmon events...")
            events = parse_procmon_csv(procmon_csv)
            write_json(procmon_json, events)
            procmon_summary = summarize_procmon_events(events)

            _emit(status_cb, "Filtering interesting Procmon events...")
            interesting_events = find_interesting_events(events)
            write_json(procmon_interesting_json, interesting_events)
            procmon_interesting_summary = summarize_interesting_events(interesting_events)

            _emit(status_cb, "Triaging dropped-file candidates...")
            dropped_candidates = collect_dropped_file_candidates(events)
            dropped_files = enrich_dropped_files(dropped_candidates)
            write_json(dropped_files_json, dropped_files)

            dropped_files_summary = summarize_dropped_files(dropped_files)
            write_json(dropped_files_summary_json, dropped_files_summary)

            _emit(status_cb, "Building dynamic findings summary...")
            findings_summary = summarize_dynamic_findings(events, interesting_events)
            write_json(findings_json, findings_summary)

    ended_at = utc_now_iso()
    duration_seconds = _seconds_between(started_at, ended_at)
    capture_quality = _build_capture_quality(
        procmon_enabled=procmon_enabled,
        procmon_started=procmon_started,
        sample_launch_attempted=sample_launch_attempted,
        exit_code=exit_code,
        procmon_summary=procmon_summary,
    )
    behavior_summary = _build_behavior_summary(
        findings_summary=findings_summary,
        task_diff_summary=task_diff_summary,
        service_diff_summary=service_diff_summary,
    )

    score_data = calculate_dynamic_score(
        findings_summary=findings_summary,
        task_diff_summary=task_diff_summary,
        service_diff_summary=service_diff_summary,
        dropped_files_summary=dropped_files_summary,
    )

    summary = {
        "schema_version": "dynamic-1.0",
        "run_id": run_id,
        "run_profile": run_profile,
        "sample": sample_info,
        "started_at_utc": started_at,
        "ended_at_utc": ended_at,
        "duration_seconds": duration_seconds,
        "exit_code": exit_code,
        "procmon_enabled": procmon_enabled,
        "capture_quality": capture_quality,
        "behavior_summary": behavior_summary,
        "score": score_data["score"],
        "severity": score_data["severity"],
        "verdict": score_data["verdict"],
        "procmon_summary": procmon_summary,
        "procmon_interesting_summary": procmon_interesting_summary,
        "task_diff_summary": task_diff_summary.get("counts", {}),
        "service_diff_summary": service_diff_summary.get("counts", {}),
        "dropped_files_summary": dropped_files_summary,
        "findings": findings_summary,
    }

    _emit(status_cb, "Writing final run summary...")
    write_json(run_summary_path, summary)
    _emit(status_cb, "Dynamic analysis completed.")

    return summary