from __future__ import annotations

import csv
import re
import subprocess
import uuid
import time
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


def _slugify(value: str, fallback: str = "dynamic_test") -> str:
    text = (value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "_", text)
    text = text.strip("._-")
    return text or fallback


def _build_run_case_dir(base_case_dir: Path, run_id: str, test_name: str | None = None) -> Path:
    runs_root = base_case_dir / "dynamic_runs"
    ensure_dir(runs_root)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_test = _slugify(test_name or "dynamic_test", fallback="dynamic_test")
    short_id = run_id.split("-")[0]
    run_dir = runs_root / f"{safe_test}_{timestamp}_{short_id}"
    ensure_dir(run_dir)
    return run_dir


def build_case_paths(case_dir: str | Path) -> dict[str, Path]:
    base = Path(case_dir)

    paths = {
        "base": base,
        "metadata": base / "metadata",
        "procmon": base / "procmon",
        "persistence": base / "persistence",
        "files": base / "files",
        "reports": base / "reports",
        "autoruns": base / "autoruns",
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


def run_sample(
    sample_path: str | Path,
    timeout_seconds: int,
    minimum_observation_seconds: int = 30,
) -> int:
    """
    Launch the sample and observe for at least minimum_observation_seconds.

    This avoids ending too quickly when Windows launcher binaries hand off to
    packaged app processes, such as Windows 11 Notepad launching the
    WindowsApps Notepad process and exiting immediately.
    """
    sample = Path(sample_path)

    start_time = time.monotonic()
    proc = subprocess.Popen([str(sample)])

    exit_code: int | None = None

    while True:
        elapsed = time.monotonic() - start_time

        if exit_code is None:
            exit_code = proc.poll()

        minimum_elapsed = elapsed >= minimum_observation_seconds
        timeout_elapsed = elapsed >= timeout_seconds

        if timeout_elapsed:
            if proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
            return exit_code if exit_code is not None else -1

        if exit_code is not None and minimum_elapsed:
            return int(exit_code)

        time.sleep(1)


def _emit(status_cb: StatusCallback, message: str) -> None:
    if status_cb:
        status_cb(message)


def _seconds_between(started_at: str, ended_at: str) -> int:
    start_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))
    duration = int((end_dt - start_dt).total_seconds())
    return max(duration, 0)


def _sum_numeric_values(data: dict[str, Any]) -> int:
    total = 0
    for value in data.values():
        if isinstance(value, (int, float)):
            total += int(value)
    return total


def _build_capture_quality(
    *,
    procmon_enabled: bool,
    procmon_started: bool,
    sample_launch_attempted: bool,
    exit_code: int | None,
    procmon_summary: dict[str, Any],
) -> dict[str, Any]:
    total_events = _sum_numeric_values(procmon_summary)

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

    passed_count = sum(1 for c in checks if c.get("passed"))
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
        "procmon_total_events": total_events,
        "checks": checks,
    }


def _build_behavior_summary(
    findings_summary: dict[str, Any],
    task_diff_summary: dict[str, Any],
    service_diff_summary: dict[str, Any],
    autoruns_diff_summary: dict[str, Any],
) -> dict[str, int]:
    counts = findings_summary.get("counts", {}) if isinstance(findings_summary, dict) else {}
    task_counts = task_diff_summary.get("counts", {}) if isinstance(task_diff_summary, dict) else {}
    service_counts = service_diff_summary.get("counts", {}) if isinstance(service_diff_summary, dict) else {}
    autoruns_counts = autoruns_diff_summary.get("counts", {}) if isinstance(autoruns_diff_summary, dict) else {}

    return {
        "interesting_events": int(counts.get("interesting_events", 0) or 0),
        "process_creates": int(counts.get("process_creates", 0) or 0),
        "network_events": int(counts.get("network_events", 0) or 0),
        "file_write_events": int(counts.get("file_write_events", 0) or 0),
        "persistence_hits": int(counts.get("persistence_hits", 0) or 0),
        "suspicious_new_or_modified_tasks": int(task_counts.get("suspicious_new_or_modified", 0) or 0),
        "suspicious_new_or_modified_services": int(service_counts.get("suspicious_new_or_modified", 0) or 0),
        "autoruns_new_entries": int(autoruns_counts.get("new_entries", 0) or 0),
        "autoruns_modified_entries": int(autoruns_counts.get("modified_entries", 0) or 0),
        "autoruns_suspicious_new_or_modified": int(autoruns_counts.get("suspicious_new_or_modified", 0) or 0),
    }



# ---------------------------------------------------------------------------
# Autorunsc / Autoruns persistence snapshot support
# ---------------------------------------------------------------------------

AUTORUNS_SUSPICIOUS_PATH_MARKERS = (
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\recycle",
)

AUTORUNS_HIGH_SIGNAL_CATEGORIES = (
    "logon",
    "scheduled tasks",
    "services",
    "drivers",
    "winlogon",
    "appinit",
    "image hijacks",
    "known dlls",
    "boot execute",
    "wmi",
)


def _default_autorunsc_path() -> Path:
    """
    Default RingForge tool path:
        <project_root>\\tools\\autorunsc64.exe

    This file lives in:
        dynamic_analysis\\orchestrator.py
    so parents[1] is the project root.
    """
    return Path(__file__).resolve().parents[1] / "tools" / "autorunsc64.exe"


def _run_autorunsc_snapshot(
    *,
    autorunsc_path: str | Path,
    output_csv: Path,
    deep_scan: bool = False,
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    """
    Run autorunsc and save a CSV snapshot.

    Fast/default mode:
        autorunsc64.exe -accepteula -a * -c

    Deep mode:
        adds -h -s for hashes and signature verification.

    Returns a small status dictionary for inclusion in run_config/summary.
    """
    exe = Path(autorunsc_path)
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    result = {
        "enabled": True,
        "tool_path": str(exe),
        "output_csv": str(output_csv),
        "deep_scan": bool(deep_scan),
        "success": False,
        "returncode": None,
        "error": "",
    }

    if not exe.exists():
        result["error"] = f"autorunsc executable not found: {exe}"
        return result

    args = [str(exe), "-accepteula", "-a", "*", "-c"]
    if deep_scan:
        args.extend(["-h", "-s"])

    try:
        with output_csv.open("w", encoding="utf-8", errors="replace", newline="") as f:
            proc = subprocess.run(
                args,
                stdout=f,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )

        result["returncode"] = int(proc.returncode)
        result["stderr"] = (proc.stderr or "").strip()[:4000]
        result["success"] = output_csv.exists() and output_csv.stat().st_size > 0

        if proc.returncode not in (0, 1):
            # Autorunsc may return non-zero in some environments while still
            # producing useful output, so do not fail the whole dynamic run.
            result["error"] = f"autorunsc returned {proc.returncode}"

    except subprocess.TimeoutExpired:
        result["error"] = f"autorunsc timed out after {timeout_seconds} seconds"
    except Exception as e:
        result["error"] = str(e)

    return result


def _read_autoruns_csv(csv_path: Path) -> list[dict[str, str]]:
    """
    Read Autorunsc CSV output.

    Handles both formats:
      1. Banner lines followed by the CSV header
      2. CSV header on the first line

    Fast mode header usually looks like:
      Time,Entry Location,Entry,Enabled,Category,Profile,Description,Company,Image Path,Version,Launch String

    Deep mode may include extra hash/signature columns:
      Time,Entry Location,Entry,Enabled,Category,Profile,Description,Signer,Company,Image Path,...
    """
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return []

    raw_text = ""
    for enc in ("utf-8-sig", "utf-16", "utf-16-le", "cp1252"):
        try:
            raw_text = csv_path.read_text(encoding=enc, errors="replace")
            if "Entry Location" in raw_text and "Image Path" in raw_text:
                break
        except Exception:
            continue

    if not raw_text:
        return []

    raw_lines = [line.strip("\ufeff") for line in raw_text.splitlines() if line.strip()]
    if not raw_lines:
        return []

    header_index = None
    for idx, line in enumerate(raw_lines):
        normalized = line.strip().lower().replace("\ufeff", "")
        if normalized.startswith("time,entry location,entry"):
            header_index = idx
            break

    if header_index is None:
        for idx, line in enumerate(raw_lines):
            lower = line.lower()
            if "entry location" in lower and "image path" in lower and "launch string" in lower:
                header_index = idx
                break

    if header_index is None:
        return []

    csv_lines = raw_lines[header_index:]
    rows: list[dict[str, str]] = []

    try:
        reader = csv.DictReader(csv_lines)
        for row in reader:
            if not row:
                continue

            normalized = {
                str(k or "").strip().replace("\ufeff", ""): str(v or "").strip()
                for k, v in row.items()
                if k is not None
            }

            if not any(normalized.get(k, "") for k in ("Entry", "Image Path", "Launch String", "Entry Location")):
                continue

            rows.append(normalized)
    except Exception:
        return []

    return rows


def _autoruns_identity(row: dict[str, str]) -> str:
    """
    Build a stable identity for an autorun entry.
    """
    parts = [
        row.get("Entry Location", ""),
        row.get("Entry", ""),
        row.get("Category", ""),
        row.get("Profile", ""),
        row.get("Image Path", ""),
        row.get("Launch String", ""),
    ]
    return "||".join(str(p).strip().lower() for p in parts)


def _autoruns_content_fingerprint(row: dict[str, str]) -> str:
    """
    Build a broad fingerprint so modified entries can be detected.
    """
    keys = [
        "Enabled",
        "Description",
        "Signer",
        "Company",
        "Image Path",
        "Version",
        "Launch String",
        "MD5",
        "SHA-1",
        "SHA-256",
        "PESHA-256",
    ]
    return "||".join(str(row.get(k, "")).strip().lower() for k in keys)


def _is_suspicious_autorun(row: dict[str, str]) -> bool:
    signer = row.get("Signer", "").lower()
    company = row.get("Company", "").lower()
    image_path = row.get("Image Path", "").lower()
    launch = row.get("Launch String", "").lower()
    category = row.get("Category", "").lower()
    enabled = row.get("Enabled", "").lower()

    if enabled and enabled not in {"enabled", "true", "yes"}:
        return False

    if any(marker in image_path or marker in launch for marker in AUTORUNS_SUSPICIOUS_PATH_MARKERS):
        return True

    if "verified" not in signer and not ("microsoft" in signer or "microsoft" in company):
        if any(cat in category for cat in AUTORUNS_HIGH_SIGNAL_CATEGORIES):
            return True

    return False


def _summarize_autorun_row(row: dict[str, str]) -> dict[str, str]:
    return {
        "time": row.get("Time", ""),
        "entry_location": row.get("Entry Location", ""),
        "entry": row.get("Entry", ""),
        "enabled": row.get("Enabled", ""),
        "category": row.get("Category", ""),
        "profile": row.get("Profile", ""),
        "description": row.get("Description", ""),
        "signer": row.get("Signer", ""),
        "company": row.get("Company", ""),
        "image_path": row.get("Image Path", ""),
        "launch_string": row.get("Launch String", ""),
        "sha256": row.get("SHA-256", ""),
    }


def diff_autoruns_snapshots(before_csv: Path, after_csv: Path) -> dict[str, Any]:
    before_rows = _read_autoruns_csv(before_csv)
    after_rows = _read_autoruns_csv(after_csv)

    before_by_id = {_autoruns_identity(row): row for row in before_rows}
    after_by_id = {_autoruns_identity(row): row for row in after_rows}

    before_ids = set(before_by_id)
    after_ids = set(after_by_id)

    new_ids = sorted(after_ids - before_ids)
    removed_ids = sorted(before_ids - after_ids)
    common_ids = sorted(before_ids & after_ids)

    modified_ids = []
    for entry_id in common_ids:
        if _autoruns_content_fingerprint(before_by_id[entry_id]) != _autoruns_content_fingerprint(after_by_id[entry_id]):
            modified_ids.append(entry_id)

    new_entries = [_summarize_autorun_row(after_by_id[i]) for i in new_ids]
    removed_entries = [_summarize_autorun_row(before_by_id[i]) for i in removed_ids]
    modified_entries = [
        {
            "before": _summarize_autorun_row(before_by_id[i]),
            "after": _summarize_autorun_row(after_by_id[i]),
        }
        for i in modified_ids
    ]

    suspicious_new = [
        _summarize_autorun_row(after_by_id[i])
        for i in new_ids
        if _is_suspicious_autorun(after_by_id[i])
    ]

    suspicious_modified = [
        {
            "before": _summarize_autorun_row(before_by_id[i]),
            "after": _summarize_autorun_row(after_by_id[i]),
        }
        for i in modified_ids
        if _is_suspicious_autorun(after_by_id[i])
    ]

    counts = {
        "before_total": len(before_rows),
        "after_total": len(after_rows),
        "new_entries": len(new_entries),
        "removed_entries": len(removed_entries),
        "modified_entries": len(modified_entries),
        "suspicious_new_entries": len(suspicious_new),
        "suspicious_modified_entries": len(suspicious_modified),
        "suspicious_new_or_modified": len(suspicious_new) + len(suspicious_modified),
    }

    return {
        "counts": counts,
        "new_entries": new_entries[:100],
        "removed_entries": removed_entries[:100],
        "modified_entries": modified_entries[:100],
        "suspicious_new_entries": suspicious_new[:100],
        "suspicious_modified_entries": suspicious_modified[:100],
    }



def calculate_dynamic_score(
    findings_summary: dict[str, Any],
    task_diff_summary: dict[str, Any],
    service_diff_summary: dict[str, Any],
    dropped_files_summary: dict[str, Any],
    autoruns_diff_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    counts = findings_summary.get("counts", {}) if isinstance(findings_summary, dict) else {}
    task_counts = task_diff_summary.get("counts", {}) if isinstance(task_diff_summary, dict) else {}
    service_counts = service_diff_summary.get("counts", {}) if isinstance(service_diff_summary, dict) else {}
    dropped = dropped_files_summary if isinstance(dropped_files_summary, dict) else {}
    autoruns_counts = (
        autoruns_diff_summary.get("counts", {})
        if isinstance(autoruns_diff_summary, dict)
        else {}
    )

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
    autoruns_new = int(autoruns_counts.get("new_entries", 0) or 0)
    autoruns_modified = int(autoruns_counts.get("modified_entries", 0) or 0)
    autoruns_suspicious = int(autoruns_counts.get("suspicious_new_or_modified", 0) or 0)

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
    score += min(autoruns_new, 5) * 2
    score += min(autoruns_modified, 5) * 2
    score += autoruns_suspicious * 10

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

    return {"score": score, "severity": severity, "verdict": verdict}


def run_dynamic_analysis(
    config: dict[str, Any],
    status_cb: StatusCallback = None,
) -> dict[str, Any]:
    sample_path = Path(config["sample_path"])
    root_case_dir = Path(config["case_dir"])
    timeout_seconds = int(config.get("timeout_seconds", 180))

    run_profile = str(config.get("run_profile", "standard") or "standard").strip().lower()
    if run_profile not in {"quick", "standard", "deep"}:
        run_profile = "standard"

    run_id = str(config.get("run_id") or uuid.uuid4())
    test_name = str(config.get("test_name") or sample_path.stem or "dynamic_test")

    # Create separate folder per test run
    run_case_dir = _build_run_case_dir(root_case_dir, run_id=run_id, test_name=test_name)

    _emit(status_cb, f"Preparing case folders in run directory: {run_case_dir}")
    paths = build_case_paths(run_case_dir)

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

    autoruns_enabled = bool(config.get("autoruns_enabled", True))
    autoruns_deep_scan = bool(config.get("autoruns_deep_scan", run_profile == "deep"))
    autoruns_timeout_seconds = int(config.get("autoruns_timeout_seconds", 180))
    autorunsc_path = Path(config.get("autorunsc_path") or _default_autorunsc_path())

    autoruns_before_csv = paths["autoruns"] / "autoruns_before.csv"
    autoruns_after_csv = paths["autoruns"] / "autoruns_after.csv"
    autoruns_diff_json = paths["autoruns"] / "autoruns_diff.json"

    dropped_files_json = paths["files"] / "dropped_files.json"
    dropped_files_summary_json = paths["files"] / "dropped_files_summary.json"
    findings_json = paths["reports"] / "dynamic_findings.json"

    _emit(status_cb, "Writing run configuration...")
    stored_config = dict(config)
    stored_config["resolved_run_case_dir"] = str(run_case_dir)
    stored_config["run_id"] = run_id
    stored_config["run_profile"] = run_profile
    stored_config["test_name"] = test_name
    write_json(run_config_path, stored_config)

    _emit(status_cb, "Collecting sample hashes and metadata...")
    sample_info = collect_sample_info(sample_path)
    write_json(sample_info_path, sample_info)

    autoruns_before_status: dict[str, Any] = {"enabled": autoruns_enabled, "success": False, "error": "not run"}
    autoruns_after_status: dict[str, Any] = {"enabled": autoruns_enabled, "success": False, "error": "not run"}
    autoruns_diff_summary: dict[str, Any] = {}

    _emit(status_cb, "Snapshotting scheduled tasks (before)...")
    tasks_before = snapshot_scheduled_tasks()
    write_json(tasks_before_json, tasks_before)

    _emit(status_cb, "Snapshotting services (before)...")
    services_before = snapshot_services()
    write_json(services_before_json, services_before)

    if autoruns_enabled:
        _emit(status_cb, "Snapshotting Autoruns entries (before)...")
        autoruns_before_status = _run_autorunsc_snapshot(
            autorunsc_path=autorunsc_path,
            output_csv=autoruns_before_csv,
            deep_scan=autoruns_deep_scan,
            timeout_seconds=autoruns_timeout_seconds,
        )
        if not autoruns_before_status.get("success"):
            _emit(status_cb, f"Autoruns before snapshot warning: {autoruns_before_status.get('error', 'unknown error')}")
    else:
        _emit(status_cb, "Autoruns snapshot disabled.")

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

        minimum_observation_seconds = int(config.get("minimum_observation_seconds", 30))

        _emit(
            status_cb,
            f"Launching sample and observing for at least {minimum_observation_seconds} seconds "
            f"(timeout: {timeout_seconds} seconds)..."
        )
        sample_launch_attempted = True
        exit_code = run_sample(
            sample_path,
            timeout_seconds,
            minimum_observation_seconds=minimum_observation_seconds,
        )
        _emit(status_cb, f"Sample observation completed with exit code {exit_code}.")

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

    if autoruns_enabled:
        _emit(status_cb, "Snapshotting Autoruns entries (after)...")
        autoruns_after_status = _run_autorunsc_snapshot(
            autorunsc_path=autorunsc_path,
            output_csv=autoruns_after_csv,
            deep_scan=autoruns_deep_scan,
            timeout_seconds=autoruns_timeout_seconds,
        )
        if not autoruns_after_status.get("success"):
            _emit(status_cb, f"Autoruns after snapshot warning: {autoruns_after_status.get('error', 'unknown error')}")

        if autoruns_before_csv.exists() and autoruns_after_csv.exists():
            _emit(status_cb, "Diffing Autoruns snapshots...")
            autoruns_diff_summary = diff_autoruns_snapshots(autoruns_before_csv, autoruns_after_csv)
            write_json(autoruns_diff_json, autoruns_diff_summary)

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
        autoruns_diff_summary=autoruns_diff_summary,
    )

    score_data = calculate_dynamic_score(
        findings_summary=findings_summary,
        task_diff_summary=task_diff_summary,
        service_diff_summary=service_diff_summary,
        dropped_files_summary=dropped_files_summary,
        autoruns_diff_summary=autoruns_diff_summary,
    )

    summary = {
        "schema_version": "dynamic-1.0",
        "run_id": run_id,
        "run_profile": run_profile,
        "test_name": test_name,
        "run_case_dir": str(run_case_dir),
        "sample": sample_info,
        "started_at_utc": started_at,
        "ended_at_utc": ended_at,
        "duration_seconds": duration_seconds,
        "exit_code": exit_code,
        "procmon_enabled": procmon_enabled,
        "autoruns_enabled": autoruns_enabled,
        "autoruns_deep_scan": autoruns_deep_scan,
        "autoruns_before_status": autoruns_before_status,
        "autoruns_after_status": autoruns_after_status,
        "capture_quality": capture_quality,
        "behavior_summary": behavior_summary,
        "score": score_data["score"],
        "severity": score_data["severity"],
        "verdict": score_data["verdict"],
        "procmon_summary": procmon_summary,
        "procmon_interesting_summary": procmon_interesting_summary,
        "task_diff_summary": task_diff_summary.get("counts", {}),
        "service_diff_summary": service_diff_summary.get("counts", {}),
        "autoruns_diff_summary": autoruns_diff_summary.get("counts", {}) if isinstance(autoruns_diff_summary, dict) else {},
        "autoruns_diff": autoruns_diff_summary,
        "dropped_files_summary": dropped_files_summary,
        "findings": findings_summary,
    }

    _emit(status_cb, "Writing final run summary...")
    write_json(run_summary_path, summary)
    _emit(status_cb, "Dynamic analysis completed.")

    return summary