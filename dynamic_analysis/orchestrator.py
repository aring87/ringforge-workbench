from __future__ import annotations

import csv
import re
import subprocess
import uuid
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from dynamic_analysis.diff_services import diff_services
from dynamic_analysis.diff_tasks import diff_scheduled_tasks
from dynamic_analysis.dropped_file_triage import (
    collect_dropped_file_candidates,
    enrich_dropped_files,
    summarize_dropped_files,
)
from dynamic_analysis.fakenet_runner import (
    FakeNetSession,
    fakenet_status,
    parse_fakenet_log,
)
from dynamic_analysis.attack_mapping import map_run, summarize_attack
from dynamic_analysis.crash_evidence import (
    CrashDumpCollector,
    collect_crashes,
    empty_crash_summary,
    summarize_abnormal_termination,
    wer_local_dump_status,
)
from dynamic_analysis.findings import summarize_dynamic_findings
from dynamic_analysis.powershell_logging import (
    collect as collect_scriptblocks,
    empty_summary as empty_powershell_summary,
    powershell_logging_status,
)
from dynamic_analysis.memory_dump import (
    DEFAULT_MAX_PROCESSES,
    DEFAULT_MAX_TOTAL_MB,
    DEFAULT_MAX_WORKING_SET_MB,
    DEFAULT_SPAWN_REDUMP_SECONDS,
    MemoryDumpSession,
    memory_dump_status,
    successful_dumps,
    reconcile_with_sysmon,
    sample_descendant_pids,
    summarize_memory_dumps,
)
from dynamic_analysis.module_integrity import (
    analyze_dump as analyze_module_integrity,
    summarize_module_integrity,
)
from dynamic_analysis.pe_carve import (
    carve_dumps,
    summarize_pe_carve,
)
from dynamic_analysis.memory_yara import (
    memory_yara_status,
    scan_memory_dumps,
    summarize_memory_yara,
)
from dynamic_analysis.network_capture import (
    COMMON_PORTS,
    PacketCapture,
    capture_status,
    extract_network_iocs,
    is_baseline_domain,
    is_local_discovery_domain,
    network_isolation_status,
    parse_pcap,
)
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
from dynamic_analysis.procmon_config import describe_procmon_filter
from dynamic_analysis.ntdll_unhooking import (
    collect_ntdll_unhooking,
    empty_ntdll_unhooking,
)
from dynamic_analysis.vm_artifact_reads import (
    collect_vm_artifact_reads,
    correlate_vm_check_with_silence,
    empty_vm_artifact_reads,
    empty_vm_check_correlation,
)
from dynamic_analysis.snapshot_services import (
    snapshot_services,
    snapshot_services_with_status,
)
from dynamic_analysis.snapshot_tasks import (
    snapshot_scheduled_tasks,
    snapshot_scheduled_tasks_with_status,
)
from dynamic_analysis.sysmon_collector import (
    collect as collect_sysmon,
    mark_start as sysmon_mark_start,
    summarize_sysmon_events,
    sysmon_status,
)
from dynamic_analysis.utils import (
    ANALYZER_TOOL_IMAGE_MARKERS,
    ensure_dir,
    is_windows_response_process,
    file_size,
    md5_file,
    sha1_file,
    sha256_file,
    utc_now_iso,
    write_json,
)

StatusCallback = Optional[Callable[[str], None]]
CancelEvent = Optional[threading.Event]


class DynamicAnalysisCancelled(Exception):
    """Raised when the analyst cancels a dynamic analysis run."""


class ContainmentError(Exception):
    """Raised when the guest can reach the internet and a run was requested.

    Its own type rather than a generic failure because the caller has to be
    able to tell "we refused to detonate" from "the run broke": one is the
    control working and the other is a bug.
    """


def _cancel_requested(cancel_event: CancelEvent) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())


def _raise_if_cancelled(cancel_event: CancelEvent) -> None:
    if _cancel_requested(cancel_event):
        raise DynamicAnalysisCancelled("Dynamic analysis cancelled by analyst.")



#: Longest sample-derived component allowed in a case or run directory name.
#:
#: Windows still caps a path at 260 characters unless long paths are enabled,
#: and this name appears twice in every artifact path:
#:
#:   cases\<name>\dynamic_analysis\dynamic_runs\<name>_<timestamp>_<id>\metadata\...
#:
#: MalwareBazaar delivers every sample named as its full SHA-256, so a real
#: sample is 64 characters and the two copies alone consume ~155 before the
#: repo root, the fixed directories, or any filename. The first live sample
#: failed at "The filename or extension is too long" for exactly this reason.
#:
#: 24 keeps a hash prefix long enough to stay recognisable and to remain
#: effectively unique within a case directory, while leaving room for the rest
#: of the path.
_MAX_NAME_COMPONENT = 24


def _slugify(value: str, fallback: str = "dynamic_test") -> str:
    text = (value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "_", text)
    text = text.strip("._-")
    if len(text) > _MAX_NAME_COMPONENT:
        text = text[:_MAX_NAME_COMPONENT].rstrip("._-")
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
        "network": base / "network",
        "sysmon": base / "sysmon",
        "memory": base / "memory",
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

def build_dynamic_launch_command(sample_path: str | Path, run_dir: str | Path | None = None) -> list[str]:
    sample = Path(sample_path)
    suffix = sample.suffix.lower()

    if run_dir is None:
        run_dir = sample.parent

    run_dir = Path(run_dir)

    if suffix == ".exe":
        return [str(sample)]

    if suffix == ".msi":
        return [
            "msiexec.exe",
            "/i",
            str(sample),
            "/qn",
            "/norestart",
            "/L*v",
            str(run_dir / "msi_install.log"),
        ]

    if suffix == ".ps1":
        return [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(sample),
        ]

    if suffix in [".bat", ".cmd"]:
        return [
            "cmd.exe",
            "/c",
            str(sample),
        ]

    raise ValueError(f"Unsupported sample type for dynamic execution: {suffix}")

def run_sample(
    sample_path: str | Path,
    timeout_seconds: int,
    minimum_observation_seconds: int = 30,
    post_exit_observation_seconds: int = 120,
    installer_observation_mode: bool = True,
    adaptive_observation: bool = True,
    max_observation_seconds: int = 600,
    observation_extension_seconds: int = 30,
    activity_probe: Optional[Callable[[], bool]] = None,
    cancel_event: CancelEvent = None,
    status_cb: StatusCallback = None,
    on_launch: Optional[Callable[[int], None]] = None,
) -> dict[str, Any]:
    """
    Launch the sample and observe runtime behavior.

    Installer-style behavior:
    - Procmon should not stop just because the initial launcher/bootstrapper exits.
    - The run observes for at least minimum_observation_seconds.
    - If the initial process exits, RingForge keeps observing for
      post_exit_observation_seconds so child installers, msiexec handoffs,
      services, scheduled tasks, and background setup activity can be captured.
    - Analyst cancellation is honored during observation.

    Adaptive window:
    - timeout_seconds is the base window, and on its own it is a guess about
      how long a sample will stay dormant. One AgentTesla binary sat dormant
      for 21, 37, 38, 41, 44 and 83 seconds across six runs of the same file,
      so there is no fixed number that is right twice.
    - When the base window expires while the sample is *still running and has
      not yet been seen to do anything*, the window is extended in
      observation_extension_seconds steps up to max_observation_seconds. That
      is the only case where waiting longer can change the result: a sample
      that has exited, or that has already acted, has given the run what it
      came for.
    - activity_probe reports whether anything has been observed yet. Without
      one, adaptive extension is unavailable and the base window stands --
      recorded as such, because extending blindly would turn every quiet run
      into a ten-minute one.

    Returns the observation record rather than a bare exit code: how long the
    run actually watched, and why it stopped, decides whether a quiet report
    means a quiet sample. ``exit_code`` carries what this used to return.

    on_launch receives the sample's PID immediately after launch. Memory
    dumping needs the PID while the process is alive, and the exit code this
    function returns arrives far too late for that.
    """
    sample = Path(sample_path)

    _raise_if_cancelled(cancel_event)

    start_time = time.monotonic()
    launch_cmd = build_dynamic_launch_command(sample)

    _emit(status_cb, f"Launch command: {' '.join(launch_cmd)}")

    proc = subprocess.Popen(launch_cmd)

    if on_launch is not None:
        # A failure in a telemetry hook must never take down the detonation.
        try:
            on_launch(proc.pid)
        except Exception as error:
            _emit(status_cb, f"Launch hook warning: {error}")

    exit_code: int | None = None
    process_exit_time: float | None = None
    last_notice_second = -1

    can_extend = bool(adaptive_observation and activity_probe is not None)
    window_seconds = int(timeout_seconds)
    extensions = 0
    activity_seen = False

    def _observed_activity() -> bool:
        """Whether the sample has been seen to act. Sticky, and never raises.

        A probe that throws must not end the observation early, and must not
        be read as activity either -- the last known answer stands.
        """
        nonlocal activity_seen
        if activity_seen or activity_probe is None:
            return activity_seen
        try:
            activity_seen = bool(activity_probe())
        except Exception as error:
            _emit(status_cb, f"Activity probe warning: {error}")
        return activity_seen

    def _result(ended_because: str, elapsed: float) -> dict[str, Any]:
        # Asked here, not only on the extension path. A Formbook run ended
        # through post-exit observation without the window ever expiring, so
        # the probe was never consulted and the record said
        # activity_observed: false -- for a sample that had spawned four
        # processes. "Never asked" and "nothing happened" must not look alike.
        _observed_activity()
        return {
            "exit_code": -1 if exit_code is None else int(exit_code),
            "sample_exited": exit_code is not None,
            "elapsed_seconds": int(elapsed),
            "base_window_seconds": int(timeout_seconds),
            "window_seconds": window_seconds,
            "max_observation_seconds": int(max_observation_seconds),
            "adaptive_observation": bool(adaptive_observation),
            "adaptive_available": can_extend,
            "extensions": extensions,
            "extended": extensions > 0,
            "activity_observed": activity_seen,
            "ended_because": ended_because,
        }

    while True:
        if _cancel_requested(cancel_event):
            if proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass

            raise DynamicAnalysisCancelled(
                "Dynamic analysis cancelled during sample observation."
            )

        now = time.monotonic()
        elapsed = now - start_time

        current_exit = proc.poll()
        if exit_code is None and current_exit is not None:
            exit_code = int(current_exit)
            process_exit_time = now
            _emit(
                status_cb,
                f"Initial sample process exited with code {exit_code}; continuing observation for installer/background activity.",
            )

        if elapsed >= window_seconds:
            still_running = proc.poll() is None

            # The one case where waiting longer can still change the result.
            if (
                can_extend
                and still_running
                and not _observed_activity()
                and window_seconds < max_observation_seconds
            ):
                window_seconds = min(
                    window_seconds + int(observation_extension_seconds),
                    int(max_observation_seconds),
                )
                extensions += 1
                _emit(
                    status_cb,
                    f"Sample is still running and nothing has been observed yet; "
                    f"extending observation to {window_seconds}s "
                    f"(cap {int(max_observation_seconds)}s).",
                )
            else:
                if still_running:
                    try:
                        proc.terminate()
                    except Exception:
                        pass

                if not still_running or not can_extend:
                    ended_because = "window_elapsed"
                elif _observed_activity():
                    ended_because = "window_elapsed_after_activity"
                else:
                    # Still running, still silent, and out of extensions. This
                    # is the case that produces a clean-looking report for a
                    # sample that had simply not started yet.
                    ended_because = "extension_cap_reached"

                return _result(ended_because, elapsed)

        minimum_elapsed = elapsed >= minimum_observation_seconds

        if not installer_observation_mode:
            if exit_code is not None and minimum_elapsed:
                return _result("sample_exited", elapsed)

        if installer_observation_mode and exit_code is not None and minimum_elapsed:
            post_exit_elapsed = 0
            if process_exit_time is not None:
                post_exit_elapsed = int(now - process_exit_time)

            if post_exit_elapsed >= post_exit_observation_seconds:
                _emit(
                    status_cb,
                    f"Post-exit observation completed after {post_exit_elapsed} seconds.",
                )
                return _result("post_exit_observation_complete", elapsed)

        elapsed_int = int(elapsed)
        if elapsed_int % 30 == 0 and elapsed_int != last_notice_second:
            last_notice_second = elapsed_int
            if exit_code is None:
                _emit(
                    status_cb,
                    f"Observation still running... elapsed={elapsed_int}s window={window_seconds}s",
                )
            else:
                post_exit_elapsed = int(now - process_exit_time) if process_exit_time else 0
                _emit(
                    status_cb,
                    f"Post-exit observation still running... elapsed={elapsed_int}s post_exit={post_exit_elapsed}s/{post_exit_observation_seconds}s window={window_seconds}s",
                )

        time.sleep(1)


#: Wall-clock of the previous `_emit`, so every status line can carry how long
#: the step before it took. Module-level because the passes that need timing are
#: spread across a 900-line teardown and threading a timer through all of them
#: would be a bigger change than the problem deserves.
_LAST_EMIT_AT: float | None = None

#: Below this, the elapsed marker is noise -- most lines are instant and a
#: `+0s` on every one of them makes the slow ones harder to spot, not easier.
_EMIT_TIMING_FLOOR_SECONDS = 2.0


#: Where every status line is also written, so the run's narrative survives the
#: window that displayed it. `None` disables the file and leaves `_emit`
#: screen-only, which is what every caller outside a real run wants.
_STATUS_LOG_PATH: "Path | None" = None


def _reset_emit_clock(log_path: "Path | str | None" = None) -> None:
    """Start a fresh timing sequence, optionally teeing status to a file.

    **Why the file exists.** The Output pane is a Tk text widget and nothing
    ever wrote it to disk, so the one artefact that says *which pass ran when*
    died with the window. That cost three runs: `33fe6c3b` stalled with no
    record of where, `eb3e1273` produced five minutes of silence with no record
    of what it was doing, and `fa23508d` was closed before its timings could be
    read. The summary JSON preserves every *result* and none of the *sequence*.

    Written next to `dynamic_run_summary.json` so exporting the case directory
    keeps it -- the same rule the report and the summary already follow.
    """
    global _LAST_EMIT_AT, _STATUS_LOG_PATH
    _LAST_EMIT_AT = None
    _STATUS_LOG_PATH = Path(log_path) if log_path else None
    if _STATUS_LOG_PATH is None:
        return
    try:
        _STATUS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Truncate: one file per run, and a run that restarts should not append
        # to the previous attempt's timings and read as one continuous sequence.
        with _STATUS_LOG_PATH.open("w", encoding="utf-8") as handle:
            handle.write(f"# status log, {datetime.now(timezone.utc).isoformat()}\n")
    except OSError:
        # A log nobody can write is not worth failing a detonation over, and a
        # silent screen-only run is the behaviour that existed before this.
        _STATUS_LOG_PATH = None


def _write_status_line(message: str, at: float) -> None:
    """Append one line to the status log, if a run configured one.

    Timestamped independently of the pane so the file is readable on its own:
    the `[+Ns]` tag says how long a step took, and the wall-clock says when.
    Never raises -- losing the log must not lose the run.
    """
    if _STATUS_LOG_PATH is None:
        return
    try:
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        with _STATUS_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"[{stamp}] {message}\n")
    except OSError:
        pass


def _emit(status_cb: StatusCallback, message: str) -> None:
    """A status line, tagged with how long the previous step took.

    **Why the timing is here rather than at each call site.** Run `33fe6c3b`
    spent 24 of 27 minutes somewhere in teardown and the pane could not say
    where: every pass emits one line when it *starts*, so the slow one is
    identified only by being the last line printed, and a pass that is slow is
    indistinguishable from one that is stuck. Run `eb3e1273` then showed the
    first diagnosis of that -- the module-integrity cache -- was wrong, because
    `modules_compared: 380` was a total across five dumps and not a per-dump
    count that would have thrashed a 96-entry cache.
    
    Guessing twice is enough. Timing `_emit` itself makes the pane a per-pass
    profile for every pass at once, including ones nobody has suspected yet,
    and costs one `perf_counter` call per line.

    The elapsed figure belongs to the step *before* this line, not to this one.
    """
    global _LAST_EMIT_AT
    now = time.perf_counter()
    # Tag before the callback check, not inside it. A headless run has no pane
    # and the file is then the only record there is -- tagging only when
    # somebody is watching would leave exactly that case untimed.
    elapsed = None if _LAST_EMIT_AT is None else now - _LAST_EMIT_AT
    if elapsed is not None and elapsed >= _EMIT_TIMING_FLOOR_SECONDS:
        message = f"{message}   [+{elapsed:.0f}s]"
    if status_cb:
        status_cb(message)
    _write_status_line(message, now)
    _LAST_EMIT_AT = now


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
    
    if not procmon_enabled:
        return {
            "score": score,
            "status": "limited",
            "procmon_total_events": 0,
            "checks": checks,
            "note": "Procmon was disabled by analyst. Process/file/registry/network telemetry was not collected.",
        }

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
    sysmon_summary: dict[str, Any] | None = None,
    network_summary: dict[str, Any] | None = None,
    fakenet_summary: dict[str, Any] | None = None,
    memory_summary: dict[str, Any] | None = None,
    memory_yara_summary: dict[str, Any] | None = None,
) -> dict[str, int]:
    counts = findings_summary.get("counts", {}) if isinstance(findings_summary, dict) else {}
    task_counts = task_diff_summary.get("counts", {}) if isinstance(task_diff_summary, dict) else {}
    service_counts = service_diff_summary.get("counts", {}) if isinstance(service_diff_summary, dict) else {}
    autoruns_counts = autoruns_diff_summary.get("counts", {}) if isinstance(autoruns_diff_summary, dict) else {}

    sysmon = sysmon_summary if isinstance(sysmon_summary, dict) else {}
    network_counts = (
        network_summary.get("counts", {}) if isinstance(network_summary, dict) else {}
    )
    fakenet_counts = (
        fakenet_summary.get("counts", {}) if isinstance(fakenet_summary, dict) else {}
    )
    memory_counts = (
        memory_summary.get("counts", {}) if isinstance(memory_summary, dict) else {}
    )
    memory_yara = memory_yara_summary if isinstance(memory_yara_summary, dict) else {}
    memory_yara_counts = memory_yara.get("counts", {}) or {}

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
        # Sysmon covers the behaviours Procmon cannot see at all.
        "sysmon_total_events": int(sysmon.get("total_events", 0) or 0),
        "sysmon_high_severity": int(sysmon.get("high_severity_count", 0) or 0),
        "sysmon_injection_events": len(sysmon.get("injection_events", []) or []),
        "sysmon_dns_queries": len(sysmon.get("dns_queries", []) or []),
        # Packet capture and simulated internet reveal intent even when the
        # connection never completes.
        "network_dns_queries": int(network_counts.get("dns_queries", 0) or 0),
        "network_http_requests": int(network_counts.get("http_requests", 0) or 0),
        "network_unique_destinations": int(network_counts.get("unique_destinations", 0) or 0),
        "network_unusual_ports": int(network_counts.get("unusual_ports", 0) or 0),
        "fakenet_dns_requests": int(fakenet_counts.get("dns_requests", 0) or 0),
        "fakenet_http_requests": int(fakenet_counts.get("http_requests", 0) or 0),
        # The dump counts are collection coverage: they say what could be
        # scanned, not what the sample did.
        "memory_processes_observed": int(memory_counts.get("processes_observed", 0) or 0),
        "memory_dumps_succeeded": int(memory_counts.get("dumps_succeeded", 0) or 0),
        "memory_dumps_mb": int(memory_counts.get("total_mb", 0) or 0),
        # The YARA counts are the behaviour. memory_only_rules is the one that
        # matters: a payload visible in memory and not on disk.
        "memory_yara_matches": int(memory_yara_counts.get("total_matches", 0) or 0),
        "memory_yara_dumps_matched": int(memory_yara_counts.get("dumps_with_matches", 0) or 0),
        "memory_only_rules": int(memory_yara_counts.get("memory_only_rules", 0) or 0),
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

#: Autorun entries created by the analysis tooling rather than by the sample.
#: Shared with the Sysmon summariser, which has to make the same judgement about
#: driver loads, so the definition lives in utils and this name is kept as the
#: autoruns-facing alias.
ANALYZER_AUTORUN_MARKERS = ANALYZER_TOOL_IMAGE_MARKERS

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


def _is_analyzer_autorun(row: dict[str, str]) -> bool:
    """True when an autorun entry was created by the analysis tooling."""
    haystack = " ".join(
        str(row.get(key, "")) for key in
        ("Entry", "Image Path", "Launch String", "Description", "Company", "Entry Location")
    ).lower()

    if any(marker in haystack for marker in ANALYZER_AUTORUN_MARKERS):
        return True

    # Anything registered out of the workbench's own tools directory.
    tools_dir = str(_default_autorunsc_path().parent).lower()
    return bool(tools_dir and tools_dir in haystack)


def _is_suspicious_autorun(row: dict[str, str]) -> bool:
    signer = row.get("Signer", "").lower()
    company = row.get("Company", "").lower()
    image_path = row.get("Image Path", "").lower()
    launch = row.get("Launch String", "").lower()
    category = row.get("Category", "").lower()
    enabled = row.get("Enabled", "").lower()

    if enabled and enabled not in {"enabled", "true", "yes"}:
        return False

    # An entry that names nothing cannot be evidence of anything. Autoruns emits
    # rows carrying only a category and a location -- section markers, and keys
    # whose value could not be read -- and one of those counted toward
    # `autoruns_suspicious` on the Remcos run, inflating two genuine Run keys to
    # three. It qualified purely by having category "Logon" and no signer, which
    # is true of every blank row.
    if not (row.get("Entry", "").strip() or image_path.strip() or launch.strip()):
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

    all_new_ids = sorted(after_ids - before_ids)
    removed_ids = sorted(before_ids - after_ids)
    common_ids = sorted(before_ids & after_ids)

    # Split the analyzer's own registrations out before anything is counted, so
    # they cannot reach the findings or the score.
    analyzer_ids = [i for i in all_new_ids if _is_analyzer_autorun(after_by_id[i])]
    new_ids = [i for i in all_new_ids if i not in set(analyzer_ids)]

    modified_ids = []
    for entry_id in common_ids:
        if _is_analyzer_autorun(after_by_id[entry_id]):
            continue
        if _autoruns_content_fingerprint(before_by_id[entry_id]) != _autoruns_content_fingerprint(after_by_id[entry_id]):
            modified_ids.append(entry_id)

    new_entries = [_summarize_autorun_row(after_by_id[i]) for i in new_ids]
    analyzer_entries = [_summarize_autorun_row(after_by_id[i]) for i in analyzer_ids]
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
        "analyzer_entries": len(analyzer_entries),
    }

    return {
        "counts": counts,
        "new_entries": new_entries[:100],
        "removed_entries": removed_entries[:100],
        "modified_entries": modified_entries[:100],
        "suspicious_new_entries": suspicious_new[:100],
        "suspicious_modified_entries": suspicious_modified[:100],
        # Kept visible so the tooling registering itself is verifiable rather
        # than silently dropped.
        "analyzer_entries": analyzer_entries[:100],
    }



#: The most that raw activity volume can contribute. Background noise alone
#: moved a score by nine points between two runs of the same control on
#: identical code; anything that noisy has to stay a minority of the total.
MAX_CONTEXT_SCORE = 15

#: Points for a kind of evidence being present at all, and for it being
#: emphatic enough to stand on its own.
CATEGORY_POINTS = 20
STRONG_CATEGORY_BONUS = 15

#: Distinct memory-only rules that make the packed-payload category strong.
#:
#: One rule is the memory canary: a single marker string, built at runtime, and
#: the whole point of that control is that it produces exactly one. Three
#: independent rules agreeing about a payload that was unreadable at rest is a
#: different claim -- mimikatz.upx produced five, live AgentTesla three.
STRONG_MEMORY_ONLY_RULES = 3


def _parse_offsets(value: Any) -> list[int]:
    """Dump offsets from a list or a "5, 15, 20" string.

    The GUI hands this over as text, so a stray comma or a blank entry must
    fall back to the profile default rather than failing the run. Sorted and
    deduplicated because the watcher pops them in order and two identical
    offsets would write two identical images.
    """
    if not value:
        return []

    if isinstance(value, str):
        parts = [p.strip() for p in value.replace(";", ",").split(",")]
    else:
        parts = list(value)

    offsets: set[int] = set()
    for part in parts:
        try:
            seconds = int(str(part).strip())
        except (TypeError, ValueError):
            continue
        if seconds > 0:
            offsets.add(seconds)

    return sorted(offsets)


def _parse_redump_seconds(value: Any) -> int:
    """The spawn re-dump delay, from a number or a GUI text field.

    Unlike the offsets, `0` is meaningful here -- it turns the second dump off
    -- so blank and zero cannot share a fallback. Blank, or anything that is not
    a number, takes the default; a real `0` disables.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return DEFAULT_SPAWN_REDUMP_SECONDS
    try:
        seconds = int(str(value).strip())
    except (TypeError, ValueError):
        return DEFAULT_SPAWN_REDUMP_SECONDS
    return max(0, seconds)


def _sample_process_names(findings_summary: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Process names the lineage filter already attributed to the sample.

    Returns ``(names, windows_response_dropped)``. The second is what lineage
    resolved into the tree correctly and this function then removed, because
    Windows starting a process *in response to* the sample is not the sample
    acting -- see `WINDOWS_RESPONSE_PROCESSES`. Returned rather than discarded so
    the caller can report it: the 06 Aug 21:15 run put WER's `192.0.2.123:443` in
    `sample_destinations`, and a run that quietly removed it would look identical
    to a run where WER never connected.

    Only the *child* of a spawn record: the parent of the first spawn is the
    analyzer's own python.exe, and taking it would attribute the workbench's
    network activity to the sample -- which is the failure this whole function
    exists to avoid.
    """
    findings = findings_summary if isinstance(findings_summary, dict) else {}
    names: set[str] = set()

    # Already lineage-filtered where lineage could be resolved.
    for entry in findings.get("top_network_processes", []) or []:
        name = str(entry.get("process_name", "") or "").strip().lower()
        if name:
            names.add(name)

    # spawned_processes is *not* purely the sample's tree. A LOLBin or an
    # encoded command line is kept as a finding whoever started it, which is
    # right for the report and wrong here: a mimikatz control run listed
    # cmd.exe, reg.exe and rundll32.exe as the sample's processes, all of them
    # Windows' own scheduled maintenance that fired because the observation
    # window ran long. Only descendants count.
    #
    # When lineage could not be resolved nothing carries the flag, and
    # filtering on it would empty the set silently. The findings degrade the
    # same way -- counting everything rather than nothing -- so this does too.
    lineage_resolved = bool(findings.get("lineage_resolved"))
    for entry in findings.get("spawned_processes", []) or []:
        if lineage_resolved and not entry.get("descends_from_sample"):
            continue
        name = str(entry.get("child_process_name", "") or "").strip().lower()
        if name:
            names.add(name)

    dropped = {name for name in names if is_windows_response_process(name)}
    return names - dropped, dropped


def _attributed_connections(
    fakenet_summary: dict[str, Any] | None, sample_names: set[str]
) -> dict[str, Any]:
    """Connection attempts FakeNet's diverter recorded for the sample.

    The diverter names the process behind each connection, which makes it the
    only per-process network attribution a run gets -- the pcap cannot say who
    sent a packet, and on the AgentTesla run it never saw the FTP session at
    all: ``unusual_ports`` was 0 while the diverter had the sample on
    ``:21`` and ``:60009``, the passive data port.

    Everything not attributable to the sample is counted rather than dropped,
    so a run where the diverter saw traffic it could not place is
    distinguishable from one where the sample was quiet.
    """
    fakenet = fakenet_summary if isinstance(fakenet_summary, dict) else {}
    destinations: list[str] = []
    unusual: list[str] = []
    unattributed = 0

    for request in fakenet.get("process_requests", []) or []:
        process = str(request.get("process", "") or "").strip().lower()
        destination = str(request.get("destination", "") or "").strip()
        if process not in sample_names:
            unattributed += 1
            continue
        if destination and destination not in destinations:
            destinations.append(destination)
        _, _, port_text = destination.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            continue
        if port not in COMMON_PORTS and destination not in unusual:
            unusual.append(destination)

    return {
        "destinations": destinations,
        "unusual_ports": unusual,
        "unattributed_requests": unattributed,
    }


def _injection_reason(
    *,
    image_timestamp_mismatch_in_target: int = 0,
    module_header_mismatch_in_target: int = 0,
    unmapped_pe_in_hollowing_target: int = 0,
    hollowing_target_crashes: int = 0,
    image_timestamp_mismatches: int = 0,
    module_header_mismatches: int = 0,
    unmapped_pe_images: int = 0,
    unmapped_memory_crashes: int = 0,
    sysmon_injections: int = 0,
) -> str:
    """Why `process_injection` fired, naming the route that actually fired it.

    Extracted from an inline conditional chain that **had no branch for two of
    the five routes**. `module_header_mismatches` and `image_timestamp_mismatches`
    outside a hollowing target both fell through to the final `else`, which says
    *"Sysmon recorded process injection (CreateRemoteThread)."*

    That is not a cosmetic slip. On run `677547d9` Dridex hollowed a copy of
    itself: 10 `header_mismatch` verdicts, `sysmon_injections` **0**, and the
    card rendered `detail: "0 injection event(s) ..."` directly above
    `reason: "Sysmon recorded process injection"`. The score was right and the
    sentence under it was false, which is worse than saying nothing.

    Ordered strongest first, and the in-target routes lead because they are what
    `strong` rests on. The final line is reachable only when `sysmon_injections`
    is the reason, so it can no longer be reached by a run where Sysmon saw
    nothing.
    """
    if image_timestamp_mismatch_in_target:
        return ("Windows recorded a different image timestamp for a binary "
                "loaders commonly hollow than the file it was started from -- "
                "the process was running something other than its own image.")
    if module_header_mismatch_in_target:
        return ("A loaded module in a binary loaders commonly hollow disagrees "
                "with the file on disk it claims to be.")
    if unmapped_pe_in_hollowing_target:
        return ("A PE image was found in the memory of a binary loaders "
                "commonly hollow, at an address that process's own module list "
                "does not cover -- an executable the loader never mapped.")
    if hollowing_target_crashes:
        return ("A binary loaders commonly hollow, started by the sample, "
                "faulted at an address with no module mapped there -- it was "
                "executing injected code.")
    # Decisive wherever it sits, and no longer conditioned on the process's
    # name: framework assemblies are excluded by their own metadata now, so
    # what reaches this count is an image nothing explains. This is the route
    # that was missing the payload in `SecurityHealthHost.exe`.
    if unmapped_pe_images:
        return ("A PE image is present in process memory at an address no "
                "loaded module covers, and it is not a framework assembly the "
                "process mapped to read -- an executable the loader never "
                "mapped.")
    # The two routes the old chain omitted. Both are real evidence of a hollow;
    # they are only not `strong` because the host is not a binary loaders
    # commonly hollow -- a sample that hollows a copy of itself, which is what
    # four of five samples run so far actually do.
    if image_timestamp_mismatches:
        return ("A running image does not match the file it was started from. "
                "The process is not one loaders commonly hollow, so this is "
                "reported without being treated as decisive on its own.")
    if module_header_mismatches:
        return ("A loaded module disagrees with the file on disk it claims to "
                "be -- a different build at the same base. The process is not "
                "one loaders commonly hollow, so this is reported without being "
                "treated as decisive on its own.")
    if unmapped_memory_crashes:
        return ("A process in the sample's tree faulted at an address with "
                "no module mapped there. In a managed process that can also "
                "be JIT-compiled code, so this is reported without being "
                "treated as decisive on its own.")
    if sysmon_injections:
        return "Sysmon recorded process injection (CreateRemoteThread)."
    # Unreachable while `present` requires one of the five, and stated rather
    # than defaulted: a category that fired for no nameable reason is a bug in
    # the caller, not a sentence to invent.
    return "No injection route reported a finding."


def _evidence_categories(
    *,
    memory_only_rules: list[Any],
    sysmon_injections: int,
    unmapped_memory_crashes: int,
    hollowing_target_crashes: int,
    unmapped_pe_images: int,
    unmapped_pe_in_hollowing_target: int,
    image_timestamp_mismatches: int = 0,
    image_timestamp_mismatch_in_target: int = 0,
    module_header_mismatches: int = 0,
    module_header_mismatch_in_target: int = 0,
    sysmon_high: int,
    suspicious_tasks: int,
    suspicious_services: int,
    autoruns_suspicious: int,
    suspicious_dropped: int,
    notable_domains: int,
    host_domains: int,
    external_destinations: int,
    unusual_ports: int,
    suspicious_scriptblocks: int,
) -> list[dict[str, Any]]:
    """The independent kinds of evidence a run can produce.

    Each entry is one claim about the sample, and they are deliberately
    unequal in kind rather than in weight: "it unpacked something", "it
    injected", "it installed persistence", "it called home". Corroboration
    across them is what the verdict is built on, so a category must fire at
    most once however many events back it -- otherwise a single chatty
    behaviour outvotes three quiet ones and the model is volume-driven again.

    ``present`` is the observation; ``strong`` is the observation being
    emphatic enough that it does not need corroborating.
    """
    persistence_total = suspicious_tasks + suspicious_services + autoruns_suspicious

    return [
        {
            "name": "packed_payload",
            "present": bool(memory_only_rules),
            "strong": len(memory_only_rules) >= STRONG_MEMORY_ONLY_RULES,
            "detail": f"{len(memory_only_rules)} rule(s) matched memory but not disk",
            "reason": (
                "YARA matched in process memory but not on disk "
                f"({', '.join(str(r) for r in memory_only_rules[:3])}), indicating a "
                "payload that was packed or encrypted at rest."
            )
            if memory_only_rules
            else "",
        },
        {
            "name": "process_injection",
            # Sysmon Event 8 is CreateRemoteThread, and process hollowing does
            # not use it -- NtUnmapViewOfSection, WriteProcessMemory and
            # SetThreadContext raise nothing. A Formbook sample hollowed
            # RegSvcs.exe and this category stayed silent, which made
            # "injection has never fired" partly a statement about the
            # detector rather than about the samples.
            #
            # A crash whose faulting module is unknown says code was executing
            # where no image is mapped. That is the same claim by a different
            # route, and it costs nothing: Windows already logged it.
            #
            # Only *strong* when the process is one loaders hollow, though.
            # In a managed process, JIT-compiled code also lives in private
            # allocations with no module mapped, so an ordinary .NET
            # application faulting in its own JITted code produces the same
            # record. The identity of the process is what separates them:
            # nothing legitimate starts RegSvcs.exe and has it fault in
            # anonymous memory.
            #
            # The third route is a PE image sitting in a dump at an address the
            # process's own module list does not cover. It is the same claim
            # again -- code is present that the loader did not map -- and it is
            # deliberately folded in here rather than scored as its own
            # category. A hollow produces the crash and the foreign image from
            # one event, and a category that fires twice for one behaviour is
            # the volume-driven model this design exists to avoid.
            #
            # Its value is that it does not need the payload to crash. Event 25
            # is silent on this technique and the crash route only fires when
            # something faults, so a loader that hollows and runs cleanly was
            # invisible to both.
            # Two further routes, folded in for exactly the reason the carver
            # was: they are the same claim reached differently, and a hollow
            # that fired all five would otherwise outvote three quiet
            # categories on its own.
            #
            # The WER route compares the TimeDateStamp Windows recorded for the
            # *running* image against the file it was started from. It needs no
            # dump at all, which is why it is here: on run d7cc5044 the watcher
            # missed the hollowed child entirely -- it lived 3.03 seconds -- and
            # this was the only route that saw the hollow while it happened.
            #
            # The module-integrity route compares a loaded module's executable
            # sections against its own file. Measured against 300 modules
            # across 12 ordinary programs it produced zero mismatches, so the
            # benign rate behind `strong` here is not a guess.
            #
            # Both are `strong` only in a binary loaders hollow, the same test
            # the other three routes use. The reason is the same too: a
            # long-running process still holding an image that has since been
            # patched on disk produces a legitimate mismatch, and Windows
            # servicing does that to something on every update. A hollowing
            # target is spawned on demand and short-lived, so it cannot have
            # outlived an update -- and nothing legitimate starts RegSvcs.exe.
            "present": (
                sysmon_injections > 0
                or unmapped_memory_crashes > 0
                or unmapped_pe_images > 0
                or image_timestamp_mismatches > 0
                or module_header_mismatches > 0
            ),
            # **The carve route no longer asks whose process it is.** The
            # `hollowing_target` test was a proxy for "this image is
            # unexplained", and it was the wrong proxy twice over. It let run
            # `c14cb5b6` grade **strong** on four framework assemblies inside a
            # legitimately spawned `csc.exe` -- reproduced exactly by a benign
            # `Add-Type`, same four images, same counts -- while the genuine
            # 258 KB payload in `SecurityHealthHost.exe` scored **nothing**,
            # because that LOLBin is not on the list. A sample picks a host
            # precisely because it is not on anyone's list.
            #
            # What made the proxy necessary was benign unmapped images, and
            # `framework_assembly` now removes them at the source, by the
            # image's own metadata rather than by the process's name.
            #
            # **The benign rate behind this, stated as what it is: 16 ordinary
            # processes on one host, zero unmapped PE images.** 12 programs on
            # 13 Aug plus 4 managed applications on 20 Aug. Those sweeps also
            # produced 870 module comparisons, but that number belongs to the
            # module-integrity pass above, not to this one --
            # `benign_baseline.py` reports *this* metric per process, so 16 is
            # the denominator here and 870 is not.
            #
            # **And note what the corpus cannot hold.** Both sweeps are ordinary
            # *running* processes; the one benign case known to produce unmapped
            # images is a *compile*, which cannot be dumped on that host at all
            # (`MiniDumpWriteDump` -> `0x80070005`). Measured in the guest it
            # gave `unmapped` 2 and 4. So this zero says ordinary desktop
            # software does not produce unmapped images -- it does not by itself
            # carry `strong` on any unmapped image anywhere. What answers the
            # compile is `framework_assembly`, not this count.
            #
            # Note the JIT argument does not apply here, only to the crash
            # route below. JITted code is an anonymous allocation; it is not a
            # PE image with a parseable header, so it cannot reach this count.
            "strong": (
                sysmon_injections >= 2
                or hollowing_target_crashes > 0
                or unmapped_pe_images > 0
                or image_timestamp_mismatch_in_target > 0
                or module_header_mismatch_in_target > 0
            ),
            "detail": (
                f"{sysmon_injections} injection event(s), "
                f"{unmapped_memory_crashes} crash(es) in unmapped memory "
                f"({hollowing_target_crashes} in a process loaders hollow), "
                f"{unmapped_pe_images} unmapped PE image(s) in memory "
                f"({unmapped_pe_in_hollowing_target} in a process loaders hollow), "
                f"{image_timestamp_mismatches} running image(s) not matching the "
                f"file on disk ({image_timestamp_mismatch_in_target} in a process "
                f"loaders hollow), "
                f"{module_header_mismatches} loaded module(s) disagreeing with "
                f"their file ({module_header_mismatch_in_target} in a process "
                f"loaders hollow)"
            ),
            "reason": _injection_reason(
                image_timestamp_mismatch_in_target=image_timestamp_mismatch_in_target,
                module_header_mismatch_in_target=module_header_mismatch_in_target,
                unmapped_pe_in_hollowing_target=unmapped_pe_in_hollowing_target,
                hollowing_target_crashes=hollowing_target_crashes,
                image_timestamp_mismatches=image_timestamp_mismatches,
                module_header_mismatches=module_header_mismatches,
                unmapped_pe_images=unmapped_pe_images,
                unmapped_memory_crashes=unmapped_memory_crashes,
                sysmon_injections=sysmon_injections,
            ),
        },
        {
            "name": "credential_access_or_tampering",
            "present": sysmon_high > 0,
            "strong": sysmon_high >= 3,
            "detail": f"{sysmon_high} high-signal Sysmon event(s)",
            "reason": (
                "Sysmon recorded high-signal behaviour (credential access, process "
                "tampering, or WMI persistence)."
            ),
        },
        {
            "name": "persistence_installed",
            "present": persistence_total > 0,
            "strong": persistence_total >= 2,
            "detail": (
                f"{suspicious_tasks} task(s), {suspicious_services} service(s), "
                f"{autoruns_suspicious} autoruns entry(s)"
            ),
            "reason": (
                "A suspicious scheduled task, service or startup entry appeared "
                "that was not present before the run."
            ),
        },
        {
            "name": "payload_dropped",
            "present": suspicious_dropped > 0,
            "strong": suspicious_dropped >= 2,
            "detail": f"{suspicious_dropped} suspicious dropped file(s)",
            "reason": "The sample wrote a file that triages as suspicious.",
        },
        {
            "name": "external_contact",
            # Under FakeNet every destination resolves locally, so the name the
            # sample asked for is the evidence -- not the address it got.
            # Scoring external IPs alone reported the AgentTesla run, which
            # authenticated to its C2 and uploaded stolen data, as having
            # contacted nothing.
            #
            # Both halves are attributed to the sample. The host's own lookups
            # and connections are counted separately and never scored.
            #
            # A connection on a non-standard port makes this present in its own
            # right, and not only strong. A Remcos run dialled a hard-coded
            # 62.60.226.68:24042 with no DNS lookup at all, so notable_domains
            # was 0; FakeNet diverted the connection so the pcap logged none and
            # external_destinations was 0 too. The diverter's per-process record
            # had it, attribution resolved it to the sample's own smng.exe, and
            # `sample_unusual_ports` named it exactly -- and then the category
            # never fired, because `strong` is only ever consulted for a
            # category that is already present. A C2 contact the pipeline
            # watched, attributed and flagged scored nothing, and the run landed
            # a whole verdict band low.
            "present": (
                notable_domains > 0
                or external_destinations > 0
                or unusual_ports > 0
            ),
            "strong": unusual_ports > 0,
            "detail": (
                f"{notable_domains} non-baseline domain(s) from the sample, "
                f"{external_destinations} external destination(s), "
                f"{unusual_ports} connection(s) on a non-standard port "
                f"({host_domains} further non-baseline lookup(s) by other "
                f"processes, not scored)"
            ),
            "reason": (
                "The sample resolved or connected to a destination that is not "
                "part of the Windows baseline."
            ),
        },
        {
            "name": "scripted_execution",
            "present": suspicious_scriptblocks > 0,
            "strong": suspicious_scriptblocks >= 2,
            "detail": f"{suspicious_scriptblocks} suspicious script block(s)",
            "reason": "PowerShell executed script text that triages as suspicious.",
        },
    ]


def calculate_dynamic_score(
    findings_summary: dict[str, Any],
    task_diff_summary: dict[str, Any],
    service_diff_summary: dict[str, Any],
    dropped_files_summary: dict[str, Any],
    autoruns_diff_summary: dict[str, Any] | None = None,
    sysmon_summary: dict[str, Any] | None = None,
    network_summary: dict[str, Any] | None = None,
    fakenet_summary: dict[str, Any] | None = None,
    memory_yara_summary: dict[str, Any] | None = None,
    powershell_summary: dict[str, Any] | None = None,
    crash_summary: dict[str, Any] | None = None,
    pe_carve_summary: dict[str, Any] | None = None,
    module_integrity_summary: dict[str, Any] | None = None,
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

    sysmon = sysmon_summary if isinstance(sysmon_summary, dict) else {}
    network_counts = (
        network_summary.get("counts", {}) if isinstance(network_summary, dict) else {}
    )
    fakenet_counts = (
        fakenet_summary.get("counts", {}) if isinstance(fakenet_summary, dict) else {}
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

    sysmon_injections = len(sysmon.get("injection_events", []) or [])
    sysmon_high = int(sysmon.get("high_severity_count", 0) or 0)

    memory_yara = memory_yara_summary if isinstance(memory_yara_summary, dict) else {}
    memory_yara_counts = memory_yara.get("counts", {}) or {}
    memory_only_rules = list(memory_yara.get("memory_only_rules", []) or [])
    memory_yara_matches = int(memory_yara_counts.get("total_matches", 0) or 0)

    network_unusual_ports = int(network_counts.get("unusual_ports", 0) or 0)
    fakenet_dns = int(fakenet_counts.get("dns_requests", 0) or 0)

    # A capture records the whole host. Scoring raw domain and request counts
    # charges the sample for Windows' own certificate-revocation and telemetry
    # traffic, so only non-baseline indicators count toward the score.
    ioc_counts = (
        network_summary.get("iocs", {}).get("counts", {})
        if isinstance(network_summary, dict) and isinstance(network_summary.get("iocs"), dict)
        else {}
    )
    if ioc_counts:
        network_destinations = int(ioc_counts.get("external_ips", 0) or 0)
        network_http = int(ioc_counts.get("notable_urls", 0) or 0)
    else:
        network_destinations = int(network_counts.get("unique_destinations", 0) or 0)
        network_http = int(network_counts.get("http_requests", 0) or 0)

    # Which domains *the sample* asked for.
    #
    # Not FakeNet's log and not the pcap: both record the whole host. A single
    # AgentTesla run had ten names in the FakeNet log, nine of them Windows' own
    # -- telemetry, Edge, PTR lookups -- while OneDrive, M365Copilot and
    # msedgewebview2 all connected during the window. Those nine happened to
    # classify as baseline, so the count came out right by luck; one
    # non-baseline lookup by any of those processes would have scored as the
    # sample's C2 contact.
    #
    # Sysmon's DNS list is attributed and already has analyzer and noise
    # lookups removed, which makes it the only honest source here. This is the
    # same rule the findings already follow: attribute by lineage or by
    # requesting process, never by a list of everything else.
    sysmon_domains = [
        name
        for name in (sysmon.get("dns_queries", []) or [])
        if not is_baseline_domain(name) and not is_local_discovery_domain(name)
    ]
    notable_domains = len(set(sysmon_domains))

    # Everything the host asked for that was *not* the sample's, kept so a run
    # that could not attribute is distinguishable from a quiet one.
    host_domains = len(
        {
            name
            for name in (
                (fakenet_summary or {}).get("dns_requests", [])
                if isinstance(fakenet_summary, dict)
                else []
            )
            if not is_baseline_domain(name) and not is_local_discovery_domain(name)
        }
    ) - notable_domains

    sample_names, windows_response_names = _sample_process_names(findings_summary)
    attributed = _attributed_connections(fakenet_summary, sample_names)

    powershell = powershell_summary if isinstance(powershell_summary, dict) else {}
    suspicious_scriptblocks = int(
        (powershell.get("counts", {}) or {}).get("blocks_suspicious", 0) or 0
    )

    crashes = crash_summary if isinstance(crash_summary, dict) else {}
    unmapped_memory_crashes = int(
        (crashes.get("counts", {}) or {}).get("crashes_in_unmapped_memory", 0) or 0
    )
    hollowing_target_crashes = int(
        (crashes.get("counts", {}) or {}).get("crashes_in_hollowing_target", 0) or 0
    )

    carved = pe_carve_summary if isinstance(pe_carve_summary, dict) else {}
    carve_counts = carved.get("counts", {}) or {}
    unmapped_pe_images = int(carve_counts.get("unmapped_images", 0) or 0)
    unmapped_pe_in_hollowing_target = int(
        carve_counts.get("unmapped_in_hollowing_target", 0) or 0
    )

    # The WER route. `available` is checked rather than the count alone: a run
    # that could compare nothing must not read the same as one that compared
    # and agreed.
    stamps = (crashes.get("image_timestamps", {}) or {})
    stamp_counts = stamps.get("counts", {}) or {}
    image_timestamp_mismatches = (
        int(stamp_counts.get("mismatch", 0) or 0) if stamps.get("available") else 0
    )
    image_timestamp_mismatch_in_target = (
        int(stamp_counts.get("mismatch_in_hollowing_target", 0) or 0)
        if stamps.get("available") else 0
    )

    # The module-integrity route, same contract.
    integrity = module_integrity_summary if isinstance(module_integrity_summary, dict) else {}
    integrity_counts = integrity.get("counts", {}) or {}
    module_header_mismatches = (
        int(integrity_counts.get("header_mismatch", 0) or 0)
        if integrity.get("available") else 0
    )
    module_header_mismatch_in_target = (
        int(integrity.get("header_mismatch_in_hollowing_target", 0) or 0)
        if integrity.get("available") else 0
    )

    # --- Context: how busy the run was ------------------------------------
    #
    # Volume is not evidence. Two runs of the same control produced scores nine
    # points apart on identical code, purely from background noise, so this is
    # clamped as a whole: it can colour a verdict but it must never set one.
    context_score = 0
    context_score += min(interesting_events, 10)
    context_score += min(process_creates, 10)
    context_score += min(network_events, 10)
    context_score += min(file_write_events, 10)
    context_score += min(suspicious_path_hits, 10) * 2
    context_score += min(persistence_hits, 10) * 3
    context_score += min(lolbin_processes, 3) * 2
    context_score += min(autoruns_new, 5)
    context_score += min(autoruns_modified, 5)
    context_score += min(memory_yara_matches, 10)
    context_score += min(network_destinations, 10)
    context_score += min(network_http, 10)
    context_score += min(fakenet_dns, 10)
    context_score = min(context_score, MAX_CONTEXT_SCORE)

    # --- Evidence: what the sample was actually seen to do -----------------
    categories = _evidence_categories(
        memory_only_rules=memory_only_rules,
        sysmon_injections=sysmon_injections,
        unmapped_memory_crashes=unmapped_memory_crashes,
        hollowing_target_crashes=hollowing_target_crashes,
        unmapped_pe_images=unmapped_pe_images,
        unmapped_pe_in_hollowing_target=unmapped_pe_in_hollowing_target,
        image_timestamp_mismatches=image_timestamp_mismatches,
        image_timestamp_mismatch_in_target=image_timestamp_mismatch_in_target,
        module_header_mismatches=module_header_mismatches,
        module_header_mismatch_in_target=module_header_mismatch_in_target,
        sysmon_high=sysmon_high,
        suspicious_tasks=suspicious_tasks,
        suspicious_services=suspicious_services,
        autoruns_suspicious=autoruns_suspicious,
        suspicious_dropped=suspicious_dropped,
        notable_domains=notable_domains,
        host_domains=max(host_domains, 0),
        external_destinations=network_destinations,
        # The diverter's per-process record, not the pcap's host-wide count.
        # The pcap missed the AgentTesla FTP session entirely.
        unusual_ports=len(attributed["unusual_ports"]) or network_unusual_ports,
        suspicious_scriptblocks=suspicious_scriptblocks,
    )

    present = [c for c in categories if c["present"]]
    strong = [c for c in present if c["strong"]]

    score = context_score
    score += len(present) * CATEGORY_POINTS
    score += len(strong) * STRONG_CATEGORY_BONUS

    # --- Verdict: corroboration, not volume --------------------------------
    #
    # The old model banded on the total, and the total could not tell a benign
    # canary (24) from live AgentTesla (60) from packed mimikatz (69): all three
    # landed in Needs Review / Medium, and High at >120 was unreachable. What
    # separates them is not how much they did but how many independent kinds of
    # evidence agree, and how emphatic each one is.
    #
    # One weak category is a single unexplained observation -- exactly what the
    # memory canary is built to produce, and it must stay at Medium so that
    # control keeps its meaning. Two agreeing categories, or one emphatic
    # enough to stand alone, is a finding.
    if not present:
        severity = "Low"
        verdict = "Low Suspicion" if score > 10 else "Benign / Clean Baseline"
    elif len(present) == 1 and not strong:
        severity = "Medium"
        verdict = "Needs Review"
    elif len(present) >= 3 or len(strong) >= 2:
        severity = "High"
        verdict = "Likely Malicious"
    else:
        severity = "High"
        verdict = "Elevated Attention"

    # Retained under their original names: the report and the controls read
    # these. The floor is now the single-category case -- one decisive
    # observation with nothing corroborating it -- which is what the old
    # qualitative escalation was reaching for.
    floor_applied = severity == "Medium" and bool(present)
    floor_reason = present[0]["reason"] if floor_applied else ""

    return {
        "score": score,
        "severity": severity,
        "verdict": verdict,
        "context_score": context_score,
        "evidence_categories": present,
        "evidence_counts": {
            "categories_present": len(present),
            "categories_strong": len(strong),
        },
        # What was attributed to the sample versus what the host did anyway.
        # Kept because a scorer that quietly reads host-wide telemetry is
        # indistinguishable from one that does not, until a sample proves it.
        "network_attribution": {
            "sample_processes": sorted(sample_names),
            "sample_domains": sorted(set(sysmon_domains)),
            "sample_destinations": attributed["destinations"],
            "sample_unusual_ports": attributed["unusual_ports"],
            "other_process_requests": attributed["unattributed_requests"],
            "other_non_baseline_domains": max(host_domains, 0),
            # Removed from the sample's set after lineage put them there, and
            # named rather than counted: WER connecting to report the sample's own
            # crash is not the sample reaching a C2, and the two must not read
            # alike. Their requests fall into other_process_requests above.
            "windows_response_processes": sorted(windows_response_names),
        },
        "severity_floor_applied": floor_applied,
        "severity_floor_reason": floor_reason,
        "score_model": "dynamic-corroboration-v3",
        "score_notes": [
            "The verdict comes from how many independent kinds of evidence agree, "
            "not from the total. Volume is capped at "
            f"{MAX_CONTEXT_SCORE} points so background noise cannot move a band.",
            "One kind of evidence on its own is Medium / Needs Review. That is "
            "deliberately where the benign memory canary lands, and it is the "
            "band a single unexplained observation belongs in.",
            "A category counts as strong when it is emphatic in its own right: "
            f"{STRONG_MEMORY_ONLY_RULES}+ distinct rules matching memory but not "
            "disk, a connection to a non-standard port, repeat injection, or a "
            "crash inside a binary loaders hollow. One strong category, or two "
            "of any kind, reaches High.",
            "Three agreeing categories, or two strong ones, is Likely Malicious. "
            "Nothing a legitimate installer does produces that combination.",
            "Absence of a category means it was not observed, which is not the "
            "same as it not happening. Check the telemetry coverage and any "
            "warnings before reading a low verdict as a clean one.",
        ],
    }

def run_dynamic_analysis(
    config: dict[str, Any],
    status_cb: StatusCallback = None,
    cancel_event: CancelEvent = None,
) -> dict[str, Any]:
    # Fresh timing sequence, so the first line of a run is not tagged with the
    # gap since whatever ran before it.
    _reset_emit_clock()
    sample_path = Path(config["sample_path"])
    root_case_dir = Path(config["case_dir"])
    timeout_seconds = int(config.get("timeout_seconds", 180))
    
    minimum_observation_seconds = int(config.get("minimum_observation_seconds", 30))
    post_exit_observation_seconds = int(config.get("post_exit_observation_seconds", 120))
    installer_observation_mode = bool(config.get("installer_observation_mode", True))

    # The base window above is a guess about dormancy, and dormancy is not a
    # property of the sample: one AgentTesla binary sat quiet for between 21 and
    # 83 seconds across six runs of the same file.
    #
    # The cap is *total* observation, not extra: the window starts at
    # timeout_seconds and grows toward this. So it has to clear the sleep being
    # outlasted with room to watch what happens afterwards. 600s covers the
    # five-minute evasion sleep this exists for and leaves five minutes to
    # observe the wake; a 300s cap would buy four extension steps and could not
    # catch that sleep at all.
    #
    # It only ever applies to a sample still running and still silent. Anything
    # that exits, or spawns, ends on the normal path, so a high cap costs
    # nothing on a run that goes normally.
    #
    # Where it does cost is a sample that is resident by design. A mimikatz
    # control sat at its interactive prompt -- alive and childless, which the
    # probe cannot distinguish from a crypter asleep -- and ran to the full cap
    # for nothing: 1148s against 271s on a fixed window. That is what the
    # per-run switch is for, and both control READMEs say to turn it off.
    # Lowering the cap is the wrong lever; it penalises the real samples this
    # is meant to catch without fixing the resident case.
    adaptive_observation = bool(config.get("adaptive_observation", True))
    max_observation_seconds = max(
        int(config.get("max_observation_seconds", 600)), timeout_seconds
    )
    observation_extension_seconds = int(config.get("observation_extension_seconds", 30))

    run_profile = str(config.get("run_profile", "standard") or "standard").strip().lower()
    if run_profile not in {"quick", "standard", "deep"}:
        run_profile = "standard"

    run_id = str(config.get("run_id") or uuid.uuid4())
    test_name = str(config.get("test_name") or sample_path.stem or "dynamic_test")

    # Create separate folder per test run.
    run_case_dir = _build_run_case_dir(root_case_dir, run_id=run_id, test_name=test_name)

    _emit(status_cb, f"Preparing case folders in run directory: {run_case_dir}")
    paths = build_case_paths(run_case_dir)

    run_config_path = paths["metadata"] / "run_config.json"
    sample_info_path = paths["metadata"] / "sample_info.json"
    run_summary_path = paths["metadata"] / "dynamic_run_summary.json"

    # From here on every status line is also written to disk. Done as soon as
    # the case directory exists rather than at the top of the run, because the
    # path is what makes the log exportable -- the handful of lines before this
    # are setup and carry no timings worth keeping.
    _reset_emit_clock(paths["metadata"] / "status.log")

    procmon_enabled = bool(config.get("procmon_enabled", False))
    procmon_path = config.get("procmon_path")
    procmon_config_path = config.get("procmon_config_path")

    # Read here rather than at capture start so a run that never gets that far
    # still records which filter it would have used.
    procmon_filter = describe_procmon_filter(procmon_config_path)

    procmon_backing = paths["procmon"] / "raw.pml"
    procmon_csv = paths["procmon"] / "export.csv"
    procmon_json = paths["procmon"] / "parsed_events.json"
    procmon_interesting_json = paths["procmon"] / "interesting_events.json"
    vm_artifact_reads_json = paths["procmon"] / "vm_artifact_reads.json"
    vm_check_bail_json = paths["procmon"] / "vm_check_and_bail.json"
    ntdll_unhooking_json = paths["procmon"] / "ntdll_unhooking.json"

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

    # --- Tier 1 telemetry: Sysmon, packet capture, simulated internet -------
    sysmon_enabled = bool(config.get("sysmon_enabled", True))
    sysmon_path = config.get("sysmon_path") or ""
    sysmon_evtx = paths["sysmon"] / "sysmon_events.evtx"
    sysmon_events_json = paths["sysmon"] / "sysmon_events.json"
    sysmon_summary_json = paths["sysmon"] / "sysmon_summary.json"
    powershell_blocks_json = paths["sysmon"] / "powershell_scriptblocks.json"

    pcap_enabled = bool(config.get("pcap_enabled", True))
    dumpcap_path = config.get("dumpcap_path") or ""
    network_interface = config.get("network_interface") or ""
    capture_filter = config.get("capture_filter") or ""
    pcap_file = paths["network"] / "capture.pcapng"
    network_summary_json = paths["network"] / "network_summary.json"
    network_iocs_json = paths["network"] / "network_iocs.json"

    fakenet_enabled = bool(config.get("fakenet_enabled", False))
    fakenet_path = config.get("fakenet_path") or ""
    fakenet_config_path = config.get("fakenet_config_path") or ""
    fakenet_summary_json = paths["network"] / "fakenet_summary.json"

    # --- Tier 2 telemetry: process memory dumps -----------------------------
    memory_dump_enabled = bool(config.get("memory_dump_enabled", True))
    procdump_path = config.get("procdump_path") or ""
    memory_dumps_json = paths["memory"] / "memory_dumps.json"

    # Offsets are seconds after the sample launches.
    #
    # Every profile opens with an early dump. The later offsets are where an
    # unpacked payload is actually expected, but a loader that unpacks, injects
    # and exits within a few seconds is gone before any of them come due -- and
    # the exit trigger cannot save it, because by the time the exit is detected
    # the process is no longer readable. A first detonation showed exactly this:
    # the launched process exited at ~1s and only a surviving child was ever
    # dumped. The early dump is pre-unpacking and mediocre on its own; it is the
    # difference between a mediocre image and none at all.
    # No set of offsets is right for every family, which is why they are
    # overridable per run. Formbook spawned its hollowing target at +20s and
    # exited immediately after, so standard's [5, 25] bracketed the entire
    # interesting window: the sample was captured once, at +5s, before it had
    # unpacked anything, and never again. Two runs produced nine dumps and no
    # image of the sample at the moment that mattered.
    default_offsets = {
        "quick": [4, 15],
        "standard": [5, 25],
        "deep": [3, 20, 60],
    }[run_profile]
    memory_dump_offsets = _parse_offsets(config.get("memory_dump_offsets")) or default_offsets

    # The guard rails, overridable for the same reason. The process cap in
    # particular is a property of the chain being analysed, not of the tool.
    memory_max_processes = int(
        config.get("memory_dump_max_processes") or DEFAULT_MAX_PROCESSES
    )
    memory_max_working_set_mb = int(
        config.get("memory_dump_max_working_set_mb") or DEFAULT_MAX_WORKING_SET_MB
    )
    memory_max_total_mb = int(
        config.get("memory_dump_max_total_mb") or DEFAULT_MAX_TOTAL_MB
    )

    # Seconds after a child appears to dump it a second time. Measured from the
    # spawn rather than from launch, because what it is waiting for -- a loader
    # unmapping its child and writing a payload into it -- happens on the
    # child's clock, while dormancy before the spawn varies run to run.
    # `0` disables it. See DEFAULT_SPAWN_REDUMP_SECONDS for why 10.
    memory_spawn_redump_seconds = _parse_redump_seconds(
        config.get("memory_dump_spawn_redump_seconds")
    )

    # A crashing descendant is the case the scheduled offsets cannot cover: a
    # hollowed process that lives four seconds falls between them, and the
    # crash dump is taken at the one moment the payload is both written and
    # running.
    # Containment. allow_uncontained is deliberately not exposed in the GUI:
    # detonating with a live network path should take a deliberate edit rather
    # than a checkbox somebody can leave ticked.
    allow_uncontained = bool(config.get("allow_uncontained", False))
    contained_gateway = str(config.get("contained_gateway", "") or "").strip()

    crash_evidence_enabled = bool(config.get("crash_evidence_enabled", True))
    crash_dumps_json = paths["memory"] / "crash_dumps.json"
    crash_events_json = paths["sysmon"] / "crash_events.json"

    memory_yara_enabled = bool(config.get("memory_yara_enabled", True))
    yara_rules_dir = config.get("yara_rules_dir") or ""
    memory_yara_timeout = int(config.get("memory_yara_timeout_seconds", 300))
    memory_yara_json = paths["memory"] / "memory_yara.json"

    # Structure rather than signature: a PE image at an address no module covers
    # was not mapped by the loader. It is the one question a dump answers that
    # YARA cannot, and it does not need anyone to have written a rule for the
    # family -- the 05 Aug payload matched nothing in the set and was still
    # conclusive from its headers alone.
    pe_carve_enabled = bool(config.get("pe_carve_enabled", True))
    pe_carve_json = paths["memory"] / "carved_pe.json"
    pe_carve_dir = paths["memory"] / "carved"
    module_integrity_enabled = bool(config.get("module_integrity_enabled", True))
    module_integrity_json = paths["memory"] / "module_integrity.json"

    # Preflight so the report records exactly which telemetry was possible.
    sysmon_preflight = sysmon_status(sysmon_path) if sysmon_enabled else {
        "available": False, "note": "Sysmon collection disabled for this run."
    }
    pcap_preflight = capture_status(dumpcap_path) if pcap_enabled else {
        "available": False, "note": "Packet capture disabled for this run."
    }
    fakenet_preflight = fakenet_status(fakenet_path) if fakenet_enabled else {
        "available": False, "note": "Simulated internet disabled for this run."
    }
    memory_preflight = memory_dump_status(procdump_path) if memory_dump_enabled else {
        "available": False, "note": "Process memory dumps disabled for this run."
    }
    memory_yara_preflight = (
        memory_yara_status(yara_rules_dir or None)
        if (memory_dump_enabled and memory_yara_enabled)
        else {"available": False, "note": "Memory YARA scanning disabled for this run."}
    )
    crash_dump_preflight = wer_local_dump_status() if crash_evidence_enabled else {
        "available": False, "note": "Crash evidence collection disabled for this run."
    }
    if crash_evidence_enabled and not crash_dump_preflight.get("available"):
        _emit(status_cb, f"Crash dumps: {crash_dump_preflight.get('note', '')}")

    # Containment check. A second adapter lets a sample bypass FakeNet entirely
    # and reach real infrastructure, and nothing in the resulting artifacts
    # would say so, hence checking before the sample is ever launched.
    isolation = network_isolation_status(
        dumpcap_path or None, contained_gateway=contained_gateway
    )
    if isolation.get("level") != "ok":
        _emit(status_cb, f"CONTAINMENT WARNING: {isolation.get('note', '')}")
        for path in isolation.get("egress", []):
            _emit(
                status_cb,
                f"  egress: {path.get('adapter') or '?'} "
                f"({path.get('interface_ip')} -> {path.get('gateway')}) "
                f"[{path.get('reaches', '?')}]",
            )
    else:
        _emit(status_cb, f"Network isolation: {isolation.get('note', '')}")

    # Refused, not warned about.
    #
    # This used to emit the line above and launch anyway, which made the
    # containment control a piece of documentation: WORKFLOW says "do not
    # detonate anything in the armed state" and nothing enforced it. A test
    # detonation run while armed produced no prompt, no dialog and no abort --
    # exactly the silent failure the warning text describes.
    #
    # Deliberately raised before any telemetry starts, so there is nothing to
    # tear down and nothing half-collected to interpret.
    if isolation.get("level") == "uncontained" and not allow_uncontained:
        raise ContainmentError(
            f"{isolation.get('note', 'The guest is not contained.')} "
            "Refusing to launch the sample. Set allow_uncontained in the run "
            "config if you intend to detonate with a live network path."
        )
    if isolation.get("level") == "uncontained" and allow_uncontained:
        _emit(
            status_cb,
            "PROCEEDING UNCONTAINED because allow_uncontained was set. The "
            "sample can reach real infrastructure, and every network finding "
            "below describes live traffic.",
        )

    sysmon_summary: dict[str, Any] = {}
    powershell_preflight: dict[str, Any] = {}
    powershell_summary: dict[str, Any] = empty_powershell_summary("not collected")
    sysmon_status_result: dict[str, Any] = {"success": False, "error": "not run"}
    network_summary: dict[str, Any] = {}
    network_iocs: dict[str, Any] = {}
    fakenet_summary: dict[str, Any] = {}
    pcap_start_result: dict[str, Any] = {"started": False}
    pcap_stop_result: dict[str, Any] = {}
    fakenet_start_result: dict[str, Any] = {"started": False}
    fakenet_stop_result: dict[str, Any] = {}

    crash_summary: dict[str, Any] = empty_crash_summary("not collected")
    abnormal_termination: dict[str, Any] = {"chain_crashed": False}
    vm_artifact_reads: dict[str, Any] = empty_vm_artifact_reads("not collected")
    vm_check_bail: dict[str, Any] = empty_vm_check_correlation("not collected")
    ntdll_unhooking: dict[str, Any] = empty_ntdll_unhooking("not collected")
    crash_dump_result: dict[str, Any] = {"collected": False, "note": "not collected"}
    crash_collector: CrashDumpCollector | None = None
    # Shared by the crash-event and crash-dump collectors below. Seeded with
    # the sample's own name so a run whose Sysmon lineage came back empty can
    # still attribute the obvious case.
    crash_names: set[str] = {sample_path.name.lower()}
    # The sample's process tree, shared by the crash-event and crash-dump
    # collectors. Declared here so the dump collector still has it when crash
    # evidence is disabled -- and passed to *both*, which it was not: the dump
    # collector attributed by name only, so a crash dump of the sample's own
    # child reported attributed_to_sample: false. See CrashDumpCollector.collect.
    crash_pids: set[int] | None = None

    memory_dump_result: dict[str, Any] = {}
    memory_summary: dict[str, Any] = {}
    memory_start_result: dict[str, Any] = {"started": False}
    memory_yara_result: dict[str, Any] = {}
    memory_yara_summary: dict[str, Any] = {}
    pe_carve_result: dict[str, Any] = {}
    pe_carve_summary: dict[str, Any] = {}
    module_integrity_result: list[dict[str, Any]] = []
    module_integrity_summary: dict[str, Any] = {}

    sysmon_since: str = ""
    packet_capture: PacketCapture | None = None
    fakenet_session: FakeNetSession | None = None
    memory_session: MemoryDumpSession | None = None

    started_at = utc_now_iso()
    exit_code: int | None = None

    # Pre-seeded so a run cancelled or failed before launch still describes its
    # observation window rather than omitting the field entirely.
    observation: dict[str, Any] = {
        "exit_code": -1,
        "sample_exited": False,
        "elapsed_seconds": 0,
        "base_window_seconds": timeout_seconds,
        "window_seconds": timeout_seconds,
        "max_observation_seconds": max_observation_seconds,
        "adaptive_observation": adaptive_observation,
        "adaptive_available": False,
        "extensions": 0,
        "extended": False,
        "activity_observed": False,
        "ended_because": "not observed",
    }

    sample_info: dict[str, Any] = {}
    procmon_summary: dict[str, int] = {}
    procmon_interesting_summary: dict[str, int] = {}
    dropped_files_summary: dict[str, int] = {}
    dropped_files: list[dict[str, Any]] = []
    findings_summary: dict[str, Any] = {}
    task_diff_summary: dict[str, Any] = {}
    service_diff_summary: dict[str, Any] = {}
    autoruns_diff_summary: dict[str, Any] = {}

    autoruns_before_status: dict[str, Any] = {
        "enabled": autoruns_enabled,
        "success": False,
        "error": "not run",
    }
    autoruns_after_status: dict[str, Any] = {
        "enabled": autoruns_enabled,
        "success": False,
        "error": "not run",
    }

    tasks_before: Any = []
    services_before: Any = []
    tasks_status: dict[str, Any] = {"success": False, "method": "", "error": "not run"}
    services_status: dict[str, Any] = {"success": False, "method": "", "error": "not run"}

    procmon_started = False
    sample_launch_attempted = False
    cancelled = False
    cancellation_reason = ""

    # Populated by the launch callback. A dict rather than a plain int because
    # the callback assigns from an inner scope.
    sample_pid_seen: dict[str, int] = {}

    try:
        _raise_if_cancelled(cancel_event)

        _emit(status_cb, "Writing run configuration...")
        stored_config = dict(config)
        stored_config["resolved_run_case_dir"] = str(run_case_dir)
        stored_config["run_id"] = run_id
        stored_config["run_profile"] = run_profile
        stored_config["test_name"] = test_name
        write_json(run_config_path, stored_config)

        _raise_if_cancelled(cancel_event)

        _emit(status_cb, "Collecting sample hashes and metadata...")
        sample_info = collect_sample_info(sample_path)
        write_json(sample_info_path, sample_info)

        _raise_if_cancelled(cancel_event)

        _emit(status_cb, "Snapshotting scheduled tasks (before)...")
        tasks_before, tasks_status = snapshot_scheduled_tasks_with_status()
        write_json(tasks_before_json, tasks_before)
        if not tasks_status.get("success"):
            _emit(
                status_cb,
                f"Scheduled task snapshot unavailable: {tasks_status.get('error', 'unknown error')}",
            )
        elif tasks_status.get("fallback_used"):
            _emit(
                status_cb,
                f"Scheduled tasks collected via {tasks_status.get('method')} "
                "(the CIM provider was unavailable).",
            )

        _raise_if_cancelled(cancel_event)

        _emit(status_cb, "Snapshotting services (before)...")
        services_before, services_status = snapshot_services_with_status()
        write_json(services_before_json, services_before)
        if not services_status.get("success"):
            _emit(
                status_cb,
                f"Service snapshot unavailable: {services_status.get('error', 'unknown error')}",
            )
        elif services_status.get("fallback_used"):
            _emit(
                status_cb,
                f"Services collected via {services_status.get('method')} "
                "(the CIM provider was unavailable).",
            )

        _raise_if_cancelled(cancel_event)

        if autoruns_enabled:
            _emit(status_cb, "Snapshotting Autoruns entries (before)...")
            autoruns_before_status = _run_autorunsc_snapshot(
                autorunsc_path=autorunsc_path,
                output_csv=autoruns_before_csv,
                deep_scan=autoruns_deep_scan,
                timeout_seconds=autoruns_timeout_seconds,
            )
            if not autoruns_before_status.get("success"):
                _emit(
                    status_cb,
                    f"Autoruns before snapshot warning: {autoruns_before_status.get('error', 'unknown error')}",
                )
        else:
            _emit(status_cb, "Autoruns snapshot disabled.")

        # Autorunsc cannot be interrupted from here once subprocess.run is
        # already inside _run_autorunsc_snapshot, but cancellation is honored
        # immediately after that snapshot returns.
        _raise_if_cancelled(cancel_event)

        # Start order matters. FakeNet installs a traffic diverter and must be
        # in place before anything connects; the packet capture then records
        # the diverted traffic; Sysmon's window opens last so it contains as
        # little analyzer setup noise as possible.
        if fakenet_enabled:
            if fakenet_preflight.get("available"):
                _emit(status_cb, "Starting simulated internet (FakeNet-NG)...")
                fakenet_session = FakeNetSession(
                    output_dir=paths["network"],
                    fakenet_path=fakenet_path or None,
                    config_path=fakenet_config_path or None,
                )
                fakenet_start_result = fakenet_session.start()
                if not fakenet_start_result.get("started"):
                    _emit(
                        status_cb,
                        f"FakeNet-NG warning: {fakenet_start_result.get('error', 'unknown error')}",
                    )
                    fakenet_session = None
            else:
                _emit(status_cb, f"Simulated internet unavailable: {fakenet_preflight.get('note', '')}")

        _raise_if_cancelled(cancel_event)

        if pcap_enabled:
            if pcap_preflight.get("available"):
                _emit(status_cb, "Starting packet capture...")
                packet_capture = PacketCapture(
                    output_path=pcap_file,
                    interface=network_interface or None,
                    dumpcap_path=dumpcap_path or None,
                    capture_filter=capture_filter,
                )
                pcap_start_result = packet_capture.start()
                if pcap_start_result.get("started"):
                    _emit(
                        status_cb,
                        f"Packet capture running on {pcap_start_result.get('interface', 'default interface')} "
                        f"via {pcap_start_result.get('backend', '?')}.",
                    )
                else:
                    _emit(
                        status_cb,
                        f"Packet capture warning: {pcap_start_result.get('error', 'unknown error')} "
                        "(capture needs Administrator rights).",
                    )
                    packet_capture = None
            else:
                _emit(status_cb, f"Packet capture unavailable: {pcap_preflight.get('note', '')}")

        _raise_if_cancelled(cancel_event)

        if sysmon_enabled:
            if sysmon_preflight.get("available"):
                sysmon_since = sysmon_mark_start()
                _emit(status_cb, f"Sysmon collection window opened at {sysmon_since}.")
            else:
                _emit(status_cb, f"Sysmon unavailable: {sysmon_preflight.get('note', '')}")

        _raise_if_cancelled(cancel_event)

        if procmon_enabled:
            _emit(status_cb, "Starting Procmon capture...")
            # Said out loud at launch rather than only in the summary. A filter
            # that cannot see the thing a run was set up to look for is worth
            # knowing about now, not after the teardown.
            if not procmon_filter.get("captures_registry_reads"):
                _emit(status_cb, f"Procmon filter: {procmon_filter.get('note', '')}")
            start_procmon_capture(
                procmon_path=procmon_path,
                backing_file=procmon_backing,
                config_path=procmon_config_path if procmon_config_path else None,
            )
            procmon_started = True

        _raise_if_cancelled(cancel_event)

        # The watcher must be running before the sample launches, because it is
        # handed the PID the moment Popen returns and the earliest dump offset
        # is measured from there.
        if memory_dump_enabled:
            if memory_preflight.get("available"):
                _emit(
                    status_cb,
                    "Starting process memory dump watcher "
                    f"(offsets: {', '.join(f'+{o}s' for o in memory_dump_offsets)}"
                    + (
                        f"; children re-dumped +{memory_spawn_redump_seconds}s "
                        "after they appear"
                        if memory_spawn_redump_seconds
                        else "; spawn re-dump disabled"
                    )
                    + ")...",
                )
                memory_session = MemoryDumpSession(
                    output_dir=paths["memory"],
                    procdump_path=procdump_path or None,
                    dump_offsets=list(memory_dump_offsets),
                    max_processes=memory_max_processes,
                    max_working_set_mb=memory_max_working_set_mb,
                    max_total_mb=memory_max_total_mb,
                    spawn_redump_seconds=memory_spawn_redump_seconds,
                    status_cb=status_cb,
                )
                memory_start_result = memory_session.start()
                if not memory_start_result.get("started"):
                    _emit(
                        status_cb,
                        f"Memory dump warning: {memory_start_result.get('error', 'unknown error')}",
                    )
                    memory_session = None
                elif memory_preflight.get("tree_note"):
                    _emit(status_cb, f"Memory dump: {memory_preflight['tree_note']}")
            else:
                _emit(status_cb, f"Memory dumps unavailable: {memory_preflight.get('note', '')}")

        # Before launch, for the same reason FakeNet's listener roots are: the
        # dump folder is shared with the whole machine, and afterwards there is
        # no way to tell this run's crash dumps from an older one's.
        if crash_evidence_enabled and crash_dump_preflight.get("available"):
            crash_collector = CrashDumpCollector(
                output_dir=paths["memory"] / "crash_dumps",
                dump_folder=crash_dump_preflight.get("dump_folder") or None,
            )
            crash_collector.snapshot()

        _raise_if_cancelled(cancel_event)


        # The dump watcher is already tracking the sample's process tree, so it
        # is the cheapest honest answer to "has this sample done anything yet".
        # Without it -- not elevated, or procdump missing -- there is no probe,
        # and the window stays fixed rather than extending on no evidence.
        activity_probe = (
            memory_session.activity_observed if memory_session is not None else None
        )

        _emit(
            status_cb,
            f"Launching sample and observing for at least {minimum_observation_seconds} seconds "
            f"(post-exit observation: {post_exit_observation_seconds} seconds, "
            f"installer mode: {installer_observation_mode}, base window: {timeout_seconds} seconds, "
            f"adaptive: {'up to ' + str(max_observation_seconds) + 's' if (adaptive_observation and activity_probe) else 'unavailable'})...",
        )

        sample_launch_attempted = True

        def _on_sample_launch(pid: int) -> None:
            # Recorded unconditionally, not only when dumping is on: findings
            # needs the sample's PID to keep the analyzer-lineage filter from
            # walking into the sample's own children.
            sample_pid_seen["pid"] = pid
            if memory_session is not None:
                memory_session.set_root_pid(pid)

        observation = run_sample(
            sample_path,
            timeout_seconds,
            minimum_observation_seconds=minimum_observation_seconds,
            post_exit_observation_seconds=post_exit_observation_seconds,
            installer_observation_mode=installer_observation_mode,
            adaptive_observation=adaptive_observation,
            max_observation_seconds=max_observation_seconds,
            observation_extension_seconds=observation_extension_seconds,
            activity_probe=activity_probe,
            cancel_event=cancel_event,
            status_cb=status_cb,
            on_launch=_on_sample_launch,
        )
        exit_code = observation.get("exit_code")
        _emit(
            status_cb,
            f"Sample observation completed with exit code {exit_code} after "
            f"{observation.get('elapsed_seconds', 0)}s ({observation.get('ended_because', '')}).",
        )
        if observation.get("ended_because") == "extension_cap_reached":
            _emit(
                status_cb,
                "WARNING: the sample was still running and had done nothing "
                f"observable when the {max_observation_seconds}s cap was reached. "
                "The findings below describe a sample that may simply not have "
                "started yet.",
            )

    except DynamicAnalysisCancelled as cancel_error:
        cancelled = True
        cancellation_reason = str(cancel_error)
        exit_code = -2
        _emit(status_cb, cancellation_reason)

    finally:
        # Stopped first, and unconditionally: a cancelled run must not leave a
        # watcher thread still dumping gigabytes into the case directory.
        if memory_session is not None:
            _emit(status_cb, "Stopping process memory dump watcher...")
            try:
                memory_dump_result = memory_session.stop()
                memory_summary = summarize_memory_dumps(memory_dump_result)
                write_json(memory_dumps_json, memory_dump_result)

                counts = memory_summary.get("counts", {})
                _emit(
                    status_cb,
                    f"Memory dumps: {counts.get('dumps_succeeded', 0)} written "
                    f"from {counts.get('processes_observed', 0)} observed process(es) "
                    f"({counts.get('total_mb', 0)} MB).",
                )
                for failure in memory_summary.get("failures", []):
                    _emit(
                        status_cb,
                        f"Memory dump failed for pid {failure.get('pid')}: "
                        f"{failure.get('error', 'unknown error')}",
                    )
            except Exception as error:
                memory_dump_result = {"stopped": False, "error": str(error)}
                memory_summary = summarize_memory_dumps(memory_dump_result)
                _emit(status_cb, f"Memory dump stop warning: {error}")

        if procmon_enabled and procmon_started:
            _emit(status_cb, "Stopping Procmon capture...")
            try:
                terminate_procmon_capture(procmon_path)
            except Exception as error:
                _emit(status_cb, f"Procmon stop warning: {error}")

        # Tear down in reverse order, and unconditionally: a cancelled run must
        # not leave a packet capture running or, worse, FakeNet's traffic
        # diverter still installed on the host.
        if packet_capture is not None:
            _emit(status_cb, "Stopping packet capture...")
            try:
                pcap_stop_result = packet_capture.stop()
                if pcap_stop_result.get("error"):
                    _emit(status_cb, f"Packet capture stop warning: {pcap_stop_result['error']}")
            except Exception as error:
                pcap_stop_result = {"stopped": False, "error": str(error)}
                _emit(status_cb, f"Packet capture stop warning: {error}")

        if fakenet_session is not None:
            _emit(status_cb, "Stopping simulated internet...")
            try:
                fakenet_stop_result = fakenet_session.stop()
                if fakenet_stop_result.get("error"):
                    _emit(status_cb, f"FakeNet-NG stop warning: {fakenet_stop_result['error']}")
            except Exception as error:
                fakenet_stop_result = {"stopped": False, "error": str(error)}
                _emit(status_cb, f"FakeNet-NG stop warning: {error}")

        if sysmon_enabled and sysmon_since:
            _emit(status_cb, "Collecting Sysmon telemetry...")
            try:
                sysmon_events, sysmon_summary, sysmon_status_result = collect_sysmon(
                    since_utc=sysmon_since,
                    evtx_path=sysmon_evtx,
                )

                # The summary `collect` returns carries no attribution: lineage
                # comes from the ProcessCreate records inside the very stream it
                # is summarising, so it cannot be known before the events are in
                # hand. Re-summarised rather than filtered afterwards, so every
                # count in it describes one decision.
                #
                # Without this a dwm.exe CreateRemoteThread whose target Sysmon
                # could not resolve became the run's only high-severity finding
                # and took the score from 70 to 90 -- a band, on the Desktop
                # Window Manager.
                sysmon_pids = sample_descendant_pids(
                    sysmon_events,
                    sample_pid=sample_pid_seen.get("pid"),
                    sample_name=sample_path.name,
                ) or None
                sysmon_summary = summarize_sysmon_events(
                    sysmon_events, descendant_pids=sysmon_pids
                )
                if sysmon_pids is None:
                    _emit(
                        status_cb,
                        "Sysmon: lineage could not be resolved, so every event in "
                        "the window is counted. Treat the attribution as unproven.",
                    )
                elif sysmon_summary.get("other_process_events_excluded"):
                    _emit(
                        status_cb,
                        f"Sysmon: {sysmon_summary['other_process_events_excluded']} "
                        "event(s) belonged to processes outside the sample's tree "
                        "and are listed separately.",
                    )

                write_json(sysmon_events_json, sysmon_events)
                write_json(sysmon_summary_json, sysmon_summary)

                high = int(sysmon_summary.get("high_severity_count", 0) or 0)
                _emit(
                    status_cb,
                    f"Sysmon collected {sysmon_summary.get('total_events', 0)} events "
                    f"({high} high-severity).",
                )
                if not sysmon_status_result.get("success"):
                    _emit(
                        status_cb,
                        f"Sysmon collection warning: {sysmon_status_result.get('error', 'unknown error')}",
                    )
                if sysmon_status_result.get("diagnosis"):
                    _emit(status_cb, f"Sysmon: {sysmon_status_result['diagnosis']}")
            except Exception as error:
                sysmon_status_result = {"success": False, "error": str(error)}
                _emit(status_cb, f"Sysmon collection warning: {error}")

        # After Sysmon, not before it. Script blocks are attributed by the PID
        # that ran them, and Sysmon's ProcessCreate records are what resolve the
        # sample's tree. Collected first -- as this was -- the only filter is
        # the time window, and a mimikatz control that spawned nothing reported
        # 24 blocks "from the sample" because Windows Troubleshooting ran during
        # the run.
        if sysmon_since:
            _emit(status_cb, "Collecting PowerShell script blocks...")
            try:
                powershell_preflight = powershell_logging_status()
                sample_pids = sample_descendant_pids(
                    sysmon_events,
                    sample_pid=sample_pid_seen.get("pid"),
                    sample_name=sample_path.name,
                ) or None
                if sample_pids is None:
                    _emit(
                        status_cb,
                        "PowerShell: lineage could not be resolved, so every block "
                        "in the window is counted. Treat the attribution as unproven.",
                    )
                scriptblocks, powershell_summary = collect_scriptblocks(
                    sysmon_since, sample_pids=sample_pids
                )
                write_json(powershell_blocks_json, scriptblocks)
                counts = powershell_summary.get("counts", {}) or {}
                if powershell_summary.get("collected"):
                    _emit(
                        status_cb,
                        f"PowerShell: {counts.get('blocks_from_sample', 0)} script block(s) "
                        f"from the sample, {counts.get('blocks_suspicious', 0)} suspicious "
                        f"({counts.get('analyzer_blocks_excluded', 0)} analyzer, "
                        f"{counts.get('other_process_blocks_excluded', 0)} other-process "
                        "block(s) excluded).",
                    )
                else:
                    _emit(status_cb, f"PowerShell script blocks: {powershell_summary.get('note', '')}")
            except Exception as error:
                powershell_summary = empty_powershell_summary(f"collection failed: {error}")
                _emit(status_cb, f"PowerShell collection warning: {error}")

        # Crash evidence, after Sysmon for the same reason: attribution needs
        # the lineage Sysmon's ProcessCreate records resolve.
        if crash_evidence_enabled and sysmon_since:
            _emit(status_cb, "Collecting crash evidence...")
            try:
                crash_pids = sample_descendant_pids(
                    sysmon_events,
                    sample_pid=sample_pid_seen.get("pid"),
                    sample_name=sample_path.name,
                ) or None
                crash_names |= {
                    str(p.get("name", "") or "").lower()
                    for p in (memory_summary.get("observed_processes", []) or [])
                }
                crash_names -= {""}

                crash_records, crash_summary = collect_crashes(
                    sysmon_since, sample_pids=crash_pids, sample_names=crash_names
                )
                write_json(crash_events_json, crash_records)

                counts = crash_summary.get("counts", {}) or {}
                unmapped = int(counts.get("crashes_in_unmapped_memory", 0) or 0)
                if counts.get("crashes"):
                    _emit(
                        status_cb,
                        f"Crashes: {counts.get('crashes', 0)} in the sample's tree, "
                        f"{unmapped} inside unmapped memory "
                        f"({counts.get('other_process_crashes_excluded', 0)} other-process "
                        "crash(es) excluded).",
                    )
                if unmapped:
                    for entry in crash_summary.get("unmapped_memory_crashes", []):
                        _emit(
                            status_cb,
                            f"  {entry.get('process')} faulted at {entry.get('fault_offset')} "
                            f"({entry.get('exception_code')}) with no module mapped there -- "
                            "code was running in injected memory.",
                        )
            except Exception as error:
                crash_summary = empty_crash_summary(f"collection failed: {error}")
                _emit(status_cb, f"Crash evidence warning: {error}")

        if crash_collector is not None:
            try:
                crash_dump_result = crash_collector.collect(
                    sample_names=crash_names, sample_pids=crash_pids
                )
                write_json(crash_dumps_json, crash_dump_result)
                counts = crash_dump_result.get("counts", {}) or {}
                if counts.get("dumps"):
                    _emit(
                        status_cb,
                        f"Crash dumps: {counts.get('dumps', 0)} collected "
                        f"({counts.get('attributed', 0)} from the sample's tree).",
                    )
                elif crash_dump_result.get("note"):
                    _emit(status_cb, f"Crash dumps: {crash_dump_result['note']}")
            except Exception as error:
                crash_dump_result = {"collected": False, "note": str(error)}
                _emit(status_cb, f"Crash dump collection warning: {error}")

        # Sysmon's process tree is a kernel callback and misses nothing; the
        # dump watcher polls twice a second and misses whatever does not
        # outlive an interval. Comparing them is the only way a process that
        # lived milliseconds gets mentioned at all -- it cannot be dumped, but
        # it can stop being invisible.
        if memory_summary and sysmon_events:
            try:
                missed = reconcile_with_sysmon(
                    memory_dump_result,
                    sysmon_events,
                    sample_pid=sample_pid_seen.get("pid"),
                    sample_name=sample_path.name,
                )
                memory_summary["missed_descendants"] = missed
                memory_summary.setdefault("counts", {})["missed_descendants"] = len(missed)
                for record in missed:
                    _emit(
                        status_cb,
                        f"Sysmon saw pid {record['pid']} descend from the sample, "
                        "but it exited before the watcher could dump it.",
                    )
            except Exception as error:
                _emit(status_cb, f"Memory/Sysmon reconciliation warning: {error}")

        if cancelled:
            _emit(status_cb, "Skipping after snapshots and Procmon export because run was cancelled.")
        else:
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

                # Findings first, because the dropped-file triage needs the
                # lineage this resolves. Attributing drops without it counted
                # two libraries written by msedgewebview2 as the sample's, and
                # took payload_dropped to strong on a loader that drops nothing.
                _emit(status_cb, "Building dynamic findings summary...")
                findings_summary = summarize_dynamic_findings(
                    events,
                    interesting_events,
                    sample_pid=sample_pid_seen.get("pid"),
                    sample_name=sample_path.name,
                )
                write_json(findings_json, findings_summary)

                # Did the sample's chain end by crash? A deliberate
                # anti-analysis bail and a broken payload leave the same trace
                # from outside, so this is not scored -- it is a guard against a
                # crashed chain reading as a clean run. Built here because it
                # needs the sample's lineage and its spawned WerFault.
                resolved = findings_summary.get("descendant_pids")
                abnormal_termination = summarize_abnormal_termination(
                    crash_summary,
                    process_records=findings_summary.get("spawned_processes", []),
                    descendant_pids=set(resolved) if resolved is not None else None,
                )
                if abnormal_termination.get("chain_crashed"):
                    tail = (
                        " (seen only via WerFault, no Application Error event)"
                        if abnormal_termination.get("witnessed_only_by_werfault")
                        else ""
                    )
                    _emit(
                        status_cb,
                        "Abnormal termination: a process in the sample's tree "
                        f"crashed{tail}. A deliberate bail is indistinguishable "
                        "from a broken payload -- treat a quiet result as "
                        "inconclusive.",
                    )

                # What the sample read, as opposed to what it did. Gap 4's other
                # half: an anti-analysis bail and a broken payload look the same
                # from outside, and the one thing that separates them is whether
                # the sample enumerated the hypervisor first. Not scored --
                # reading SystemBiosVersion is not malicious -- and taken over
                # the full event stream rather than the interesting events,
                # because a read is deliberately never high signal.
                _emit(status_cb, "Collecting registry reads of VM artifacts...")
                vm_artifact_reads = collect_vm_artifact_reads(
                    events,
                    descendant_pids=set(resolved) if resolved is not None else None,
                )
                write_json(vm_artifact_reads_json, vm_artifact_reads)

                if not vm_artifact_reads.get("collection_available"):
                    _emit(
                        status_cb,
                        "This Procmon config captured no registry reads, so a VM "
                        "check could not have been seen. Use "
                        "tools/procmon-configs/dynamic_registry_reads.pmc to "
                        "collect them.",
                    )
                else:
                    vm_counts = vm_artifact_reads.get("counts", {})
                    _emit(
                        status_cb,
                        f"Registry reads: {vm_artifact_reads.get('sample_reads', 0)} by the "
                        f"sample's tree, {vm_counts.get('artifacts_read', 0)} of them naming a "
                        f"VM artifact ({vm_counts.get('vm_specific', 0)} VM-specific), "
                        f"{vm_artifact_reads.get('background_reads', 0)} by other processes.",
                    )

                # A process that opens ntdll.dll as a *file* is asking for a
                # clean copy off disk, which is how user-mode unhooking starts.
                # Load Image is excluded deliberately: every process maps ntdll,
                # so counting that would fire on the whole machine. Not scored
                # until a live run shows the background rate.
                # Gap 4's active half, built on the reads just collected: a
                # sample that checks for a hypervisor and then stops. Not
                # scored, and its threshold is declared uncalibrated -- no run
                # has yet produced a VM read for it to be aimed with.
                vm_check_bail = correlate_vm_check_with_silence(
                    vm_artifact_reads,
                    events,
                    descendant_pids=set(resolved) if resolved is not None else None,
                )
                write_json(vm_check_bail_json, vm_check_bail)
                if vm_check_bail.get("verdict") == "checked_then_quiet":
                    _emit(
                        status_cb,
                        "The sample read a VM-specific artifact and then went "
                        "quiet. Read an otherwise-empty run as inconclusive "
                        "rather than clean.",
                    )

                _emit(status_cb, "Checking for self-unhooking reads of ntdll...")
                ntdll_unhooking = collect_ntdll_unhooking(
                    events,
                    descendant_pids=set(resolved) if resolved is not None else None,
                )
                write_json(ntdll_unhooking_json, ntdll_unhooking)

                if not ntdll_unhooking.get("collection_available"):
                    _emit(
                        status_cb,
                        "This capture recorded no file opens, so a read of ntdll "
                        "could not have been seen.",
                    )
                else:
                    nt_counts = ntdll_unhooking.get("counts", {})
                    _emit(
                        status_cb,
                        f"System DLL opens: {nt_counts.get('ntdll_opens_by_sample', 0)} of "
                        f"ntdll by the sample's tree "
                        f"({nt_counts.get('ntdll_opens_in_hollowing_target', 0)} in a "
                        f"hollowing target), "
                        f"{nt_counts.get('system_dll_opens_by_others', 0)} by other "
                        f"processes.",
                    )

                _emit(status_cb, "Triaging dropped-file candidates...")
                resolved_pids = findings_summary.get("descendant_pids")
                dropped_candidates = collect_dropped_file_candidates(
                    events,
                    descendant_pids=set(resolved_pids) if resolved_pids is not None else None,
                )
                dropped_files = enrich_dropped_files(dropped_candidates)
                write_json(dropped_files_json, dropped_files)

                dropped_files_summary = summarize_dropped_files(dropped_files)
                write_json(dropped_files_summary_json, dropped_files_summary)

            # Network artifacts are parsed even when Procmon is off, since the
            # capture stands on its own.
            if pcap_stop_result.get("pcap_exists"):
                _emit(status_cb, "Parsing packet capture...")
                try:
                    network_summary = parse_pcap(pcap_file)
                    network_summary["capture"] = pcap_stop_result
                    write_json(network_summary_json, network_summary)

                    if network_summary.get("parsed"):
                        counts = network_summary.get("counts", {})
                        _emit(
                            status_cb,
                            f"Network: {counts.get('dns_queries', 0)} DNS, "
                            f"{counts.get('tls_sni', 0)} TLS SNI, "
                            f"{counts.get('http_requests', 0)} HTTP, "
                            f"{counts.get('unique_destinations', 0)} destinations.",
                        )
                    else:
                        _emit(status_cb, f"Packet capture not parsed: {network_summary.get('note', '')}")
                except Exception as error:
                    _emit(status_cb, f"Packet capture parse warning: {error}")

            if fakenet_stop_result.get("log_exists"):
                _emit(status_cb, "Parsing simulated internet log...")
                try:
                    fakenet_summary = parse_fakenet_log(fakenet_stop_result.get("log_path", ""))
                    fakenet_summary["session"] = fakenet_stop_result
                    write_json(fakenet_summary_json, fakenet_summary)

                    counts = fakenet_summary.get("counts", {})
                    _emit(
                        status_cb,
                        f"Simulated internet served {counts.get('dns_requests', 0)} DNS and "
                        f"{counts.get('http_requests', 0)} HTTP requests.",
                    )
                except Exception as error:
                    _emit(status_cb, f"Simulated internet parse warning: {error}")

            # Lifted out of the session record and written whether or not the
            # log parsed. A file the sample uploaded is the run's most valuable
            # artifact, and it must not be reachable only through a nested key
            # that a failed log parse can cost.
            received_files = fakenet_stop_result.get("received_files")
            if isinstance(received_files, dict):
                fakenet_summary["received_files"] = received_files
                received_counts = received_files.get("counts", {}) or {}
                if received_counts.get("files"):
                    _emit(
                        status_cb,
                        f"Simulated internet received {received_counts.get('files', 0)} file(s) "
                        f"from the sample ({received_counts.get('overwritten', 0)} overwriting a "
                        f"served file); collected into {received_files.get('output_dir', '')}.",
                    )
                elif received_files.get("note"):
                    _emit(status_cb, f"Simulated internet: {received_files['note']}")
                write_json(fakenet_summary_json, fakenet_summary)

            # **After both parsers, and outside either block.** The IOC set is
            # built from the pcap *and* FakeNet, and it used to be built inside
            # the pcap block -- which runs before FakeNet's log is parsed, so
            # the merge could never have seen it. It also meant a run with no
            # pcap produced no IOC file at all, even when the simulated
            # internet had recorded every name the sample asked for.
            try:
                network_iocs = extract_network_iocs(network_summary, fakenet_summary)
                write_json(network_iocs_json, network_iocs)
                # Attach so scoring can use the baseline-filtered counts.
                network_summary["iocs"] = network_iocs
                if network_iocs.get("pcap_blind"):
                    _emit(status_cb, f"Network IOCs: {network_iocs.get('note', '')}")
            except Exception as error:
                _emit(status_cb, f"Network IOC extraction warning: {error}")

            # Scanned last: it is the slowest step in teardown, and it depends
            # on the dumps having been written and closed.
            # Crash dumps join the scan. A hollowed process that lives four
            # seconds falls between the scheduled offsets, so its crash image
            # is often the only one taken after the payload was written.
            scannable = successful_dumps(memory_dump_result) + [
                d
                for d in (crash_dump_result.get("dumps", []) or [])
                if d.get("success") and d.get("attributed_to_sample")
            ]
            # Carved before the YARA pass. It is seconds against minutes, and a
            # rule set that times out on a 400 MB image must not also cost the
            # structural finding, which needs no rules at all.
            if pe_carve_enabled and scannable:
                _emit(status_cb, "Searching memory dumps for unmapped PE images...")
                try:
                    pe_carve_result = carve_dumps(
                        dump_records=scannable,
                        output_dir=pe_carve_dir,
                        status_cb=status_cb,
                    )
                    pe_carve_summary = summarize_pe_carve(pe_carve_result)
                    write_json(pe_carve_json, pe_carve_result)
                except Exception as error:
                    pe_carve_result = {"carved": False, "error": str(error)}
                    pe_carve_summary = summarize_pe_carve(pe_carve_result)
                    _emit(status_cb, f"PE carve warning: {error}")

            # Over the same dumps, and deliberately after the carve: the two
            # answer opposite halves of one question. The carver finds a
            # payload mapped *beside* a real image; this finds one written
            # *over* it, which is the case gap 5 documents as its blind spot
            # because the module list is read from the memory the payload
            # now occupies.
            if memory_dump_enabled and module_integrity_enabled and scannable:
                # Per-dump progress, because this pass is the slowest thing in
                # the teardown and a slow one used to be indistinguishable from a
                # hung one. On run `33fe6c3b` it took 24 of 27 minutes over five
                # 200 MB `powershell.exe` dumps and emitted exactly one line, at
                # the start -- the same failure as an empty result from a
                # disabled collector looking like a sample that did nothing.
                _emit(status_cb,
                      f"Comparing loaded modules against their files "
                      f"({len(scannable)} dump(s))...")
                try:
                    for index, record in enumerate(scannable, 1):
                        path = record.get("path") if isinstance(record, dict) else None
                        if path:
                            # **Emitted before the work, not after.** The first
                            # version printed on completion, which left the one
                            # case it existed for -- grinding through dump 1 --
                            # producing no output at all. Five minutes of
                            # silence on run `eb3e1273` looked exactly like a
                            # hang, which is the failure this was meant to end.
                            _emit(status_cb,
                                  f"  module integrity: dump {index} of "
                                  f"{len(scannable)}, {Path(path).name}")
                            result = analyze_module_integrity(path)
                            module_integrity_result.append(result)
                    module_integrity_summary = summarize_module_integrity(
                        module_integrity_result)
                    write_json(module_integrity_json, module_integrity_result)
                    counts = module_integrity_summary.get("counts", {})
                    if not module_integrity_summary.get("available"):
                        # Every module unmatched is a statement about the
                        # reference files, not about the sample. Say which.
                        _emit(status_cb,
                              "Module integrity: nothing could be compared -- no "
                              f"matching build on this host for any of "
                              f"{counts.get('no_reference', 0)} module(s)")
                    else:
                        _emit(status_cb,
                              f"Module integrity: {counts.get('replaced', 0)} replaced, "
                              f"{counts.get('patched', 0)} patched, "
                              f"{counts.get('identical', 0)} identical, "
                              f"{counts.get('no_reference', 0)} without a reference")
                except Exception as error:
                    module_integrity_summary = {"available": False, "error": str(error)}
                    _emit(status_cb, f"Module integrity warning: {error}")

            if memory_dump_enabled and memory_yara_enabled and scannable:
                if memory_yara_preflight.get("available"):
                    _emit(status_cb, "Scanning process memory with YARA...")
                    try:
                        memory_yara_result = scan_memory_dumps(
                            dump_records=scannable,
                            sample_path=sample_path,
                            rules_dir=yara_rules_dir or None,
                            timeout=memory_yara_timeout,
                            status_cb=status_cb,
                        )
                        memory_yara_summary = summarize_memory_yara(memory_yara_result)
                        write_json(memory_yara_json, memory_yara_result)

                        counts = memory_yara_summary.get("counts", {})
                        memory_only = memory_yara_summary.get("memory_only_rules", [])
                        _emit(
                            status_cb,
                            f"Memory YARA: {counts.get('total_matches', 0)} match(es) across "
                            f"{counts.get('dumps_scanned', 0)} dump(s); "
                            f"{len(memory_only)} rule(s) matched in memory but not on disk.",
                        )
                        if memory_yara_result.get("error"):
                            _emit(
                                status_cb,
                                f"Memory YARA warning: {memory_yara_result['error']}",
                            )
                    except Exception as error:
                        memory_yara_result = {"scanned": False, "error": str(error)}
                        memory_yara_summary = summarize_memory_yara(memory_yara_result)
                        _emit(status_cb, f"Memory YARA warning: {error}")
                else:
                    _emit(
                        status_cb,
                        f"Memory YARA unavailable: {memory_yara_preflight.get('note', '')} "
                        "The dumps are kept and can be scanned manually.",
                    )

    if autoruns_enabled and not cancelled:
        _emit(status_cb, "Snapshotting Autoruns entries (after)...")
        autoruns_after_status = _run_autorunsc_snapshot(
            autorunsc_path=autorunsc_path,
            output_csv=autoruns_after_csv,
            deep_scan=autoruns_deep_scan,
            timeout_seconds=autoruns_timeout_seconds,
        )
        if not autoruns_after_status.get("success"):
            _emit(
                status_cb,
                f"Autoruns after snapshot warning: {autoruns_after_status.get('error', 'unknown error')}",
            )

        if autoruns_before_csv.exists() and autoruns_after_csv.exists():
            _emit(status_cb, "Diffing Autoruns snapshots...")
            autoruns_diff_summary = diff_autoruns_snapshots(autoruns_before_csv, autoruns_after_csv)
            write_json(autoruns_diff_json, autoruns_diff_summary)
    elif autoruns_enabled and cancelled:
        _emit(status_cb, "Skipping Autoruns after snapshot because run was cancelled.")

    ended_at = utc_now_iso()
    duration_seconds = _seconds_between(started_at, ended_at)
    timed_out = bool(exit_code == -1 and not cancelled)

    capture_quality = _build_capture_quality(
        procmon_enabled=procmon_enabled,
        procmon_started=procmon_started,
        sample_launch_attempted=sample_launch_attempted,
        exit_code=exit_code,
        procmon_summary=procmon_summary,
    )
    
    if cancelled:
        capture_quality["status"] = "cancelled"
        capture_quality["note"] = cancellation_reason or "Dynamic analysis was cancelled before full telemetry collection completed."
    elif timed_out:
        capture_quality["status"] = "timed_out"
        capture_quality["note"] = (
            f"Sample observation reached its {observation.get('window_seconds', timeout_seconds)}s "
            f"window before the sample exited ({observation.get('ended_because', '')}). "
            "This can be normal for GUI applications that remain open."
        )

    behavior_summary = _build_behavior_summary(
        findings_summary=findings_summary,
        task_diff_summary=task_diff_summary,
        service_diff_summary=service_diff_summary,
        autoruns_diff_summary=autoruns_diff_summary,
        sysmon_summary=sysmon_summary,
        network_summary=network_summary,
        fakenet_summary=fakenet_summary,
        memory_summary=memory_summary,
        memory_yara_summary=memory_yara_summary,
    )

    score_data = calculate_dynamic_score(
        findings_summary=findings_summary,
        task_diff_summary=task_diff_summary,
        service_diff_summary=service_diff_summary,
        dropped_files_summary=dropped_files_summary,
        autoruns_diff_summary=autoruns_diff_summary,
        sysmon_summary=sysmon_summary,
        network_summary=network_summary,
        fakenet_summary=fakenet_summary,
        memory_yara_summary=memory_yara_summary,
        powershell_summary=powershell_summary,
        crash_summary=crash_summary,
        pe_carve_summary=pe_carve_summary,
        module_integrity_summary=module_integrity_summary,
    )

    if cancelled:
        score_data = {
            "score": 0,
            "severity": "Info",
            "verdict": "Cancelled",
        }

    summary = {
        "schema_version": "dynamic-1.0",
        "run_id": run_id,
        "run_profile": run_profile,
        "test_name": test_name,
        "run_case_dir": str(run_case_dir),
        "timeout_seconds": timeout_seconds,
        "minimum_observation_seconds": minimum_observation_seconds,
        "post_exit_observation_seconds": post_exit_observation_seconds,
        "installer_observation_mode": installer_observation_mode,
        # How long the run actually watched, and why it stopped. Without this a
        # report cannot distinguish a sample that did nothing from one that had
        # not started yet.
        "observation": observation,
        "sample": sample_info,
        "started_at_utc": started_at,
        "ended_at_utc": ended_at,
        "duration_seconds": duration_seconds,
        "exit_code": exit_code,
        "cancelled": bool(cancelled),
        "timed_out": timed_out,
        "cancellation_reason": cancellation_reason,
        "procmon_enabled": procmon_enabled,
        # Which filter ran, and whether it could see a registry read. The one
        # capture setting that was not in the record, on a run whose result
        # turned entirely on it.
        "procmon_filter": procmon_filter,
        "autoruns_enabled": autoruns_enabled,
        "autoruns_deep_scan": autoruns_deep_scan,
        "autoruns_before_status": autoruns_before_status,
        "autoruns_after_status": autoruns_after_status,
        "capture_quality": capture_quality,
        "behavior_summary": behavior_summary,
        "score": score_data["score"],
        "severity": score_data["severity"],
        "verdict": score_data["verdict"],
        # What the verdict was actually built from. Without this the band is an
        # assertion; with it the reader can check the reasoning and disagree.
        "score_detail": score_data,
        "procmon_summary": procmon_summary,
        "procmon_interesting_summary": procmon_interesting_summary,
        "task_diff_summary": task_diff_summary.get("counts", {}) if isinstance(task_diff_summary, dict) else {},
        "service_diff_summary": service_diff_summary.get("counts", {}) if isinstance(service_diff_summary, dict) else {},
        "autoruns_diff_summary": autoruns_diff_summary.get("counts", {}) if isinstance(autoruns_diff_summary, dict) else {},
        "autoruns_diff": autoruns_diff_summary,
        "dropped_files_summary": dropped_files_summary,
        # The list, not just the counts. `payload_dropped` can reach strong off
        # this, and a reader could not previously see what the count was made of
        # -- a Remcos run reported 13 suspicious drops of which 11 did not exist.
        "dropped_files": dropped_files[:50],
        "findings": findings_summary,
        # --- Tier 1 telemetry ------------------------------------------------
        "tasks_snapshot_status": tasks_status,
        "services_snapshot_status": services_status,
        "sysmon_enabled": sysmon_enabled,
        "sysmon_preflight": sysmon_preflight,
        "sysmon_collection": sysmon_status_result,
        "sysmon_summary": sysmon_summary,
        "network_isolation": isolation,
        "pcap_enabled": pcap_enabled,
        "pcap_preflight": pcap_preflight,
        "pcap_capture": pcap_stop_result,
        "network_summary": network_summary,
        "network_iocs": network_iocs,
        "fakenet_enabled": fakenet_enabled,
        "fakenet_preflight": fakenet_preflight,
        "fakenet_summary": fakenet_summary,
        # --- Tier 2 telemetry ------------------------------------------------
        "memory_dump_enabled": memory_dump_enabled,
        "memory_dump_offsets": list(memory_dump_offsets),
        # The delay a `spawn-redump` row was taken at, and the one that a
        # "exited before its +Ns re-dump" skip was measured against. A run that
        # collected no re-dumps reads differently at 10s than at 0.
        "memory_dump_spawn_redump_seconds": memory_spawn_redump_seconds,
        # Recorded because "process cap reached" in the skipped list only makes
        # sense next to the cap that was reached.
        "memory_dump_limits": {
            "max_processes": memory_max_processes,
            "max_working_set_mb": memory_max_working_set_mb,
            "max_total_mb": memory_max_total_mb,
        },
        "memory_preflight": memory_preflight,
        "memory_dump_start": memory_start_result,
        "memory_summary": memory_summary,
        "memory_yara_enabled": memory_yara_enabled,
        "memory_yara_preflight": memory_yara_preflight,
        "memory_yara_summary": memory_yara_summary,
        "pe_carve_enabled": pe_carve_enabled,
        "pe_carve_summary": pe_carve_summary,
        "module_integrity_enabled": module_integrity_enabled,
        "module_integrity_summary": module_integrity_summary,
        "crash_evidence_enabled": crash_evidence_enabled,
        "crash_dump_preflight": crash_dump_preflight,
        "crash_summary": crash_summary,
        "abnormal_termination": abnormal_termination,
        "vm_artifact_reads": vm_artifact_reads,
        "vm_check_and_bail": vm_check_bail,
        "ntdll_unhooking": ntdll_unhooking,
        "crash_dumps": crash_dump_result,
        "powershell_preflight": powershell_preflight,
        "powershell_summary": powershell_summary,
    }

    # Mapped last, from the assembled summary, so it sees every source rather
    # than a subset that happens to be ready earlier.
    summary["attack_mapping"] = summarize_attack(map_run(summary))

    _emit(status_cb, "Writing final run summary...")
    write_json(run_summary_path, summary)

    if cancelled:
        _emit(status_cb, "Dynamic analysis cancelled. Partial summary written.")
    else:
        _emit(status_cb, "Dynamic analysis completed.")

    return summary
