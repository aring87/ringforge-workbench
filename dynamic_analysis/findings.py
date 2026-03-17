from __future__ import annotations

from collections import Counter
from typing import Any


KNOWN_NOISE_PROCESSES = {
    "spotify.exe",
    "chrome.exe",
    "steamwebhelper.exe",
    "discord.exe",
    "onedrive.exe",
    "steelseriesgg.exe",
    "steelseriesengine.exe",
    "steelseriessonar.exe",
    "steelseriesprism.exe",
    "nvidia overlay.exe",
    "gamemanagerservice.exe",
    "gamemanagerservice3.exe",
    "game managerservice.exe",
    "razer synapse service.exe",
    "razercortex.exe",
    "msedge.exe",
    "teams.exe",
    "epicgameslauncher.exe",
    "epicwebhelper.exe",
    "dashost.exe",
    "sihost.exe",
    "asus_framework.exe",
    "acpowernotification.exe",
    "bdservicehost.exe",
    "productagentservice.exe",
    "wsnativepushservice.exe",
    "galaxyclient.exe",
}


KNOWN_NOISE_PATH_SUBSTRINGS = (
    r"\onedrive\logs\\",
    r"\google\chrome\user data\\",
    r"\razer\gamemanager3\logs\\",
    r"\windows\debug\wia\\",
    r"startupprofiledata-noninteractive",
    r".vdi",
    r"g:\vms\\",
        r"\program files\bitdefender\\",
    r"\users\aring\appdata\local\google\chrome\\",
    r"\users\aring\appdata\local\microsoft\onedrive\logs\\",
    r"\programdata\gog.com\galaxy\logs\\",
    r"\users\aring\appdata\local\asus\armoury crate diagnosis\\",
    r"\windows\system32\winevt\logs\microsoft-windows-powershell%4operational.evtx",
    r"\windows\debug\wia\\",
)


ANALYZER_NOISE_PATH_SUBSTRINGS = (
    r"\appdata\local\temp\tmp",
    r"__psscriptpolicytest_",
    r"d:\ring_forge_analyzer\cases\\",   
)


SUSPICIOUS_PATH_KEYWORDS = (
    r"\appdata\roaming\microsoft\windows\start menu\programs\startup",
    r"\windows\system32\tasks",
    r"\windows\tasks",
    r"\software\microsoft\windows\currentversion\run",
    r"\software\microsoft\windows\currentversion\runonce",
    r"\software\microsoft\windows nt\currentversion\winlogon",
    r"\services",
    r"\drivers",
    r"\temp",
    r"\programdata",
)


PERSISTENCE_KEYWORDS = (
    r"\software\microsoft\windows\currentversion\run",
    r"\software\microsoft\windows\currentversion\runonce",
    r"\windows\system32\tasks",
    r"\windows\tasks",
    "schtasks",
    "service control manager",
)


LOLBIN_NAMES = {
    "powershell.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "wmic.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msbuild.exe",
    "installutil.exe",
    "reg.exe",
    "net.exe",
    "net1.exe",
}


def _normalize_process_name(value: object) -> str:
    return str(value or "").strip().lower()


def _normalize_text(value: object) -> str:
    return str(value or "").strip()


def _normalize_text_lower(value: object) -> str:
    return _normalize_text(value).lower()


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _is_noise_process(value: object) -> bool:
    return _normalize_process_name(value) in KNOWN_NOISE_PROCESSES


def _is_noise_path(value: object) -> bool:
    lowered = _normalize_text_lower(value)
    return any(part in lowered for part in KNOWN_NOISE_PATH_SUBSTRINGS)


def _is_analyzer_noise_path(value: object) -> bool:
    lowered = _normalize_text_lower(value)
    return any(part in lowered for part in ANALYZER_NOISE_PATH_SUBSTRINGS)

def _is_analyzer_activity(process_name: object, path: object = None, detail: object = None) -> bool:
    proc = _normalize_process_name(process_name)
    path_l = _normalize_text_lower(path)
    detail_l = _normalize_text_lower(detail)

    if _is_analyzer_noise_path(path_l):
        return True

    if r"d:\ring_forge_analyzer\cases\\" in path_l or r"d:\ring_forge_analyzer\cases\\" in detail_l:
        return True

    if r"d:\ring_forge_analyzer\\" in path_l and r"\cases\\" in path_l:
        return True

    if "get-scheduledtask" in detail_l:
        return True

    if "get-ciminstance win32_service" in detail_l:
        return True

    if "convertto-json" in detail_l and "set-content -path" in detail_l:
        return True

    if "executionpolicy bypass" in detail_l and "powershell.exe" in detail_l:
        return True

    if proc == "powershell.exe":
        if "write-output $outfile" in detail_l:
            return True
        if "$outfile =" in detail_l:
            return True

    if proc == "python.exe":
        if "powershell.exe -noprofile -executionpolicy bypass" in detail_l:
            return True

    return False

def _looks_suspicious_path(value: object) -> bool:
    lowered = _normalize_text_lower(value)
    return any(part in lowered for part in SUSPICIOUS_PATH_KEYWORDS)


def _looks_persistence(value: object) -> bool:
    lowered = _normalize_text_lower(value)
    return any(part in lowered for part in PERSISTENCE_KEYWORDS)

def _is_benign_registry_noise(path: object, operation: object, detail: object = None) -> bool:
    path_l = _normalize_text_lower(path)
    op_l = _normalize_text_lower(operation)
    detail_l = _normalize_text_lower(detail)

    if "services\\bam\\state\\usersettings" in path_l and op_l == "regsetvalue":
        return True

    if r"\software\microsoft\windows\currentversion\run" in path_l and "reg_opened_existing_key" in detail_l:
        return True

    return False

def _is_lolbin(process_name: object, path: object = None, detail: object = None) -> bool:
    proc = _normalize_process_name(process_name)
    if proc in LOLBIN_NAMES:
        return True
    combined = " ".join(
        [
            _normalize_text_lower(process_name),
            _normalize_text_lower(path),
            _normalize_text_lower(detail),
        ]
    )
    return any(name in combined for name in LOLBIN_NAMES)


def _event_process_name(event: dict[str, Any]) -> str:
    for key in ("process_name", "Process Name", "image", "Image", "process"):
        if key in event and event.get(key):
            return _normalize_text(event.get(key))
    return ""


def _event_path(event: dict[str, Any]) -> str:
    for key in ("path", "Path", "target_path", "TargetPath"):
        if key in event and event.get(key):
            return _normalize_text(event.get(key))
    return ""


def _event_operation(event: dict[str, Any]) -> str:
    for key in ("operation", "Operation"):
        if key in event and event.get(key):
            return _normalize_text_lower(event.get(key))
    return ""


def _event_detail(event: dict[str, Any]) -> str:
    for key in ("detail", "Detail", "details"):
        if key in event and event.get(key):
            return _normalize_text(event.get(key))
    return ""


def _event_timestamp(event: dict[str, Any]) -> str:
    for key in ("timestamp", "Timestamp", "time", "Time of Day"):
        if key in event and event.get(key):
            return _normalize_text(event.get(key))
    return ""


def _event_pid(event: dict[str, Any]) -> int | None:
    for key in ("pid", "PID", "process_id", "ProcessId"):
        if key in event and event.get(key) not in (None, ""):
            return _safe_int(event.get(key), default=0)
    return None


def _build_process_create_record(event: dict[str, Any]) -> dict[str, Any]:
    process_name = _event_process_name(event)
    path = _event_path(event)
    detail = _event_detail(event)
    return {
        "timestamp": _event_timestamp(event),
        "process_name": process_name,
        "pid": _event_pid(event),
        "path": path,
        "detail": detail,
        "is_lolbin": _is_lolbin(process_name, path, detail),
        "is_analyzer_activity": _is_analyzer_activity(process_name, path, detail),
    }


def summarize_dynamic_findings(
    events: list[dict[str, Any]],
    interesting_events: list[dict[str, Any]],
) -> dict[str, Any]:
    findings: dict[str, Any] = {
        "highlights": [],
        "top_written_paths": [],
        "top_network_processes": [],
        "spawned_processes": [],
        "suspicious_path_hits": [],
        "persistence_hits": [],
        "counts": {},
    }

    write_counter: Counter[str] = Counter()
    write_counter_clean: Counter[str] = Counter()
    network_counter: Counter[str] = Counter()
    network_counter_clean: Counter[str] = Counter()

    process_creates: list[dict[str, Any]] = []
    suspicious_path_hits: list[dict[str, Any]] = []
    persistence_hits: list[dict[str, Any]] = []

    process_create_count = 0
    network_event_count = 0
    file_write_event_count = 0
    lolbin_count = 0

    for event in interesting_events:
        operation = _event_operation(event)
        process_name = _event_process_name(event)
        path = _event_path(event)
        detail = _event_detail(event)

        is_noise_proc = _is_noise_process(process_name)
        is_noise_path = _is_noise_path(path)
        is_analyzer = _is_analyzer_activity(process_name, path, detail)
        is_benign_registry = _is_benign_registry_noise(path, operation, detail)

        if "process" in operation and "create" in operation:
            record = _build_process_create_record(event)
            process_creates.append(record)
            process_create_count += 1
            if record["is_lolbin"] and not record["is_analyzer_activity"]:
                lolbin_count += 1

        if "tcp" in operation or "udp" in operation or "network" in operation:
            network_event_count += 1
            if process_name:
                network_counter[process_name] += 1
                if not is_noise_proc and not is_analyzer:
                    network_counter_clean[process_name] += 1

        if (
            "writefile" in operation
            or "setrenameinformationfile" in operation
            or "setdispositioninformationfile" in operation
        ):
            file_write_event_count += 1
            if path:
                write_counter[path] += 1
                if not is_noise_path and not is_analyzer:
                    write_counter_clean[path] += 1

        if path and _looks_suspicious_path(path):
            if not is_noise_proc and not is_noise_path and not is_analyzer and not is_benign_registry:
                suspicious_path_hits.append(
                    {
                        "timestamp": _event_timestamp(event),
                        "process_name": process_name,
                        "path": path,
                        "operation": operation,
                        "detail": detail,
                    }
                )

        joined = f"{path} {detail}"
        if joined and _looks_persistence(joined):
            if not is_noise_proc and not is_noise_path and not is_analyzer and not is_benign_registry:
                persistence_hits.append(
                    {
                        "timestamp": _event_timestamp(event),
                        "process_name": process_name,
                        "path": path,
                        "operation": operation,
                        "detail": detail,
                    }
                )

    top_written_source = write_counter_clean if write_counter_clean else write_counter
    findings["top_written_paths"] = [
        {"path": path, "count": count}
        for path, count in top_written_source.most_common(10)
    ]

    top_network_source = network_counter_clean if network_counter_clean else network_counter
    findings["top_network_processes"] = [
        {"process_name": process_name, "count": count}
        for process_name, count in top_network_source.most_common(10)
    ]

    clean_process_creates = [
        item
        for item in process_creates
        if not _is_noise_process(item.get("process_name"))
        and not item.get("is_analyzer_activity", False)
    ]
    findings["spawned_processes"] = (clean_process_creates if clean_process_creates else process_creates)[:25]
    findings["suspicious_path_hits"] = suspicious_path_hits[:50]
    findings["persistence_hits"] = persistence_hits[:25]

    counts = {
        "interesting_events": len(interesting_events),
        "process_creates": process_create_count,
        "network_events": network_event_count,
        "file_write_events": file_write_event_count,
        "suspicious_path_hits": len(suspicious_path_hits),
        "persistence_hits": len(persistence_hits),
        "lolbin_processes": lolbin_count,
    }
    findings["counts"] = counts

    highlights: list[str] = []
    if process_create_count:
        highlights.append(f"Spawned processes observed: {process_create_count}")
    if network_event_count:
        highlights.append(f"Network events observed: {network_event_count}")
    if file_write_event_count:
        highlights.append(f"File writes observed: {file_write_event_count}")
    if suspicious_path_hits:
        highlights.append(f"Suspicious path hits observed: {len(suspicious_path_hits)}")
    if persistence_hits:
        highlights.append(f"Persistence-related hits observed: {len(persistence_hits)}")
    if lolbin_count:
        highlights.append(f"LOLBin processes observed: {lolbin_count}")

    findings["highlights"] = highlights
    return findings