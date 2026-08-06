from __future__ import annotations

import re
from collections import Counter
from pathlib import PureWindowsPath
from typing import Any


KNOWN_NOISE_PROCESSES = {
    "windowspackagemanagerserver.exe",
    "microsoftedgeupdate.exe",
    "softlandingtask.exe",
    "taskhostw.exe",
    "sppsvc.exe",
    "deviceenroller.exe",
    "securityhealthservice.exe",
    "mssense.exe",
    "senseir.exe",
    "vssvc.exe",
    "spotify.exe",
    "chrome.exe",
    "steamwebhelper.exe",
    "discord.exe",
    "onedrive.exe",
    # Same product, and the one that actually appears: svchost starts
    # OneDriveLauncher from AppData, which now reads as an executable in a
    # user-writable location and would otherwise be a finding on every run.
    "onedrivelauncher.exe",
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
    # The WebView2 host, which is what Office and Copilot actually run in. It
    # spawns a tree of --type=gpu-process / --type=renderer children under its
    # own name, so a run with Copilot resident reports several "spawned
    # processes" that have nothing to do with the sample.
    "msedgewebview2.exe",
    # Office Copilot. It was the top network process of an AgentTesla run --
    # once FakeNet could intercept, every resident Microsoft app started
    # reaching the simulated internet and counting as the sample's traffic.
    "m365copilot.exe",
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
    "consent.exe",
    "ctfmon.exe",
    "wmiprvse.exe",
    "dllhost.exe",
    "backgroundtaskhost.exe",
    "applicationframehost.exe",
    "dataexchangehost.exe",
    "runtimebroker.exe",
    "textinputhost.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "searchhost.exe",
    "widgets.exe",
    "widgetservice.exe",
    "msmpeng.exe",
    "nisserv.exe",

    # RingForge / analysis tooling noise. These are launched by the analyzer,
    # not by the sample, and should not count as sample behavior.
    "procmon.exe",
    "procmon64.exe",
    "procmon64a.exe",
    "autorunsc.exe",
    "autorunsc64.exe",
    "autoruns.exe",
    "autoruns64.exe",
}

KNOWN_NOISE_PATH_SUBSTRINGS = (
    r"\windows\system32\tasks\microsoft\windows\flighting\onesettings\refreshcache",
    r"\windows\system32\tasks\microsoft\windows\softwareprotectionplatform\svcrestarttask",
    r"\program files\windowsapps\microsoft.desktopappinstaller_",
    "\\program files (x86)\\microsoft\\edgeupdate\\",
    r"\systemapps\microsoftwindows.client.cbs_",
    "\\onedrive\\logs\\",
    "\\google\\chrome\\user data\\",
    "\\razer\\gamemanager3\\logs\\",
    "\\windows\\debug\\wia\\",
    "startupprofiledata-noninteractive",
    r".vdi",
    "g:\\vms\\",
    "\\program files\\bitdefender\\",
    "\\programdata\\gog.com\\galaxy\\logs\\",
    "\\users\\aring\\appdata\\local\\asus\\armoury crate diagnosis\\",
    r"\windows\system32\winevt\logs\microsoft-windows-powershell%4operational.evtx",
    "\\programdata\\microsoft\\windows defender\\",
    "\\programdata\\microsoft\\windows defender advanced threat protection\\",
    "\\windows\\system32\\wbem\\repository\\",
    "\\windows\\system32\\logfiles\\",
)

ANALYZER_NOISE_PATH_SUBSTRINGS = (
    r"\appdata\local\temp\tmp",
    r"__psscriptpolicytest_",
    "\\cases\\",
    "\\procmon\\",
    r"\reports\dynamic_findings.json",
    r"\reports\dynamic_report",
    "\\persistence\\",
    "\\metadata\\",
    r"\files\dropped_files",
    "\\autoruns\\",
    "autoruns_before.csv",
    "autoruns_after.csv",
    "autoruns_diff.json",
    "raw.pml",
    "export.csv",
    "parsed_events.json",
    "interesting_events.json",
)

SUSPICIOUS_PATH_KEYWORDS = (
    r"\appdata\roaming\microsoft\windows\start menu\programs\startup",
    r"\windows\system32\tasks",
    r"\windows\tasks",
    r"\software\microsoft\windows\currentversion\run",
    r"\software\microsoft\windows\currentversion\runonce",
    r"\software\microsoft\windows nt\currentversion\winlogon",
    # Both of these ended in a doubled separator and had never matched, so
    # service and driver persistence was invisible to the findings.
    "\\currentcontrolset\\services\\",
    "\\drivers\\",
)

#: Subdirectories of a case folder that only RingForge writes. A path under
#: `\cases\` *and* one of these is the analyzer's own output, not the sample's.
#:
#: Both halves used to carry a doubled separator, so this test never fired and
#: the two copies of it -- one against the path, one against the detail -- were
#: dead code that read as working suppression.
ANALYZER_CASE_SUBDIRS = (
    "\\reports\\",
    "\\metadata\\",
    "\\procmon\\",
    "\\autoruns\\",
    "\\files\\",
    "\\persistence\\",
    "\\unified_report\\",
)


def _is_analyzer_case_path(text: str) -> bool:
    """True for a path inside one of RingForge's own case subdirectories."""
    return "\\cases\\" in text and any(part in text for part in ANALYZER_CASE_SUBDIRS)


PERSISTENCE_KEYWORDS = (
    r"\software\microsoft\windows\currentversion\run",
    r"\software\microsoft\windows\currentversion\runonce",
    r"\windows\system32\tasks",
    r"\windows\tasks",
    "\\currentcontrolset\\services\\",
    "schtasks",
    "service control manager",
)

EXECUTION_RELATED_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".ps1",
    ".bat",
    ".cmd",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".hta",
    ".scr",
    ".com",
    ".pif",
    ".jar",
    ".msi",
}

#: Matched with a plain substring test, not a regex, so a single backslash is a
#: single backslash. These were written r"\temp\\" -- regex escaping -- which
#: asks for two consecutive backslashes and therefore never matched any real
#: path. _path_is_user_writable returned False for everything, including
#: C:\Users\a\AppData\Local\Temp\dropped.exe, so "an executable running from a
#: user-writable location" has never once fired.
#: Written as ordinary strings rather than raw ones, because a raw string
#: cannot end in a backslash -- which is the trap that produced the doubled
#: form in the first place.
USER_WRITABLE_PATH_MARKERS = (
    "\\users\\",
    "\\programdata\\",
    "\\appdata\\",
    "\\temp\\",
)

#: Command-line shapes that make a process create worth reading whatever
#: launched it. Shared by the Windows-baseline filter, which refuses to wave a
#: process through when one is present, and by the lineage split, which refuses
#: to demote one to context.
SUSPICIOUS_LAUNCH_MARKERS = (
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "http://",
    "https://",
    "-enc",
    "encodedcommand",
)

#: The subset strong enough to override lineage and promote a process the
#: sample did not cause back into the findings.
#:
#: Deliberately narrower than the tuple above, which also lists bare URLs and
#: interpreter names. A URL on a command line is ordinary in enterprise
#: software -- an Intune agent passes https://manage.microsoft.com on every
#: check-in -- and the interpreter names are already covered by LOLBIN_NAMES.
#: An encoded command has no such innocent reading.
NOTABLE_LAUNCH_MARKERS = (
    "-enc",
    "encodedcommand",
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

ANALYZER_TOOL_PROCESS_NAMES = {
    "procmon.exe",
    "procmon64.exe",
    "procmon64a.exe",
    "autorunsc.exe",
    "autorunsc64.exe",
    "autoruns.exe",
    "autoruns64.exe",
    "python.exe",
    "pythonw.exe",
    # Tier-1 and tier-2 telemetry tools. FakeNet in particular is not passive:
    # it shells out on startup, and those children were being counted as the
    # sample's own LOLBin activity.
    "fakenet.exe",
    "dumpcap.exe",
    "tshark.exe",
    "sysmon.exe",
    "sysmon64.exe",
    "procdump.exe",
    "procdump64.exe",
}

ANALYZER_TOOL_COMMAND_MARKERS = (
    "procmon64.exe /accepteula",
    "procmon.exe /accepteula",
    "procmon64.exe /terminate",
    "procmon.exe /terminate",
    "autorunsc64.exe -accepteula",
    "autorunsc.exe -accepteula",
    "autoruns_before.csv",
    "autoruns_after.csv",
    "autoruns_diff.json",
)

#: The workbench's own directory names. Far broader than the invocations above
#: -- they match anything anywhere in the project tree, samples included.
#:
#: Samples live inside that tree by design: the README says to keep them in
#: samples\, which is gitignored. So every event involving a sample carried
#: "ringforge-workbench" in its path and was filed as the analyzer's own
#: activity. An AgentTesla run reported zero spawned processes while the memory
#: dumper was recording the child the sample had just spawned, and the score
#: came out at 45 because the behaviour had been attributed to us.
#:
#: Consulted only outside samples\ for that reason. The precise tool
#: invocations above are unaffected and still match anywhere, so a Procmon
#: command line that happens to name a sample path is still caught.
ANALYZER_WORKSPACE_MARKERS = (
    "dynamic_analysis",
    "static-software-malware-analysis",
    "ringforge_analyzer",
    "ringforge-workbench",
    # FakeNet ships as a PyInstaller one-file build, which unpacks itself into
    # %TEMP%\_MEInnnnn and loads its WinDivert driver from there. That path
    # contains none of the names above, so the diverter's own driver was landing
    # in the sample's suspicious-path hits -- three times on the Remcos run. The
    # autoruns diff already excluded WinDivert as analyzer activity; this is the
    # same exclusion for the findings.
    "\\_mei",
    "\\pydivert\\",
    "windivert",
)

#: Where samples are kept, and therefore where the workspace markers above
#: cannot be trusted to mean "this was the analyzer".
SAMPLE_DIR_MARKER = "\\samples\\"


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


def _path_suffix(path_value: object) -> str:
    try:
        return PureWindowsPath(_normalize_text(path_value)).suffix.lower()
    except Exception:
        return ""


def _basename_from_event_path(value: object) -> str:
    value_l = _normalize_text_lower(value).replace("/", "\\").strip().strip('"')
    if not value_l:
        return ""
    return value_l.split("\\")[-1].strip().strip('"')


def _event_process_image_name(process_name: object, path: object = None, detail: object = None) -> str:
    """
    For Procmon Process Create rows, process_name is often the parent process
    and path is the child executable that was created. Prefer the child image.
    """
    path_base = _basename_from_event_path(path)
    if path_base.endswith(".exe"):
        return path_base

    detail_l = _normalize_text_lower(detail).replace("/", "\\")
    match = re.search(r"command line:\s*\"?([a-z]:\\[^\"\r\n]+?\.exe)", detail_l)
    if match:
        return match.group(1).split("\\")[-1].strip().strip('"')

    match = re.search(r"command line:\s*([^,\r\n]+?\.exe)", detail_l)
    if match:
        return match.group(1).split("\\")[-1].strip().strip('"')

    return _normalize_process_name(process_name)


def _is_noise_process(value: object) -> bool:
    return _normalize_process_name(value) in KNOWN_NOISE_PROCESSES


def _is_noise_path(value: object) -> bool:
    lowered = _normalize_text_lower(value)
    return any(part in lowered for part in KNOWN_NOISE_PATH_SUBSTRINGS)


def _is_analyzer_noise_path(value: object) -> bool:
    lowered = _normalize_text_lower(value)
    return any(part in lowered for part in ANALYZER_NOISE_PATH_SUBSTRINGS)


def _is_defender_or_wbem_noise(path: object, process_name: object, detail: object = None) -> bool:
    path_l = _normalize_text_lower(path)
    proc_l = _normalize_process_name(process_name)
    detail_l = _normalize_text_lower(detail)

    if proc_l in {"msmpeng.exe", "nisserv.exe", "wmiprvse.exe"}:
        return True

    if "\\programdata\\microsoft\\windows defender\\" in path_l:
        return True
    if "\\windows defender advanced threat protection\\" in path_l:
        return True
    if "\\windows\\system32\\wbem\\" in path_l or "\\windows\\system32\\wbem\\" in detail_l:
        return True
    if "mofcomp" in detail_l:
        return True

    return False


def _is_windows_baseline_process_create(process_name: object, path: object = None, detail: object = None) -> bool:
    """
    Filters normal Windows 10/11 helper processes and packaged app activation
    noise. This is only for process-create/event counting; it does not hide
    suspicious paths, LOLBins, encoded commands, or persistence evidence.
    """
    parent_proc = _normalize_process_name(process_name)
    child_proc = _event_process_image_name(process_name, path, detail)
    path_l = _normalize_text_lower(path).replace("/", "\\")
    detail_l = _normalize_text_lower(detail).replace("/", "\\")
    combined = f"{parent_proc} {child_proc} {path_l} {detail_l}"

    suspicious_launch_markers = SUSPICIOUS_LAUNCH_MARKERS

    baseline_children = {
        "dllhost.exe",
        "dataexchangehost.exe",
        "applicationframehost.exe",
        "runtimebroker.exe",
        "backgroundtaskhost.exe",
        "textinputhost.exe",
        "sihost.exe",
        "ctfmon.exe",
    }

    if child_proc in baseline_children or parent_proc in baseline_children:
        return True

    #: Waved through as a child only, unlike the set above. Console Window Host
    #: is attached by Windows to any process that opens a console, so it turns
    #: up behind whatever happened to run -- four of the six spawns in one
    #: mimikatz run were conhost, behind MpCmdRun and an Intune agent.
    #:
    #: Not accepted as a parent, because conhost spawning something is not
    #: ordinary housekeeping and is worth reading.
    if child_proc == "conhost.exe":
        return True

    if child_proc == "svchost.exe" and "-s netsetupsvc" in combined:
        return True

    # services.exe starting a service host group. This is how Windows starts
    # every service it hosts, and the groups that appear depend on what the
    # machine happens to do during the observation window -- GPSvcGroup turned
    # up in a mimikatz run and had nothing to do with the sample.
    #
    # Requires the real System32 svchost and an actual -k group, because a
    # renamed binary or an svchost launched from anywhere else is a known
    # masquerade and must still be reported.
    if (
        parent_proc == "services.exe"
        and child_proc == "svchost.exe"
        and "\\windows\\system32\\svchost.exe" in path_l
        and "-k " in combined
        and not any(marker in combined for marker in suspicious_launch_markers)
    ):
        return True

    # Windows maintenance helpers that svchost starts on its own schedule. They
    # turn up in runs of any length -- three different ones appeared across three
    # mimikatz detonations -- and none of them relate to the sample.
    #
    # Deliberately narrower than the baseline_children check above: this requires
    # the genuine System32 path and a clean command line, because usoclient.exe
    # is a documented LOLBin. A copy of it living somewhere else, or one invoked
    # with an unexpected command line, is exactly what should still be reported.
    svchost_maintenance = {
        "usoclient.exe",
        "useroobebroker.exe",
        "compattelrunner.exe",
        "mousocoreworker.exe",
        "wermgr.exe",
        # Audio Device Graph Isolation. Started by svchost on its own schedule
        # whenever anything touches audio, which on a desktop VM is often.
        "audiodg.exe",
    }
    #: Trusted homes for the binaries above. System32 is the obvious one;
    #: %WINDIR%\uus\<arch>\ is the Update Universal Store, which is where
    #: Windows 11 actually services MoUsoCoreWorker.exe from. Requiring
    #: System32 alone is why a real canary run still reported
    #: C:\WINDOWS\uus\AMD64\MoUsoCoreWorker.exe as a spawned process.
    maintenance_roots = ("\\windows\\system32\\", "\\windows\\uus\\")
    if parent_proc == "svchost.exe" and child_proc in svchost_maintenance:
        if any(root in path_l for root in maintenance_roots) and not any(
            marker in combined for marker in suspicious_launch_markers
        ):
            return True

    # Windows 11 Notepad often runs as a packaged app:
    # C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_...\Notepad.exe /SESSION...
    if child_proc == "notepad.exe" and "\\windowsapps\\" in combined and "notepad" in combined:
        if not any(marker in combined for marker in suspicious_launch_markers):
            return True

    # Other common Microsoft packaged apps without suspicious command lines.
    if "\\windowsapps\\" in combined and any(
        marker in combined
        for marker in (
            "microsoft.windowsnotepad",
            "microsoft.windowscalculator",
            "microsoft.paint",
        )
    ):
        if not any(marker in combined for marker in suspicious_launch_markers):
            return True

    return False


def _is_analyzer_activity(
    process_name: object,
    path: object = None,
    detail: object = None,
    sample_name: str = "",
) -> bool:
    """
    Return True when an event was created by RingForge or one of its helper
    tools instead of the sample being analyzed.

    This keeps Procmon, Autorunsc, report writing, metadata creation, and
    PowerShell snapshot commands from inflating the sample's dynamic score.
    """
    proc = _normalize_process_name(process_name)
    path_l = _normalize_text_lower(path)
    detail_l = _normalize_text_lower(detail)
    child_proc = _event_process_image_name(process_name, path, detail)
    combined = f"{proc} {child_proc} {path_l} {detail_l}"

    # The sample is never the analyzer, wherever it is stored. Checked first so
    # that a sample named after a tool -- which is an evasion technique, not a
    # coincidence -- is reported rather than suppressed.
    sample_proc = _normalize_process_name(sample_name)
    if sample_proc and sample_proc in (proc, child_proc):
        return False

    if proc in ANALYZER_TOOL_PROCESS_NAMES or child_proc in ANALYZER_TOOL_PROCESS_NAMES:
        return True

    if _is_analyzer_noise_path(path_l) or _is_analyzer_noise_path(detail_l):
        return True

    if any(marker in combined for marker in ANALYZER_TOOL_COMMAND_MARKERS):
        return True

    # Broad project-tree markers, trusted only outside samples\. See the note
    # on ANALYZER_WORKSPACE_MARKERS: samples live inside the workbench, so
    # matching on the project name attributed their behaviour to us.
    if SAMPLE_DIR_MARKER not in combined and any(
        marker in combined for marker in ANALYZER_WORKSPACE_MARKERS
    ):
        return True

    if _is_analyzer_case_path(path_l) or _is_analyzer_case_path(detail_l):
        return True

    if "get-scheduledtask" in detail_l:
        return True
    if "get-ciminstance win32_service" in detail_l:
        return True
    if "convertto-json" in detail_l and "set-content -path" in detail_l:
        return True
    if "executionpolicy bypass" in detail_l and "powershell.exe" in detail_l:
        return True

    if proc == "powershell.exe" and ("write-output $outfile" in detail_l or "$outfile =" in detail_l):
        return True
    if proc in {"python.exe", "pythonw.exe"} and "powershell.exe -noprofile -executionpolicy bypass" in detail_l:
        return True

    return False


#: Procmon records a process-create as "PID: <child>, Command line: ...", where
#: the record's own ``pid`` field is the *parent*. Both halves are needed to
#: reconstruct lineage.
_CHILD_PID_IN_DETAIL = re.compile(r"\bpid:\s*(\d+)", re.IGNORECASE)


def _child_pid_from_detail(detail: object) -> int | None:
    match = _CHILD_PID_IN_DETAIL.search(_normalize_text(detail))
    if not match:
        return None
    return _safe_int(match.group(1), default=0) or None


def _propagate_analyzer_lineage(
    records: list[dict[str, Any]],
    sample_pid: int | None = None,
    sample_name: str = "",
) -> None:
    """Mark descendants of analyzer processes as analyzer activity, in place.

    Naming a tool in ANALYZER_TOOL_PROCESS_NAMES only ever catches its direct
    children. FakeNet's startup is `fakenet.exe -> cmd.exe -> ipconfig.exe`, so
    the ipconfig was still landing in the sample's findings with cmd.exe as its
    apparent parent -- indistinguishable, by name alone, from a sample shelling
    out.

    The sample is deliberately excluded. It is launched *by* the analyzer, so its
    launch record is genuinely analyzer activity, but letting the sample's PID
    into the lineage set would suppress every process the sample goes on to
    create -- hiding precisely what the run exists to observe. That failure would
    be silent and would look like a well-behaved sample.
    """
    sample_proc = _normalize_process_name(sample_name)

    def _is_sample(record: dict[str, Any]) -> bool:
        if sample_pid and _child_pid_from_detail(record.get("detail")) == sample_pid:
            return True
        return bool(sample_proc) and _normalize_process_name(record.get("child_process_name")) == sample_proc

    analyzer_pids: set[int] = set()

    def _seed_from(record: dict[str, Any]) -> None:
        if _is_sample(record):
            return
        child_pid = _child_pid_from_detail(record.get("detail"))
        if child_pid:
            analyzer_pids.add(child_pid)

    for record in records:
        if record.get("is_analyzer_activity"):
            _seed_from(record)

    # Iterated to a fixed point rather than swept once: a single pass reaches
    # only the first generation, and the chain that motivated this is already
    # two deep.
    changed = True
    while changed:
        changed = False
        for record in records:
            if record.get("is_analyzer_activity"):
                continue
            parent_pid = record.get("pid")
            if not parent_pid or parent_pid not in analyzer_pids:
                continue
            if _is_sample(record):
                continue
            record["is_analyzer_activity"] = True
            record["analyzer_lineage"] = True
            _seed_from(record)
            changed = True


def _mark_sample_lineage(
    records: list[dict[str, Any]],
    sample_pid: int | None = None,
    sample_name: str = "",
) -> set[int] | None:
    """Mark process creates descending from the sample.

    Returns the descendant PIDs, or None when the sample could not be
    identified. The set is returned rather than a flag because network events
    need the same answer and are judged after this runs -- a connection is the
    sample's for exactly the same reason a process create is.

    Filtering background activity by name does not converge. Two runs of the
    same control reported entirely different sets -- one caught a Group Policy
    service host, the next caught an Intune check-in, OneDrive starting and
    three Defender console hosts -- because what Windows happens to do during
    a five-minute window is not a fixed list. Each fix only ever removed the
    instance in front of it.

    Lineage is the property that actually distinguishes them: the sample was
    pid 8696, and not one of those six descended from it.

    Returns False when the sample cannot be identified at all, which the caller
    must treat as "cannot tell" rather than "nothing descends". Getting that
    backwards would silently empty the findings of a run whose PID was never
    recorded -- a clean report on an unexamined sample.
    """
    sample_proc = _normalize_process_name(sample_name)

    descendant_pids: set[int] = set()
    if sample_pid:
        descendant_pids.add(int(sample_pid))

    # Any process running the sample's own image is the sample, whatever its
    # PID. A dropper relaunching itself is the shape this exists for: one
    # AgentTesla sample sat dormant for 77 seconds and then launched a second
    # copy of itself, and what that copy goes on to do is the sample's
    # behaviour by any reading. Seeding on the launched PID alone would file
    # all of it as background.
    if sample_proc:
        for record in records:
            child_pid = _child_pid_from_detail(record.get("detail"))
            if child_pid and _normalize_process_name(record.get("child_process_name")) == sample_proc:
                descendant_pids.add(child_pid)
            parent_pid = record.get("pid")
            if parent_pid and _normalize_process_name(record.get("process_name")) == sample_proc:
                descendant_pids.add(int(parent_pid))

    if not descendant_pids:
        return None

    # Fixed point for the same reason the analyzer sweep needs one: a
    # grandchild can be recorded before the child that connects it.
    changed = True
    while changed:
        changed = False
        for record in records:
            if record.get("descends_from_sample"):
                continue
            parent_pid = record.get("pid")
            child_pid = _child_pid_from_detail(record.get("detail"))
            if parent_pid in descendant_pids or (child_pid and child_pid in descendant_pids):
                record["descends_from_sample"] = True
                if child_pid:
                    descendant_pids.add(child_pid)
                changed = True

    return descendant_pids


def _is_independently_notable(record: dict[str, Any]) -> bool:
    """True when a process create is worth reporting whatever launched it.

    Lineage demotes activity that is otherwise unremarkable. It must not demote
    something already wrong on its own terms, because the case that motivated
    keeping non-descendants at all -- a sample acting through a process it does
    not parent, via injection, COM, a service or WMI -- shows up exactly here.
    In that case the command line is the evidence and the process tree is not.
    """
    if record.get("is_lolbin"):
        return True

    combined = (
        f"{_normalize_text_lower(record.get('path'))} "
        f"{_normalize_text_lower(record.get('detail'))}"
    )
    if any(marker in combined for marker in NOTABLE_LAUNCH_MARKERS):
        return True

    path = record.get("path")
    if path and (
        _looks_suspicious_path(path)
        or (_path_is_executable_or_script(path) and _path_is_user_writable(path))
    ):
        return True

    return False


def _looks_suspicious_path(value: object) -> bool:
    lowered = _normalize_text_lower(value)
    return any(part in lowered for part in SUSPICIOUS_PATH_KEYWORDS)


def _looks_persistence(value: object) -> bool:
    lowered = _normalize_text_lower(value)
    return any(part in lowered for part in PERSISTENCE_KEYWORDS)

def _is_low_confidence_persistence_dll_load(path: object, operation: object, process_name: object = None) -> bool:
    """
    Loading task scheduler DLLs is not persistence by itself.

    Procmon frequently records normal Windows components loading taskschd.dll
    or TaskSchdPS.dll. These should not count as persistence unless there is
    also a real task/service/Run-key write elsewhere.
    """
    op_l = _normalize_text_lower(operation)
    path_l = _normalize_text_lower(path).replace("/", "\\")
    proc_l = _normalize_process_name(process_name)

    if "load image" not in op_l:
        return False

    low_confidence_dlls = (
        r"\windows\system32\taskschd.dll",
        r"\windows\system32\taskschdps.dll",
    )

    if any(dll in path_l for dll in low_confidence_dlls):
        return True

    if proc_l in {
        "taskhostw.exe",
        "softlandingtask.exe",
        "sppsvc.exe",
        "deviceenroller.exe",
        "svchost.exe",
    } and "taskschd" in path_l:
        return True

    return False


def _path_is_user_writable(value: object) -> bool:
    lowered = _normalize_text_lower(value)
    return any(part in lowered for part in USER_WRITABLE_PATH_MARKERS)


def _path_is_executable_or_script(value: object) -> bool:
    return _path_suffix(value) in EXECUTION_RELATED_EXTENSIONS


#: Procmon results meaning the file was not there. Same list as the one in
#: dropped_file_triage, and needed separately here for the same reason the
#: analyzer markers were: these two modules judge the same events and neither
#: consults the other.
NOT_FOUND_RESULTS = {
    "name not found",
    "path not found",
    "no such file",
    "object name not found",
    "object path not found",
}

#: CreateFile dispositions that leave a file where there was none, or replace
#: what was there. `Open` is the one that cannot: it opens an existing file and
#: fails if there is nothing to open.
#:
#: This is what separates a drop from a touch, and the proportions are stark. Of
#: 42 suspicious-path hits on a Remcos run, **one** carried `Disposition:
#: OverwriteIf` -- the actual write of `%APPDATA%\Roaming\Config\smng.exe`. The
#: other 37 file events were all `Disposition: Open`: the payload reading itself,
#: `svchost.exe` noticing a new executable, and a DLL search walking a directory
#: for imports that were not there.
_PRODUCTIVE_DISPOSITIONS = ("create", "overwrite", "supersede", "openif")

_WRITE_OPERATIONS = (
    "writefile",
    "setrenameinformationfile",
    "setdispositioninformationfile",
)


def _event_result(event: dict[str, Any]) -> str:
    return _normalize_text_lower(event.get("result"))


def _result_is_not_found(event: dict[str, Any]) -> bool:
    """True when Procmon said the file was not there."""
    return _event_result(event) in NOT_FOUND_RESULTS


def _is_productive_file_operation(operation: object, detail: object) -> bool:
    """True when the event puts content on disk rather than reading it.

    A bare `CreateFile` is not a creation -- Procmon uses it for opens too, and
    the disposition in the detail is the only thing that says which. Treating
    every CreateFile as a drop is what let a DLL search read as eight dropped
    files.
    """
    op = _normalize_text_lower(operation)
    if any(marker in op for marker in _WRITE_OPERATIONS):
        return True
    if "createfile" not in op:
        return False
    return not _is_mere_file_open(operation, detail)


def _is_mere_file_open(operation: object, detail: object) -> bool:
    """True only for a CreateFile that opens an existing file and nothing more.

    Narrow on purpose, and the inverse of the test above rather than the same
    one. Anything that is not a file operation at all -- a process create, a
    registry write, an image load -- is not a "mere open", because the question
    does not apply to it. Conflating the two suppressed a process create of a
    relocated executable, which is a finding whoever started it and has its own
    test saying so.
    """
    op = _normalize_text_lower(operation)
    if "createfile" not in op:
        return False

    match = re.search(r"disposition:\s*([a-z]+)", _normalize_text_lower(detail))
    if not match:
        # Procmon always emits one; a missing disposition means the event is
        # unreadable rather than harmless, so it is not treated as a bare open.
        return False
    return not any(kind in match.group(1) for kind in _PRODUCTIVE_DISPOSITIONS)


def _is_independently_notable_path(path: object) -> bool:
    """True when the path is a finding whoever produced it.

    The same split the process-create filter already makes. Both of the
    conditions that put an event into the suspicious-path list are not equal:

    - an OS persistence surface (`\\Windows\\System32\\Tasks`, a Run key) is
      touched constantly by Windows itself, and only means something when the
      sample is the one touching it;
    - an executable or script written into a user-writable directory is notable
      regardless, because a sample can cause a write it does not perform --
      through injection, COM, a service or WMI -- and lineage cannot see that.

    So the first is attributed by lineage and the second is not. Collapsing them
    was what put Windows Update rewriting its own scheduled task into 12 of 14
    persistence hits; gating both would have thrown away a payload dropped into
    %TEMP% by an injected `svchost.exe`.
    """
    text = _normalize_text_lower(path)
    return _path_is_executable_or_script(text) and _path_is_user_writable(text)


def _is_high_signal_write(path: object, operation: object, detail: object = "") -> bool:
    """A file appearing where none was is a write, whatever Procmon calls it.

    This accepted only WriteFile and the rename/delete operations, so a run that
    demonstrably dropped a PE reported `file_write_events: 0` while the tile grid
    showed "Dropped Files 1" beside it. The drop had been logged as a CreateFile
    with `Disposition: OverwriteIf`, which is a write in every sense an analyst
    cares about.

    An *open* is still not a write, which is why this goes through
    ``_is_productive_file_operation`` rather than just adding CreateFile to the
    list above.
    """
    if not _is_productive_file_operation(operation, detail):
        return False

    path_l = _normalize_text_lower(path)
    if _looks_suspicious_path(path_l):
        return True
    if _path_is_executable_or_script(path_l) and _path_is_user_writable(path_l):
        return True
    return False


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
    child_proc = _event_process_image_name(process_name, path, detail)
    if proc in LOLBIN_NAMES or child_proc in LOLBIN_NAMES:
        return True
    combined = " ".join([_normalize_text_lower(process_name), _normalize_text_lower(path), _normalize_text_lower(detail)])
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


def _build_process_create_record(
    event: dict[str, Any], sample_name: str = ""
) -> dict[str, Any]:
    process_name = _event_process_name(event)
    path = _event_path(event)
    detail = _event_detail(event)
    child_process_name = _event_process_image_name(process_name, path, detail)

    return {
        "timestamp": _event_timestamp(event),
        "process_name": process_name,
        "child_process_name": child_process_name,
        "pid": _event_pid(event),
        "path": path,
        "detail": detail,
        "is_lolbin": _is_lolbin(process_name, path, detail),
        "is_analyzer_activity": _is_analyzer_activity(
            process_name, path, detail, sample_name=sample_name
        ),
        # Set by _mark_sample_lineage when the created process descends from
        # the sample. Absent lineage, a process create is something that
        # happened during the window, not something the sample did.
        "descends_from_sample": False,
        # Set by _propagate_analyzer_lineage when the record was excluded for
        # its ancestry rather than its own name, so the reason stays visible.
        "analyzer_lineage": False,
        "is_windows_baseline": _is_windows_baseline_process_create(process_name, path, detail),
        "is_noise_process": _is_noise_process(process_name) or _is_noise_process(child_process_name),
    }


def summarize_dynamic_findings(
    events: list[dict[str, Any]],
    interesting_events: list[dict[str, Any]],
    sample_pid: int | None = None,
    sample_name: str = "",
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
    background_write_counter: Counter[str] = Counter()
    write_records: list[dict[str, Any]] = []
    network_counter: Counter[str] = Counter()
    background_network_counter: Counter[str] = Counter()
    network_records: list[dict[str, Any]] = []

    process_creates: list[dict[str, Any]] = []
    background_processes: list[dict[str, Any]] = []
    process_create_records: list[dict[str, Any]] = []
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

        # On a process create the path names the process being *created*, so a
        # noise child matters as much as a noise parent. Only the parent was
        # checked, which is why svchost starting OneDriveLauncher out of AppData
        # was reported as a suspicious path even with onedrivelauncher.exe
        # listed as noise -- the name being tested was svchost's.
        #
        # Confined to process creates on purpose: for a file write or a registry
        # set the path is not a process at all, and reading it as one would
        # suppress on a filename that merely happens to match a noise process.
        if "process" in operation and "create" in operation:
            if _is_noise_process(_event_process_image_name(process_name, path, detail)):
                is_noise_proc = True

        is_noise_path = _is_noise_path(path)
        is_analyzer = _is_analyzer_activity(
            process_name, path, detail, sample_name=sample_name
        )
        is_windows_baseline = _is_windows_baseline_process_create(process_name, path, detail)
        is_benign_registry = _is_benign_registry_noise(path, operation, detail)
        is_defender_or_wbem = _is_defender_or_wbem_noise(path, process_name, detail)
        
        is_low_confidence_persistence_load = _is_low_confidence_persistence_dll_load(
            path,
            operation,
            process_name,
        )

        if "process" in operation and "create" in operation:
            # Collected whole and filtered after the loop. Lineage cannot be
            # resolved one event at a time: a child can be seen before the
            # parent that condemns it.
            process_create_records.append(
                _build_process_create_record(event, sample_name=sample_name)
            )

        if "tcp connect" in operation or ("network" in operation and "connect" in operation):
            if process_name and not is_noise_proc and not is_analyzer and not is_windows_baseline and not is_defender_or_wbem:
                # Collected with its PID and judged after the loop, for the
                # same reason process creates are: lineage cannot be resolved
                # one event at a time. A connection from svchost or Defender is
                # the machine's, not the sample's, and naming every such
                # process is the approach that already failed for spawns.
                network_records.append(
                    {"process_name": process_name, "pid": _event_pid(event)}
                )

        # A Procmon event that failed with "not found" observed an absence. It
        # is never evidence of a drop, a write or a persistence change, and
        # letting them through put eight non-existent DLLs into the suspicious
        # paths of one run. dropped_file_triage filters these too; neither
        # module consults the other.
        if _result_is_not_found(event):
            continue

        if _is_high_signal_write(path, operation, detail):
            if path and not is_noise_path and not is_analyzer and not is_windows_baseline and not is_defender_or_wbem:
                # Staged with its PID and judged after the loop, like the
                # network records below. Attributing a write on the spot counted
                # Windows Update rewriting its own scheduled task as the
                # sample's: svchost.exe accounted for every entry in
                # top_written_paths on the first run where file events reached
                # the findings at all.
                write_records.append({"path": path, "pid": _event_pid(event)})

        joined = f"{path} {detail}"
        if path and (_looks_suspicious_path(path) or (_path_is_executable_or_script(path) and _path_is_user_writable(path))):
            if (
                not is_noise_proc
                and not is_noise_path
                and not is_analyzer
                and not is_windows_baseline
                and not is_benign_registry
                and not is_defender_or_wbem
                and not is_low_confidence_persistence_load
            ):
                suspicious_path_hits.append(
                    {
                        "timestamp": _event_timestamp(event),
                        "process_name": process_name,
                        "path": path,
                        "operation": operation,
                        "detail": detail,
                        "_pid": _event_pid(event),
                        "_produced": not _is_mere_file_open(operation, detail),
                    }
                )

        if joined and _looks_persistence(joined):
            if (
                not is_noise_proc
                and not is_noise_path
                and not is_analyzer
                and not is_windows_baseline
                and not is_benign_registry
                and not is_defender_or_wbem
                and not is_low_confidence_persistence_load
            ):
                persistence_hits.append(
                    {
                        "timestamp": _event_timestamp(event),
                        "process_name": process_name,
                        "path": path,
                        "operation": operation,
                        "detail": detail,
                        "_pid": _event_pid(event),
                    }
                )

    _propagate_analyzer_lineage(process_create_records, sample_pid=sample_pid, sample_name=sample_name)

    descendant_pids = _mark_sample_lineage(
        process_create_records, sample_pid=sample_pid, sample_name=sample_name
    )
    lineage_resolved = descendant_pids is not None

    # Network connections judged the same way. Without this, an AgentTesla run
    # counted svchost and MpDefenderCoreService among the sample's network
    # events -- once FakeNet could intercept, every resident service started
    # reaching the simulated internet and reading as the sample's traffic.
    #
    # Unresolved lineage counts everything, as it does for process creates:
    # "we could not tell whose connection this was" must not silently empty the
    # network findings.
    for record in network_records:
        pid = record.get("pid")
        if lineage_resolved and pid not in descendant_pids:
            background_network_counter[record["process_name"]] += 1
            continue
        network_counter[record["process_name"]] += 1
        network_event_count += 1

    # Writes, suspicious paths and persistence hits get the same treatment, and
    # for the same reason. Until file events reached the findings at all, none of
    # these three had ever been attributed: the first run that surfaced them put
    # Windows Update's own `svchost.exe` rewriting
    # `\Tasks\Microsoft\Windows\UpdateOrchestrator\Schedule Work` into 12 of 14
    # persistence hits and into every row of top_written_paths.
    #
    # A path keyword says what kind of thing happened. It cannot say who did it,
    # and the OS touches its own autostart surfaces constantly.
    def _belongs_to_sample(pid: object) -> bool:
        return not lineage_resolved or pid in descendant_pids

    def _keep(pid: object, path: object = None, produced: bool = True) -> bool:
        # See _is_independently_notable_path: an executable dropped into a
        # user-writable directory stands on its own, an OS persistence surface
        # does not.
        #
        # ``produced`` narrows that exemption to events that actually put the
        # file there. It was written as "notable whoever produced it" and then
        # applied to any event naming the path, so `svchost.exe` opening the
        # payload six times -- Defender and the indexer noticing a new
        # executable -- was exempted from lineage along with the drop itself.
        if produced and _is_independently_notable_path(path):
            return True
        return _belongs_to_sample(pid)

    for record in write_records:
        if _keep(record.get("pid"), record["path"]):
            write_counter[record["path"]] += 1
            file_write_event_count += 1
        else:
            background_write_counter[record["path"]] += 1

    background_suspicious_paths = 0
    kept_suspicious: list[dict[str, Any]] = []
    for hit in suspicious_path_hits:
        if _keep(hit.pop("_pid", None), hit.get("path"), hit.pop("_produced", True)):
            kept_suspicious.append(hit)
        else:
            background_suspicious_paths += 1
    suspicious_path_hits = kept_suspicious

    # Persistence is attributed by lineage alone. Every entry here is a pure
    # keyword match against an autostart surface, with no independently notable
    # arm to preserve -- and those surfaces belong to the OS, which writes to
    # them on its own schedule.
    background_persistence = 0
    kept_persistence: list[dict[str, Any]] = []
    for hit in persistence_hits:
        if _belongs_to_sample(hit.pop("_pid", None)):
            kept_persistence.append(hit)
        else:
            background_persistence += 1
    persistence_hits = kept_persistence

    # Exclude RingForge helper tools and their descendants, known OS noise, and
    # normal Windows packaged-app helper behavior from the sample's findings.
    for record in process_create_records:
        if (
            record["is_noise_process"]
            or record["is_analyzer_activity"]
            or record["is_windows_baseline"]
        ):
            continue

        # Everything else that ran during the window but did not come from the
        # sample is context, not a finding: recorded and reportable, but not
        # counted and not scored. Kept rather than dropped because a sample can
        # cause a process it does not parent -- through injection, COM, a
        # service, or WMI -- and that evidence would otherwise be destroyed by
        # the same filter that removes Windows' housekeeping.
        #
        # Only applied when lineage was actually resolved. Without it every
        # record would land here and the run would report nothing at all.
        #
        # And never applied to something suspicious in its own right: a
        # relocated LOLBin or an encoded command line is a finding whoever
        # started it, which is the half of this that lineage cannot see.
        if (
            lineage_resolved
            and not record.get("descends_from_sample")
            and not _is_independently_notable(record)
        ):
            background_processes.append(record)
            continue

        process_creates.append(record)
        process_create_count += 1
        if record["is_lolbin"]:
            lolbin_count += 1

    findings["top_written_paths"] = [{"path": path, "count": count} for path, count in write_counter.most_common(10)]
    findings["top_network_processes"] = [{"process_name": process_name, "count": count} for process_name, count in network_counter.most_common(10)]
    # Context, like the background process creates: these connected during the
    # window but not from the sample, so they are reported and not scored.
    findings["background_network_processes"] = [
        {"process_name": process_name, "count": count}
        for process_name, count in background_network_counter.most_common(10)
    ]
    # Same contract as the background processes and connections: reported so a
    # reader can see the machine was busy, never counted and never scored.
    findings["background_written_paths"] = [
        {"path": path, "count": count}
        for path, count in background_write_counter.most_common(10)
    ]
    findings["spawned_processes"] = process_creates[:25]
    findings["background_processes"] = background_processes[:25]
    # Distinguishes "nothing ran that the sample did not cause" from "we could
    # not tell", which are the same empty list otherwise.
    findings["lineage_resolved"] = lineage_resolved
    # Published so other passes can attribute by the same lineage rather than
    # resolving it again from a different source. `None` when it could not be
    # resolved, which callers must treat as "count everything" rather than as an
    # empty tree -- the same contract the PowerShell blocks follow.
    findings["descendant_pids"] = (
        sorted(descendant_pids) if lineage_resolved else None
    )
    findings["suspicious_path_hits"] = suspicious_path_hits[:50]
    findings["persistence_hits"] = persistence_hits[:25]

    counts = {
        "interesting_events": len(interesting_events),
        "process_creates": process_create_count,
        "background_processes": len(background_processes),
        "background_network_events": sum(background_network_counter.values()),
        "network_events": network_event_count,
        "file_write_events": file_write_event_count,
        "suspicious_path_hits": len(suspicious_path_hits),
        "persistence_hits": len(persistence_hits),
        "lolbin_processes": lolbin_count,
        # Every filter that removes something records that it did, so a run with
        # nothing to show stays distinguishable from one that could not tell.
        "background_write_events": sum(background_write_counter.values()),
        "background_suspicious_path_hits": background_suspicious_paths,
        "background_persistence_hits": background_persistence,
    }
    findings["counts"] = counts

    highlights: list[str] = []
    if process_create_count:
        highlights.append(f"Spawned processes observed: {process_create_count}")
    if network_event_count:
        highlights.append(f"Network connect events observed: {network_event_count}")
    if file_write_event_count:
        highlights.append(f"High-signal file writes observed: {file_write_event_count}")
    if suspicious_path_hits:
        highlights.append(f"Suspicious path hits observed: {len(suspicious_path_hits)}")
    if persistence_hits:
        highlights.append(f"Persistence-related hits observed: {len(persistence_hits)}")
    if lolbin_count:
        highlights.append(f"LOLBin processes observed: {lolbin_count}")

    findings["highlights"] = highlights
    return findings
