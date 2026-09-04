"""What has to be true before a detonation starts, decided without a display.

**Why this is a module and not a method on the window.** Roughly 150 lines in
`gui/dynamic_window.py` decided whether a run may start: which conditions stop
it, which merely warn, and the wording of each. Every one of those decisions
referenced no widget -- the `messagebox` calls were the last three lines -- so
none of them could be imported without a display and none had a test. Fifth
module through this pass, and the same shape as the other four.

**The one this was hiding.** The Procmon config check warned only when the
config file could be *read* and said it captures no registry reads:

    if described.get("readable") and not described.get("captures_registry_reads")

A config that could not be parsed produced no warning at all. That is missing
data read as a clean result, about the one setting `procmon_config` documents
as unrecoverable: registry reads are dropped at capture, and no later pass over
the PML can bring them back. A run started against an unreadable config, found
nothing, and the absence looked like a finding about the sample.

**Blocking and warning are different claims.** An issue means the run cannot
produce a valid case; a warning means it can, with a hole in it the analyst
should know about before rather than after. Nothing here decides for the
analyst -- the caller shows the warnings and asks.
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from dynamic_analysis.procmon_config import describe_procmon_filter

#: Autorunsc, under every spelling this tool has shipped it as. Optional, so
#: its absence is a warning rather than a stop.
AUTORUNSC_NAMES = ("autorunsc64.exe", "Autorunsc64.exe",
                   "autorunsc.exe", "Autorunsc.exe")

#: The config that does capture registry reads, named in the warning so the
#: analyst has somewhere to go rather than only something to worry about.
REGISTRY_READS_CONFIG = "tools/procmon-configs/dynamic_registry_reads.pmc"


@dataclass
class Preflight:
    """Everything the dialog needs, and no opinion about how to show it."""

    #: Conditions that stop the run. A non-empty list means do not start.
    issues: list[str] = field(default_factory=list)
    #: Conditions the analyst may accept. The caller asks; this does not.
    warnings: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.issues)


def is_running_as_admin() -> bool:
    """True when this process is elevated.

    Procmon capture, service and scheduled-task snapshots and Autoruns
    collection are all less complete without it, which is a warning rather
    than a stop: a run without them is still a run.
    """
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def find_autorunsc(project_root: str | Path) -> Path | None:
    tools = Path(project_root) / "tools"
    for name in AUTORUNSC_NAMES:
        candidate = tools / name
        if candidate.exists():
            return candidate
    return None


def check_folder_writable(folder: str | Path) -> tuple[bool, str]:
    """Create the folder and write a byte into it.

    Asking the filesystem rather than checking a permission bit: a network
    share, a read-only mount and a path too long all fail here and none of
    them fails a bit test.
    """
    folder = Path(folder)
    try:
        folder.mkdir(parents=True, exist_ok=True)
        probe = folder / ".ringforge_write_test"
        probe.write_text("ringforge write test", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True, ""
    except Exception as error:
        return False, str(error)


def case_matches_sample(sample_stem: str, case_name: str) -> bool:
    """Whether the case folder plausibly belongs to this sample.

    Substring either way, because a case is routinely named for the sample
    with a suffix. Empty on either side is not a mismatch -- there is nothing
    to disagree with, and blocking on it would fire on every unnamed case.
    """
    sample_stem = (sample_stem or "").strip().lower()
    case_name = (case_name or "").strip().lower()
    if not sample_stem or not case_name:
        return True
    return (case_name == sample_stem
            or sample_stem in case_name
            or case_name in sample_stem)


def observation_conflict(
    timeout_seconds: int,
    minimum_observation_seconds: int,
    post_exit_observation_seconds: int,
) -> str | None:
    """The post-exit window against the hard timeout, in seconds.

    Returns the warning to show, or `None` when the settings fit. This is
    allowed rather than blocked -- a quick baseline run against Notepad wants
    exactly this shape -- but the timeout wins and the analyst should know
    before the run rather than infer it from a short capture afterwards.
    """
    if timeout_seconds <= 0 or post_exit_observation_seconds <= 0:
        return None

    settings = (f"Sample observation timeout: {timeout_seconds} seconds\n"
                f"Minimum observation: {minimum_observation_seconds} seconds\n"
                f"Post-exit observation target: "
                f"{post_exit_observation_seconds} seconds")

    if post_exit_observation_seconds >= timeout_seconds:
        return (
            "Post-exit observation is longer than or equal to the sample "
            "observation timeout.\n\n"
            f"{settings}\n\n"
            "The run can still continue, but RingForge will stop at the "
            "timeout before the full post-exit observation window completes."
            "\n\nThis is usually fine for quick baseline tests like Notepad. "
            "For larger installers, increase the timeout.")

    remaining = timeout_seconds - minimum_observation_seconds
    if remaining > 0 and post_exit_observation_seconds > remaining:
        return (
            "Post-exit observation may not fully fit after the minimum "
            "observation window.\n\n"
            f"{settings}\n"
            f"Maximum possible post-exit time after minimum observation: "
            f"{remaining} seconds\n\n"
            "The run can still continue, but RingForge may stop at the "
            "timeout before the full post-exit observation window completes.")

    return None


def _procmon_config_warnings(
    procmon_config: str, describe=describe_procmon_filter
) -> list[str]:
    """What the configured Procmon filter will and will not capture.

    **The unreadable case is a warning, added 03 Sep.** This used to require
    `readable` before it would say anything, so a config that could not be
    parsed passed in silence -- and registry reads are dropped at capture,
    which means a run started that way cannot be repaired afterwards. Not
    knowing what a filter captures is the thing worth saying, not the thing
    that excuses saying nothing.
    """
    if not procmon_config:
        return []

    path = Path(procmon_config)
    if not path.exists():
        return ["Procmon config file was not found. RingForge will continue, "
                "but Procmon may run with default capture behavior:\n"
                f"{path}"]

    described = describe(path) or {}
    if not described.get("readable"):
        note = str(described.get("note", "") or "").strip()
        return ["This Procmon config could not be read, so what it captures "
                "is unknown. If it drops registry reads, a sample checking "
                "for a VM artifact could not be seen and no later pass can "
                "recover that.\n\n"
                f"{path}\n"
                + (f"\n{note}\n" if note else "")
                + f"\nUse {REGISTRY_READS_CONFIG} instead."]

    if not described.get("captures_registry_reads"):
        return ["This Procmon config captures no registry reads, so a sample "
                "checking for a VM artifact could not be seen. The reads are "
                "dropped at capture and no later pass can recover them.\n\n"
                f"{path}\n\n"
                f"Use {REGISTRY_READS_CONFIG} instead."]

    return []


def run_preflight(
    *,
    sample: str | Path,
    case_home: str | Path,
    dynamic_output: str | Path,
    procmon_enabled: bool,
    procmon_path: str | Path,
    procmon_config: str = "",
    project_root: str | Path = ".",
    describe=describe_procmon_filter,
    admin: bool | None = None,
) -> Preflight:
    """Every gate on a dynamic run, as data.

    `admin` is injectable so the elevation warning can be exercised on a bench
    that happens to be elevated, or on one that is not.
    """
    sample = Path(sample)
    case_home = Path(case_home)
    dynamic_output = Path(dynamic_output)
    procmon_path = Path(procmon_path)
    result = Preflight()

    if not sample.exists():
        result.issues.append(f"Sample file not found:\n{sample}")
    elif not sample.is_file():
        result.issues.append(f"Selected sample path is not a file:\n{sample}")

    for label, folder in (("Case folder", case_home),
                          ("Dynamic output folder", dynamic_output)):
        ok, error = check_folder_writable(folder)
        if not ok:
            result.issues.append(
                f"{label} is not writable:\n{folder}\n\n{error}")

    if procmon_enabled:
        if not procmon_path.exists():
            result.issues.append(
                "Procmon is enabled but the executable was not found:\n"
                f"{procmon_path}")
        elif not procmon_path.is_file():
            result.issues.append(f"Procmon path is not a file:\n{procmon_path}")
        # **Gated on Procmon being enabled, corrected 03 Sep.** The config
        # checks ran regardless, so a run with Procmon switched off warned
        # about a filter that was never going to be loaded -- noise in the one
        # dialog that has to be read.
        result.warnings.extend(_procmon_config_warnings(procmon_config, describe))

    if find_autorunsc(project_root) is None:
        tools = Path(project_root) / "tools"
        result.warnings.append(
            "Autorunsc was not found in the local tools folder. "
            "Autoruns persistence diffing may be skipped.\n\n"
            "Expected one of:\n"
            f"{tools / 'autorunsc64.exe'}\n{tools / 'autorunsc.exe'}")

    elevated = is_running_as_admin() if admin is None else admin
    if os.name == "nt" and not elevated:
        result.warnings.append(
            "RingForge is not running as Administrator. Procmon capture, "
            "service snapshots, scheduled task snapshots, and Autoruns "
            "collection may be incomplete.")

    return result


def issues_message(issues: Sequence[str]) -> str:
    return ("Dynamic Analysis cannot start until these issues are fixed:\n\n"
            + "\n\n".join(issues))


def warnings_message(warnings: Sequence[str]) -> str:
    return ("Dynamic Analysis can start, but these warnings were found:\n\n"
            + "\n\n".join(warnings)
            + "\n\nContinue anyway?")


def case_mismatch_message(sample_name: str, case_home: Any) -> str:
    return ("The selected sample name does not appear to match the selected "
            "case folder.\n\n"
            f"Sample:\n{sample_name}\n\n"
            f"Case folder:\n{case_home}\n\n"
            "This may mix dynamic results into the wrong case.\n\n"
            "Continue anyway?")
