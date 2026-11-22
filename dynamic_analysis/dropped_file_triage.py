from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from dynamic_analysis.utils import file_size, md5_file, sha1_file, sha256_file


DROPPED_FILE_EXTENSIONS = {
    ".exe": "executable",
    ".dll": "library",
    ".sys": "driver",
    ".ps1": "powershell_script",
    ".bat": "batch_script",
    ".cmd": "batch_script",
    ".js": "javascript",
    ".jse": "javascript",
    ".vbs": "vbscript",
    ".vbe": "vbscript",
    ".hta": "html_application",
    ".scr": "screensaver_executable",
    ".com": "executable",
    ".pif": "program_information_file",
    ".jar": "java_archive",
    ".msi": "windows_installer",
}

# Every marker here is matched with a plain `in` or `startswith` test, and every
# one of them used to carry a doubled separator that no real path contains. This
# module is where that mattered most: `collect_dropped_file_candidates` discards
# any candidate whose path is not in a suspicious location, so with the list dead
# `total_candidates` was structurally pinned at 0. Fixing the Procmon-side
# markers alone would not have moved it -- the Remcos drop of
# %APPDATA%\Roaming\Config\smng.exe would have reached this function and been
# thrown away here instead.
#
# The exclusions had the same defect, so nothing was ever excluded either. They
# only start doing work now that the suspicious list does, which is why both are
# in one change.
SUSPICIOUS_PATH_KEYWORDS = [
    "\\appdata\\",
    "\\temp\\",
    "\\programdata\\",
    "\\startup\\",
    "\\users\\public\\",
]

EXCLUDED_PATH_PREFIXES = [
    "c:\\windows\\system32\\",
    "c:\\windows\\winsxs\\",
    "c:\\windows\\servicing\\",
    "c:\\windows\\installer\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\windows defender\\",
]

ANALYZER_NOISE_MARKERS = [
    "\\cases\\",
    "\\procmon\\",
    "\\reports\\",
    "\\metadata\\",
    "\\persistence\\",
    "\\files\\",
    # This module keeps its own list, separate from findings.py's, so the
    # FakeNet exclusion has to be added in both places -- repairing only the
    # findings side still left the diverter's own driver counted as a dropped
    # file, and `payload_dropped` reaching strong on it plus one real drop.
    "\\_mei",
    "\\pydivert\\",
    "windivert",
    # PowerShell writes one of these into %TEMP% on every invocation to test the
    # execution policy, then deletes it. They are the sample's own lineage --
    # its powershell.exe wrote them -- and they are still not drops. Two of them
    # helped push payload_dropped to strong on a loader that drops nothing.
    "__psscriptpolicytest_",
]

#: Procmon results meaning the file was not there. A `CreateFile` that returns
#: one of these did not create anything -- it asked and was told no.
#:
#: This is the difference between a drop and a probe, and without it the two are
#: indistinguishable. A Remcos run reported 13 suspicious dropped files of which
#: 11 did not exist: `smng.exe`, running out of %APPDATA%\Roaming\Config, walking
#: the DLL search order for WINMM.dll, urlmon.dll, WININET.dll and iertutil.dll
#: in its own directory. Every one of those was a failed open, and together they
#: took `payload_dropped` to strong on a true count of one.
#:
#: Deliberately a not-found list rather than "keep only SUCCESS". A write that
#: succeeded and was then deleted by the sample is still a drop, and results
#: like REPARSE or FAST IO DISALLOWED are ordinary intermediate steps.
NOT_FOUND_RESULTS = {
    "name not found",
    "path not found",
    "no such file",
    "object name not found",
    "object path not found",
}

ALLOWED_EVENT_CATEGORIES = {
    "file_create",
    "file_write",
}


def normalize_windows_path(path_value: str) -> str:
    return str(Path(path_value))


def looks_like_candidate_file(path_value: str) -> bool:
    p = str(path_value).strip()
    if not p:
        return False

    ext = Path(p).suffix.lower()
    return ext in DROPPED_FILE_EXTENSIONS


def result_is_not_found(result_value: object) -> bool:
    """True when a Procmon result says the file was not there."""
    return str(result_value or "").strip().lower() in NOT_FOUND_RESULTS


def path_is_in_suspicious_location(path_value: str) -> bool:
    p = path_value.lower()
    return any(keyword in p for keyword in SUSPICIOUS_PATH_KEYWORDS)


def path_is_excluded(path_value: str) -> bool:
    p = path_value.lower()
    if any(p.startswith(prefix) for prefix in EXCLUDED_PATH_PREFIXES):
        return True
    return any(marker in p for marker in ANALYZER_NOISE_MARKERS)


#: The .NET CodeDom compiler's scratch output. `Add-Type` in PowerShell shells
#: out to `csc.exe`, which writes its temporary assembly to
#: `%TEMP%\<random>\<random>.dll` -- directory basename and file stem identical
#: -- plus `CSC<hex>.TMP` and `RES<hex>.tmp` alongside it.
#:
#: Found on run `33fe6c3b`, where a PowerShell RunPE script took
#: `payload_dropped` to **strong** on exactly two of these:
#:
#:     C:\Users\adam\AppData\Local\Temp\zrudxjpg\zrudxjpg.dll
#:     C:\Users\adam\AppData\Local\Temp\hryya5bb\hryya5bb.dll
#:
#: Both are real files the sample's tree really wrote, so the collection is
#: right and the *claim* is wrong: **every** PowerShell script that calls
#: `Add-Type` drops these, and that population is mostly legitimate
#: administration. A category reaching `strong` on a compiler's scratch files is
#: the volume-driven model the score design exists to avoid.
#:
#: Set aside and counted rather than dropped -- the same treatment `pe_carve`
#: gives `resource_only` images. A signal that fires on every process on the
#: machine says nothing about any of them, and hiding the count would make this
#: pass unauditable.
_CSC_SCRATCH = re.compile(r"^(csc[0-9a-f]+\.tmp|res[0-9a-f]+\.tmp)$", re.I)


def path_is_compiler_artifact(path_value: str) -> bool:
    r"""A `csc.exe` temporary assembly or its scratch files.

    Deliberately narrow. The shape is `<temp>\<name>\<name>.dll|.pdb` with the
    directory and the stem equal, which is what `Path.GetRandomFileName` plus
    CodeDom produces and is not a shape ordinary droppers use. A malicious
    assembly compiled this way is still collected and still reported -- it
    simply stops carrying a scored category by itself, because the behaviour
    that matters is the scripted execution around it, and that is scored
    separately as `scripted_execution`.
    """
    norm = normalize_windows_path(path_value)
    if not path_is_in_suspicious_location(norm):
        return False
    parts = [seg for seg in norm.replace("/", "\\").split("\\") if seg]
    if len(parts) < 2:
        return False
    name = parts[-1]
    if _CSC_SCRATCH.match(name):
        return True
    stem, dot, ext = name.rpartition(".")
    if not dot or ext.lower() not in {"dll", "pdb"}:
        return False
    return stem.lower() == parts[-2].lower()


#: Where an installer or a self-extracting runtime unpacks **its own** files
#: into temp, to load them in its own process.
#:
#: Added 21 Nov (roadmap Step 3b). On the held-out benign corpus,
#: `payload_dropped` was in 35 of the 44 installers at Corroborated or
#: stronger -- strong in 26 -- and almost all of it was these. Every such
#: installer or app writes them, benign or not, so on their own they say
#: nothing about the sample.
#:
#:     %TEMP%\nsXXXX.tmp\          NSIS $PLUGINSDIR (System.dll, nsExec.dll, ...)
#:     %TEMP%\.net\<app>\          .NET single-file extraction
#:     %TEMP%\e4j*.tmp_dir*\       install4j's bundled Java runtime
#:     %TEMP%\AI_EXTUI_BIN_*\      Advanced Installer UI
#:     %TEMP%\aitmp<n>\            Advanced Installer scratch
#:
#: **Not exempt, deliberately:** install destinations (`%LOCALAPPDATA%\
#: Programs\`, Squirrel's `app-x.y`), where malware posing as an app would
#: write; Inno's `is-*.tmp`, which two held-out malware samples used; and
#: anything outside these exact shapes, even from the same installer.
#:
#: Measured before it was made (HANDOFF, *21 Nov night, Step 3b*): held-out
#: benign 46.8% -> 25.5% Corroborated or stronger, and **no malware case left
#: Corroborated+** on either corpus. The 15 NSIS-built malware in `mal-112b`,
#: whose only drop was NSIS's own `System.dll`, all stayed on other evidence.
_INSTALLER_SCRATCH = re.compile("|".join([
    r"\\temp\\ns[a-z0-9]{2,8}\.tmp\\",
    r"\\temp\\[.]net\\",
    r"\\temp\\e4j[^\\]*\.tmp_dir",
    r"\\temp\\ai_extui_bin_[^\\]*",
    r"\\temp\\aitmp\d+\\",
]), re.I)

#: A Windows 8.3 short-name segment inside temp, e.g. `E4J1C1~1.TMP`. Sysmon
#: reports an image by the path it was started with, so a scratch folder can
#: arrive under a name the shapes above do not match.
_SHORT_TEMP_SEGMENT = re.compile(r"\\temp\\[^\\]*~\d[^\\]*\\", re.I)

#: A file name with a candidate extension, as it appears in a command line or
#: a persistence entry.
_NAMED_FILE = re.compile(
    r"([^\\/:*?\"<>|\s,;=']+\.(?:" +
    "|".join(ext.lstrip(".") for ext in DROPPED_FILE_EXTENSIONS) + r"))\b", re.I)


def path_is_installer_scratch(path_value: str) -> bool:
    """A file an installer or runtime unpacked into temp for itself. See
    `_INSTALLER_SCRATCH`."""
    return bool(_INSTALLER_SCRATCH.search(normalize_windows_path(path_value)))


def _read_json(path: Path) -> Any:
    try:
        with open(path, encoding="utf-8-sig") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def started_and_persisted(run_dir: Path) -> dict[str, Any] | None:
    """What this run started as a process, and what it made persistent.

    Read from the files the run writes, so detonation and `runcontrol.rescore`
    answer the same question the same way:

    * Sysmon event 1 (image and command line) and Procmon `process_create`
      (path and command line) -- every process started, whoever started it;
    * the Autoruns, task and service diffs -- every new persistence entry.

    Returns the lower-cased file names those mention, and whether anything
    was started from inside a scratch folder -- by its long path, or by a
    short `~1` path in temp, which the shapes cannot recognise.

    **Returns None when neither process-start record could be read.** Not
    knowing what was started is not evidence that nothing was, and
    `apply_installer_scratch` sets nothing aside on None. A missing
    persistence diff alone does not do this: Autoruns has failed on runs
    before, and a scratch file made persistent would usually be started too.
    """
    run_dir = Path(run_dir)
    names: set[str] = set()
    from_scratch = False
    lines: list[str] = []

    sysmon = _read_json(run_dir / "sysmon" / "sysmon_events.json")
    procmon = _read_json(run_dir / "procmon" / "interesting_events.json")
    if not isinstance(sysmon, list) and not isinstance(procmon, list):
        return None
    for event in sysmon if isinstance(sysmon, list) else []:
        if not isinstance(event, dict) or str(event.get("event_id")) != "1":
            continue
        values = event.get("data_values") or []
        image = str(values[4]) if len(values) > 4 else ""
        command = str(values[10]) if len(values) > 10 else ""
        lines += [image, command]

    for event in procmon if isinstance(procmon, list) else []:
        if isinstance(event, dict) and event.get("category") == "process_create":
            lines += [str(event.get("path", "")), str(event.get("detail", ""))]

    for line in lines:
        if not line:
            continue
        names.update(n.lower() for n in _NAMED_FILE.findall(line))
        names.add(Path(line.strip().strip('"').replace("/", "\\").split("\\")[-1]).name.lower())
        if _INSTALLER_SCRATCH.search(line) or _SHORT_TEMP_SEGMENT.search(line):
            from_scratch = True

    for rel in (("autoruns", "autoruns_diff.json"), ("persistence", "task_diffs.json"),
                ("persistence", "service_diffs.json")):
        try:
            text = (run_dir.joinpath(*rel)).read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        names.update(n.lower() for n in _NAMED_FILE.findall(text.replace("\\\\", "\\")))

    return {"names": names, "started_from_scratch": from_scratch}


def apply_installer_scratch(items: list[dict[str, Any]],
                            evidence: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Set installer scratch aside -- unless the run started it or persisted it.

    `installer_scratch` says where a file is; `installer_scratch_set_aside`
    says it is not scored. **A scratch file counts again as an ordinary drop**
    when its name was started as a process, appears in a command line or a
    new persistence entry, or when anything at all was started from inside a
    scratch folder -- the shape malware unpacking a payload there and running
    it would leave. Matching by name, and the case-wide rule, are
    deliberately loose: they err towards counting.

    `evidence` is `started_and_persisted(...)`. **None means it could not be
    read, and then nothing is set aside**: the exemption is only granted on
    evidence that the files were not run.

    Measured on the scored corpora (21 Nov): of 25 scratch files in 15
    malware cases, none was started or persisted; of 3,501 in benign
    installers, 3 were (one install4j app starting its own Java runtime).
    """
    names = set(evidence.get("names", ())) if evidence else set()
    from_scratch = bool(evidence.get("started_from_scratch")) if evidence else False
    out: list[dict[str, Any]] = []
    for item in items:
        record = dict(item)
        scratch = path_is_installer_scratch(str(record.get("path", "")))
        record["installer_scratch"] = scratch
        reinstated = scratch and (
            evidence is None or from_scratch
            or Path(str(record.get("path", ""))).name.lower() in names)
        record["installer_scratch_set_aside"] = scratch and not reinstated
        if scratch and reinstated:
            record["installer_scratch_reinstated_because"] = (
                "the run's start and persistence records could not be read"
                if evidence is None else
                "something was started from inside a scratch folder"
                if from_scratch else
                "it was started as a process or named by new persistence")
        # Recomputed, so this stays right however the record arrived -- fresh
        # from the guest, or re-read from an old case by a rescore. A record
        # too old to carry `reasons` keeps the verdict it was written with.
        record["compiler_artifact"] = path_is_compiler_artifact(str(record.get("path", "")))
        base = (bool(record.get("reasons")) if "reasons" in record
                else bool(record.get("suspicious")))
        record["suspicious"] = (base
                                and not record["compiler_artifact"]
                                and not record["installer_scratch_set_aside"])
        out.append(record)
    return out


def classify_path(path_value: str) -> str:
    ext = Path(path_value).suffix.lower()
    return DROPPED_FILE_EXTENSIONS.get(ext, "unknown")


def collect_dropped_file_candidates(
    events: list[dict[str, Any]],
    descendant_pids: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Files the sample put on disk.

    ``descendant_pids`` is the sample's process tree. Without it every write on
    the machine counts as the sample's, which is how a loader that drops nothing
    reported `payload_dropped` **strong**: two libraries written by
    `msedgewebview2.exe` into an Office package directory, from a browser that
    had nothing to do with the run.

    Passing ``None`` is not the same as passing an empty set. ``None`` means
    lineage could not be resolved and everything is counted, the way the
    findings and the PowerShell blocks already degrade; an empty set would mean
    the sample provably wrote nothing.
    """
    seen: set[str] = set()
    candidates: list[dict[str, Any]] = []

    for event in events:
        category = str(event.get("category", ""))
        path_value = str(event.get("path", "")).strip()

        if category not in ALLOWED_EVENT_CATEGORIES:
            continue

        if descendant_pids is not None:
            try:
                pid = int(event.get("pid"))
            except (TypeError, ValueError):
                pid = None
            if pid not in descendant_pids:
                continue

        if result_is_not_found(event.get("result")):
            continue

        if not looks_like_candidate_file(path_value):
            continue

        norm = normalize_windows_path(path_value)
        norm_key = norm.lower()

        if path_is_excluded(norm):
            continue

        suspicious_location = path_is_in_suspicious_location(norm)

        # Keep only clearly suspicious/user-writable style locations for v1.
        if not suspicious_location:
            continue

        if norm_key in seen:
            continue

        seen.add(norm_key)

        candidates.append(
            {
                "path": norm,
                "extension": Path(norm).suffix.lower(),
                "classification": classify_path(norm),
                "source_category": category,
                "source_process_name": str(event.get("process_name", "")),
                "source_pid": event.get("pid"),
                "timestamp": str(event.get("timestamp", "")),
                "suspicious_path": suspicious_location,
            }
        )

    return candidates


def enrich_dropped_files(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []

    for item in candidates:
        path_str = str(item["path"])
        p = Path(path_str)

        exists = p.exists()
        record = dict(item)
        record["exists_on_disk"] = exists

        if exists and p.is_file():
            try:
                record["size"] = file_size(p)
                record["md5"] = md5_file(p)
                record["sha1"] = sha1_file(p)
                record["sha256"] = sha256_file(p)
            except Exception as e:
                record["hash_error"] = str(e)
                record["size"] = None
                record["md5"] = None
                record["sha1"] = None
                record["sha256"] = None
        else:
            record["size"] = None
            record["md5"] = None
            record["sha1"] = None
            record["sha256"] = None

        compiler_artifact = path_is_compiler_artifact(str(record.get("path", "")))
        record["compiler_artifact"] = compiler_artifact

        reasons: list[str] = []
        if record.get("suspicious_path"):
            reasons.append("path_in_suspicious_location")

        classification = str(record.get("classification", ""))
        if classification in {
            "executable",
            "library",
            "driver",
            "powershell_script",
            "batch_script",
            "javascript",
            "vbscript",
            "html_application",
            "screensaver_executable",
        }:
            reasons.append(f"classification:{classification}")

        record["reasons"] = reasons
        # Counted, shown, and not scored. See `path_is_compiler_artifact`.
        record["suspicious"] = len(reasons) > 0 and not compiler_artifact

        enriched.append(record)

    return enriched


def summarize_dropped_files(items: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "total_candidates": len(items),
        "existing_on_disk": 0,
        "missing_on_disk": 0,
        "suspicious": 0,
        "compiler_artifacts": 0,
        "installer_scratch_set_aside": 0,
        "installer_scratch_reinstated": 0,
    }

    for item in items:
        if item.get("exists_on_disk"):
            summary["existing_on_disk"] += 1
        else:
            summary["missing_on_disk"] += 1

        if item.get("suspicious"):
            summary["suspicious"] += 1
        if item.get("compiler_artifact"):
            summary["compiler_artifacts"] += 1
        if item.get("installer_scratch_set_aside"):
            summary["installer_scratch_set_aside"] += 1
        elif item.get("installer_scratch"):
            summary["installer_scratch_reinstated"] += 1

    return summary