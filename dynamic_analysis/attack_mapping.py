"""Map observed behaviour to MITRE ATT&CK techniques.

The value here is not the labels themselves. It is that a technique ID is a
join key: once a detonation says T1055, it can be lined up against detection
content, coverage matrices and Sigma rules that speak the same vocabulary.
Without it a report is prose that a human has to translate before it can be
used for anything.

Mapping is therefore deliberately conservative. Every technique claimed is
backed by a specific observation carried alongside it, and behaviours that
could plausibly be several techniques are mapped to the one actually evidenced
rather than to all of them. An over-eager mapping is worse than none: it
produces coverage claims that do not survive scrutiny, and the whole point is
to be able to trust the join.

Sub-techniques are used only where the evidence really distinguishes them.
Reporting T1059.001 (PowerShell) is honest when script blocks were captured;
reporting T1027.002 (Software Packing) from a memory-only YARA hit is not,
because the delta shows something was unreadable at rest without saying how.
"""

from __future__ import annotations

from typing import Any

ATTACK_VERSION = "v15"

#: technique id -> (name, tactic)
_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1027.002": ("Software Packing", "Defense Evasion"),
    "T1027.010": ("Command Obfuscation", "Defense Evasion"),
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1112": ("Modify Registry", "Defense Evasion"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1218": ("System Binary Proxy Execution", "Defense Evasion"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "T1620": ("Reflective Code Loading", "Defense Evasion"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
}

#: PowerShell behaviour label -> technique. Keyed off the labels
#: powershell_logging.classify_script produces, so the two stay in step.
_POWERSHELL_TECHNIQUES: dict[str, str] = {
    "Base64 decoding": "T1140",
    "Dynamic code execution": "T1059.001",
    "Remote content download": "T1105",
    "Web client use": "T1071.001",
    "Shellcode / injection APIs": "T1055",
    "In-memory assembly load": "T1620",
    "AMSI tampering": "T1562.001",
    "Encoded command": "T1027.010",
    "Defender modification": "T1562.001",
    "Raw network object": "T1071",
    "Hidden window": "T1564.003",
    "Execution policy bypass": "T1059.001",
    "Scheduled task creation": "T1053.005",
    "Process launch": "T1059",
}

_TECHNIQUES.setdefault("T1564.003", ("Hidden Window", "Defense Evasion"))

#: LOLBins whose presence evidences proxy execution specifically.
_PROXY_BINARIES = {
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "msbuild.exe",
    "installutil.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
}


def _technique(technique_id: str) -> dict[str, str]:
    name, tactic = _TECHNIQUES.get(technique_id, ("Unknown", "Unknown"))
    return {"id": technique_id, "name": name, "tactic": tactic}


class _Collector:
    """Accumulates techniques with the evidence that justified each."""

    def __init__(self) -> None:
        self._found: dict[str, list[str]] = {}

    def add(self, technique_id: str, evidence: str) -> None:
        if not technique_id or not evidence:
            return
        entries = self._found.setdefault(technique_id, [])
        if evidence not in entries:
            entries.append(evidence)

    def result(self) -> list[dict[str, Any]]:
        rows = []
        for technique_id, evidence in self._found.items():
            row = _technique(technique_id)
            row["evidence"] = evidence[:6]
            row["evidence_count"] = len(evidence)
            rows.append(row)
        # Grouped by tactic, then id, so the same run always renders in the
        # same order regardless of the order things were observed.
        rows.sort(key=lambda r: (r["tactic"], r["id"]))
        return rows


def map_run(summary: dict[str, Any]) -> dict[str, Any]:
    """Derive ATT&CK techniques from a completed run summary."""
    found = _Collector()

    _map_memory_yara(summary, found)
    _map_powershell(summary, found)
    _map_processes(summary, found)
    _map_persistence(summary, found)
    _map_network(summary, found)
    _map_sysmon(summary, found)

    techniques = found.result()
    tactics = sorted({t["tactic"] for t in techniques})

    return {
        "mapped": True,
        "attack_version": ATTACK_VERSION,
        "techniques": techniques,
        "tactics": tactics,
        "counts": {
            "techniques": len(techniques),
            "tactics": len(tactics),
        },
        "note": (
            "Every technique is backed by the evidence listed with it. Absence "
            "of a technique means it was not observed, not that it did not occur."
        ),
    }


def _map_memory_yara(summary: dict[str, Any], found: _Collector) -> None:
    yara = summary.get("memory_yara_summary", {}) or {}
    memory_only = yara.get("memory_only_rules", []) or []
    if not memory_only:
        return

    # A rule matching memory but not disk says the payload was unreadable at
    # rest. It does not say *how* -- packed, encrypted, or downloaded -- so the
    # parent technique is claimed and the sub-technique is not.
    evidence = f"{len(memory_only)} rule(s) matched process memory but not the file on disk: " + \
               ", ".join(str(r) for r in memory_only[:4])
    found.add("T1027", evidence)
    found.add("T1140", evidence)


def _map_powershell(summary: dict[str, Any], found: _Collector) -> None:
    powershell = summary.get("powershell_summary", {}) or {}
    if not powershell.get("collected"):
        return

    blocks = powershell.get("blocks", []) or []
    if blocks:
        found.add("T1059.001", f"{len(blocks)} PowerShell script block(s) recorded")

    for behaviour in powershell.get("behaviours", []) or []:
        technique_id = _POWERSHELL_TECHNIQUES.get(behaviour)
        if technique_id:
            found.add(technique_id, f"PowerShell: {behaviour}")


def _map_processes(summary: dict[str, Any], found: _Collector) -> None:
    findings = summary.get("findings", {}) or {}
    for record in findings.get("spawned_processes", []) or []:
        # Analyzer and baseline records are already excluded upstream; this is
        # the sample's own activity.
        child = str(record.get("child_process_name", "") or "").lower()
        detail = str(record.get("detail", "") or "")

        if child in _PROXY_BINARIES:
            found.add("T1218", f"{child} launched: {detail[:120]}")
        elif child == "powershell.exe":
            found.add("T1059.001", f"powershell.exe launched: {detail[:120]}")
        elif child == "cmd.exe":
            found.add("T1059.003", f"cmd.exe launched: {detail[:120]}")


def _map_persistence(summary: dict[str, Any], found: _Collector) -> None:
    tasks = summary.get("task_diff_summary", {}) or {}
    if int(tasks.get("suspicious_new_or_modified", 0) or 0) > 0:
        found.add("T1053.005", f"{tasks['suspicious_new_or_modified']} suspicious scheduled task change(s)")

    services = summary.get("service_diff_summary", {}) or {}
    if int(services.get("suspicious_new_or_modified", 0) or 0) > 0:
        found.add("T1543.003", f"{services['suspicious_new_or_modified']} suspicious service change(s)")

    autoruns = summary.get("autoruns_diff_summary", {}) or {}
    if int(autoruns.get("suspicious_new_or_modified", 0) or 0) > 0:
        found.add("T1547.001", f"{autoruns['suspicious_new_or_modified']} suspicious autorun entr(ies)")

    findings = summary.get("findings", {}) or {}
    hits = findings.get("persistence_hits", []) or []
    if hits:
        first = str((hits[0] or {}).get("path", ""))[:120]
        found.add("T1547.001", f"{len(hits)} persistence-related event(s), e.g. {first}")


def _map_network(summary: dict[str, Any], found: _Collector) -> None:
    iocs = summary.get("network_iocs", {}) or {}

    # Only genuinely notable indicators. Baseline domains, local discovery and
    # non-routable addresses are excluded upstream precisely so they cannot
    # manufacture a C2 claim here.
    if iocs.get("notable_domains") or iocs.get("external_ips"):
        targets = list(iocs.get("notable_domains", []))[:3] + list(iocs.get("external_ips", []))[:3]
        found.add("T1071", "Contacted: " + ", ".join(str(t) for t in targets))

    if iocs.get("notable_urls"):
        found.add("T1071.001", f"{len(iocs['notable_urls'])} plaintext HTTP request(s)")


def _map_sysmon(summary: dict[str, Any], found: _Collector) -> None:
    sysmon = summary.get("sysmon_summary", {}) or {}

    injections = sysmon.get("injection_events", []) or []
    if injections:
        first = injections[0] or {}
        found.add(
            "T1055",
            f"{len(injections)} CreateRemoteThread event(s), e.g. "
            f"{first.get('source', '?')} -> {first.get('target', '?')}",
        )

    for highlight in sysmon.get("highlights", []) or []:
        title = str(highlight.get("title", "") or "").lower()
        detail = str(highlight.get("detail", "") or "")[:120]
        if "tampering" in title or "hollowing" in title:
            found.add("T1055", f"{highlight.get('title')}: {detail}")
        elif "wmi event" in title or "wmi filter" in title:
            found.add("T1546.003", f"{highlight.get('title')}: {detail}")


_TECHNIQUES.setdefault("T1546.003", ("WMI Event Subscription", "Persistence"))


def summarize_attack(mapping: dict[str, Any]) -> dict[str, Any]:
    """Compact form for the run summary."""
    if not isinstance(mapping, dict) or not mapping.get("mapped"):
        return {"mapped": False, "techniques": [], "tactics": [], "counts": {}}

    return {
        "mapped": True,
        "attack_version": mapping.get("attack_version", ATTACK_VERSION),
        "technique_ids": [t["id"] for t in mapping.get("techniques", [])],
        "tactics": mapping.get("tactics", []),
        "counts": mapping.get("counts", {}),
        "techniques": mapping.get("techniques", []),
        "note": mapping.get("note", ""),
    }
