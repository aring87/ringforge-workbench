"""Is the machine this is running on an analysis bench, or somebody's desktop?

**Why the telemetry strip needs this.** The Dynamic Analysis window reports
`Sysmon: not installed | FakeNet: not installed | Memory: not installed`, and
on a developer's workstation every one of those is *correct and desirable*:
Sysmon and Npcap install kernel drivers and FakeNet installs a system-wide
traffic diverter, which is why `scripts/bootstrap_tools.ps1` refuses to run on
physical hardware without `-Force`.

Read without that context the strip looks like a broken bench, and the obvious
response -- install the missing tools -- is the wrong one on the wrong machine.
The strip was stating a fact about the host as though it were a fact about the
run environment, which is the same shape as every other defect this codebase
has been chasing: a true statement that reads as a different one.

**Evidence, not a verdict.** Several independent sources are consulted and any
one hit is enough, for the reason the PowerShell guard gives: analysis VMs are
routinely hardened against anti-VM evasion by spoofing DMI strings, which also
defeats a naive single-source check. Nothing here is a security control -- a
sample can defeat all of it. It exists to caption a status line.
"""

from __future__ import annotations

import os
import re
from typing import Any

#: Vendor strings that mean a hypervisor. Deliberately specific: a bare
#: "Virtual" matches a mounted VHD and "Microsoft Virtual Disk" on ordinary
#: physical machines, and matching those would make this a rubber stamp.
#: Matches `bootstrap_tools.ps1` exactly, Hyper-V deliberately absent: the
#: hypervisor being *available* on a machine says nothing about whether this
#: machine is a guest, and Windows 11 ships those components widely.
VENDOR_PATTERN = re.compile(
    r"VirtualBox|VBOX|VMware|QEMU|Xen|innotek|Parallels|Bochs",
    re.IGNORECASE)

#: Guest-addition services. These survive DMI spoofing, which the identity
#: strings do not.
#:
#: **`vmicheartbeat` is deliberately not here.** It was, and it made this
#: developer workstation report itself an analysis VM -- the Hyper-V
#: integration services are registered on ordinary Windows hosts that merely
#: have the feature available. A guest hint that fires on hosts is not a hint.
GUEST_SERVICES = ("VBoxService", "VBoxGuest", "vmtools", "VMTools",
                  "vmhgfs", "vmci", "prl_tools", "xenbus")


def _registry_values() -> list[str]:
    """Identity strings from the registry. Cheap, and no subprocess."""
    values: list[str] = []
    if os.name != "nt":
        return values
    try:
        import winreg
    except Exception:
        return values

    probes = (
        (r"HARDWARE\DESCRIPTION\System\BIOS",
         ("SystemManufacturer", "SystemProductName", "BIOSVendor",
          "BaseBoardManufacturer")),
        (r"SYSTEM\CurrentControlSet\Services\Disk\Enum", ("0",)),
    )
    for path, names in probes:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                for name in names:
                    try:
                        value, _ = winreg.QueryValueEx(key, name)
                        if value:
                            values.append(f"{name}: {value}")
                    except OSError:
                        continue
        except OSError:
            continue
    return values


def _guest_services() -> list[str]:
    if os.name != "nt":
        return []
    found = []
    try:
        import winreg

        for service in GUEST_SERVICES:
            try:
                winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    rf"SYSTEM\CurrentControlSet\Services\{service}").Close()
                found.append(f"service: {service}")
            except OSError:
                continue
    except Exception:
        return []
    return found


def bench_profile() -> dict[str, Any]:
    """Whether this machine looks like a disposable analysis VM.

    `looks_like_vm` is `None` when the question could not be asked -- on a
    non-Windows host, or if every probe failed. Unknown is not the same as no,
    and a caption built from this must not turn one into the other.
    """
    if os.name != "nt":
        return {"looks_like_vm": None, "evidence": [],
                "note": "not a Windows host; the bench probes do not apply."}

    evidence = [v for v in _registry_values() if VENDOR_PATTERN.search(v)]
    evidence += _guest_services()

    asked = bool(_registry_values()) or bool(evidence)
    if not asked:
        return {"looks_like_vm": None, "evidence": [],
                "note": "could not read the identity strings this uses."}

    if evidence:
        return {"looks_like_vm": True, "evidence": evidence,
                "note": "looks like an analysis VM."}
    return {
        "looks_like_vm": False,
        "evidence": [],
        "note": "looks like physical hardware, not an analysis VM.",
    }


def telemetry_caption(profile: dict[str, Any] | None = None) -> str:
    """One line saying which machine the telemetry strip is describing.

    Empty on a bench, because there the strip means what it says and a caption
    would be noise.
    """
    profile = profile or bench_profile()
    state = profile.get("looks_like_vm")
    if state is True:
        return ""
    if state is None:
        return ("Could not tell whether this machine is an analysis VM; the "
                "telemetry above describes this host.")
    return ("This machine looks like physical hardware, not an analysis VM. "
            "The telemetry above describes this host -- install the tier-1 "
            "tools in the guest, not here.")
