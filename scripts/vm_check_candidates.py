"""Which samples check for a VM *through the registry*, read out of their own bytes.

Gap 4's detector counts only `vm_specific` registry reads, and it has never
fired. Two detonations were spent on samples chosen for *detecting
virtualisation*, and both produced `artifacts_read: 0` -- FormBook checks by
module hash, and `a6a86646...` announced "cannot run inside a virtual machine"
on screen while touching no registry key at all. The registry is one narrow
surface of VM detection and the field does not favour it, so a third sample
picked the same way would fail the same way.

    .venv\\Scripts\\python.exe scripts\\vm_check_candidates.py \\
        --cases C:\\mal-bazaar-cases\\cases --cases C:\\mal-datalake-cases\\cases

Reads `strings.txt` and `capa.json` out of each case directory; runs nothing and
writes nothing.

**Do not pick a sample from capa's anti-VM namespace.** That is the mistake this
script exists to stop repeating, and the numbers say why. On the 227 malware
cases, 49 fire a rule in `anti-analysis/anti-vm` and **39 of those show no VM
check of any kind in their own strings** -- no registry key, no WMI class, no
device path, no CPUID literal. `reference anti-VM strings targeting Xen` alone
accounts for 22 of the 49 and 20 of the 39: it is matching the substring, the
way the Go runtime's symbols once read as four malware hosts.

**The three columns are not interchangeable, which is the point.**

* `vm-only`   -- a registry key that exists only on a virtual machine. This is
  the one that can produce the detector's input. Measured 28 Aug: **1 of 226**.
* `identity`  -- `SystemBiosVersion` and friends. A VM check reads these and so
  does an inventory agent, which is why `VM_ARTIFACT_MARKERS` calls them
  `identity_surface` and the detector refuses to count them.
* `non-reg`   -- WMI, device files, drivers, CPUID. A real VM check that this
  pass cannot see, and 15 samples are in here.

Backslashes are normalised to `/` on both sides so the escaping is not the thing
under test. The patterns are the API forms a sample writes, not the Procmon path
fragments in `VM_ARTIFACT_MARKERS`; the two lists describe the same keys from
opposite ends and neither substitutes for the other.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

#: Registry key forms that exist only on a virtual machine. A hit here means the
#: sample can produce a `vm_specific` read for gap 4's detector to correlate.
REGISTRY_VM_ONLY = {
    "VirtualBox Guest Additions install key": "oracle/virtualbox guest additions",
    "VMware Tools install key": "vmware, inc[.]/vmware tools",
    "VirtualBox guest driver service": "services/vbox(guest|service|sf|mouse|video)",
    "VMware guest driver service": "services/vm(tools|mouse|hgfs|memctl|ci|rawdsk|usbmouse)",
    "virtio / QEMU guest driver service": "services/(qemu-ga|viostor|vioserial|vioinput|netkvm)",
    "Xen guest driver service": "services/xen(evtchn|svc|net|vbd)",
    "Hyper-V guest service": "services/vm(bus|icheartbeat|icvss)",
    "ACPI table signed VBOX__": "acpi/(dsdt|fadt|rsdt)/vbox__",
    "Hyper-V guest parameters": "virtual machine/guest/parameters",
}

#: Machine-identity keys. A VM check reads these to compare the answer against
#: "VBOX"; so does anything that wants a BIOS version. `HARDWARE\\Description\\
#: System` is deliberately excluded -- it is the parent of `SystemBiosVersion`
#: and six samples name it and nothing else, which says nothing either way.
REGISTRY_IDENTITY = {
    "SystemBiosVersion": "systembiosversion",
    "SystemManufacturer": "systemmanufacturer",
    "SystemProductName": "systemproductname",
    "BaseBoardManufacturer": "baseboardmanufacturer",
    "BaseBoardProduct": "baseboardproduct",
    "SCSI device map": "hardware/devicemap/scsi",
    "Disk device enumeration": "services/disk/enum",
}

#: VM checks that are not registry reads. Collected so a sample can be recorded
#: as *checking, invisibly* rather than as *not checking* -- the distinction the
#: two failed detonations turned on.
NON_REGISTRY_CHECKS = {
    "WMI": "win32_(computersystem|videocontroller|bios|baseboard|processor)",
    "device file": "[.]/(vboxguest|vboxmouse|vmci|hgfs)|pipe/vmware|vboxhook[.]dll|sbiedll[.]dll",
    "driver file": "(vboxsf|vmmouse|vmhgfs|balloon|vboxguest)[.]sys",
    "CPUID vendor": "vmwarevmware|kvmkvmkvm|xenvmmxenvmm|microsoft hv|prl hyperv",
}

_ANTI_VM_NAMESPACE = "anti-vm"


def _matches(text: str, table: dict[str, str]) -> list[str]:
    return [label for label, pattern in table.items() if re.search(pattern, text)]


def _capa_anti_vm_rules(case: Path) -> list[str] | None:
    """Rule names in capa's anti-VM namespace, or ``None`` when capa did not run.

    ``None`` and ``[]`` are different answers and the caller keeps them apart:
    203 of 227 cases carry `capa.json` on the host, and a missing one is a gap
    in collection rather than a sample that does not check.
    """
    path = case / "capa.json"
    if not path.exists():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    return sorted(
        name
        for name, rule in (document.get("rules") or {}).items()
        if _ANTI_VM_NAMESPACE in ((rule.get("meta") or {}).get("namespace") or "")
    )


def _sample_strings(case: Path) -> str | None:
    """The case's strings, lowered and slash-normalised, or ``None`` if absent.

    `step_strings` collects ASCII and UTF-16LE runs of six characters or more,
    so a key literal is here in whichever encoding the compiler emitted it. A
    packed sample has none of this and reads as a clean negative, which is the
    known limit of the whole approach.
    """
    path = case / "strings.txt"
    if not path.exists() or path.stat().st_size == 0:
        return None
    return path.read_text(encoding="utf-8", errors="replace").lower().replace("\\", "/")


def scan_case(case: Path) -> dict[str, object]:
    text = _sample_strings(case)
    rules = _capa_anti_vm_rules(case)
    return {
        "case": case.name,
        "strings_collected": text is not None,
        "capa_ran": rules is not None,
        "capa_anti_vm": rules or [],
        "vm_only": _matches(text, REGISTRY_VM_ONLY) if text else [],
        "identity": _matches(text, REGISTRY_IDENTITY) if text else [],
        "non_registry": _matches(text, NON_REGISTRY_CHECKS) if text else [],
    }


def scan_corpus(cases_dir: Path) -> list[dict[str, object]]:
    return [scan_case(case) for case in sorted(cases_dir.iterdir()) if case.is_dir()]


def _report(rows: list[dict[str, object]]) -> None:
    total = len(rows)
    with_strings = sum(1 for r in rows if r["strings_collected"])
    with_capa = sum(1 for r in rows if r["capa_ran"])
    anti_vm = [r for r in rows if r["capa_anti_vm"]]
    vm_only = [r for r in rows if r["vm_only"]]
    identity = [r for r in rows if r["identity"] and not r["vm_only"]]
    non_reg = [r for r in rows if r["non_registry"] and not r["vm_only"]]
    blind = [r for r in anti_vm if not (r["vm_only"] or r["identity"] or r["non_registry"])]

    print(f"{total} cases, {with_strings} with strings, {with_capa} with capa\n")
    print(f"  capa anti-VM rule fires        {len(anti_vm):4}")
    print(f"    ...with no VM check visible  {len(blind):4}   <- capa is not a proxy")
    print(f"  names a VM-only registry key   {len(vm_only):4}   <- can exercise gap 4")
    print(f"  identity keys only             {len(identity):4}")
    print(f"  checks by other means only     {len(non_reg):4}")

    rule_counts: Counter[str] = Counter()
    blind_counts: Counter[str] = Counter()
    for row in anti_vm:
        for name in row["capa_anti_vm"]:
            rule_counts[name] += 1
    for row in blind:
        for name in row["capa_anti_vm"]:
            blind_counts[name] += 1

    if rule_counts:
        print(f"\n  capa anti-VM rule{'':36}fires   blind")
        for name, count in rule_counts.most_common():
            print(f"  {name[:50]:52} {count:4}  {blind_counts[name]:6}")

    print(f"\n{len(vm_only)} candidate(s) for a registry-visible VM check:\n")
    for row in vm_only:
        print(f"  {row['case']}")
        print(f"    vm-only  : {', '.join(row['vm_only'])}")
        print(f"    identity : {', '.join(row['identity']) or '-'}")
        print(f"    non-reg  : {', '.join(row['non_registry']) or '-'}")
        print(f"    capa     : {', '.join(row['capa_anti_vm']) or '-'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--cases",
        action="append",
        required=True,
        help="a corpus's cases directory; repeatable",
    )
    parser.add_argument("--json", help="write the per-case rows here")
    args = parser.parse_args(argv)

    rows: list[dict[str, object]] = []
    for raw in args.cases:
        cases_dir = Path(raw)
        if not cases_dir.is_dir():
            print(f"not a directory: {cases_dir}", file=sys.stderr)
            return 2
        rows.extend(scan_corpus(cases_dir))

    _report(rows)

    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
