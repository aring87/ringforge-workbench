"""Registry reads of the artifacts that give a virtual machine away.

Gap 4's second half, and only the collection path: what the sample *looked at*.
The detector -- "read a VM artifact and then went quiet" -- needs this to exist
first, and needs it to be trustworthy before anything is built on top of it.

Deliberately not scored, for the same reason the chain-crashed warning is not.
Reading `SystemBiosVersion` is not malicious; installers, licensing checks,
crash reporters and hardware inventory tools all do it. What it is, is *the other
half of an inconclusive run*: a quiet result from a sample that first enumerated
the hypervisor reads very differently from a quiet result from one that did not
look.

Three things this module is careful about, each of them a lesson this project
already paid for:

**A signal that fires on everything says nothing about anything.** Windows reads
most of these keys constantly -- the Service Control Manager enumerates every
service key including the guest additions', and Defender and the licensing
service read SMBIOS. So hits are attributed by lineage, and the background count
is reported rather than dropped, because "Windows read it 400 times and the
sample never did" is the answer, not noise to hide.

**Markers are literals matched with `in`, so they are tested against real
paths.** 46 markers in this package were once written regex-style and matched
nothing for the life of the project. The tests here assert against full Procmon
path strings, never against the constants.

**Silence must be distinguishable from absence.** The Procmon config decides
whether a registry read exists in the event stream at all, and the default one
does not capture reads. Zero hits from a run that never collected reads is not a
finding about the sample, so `collection_available` says which case it is and the
report refuses to imply the sample did not look.
"""

from __future__ import annotations

from typing import Any


#: The Procmon operations that are registry *reads*.
#:
#: `RegQueryValue` and `RegOpenKey` carry every VM check seen in the wild -- a
#: value read and a key-existence probe. The enumeration operations are here
#: because a config that captures them should still be understood, not because
#: `dynamic_registry_reads.pmc` includes them; it does not, they are the most
#: expensive registry operations there are.
REGISTRY_READ_OPERATIONS = {
    "regqueryvalue",
    "regopenkey",
    "regquerykey",
    "regenumkey",
    "regenumvalue",
    "regqueryvalueex",
    "regquerymultiplevalues",
}

READ_CATEGORY = "registry_read"

#: `(marker, family, artifact, specificity)`.
#:
#: `specificity` is the part that keeps this honest. `vm_specific` markers name
#: something that only exists on a virtual machine -- a guest-additions service
#: key, an ACPI table signed `VBOX__`. Reading one is a VM check and nothing
#: else. `identity_surface` markers name a key that describes the machine, which
#: a VM check reads *and so does ordinary software*: `SystemBiosVersion` is where
#: you look for "VBOX" and also where an inventory agent looks for a BIOS
#: version. Both are collected; only the first means anything on its own, and a
#: detector built on this must not treat them alike.
#:
#: Every marker is lowercase and matched with a plain `in` test against the
#: lowered Procmon path. A key read gives the key path; a value read gives
#: `key\value`, so a marker naming either still matches.
VM_ARTIFACT_MARKERS: tuple[tuple[str, str, str, str], ...] = (
    # --- VirtualBox: what this workbench's own guest runs on ----------------
    ("\\services\\vboxguest", "virtualbox", "VBoxGuest driver service", "vm_specific"),
    ("\\services\\vboxservice", "virtualbox", "VBoxService service", "vm_specific"),
    ("\\services\\vboxsf", "virtualbox", "VBoxSF shared-folder driver", "vm_specific"),
    ("\\services\\vboxmouse", "virtualbox", "VBoxMouse driver", "vm_specific"),
    ("\\services\\vboxvideo", "virtualbox", "VBoxVideo driver", "vm_specific"),
    ("\\oracle\\virtualbox guest additions", "virtualbox", "Guest Additions install key", "vm_specific"),
    ("\\acpi\\dsdt\\vbox__", "virtualbox", "ACPI DSDT signed VBOX__", "vm_specific"),
    ("\\acpi\\fadt\\vbox__", "virtualbox", "ACPI FADT signed VBOX__", "vm_specific"),
    ("\\acpi\\rsdt\\vbox__", "virtualbox", "ACPI RSDT signed VBOX__", "vm_specific"),
    # --- VMware ------------------------------------------------------------
    ("\\services\\vmtools", "vmware", "VMware Tools service", "vm_specific"),
    ("\\services\\vmmouse", "vmware", "VMware mouse driver", "vm_specific"),
    ("\\services\\vmhgfs", "vmware", "VMware shared-folder driver", "vm_specific"),
    ("\\services\\vmmemctl", "vmware", "VMware balloon driver", "vm_specific"),
    ("\\services\\vmci", "vmware", "VMware VMCI driver", "vm_specific"),
    ("\\services\\vmrawdsk", "vmware", "VMware raw-disk driver", "vm_specific"),
    ("\\services\\vmusbmouse", "vmware", "VMware USB mouse driver", "vm_specific"),
    ("\\vmware, inc.\\vmware tools", "vmware", "VMware Tools install key", "vm_specific"),
    # --- QEMU / KVM --------------------------------------------------------
    ("\\services\\qemu-ga", "qemu", "QEMU guest agent", "vm_specific"),
    ("\\services\\viostor", "qemu", "virtio storage driver", "vm_specific"),
    ("\\services\\vioserial", "qemu", "virtio serial driver", "vm_specific"),
    ("\\services\\vioinput", "qemu", "virtio input driver", "vm_specific"),
    ("\\services\\netkvm", "qemu", "virtio network driver", "vm_specific"),
    ("\\services\\balloon", "qemu", "virtio balloon driver", "vm_specific"),
    # --- Xen ---------------------------------------------------------------
    ("\\services\\xenevtchn", "xen", "Xen event channel driver", "vm_specific"),
    ("\\services\\xensvc", "xen", "Xen guest service", "vm_specific"),
    ("\\services\\xennet", "xen", "Xen network driver", "vm_specific"),
    ("\\services\\xenvbd", "xen", "Xen block driver", "vm_specific"),
    # --- Hyper-V -----------------------------------------------------------
    ("\\services\\vmbus", "hyper-v", "VMBus driver", "vm_specific"),
    ("\\services\\vmicheartbeat", "hyper-v", "Hyper-V heartbeat service", "vm_specific"),
    ("\\services\\vmicvss", "hyper-v", "Hyper-V VSS service", "vm_specific"),
    ("\\microsoft\\virtual machine\\guest\\parameters", "hyper-v", "Guest parameters key", "vm_specific"),
    # --- Parallels, Wine ---------------------------------------------------
    ("\\services\\prl_", "parallels", "Parallels guest driver", "vm_specific"),
    ("\\software\\wine", "wine", "Wine install key", "vm_specific"),
    # --- Firmware and board identity ---------------------------------------
    #
    # Where the VM name is *read from* rather than a VM-only key. An inventory
    # agent reads exactly these, which is what `identity_surface` is for.
    ("\\systembiosversion", "firmware identity", "SystemBiosVersion", "identity_surface"),
    ("\\systembiosdate", "firmware identity", "SystemBiosDate", "identity_surface"),
    ("\\videobiosversion", "firmware identity", "VideoBiosVersion", "identity_surface"),
    ("\\biosversion", "firmware identity", "BIOSVersion", "identity_surface"),
    ("\\systemmanufacturer", "firmware identity", "SystemManufacturer", "identity_surface"),
    ("\\systemproductname", "firmware identity", "SystemProductName", "identity_surface"),
    ("\\baseboardmanufacturer", "firmware identity", "BaseBoardManufacturer", "identity_surface"),
    ("\\baseboardproduct", "firmware identity", "BaseBoardProduct", "identity_surface"),
    ("\\services\\mssmbios\\data", "firmware identity", "Raw SMBIOS table", "identity_surface"),
    ("\\description\\system\\bios", "firmware identity", "BIOS description key", "identity_surface"),
    # --- Disk and adapter identity -----------------------------------------
    #
    # `VBOX HARDDISK` and `VMware Virtual S` live in these, and a MAC prefix
    # check reads NetworkAddress.
    ("\\services\\disk\\enum", "device identity", "Disk device enumeration", "identity_surface"),
    ("\\devicemap\\scsi", "device identity", "SCSI device map", "identity_surface"),
    ("\\enum\\ide", "device identity", "IDE device enumeration", "identity_surface"),
    ("\\enum\\scsi", "device identity", "SCSI device enumeration", "identity_surface"),
    ("\\networkaddress", "device identity", "Adapter NetworkAddress override", "identity_surface"),
)

#: Windows' *response* to the sample, which is not the sample acting.
#:
#: Error Reporting collects machine identity to put in a crash report --
#: SystemManufacturer, BIOSVersion, SystemProductName, the BIOS key. On the
#: 07 Aug 14:53 run that produced five "VM artifact reads" attributed to the
#: sample, because `RegSvcs` spawned `WerFault` and lineage counted it, entirely
#: correctly. Lineage says the process belongs to the tree; it cannot say the
#: behaviour belongs to the malware, and for WER it does not.
#:
#: The same crossed wire is already logged against network attribution, where
#: WER's upload attempt counts as the sample's traffic. Second pass to be bitten.
#: A suppression aid that runs *before* attribution, which is the only role a
#: name list is allowed to have here.
WINDOWS_RESPONSE_PROCESSES = {
    "werfault.exe",
    "werfaultsecure.exe",
    "wermgr.exe",
}

#: Reads of a VM-specific key that Windows makes for its own reasons.
#:
#: `...\\Services\\VBoxSF\\NetworkProvider` is a network-provider registration, and
#: Windows walks every registered provider when anything touches a UNC path --
#: PowerShell startup does it. On the 07 Aug 14:53 run that produced four hits on
#: the VirtualBox shared-folder driver from `powershell.exe`, none of which was a
#: VM check.
#:
#: The marker on the driver's service key stays, because a sample reading it *is*
#: a VM check. Only the subkey Windows enumerates is set aside, and the count is
#: reported so the narrowing stays visible.
ROUTINE_SUBPATH_MARKERS = (
    "\\vboxsf\\networkprovider",
)

#: Procmon results meaning the key or value was not there. The same list the
#: dropped-file triage keeps, for the same reason -- an operation name does not
#: say what the operation did, and here the result carries the more interesting
#: half: whether the artifact the sample went looking for was still on the box.
NOT_FOUND_RESULTS = {
    "name not found",
    "path not found",
    "no such file",
    "object name not found",
    "object path not found",
}

#: Results that mean the read succeeded in observing something. `BUFFER
#: OVERFLOW` and `BUFFER TOO SMALL` are here on purpose: a value query with an
#: undersized buffer is the ordinary first half of a two-call read, and treating
#: it as a failure would report an artifact as absent that the sample went on to
#: read in full.
FOUND_RESULTS = {
    "success",
    "buffer overflow",
    "buffer too small",
    "more data",
}


def _lower(value: object) -> str:
    return str(value or "").strip().lower()


def _is_windows_response(process_name: object) -> bool:
    return _lower(process_name) in WINDOWS_RESPONSE_PROCESSES


def _is_routine_subpath(path: object) -> bool:
    lowered = _lower(path)
    return any(marker in lowered for marker in ROUTINE_SUBPATH_MARKERS)


def is_registry_read(event: dict[str, Any]) -> bool:
    if str(event.get("category", "")) == READ_CATEGORY:
        return True
    return _lower(event.get("operation")) in REGISTRY_READ_OPERATIONS


def classify_vm_artifact_path(path: object) -> dict[str, str] | None:
    """The VM artifact a registry path names, or ``None``.

    First match wins, and the table is ordered VM-specific first, so a read of
    `...\\Services\\VBoxGuest\\ImagePath` is reported as a VirtualBox artifact
    rather than as whatever generic marker also happened to match.
    """
    lowered = _lower(path)
    if not lowered:
        return None
    for marker, family, artifact, specificity in VM_ARTIFACT_MARKERS:
        if marker in lowered:
            return {
                "marker": marker,
                "family": family,
                "artifact": artifact,
                "specificity": specificity,
            }
    return None


def _artifact_found(result: object) -> bool | None:
    """Whether the read found the artifact. ``None`` when the result says neither.

    Worth having in both directions. `SUCCESS` on `...\\Services\\VBoxGuest`
    means the sample was told it is on a VirtualBox guest; `NAME NOT FOUND`
    means `vm_hygiene.ps1` held and the check came back clean. An
    `ACCESS DENIED` says only that the sample asked.
    """
    lowered = _lower(result)
    if lowered in NOT_FOUND_RESULTS:
        return False
    if lowered in FOUND_RESULTS:
        return True
    return None


def _event_pid(event: dict[str, Any]) -> int | None:
    try:
        return int(event.get("pid"))
    except (TypeError, ValueError):
        return None


def collect_vm_artifact_reads(
    events: list[dict[str, Any]],
    descendant_pids: set[int] | None = None,
) -> dict[str, Any]:
    """VM artifacts the sample's own processes read out of the registry.

    ``descendant_pids`` is the sample's process tree, resolved the same way the
    findings, the PowerShell blocks and the dropped files resolve it. It matters
    more here than anywhere: Windows reads most of these keys on every boot, and
    a pass without lineage would report the Service Control Manager's own
    enumeration of the guest-additions services as the sample checking for a VM.

    ``None`` means lineage could not be resolved, and everything is counted --
    the same degrade the other passes use. An empty set means the tree resolved
    to nothing, and nothing is attributed.

    Reads by processes outside the tree are counted, not discarded, because the
    count is what distinguishes "the sample did not look" from "this pass is not
    working".
    """
    reads_in_stream = 0
    sample_reads = 0
    background_reads = 0

    hits: list[dict[str, Any]] = []
    background_hits: list[dict[str, Any]] = []
    windows_response_hits: list[dict[str, Any]] = []
    routine_hits: list[dict[str, Any]] = []
    seen: set[tuple[int | None, str]] = set()

    for event in events:
        if not is_registry_read(event):
            continue

        reads_in_stream += 1
        pid = _event_pid(event)
        belongs = descendant_pids is None or pid in descendant_pids

        if belongs:
            sample_reads += 1
        else:
            background_reads += 1

        classified = classify_vm_artifact_path(event.get("path"))
        if classified is None:
            continue

        path = str(event.get("path", "") or "").strip()
        process_name = str(event.get("process_name", "") or "")
        record = {
            "timestamp": str(event.get("timestamp", "") or ""),
            "process_name": str(event.get("process_name", "") or ""),
            "pid": pid,
            "operation": str(event.get("operation", "") or ""),
            "path": path,
            "result": str(event.get("result", "") or ""),
            "artifact_found": _artifact_found(event.get("result")),
            **classified,
        }

        if not belongs:
            background_hits.append(record)
            continue

        # Windows reacting to the sample is not the sample acting. WER collects
        # machine identity for its crash report, and on the 07 Aug 14:53 run that
        # was five of the nine "artifacts read" -- inside the tree, because
        # `RegSvcs` spawned it, and nothing to do with the malware.
        if _is_windows_response(process_name):
            windows_response_hits.append(record)
            continue

        # And a VM-specific key that Windows itself enumerates. The VBoxSF
        # network-provider registration was the other four on that run, read by
        # PowerShell walking the provider chain.
        if _is_routine_subpath(path):
            routine_hits.append(record)
            continue

        # One row per process per path: a sample that polls a key in a loop
        # should read as one check, not as a hundred.
        key = (pid, path.lower())
        if key in seen:
            continue
        seen.add(key)
        hits.append(record)

    families: dict[str, int] = {}
    for hit in hits:
        family = str(hit["family"])
        families[family] = families.get(family, 0) + 1

    vm_specific = [h for h in hits if h["specificity"] == "vm_specific"]
    collection_available = reads_in_stream > 0

    return {
        # The field to read before anything else here. False means this run's
        # Procmon filter did not capture registry reads, so no VM check could
        # have been seen whether or not the sample made one.
        "collection_available": collection_available,
        "lineage_resolved": descendant_pids is not None,
        "reads_in_stream": reads_in_stream,
        "sample_reads": sample_reads,
        "background_reads": background_reads,
        "hits": hits,
        "counts": {
            "artifacts_read": len(hits),
            "vm_specific": len(vm_specific),
            "identity_surface": len(hits) - len(vm_specific),
            "artifacts_found": sum(1 for h in hits if h["artifact_found"] is True),
            "artifacts_absent": sum(1 for h in hits if h["artifact_found"] is False),
            "background_artifact_reads": len(background_hits),
            # Both counted rather than dropped. A pass that removed five reads
            # and a pass that saw none must not report the same thing.
            "windows_response_reads": len(windows_response_hits),
            "routine_subpath_reads": len(routine_hits),
        },
        "windows_response_hits": windows_response_hits[:50],
        "routine_subpath_hits": routine_hits[:50],
        "families": families,
        "note": _note(collection_available, hits, vm_specific),
    }


def _note(
    collection_available: bool,
    hits: list[dict[str, Any]],
    vm_specific: list[dict[str, Any]],
) -> str:
    if not collection_available:
        return (
            "This run's Procmon filter did not capture registry reads, so a VM "
            "check would not have been seen. Zero artifacts read is a statement "
            "about the collection, not about the sample. Re-run with "
            "tools/procmon-configs/dynamic_registry_reads.pmc to collect them."
        )
    if not hits:
        return (
            "Registry reads were collected and the sample's processes read none "
            "of the known virtual-machine artifacts."
        )

    found = [h for h in hits if h["artifact_found"] is True]
    tail = ""
    if vm_specific:
        names = ", ".join(sorted({str(h["artifact"]) for h in vm_specific})[:4])
        exists = "exists" if len(vm_specific) == 1 else "exist"
        tail = (
            f" {len(vm_specific)} of them {exists} only on a virtual machine "
            f"({names}), so those reads are environment checks and nothing else."
        )
    if found:
        reads = "read" if len(found) == 1 else "reads"
        tail += (
            f" {len(found)} {reads} returned the artifact, meaning the sample "
            "was told it is running in a VM."
        )

    return (
        f"The sample's processes read {len(hits)} virtual-machine artifact(s) "
        f"from the registry.{tail} This is not scored -- ordinary software reads "
        "hardware identity too -- but where the run is otherwise quiet it is the "
        "difference between a sample that did nothing and one that looked first."
    )


def empty_vm_artifact_reads(reason: str = "not collected") -> dict[str, Any]:
    """The shape a run that never got here still reports."""
    return {
        "collection_available": False,
        "lineage_resolved": False,
        "reads_in_stream": 0,
        "sample_reads": 0,
        "background_reads": 0,
        "hits": [],
        "counts": {
            "artifacts_read": 0,
            "vm_specific": 0,
            "identity_surface": 0,
            "artifacts_found": 0,
            "artifacts_absent": 0,
            "background_artifact_reads": 0,
            "windows_response_reads": 0,
            "routine_subpath_reads": 0,
        },
        "windows_response_hits": [],
        "routine_subpath_hits": [],
        "families": {},
        "note": f"Registry reads were {reason}.",
    }
