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

from dynamic_analysis.utils import is_windows_response_process


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

#: The Windows-response list lives in `utils`, because the network attribution
#: needs the same one and neither module can import the other. See
#: `WINDOWS_RESPONSE_PROCESSES` there for why WER is in the sample's tree and
#: still is not the sample's behaviour.

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
    means the artifact was not on that guest and the check came back clean.
    An `ACCESS DENIED` says only that the sample asked.

    **Nothing in this project removes those artifacts, and an earlier version
    of this line said `vm_hygiene.ps1` did.** That script only *detects* a VM,
    so it can refuse to run on a real workstation; it disables updaters and
    telemetry and touches no guest-additions key or service. On this
    workbench's own guest a check for the VirtualBox additions is therefore
    expected to return `SUCCESS`, and a prediction of `NAME NOT FOUND` would
    be predicting from a de-artifacting step that does not exist.
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
        if is_windows_response_process(process_name):
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
        # The rows, not only the count. Run `ce0d08be...` on 31 Aug reported
        # `background_artifact_reads: 3` and nothing else -- three reads of a VM
        # artifact by a process outside the resolved tree, with no way to see
        # which process or which key. That sample drops a copy and exits in
        # eight seconds, so the process that would do the checking is exactly
        # the one lineage does not reach, and the three rows were the answer to
        # the run's whole question. Counted and discarded is the failure this
        # module's own docstring warns about, applied to itself.
        "background_hits": background_hits[:50],
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


# ---------------------------------------------------------------------------
# Gap 4's active half: read a VM artifact, and then go quiet
# ---------------------------------------------------------------------------
#
# The passive half -- `summarize_abnormal_termination` -- refuses to let a
# crashed chain read as a clean one. This is the other shape the same problem
# takes: a sample that checks for a hypervisor, decides it does not like the
# answer, and *exits tidily*. No crash, no error, an empty report and a clean
# verdict. From outside the guest that is indistinguishable from a sample that
# simply had nothing to do, and this does not pretend otherwise. What it does is
# make the *coincidence* visible: the last thing the sample did before going
# quiet was ask whether it was on a virtual machine.
#
# **Nothing here is scored, and the thresholds below are not calibrated.**
# Registry-read collection has now been configured for three runs and captured
# on one, and the sample this exists for has never produced a read this pass
# could see. So the mechanism is built and its numbers are declared unvalidated
# rather than presented as tuned -- the alternative is a detector whose
# false-positive rate is a guess wearing a constant's clothing.

#: Events by the sample's own tree after the check, below which the run is
#: described as having gone quiet.
#:
#: **A placeholder, and labelled as one.** It is a count rather than a duration
#: because Procmon's `Time of Day` carries no date and parsing it to compare
#: across midnight is a second bug waiting to happen; capture order is exact and
#: needs no parsing. The right value is whatever a live run shows separates a
#: bail from a pause, and no live run has shown it.
QUIET_EVENT_THRESHOLD = 10


def correlate_vm_check_with_silence(
    vm_reads: dict[str, Any],
    events: list[dict[str, Any]],
    descendant_pids: set[int] | None = None,
) -> dict[str, Any]:
    """Did the sample check for a VM and then stop doing anything?

    Answers one of four ways, and the distinction between the first two is the
    whole point:

    * ``not_collected`` -- the Procmon filter captured no registry reads, so no
      check could have been seen. Says nothing about the sample.
    * ``no_vm_check`` -- reads were captured and none named a VM artifact.
    * ``checked_then_active`` -- it looked, and carried on working.
    * ``checked_then_quiet`` -- it looked, and then did almost nothing. The
      case worth a human reading the run again.

    Only `vm_specific` reads count as the check. An `identity_surface` read --
    `SystemBiosVersion` and friends -- is where a VM check looks *and* where an
    inventory agent looks, so building a bail detector on one would fire on
    ordinary software asking what machine it is on.
    """
    result: dict[str, Any] = {
        "available": False,
        "scored": False,
        "verdict": "not_collected",
        "checked_at_event": None,
        "last_check": {},
        "events_after_check": 0,
        "sample_events_after_check": 0,
        "threshold": QUIET_EVENT_THRESHOLD,
        "threshold_calibrated": False,
        "note": "",
    }

    if not vm_reads.get("collection_available"):
        result["note"] = (
            "This run captured no registry reads, so a VM check could not have "
            "been seen. Nothing here is a statement about the sample."
        )
        return result

    result["available"] = True

    vm_specific = [
        h for h in (vm_reads.get("hits") or [])
        if h.get("specificity") == "vm_specific"
    ]
    if not vm_specific:
        result["verdict"] = "no_vm_check"
        result["note"] = (
            "Registry reads were captured and none of them named an artifact "
            "that only exists on a virtual machine."
        )
        return result

    last = vm_specific[-1]
    result["last_check"] = {
        k: last.get(k) for k in
        ("timestamp", "process_name", "pid", "path", "artifact", "family",
         "result", "artifact_found")
    }

    # Position by capture order rather than by clock. Matching on the tuple the
    # hit was built from, because a path can be read more than once and it is
    # the *last* one that the silence has to follow.
    index = None
    for position, event in enumerate(events):
        if (str(event.get("path", "") or "").lower() == str(last.get("path", "")).lower()
                and _event_pid(event) == last.get("pid")
                and str(event.get("timestamp", "") or "") == last.get("timestamp")):
            index = position
    if index is None:
        result["note"] = (
            "A VM-specific read was found but could not be located in the event "
            "stream, so what followed it could not be measured."
        )
        result["available"] = False
        return result

    after = events[index + 1:]
    result["checked_at_event"] = index
    result["events_after_check"] = len(after)

    mine = 0
    for event in after:
        pid = _event_pid(event)
        if descendant_pids is None or (pid is not None and pid in descendant_pids):
            mine += 1
    result["sample_events_after_check"] = mine

    if mine <= QUIET_EVENT_THRESHOLD:
        result["verdict"] = "checked_then_quiet"
        result["note"] = (
            f"The sample read {last.get('artifact', 'a VM artifact')} and then "
            f"produced {mine} further event(s) before the run ended. A sample "
            "that checks for a hypervisor and then stops is the shape of a "
            "deliberate bail -- but a sample with nothing left to do looks "
            "identical from here, so read an otherwise-empty run as "
            "inconclusive rather than clean."
        )
    else:
        result["verdict"] = "checked_then_active"
        result["note"] = (
            f"The sample read {last.get('artifact', 'a VM artifact')} and went "
            f"on to produce {mine} further event(s), so the check did not end "
            "the run."
        )
    return result


def empty_vm_check_correlation(reason: str = "not collected") -> dict[str, Any]:
    return {
        "available": False,
        "scored": False,
        "verdict": "not_collected",
        "checked_at_event": None,
        "last_check": {},
        "events_after_check": 0,
        "sample_events_after_check": 0,
        "threshold": QUIET_EVENT_THRESHOLD,
        "threshold_calibrated": False,
        "note": reason,
    }


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
        "background_hits": [],
        "windows_response_hits": [],
        "routine_subpath_hits": [],
        "families": {},
        "note": f"Registry reads were {reason}.",
    }
