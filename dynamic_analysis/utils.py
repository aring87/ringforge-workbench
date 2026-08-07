from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


#: Images belonging to the analysis tooling rather than to the sample.
#:
#: FakeNet-NG registers its WinDivert traffic diverter as a driver, Procmon and
#: Npcap install theirs, and all of it happens inside the observation window --
#: so without this the workbench reports its own plumbing as the sample's
#: behaviour. The list lives here, in a module that imports nothing else from
#: the package, because both the autoruns diff and the Sysmon summariser need it
#: and neither can import the other.
#:
#: Matches are classified, never discarded. An analyst who wants to confirm the
#: tooling loaded correctly can still see it; it simply stops counting as a
#: finding.
ANALYZER_TOOL_IMAGE_MARKERS = (
    "windivert",     # FakeNet-NG's traffic diverter
    "pydivert",      # ...and the Python package that ships it
    "\\fakenet",
    "procmon",
    "procdump",
    "autorunsc",
    "sysmondrv",
    "sysmon64",
    "npcap",
    "npf.sys",
    # The packet capture backend itself, not just its driver. A mimikatz run
    # reported "<unknown process> -> dumpcap.exe" as process injection and the
    # ATT&CK mapping raised T1055 against the sample -- for a CreateRemoteThread
    # into the workbench's own capture tool. npcap and npf.sys were listed;
    # the binary doing the capturing was not.
    "dumpcap",
    "tshark",
    "\\wireshark\\",
)


def is_analyzer_image(value: object) -> bool:
    """True when a path or image name belongs to the analysis tooling."""
    lowered = str(value or "").strip().lower().replace("/", "\\")
    if not lowered:
        return False
    return any(marker in lowered for marker in ANALYZER_TOOL_IMAGE_MARKERS)


#: Windows *reacting to* the sample, which is not the sample acting.
#:
#: Error Reporting is the case that keeps arising. The sample crashes, Windows
#: starts `WerFault.exe` as a child of the crashed process, and lineage counts it
#: as the sample's -- correctly, because the sample's tree really is where it came
#: from. Then WER reads `SystemManufacturer`, `BIOSVersion` and `SystemProductName`
#: for its crash report and tries to upload it over `:443`. Attributed by lineage
#: alone that reads as a VM check and a C2 contact, and it is neither.
#:
#: **Lineage says a process belongs to the tree; it cannot say the behaviour
#: belongs to the malware.** That distinction is what this list is for, and it is
#: the only thing it is for -- a suppression aid that runs *before* attribution,
#: never a substitute for it.
#:
#: Here rather than in either caller, because the VM-artifact pass and the network
#: attribution both need it and neither imports the other. Both count what they
#: removed rather than dropping it silently.
#:
#: Deliberately short. Every name is a process Windows starts *in response to*
#: something the sample did, so the same reasoning would cover a troubleshooter
#: fired by a crash or the indexer noticing a dropped file -- but those have not
#: been observed polluting a finding yet, and a suppression list that grows on
#: speculation is how attribution gets replaced by a name list.
WINDOWS_RESPONSE_PROCESSES = frozenset({
    "werfault.exe",
    "werfaultsecure.exe",
    "wermgr.exe",
})


def is_windows_response_process(value: object) -> bool:
    """True when the process is Windows responding to the sample, not the sample."""
    name = str(value or "").strip().lower().replace("/", "\\").rsplit("\\", 1)[-1]
    return name in WINDOWS_RESPONSE_PROCESSES


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_json(path: str | Path, data: Any) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return p


def read_json(path: str | Path) -> Any:
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8"))


def sha256_file(path: str | Path) -> str:
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha1_file(path: str | Path) -> str:
    p = Path(path)
    h = hashlib.sha1()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path: str | Path) -> str:
    p = Path(path)
    h = hashlib.md5()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_size(path: str | Path) -> int:
    return Path(path).stat().st_size