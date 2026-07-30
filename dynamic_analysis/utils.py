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
)


def is_analyzer_image(value: object) -> bool:
    """True when a path or image name belongs to the analysis tooling."""
    lowered = str(value or "").strip().lower().replace("/", "\\")
    if not lowered:
        return False
    return any(marker in lowered for marker in ANALYZER_TOOL_IMAGE_MARKERS)


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