"""Launching a DLL sample: which host, which export.

**Decided by the PE header, never the extension.** Eight of the ten DLLs in
`mal-112b` are named `.exe` -- a sideloading payload is usually delivered
under whatever name its host expects -- and CreateProcess on one fails with
`WinError 193`, so the run came home static-only with no sign that it had
never executed. The other two are named `.dll` and were refused outright.

**The host is `rundll32.exe`, matched to the DLL's machine.** A 32-bit DLL
needs the `SysWOW64` copy; a 64-bit one needs the native copy, which a 32-bit
interpreter can only reach through `Sysnative`.

**The export.** `rundll32` loads the DLL -- which runs `DllMain`, where a
sideloaded payload does its work -- and then calls one export. A name a
loader is written to be called by is taken first (`STEALERDLL.dll` exports
`Main`); otherwise the lowest ordinal, which is what CAPE does by default. The
corpus's proxy DLLs (`MpClient`, `OLEACC`, readline) export dozens of real
API names, and calling one with `rundll32`'s arguments may crash: that is the
host faulting in mapped code, which no category reads. A DLL with no exports
gets `#1`, which `rundll32` cannot resolve -- `DllMain` still runs.

**The host is the bench's, not the sample's.** A `rundll32.exe` the analyzer
started is not a process a loader chose to hollow, and it is not the sample's
LOLBin: the orchestrator excludes the root host from the hollowing-target
crash count and keeps its image name out of name-based crash attribution,
where it would otherwise claim every `rundll32` crash Windows' own
maintenance produces.

**The command line is a string, not a list.** `rundll32` wants
`"<path>",Export` -- the comma outside the quotes -- and
`list2cmdline` would quote the comma inside them on any path with a space.
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path
from typing import Any

IMAGE_FILE_DLL = 0x2000

MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664

#: Export names written to be called by a loader, most specific first. Exact,
#: case-sensitive matches: an export is a symbol, not a word.
ENTRY_EXPORTS = (
    "Main", "main", "Start", "start", "Run", "run", "Entry", "entry",
    "DllInstall", "DllRegisterServer", "Control_RunDLL",
)


def read_pe_header(path: str | Path) -> dict[str, int] | None:
    """`{"machine", "characteristics"}` from the COFF header, or None.

    Read by hand rather than through `pefile`: this decides whether a run
    happens at all, and it must not depend on an optional import.
    """
    try:
        with open(path, "rb") as handle:
            dos = handle.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return None
            (e_lfanew,) = struct.unpack_from("<I", dos, 0x3C)
            handle.seek(e_lfanew)
            head = handle.read(24)
    except OSError:
        return None
    if len(head) < 24 or head[:4] != b"PE\0\0":
        return None
    machine, = struct.unpack_from("<H", head, 4)
    characteristics, = struct.unpack_from("<H", head, 22)
    return {"machine": machine, "characteristics": characteristics}


def is_dll(path: str | Path) -> bool:
    header = read_pe_header(path)
    return bool(header and header["characteristics"] & IMAGE_FILE_DLL)


def rundll32_for(machine: int, system_root: str | None = None,
                 interpreter_is_64bit: bool | None = None) -> str:
    """The `rundll32.exe` that can load a DLL built for `machine`."""
    root = system_root or os.environ.get("SystemRoot", r"C:\Windows")
    if interpreter_is_64bit is None:
        interpreter_is_64bit = sys.maxsize > 2 ** 32
    if machine == MACHINE_I386:
        return str(Path(root) / "SysWOW64" / "rundll32.exe")
    if machine == MACHINE_AMD64:
        native = "System32" if interpreter_is_64bit else "Sysnative"
        return str(Path(root) / native / "rundll32.exe")
    raise ValueError(f"No rundll32 for DLL machine type {machine:#06x}")


def list_exports(path: str | Path) -> list[tuple[int, str]] | None:
    """`(ordinal, name)` for every export, name "" when by ordinal only.

    None when the table could not be read -- `pefile` absent or the parse
    failed -- which the caller records rather than treating as "no exports".
    """
    try:
        import pefile
    except ImportError:
        return None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    except Exception:
        return None
    try:
        table = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if table is None:
            return []
        return [(int(s.ordinal),
                 s.name.decode("ascii", "replace") if s.name else "")
                for s in table.symbols]
    finally:
        pe.close()


def choose_export(exports: list[tuple[int, str]] | None) -> tuple[str, str]:
    """`(export argument for rundll32, why it was chosen)`."""
    if exports is None:
        return "#1", "export table unreadable"
    if not exports:
        return "#1", "no exports; DllMain runs on load"
    names = {name for _, name in exports if name}
    for candidate in ENTRY_EXPORTS:
        if candidate in names:
            return candidate, "entry-point export"
    ordinal, name = min(exports)
    return f"#{ordinal}", f"lowest ordinal ({name or 'unnamed'})"


def plan_dll_launch(path: str | Path, system_root: str | None = None,
                    interpreter_is_64bit: bool | None = None) -> dict[str, Any] | None:
    """The hosted launch for a DLL sample, or None when it is not a DLL."""
    header = read_pe_header(path)
    if not header or not header["characteristics"] & IMAGE_FILE_DLL:
        return None
    host = rundll32_for(header["machine"], system_root, interpreter_is_64bit)
    export, reason = choose_export(list_exports(path))
    return {
        "host": host,
        "host_image": "rundll32.exe",
        "export": export,
        "export_reason": reason,
        "machine": f"{header['machine']:#06x}",
        "command": [host, f"{Path(path)},{export}"],
        "command_line": f'"{host}" "{Path(path)}",{export}',
    }
