"""Write a real minidump of this process, for testing dump parsers against.

Not a test. A helper the module-integrity tests call, and one worth keeping
separate for a reason this project has already paid for: the PE carver's first
false-positive class -- eleven "unmapped" images that were Windows MUI resource
files -- was invisible to every synthetic fixture in the suite and turned up the
moment it met a dump the operating system had written. A fixture contains what
its author thought of; a real dump contains what Windows does.

ProcDump is on the guest, not the bench, so this goes straight to
`dbghelp!MiniDumpWriteDump` against the calling process. That is what a crash
reporter does with its own process and needs no privileges beyond the ones it
already has.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
from pathlib import Path

#: MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData.
#: Full memory matters: the point is to compare mapped module bytes against the
#: files they came from, and a normal minidump does not carry the images.
_FULL = 0x00000002 | 0x00000800 | 0x00000004


def write_self_dump(path: str | Path) -> Path:
    """Dump the current process to `path`, full memory. Returns the path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    dbghelp = ctypes.WinDLL("dbghelp.dll")
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

    dbghelp.MiniDumpWriteDump.restype = wt.BOOL
    dbghelp.MiniDumpWriteDump.argtypes = [
        wt.HANDLE, wt.DWORD, wt.HANDLE, wt.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = wt.HANDLE
    kernel32.CreateFileW.argtypes = [
        wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
        wt.DWORD, wt.DWORD, wt.HANDLE,
    ]

    handle = kernel32.CreateFileW(str(path), 0x40000000, 0, None, 2, 0x80, None)
    if handle == wt.HANDLE(-1).value:
        raise OSError(ctypes.get_last_error(), f"cannot create {path}")
    try:
        ok = dbghelp.MiniDumpWriteDump(
            kernel32.GetCurrentProcess(), kernel32.GetCurrentProcessId(),
            handle, _FULL, None, None, None)
        if not ok:
            raise OSError(ctypes.get_last_error(), "MiniDumpWriteDump failed")
    finally:
        kernel32.CloseHandle(handle)
    return path


if __name__ == "__main__":
    import sys
    out = write_self_dump(sys.argv[1] if len(sys.argv) > 1 else "self.dmp")
    print(f"{out}  {out.stat().st_size / 1e6:.1f} MB")
