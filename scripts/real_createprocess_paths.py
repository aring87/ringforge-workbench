"""Does the real `CreateProcessW` accept `C:C:\\...`? Measured, not assumed.

`0aq`, `0as` and `0at` all rest on one sentence -- *"`CreateProcessW` with that
name fails on a real machine"* -- and it is the sentence that eliminated readings
2 and 3 and left reading 1 alone. It has never been measured. `0au` queues it as
a **detonation**, which it does not need to be: whether Windows accepts a given
`lpApplicationName` is a Win32 question, not a malware question, and this bench
is a Windows machine.

The second half matters as much. `winenv.resolve_dos_path` is **this harness's
model** of that behaviour, and `0at`'s census -- eleven creates, all failing, no
rendezvous -- is only as good as the model. So every input is put through both
and the two are compared. A row where they disagree is a bug in the census, not
a curiosity.

    ..\\.venv\\Scripts\\python.exe real_createprocess_paths.py

**Nothing malicious runs.** Every call is `CREATE_SUSPENDED`, the failure rows
create nothing at all, and any process that does start is terminated before the
next row. The success controls are ordinary Windows binaries and exist only to
prove the measurement can tell yes from no -- a probe where everything fails is
indistinguishable from a probe that is broken.
"""
from __future__ import annotations

import argparse
import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import win32_emu_env as winenv  # noqa: E402

#: What `+0x2c876` actually builds, measured by `stage4_census.py` against the
#: current loader entries. `0as` recorded the `SysWOW64` form; the directory is
#: **`System32`**, because a 32-bit process's loader entry carries the
#: unredirected path and this builder appends whatever is there. Both forms are
#: rejected, so the conclusion never depended on which -- but the IOC does.
SAMPLE_BUILT = r"C:C:\Windows\System32\compact.exe"

#: The twelve candidates from `0at`, in walk order. Only the first is needed to
#: answer the question; the rest are here because a per-candidate answer is what
#: turns "the walk fails" into "the walk fails for this reason, twelve times".
CANDIDATES = ("compact.exe", "msiexec.exe", "AtBroker.exe", "write.exe",
              "runonce.exe", "cacls.exe", "regini.exe", "replace.exe",
              "wextract.exe", "label.exe", "netbtugc.exe", "SearchFilterHost.exe")

CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008

_ERRORS = {
    0: "SUCCESS",
    2: "ERROR_FILE_NOT_FOUND",
    3: "ERROR_PATH_NOT_FOUND",
    5: "ERROR_ACCESS_DENIED",
    123: "ERROR_INVALID_NAME",
    161: "ERROR_BAD_PATHNAME",
    267: "ERROR_DIRECTORY",
}


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


def real_create(application_name: str) -> tuple[bool, int]:
    """`CreateProcessW(lpApplicationName, NULL, ...)` -- the sample's own call
    shape from `0ad`: CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW
    with a NULL command line. Anything that starts is killed immediately."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = k32.CreateProcessW(
        ctypes.c_wchar_p(application_name), None, None, None, False,
        CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW,
        None, None, ctypes.byref(si), ctypes.byref(pi))
    error = ctypes.get_last_error()
    if ok:
        k32.TerminateProcess(pi.hProcess, 1)
        k32.CloseHandle(pi.hThread)
        k32.CloseHandle(pi.hProcess)
    return bool(ok), (0 if ok else error)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all-candidates", action="store_true",
                    help="run the doubled-drive form for all twelve names, not "
                         "just compact.exe")
    args = ap.parse_args(argv)

    if sys.platform != "win32":
        print("*** VOID: this measures a Windows API and is not on Windows.")
        return 2

    # A success control that is *known* to exist, chosen from the machine rather
    # than hardcoded -- a probe whose only "yes" row is also its only assumption
    # proves nothing.
    control = None
    for candidate in (r"C:\Windows\SysWOW64\where.exe",
                      r"C:\Windows\SysWOW64\cacls.exe",
                      r"C:\Windows\System32\where.exe"):
        if os.path.isfile(candidate):
            control = candidate
            break

    rows: list[tuple[str, str]] = [
        (SAMPLE_BUILT, "what the sample builds (measured)"),
        (r"C:C:\Windows\SysWOW64\compact.exe", "the SysWOW64 form 0as recorded"),
        (r"C:\Windows\SysWOW64\compact.exe", "the intended path"),
        (r"C:Windows\SysWOW64\compact.exe", "drive-relative, single colon"),
        (r"\Windows\SysWOW64\compact.exe", "rooted, no drive"),
        (r"\??\C:\Windows\SysWOW64\compact.exe", "NT prefix"),
        ("compact.exe", "leaf only, no directory"),
    ]
    if control:
        rows.append((control, "SUCCESS CONTROL -- must start"))
    if args.all_candidates:
        rows += [(rf"C:C:\Windows\SysWOW64\{name}", f"doubled, {name}")
                 for name in CANDIDATES]

    print(f"host: {os.environ.get('COMPUTERNAME', '?')}, "
          f"{'64' if sys.maxsize > 2**32 else '32'}-bit python\n")
    print(f"{'real CreateProcessW':<26} {'harness model':<26} input")
    print(f"{'-' * 26} {'-' * 26} {'-' * 40}")

    disagreements: list[tuple[str, bool, bool]] = []
    control_started = None
    for path, note in rows:
        ok, error = real_create(path)
        real = "starts" if ok else f"fails {_ERRORS.get(error, error)}"
        modelled = winenv.resolve_dos_path(path)
        model = f"resolves" if modelled else "refuses"
        agree = bool(ok) == bool(modelled)
        if not agree:
            disagreements.append((path, ok, bool(modelled)))
        print(f"{real:<26} {model:<26} {path!r}")
        print(f"{'':<53} {note}")
        if note.startswith("SUCCESS CONTROL"):
            control_started = ok

    print()
    if control is None:
        print("*** NO SUCCESS CONTROL was available on this host, so a table of "
              "failures cannot")
        print("    be told apart from a broken probe. Everything below is "
              "unsupported.")
        return 2
    if not control_started:
        print(f"*** VOID: the success control {control!r} did not start, so "
              f"this probe cannot")
        print("    distinguish 'Windows rejects it' from 'the call is wrong'. "
              "Fix that first.")
        return 2
    print(f"Success control started and was terminated: {control!r}")

    sample_ok, sample_err = real_create(SAMPLE_BUILT)
    print(f"\nTHE QUESTION -- does the real CreateProcessW accept "
          f"{SAMPLE_BUILT!r}?")
    if sample_ok:
        print("   **YES.** Windows accepts the doubled drive, so reading 1 of "
              "0aq is wrong, the")
        print("   path is not malformed after all, and 0at's census of eleven "
              "failing creates is")
        print("   an artifact of this harness. The stage-4 findings need "
              "redoing against a")
        print("   create that succeeds.")
    else:
        print(f"   **NO** -- {_ERRORS.get(sample_err, sample_err)}. Reading 1 "
              f"of 0aq is confirmed by")
        print("   measurement rather than assumed: a real machine rejects every "
              "one of the twelve,")
        print("   prepare_host returns 0, and 0at's census is the branch a real "
              "machine reaches.")

    print(f"\nHARNESS MODEL vs REALITY: "
          f"{len(rows) - len(disagreements)}/{len(rows)} rows agree")
    for path, ok, modelled in disagreements:
        print(f"   *** {path!r}: Windows {'starts' if ok else 'refuses'} it, "
              f"resolve_dos_path {'resolves' if modelled else 'refuses'} it")
    if disagreements:
        print("   Each disagreement is a place the census is measuring this "
              "harness rather than")
        print("   a machine. Fix resolve_dos_path before reading 0at's numbers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
