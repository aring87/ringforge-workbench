"""Which call produced the allocation an address lives in? Restore only, no run.

Written to answer "is the control block stage 4 polls a section, or heap?" and
kept because getting it wrong is easy in two specific ways, both encoded here.

    ..\\.venv\\Scripts\\python.exe where_allocated.py 0x3eee874

**Do not read `section_requests` / `section_views` / `section_maps` / `sections`
/ `named_objects` / `remote_targets` off a restored state.** `_init_observations`
resets them and `restore()` does not put them back, so a state whose loader made
three `NtCreateSection` calls reports **zero sections**. `calls`, `allocs` and
`log` are restored and are the only ones that mean anything here.

**The correlation is n-th-to-n-th and only sound if the lists match.** `allocs`
is append-ordered and every allocation goes through `Emulator.alloc`, so the n-th
allocating call in the log is the n-th `allocs` entry. Miss one allocating name
and every later row is mislabelled: leaving out `RtlDosPathNameToNtPathName_U`
(`emulate_native_stub.py:755`, it allocates a buffer that has to outlive the
call) gave 53 against 55 and relabelled the answer from `NtMapViewOfSection` to
`NtAllocateVirtualMemory`. This refuses to pair them when the lengths differ
rather than lining them up anyway.
"""
from __future__ import annotations

import argparse

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"

#: Every API in `Emulator.api` whose handler calls `alloc`. Kept as one list
#: because the correctness of the whole report is "is this list complete".
ALLOCATING = {"VirtualAlloc", "VirtualAllocEx", "NtAllocateVirtualMemory",
              "ZwAllocateVirtualMemory", "HeapAlloc", "RtlAllocateHeap",
              "LocalAlloc", "GlobalAlloc", "NtMapViewOfSection",
              "RtlDosPathNameToNtPathName_U"}

#: Fields `_init_observations` creates and `restore` does not repopulate.
#: Reading any of these off a restored state gives the empty value, not the
#: measurement.
NOT_RESTORED = ("section_requests", "section_views", "section_maps", "sections",
                "named_objects", "remote_targets", "remote_writes",
                "control_calls", "process_handles", "_next_handle")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("addresses", nargs="+", type=lambda v: int(v, 0),
                    help="addresses to locate")
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--all", action="store_true",
                    help="list every allocation, not just the matching ones")
    args = ap.parse_args(argv)

    emu = Emulator.restore(args.state)
    log = emu.log or []

    seq, mapped = [], set()
    for e in log:
        if e["name"] not in ALLOCATING:
            continue
        if e["name"] == "NtMapViewOfSection":
            # A second map of the same handle reuses the existing view and does
            # not allocate. Count one per distinct section handle.
            handle = (e.get("args") or ["0x0"])[0]
            if handle in mapped:
                continue
            mapped.add(handle)
        seq.append(e)

    print(f"allocating calls in the log : {len(seq)}")
    print(f"entries in emu.allocs       : {len(emu.allocs)}")
    if len(seq) != len(emu.allocs):
        print(f"\n*** VOID: the lists differ by {len(emu.allocs) - len(seq)}, so "
              f"the n-th/n-th pairing is unsound and\n    every row after the "
              f"first unaccounted allocation would be mislabelled.\n"
              f"    Something allocates outside ALLOCATING -- grep "
              f"`self.alloc(` in emulate_native_stub.py\n    and add what is "
              f"missing. Reporting nothing rather than something wrong.")
        return 2
    print("    same length, so the pairing is one-to-one\n")

    for i, (p, n) in enumerate(emu.allocs):
        hits = [a for a in args.addresses if p <= a < p + n]
        if not hits and not args.all:
            continue
        e = seq[i]
        print(f"{i:>3}  {p:#010x} + {n:>12,} = {p + n:#010x}")
        print(f"     {e['name']} at {e['blocks']:,} blocks")
        if e.get("args"):
            print(f"     args={e['args']}")
        for a in hits:
            print(f"     >>> {a:#010x} is at +{a - p:#x} into this allocation")
        print()

    print("NOT RESTORED, so do not read these off this state:")
    for field in NOT_RESTORED:
        value = getattr(emu, field, None)
        size = value if isinstance(value, int) else len(value or ())
        print(f"   emu.{field:20} = {size!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
