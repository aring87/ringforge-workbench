"""Record which code a single process enumeration runs, so two passes can be diffed.

The seven enumerations before `ExitProcess` are not seven identical sweeps.
Measured with `trace_blocklist.py --which N`, passes #4 and #6 reach the crc32
epilogue after 2.3M blocks, while #5 and #7 run 9.4M and put no served name and
no blocklist constant in EAX at all. Two shapes, alternating, with the exact
same numbers each time -- so the last thing the sample does before leaving is a
pass that never consults the blocklist.

`trace_blocklist.py` cannot say what that pass *does*, because it anchors on a
known value reaching EAX and in the quiet pass no known value ever does. This
asks the other question: which addresses execute. Run it on a hashing pass and a
non-hashing one, then `--diff` the two, and what comes out is the code that is
unique to the pass that decides to give up.

    ..\\.venv\\Scripts\\python.exe trace_poll_pass.py --which 6 --out pass6.json
    ..\\.venv\\Scripts\\python.exe trace_poll_pass.py --which 7 --out pass7.json
    ..\\.venv\\Scripts\\python.exe trace_poll_pass.py --diff pass6.json pass7.json

Run it from `scripts/`.
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

import capstone
from unicorn import UC_HOOK_CODE

import win32_emu_env as winenv
from emulate_native_stub import Emulator
from trace_blocklist import STATE, arm_at_process_list


def _disassembly(emu: Emulator) -> dict[int, tuple[str, str]]:
    alloc_base, alloc_size = emu.allocs[0]
    blob = bytes(emu.mu.mem_read(alloc_base, alloc_size))
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.skipdata = True
    return {i.address: (i.mnemonic, i.op_str) for i in md.disasm(blob, alloc_base)}


def record(args: argparse.Namespace) -> int:
    emu = Emulator.restore(args.state)
    emu.repair_wow64_crash()
    print(f"restored at {emu.blocks:,} blocks")

    if not arm_at_process_list(emu, args.which):
        return 1

    started = emu.blocks
    alloc_base, alloc_size = emu.allocs[0]
    alloc_end = alloc_base + alloc_size

    # Counting every address, not just the allocation's, would drown the result
    # in ntdll's own code -- the question is what *stage 3* runs.
    counts: collections.Counter[int] = collections.Counter()

    def cb(uc, address, size, _user):
        if alloc_base <= address < alloc_end:
            counts[address] += 1

    handle = emu.mu.hook_add(UC_HOOK_CODE, cb)
    print(f"  tracing {args.window:,} instructions...")
    status = emu.resume(count=args.window)
    emu.mu.hook_del(handle)
    ran = emu.blocks - started
    print(f"  {status}  ({emu.blocks:,} blocks, {ran:,} in this pass)")
    print(f"  {len(counts):,} distinct addresses executed in the allocation")

    payload = {
        "which": args.which,
        "state": args.state,
        "blocks_at_arm": started,
        "blocks_run": ran,
        "status": status,
        "alloc_base": alloc_base,
        "counts": {str(a): c for a, c in counts.items()},
    }
    Path(args.out).write_text(json.dumps(payload), encoding="utf-8")
    print(f"  wrote {args.out}")
    return 0


def diff(args: argparse.Namespace) -> int:
    left, right = (json.loads(Path(p).read_text(encoding="utf-8")) for p in args.diff)
    lc = {int(a): c for a, c in left["counts"].items()}
    rc = {int(a): c for a, c in right["counts"].items()}

    print(f"pass #{left['which']}: {left['blocks_run']:,} blocks, {len(lc):,} addresses")
    print(f"pass #{right['which']}: {right['blocks_run']:,} blocks, {len(rc):,} addresses")

    only_left = sorted(set(lc) - set(rc))
    only_right = sorted(set(rc) - set(lc))
    print(f"\nonly in #{left['which']}: {len(only_left):,}")
    print(f"only in #{right['which']}: {len(only_right):,}")

    # Re-disassemble once so the diff is readable without a second emulator run.
    emu = Emulator.restore(args.state)
    dis = _disassembly(emu)

    for label, addrs, counts in (
        (f"only in pass #{left['which']} (the hashing pass)", only_left, lc),
        (f"only in pass #{right['which']} (the quiet pass)", only_right, rc),
    ):
        print(f"\n{'=' * 70}\n{label}\n{'=' * 70}")
        if not addrs:
            print("  nothing")
            continue
        runs = _contiguous(addrs)
        for start, end in runs[: args.runs]:
            total = sum(counts[a] for a in addrs if start <= a <= end)
            print(f"\n  {start:#010x}-{end:#010x}   {total:,} executions")
            for a in [x for x in addrs if start <= x <= end][: args.lines]:
                m, o = dis.get(a, ("?", ""))
                print(f"    {a:#010x}  {m:<9} {o}")
        if len(runs) > args.runs:
            print(f"\n  ... {len(runs) - args.runs} more regions")
    return 0


def _contiguous(addrs: list[int], gap: int = 64) -> list[tuple[int, int]]:
    """Group addresses into regions, so the output reads as code not as a list."""
    if not addrs:
        return []
    runs = [[addrs[0], addrs[0]]]
    for a in addrs[1:]:
        if a - runs[-1][1] <= gap:
            runs[-1][1] = a
        else:
            runs.append([a, a])
    return [(s, e) for s, e in sorted(runs, key=lambda r: r[0] - r[1])]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--which", type=int, default=7)
    ap.add_argument("--window", type=int, default=40_000_000)
    ap.add_argument("--out", default="pass.json")
    ap.add_argument("--diff", nargs=2, metavar=("LEFT", "RIGHT"))
    ap.add_argument("--runs", type=int, default=8, help="regions to print per side")
    ap.add_argument("--lines", type=int, default=24, help="instructions per region")
    args = ap.parse_args(argv)

    return diff(args) if args.diff else record(args)


if __name__ == "__main__":
    raise SystemExit(main())
