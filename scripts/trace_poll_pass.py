"""Record which code a single process enumeration runs, so two passes can be diffed.

The seven enumerations before `ExitProcess` are not seven identical sweeps: some
consult the process-name blocklist and some do not. `trace_blocklist.py --which
N` shows that much, because a served name's hash reaches EAX on #4 and #6 and on
neither #5 nor #7.

**It cannot say how long a pass is, and reading its block counts that way is a
mistake this tool exists partly to correct.** It calls `emu_stop()` a few
hundred instructions after it captures a hit, so a pass that hashes appears
short (~2.3M blocks) purely because the instrument stopped. Measured here
without that early stop, #6 runs 9,449,663 blocks and #7 runs 9,439,946 -- the
same length within 0.1%.

So the difference is *which code runs*, not how much. This records the addresses
executed inside the allocation during one enumeration; `--diff` two passes and
what comes out is the code unique to each, which for the quiet pass is the
shortest path to whatever decides to give up.

    ..\\.venv\\Scripts\\python.exe trace_poll_pass.py --which 6 --out pass6.json
    ..\\.venv\\Scripts\\python.exe trace_poll_pass.py --which 7 --out pass7.json
    ..\\.venv\\Scripts\\python.exe trace_poll_pass.py --diff pass6.json pass7.json

Run it from `scripts/`.
"""
from __future__ import annotations

import argparse
import base64
import collections
import json
from pathlib import Path

import capstone
from unicorn import UC_HOOK_CODE

import win32_emu_env as winenv
from emulate_native_stub import Emulator
from trace_blocklist import STATE, arm_at_process_list


def _decode_at(blob: bytes, base: int, address: int) -> str:
    """Decode one instruction at an address the CPU actually executed.

    Two ways to get this wrong, both already recorded in the handoff as having
    produced a retracted conclusion, and both hit here on the first attempt.

    A linear sweep from `base` desynchronises and renders ordinary code as
    `iretd` / `fmul` / `?`. Every address in a trace was executed, so decoding
    one instruction at each is exact by construction and needs no sweep.

    Worse, the allocation **keeps decrypting as it runs**. Bytes read from a
    fresh restore of `after_scan.state` at 348M blocks are not the bytes that
    executed at 597M, so the disassembly must come from memory captured at
    trace time -- which is why `counts` and `alloc` travel together in one file.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    offset = address - base
    if not 0 <= offset < len(blob):
        return "(outside the captured allocation)"
    decoded = next(md.disasm(blob[offset:offset + 16], address), None)
    return f"{decoded.mnemonic:<8} {decoded.op_str}" if decoded else "(undecodable)"


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

    # Captured *after* the pass, because the allocation decrypts as it runs and
    # a disassembly taken from any other moment is of different bytes.
    alloc = bytes(emu.mu.mem_read(alloc_base, alloc_size))

    payload = {
        "which": args.which,
        "state": args.state,
        "blocks_at_arm": started,
        "blocks_run": ran,
        "status": status,
        "alloc_base": alloc_base,
        "alloc": base64.b64encode(alloc).decode("ascii"),
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

    for label, addrs, counts, side in (
        (f"only in pass #{left['which']}", only_left, lc, left),
        (f"only in pass #{right['which']}", only_right, rc, right),
    ):
        print(f"\n{'=' * 70}\n{label}\n{'=' * 70}")
        if not addrs:
            print("  nothing")
            continue
        if "alloc" not in side:
            print("  no allocation captured -- re-record with the current tool")
            continue
        blob = base64.b64decode(side["alloc"])
        base = side["alloc_base"]
        runs = _contiguous(addrs)
        for start, end in runs[: args.runs]:
            total = sum(counts[a] for a in addrs if start <= a <= end)
            print(f"\n  {start:#010x}-{end:#010x}   {total:,} executions")
            for a in [x for x in addrs if start <= x <= end][: args.lines]:
                print(f"    {a:#010x}  {counts[a]:>7}x  {_decode_at(blob, base, a)}")
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
