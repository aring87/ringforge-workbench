"""Find what produced the size stage 3 hands to `NtCreateSection`.

The explorer-child run reached a complete section-mapping injection and asked
for a **24,820,736 byte** section -- `MaximumSize raw 00bc7a0100000000`, so the
value is genuinely the sample's, not a misread. It then filled the whole view
with uniformly random bytes: entropy 8.000 in every megabyte, 99.61% non-zero,
which is 255/256 exactly. No PE, no strings. That is a keystream, not a payload,
and this sample's known payload is 57,344 bytes.

So the size is the suspect. If `0x17abc00` traces back to something this harness
invented -- an unhandled API's `0x1`, a fabricated handle, an uninitialised read
-- then the injection is real in shape but running on a bogus length, and the
divergence is the finding rather than the payload. That is the standing unknown
`emulate_native_stub`'s own docstring names.

The `LARGE_INTEGER` lives on the stack at `0x2fce24`, and a stack slot is reused
constantly, so a write-watch there catches a great deal that is unrelated. The
answer is the *last* write before `NtCreateSection`, which this reports along
with the instruction that made it.

    ..\\.venv\\Scripts\\python.exe trace_section_size.py
    ..\\.venv\\Scripts\\python.exe trace_section_size.py --addr 0x2fce24 --keep 40

Run it from `scripts/`.
"""
from __future__ import annotations

import argparse
import collections
from pathlib import Path

import capstone
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_ECX,
                               UC_X86_REG_EDX, UC_X86_REG_EIP)

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator
from trace_blocklist import STATE

#: Where the run logged `NtCreateSection`, so the trace can stop just past it.
CREATE_SECTION_BLOCKS = 542_537_463

#: The window in which the payload has to reach the view: the local
#: `NtMapViewOfSection` at 547M through `NtClose` on the section handle at 700M.
#: Nothing is logged in between, because the copy is ordinary instructions.
COPY_WINDOW = (547_430_617, 700_969_896)

#: The payload copy itself, measured: 0x0202f454 reads the source exactly
#: once per byte across this span, ending 645 blocks before NtClose. The
#: rest of COPY_WINDOW is keystream fill.
COPY_PASS = (700_695_844, 700_969_251)


def copy_dest(args: argparse.Namespace) -> int:
    """Where in the view the payload lands, and what the copy does to it.

    The source at `0x27e7000` is read exactly once per byte across
    700,695,844-700,969,251 blocks and its bytes are not in the view verbatim,
    so the copy transforms them. Watching writes to the view during only that
    window isolates the destination from the 24 MB of keystream fill that
    precedes it -- the fill would otherwise drown the 273,408 bytes that matter.

    With source and destination in hand the transform is one XOR away.
    """
    emu = Emulator.restore(args.state)
    emu.repair_wow64_crash()
    print(f"restored at {emu.blocks:,} blocks")
    lo, hi = args.copy_dest, args.copy_dest + args.dest_len
    print(f"watching writes to {lo:#x}..{hi:#x}")
    print(f"recording only within {COPY_PASS[0]:,}-{COPY_PASS[1]:,} blocks\n")

    spans: list[list[int]] = []
    writers: collections.Counter = collections.Counter()
    total = {"n": 0, "ignored": 0}

    def on_write(uc, access, address, length, value, _user):
        if not COPY_PASS[0] <= emu.blocks <= COPY_PASS[1]:
            total["ignored"] += 1
            return
        total["n"] += 1
        writers[uc.reg_read(UC_X86_REG_EIP)] += 1
        end = address + length
        if spans and address <= spans[-1][1] + 0x40:
            spans[-1][1] = max(spans[-1][1], end)
        else:
            spans.append([address, end])

    handle = emu.mu.hook_add(UC_HOOK_MEM_WRITE, on_write, begin=lo, end=hi - 1)
    status = ""
    while emu.blocks < args.until:
        status = emu.resume(count=200_000_000)
        if "returned" not in status:
            break
    emu.mu.hook_del(handle)
    print(f"  {status}  ({emu.blocks:,} blocks)")
    print(f"  {total['n']:,} write(s) inside the pass, {total['ignored']:,} outside it\n")

    if not total["n"]:
        print("  nothing written in that window -- check COPY_PASS against a")
        print("  fresh --reads-of before concluding the copy goes elsewhere.")
        return 1

    print(f"  {len(spans)} destination span(s):")
    for lo2, hi2 in spans[:10]:
        print(f"    {lo2:#x}-{hi2:#x}  (+{lo2 - args.copy_dest:#x}, {hi2 - lo2:,} bytes)")
    print("\n  writers:")
    for eip, count in writers.most_common(6):
        print(f"    {eip:#010x}  {count:,}x")

    if args.dump_dest and spans:
        start = spans[0][0]
        end = spans[-1][1]
        Path(args.dump_dest).write_bytes(bytes(emu.mu.mem_read(start, end - start)))
        print(f"\n  destination {start:#x}-{end:#x} written to {args.dump_dest}")
    return 0


def reads_of(args: argparse.Namespace) -> int:
    """Who reads a buffer, and when -- for linking a source to a destination.

    The section's base size is `0x42c00`, and an allocation of exactly that size
    exists at `0x27e7000` holding 273,408 bytes of high-entropy data that match
    nothing on the artifact drive. Tempting, but its bytes do not appear in the
    section view at any offset, so the size match alone proves nothing.

    A read-watch settles it. If the loader reads this buffer during the copy
    window then the two are linked and whatever sits between them is a
    transformation; if it never touches it, the size match is chance and the
    real source is somewhere else.
    """
    emu = Emulator.restore(args.state)
    emu.repair_wow64_crash()
    print(f"restored at {emu.blocks:,} blocks")
    lo, hi = args.reads_of, args.reads_of + args.reads_len
    print(f"watching reads of {lo:#x}..{hi:#x} until {args.until:,} blocks")

    first: list = []
    spans: list[list[int]] = []
    readers: collections.Counter = collections.Counter()
    # First and last block at which each instruction touched the buffer. *When*
    # a reader runs is what links it to the copy: the payload goes into the view
    # between the two NtMapViewOfSection calls and NtClose on the section, so a
    # linear pass inside that window is the copy and one outside it is not.
    windows: dict[int, list[int]] = {}
    total = {"n": 0}

    def on_read(uc, access, address, length, value, _user):
        total["n"] += 1
        eip = uc.reg_read(UC_X86_REG_EIP)
        readers[eip] += 1
        seen = windows.get(eip)
        if seen is None:
            windows[eip] = [emu.blocks, emu.blocks]
        else:
            seen[1] = emu.blocks
        if not first:
            first.append((emu.blocks, eip, address))
        end = address + length
        if spans and address <= spans[-1][1] + 0x40:
            spans[-1][1] = max(spans[-1][1], end)
        else:
            spans.append([address, end])

    handle = emu.mu.hook_add(UC_HOOK_MEM_READ, on_read, begin=lo, end=hi - 1)
    status = ""
    while emu.blocks < args.until:
        status = emu.resume(count=200_000_000)
        if "returned" not in status:
            break
    emu.mu.hook_del(handle)
    print(f"  {status}  ({emu.blocks:,} blocks)")
    print(f"  {total['n']:,} read(s) of that buffer\n")

    if not total["n"]:
        print("  never read -- the size match is coincidence, or the copy")
        print("  happens outside this window. Widen --until before concluding.")
        return 1

    blocks, eip, address = first[0]
    print(f"  first read at {blocks:,}blk  eip {eip:#010x}  [{address:#x}]")
    print(f"  {len(spans)} span(s) touched:")
    for lo2, hi2 in spans[:10]:
        print(f"    {lo2:#x}-{hi2:#x}  (+{lo2 - args.reads_of:#x}, {hi2 - lo2:,} bytes)")
    print(f"\n  readers, by instruction, with the window each ran in:")
    for eip, count in readers.most_common(8):
        lo2, hi2 = windows[eip]
        inside = COPY_WINDOW[0] <= lo2 and hi2 <= COPY_WINDOW[1]
        overlaps = lo2 <= COPY_WINDOW[1] and hi2 >= COPY_WINDOW[0]
        where = ("INSIDE the copy window" if inside
                 else "overlaps the copy window" if overlaps
                 else "outside the copy window")
        print(f"    {eip:#010x}  {count:,}x  {lo2:,}-{hi2:,}blk  -- {where}")
    print(f"\n  copy window is {COPY_WINDOW[0]:,}-{COPY_WINDOW[1]:,}blk: the two "
          f"NtMapViewOfSection calls\n  through NtClose on the section handle.")
    return 0


def regs_at(args: argparse.Namespace) -> int:
    """Read registers wherever execution reaches one of `--regs-at`.

    `mov [ebp-8], edx` at 0x0201bc64 takes the size from `edx`, and `edx` came
    from `[ecx]` a few instructions earlier with `ecx` supplied by the caller.
    So the address holding the size is only knowable at runtime -- read `ecx`
    there and the next watch has something to aim at. `eax` says which of the
    three branches ran, and therefore whether the caller's own figure was
    0x17abc00 or 0x17abc00 - 0x80000.
    """
    emu = Emulator.restore(args.state)
    emu.repair_wow64_crash()
    print(f"restored at {emu.blocks:,} blocks")
    targets = set(args.regs_at)
    print("breaking at " + ", ".join(f"{t:#x}" for t in sorted(targets)))

    hits: list[tuple] = []

    def cb(uc, address, size, _user):
        if address not in targets:
            return
        hits.append((
            emu.blocks, address,
            uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_ECX),
            uc.reg_read(UC_X86_REG_EDX), uc.reg_read(UC_X86_REG_EBP)))
        if len(hits) >= args.hits:
            uc.emu_stop()

    handle = emu.mu.hook_add(UC_HOOK_CODE, cb)
    status = ""
    while emu.blocks < args.until and len(hits) < args.hits:
        status = emu.resume(count=200_000_000)
        if "returned" not in status:
            break
    emu.mu.hook_del(handle)
    print(f"  {status}  ({emu.blocks:,} blocks)\n")

    if not hits:
        print("  never reached -- widen --until")
        return 1
    for blocks, address, eax, ecx, edx, ebp in hits:
        print(f"  {blocks:>13,}blk  at {address:#010x}  eax={eax:#x} ({eax})  "
              f"ecx={ecx:#010x}  edx={edx:#010x}  ebp={ebp:#010x}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--regs-at", type=lambda v: [int(x, 0) for x in v.split(",")],
                    default=None, help="dump registers at these addresses")
    ap.add_argument("--hits", type=int, default=6)
    ap.add_argument("--addr", type=lambda v: int(v, 0), default=0x2FCE24,
                    help="the LARGE_INTEGER MaximumSize lives here")
    ap.add_argument("--len", type=int, default=8)
    ap.add_argument("--keep", type=int, default=24,
                    help="how many of the most recent writes to report")
    ap.add_argument("--copy-dest", type=lambda v: int(v, 0), default=None,
                    help="watch writes to the view during the copy pass only")
    ap.add_argument("--dest-len", type=lambda v: int(v, 0), default=0x17ABC00)
    ap.add_argument("--dump-dest", default=None,
                    help="write the destination bytes for XOR against the source")
    ap.add_argument("--reads-of", type=lambda v: int(v, 0), default=None,
                    help="watch reads of a buffer, to link a source to a copy")
    ap.add_argument("--reads-len", type=lambda v: int(v, 0), default=0x42C00)
    ap.add_argument("--dump-alloc", default=None,
                    help="write the allocation as it stands at the stop point")
    ap.add_argument("--until", type=int, default=CREATE_SECTION_BLOCKS + 2_000_000)
    args = ap.parse_args(argv)

    if args.copy_dest is not None:
        return copy_dest(args)
    if args.reads_of is not None:
        return reads_of(args)
    if args.regs_at:
        return regs_at(args)

    emu = Emulator.restore(args.state)
    emu.repair_wow64_crash()
    print(f"restored at {emu.blocks:,} blocks")
    print(f"watching writes to {args.addr:#x}..{args.addr + args.len:#x} "
          f"until {args.until:,} blocks")

    alloc_base, alloc_size = emu.allocs[0]
    recent: collections.deque = collections.deque(maxlen=args.keep)
    total = {"n": 0}

    def on_write(uc, access, address, length, value, _user):
        total["n"] += 1
        recent.append((emu.blocks, uc.reg_read(UC_X86_REG_EIP), address, length, value))

    handle = emu.mu.hook_add(UC_HOOK_MEM_WRITE, on_write,
                             begin=args.addr, end=args.addr + args.len - 1)
    # `resume(count=...)` is an *instruction* budget while `emu.blocks` counts
    # basic blocks, and the two are about four to one here. Passing a block
    # difference as a count stops the trace a hundred million blocks short of
    # the call it was aimed at, which is how the first version of this reported
    # "0 writes" and looked like a finding.
    status = ""
    while emu.blocks < args.until:
        status = emu.resume(count=200_000_000)
        if "returned" not in status:
            break
    emu.mu.hook_del(handle)
    print(f"  {status}  ({emu.blocks:,} blocks)")
    print(f"  {total['n']:,} write(s) to that range; last {len(recent)}:\n")

    # The allocation as it stands at the stop point. Disassembling the code that
    # produced a value needs the bytes from *that* moment: the region keeps
    # changing, and an end-of-run dump does not decode at these addresses at all
    # -- no alignment reaches 0x020196e1 in one. One capture here saves a
    # fifteen-minute re-run per question.
    if args.dump_alloc:
        Path(args.dump_alloc).write_bytes(bytes(emu.mu.mem_read(alloc_base, alloc_size)))
        print(f"  allocation at {alloc_base:#x} written to {args.dump_alloc}\n")

    # Disassemble from memory as it is *now*, for the same reason
    # `trace_poll_pass` does: the allocation decrypts as it runs.
    blob = bytes(emu.mu.mem_read(alloc_base, alloc_size))
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    for blocks, eip, address, length, value in recent:
        where = ""
        if alloc_base <= eip < alloc_base + alloc_size:
            decoded = next(md.disasm(blob[eip - alloc_base:eip - alloc_base + 16], eip), None)
            if decoded:
                where = f"{decoded.mnemonic} {decoded.op_str}"
        flag = "   <== 0x17abc00" if value == 0x17ABC00 else ""
        print(f"  {blocks:>13,}blk  eip {eip:#010x}  [{address:#x}] "
              f"{length}B = {value:#x}{flag}   {where}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
