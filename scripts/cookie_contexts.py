"""How many context objects does stage 3 have, and where do they live?

`0az` left one structural difference between the bench and the guest and called
it the obvious next thread: **the bench's context is on the stack (`0x2fe724`);
the guest's copies of the constant are on the heap (`0xc3f554`, `0xd3d180`, …).**
Nothing so far distinguishes "this harness's layout" from "stage 3 ran a
different path on the guest", and the difference matters because the second
reading means the guest reached the cookie by code the bench never runs -- which
is the only unexplored route to the store the guest took without a matching
module.

This hooks **every** instruction that names `+0x6d8` and records the base
register at each execution, then classifies each distinct base by region. One
stack base and nothing else means the bench has a single context and the guest's
heap copies are a real divergence. A heap base here means both layouts occur
naturally and the difference is not evidence of anything.

    ..\\.venv\\Scripts\\python.exe cookie_contexts.py

**The site list is 23, not the 18 `0ax` recorded.** That census was five reads
short and, more importantly, missed `rva 0x1601b` -- a `cmp [esi+0x6d8], 0`
sitting immediately before the gate, which is what decides whether the cookie
gets initialised at all. Re-derived here by anchoring on the displacement bytes
`d8 06 00 00` and decoding backwards, rather than sweeping linearly: 23 raw
occurrences in the unpacked image, 23 of them decodable, each with exactly one
candidate decoding. A store carrying an imm32 runs four bytes past the end of
its displacement, which is how the first attempt at this dropped the gate store
itself.
"""
from __future__ import annotations

import argparse
import collections
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDI, UC_X86_REG_EIP, UC_X86_REG_ESI

import win32_emu_env as winenv
from dotnet_meta import XOR_SUFFIX, xor_unwrap
from emulate_native_stub import STACK, STACK_SIZE, Emulator

PAYLOAD = r"G:\ringforge-artifacts\422e30ed_stage2\stage3_native_e84f7824.xor9"
ENTRY = 0x2680

ALLOC, ALLOC_SIZE = 0x02001000, 0x46000
POISON = 0x32DFD514

#: Every reference to `+0x6d8` in the unpacked image: `(rva, base register,
#: what it does)`. Ordered by rva. The two stores are the ones `0ay` measured;
#: everything else reads the field.
SITES: tuple[tuple[int, int, str], ...] = (
    (0x03281, UC_X86_REG_EAX, "mov eax, [eax+6d8]"),
    (0x13B92, UC_X86_REG_ESI, "sub ecx, [esi+6d8]"),
    (0x13F04, UC_X86_REG_ESI, "cmp [esi+6d8], 0"),
    (0x146EE, UC_X86_REG_EDI, "cmp [edi+6d8], 0"),
    (0x14725, UC_X86_REG_EDI, "cmp ecx, [edi+6d8]"),
    (0x14730, UC_X86_REG_EDI, "add eax, [edi+6d8]"),
    (0x15509, UC_X86_REG_ESI, "mov edx, [esi+6d8]"),
    (0x15F96, UC_X86_REG_ESI, "mov edx, [esi+6d8]"),
    (0x15FC0, UC_X86_REG_ESI, "xor eax, [esi+6d8]"),
    (0x1601B, UC_X86_REG_ESI, "cmp [esi+6d8], 0      <- gates the initialiser"),
    (0x1605F, UC_X86_REG_ESI, "STORE [esi+6d8] = 32dfd514   <- the gate"),
    (0x18010, UC_X86_REG_ESI, "mov ebx, [esi+6d8]"),
    (0x1805D, UC_X86_REG_ESI, "sub eax, [esi+6d8]"),
    (0x180A9, UC_X86_REG_ESI, "mov ecx, [esi+6d8]"),
    (0x1DC42, UC_X86_REG_EDI, "mov eax, [edi+6d8]"),
    (0x24723, UC_X86_REG_EDI, "mov edx, [edi+6d8]"),
    (0x24737, UC_X86_REG_EDI, "mov edx, [edi+6d8]"),
    (0x26C91, UC_X86_REG_ESI, "STORE [esi+6d8] = eax        <- the computed one"),
    (0x26CAF, UC_X86_REG_ESI, "mov eax, [esi+6d8]"),
    (0x2CE06, UC_X86_REG_ESI, "xor ecx, [esi+6d8]"),
    (0x2D5C0, UC_X86_REG_ESI, "xor eax, [esi+6d8]"),
    (0x2D5EA, UC_X86_REG_ESI, "mov eax, [esi+6d8]"),
    (0x2D611, UC_X86_REG_ESI, "xor eax, [esi+6d8]"),
)

#: Distinct bases to remember before giving up on an exhaustive list. A context
#: count in the thousands would itself be the finding, so the cap is reported
#: rather than silently applied.
MAX_BASES = 256


def region_of(addr: int) -> str:
    """Which part of the synthetic process an address falls in."""
    if ALLOC <= addr < ALLOC + ALLOC_SIZE:
        return "allocation"      # stage 3's own decrypted image
    if STACK <= addr < STACK + STACK_SIZE:
        return "STACK"
    if winenv.HEAP_BASE <= addr < winenv.HEAP_BASE + winenv.HEAP_SIZE:
        return "HEAP"
    if 0x400000 <= addr < 0x500000:
        return "pe image"
    return "elsewhere"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--payload", default=PAYLOAD)
    ap.add_argument("--entry", type=lambda v: int(v, 0), default=ENTRY)
    # **INSTRUCTIONS, not blocks** -- see the method warning in the 17 Aug
    # pick-up entry. The RUN CHECK below refuses to summarise a truncated run.
    ap.add_argument("--instructions", type=int, default=4_000_000_000)
    ap.add_argument("--stop-after", type=int, default=0, metavar="BLOCKS",
                    help="stop at the first +0x6d8 site reached after this many "
                         "blocks; 0 runs to the end. The check lives in the "
                         "hook, so the actual stop is at the next site rather "
                         "than at the number given. A bounded run is honest "
                         "about being bounded -- the summary says so rather "
                         "than reporting a partial census as a complete one.")
    args = ap.parse_args(argv)

    path = Path(args.payload)
    raw = path.read_bytes()
    if path.suffix == XOR_SUFFIX:
        raw = xor_unwrap(raw)

    emu = Emulator(raw)

    #: base -> [first block seen, first site rva, hit count]
    bases: dict[int, list[int]] = {}
    per_site: collections.Counter = collections.Counter()
    overflowed = False
    stopped_early = False

    def make_hook(rva: int, reg: int):
        def hook(uc, addr, size, user):
            nonlocal overflowed, stopped_early
            per_site[rva] += 1
            base = uc.reg_read(reg)
            row = bases.get(base)
            if row is None:
                if len(bases) >= MAX_BASES:
                    overflowed = True
                else:
                    bases[base] = [emu.blocks, rva, 1]
                    print(f"  [{emu.blocks:>13,}blk] new context base "
                          f"{base:#010x}  ({region_of(base)})  first seen at "
                          f"rva {rva:#07x}", flush=True)
            else:
                row[2] += 1
            if args.stop_after and emu.blocks >= args.stop_after:
                stopped_early = True
                uc.emu_stop()
        return hook

    for rva, reg, _what in SITES:
        site = ALLOC + rva
        emu.mu.hook_add(UC_HOOK_CODE, make_hook(rva, reg), begin=site, end=site)

    print(f"stage 3 from {args.entry:#x}, watching all {len(SITES)} references "
          f"to +0x6d8\n", flush=True)

    status = emu.run(args.entry, 0xFFFFFFF, count=args.instructions)
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    inside = ALLOC <= eip < ALLOC + ALLOC_SIZE
    print(f"\nstopped: {status} after {emu.blocks:,} blocks, eip {eip:#010x}"
          + (f"  (rva {eip - ALLOC:#x})" if inside else ""))

    # RUN CHECK, before any conclusion and naming the observation it rests on.
    if inside and not emu.faults and not stopped_early:
        print(f"\n*** VOID: EIP is inside the allocation, nothing faulted, and "
              f"--stop-after was not\n    what ended it -- so the instruction "
              f"budget did. The clean exit is ~633M blocks,\n    in kernel32. "
              f"Everything below would be a statement about the budget.")
        return 2

    print(f"\nSITES THAT EXECUTED: {len(per_site)} of {len(SITES)}")
    for rva, _reg, what in SITES:
        n = per_site.get(rva, 0)
        mark = "   " if n else "  ."
        print(f"{mark} rva {rva:#07x}  {n:>12,}  {what}")

    print(f"\nDISTINCT CONTEXT BASES: {len(bases)}"
          + ("  (CAPPED -- there were more)" if overflowed else ""))
    by_region: collections.Counter = collections.Counter()
    for base, (blk, rva, hits) in sorted(bases.items()):
        region = region_of(base)
        by_region[region] += 1
        print(f"   {base:#010x}  {region:<10}  first at {blk:>13,}blk "
              f"(rva {rva:#07x}), {hits:,} hits")
    print("\n   by region: " + ", ".join(f"{r}={n}" for r, n in by_region.most_common()))

    # The guest side is a *measurement*, not a memory: `0ba` classified the
    # dump's copies against its own THREAD_LIST and MEMORY_INFO_LIST. Six of
    # the seven are on the crashed thread's stack and one is private committed
    # memory. `scripts/guest_cookie_regions.py` reproduces it.
    print("\nAGAINST THE GUEST (`0ba`: 6 of 7 copies on its own thread stack, "
          "1 in private memory):")
    if stopped_early:
        print("   **Bounded run.** --stop-after ended it before the payload did, "
              "so a context")
        print("   created later would not appear. This is a lower bound on the "
              "count, not a census.")
    if by_region.get("STACK") and not by_region.get("HEAP"):
        print(f"   Every context here is on the STACK ({by_region['STACK']} of "
              f"them) and none on the heap,")
        print("   which is the same shape the guest shows. **No divergence.** "
              "0az's structural")
        print("   difference was a misreading of the dump, not a fact about "
              "either run.")
    elif by_region.get("HEAP"):
        print(f"   {by_region['HEAP']} context(s) on the heap here against the "
              f"guest's one private-memory")
        print("   copy. Worth reading only alongside guest_cookie_regions.py -- "
              "the guest's six")
        print("   stack copies are the bulk of it and this does not touch them.")
    else:
        print("   No context base landed in either region, which contradicts "
              "0az's `0x2fe724`.")
        print("   Check the site table before reading anything into this.")

    # The first touch of the field in the whole run, which is an ordering fact
    # the per-site counts cannot give: nothing reads the cookie before it is
    # written. An uninitialised read would show up as a first-seen at a read
    # site rather than at rva 0x26c91.
    if bases:
        first_base, (first_blk, first_rva, _hits) = min(
            bases.items(), key=lambda kv: kv[1][0])
        print(f"\nFIRST TOUCH OF THE FIELD: rva {first_rva:#07x} at "
              f"{first_blk:,} blocks, ctx {first_base:#010x}")
        if first_rva == 0x26C91:
            print("   The computed store, so the cookie is written before it is "
                  "ever read and the")
            print("   'recovery of an uninitialised value' half of 0ax's leading "
                  "model does not")
            print("   happen on this bench.")
        else:
            print("   A READ, not the store -- so the field is read before it is "
                  "initialised, which is")
            print("   the unverified step 0ax's leading model needs. Follow it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
