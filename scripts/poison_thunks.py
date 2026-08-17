"""What is `0x32dfd514` to the author? A poison address, and here is the proof.

`0ax` found the constant three times in the unpacked image: the gate's store
into `[ctx+0x6d8]`, and two sites it described as
`push 0x32dfd514 ; pushad ; call`, reading them as "a magic pushed before a
`pushad` and a call looks more like an error or abort helper's argument than a
buffer address". **The argument reading is wrong, and the shape is the answer.**

`pushad` and `popad` balance, and neither helper touches the stack above its own
frame -- so at the trailing `ret` the stack top is the pushed immediate. The
stub is not passing an argument. It is:

    call <helper>  ;  jmp 0x32dfd514

into an address nothing maps, on any machine. This script establishes both
halves without inference:

1. **The sweep.** Every `push imm32 ; pushad ; call rel32 ; popad ; ret` in the
   image, grouped by immediate. If `0x32dfd514` is the only immediate used this
   way it is the author's single poison address rather than one dispatch id
   among many.
2. **The mechanics, executed.** One stub assembled from scratch and run under
   Unicorn with the helper replaced by a bare `ret`, so where control goes does
   not depend on what the helper does. Reading this off a disassembly is exactly
   the method that has been retracted repeatedly in this file.

    ..\\.venv\\Scripts\\python.exe poison_thunks.py
"""
from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_MODE_32, Uc, UcError
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESI, UC_X86_REG_ESP

from dotnet_meta import XOR_SUFFIX, xor_unwrap

IMAGE = r"G:\ringforge-artifacts\422e30ed_stage2\stage3_alloc_at540M_dc038cc7.xor9"
ALLOC, ALLOC_SIZE = 0x02001000, 0x46000
POISON = 0x32DFD514

#: `68 imm32 | 60 pushad | e8 rel32 | 61 popad | c3 ret`
_STUB = re.compile(rb"\x68(....)\x60\xe8(....)\x61\xc3", re.S)


def sweep(raw: bytes) -> dict[int, list[tuple[int, int]]]:
    found: dict[int, list[tuple[int, int]]] = {}
    for match in _STUB.finditer(raw):
        offset = match.start()
        immediate = struct.unpack("<I", match.group(1))[0]
        rel = struct.unpack("<i", match.group(2))[0]
        helper = offset + 6 + 5 + rel          # the e8 sits at +6 and is 5 long
        found.setdefault(immediate, []).append((offset, helper))
    return found


def prove_mechanics(immediate: int) -> tuple[int, int, bool]:
    """Assemble one stub, run it, and report where control ended up.

    The helper is a bare `ret` so this measures the stub's stack arithmetic and
    nothing else. Registers are seeded with markers to check `pushad`/`popad`
    really did restore them -- a stub that clobbered them would be doing
    something other than what this claims.
    """
    base, stack, rel = 0x02001000, 0x00300000, 0x100
    stub = (b"\x68" + struct.pack("<I", immediate) + b"\x60"
            + b"\xe8" + struct.pack("<I", rel) + b"\x61\xc3")
    helper = base + 6 + 5 + rel
    caller_return = 0xDEADBEE0

    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(base, 0x1000)
    mu.mem_map(stack, 0x10000)
    mu.mem_write(base, stub)
    mu.mem_write(helper, b"\xc3")
    esp = stack + 0x8000
    mu.mem_write(esp, struct.pack("<I", caller_return))
    mu.reg_write(UC_X86_REG_ESP, esp)
    mu.reg_write(UC_X86_REG_EAX, 0x11111111)
    mu.reg_write(UC_X86_REG_ESI, 0x33333333)

    fault = ""
    try:
        mu.emu_start(base, 0, count=200)
    except UcError as exc:
        fault = str(exc)
    eip = mu.reg_read(UC_X86_REG_EIP)
    preserved = (mu.reg_read(UC_X86_REG_EAX) == 0x11111111
                 and mu.reg_read(UC_X86_REG_ESI) == 0x33333333)
    print(f"   ran the stub, helper stubbed to `ret`")
    print(f"   stopped: {fault or 'no fault'}")
    print(f"   EIP {eip:#010x}   (the caller's return address was "
          f"{caller_return:#010x})")
    print(f"   registers preserved across pushad/popad: {preserved}")
    return eip, caller_return, preserved


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", default=IMAGE,
                    help="the UNPACKED allocation. The packed stage 3 contains "
                         "no occurrence of the constant at all (0ax), so a "
                         "sweep over it finds nothing and means nothing.")
    args = ap.parse_args(argv)

    path = Path(args.image)
    raw = path.read_bytes()
    if path.suffix == XOR_SUFFIX:
        raw = xor_unwrap(raw)
    print(f"{path.name}  {len(raw):,} bytes, base {ALLOC:#x}\n")

    found = sweep(raw)
    total = sum(len(v) for v in found.values())
    print(f"STUBS OF THE SHAPE `push imm32 ; pushad ; call ; popad ; ret`: {total}")
    for immediate in sorted(found):
        sites = found[immediate]
        mapped = ALLOC <= immediate < ALLOC + ALLOC_SIZE
        print(f"\n   immediate {immediate:#010x}   {len(sites)} stub(s)   "
              f"{'inside the allocation' if mapped else 'MAPPED BY NOTHING'}")
        for offset, helper in sites:
            print(f"      stub rva {offset:#07x}  ->  helper rva {helper:#07x}")

    print("\nMECHANICS, EXECUTED:")
    eip, caller_return, preserved = prove_mechanics(POISON)

    print("\nVERDICT:")
    if eip == POISON and preserved:
        print(f"   The trailing `ret` transfers to {POISON:#010x}. Both stubs are")
        print(f"      call <helper>  ;  jmp {POISON:#010x}")
        print("   and neither returns to its caller. The immediate is a jump "
              "target, not an")
        print("   argument -- 0ax's 'an error or abort helper's argument' is "
              "retracted.")
        if len(found) == 1 and POISON in found:
            print(f"\n   It is also the *only* immediate used this way, so "
                  f"{POISON:#010x} is this")
            print("   author's single designated poison address rather than one "
                  "dispatch id among")
            print("   many. The gate at rva 0x1605f stores that same address "
                  "into the context")
            print("   cookie, which is a deliberate act with a name.")
    elif eip == caller_return:
        print("   It returned to its caller, so the stub passes the immediate "
              "as an argument")
        print("   after all and 0ax's reading stands. Everything above is wrong.")
    else:
        print(f"   Neither: {eip:#010x}. The harness is not modelling the stub "
              f"-- fix it before")
        print("   reading anything into the sweep.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
