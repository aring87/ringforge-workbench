"""Once the gate fires, how does the constant get to seven places?

`0ay` settled that only one instruction writes `0x32dfd514` into `[ctx+0x6d8]`
directly. The guest's dump holds **ten** copies -- three in the image (the
literal, and two `push` operands) and seven elsewhere -- so something propagates
it, and a `memcpy` of a context would do that without ever naming `+0x6d8`.

`RINGFORGE_FORGE_MODULE=1` puts a module hashing to `0xe11da208` in the loader
list, which is what makes the gate fire on the bench. This runs stage 3 with it,
stops where the guest stopped, and scans every mapped page for the constant --
the same measurement `0ax` made on the crash dump, so the two are directly
comparable.

    set RINGFORGE_FORGE_MODULE=1
    ..\\.venv\\Scripts\\python.exe cookie_spread.py

**The forged module is a fed answer and the run is worthless without saying so.**
Nothing here is evidence that the guest had such a module -- `0aw` and `0ax`
between them show it had none, loaded or unloaded. This reproduces the *state*
the guest reached in order to watch what happens next, which is a different
claim and a much weaker one.
"""
from __future__ import annotations

import argparse
import os
import struct
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESI

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from dotnet_meta import XOR_SUFFIX, xor_unwrap
from emulate_native_stub import Emulator

PAYLOAD = r"G:\ringforge-artifacts\422e30ed_stage2\stage3_native_e84f7824.xor9"
ENTRY = 0x2680
ALLOC = 0x02001000
GATE_STORE = ALLOC + 0x1605F
POISON = 0x32DFD514

#: What the guest's crash dump held, for comparison. Three in the image at these
#: rvas, seven outside it.
GUEST_IMAGE_RVAS = (0xD809, 0x16065, 0x2DCA9)
GUEST_OUTSIDE = 7


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--payload", default=PAYLOAD)
    ap.add_argument("--entry", type=lambda v: int(v, 0), default=ENTRY)
    # **INSTRUCTIONS, not blocks.** `emu_start`'s `count` is instructions, and
    # the first version of this called the argument `--blocks` and defaulted to
    # 100,000,000 -- which stopped at 11,886,450 blocks, short of the crash at
    # ~17.3M, and reported "GATE EXECUTIONS: 0" as though that meant something.
    # Fourth instance of this shape in two days. The default now clears the
    # crash with room, and the RUN CHECK below refuses to report on a run that
    # ended inside the payload.
    ap.add_argument("--instructions", type=int, default=1_000_000_000)
    args = ap.parse_args(argv)

    if os.environ.get("RINGFORGE_FORGE_MODULE") != "1":
        print("*** VOID: RINGFORGE_FORGE_MODULE is not 1, so the gate will not "
              "fire and this\n    measures nothing. Set it -- and read the "
              "docstring about what that does and does\n    not entitle you to "
              "conclude.")
        return 2

    path = Path(args.payload)
    raw = path.read_bytes()
    if path.suffix == XOR_SUFFIX:
        raw = xor_unwrap(raw)

    emu = Emulator(raw)
    fired: list[tuple[int, int]] = []

    def on_gate(uc, addr, size, user):
        esi = uc.reg_read(UC_X86_REG_ESI)
        fired.append((emu.blocks, esi + 0x6D8))
        print(f"  [{emu.blocks:>13,}blk] GATE fired -> [{esi + 0x6D8:#010x}] = "
              f"{POISON:#010x}", flush=True)

    emu.mu.hook_add(UC_HOOK_CODE, on_gate, begin=GATE_STORE, end=GATE_STORE)

    print("stage 3 with the forged module -- the gate should fire and the run "
          "should die\n", flush=True)
    status = emu.run(args.entry, 0xFFFFFFF, count=args.instructions)
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    inside = ALLOC <= eip < ALLOC + 0x46000
    print(f"\nstopped: {status}")
    print(f"  after {emu.blocks:,} blocks, eip {eip:#010x}"
          + (f"  (rva {eip - ALLOC:#x} in the allocation)" if inside else ""))
    if emu.faults:
        access, addr, at = emu.faults[0]
        print(f"  first fault: access {access} at {addr:#010x} from eip {at:#010x}")

    if inside and not emu.faults:
        print(f"\n*** VOID: EIP is still inside the allocation and nothing "
              f"faulted, so the run was\n    cut short by the instruction "
              f"budget rather than finishing. The expected end is a\n    fault "
              f"around 17.3M blocks. Raise --instructions; everything below "
              f"would be a\n    statement about the budget.")
        return 2

    print(f"\nGATE EXECUTIONS: {len(fired)}")
    if not fired:
        print("   The gate never fired even with the module served, and the run "
              "did reach its end.")
        print("   That is a real negative, and it contradicts what this file "
              "records -- check it")
        print("   before building on it.")

    needle = struct.pack("<I", POISON)
    inside, outside = [], []
    for begin, end, _perms in emu.mu.mem_regions():
        size = end - begin + 1
        try:
            blob = bytes(emu.mu.mem_read(begin, size))
        except Exception:
            continue
        start = 0
        while True:
            i = blob.find(needle, start)
            if i < 0:
                break
            va = begin + i
            (inside if ALLOC <= va < ALLOC + 0x46000 else outside).append(va)
            start = i + 1

    print(f"\nCOPIES OF {POISON:#010x} IN MEMORY AT THE STOP:")
    print(f"   inside the allocation : {len(inside)}   "
          f"(guest had 3, at rvas {', '.join(hex(r) for r in GUEST_IMAGE_RVAS)})")
    for va in inside:
        print(f"      {va:#010x}  rva {va - ALLOC:#07x}")
    print(f"   elsewhere             : {len(outside)}   "
          f"(guest had {GUEST_OUTSIDE})")
    for va in outside[:20]:
        print(f"      {va:#010x}")
    if len(outside) > 20:
        print(f"      ... {len(outside) - 20} more")

    print("\nAGAINST THE GUEST:")
    if len(inside) == 3 and len(outside) == GUEST_OUTSIDE:
        print("   Same shape, 3 inside and 7 outside. The bench reproduces the "
              "guest's memory, so")
        print("   whatever spreads it is in this run and can be hooked.")
    else:
        print(f"   Different shape: {len(inside)} inside and {len(outside)} "
              f"outside against the guest's 3 and {GUEST_OUTSIDE}.")
        print("   **Do not read the difference as a finding yet.** The dump is a "
              "snapshot at the")
        print("   fault and this is a snapshot at the stop; they are only "
              "comparable if the run")
        print("   died in the same place, which the eip above says.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
