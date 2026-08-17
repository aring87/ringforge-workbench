"""Can the *computed* store ever write the crash constant into the cookie?

`0ax` read the crash dump and found `[ctx+0x6d8]` is a **cookie**, not a buffer
base: 18 references in stage 3's decrypted image, 16 of them reads feeding an
XOR recovery, and exactly two stores --

    rva 0x1605f   mov dword [esi+0x6d8], 0x32dfd514    the gate, hardcoded
    rva 0x26c91   mov dword [esi+0x6d8], eax           value from a call

The hardcoded one is the anomaly; the computed one looks like the normal
initialiser. That leaves one question, and it is the last one standing on the
crash: **`rva 0x26c91` writes whatever is in EAX, and the image contains two
`push 0x32dfd514` sites -- can it ever write the constant?**

    ..\\.venv\\Scripts\\python.exe cookie_stores.py

Hooks both instructions in a fresh stage-3 run and records every execution with
the value written and the context it was written into. No inference: the answer
is a list of what each store actually did.

A fresh run is required rather than a stored state. The gate fires around 17.3M
blocks and every checkpoint on the artifact drive is later than that -- and the
sites do not exist in the carved image at all, because stage 3 decrypts itself
into `0x02001000` as it runs (`0ax`: the carved copy has zero occurrences of the
constant, the late allocation dump has three).
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESI)

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from dotnet_meta import XOR_SUFFIX, xor_unwrap
from emulate_native_stub import Emulator

PAYLOAD = r"G:\ringforge-artifacts\422e30ed_stage2\stage3_native_e84f7824.xor9"
ENTRY = 0x2680

#: Where stage 3 decrypts itself to, and the two stores within it.
ALLOC = 0x02001000
GATE_STORE = ALLOC + 0x1605F        # mov [esi+0x6d8], 0x32dfd514
COMPUTED_STORE = ALLOC + 0x26C91    # mov [esi+0x6d8], eax
POISON = 0x32DFD514


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--payload", default=PAYLOAD)
    ap.add_argument("--entry", type=lambda v: int(v, 0), default=ENTRY)
    ap.add_argument("--blocks", type=int, default=4_000_000_000)
    args = ap.parse_args(argv)

    path = Path(args.payload)
    raw = path.read_bytes()
    if path.suffix == XOR_SUFFIX:
        raw = xor_unwrap(raw)

    emu = Emulator(raw)
    hits: list[tuple[str, int, int, int]] = []

    def on_store(uc, addr, size, user):
        which = "GATE (hardcoded)" if addr == GATE_STORE else "computed"
        esi = uc.reg_read(UC_X86_REG_ESI)
        value = POISON if addr == GATE_STORE else uc.reg_read(UC_X86_REG_EAX)
        hits.append((which, emu.blocks, esi + 0x6D8, value))
        print(f"  [{emu.blocks:>13,}blk] {which:18} -> [{esi + 0x6D8:#010x}] = "
              f"{value:#010x}"
              + ("   *** THE CONSTANT" if value == POISON else ""), flush=True)

    for site in (GATE_STORE, COMPUTED_STORE):
        emu.mu.hook_add(UC_HOOK_CODE, on_store, begin=site, end=site)

    print(f"stage 3 from {args.entry:#x}, watching")
    print(f"  {GATE_STORE:#010x}  rva 0x1605f  mov [esi+0x6d8], {POISON:#010x}")
    print(f"  {COMPUTED_STORE:#010x}  rva 0x26c91  mov [esi+0x6d8], eax\n", flush=True)

    status = emu.run(args.entry, 0xFFFFFFF, count=args.blocks)
    print(f"\nstopped: {status} after {emu.blocks:,} blocks, "
          f"eip {emu.mu.reg_read(UC_X86_REG_EIP):#010x}")

    gate = [h for h in hits if h[0].startswith("GATE")]
    computed = [h for h in hits if h[0] == "computed"]
    print(f"\nSTORE EXECUTIONS: {len(gate)} gate, {len(computed)} computed")

    print("\nDID THE COMPUTED STORE EVER WRITE THE CONSTANT?")
    poisoned = [h for h in computed if h[3] == POISON]
    if poisoned:
        for _w, blocks, where, value in poisoned:
            print(f"   *** YES, at {blocks:,} blocks -> [{where:#x}] = {value:#010x}")
        print("   So the constant reaches the cookie by a route the module "
              "lookup does not gate,")
        print("   and the Sandboxie reading of the crash is wrong.")
    elif computed:
        values = sorted({h[3] for h in computed})
        print(f"   No. {len(computed)} execution(s), "
              f"{len(values)} distinct value(s) written:")
        for v in values[:12]:
            print(f"      {v:#010x}")
        print("   The computed store initialises the cookie with something else, "
              "so the gate remains")
        print("   the only route to the constant -- and the guest taking it "
              "without a matching module")
        print("   stays unexplained.")
    else:
        print("   The computed store never executed in this run, so this says "
              "nothing about it.")
        print("   **Not evidence either way.** It needs a run that reaches "
              "rva 0x26c91.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
