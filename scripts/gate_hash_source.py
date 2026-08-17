"""Is the gate's hash a constant, or is it a function of where the run landed?

**`0xe11da208` is not in stage 3's code.** The gate block pushes a literal
`0x246e8fe6` with a length byte, calls the XOR decoder at `+0x4181`, and hands
whatever comes back to `get_module_base_by_hash`:

    0x16038  push 0xd3 ; push 0x246e8fe6
    0x16046  call 0x4181        <- the decoder
    0x1604b  push eax           <- the hash, whatever it is
    0x1604c  call 0x2dc01       <- the lookup
    0x16054  test eax, eax      <- the gate

`0xe11da208` is what that decoder **returned on this bench**, once, at
17,165,663 blocks. Every link of the crash chain treats it as a constant, and
nothing has established that it is one.

`0ar` proved this sample does the opposite elsewhere: `which_module.py` read a
decoder call whose literal `0x2c6e6e44` decoded to `0x77000000` -- `NTDLL_BASE`,
a **runtime value**. Its own recorded lesson was *"constants are decoded before
use, so a constant lifted out of a disassembly is rarely the value."*

The bench allocation sits at `0x02001000` and the guest's at `0x01010000`; the
cookie is a runtime self-address and differs between them. **If any of that
feeds the decoder, the guest's gate hash was never `0xe11da208`** -- and if what
it produced instead matched one of the four modules the guest actually had
loaded, the lookup succeeded honestly and there is no contradiction left to
explain.

    ..\\.venv\\Scripts\\python.exe gate_hash_source.py

Runs the payload once per heap base, reads EAX at `0x1604b`, and compares. A
fixed output across relocations means the decoder is a pure function of its
literal and the hash really is `0xe11da208` on any machine. A moving output
means the gate's hash is run-dependent and the chain's third link is wrong.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP

import win32_emu_env as winenv
from dotnet_meta import XOR_SUFFIX, xor_unwrap
from emulate_native_stub import Emulator

PAYLOAD = r"G:\ringforge-artifacts\422e30ed_stage2\stage3_native_e84f7824.xor9"
ENTRY = 0x2680

#: `push eax` -- the instruction after the decoder call, where EAX is its result.
DECODED_AT = 0x1604B
BENCH_ANSWER = 0xE11DA208

#: Heap bases to run at. The payload's allocation is carved from `HEAP_BASE +
#: 0x1000`, so moving this moves the image, every self-address in it, and the
#: cookie. Kept clear of STACK (0x200000), the PE image (0x400000),
#: REMOTE_STACK (0x10000000), the served modules (0x20000000-0x218a0000) and
#: kernel32/ntdll (0x76000000/0x77000000).
DEFAULT_BASES = (0x02000000, 0x28000000, 0x40000000)

#: What the guest actually had in `PEB->Ldr` at the crash (`guest_ldr_walk.py`).
#: If a relocated run produces one of these, the lookup succeeded honestly
#: there and the whole contradiction dissolves.
GUEST_MODULES = {
    0xE2E77DAF: "RegSvcs.exe",
    0x0B4E1AE2: "ntdll.dll",
    0xADEDAB08: "KERNEL32.DLL",
    0x21094B62: "KERNELBASE.dll",
}


def decoded_hash(raw: bytes, heap_base: int, instructions: int) -> tuple:
    """The decoder's output at the gate site, for one heap base.

    Returns `(hash, blocks, note)`; `hash` is None when the site never ran,
    which must not be reported as an answer -- a relocation that breaks the run
    before 17.3M blocks would otherwise look like "the hash changed to nothing".
    """
    winenv.HEAP_BASE = heap_base
    alloc = heap_base + 0x1000
    emu = Emulator(raw)
    captured: list[tuple[int, int]] = []

    def on_decoded(uc, addr, size, user):
        captured.append((emu.blocks, uc.reg_read(UC_X86_REG_EAX)))
        uc.emu_stop()

    emu.mu.hook_add(UC_HOOK_CODE, on_decoded,
                    begin=alloc + DECODED_AT, end=alloc + DECODED_AT)
    status = emu.run(ENTRY, 0xFFFFFFF, count=instructions)
    if captured:
        blocks, value = captured[0]
        return value, blocks, ""
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    inside = alloc <= eip < alloc + 0x46000
    return None, emu.blocks, (
        f"site never reached -- {status}, eip {eip:#x}"
        + (f" (rva {eip - alloc:#x})" if inside else "")
        + ("; the budget ran out, raise --instructions" if inside else
           "; the run ended elsewhere, so this relocation broke it"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--payload", default=PAYLOAD)
    ap.add_argument("--instructions", type=int, default=1_000_000_000,
                    help="INSTRUCTIONS, not blocks. The site is reached at "
                         "about 17.2M blocks.")
    ap.add_argument("--bases", type=lambda v: [int(x, 0) for x in v.split(",")],
                    default=list(DEFAULT_BASES))
    args = ap.parse_args(argv)

    path = Path(args.payload)
    raw = path.read_bytes()
    if path.suffix == XOR_SUFFIX:
        raw = xor_unwrap(raw)

    original = winenv.HEAP_BASE
    results: list[tuple[int, int | None, int, str]] = []
    try:
        for base in args.bases:
            print(f"--- heap base {base:#010x}, allocation at "
                  f"{base + 0x1000:#010x}", flush=True)
            value, blocks, note = decoded_hash(raw, base, args.instructions)
            results.append((base, value, blocks, note))
            if value is None:
                print(f"    {note}", flush=True)
            else:
                print(f"    decoder returned {value:#010x} at {blocks:,} blocks",
                      flush=True)
    finally:
        winenv.HEAP_BASE = original

    answered = [(base, value) for base, value, _b, _n in results
                if value is not None]
    print(f"\nRUNS THAT REACHED THE SITE: {len(answered)} of {len(results)}")
    if len(answered) < 2:
        print("   **Not an answer.** At least two relocations have to reach the "
              "decoder before")
        print("   anything can be said about whether its output moves.")
        return 2

    values = {value for _base, value in answered}
    print(f"DISTINCT OUTPUTS: {len(values)}")
    for base, value in answered:
        mark = "  == the bench answer" if value == BENCH_ANSWER else ""
        named = GUEST_MODULES.get(value)
        if named:
            mark = f"  *** matches the guest's {named}"
        print(f"   allocation {base + 0x1000:#010x} -> {value:#010x}{mark}")

    print("\nVERDICT:")
    if len(values) == 1:
        print(f"   **Fixed at {values.pop():#010x} across "
              f"{len(answered)} relocations.** The decoder is a pure function "
              f"of its")
        print("   literal, so the gate's hash is the same on any machine and "
              "the chain's third")
        print("   link holds on the guest. The temporal hypothesis is what is "
              "left.")
    else:
        print("   **The gate's hash is RUN-DEPENDENT.** It moves with the load "
              "address, so")
        print(f"   {BENCH_ANSWER:#010x} is this bench's answer and not the "
              f"guest's. The chain's third")
        print("   link -- 'gated on a module hashing to 0xe11da208' -- is a "
              "statement about this")
        print("   emulator. Work out what the guest's load base makes it and "
              "check that against")
        print("   the four modules it had.")
        if any(value in GUEST_MODULES for _b, value in answered):
            print("\n   And one relocation already lands on a module the guest "
                  "had loaded, which is")
            print("   the mechanism outright.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
