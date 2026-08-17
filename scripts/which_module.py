"""Which module does the path builder's lookup actually resolve?

`0aq` leaves three readings of the doubled drive, and the second is "the hash
`0x2c6e6e44` resolves to a different module on a real machine, one whose
`FullDllName` has no volume". This settles it.

    ..\\.venv\\Scripts\\python.exe which_module.py

**`0x2c6e6e44` is not the hash.** `+0x192d5` pushes it and calls `+0x14350`
first, so the constant is decoded and the *result* is what the module lookup at
`+0x2c130` is given. Cracking the literal against filenames would be cracking the
wrong number -- so this reads the decoded value out of EAX at the call boundary
instead, and then reads back which loader entry came out.

The comparison list is built with the algorithm this project already recovered
and validated against names the emulator was *observed* hashing: CRC-32/MPEG-2,
init 0xFFFFFFFF, non-reflected, poly 0x04C11DB7, final NOT. It reproduces
`ntdll.dll` as `0x0b4e1ae2`, which is the check that the list means anything.

Stops at the lookup, ~17.4M blocks in, so this is a couple of minutes.
"""
from __future__ import annotations

import argparse
import struct

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000

#: After `call +0x14350` (the constant decoder) and after `call +0x2c130`
#: (the module lookup), in `+0x192b0`.
AFTER_DECODE, AFTER_LOOKUP = 0x3EACF53, 0x3EACF5B


def crc(name: bytes) -> int:
    """CRC-32/MPEG-2: init 0xFFFFFFFF, non-reflected, poly 0x04C11DB7, final NOT."""
    value = 0xFFFFFFFF
    for byte in name:
        value ^= byte << 24
        for _ in range(8):
            value = ((value << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if value & 0x80000000 \
                else (value << 1) & 0xFFFFFFFF
    return (~value) & 0xFFFFFFFF


def candidates() -> dict[int, str]:
    """Every module this harness serves, in the encodings the payload might use."""
    names = [winenv.IMAGE_NAME, "ntdll.dll", "KERNEL32.DLL", *winenv.EXTRA_MODULES]
    table: dict[int, str] = {}
    for name in names:
        for text, how in ((name, "as-is"), (name.lower(), "lower"),
                          (name.upper(), "upper")):
            for blob, enc in ((text.encode(), "ascii"),
                              (text.encode("utf-16-le"), "utf-16le")):
                table.setdefault(crc(blob), f"{name} ({how}, {enc})")
    return table


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--instructions", type=int, default=1_500_000_000)
    args = ap.parse_args(argv)

    # Self-check before anything else: an algorithm that does not reproduce the
    # value this project already measured would make every line below noise.
    assert crc(b"ntdll.dll") == 0x0B4E1AE2, \
        f"crc is wrong: ntdll.dll came out {crc(b'ntdll.dll'):#010x}, not 0x0b4e1ae2"
    print(f"crc self-check: ntdll.dll -> {crc(b'ntdll.dll'):#010x}  (as recorded)")

    emu = Emulator.restore(args.state)
    mu = emu.mu
    mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    table = candidates()
    seen = {}

    def name_of(entry: int) -> str:
        try:
            length, _, buf = struct.unpack("<HHI", mu.mem_read(entry + 0x2C, 8))
            return bytes(mu.mem_read(buf, length)).decode("utf-16-le")
        except Exception:
            return "<unreadable>"

    def full_of(entry: int) -> str:
        try:
            length, _, buf = struct.unpack("<HHI", mu.mem_read(entry + 0x24, 8))
            return bytes(mu.mem_read(buf, length)).decode("utf-16-le")
        except Exception:
            return "<unreadable>"

    def on_decode(uc, addr, size, user):
        seen["hash"] = uc.reg_read(UC_X86_REG_EAX)

    def on_lookup(uc, addr, size, user):
        entry = uc.reg_read(UC_X86_REG_EAX)
        value = seen.get("hash")
        print(f"\nliteral pushed  0x2c6e6e44")
        print(f"decoded to      {value:#010x}" if value is not None else
              "decoded value not captured")
        print(f"matches         {table.get(value, '*** nothing this harness serves')}")
        print(f"\nlookup returned entry {entry:#x}")
        if entry:
            print(f"   BaseDllName {name_of(entry)!r}")
            print(f"   FullDllName {full_of(entry)!r}")
        else:
            print("   NULL -- the lookup found nothing")
        mu.emu_stop()

    mu.hook_add(UC_HOOK_CODE, on_decode, begin=AFTER_DECODE, end=AFTER_DECODE)
    mu.hook_add(UC_HOOK_CODE, on_lookup, begin=AFTER_LOOKUP, end=AFTER_LOOKUP)

    print("running to the module lookup...", flush=True)
    emu.resume(count=args.instructions)
    if "hash" not in seen:
        print("*** VOID: never reached the lookup; raise --instructions")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
