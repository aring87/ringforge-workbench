"""Which six names does stage 4 accept, out of 990,570?

The matcher at 0x3ec0714 is entered 990,570 times and leaves through
`xor eax,eax / ret` 990,564 of them. Six succeed, and exactly one became an API
call. Those six are the only things stage 4 is known to have found before
deciding it had nothing to do, so they are the smallest remaining lead.

    ..\\.venv\\Scripts\\python.exe stage4_matches.py

Two hooks, both single-address, because a range hook over the payload is a
Python callback per instruction and costs hours. The entry hook stores the
argument pointers only -- decoding a string a million times would dominate the
run -- and the caller's result check decodes just the ones that matched.
"""
from __future__ import annotations

import argparse

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000

#: `push ebp / mov ebp,esp / ...` -- args are still at [esp+4..] here.
MATCHER = 0x03EC0714
#: The caller's `add esp,0xc / test eax,eax / je`, immediately after the call.
RESULT = 0x03EC0005


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--blocks", type=int, default=60_000_000)
    args = ap.parse_args(argv)

    emu = Emulator.restore(args.state)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    start = emu.blocks

    pending = [0, 0]
    calls = [0]
    hits: list[tuple[int, str, int]] = []

    def on_matcher(uc, addr, size, user):
        calls[0] += 1
        esp = uc.reg_read(UC_X86_REG_ESP)
        try:
            pending[0] = int.from_bytes(uc.mem_read(esp + 4, 4), "little")
            pending[1] = int.from_bytes(uc.mem_read(esp + 8, 4), "little")
        except Exception:
            pending[0] = pending[1] = 0

    def on_result(uc, addr, size, user):
        eax = uc.reg_read(UC_X86_REG_EAX)
        if not eax:
            return
        begin, end = pending
        # Read from the pointer regardless of what the second argument is. The
        # first attempt gated on `end > begin` and a 512-byte span and reported
        # every match as unreadable, which says the pair is not the (begin, end)
        # it was assumed to be -- so record the raw values and let the bytes
        # speak instead of filtering on a guess about their meaning.
        raw = b""
        try:
            raw = bytes(uc.mem_read(begin, 64)) if begin else b""
        except Exception:
            raw = b""
        hits.append((emu.blocks - start, begin, end, raw, eax))

    emu.mu.hook_add(UC_HOOK_CODE, on_matcher, begin=MATCHER, end=MATCHER)
    emu.mu.hook_add(UC_HOOK_CODE, on_result, begin=RESULT, end=RESULT)

    print("running...")
    status = emu.resume(count=args.blocks)
    print(f"  {status} after {emu.blocks - start:,} blocks")
    print(f"  matcher entered {calls[0]:,} time(s), {len(hits)} accepted\n")

    if not hits:
        print("NOTHING MATCHED. The six accepted at the same call count earlier")
        print("came through a different exit -- re-check which block returns")
        print("non-zero before reading anything into this.")
        return 1

    print("accepted:")
    for blocks, begin, end, raw, eax in hits:
        nul = raw.find(b"\0")
        ascii_text = raw[:nul if nul >= 0 else len(raw)]
        wide = raw[:raw.find(b"\0\0")] if b"\0\0" in raw else raw
        print(f"\n   [{blocks:>12,}blk]  eax={eax:#010x}  "
              f"arg1={begin:#010x} arg2={end:#010x} (delta {end - begin:#x})")
        print(f"      bytes  {raw[:32].hex(' ')}")
        if ascii_text and all(32 <= b < 127 for b in ascii_text):
            print(f"      ascii  {ascii_text.decode('latin-1')!r}")
        try:
            text = wide.decode("utf-16-le")
            if text and all(32 <= ord(c) < 127 for c in text):
                print(f"      wide   {text!r}")
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
