"""Who calls the sleeps, and who calls the host preparation?

`0ag` measured the twelve sleeps and found them identical -- 1,000.0 ms, not
alertable, all returning to the same dispatch thunk at payload `+0x29d46`. That
thunk is the *inner* wrapper every API goes through, so it names nothing: there
are fourteen call sites for the sleep wrapper in this image and `+0x29d46` is
common to all of them.

    ..\\.venv\\Scripts\\python.exe stage4_backtrace.py

This walks the stack at each host event and reports the payload return addresses
on it. That is what says whether the twelve-second delay is inside the same
routine that prepared the host, above it, or somewhere else entirely -- and
"somewhere else entirely" would mean the delay has nothing to do with the
process it created, which is the reading `0ah` could not rule out.

No block or memory hooks, so this run costs about what the emulation costs.
"""
from __future__ import annotations

import argparse
import struct

from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000
PAY, PLEN = 0x3E93C74, 0x42C00

WATCH = ("CreateProcessInternalW", "NtQueryInformationProcess",
         "NtReadVirtualMemory", "NtDelayExecution", "NtCreateFile",
         "NtReadFile", "NtQueryInformationFile")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--instructions", type=int, default=1_500_000_000)
    ap.add_argument("--depth", type=int, default=96,
                    help="stack dwords to scan for payload return addresses")
    ap.add_argument("--frames", type=int, default=6)
    args = ap.parse_args(argv)

    emu = Emulator.restore(args.state)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    start = emu.blocks

    original_api = emu.api
    seen: dict[str, int] = {}

    def traced_api(name, *a, **kw):
        if name in WATCH:
            n = seen[name] = seen.get(name, 0) + 1
            esp = emu.mu.reg_read(UC_X86_REG_ESP)
            off = kw.get("arg_offset", 4)
            detail = ""
            if name == "NtDelayExecution":
                try:
                    lo, hi = struct.unpack(
                        "<iI", emu.mu.mem_read(
                            struct.unpack("<I", emu.mu.mem_read(esp + off + 4, 4))[0], 8))
                    detail = (f"  alertable={struct.unpack('<I', emu.mu.mem_read(esp + off, 4))[0]}"
                              f" interval={-lo / 1e4:.1f}ms"
                              f" {'relative' if hi == 0xFFFFFFFF else 'ABSOLUTE'}")
                except Exception:
                    detail = "  <interval unreadable>"
            # Return addresses, innermost first. Reading the raw stack rather
            # than following EBP: this image mixes frame-pointer and
            # frame-pointer-omitted routines, and a chain walk stops at the
            # first of the latter.
            frames = []
            try:
                raw = bytes(emu.mu.mem_read(esp, 4 * args.depth))
            except Exception:
                raw = b""
            for i in range(0, len(raw), 4):
                v = struct.unpack_from("<I", raw, i)[0]
                if PAY <= v < PAY + PLEN and (not frames or v != frames[-1]):
                    frames.append(v)
                    if len(frames) >= args.frames:
                        break
            print(f"[{emu.blocks - start:>13,}blk] {name} #{n}{detail}")
            print("      via " + "  <- ".join(f"+{v - PAY:#07x}" for v in frames))
        return original_api(name, *a, **kw)

    emu.api = traced_api
    print(f"running stage 4 from {INJECT_EIP:#x}, "
          f"{args.instructions:,} instruction budget\n", flush=True)
    status = emu.resume(count=args.instructions)
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    print(f"\nRUN CHECK: {emu.blocks - start:,} blocks, eip {eip:#010x} -- {status}")
    if PAY <= eip < PAY + PLEN:
        print("*** VOID: EIP still inside the payload; the budget ran out.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
