"""Every write into the buffer that becomes `lpApplicationName`.

`0aq` has two readings left for the doubled drive, and this tests the cheaper:
that something between the path builder and `CreateProcessInternalW` strips the
leading volume, so the name actually passed is well formed and `0ac` was wrong
about the buffer being handed over as built.

    ..\\.venv\\Scripts\\python.exe trace_appname.py

The buffer is `desc + 0x30`, where `desc` is `+0x192b0`'s fourth argument, loaded
into EBX at `+0x1937f`. That address is only known at runtime, so the write hook
is armed there -- and the translation cache flushed with it, because a hook
attached mid-run does not reach blocks unicorn has already translated (the trap
that made the first version of `stage4_intent.py` report a silent payload).

If a write ever moves the string down by two characters, reading 3 is right. If
the bytes go in once and are never touched again, it is wrong and reading 1 --
the branch is simply broken in this sample -- is what is left.
"""
from __future__ import annotations

import argparse
import struct

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_EIP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000
PAY, PLEN = 0x3E93C74, 0x42C00

#: Just after `mov ebx, [ebp+0x14]` in `+0x192b0`, so EBX holds the descriptor.
DESC_READY = 0x3EACFF6
#: The application-name field within it, and how much of it to watch.
NAME_OFF, NAME_SPAN = 0x30, 0x220


def wide(mu, ptr, limit=0x220):
    try:
        raw = bytes(mu.mem_read(ptr, limit))
    except Exception:
        return "<unreadable>"
    end = raw.find(b"\x00\x00")
    if end < 0:
        end = len(raw)
    if end % 2:
        end += 1
    return raw[:end].decode("utf-16-le", "replace")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--instructions", type=int, default=1_500_000_000)
    ap.add_argument("--show", type=int, default=40, help="writes to print")
    args = ap.parse_args(argv)

    emu = Emulator.restore(args.state)
    mu = emu.mu
    mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    from unicorn.x86_const import UC_X86_REG_ESP
    mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    start = emu.blocks

    writes: list[tuple[int, int, int, int, int]] = []
    state: dict[str, int] = {}

    def on_write(uc, access, address, size, value, user):
        writes.append((emu.blocks, uc.reg_read(UC_X86_REG_EIP),
                       address - state["buf"], size, value))

    def on_desc(uc, addr, size, user):
        if "buf" in state:
            return
        ebx = uc.reg_read(UC_X86_REG_EBX)
        ebp = uc.reg_read(UC_X86_REG_EBP)
        state["desc"] = ebx
        state["buf"] = ebx + NAME_OFF
        try:
            state["out_arg"] = struct.unpack("<I", uc.mem_read(ebp + 0xC, 4))[0]
        except Exception:
            state["out_arg"] = 0
        print(f"[{emu.blocks - start:,}blk] descriptor {ebx:#x}, "
              f"application-name buffer {state['buf']:#x}")
        print(f"          +0x192b0's second argument = {state['out_arg']:#x}"
              + ("  (the same buffer)" if state["out_arg"] == state["buf"]
                 else "  (a different buffer)"))
        uc.hook_add(UC_HOOK_MEM_WRITE, on_write,
                    begin=state["buf"], end=state["buf"] + NAME_SPAN - 1)
        uc.ctl_flush_tb()
        print(f"          watching +0x0..+{NAME_SPAN:#x}", flush=True)

    mu.hook_add(UC_HOOK_CODE, on_desc, begin=DESC_READY, end=DESC_READY)

    original_api = emu.api

    def traced_api(name, *a, **kw):
        if name == "CreateProcessInternalW" and "buf" in state:
            print(f"\n[{emu.blocks - start:,}blk] CreateProcessInternalW reached")
            print(f"    buffer now = {wide(mu, state['buf'])!r}")
            result = original_api(name, *a, **kw)
            mu.emu_stop()
            return result
        return original_api(name, *a, **kw)

    emu.api = traced_api
    print(f"running stage 4 from {INJECT_EIP:#x}", flush=True)
    emu.resume(count=args.instructions)

    if "buf" not in state:
        print("*** VOID: never reached +0x1937f, so nothing was watched.")
        return 2

    print(f"\nWRITES INTO THE APPLICATION-NAME BUFFER ({len(writes)}):")
    shown = 0
    for blocks, ip, off, size, value in writes:
        if shown >= args.show:
            print(f"   ... {len(writes) - shown} more")
            break
        where = f"+{ip - PAY:#07x}" if PAY <= ip < PAY + PLEN else f"{ip:#x}"
        char = ""
        if size <= 2 and 0x20 <= (value & 0xFF) < 0x7F:
            char = f"  {chr(value & 0xFF)!r}"
        print(f"   [{blocks - start:>12,}blk] {where} wrote {size}B "
              f"{value:#0{2 + size * 2}x} at +{off:#05x}{char}")
        shown += 1

    print("\nDID ANYTHING SHIFT THE STRING DOWN BY TWO CHARACTERS?")
    starts = [w for w in writes if w[2] == 0]
    print(f"   writes landing at +0x0 (the first character): {len(starts)}")
    for blocks, ip, off, size, value in starts:
        where = f"+{ip - PAY:#07x}" if PAY <= ip < PAY + PLEN else f"{ip:#x}"
        print(f"      [{blocks - start:>12,}blk] {where} wrote "
              f"{value:#0{2 + size * 2}x}")
    if len(starts) <= 1:
        print("   The first character is written once and never rewritten, so "
              "nothing strips the")
        print("   volume afterwards. Reading 3 is out and reading 1 is what "
              "remains.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
