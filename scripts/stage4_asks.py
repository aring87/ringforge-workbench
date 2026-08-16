"""What does stage 4 actually ask the environment for?

Before building bait, find out what is requested. The FLOSS strings name browser
paths, but they came from decoders emulated in isolation -- they are evidence of
capability, not evidence that this execution path ever asks for those paths. The
survey says 23 of 67 pages run, so most of the stealer never executes, and bait
built from the strings rather than from the requests would be answering a
question nothing asked.

This logs every API stage 4 calls, and every name it passes, with block numbers
-- counting only from the injected thread's entry, so the loader's own calls are
excluded rather than mixed in.

    ..\\.venv\\Scripts\\python.exe stage4_asks.py

If the answer is "it opens no file and reads no key", bait cannot help and the
branch that skips the harvesting is decided earlier, on something else.
"""
from __future__ import annotations

import argparse
import collections
from pathlib import Path

from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--eip", type=lambda v: int(v, 0), default=INJECT_EIP)
    ap.add_argument("--esp", type=lambda v: int(v, 0), default=INJECT_ESP)
    # `emu_start`'s count is INSTRUCTIONS, not blocks. 60M stops this payload
    # mid-scan at 16,096,220 blocks, and that truncation was mistaken all day
    # for a completed run. 400M reaches the real end at 42,072,701 blocks.
    ap.add_argument("--instructions", type=int, default=400_000_000,
                    dest="blocks")
    args = ap.parse_args(argv)

    emu = Emulator.restore(args.state)
    emu.mu.reg_write(UC_X86_REG_EIP, args.eip)
    emu.mu.reg_write(UC_X86_REG_ESP, args.esp)

    # Snapshot the counters so everything reported below belongs to stage 4
    # rather than to the loader that ran before this state was saved.
    before_calls = collections.Counter(emu.calls)
    before_unhandled = collections.Counter(emu.unhandled)
    start_blocks = emu.blocks

    # Wrap the API dispatcher to record the name and its first argument as a
    # path, when the argument looks like one. `api()` is the single funnel every
    # stub goes through, so this catches whatever the payload calls.
    asked: list[tuple[int, str, str]] = []
    original_api = emu.api

    def traced_api(name, *a, **kw):
        detail = ""
        try:
            esp = emu.mu.reg_read(UC_X86_REG_ESP)
            for slot in range(1, 5):
                ptr = int.from_bytes(emu.mu.mem_read(esp + 4 * slot, 4), "little")
                if not ptr:
                    continue
                text = emu.describe(ptr)
                if text and any(ch in str(text) for ch in "\\/") and len(str(text)) > 3:
                    detail = str(text)
                    break
        except Exception:
            pass
        if detail or name not in ("NtDelayExecution",):
            asked.append((emu.blocks, name, detail))
        return original_api(name, *a, **kw)

    emu.api = traced_api
    print(f"running stage 4 from {args.eip:#x}, {args.blocks:,} instruction budget")
    status = emu.resume(count=args.blocks)
    ran = emu.blocks - start_blocks
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    print(f"  {status} after {ran:,} blocks, ending at eip {eip:#010x}")
    if 0x3E93C74 <= eip < 0x3E93C74 + 0x42C00:
        print("  *** VOID: EIP is still inside the payload, so the budget ran "
              "out mid-execution and 'asks for nothing' would be unearned.")
        return 2
    print()

    calls = collections.Counter(emu.calls) - before_calls
    unhandled = collections.Counter(emu.unhandled) - before_unhandled

    print("APIs called BY STAGE 4 (loader's excluded):")
    if not calls:
        print("   none -- stage 4 calls no API at all on this path")
    for name, n in calls.most_common():
        print(f"   {n:>6}  {name}")

    print("\nUNHANDLED by the harness:")
    print("   none" if not unhandled else "")
    for name, n in unhandled.most_common():
        print(f"   {n:>6}  {name}  <-- a stub returning nothing can be the "
              f"reason a branch is skipped")

    named = [(b, n, d) for b, n, d in asked if d]
    print(f"\nNAMES REQUESTED ({len(named)} with a path-like argument):")
    seen = set()
    for blocks, name, detail in named:
        key = (name, detail)
        if key in seen:
            continue
        seen.add(key)
        print(f"   [{blocks - start_blocks:>12,}blk] {name:28} {detail}")
    if not named:
        print("   NONE. Stage 4 asks for no file, key or object by name.")
        print("   Bait cannot answer a question that is never asked -- find the")
        print("   branch that skips the harvesting before building a fixture.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
