"""Run the injected code, and watch it decrypt itself.

Stage 3 does not write plaintext anywhere. The payload is stored encrypted at
`0x27e7000`, re-encrypted byte by byte on the way into the section view, and the
XOR difference between the two is itself entropy 7.999 with no period -- so
there is nothing to solve for offline. Whatever decrypts it runs on the far
side, in the thread `NtSetContextThread` points at, and that thread is the one
thing the harness answered with a stub.

So run it here instead. Everything needed is already in hand:

    state    after_inject.state, saved at the first NtResumeThread
    entry    0x3e9f89b -- from the CONTEXT the loader wrote
    stack    0x2fcd6c  -- inside the already-mapped stack region
    payload  0x3e93c74, 273,408 bytes, in the mapped view

**This is the same move that has worked at every earlier obstacle here: let the
sample do the decryption and watch, rather than reverse the transform.**

Two ways it can fail, and both are results rather than accidents. The injected
code believes it is inside `notepad.exe` while the harness serves `RegSvcs.exe`
-- if it reads its image base, command line or image name, it diverges. And if
it is not self-decrypting, resuming lands in a crash rather than plaintext,
which says the key stayed with the loader and the answer is back in stage 3.

    ..\\.venv\\Scripts\\python.exe follow_injection.py --blocks 50000000
    ..\\.venv\\Scripts\\python.exe follow_injection.py --dump-region out.bin

Run it from `scripts/`.
"""
from __future__ import annotations

import argparse
import collections
import math
from pathlib import Path

from unicorn import UC_HOOK_BLOCK, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP)

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator, entropy

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_inject.state"

#: Measured, and defaults only because the state that carries them predates the
#: v3 snapshot format. A v3 state supplies them itself.
INJECT_EIP = 0x3E9F89B
INJECT_ESP = 0x2FCD6C
INJECT_EAX = 0x2FCF0C

#: Where the payload landed in the view, from `--copy-dest`.
PAYLOAD_AT = 0x3E93C74
PAYLOAD_LEN = 0x42C00


def _registers(emu: Emulator, args: argparse.Namespace) -> tuple[int, int, int]:
    """Explicit flags win, then the state's own record, then the measured values."""
    eip, esp, eax = args.eip, args.esp, args.eax
    for entry in reversed(getattr(emu, "thread_contexts", []) or []):
        fields = entry.get("fields") or {}
        if entry.get("call") == "NtSetContextThread" and fields.get("Eip"):
            eip = eip or fields.get("Eip")
            esp = esp or fields.get("Esp")
            eax = eax or fields.get("Eax")
            print(f"  entry from the state's own CONTEXT record "
                  f"({entry['blocks']:,}blk)")
            break
    return eip or INJECT_EIP, esp or INJECT_ESP, eax or INJECT_EAX


def _report(label: str, blob: bytes) -> None:
    nz = sum(1 for b in blob if b)
    print(f"  {label}: entropy {entropy(blob):.3f}, non-zero {100 * nz / len(blob):.2f}%")
    for needle in (b"MZ", b"PE\0\0", b"This program cannot"):
        count = blob.count(needle)
        flag = "   <-- !!" if needle != b"MZ" and count else ""
        print(f"    {needle!r}: {count}{flag}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--eip", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--esp", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--eax", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--at", type=lambda v: int(v, 0), default=PAYLOAD_AT)
    ap.add_argument("--len", type=lambda v: int(v, 0), default=PAYLOAD_LEN)
    ap.add_argument("--blocks", type=int, default=50_000_000)
    ap.add_argument("--dump-region", default=None)
    ap.add_argument("--resume", action="store_true",
                    help="the state is one this script saved mid-stall; "
                         "keep its registers instead of re-seeding")
    ap.add_argument("--save-state", default=None,
                    help="snapshot where the budget ran out, so a long "
                         "stall can be continued instead of restarted")
    ap.add_argument("--survey", action="store_true",
                    help="also record where every write lands and which "
                         "code is hot, to tell a stub decrypting elsewhere "
                         "from one that is merely spinning")
    args = ap.parse_args(argv)

    emu = Emulator.restore(args.state)
    print(f"restored at {emu.blocks:,} blocks")
    eip, esp, eax = _registers(emu, args)
    print(f"resuming as the injected thread: eip={eip:#x} esp={esp:#x} eax={eax:#x}")

    before = bytes(emu.mu.mem_read(args.at, args.len))
    _report("payload before", before)

    if not args.at <= eip < args.at + args.len:
        print(f"  NOTE: {eip:#x} is outside the payload region -- resuming anyway, "
              f"but check --at/--len before reading anything into the result")

    # Only writes *into the payload* matter: a self-decrypting stub rewrites the
    # region it was loaded from, and anything else it touches is scaffolding.
    spans: list[list[int]] = []
    writers: collections.Counter = collections.Counter()

    def on_write(uc, access, address, length, value, _user):
        writers[uc.reg_read(UC_X86_REG_EIP)] += 1
        end = address + length
        if spans and address <= spans[-1][1] + 0x40:
            spans[-1][1] = max(spans[-1][1], end)
        else:
            spans.append([address, end])

    emu.mu.hook_add(UC_HOOK_MEM_WRITE, on_write,
                    begin=args.at, end=args.at + args.len - 1)

    # Watching only the payload answers "did it decrypt in place" and nothing
    # else. A stub that decrypts into fresh memory, or one that is simply
    # spinning, both look identical from there -- one byte written and no
    # explanation. These two say which.
    elsewhere: collections.Counter = collections.Counter()
    hot: collections.Counter = collections.Counter()
    if args.survey:
        def on_any_write(uc, access, address, length, value, _user):
            elsewhere[address >> 16] += 1

        def on_block(uc, address, size, _user):
            hot[address >> 12] += 1

        emu.mu.hook_add(UC_HOOK_MEM_WRITE, on_any_write)
        emu.mu.hook_add(UC_HOOK_BLOCK, on_block)

    if args.resume:
        # Continuing a state this script itself saved: its registers are
        # already correct and mid-loop. Re-seeding them would silently
        # restart the stall from zero and look like no progress at all.
        eip = emu.mu.reg_read(UC_X86_REG_EIP)
        print(f"  continuing mid-run at eip={eip:#x} (registers left alone)")
    else:
        emu.mu.reg_write(UC_X86_REG_ESP, esp)
        emu.mu.reg_write(UC_X86_REG_EAX, eax)
        emu.mu.reg_write(UC_X86_REG_EIP, eip)

    status = emu.run(eip - emu.base, 0xFFFFFFF, count=args.blocks)
    print(f"\nstopped: {status}  ({emu.blocks:,} blocks)")

    after = bytes(emu.mu.mem_read(args.at, args.len))
    _report("payload after ", after)
    changed = sum(1 for a, b in zip(before, after) if a != b)
    print(f"  bytes changed in the payload: {changed:,} of {len(after):,}")

    if writers:
        print(f"\n  {sum(writers.values()):,} write(s) into the payload, "
              f"{len(spans)} span(s):")
        for lo, hi in spans[:8]:
            print(f"    {lo:#x}-{hi:#x}  (+{lo - args.at:#x}, {hi - lo:,} bytes)")
        print("  writers:")
        for addr, count in writers.most_common(5):
            print(f"    {addr:#010x}  {count:,}x")

    if args.survey:
        print("\n  writes by 64K region (top 8):")
        for page, count in elsewhere.most_common(8):
            print(f"    {page << 16:#010x}  {count:,}")
        print(f"  hottest code pages (top 8), of {len(hot):,} touched:")
        for page, count in hot.most_common(8):
            where = ""
            if args.at <= (page << 12) < args.at + args.len:
                where = f"  <- payload +{(page << 12) - args.at:#x}"
            print(f"    {page << 12:#010x}  {count:,} block(s){where}")

    if args.dump_region:
        Path(args.dump_region).write_bytes(after)
        print(f"\n  region written to {args.dump_region}")

    # A stall of 512,371,392 iterations at two basic blocks each is over a
    # billion blocks, and guessing the budget wrong means paying the whole run
    # again. Saving here makes a long run resumable: `--state` the result back
    # in with `--eip 0` and it continues from wherever the budget ran out
    # rather than from the injection.
    if args.save_state:
        emu.snapshot(args.save_state)
        print(f"  state saved to {args.save_state} at {emu.blocks:,} blocks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
