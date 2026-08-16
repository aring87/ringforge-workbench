"""What are stage 4's two hot pages computing, and what ends the loop?

14M of stage 4's 16M blocks run inside `0x3ec0000` and `0x3ea8000`, with 9.58M
writes to the stack and only 249 of 273,408 payload bytes changed. That is a
tight compute loop that terminates by itself -- the same shape as stage 3's
512-million-iteration stall, which took three runs to recognise for what it was.

This counts every basic block inside those pages, so the loop body shows up as a
handful of addresses with enormous counts, and the exit shows up as the blocks
that run once. Then it disassembles them.

    ..\\.venv\\Scripts\\python.exe trace_stage4_loop.py

Hooks are range-limited to the two pages on purpose. An unrestricted
`UC_HOOK_CODE` over the payload is a Python callback per instruction across the
hot pages, which is hours rather than minutes -- that mistake cost a run here.
"""
from __future__ import annotations

import argparse
import collections

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import UC_HOOK_BLOCK
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
                               UC_X86_REG_EDI, UC_X86_REG_EDX, UC_X86_REG_EIP,
                               UC_X86_REG_ESI, UC_X86_REG_ESP)

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000
PAYLOAD_AT = 0x3E93C74
HOT = ((0x03EC0000, 0x03EC0FFF), (0x03EA8000, 0x03EA8FFF))

md = Cs(CS_ARCH_X86, CS_MODE_32)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--blocks", type=int, default=60_000_000)
    ap.add_argument("--top", type=int, default=8)
    args = ap.parse_args(argv)

    emu = Emulator.restore(args.state)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    start = emu.blocks

    counts: collections.Counter[int] = collections.Counter()
    order: list[int] = []          # first few, in execution order
    last: collections.deque[int] = collections.deque(maxlen=12)

    def on_block(uc, addr, size, user):
        counts[addr] += 1
        if len(order) < 12:
            order.append(addr)
        last.append(addr)

    for lo, hi in HOT:
        emu.mu.hook_add(UC_HOOK_BLOCK, on_block, begin=lo, end=hi)

    print(f"running, hooking {len(HOT)} page(s)...")
    status = emu.resume(count=args.blocks)
    print(f"  {status} after {emu.blocks - start:,} blocks\n")

    total = sum(counts.values())
    print(f"{len(counts)} distinct block(s) in the hot pages, {total:,} entries")
    once = [a for a, n in counts.items() if n == 1]
    print(f"  {len(once)} ran exactly once -- entry and exit paths\n")

    print(f"the loop body, top {args.top} by count:")
    for addr, n in counts.most_common(args.top):
        print(f"\n  {addr:#010x}  x{n:,}   (payload +{addr - PAYLOAD_AT:#x})")
        try:
            code = bytes(emu.mu.mem_read(addr, 64))
        except Exception as exc:
            print(f"     unreadable: {exc}")
            continue
        for ins in md.disasm(code, addr):
            print(f"     {ins.address:#010x}  {ins.mnemonic:7} {ins.op_str}")
            if ins.mnemonic.startswith(("j", "ret", "call")):
                break

    print("\nblocks that ran exactly once (the exit path), last 12 seen:")
    for addr in last:
        if counts[addr] > 4:
            continue
        print(f"\n  {addr:#010x}  x{counts[addr]}   (payload +{addr - PAYLOAD_AT:#x})")
        try:
            code = bytes(emu.mu.mem_read(addr, 48))
        except Exception:
            continue
        for ins in md.disasm(code, addr):
            print(f"     {ins.address:#010x}  {ins.mnemonic:7} {ins.op_str}")
            if ins.mnemonic.startswith(("j", "ret", "call")):
                break

    regs = {"eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX,
            "edx": UC_X86_REG_EDX, "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI,
            "esp": UC_X86_REG_ESP}
    print("\nregisters at exit: " + "  ".join(
        f"{n}={emu.mu.reg_read(r):#010x}" for n, r in regs.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
