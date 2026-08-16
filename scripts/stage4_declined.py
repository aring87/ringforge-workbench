"""Which branches decline into stage 4's unexecuted two-thirds?

23 of stage 4's 67 pages ever execute. The credential-harvesting code is in the
other 44, and three independent lines of evidence now agree on that -- the page
count, the instruction-level trace, and the cipher census (RC4 turns out to wrap
keys, not decrypt strings). So the question is no longer *where* the dead code
is but *what decides not to enter it*.

This answers it without inferring anything from a disassembly reading, which is
the method that failed repeatedly on this payload. It records every basic block
actually executed, then walks each executed block to its terminating branch and
asks a purely mechanical question: of this branch's two successors, was one
taken and the other never? Those are the declined branches, and the ones whose
untaken side lands in a never-executed page are the gates.

    ..\\.venv\\Scripts\\python.exe stage4_declined.py

Indirect calls (`call eax`, `call [edi]`) have no static target and are reported
separately -- this family dispatches through resolved pointers, so a gate may
well be an indirect call that was simply never reached rather than a branch that
was evaluated and declined.
"""
from __future__ import annotations

import argparse
import collections

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM
from unicorn import UC_HOOK_BLOCK
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000
PAY, PLEN = 0x3E93C74, 0x42C00

#: `Emulator.run` returns the string "returned or budget reached" for BOTH a
#: clean `emu_start` return and an exhausted budget, because it cannot tell them
#: apart. That ambiguity cost a day: `emu_start`'s `count` is **instructions**,
#: not blocks, so a 60,000,000-instruction budget stopped this payload at
#: 16,096,220 blocks *mid-loop*, and that number was then adopted as the
#: signature of a completed run -- including as a RUN CHECK that "validated"
#: truncated runs against the truncation itself.
#:
#: The reliable test is where EIP finishes. The trampoline returns to
#: `0x77009ff0` in ntdll, so EIP still inside the payload means the budget ran
#: out with work left to do.
RESUME_ADDR = 0x77009FF0

COND = {"je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl",
        "jle", "js", "jns", "jo", "jno", "jp", "jnp", "jcxz", "jecxz"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--instructions", type=int, default=400_000_000,
                    help="INSTRUCTION budget for emu_start, not a block count. "
                         "60M stops this payload mid-scan at 16,096,220 blocks")
    args = ap.parse_args(argv)

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    emu = Emulator.restore(args.state)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    start = emu.blocks

    executed: set[int] = set()
    emu.mu.hook_add(UC_HOOK_BLOCK, lambda u, a, s, x: executed.add(a),
                    begin=PAY, end=PAY + PLEN - 1)
    status = emu.resume(count=args.instructions)
    ran = emu.blocks - start
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    inside = PAY <= eip < PAY + PLEN
    print(f"RUN CHECK: {ran:,} blocks, {args.instructions:,} instruction budget")
    print(f"           ended at eip {eip:#010x} -- {status}")
    if inside:
        print(f"*** VOID: EIP is still inside the payload (+{eip - PAY:#x}), so "
              f"the budget ran out mid-execution.\n"
              f"    Every 'never executed' below would be a lie of omission. "
              f"Raise --instructions.")
        return 2
    print(f"           EIP left the payload, so execution finished.\n")

    pages = {a >> 12 for a in executed}
    total_pages = (PLEN + 0xFFF) >> 12
    print(f"{len(executed):,} distinct block(s) executed, "
          f"{len(pages)} of {total_pages} pages\n")

    image = bytes(emu.mu.mem_read(PAY, PLEN))

    declined: list[tuple[int, str, int, int]] = []
    indirect: collections.Counter[str] = collections.Counter()
    for block in sorted(executed):
        off = block - PAY
        if not (0 <= off < PLEN):
            continue
        for ins in md.disasm(image[off:off + 64], block):
            m = ins.mnemonic
            if m in COND:
                if not ins.operands or ins.operands[0].type != X86_OP_IMM:
                    break
                target = ins.operands[0].imm
                fall = ins.address + ins.size
                t_hit, f_hit = target in executed, fall in executed
                if t_hit != f_hit:
                    untaken = fall if t_hit else target
                    if (untaken >> 12) not in pages:
                        declined.append((ins.address, f"{m} {ins.op_str}",
                                         untaken, block))
                break
            if m == "call":
                if ins.operands and ins.operands[0].type == X86_OP_IMM:
                    t = ins.operands[0].imm
                    if PAY <= t < PAY + PLEN and (t >> 12) not in pages:
                        declined.append((ins.address, f"call {ins.op_str}",
                                         t, block))
                else:
                    indirect[ins.op_str] += 1
                break
            if m in ("ret", "jmp"):
                break

    print(f"{len(declined)} branch(es)/call(s) whose untaken side is in a page "
          f"that never ran:\n")
    for addr, text, untaken, block in declined[:args.top]:
        print(f"  {addr:#010x}  (payload +{addr - PAY:#07x})  {text}")
        print(f"      declines to {untaken:#010x} "
              f"(+{untaken - PAY:#07x}, page {(untaken - PAY) >> 12})")
        lo = max(0, addr - PAY - 24)
        for pre in md.disasm(image[lo:addr - PAY + 8], PAY + lo):
            if pre.address <= addr:
                print(f"        {pre.address:#010x}  {pre.mnemonic:7} {pre.op_str}")

    if indirect:
        print(f"\nindirect call targets seen in executed blocks "
              f"({sum(indirect.values())} site(s)):")
        for op, n in indirect.most_common(10):
            print(f"   call {op:24} x{n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
