"""Where do stage 4's ten indirect calls actually go?

`stage4_declined.py` closed the direct route: **0 branches whose untaken side is
in a page that never ran.** No executed branch declines into the dead region, so
there is no gate in the direct control flow -- which reproduces `0j` rather than
contradicting it.

What that leaves is the ten indirect call sites in executed blocks --
`call eax` x3, `call ecx` x3, `call dword ptr [ebp+0x1f]` x2, `call edx` x2.
This family dispatches through computed pointers; `0ai` found the rendezvous
*server* is reached that way and is called from nowhere at all. So if any path
from live code into the dead pages exists, it goes through one of these ten.

**This resolves them by execution rather than by reading.** Every value comes
out of the register or memory operand at the moment the call executes; nothing
is inferred from a disassembly, which is the method that has been wrong every
time on this payload.

    set RINGFORGE_EXPLORER_CHILD=1
    ..\\.venv\\Scripts\\python.exe stage4_indirect_targets.py

Two passes, because the sites are not known until the blocks are: pass one
records executed blocks, pass two hooks each indirect site found in them. Each
hook is address-limited, so unicorn filters in C and the cost is nothing.

**Both outcomes are worth having.** A target landing in a dead page is the door
into the unexecuted two-thirds and the first one this chain has found. All ten
resolving into live code or into API stubs closes the last route from executed
code, and that is a real result: it would say the dead pages are unreachable
from anything stage 4 does in this run, by any mechanism, and the reason it does
not harvest is upstream of every branch and every pointer it takes.
"""
from __future__ import annotations

import argparse
import collections

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_MEM, X86_OP_REG
from unicorn import UC_HOOK_BLOCK, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000
PAY, PLEN = 0x3E93C74, 0x42C00

#: Dead pages at code-like entropy, from `stage4_string_pages.py`. A target
#: landing in one of these is the finding this probe exists for.
CODE_LIKE_DEAD = {0x03EA0000, 0x03EA1000, 0x03EAB000, 0x03EAF000, 0x03EBC000}


def executed_blocks(state: str, budget: int) -> tuple[set[int], bool]:
    emu = Emulator.restore(state)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    seen: set[int] = set()
    emu.mu.hook_add(UC_HOOK_BLOCK, lambda u, a, s, x: seen.add(a),
                    begin=PAY, end=PAY + PLEN - 1)
    emu.resume(count=budget)
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    return seen, not (PAY <= eip < PAY + PLEN)


def indirect_sites(image: bytes, blocks: set[int]) -> dict[int, str]:
    """Address -> text, for every indirect call in an executed block.

    Disassembly is used to *locate* the sites and never to decide what they
    call. A block is disassembled from its own start, so this does not suffer
    the desynchronisation that a linear sweep does.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    sites: dict[int, str] = {}
    for block in sorted(blocks):
        offset = block - PAY
        if not 0 <= offset < len(image):
            continue
        for insn in md.disasm(image[offset:offset + 0x200], block):
            if insn.mnemonic == "call" and insn.operands:
                operand = insn.operands[0]
                if operand.type in (X86_OP_REG, X86_OP_MEM):
                    sites[insn.address] = f"{insn.mnemonic} {insn.op_str}"
            if insn.mnemonic in ("ret", "jmp") or insn.address - block > 0x180:
                break
    return sites


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--instructions", type=int, default=4_000_000_000)
    args = ap.parse_args(argv)

    print("pass 1: recording executed blocks", flush=True)
    blocks, finished = executed_blocks(args.state, args.instructions)
    if not finished:
        print("*** VOID: the budget ran out inside the payload; the site list "
              "would be partial.")
        return 2
    print(f"        {len(blocks)} blocks, "
          f"{len({b & ~0xFFF for b in blocks})} pages\n")

    emu = Emulator.restore(args.state)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    image = bytes(emu.mu.mem_read(PAY, PLEN))

    sites = indirect_sites(image, blocks)
    print(f"pass 2: {len(sites)} indirect call site(s) in executed blocks")
    for address, text in sorted(sites.items()):
        print(f"        {address:#010x}  +{address - PAY:#07x}  {text}")
    if not sites:
        print("\n*** No indirect call site found in any executed block, which "
              "contradicts\n    stage4_declined.py's count of ten. Settle that "
              "before reading on.")
        return 2

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    decoded = {}
    for address, _ in sites.items():
        offset = address - PAY
        for insn in md.disasm(image[offset:offset + 16], address):
            decoded[address] = insn
            break

    targets: collections.Counter = collections.Counter()
    per_site: dict[int, collections.Counter] = collections.defaultdict(
        collections.Counter)

    def on_site(uc, addr, size, user):
        insn = decoded.get(addr)
        if insn is None or not insn.operands:
            return
        operand = insn.operands[0]
        try:
            if operand.type == X86_OP_REG:
                value = uc.reg_read(_reg_id(operand.reg))
            else:
                mem = operand.mem
                effective = mem.disp
                if mem.base:
                    effective += uc.reg_read(_reg_id(mem.base))
                if mem.index:
                    effective += uc.reg_read(_reg_id(mem.index)) * mem.scale
                value = int.from_bytes(uc.mem_read(effective & 0xFFFFFFFF, 4),
                                       "little")
        except Exception:
            return
        targets[value] += 1
        per_site[addr][value] += 1

    from unicorn import x86_const

    def _reg_id(cs_reg: int) -> int:
        name = md.reg_name(cs_reg)
        return getattr(x86_const, f"UC_X86_REG_{name.upper()}")

    for address in sites:
        emu.mu.hook_add(UC_HOOK_CODE, on_site, begin=address, end=address)

    print("\n        resolving them by execution...", flush=True)
    emu.resume(count=args.instructions)

    print(f"\n=== {sum(targets.values())} indirect call(s) taken, "
          f"{len(targets)} distinct target(s)")
    into_dead = []
    for address in sorted(per_site):
        print(f"\n  site {address:#010x} (+{address - PAY:#07x})  "
              f"{sites[address]}")
        for value, count in per_site[address].most_common(8):
            page = value & ~0xFFF
            inside = PAY <= value < PAY + PLEN
            where = ("payload" if inside else "outside the payload")
            mark = ""
            if inside and page not in {b & ~0xFFF for b in blocks}:
                mark = "   <-- INTO A PAGE THAT NEVER RAN"
                into_dead.append((address, value))
            if page in CODE_LIKE_DEAD:
                mark += "  [code-like dead page]"
            print(f"      -> {value:#010x}  x{count:<5} {where}{mark}")

    print("\n--- what this run says")
    if into_dead:
        print(f"  {len(into_dead)} indirect call(s) target a page that never "
              f"ran. **That is the door**")
        print("  into the unexecuted region, and the first one found on this "
              "chain.")
    else:
        print("  Every indirect target resolves into live code or outside the "
              "payload. Combined")
        print("  with stage4_declined.py's zero declined branches, **no path "
              "from executed code")
        print("  into the dead pages exists in this run by any mechanism** -- "
              "not a branch, not")
        print("  a pointer. Whatever stops the harvesting is upstream of every "
              "branch and every")
        print("  pointer stage 4 takes here.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
