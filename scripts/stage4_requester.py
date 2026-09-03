"""What reaches the requester's call sites, and where does the path stop?

`0ai` mapped a two-party rendezvous inside stage 4 and found it runs the
**server** side of both halves. The requester is called directly, from
`+0x1654c` and `+0x16900`; all twelve sleeps come from the server sites and the
requester's own never fire. So stage 4 is waiting to be asked to inject and
nothing on this path asks -- and `c9f3918` established that giving it a host
does not change that.

This walks **backwards** from those two call sites to the nearest code that
actually executed, which names the exact link where the path stops.

**It does not trust a disassembly sweep.** A linear capstone pass over this
image silently drops every site after a desynchronisation -- that is measured,
not feared: it is what made `hash_call_sites.py` report 45 sites where there
were 65. So direct edges are found by **encoding search** instead. A direct
`call rel32` at `A` targeting `T` is `E8` followed by `T - (A+5)`, so testing
every offset for that exact encoding finds every such call with no disassembly
and no desynchronisation. `E9` covers `jmp rel32` the same way.

That trades one error for another and the trade is stated: an `E8` byte inside
data whose following dword happens to encode a live target is a false edge.
They are rare, they are visible as edges from implausible places, and a false
edge can only *add* a candidate path -- it cannot hide the real one, which is
the direction that matters here.

**Indirect dispatch is reported separately and never silently.** This family
dispatches through computed pointers -- the server side is reached that way and
is called from nowhere at all -- so an address that appears as a literal dword
is listed as a possible indirect target rather than folded into the call graph.

    set RINGFORGE_EXPLORER_CHILD=1
    ..\\.venv\\Scripts\\python.exe stage4_requester.py
"""
from __future__ import annotations

import argparse
import collections
import struct

from unicorn import UC_HOOK_BLOCK
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000
PAY, PLEN = 0x3E93C74, 0x42C00

#: The requester's two call sites, and the requester itself (`0ai`).
CALL_SITES = {0x1654C: "requester call site 1", 0x16900: "requester call site 2"}
REQUESTER = {0x03E70: "requester, first half", 0x03EE0: "requester, second half"}
SERVER = {0x03F40: "server, first half", 0x04090: "server, second half"}


def direct_edges(image: bytes, base: int) -> dict[int, list[tuple[int, str]]]:
    """target -> [(site, kind)], by encoding search rather than disassembly."""
    edges: dict[int, list[tuple[int, str]]] = collections.defaultdict(list)
    end = len(image) - 5
    for offset in range(end):
        opcode = image[offset]
        if opcode not in (0xE8, 0xE9):
            continue
        (rel,) = struct.unpack_from("<i", image, offset + 1)
        target = base + offset + 5 + rel
        if base <= target < base + len(image):
            edges[target].append((base + offset,
                                  "call" if opcode == 0xE8 else "jmp"))
    return edges


def literal_refs(image: bytes, base: int, address: int) -> list[int]:
    """Offsets whose dword equals `address` -- possible indirect dispatch."""
    needle = struct.pack("<I", address)
    found, start = [], 0
    while True:
        index = image.find(needle, start)
        if index < 0:
            return found
        found.append(base + index)
        start = index + 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--instructions", type=int, default=4_000_000_000)
    ap.add_argument("--depth", type=int, default=6,
                    help="how far back to walk before giving up")
    args = ap.parse_args(argv)

    emu = Emulator.restore(args.state)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)

    executed: set[int] = set()
    emu.mu.hook_add(UC_HOOK_BLOCK, lambda u, a, s, x: executed.add(a),
                    begin=PAY, end=PAY + PLEN - 1)
    start = emu.blocks
    status = emu.resume(count=args.instructions)
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    print(f"RUN CHECK: {emu.blocks - start:,} blocks -- {status}")
    if PAY <= eip < PAY + PLEN:
        print(f"*** VOID: EIP still inside the payload (+{eip - PAY:#x}); the "
              f"budget ran out and\n    'never executed' below would be a lie "
              f"of omission.")
        return 2
    pages_ran = {a & ~0xFFF for a in executed}
    print(f"           {len(executed)} distinct blocks in {len(pages_ran)} of "
          f"{(PLEN + 0xFFF) // 0x1000} pages\n")

    def page_state(address: int) -> str:
        """Whether any code in this page ran at all.

        A block that did not execute may still sit in a live page, one declined
        branch away. A block in a page where *nothing* ran is a different claim:
        on this payload those pages are still packed (`0j`), so the code there
        is not merely unreached -- it is not yet code.
        """
        return "live page" if (address & ~0xFFF) in pages_ran else "DEAD PAGE"

    image = bytes(emu.mu.mem_read(PAY, PLEN))
    edges = direct_edges(image, PAY)
    entries = sorted(edges)
    print(f"direct edges found by encoding search: "
          f"{sum(len(v) for v in edges.values())} into {len(entries)} targets\n")

    def containing_entry(address: int) -> int | None:
        """The nearest call target at or below `address`."""
        best = None
        for entry in entries:
            if entry <= address:
                best = entry
            else:
                break
        return best

    print("=== the sites in question")
    for offset, label in {**CALL_SITES, **REQUESTER, **SERVER}.items():
        address = PAY + offset
        ran = "EXECUTED" if address in executed else "never executed"
        print(f"  +{offset:#07x}  {address:#010x}  {label:<26} {ran}"
              f", {page_state(address)}")

    print("\n=== walking back from each requester call site")
    for offset, label in CALL_SITES.items():
        site = PAY + offset
        print(f"\n  {label} at +{offset:#07x}")
        if site in executed:
            print("    it EXECUTED -- nothing to walk back to.")
            continue

        entry = containing_entry(site)
        if entry is None:
            print("    no call target at or below it: this site is not inside "
                  "any function this\n    search can name. Indirect dispatch "
                  "only.")
            continue

        seen, frontier, level = {entry}, [entry], 0
        print(f"    inside the function entered at {entry:#010x} "
              f"(+{entry - PAY:#07x}), "
              f"{'EXECUTED' if entry in executed else 'never executed'}")
        while frontier and level < args.depth:
            level += 1
            callers: list[tuple[int, int, str]] = []
            for target in frontier:
                for caller, kind in edges.get(target, []):
                    callers.append((caller, target, kind))
            if not callers:
                print(f"    level {level}: NO direct caller. The path into this "
                      f"function is indirect,\n               which is how the "
                      f"server side is reached too.")
                break
            ran = [c for c, _, _ in callers if c in executed]
            print(f"    level {level}: {len(callers)} direct caller(s), "
                  f"{len(ran)} of them executed")
            for caller, target, kind in callers[:8]:
                mark = "EXECUTED" if caller in executed else "never"
                print(f"               {kind} at {caller:#010x} "
                      f"(+{caller - PAY:#07x}) -> {target:#010x}   {mark}"
                      f", {page_state(caller)}")
            if ran:
                print(f"    ** THE PATH STOPS HERE. {len(ran)} executed "
                      f"caller(s) reach this function's\n       neighbourhood "
                      f"and did not take the branch into it.")
                break
            nxt = []
            for caller, _, _ in callers:
                entry_of = containing_entry(caller)
                if entry_of is not None and entry_of not in seen:
                    seen.add(entry_of)
                    nxt.append(entry_of)
            frontier = nxt

    print("\n=== indirect candidates (literal dwords, never folded into edges)")
    for offset, label in {**CALL_SITES, **REQUESTER}.items():
        refs = literal_refs(image, PAY, PAY + offset)
        where = ", ".join(f"+{r - PAY:#07x}" for r in refs[:6]) or "none"
        print(f"  {label:<26} {len(refs)} literal ref(s): {where}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
