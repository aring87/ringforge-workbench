"""Which PEB fields does the payload actually read?

Written to settle one suspect: `lpApplicationName` comes out as
`C:C:\\Windows\\SysWOW64\\compact.exe` even with every loader entry carrying a
real `FullDllName` (*0ap*), and `ProcessParameters` at `PEB+0x10` is the obvious
place a stray drive letter could come from -- **this harness never writes it**.
`setup()` fills `+0x02` (BeingDebugged), `+0x08` (ImageBaseAddress) and `+0x0C`
(Ldr) and leaves the rest of the page zero.

    ..\\.venv\\Scripts\\python.exe peb_reads.py

If `+0x10` is never read the suspect is dead and the doubling comes from
somewhere else. If it is read, the payload is being handed a NULL pointer to
`RTL_USER_PROCESS_PARAMETERS` and everything it derives from it is this
harness's invention -- which is the same shape as the empty export tables in
*0b* and the leaf `FullDllName` in *0al*.

A read hook narrowed to one page costs nothing: unicorn filters the range in C
and only calls back on a hit, unlike the unfiltered hook in `stage4_intent.py`.
"""
from __future__ import annotations

import argparse
import collections

from unicorn import UC_HOOK_MEM_READ
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000
PAY, PLEN = 0x3E93C74, 0x42C00

#: Only offsets worth naming with confidence. Anything else is reported by
#: offset -- a wrong label here would be worse than none, because the whole
#: point is to say which field was consulted.
FIELDS = {
    0x00: "InheritedAddressSpace",
    0x02: "BeingDebugged",
    0x04: "Mutant",
    0x08: "ImageBaseAddress",
    0x0C: "Ldr",
    0x10: "ProcessParameters   <-- the suspect",
    0x18: "ProcessHeap",
    0x1C: "FastPebLock",
    0x38: "ApiSetMap",
    0x68: "NtGlobalFlag",
    0x94: "NumberOfHeaps",
    0x9C: "ProcessHeaps",
    0xA4: "OSMajorVersion",
    0xA8: "OSMinorVersion",
    0xAC: "OSBuildNumber",
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--instructions", type=int, default=1_500_000_000)
    args = ap.parse_args(argv)

    emu = Emulator.restore(args.state)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    start = emu.blocks

    hits: collections.Counter = collections.Counter()
    readers: dict[int, collections.Counter] = collections.defaultdict(
        collections.Counter)
    first: dict[int, int] = {}

    def on_read(uc, access, address, size, value, user):
        off = address - winenv.PEB_ADDR
        hits[off] += 1
        readers[off][uc.reg_read(UC_X86_REG_EIP)] += 1
        first.setdefault(off, emu.blocks)

    emu.mu.hook_add(UC_HOOK_MEM_READ, on_read,
                    begin=winenv.PEB_ADDR, end=winenv.PEB_ADDR + 0xFFF)

    print(f"running stage 4 from {INJECT_EIP:#x}, watching "
          f"PEB {winenv.PEB_ADDR:#x}..+0x1000", flush=True)
    status = emu.resume(count=args.instructions)
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    print(f"\nRUN CHECK: {emu.blocks - start:,} blocks, eip {eip:#010x} -- {status}")
    if PAY <= eip < PAY + PLEN:
        print("*** VOID: EIP still inside the payload; the budget ran out.")
        return 2

    print(f"\nPEB BYTES READ ({len(hits)} distinct offsets, "
          f"{sum(hits.values()):,} reads):")
    for off in sorted(hits):
        name = FIELDS.get(off, "")
        who = readers[off].most_common(2)
        where = ", ".join(
            f"+{ip - PAY:#07x}" if PAY <= ip < PAY + PLEN else f"{ip:#x}"
            for ip, _ in who)
        print(f"   +{off:#05x}  {hits[off]:>8,} reads  "
              f"[first at {first[off] - start:,}blk]  {name}")
        print(f"            by {where}")

    suspect = [o for o in hits if 0x10 <= o < 0x14]
    print("\nTHE SUSPECT:")
    if suspect:
        print(f"   ProcessParameters IS read ({sum(hits[o] for o in suspect)} "
              f"times). This harness leaves it 0, so whatever")
        print(f"   the payload derives from it is derived from a NULL pointer "
              f"-- ours, not the sample's.")
    else:
        print("   ProcessParameters at +0x10 is NEVER read. It cannot be the "
              "source of the doubled")
        print("   drive, and populating it would be answering a question "
              "nothing asks.")

    print(f"\nFAULTS DURING THE RUN ({len(emu.faults)}):")
    for access, addr, ip in emu.faults[:10]:
        where = f"+{ip - PAY:#07x}" if PAY <= ip < PAY + PLEN else f"{ip:#x}"
        print(f"   access {access} at {addr:#x} from {where}")
    if not emu.faults:
        print("   none -- nothing dereferenced a null or unmapped pointer")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
