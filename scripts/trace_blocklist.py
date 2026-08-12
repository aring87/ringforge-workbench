"""Catch stage 3 comparing a process-name hash, and show where the constant came from.

The 20 blocklist constants are not in the image, not in any mapped region at any
checkpoint, not among the 45 XOR-decoder sites, and the names are not in memory
as strings -- see *The blocklist seven* in docs/HANDOFF.md. So they are produced
by a runtime computation nobody has located, and knowing the constants (we
already do) is not the goal. **The provenance is the goal**, because that is
what leads back to the seven names.

The obstacle is cost: a per-instruction Python hook over the ~48M blocks between
`after_scan.state` and the enumeration would take hours. The fix is that the
harness knows exactly when it hands over the process list, so the expensive hook
can be armed at that instant and only then:

1. resume with no instruction hook at all until `system_process_information`
   is called, and stop there -- `emu_stop()` from inside the handler is safe,
   Unicorn finishes the current callback so the buffer is still written;
2. install the fine-grained hook and run a bounded window;
3. on every `cmp` whose operands hold a known constant, dump a ring buffer of
   the instructions that led there.

Run it from `scripts/`.
"""
from __future__ import annotations

import argparse
import collections
import sys
from pathlib import Path

import capstone
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_ECX,
    UC_X86_REG_EDI, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_ESP)

import win32_emu_env as winenv
from crack_name_hashes import crc
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_scan.state"

UNCRACKED = {0x0263178B, 0x0CC39FEF, 0x57585356, 0x9CB95240,
             0xA8D123C8, 0xC72CE2D5, 0xD0C58467}
KNOWN = {crc(n.encode()): n for n in [
    "procmon.exe", "regmon.exe", "filemon.exe", "wireshark.exe", "netmon.exe",
    "vmwareuser.exe", "vmwareservice.exe", "vmsrvc.exe", "vmusrvc.exe",
    "sandboxiedcomlaunch.exe", "sandboxierpcss.exe", "python.exe", "perl.exe"]}
BLOCKLIST = set(KNOWN) | UNCRACKED

REGS = {
    "eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX,
    "edx": UC_X86_REG_EDX, "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI,
    "ebp": UC_X86_REG_EBP, "esp": UC_X86_REG_ESP,
}


def arm_at_process_list(emu: Emulator, which: int) -> bool:
    """Resume until the Nth SystemProcessInformation, then stop there."""
    original = winenv.system_process_information
    seen = {"n": 0}

    def patched(buf, *a, **kw):
        blob = original(buf, *a, **kw)
        seen["n"] += 1
        if seen["n"] >= which:
            emu.mu.emu_stop()
        return blob

    winenv.system_process_information = patched
    try:
        for _ in range(12):
            status = emu.resume(count=200_000_000)
            if seen["n"] >= which:
                print(f"  armed: process list served (call #{seen['n']}) "
                      f"at {emu.blocks:,} blocks")
                return True
            if "returned" not in status:
                print(f"  stopped early: {status}")
                return False
            if emu.blocks > 640_000_000:
                print("  reached the clean exit without a process enumeration")
                return False
    finally:
        winenv.system_process_information = original
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--which", type=int, default=1,
                    help="arm on the Nth process enumeration (default 1)")
    ap.add_argument("--window", type=int, default=40_000_000,
                    help="instructions to trace after arming")
    ap.add_argument("--ring", type=int, default=48,
                    help="instructions of history to show per hit")
    ap.add_argument("--forward", type=int, default=0,
                    help="after the first served-name hash, trace this many "
                         "instructions forward with register values -- this is "
                         "where the comparison and the constant have to appear")
    args = ap.parse_args()

    emu = Emulator.restore(args.state)
    mu = emu.mu
    emu.repair_wow64_crash()
    print(f"restored at {emu.blocks:,} blocks")

    if not arm_at_process_list(emu, args.which):
        return 1

    # Pre-disassemble so the hook does a dict lookup, not a decode, per step.
    alloc_base, alloc_size = emu.allocs[0]
    blob = bytes(mu.mem_read(alloc_base, alloc_size))
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.skipdata = True
    dis = {i.address: (i.mnemonic, i.op_str) for i in md.disasm(blob, alloc_base)}
    print(f"  {len(dis):,} instructions pre-decoded from the allocation")

    # Anchor on the *name* hash landing in EAX, not on the constant appearing in
    # a `cmp`. The first version of this hook looked only at `cmp reg, reg`
    # inside the allocation and saw nothing -- which was a statement about the
    # hook, since the compare may be against memory, may use sub/xor, and may
    # live outside the pre-decoded range. crc32 returns in EAX, so one register
    # read per instruction catches the hash however it is then consumed.
    served = {crc(n.lower().encode()): n for n, _pid, _ppid in winenv.PROCESS_LIST}
    targets = dict(served)
    for h, n in KNOWN.items():
        targets[h] = f"blocklist:{n}"
    for h in UNCRACKED:
        targets[h] = "blocklist:*** UNCRACKED ***"
    print(f"  watching EAX for {len(served)} served-name hashes "
          f"and {len(BLOCKLIST)} blocklist constants")

    ring: collections.deque[int] = collections.deque(maxlen=args.ring)
    hits: list[tuple[int, int, list[int]]] = []
    seen: set[int] = set()
    fwd: list[tuple[int, int, int, int]] = []
    state = {"cap": 0}

    def cb(uc, address, size, _user):
        # Forward capture: once a served name's hash is in EAX we are at the
        # crc32 epilogue, and the comparison is in whatever runs next. That is
        # the part worth seeing -- the constant has to be materialised there.
        if state["cap"] > 0:
            state["cap"] -= 1
            fwd.append((address,
                        uc.reg_read(UC_X86_REG_EAX),
                        uc.reg_read(UC_X86_REG_ECX),
                        uc.reg_read(UC_X86_REG_EDX)))
            if state["cap"] == 0:
                uc.emu_stop()
            return
        ring.append(address)
        v = uc.reg_read(UC_X86_REG_EAX)
        if v in targets and v not in seen:
            seen.add(v)
            hits.append((address, v, list(ring)))
            if args.forward and v in served:
                state["cap"] = args.forward

    h = mu.hook_add(UC_HOOK_CODE, cb)
    print(f"  tracing {args.window:,} instructions...")
    status = emu.resume(count=args.window)
    mu.hook_del(h)
    print(f"  {status}  ({emu.blocks:,} blocks)\n")

    if not hits:
        print("Nothing watched appeared in EAX in the window.")
        print("That is a statement about the window and the hook, not about the")
        print("sample: widen --window, or try --which 2 for a later enumeration.")
        return 1

    if fwd:
        print(f"{'=' * 70}\nforward trace from the crc32 epilogue "
              f"({len(fwd)} instructions)\n{'=' * 70}")
        for a, eax, ecx, edx in fwd:
            m, o = dis.get(a, ("?", ""))
            flag = ""
            for v, r in ((eax, "eax"), (ecx, "ecx"), (edx, "edx")):
                if v in BLOCKLIST:
                    flag += f"   <== {r}={v:#010x} {targets[v]}"
            print(f"  {a:#010x}  {m:<9} {o:<30} "
                  f"eax={eax:08x} ecx={ecx:08x} edx={edx:08x}{flag}")
        print()

    print(f"{len(hits)} distinct watched values appeared in EAX\n")
    for addr, const, hist in hits:
        label = targets.get(const, "?")
        print(f"{'=' * 70}\n{const:#010x}  {label}\n  first seen at {addr:#010x}\n")
        for a in hist:
            m, o = dis.get(a, ("?", ""))
            mark = " <==" if a == addr else ""
            print(f"    {a:#010x}  {m:<8} {o}{mark}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
