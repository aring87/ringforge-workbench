"""The twelve sleeps are two six-second polls, and this is what they poll.

`0ag` read the twelve sleeps as "a 12-second delay chunked into twelve one-second
sleeps, the standard shape for defeating sandboxes that patch out long waits",
on the measurement that the loop body touched nothing but its own stack. That is
**retracted here**. The twelve are two separate loops of six, at payload
`+0x03f86` and `+0x040a6`, and each one is:

    do { Sleep(1000); if (*state == 1) goto proceed; } while (++n < 6);
    *state = -1; return 0;                      <-- what actually happened

`proceed` in the first loop is `NtCreateSection(SECTION_ALL_ACCESS,
PAGE_EXECUTE_READWRITE, SEC_COMMIT)` -> `NtOpenProcess(0x438)` ->
`NtMapViewOfSection` **twice**, into the remote process and into this one. That
is shared-section injection, fully formed, six instructions past the poll.

    ..\\.venv\\Scripts\\python.exe stage4_gate.py
    ..\\.venv\\Scripts\\python.exe stage4_gate.py --force-ready

The plain run measures: where the state word lives, what it holds at each of the
twelve checks, and whether **anything at all writes it** between the first sleep
and the end of the run.

`--force-ready` writes 1 into it at the first check. That is **feeding the
payload an answer**, not fixing the harness, and it is here for exactly one
purpose: to show behaviourally what the disassembly says structurally. Nothing
measured under `--force-ready` is evidence about the sample's environment -- it
is evidence about what code sits behind the gate.
"""
from __future__ import annotations

import argparse
import struct

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EBX, UC_X86_REG_EDI, UC_X86_REG_EIP,
                               UC_X86_REG_ESP)

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000
PAY, PLEN = 0x3E93C74, 0x42C00

#: The two `cmp` sites, and the register holding the pointer at each. The first
#: loop tests `[ebx+0x10]`, the second `[edi]` -- different structures, or the
#: same one at different offsets; the run says which.
POLLS = {
    0x3E97C02: ("+0x03f8e", UC_X86_REG_EBX, 0x10),
    0x3E97D22: ("+0x040ae", UC_X86_REG_EDI, 0x00),
}

#: Everything the gated path calls. Present in the census means the injection
#: ran; absent means it did not. `NtOpenProcess` with 0x438 is
#: VM_OPERATION|VM_READ|VM_WRITE|QUERY_INFORMATION, which is what a writer of
#: another process's memory asks for and nothing else does.
GATED = ("NtCreateSection", "NtOpenProcess", "NtMapViewOfSection",
         "NtWriteVirtualMemory", "NtUnmapViewOfSection", "NtResumeThread",
         "NtSetContextThread", "NtGetContextThread", "NtCreateThreadEx",
         "RtlCreateUserThread", "NtQueueApcThread")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--instructions", type=int, default=2_000_000_000)
    ap.add_argument("--force-ready", action="store_true",
                    help="write 1 into the polled state word at the first "
                         "check -- an experiment, not a fix")
    ap.add_argument("--force-all", action="store_true",
                    help="answer every poll, not just the first. Shows how far "
                         "the chain runs when both rendezvous are satisfied")
    args = ap.parse_args(argv)
    if args.force_all:
        args.force_ready = True

    emu = Emulator.restore(args.state)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    start = emu.blocks
    before = dict(emu.calls)

    checks: list[tuple[int, str, int, int]] = []
    writes: list[tuple[int, int, int, int]] = []
    watched: set[int] = set()
    forced: list[int] = []

    def on_write(uc, access, address, size, value, user):
        if any(w <= address < w + 4 for w in watched):
            writes.append((emu.blocks, uc.reg_read(UC_X86_REG_EIP), address, value))

    def on_poll(uc, addr, size, user):
        label, reg, off = POLLS[addr]
        ptr = uc.reg_read(reg) + off
        try:
            val = struct.unpack("<i", uc.mem_read(ptr, 4))[0]
        except Exception:
            return
        checks.append((emu.blocks, label, ptr, val))
        if ptr not in watched:
            watched.add(ptr)
            # Watch from here on. Writes before the first check cannot be the
            # 0 -> 1 transition this loop waits for, since the word is still 0
            # when it is first read.
            uc.hook_add(UC_HOOK_MEM_WRITE, on_write, begin=ptr, end=ptr + 3)
            uc.ctl_flush_tb()      # hooks do not reach already-translated blocks
        if args.force_ready and val == 0 and (args.force_all or not forced):
            forced.append(ptr)
            uc.mem_write(ptr, struct.pack("<i", 1))
            print(f"  [{emu.blocks - start:,}blk] FORCED {ptr:#x} = 1 "
                  f"(experiment: an answer fed to the payload, not a fix)",
                  flush=True)

    for addr in POLLS:
        emu.mu.hook_add(UC_HOOK_CODE, on_poll, begin=addr, end=addr)

    print(f"running stage 4 from {INJECT_EIP:#x}, "
          f"{args.instructions:,} instruction budget"
          + ("  [--force-ready]" if args.force_ready else ""), flush=True)
    status = emu.resume(count=args.instructions)
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    print(f"\nRUN CHECK: {emu.blocks - start:,} blocks, eip {eip:#010x} -- {status}")
    if PAY <= eip < PAY + PLEN:
        print(f"*** VOID: EIP still inside the payload (+{eip - PAY:#x}); "
              f"the budget ran out.")
        return 2

    print(f"\nPOLL CHECKS ({len(checks)}):")
    for blocks, label, ptr, val in checks:
        meaning = {0: "not ready", 1: "READY", 2: "done",
                   -1: "failed"}.get(val, "?")
        print(f"   [{blocks - start:>13,}blk] {label}  [{ptr:#x}] = "
              f"{val:<12} {meaning}")

    print(f"\nWRITES TO THE POLLED WORD after the first check ({len(writes)}):")
    if not writes:
        print("   NONE. Nothing in this run ever moves the state word, so the "
              "poll cannot succeed here")
        print("   no matter how long it waits -- the six seconds are not a "
              "stall, they are a timeout.")
    for blocks, ip, addr, val in writes:
        where = f"+{ip - PAY:#07x}" if PAY <= ip < PAY + PLEN else f"{ip:#x}"
        print(f"   [{blocks - start:>13,}blk] {where} wrote {val:#x} "
              f"to {addr:#x}")

    print("\nDID THE GATED PATH RUN?")
    hit = False
    for name in GATED:
        n = emu.calls.get(name, 0) - before.get(name, 0)
        if n:
            hit = True
            print(f"   {n:>4}  {name}")
    if not hit:
        print("   no. None of NtCreateSection / NtOpenProcess / "
              "NtMapViewOfSection / NtWriteVirtualMemory")
        print("   was reached, which is the same census 0ae reports and the "
              "same conclusion -- but now")
        print("   with the reason attached rather than the absence alone.")
        return 0

    # The mapping is only half the story. Section injection copies the body in
    # with ordinary instructions -- no API is involved -- so the bytes written
    # into the local view are the only evidence of what would land in the host.
    print("\nSECTIONS")
    for r in emu.section_requests:
        print(f"   [{r['blocks'] - start:>13,}blk] requested {r['requested']:,} "
              f"bytes, granted {r['granted']:,}  (handle {r['handle']:#x})")
    for m in emu.section_maps:
        print(f"   [{m['blocks'] - start:>13,}blk] mapped section {m['section']:#x} "
              f"at {m['at']:#x}, {m['size']:,} bytes, into pid {m['pid']}")
    print("\nBYTES WRITTEN INTO THE VIEW")
    if not emu.section_writes:
        print("   none recorded -- the section was mapped and left empty in "
              "this run")
    for w in emu.section_writes[:20]:
        print(f"   {w}")
    if emu.remote_targets:
        print("\nREMOTE TARGETS OPENED")
        for t in emu.remote_targets:
            print(f"   {t}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
