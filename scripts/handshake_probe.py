"""Interleave the loader and the code it injected, to test a shared-memory handshake.

The injected stub spins until the byte at `0x3e9f8a8` equals `0x1d`, and the only
write it makes goes to `0x3e9f8ad` -- five bytes past it -- where it stores
`0x56`. Neither side of that can be satisfied by one thread:

  * run only the loader and `*ptr+5` stays ciphertext, so if the loader waits for
    `0x56` it never sees it and never answers
  * run only the stub and `*ptr` stays ciphertext, so it spins forever

Both were observed exactly so. That is the signature of a handshake over the
section both processes share, and testing it needs the two run in turn:

  1. from `after_inject.state`, save the loader's registers
  2. run the stub until it writes `0x56` -- it does this before the long stall
  3. put the loader's registers back and let it continue
  4. watch whether it now reads `ptr+5` or writes `ptr`

If it does, the emulation needs interleaving rather than a longer budget, and the
`0x1d` is the loader's reply. If it ignores the location entirely, the handshake
reading is wrong and the byte comes from somewhere else.

    ..\\.venv\\Scripts\\python.exe handshake_probe.py

Run it from `scripts/`.
"""
from __future__ import annotations

import argparse

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_inject.state"

STUB_EIP, STUB_EAX = 0x3E9F89B, 0
#: The redirected thread's own stack, from `REMOTE_STACK` in the emulator.
#: Running the stub on 0x2fcd6c -- the value the *buggy*
#: `NtGetContextThread` handed back -- put it on the loader's stack and
#: flattened it, which is what made the first interleave meaningless.
STUB_ESP = 0x10080000
#: Where the stub stores 0x56, reached before the 512M-iteration stall.
STUB_WRITE_AT = 0x3E9F67F
#: The shared cell: ptr is what the stub waits on, ptr+5 what it writes.
PTR = 0x3E9F8A8


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--stub-blocks", type=int, default=5_000_000)
    ap.add_argument("--loader-blocks", type=int, default=1_000_000_000,
                    help="BLOCKS, not instructions -- roughly five times "
                         "as many instructions. Confusing the two turned a "
                         "one-hour estimate into a 24-hour run.")
    ap.add_argument("--watch-reads", action="store_true",
                    help="also watch reads of the cell; costs a range test "
                         "on every memory read in the emulation")
    args = ap.parse_args(argv)

    emu = Emulator.restore(args.state)
    print(f"restored at {emu.blocks:,} blocks")

    # The loader is mid-flight here, so *every* register has to come back, not
    # the three the stub needs. Restoring a subset would leave it running with
    # the stub's stack and look like the loader crashing.
    saved = {r: emu.mu.reg_read(emu._reg_id(r)) for r in emu._REGS}
    print(f"  loader parked at eip={saved.get('EIP', 0):#x}")

    print(f"\n-- phase 1: run the stub until it writes 0x56 at {PTR + 5:#x}")
    reached = {"hit": False}

    def on_stub_write(uc, address, size, _user):
        if address == STUB_WRITE_AT:
            reached["hit"] = True
            uc.emu_stop()

    handle = emu.mu.hook_add(UC_HOOK_CODE, on_stub_write)
    emu.mu.reg_write(UC_X86_REG_ESP, STUB_ESP)
    emu.mu.reg_write(UC_X86_REG_EAX, STUB_EAX)
    emu.mu.reg_write(UC_X86_REG_EIP, STUB_EIP)
    emu.run(STUB_EIP - emu.base, 0xFFFFFFF, count=args.stub_blocks)
    emu.mu.hook_del(handle)

    if not reached["hit"]:
        print("  the stub never reached its write -- nothing to hand the loader")
        return 1
    # Let the store itself retire, then read the cell back.
    emu.resume(count=4)
    cell = bytes(emu.mu.mem_read(PTR, 8))
    print(f"  reached it. cell now {cell.hex()}  (*ptr={cell[0]:#04x}, *ptr+5={cell[5]:#04x})")

    print(f"\n-- phase 2: put the loader back and watch {PTR:#x}..{PTR + 8:#x}")
    for reg, value in saved.items():
        try:
            emu.mu.reg_write(emu._reg_id(reg), value)
        except Exception:
            pass

    reads, writes = [], []
    # The read watch is off by default because it is expensive out of all
    # proportion to what it answers. Unicorn range-tests every memory read when
    # one is installed, and with it the loader covered 1.7B blocks in 27 minutes
    # and then effectively stopped -- 24 hours of pegged CPU produced no further
    # output at all. Writes are the question anyway: "does the loader put 0x1d
    # in the cell". Reads only refine a negative.
    if args.watch_reads:
        emu.mu.hook_add(UC_HOOK_MEM_READ,
                        lambda uc, a, addr, sz, v, u: reads.append(
                            (emu.blocks, uc.reg_read(UC_X86_REG_EIP), addr)),
                        begin=PTR, end=PTR + 7)
    emu.mu.hook_add(UC_HOOK_MEM_WRITE,
                    lambda uc, a, addr, sz, v, u: writes.append(
                        (emu.blocks, uc.reg_read(UC_X86_REG_EIP), addr, v)),
                    begin=PTR, end=PTR + 7)

    status = ""
    start = emu.blocks
    while emu.blocks - start < args.loader_blocks:
        status = emu.resume(count=200_000_000)
        if "returned" not in status:
            break
    print(f"  loader stopped: {status}  ({emu.blocks:,} blocks)")

    print(f"\n  {len(reads)} read(s) of the cell by the loader:")
    for blocks, eip, addr in reads[:8]:
        print(f"    {blocks:>13,}blk  eip {eip:#010x}  [{addr:#x}]")
    print(f"  {len(writes)} write(s) to the cell by the loader:")
    for blocks, eip, addr, value in writes[:8]:
        flag = "   <-- the 0x1d the stub waits for" if value == 0x1D else ""
        print(f"    {blocks:>13,}blk  eip {eip:#010x}  [{addr:#x}] = {value:#x}{flag}")

    cell = bytes(emu.mu.mem_read(PTR, 8))
    print(f"\n  cell after the loader ran: {cell.hex()}  (*ptr={cell[0]:#04x})")

    # A faulted loader may not conclude anything. The first version of this
    # printed "the loader never touches it, so the handshake reading is wrong"
    # from a run that had died 138K blocks in, executing garbage off a stack the
    # stub had flattened -- zero reads is what a corpse looks like, not evidence
    # of a decision. Any verdict has to check the run survived first.
    faulted = "returned" not in status and "RETURNED" not in status
    if faulted:
        print(f"  NO VERDICT: the loader did not run to completion ({status}).")
        print("  Zero reads here means it died, not that it declined to look.")
        return 1

    if cell[0] == 0x1D:
        print("  HANDSHAKE CONFIRMED -- the loader answered; the emulation needs "
              "interleaving, not a longer budget.")
    elif writes or reads:
        print("  the loader touches the cell but did not answer with 0x1d -- read "
              "the eip above before concluding either way.")
    elif args.watch_reads:
        print("  the loader ran to completion and neither read nor wrote it, so "
              "the handshake reading is wrong and 0x1d comes from elsewhere.")
    else:
        print("  the loader ran to completion and never WROTE it. That rules out\n"
              "  the loader answering, but not it watching -- re-run with\n"
              "  --watch-reads to separate those, and expect it to be slow.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
