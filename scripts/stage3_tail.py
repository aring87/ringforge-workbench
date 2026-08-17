"""What is stage 3 waiting for, and does it ever post stage 4's request?

Every stage-4 probe in this file overrides EIP to `0x3E9F89B` and runs the
*injected* thread. `after_handshake.state` was saved with stage 3's own thread
mid-poll: eleven `NtDelayExecution` calls at a dead-regular 2,442,658 blocks
apart, immediately after the third `NtResumeThread`. **This resumes that thread
instead**, changing nothing, and watches the control block stage 4 polls.

    ..\\.venv\\Scripts\\python.exe stage3_tail.py

It matters because stage 3 mapped the 24.8 MB section into *itself* as well as
into the process it injected (*0am*), so it holds the same view as the stage-4
server and is the one party inside this harness that could post the request. If
it never writes `0x3eee874`, the peer is not stage 3 and `0am`'s reading -- that
the asker is the injected process -- survives. If it does, `0am` is wrong about
which side asks.

The block is **all zero** in the state as saved, so anything seen here is new.
"""
from __future__ import annotations

import argparse
import struct

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
BLOCK = 0x3EEE874          # the control block: slot at +0x00 and slot at +0x10
VIEW = (0x028EA000, 24_820_736)
STAGE3 = (0x02001000, 284_641)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--instructions", type=int, default=2_000_000_000)
    ap.add_argument("--watch", type=int, default=0x40,
                    help="bytes of the control block to watch")
    args = ap.parse_args(argv)

    emu = Emulator.restore(args.state)
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    start = emu.blocks
    before = dict(emu.calls)

    where = ("stage-3 image" if STAGE3[0] <= eip < STAGE3[0] + STAGE3[1]
             else "the shared view" if VIEW[0] <= eip < VIEW[0] + VIEW[1]
             else "elsewhere")
    print(f"resuming the saved thread at eip {eip:#010x} -- in {where}")
    print(f"  (no EIP override: this is stage 3's thread, not the injected one)")
    print(f"  state holds {emu.blocks:,} blocks, "
          f"{emu.clock_sleep_100ns / 1e7:.2f}s already slept\n", flush=True)

    writes: list[tuple[int, int, int, int]] = []
    stopped: list[int] = []

    def on_write(uc, access, address, size, value, user):
        writes.append((emu.blocks, uc.reg_read(UC_X86_REG_EIP), address, value))
        print(f"  [{emu.blocks - start:>13,}blk] WRITE {value:#x} to "
              f"{address:#x} (+{address - BLOCK:#x}) from eip "
              f"{uc.reg_read(UC_X86_REG_EIP):#010x}", flush=True)

    emu.mu.hook_add(UC_HOOK_MEM_WRITE, on_write,
                    begin=BLOCK, end=BLOCK + args.watch - 1)

    sleeps = [0]
    original_api = emu.api

    #: `PostThreadMessageW` is UNHANDLED here, which means `nargs` is 0 and its
    #: four arguments are left on the stack for the caller's own `ret` to return
    #: into. Everything after it is unsound -- the first run of this probe
    #: carried on for 132M blocks and died at `0x02014f78`, and any "stage 3
    #: never wrote the block" claim covering that stretch would be worthless.
    #: So: capture the arguments and stop, rather than measure noise.
    STOP_AT = "PostThreadMessageW"

    def traced_api(name, *a, **kw):
        if name == "NtDelayExecution":
            sleeps[0] += 1
        if name == STOP_AT:
            esp = emu.mu.reg_read(UC_X86_REG_ESP)
            off = kw.get("arg_offset", 4)
            vals = []
            for i in range(4):
                try:
                    vals.append(struct.unpack(
                        "<I", emu.mu.mem_read(esp + off + 4 * i, 4))[0])
                except Exception:
                    vals.append(0)
            print(f"\n  [{emu.blocks - start:,}blk] {name}"
                  f"(idThread={vals[0]:#x}, Msg={vals[1]:#x}, "
                  f"wParam={vals[2]:#x}, lParam={vals[3]:#x})")
            print(f"      UNHANDLED by this harness. Stopping here: with nargs 0 "
                  f"its arguments stay on\n      the stack and the caller returns "
                  f"into them, so nothing past this point is sound.")
            stopped.append(emu.blocks)
            result = original_api(name, *a, **kw)
            emu.mu.emu_stop()
            return result
        return original_api(name, *a, **kw)

    emu.api = traced_api
    status = emu.resume(count=args.instructions)
    ran = emu.blocks - start
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    print(f"\nRUN CHECK: {ran:,} more blocks, ended at eip {eip:#010x} -- {status}")
    print(f"           {sleeps[0]} further NtDelayExecution call(s)")

    calls = {k: emu.calls.get(k, 0) - before.get(k, 0)
             for k in set(emu.calls) | set(before)}
    calls = {k: v for k, v in calls.items() if v}
    print(f"\nAPIs CALLED BY STAGE 3 AFTER THE SNAPSHOT:")
    for name, n in sorted(calls.items(), key=lambda kv: -kv[1]):
        print(f"   {n:>6}  {name}")
    if not calls:
        print("   none")

    print(f"\nWRITES INTO THE CONTROL BLOCK ({len(writes)}):")
    if not writes and stopped:
        print(f"   none in the {stopped[0] - start:,} sound blocks before "
              f"{STOP_AT}.")
        print(f"   **That is a bound, not a result.** Stage 3 polls and then "
              f"signals, and the signal is")
        print(f"   the call this harness does not implement -- so whether it "
              f"posts the request after")
        print(f"   being answered is exactly what has not been measured. "
              f"Implement {STOP_AT} first.")
    elif not writes:
        print(f"   NONE. Stage 3 holds the same view and never posts a request,")
        print(f"   so it is not the peer the stage-4 server is waiting for.")
    raw = bytes(emu.mu.mem_read(BLOCK, args.watch))
    print(f"\nCONTROL BLOCK NOW: {'all zero' if not any(raw) else raw.hex(' ')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
