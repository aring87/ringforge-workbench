"""What did stage 4 do with the host it created?

THE QUESTION as `0ah` leaves it: does stage 4 ever *intend* to inject here? The
retired framing was "what is blocking the injection", and it is retired because
the 146,255 blocks after the twelve sleeps call no API at all -- nothing there
asks this harness for anything, so no further stub can change what happens.

    ..\\.venv\\Scripts\\python.exe stage4_intent.py

`0ah` measured the tail by *blocks and API calls*. Neither is the interesting
quantity: a decision taken on data already in hand reads the data, it does not
call anything. So this measures the windows nobody has measured -- what MEMORY
is touched between being told the target's `ImageBaseAddress` and starting to
sleep, and again after the last sleep -- and it splits the run at the host
events rather than reporting one number for the whole of it.

Windows, in order:

    create      CreateProcessInternalW returns  ->  ProcessBasicInformation
    peb         ProcessBasicInformation         ->  NtReadVirtualMemory
    decide      NtReadVirtualMemory returns     ->  first NtDelayExecution
    sleeping    first sleep                     ->  last sleep returns
    tail        last sleep returns              ->  EIP leaves the payload

`decide` is the window that matters and the one no probe has isolated. If the
value we served is ever read back, it is read there. If it is never read back,
the base was gathered and discarded, and "being blocked" is not what is
happening.

Hooks are installed lazily at the first `CreateProcessInternalW`, ~52M blocks
in: a memory hook over the whole run costs more than the run does, and every
window of interest is after that call.
"""
from __future__ import annotations

import argparse
import collections
from typing import Optional

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import UC_HOOK_BLOCK, UC_HOOK_MEM_READ
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000
PAY, PLEN = 0x3E93C74, 0x42C00

#: The trampoline returns here. EIP still inside the payload means the budget
#: ran out, and every "never happened" below would be a lie of omission --
#: the mistake `0aa` records, encoded once as a RUN CHECK that certified it.
RESUME_ADDR = 0x77009FF0

WINDOWS = ("create", "peb", "decide", "sleeping", "tail")


def classify(addr: int, emu: Emulator, peb_of: dict[int, str]) -> str:
    """Which region an address belongs to, named the way the question needs.

    Deliberately separates *its own* stack and payload from anything belonging
    to the process it created: the whole point is whether it looked at the host
    again after being told where the host's image is.
    """
    if PAY <= addr < PAY + PLEN:
        return "payload"
    if addr in peb_of or any(p <= addr < p + 0x1000 for p in peb_of):
        return "SPAWNED PEB"
    base = winenv.HOST_IMAGE_BASE
    if base <= addr < base + winenv.HOST_IMAGE_STRIDE * 16:
        return "SPAWNED IMAGE"
    if winenv.KUSER_SHARED_DATA <= addr < winenv.KUSER_SHARED_DATA + 0x1000:
        return "KUSER_SHARED_DATA"
    if 0x7FFD0000 <= addr < 0x7FFE0000:
        return "own PEB/TEB/LDR"
    if winenv.NTDLL_BASE <= addr < winenv.NTDLL_BASE + 0x1000000:
        return "ntdll image"
    if winenv.KERNEL32_BASE <= addr < winenv.KERNEL32_BASE + 0x1000000:
        return "kernel32 image"
    if winenv.REAL_MODULE_BASE <= addr < winenv.REAL_MODULE_LIMIT:
        return "other DLL images"
    if winenv.HEAP_BASE <= addr < winenv.HEAP_BASE + winenv.HEAP_SIZE:
        return "heap"
    if 0x10000000 <= addr < 0x10100000:
        return "own stack"
    return f"other ({addr:#010x})"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--instructions", type=int, default=1_500_000_000,
                    help="INSTRUCTION budget for emu_start, not a block count")
    ap.add_argument("--top", type=int, default=12)
    #: The counterfactual. `SPAWNED_IMAGE_BASE` is a harness answer, not a
    #: measurement -- 0x400000 was chosen because it is the classic base for the
    #: non-ASLR SysWOW64 binaries stage 4 picks. If the run is identical with a
    #: different one, the value the payload was told is not what decided
    #: anything, and no better answer to that question will change the outcome.
    ap.add_argument("--image-base", type=lambda v: int(v, 0), default=None,
                    help="override the ImageBaseAddress served for the spawned "
                         "process (default: the harness's 0x400000)")
    args = ap.parse_args(argv)

    if args.image_base is not None:
        winenv.SPAWNED_IMAGE_BASE = args.image_base
        print(f"COUNTERFACTUAL: serving ImageBaseAddress "
              f"{args.image_base:#x} instead of 0x400000")

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    emu = Emulator.restore(args.state)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    start = emu.blocks

    state = {"window": None, "sleeps": 0, "base_buf": 0, "base_val": None}
    #: Per window: block entries, distinct blocks, reads by region, and the
    #: instruction addresses that did the reading.
    blocks_in: dict[str, collections.Counter] = {w: collections.Counter() for w in WINDOWS}
    reads_in: dict[str, collections.Counter] = {w: collections.Counter() for w in WINDOWS}
    readers: dict[str, collections.Counter] = {w: collections.Counter() for w in WINDOWS}
    #: Every read that lands on the four bytes we answered the image-base
    #: question with. The single most load-bearing measurement here.
    base_reads: list[tuple[int, int, int]] = []
    events: list[tuple[int, str]] = []
    peb_of: dict[int, str] = {}
    hooks: list[int] = []

    def on_block(uc, addr, size, user):
        w = state["window"]
        if w:
            blocks_in[w][addr] += 1

    #: Region names memoised per page. The windows run to millions of blocks and
    #: `classify` is a chain of range tests; without this the probe costs more
    #: than the emulation it is measuring.
    region_of: dict[int, str] = {}

    def on_read(uc, access, address, size, value, user):
        w = state["window"]
        if not w:
            return
        eip = uc.reg_read(UC_X86_REG_EIP)
        if not (PAY <= eip < PAY + PLEN):
            return                      # a stub's own read, not the payload's
        page = address >> 12
        region = region_of.get(page)
        if region is None:
            region = classify(address, emu, peb_of)
            if region.startswith("other ("):
                region = f"other ({page << 12:#010x})"
            region_of[page] = region
        reads_in[w][region] += 1
        readers[w][eip] += 1
        buf = state["base_buf"]
        if buf and buf <= address < buf + 4:
            base_reads.append((emu.blocks, eip, address))

    def arm():
        """Attach the window hooks, **between** `emu_start` calls.

        Adding a memory hook in the middle of a run would be cheaper, but
        unicorn has already translated the blocks that ran before it and a hook
        added mid-flight is not guaranteed to reach them -- which would report
        "read nothing" for code that read plenty. So the API wrapper asks for a
        stop instead, and this runs while the emulator is idle. `api()` has
        already set EIP to the return address by then, so `resume()` continues
        from exactly where the call left off.
        """
        if hooks:
            return
        hooks.append(emu.mu.hook_add(UC_HOOK_BLOCK, on_block))
        hooks.append(emu.mu.hook_add(UC_HOOK_MEM_READ, on_read))
        # **And flush the translation cache.** Stopping between `emu_start`
        # calls is not enough on its own: unicorn keeps the blocks it has
        # already translated, and those were translated without these hooks, so
        # they keep running without them. The first version of this probe
        # reported 15 block entries and 68 reads across the 2.9 million blocks
        # between the process creation and the PEB query -- not a quiet payload,
        # a hook that only reached code translated after it was attached. That
        # is the same failure mode as the `FileNameInformation` gap and the RUN
        # CHECK that certified its own truncation: the measurement succeeded and
        # reported nothing.
        emu.mu.ctl_flush_tb()

    original_api = emu.api

    def traced_api(name, *a, **kw):
        esp = emu.mu.reg_read(UC_X86_REG_ESP)

        def stack_arg(n: int, offset: int = 4) -> int:
            try:
                return int.from_bytes(
                    emu.mu.mem_read(esp + offset + 4 * n, 4), "little")
            except Exception:
                return 0

        # Syscall stubs carry two return addresses and ordinary exports one, so
        # the argument offset differs. Take it from the call rather than
        # guessing by name: `_on_syscall` passes `arg_offset=8` and `_on_stub`
        # leaves the default, and guessing "starts with Nt" read the wrong four
        # bytes and reported `NtReadVirtualMemory` buffer `0x4`.
        off = kw.get("arg_offset", 4)
        if name == "CreateProcessInternalW":
            result = original_api(name, *a, **kw)
            state["window"] = "create"
            state["arm"] = True
            emu.mu.emu_stop()
            events.append((emu.blocks, "CreateProcessInternalW"))
            return result
        elif name == "NtQueryInformationProcess" and stack_arg(1, off) == 0:
            state["window"] = "peb"
            events.append((emu.blocks, "ProcessBasicInformation"))
        elif name == "NtReadVirtualMemory":
            src, buf = stack_arg(1, off), stack_arg(2, off)
            result = original_api(name, *a, **kw)
            try:
                state["base_val"] = int.from_bytes(emu.mu.mem_read(buf, 4), "little")
            except Exception:
                state["base_val"] = None
            state["base_buf"] = buf
            state["window"] = "decide"
            events.append((emu.blocks,
                           f"NtReadVirtualMemory({src:#x}) -> buffer {buf:#x} "
                           f"= {state['base_val']!r}"))
            return result
        elif name == "NtDelayExecution":
            state["sleeps"] += 1
            if state["sleeps"] == 1:
                events.append((emu.blocks, "first NtDelayExecution"))
            result = original_api(name, *a, **kw)
            # The window opens *after* the sleep returns, so the tail is what
            # runs once the last one is done rather than including it.
            state["window"] = "sleeping" if state["sleeps"] < 12 else "tail"
            return result
        elif state["window"] and name not in ("NtDelayExecution",):
            events.append((emu.blocks, f"  ...{name} during '{state['window']}'"))
        result = original_api(name, *a, **kw)
        if name == "NtQueryInformationProcess":
            for s in emu.spawned:
                if s.get("peb"):
                    peb_of[s["peb"]] = s["leaf"]
        return result

    emu.api = traced_api
    print(f"running stage 4 from {INJECT_EIP:#x}, "
          f"{args.instructions:,} instruction budget", flush=True)
    status = emu.resume(count=args.instructions)
    if state.get("arm"):
        print(f"  [{emu.blocks - start:,}blk] host created -- arming the block "
              f"and memory hooks and continuing", flush=True)
        arm()
        status = emu.resume(count=args.instructions)
    ran = emu.blocks - start
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    print(f"\nRUN CHECK: {ran:,} blocks, ended at eip {eip:#010x} -- {status}")
    if PAY <= eip < PAY + PLEN:
        print(f"*** VOID: EIP is still inside the payload (+{eip - PAY:#x}); the "
              f"budget ran out. Raise --instructions.")
        return 2
    print(f"           EIP left the payload, so execution finished.")
    print(f"           {state['sleeps']} sleep(s), "
          f"{emu.clock_sleep_100ns / 1e7:.2f}s slept\n")

    print("HOST EVENTS")
    for blocks, text in events:
        print(f"   [{blocks - start:>14,}blk] {text}")

    print("\nWINDOWS -- what ran, and what it read\n")
    for w in WINDOWS:
        entries = sum(blocks_in[w].values())
        if not entries:
            continue
        pay = {a for a in blocks_in[w] if PAY <= a < PAY + PLEN}
        print(f"  {w.upper():10} {entries:>12,} block entries, "
              f"{len(blocks_in[w]):>4} distinct ({len(pay)} in the payload)")
        total = sum(reads_in[w].values())
        if not total:
            print(f"             reads by the payload: NONE")
            continue
        for region, n in reads_in[w].most_common(8):
            print(f"             {n:>10,}  {region}")
        print()

    print("\nDID IT EVER READ THE IMAGE BASE BACK?")
    if state["base_val"] is None:
        print("   no NtReadVirtualMemory succeeded, so there was nothing to read")
    elif not base_reads:
        print(f"   NO. The four bytes at {state['base_buf']:#x} "
              f"(= {state['base_val']:#x}) are written by the read and never "
              f"loaded again by the payload.")
        print("   A hollowing routine that does not look at the base it asked "
              "for was not stopped -- it never used it.")
    else:
        print(f"   YES -- {len(base_reads)} read(s) of "
              f"{state['base_buf']:#x} (= {state['base_val']:#x}):")
        for blocks, ip, addr in base_reads[:20]:
            print(f"      [{blocks - start:>14,}blk] by +{ip - PAY:#07x} "
                  f"at {addr:#x}")

    image = bytes(emu.mu.mem_read(PAY, PLEN))
    for w in ("decide", "tail"):
        pay = sorted(a for a in blocks_in[w] if PAY <= a < PAY + PLEN)
        if not pay:
            continue
        print(f"\nPAYLOAD BLOCKS IN '{w.upper()}' "
              f"({len(pay)} distinct, hottest first)\n")
        for block in sorted(pay, key=lambda a: -blocks_in[w][a])[:args.top]:
            print(f"  +{block - PAY:#07x}  x{blocks_in[w][block]:,}")
            off = block - PAY
            for ins in md.disasm(image[off:off + 64], block):
                print(f"      {ins.address:#010x}  {ins.mnemonic:8} {ins.op_str}")
                if ins.mnemonic in ("ret", "jmp", "call") or ins.mnemonic[0] == "j":
                    break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
