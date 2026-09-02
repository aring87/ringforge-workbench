"""Where does the path builder get its bytes? Read them, do not infer them.

`0aq` black-boxed the routine at `+0x117a0` and got a rule: **the input's first
segment up to the first backslash, then the input's own directory**. That rule
is why every candidate comes out `C:C:\Windows\System32\<name>` and why the real
`CreateProcessW` rejects all twelve.

Reading those four rows together says something they were not asked: the rule
can only produce a well-formed path when `FullDllName` has **no volume**, and
every real WOW64 loader entry carries one. So either this build's host walk is
simply broken, or the doubling is downstream of something else.

**The something else worth eliminating first is the context cookie.** Stage 4
builds its other strings off `[esi+0x6d8]` -- `0k` records `mov ebx,[esi+0x6d8]`
in the `kernel32.dll` UNICODE_STRING construction -- and `[ctx+0x6d8]` is the
same cookie the Sandboxie gate poisons with `0x32dfd514` (`0ax`, `0bd`). If the
builder reads it, a malformed path is a *symptom* of the gate rather than an
independent bug, and the two open threads on this chain are one thread.

**This probe answers that by reading, not by arguing.** It logs every memory
read the builder makes between its call and its return, aggregated by address,
and reports whether any of them is a cookie candidate. If the cookie is never
read, the hypothesis dies for the cost of one hook -- the same disproof shape as
`ApiSetMap` in `0d`, and the reason to probe before building anything.

It also prints the reads themselves, which is the part no hypothesis asked for:
the routine's real data sources, for whoever picks up "why `write.exe` alone
skips the create".

    set RINGFORGE_EXPLORER_CHILD=1
    ..\\.venv\\Scripts\\python.exe stage4_path_sources.py

The toggle is not optional: `after_handshake.state` was written with it and
`restore()` refuses a resume that contradicts the state's env toggles. The call
lands at ~17.4M blocks, so this is a couple of minutes rather than a full run.

**It concludes nothing when the builder is not reached.** Three wrong readings
on this chain came from a summary line written for the expected case and printed
unconditionally (the `0aa` RUN CHECK, `stage3_tail`'s "no writes", and
`stage4_gate`'s "six seconds are not a stall"). Every count below is printed
from what happened.
"""
from __future__ import annotations

import argparse
import collections
import struct

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.x86_const import (
    UC_X86_REG_EBX,
    UC_X86_REG_EDI,
    UC_X86_REG_EIP,
    UC_X86_REG_ESI,
    UC_X86_REG_ESP,
)

import win32_emu_env as winenv
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"

#: Where the injected code starts, and the stack it starts on. The snapshot does
#: not carry these; every probe that runs stage 4 sets them explicitly.
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000

#: The builder's call boundary, from `probe_path_builder.py`.
BUILD_CALL, BUILD_RET = 0x3EACF75, 0x3EACF7A

#: The context offset the cookie lives at, from `0ax`.
COOKIE_OFFSET = 0x6D8

#: The poison the Sandboxie gate stores, from `0bd`. Named so a hit is
#: recognised rather than read as an ordinary pointer.
POISON = 0x32DFD514


def wide(mu, ptr: int, limit: int = 0x140) -> str:
    if not ptr:
        return ""
    raw = bytes(mu.mem_read(ptr, limit))
    end = raw.find(b"\x00\x00")
    if end % 2:
        end += 1
    return raw[:end].decode("utf-16-le", "replace")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--cookie", metavar="HEX",
        help="overwrite [ctx+0x6d8] at the builder's call and print what the "
             "path comes out as. A read inside a 3-million-read call tree is "
             "not evidence that the value reaches the path; changing it and "
             "watching the output is. Try 0x32dfd514 for the gate's poison",
    )
    args = parser.parse_args()
    forced = int(args.cookie, 16) if args.cookie else None

    emu = Emulator.restore(STATE)
    mu = emu.mu
    mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)

    state: dict = {"inside": False, "entered": 0}
    reads: collections.Counter = collections.Counter()
    read_sites: dict[int, set] = collections.defaultdict(set)

    def on_read(uc, access, address, size, value, user):
        if state["inside"]:
            reads[address] += 1
            read_sites[address].add(uc.reg_read(UC_X86_REG_EIP))

    def on_call(uc, addr, size, user):
        state["entered"] += 1
        state["inside"] = True
        esp = uc.reg_read(UC_X86_REG_ESP)
        state["out"] = struct.unpack("<I", uc.mem_read(esp + 8, 4))[0]
        src = struct.unpack("<I", uc.mem_read(esp + 4, 4))[0]

        # Every register that might be the context base, so the cookie is
        # looked for rather than assumed to hang off esi.
        state["candidates"] = {
            "esi": uc.reg_read(UC_X86_REG_ESI),
            "edi": uc.reg_read(UC_X86_REG_EDI),
            "ebx": uc.reg_read(UC_X86_REG_EBX),
        }
        print(f"\n[{emu.blocks:,}blk] builder called")
        print(f"    src = {wide(mu, src)!r}")
        for name, base in state["candidates"].items():
            addr = base + COOKIE_OFFSET
            try:
                value = struct.unpack("<I", uc.mem_read(addr, 4))[0]
            except Exception:
                print(f"    {name}+0x6d8 = {addr:#x}  <unmapped>")
                continue
            note = "  <-- THE POISON" if value == POISON else ""
            print(f"    {name}+0x6d8 = {addr:#x} -> {value:#010x}{note}")
            if name == "esi":
                state["cookie_value"] = value

        # Black-box the cookie the way `0aq` black-boxed the input: change it
        # and read the output. `esi` and `edi` agree on the context here, so
        # one write covers both.
        if forced is not None:
            target = state["candidates"]["esi"] + COOKIE_OFFSET
            uc.mem_write(target, struct.pack("<I", forced))
            print(f"    OVERRIDDEN {target:#x} -> {forced:#010x} -- an "
                  f"experiment on the builder, not a claim about the machine")

    def on_ret(uc, addr, size, user):
        if not state["inside"]:
            return
        state["inside"] = False
        print(f"    out = {wide(mu, state['out'])!r}")
        mu.emu_stop()

    mu.hook_add(UC_HOOK_CODE, on_call, begin=BUILD_CALL, end=BUILD_CALL)
    mu.hook_add(UC_HOOK_CODE, on_ret, begin=BUILD_RET, end=BUILD_RET)
    mu.hook_add(UC_HOOK_MEM_READ, on_read)

    emu.resume(count=1_500_000_000)

    print(f"\nstopped at {mu.reg_read(UC_X86_REG_EIP):#x}")
    print(f"builder entered: {state['entered']}")

    if not state["entered"]:
        print("\nThe builder was never reached. Nothing below is a measurement "
              "of it, and this run concludes nothing about the cookie.")
        return 1

    print(f"distinct addresses read inside the builder: {len(reads)}")
    print(f"total reads: {sum(reads.values())}")

    cookie_addrs = {base + COOKIE_OFFSET for base in state["candidates"].values()}
    hits = {a: reads[a] for a in cookie_addrs if a in reads}

    print("\n--- the question this was written for")
    built = wide(mu, state["out"])
    doubled = ":" in built[2:]
    cookie = state.get("cookie_value")
    poisoned = cookie == POISON

    print(f"  cookie at build time : {cookie:#010x}"
          f"{'  <-- THE POISON' if poisoned else '  (a clean self-address)'}")
    print(f"  path built           : {built!r}"
          f"{'  <-- DOUBLED' if doubled else ''}")

    # **The discriminator is the cookie's VALUE against the path's shape, and
    # not the read count.** A routine can read a value without that value
    # reaching its output, and the first version of this probe concluded "may
    # be downstream of the gate" from 15 reads inside a call tree that makes
    # three million of them -- the same shape as the three summary lines this
    # chain has already had to retract.
    #
    # `0aq` had settled it in advance and nobody read the table that way: both
    # halves of the output follow the INPUT. Feeding `D:\Foo\Bar\ntdll.dll`
    # returns `D:D:\Foo\Bar\` with the cookie untouched, so neither half comes
    # from the cookie.
    if doubled and not poisoned:
        print("\n  The gate did NOT fire on this path -- the cookie holds a "
              "clean self-address -- and the path is doubled anyway.")
        print("  So the doubling is NOT downstream of the Sandboxie gate. It "
              "is the sample's own construction, as 0aq found.")
    elif doubled and poisoned:
        print("\n  Poisoned cookie AND a doubled path, which is not yet "
              "causation. Re-run with a clean cookie and compare.")
    else:
        print("\n  The path is NOT doubled on this run, which contradicts 0aq "
              "and stage4_census. Do not build on it until it reproduces.")

    if hits:
        print("\n  Context, and NOT evidence for the above: the builder's call "
              "tree does read a cookie candidate.")
        for addr, count in hits.items():
            print(f"    {addr:#x}, {count} time(s), "
                  f"from {sorted(hex(e) for e in read_sites[addr])}")
        print("    Overriding the cookie to test it directly derails the run "
              "before the builder returns -- it is a live pointer -- so the "
              "value above is the discriminator, not this.")
    else:
        print("\n  The builder's call tree reads no cookie candidate at all "
              f"({', '.join(f'{a:#x}' for a in sorted(cookie_addrs))}).")

    print("\n--- the 20 most-read addresses inside the builder")
    for addr, count in reads.most_common(20):
        sites = sorted(hex(e) for e in read_sites[addr])[:3]
        print(f"  {addr:#012x}  {count:>6}  from {sites}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
