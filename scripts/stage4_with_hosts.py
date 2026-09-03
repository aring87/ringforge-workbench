"""Give stage 4 the hosts it cannot get, and see whether it unpacks.

**THE QUESTION this chain has been circling since `0j`:** stage 4 executes an
initialisation stub, self-locates its image, walks twelve host candidates and
returns. **23 of its 67 pages ever execute**; the credential-harvesting code
sits in the other 44 and has never run. Not because a gate declines it -- `0j`
found no declined branch reaching those pages -- but because they are **still
packed**. So the question is what would make it unpack itself.

**The candidate answer, from 02 Sep:** it never obtains a host. Every path it
builds is `C:C:\\Windows\\System32\\<name>`, the real API rejects all twelve
(`real_createprocess_paths.py`), and with `backing` resolving paths honestly the
walk now opens twelve files, reads nothing from any of them, and creates
**zero** processes. A payload that vets each candidate by reading it and
declines an empty one never reaches the process half of its own loop.

**That is an inference, and this measures it.** `--serve` answers the twelve
candidates with real bytes, restoring by hand exactly the unfaithful behaviour
`backing` used to have and only for those names.

    ..\\.venv\\Scripts\\python.exe stage4_with_hosts.py           # faithful
    ..\\.venv\\Scripts\\python.exe stage4_with_hosts.py --serve   # invented

**`--serve` INVENTS THE MACHINE, and nothing measured under it is evidence
about the sample's environment.** It is the same instrument as
`stage4_gate.py --force-ready`, carrying the same warning: it shows
behaviourally what the sample does when given an answer, not what it would be
given. The eleven-host walk of `0af` is this project's standing proof that an
invented answer reads convincingly as the sample's behaviour.

**What makes it worth running anyway is that both outcomes are informative.**

    pages rise from 23   the host walk is the gate on unpacking. The stealer's
                         runtime becomes reachable, and the FLOSS strings of
                         `0m` become behaviour instead of capability
    pages stay at 23     "no host" is NOT what stops it. The decision is
                         somewhere else entirely and the 02 Sep reading, though
                         still true about the walk, does not explain the silence

Every number below is printed from what happened, and the RUN CHECK voids the
run when EIP is still inside the payload -- a budget that expires mid-execution
reports "44 pages never ran" in the shape of a real negative.
"""
from __future__ import annotations

import argparse
import collections
from pathlib import Path

from unicorn import UC_HOOK_BLOCK, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000

#: The payload image, from `stage4_declined.py`. 67 pages.
PAY, PLEN = 0x3E93C74, 0x42C00

#: The twelve, in walk order (`0at`).
CANDIDATES = ("compact.exe", "msiexec.exe", "AtBroker.exe", "write.exe",
              "runonce.exe", "cacls.exe", "regini.exe", "replace.exe",
              "wextract.exe", "label.exe", "netbtugc.exe", "SearchFilterHost.exe")

#: This host has no WordPad, so `write.exe` is absent and gets a stand-in. The
#: experiment is about the walk proceeding, not about which image it proceeds
#: with.
STAND_IN = Path(r"C:\Windows\SysWOW64\label.exe")

#: What the process half of the loop would use, if it were reached.
INJECTION_APIS = ("CreateProcessInternalW", "NtQueryInformationProcess",
                  "NtCreateSection", "NtMapViewOfSection",
                  "NtWriteVirtualMemory", "NtOpenProcess",
                  "NtResumeThread", "NtUnmapViewOfSection")


def serve_leaf(nt_path: str) -> bytes | None:
    """The old, unfaithful lookup -- by leaf, for the candidates only."""
    name = nt_path.rsplit("\\", 1)[-1].lower()
    if name not in {c.lower() for c in CANDIDATES}:
        return None
    for folder in (r"C:\Windows\SysWOW64", r"C:\Windows\System32"):
        candidate = Path(folder) / name
        if candidate.is_file():
            return candidate.read_bytes()
    return STAND_IN.read_bytes() if STAND_IN.is_file() else b""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--serve", action="store_true",
                    help="answer the twelve candidates with real bytes. This "
                         "INVENTS THE MACHINE -- see the module docstring")
    ap.add_argument("--instructions", type=int, default=4_000_000_000)
    args = ap.parse_args(argv)

    served = {"count": 0}
    real_backing = Emulator.backing

    def backing(self, nt_path: str) -> bytes:
        if args.serve:
            data = serve_leaf(nt_path)
            if data is not None:
                served["count"] += 1
                return data
        return real_backing(self, nt_path)

    Emulator.backing = backing

    emu = Emulator.restore(args.state)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)

    executed: set[int] = set()
    writes: collections.Counter = collections.Counter()
    emu.mu.hook_add(UC_HOOK_BLOCK, lambda u, a, s, x: executed.add(a),
                    begin=PAY, end=PAY + PLEN - 1)
    emu.mu.hook_add(UC_HOOK_MEM_WRITE,
                    lambda u, t, a, s, v, x: writes.update([a & ~0xFFF]),
                    begin=PAY, end=PAY + PLEN - 1)

    before = collections.Counter(emu.calls)
    start = emu.blocks
    mode = "SERVED (invented)" if args.serve else "faithful"
    print(f"mode: {mode}\n", flush=True)

    status = emu.resume(count=args.instructions)
    ran = emu.blocks - start
    eip = emu.mu.reg_read(UC_X86_REG_EIP)

    print(f"RUN CHECK: {ran:,} blocks, budget {args.instructions:,} instructions")
    print(f"           ended at eip {eip:#010x} -- {status}")
    if PAY <= eip < PAY + PLEN:
        print(f"\n*** VOID: EIP is still inside the payload (+{eip - PAY:#x}), "
              f"so the budget ran out\n    mid-execution. Every page count "
              f"below would be a lie of omission.")
        return 2
    print("           EIP left the payload, so execution finished.\n")

    pages = {a & ~0xFFF for a in executed}
    total_pages = (PLEN + 0xFFF) // 0x1000
    stage4 = collections.Counter(emu.calls) - before

    print(f"candidate files answered with bytes: {served['count']}")
    print(f"PAGES EXECUTED: {len(pages)} of {total_pages}"
          f"    (baseline, 0j: 23 of 67)")
    print(f"pages written into: {len(writes)}"
          f"    (in-place decryption would show here)")
    print(f"distinct blocks in the payload: {len(executed)}")

    print("\nstage 4's own calls on the process half:")
    for name in INJECTION_APIS:
        print(f"    {name:<28} {stage4.get(name, 0)}")

    print("\n--- what this run says")
    attempted = stage4.get("CreateProcessInternalW", 0)
    granted = sum(1 for c in emu.control_calls
                  if c.get("call") == "CreateProcessInternalW"
                  and c.get("resolved"))
    unpacked = len(pages) > 30
    print(f"  creates attempted {attempted}, GRANTED {granted}, "
          f"pages {len(pages)} of {total_pages}")

    # **The discriminator is whether a host was OBTAINED, not whether a create
    # was attempted.** The first version of this concluded "no host is not what
    # stops it" from twelve creates that all failed -- the payload had no more
    # of a host than in the faithful run, so that run tested nothing. Same
    # shape as the summary lines this chain has already retracted three times.
    if args.serve and granted and unpacked:
        print(f"  A host was obtained and execution went from 23 pages to "
              f"{len(pages)}. **The host")
        print("  walk gates the unpacking**, and the stealer's runtime is "
              "reachable from here.")
    elif args.serve and granted:
        print("  A host WAS obtained and the page count did not move. "
              "Obtaining a host is not")
        print("  what unpacks it.")
    elif args.serve:
        print(f"  The walk reached the create -- {attempted} attempts, up from "
              f"0 -- and every one")
        print("  FAILED, because the path is still malformed. So the read "
              "gates the create, which")
        print("  is experiment B confirmed a third way. But the payload had no "
              "host here either,")
        print("  and **this run does not test whether a host would change "
              "anything**.")
        print("  `0af` already did: with creates granted and the target's PEB "
              "readable it made")
        print("  ONE create, read ImageBaseAddress once, slept twelve times "
              "and returned --")
        print("  `0ah`, no APIs at all after the last sleep. **A granted host "
              "did not unpack it.**")
    else:
        print(f"  Faithful baseline: {len(pages)} pages, {attempted} create(s).")
        print("  Run again with --serve for the comparison.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
