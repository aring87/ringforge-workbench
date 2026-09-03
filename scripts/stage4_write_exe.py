"""Why does `write.exe` alone skip the create? Serve it bytes and find out.

`fbdf40b` left this open and reasoned it could not be file presence: the open
path is `C:C:\\Windows\\System32\\write.exe`, which names nothing on any
machine, so all twelve should fail identically.

**That reasoning is right about a real machine and wrong about this harness.**
`Emulator.backing` resolves by **leaf name** against the host's `SysWOW64` and
then `System32`, ignoring the doubled prefix entirely -- so inside the emulator
each candidate is answered with the bench's real bytes. Measured on this host:

    eleven candidates   present in SysWOW64, 15 KB - 452 KB, all x86
    write.exe           ABSENT from both directories

WordPad was removed from Windows 11, so `write.exe` is the one leaf `backing`
cannot answer, and it returns `b""`.

**So the hypothesis is that stage 4 vets each candidate by reading it and
declines an empty one.** This tests that by intervention rather than by
argument: `--serve` answers `write.exe` with another candidate's bytes and asks
whether the create then happens. Inference from disassembly has been wrong every
time on this payload, and inference from a plausible mechanism is no better.

    set RINGFORGE_EXPLORER_CHILD=1
    ..\\.venv\\Scripts\\python.exe stage4_write_exe.py            # baseline
    ..\\.venv\\Scripts\\python.exe stage4_write_exe.py --serve    # with bytes

**Read the result carefully, because it decides whose behaviour this is.** If
serving bytes produces a twelfth create, the skip is an artifact of what this
bench happens to have installed, and the census's "eleven creates" is partly
harness-shaped -- the same class as the eleven-host walk of `0af`. If it changes
nothing, the skip is the sample's and something else distinguishes the name.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000

#: The leaf this bench cannot answer, and the one whose bytes stand in for it.
#: `label.exe` because it is the smallest of the eleven and nothing about the
#: experiment depends on which real image is served.
MISSING = "write.exe"
STAND_IN = Path(r"C:\Windows\SysWOW64\label.exe")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--serve", action="store_true",
                    help=f"answer {MISSING} with {STAND_IN.name}'s bytes")
    ap.add_argument("--instructions", type=int, default=4_000_000_000)
    args = ap.parse_args(argv)

    if args.serve and not STAND_IN.is_file():
        print(f"*** VOID: {STAND_IN} is not on this host, so there are no "
              f"bytes to serve.")
        return 2

    served = STAND_IN.read_bytes() if args.serve else b""
    real_backing = Emulator.backing
    hits = {"asked": 0}

    def backing(self, nt_path: str) -> bytes:
        if nt_path.rsplit("\\", 1)[-1].lower() == MISSING:
            hits["asked"] += 1
            if args.serve:
                return served
        return real_backing(self, nt_path)

    Emulator.backing = backing

    emu = Emulator.restore(STATE)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    print(f"{MISSING}: serving {len(served):,} bytes"
          if args.serve else f"{MISSING}: serving nothing (the bench's answer)")

    start = emu.blocks
    status = emu.resume(count=args.instructions)
    print(f"stopped: {status} after {emu.blocks - start:,} blocks")

    creates = [c for c in emu.control_calls
               if c.get("call") == "CreateProcessInternalW"]
    names = [str(c.get("detail") or c.get("path") or c) for c in creates]

    print(f"\n{MISSING} opened: {hits['asked']} time(s)")
    print(f"creates: {len(creates)}")

    if not creates:
        print("\n*** VOID: no CreateProcessInternalW in this run at all, so "
              "the walk did not\n    happen and nothing here is a statement "
              "about the sample.")
        return 2

    created_missing = [n for n in names if MISSING.lower() in n.lower()]
    print(f"a create for {MISSING}: {'YES' if created_missing else 'no'}")
    for name in created_missing:
        print(f"    {name}")

    print("\n--- what this run says")
    if args.serve and created_missing:
        print(f"  Serving bytes produced a create for {MISSING}. **The skip is "
              f"an artifact of this bench**, not the sample: stage 4 reads each")
        print("  candidate and declines an empty one, and write.exe is empty "
              "here only because")
        print("  WordPad was removed from Windows 11. The census's eleven "
              "creates are partly")
        print("  harness-shaped -- on a real machine the doubled path fails "
              "every open equally.")
    elif args.serve:
        print(f"  Serving bytes changed nothing: still {len(creates)} creates "
              f"and no {MISSING}.")
        print("  Content is NOT the discriminator, and the skip belongs to the "
              "sample. Something")
        print("  about the name itself is what to look at next.")
    else:
        print(f"  Baseline: {len(creates)} creates, {MISSING} "
              f"{'created' if created_missing else 'skipped'}.")
        print("  Run again with --serve to see whether bytes change it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
