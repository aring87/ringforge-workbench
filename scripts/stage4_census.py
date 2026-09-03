"""The stage-4 host walk, on the branch a real machine actually reaches.

`0at` made `CreateProcessInternalW` validate its path and left every stage-4
finding from `0ad` to `0as` carrying *"given a create it should not have been
granted"*. This is the re-run that removes the qualifier. It captures every
`NtCreateFile` path and every `CreateProcessInternalW` `lpApplicationName` in
order, paired by candidate, so the walk can be read per name rather than as a
count.

    set RINGFORGE_EXPLORER_CHILD=1
    ..\\.venv\\Scripts\\python.exe stage4_census.py

The toggle is not optional: `after_handshake.state` was written with it and
`restore()` refuses a resume that contradicts the state's env toggles.

**What it found, against what it was written to look for.** The hypothesis was
*two constructions* -- a well-formed path for the file it opens and a doubled
one for the process it creates, which would have shown the sample is capable of
the right string. **There is one construction and it is doubled everywhere**:
all twelve opens and all eleven creates carry `C:C:\\`. The routine never
produces a usable name for any candidate, so reading 1 of `0aq` covers the whole
walk rather than one call.

**The directory is `System32`, not the `SysWOW64` `0as` recorded.** A 32-bit
process's loader entry carries the *unredirected* path -- `winenv` has this
measured and commented at `LOADER_SYSTEM_DIR` -- and this builder appends
whatever is in `FullDllName`. Both forms are rejected identically, so no
conclusion turned on it, but the IOC does.

**The `C:C:\\...` rejection is measured, not modelled.** See
`scripts/real_createprocess_paths.py`: the real `CreateProcessW` on this bench
returns `ERROR_INVALID_NAME` for all twelve doubled paths, and
`winenv.resolve_dos_path` agrees with the real API on every input tried. That is
what entitles this run's failures to be read as a real machine's failures.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"

#: Where the injected code starts, and the stack it starts on. The snapshot does
#: **not** carry these -- resuming from the state's own EIP faults after 13
#: blocks -- so every probe that runs stage 4 sets them explicitly, as
#: `stage4_gate.py` does.
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000

#: The twelve, in walk order (`0at`). Used only to label rows.
CANDIDATES = ("compact.exe", "msiexec.exe", "AtBroker.exe", "write.exe",
              "runonce.exe", "cacls.exe", "regini.exe", "replace.exe",
              "wextract.exe", "label.exe", "netbtugc.exe", "SearchFilterHost.exe")

_LEAF = re.compile(r"[^\\/]+$")


def leaf(path: str) -> str:
    match = _LEAF.search(path or "")
    return match.group(0) if match else ""


def is_doubled(path: str) -> bool:
    """A `X:` volume followed by something that is not a separator.

    The `\\??\\` prefix is stripped first. Without that, an open path indexes
    `?` where the volume colon belongs and reads as well formed -- which is how
    the first version of this probe confirmed its own hypothesis.
    """
    text = path or ""
    if text.startswith("\\??\\"):
        text = text[4:]
    return len(text) > 2 and text[1] == ":" and text[2] not in "\\/"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--instructions", type=int, default=4_000_000_000,
                    help="INSTRUCTIONS, not blocks -- emu_start's count is "
                         "instructions and a truncated run reports 'nothing "
                         "happened' in the shape of a real negative.")
    args = ap.parse_args(argv)

    path = Path(args.state)
    if not path.exists():
        print(f"*** VOID: {path} is missing. This run needs the checkpoint; "
              f"there is nothing\n    to measure without it.")
        return 2

    emu = Emulator.restore(str(path))
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)
    print(f"restored {path.name} at {emu.blocks:,} blocks, running stage 4 "
          f"from {INJECT_EIP:#x}\n", flush=True)

    start_blocks = emu.blocks
    status = emu.resume(count=args.instructions)
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    print(f"stopped: {status} after {emu.blocks - start_blocks:,} further "
          f"blocks ({emu.blocks:,} total), eip {eip:#010x}")

    creates = [c for c in emu.control_calls
               if c.get("call") == "CreateProcessInternalW"]
    opens = list(emu.files)

    # RUN CHECK, naming its observation. A run cut short by the budget produces
    # a short walk, which reads exactly like a walk that ended early for a
    # reason -- and that is the `0aa` shape this project has hit four times.
    # **Zero creates is a RESULT now, not only a truncation.** This guard was
    # written when the harness answered every open by leaf name, so a walk that
    # ran always produced creates and their absence could only mean the run was
    # cut short. Since `backing` resolves the path instead, the faithful outcome
    # of a walk built on `C:C:\...` is zero creates -- and the guard called that
    # VOID, which is a check written for the expected case reporting the
    # measured one as a failure.
    #
    # The walk's own opens are the discriminator: a run cut short has neither,
    # a faithful run has twelve opens and no create.
    candidate_opens = [o for o in opens if leaf(o.get("path", "")) in CANDIDATES]
    if not creates and not candidate_opens:
        print("\n*** VOID: no CreateProcessInternalW call and no candidate open "
              "in this run at\n    all. Either the budget ran out before the "
              "walk or the checkpoint is past\n    it. Nothing below is a "
              "statement about the sample.")
        return 2
    if not creates:
        refused = getattr(emu, "refused_opens", [])
        print(f"\nNO CREATES, AND THE WALK RAN: {len(candidate_opens)} "
              f"candidate open(s), 0 create(s).")
        print(f"    {len(refused)} open(s) resolved to nothing on this machine, "
              f"which is what a real\n    machine does with every path this "
              f"walk builds. Stage 4 reads each candidate\n    and declines an "
              f"empty one, so it declines all of them.")
        print("    This is the faithful outcome, not a truncated run -- see "
              "`backing` and 0aq.")

    print(f"\nTHE WALK: {len(opens)} file open(s), {len(creates)} create(s)\n")
    print(f"{'#':<3} {'NtCreateFile called with':<44} "
          f"{'created (lpApplicationName)':<44}")
    print(f"{'-' * 3} {'-' * 44} {'-' * 44}")

    by_leaf: dict[str, dict[str, str]] = {}
    for entry in opens:
        name = leaf(entry.get("path", ""))
        by_leaf.setdefault(name, {})["open"] = entry.get("path", "")
    for entry in creates:
        name = leaf(entry.get("image", ""))
        by_leaf.setdefault(name, {})["create"] = entry.get("image", "")

    for index, name in enumerate(CANDIDATES):
        row = by_leaf.get(name, {})
        opened = row.get("open", "--")
        created = row.get("create", "--")
        print(f"{index:<3} {opened:<44} {created:<44}")
    extra = sorted(set(by_leaf) - set(CANDIDATES))
    for name in extra:
        row = by_leaf[name]
        print(f"{'':<3} {row.get('open', '--'):<44} "
              f"{row.get('create', '--'):<44}   (not a candidate)")

    # The comparison this run exists for.
    #
    # **Strip `\??\` first.** The open paths carry the NT prefix, so a doubling
    # test that indexes `path[1]` sees `?` and calls every one of them well
    # formed. The first version of this did exactly that and printed "the same
    # routine builds a correct path for the file it opens and a doubled one for
    # the process it creates" -- the hypothesis this probe was written to test,
    # produced by a broken detector rather than by the run.
    doubled_creates = [c["image"] for c in creates if is_doubled(c.get("image", ""))]
    candidate_opens = [e.get("path", "") for e in opens
                       if leaf(e.get("path", "")) in CANDIDATES]
    doubled_opens = [p for p in candidate_opens if is_doubled(p)]

    print(f"\nONE CONSTRUCTION OR TWO?")
    print(f"   creates with a doubled volume        : "
          f"{len(doubled_creates)} of {len(creates)}")
    print(f"   candidate opens with a doubled volume: "
          f"{len(doubled_opens)} of {len(candidate_opens)}")
    if doubled_creates and len(doubled_opens) == len(candidate_opens):
        print("\n   **One construction, and it is doubled everywhere.** The "
              "open path and the create")
        print("   path carry the same defect, so this routine never produces a "
              "usable name for any")
        print("   of the twelve. Reading 1 of 0aq covers the whole walk rather "
              "than one call.")
    elif doubled_creates and doubled_opens:
        print("\n   **Two constructions.** Some opens are well formed while "
              "every create is doubled,")
        print("   so the sample can build the right string and does on one "
              "path.")
    elif doubled_creates:
        print("\n   Creates doubled, opens clean -- two constructions, and the "
              "sample is capable of")
        print("   the correct string. The doubling is a defect in one of them.")
    elif doubled_opens and not creates:
        # The faithful case since `backing` started resolving paths: every open
        # is doubled, every open resolves to nothing, and the walk therefore
        # never reaches a create. Saying "contradicts 0as" here would be this
        # probe reporting its own correctness as a fault.
        print("\n   **One construction, and it never reaches a create.** All "
              f"{doubled_opens} candidate opens")
        print("   are doubled and none resolves, so stage 4 declines every "
              "candidate and creates")
        print("   nothing. `0as` saw doubled creates because the harness then "
              "answered opens by")
        print("   leaf name; it no longer does. Consistent with 0as, not a "
              "contradiction of it.")
    else:
        print("\n   No doubled create in this run, and opens are not doubled "
              "either, which")
        print("   contradicts 0as. Settle that before reading anything else "
              "here.")

    # The volume the whole thing is built from, which is not what 0as recorded.
    directories = {p.rsplit("\\", 1)[0] for p in candidate_opens}
    print(f"\n   directory built from: {', '.join(sorted(directories)) or '--'}")

    failed = [c for c in creates if not c.get("resolved")]
    print(f"\nCREATES: {len(creates)} attempted, {len(failed)} refused by the "
          f"resolver")
    if len(failed) == len(creates):
        print("   All of them, which is what the real CreateProcessW does with "
              "these strings")
        print("   (ERROR_INVALID_NAME, measured -- real_createprocess_paths.py). "
              "So prepare_host")
        print("   returns 0 on a real machine and the rendezvous is never "
              "reached, exactly as 0at")
        print("   found. **That census is now standing on a measurement rather "
              "than an assumption.**")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
