"""Scan emulated memory for stage 4's runtime-built strings.

The IOCs recovered by FLOSS -- the Nokia user agent, the SQLite URL, the browser
credential paths -- are **not byte-contiguous anywhere in the decrypted stage**.
Checked: 30 candidates, ascii and wide, zero hits, and not even as the 4-byte
`mov [ebp-X], imm32` chunks a stack string would leave behind. They are produced
by code that runs, so the only image that can hold them is a running one.

That matters because a YARA rule keyed on those strings is unfalsifiable until
somebody produces the image it is supposed to match. This script produces it:
restore a checkpoint, run stage 4, then sweep **every mapped region** for each
candidate and report where it landed and in what encoding.

    ..\\.venv\\Scripts\\python.exe scan_stage4_memory.py --state <after_decrypt.state>

`--dump-hits` writes the regions that matched, so a real `yara` binary can be run
against them rather than trusting this script's own substring search.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from unicorn import UC_HOOK_BLOCK
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_decrypt.state"

#: Every string the 16 Aug FLOSS pass recovered, plus the substrings a rule would
#: realistically key on. Grouped so the report says which capability fired.
CANDIDATES: dict[str, tuple[str, ...]] = {
    "user_agent": (
        "Nokia5130c-2/2.0 (07.97) Profile/MIDP-2.1 Configuration/CLDC-1.1",
        "Nokia5130c-2",
        "MIDP-2.1",
        "CLDC-1.1",
    ),
    "sqlite_fetch": (
        "http://www.sqlite.org/2014/sqlite-dll-win32-x86-3080300.zip",
        "sqlite-dll-win32-x86-3080300.zip",
        "sqlite.org",
    ),
    "browser_paths": (
        r"Internet Explorer\IntelliForms\Storage2",
        "IntelliForms",
        "Local State",
        "Chrome",
        "Firefox",
        "Cookies",
        "Autofill",
    ),
    "http": (
        "gzip, deflate, br",
        "no-cache",
        "200OK",
    ),
    "environment": (
        "windir",
        "ProgramFiles",
        "Program Files",
        "SysWOW64",
        r"\explorer.exe",
    ),
}


def sweep(emu: Emulator, dump_dir: Path | None) -> dict[str, list[tuple[str, int, str]]]:
    """Read every mapped region once and search it for every candidate."""
    found: dict[str, list[tuple[str, int, str]]] = {}
    for begin, end, _perms in emu.mu.mem_regions():
        size = end - begin + 1
        try:
            blob = bytes(emu.mu.mem_read(begin, size))
        except Exception as exc:  # a region can be unreadable after a fault
            print(f"  !! {begin:#x}-{end:#x} unreadable: {exc}")
            continue
        hit_here = False
        for group, needles in CANDIDATES.items():
            for needle in needles:
                for enc, raw in (("ascii", needle.encode("latin-1")),
                                 ("wide", needle.encode("utf-16-le"))):
                    at = blob.find(raw)
                    if at < 0:
                        continue
                    hit_here = True
                    found.setdefault(group, []).append((needle, begin + at, enc))
        if hit_here and dump_dir is not None:
            out = dump_dir / f"region_{begin:08x}_{size}.bin"
            out.write_bytes(blob)
            print(f"  region {begin:#x} ({size:,} bytes) written to {out.name}")
    return found


#: Short and distinctive, so a sweep every few million blocks stays cheap.
WATCH_NEEDLES = ("Nokia5130c-2", "sqlite-dll", "IntelliForms", "Local State",
                 "Autofill", "gzip, deflate, br")


def _run_watching(emu: Emulator, budget: int, every: int) -> str:
    """Sweep from inside emulation, without interrupting it.

    The end-of-run sweep is structurally blind: `--survey` showed stage 4 zeroing
    two 64 KB regions on its way out, so anything it built is gone before it
    returns. Whatever it holds has to be caught while it holds it.

    **Do not do that by chunking `resume()`.** The first version of this did, and
    the run length tracked the chunk size -- 4.40M blocks at 250K chunks,
    16.10M at 2M chunks, against 16.10M unchunked. Every sweep was therefore
    sampling a truncated run, and a clean "nothing sighted" meant nothing. A
    block hook sweeps the same points without restarting `emu_start`.

    Only the regions a runtime-built string can live in are scanned -- the stack
    and the two 64 KB regions the payload wipes -- so the sweep is ~1 MB rather
    than the 134 MB section, and can run often enough to catch something built
    and destroyed inside one window.
    """
    seen: dict[str, int] = {}
    watched = [(0x10000000, 0x100FFFFF), (0x03EE0000, 0x03EFFFFF)]
    encoded = [(n, e, s.encode("latin-1") if e == "ascii" else s.encode("utf-16-le"))
               for n in WATCH_NEEDLES for e, s in (("ascii", n), ("wide", n))]
    state = {"next": every}

    def on_block(uc, addr, size, user):
        if emu.blocks < state["next"]:
            return
        state["next"] = emu.blocks + every
        for begin, end in watched:
            try:
                blob = bytes(uc.mem_read(begin, end - begin + 1))
            except Exception:
                continue
            for needle, enc, raw in encoded:
                if needle in seen:
                    continue
                at = blob.find(raw)
                if at >= 0:
                    seen[needle] = emu.blocks
                    print(f"  [{emu.blocks:>13,}blk] FIRST SIGHTING "
                          f"{needle!r} ({enc}) at {begin + at:#010x}")

    handle = emu.mu.hook_add(UC_HOOK_BLOCK, on_block)
    try:
        status = emu.resume(count=budget)
    finally:
        emu.mu.hook_del(handle)
    if not seen:
        print(f"  (nothing sighted in {len(watched)} watched region(s), "
              f"swept every {every:,} blocks)")
    return status


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--eip", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--esp", type=lambda v: int(v, 0), default=0)
    # INSTRUCTIONS, not blocks -- `emu_start`'s count is an instruction budget,
    # and 60M stops this payload mid-scan at 16,096,220 blocks. 400M reaches the
    # real end at 42,072,701. See the handoff, 0aa.
    ap.add_argument("--blocks", type=int, default=400_000_000,
                    metavar="INSTRUCTIONS")
    ap.add_argument("--dump-hits", default=None,
                    help="directory to write each matching region into, so the "
                         "real yara binary can be pointed at them")
    ap.add_argument("--no-run", action="store_true",
                    help="sweep the state as restored, without running it -- the "
                         "control that says whether running is what produced a hit")
    ap.add_argument("--watch", type=int, default=0, metavar="BLOCKS",
                    help="sweep every BLOCKS during the run instead of only at "
                         "the end. Stage 4 zeroes two 64 KB regions on its way "
                         "out, so a string that existed while it ran is gone by "
                         "the time it returns -- an end-only sweep cannot see it")
    args = ap.parse_args(argv)

    print(f"restoring {args.state}")
    emu = Emulator.restore(args.state)
    print(f"  restored at {emu.blocks:,} blocks")

    dump_dir = None
    if args.dump_hits:
        dump_dir = Path(args.dump_hits)
        dump_dir.mkdir(parents=True, exist_ok=True)

    if args.no_run:
        print("\n-- control sweep, state as restored --")
    else:
        # A bare resume is wrong for the checkpoints on the artifact drive: they
        # were saved while the *loader* held the machine, so EIP points into
        # ntdll and resuming faults at zero blocks. That failure produced a
        # clean-looking "no strings found" on the first attempt here, which is
        # the same false negative this chain has manufactured four times before.
        # So seed the injected thread explicitly, exactly as follow_injection.py
        # does, and refuse to sweep if nothing actually ran.
        if args.eip:
            emu.mu.reg_write(UC_X86_REG_EIP, args.eip)
        if args.esp:
            emu.mu.reg_write(UC_X86_REG_ESP, args.esp)
        started = emu.blocks
        eip = emu.mu.reg_read(UC_X86_REG_EIP)
        print(f"\nrunning up to {args.blocks:,} blocks from eip {eip:#x}")
        if args.watch:
            status = _run_watching(emu, args.blocks, args.watch)
        else:
            status = emu.resume(count=args.blocks)
        ran = emu.blocks - started
        end_eip = emu.mu.reg_read(UC_X86_REG_EIP)
        print(f"  stopped: {status} at {emu.blocks:,} blocks ({ran:,} executed), "
              f"eip {end_eip:#010x}")
        if 0x3E93C74 <= end_eip < 0x3E93C74 + 0x42C00:
            print("  *** VOID: EIP is still inside the payload, so the budget "
                  "ran out mid-execution. A sweep that found nothing would mean "
                  "nothing. Raise the instruction budget.")
            return 2
        if ran < 1000:
            print("\n*** VOID: the run executed almost nothing, so a sweep now "
                  "measures the checkpoint, not stage 4. Seed --eip/--esp.")
            return 2

    print("\nsweeping mapped memory")
    found = sweep(emu, dump_dir)

    print()
    print("=" * 72)
    total = sum(len(v) for v in found.values())
    if not total:
        print("NO CANDIDATE STRING IS PRESENT IN MEMORY.")
        print("A string-based rule cannot match this image. Do not write one on")
        print("the assumption that a real dump would differ -- find out why the")
        print("strings did not materialise first.")
        return 1
    for group in CANDIDATES:
        hits = found.get(group, [])
        print(f"\n{group}: {len(hits)} hit(s)")
        for needle, addr, enc in hits:
            shown = needle if len(needle) <= 52 else needle[:49] + "..."
            print(f"    {addr:#010x}  {enc:5}  {shown!r}")
    print()
    print(f"{total} hits across {len(found)} of {len(CANDIDATES)} capability groups.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
