"""What kind of memory holds the guest's copies of `0x32dfd514`?

`0ax` counted them -- 3 inside stage 3's image and 7 elsewhere -- and `0az`
described the seven as **heap**, against a bench run that put its three on the
**stack**. The 17 Aug pick-up entry then named that difference "the only
structural difference left on that path ... the obvious next thread."

The word was never measured. This classifies every copy against the dump's own
`THREAD_LIST` (stack bounds) and `MEMORY_INFO_LIST` (State/Type/Protect), which
is what `dynamic_analysis.minidump` grew `threads()`, `memory_info()` and
`region_of()` for.

    ..\\.venv\\Scripts\\python.exe guest_cookie_regions.py <dump>

The census is a byte scan, deliberately: it re-derives `0ax`'s numbers from the
file instead of trusting them, and the two agreeing is the check that this is
reading the same dump the same way.
"""
from __future__ import annotations

import argparse
import collections
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dynamic_analysis import minidump  # noqa: E402

DUMP = r"C:\Users\aring\Downloads\ringforge\outputs\RegSvcs.exe.5272.dmp"
POISON = 0x32DFD514

#: Where stage 3 was executing on the guest, and how big it is. `0ax` read the
#: fault at `0x01012c7c` as rva `0x2c7c` of this region.
STAGE3 = 0x01010000
STAGE3_SIZE = 0x46000

#: What `0ax` recorded, so a disagreement is loud rather than quiet.
EXPECTED_INSIDE = (0xD809, 0x16065, 0x2DCA9)
EXPECTED_OUTSIDE = 7

_PROTECT = {0x01: "NOACCESS", 0x02: "R", 0x04: "RW", 0x08: "RWC", 0x10: "X",
            0x20: "RX", 0x40: "RWX", 0x80: "RWXC"}


def protect_name(value: int) -> str:
    name = _PROTECT.get(value & ~0x100, f"{value:#x}")
    return name + ("+GUARD" if value & 0x100 else "")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump", nargs="?", default=DUMP)
    args = ap.parse_args(argv)

    path = Path(args.dump)
    dump = minidump.parse(path)
    print(f"{path.name}  {path.stat().st_size:,} bytes")

    threads = dump.threads()
    print(f"\nTHREADS: {len(threads)}")
    for thread in threads:
        print(f"   tid {thread['thread_id']:<7} teb {thread['teb']:#012x}  "
              f"stack {thread['stack_base']:#010x}..{thread['stack_end']:#010x} "
              f"({thread['stack_size']:,} bytes captured)")

    regions = dump.memory_info()
    print(f"REGIONS: {len(regions)}")
    if dump.warnings:
        print("WARNINGS:", *dump.warnings, sep="\n   ")

    def describe(addr: int) -> tuple[str, str]:
        for thread in threads:
            if thread["stack_base"] <= addr < thread["stack_end"]:
                return "stack", f"THREAD STACK of tid {thread['thread_id']}"
        region = dump.region_of(addr)
        if region is None:
            return "unknown", "no region info"
        kind = region["type_name"]
        return kind, (f"{kind.upper()} {region['state_name'].upper()} "
                      f"{protect_name(region['protect'])}  region "
                      f"{region['base']:#x}+{region['size']:#x}")

    needle = struct.pack("<I", POISON)
    hits: list[int] = []
    for va, file_offset, size in dump.memory_ranges():
        # `memory_ranges` returns (virtual_address, FILE OFFSET, size). Reading
        # that tuple as (va, size, offset) produced 559 hits at plausible-looking
        # addresses -- a wrong answer that looks like a finding, which is the
        # reason this comment is here.
        blob = bytes(dump._data[file_offset:file_offset + size])
        start = 0
        while True:
            i = blob.find(needle, start)
            if i < 0:
                break
            hits.append(va + i)
            start = i + 1

    inside = [a for a in hits if STAGE3 <= a < STAGE3 + STAGE3_SIZE]
    outside = [a for a in hits if a not in set(inside)]

    print(f"\nCOPIES OF {POISON:#010x}: {len(hits)}\n")
    kinds: collections.Counter = collections.Counter()
    for addr in sorted(hits):
        kind, text = describe(addr)
        if addr in set(inside):
            print(f"   {addr:#010x}   rva {addr - STAGE3:#07x} of stage 3   {text}")
        else:
            kinds[kind] += 1
            print(f"   {addr:#010x}   {text}")

    print(f"\nAGAINST 0ax's CENSUS ({len(EXPECTED_INSIDE)} inside, "
          f"{EXPECTED_OUTSIDE} outside):")
    got_rvas = tuple(sorted(a - STAGE3 for a in inside))
    if got_rvas == tuple(sorted(EXPECTED_INSIDE)) and len(outside) == EXPECTED_OUTSIDE:
        print("   Reproduced exactly, so this is the same dump read the same way.")
    else:
        print(f"   **DISAGREES**: {len(inside)} inside at "
              f"{', '.join(hex(r) for r in got_rvas)}, {len(outside)} outside.")
        print("   Settle that before reading anything below.")

    print("\nWHAT THE SEVEN ACTUALLY ARE:")
    for kind, count in kinds.most_common():
        print(f"   {kind:<8} {count}")
    if kinds.get("stack", 0) > kinds.get("private", 0):
        print("\n   Overwhelmingly **stack**, not heap. The bench's three are on "
              "its stack too, so")
        print("   0az's structural difference does not exist and the thread it "
              "opened is closed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
