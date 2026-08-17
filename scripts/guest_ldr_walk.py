"""Walk the guest's `PEB->Ldr` from the crash dump, the way the sample does.

**This is not the measurement `0aw` and `0ax` already made, and the difference
is the whole point.** `0aw` hashed Procmon's `Load Image` events; `0ax` hashed
the dump's `MODULE_LIST` and `UNLOADED_MODULE_LIST` streams. Both are a
*writer's* view of what was loaded -- Procmon's from its driver, the minidump's
from `MiniDumpWriteDump` enumerating the loader at dump time.

`get_module_base_by_hash` at rva `0x2dc01` sees none of that. It walks
`PEB->Ldr->InLoadOrderModuleList` in the process's own memory, lowercases each
`BaseDllName`, CRC-32s it, and returns `DllBase` on a match. **That list is in
the dump too**, as ordinary memory, and it is the only artifact that shows what
the sample itself would have seen. If it disagrees with the streams -- an extra
entry, a corrupted name, a truncated or looped list -- that is the answer to the
question this file has carried since 10 Aug.

    ..\\.venv\\Scripts\\python.exe guest_ldr_walk.py [dump]

The walk is deliberately literal: same list, same field offsets, same
lowercasing, same CRC, same early-exit on match. Where it can no longer follow
the list it says so rather than returning a short answer, because "the walk
found nothing" and "the walk stopped" are the distinction the whole question
turns on.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dynamic_analysis import minidump  # noqa: E402

DUMP = r"C:\Users\aring\Downloads\ringforge\outputs\RegSvcs.exe.5272.dmp"

#: The gate's hash: `crc32("sbiedll.dll")` under this sample's variant.
WANTED = 0xE11DA208

#: Everything else this project is still carrying, so one walk answers them all.
ALSO = {
    0x5C4EE455: 'cracked: "wow64"',
    0x79DBE71D: 'cracked: "sychpe32"',
    0x0B4E1AE2: 'cracked: "ntdll.dll" -- the self-check',
}

#: 32-bit PEB / PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY offsets.
PEB_LDR = 0x0C
LDR_IN_LOAD_ORDER = 0x0C
ENTRY_DLL_BASE = 0x18
ENTRY_SIZE_OF_IMAGE = 0x20
ENTRY_FULL_NAME = 0x24
ENTRY_BASE_NAME = 0x2C

#: A loader list longer than this is a loop or a corrupt Flink, not a process.
MAX_ENTRIES = 4096


def crc(name: bytes) -> int:
    """CRC-32/MPEG-2: init 0xFFFFFFFF, non-reflected, poly 0x04C11DB7, final NOT.

    The same function as `crash_gate_check.py`, kept in step by the assertion in
    `main` rather than by hope -- `crc(b"ntdll.dll")` is a value this project has
    independently confirmed twice.
    """
    value = 0xFFFFFFFF
    for byte in name:
        value ^= byte << 24
        for _ in range(8):
            value = ((value << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if value & 0x80000000 \
                else (value << 1) & 0xFFFFFFFF
    return (~value) & 0xFFFFFFFF


class DumpMemory:
    """Random access to the dump's captured memory by virtual address."""

    def __init__(self, dump: minidump.Minidump) -> None:
        self._data = dump._data
        self._ranges = sorted(dump.memory_ranges())

    def read(self, va: int, length: int) -> bytes | None:
        for base, file_offset, size in self._ranges:
            if base <= va < base + size:
                if va + length > base + size:
                    return None          # straddles a gap; a short read would lie
                start = file_offset + (va - base)
                return bytes(self._data[start:start + length])
        return None

    def u32(self, va: int) -> int | None:
        blob = self.read(va, 4)
        return struct.unpack("<I", blob)[0] if blob else None

    def unicode_string(self, va: int) -> tuple[str, str]:
        """A 32-bit UNICODE_STRING at `va`, and why it failed if it did."""
        header = self.read(va, 8)
        if not header:
            return "", "descriptor not in the dump"
        length, _maximum, buffer = struct.unpack("<HHI", header)
        if not buffer:
            return "", "null buffer"
        if length == 0:
            return "", "zero length"
        raw = self.read(buffer, length)
        if raw is None:
            return "", f"buffer {buffer:#x} not in the dump"
        try:
            return raw.decode("utf-16-le"), ""
        except UnicodeDecodeError:
            return "", f"undecodable: {raw[:16].hex(' ')}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump", nargs="?", default=DUMP)
    args = ap.parse_args(argv)

    assert crc(b"ntdll.dll") == 0x0B4E1AE2, "the CRC variant does not match"

    path = Path(args.dump)
    dump = minidump.parse(path)
    info = dump.system_info()
    print(f"{path.name}  {path.stat().st_size:,} bytes, {info.get('architecture')}")
    if info.get("architecture") != "x86":
        print("*** VOID: the 32-bit loader list is what the sample walks and "
              "this is not a\n    32-bit dump. The offsets below would be wrong.")
        return 2

    memory = DumpMemory(dump)
    threads = dump.threads()
    if not threads:
        print("*** VOID: no thread list, so there is no TEB to start from.")
        return 2

    teb = threads[0]["teb"]
    peb = memory.u32(teb + 0x30)
    print(f"TEB {teb:#010x} -> PEB {peb:#010x}" if peb else
          f"*** VOID: TEB {teb:#010x} is not in the dump.")
    if not peb:
        return 2
    ldr = memory.u32(peb + PEB_LDR)
    if not ldr:
        print(f"*** VOID: PEB {peb:#010x} is in the dump but Ldr is not "
              f"readable.")
        return 2
    head = ldr + LDR_IN_LOAD_ORDER
    print(f"PEB -> Ldr {ldr:#010x}, InLoadOrderModuleList head {head:#010x}\n")

    entries: list[dict] = []
    problems: list[str] = []
    seen: set[int] = set()
    link = memory.u32(head)
    while link and link != head:
        if link in seen:
            problems.append(f"list loops back to {link:#x}")
            break
        if len(entries) >= MAX_ENTRIES:
            problems.append(f"more than {MAX_ENTRIES} entries; giving up")
            break
        seen.add(link)
        base = memory.u32(link + ENTRY_DLL_BASE)
        size = memory.u32(link + ENTRY_SIZE_OF_IMAGE)
        name, why = memory.unicode_string(link + ENTRY_BASE_NAME)
        full, _ = memory.unicode_string(link + ENTRY_FULL_NAME)
        if why:
            problems.append(f"entry at {link:#x}: BaseDllName {why}")
        entries.append({"entry": link, "base": base or 0, "size": size or 0,
                        "name": name, "full": full,
                        "hash": crc(name.lower().encode()) if name else None})
        nxt = memory.u32(link)
        if nxt is None:
            problems.append(f"entry at {link:#x}: Flink not in the dump -- "
                            f"the walk STOPPED here, it did not finish")
            break
        link = nxt

    print(f"{'#':<4} {'DllBase':<12} {'hash':<12} BaseDllName")
    print(f"{'-' * 4} {'-' * 12} {'-' * 12} {'-' * 40}")
    hit = None
    for index, entry in enumerate(entries):
        mark = ""
        if entry["hash"] == WANTED:
            mark = "   <<<< THE GATE'S HASH"
            hit = entry
        elif entry["hash"] in ALSO:
            mark = f"   <- {ALSO[entry['hash']]}"
        digest = f"{entry['hash']:#010x}" if entry["hash"] is not None else "--"
        print(f"{index:<4} {entry['base']:#010x}   {digest:<12} "
              f"{entry['name'] or '(unreadable)'}{mark}")

    print(f"\nENTRIES WALKED: {len(entries)}")
    if problems:
        print("PROBLEMS -- the walk did not complete cleanly:")
        for line in problems:
            print(f"   *** {line}")

    # The dump writer's view, for comparison. A disagreement here is the finding.
    streamed = {m["path"].rsplit("\\", 1)[-1].lower() for m in dump.modules()}
    walked = {e["name"].lower() for e in entries if e["name"]}
    print(f"\nAGAINST THE MODULE_LIST STREAM ({len(streamed)} entries):")
    only_walk = sorted(walked - streamed)
    only_stream = sorted(streamed - walked)
    if not only_walk and not only_stream:
        print("   Identical. The sample's own view and the writer's view agree, "
              "so 0ax's negative")
        print("   covers the list the gate actually walks and is not merely a "
              "statement about")
        print("   what MiniDumpWriteDump chose to report.")
    else:
        for name in only_walk:
            print(f"   *** in the LOADER LIST but not the stream: {name}")
        for name in only_stream:
            print(f"   *** in the stream but not the loader list: {name}")

    print(f"\nDOES ANYTHING HASH TO {WANTED:#010x}?")
    if hit:
        print(f"   *** YES -- {hit['name']!r} at {hit['base']:#010x}")
        print(f"       {hit['full']}")
        print("   The gate was right, the guest genuinely had it, and the "
              "question becomes what")
        print("   put it there -- including the possibility that it is the "
              "analysis tooling.")
    elif problems:
        print("   No match among the entries reached -- **but the walk did not "
              "complete.** That is")
        print("   not a negative. A module past the break would be invisible "
              "here and visible to")
        print("   the sample, which is exactly the gap this probe exists to "
              "close.")
    else:
        print("   No, and the walk completed cleanly, so this is a real "
              "negative over the list")
        print("   the gate itself reads. The contradiction survives its last "
              "cheap explanation:")
        print("   the sample walked this list, found nothing, and stored the "
              "poison anyway.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
