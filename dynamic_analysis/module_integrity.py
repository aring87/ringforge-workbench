"""Does a loaded module still contain the code its file on disk contains?

**This exists for the blind spot gap 5 documents and cannot cover.** The PE
carver finds a payload mapped *alongside* a real image, because the loader's
module list says no module covers it. The classic hollow -- unmap the target's
image and write the payload over it at the same base -- defeats that completely:
the module list is read from the very memory the payload now occupies, so the
image reports itself as `at_module_base` and there is nothing left to compare
against.

Nothing left *in the dump*. The file the module was loaded from is still on
disk, and a hollowed image differs from it wholesale. That is the comparison
this module makes, and it is the one reading of the 06 Aug 20:23 run that the
carver could not test: `unmapped: 0` on every `RegSvcs` image including the
crash dump made overwrite-in-place the better-supported explanation, and
overwrite-in-place is exactly what this sees.

WHAT MAKES IT MORE THAN A DIFF, in order of how much trouble each one saves:

* **Relocations are applied before comparing, not thresholded around.** A module
  loaded away from its preferred base differs from its file at every fixup, and
  "mostly the same" is a much weaker claim than "identical once relocated".
* **Only executable sections are compared.** `.data` legitimately changes the
  moment the process runs; comparing it would report every module as modified
  and the signal would be worthless -- the standing lesson that a detector which
  fires on everything says nothing about anything.
* **The reference must be the same build.** A guest's `ntdll` against the
  bench's `ntdll` is two different files and would differ for reasons that have
  nothing to do with the sample. `TimeDateStamp` and `SizeOfImage` from the
  dump's own module list have to match the candidate file, or the module is
  reported `no_reference` and counted rather than quietly skipped.

THREE OUTCOMES, because two would collapse the interesting middle:

    identical   relocated file and mapped image agree
    patched     a small fraction differs -- inline hooks. Real and common:
                any EDR or AV that hooks user mode puts them in ntdll's .text,
                and the reference dump this was built against has Bitdefender's
                hooks in it. Reported, never scored.
    replaced    most of the section differs. That is a hollow.

`replaced` in a process that loaders hollow is the finding, and it is the same
`HOLLOWING_TARGETS` test the crash evidence and the carver already use, so a
hollow raises one category rather than three.
"""
from __future__ import annotations

import mmap
from collections import OrderedDict
from pathlib import Path
from typing import Any, Iterable, Optional

from .crash_evidence import HOLLOWING_TARGETS
from .pe_carve import _Region, _streams, read_modules, read_regions

#: A section has to be at least this big before its differing fraction means
#: anything. A 200-byte thunk section reads as "100% replaced" the moment one
#: instruction is patched.
MIN_SECTION_BYTES = 0x400

#: Below this, the difference is hooks. Above it, the code was replaced. The gap
#: between them is deliberately wide: nothing has to be decided in the middle,
#: because the middle is reported as `patched` and left unscored.
PATCHED_ABOVE = 0.001
REPLACED_ABOVE = 0.25

IMAGE_SCN_MEM_EXECUTE = 0x20000000

#: Comparison granularity. Whole-buffer `==` is a memcmp and effectively free;
#: counting differing bytes in Python is not, at roughly a megabyte a second.
#: Since an untampered module differs in a handful of places at most, chunking
#: lets almost every block take the fast path and only the few that actually
#: differ get counted. On the reference dump this is the difference between six
#: minutes and a few seconds -- and it is production code, not just test speed:
#: a run carries a dozen dumps.
_CHUNK = 0x1000


def _count_differences(left: bytes, right: bytes) -> int:
    """Bytes differing between two equal-length buffers."""
    if left == right:
        return 0
    total = 0
    for start in range(0, len(left), _CHUNK):
        a = left[start:start + _CHUNK]
        b = right[start:start + _CHUNK]
        if a != b:
            total += sum(1 for x, y in zip(a, b) if x != y)
    return total


def _image_name(path: str) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


class _AddressSpace:
    """Reads by virtual address across a dump's mapped regions."""

    def __init__(self, data: Any, regions: Iterable[_Region]):
        self._data = data
        self._regions = sorted(regions, key=lambda r: r.va)

    def read(self, va: int, length: int) -> Optional[bytes]:
        """Bytes at `va`, or None if any part of the range is not in the dump.

        Partial reads are refused rather than zero-filled. A zero-filled hole
        would count as a difference and turn an absent page into evidence of
        tampering, which is the same error as reading absence as an answer.
        """
        out = bytearray()
        want = length
        cursor = va
        for region in self._regions:
            if region.va + region.size <= cursor:
                continue
            if region.va > cursor:
                return None                      # a gap inside the range
            offset = cursor - region.va
            take = min(region.size - offset, want)
            start = region.file_offset + offset
            chunk = self._data[start:start + take]
            if len(chunk) != take:
                return None
            out += chunk
            cursor += take
            want -= take
            if not want:
                return bytes(out)
        return None


#: Relocated reference sections, keyed by the module and the base it is loaded
#: at. Relocating an image is the expensive part of this pass -- pefile walks
#: every fixup in Python, and ntdll has tens of thousands -- and a run carries a
#: dozen dumps of processes that share both the same DLLs and the same bases,
#: because ASLR randomises per boot rather than per process. Without this the
#: same relocation is recomputed a dozen times and the pass adds minutes to a
#: teardown this project already considers too slow.
#: `key -> (sections, identity_mismatch)`.
#:
#: The mismatch travels *with* the sections rather than in a second dict, and
#: that is a bug fix rather than tidying. It used to live in a parallel
#: `_MISMATCHED` map written during lookup and read afterwards, with the cache
#: eviction between them:
#:
#:     _MISMATCHED[key] = {...}          # this module disagrees with its file
#:     ...
#:     if len(_REFERENCE_CACHE) >= _CACHE_LIMIT:
#:         _REFERENCE_CACHE.clear()
#:         _MISMATCHED.clear()           # <- including the entry just written
#:     _REFERENCE_CACHE[key] = sections
#:
#: So whichever module happened to cross the 96-entry limit lost its
#: `header_mismatch` and was then graded *by degree* -- exactly the outcome the
#: comment on that branch says must never happen, since a payload sharing most
#: of its bytes with the file it impersonates would file as `identical`. Any
#: process with more than 96 distinct modules could hit it, and a browser or
#: `explorer.exe` has hundreds. One dict cannot desynchronise from itself.
#: **Bounded by bytes with LRU eviction, not by a count with a wholesale clear.**
#: Measured on run `33fe6c3b`: a `powershell.exe` sample carried **380 modules**
#: past a 96-entry limit whose eviction was `_REFERENCE_CACHE.clear()`. The
#: access pattern here is *for each dump, for each module*, so a small cache
#: under a wholesale clear degenerates to no cache at all -- every module's
#: relocation is recomputed on every dump. Module integrity took **24 of that
#: run's 27 minutes**.
#:
#: The cost being avoided is real and was measured on the bench: a full `pefile`
#: parse plus `relocate_image` averages **1,105 ms** per module (`shell32`
#: 1.9 s, `windows.storage` 2.2 s), so ~750 uncached lookups is ~14 minutes here
#: and more on the guest.
#:
#: **A count limit is the wrong bound.** What has to stay bounded is memory --
#: entries hold relocated executable sections, which are megabytes for a large
#: DLL and kilobytes for a small one -- so 96 entries can be 200 MB or 2 MB
#: depending on the process. A byte budget holds the whole working set of an
#: ordinary process while still refusing to grow without limit.
#:
#: **And `fast_load` is not the fix**, measured before this one was written:
#: parsing only `IMAGE_DIRECTORY_ENTRY_BASERELOC` is **1.1x**, because
#: `relocate_image` forces the parse regardless. The resource tree is not the
#: cost. Recorded so nobody spends an afternoon re-deriving it.
_REFERENCE_CACHE: "OrderedDict[tuple, tuple[Optional[list], Optional[dict]]]" = OrderedDict()

#: Roughly one large process's worth of relocated sections.
_CACHE_BYTES_LIMIT = 256 * 1024 * 1024

#: A backstop for pathological inputs -- thousands of tiny modules would stay
#: under the byte budget forever. Far above any observed module count (380 on
#: run `33fe6c3b`, 732 on `e8ab2151`).
_CACHE_ENTRY_LIMIT = 4096

_cache_bytes = 0


def _entry_bytes(sections: Optional[list]) -> int:
    if not sections:
        return 0
    return sum(len(data) for _name, _rva, data, _spans in sections)


def _cache_store(key: tuple, value: tuple) -> None:
    """Insert, then evict least-recently-used until inside both bounds."""
    global _cache_bytes
    if key in _REFERENCE_CACHE:
        _cache_bytes -= _entry_bytes(_REFERENCE_CACHE[key][0])
        del _REFERENCE_CACHE[key]
    _REFERENCE_CACHE[key] = value
    _cache_bytes += _entry_bytes(value[0])
    while _REFERENCE_CACHE and (
            _cache_bytes > _CACHE_BYTES_LIMIT
            or len(_REFERENCE_CACHE) > _CACHE_ENTRY_LIMIT):
        _oldest, evicted = _REFERENCE_CACHE.popitem(last=False)
        _cache_bytes -= _entry_bytes(evicted[0])


def reset_reference_cache() -> None:
    """Drop everything. For tests, and for a caller that wants the memory back."""
    global _cache_bytes
    _REFERENCE_CACHE.clear()
    _cache_bytes = 0


def reference_cache_stats() -> dict[str, int]:
    """Entries and bytes held, so a slow pass can be explained rather than guessed."""
    return {"entries": len(_REFERENCE_CACHE), "bytes": _cache_bytes}


def _mapped_header(space: "_AddressSpace", base: int) -> dict[str, Any]:
    """What the image *in memory* claims about itself.

    When the loader's record and the file disagree, this is the half nobody
    reads: an imposter at a module base carries its own header, and its
    `TimeDateStamp`, `SizeOfImage` and entry point are the first description of
    the payload available without carving it out.
    """
    out: dict[str, Any] = {}
    head = space.read(base, 0x400)
    if not head or head[:2] != b"MZ":
        return out
    try:
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
        if not 0x40 <= e_lfanew < 0x380 or head[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return out
        coff = e_lfanew + 4
        opt = e_lfanew + 24
        # `ImageBase` is the one field that moves between PE32 and PE32+: 4 bytes
        # at +28 after `BaseOfData`, or 8 bytes at +24 with no `BaseOfData` at
        # all. Reading the 32-bit layout on a 64-bit image yields the *top* half
        # of the address and prints as a plausible-looking `0x7fff`, which is
        # the kind of wrong that reads as right. `AddressOfEntryPoint` and
        # `SizeOfImage` sit at the same offsets in both.
        pe32_plus = int.from_bytes(head[opt:opt + 2], "little") == 0x20B
        out = {
            "machine": int.from_bytes(head[coff:coff + 2], "little"),
            "timestamp": int.from_bytes(head[coff + 4:coff + 8], "little"),
            "sections": int.from_bytes(head[coff + 2:coff + 4], "little"),
            "entry_point": int.from_bytes(head[opt + 16:opt + 20], "little"),
            "image_base": int.from_bytes(
                head[opt + 24:opt + 32] if pe32_plus else head[opt + 28:opt + 32],
                "little"),
            "size_of_image": int.from_bytes(head[opt + 56:opt + 60], "little"),
        }
    except Exception:
        return {}
    return out


#: Bytes each base-relocation type rewrites. `ABSOLUTE` is padding and moves
#: nothing, so it is deliberately absent rather than mapped to 0.
_RELOCATION_WIDTHS = {
    1: 2,    # HIGH
    2: 2,    # LOW
    3: 4,    # HIGHLOW
    4: 4,    # HIGHADJ
    10: 8,   # DIR64
}


def _relocation_widths(pe: Any) -> dict[int, int]:
    """`rva -> bytes rewritten`, for every fixup that rewrites anything.

    **This replaces relocating the image, and the reason is measured.** An image
    is relocated here only so its on-disk bytes line up with the copy in memory:
    the fixups are precisely the bytes that legitimately differ. Blanking them
    on both sides compares exactly the same content.

    `pefile.relocate_image` applies every fixup in a Python loop, and on run
    `ff504255` that was 81% of a 28-minute run. Split on the bench for
    `mscorlib.ni.dll`, 22.1 MB and 271,740 fixups:

        open (fast_load) :   0.00s
        parse relocs     :   1.38s
        APPLY relocs     : 186.14s     <- what this avoids

    99.3% of the cost is the apply. Dump 1 of that run held the CLR native
    images -- `clr.dll`, `System.ni.dll`, `mscorlib.ni.dll` -- and took 1,266s
    against 83s for the other four dumps combined.
    """
    widths: dict[int, int] = {}
    for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", None) or []:
        for entry in block.entries:
            width = _RELOCATION_WIDTHS.get(entry.type)
            if width:
                widths[entry.rva] = width
    return widths


def _blank_spans(data: bytes, spans: Iterable[tuple[int, int]]) -> bytes:
    """`data` with each `(offset, width)` zeroed.

    Applied to the reference once when it is cached and to the in-memory copy at
    each comparison. Zeroed rather than skipped so `_count_differences` keeps its
    C-speed `left == right` fast path, which is what makes an unmodified module
    free to check.
    """
    spans = list(spans)
    if not spans:
        return data
    out = bytearray(data)
    limit = len(out)
    for offset, width in spans:
        if 0 <= offset and offset + width <= limit:
            out[offset:offset + width] = bytes(width)
    return bytes(out)


def _reference_sections(
    path: str, timestamp: int, size_of_image: int, base: int,
    roots: Iterable[str] = (),
) -> tuple[Optional[list], Optional[dict]]:
    """Executable sections of the file this module came from, relocated to
    `base`. `None` when this host has no matching build.

    Identity is `TimeDateStamp` plus `SizeOfImage`, the same fingerprint the
    carver's known-module index uses. Matching on path alone would compare a
    guest's binary against the bench's copy of a different build and call the
    difference tampering.

    Returns `[(section name, rva, bytes)]`, or `None`. An empty list is a real
    answer -- a module with no comparable executable section -- and is not the
    same as no reference at all.
    """
    import pefile

    name = _image_name(path)
    if not name:
        return None
    key = (name, timestamp, size_of_image, base)
    if key in _REFERENCE_CACHE:
        # Move to the end: this is what makes the eviction LRU rather
        # than FIFO, and the access pattern here rewards it.
        _REFERENCE_CACHE.move_to_end(key)
        return _REFERENCE_CACHE[key]

    sections: Optional[list] = None
    mismatch: Optional[dict] = None
    candidates = [Path(path)] + [Path(root) / name for root in roots]
    for candidate in candidates:
        try:
            if not candidate.is_file():
                continue
            pe = pefile.PE(str(candidate), fast_load=True)
        except Exception:
            continue
        with pe:
            matched = (pe.FILE_HEADER.TimeDateStamp == timestamp
                       and pe.OPTIONAL_HEADER.SizeOfImage == size_of_image)
            if not matched:
                # **Do not skip.** An earlier version returned here, and that
                # single `continue` is what walked past this sample's payload: a
                # second image claiming to be `RegSvcs.exe`, mapped at the
                # preferred base `0x400000` while the real one sat relocated and
                # byte-identical elsewhere. Its header does not match the file
                # *because it is not that file*, which is the finding, not a
                # reason to stop looking. The comparison still runs; the verdict
                # records that the identity check failed.
                mismatch = {
                    "file_timestamp": pe.FILE_HEADER.TimeDateStamp,
                    "file_size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
                    "module_timestamp": timestamp,
                    "module_size_of_image": size_of_image,
                    "reference": str(candidate),
                }
            fixups: dict[int, int] = {}
            if base != pe.OPTIONAL_HEADER.ImageBase:
                try:
                    pe.parse_data_directories([5])          # BASERELOC
                    fixups = _relocation_widths(pe)
                except Exception:
                    # No reloc table, or a malformed one. Refuse rather than
                    # compare unrelocated bytes and call the fixups tampering.
                    break
                if not fixups:
                    break
            sections = []
            for section in pe.sections:
                if not section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
                    continue
                length = min(section.SizeOfRawData,
                             section.Misc_VirtualSize or section.SizeOfRawData)
                if length < MIN_SECTION_BYTES:
                    continue
                data = section.get_data()[:length]
                # Offsets *within this section* that a fixup rewrites. The
                # image is never relocated; both sides are blanked at these
                # positions instead, which compares the same bytes for a
                # fraction of the cost. See `_relocation_widths`.
                spans = [(rva - section.VirtualAddress, width)
                         for rva, width in fixups.items()
                         if section.VirtualAddress <= rva
                         < section.VirtualAddress + length]
                sections.append((
                    section.Name.rstrip(b"\0").decode("ascii", "replace"),
                    section.VirtualAddress,
                    _blank_spans(data, spans),
                    spans))
        break

    _cache_store(key, (sections, mismatch))
    return sections, mismatch


def compare_module(space: _AddressSpace, module: dict[str, Any],
                   roots: Iterable[str] = ()) -> dict[str, Any]:
    """One module's executable sections, mapped versus on disk."""
    base = module["base"]
    result: dict[str, Any] = {
        "name": _image_name(module.get("path", "")),
        "path": module.get("path", ""),
        "base": base,
        "verdict": "no_reference",
        "compared_bytes": 0,
        "differing_bytes": 0,
        "differing_fraction": 0.0,
        "sections": [],
        "relocated": False,
    }

    # Relocated to where the module actually sits, so the comparison is exact
    # rather than approximate: without it every ASLR-relocated system DLL reads
    # as lightly modified and the threshold would have to be loosened to cover
    # fixups, which is exactly the slack a hollow would hide in.
    sections, mismatch = _reference_sections(
        module.get("path", ""), module.get("timestamp", 0),
        module.get("size", 0), base, roots)
    if mismatch:
        # Whatever is mapped here is not the file the loader named. Describe it
        # from its own header, which is the cheapest description of a payload
        # there is -- no carving required.
        result["identity"] = mismatch
        result["mapped_header"] = _mapped_header(space, base)
    if sections is None:
        # A known identity disagreement outranks having nothing to compare.
        # The `if not total` branch below already applies that rule when there
        # were sections but none was readable; this exit did not, so the same
        # knowledge produced `header_mismatch` on one path and `no_reference`
        # -- *could not tell* -- on the other.
        #
        # **Not a demonstrated bug.** Reaching it needs `mismatch` set and
        # `sections` None, which means the reference opened, disagreed, and
        # then failed to relocate; pefile tolerated every malformed reloc
        # directory tried, so it is written as a guard rather than a fix. The
        # rule is what matters: never report *could not tell* about something
        # already known.
        if mismatch:
            result["verdict"] = "header_mismatch"
        return result
    result["relocated"] = True

    total = differing = 0
    for name, rva, on_disk, spans in sections:
        in_memory = space.read(base + rva, len(on_disk))
        if in_memory is None:
            continue
        # The reference was blanked at its fixups when it was built; blank
        # the same positions here so both sides omit the bytes the loader
        # legitimately rewrote. Equivalent to relocating, minus the 186s.
        diff = _count_differences(on_disk, _blank_spans(in_memory, spans))
        total += len(on_disk)
        differing += diff
        result["sections"].append({
            "name": name,
            "bytes": len(on_disk),
            "differing": diff,
            "fraction": round(diff / len(on_disk), 6),
        })

    if not total:
        if mismatch:
            result["verdict"] = "header_mismatch"
        return result

    fraction = differing / total
    result.update(compared_bytes=total, differing_bytes=differing,
                  differing_fraction=round(fraction, 6))
    if mismatch:
        # Reported by *identity*, not by degree. A module whose header disagrees
        # with its file is a different image whatever fraction of bytes happens
        # to coincide, and letting a low fraction downgrade it to `identical`
        # would hide precisely the case this exists for.
        result["verdict"] = "header_mismatch"
        return result
    if fraction > REPLACED_ABOVE:
        result["verdict"] = "replaced"
    elif fraction > PATCHED_ABOVE:
        result["verdict"] = "patched"
    else:
        result["verdict"] = "identical"
    return result


def analyze_dump(path: str | Path, roots: Iterable[str] = ()) -> dict[str, Any]:
    """Every module in one dump, compared against its file."""
    path = Path(path)
    out: dict[str, Any] = {"dump": path.name, "modules": [], "error": ""}
    try:
        with open(path, "rb") as handle:
            data = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                size = len(data)
                streams = _streams(data, size)
                modules = read_modules(data, size, streams)
                space = _AddressSpace(data, read_regions(data, size, streams))
                if not modules:
                    out["error"] = "no module list in this dump"
                    return out
                for module in modules:
                    out["modules"].append(compare_module(space, module, roots))
            finally:
                data.close()
    except OSError as exc:
        out["error"] = str(exc)
    return out


def summarize_module_integrity(results: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Reduce per-dump results to what the run summary and report carry.

    `no_reference` is a first-class count, not a silent skip. On a guest whose
    binaries this bench does not have, *every* module lands there and the pass
    says nothing at all -- which has to read as "could not tell" rather than as
    "nothing was modified". Same shape as `collection_available` in gap 4b.
    """
    blank = {"identical": 0, "patched": 0, "replaced": 0,
             "header_mismatch": 0, "no_reference": 0}
    counts = dict(blank)
    replaced: list[dict[str, Any]] = []
    mismatched: list[dict[str, Any]] = []
    unreferenced: list[dict[str, Any]] = []
    per_dump: list[dict[str, Any]] = []

    for result in results:
        seen = dict(blank)
        for module in result.get("modules", []):
            verdict = module.get("verdict", "no_reference")
            counts[verdict] = counts.get(verdict, 0) + 1
            seen[verdict] = seen.get(verdict, 0) + 1
            entry = dict(module)
            entry["dump"] = result.get("dump", "")
            entry["hollowing_target"] = module.get("name", "") in HOLLOWING_TARGETS
            if verdict == "replaced":
                replaced.append(entry)
            elif verdict == "header_mismatch":
                mismatched.append(entry)
            elif verdict == "no_reference":
                # Named, not merely counted. Counting it made "could not tell"
                # visible; only naming it says *what* could not be told, and on
                # the first live run the unnamed one was the whole answer.
                unreferenced.append({k: entry[k] for k in
                                     ("dump", "name", "base", "path", "hollowing_target")
                                     if k in entry})
        per_dump.append({"dump": result.get("dump", ""),
                         "error": result.get("error", ""), **seen})

    compared = counts["identical"] + counts["patched"] + counts["replaced"]
    return {
        "available": compared > 0,
        "counts": counts,
        "modules_compared": compared,
        "replaced": replaced,
        "replaced_in_hollowing_target": sum(1 for r in replaced if r["hollowing_target"]),
        "header_mismatch": mismatched,
        "header_mismatch_in_hollowing_target":
            sum(1 for m in mismatched if m["hollowing_target"]),
        "no_reference_modules": unreferenced,
        "per_dump": per_dump,
    }


def main(argv: list[str] | None = None) -> int:
    """Re-run this pass over dumps already on disk.

    Exists because the first live run answered the wrong question -- the module
    that mattered was skipped by an identity check -- and re-detonating to ask
    again would have been absurd when the dumps were sitting in the case
    directory. A detector that can only be exercised by a new detonation is a
    detector that gets exercised rarely.

        python -m dynamic_analysis.module_integrity <dump-or-directory> [...]
    """
    import argparse
    import json

    parser = argparse.ArgumentParser(description=main.__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+", help="a .dmp, or a directory of them")
    parser.add_argument("--json", metavar="FILE", help="write the full result here")
    parser.add_argument("--root", action="append", default=[],
                        help="extra directory to look for reference binaries in")
    args = parser.parse_args(argv)

    dumps: list[Path] = []
    for raw in args.paths:
        path = Path(raw)
        dumps.extend(sorted(path.glob("*.dmp")) if path.is_dir() else [path])
    if not dumps:
        print("no dumps found")
        return 1

    results = [analyze_dump(d, args.root) for d in dumps]
    summary = summarize_module_integrity(results)

    print(f"{len(dumps)} dump(s), {summary['modules_compared']} module(s) compared")
    print(f"counts: {summary['counts']}")
    for entry in summary["header_mismatch"]:
        head = entry.get("mapped_header") or {}
        ident = entry.get("identity") or {}
        print(f"\n  *** HEADER MISMATCH  {entry['name']} @ {entry['base']:#x}"
              f"{'  (a process loaders hollow)' if entry['hollowing_target'] else ''}")
        print(f"      in {entry['dump']}")
        print(f"      loader says  timestamp {ident.get('module_timestamp', 0):#010x} "
              f"size_of_image {ident.get('module_size_of_image', 0):#x}")
        print(f"      the file has timestamp {ident.get('file_timestamp', 0):#010x} "
              f"size_of_image {ident.get('file_size_of_image', 0):#x}")
        if head:
            print(f"      the image in memory claims: timestamp "
                  f"{head.get('timestamp', 0):#010x}  size_of_image "
                  f"{head.get('size_of_image', 0):#x}  entry {head.get('entry_point', 0):#x}"
                  f"  image_base {head.get('image_base', 0):#x}"
                  f"  sections {head.get('sections', 0)}")
        if entry.get("compared_bytes"):
            print(f"      compared anyway: {entry['differing_fraction']:.4f} of "
                  f"{entry['compared_bytes']} bytes differ")
    for entry in summary["replaced"]:
        print(f"\n  *** REPLACED  {entry['name']} @ {entry['base']:#x}  "
              f"{entry['differing_fraction']:.4f} differing  in {entry['dump']}")
    if summary["no_reference_modules"]:
        print("\n  no reference on this host (named, so a skip cannot pass for a pass):")
        for entry in summary["no_reference_modules"]:
            print(f"    {entry['name']} @ {entry['base']:#x}  {entry['dump']}")

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1), encoding="utf-8")
        print(f"\nwritten to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
