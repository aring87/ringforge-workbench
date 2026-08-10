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
_REFERENCE_CACHE: dict[tuple, Optional[list]] = {}
_CACHE_LIMIT = 96


def _reference_sections(path: str, timestamp: int, size_of_image: int, base: int,
                        roots: Iterable[str] = ()) -> Optional[list]:
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
        return _REFERENCE_CACHE[key]

    sections: Optional[list] = None
    candidates = [Path(path)] + [Path(root) / name for root in roots]
    for candidate in candidates:
        try:
            if not candidate.is_file():
                continue
            pe = pefile.PE(str(candidate), fast_load=True)
        except Exception:
            continue
        with pe:
            if (pe.FILE_HEADER.TimeDateStamp != timestamp
                    or pe.OPTIONAL_HEADER.SizeOfImage != size_of_image):
                continue
            if base != pe.OPTIONAL_HEADER.ImageBase:
                try:
                    pe.parse_data_directories([5])          # BASERELOC
                    pe.relocate_image(base)
                except Exception:
                    # No reloc table, or a malformed one. Refuse rather than
                    # compare unrelocated bytes and call the fixups tampering.
                    break
            sections = []
            for section in pe.sections:
                if not section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
                    continue
                length = min(section.SizeOfRawData,
                             section.Misc_VirtualSize or section.SizeOfRawData)
                if length < MIN_SECTION_BYTES:
                    continue
                sections.append((section.Name.rstrip(b"\0").decode("ascii", "replace"),
                                 section.VirtualAddress,
                                 section.get_data()[:length]))
        break

    if len(_REFERENCE_CACHE) >= _CACHE_LIMIT:
        _REFERENCE_CACHE.clear()
    _REFERENCE_CACHE[key] = sections
    return sections


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
    sections = _reference_sections(module.get("path", ""), module.get("timestamp", 0),
                                   module.get("size", 0), base, roots)
    if sections is None:
        return result
    result["relocated"] = True

    total = differing = 0
    for name, rva, on_disk in sections:
        in_memory = space.read(base + rva, len(on_disk))
        if in_memory is None:
            continue
        diff = _count_differences(on_disk, in_memory)
        total += len(on_disk)
        differing += diff
        result["sections"].append({
            "name": name,
            "bytes": len(on_disk),
            "differing": diff,
            "fraction": round(diff / len(on_disk), 6),
        })

    if not total:
        return result

    fraction = differing / total
    result.update(compared_bytes=total, differing_bytes=differing,
                  differing_fraction=round(fraction, 6))
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
    counts = {"identical": 0, "patched": 0, "replaced": 0, "no_reference": 0}
    replaced: list[dict[str, Any]] = []
    per_dump: list[dict[str, Any]] = []

    for result in results:
        seen = {"identical": 0, "patched": 0, "replaced": 0, "no_reference": 0}
        for module in result.get("modules", []):
            verdict = module.get("verdict", "no_reference")
            counts[verdict] = counts.get(verdict, 0) + 1
            seen[verdict] = seen.get(verdict, 0) + 1
            if verdict == "replaced":
                entry = dict(module)
                entry["dump"] = result.get("dump", "")
                entry["hollowing_target"] = module.get("name", "") in HOLLOWING_TARGETS
                replaced.append(entry)
        per_dump.append({"dump": result.get("dump", ""),
                         "error": result.get("error", ""), **seen})

    compared = counts["identical"] + counts["patched"] + counts["replaced"]
    return {
        "available": compared > 0,
        "counts": counts,
        "modules_compared": compared,
        "replaced": replaced,
        "replaced_in_hollowing_target": sum(1 for r in replaced if r["hollowing_target"]),
        "per_dump": per_dump,
    }
