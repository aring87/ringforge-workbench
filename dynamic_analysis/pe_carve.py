"""PE images found inside a memory dump that the loader never mapped.

A dump is an image of an address space, and the one question worth asking of it
that YARA cannot is structural: *is there a second executable in here that
Windows did not put there?* That is what process hollowing and reflective
loading leave behind, and unlike a signature match it does not depend on anyone
having written a rule for the family.

The method is the one that worked by hand on 05 Aug, when the .NET loader's
stage-2 payload was recovered from a WER crash dump: find `MZ` headers, follow
`e_lfanew` to the PE signature, and compare what you find against the image that
is supposed to be there. It took one small script and produced the single most
informative artifact of that investigation -- an obfuscated 56 KB .NET assembly
that matched no rule in the set, from three runs that had otherwise reported
nothing at all.

**The module list is what makes this precise.** A minidump carries the process's
own loader data: every module Windows mapped, with its base address and size. A
PE header at an address no module covers was not mapped by the loader. Every
legitimate DLL in the dump is covered by definition, so the check answers
"foreign?" directly rather than by a heuristic about what a normal process
contains.

Four classifications come out of it, and only the first is treated as evidence:

- ``unmapped`` -- no module covers the address, and the image carries code.
  This is the finding.
- ``resource_only`` -- unmapped, but with no code in it. Windows maps localised
  resource files as data into every process, so this fires constantly and means
  nothing; see ``_RESOURCE_ONLY_NOTE``, which is the reason the test is "a PE
  that could execute" rather than "a PE".
- ``inside_module`` -- a second PE within a module's range but not at its base.
  Real loaders produce this occasionally (a DLL stored in a resource section),
  so it is reported and not scored.
- ``at_module_base`` -- an ordinary loaded module. Counted and otherwise ignored.

**What this cannot do.** The classic overwrite-in-place hollow, where the payload
is written over the host image at its original base, lands at ``at_module_base``
and is invisible here: the module list is read from the same memory the payload
now occupies, so there is nothing left to compare against. The 05 Aug sample
mapped its payload alongside the real image rather than over it, which is what
made it visible. This widens injection detection; it does not close it.

Nothing here raises into a run. A truncated dump, an unreadable stream or a
malformed header costs that dump and nothing else.
"""

from __future__ import annotations

import datetime as _datetime
import mmap
import os
import struct
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from dynamic_analysis.crash_evidence import is_hollowing_target
from dynamic_analysis.utils import sha256_file

StatusCallback = Optional[Callable[[str], None]]

#: 'MDMP'. A dump that does not start with this is not a minidump, whatever its
#: extension says.
_MINIDUMP_SIGNATURE = b"MDMP"

_MODULE_LIST_STREAM = 4
_MEMORY_LIST_STREAM = 5
_MEMORY64_LIST_STREAM = 9

#: MINIDUMP_MODULE is a fixed 108 bytes: base, size, checksum, timestamp, name
#: RVA, then VS_FIXEDFILEINFO and two location descriptors that are not needed
#: here.
_MODULE_ENTRY_SIZE = 108

_MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "arm",
    0x01C4: "armnt",
    0xAA64: "arm64",
    0x0200: "ia64",
}

#: IMAGE_FILE_EXECUTABLE_IMAGE. A payload written into another process is an
#: executable image; requiring this discards the bulk of the incidental `MZ`
#: bytes that turn up in any large dump.
_FILE_EXECUTABLE_IMAGE = 0x0002
_FILE_DLL = 0x2000

#: IMAGE_SECTION_HEADER is 40 bytes; Characteristics is the last field.
_SECTION_ENTRY_SIZE = 40
_SCN_CNT_CODE = 0x00000020
_SCN_MEM_EXECUTE = 0x20000000

#: Why an image with no code in it is not reported.
#:
#: Found by running this over a real minidump of an idle Python process, which
#: reported eleven unmapped PE images. All eleven were genuine: two sections,
#: ``.rdata`` and ``.rsrc``, no code, IMAGE_FILE_DLL set. They are MUI resource
#: files -- Windows loads localised resources with LOAD_LIBRARY_AS_DATAFILE,
#: which maps the image without registering it with the loader, so it is
#: correctly absent from the module list.
#:
#: That is not a parser bug; the images really are there and really are
#: unmapped. It is a claim problem: a signal that fires on every process on the
#: machine says nothing about any of them. So the test is narrowed from "a PE"
#: to "a PE that could execute" -- SizeOfCode, an entry point, or a section
#: marked executable. A hollowing payload has all three; a resource file has
#: none.
#:
#: The synthetic dumps in the test suite could never have shown this. They only
#: contain what the test author thought to put in them.
_RESOURCE_ONLY_NOTE = "no code: not an executable payload"

#: Bounds on what will be believed as a PE header. Each one exists to reject
#: coincidental bytes rather than to characterise malware: two ASCII letters
#: appear constantly in a few hundred megabytes of heap.
_MAX_E_LFANEW = 0x1000
_MIN_SIZE_OF_IMAGE = 0x1000
_MAX_SIZE_OF_IMAGE = 512 * 1024 * 1024
_MAX_SECTIONS = 96

#: Data directory index 14 is the CLR header. Its presence is what makes an
#: image a .NET assembly, which matters because a managed payload explains both
#: why a signature set can match nothing and why the fault address sat outside
#: the image.
_CLR_DIRECTORY_INDEX = 14

#: Per-image carve ceiling. A carved image is a memory-aligned copy of what was
#: mapped, so it is bounded by SizeOfImage; this is the guard against a
#: malformed header claiming half a gigabyte.
DEFAULT_MAX_CARVE_BYTES = 64 * 1024 * 1024

#: Per-dump ceiling on carved images. A dump with dozens of unmapped PEs is
#: either an unusual sample or a parser being fooled, and neither is worth
#: filling the case directory over. The records are kept either way.
DEFAULT_MAX_CARVED_PER_DUMP = 8


class _Region:
    """One contiguous slice of the address space, and where it sits in the file."""

    __slots__ = ("va", "file_offset", "size")

    def __init__(self, va: int, file_offset: int, size: int):
        self.va = va
        self.file_offset = file_offset
        self.size = size


# ---------------------------------------------------------------------------
# Minidump structure
# ---------------------------------------------------------------------------

def _u16(data: Any, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: Any, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: Any, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _streams(data: Any, size: int) -> dict[int, tuple[int, int]]:
    """Stream type -> (rva, size), from the minidump directory."""
    if size < 32 or data[:4] != _MINIDUMP_SIGNATURE:
        raise ValueError("not a minidump (bad signature)")

    stream_count = _u32(data, 8)
    directory_rva = _u32(data, 12)

    streams: dict[int, tuple[int, int]] = {}
    for index in range(stream_count):
        entry = directory_rva + index * 12
        if entry + 12 > size:
            break
        stream_type = _u32(data, entry)
        data_size = _u32(data, entry + 4)
        rva = _u32(data, entry + 8)
        if rva + data_size <= size:
            streams[stream_type] = (rva, data_size)
    return streams


def _minidump_string(data: Any, size: int, rva: int) -> str:
    if rva <= 0 or rva + 4 > size:
        return ""
    length = _u32(data, rva)
    start = rva + 4
    if length <= 0 or start + length > size:
        return ""
    try:
        return data[start:start + length].decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return ""


def read_modules(data: Any, size: int, streams: dict[int, tuple[int, int]]) -> list[dict[str, Any]]:
    """The loader's own module list: what Windows mapped, and where."""
    location = streams.get(_MODULE_LIST_STREAM)
    if not location:
        return []

    rva, stream_size = location
    if rva + 4 > size:
        return []

    count = _u32(data, rva)
    modules: list[dict[str, Any]] = []
    for index in range(count):
        entry = rva + 4 + index * _MODULE_ENTRY_SIZE
        if entry + _MODULE_ENTRY_SIZE > size or entry + _MODULE_ENTRY_SIZE > rva + stream_size + 4:
            break
        base = _u64(data, entry)
        image_size = _u32(data, entry + 8)
        timestamp = _u32(data, entry + 16)
        name_rva = _u32(data, entry + 20)
        modules.append(
            {
                "base": base,
                "size": image_size,
                "timestamp": timestamp,
                "path": _minidump_string(data, size, name_rva),
            }
        )
    return modules


def read_regions(data: Any, size: int, streams: dict[int, tuple[int, int]]) -> list[_Region]:
    """Mapped memory ranges, as (virtual address -> file offset) slices.

    Full dumps (``procdump -ma``) use Memory64List, whose data is one contiguous
    run starting at ``BaseRva``. Minidumps use MemoryList, where each range
    carries its own file location. Both are read because a crash dump written
    with DumpType=1 is still worth looking at, even though it may not contain
    the injected region at all.
    """
    regions: list[_Region] = []

    location = streams.get(_MEMORY64_LIST_STREAM)
    if location:
        rva, _ = location
        if rva + 16 <= size:
            count = _u64(data, rva)
            base_rva = _u64(data, rva + 8)
            offset = base_rva
            for index in range(count):
                entry = rva + 16 + index * 16
                if entry + 16 > size:
                    break
                start_va = _u64(data, entry)
                data_size = _u64(data, entry + 8)
                if offset + data_size > size:
                    # A dump truncated mid-write. Everything before the cut is
                    # still readable, so the loop keeps what it has.
                    remaining = max(0, size - offset)
                    if remaining:
                        regions.append(_Region(start_va, offset, remaining))
                    break
                regions.append(_Region(start_va, offset, data_size))
                offset += data_size
        return regions

    location = streams.get(_MEMORY_LIST_STREAM)
    if location:
        rva, _ = location
        if rva + 4 <= size:
            count = _u32(data, rva)
            for index in range(count):
                entry = rva + 4 + index * 16
                if entry + 16 > size:
                    break
                start_va = _u64(data, entry)
                data_size = _u32(data, entry + 8)
                data_rva = _u32(data, entry + 12)
                if data_rva + data_size <= size:
                    regions.append(_Region(start_va, data_rva, data_size))

    return regions


# ---------------------------------------------------------------------------
# PE headers
# ---------------------------------------------------------------------------

#: A TimeDateStamp past this is not a date at all.
#:
#: Microsoft's reproducible builds put a *hash* in the field rather than a build
#: time, so system binaries carry values that decode to absurd futures --
#: ntdll.dll on the reference guest reads `0xd277d290`, which renders as
#: 2081-11-22. The old bound was the year 2100, so that came out as a plausible
#: looking date and six copies of ntdll were reported as a payload "compiled"
#: after the analyst's lifetime. A date in the future is a signal that the field
#: is not a date, and saying nothing is better than saying something false.
_MAX_PLAUSIBLE_YEAR = _datetime.datetime.now(_datetime.timezone.utc).year + 1


def _iso_timestamp(value: int) -> str:
    """A PE TimeDateStamp as a date, or "" when it is not one.

    Kept as text next to the raw value rather than replacing it: the raw value
    is what a header comparison is done on, and the date is what makes "this
    image is four years newer than the process it is sitting in" legible.
    """
    if value <= 0 or value > 0xFFFFFFFF:
        return ""
    try:
        stamp = _datetime.datetime.fromtimestamp(value, _datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    if not (1990 <= stamp.year <= _MAX_PLAUSIBLE_YEAR):
        return ""
    return stamp.strftime("%Y-%m-%d")


def _has_executable_section(data: Any, table: int, sections: int, limit: int) -> bool:
    """True if any section header is marked as code or executable."""
    for index in range(sections):
        entry = table + index * _SECTION_ENTRY_SIZE
        if entry + _SECTION_ENTRY_SIZE > limit:
            return False
        try:
            characteristics = _u32(data, entry + 36)
        except struct.error:
            return False
        if characteristics & (_SCN_CNT_CODE | _SCN_MEM_EXECUTE):
            return True
    return False


def _file_layout_size(data: Any, table: int, sections: int, limit: int) -> int:
    """How many bytes the image occupies as a *file*, or 0 if unreadable.

    `SizeOfImage` is the mapped footprint -- what the loader spreads the image
    into once section boundaries are rounded up to pages. A payload that has not
    been mapped yet is smaller than that, and comparing the two is what made a
    complete carve report itself as truncated.

    That is not an edge case. `Assembly.Load(byte[])`, and every decrypt-into-a-
    buffer-then-map loader, holds the payload in file layout: exactly the state
    a dump of the *unpacking* process catches it in. SmartOptimization.dll
    declares SizeOfImage 0x14000 while its sections sum to about 54 KB, so a
    carve holding every byte of it read as 24 KB short.

    The end of the last section's raw data is the file's end.
    """
    end = 0
    for index in range(sections):
        entry = table + index * _SECTION_ENTRY_SIZE
        if entry + _SECTION_ENTRY_SIZE > limit:
            return 0
        try:
            raw_size = _u32(data, entry + 16)
            raw_ptr = _u32(data, entry + 20)
        except struct.error:
            return 0
        if raw_ptr and raw_size:
            end = max(end, raw_ptr + raw_size)
    return end


def parse_pe_header(data: Any, offset: int, limit: int) -> Optional[dict[str, Any]]:
    """Read a PE header at ``offset``, or ``None`` if it is not one.

    ``limit`` is the end of the memory region the candidate was found in. A
    header is only believed when every field it needs is inside the same region:
    two bytes reading `MZ` at the very end of one range and unrelated bytes
    following it in the file is exactly the coincidence this rejects.
    """
    if offset + 0x40 > limit:
        return None

    try:
        e_lfanew = _u32(data, offset + 0x3C)
    except struct.error:
        return None

    if not (0x40 <= e_lfanew <= _MAX_E_LFANEW):
        return None

    pe = offset + e_lfanew
    if pe + 0x78 > limit:
        return None

    try:
        if data[pe:pe + 4] != b"PE\x00\x00":
            return None

        machine = _u16(data, pe + 4)
        sections = _u16(data, pe + 6)
        timestamp = _u32(data, pe + 8)
        optional_size = _u16(data, pe + 20)
        characteristics = _u16(data, pe + 22)

        optional = pe + 24
        magic = _u16(data, optional)
    except struct.error:
        return None

    if machine not in _MACHINE_NAMES:
        return None
    if not (1 <= sections <= _MAX_SECTIONS):
        return None
    if optional_size < 0x60:
        return None
    if magic not in (0x10B, 0x20B):
        return None
    if not characteristics & _FILE_EXECUTABLE_IMAGE:
        return None

    try:
        size_of_image = _u32(data, optional + 56)
    except struct.error:
        return None

    if not (_MIN_SIZE_OF_IMAGE <= size_of_image <= _MAX_SIZE_OF_IMAGE):
        return None
    # SizeOfImage is rounded up to SectionAlignment, which is a page on every
    # image that will ever be mapped. A value that is not is a coincidence.
    if size_of_image % 0x1000:
        return None

    try:
        size_of_code = _u32(data, optional + 4)
        entry_point = _u32(data, optional + 16)
    except struct.error:
        return None

    section_table = pe + 24 + optional_size
    carries_code = bool(size_of_code or entry_point) or _has_executable_section(
        data, section_table, sections, limit
    )
    file_size = _file_layout_size(data, section_table, sections, limit)

    # The data directory sits after the 96-byte (PE32) or 112-byte (PE32+) fixed
    # part of the optional header.
    directory = optional + (112 if magic == 0x20B else 96)
    dotnet = False
    try:
        clr_entry = directory + _CLR_DIRECTORY_INDEX * 8
        if clr_entry + 8 <= limit and clr_entry + 8 <= pe + 24 + optional_size:
            dotnet = _u32(data, clr_entry) != 0
    except struct.error:
        dotnet = False

    return {
        "machine": _MACHINE_NAMES.get(machine, hex(machine)),
        "sections": sections,
        "timestamp": timestamp,
        "timestamp_hex": f"0x{timestamp:08x}",
        "compiled": _iso_timestamp(timestamp),
        "size_of_image": size_of_image,
        # The image's size as a file, against SizeOfImage as a mapping. Which of
        # the two applies is decided per image in _resolve_layout.
        "file_size": file_size,
        "dotnet": dotnet,
        "is_dll": bool(characteristics & _FILE_DLL),
        # See _RESOURCE_ONLY_NOTE. An image with no code in it is not a payload,
        # and Windows maps a dozen of them into every process.
        "carries_code": carries_code,
    }


def _resolve_layout(header: dict[str, Any], available: int) -> tuple[str, int, bool]:
    """Decide how much of an image is really there. Returns (layout, want, truncated).

    An image found in memory is in one of two shapes, and they are different
    sizes:

    - **mapped** -- the loader has spread it out, section boundaries rounded up
      to pages, occupying `SizeOfImage`;
    - **file** -- the raw bytes, as they would sit on disk, ending after the last
      section's raw data.

    Judging everything against `SizeOfImage` made a complete carve of a
    file-layout payload report itself 24 KB short, and every such payload would
    have done the same forever. `Assembly.Load(byte[])` and every
    decrypt-then-map loader hold their payload this way, which is exactly the
    state a dump of the unpacking process catches.

    Mapped is tested first: an image big enough to be the mapping is the
    mapping. Only when it is not, and the bytes reach the end of the file
    layout, is it a complete file.
    """
    mapped = int(header.get("size_of_image", 0) or 0)
    file_size = int(header.get("file_size", 0) or 0)

    if mapped and available >= mapped:
        return "mapped", mapped, False
    if file_size and available >= file_size:
        return "file", file_size, False
    return ("file" if file_size and file_size < mapped else "mapped"), available, True


def _candidates(data: Any, region: _Region) -> Iterator[int]:
    """File offsets of page-aligned `MZ` within one region.

    Alignment is the cheap filter and it is a strong one. Both a mapped image
    and a manually mapped payload begin on a page boundary; `MZ` inside a buffer
    holding a copy of a file almost never does.
    """
    start = region.file_offset
    end = region.file_offset + region.size
    # Whatever the region's own alignment, the address is what has to be aligned.
    skew = (-region.va) % 0x1000
    position = start + skew

    while position < end:
        found = data.find(b"MZ", position, end)
        if found < 0:
            return
        if (region.va + (found - region.file_offset)) % 0x1000 == 0:
            yield found
            position = found + 0x1000
        else:
            position = found + 1


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _image_chunks(
    ordered: list["_Region"], index: int, offset: int, want: int
) -> tuple[list[tuple[int, int]], int]:
    """Where to read ``want`` bytes of an image that starts in ``ordered[index]``.

    A minidump splits an address space by protection, so a mapped image
    routinely spans several ranges: the header and code in one, writable data in
    the next. Reading only the range the `MZ` was found in stops at the first
    boundary.

    That cost 24 KB of the one payload this pipeline has recovered by itself.
    `SmartOptimization.dll` declares `SizeOfImage` 0x14000 and its first region
    ended 0xE000 in, so 57,344 of 81,920 bytes were carved and the `.rsrc` came
    out at 1,206 bytes against the 2,380 a hand-carve had recorded -- the
    configuration blob was in the part that was never read.

    Continues only into ranges that are *virtually* contiguous. A gap in the
    address space means the rest of the image was not captured, and splicing the
    next range onto it would fabricate an artifact rather than truncate one.
    Each chunk carries its own file offset because MemoryList ranges are not
    contiguous in the file even when they are in memory.
    """
    region = ordered[index]
    chunks: list[tuple[int, int]] = []

    first = min(want, (region.file_offset + region.size) - offset)
    if first <= 0:
        return [], 0
    chunks.append((offset, first))

    remaining = want - first
    next_va = region.va + region.size
    cursor = index + 1

    while remaining > 0 and cursor < len(ordered) and ordered[cursor].va == next_va:
        take = min(remaining, ordered[cursor].size)
        chunks.append((ordered[cursor].file_offset, take))
        remaining -= take
        next_va += ordered[cursor].size
        cursor += 1

    return chunks, want - remaining


def module_fingerprint(timestamp: object, size_of_image: object) -> tuple[int, int]:
    """Identity of a PE image that is stable across processes.

    ``TimeDateStamp`` and ``SizeOfImage`` together identify a build of a binary,
    and both are in a minidump's module list as well as in the header of a
    carved image, so the two can be compared without reading either file off
    disk.
    """
    try:
        return (int(timestamp or 0), int(size_of_image or 0))
    except (TypeError, ValueError):
        return (0, 0)


def _classify(
    va: int,
    modules: list[dict[str, Any]],
    carries_code: bool,
    header: dict[str, Any] | None = None,
    known_modules: set[tuple[int, int]] | None = None,
) -> tuple[str, dict[str, Any] | None]:
    for module in modules:
        base = int(module.get("base", 0) or 0)
        size = int(module.get("size", 0) or 0)
        if base and va == base:
            return "at_module_base", module
        if base and size and base < va < base + size:
            return "inside_module", module

    # Module coverage is decided first: a resource file mapped over a module's
    # range is a different question from one sitting on its own, and neither is
    # a finding.
    if not carries_code:
        return "resource_only", None

    # Not covered by *this* dump's module list, but enumerated as a legitimate
    # module somewhere else in the run.
    #
    # This is the false positive that made the carver's first strong finding
    # wrong. A process created suspended -- which is exactly what hollowing does
    # -- has ntdll mapped before the loader has populated its module list, so
    # ntdll is physically present and legitimately absent from the list being
    # checked against. Those dumps enumerated 6 and 11 modules; the loader's own
    # dump enumerated 65, ntdll among them. Six carved copies of ntdll.dll were
    # reported as unmapped images inside a hollowing target.
    #
    # Matching on the build rather than on a name means no list to maintain and
    # nothing to keep in step with a Windows version.
    if known_modules and header is not None:
        if module_fingerprint(header.get("timestamp"), header.get("size_of_image")) in known_modules:
            return "known_module", None

    return "unmapped", None


def read_module_index(path: str | Path) -> set[tuple[int, int]]:
    """Every module a dump enumerates, as build fingerprints.

    Read in a first pass over all of a run's dumps so that a later pass can tell
    a system DLL that one dump failed to enumerate from an image nothing on the
    machine knows about.
    """
    dump_path = Path(path)
    try:
        size = dump_path.stat().st_size
        if size < 32:
            return set()
        with open(dump_path, "rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
                modules = read_modules(data, size, _streams(data, size))
    except Exception:
        return set()

    return {
        module_fingerprint(m.get("timestamp"), m.get("size"))
        for m in modules
        if m.get("timestamp") and m.get("size")
    }


def analyze_dump(
    path: str | Path, known_modules: set[tuple[int, int]] | None = None
) -> dict[str, Any]:
    """Every PE image in one dump, classified against the dump's module list."""
    dump_path = Path(path)
    result: dict[str, Any] = {
        "path": str(dump_path),
        "file": dump_path.name,
        "parsed": False,
        "module_count": 0,
        "region_count": 0,
        "host_image": "",
        "host_image_timestamp_hex": "",
        "images": [],
        "counts": {
            "at_module_base": 0,
            "inside_module": 0,
            "unmapped": 0,
            "known_module": 0,
            "rejected": 0,
        },
        "error": "",
    }

    try:
        size = dump_path.stat().st_size
    except OSError as error:
        result["error"] = f"could not stat: {error}"
        return result

    if size < 32:
        result["error"] = "file is too small to be a minidump"
        return result

    try:
        with open(dump_path, "rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
                streams = _streams(data, size)
                modules = read_modules(data, size, streams)
                regions = read_regions(data, size, streams)

                result["module_count"] = len(modules)
                result["region_count"] = len(regions)
                if modules:
                    # The first module in a minidump is the executable itself.
                    # Its timestamp is the comparison that made the 05 Aug carve
                    # conclusive: the host image carried 0x5ff2b99b and the
                    # image sitting beside it carried a 2025 one.
                    result["host_image"] = modules[0].get("path", "")
                    result["host_image_timestamp_hex"] = f"0x{int(modules[0].get('timestamp', 0)):08x}"

                if not regions:
                    result["error"] = (
                        "the dump carries no memory ranges; it was written "
                        "without memory (DumpType=1 records metadata only)"
                    )
                    return result

                images: list[dict[str, Any]] = []
                rejected = 0
                # Sorted by address so a region's neighbour can be found: the
                # stream order is capture order, not address order.
                ordered = sorted(regions, key=lambda r: r.va)
                for index, region in enumerate(ordered):
                    region_end = region.file_offset + region.size
                    for offset in _candidates(data, region):
                        header = parse_pe_header(data, offset, region_end)
                        if header is None:
                            rejected += 1
                            continue

                        va = region.va + (offset - region.file_offset)
                        classification, module = _classify(
                            va,
                            modules,
                            header["carries_code"],
                            header=header,
                            known_modules=known_modules,
                        )

                        # Bounded by what was actually captured, following the
                        # image across contiguous ranges. A payload can sit at
                        # the end of one range and continue in the next, and
                        # reading past a *gap* would splice unrelated memory
                        # onto the carved image.
                        chunks, available = _image_chunks(
                            ordered, index, offset, header["size_of_image"]
                        )
                        layout, want, truncated = _resolve_layout(header, available)
                        # Trim to what the layout says the image is, so a carve
                        # of a file-layout payload does not carry the trailing
                        # page padding of the range it was found in.
                        chunks, _ = _image_chunks(ordered, index, offset, want)

                        images.append(
                            {
                                **header,
                                "classification": classification,
                                "module": (module or {}).get("path", ""),
                                "virtual_address": f"0x{va:x}",
                                "dump_file_offset": f"0x{offset:x}",
                                "_offset": offset,
                                "_chunks": chunks,
                                # How many ranges the image was reassembled
                                # from. Anything above 1 is a case the old
                                # single-range read would have truncated.
                                "regions_spanned": len(chunks),
                                # Which shape it was found in. A payload in file
                                # layout has not been mapped yet, which says
                                # where in the chain it was caught.
                                "layout": layout,
                                "carve_bytes": int(want),
                                "available_bytes": int(available),
                                "truncated": truncated,
                            }
                        )

                result["parsed"] = True
                result["images"] = images
                result["counts"] = {
                    "at_module_base": sum(1 for i in images if i["classification"] == "at_module_base"),
                    "inside_module": sum(1 for i in images if i["classification"] == "inside_module"),
                    "unmapped": sum(1 for i in images if i["classification"] == "unmapped"),
                    # Unmapped and real, but carrying no code. Counted rather
                    # than discarded: an idle Python process holds eleven, so a
                    # run reporting none of these is a run whose dumps were not
                    # searched properly. See _RESOURCE_ONLY_NOTE.
                    "resource_only": sum(1 for i in images if i["classification"] == "resource_only"),
                    # A system DLL this dump failed to enumerate but another
                    # dump in the run did. Counted for the same reason: six
                    # copies of ntdll once read as a hollowing finding, and a
                    # run reporting none of these in a suspended process is a
                    # run whose module index was not built.
                    "known_module": sum(1 for i in images if i["classification"] == "known_module"),
                    # Recorded because "we found no foreign image" and "we
                    # rejected 4,000 things that started with MZ" are different
                    # statements about the same dump.
                    "rejected": rejected,
                }
    except ValueError as error:
        result["error"] = str(error)
    except Exception as error:  # pragma: no cover - defensive
        result["error"] = f"{type(error).__name__}: {error}"

    return result


#: Longest process-name fragment allowed in a carved filename.
#:
#: Samples are stored under their SHA256, so `record["name"]` can be a 64-hex
#: string plus ".exe". Added to a run directory that already carries the case id
#: and a timestamped run id, that pushed the full path past Windows' 260
#: character limit, and the carve failed with a bare "No such file or
#: directory" -- on the one image of that run worth having, an 81,920-byte .NET
#: PE unpacked inside the loader itself.
#:
#: 24 keeps `RegSvcs.exe` and friends intact and truncates a hash to something
#: still recognisable. The address in the name is what identifies the image
#: anyway, and the full path is recorded in carved_pe.json.
_MAX_NAME_FRAGMENT = 24


def _carve_name(record: dict[str, Any], image: dict[str, Any]) -> str:
    """Filename for one carved image, unique across the dumps of a run.

    The offset and trigger are in here for the same reason they are in the dump
    filenames one layer down, and the reason was proved by leaving them out: a
    run carved seven images into five files, because the same PID at the same
    address taken from the spawn dump and from the exit dump produced the same
    name and the second silently replaced the first.

    Two dumps of one process are two moments, which is the entire point of
    taking both. Their contents happened to be identical on the run that
    exposed this, so nothing was lost -- but `carved: 7` against five files on
    disk is the report disagreeing with the case directory, and a record whose
    `carved_sha256` describes bytes that have since been overwritten.
    """
    process = str(record.get("name", "") or record.get("process_name", "") or "dump")
    process = "".join(c if c.isalnum() or c in "._-" else "_" for c in process)
    process = process[:_MAX_NAME_FRAGMENT] or "dump"

    pid = record.get("pid")
    offset = record.get("offset_seconds")
    trigger = "".join(
        c if c.isalnum() else "-" for c in str(record.get("trigger", "") or "")
    )
    va = image.get("virtual_address", "0x0")

    stamp = f"t{offset}" if offset is not None else "t"
    # Deliberately not .exe or .dll. This is live malware written to a directory
    # an analyst browses; the extension should not be one a double-click runs.
    return f"{process}_{pid}_{stamp}_{trigger}_{va}.bin_"


def _long_path(path: Path) -> str:
    """A form of ``path`` that Windows will accept past 260 characters.

    Truncating the filename is the first defence and this is the second: a case
    directory deep enough can exceed the limit on its own, whatever the image is
    called. The prefix is a no-op on other platforms and on paths that are
    already short enough.
    """
    text = str(path)
    if os.name != "nt" or len(text) < 250 or text.startswith("\\\\?\\"):
        return text
    absolute = os.path.abspath(text)
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC" + absolute[1:]
    return "\\\\?\\" + absolute


def carve_image(
    dump_path: str | Path,
    image: dict[str, Any],
    destination: str | Path,
    max_bytes: int = DEFAULT_MAX_CARVE_BYTES,
) -> dict[str, Any]:
    """Write one image out of a dump. Returns what was written."""
    out_path = Path(destination)
    record: dict[str, Any] = {
        "path": str(out_path),
        "file": out_path.name,
        "size": 0,
        "sha256": "",
        "success": False,
        "truncated": False,
        "error": "",
    }

    # carve_bytes is what the layout resolved to; the fallback keeps a caller
    # that has not been through analyze_dump working.
    want = min(
        int(image.get("carve_bytes")
            or image.get("size_of_image", 0) or 0),
        int(image.get("available_bytes", 0) or 0) or int(max_bytes),
        int(max_bytes),
    )
    if want <= 0:
        record["error"] = "nothing to carve"
        return record

    # Where to read from, one entry per memory range the image spans. Falls back
    # to a single read for a caller that has not been through analyze_dump.
    chunks = list(image.get("_chunks") or [(int(image.get("_offset", 0) or 0), want)])

    try:
        # The directory hits the limit before the file does, so it needs the
        # same treatment.
        os.makedirs(_long_path(out_path.parent), exist_ok=True)
        pieces: list[bytes] = []
        remaining = want
        with open(dump_path, "rb") as source:
            for chunk_offset, chunk_len in chunks:
                if remaining <= 0:
                    break
                source.seek(int(chunk_offset))
                piece = source.read(min(int(chunk_len), remaining))
                if not piece:
                    break
                pieces.append(piece)
                remaining -= len(piece)
        payload = b"".join(pieces)
        if not payload:
            record["error"] = "read returned no data"
            return record
        with open(_long_path(out_path), "wb") as out:
            out.write(payload)
    except Exception as error:
        record["error"] = f"could not carve: {error}"
        return record

    record["size"] = len(payload)
    record["success"] = True
    # Against what the layout says the image is, not against SizeOfImage: a
    # complete file-layout payload is always smaller than its mapped footprint.
    record["truncated"] = len(payload) < want
    try:
        record["sha256"] = sha256_file(_long_path(out_path))
    except Exception:
        pass
    return record


def carve_dumps(
    dump_records: list[dict[str, Any]],
    output_dir: str | Path,
    max_bytes: int = DEFAULT_MAX_CARVE_BYTES,
    max_per_dump: int = DEFAULT_MAX_CARVED_PER_DUMP,
    status_cb: StatusCallback = None,
) -> dict[str, Any]:
    """Analyse every dump and write out the images the loader did not map.

    ``dump_records`` are the successful entries from a MemoryDumpSession or the
    crash-dump collector -- the same list the YARA pass scans, so a carved image
    can be traced back to the process and moment it came from.
    """
    def emit(message: str) -> None:
        if status_cb:
            status_cb(message)

    result: dict[str, Any] = {
        "carved": False,
        "output_dir": str(output_dir),
        "dumps": [],
        "images": [],
        "counts": {
            "dumps_analyzed": 0,
            "dumps_failed": 0,
            "unmapped_images": 0,
            "unmapped_in_hollowing_target": 0,
            "dotnet_images": 0,
            "inside_module_images": 0,
            "carved": 0,
            "carve_failures": 0,
        },
        "error": "",
    }

    analyzed = 0
    failed = 0
    resource_only = 0
    known_module_images = 0
    carried: list[dict[str, Any]] = []

    # First pass: everything any dump in the run enumerates as a loaded module.
    #
    # A process created suspended -- which is what hollowing does -- has ntdll
    # mapped before its module list is populated, so a dump taken then shows the
    # DLL with nothing to identify it. The loader's own dump enumerates it
    # properly. Reading all the module lists first is what lets the second pass
    # tell those apart, without a name list to maintain.
    known_modules: set[tuple[int, int]] = set()
    for record in dump_records or []:
        path = str(record.get("path", "") or "")
        if path:
            known_modules |= read_module_index(path)

    for record in dump_records or []:
        path = str(record.get("path", "") or "")
        if not path:
            continue

        analysis = analyze_dump(path, known_modules=known_modules)
        analysis["pid"] = record.get("pid")
        analysis["process_name"] = record.get("name", "") or record.get("process_name", "")
        analysis["trigger"] = record.get("trigger", "")
        analysis["offset_seconds"] = record.get("offset_seconds")

        if analysis.get("error"):
            failed += 1
            emit(f"  {analysis['file']}: {analysis['error']}")
        else:
            analyzed += 1

        hollowing_target = is_hollowing_target(analysis["process_name"])

        # Only the images that are not ordinary loaded modules are reported, and
        # only they are carved. Writing out every mapped DLL would bury the one
        # image that matters under fifty copies of ntdll.
        notable = [
            image
            for image in analysis.get("images", [])
            if image["classification"] in ("unmapped", "inside_module")
        ]
        resource_only += int((analysis.get("counts", {}) or {}).get("resource_only", 0) or 0)
        known_module_images += int((analysis.get("counts", {}) or {}).get("known_module", 0) or 0)
        notable.sort(key=lambda i: (i["classification"] != "unmapped", i["_offset"]))

        carved_here = 0
        for image in notable:
            entry = {
                key: value for key, value in image.items() if not key.startswith("_")
            }
            entry.update(
                {
                    "pid": analysis["pid"],
                    "process_name": analysis["process_name"],
                    "trigger": analysis["trigger"],
                    "offset_seconds": analysis["offset_seconds"],
                    "dump_file": analysis["file"],
                    "host_image_timestamp_hex": analysis.get("host_image_timestamp_hex", ""),
                    "hollowing_target": hollowing_target,
                    "carved_path": "",
                    "carved_sha256": "",
                    "carved_size": 0,
                    "carve_error": "",
                }
            )

            if image["classification"] == "unmapped" and carved_here < max_per_dump:
                carve = carve_image(
                    path,
                    image,
                    Path(output_dir) / _carve_name(analysis, image),
                    max_bytes=max_bytes,
                )
                entry["carved_path"] = carve["path"] if carve["success"] else ""
                entry["carved_sha256"] = carve["sha256"]
                entry["carved_size"] = carve["size"]
                entry["carve_error"] = carve["error"]
                if carve["success"]:
                    carved_here += 1
                    emit(
                        f"  carved {Path(carve['path']).name} "
                        f"({carve['size']} bytes) from {analysis['file']} "
                        f"at {entry['virtual_address']}"
                    )
            elif image["classification"] == "unmapped":
                entry["carve_error"] = (
                    f"per-dump carve limit of {max_per_dump} reached"
                )

            carried.append(entry)

        analysis.pop("images", None)
        result["dumps"].append(analysis)

    unmapped = [i for i in carried if i["classification"] == "unmapped"]

    result["carved"] = True
    result["images"] = carried
    result["counts"] = {
        "dumps_analyzed": analyzed,
        "dumps_failed": failed,
        "unmapped_images": len(unmapped),
        # The emphatic subset, for the same reason the crash evidence keeps one:
        # a foreign image inside a binary that loaders hollow is a different
        # claim from a foreign image inside anything else.
        "unmapped_in_hollowing_target": sum(1 for i in unmapped if i["hollowing_target"]),
        "dotnet_images": sum(1 for i in unmapped if i["dotnet"]),
        "inside_module_images": sum(1 for i in carried if i["classification"] == "inside_module"),
        # Real, unmapped, and not evidence. Windows maps localised resource
        # files as data into every process; see _RESOURCE_ONLY_NOTE.
        "resource_only_images": resource_only,
        # System DLLs a dump failed to enumerate. Six of these -- all ntdll --
        # were once reported as unmapped images inside a hollowing target, and
        # took process_injection to strong on a route that had not earned it.
        "known_module_images": known_module_images,
        "carved": sum(1 for i in carried if i["carved_path"]),
        "carve_failures": sum(1 for i in carried if i["carve_error"]),
    }

    if unmapped:
        emit(
            f"PE carve: {len(unmapped)} image(s) present that no module covers "
            f"({result['counts']['unmapped_in_hollowing_target']} in a process "
            f"loaders hollow, {result['counts']['dotnet_images']} .NET)."
        )
    elif analyzed:
        emit(f"PE carve: {analyzed} dump(s) analysed, no unmapped PE images.")

    return result


# ---------------------------------------------------------------------------
# Summarising
# ---------------------------------------------------------------------------

def summarize_pe_carve(carve_result: dict[str, Any]) -> dict[str, Any]:
    """Reduce a carve to the shape the run summary and report carry."""
    if not isinstance(carve_result, dict) or not carve_result.get("carved"):
        return {
            "carved": False,
            "error": (carve_result or {}).get("error", "") if isinstance(carve_result, dict) else "",
            "counts": {},
            "images": [],
            "per_dump": [],
        }

    return {
        "carved": True,
        "error": carve_result.get("error", ""),
        "output_dir": carve_result.get("output_dir", ""),
        "counts": carve_result.get("counts", {}) or {},
        "images": [
            {
                "process": image.get("process_name", ""),
                "pid": image.get("pid"),
                "dump_file": image.get("dump_file", ""),
                "trigger": image.get("trigger", ""),
                "classification": image.get("classification", ""),
                "virtual_address": image.get("virtual_address", ""),
                "machine": image.get("machine", ""),
                "size_of_image": image.get("size_of_image", 0),
                "compiled": image.get("compiled", ""),
                "timestamp_hex": image.get("timestamp_hex", ""),
                # Side by side because that comparison is the finding: an image
                # four years newer than the process hosting it did not ship with
                # it.
                "host_image_timestamp_hex": image.get("host_image_timestamp_hex", ""),
                "dotnet": bool(image.get("dotnet")),
                "hollowing_target": bool(image.get("hollowing_target")),
                "carved_file": Path(str(image.get("carved_path", ""))).name
                if image.get("carved_path")
                else "",
                "carved_sha256": image.get("carved_sha256", ""),
                "truncated": bool(image.get("truncated")),
                # Above 1 means the image was reassembled across memory ranges,
                # which the single-range read used to cut short.
                "regions_spanned": image.get("regions_spanned", 1),
                # "file" means it had not been mapped yet when the dump was
                # taken -- the shape a decrypt-then-map loader holds it in.
                "layout": image.get("layout", ""),
                "error": image.get("carve_error", ""),
            }
            for image in carve_result.get("images", []) or []
        ],
        "per_dump": [
            {
                "file": dump.get("file", ""),
                "pid": dump.get("pid"),
                "process_name": dump.get("process_name", ""),
                "trigger": dump.get("trigger", ""),
                "modules": dump.get("module_count", 0),
                "regions": dump.get("region_count", 0),
                "unmapped": (dump.get("counts", {}) or {}).get("unmapped", 0),
                "rejected": (dump.get("counts", {}) or {}).get("rejected", 0),
                "error": dump.get("error", ""),
            }
            for dump in carve_result.get("dumps", []) or []
        ],
    }
