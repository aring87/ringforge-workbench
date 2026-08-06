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
    if not (1990 <= stamp.year <= 2100):
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

    carries_code = bool(size_of_code or entry_point) or _has_executable_section(
        data, pe + 24 + optional_size, sections, limit
    )

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
        "dotnet": dotnet,
        "is_dll": bool(characteristics & _FILE_DLL),
        # See _RESOURCE_ONLY_NOTE. An image with no code in it is not a payload,
        # and Windows maps a dozen of them into every process.
        "carries_code": carries_code,
    }


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

def _classify(
    va: int, modules: list[dict[str, Any]], carries_code: bool
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
    return ("unmapped" if carries_code else "resource_only"), None


def analyze_dump(path: str | Path) -> dict[str, Any]:
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
        "counts": {"at_module_base": 0, "inside_module": 0, "unmapped": 0, "rejected": 0},
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
                for region in regions:
                    region_end = region.file_offset + region.size
                    for offset in _candidates(data, region):
                        header = parse_pe_header(data, offset, region_end)
                        if header is None:
                            rejected += 1
                            continue

                        va = region.va + (offset - region.file_offset)
                        classification, module = _classify(
                            va, modules, header["carries_code"]
                        )

                        # Bounded by the region as well as by the header: a
                        # payload can sit at the end of what was captured, and
                        # reading past it would splice unrelated memory onto the
                        # carved image.
                        available = region_end - offset

                        images.append(
                            {
                                **header,
                                "classification": classification,
                                "module": (module or {}).get("path", ""),
                                "virtual_address": f"0x{va:x}",
                                "dump_file_offset": f"0x{offset:x}",
                                "_offset": offset,
                                "available_bytes": int(available),
                                "truncated": available < header["size_of_image"],
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
    process = str(record.get("name", "") or record.get("process_name", "") or "dump")
    process = "".join(c if c.isalnum() or c in "._-" else "_" for c in process)
    process = process[:_MAX_NAME_FRAGMENT] or "dump"
    pid = record.get("pid")
    va = image.get("virtual_address", "0x0")
    # Deliberately not .exe or .dll. This is live malware written to a directory
    # an analyst browses; the extension should not be one a double-click runs.
    return f"{process}_{pid}_{va}.bin_"


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

    offset = int(image.get("_offset", 0) or 0)
    want = min(
        int(image.get("size_of_image", 0) or 0),
        int(image.get("available_bytes", 0) or 0),
        int(max_bytes),
    )
    if want <= 0:
        record["error"] = "nothing to carve"
        return record

    try:
        # The directory hits the limit before the file does, so it needs the
        # same treatment.
        os.makedirs(_long_path(out_path.parent), exist_ok=True)
        with open(dump_path, "rb") as source:
            source.seek(offset)
            payload = source.read(want)
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
    record["truncated"] = len(payload) < int(image.get("size_of_image", 0) or 0)
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
    carried: list[dict[str, Any]] = []

    for record in dump_records or []:
        path = str(record.get("path", "") or "")
        if not path:
            continue

        analysis = analyze_dump(path)
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
