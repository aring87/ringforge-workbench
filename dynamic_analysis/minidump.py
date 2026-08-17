"""A minidump reader that is checked rather than guessed at.

Gap 5's last item. This pipeline reads dumps constantly -- the carver, the YARA
pass and the module-integrity check all walk them -- and the structure parsing
was private to whichever module needed it. When the crash investigation wanted
the *unloaded*-module list, it got hand-rolled twice and produced **a count of
7.6 quintillion, then the process id.** Both were loud enough to catch. A layout
error that lands on a plausible number is not, which is the argument for having
one reader with tests instead of three sketches.

**Why the unloaded list specifically breaks people.** `MINIDUMP_MODULE_LIST`
opens with a bare `ULONG32 NumberOfModules` and is followed by fixed 108-byte
entries. `MINIDUMP_UNLOADED_MODULE_LIST` does not:

    ULONG32 SizeOfHeader;      // 12
    ULONG32 SizeOfEntry;       // 24
    ULONG32 NumberOfEntries;

Read it like the loaded list and the "count" you get is `SizeOfHeader`, the
entries start 8 bytes early, and every field after that is shifted. That is the
whole bug, and it is invisible unless you know the two streams differ. The same
`SizeOfHeader`/`SizeOfEntry` preamble appears on `MINIDUMP_MEMORY_INFO_LIST`,
so both are read the file's way -- **entry stride is taken from the dump, never
assumed** -- which also means a future Windows that grows an entry still parses.

Two conventions worth keeping when using this:

* Nothing here raises on a malformed dump except `MinidumpError` from `parse`
  itself, and every stream reader that has to give up appends to `warnings`.
  A silently empty list and a stream that could not be read must not look the
  same -- the `collection_available` distinction, applied to file structure.
* Offsets are validated against the real file size before every read, so a
  corrupt RVA truncates the result instead of raising or inventing data.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

MINIDUMP_SIGNATURE = b"MDMP"

#: MINIDUMP_STREAM_TYPE, the ones this project has a use for.
THREAD_LIST = 3
MODULE_LIST = 4
MEMORY_LIST = 5
EXCEPTION_STREAM = 6
SYSTEM_INFO = 7
MEMORY64_LIST = 9
UNLOADED_MODULE_LIST = 14
MISC_INFO = 15
MEMORY_INFO_LIST = 16

#: MINIDUMP_MODULE. Fixed size, and the fixed-ness is the difference from the
#: unloaded entry below.
_MODULE_ENTRY_SIZE = 108

#: MINIDUMP_UNLOADED_MODULE, as documented. Used only as a sanity floor: the
#: real stride comes from the stream's own `SizeOfEntry`.
_UNLOADED_ENTRY_MIN = 24

#: MINIDUMP_THREAD: ThreadId, SuspendCount, PriorityClass, Priority (4 each),
#: Teb (8), Stack as a MINIDUMP_MEMORY_DESCRIPTOR (8 + 4 + 4), then
#: ThreadContext as a MINIDUMP_LOCATION_DESCRIPTOR (4 + 4). Fixed, like the
#: loaded module list and unlike the unloaded one.
_THREAD_ENTRY_SIZE = 48

#: MINIDUMP_MEMORY_INFO, as documented. A floor, not the stride.
_MEMORY_INFO_ENTRY_MIN = 48

#: MEMORY_BASIC_INFORMATION State and Type.
_MEM_STATE = {0x1000: "commit", 0x2000: "reserve", 0x10000: "free"}
_MEM_TYPE = {0x20000: "private", 0x40000: "mapped", 0x1000000: "image"}

_PROCESSOR_ARCHITECTURES = {
    0: "x86", 5: "arm", 6: "ia64", 9: "x64", 12: "arm64",
}


class MinidumpError(ValueError):
    """The file is not a minidump, or its header cannot be believed."""


def _u16(data: Any, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: Any, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: Any, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


class Minidump:
    """A parsed minidump. Construct with `parse`."""

    def __init__(self, data: bytes | memoryview, size: int) -> None:
        self._data = data
        self._size = size
        self.warnings: list[str] = []
        self.streams: dict[int, tuple[int, int]] = {}
        self._read_directory()

    # -- structure ---------------------------------------------------------

    def _fits(self, offset: int, length: int) -> bool:
        return offset >= 0 and length >= 0 and offset + length <= self._size

    def _read_directory(self) -> None:
        if self._size < 32 or bytes(self._data[:4]) != MINIDUMP_SIGNATURE:
            raise MinidumpError("not a minidump (bad signature)")

        stream_count = _u32(self._data, 8)
        directory_rva = _u32(self._data, 12)

        # A plausible-looking header with an absurd stream count is the shape a
        # truncated or mangled dump takes. Bound it by what the file could hold.
        if not self._fits(directory_rva, 0) or stream_count > self._size // 12 + 1:
            raise MinidumpError(
                f"header claims {stream_count} streams at {directory_rva:#x}, "
                f"which a {self._size}-byte file cannot hold")

        for index in range(stream_count):
            entry = directory_rva + index * 12
            if not self._fits(entry, 12):
                self.warnings.append(
                    f"stream directory truncated after {index} of {stream_count}")
                break
            stream_type = _u32(self._data, entry)
            data_size = _u32(self._data, entry + 4)
            rva = _u32(self._data, entry + 8)
            if not self._fits(rva, data_size):
                self.warnings.append(
                    f"stream {stream_type} points outside the file "
                    f"(rva {rva:#x}, size {data_size})")
                continue
            self.streams[stream_type] = (rva, data_size)

    def string(self, rva: int) -> str:
        """MINIDUMP_STRING: a ULONG32 byte-length then UTF-16LE."""
        if rva <= 0 or not self._fits(rva, 4):
            return ""
        length = _u32(self._data, rva)
        if length <= 0 or not self._fits(rva + 4, length):
            return ""
        raw = bytes(self._data[rva + 4:rva + 4 + length])
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")

    # -- streams -----------------------------------------------------------

    def modules(self) -> list[dict[str, Any]]:
        """The loader's module list: what Windows had mapped, and where."""
        location = self.streams.get(MODULE_LIST)
        if not location:
            return []
        rva, stream_size = location
        if not self._fits(rva, 4):
            self.warnings.append("module list header outside the file")
            return []

        count = _u32(self._data, rva)
        out: list[dict[str, Any]] = []
        for index in range(count):
            entry = rva + 4 + index * _MODULE_ENTRY_SIZE
            if not self._fits(entry, _MODULE_ENTRY_SIZE) or \
                    entry + _MODULE_ENTRY_SIZE > rva + 4 + stream_size:
                self.warnings.append(
                    f"module list truncated after {len(out)} of {count}")
                break
            out.append({
                "base": _u64(self._data, entry),
                "size": _u32(self._data, entry + 8),
                "checksum": _u32(self._data, entry + 12),
                "timestamp": _u32(self._data, entry + 16),
                "path": self.string(_u32(self._data, entry + 20)),
            })
        return out

    def unloaded_modules(self) -> list[dict[str, Any]]:
        """Modules that were loaded and then unloaded before the dump.

        The stream this project got wrong twice. Its header is
        `SizeOfHeader / SizeOfEntry / NumberOfEntries`, not a bare count, and
        the stride is read from the file rather than assumed -- so a build that
        widens the entry parses instead of producing shifted garbage.
        """
        location = self.streams.get(UNLOADED_MODULE_LIST)
        if not location:
            return []
        rva, stream_size = location
        if not self._fits(rva, 12):
            self.warnings.append("unloaded module list header outside the file")
            return []

        size_of_header = _u32(self._data, rva)
        size_of_entry = _u32(self._data, rva + 4)
        count = _u32(self._data, rva + 8)

        if size_of_header < 12 or size_of_entry < _UNLOADED_ENTRY_MIN:
            self.warnings.append(
                f"unloaded module list header not believable "
                f"(SizeOfHeader {size_of_header}, SizeOfEntry {size_of_entry})")
            return []
        # The count is bounded by the stream's own declared size. Without this
        # a bad dword reads as billions of entries and the loop is the bug.
        room = max(0, stream_size - size_of_header) // size_of_entry
        if count > room:
            self.warnings.append(
                f"unloaded module list claims {count} entries, stream holds {room}")
            count = room

        out: list[dict[str, Any]] = []
        for index in range(count):
            entry = rva + size_of_header + index * size_of_entry
            if not self._fits(entry, _UNLOADED_ENTRY_MIN):
                self.warnings.append(
                    f"unloaded module list truncated after {len(out)} of {count}")
                break
            out.append({
                "base": _u64(self._data, entry),
                "size": _u32(self._data, entry + 8),
                "checksum": _u32(self._data, entry + 12),
                "timestamp": _u32(self._data, entry + 16),
                "path": self.string(_u32(self._data, entry + 20)),
            })
        return out

    def threads(self) -> list[dict[str, Any]]:
        """Each thread, with the bounds of the stack the dump captured.

        Written for one question: an address found in a dump is meaningless
        until you know what it is *in*. `0az` called the guest's copies of the
        crash constant "heap" and built a lead on the bench having them on the
        stack instead -- and the word was never measured. Six of the seven are
        inside `Stack` below.
        """
        location = self.streams.get(THREAD_LIST)
        if not location:
            return []
        rva, stream_size = location
        if not self._fits(rva, 4):
            self.warnings.append("thread list header outside the file")
            return []

        count = _u32(self._data, rva)
        # MINIDUMP_THREAD is fixed-size, unlike the unloaded-module entry --
        # there is no SizeOfEntry to read here, so the stride is bounded by the
        # stream's own declared size instead.
        room = max(0, stream_size - 4) // _THREAD_ENTRY_SIZE
        if count > room:
            self.warnings.append(
                f"thread list claims {count} threads, stream holds {room}")
            count = room

        out: list[dict[str, Any]] = []
        for index in range(count):
            entry = rva + 4 + index * _THREAD_ENTRY_SIZE
            if not self._fits(entry, _THREAD_ENTRY_SIZE):
                self.warnings.append(
                    f"thread list truncated after {len(out)} of {count}")
                break
            stack_base = _u64(self._data, entry + 24)
            stack_size = _u32(self._data, entry + 32)
            out.append({
                "thread_id": _u32(self._data, entry),
                "suspend_count": _u32(self._data, entry + 4),
                "teb": _u64(self._data, entry + 16),
                "stack_base": stack_base,
                "stack_size": stack_size,
                "stack_end": stack_base + stack_size,
            })
        return out

    def memory_info(self) -> list[dict[str, Any]]:
        """`VirtualQuery` for every region: State, Type and protection.

        The stream that says whether an address is image, mapped file or
        private, and whether it was executable. Same
        `SizeOfHeader / SizeOfEntry / NumberOfEntries` preamble as the unloaded
        module list, and read the same way -- stride from the file.

        Note the count here is a **ULONG64**, where the unloaded list's is a
        ULONG32. Reading it as 32 bits happens to work on a little-endian dump
        with few regions, which is exactly the kind of layout error that lands
        on a plausible number.
        """
        location = self.streams.get(MEMORY_INFO_LIST)
        if not location:
            return []
        rva, stream_size = location
        if not self._fits(rva, 16):
            self.warnings.append("memory info list header outside the file")
            return []

        size_of_header = _u32(self._data, rva)
        size_of_entry = _u32(self._data, rva + 4)
        count = _u64(self._data, rva + 8)

        if size_of_header < 16 or size_of_entry < _MEMORY_INFO_ENTRY_MIN:
            self.warnings.append(
                f"memory info list header not believable "
                f"(SizeOfHeader {size_of_header}, SizeOfEntry {size_of_entry})")
            return []
        room = max(0, stream_size - size_of_header) // size_of_entry
        if count > room:
            self.warnings.append(
                f"memory info list claims {count} regions, stream holds {room}")
            count = room

        out: list[dict[str, Any]] = []
        for index in range(count):
            entry = rva + size_of_header + index * size_of_entry
            if not self._fits(entry, _MEMORY_INFO_ENTRY_MIN):
                self.warnings.append(
                    f"memory info list truncated after {len(out)} of {count}")
                break
            base = _u64(self._data, entry)
            size = _u64(self._data, entry + 24)
            state = _u32(self._data, entry + 32)
            out.append({
                "base": base,
                "size": size,
                "end": base + size,
                "allocation_base": _u64(self._data, entry + 8),
                "allocation_protect": _u32(self._data, entry + 16),
                "state": state,
                "state_name": _MEM_STATE.get(state, f"unknown({state:#x})"),
                "protect": _u32(self._data, entry + 36),
                "type": _u32(self._data, entry + 40),
                "type_name": _MEM_TYPE.get(
                    _u32(self._data, entry + 40),
                    # A free region carries Type 0 rather than one of the three
                    # MEM_* values, so 0 is a real answer and not a parse fault.
                    "free" if state == 0x10000 else
                    f"unknown({_u32(self._data, entry + 40):#x})"),
            })
        return out

    def region_of(self, address: int) -> dict[str, Any] | None:
        """The `memory_info` region containing `address`, or None."""
        for region in self.memory_info():
            if region["base"] <= address < region["end"]:
                return region
        return None

    def system_info(self) -> dict[str, Any]:
        location = self.streams.get(SYSTEM_INFO)
        if not location:
            return {}
        rva, _ = location
        if not self._fits(rva, 24):
            self.warnings.append("system info stream outside the file")
            return {}
        arch = _u16(self._data, rva)
        return {
            "architecture": _PROCESSOR_ARCHITECTURES.get(arch, f"unknown({arch})"),
            "processors": self._data[rva + 6],
            "major_version": _u32(self._data, rva + 8),
            "minor_version": _u32(self._data, rva + 12),
            "build_number": _u32(self._data, rva + 16),
        }

    def process_id(self) -> int | None:
        """From MISC_INFO, when the writer included it."""
        location = self.streams.get(MISC_INFO)
        if not location:
            return None
        rva, _ = location
        if not self._fits(rva, 12):
            self.warnings.append("misc info stream outside the file")
            return None
        flags1 = _u32(self._data, rva + 4)
        if not flags1 & 0x00000001:          # MINIDUMP_MISC1_PROCESS_ID
            return None
        return _u32(self._data, rva + 8)

    def memory_ranges(self) -> list[tuple[int, int, int]]:
        """`(virtual_address, file_offset, size)` for every mapped range."""
        out: list[tuple[int, int, int]] = []

        location = self.streams.get(MEMORY64_LIST)
        if location:
            rva, _ = location
            if self._fits(rva, 16):
                count = _u64(self._data, rva)
                base_rva = _u64(self._data, rva + 8)
                offset = base_rva
                for index in range(count):
                    entry = rva + 16 + index * 16
                    if not self._fits(entry, 16):
                        self.warnings.append(
                            f"memory64 list truncated after {len(out)} of {count}")
                        break
                    va = _u64(self._data, entry)
                    length = _u64(self._data, entry + 8)
                    if offset + length > self._size:
                        # A dump cut off mid-write. Everything before the cut is
                        # still real memory and still worth reading, so keep the
                        # partial range rather than discarding the tail.
                        remaining = max(0, self._size - offset)
                        if remaining:
                            out.append((va, offset, remaining))
                        self.warnings.append(
                            f"memory64 data truncated at range {len(out)} of {count}")
                        break
                    out.append((va, offset, length))
                    offset += length
            else:
                self.warnings.append("memory64 list header outside the file")
            return out

        location = self.streams.get(MEMORY_LIST)
        if location:
            rva, _ = location
            if not self._fits(rva, 4):
                self.warnings.append("memory list header outside the file")
                return out
            count = _u32(self._data, rva)
            for index in range(count):
                entry = rva + 4 + index * 16
                if not self._fits(entry, 16):
                    self.warnings.append(
                        f"memory list truncated after {len(out)} of {count}")
                    break
                va = _u64(self._data, entry)
                length = _u32(self._data, entry + 8)
                file_offset = _u32(self._data, entry + 12)
                out.append((va, file_offset, length))
        return out


def parse(source: str | Path | bytes | bytearray | memoryview) -> Minidump:
    """Parse a minidump from a path or from bytes already in hand."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = memoryview(bytes(source))
        return Minidump(data, len(data))
    path = Path(source)
    data = path.read_bytes()
    return Minidump(memoryview(data), len(data))
