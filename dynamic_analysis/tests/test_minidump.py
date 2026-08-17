"""The minidump reader, including the stream that got hand-rolled wrong twice.

The headline case is `test_unloaded_list_read_as_a_loaded_list_is_wrong`: it
builds a valid unloaded-module list and shows what the naive read produces, so
the bug is pinned by a test rather than by a comment. Two attempts at this
stream in the crash investigation returned a count of 7.6 quintillion and then
the process id.

The synthetic fixtures here prove the layout arithmetic. They cannot prove the
parser survives what Windows actually writes -- that is what the `slow` test at
the bottom is for, and it is the standing rule in this suite after the carver's
eleven MUI resource files survived every synthetic fixture in the project.
"""
import struct
import tempfile
import unittest
from pathlib import Path

import pytest

from dynamic_analysis.minidump import (
    EXCEPTION_STREAM,
    MEMORY_INFO_LIST,
    MODULE_LIST,
    SYSTEM_INFO,
    THREAD_LIST,
    UNLOADED_MODULE_LIST,
    Minidump,
    MinidumpError,
    parse,
)


def _string(text: str) -> bytes:
    raw = text.encode("utf-16-le")
    return struct.pack("<I", len(raw)) + raw


def _dump(streams: dict[int, bytes], blobs: bytes = b"") -> bytes:
    """Assemble a minimal but structurally correct minidump."""
    header_size = 32
    directory_size = 12 * len(streams)
    body = bytearray()
    placed: list[tuple[int, int, int]] = []
    cursor = header_size + directory_size
    for stream_type, payload in streams.items():
        placed.append((stream_type, len(payload), cursor))
        body += payload
        cursor += len(payload)
    blob_base = cursor

    out = bytearray()
    out += b"MDMP"
    out += struct.pack("<I", 0xA793)                 # version
    out += struct.pack("<I", len(streams))
    out += struct.pack("<I", header_size)            # directory rva
    out += struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 0)
    for stream_type, size, rva in placed:
        out += struct.pack("<III", stream_type, size, rva)
    out += body
    out += blobs
    assert len(out) >= blob_base
    return bytes(out)


def _module_entry(base, size, timestamp, name_rva):
    entry = bytearray(108)
    struct.pack_into("<Q", entry, 0, base)
    struct.pack_into("<I", entry, 8, size)
    struct.pack_into("<I", entry, 16, timestamp)
    struct.pack_into("<I", entry, 20, name_rva)
    return bytes(entry)


def _unloaded_entry(base, size, timestamp, name_rva):
    return struct.pack("<QIIII", base, size, 0, timestamp, name_rva)


def _thread_entry(thread_id, teb, stack_base, stack_size):
    entry = bytearray(48)
    struct.pack_into("<IIII", entry, 0, thread_id, 0, 0, 0)
    struct.pack_into("<Q", entry, 16, teb)
    struct.pack_into("<QII", entry, 24, stack_base, stack_size, 0)
    return bytes(entry)


def _memory_info(base, size, state, protect, mtype, allocation_base=None):
    entry = bytearray(48)
    struct.pack_into("<QQ", entry, 0, base,
                     base if allocation_base is None else allocation_base)
    struct.pack_into("<I", entry, 16, protect)          # AllocationProtect
    struct.pack_into("<Q", entry, 24, size)
    struct.pack_into("<III", entry, 32, state, protect, mtype)
    return bytes(entry)


class Header(unittest.TestCase):
    def test_rejects_a_non_minidump(self):
        with self.assertRaises(MinidumpError):
            parse(b"MZ" + b"\0" * 100)

    def test_rejects_an_absurd_stream_count(self):
        blob = bytearray(_dump({}))
        struct.pack_into("<I", blob, 8, 0xFFFFFFFF)
        with self.assertRaises(MinidumpError):
            parse(bytes(blob))

    def test_a_stream_pointing_off_the_end_warns_rather_than_raising(self):
        blob = bytearray(_dump({MODULE_LIST: struct.pack("<I", 0)}))
        struct.pack_into("<I", blob, 32 + 8, 0x7FFFFFFF)   # directory[0].rva
        dump = parse(bytes(blob))
        self.assertNotIn(MODULE_LIST, dump.streams)
        self.assertTrue(any("outside the file" in w for w in dump.warnings))


class ModuleList(unittest.TestCase):
    def test_reads_entries_and_names(self):
        name_rva = 0             # patched below
        payload = struct.pack("<I", 1) + _module_entry(0x400000, 0x46000, 0x5FF2B99B, 0)
        raw = bytearray(_dump({MODULE_LIST: payload}, _string(r"C:\Windows\RegSvcs.exe")))
        blob_rva = len(raw) - len(_string(r"C:\Windows\RegSvcs.exe"))
        struct.pack_into("<I", raw, 32 + 12 + 4 + 20, blob_rva)
        modules = parse(bytes(raw)).modules()
        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0]["base"], 0x400000)
        self.assertEqual(modules[0]["timestamp"], 0x5FF2B99B)
        self.assertEqual(modules[0]["path"], r"C:\Windows\RegSvcs.exe")

    def test_a_lying_count_truncates_and_warns(self):
        payload = struct.pack("<I", 9999) + _module_entry(0x400000, 0x1000, 0, 0)
        dump = parse(_dump({MODULE_LIST: payload}))
        self.assertEqual(len(dump.modules()), 1)
        self.assertTrue(any("truncated" in w for w in dump.warnings))


class UnloadedModuleList(unittest.TestCase):
    """The stream that produced 7.6 quintillion and then the process id."""

    def _payload(self, entries):
        header = struct.pack("<III", 12, 24, len(entries))
        return header + b"".join(entries)

    def test_reads_the_list(self):
        payload = self._payload([
            _unloaded_entry(0x70000000, 0x2000, 0x11111111, 0),
            _unloaded_entry(0x71000000, 0x3000, 0x22222222, 0),
        ])
        unloaded = parse(_dump({UNLOADED_MODULE_LIST: payload})).unloaded_modules()
        self.assertEqual(len(unloaded), 2)
        self.assertEqual(unloaded[0]["base"], 0x70000000)
        self.assertEqual(unloaded[1]["timestamp"], 0x22222222)

    def test_unloaded_list_read_as_a_loaded_list_is_wrong(self):
        """Pin the actual bug, not a description of it.

        Read as a loaded list the first dword is a 'count' of 12 -- the
        SizeOfHeader -- and the entries begin 8 bytes early. Every field after
        that is shifted, which is how a hand-rolled read produces numbers like
        a process id where a base address belongs.
        """
        payload = self._payload([_unloaded_entry(0x70000000, 0x2000, 0xABCD, 0)])
        naive_count = struct.unpack_from("<I", payload, 0)[0]
        self.assertEqual(naive_count, 12)          # SizeOfHeader, not a count
        self.assertNotEqual(naive_count, 1)

        naive_base = struct.unpack_from("<Q", payload, 4)[0]
        self.assertNotEqual(naive_base, 0x70000000)

        correct = parse(_dump({UNLOADED_MODULE_LIST: payload})).unloaded_modules()
        self.assertEqual(correct[0]["base"], 0x70000000)

    def test_entry_stride_is_taken_from_the_file(self):
        # A writer that widens the entry must still parse. Hardcoding 24 here
        # would be the same class of assumption that broke the header.
        wide = 32
        entries = [_unloaded_entry(0x70000000, 0x2000, 0xAAAA, 0) + b"\0" * 8,
                   _unloaded_entry(0x71000000, 0x3000, 0xBBBB, 0) + b"\0" * 8]
        payload = struct.pack("<III", 12, wide, 2) + b"".join(entries)
        unloaded = parse(_dump({UNLOADED_MODULE_LIST: payload})).unloaded_modules()
        self.assertEqual([u["base"] for u in unloaded], [0x70000000, 0x71000000])

    def test_a_count_larger_than_the_stream_is_clamped(self):
        # The 7.6-quintillion failure mode: believe the count and the loop is
        # the bug. The stream's own size bounds it.
        payload = struct.pack("<III", 12, 24, 0xFFFFFFFF) + \
            _unloaded_entry(0x70000000, 0x2000, 0, 0)
        dump = parse(_dump({UNLOADED_MODULE_LIST: payload}))
        self.assertEqual(len(dump.unloaded_modules()), 1)
        self.assertTrue(any("stream holds" in w for w in dump.warnings))

    def test_nonsense_header_refuses_rather_than_guessing(self):
        payload = struct.pack("<III", 0, 0, 5) + b"\0" * 64
        dump = parse(_dump({UNLOADED_MODULE_LIST: payload}))
        self.assertEqual(dump.unloaded_modules(), [])
        self.assertTrue(any("not believable" in w for w in dump.warnings))

    def test_absent_stream_is_empty_without_a_warning(self):
        dump = parse(_dump({MODULE_LIST: struct.pack("<I", 0)}))
        self.assertEqual(dump.unloaded_modules(), [])
        self.assertEqual(dump.warnings, [])


class ThreadList(unittest.TestCase):
    """Stack bounds, which is what turns an address into a fact.

    `0az` called the guest's copies of the crash constant "heap" and made the
    bench having them on the stack the next thread to pull. Six of the seven
    are inside this stream's `Stack` descriptor. The word was the finding.
    """

    def test_reads_threads_and_stack_bounds(self):
        payload = struct.pack("<I", 1) + _thread_entry(
            thread_id=2180, teb=0xBDD000, stack_base=0xD3D3BC, stack_size=0x2C44)
        threads = parse(_dump({THREAD_LIST: payload})).threads()
        self.assertEqual(len(threads), 1)
        self.assertEqual(threads[0]["thread_id"], 2180)
        self.assertEqual(threads[0]["stack_base"], 0xD3D3BC)
        self.assertEqual(threads[0]["stack_end"], 0xD3D3BC + 0x2C44)

    def test_a_lying_count_is_clamped_and_warns(self):
        payload = struct.pack("<I", 0xFFFFFFFF) + _thread_entry(
            thread_id=7, teb=0x1000, stack_base=0x2000, stack_size=0x100)
        dump = parse(_dump({THREAD_LIST: payload}))
        self.assertEqual(len(dump.threads()), 1)
        self.assertTrue(any("stream holds" in w for w in dump.warnings))

    def test_absent_stream_is_empty_without_a_warning(self):
        dump = parse(_dump({MODULE_LIST: struct.pack("<I", 0)}))
        self.assertEqual(dump.threads(), [])
        self.assertEqual(dump.warnings, [])


class MemoryInfoList(unittest.TestCase):
    """Region State/Type/Protect -- image vs mapped vs private."""

    def _payload(self, entries, count=None, size_of_entry=48):
        header = struct.pack("<IIQ", 16, size_of_entry,
                             len(entries) if count is None else count)
        return header + b"".join(entries)

    def test_reads_regions_with_state_and_type(self):
        payload = self._payload([
            _memory_info(0x1010000, 0x46000, state=0x1000, protect=0x40,
                         mtype=0x20000),
            _memory_info(0x990000, 0xE000, state=0x1000, protect=0x02,
                         mtype=0x1000000),
        ])
        regions = parse(_dump({MEMORY_INFO_LIST: payload})).memory_info()
        self.assertEqual(len(regions), 2)
        self.assertEqual(regions[0]["type_name"], "private")
        self.assertEqual(regions[0]["state_name"], "commit")
        self.assertEqual(regions[0]["end"], 0x1010000 + 0x46000)
        self.assertEqual(regions[1]["type_name"], "image")

    def test_the_count_is_64_bit(self):
        """Read as a ULONG32 this happens to work, which is the danger.

        The unloaded module list's count *is* a ULONG32 and this one is not.
        A 32-bit read of a little-endian 2 gives 2, so the mistake survives
        every small fixture and only shows up as a shifted stride later.
        """
        payload = self._payload([
            _memory_info(0x1000, 0x1000, state=0x1000, protect=0x04,
                         mtype=0x20000)])
        self.assertEqual(struct.unpack_from("<Q", payload, 8)[0], 1)
        # The four bytes after the count are padding inside the 64-bit field,
        # so a reader that treats the header as three dwords lands its first
        # entry four bytes early.
        self.assertEqual(struct.unpack_from("<I", payload, 12)[0], 0)
        regions = parse(_dump({MEMORY_INFO_LIST: payload})).memory_info()
        self.assertEqual(regions[0]["base"], 0x1000)

    def test_a_free_region_is_named_free_rather_than_unknown(self):
        # MEM_FREE carries Type 0, which is not one of the three MEM_* values.
        # Reporting that as "unknown(0x0)" would read as a parse fault.
        payload = self._payload([
            _memory_info(0xDDB000, 0x5000, state=0x10000, protect=0x01, mtype=0)])
        region = parse(_dump({MEMORY_INFO_LIST: payload})).memory_info()[0]
        self.assertEqual(region["state_name"], "free")
        self.assertEqual(region["type_name"], "free")

    def test_entry_stride_is_taken_from_the_file(self):
        wide = 64
        entries = [_memory_info(0x1000, 0x1000, 0x1000, 0x04, 0x20000) + b"\0" * 16,
                   _memory_info(0x9000, 0x1000, 0x1000, 0x04, 0x20000) + b"\0" * 16]
        payload = self._payload(entries, size_of_entry=wide)
        regions = parse(_dump({MEMORY_INFO_LIST: payload})).memory_info()
        self.assertEqual([r["base"] for r in regions], [0x1000, 0x9000])

    def test_a_count_larger_than_the_stream_is_clamped(self):
        payload = self._payload(
            [_memory_info(0x1000, 0x1000, 0x1000, 0x04, 0x20000)], count=1 << 40)
        dump = parse(_dump({MEMORY_INFO_LIST: payload}))
        self.assertEqual(len(dump.memory_info()), 1)
        self.assertTrue(any("stream holds" in w for w in dump.warnings))

    def test_nonsense_header_refuses_rather_than_guessing(self):
        payload = struct.pack("<IIQ", 0, 0, 5) + b"\0" * 128
        dump = parse(_dump({MEMORY_INFO_LIST: payload}))
        self.assertEqual(dump.memory_info(), [])
        self.assertTrue(any("not believable" in w for w in dump.warnings))

    def test_region_of_finds_the_containing_region(self):
        payload = self._payload([
            _memory_info(0x1010000, 0x46000, 0x1000, 0x40, 0x20000)])
        dump = parse(_dump({MEMORY_INFO_LIST: payload}))
        self.assertEqual(dump.region_of(0x101D809)["base"], 0x1010000)
        self.assertIsNone(dump.region_of(0x2000000))



class ExceptionStream(unittest.TestCase):
    """The fault and its register file -- unread until 17 Aug.

    `0ax` reconstructed the guest's faulting instruction from the eip in the
    WER report and then reasoned about what `esi` must have held. The registers
    were in the dump the whole time, and `esi` is the value the entire
    cookie-recovery model of the crash is about.
    """

    def _payload(self, context_rva, context_size=0xCC, code=0xC0000005):
        blob = bytearray(168)
        struct.pack_into("<I", blob, 0, 2180)            # ThreadId
        struct.pack_into("<I", blob, 8, code)            # ExceptionCode
        struct.pack_into("<I", blob, 28, 0)              # NumberParameters
        struct.pack_into("<II", blob, 160, context_size, context_rva)
        return bytes(blob)

    def _context(self, **registers):
        blob = bytearray(0xCC)
        for name, offset in (("edi", 0x9C), ("esi", 0xA0), ("ebx", 0xA4),
                             ("edx", 0xA8), ("ecx", 0xAC), ("eax", 0xB0),
                             ("ebp", 0xB4), ("eip", 0xB8), ("esp", 0xC4)):
            struct.pack_into("<I", blob, offset, registers.get(name, 0))
        return bytes(blob)

    def _dump_with(self, context, **kwargs):
        """Assemble a dump whose exception stream points at `context`."""
        sysinfo = struct.pack("<HHBBHIIII", 0, 0, 0, 4, 0, 10, 0, 26200, 0)
        placeholder = self._payload(0)
        raw = bytearray(_dump({EXCEPTION_STREAM: placeholder,
                               SYSTEM_INFO: sysinfo}, context))
        context_rva = len(raw) - len(context)
        # Patch the real RVA in now that the layout is known.
        exception_rva = struct.unpack_from("<I", raw, 32 + 8)[0]
        struct.pack_into("<II", raw, exception_rva + 160,
                         kwargs.get("context_size", 0xCC), context_rva)
        return bytes(raw)

    def test_reads_the_code_and_the_registers(self):
        context = self._context(eip=0x01012C7C, esi=0x320BF2BC, ecx=0x00D3E258,
                                edx=0x32DFD514, ebp=0x00D3E1A0)
        exception = parse(self._dump_with(context)).exception()
        self.assertEqual(exception["code"], 0xC0000005)
        self.assertEqual(exception["context"]["eip"], 0x01012C7C)
        self.assertEqual(exception["context"]["esi"], 0x320BF2BC)
        self.assertEqual(exception["context"]["ecx"], 0x00D3E258)

    def test_the_guest_arithmetic_the_offsets_have_to_support(self):
        """`cmp al,[esi+ecx]` -- the sum is the faulting address.

        If `FloatSave`'s 112 bytes were mishandled every register would read as
        its neighbour, and a shift like that lands on plausible values rather
        than on obvious garbage. This pins the layout against the one
        arithmetic identity the real dump has to satisfy.
        """
        context = self._context(esi=0x320BF2BC, ecx=0x00D3E258)
        registers = parse(self._dump_with(context)).exception()["context"]
        self.assertEqual(
            (registers["esi"] + registers["ecx"]) & 0xFFFFFFFF, 0x32DFD514)

    def test_a_context_pointing_off_the_end_warns_and_keeps_the_code(self):
        blob = bytearray(_dump({EXCEPTION_STREAM: self._payload(0x7FFFFFFF),
                                SYSTEM_INFO: struct.pack(
                                    "<HHBBHIIII", 0, 0, 0, 4, 0, 10, 0, 26200, 0)}))
        dump = parse(bytes(blob))
        exception = dump.exception()
        self.assertEqual(exception["code"], 0xC0000005)
        self.assertNotIn("context", exception)
        self.assertTrue(any("thread context" in w for w in dump.warnings))

    def test_absent_stream_is_empty_without_a_warning(self):
        dump = parse(_dump({MODULE_LIST: struct.pack("<I", 0)}))
        self.assertEqual(dump.exception(), {})
        self.assertEqual(dump.warnings, [])


@pytest.mark.slow
class AgainstARealDump(unittest.TestCase):
    """Validated against a dump the operating system wrote.

    The standing rule in this suite. A fixture contains what its author thought
    of; the carver's first false-positive class was invisible to every synthetic
    dump in the project and turned up immediately against a real one.
    """

    def test_parses_a_dump_windows_wrote(self):
        from dynamic_analysis.tests.make_reference_dump import write_self_dump

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "self.dmp"
            try:
                write_self_dump(path)
            except Exception as exc:                      # pragma: no cover
                self.skipTest(f"MiniDumpWriteDump unavailable: {exc}")

            dump = parse(path)
            modules = dump.modules()
            self.assertGreater(len(modules), 5, "a real process has modules")
            names = {m["path"].rsplit("\\", 1)[-1].lower() for m in modules}
            self.assertIn("ntdll.dll", names)

            # Every module must have a plausible base and a name; a shifted
            # read shows up here as zeros or as unreadable strings.
            for module in modules:
                self.assertGreater(module["base"], 0)
                self.assertTrue(module["path"])

            self.assertEqual(dump.warnings, [], f"warnings: {dump.warnings}")

            info = dump.system_info()
            self.assertIn(info.get("architecture"), {"x86", "x64", "arm64"})

            # The unloaded list is genuinely often absent. Absent is fine;
            # present-and-garbled is not, so check shape only when it exists.
            for entry in dump.unloaded_modules():
                self.assertGreater(entry["base"], 0)
                self.assertLess(entry["size"], 1 << 32)

            ranges = dump.memory_ranges()
            self.assertTrue(ranges, "a full-memory dump has ranges")
            for _va, offset, size in ranges[:200]:
                self.assertLessEqual(offset + size, path.stat().st_size)

            threads = dump.threads()
            self.assertTrue(threads, "a real process has at least one thread")
            for thread in threads:
                self.assertGreater(thread["stack_base"], 0)
                self.assertGreater(thread["stack_end"], thread["stack_base"])
                self.assertGreater(thread["teb"], 0)

            # Regions must partition the address space in order, with no
            # overlaps -- the shape a shifted stride destroys first.
            regions = dump.memory_info()
            self.assertTrue(regions, "a real dump carries VirtualQuery data")
            previous_end = 0
            for region in regions:
                self.assertGreaterEqual(region["base"], previous_end)
                self.assertGreater(region["size"], 0)
                self.assertIn(region["state_name"],
                              {"commit", "reserve", "free"})
                previous_end = region["end"]

            # And every thread stack must fall inside a region this reader can
            # name, which is the cross-check the two streams give each other.
            for thread in threads:
                region = dump.region_of(thread["stack_base"])
                self.assertIsNotNone(
                    region, f"stack {thread['stack_base']:#x} in no region")



if __name__ == "__main__":
    unittest.main()
