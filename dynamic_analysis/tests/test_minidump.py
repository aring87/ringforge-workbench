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
    MODULE_LIST,
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



if __name__ == "__main__":
    unittest.main()
