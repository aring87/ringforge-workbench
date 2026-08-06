"""Finding the PE a loader wrote into a process it did not own.

Reconstructed from the 05 Aug hand-carve. A .NET loader hollowed RegSvcs.exe and
mapped a 56 KB stage-2 assembly alongside the real image; the host header
carried timestamp 0x5ff2b99b and the image beside it carried a 2025 one, which
is process hollowing confirmed by PE headers independently of any detector. That
payload matched no rule in the set -- 428 strings, no URLs, no domains, no family
markers -- so a signature was never going to find it.

The dumps are synthesised here rather than fixtured. A real minidump is hundreds
of megabytes and cannot go in a repository, and building one by hand states what
the parser actually depends on: the module list, the memory ranges, and where
those two disagree.
"""

import struct
import tempfile
import unittest
from pathlib import Path

from dynamic_analysis.pe_carve import (
    analyze_dump,
    carve_dumps,
    parse_pe_header,
    read_module_index,
    summarize_pe_carve,
)

MODULE_LIST_STREAM = 4
MEMORY64_LIST_STREAM = 9


#: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
_CODE_SECTION = 0x20000020
#: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
_DATA_SECTION = 0x40000040


def make_pe(
    size_of_image: int = 0x4000,
    timestamp: int = 0x5FF2B99B,
    machine: int = 0x014C,
    dotnet: bool = False,
    sections: int = 3,
    characteristics: int = 0x0102,
    e_lfanew: int = 0x80,
    code: bool = True,
    raw_layout: bool = False,
) -> bytes:
    """A memory image of a PE: valid headers, zeroed body.

    ``code=False`` produces a resource-only image -- no SizeOfCode, no entry
    point, no executable section -- which is what Windows maps into every
    process when it loads localised resources, and which the carver must not
    report.
    """
    image = bytearray(size_of_image)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, e_lfanew)

    pe = e_lfanew
    image[pe:pe + 4] = b"PE\x00\x00"
    struct.pack_into("<H", image, pe + 4, machine)
    struct.pack_into("<H", image, pe + 6, sections)
    struct.pack_into("<I", image, pe + 8, timestamp)
    struct.pack_into("<H", image, pe + 20, 0xE0)          # SizeOfOptionalHeader
    struct.pack_into("<H", image, pe + 22, characteristics)

    optional = pe + 24
    struct.pack_into("<H", image, optional, 0x010B)        # PE32
    struct.pack_into("<I", image, optional + 4, 0x1000 if code else 0)   # SizeOfCode
    struct.pack_into("<I", image, optional + 16, 0x1000 if code else 0)  # EntryPoint
    struct.pack_into("<I", image, optional + 56, size_of_image)

    table = optional + 0xE0
    raw_cursor = 0x400
    for index in range(sections):
        entry = table + index * 40
        if entry + 40 > size_of_image:
            break
        executable = code and index == 0
        image[entry:entry + 8] = (b".text" if executable else b".rdata").ljust(8, b"\x00")
        if raw_layout:
            # SizeOfRawData / PointerToRawData, so the image has a file size
            # distinct from its mapped SizeOfImage -- the shape a payload sits
            # in before a loader maps it.
            struct.pack_into("<I", image, entry + 16, 0x1000)
            struct.pack_into("<I", image, entry + 20, raw_cursor)
            raw_cursor += 0x1000
        struct.pack_into("<I", image, entry + 36,
                         _CODE_SECTION if executable else _DATA_SECTION)

    if dotnet:
        directory = optional + 96
        struct.pack_into("<I", image, directory + 14 * 8, 0x2008)  # CLR header RVA

    return bytes(image)


def build_minidump(modules: list[dict], regions: list[dict]) -> bytes:
    """A minidump carrying a module list and a set of memory ranges.

    ``modules`` are {base, size, timestamp, path}; ``regions`` are {va, data}.
    """
    stream_count = 2
    directory_rva = 32
    body_start = directory_rva + stream_count * 12

    # --- module list, with the name strings after it ---------------------
    module_list_rva = body_start
    module_list_size = 4 + len(modules) * 108
    strings_rva = module_list_rva + module_list_size

    strings = bytearray()
    name_rvas = []
    for module in modules:
        name_rvas.append(strings_rva + len(strings))
        encoded = module["path"].encode("utf-16-le")
        strings += struct.pack("<I", len(encoded)) + encoded

    module_blob = bytearray(struct.pack("<I", len(modules)))
    for module, name_rva in zip(modules, name_rvas):
        entry = bytearray(108)
        struct.pack_into("<Q", entry, 0, module["base"])
        struct.pack_into("<I", entry, 8, module["size"])
        struct.pack_into("<I", entry, 16, module.get("timestamp", 0))
        struct.pack_into("<I", entry, 20, name_rva)
        module_blob += entry

    # --- memory64 list, whose data is one contiguous run ------------------
    memory_list_rva = strings_rva + len(strings)
    memory_list_size = 16 + len(regions) * 16
    base_rva = memory_list_rva + memory_list_size

    memory_blob = bytearray(struct.pack("<QQ", len(regions), base_rva))
    payload = bytearray()
    for region in regions:
        memory_blob += struct.pack("<QQ", region["va"], len(region["data"]))
        payload += region["data"]

    header = bytearray(32)
    header[0:4] = b"MDMP"
    struct.pack_into("<I", header, 4, 0xA793)
    struct.pack_into("<I", header, 8, stream_count)
    struct.pack_into("<I", header, 12, directory_rva)

    directory = bytearray()
    directory += struct.pack("<III", MODULE_LIST_STREAM, module_list_size, module_list_rva)
    directory += struct.pack("<III", MEMORY64_LIST_STREAM, memory_list_size, memory_list_rva)

    return bytes(header + directory + module_blob + strings + memory_blob + payload)


class PeHeaderTests(unittest.TestCase):
    def test_a_real_header_is_read(self) -> None:
        image = make_pe(size_of_image=0x4000, timestamp=0x5FF2B99B)
        header = parse_pe_header(image, 0, len(image))

        self.assertIsNotNone(header)
        self.assertEqual(header["machine"], "x86")
        self.assertEqual(header["size_of_image"], 0x4000)
        self.assertEqual(header["timestamp_hex"], "0x5ff2b99b")
        self.assertEqual(header["compiled"], "2021-01-04")
        self.assertFalse(header["dotnet"])

    def test_a_dotnet_image_is_identified(self) -> None:
        # It is why a signature set can match nothing: the 05 Aug payload was an
        # obfuscated managed assembly with its config in a .rsrc blob.
        header = parse_pe_header(make_pe(dotnet=True), 0, 0x4000)
        self.assertTrue(header["dotnet"])

    def test_mz_without_a_pe_signature_is_not_a_pe(self) -> None:
        image = bytearray(make_pe())
        image[0x80:0x84] = b"XXXX"
        self.assertIsNone(parse_pe_header(bytes(image), 0, len(image)))

    def test_a_header_running_past_its_region_is_refused(self) -> None:
        # Two bytes reading MZ at the end of one range and unrelated bytes
        # following them in the file is exactly the coincidence to reject.
        image = make_pe()
        self.assertIsNone(parse_pe_header(image, 0, 0x40))

    def test_implausible_fields_are_refused(self) -> None:
        self.assertIsNone(parse_pe_header(make_pe(machine=0x1234), 0, 0x4000))
        self.assertIsNone(parse_pe_header(make_pe(sections=0), 0, 0x4000))
        # Not a multiple of the page size, so not something that was mapped.
        self.assertIsNone(parse_pe_header(make_pe(size_of_image=0x4321), 0, 0x4321))
        # No IMAGE_FILE_EXECUTABLE_IMAGE.
        self.assertIsNone(parse_pe_header(make_pe(characteristics=0x0100), 0, 0x4000))


class AnalyzeDumpTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _write(self, name: str, blob: bytes) -> Path:
        path = self.tmp / name
        path.write_bytes(blob)
        return path

    def _hollowed(self) -> bytes:
        """RegSvcs.exe with a foreign .NET image mapped alongside the real one."""
        host = make_pe(size_of_image=0x10000, timestamp=0x5FF2B99B)
        payload = make_pe(size_of_image=0xE000, timestamp=0x6851D400, dotnet=True)
        return build_minidump(
            modules=[
                {"base": 0x400000, "size": 0x10000, "timestamp": 0x5FF2B99B,
                 "path": r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe"},
                {"base": 0x77000000, "size": 0x20000, "timestamp": 0x5A4A1B2C,
                 "path": r"C:\Windows\System32\ntdll.dll"},
            ],
            regions=[
                {"va": 0x400000, "data": host},
                {"va": 0x77000000, "data": make_pe(size_of_image=0x20000)},
                {"va": 0x2000000, "data": payload},
            ],
        )

    def test_the_foreign_image_is_the_one_reported(self) -> None:
        path = self._write("RegSvcs.dmp", self._hollowed())
        result = analyze_dump(path)

        self.assertTrue(result["parsed"], result["error"])
        self.assertEqual(result["counts"]["at_module_base"], 2)
        self.assertEqual(result["counts"]["unmapped"], 1)

        unmapped = [i for i in result["images"] if i["classification"] == "unmapped"]
        self.assertEqual(unmapped[0]["virtual_address"], "0x2000000")
        self.assertEqual(unmapped[0]["size_of_image"], 0xE000)
        self.assertTrue(unmapped[0]["dotnet"])

    def test_the_host_timestamp_is_kept_for_comparison(self) -> None:
        # The comparison is the finding: an image four years newer than the
        # process hosting it did not ship with it.
        result = analyze_dump(self._write("RegSvcs.dmp", self._hollowed()))

        self.assertEqual(result["host_image_timestamp_hex"], "0x5ff2b99b")
        unmapped = [i for i in result["images"] if i["classification"] == "unmapped"]
        self.assertEqual(unmapped[0]["compiled"], "2025-06-17")

    def test_ordinary_modules_are_not_findings(self) -> None:
        clean = build_minidump(
            modules=[
                {"base": 0x400000, "size": 0x10000, "timestamp": 1, "path": "app.exe"},
                {"base": 0x77000000, "size": 0x20000, "timestamp": 2, "path": "ntdll.dll"},
            ],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x10000)},
                {"va": 0x77000000, "data": make_pe(size_of_image=0x20000)},
            ],
        )
        result = analyze_dump(self._write("clean.dmp", clean))

        self.assertEqual(result["counts"]["unmapped"], 0)
        self.assertEqual(result["counts"]["at_module_base"], 2)

    def test_a_second_image_within_a_module_is_reported_separately(self) -> None:
        # Real loaders produce this occasionally -- a DLL held in a resource
        # section -- so it is reported and deliberately not scored.
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x10000, "timestamp": 1, "path": "app.exe"}],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x4000)
                 + bytes(0x4000) + make_pe(size_of_image=0x4000, timestamp=0x60000000)},
            ],
        )
        result = analyze_dump(self._write("resource.dmp", blob))

        self.assertEqual(result["counts"]["inside_module"], 1)
        self.assertEqual(result["counts"]["unmapped"], 0)

    def test_unaligned_mz_bytes_are_not_candidates(self) -> None:
        # A copy of a file sitting in a heap buffer is the common case, and it
        # does not land on a page boundary.
        noise = bytearray(0x4000)
        noise[0x1234:0x1234 + 0x1000] = make_pe(size_of_image=0x1000)[:0x1000]
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x4000, "timestamp": 1, "path": "app.exe"}],
            regions=[{"va": 0x900000, "data": bytes(noise)}],
        )
        result = analyze_dump(self._write("heap.dmp", blob))

        self.assertEqual(result["counts"]["unmapped"], 0)

    def test_a_resource_only_image_is_not_a_finding(self) -> None:
        # Found by running this over a real minidump of an idle Python process,
        # which reported eleven unmapped PE images. All eleven were genuine --
        # .rdata and .rsrc, no code -- and all eleven were MUI resource files
        # that Windows maps as data without registering them with the loader.
        # A signal that fires on every process on the machine says nothing
        # about any of them, so the test is "a PE that could execute".
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x10000, "timestamp": 1, "path": "app.exe"}],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x10000)},
                {"va": 0x1B3E7840000, "data": make_pe(size_of_image=0x8000, sections=2,
                                                      characteristics=0x2102, code=False)},
            ],
        )
        result = analyze_dump(self._write("mui.dmp", blob))

        self.assertEqual(result["counts"]["unmapped"], 0)
        # Counted, not discarded: a run reporting none of these is a run whose
        # dumps were not searched properly.
        self.assertEqual(result["counts"]["resource_only"], 1)

    def test_a_payload_next_to_resource_files_is_still_found(self) -> None:
        # The narrowing must not cost the finding it was added around.
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x10000, "timestamp": 1,
                      "path": r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe"}],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x10000)},
                {"va": 0x1B3E7840000, "data": make_pe(size_of_image=0x8000, sections=2,
                                                      characteristics=0x2102, code=False)},
                {"va": 0x2000000, "data": make_pe(size_of_image=0xE000, dotnet=True,
                                                  timestamp=0x6851D400)},
            ],
        )
        result = analyze_dump(self._write("both.dmp", blob))

        self.assertEqual(result["counts"]["unmapped"], 1)
        self.assertEqual(result["counts"]["resource_only"], 1)
        unmapped = [i for i in result["images"] if i["classification"] == "unmapped"]
        self.assertEqual(unmapped[0]["virtual_address"], "0x2000000")

    def test_a_system_dll_another_dump_enumerated_is_not_a_finding(self) -> None:
        # The false positive that made the carver's first strong finding wrong.
        # A process created suspended -- which is what hollowing does -- has
        # ntdll mapped before its module list is populated, so it is physically
        # present and legitimately absent from the list being checked against.
        # Six carved copies of ntdll.dll were reported as unmapped images inside
        # a hollowing target, on dumps enumerating 6 and 11 modules while the
        # loader's own dump enumerated 65 including ntdll.
        ntdll = make_pe(size_of_image=0x8000, timestamp=0xD277D290)
        suspended = build_minidump(
            modules=[{"base": 0x400000, "size": 0x10000, "timestamp": 1,
                      "path": r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe"}],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x10000)},
                {"va": 0x1750000, "data": ntdll},
            ],
        )
        path = self._write("suspended.dmp", suspended)

        # Without the index it reads as a foreign image.
        self.assertEqual(analyze_dump(path)["counts"]["unmapped"], 1)

        # The loader's own dump enumerates the same build properly.
        known = {(0xD277D290, 0x8000)}
        result = analyze_dump(path, known_modules=known)

        self.assertEqual(result["counts"]["unmapped"], 0)
        self.assertEqual(result["counts"]["known_module"], 1)

    def test_a_payload_nothing_enumerates_is_still_a_finding(self) -> None:
        # The narrowing must not cost the image it was built to find:
        # SmartOptimization.dll appears in no module list anywhere.
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x10000, "timestamp": 1,
                      "path": r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe"}],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x10000)},
                {"va": 0x1750000, "data": make_pe(size_of_image=0x8000, timestamp=0xD277D290)},
                {"va": 0x2000000, "data": make_pe(size_of_image=0xE000, dotnet=True,
                                                  timestamp=0x6A71514C)},
            ],
        )
        result = analyze_dump(
            self._write("both.dmp", blob), known_modules={(0xD277D290, 0x8000)}
        )

        self.assertEqual(result["counts"]["known_module"], 1)
        self.assertEqual(result["counts"]["unmapped"], 1)
        unmapped = [i for i in result["images"] if i["classification"] == "unmapped"]
        self.assertTrue(unmapped[0]["dotnet"])

    def test_the_index_is_read_from_a_dumps_module_list(self) -> None:
        blob = build_minidump(
            modules=[
                {"base": 0x400000, "size": 0x10000, "timestamp": 0x5FF2B99B, "path": "app.exe"},
                {"base": 0x1750000, "size": 0x8000, "timestamp": 0xD277D290, "path": "ntdll.dll"},
            ],
            regions=[{"va": 0x400000, "data": make_pe(size_of_image=0x10000)}],
        )

        index = read_module_index(self._write("index.dmp", blob))

        self.assertIn((0xD277D290, 0x8000), index)
        self.assertIn((0x5FF2B99B, 0x10000), index)

    def test_an_impossible_timestamp_is_not_rendered_as_a_date(self) -> None:
        # Microsoft's reproducible builds put a hash in TimeDateStamp, not a
        # build time, so ntdll reads 0xd277d290 -- which the old bound rendered
        # as "2081-11-22". A date in the future is a signal the field is not a
        # date; saying nothing beats saying something false.
        header = parse_pe_header(make_pe(timestamp=0xD277D290), 0, 0x4000)

        self.assertEqual(header["timestamp_hex"], "0xd277d290")
        self.assertEqual(header["compiled"], "")

    def test_an_image_split_across_regions_is_reassembled(self) -> None:
        # A minidump splits an address space by protection, so a mapped image
        # routinely spans several ranges -- headers and code in one, writable
        # data in the next. Reading only the range the MZ was found in cost
        # 24 KB of SmartOptimization.dll: 57,344 of 81,920 bytes carved, and its
        # .rsrc came out at half size with the config blob in the part never
        # read.
        payload = make_pe(size_of_image=0x4000, dotnet=True)
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x10000, "timestamp": 1, "path": "app.exe"}],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x10000)},
                # The payload, cut in half across two adjacent ranges.
                {"va": 0x2000000, "data": payload[:0x2000]},
                {"va": 0x2002000, "data": payload[0x2000:]},
            ],
        )
        path = self._write("split.dmp", blob)

        unmapped = [
            i for i in analyze_dump(path)["images"]
            if i["classification"] == "unmapped"
        ]

        self.assertEqual(len(unmapped), 1)
        self.assertEqual(unmapped[0]["available_bytes"], 0x4000)
        self.assertFalse(unmapped[0]["truncated"])
        self.assertEqual(unmapped[0]["regions_spanned"], 2)

        carved = carve_dumps(
            [{"pid": 1, "name": "app.exe", "path": str(path),
              "trigger": "scheduled", "offset_seconds": 5}],
            output_dir=self.tmp / "out",
        )
        written = Path(carved["images"][0]["carved_path"]).read_bytes()

        self.assertEqual(len(written), 0x4000)
        self.assertEqual(written, payload)

    def test_a_payload_in_file_layout_is_complete_not_truncated(self) -> None:
        # SizeOfImage is the *mapped* footprint. A payload that has not been
        # mapped yet is smaller, and judging it against SizeOfImage reported a
        # complete carve of SmartOptimization.dll as 24 KB short -- 57,344 of a
        # declared 81,920, when 57,344 was every byte there was. Every payload
        # held by Assembly.Load(byte[]) or a decrypt-then-map loader would have
        # read as truncated forever.
        payload = make_pe(size_of_image=0x4000, dotnet=True, raw_layout=True)
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x10000, "timestamp": 1, "path": "app.exe"}],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x10000)},
                # The region holds the whole file plus its page padding, and
                # stops well short of SizeOfImage.
                {"va": 0x2000000, "data": payload[:0x3800]},
            ],
        )
        path = self._write("filelayout.dmp", blob)

        unmapped = [
            i for i in analyze_dump(path)["images"]
            if i["classification"] == "unmapped"
        ]

        self.assertEqual(len(unmapped), 1)
        self.assertEqual(unmapped[0]["layout"], "file")
        self.assertFalse(unmapped[0]["truncated"])
        # 0x400 headers + three sections of 0x1000.
        self.assertEqual(unmapped[0]["file_size"], 0x3400)
        self.assertEqual(unmapped[0]["carve_bytes"], 0x3400)

    def test_a_file_layout_carve_drops_the_trailing_padding(self) -> None:
        payload = make_pe(size_of_image=0x4000, dotnet=True, raw_layout=True)
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x10000, "timestamp": 1, "path": "app.exe"}],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x10000)},
                {"va": 0x2000000, "data": payload[:0x3800]},
            ],
        )
        path = self._write("padding.dmp", blob)

        carved = carve_dumps(
            [{"pid": 1, "name": "app.exe", "path": str(path),
              "trigger": "scheduled", "offset_seconds": 5}],
            output_dir=self.tmp / "out",
        )
        written = Path(carved["images"][0]["carved_path"]).read_bytes()

        self.assertEqual(len(written), 0x3400)
        self.assertFalse(carved["images"][0]["truncated"])

    def test_a_mapped_image_is_still_judged_against_size_of_image(self) -> None:
        # Mapped is tested first: an image big enough to be the mapping is the
        # mapping, whatever its file size would have been.
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x10000, "timestamp": 1, "path": "app.exe"}],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x10000)},
                {"va": 0x2000000, "data": make_pe(size_of_image=0x4000, dotnet=True,
                                                  raw_layout=True)},
            ],
        )

        unmapped = [
            i for i in analyze_dump(self._write("mapped.dmp", blob))["images"]
            if i["classification"] == "unmapped"
        ]

        self.assertEqual(unmapped[0]["layout"], "mapped")
        self.assertEqual(unmapped[0]["carve_bytes"], 0x4000)
        self.assertFalse(unmapped[0]["truncated"])

    def test_a_genuinely_short_image_is_still_truncated(self) -> None:
        # The narrowing must not turn every short read into a clean result.
        payload = make_pe(size_of_image=0x4000, dotnet=True, raw_layout=True)
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x10000, "timestamp": 1, "path": "app.exe"}],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x10000)},
                # Less than even the file layout needs.
                {"va": 0x2000000, "data": payload[:0x2000]},
            ],
        )

        unmapped = [
            i for i in analyze_dump(self._write("short.dmp", blob))["images"]
            if i["classification"] == "unmapped"
        ]

        self.assertTrue(unmapped[0]["truncated"])
        self.assertEqual(unmapped[0]["carve_bytes"], 0x2000)

    def test_a_gap_in_the_address_space_is_not_bridged(self) -> None:
        # Splicing across a gap would fabricate an artifact rather than truncate
        # one: the rest of the image was simply never captured.
        payload = make_pe(size_of_image=0x4000, dotnet=True)
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x10000, "timestamp": 1, "path": "app.exe"}],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x10000)},
                {"va": 0x2000000, "data": payload[:0x2000]},
                # Not adjacent: a page of address space is missing.
                {"va": 0x2003000, "data": payload[0x2000:]},
            ],
        )

        unmapped = [
            i for i in analyze_dump(self._write("gap.dmp", blob))["images"]
            if i["classification"] == "unmapped"
        ]

        self.assertEqual(unmapped[0]["available_bytes"], 0x2000)
        self.assertTrue(unmapped[0]["truncated"])
        self.assertEqual(unmapped[0]["regions_spanned"], 1)

    def test_rejected_candidates_are_counted(self) -> None:
        # "We found no foreign image" and "we rejected everything that started
        # with MZ" are different statements about the same dump.
        page = bytearray(0x1000)
        page[0:2] = b"MZ"
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x1000, "timestamp": 1, "path": "app.exe"}],
            regions=[{"va": 0x900000, "data": bytes(page)}],
        )
        result = analyze_dump(self._write("junk.dmp", blob))

        self.assertEqual(result["counts"]["unmapped"], 0)
        self.assertEqual(result["counts"]["rejected"], 1)

    def test_a_file_that_is_not_a_minidump_degrades(self) -> None:
        result = analyze_dump(self._write("nope.dmp", b"not a dump" * 100))

        self.assertFalse(result["parsed"])
        self.assertIn("not a minidump", result["error"])

    def test_a_dump_without_memory_says_so(self) -> None:
        # DumpType=1 records metadata only, and that has to be tellable from a
        # dump that was searched and had nothing in it.
        blob = build_minidump(
            modules=[{"base": 0x400000, "size": 0x1000, "timestamp": 1, "path": "app.exe"}],
            regions=[],
        )
        result = analyze_dump(self._write("meta.dmp", blob))

        self.assertFalse(result["parsed"])
        self.assertIn("no memory ranges", result["error"])


class CarveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

        blob = build_minidump(
            modules=[
                {"base": 0x400000, "size": 0x10000, "timestamp": 0x5FF2B99B,
                 "path": r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe"},
            ],
            regions=[
                {"va": 0x400000, "data": make_pe(size_of_image=0x10000, timestamp=0x5FF2B99B)},
                {"va": 0x2000000, "data": make_pe(size_of_image=0xE000,
                                                  timestamp=0x6851D400, dotnet=True)},
            ],
        )
        self.dump = self.tmp / "RegSvcs.exe_4312_t20_redump.dmp"
        self.dump.write_bytes(blob)
        self.record = {
            "pid": 4312,
            "name": "RegSvcs.exe",
            "path": str(self.dump),
            "trigger": "spawn-redump",
            "offset_seconds": 30,
        }

    def test_the_payload_is_written_out(self) -> None:
        out = self.tmp / "carved"
        result = carve_dumps([self.record], output_dir=out)

        self.assertEqual(result["counts"]["unmapped_images"], 1)
        self.assertEqual(result["counts"]["carved"], 1)

        image = result["images"][0]
        carved = Path(image["carved_path"])
        self.assertTrue(carved.exists())
        self.assertEqual(carved.stat().st_size, 0xE000)
        self.assertEqual(carved.read_bytes()[:2], b"MZ")
        self.assertTrue(image["carved_sha256"])

    def test_a_hollowing_target_is_marked(self) -> None:
        # The same distinction the crash evidence draws: a foreign image inside
        # a binary loaders hollow is a different claim from one anywhere else.
        result = carve_dumps([self.record], output_dir=self.tmp / "carved")

        self.assertEqual(result["counts"]["unmapped_in_hollowing_target"], 1)
        self.assertEqual(result["counts"]["dotnet_images"], 1)

    def test_the_carved_file_is_not_double_clickable(self) -> None:
        # This is live malware written to a directory an analyst browses.
        result = carve_dumps([self.record], output_dir=self.tmp / "carved")

        self.assertTrue(result["images"][0]["carved_path"].endswith(".bin_"))

    def test_the_carve_is_bounded_by_the_ceiling(self) -> None:
        result = carve_dumps(
            [self.record], output_dir=self.tmp / "carved", max_bytes=0x1000
        )

        image = result["images"][0]
        self.assertEqual(image["carved_size"], 0x1000)
        self.assertTrue(Path(image["carved_path"]).exists())

    def test_mapped_modules_are_not_written_out(self) -> None:
        # Writing every mapped DLL would bury the one image that matters.
        result = carve_dumps([self.record], output_dir=self.tmp / "carved")

        carved = list((self.tmp / "carved").glob("*"))
        self.assertEqual(len(carved), 1)

    def test_a_failed_dump_costs_only_that_dump(self) -> None:
        bad = self.tmp / "truncated.dmp"
        bad.write_bytes(b"MDMP" + bytes(28))
        result = carve_dumps(
            [{"pid": 1, "name": "x.exe", "path": str(bad)}, self.record],
            output_dir=self.tmp / "carved",
        )

        self.assertEqual(result["counts"]["dumps_failed"], 1)
        self.assertEqual(result["counts"]["dumps_analyzed"], 1)
        self.assertEqual(result["counts"]["carved"], 1)

    def test_the_summary_pairs_the_two_timestamps(self) -> None:
        summary = summarize_pe_carve(carve_dumps([self.record], output_dir=self.tmp / "carved"))

        image = summary["images"][0]
        self.assertEqual(image["host_image_timestamp_hex"], "0x5ff2b99b")
        self.assertEqual(image["timestamp_hex"], "0x6851d400")
        self.assertEqual(image["process"], "RegSvcs.exe")
        self.assertTrue(image["hollowing_target"])

    def test_an_empty_result_summarises_without_raising(self) -> None:
        self.assertFalse(summarize_pe_carve({})["carved"])
        self.assertFalse(summarize_pe_carve(None)["carved"])


if __name__ == "__main__":
    unittest.main()
