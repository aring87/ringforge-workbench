"""The reference cache, and the header_mismatch it used to drop.

Fast: no dump is written. These drive `_reference_sections` directly, because
the bug they pin is in the cache handoff rather than in dump parsing, and a bug
reachable without a 125 MB fixture should be caught by a test that does not need
one.

The bug: the identity mismatch was written into a `_MISMATCHED` dict during
lookup and read back after, with the cache eviction sitting between the two --

    _MISMATCHED[key] = {...}
    if len(_REFERENCE_CACHE) >= _CACHE_LIMIT:
        _REFERENCE_CACHE.clear()
        _MISMATCHED.clear()          # including the entry just written
    _REFERENCE_CACHE[key] = sections

so the module that happened to cross the 96-entry limit lost its
`header_mismatch` and was graded by degree instead. That is the outcome the
comment on that branch says must never happen: a payload sharing most of its
bytes with the file it impersonates would file as `identical`. Any process with
more than 96 distinct modules can reach it.
"""
import struct
import tempfile
import unittest
from pathlib import Path

from dynamic_analysis import module_integrity as mi


def _pe_on_disk(path: Path, timestamp: int, size_of_image: int = 0x2000) -> None:
    """A PE just complete enough for pefile to open and report identity."""
    import pefile

    # Build from a real minimal PE rather than by hand: pefile is strict, and a
    # fixture it refuses to parse would test nothing.
    e_lfanew = 0x80
    opt_size = 0xE0
    n_sections = 1
    size = e_lfanew + 24 + opt_size + 40 + 0x200
    blob = bytearray(size)
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, e_lfanew)
    blob[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<H", blob, e_lfanew + 4, 0x8664)          # machine
    struct.pack_into("<H", blob, e_lfanew + 6, n_sections)
    struct.pack_into("<I", blob, e_lfanew + 8, timestamp)
    struct.pack_into("<H", blob, e_lfanew + 20, opt_size)
    struct.pack_into("<H", blob, e_lfanew + 22, 0x0002)         # executable
    opt = e_lfanew + 24
    struct.pack_into("<H", blob, opt, 0x20B)                    # PE32+
    struct.pack_into("<Q", blob, opt + 24, 0x140000000)         # ImageBase
    struct.pack_into("<I", blob, opt + 32, 0x1000)              # SectionAlignment
    struct.pack_into("<I", blob, opt + 36, 0x200)               # FileAlignment
    struct.pack_into("<I", blob, opt + 56, size_of_image)
    struct.pack_into("<I", blob, opt + 60, 0x200)               # SizeOfHeaders
    sec = opt + opt_size
    blob[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<I", blob, sec + 8, 0x400)                # VirtualSize
    struct.pack_into("<I", blob, sec + 12, 0x1000)              # VirtualAddress
    struct.pack_into("<I", blob, sec + 16, 0x400)               # SizeOfRawData
    struct.pack_into("<I", blob, sec + 20, 0x200)               # PointerToRawData
    struct.pack_into("<I", blob, sec + 36, 0x60000020)          # CODE|EXEC|READ
    path.write_bytes(bytes(blob))
    pefile.PE(str(path), fast_load=True).close()                # must parse


class MismatchSurvivesEviction(unittest.TestCase):
    def setUp(self):
        mi._REFERENCE_CACHE.clear()
        self.addCleanup(mi._REFERENCE_CACHE.clear)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def test_a_mismatch_is_reported_on_a_cold_cache(self):
        path = self.tmp / "victim.dll"
        _pe_on_disk(path, timestamp=0x11111111)
        _sections, mismatch = mi._reference_sections(
            str(path), timestamp=0xDEADBEEF, size_of_image=0x2000,
            base=0x140000000)
        self.assertIsNotNone(mismatch)
        self.assertEqual(mismatch["file_timestamp"], 0x11111111)
        self.assertEqual(mismatch["module_timestamp"], 0xDEADBEEF)

    def test_a_mismatch_survives_the_lookup_that_evicts_the_cache(self):
        """The regression. Fill the cache to the limit, then mismatch."""
        filler = self.tmp / "filler.dll"
        _pe_on_disk(filler, timestamp=0x22222222)
        for n in range(mi._CACHE_LIMIT):
            # Distinct keys, same file: the point is cache pressure, not IO.
            mi._reference_sections(str(filler), timestamp=0x22222222,
                                   size_of_image=0x2000, base=0x140000000 + n * 0x1000)
        self.assertGreaterEqual(len(mi._REFERENCE_CACHE), mi._CACHE_LIMIT)

        victim = self.tmp / "victim.dll"
        _pe_on_disk(victim, timestamp=0x11111111)
        _sections, mismatch = mi._reference_sections(
            str(victim), timestamp=0xDEADBEEF, size_of_image=0x2000,
            base=0x140000000)
        # Before the fix this was None: the eviction cleared the parallel dict
        # between the write and the read, and the module graded by degree.
        self.assertIsNotNone(
            mismatch,
            "header_mismatch was dropped by the cache eviction -- a payload "
            "would grade by degree and could file as identical")

    def test_the_cached_answer_keeps_its_mismatch(self):
        path = self.tmp / "victim.dll"
        _pe_on_disk(path, timestamp=0x11111111)
        args = dict(timestamp=0xDEADBEEF, size_of_image=0x2000, base=0x140000000)
        first = mi._reference_sections(str(path), **args)
        second = mi._reference_sections(str(path), **args)   # served from cache
        self.assertEqual(first[1], second[1])
        self.assertIsNotNone(second[1])

    def test_a_matching_build_reports_no_mismatch(self):
        path = self.tmp / "clean.dll"
        _pe_on_disk(path, timestamp=0x33333333)
        _sections, mismatch = mi._reference_sections(
            str(path), timestamp=0x33333333, size_of_image=0x2000,
            base=0x140000000)
        self.assertIsNone(mismatch)


if __name__ == "__main__":
    unittest.main()
