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
        mi.reset_reference_cache()
        self.addCleanup(mi.reset_reference_cache)
        # The cache is bounded by BYTES with LRU eviction now, not by a count
        # with a wholesale clear -- run `33fe6c3b` put 380 modules past a
        # 96-entry limit, which meant no cache at all. Shrink the entry backstop
        # so eviction is reachable without writing thousands of files; the
        # invariant under test is "a mismatch survives eviction", whatever
        # triggers the eviction.
        self._entry_limit = mi._CACHE_ENTRY_LIMIT
        mi._CACHE_ENTRY_LIMIT = 8
        self.addCleanup(setattr, mi, "_CACHE_ENTRY_LIMIT", self._entry_limit)
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
        for n in range(mi._CACHE_ENTRY_LIMIT * 2):
            # Distinct keys, same file: the point is cache pressure, not IO.
            mi._reference_sections(str(filler), timestamp=0x22222222,
                                   size_of_image=0x2000, base=0x140000000 + n * 0x1000)
        # Eviction really happened: bounded, not holding all the keys put in.
        self.assertLessEqual(len(mi._REFERENCE_CACHE), mi._CACHE_ENTRY_LIMIT)

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


class KnownMismatchOutranksCouldNotTell(unittest.TestCase):
    """Both exits from `compare_module` must agree about the same knowledge.

    `if not total: if mismatch: header_mismatch` already says a known identity
    disagreement beats having nothing to compare. The `sections is None` exit
    used to return `no_reference` instead -- *could not tell* about something
    already known.

    Driven through a stub because the natural route needs pefile to fail a
    relocation, and it tolerated every malformed reloc directory tried. The
    rule is worth pinning even where the path is hard to reach.
    """

    def setUp(self):
        self._real = mi._reference_sections
        self.addCleanup(setattr, mi, "_reference_sections", self._real)

    class _Space:
        def read(self, *_a, **_k):
            return None

    def _compare(self, sections, mismatch):
        mi._reference_sections = lambda *a, **k: (sections, mismatch)
        return mi.compare_module(
            self._Space(),
            {"base": 0x400000, "path": r"C:\Windows\RegSvcs.exe",
             "timestamp": 0xDEADBEEF, "size": 0x2000})

    IDENTITY = {"file_timestamp": 1, "module_timestamp": 0xDEADBEEF,
                "file_size_of_image": 0x2000, "module_size_of_image": 0x2000,
                "reference": r"C:\Windows\RegSvcs.exe"}

    def test_no_sections_but_a_known_mismatch_is_header_mismatch(self):
        result = self._compare(None, self.IDENTITY)
        self.assertEqual(result["verdict"], "header_mismatch")
        self.assertEqual(result["identity"], self.IDENTITY)

    def test_empty_sections_and_a_known_mismatch_agree_with_it(self):
        result = self._compare([], self.IDENTITY)
        self.assertEqual(result["verdict"], "header_mismatch")

    def test_no_sections_and_no_mismatch_is_still_no_reference(self):
        # The genuine "could not tell" case must keep saying so.
        result = self._compare(None, None)
        self.assertEqual(result["verdict"], "no_reference")


if __name__ == "__main__":
    unittest.main()


class TheCacheIsBoundedByBytesNotByCount(unittest.TestCase):
    """Run `33fe6c3b`: module integrity took 24 of the run's 27 minutes.

    A `powershell.exe` sample carried **380 modules** past a 96-entry limit
    whose eviction was `_REFERENCE_CACHE.clear()`. The access pattern is *for
    each dump, for each module*, so a small cache under a wholesale clear
    degenerates to no cache at all -- every relocation recomputed on every dump,
    at a measured 1,105 ms mean.

    A count limit is also the wrong bound: what needs bounding is memory, and 96
    entries is 2 MB or 200 MB depending on which DLLs they are.
    """

    def setUp(self):
        mi.reset_reference_cache()
        self.addCleanup(mi.reset_reference_cache)

    def _store(self, key, nbytes):
        mi._cache_store(key, ([("s", 0x1000, b"\0" * nbytes)], None))

    def test_a_hit_does_not_evict_the_rest(self):
        """The regression in one line: the old code cleared everything."""
        for n in range(50):
            self._store(("m", n), 1024)
        self.assertEqual(mi.reference_cache_stats()["entries"], 50)

    def test_eviction_is_lru_and_keeps_what_was_used(self):
        limit, mi._CACHE_ENTRY_LIMIT = mi._CACHE_ENTRY_LIMIT, 4
        self.addCleanup(setattr, mi, "_CACHE_ENTRY_LIMIT", limit)
        for n in range(4):
            self._store(("m", n), 16)
        mi._REFERENCE_CACHE.move_to_end(("m", 0))     # what a cache hit does
        self._store(("m", 99), 16)                    # forces one eviction
        keys = set(mi._REFERENCE_CACHE)
        self.assertIn(("m", 0), keys, "the recently used entry was evicted")
        self.assertNotIn(("m", 1), keys, "the least recently used survived")

    def test_the_byte_budget_bounds_memory(self):
        budget, mi._CACHE_BYTES_LIMIT = mi._CACHE_BYTES_LIMIT, 1024
        self.addCleanup(setattr, mi, "_CACHE_BYTES_LIMIT", budget)
        for n in range(20):
            self._store(("big", n), 256)
        self.assertLessEqual(mi.reference_cache_stats()["bytes"], 1024)
        self.assertGreater(mi.reference_cache_stats()["entries"], 0)

    def test_bytes_are_not_double_counted_when_a_key_is_rewritten(self):
        self._store(("m", 1), 4096)
        before = mi.reference_cache_stats()["bytes"]
        self._store(("m", 1), 4096)
        self.assertEqual(mi.reference_cache_stats()["bytes"], before)
        self.assertEqual(mi.reference_cache_stats()["entries"], 1)

    def test_an_entry_with_no_sections_costs_nothing(self):
        # `no_reference` results are cached too -- they are the answer "this
        # host has no matching build", and recomputing them is the same waste.
        mi._cache_store(("none", 1), (None, {"file_timestamp": 1}))
        self.assertEqual(mi.reference_cache_stats()["bytes"], 0)
        self.assertEqual(mi.reference_cache_stats()["entries"], 1)

    def test_a_process_with_380_modules_stays_cached(self):
        """The exact shape of run `33fe6c3b`, which used to thrash to zero."""
        for n in range(380):
            self._store(("mod", n), 64 * 1024)
        self.assertEqual(mi.reference_cache_stats()["entries"], 380)
