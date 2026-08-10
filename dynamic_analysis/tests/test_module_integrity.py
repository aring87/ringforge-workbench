"""Module-integrity checks, against a dump Windows wrote rather than a fixture.

The suite's synthetic dumps contain what their authors thought to put in them,
which is why the PE carver's real false-positive class -- Windows MUI resource
files -- survived 332 passing tests and turned up the first time it met a real
minidump. So this generates one: `make_reference_dump.write_self_dump` calls
`MiniDumpWriteDump` on the test process, giving a genuine module list, genuine
ASLR bases and whatever the host's security software has injected.

The negative control is the interesting half. The positive is synthesised by
overwriting a module's mapped `.text` inside a *copy* of that dump, which tests
the comparison rather than any claim about real malware -- and is labelled that
way in the proven table.
"""
from __future__ import annotations

import mmap
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import pytest

#: Writing a full-memory dump of this process takes tens of seconds, which does
#: not belong in a suite that otherwise runs in two. Marked so the fast loop can
#: skip it -- `pytest -m "not slow"` -- and kept in the system temp directory
#: between runs so a repeat pays only for the analysis.
pytestmark = pytest.mark.slow

from dynamic_analysis.module_integrity import (
    PATCHED_ABOVE, REPLACED_ABOVE, _AddressSpace, analyze_dump,
    summarize_module_integrity)
from dynamic_analysis.pe_carve import _streams, read_modules, read_regions
from dynamic_analysis.tests.make_reference_dump import write_self_dump

_DUMP: Path | None = None
#: `analyze_dump` is the expensive part; the dump does not change between
#: assertions, so it is read once per file rather than once per test.
_CACHE: dict[Path, dict] = {}


def analysis(path: Path) -> dict:
    if path not in _CACHE:
        _CACHE[path] = analyze_dump(path)
    return _CACHE[path]


def _scratch() -> Path:
    root = Path(tempfile.gettempdir()) / "ringforge-test-dumps"
    root.mkdir(parents=True, exist_ok=True)
    return root


def setUpModule() -> None:
    global _DUMP
    target = _scratch() / "reference_self.dmp"
    # Reused across runs. It is a dump of *this* interpreter, so it stays valid
    # as long as the interpreter and its DLLs do; a stale one shows up
    # immediately as modules that no longer resolve to a matching build.
    if not target.exists() or target.stat().st_size < 1_000_000:
        write_self_dump(target)
    _DUMP = target


def tearDownModule() -> None:
    hollowed = _scratch() / "reference_hollowed.dmp"
    if hollowed.exists():
        hollowed.unlink()


class RealDumpTests(unittest.TestCase):
    """Against a dump the operating system wrote."""

    def test_modules_compare_clean(self):
        """No module in an untampered process may read as replaced.

        This is the check that matters. A detector that fires here fires on
        every process on the machine and therefore says nothing about any of
        them -- the carver's eleven-unmapped-images lesson, applied before the
        thing ships rather than after.
        """
        summary = summarize_module_integrity([analysis(_DUMP)])
        self.assertTrue(summary["available"], "nothing was compared at all")
        self.assertGreater(summary["modules_compared"], 10)
        self.assertEqual(summary["counts"]["replaced"], 0, summary["replaced"])
        self.assertEqual(summary["replaced_in_hollowing_target"], 0)

    def test_relocation_is_applied(self):
        """System DLLs are ASLR-relocated, so an unrelocated comparison would
        differ everywhere. If this stops holding, the thresholds below are
        measuring the wrong thing."""
        modules = analysis(_DUMP)["modules"]
        compared = [m for m in modules if m["verdict"] != "no_reference"]
        self.assertTrue(compared)
        self.assertTrue(any(m["relocated"] for m in compared))

    def test_the_measured_floor_sits_under_the_patched_threshold(self):
        """`PATCHED_ABOVE` is set from this, not chosen.

        Across the host's real system DLLs -- including whatever its security
        product hooks into ntdll -- the differing fraction of an untampered
        module stays below a thousandth. The threshold has to sit above that
        floor or every module reads as modified.
        """
        modules = analysis(_DUMP)["modules"]
        floors = [m["differing_fraction"] for m in modules
                  if m["verdict"] == "identical"]
        self.assertTrue(floors)
        self.assertLess(max(floors), PATCHED_ABOVE)
        self.assertLess(PATCHED_ABOVE * 10, REPLACED_ABOVE)

    def test_absent_reference_is_counted_not_skipped(self):
        """A module this host has no matching build of must be reported, so a
        run where nothing could be compared cannot read as a clean run."""
        summary = summarize_module_integrity([analysis(_DUMP)])
        self.assertIn("no_reference", summary["counts"])
        total = sum(summary["counts"].values())
        self.assertEqual(total, len(analysis(_DUMP)["modules"]))


class HollowedDumpTests(unittest.TestCase):
    """Against a copy of that dump with one module's code overwritten.

    Synthetic, and only a test of the comparison: it says the detector notices
    replaced code, not that real hollowing looks like this.
    """

    @classmethod
    def setUpClass(cls):
        cls.path = _scratch() / "reference_hollowed.dmp"
        shutil.copy(_DUMP, cls.path)
        cls.victim = cls._overwrite_a_text_section(cls.path)

    @staticmethod
    def _overwrite_a_text_section(path: Path) -> str:
        """Fill the largest module's mapped `.text` with other bytes, in place."""
        import pefile

        with open(path, "r+b") as handle:
            data = mmap.mmap(handle.fileno(), 0)
            try:
                size = len(data)
                streams = _streams(data, size)
                modules = read_modules(data, size, streams)
                regions = read_regions(data, size, streams)
                space = _AddressSpace(data, regions)
                for module in sorted(modules, key=lambda m: -m["size"]):
                    try:
                        pe = pefile.PE(module["path"], fast_load=True)
                    except Exception:
                        continue
                    with pe:
                        text = next((s for s in pe.sections
                                     if s.Characteristics & 0x20000000
                                     and s.SizeOfRawData > 0x10000), None)
                        if text is None:
                            continue
                        va = module["base"] + text.VirtualAddress
                        length = text.SizeOfRawData
                        if space.read(va, length) is None:
                            continue
                        for region in regions:
                            if region.va <= va < region.va + region.size:
                                offset = region.file_offset + (va - region.va)
                                take = min(length, region.size - (va - region.va))
                                # 0x90 is a byte that appears in real code, so
                                # this is not detected by being implausible.
                                data[offset:offset + take] = b"\x90" * take
                                data.flush()
                                return module["path"].rsplit("\\", 1)[-1].lower()
                raise unittest.SkipTest("no suitable module to overwrite")
            finally:
                data.close()

    def test_overwritten_module_reads_as_replaced(self):
        summary = summarize_module_integrity([analysis(self.path)])
        names = [m["name"] for m in summary["replaced"]]
        self.assertIn(self.victim, names, f"replaced={names}")

    def test_only_the_overwritten_module_is_flagged(self):
        """The rest of the dump is untouched, so exactly one module moves.
        Without this the test would pass just as well on a detector that
        flags everything."""
        summary = summarize_module_integrity([analysis(self.path)])
        self.assertEqual(summary["counts"]["replaced"], 1, summary["replaced"])

    def test_the_difference_is_wholesale(self):
        replaced = summarize_module_integrity([analysis(self.path)])["replaced"]
        self.assertTrue(replaced)
        self.assertGreater(replaced[0]["differing_fraction"], REPLACED_ABOVE)


class SummaryShapeTests(unittest.TestCase):

    def test_empty_input_is_unavailable_not_clean(self):
        summary = summarize_module_integrity([])
        self.assertFalse(summary["available"])
        self.assertEqual(summary["modules_compared"], 0)

    def test_a_dump_with_no_references_is_unavailable(self):
        """Every module unmatched must not read as every module clean."""
        summary = summarize_module_integrity([
            {"dump": "x.dmp", "modules": [{"verdict": "no_reference", "name": "a.dll"}]}])
        self.assertFalse(summary["available"])
        self.assertEqual(summary["counts"]["no_reference"], 1)


if __name__ == "__main__":
    unittest.main()


class HeaderMismatchTests(unittest.TestCase):
    """A module whose loader record disagrees with its file.

    This is the case that walked past the loader's payload on the first live
    run: a second image claiming to be `RegSvcs.exe`, mapped at the preferred
    base while the real one sat relocated and byte-identical elsewhere. The
    identity check that exists to stop version drift from reading as tampering
    also skipped it. It must now be reported, not skipped, and it must be
    reported by *identity* rather than by how many bytes happen to coincide.
    """

    @classmethod
    def setUpClass(cls):
        from dynamic_analysis.pe_carve import _MODULE_ENTRY_SIZE, _MODULE_LIST_STREAM
        cls.path = _scratch() / "reference_mismatch.dmp"
        shutil.copy(_DUMP, cls.path)
        with open(cls.path, "r+b") as handle:
            data = mmap.mmap(handle.fileno(), 0)
            try:
                rva, _ = _streams(data, len(data))[_MODULE_LIST_STREAM]
                # Falsify one module's recorded TimeDateStamp, which is what an
                # image that is not the file it claims to be looks like.
                entry = rva + 4 + 1 * _MODULE_ENTRY_SIZE
                data[entry + 16:entry + 20] = (0xDEADBEEF).to_bytes(4, "little")
                data.flush()
            finally:
                data.close()
        _CACHE.pop(cls.path, None)

    def test_reported_as_header_mismatch_not_skipped(self):
        summary = summarize_module_integrity([analysis(self.path)])
        self.assertEqual(summary["counts"]["header_mismatch"], 1,
                         summary["counts"])

    def test_it_names_what_it_found_and_what_memory_claims(self):
        entry = summarize_module_integrity([analysis(self.path)])["header_mismatch"][0]
        self.assertTrue(entry["name"])
        self.assertEqual(entry["identity"]["module_timestamp"], 0xDEADBEEF)
        self.assertNotEqual(entry["identity"]["file_timestamp"], 0xDEADBEEF)
        # The image in memory is the honest one here, so its header still reads.
        self.assertTrue(entry["mapped_header"].get("size_of_image"))

    def test_identity_beats_degree(self):
        """The bytes are untouched, so the fraction is ~0 -- and it must still
        not read as `identical`. Degree cannot be allowed to overrule identity,
        or a payload that shares most of its bytes with the file it impersonates
        would be filed as clean."""
        entry = summarize_module_integrity([analysis(self.path)])["header_mismatch"][0]
        self.assertLess(entry["differing_fraction"], PATCHED_ABOVE)
        self.assertEqual(entry["verdict"], "header_mismatch")


class NamingTests(unittest.TestCase):

    def test_no_reference_modules_are_named(self):
        """Counting a skip made "could not tell" visible; naming it says what
        could not be told. On the first live run the unnamed one was the answer."""
        summary = summarize_module_integrity([
            {"dump": "x.dmp", "modules": [
                {"verdict": "no_reference", "name": "regsvcs.exe",
                 "base": 0x400000, "path": r"C:\x\RegSvcs.exe"}]}])
        named = summary["no_reference_modules"]
        self.assertEqual(len(named), 1)
        self.assertEqual(named[0]["name"], "regsvcs.exe")
        self.assertEqual(named[0]["base"], 0x400000)
