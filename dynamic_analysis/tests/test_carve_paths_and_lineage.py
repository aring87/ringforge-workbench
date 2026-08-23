"""Three defects the loader re-run of 06 Aug exposed.

The carver's finding path fired for the first time on that run -- two unmapped
images inside a hollowed `RegSvcs.exe`, `process_injection` strong by a route
that had never been exercised. The same run lost the single most interesting
image it found, scored `payload_dropped` strong on a sample that drops nothing,
and silently downgraded the crash-dump route.
"""

import tempfile
import unittest
from pathlib import Path

from dynamic_analysis.crash_evidence import is_hollowing_target
from dynamic_analysis.dropped_file_triage import collect_dropped_file_candidates
from dynamic_analysis.pe_carve import _carve_name, _long_path, carve_image

SAMPLE_SHA = "422e30edd409936c649905ba4a8f58ed533287da77965268342ec38221d28231"


def _event(operation, category, process, pid, path, result="SUCCESS", detail=""):
    return {
        "timestamp": "t", "operation": operation, "category": category,
        "process_name": process, "pid": pid, "path": path,
        "result": result, "detail": detail,
    }


class CarveFilenameTests(unittest.TestCase):
    """Samples are stored under their SHA256, so the process name is 68 chars.

    Added to a run directory carrying a case id and a timestamped run id, that
    pushed the path past 260 characters and the carve failed with a bare "No
    such file or directory" -- on an 81,920-byte .NET PE unpacked inside the
    loader itself, the one image of that run worth having.
    """

    def test_a_hash_named_sample_does_not_produce_an_unwritable_name(self) -> None:
        name = _carve_name(
            {"name": f"{SAMPLE_SHA}.exe", "pid": 7076,
             "offset_seconds": 1, "trigger": "scheduled"},
            {"virtual_address": "0x5260000"},
        )

        self.assertLess(len(name), 80, name)
        self.assertTrue(name.endswith("0x5260000.bin_"))

    def test_an_ordinary_process_name_survives_intact(self) -> None:
        name = _carve_name(
            {"name": "RegSvcs.exe", "pid": 10784,
             "offset_seconds": 20, "trigger": "process-spawn"},
            {"virtual_address": "0x1240000"},
        )

        self.assertEqual(
            name, "RegSvcs.exe_10784_t20_process-spawn_0x1240000.bin_"
        )

    def test_two_dumps_of_one_process_do_not_overwrite_each_other(self) -> None:
        # A run carved seven images into five files: the same PID at the same
        # address, taken from the spawn dump and from the exit dump, produced
        # one name and the second silently replaced the first. Two dumps of a
        # process are two moments, which is why both were taken.
        common = {"name": "RegSvcs.exe", "pid": 5932, "offset_seconds": 20}
        image = {"virtual_address": "0x1750000"}

        names = {
            _carve_name({**common, "trigger": trigger}, image)
            for trigger in ("process-spawn", "root-exit", "spawn-redump", "crash")
        }

        self.assertEqual(len(names), 4, names)

    def test_the_address_always_survives(self) -> None:
        # It is what identifies the image; the name is only for the reader.
        name = _carve_name(
            {"name": "x" * 200, "pid": 1, "offset_seconds": 0, "trigger": "scheduled"},
            {"virtual_address": "0xdead"},
        )

        self.assertIn("0xdead", name)

    def test_a_nameless_record_still_produces_a_filename(self) -> None:
        self.assertTrue(_carve_name({"pid": 1}, {"virtual_address": "0x1"}))


class LongPathTests(unittest.TestCase):
    def test_a_short_path_is_untouched(self) -> None:
        self.assertEqual(_long_path(Path(r"C:\x\y.bin_")), r"C:\x\y.bin_")

    def test_a_deep_path_is_written_anyway(self) -> None:
        # Truncating the filename is the first defence; a case directory deep
        # enough exceeds the limit on its own, whatever the image is called.
        #
        # ignore_cleanup_errors because shutil.rmtree cannot traverse the very
        # path this test exists to create -- that is the harness hitting the
        # limit, not the code under test.
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            deep = Path(tmp)
            for _ in range(12):
                deep = deep / ("d" * 20)
            target = deep / ("f" * 40 + ".bin_")

            source = Path(tmp) / "src.dmp"
            source.write_bytes(b"MZ" + b"\x00" * 4094)

            record = carve_image(
                source,
                {"_offset": 0, "size_of_image": 4096, "available_bytes": 4096},
                target,
            )

            self.assertTrue(record["success"], record["error"])
            self.assertEqual(record["size"], 4096)
            self.assertTrue(record["sha256"])
            self.assertGreater(len(str(target)), 260)

            import os as _os

            _os.remove(_long_path(target))


class CrashDumpNameTests(unittest.TestCase):
    def test_a_crash_dump_process_is_recognised_as_a_hollowing_target(self) -> None:
        # WER writes RegSvcs.10784.dmp. The bare stem is "RegSvcs", which is not
        # in HOLLOWING_TARGETS, so the same carved image scored `present` from a
        # crash dump and `strong` from a live dump.
        self.assertTrue(is_hollowing_target("RegSvcs.exe"))
        self.assertFalse(is_hollowing_target("RegSvcs"))

    def test_the_collector_keeps_the_extension(self) -> None:
        from dynamic_analysis.crash_evidence import CrashDumpCollector

        with tempfile.TemporaryDirectory() as tmp:
            watched = Path(tmp) / "werdumps"
            watched.mkdir()
            collector = CrashDumpCollector(
                output_dir=Path(tmp) / "out", dump_folder=watched
            )
            collector.snapshot()
            (watched / "RegSvcs.10784.dmp").write_bytes(b"MDMP" + b"\x00" * 64)

            result = collector.collect(sample_names={"regsvcs.exe"})

            self.assertEqual(len(result["dumps"]), 1)
            record = result["dumps"][0]
            self.assertEqual(record["name"], "regsvcs.exe")
            self.assertTrue(is_hollowing_target(record["name"]))
            self.assertTrue(record["attributed_to_sample"])


class DroppedFileLineageTests(unittest.TestCase):
    """A browser writing its own libraries is not the sample dropping a payload."""

    EDGE = r"C:\Users\adam\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wek\x.dll"
    POLICY = r"C:\Users\adam\AppData\Local\Temp\__PSScriptPolicyTest_hkmuwxnl.eou.ps1"
    REAL = r"C:\Users\adam\AppData\Roaming\Config\smng.exe"

    def test_another_processs_write_is_not_the_samples_drop(self) -> None:
        candidates = collect_dropped_file_candidates(
            [_event("WriteFile", "file_write", "msedgewebview2.exe", 9999, self.EDGE)],
            descendant_pids={7076, 10784},
        )

        self.assertEqual(candidates, [])

    def test_the_samples_own_drop_survives(self) -> None:
        candidates = collect_dropped_file_candidates(
            [_event("WriteFile", "file_write", "sample.exe", 7076, self.REAL)],
            descendant_pids={7076, 10784},
        )

        self.assertEqual(len(candidates), 1)

    def test_powershells_policy_probe_is_never_a_drop(self) -> None:
        # Written by the sample's own powershell.exe, so lineage keeps it, and
        # it is still not a drop -- PowerShell writes one on every invocation.
        candidates = collect_dropped_file_candidates(
            [_event("WriteFile", "file_write", "powershell.exe", 10732, self.POLICY)],
            descendant_pids={7076, 10732},
        )

        self.assertEqual(candidates, [])

    def test_unresolved_lineage_counts_everything(self) -> None:
        # None is not an empty set. "We could not tell whose write this was"
        # must not silently empty the dropped files, the way the findings and
        # the PowerShell blocks already degrade.
        candidates = collect_dropped_file_candidates(
            [_event("WriteFile", "file_write", "msedgewebview2.exe", 9999, self.EDGE)],
            descendant_pids=None,
        )

        self.assertEqual(len(candidates), 1)


if __name__ == "__main__":
    unittest.main()
