"""What the BOM stripper edits, and everything it refuses to edit.

This is the only tool in the bench that rewrites a corpus in place, and
`cases/` is not in git. So the tests are weighted towards the refusals and
towards proving that a file which *was* edited differs from its original by
exactly three bytes and in no other way.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from runcontrol.debom import (
    BACKUP_DIR, BOM, RECORD_NAME, DebomRefused, debom, find_bommed, main,
)

CLEAN = {"band": "No Evidence", "score": 15, "modules_run": ["static", "dyn"]}


class DebomFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.run = self.tmp / "benign-102-v2"
        self.cases = self.run / "cases"
        self.cases.mkdir(parents=True)
        self.write_manifest("completed")
        # Every test runs as though no controller is alive; the ones about
        # that guard patch it back on deliberately.
        patcher = mock.patch("runcontrol.debom._sweep_running",
                             return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_manifest(self, state: str) -> None:
        (self.run / "manifest.json").write_bytes(
            json.dumps({"schema": 1, "run_id": "benign-102-v2",
                        "state": state}).encode("utf-8"))

    def case_file(self, name: str, document=None, *, bom: bool = True,
                  raw: bytes | None = None) -> Path:
        path = self.cases / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if raw is not None:
            path.write_bytes(raw)
            return path
        body = json.dumps(CLEAN if document is None else document,
                          indent=2).encode("utf-8")
        path.write_bytes((BOM if bom else b"") + body)
        return path

    def record(self) -> dict:
        return json.loads((self.run / RECORD_NAME).read_text(encoding="utf-8"))


class TheBomComesOff(DebomFixture):
    def test_a_bommed_file_becomes_readable_by_a_strict_load(self) -> None:
        # The whole point: json.load with plain utf-8, which is what every
        # consumer in this codebase would reach for first.
        path = self.case_file("a/scan.json")
        debom(self.run)
        self.assertEqual(CLEAN, json.loads(path.read_text(encoding="utf-8")))

    def test_it_differs_from_the_original_by_exactly_the_bom(self) -> None:
        path = self.case_file("a/scan.json")
        before = path.read_bytes()
        debom(self.run)
        self.assertEqual(before[len(BOM):], path.read_bytes())
        self.assertEqual(len(before) - 3, path.stat().st_size)

    def test_non_ascii_survives(self) -> None:
        document = {"name": "café — naïve", "band": "No Evidence"}
        path = self.case_file("a/combined.json", document)
        debom(self.run)
        self.assertEqual(document, json.loads(path.read_text(encoding="utf-8")))

    def test_every_bommed_json_under_cases_is_found(self) -> None:
        for name in ("a/scan.json", "a/combined.json",
                     "a/a/pruned_artifacts.json", "b/scan.json"):
            self.case_file(name)
        self.case_file("a/summary.json", bom=False)
        result = debom(self.run)
        self.assertEqual(4, result.stripped)

    def test_a_clean_file_is_not_touched(self) -> None:
        path = self.case_file("a/summary.json", bom=False)
        before = path.read_bytes()
        debom(self.run)
        self.assertEqual(before, path.read_bytes())

    def test_running_it_twice_changes_nothing_the_second_time(self) -> None:
        self.case_file("a/scan.json")
        first = debom(self.run)
        self.assertEqual(1, first.stripped)
        second = debom(self.run)
        self.assertEqual(0, second.stripped)
        self.assertEqual([], second.files)

    def test_only_cases_is_walked(self) -> None:
        # The run directory holds the manifest and whatever else an operator
        # put beside it. This edits the corpus, not the run's paperwork.
        outside = self.run / "notes.json"
        outside.write_bytes(BOM + b'{"mine": true}')
        self.case_file("a/scan.json")
        result = debom(self.run)
        self.assertEqual(1, result.stripped)
        self.assertTrue(outside.read_bytes().startswith(BOM),
                        "a file beside the manifest was edited")


class TheOriginalIsKept(DebomFixture):
    def test_the_original_is_copied_before_anything_is_written(self) -> None:
        path = self.case_file("a/scan.json")
        before = path.read_bytes()
        debom(self.run)
        backup = self.run / BACKUP_DIR / "cases" / "a" / "scan.json"
        self.assertTrue(backup.is_file(), "no backup was kept")
        self.assertEqual(before, backup.read_bytes())

    def test_the_backup_keeps_the_path_so_two_cases_do_not_collide(self) -> None:
        self.case_file("a/scan.json")
        self.case_file("b/scan.json", {"band": "Corroborated", "score": 70})
        debom(self.run)
        root = self.run / BACKUP_DIR / "cases"
        self.assertTrue((root / "a" / "scan.json").is_file())
        self.assertTrue((root / "b" / "scan.json").is_file())
        self.assertEqual(
            {"band": "Corroborated", "score": 70},
            json.loads((root / "b" / "scan.json").read_text(encoding="utf-8-sig")))

    def test_the_backup_lives_inside_the_run_so_it_moves_with_it(self) -> None:
        self.case_file("a/scan.json")
        debom(self.run)
        self.assertTrue((self.run / BACKUP_DIR).is_dir())


class WhatItDidIsRecorded(DebomFixture):
    def test_a_record_is_written_beside_the_manifest(self) -> None:
        self.case_file("a/scan.json")
        debom(self.run)
        record = self.record()
        self.assertEqual("runcontrol.debom", record["tool"])
        self.assertEqual("benign-102-v2", record["run_id"])
        self.assertEqual(1, record["stripped"])

    def test_every_file_carries_a_hash_before_and_after(self) -> None:
        # "These bytes were edited after the run, and here is exactly how"
        # has to be answerable later rather than inferred from mtimes.
        path = self.case_file("a/scan.json")
        debom(self.run)
        entry = self.record()["files"][0]
        self.assertNotEqual(entry["sha256_before"], entry["sha256_after"])
        self.assertEqual(entry["bytes_before"] - 3, entry["bytes_after"])
        import hashlib
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         entry["sha256_after"])

    def test_no_record_is_written_when_nothing_was_stripped(self) -> None:
        self.case_file("a/summary.json", bom=False)
        debom(self.run)
        self.assertFalse((self.run / RECORD_NAME).exists())

    def test_the_record_has_no_carriage_returns(self) -> None:
        self.case_file("a/scan.json")
        debom(self.run)
        self.assertNotIn(b"\r\n", (self.run / RECORD_NAME).read_bytes())


class AFileItCannotProveIsLeftAlone(DebomFixture):
    def test_a_bommed_file_that_is_not_json_is_untouched(self) -> None:
        path = self.case_file("a/scan.json", raw=BOM + b"{ truncated")
        before = path.read_bytes()
        result = debom(self.run)
        self.assertEqual(before, path.read_bytes())
        self.assertEqual(0, result.stripped)
        self.assertIn("does not parse", result.files[0].reason)

    def test_it_is_reported_rather_than_passed_over_in_silence(self) -> None:
        self.case_file("a/scan.json", raw=BOM + b"not json at all")
        said: list[str] = []
        debom(self.run, on_event=said.append)
        self.assertTrue(any("left alone" in line for line in said), said)

    def test_one_bad_file_does_not_stop_the_good_ones(self) -> None:
        self.case_file("a/scan.json", raw=BOM + b"{ truncated")
        self.case_file("b/scan.json")
        result = debom(self.run)
        self.assertEqual(1, result.stripped)
        self.assertEqual(1, result.refused)


class TheDryRun(DebomFixture):
    def test_it_edits_nothing(self) -> None:
        path = self.case_file("a/scan.json")
        before = path.read_bytes()
        result = debom(self.run, dry_run=True)
        self.assertEqual(before, path.read_bytes())
        self.assertEqual(0, result.stripped)

    def test_it_writes_no_record_and_no_backup(self) -> None:
        self.case_file("a/scan.json")
        debom(self.run, dry_run=True)
        self.assertFalse((self.run / RECORD_NAME).exists())
        self.assertFalse((self.run / BACKUP_DIR).exists())

    def test_it_still_reports_what_it_found(self) -> None:
        self.case_file("a/scan.json")
        said: list[str] = []
        debom(self.run, dry_run=True, on_event=said.append)
        self.assertTrue(any("1 JSON files carry a BOM" in s for s in said), said)


class ItRefusesAnythingItIsNotSureAbout(DebomFixture):
    def test_a_running_sweep_is_refused_by_state(self) -> None:
        self.write_manifest("running")
        self.case_file("a/scan.json")
        with self.assertRaises(DebomRefused) as caught:
            debom(self.run)
        self.assertIn("finished", str(caught.exception))

    def test_a_live_controller_is_refused_even_if_the_state_says_done(self) -> None:
        # The manifest can say completed while a controller is still shutting
        # down, or while a different run is going. Either way, not now.
        self.case_file("a/scan.json")
        with mock.patch("runcontrol.debom._sweep_running", return_value=True):
            with self.assertRaises(DebomRefused) as caught:
                debom(self.run)
        self.assertIn("still alive", str(caught.exception))

    def test_a_missing_manifest_is_refused(self) -> None:
        (self.run / "manifest.json").unlink()
        with self.assertRaises(DebomRefused) as caught:
            debom(self.run)
        self.assertIn("no manifest", str(caught.exception))

    def test_a_manifest_with_a_bom_is_still_readable(self) -> None:
        # A tool about BOMs must not be defeated by one on its own input. A
        # test harness writing its manifest from PowerShell found this.
        manifest = self.run / "manifest.json"
        manifest.write_bytes(BOM + manifest.read_bytes())
        self.case_file("a/scan.json")
        self.assertEqual(1, debom(self.run).stripped)

    def test_an_unparseable_manifest_is_refused(self) -> None:
        (self.run / "manifest.json").write_text("{ truncated", encoding="utf-8")
        with self.assertRaises(DebomRefused) as caught:
            debom(self.run)
        self.assertIn("will not parse", str(caught.exception))

    def test_a_missing_cases_directory_is_refused(self) -> None:
        shutil.rmtree(self.cases)
        with self.assertRaises(DebomRefused):
            debom(self.run)

    def test_a_refusal_edits_nothing(self) -> None:
        self.write_manifest("running")
        path = self.case_file("a/scan.json")
        before = path.read_bytes()
        with self.assertRaises(DebomRefused):
            debom(self.run)
        self.assertEqual(before, path.read_bytes())
        self.assertFalse((self.run / BACKUP_DIR).exists())

    def test_an_aborted_run_is_still_editable(self) -> None:
        # It finished, just not well. Its cases are real cases.
        self.write_manifest("aborted")
        self.case_file("a/scan.json")
        self.assertEqual(1, debom(self.run).stripped)


class TheCommandLine(DebomFixture):
    def test_a_refusal_has_its_own_exit_code(self) -> None:
        self.write_manifest("running")
        self.case_file("a/scan.json")
        self.assertEqual(3, main([str(self.run)]))

    def test_a_clean_pass_returns_zero(self) -> None:
        self.case_file("a/scan.json")
        self.assertEqual(0, main([str(self.run)]))

    def test_dry_run_from_the_command_line_edits_nothing(self) -> None:
        path = self.case_file("a/scan.json")
        before = path.read_bytes()
        self.assertEqual(0, main([str(self.run), "--dry-run"]))
        self.assertEqual(before, path.read_bytes())


class TheLivenessCheckItself(unittest.TestCase):
    """Deliberately outside the fixture, which stubs this out for every test."""

    def test_an_unreadable_process_table_counts_as_running(self) -> None:
        # The conservative direction: a needless refusal costs a re-run of
        # this tool, and editing a corpus mid-write costs the corpus.
        from runcontrol import debom as module
        # psutil is imported inside the function, so the real module object is
        # what has to be patched, not an attribute of this one.
        with mock.patch("psutil.process_iter", side_effect=OSError("denied")):
            self.assertTrue(module._sweep_running())

    def test_a_quiet_process_table_means_not_running(self) -> None:
        from runcontrol import debom as module
        with mock.patch("psutil.process_iter", return_value=iter([])):
            self.assertFalse(module._sweep_running())


class LongPaths(unittest.TestCase):
    """MAX_PATH, which this corpus is already two characters away from."""

    def test_a_windows_path_is_given_the_extended_prefix(self) -> None:
        from runcontrol.debom import _extended
        if os.name != "nt":
            self.skipTest("Windows path rules")
        self.assertTrue(_extended(Path(r"G:\a\b.json")).startswith("\\\\?\\"))

    def test_it_is_not_applied_twice(self) -> None:
        from runcontrol.debom import _extended
        if os.name != "nt":
            self.skipTest("Windows path rules")
        once = _extended(Path(r"G:\a\b.json"))
        self.assertEqual(once, _extended(once))

    def test_a_unc_path_gets_the_unc_form(self) -> None:
        from runcontrol.debom import _extended
        if os.name != "nt":
            self.skipTest("Windows path rules")
        self.assertTrue(
            _extended(Path(r"\\VBOXSVR\share\a.json")).startswith("\\\\?\\UNC\\"))


class Finding(DebomFixture):
    def test_it_reads_the_bytes_rather_than_guessing_by_name(self) -> None:
        # A tool that predicted which filenames ought to carry a BOM would go
        # wrong the first time the agent changed what it writes.
        self.case_file("a/something_unexpected.json")
        self.case_file("a/scan.json", bom=False)
        found = [p.name for p in find_bommed(self.cases)]
        self.assertEqual(["something_unexpected.json"], found)

    def test_non_json_is_ignored(self) -> None:
        (self.cases / "a").mkdir(parents=True, exist_ok=True)
        (self.cases / "a" / "notes.txt").write_bytes(BOM + b"hello")
        self.assertEqual([], find_bommed(self.cases))


if __name__ == "__main__":
    unittest.main()
