"""What re-scoring a finished corpus changes, and everything it must not.

This and `test_debom` cover the only two tools in the bench that edit a corpus
in place, and `cases/` is not in git. So the weight here is on the refusals,
on proving that exactly four fields move, and on the half that is easy to get
wrong: leaving `combined_verdict.json` stale against the summary it is derived
from would put two different answers in one case folder.
"""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dynamic_analysis.orchestrator import calculate_dynamic_score
from runcontrol.rescore import (
    BACKUP_DIR, RECORD_NAME, RUN_SUMMARY, RescoreRefused, find_run_summaries,
    main, rescore,
)

#: A sample that talked only to its own service over loopback -- the shape
#: that banded `aura-wallpaper-editor` Corroborated/70 before the fix.
LOOPBACK_RUN = {
    "schema_version": "dynamic-1.0",
    "run_id": "case_20260918_221748_74dd3226",
    "cancelled": False,
    "duration_seconds": 3954.0,
    "sample": {"sha256": "17d08541" + "0" * 56, "filename": "sample.exe"},
    "findings": {"spawned_processes": [
        {"process_name": "python.exe", "child_process_name": "sample.exe"}
    ]},
    "sysmon_summary": {"dns_queries": []},
    "network_summary": {"counts": {"unusual_ports": 0, "unique_destinations": 0}},
    "fakenet_summary": {
        "dns_requests": [],
        "process_requests": [
            {"process": "sample.exe", "protocol": "TCP",
             "destination": "127.0.0.1:11001"},
        ],
    },
    # What the guest stored, under the code the run started with.
    "score": 50,
    "severity": "High",
    "verdict": "Elevated Attention",
    "score_detail": {"score": 50, "severity": "High",
                     "verdict": "Elevated Attention", "stale": True},
}


def expected_for(document: dict) -> dict:
    """What the current scorer makes of a stored run's own inputs."""
    def part(name):
        value = document.get(name)
        return value if isinstance(value, dict) else {}
    return calculate_dynamic_score(
        findings_summary=part("findings"),
        task_diff_summary=part("task_diff_summary"),
        service_diff_summary=part("service_diff_summary"),
        dropped_files_summary=part("dropped_files_summary"),
        autoruns_diff_summary=part("autoruns_diff_summary"),
        sysmon_summary=part("sysmon_summary"),
        network_summary=part("network_summary"),
        fakenet_summary=part("fakenet_summary"),
        memory_yara_summary=part("memory_yara_summary"),
        powershell_summary=part("powershell_summary"),
        crash_summary=part("crash_summary"),
        pe_carve_summary=part("pe_carve_summary"),
        module_integrity_summary=part("module_integrity_summary"),
    )


class RescoreFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.run = self.tmp / "benign-102-v2"
        self.cases = self.run / "cases"
        self.cases.mkdir(parents=True)
        self.write_manifest("completed")

        alive = mock.patch("runcontrol.rescore._sweep_running",
                           return_value=False)
        alive.start()
        self.addCleanup(alive.stop)

        # `combine_case` needs a real case to read; here it is stubbed and its
        # calls recorded, because what matters to this module is *that* the
        # verdict is regenerated for the cases it changed.
        self.combined: list[Path] = []
        combine = mock.patch(
            "static_triage_engine.combine_case.combine_case",
            side_effect=self._combine)
        self.combine = combine.start()
        self.addCleanup(combine.stop)

    def _combine(self, home, write_output=True):
        self.combined.append(Path(home))
        return {"band": "No Evidence", "score": 15}

    def write_manifest(self, state: str) -> None:
        (self.run / "manifest.json").write_bytes(
            json.dumps({"schema": 1, "run_id": "benign-102-v2",
                        "state": state}).encode("utf-8"))

    def add_case(self, name: str = "sample_17d08541", document=None,
                 run: str = "r1") -> Path:
        body = copy.deepcopy(LOOPBACK_RUN if document is None else document)
        path = (self.cases / name / name / "dynamic_analysis" / "dynamic_runs"
                / run / "metadata" / RUN_SUMMARY)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(json.dumps(body, indent=2).encode("utf-8") + b"\n")
        (path.parents[4] / "combined_verdict.json").write_bytes(
            json.dumps({"band": "Corroborated", "score": 70}).encode("utf-8"))
        return path

    def stored(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8-sig"))

    def record(self) -> dict:
        return json.loads((self.run / RECORD_NAME).read_text(encoding="utf-8"))


class AStaleScoreIsRecomputed(RescoreFixture):
    def test_the_stored_score_is_replaced_with_the_current_one(self) -> None:
        path = self.add_case()
        want = expected_for(LOOPBACK_RUN)

        result = rescore(self.run)

        self.assertEqual(1, result.changed)
        after = self.stored(path)
        self.assertEqual(want["score"], after["score"])
        self.assertEqual(want["severity"], after["severity"])
        self.assertEqual(want["verdict"], after["verdict"])
        self.assertEqual(want, after["score_detail"])

    def test_the_loopback_case_stops_being_high(self) -> None:
        # The measured case, end to end: a sample whose only connection was to
        # its own service must not come out of this a High.
        path = self.add_case()
        rescore(self.run)
        after = self.stored(path)

        self.assertEqual("High", LOOPBACK_RUN["severity"])
        self.assertNotEqual("High", after["severity"])

    def test_nothing_but_the_four_scored_fields_moves(self) -> None:
        # The contract with the run summary. Everything else in that file is
        # what the run *observed*, and re-scoring does not re-observe.
        path = self.add_case()
        before = self.stored(path)
        rescore(self.run)
        after = self.stored(path)

        for key in ("score", "severity", "verdict", "score_detail"):
            before.pop(key, None)
            after.pop(key, None)
        self.assertEqual(before, after)

    def test_the_verdict_is_regenerated_for_a_case_that_changed(self) -> None:
        # Leaving combined_verdict.json stale would put two different answers
        # in one case folder, which is worse than either on its own.
        path = self.add_case()
        rescore(self.run)

        self.assertEqual([path.parents[4]], self.combined)

    def test_a_case_that_did_not_change_is_not_recombined(self) -> None:
        document = copy.deepcopy(LOOPBACK_RUN)
        current = expected_for(document)
        document.update({
            "score": current["score"], "severity": current["severity"],
            "verdict": current["verdict"], "score_detail": current,
        })
        self.add_case(document=document)

        result = rescore(self.run)

        self.assertEqual(0, result.changed)
        self.assertEqual(1, result.unchanged)
        self.assertEqual([], self.combined)

    def test_running_it_twice_changes_nothing_the_second_time(self) -> None:
        # Scoring is deterministic, so the second pass is a no-op.
        self.add_case()
        self.assertEqual(1, rescore(self.run).changed)
        self.combined.clear()
        second = rescore(self.run)

        self.assertEqual(0, second.changed)
        self.assertEqual([], self.combined)

    def test_every_dynamic_run_in_a_case_is_scored(self) -> None:
        # A retry leaves two runs in one case and each carries its own score.
        self.add_case(run="r1")
        self.add_case(run="r2")

        self.assertEqual(2, rescore(self.run).changed)


class TheOriginalIsKept(RescoreFixture):
    def test_the_original_is_copied_before_anything_is_written(self) -> None:
        path = self.add_case()
        before = path.read_bytes()
        rescore(self.run)

        backups = list((self.run / BACKUP_DIR).rglob(RUN_SUMMARY))
        self.assertEqual(1, len(backups), backups)
        self.assertEqual(before, backups[0].read_bytes())

    def test_it_does_not_share_a_directory_with_deboms_originals(self) -> None:
        # Two tools edit this corpus; a restore must not be ambiguous about
        # which change it is undoing.
        self.add_case()
        rescore(self.run)

        self.assertTrue((self.run / "rescore-originals").is_dir())
        self.assertFalse((self.run / "bom-originals").exists())


class WhatItDidIsRecorded(RescoreFixture):
    def test_a_record_names_the_before_and_after(self) -> None:
        self.add_case()
        rescore(self.run)
        record = self.record()

        self.assertEqual("runcontrol.rescore", record["tool"])
        self.assertEqual(1, record["changed"])
        case = record["cases"][0]
        self.assertEqual(50, case["score_before"])
        self.assertNotEqual(50, case["score_after"])
        self.assertTrue(case["sha256_before"])
        self.assertNotEqual(case["sha256_before"], case["sha256_after"])

    def test_the_record_names_the_code_that_did_it(self) -> None:
        # Which analyzer re-scored a corpus is provenance, not a detail: the
        # cases were produced by one commit and scored by another.
        self.add_case()
        rescore(self.run)

        self.assertIn("analyzer", self.record())

    def test_no_record_when_nothing_changed(self) -> None:
        document = copy.deepcopy(LOOPBACK_RUN)
        current = expected_for(document)
        document.update({
            "score": current["score"], "severity": current["severity"],
            "verdict": current["verdict"], "score_detail": current,
        })
        self.add_case(document=document)
        rescore(self.run)

        self.assertFalse((self.run / RECORD_NAME).exists())

    def test_the_record_has_no_carriage_returns(self) -> None:
        self.add_case()
        rescore(self.run)

        self.assertNotIn(b"\r\n", (self.run / RECORD_NAME).read_bytes())


class WhatItRefusesToScore(RescoreFixture):
    def test_a_cancelled_run_is_skipped(self) -> None:
        # Its verdict was assigned wholesale, not derived from evidence.
        document = copy.deepcopy(LOOPBACK_RUN)
        document.update({"cancelled": True, "verdict": "Cancelled",
                         "severity": "Info", "score": 0})
        path = self.add_case(document=document)
        before = path.read_bytes()

        result = rescore(self.run)

        self.assertEqual(1, result.skipped)
        self.assertEqual(0, result.changed)
        self.assertEqual(before, path.read_bytes())

    def test_a_scorer_that_raises_is_reported_not_swallowed(self) -> None:
        path = self.add_case()
        before = path.read_bytes()
        with mock.patch("dynamic_analysis.orchestrator.calculate_dynamic_score",
                        side_effect=ValueError("boom")):
            result = rescore(self.run)

        self.assertEqual(1, result.failed)
        self.assertEqual(before, path.read_bytes())

    def test_a_failed_combine_is_recorded_as_a_stale_verdict(self) -> None:
        # The dangerous half-state. The summary is re-scored and the verdict
        # is not, so the case folder now holds two different answers -- it has
        # to be loud rather than counted as a success.
        self.add_case()
        self.combine.side_effect = RuntimeError("combine exploded")

        result = rescore(self.run)

        self.assertEqual(1, result.failed)
        self.assertIn("stale", result.cases[0].error)


class ItRefusesAnythingItIsNotSureAbout(RescoreFixture):
    def test_a_running_sweep_is_refused_by_state(self) -> None:
        self.write_manifest("running")
        self.add_case()
        with self.assertRaises(RescoreRefused) as caught:
            rescore(self.run)
        self.assertIn("finished", str(caught.exception))

    def test_a_live_controller_is_refused(self) -> None:
        self.add_case()
        with mock.patch("runcontrol.rescore._sweep_running", return_value=True):
            with self.assertRaises(RescoreRefused) as caught:
                rescore(self.run)
        self.assertIn("still alive", str(caught.exception))

    def test_a_missing_manifest_is_refused(self) -> None:
        (self.run / "manifest.json").unlink()
        with self.assertRaises(RescoreRefused):
            rescore(self.run)

    def test_an_unparseable_manifest_is_refused(self) -> None:
        (self.run / "manifest.json").write_text("{ truncated", encoding="utf-8")
        with self.assertRaises(RescoreRefused):
            rescore(self.run)

    def test_a_missing_cases_directory_is_refused(self) -> None:
        shutil.rmtree(self.cases)
        with self.assertRaises(RescoreRefused):
            rescore(self.run)

    def test_a_refusal_edits_nothing(self) -> None:
        self.write_manifest("running")
        path = self.add_case()
        before = path.read_bytes()
        with self.assertRaises(RescoreRefused):
            rescore(self.run)

        self.assertEqual(before, path.read_bytes())
        self.assertFalse((self.run / BACKUP_DIR).exists())
        self.assertEqual([], self.combined)

    def test_an_aborted_run_is_still_scoreable(self) -> None:
        self.write_manifest("aborted")
        self.add_case()
        self.assertEqual(1, rescore(self.run).changed)


class TheDryRun(RescoreFixture):
    def test_it_edits_nothing(self) -> None:
        path = self.add_case()
        before = path.read_bytes()
        result = rescore(self.run, dry_run=True)

        self.assertEqual(before, path.read_bytes())
        self.assertEqual([], self.combined)
        self.assertFalse((self.run / BACKUP_DIR).exists())
        self.assertFalse((self.run / RECORD_NAME).exists())

    def test_it_still_says_what_would_change(self) -> None:
        self.add_case()
        result = rescore(self.run, dry_run=True)

        self.assertEqual(1, result.changed)
        self.assertEqual(50, result.cases[0].score_before)
        self.assertNotEqual(50, result.cases[0].score_after)


class Finding(RescoreFixture):
    def test_the_case_home_is_derived_from_the_summarys_path(self) -> None:
        # A corpus nests a directory named for the case twice over, so "the
        # first ancestor that looks like a case" would pick the wrong one.
        path = self.add_case()
        rescore(self.run)

        self.assertEqual(path.parents[4], self.combined[0])
        self.assertEqual("sample_17d08541", self.combined[0].name)

    def test_summaries_come_back_in_a_stable_order(self) -> None:
        self.add_case(name="b_case")
        self.add_case(name="a_case")
        found = [p.parents[4].name for p in find_run_summaries(self.cases)]

        self.assertEqual(sorted(found), found)


class TheCommandLine(RescoreFixture):
    def test_a_refusal_has_its_own_exit_code(self) -> None:
        self.write_manifest("running")
        self.add_case()
        self.assertEqual(3, main([str(self.run)]))

    def test_a_clean_pass_returns_zero(self) -> None:
        self.add_case()
        self.assertEqual(0, main([str(self.run)]))

    def test_a_failure_does_not_return_zero(self) -> None:
        self.add_case()
        self.combine.side_effect = RuntimeError("combine exploded")
        self.assertEqual(1, main([str(self.run)]))

    def test_dry_run_from_the_command_line_edits_nothing(self) -> None:
        path = self.add_case()
        before = path.read_bytes()
        self.assertEqual(0, main([str(self.run), "--dry-run"]))
        self.assertEqual(before, path.read_bytes())


if __name__ == "__main__":
    unittest.main()
