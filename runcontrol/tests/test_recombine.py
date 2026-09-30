"""`runcontrol.recombine`: a static scoring change, applied to a finished corpus.

What matters is what it leaves alone as much as what it writes: a case whose
decision did not change is not rewritten, every original is kept before a
write, and a corpus that is not finished -- or has a controller alive -- is
refused outright. `combine` is injected as a fake that returns a scripted
verdict, because the question here is what this module does with the answer.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from runcontrol.recombine import (
    BACKUP_DIR, RECORD_NAME, RecombineRefused, find_case_homes, main, recombine)

STORED = {"band": "Corroborated", "score": 50, "context_score": 15,
          "evidence": [{"name": "dangerous_capability", "strong": True}],
          "generated_utc": "2026-09-18T00:00:00Z", "provenance": {"analyzer": {"commit": "old"}}}


class Fixture(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.run = self.tmp / "mal-112b"
        (self.run / "cases").mkdir(parents=True)
        self.manifest("completed")
        alive = mock.patch("runcontrol.recombine._sweep_running", return_value=False)
        alive.start()
        self.addCleanup(alive.stop)
        self.fresh: dict[str, dict] = {}     # case name -> what combine returns
        self.writes: list[str] = []

    def manifest(self, state: str) -> None:
        (self.run / "manifest.json").write_text(
            json.dumps({"run_id": "mal-112b", "state": state}), encoding="utf-8")

    def add_case(self, name: str, fresh: dict | None = None) -> Path:
        home = self.run / "cases" / name / name
        (home / "metadata").mkdir(parents=True)
        text = json.dumps(STORED)
        (home / "combined_verdict.json").write_text(text, encoding="utf-8")
        (home / "metadata" / "combined_verdict.json").write_text(text, encoding="utf-8")
        self.fresh[name] = fresh if fresh is not None else dict(STORED)
        return home

    def combine(self, home, write_output=True):
        home = Path(home)
        verdict = dict(self.fresh[home.name])
        verdict["generated_utc"] = "2026-09-29T23:00:00Z"
        verdict["provenance"] = {"analyzer": {"commit": "new"}}
        if write_output:
            self.writes.append(home.name)
            text = json.dumps(verdict)
            (home / "combined_verdict.json").write_text(text, encoding="utf-8")
            (home / "metadata" / "combined_verdict.json").write_text(text, encoding="utf-8")
        return verdict

    def go(self, **kwargs):
        return recombine(self.run, combine=self.combine, **kwargs)


class WhatItWrites(Fixture):

    def test_a_changed_decision_is_written_and_the_original_kept(self) -> None:
        home = self.add_case("5b95", {**STORED, "band": "Single Observation", "score": 35})
        result = self.go()
        self.assertEqual(result.changed, 1)
        self.assertEqual(self.writes, ["5b95"])
        now = json.loads((home / "combined_verdict.json").read_text(encoding="utf-8"))
        self.assertEqual(now["band"], "Single Observation")
        kept = self.run / BACKUP_DIR / "cases" / "5b95" / "5b95"
        self.assertEqual(json.loads((kept / "combined_verdict.json").read_text()), STORED)
        self.assertEqual(json.loads((kept / "metadata" / "combined_verdict.json").read_text()), STORED)
        record = json.loads((self.run / RECORD_NAME).read_text(encoding="utf-8"))
        self.assertEqual(record["changed"], 1)
        self.assertEqual(record["cases"][0]["band_before"], "Corroborated")
        self.assertEqual(record["cases"][0]["band_after"], "Single Observation")
        self.assertTrue(record["cases"][0]["sha256_before"])
        self.assertTrue(record["cases"][0]["sha256_after"])

    def test_only_a_timestamp_and_provenance_is_not_a_change(self) -> None:
        """Every combine stamps a new time and analyzer; that alone must not
        rewrite a corpus."""
        home = self.add_case("same")
        before = (home / "combined_verdict.json").read_bytes()
        result = self.go()
        self.assertEqual((result.changed, result.unchanged), (0, 1))
        self.assertEqual(self.writes, [])
        self.assertEqual((home / "combined_verdict.json").read_bytes(), before)
        self.assertFalse((self.run / RECORD_NAME).exists())
        self.assertFalse((self.run / BACKUP_DIR).exists())

    def test_a_score_only_change_is_still_a_change(self) -> None:
        """Strong -> present without a band move changes the score; the
        verdict on disk must say what the code now says."""
        self.add_case("nano", {**STORED, "score": 35,
                               "evidence": [{"name": "dangerous_capability", "strong": False}]})
        result = self.go()
        self.assertEqual(result.changed, 1)
        self.assertEqual(result.cases[0].fields_changed, ["evidence", "score"])

    def test_dry_run_edits_nothing(self) -> None:
        home = self.add_case("x", {**STORED, "band": "No Evidence"})
        before = (home / "combined_verdict.json").read_bytes()
        result = self.go(dry_run=True)
        self.assertEqual(result.changed, 1)
        self.assertEqual(self.writes, [])
        self.assertEqual((home / "combined_verdict.json").read_bytes(), before)
        self.assertFalse((self.run / BACKUP_DIR).exists())

    def test_a_second_pass_keeps_the_first_record(self) -> None:
        self.add_case("a", {**STORED, "score": 1})
        self.go()
        first = (self.run / RECORD_NAME).read_bytes()
        self.fresh["a"] = {**STORED, "score": 2}
        self.go()
        self.assertEqual((self.run / RECORD_NAME).read_bytes(), first)
        self.assertEqual(len(list(self.run.glob("recombine-*.json"))), 1)

    def test_a_lost_module_is_never_written(self) -> None:
        """The host could not read what the guest did -- MAX_PATH on two
        long-named benign cases, 29 Sep. Writing would delete evidence."""
        stored = {**STORED, "modules_run": ["dynamic", "static"]}
        home = self.add_case("Microsoft.VisualStudio.Setup.ToastNotification_9253af16",
                             {**STORED, "band": "No Evidence", "score": 1,
                              "modules_run": ["static"]})
        (home / "combined_verdict.json").write_text(json.dumps(stored), encoding="utf-8")
        before = (home / "combined_verdict.json").read_bytes()
        result = self.go()
        self.assertEqual(result.changed, 0)
        self.assertEqual(result.cases[0].skipped, "host_cannot_read")
        self.assertEqual(self.writes, [])
        self.assertEqual((home / "combined_verdict.json").read_bytes(), before)
        record = json.loads((self.run / RECORD_NAME).read_text(encoding="utf-8"))
        self.assertEqual(record["host_cannot_read_left"], 1)

    def test_a_context_only_difference_is_left(self) -> None:
        """Volume never decides a band; fifty rewrites for it is churn."""
        home = self.add_case("ctx", {**STORED, "subscores": {"static": 2},
                                     "context_score": 16})
        before = (home / "combined_verdict.json").read_bytes()
        result = self.go()
        self.assertEqual((result.changed, result.skipped), (0, 1))
        self.assertEqual(result.cases[0].skipped, "context_only")
        self.assertEqual((home / "combined_verdict.json").read_bytes(), before)

    def test_context_alongside_a_real_change_is_written(self) -> None:
        self.add_case("both", {**STORED, "subscores": {"static": 2}, "band": "Single Observation"})
        result = self.go()
        self.assertEqual(result.changed, 1)
        self.assertIn("band", result.cases[0].fields_changed)

    def test_homes_are_the_doubled_segment_not_metadata(self) -> None:
        self.add_case("a")
        self.add_case("b")
        homes = find_case_homes(self.run / "cases")
        self.assertEqual([h.name for h in homes], ["a", "b"])
        self.assertTrue(all(h.parent.name == h.name for h in homes))


class WhatItRefuses(Fixture):

    def test_a_running_sweep(self) -> None:
        self.manifest("running")
        self.add_case("a", {**STORED, "band": "No Evidence"})
        with self.assertRaises(RecombineRefused):
            self.go()
        self.assertEqual(self.writes, [])

    def test_a_live_controller(self) -> None:
        self.add_case("a", {**STORED, "band": "No Evidence"})
        with mock.patch("runcontrol.recombine._sweep_running", return_value=True):
            with self.assertRaises(RecombineRefused):
                self.go()
        self.assertEqual(self.writes, [])

    def test_no_manifest(self) -> None:
        (self.run / "manifest.json").unlink()
        with self.assertRaises(RecombineRefused):
            self.go()

    def test_the_cli_exits_3_on_refusal(self) -> None:
        self.manifest("running")
        self.assertEqual(main([str(self.run)]), 3)


if __name__ == "__main__":
    unittest.main()
