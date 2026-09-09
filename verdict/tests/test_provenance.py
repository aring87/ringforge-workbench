"""The envelope around a verdict: what it describes, and what produced it.

`combine` says what the band is. Until 04 Sep the stored document said nothing
about *which sample*, *which analyzer* or *what the collectors managed to
load* -- so two runs of the same case could not be compared and a wrong result
could not be explained without re-running it by hand.

The `yara` collector block is the one that earns its place. On 20 Aug a case
recorded `rule_file_count: 1593` and no matches; the rule set had failed to
compile and nothing ran. Counting files on disk is not the same as loading
them, and only one of those two numbers was in the artifact.
"""

import json
import tempfile
import sys
import types
import unittest
from unittest import mock
from pathlib import Path

from static_triage_engine.combine_case import combine_case
from verdict.provenance import (
    SCHEMA_VERSION,
    analyzer_provenance,
    tool_versions,
    yara_collector,
)

SAMPLE = {
    "sha256": "7ea500ad175878014fa1ec391416ae477066b2622c96c8b882126febdeddf004",
    "md5": "dfc0bdba385a3011c46b72ab4a86f618",
    "sha1": "e696f56f3874794006f7c5373df6b2fbbb15ef91",
    "filename": "payload.bin",
    "size_bytes": 258048,
}


def _case(**files) -> Path:
    case = Path(tempfile.mkdtemp(prefix="ringforge_provenance_"))
    for name, payload in files.items():
        path = case / name.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    return case


class TheYaraCollectorBlock(unittest.TestCase):
    """The field that would have made a fortnight-old wrong result a diff."""

    def test_a_failed_scan_is_visible_in_the_provenance(self) -> None:
        block = yara_collector({
            "engine": "yara-python", "rule_file_count": 1593,
            "matched": False, "match_count": 0,
            "error": 'general_cloaking.yar(60): undefined identifier "filepath"',
        })

        self.assertTrue(block["error"])
        # The number that misled: files on disk, with nothing saying whether a
        # single one of them compiled.
        self.assertEqual(block["rule_file_count"], 1593)
        self.assertIsNone(block["rules_compiled"])

    def test_a_healthy_scan_records_what_loaded(self) -> None:
        block = yara_collector({
            "engine": "yara-python", "rule_file_count": 1594,
            "rules_compiled": 1594, "rules_skipped": [], "error": None,
        })

        self.assertIsNone(block["error"])
        self.assertEqual(block["rules_compiled"], 1594)
        self.assertEqual(block["rules_skipped"], 0)

    def test_an_empty_error_string_is_reported_as_no_error(self) -> None:
        """`run_yara_scan` initialises `error` to `None` but other writers use
        `""`. Both mean the same thing and must not read differently."""
        self.assertIsNone(yara_collector({"error": ""})["error"])

    def test_a_scan_that_never_ran_says_so(self) -> None:
        """Absent is not clean. A case with no `yara_results.json` must not
        produce a block that looks like a successful scan."""
        self.assertEqual(yara_collector(None), {"collected": False})


class TheAnalyzerBlock(unittest.TestCase):
    def test_it_names_itself_and_never_raises(self) -> None:
        block = analyzer_provenance()

        self.assertEqual(block["name"], "ringforge-workbench")
        self.assertIn("version", block)
        self.assertIn("commit", block)
        self.assertIn("tools", block)

    def test_an_unknown_value_is_null_rather_than_absent_or_zero(self) -> None:
        """The distinction this project is built on, applied to its own
        metadata: not knowing a version is a different fact from there being
        no version."""
        versions = tool_versions()

        self.assertIn("yara-python", versions)
        for name, value in versions.items():
            self.assertTrue(value is None or isinstance(value, str), name)

    def test_a_missing_git_checkout_is_not_an_error(self) -> None:
        from verdict.provenance import git_commit

        self.assertIsNone(git_commit(tempfile.mkdtemp()))


class AFrozenBuildStillIdentifiesItself(unittest.TestCase):
    """A PyInstaller bundle has no git history and no distribution metadata.

    Both answers would be null, which is a verdict nobody can trace back to the
    build that produced it -- in the envelope that exists to make verdicts
    traceable. `ringforge.spec` stamps them in and `_baked` reads them back.
    """

    def _stub(self, **attributes):
        """Stand in for the generated `ringforge._build_info`."""
        module = types.ModuleType("ringforge._build_info")
        for name, value in attributes.items():
            setattr(module, name, value)
        return mock.patch.dict(sys.modules, {"ringforge._build_info": module})

    def test_the_stamp_answers_when_git_and_metadata_cannot(self) -> None:
        from verdict.provenance import analyzer_version, git_commit

        with mock.patch.object(sys, "frozen", True, create=True),                 self._stub(VERSION="9.9.9", COMMIT="deadbeef"),                 mock.patch("verdict.provenance._package_version", return_value=None):
            self.assertEqual("deadbeef", git_commit(tempfile.mkdtemp()))
            self.assertEqual("9.9.9", analyzer_version())

    def test_the_stamp_never_answers_for_a_source_run(self) -> None:
        # The spec writes `_build_info` into the source tree, where it is
        # gitignored but survives the build. Unfrozen it must be ignored, or a
        # developer who once built an exe gets a stale commit reported against
        # whatever is in their working tree now.
        from verdict.provenance import analyzer_version, git_commit

        with self._stub(VERSION="9.9.9", COMMIT="deadbeef"),                 mock.patch("verdict.provenance._package_version", return_value=None):
            self.assertIsNone(git_commit(tempfile.mkdtemp()))
            self.assertIsNone(analyzer_version())

    def test_a_real_checkout_still_beats_the_stamp(self) -> None:
        # Frozen or not, a working git answer wins: the stamp is a fallback,
        # not an override.
        from verdict.provenance import git_commit

        with mock.patch.object(sys, "frozen", True, create=True),                 self._stub(COMMIT="deadbeef"):
            commit = git_commit(Path(__file__).resolve().parents[2])
            if commit is not None:      # skipped where git is unavailable
                self.assertNotEqual("deadbeef", commit)


class TheEnvelope(unittest.TestCase):
    def test_a_verdict_carries_its_schema_and_its_subject(self) -> None:
        case = _case(**{"summary.json": {"sample": SAMPLE}})

        result = combine_case(case, write_output=False)

        self.assertEqual(result["schema_version"], SCHEMA_VERSION)
        self.assertEqual(result["case_name"], case.name)
        self.assertEqual(result["sample"]["sha256"], SAMPLE["sha256"])
        self.assertTrue(result["generated_utc"].endswith("Z"))

    def test_the_case_id_is_the_sample_so_a_re_run_updates_rather_than_duplicates(self) -> None:
        case = _case(**{"summary.json": {"sample": SAMPLE}})

        first = combine_case(case, write_output=False)
        second = combine_case(case, write_output=False)

        self.assertEqual(first["case_id"], SAMPLE["sha256"])
        self.assertEqual(first["case_id"], second["case_id"])

    def test_a_case_with_no_recorded_hash_falls_back_to_its_name(self) -> None:
        case = _case(**{"summary.json": {"verdict": "SUSPICIOUS"}})

        result = combine_case(case, write_output=False)

        self.assertEqual(result["case_id"], case.name)
        self.assertEqual(result["sample"], {})

    def test_the_absolute_path_is_gone(self) -> None:
        """`case_dir` identified the analyst's machine rather than the case,
        changed when a folder moved, and was read by nothing."""
        case = _case(**{"summary.json": {"sample": SAMPLE}})

        result = combine_case(case, write_output=False)

        self.assertNotIn("case_dir", result)
        self.assertNotIn(str(case), json.dumps(result))

    def test_the_verdict_fields_still_sit_at_the_top_level(self) -> None:
        """The envelope wraps the verdict; it must not nest it, or every
        existing consumer breaks."""
        case = _case(**{"summary.json": {"sample": SAMPLE}})

        result = combine_case(case, write_output=False)

        for key in ("verdict", "severity", "band", "score", "score_model",
                    "modules_run", "modules_absent", "coverage_complete"):
            self.assertIn(key, result)

    def test_the_provenance_reaches_the_written_file(self) -> None:
        case = _case(**{"summary.json": {"sample": SAMPLE},
                        "yara_results.json": {"rule_file_count": 1594,
                                              "rules_compiled": 1594,
                                              "error": None}})

        combine_case(case, write_output=True)
        written = json.loads(
            (case / "combined_verdict.json").read_text(encoding="utf-8"))

        self.assertEqual(written["schema_version"], SCHEMA_VERSION)
        self.assertEqual(
            written["provenance"]["collectors"]["yara"]["rules_compiled"], 1594)
        self.assertEqual(written["provenance"]["analyzer"]["name"],
                         "ringforge-workbench")


if __name__ == "__main__":
    unittest.main()
