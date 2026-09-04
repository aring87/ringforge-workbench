"""Which modules ran on a case, and what each of them found.

The other half of `gui.UnifiedReportWindow` -- `case_summary.py` took its
verdict functions early in this thread, and this is the artifact detection and
finding extraction, about 500 widget-free lines behind a display with no tests.
Seventh and last module through this pass.

**Two defects, both of which a case page shows rather than reports:**

* the producer named the verdict module `Case Verdict` and two consumers asked
  for `Combined Score`, the name it had before `combined_score.json` became
  `combined_verdict.json` -- so the section for the file the whole scoring
  model exists to produce was permanently empty;
* every candidate list is written canonical-first, and the loader sorted the
  whole list by modification time instead, so a stale legacy file that had
  merely been touched more recently spoke for the case.
"""

import json
import tempfile
import time
import unittest
from pathlib import Path

from verdict.case_artifacts import (
    CASE_VERDICT,
    MODULES,
    build_findings,
    detect_artifacts,
    dynamic_summary_candidates,
    existing_paths,
    first_existing,
    load_summary,
    spec_findings,
)
from verdict.case_summary import overall_verdict


def _case(**files) -> Path:
    """A case folder. Keys use `__` for a path separator, written in order so
    the later ones have later modification times."""
    case = Path(tempfile.mkdtemp(prefix="ringforge_case_artifacts_"))
    for name, payload in files.items():
        path = case / name.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload) if not isinstance(payload, str)
                        else payload, encoding="utf-8")
        time.sleep(0.01)
    return case


class TheCaseVerdictNeverReachedThePage(unittest.TestCase):
    """The defect that matters most, because it is the case page's headline
    input and the section for it was simply blank."""

    VERDICT = {"verdict": "Elevated Attention", "severity": "High",
               "band": "Corroborated", "score": 55,
               "score_model": "corroboration-v1",
               "subscores": {"static": 42, "dynamic": 13},
               "modules_run": ["static", "dynamic"]}

    def test_the_producer_and_the_consumer_agree_on_the_name(self) -> None:
        """The whole bug in one assertion: `detect_artifacts` emits the key
        that `build_findings` looks up."""
        case = _case(**{"combined_verdict.json": self.VERDICT})

        artifacts = detect_artifacts(case)

        self.assertIn(CASE_VERDICT, artifacts)
        self.assertTrue(artifacts[CASE_VERDICT]["found"])
        self.assertEqual(set(MODULES) - set(artifacts), set())

    def test_the_verdict_reaches_the_findings(self) -> None:
        case = _case(**{"combined_verdict.json": self.VERDICT})

        findings = build_findings(detect_artifacts(case))

        self.assertIn("Verdict: Elevated Attention", findings["combined"])
        self.assertIn("Severity: High", findings["combined"])
        self.assertIn("Band: Corroborated", findings["combined"])

    def test_the_per_module_subscores_come_through(self) -> None:
        case = _case(**{"combined_verdict.json": self.VERDICT})

        findings = build_findings(detect_artifacts(case))

        self.assertIn("Static score: 42", findings["combined"])
        self.assertIn("Dynamic score: 13", findings["combined"])

    def test_coverage_is_reported_beside_the_band(self) -> None:
        """Which modules ran is half of what a corroboration verdict means."""
        case = _case(**{"combined_verdict.json": self.VERDICT})

        findings = build_findings(detect_artifacts(case))

        self.assertIn("Modules run: static, dynamic", findings["combined"])

    def test_the_metadata_copy_is_found_too(self) -> None:
        case = _case(**{"metadata__combined_verdict.json": self.VERDICT})

        findings = build_findings(detect_artifacts(case))

        self.assertTrue(findings["combined"])

    def test_an_artifacts_map_using_the_retired_name_still_reads(self) -> None:
        """A stored scan from an older build names the module the old way."""
        case = _case(**{"combined_verdict.json": self.VERDICT})
        artifacts = detect_artifacts(case)
        artifacts["Combined Score"] = artifacts.pop(CASE_VERDICT)

        findings = build_findings(artifacts)

        self.assertIn("Verdict: Elevated Attention", findings["combined"])

    def test_the_older_additive_shape_still_renders(self) -> None:
        case = _case(**{"combined_verdict.json": {
            "total_score": 31, "verdict": "SUSPICIOUS",
            "static_score": 21, "dynamic_score": 10}})

        findings = build_findings(detect_artifacts(case))

        self.assertIn("Total score: 31", findings["combined"])
        self.assertIn("Static score: 21", findings["combined"])


class PreferenceNotModificationTime(unittest.TestCase):
    """A candidate list is ordered for a reason."""

    def test_the_canonical_file_beats_a_newer_legacy_one(self) -> None:
        """Written second, so the legacy file has the later mtime. Sorting by
        time picked it; the canonical location is the answer."""
        case = _case(**{
            "static_analysis__summary.json": {"verdict": "Likely Malicious",
                                              "severity": "High", "score": 42},
            "summary.json": {"verdict": "LOW_RISK", "score": 3}})

        self.assertEqual(load_summary(case, "Static Analysis")["verdict"],
                         "Likely Malicious")

    def test_a_stale_file_could_change_the_case_verdict(self) -> None:
        """Why it matters: with no combined verdict, `overall_verdict` returns
        the static module's. The retired `LOW_RISK` wording would have been
        shown for a sample the engine called Likely Malicious."""
        case = _case(**{
            "static_analysis__summary.json": {"verdict": "Likely Malicious"},
            "summary.json": {"verdict": "LOW_RISK"}})

        got = overall_verdict(artifacts=detect_artifacts(case),
                              static_summary=load_summary(case, "Static Analysis"))

        self.assertEqual(got, "Likely Malicious")

    def test_the_legacy_file_is_still_used_when_it_is_the_only_one(self) -> None:
        case = _case(**{"summary.json": {"verdict": "SUSPICIOUS"}})

        self.assertEqual(load_summary(case, "Static Analysis")["verdict"],
                         "SUSPICIOUS")

    def test_first_existing_walks_in_order(self) -> None:
        case = _case(**{"b.json": {}, "a.json": {}})

        self.assertEqual(first_existing([case / "missing.json",
                                         case / "a.json",
                                         case / "b.json"]).name, "a.json")

    def test_first_existing_answers_none_rather_than_raising(self) -> None:
        self.assertIsNone(first_existing([]))
        self.assertIsNone(first_existing([Path("nowhere-at-all/x.json")]))

    def test_run_history_is_still_newest_first(self) -> None:
        """The one place time *is* the question -- which run happened last --
        and the ordering encodes it rather than a later sort overriding it."""
        case = _case(**{
            "dynamic_analysis__dynamic_runs__001__metadata__dynamic_run_summary.json":
                {"verdict": "Needs Review"},
            "dynamic_analysis__dynamic_runs__002__metadata__dynamic_run_summary.json":
                {"verdict": "Likely Malicious"}})

        candidates = dynamic_summary_candidates(case)

        self.assertIn("002", str(candidates[0]))
        self.assertEqual(load_summary(case, "Dynamic Analysis")["verdict"],
                         "Likely Malicious")

    def test_a_run_beats_a_legacy_root_summary(self) -> None:
        case = _case(**{
            "dynamic_analysis__dynamic_runs__001__metadata__dynamic_run_summary.json":
                {"verdict": "Likely Malicious"},
            "dynamic_run_summary.json": {"verdict": "STALE"}})

        self.assertEqual(load_summary(case, "Dynamic Analysis")["verdict"],
                         "Likely Malicious")


class WhatCountsAsAModuleHavingRun(unittest.TestCase):
    def test_a_report_file_alone_is_enough(self) -> None:
        """A module that wrote a page did run, even if its JSON is gone."""
        case = _case(**{"static_analysis__report.html": "<html></html>"})

        self.assertTrue(detect_artifacts(case)["Static Analysis"]["found"])

    def test_an_empty_case_finds_nothing(self) -> None:
        artifacts = detect_artifacts(_case())

        self.assertEqual([m for m, meta in artifacts.items() if meta["found"]], [])

    def test_an_unreadable_artifact_still_counts_as_having_run(self) -> None:
        """Ran and produced nothing readable is a different fact from did not
        run, and the page must be able to tell them apart."""
        case = _case(**{"static_analysis__summary.json": "{ not json"})

        artifacts = detect_artifacts(case)
        findings = build_findings(artifacts)

        self.assertTrue(artifacts["Static Analysis"]["found"])
        self.assertEqual(findings["static"], [])
        self.assertIsNone(load_summary(case, "Static Analysis"))

    def test_paths_are_deduplicated_and_ordered(self) -> None:
        case = _case(**{"static_analysis__summary.json": {}})

        paths = detect_artifacts(case)["Static Analysis"]["paths"]

        self.assertEqual(len(paths), len(set(p.lower() for p in paths)))

    def test_existing_paths_survives_an_unreadable_entry(self) -> None:
        self.assertEqual(existing_paths([Path("nowhere/x"), Path("nowhere/y")]),
                         [])


class TheFindings(unittest.TestCase):
    def test_static_merges_across_its_artifacts(self) -> None:
        """Static spreads its answer over several files -- the summary and the
        YARA results are both `Static Analysis`."""
        case = _case(**{
            "static_analysis__summary.json": {"verdict": "Likely Malicious",
                                              "score": 42},
            "yara_results.json": {"matched": True, "match_count": 3,
                                  "matches": [{"rule": "Trojan_Generic"}]}})

        findings = build_findings(detect_artifacts(case))

        self.assertIn("Verdict: Likely Malicious", findings["static"])
        self.assertIn("YARA match count: 3", findings["static"])
        self.assertIn("Matched rules: Trojan_Generic", findings["static"])

    def test_yara_finding_nothing_is_stated(self) -> None:
        """Not silence. A rule set that ran and matched nothing is a result."""
        case = _case(**{"yara_results.json": {"matched": False}})

        self.assertIn("YARA produced no matches",
                      build_findings(detect_artifacts(case))["static"])

    def test_a_failed_yara_scan_is_not_reported_as_no_matches(self) -> None:
        """`run_yara_scan` returns `matched: False, match_count: 0` on the
        record it writes when the scan *errored* -- those are initialised
        values, not observations. Found on a real case page: the stored
        summary for `c14cb5b6` says the rule set failed to compile and "no
        matches", and the same sample against the same rules today matches
        two rules.
        """
        case = _case(**{"yara_results.json": {
            "matched": False, "match_count": 0, "rule_file_count": 1593,
            "error": "YARA scan failed: undefined identifier \"filepath\""}})

        static = build_findings(detect_artifacts(case))["static"]

        self.assertNotIn("YARA produced no matches", static)
        self.assertTrue(any("YARA error" in line for line in static))
        self.assertTrue(any("not scanned, never as clean" in line
                            for line in static))

    def test_a_clean_scan_is_still_allowed_to_say_so(self) -> None:
        """The fix must not swallow a genuine clean result."""
        case = _case(**{"yara_results.json": {
            "matched": False, "match_count": 0, "rule_file_count": 1594,
            "error": None}})

        static = build_findings(detect_artifacts(case))["static"]

        self.assertIn("YARA produced no matches", static)

    def test_a_spawn_count_is_taken_before_the_preview_is_truncated(self) -> None:
        """The count is a measurement and the name list is presentation.
        Counting the truncated list would report ten spawns for forty."""
        case = _case(**{"dynamic_run_summary.json": {
            "findings": {"spawned_processes": [
                {"path": f"C:/x/p{i}.exe"} for i in range(40)]}}})

        findings = build_findings(detect_artifacts(case))

        self.assertIn("Spawned processes: 40", findings["dynamic"])

    def test_spec_auth_schemes_use_the_spec_module_s_vocabulary(self) -> None:
        """The case page printed the scheme names as the spec author wrote
        them, so it said `bearerAuth` where the spec report -- reading the same
        file -- said `bearer`."""
        lines = spec_findings({"auth_summary": ["bearerAuth", "JWT", "api_key"]})

        self.assertIn("Auth schemes: bearer, api-key", lines)

    def test_no_auth_scheme_is_stated_rather_than_omitted(self) -> None:
        self.assertIn("Auth schemes: none", spec_findings({"auth_summary": []}))

    def test_extension_risk_notes_survive_a_missing_summary_block(self) -> None:
        """The extension extractor was written out twice, and one copy nested
        the risk notes inside the summary check -- so an artifact with notes
        and no summary showed nothing."""
        case = _case(**{"browser_extension_analysis__browser_extension_analysis.json":
                        {"risk_notes": ["Requests <all_urls> host access."]}})

        findings = build_findings(detect_artifacts(case))

        self.assertIn("Risk notes:", findings["extension"])
        self.assertIn("  Requests <all_urls> host access.", findings["extension"])

    def test_the_extension_band_is_reported_when_the_export_carries_it(self) -> None:
        case = _case(**{"browser_extension_analysis__browser_extension_analysis.json":
                        {"summary": {"risk_verdict": "Elevated Attention",
                                     "risk_severity": "High"}}})

        findings = build_findings(detect_artifacts(case))

        self.assertIn("Extension verdict: Elevated Attention",
                      findings["extension"])
        self.assertIn("Extension band: High", findings["extension"])

    def test_every_bucket_exists_even_when_empty(self) -> None:
        """The page iterates them; a missing key would be a crash rather than
        an empty section."""
        findings = build_findings({})

        self.assertEqual(set(findings), set(MODULES.values()))

    def test_duplicates_are_collapsed(self) -> None:
        case = _case(**{
            "static_analysis__summary.json": {"verdict": "Likely Malicious"},
            "static_analysis__metadata__static_run_summary.json":
                {"verdict": "Likely Malicious"}})

        findings = build_findings(detect_artifacts(case))

        self.assertEqual(findings["static"].count("Verdict: Likely Malicious"), 1)


class AgainstARealCaseFolder(unittest.TestCase):
    """Read against the folder as it is, never against a snapshot of it.

    These pinned the 20 Aug contents of `cases/c14cb5b6_payload` and broke the
    first time static analysis was re-run on it. A case folder is a mutable
    artifact; the invariant is that detection agrees with the filesystem and
    the findings agree with the files.
    """

    CASE = Path("cases/c14cb5b6_payload")

    def setUp(self) -> None:
        if not (self.CASE / "summary.json").exists():
            self.skipTest("reference case folder is not checked out")

    def test_it_detects_the_static_module(self) -> None:
        self.assertTrue(detect_artifacts(self.CASE)["Static Analysis"]["found"])

    def test_case_verdict_detection_agrees_with_the_filesystem(self) -> None:
        on_disk = ((self.CASE / "combined_verdict.json").exists()
                   or (self.CASE / "metadata" / "combined_verdict.json").exists())

        self.assertEqual(detect_artifacts(self.CASE)[CASE_VERDICT]["found"], on_disk)

    def test_the_static_findings_quote_the_summary(self) -> None:
        raw = json.loads((self.CASE / "summary.json").read_text(encoding="utf-8"))
        findings = build_findings(detect_artifacts(self.CASE))

        self.assertIn(f"Verdict: {raw['verdict']}", findings["static"])


if __name__ == "__main__":
    unittest.main()
