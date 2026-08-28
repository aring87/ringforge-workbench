"""Reading a case off disk without collapsing "did not run" into "found nothing".

Phase 4a of `docs/SCORING.md`. `verdict/tests/test_combine.py` covers the
deciding; this covers the reading, which is where the distinction the whole
model rests on is easiest to lose. A case folder with no `yara_results.json`
and a case folder whose YARA scan matched nothing look identical to any loader
that reaches for a dict and falls back to `{}`.
"""

import json
import tempfile
import unittest
from pathlib import Path

from static_triage_engine.combine_case import (
    VERDICT_FILENAME,
    case_home,
    combine_case,
    load_case,
    virustotal_dissent,
)


def _case(**files) -> Path:
    """A case folder holding exactly the files named."""
    home = Path(tempfile.mkdtemp()) / "case"
    static = home / "static_analysis"
    static.mkdir(parents=True)
    for name, payload in files.items():
        (static / f"{name}.json").write_text(json.dumps(payload), encoding="utf-8")
    return home


def _clean_static():
    return dict(
        summary={"sample": {"filename": "vendor_setup.exe"}},
        pe_metadata={"version_info_collected": True, "version_info": {
            "CompanyName": "Vendor", "ProductName": "Product",
            "FileDescription": "Installer", "OriginalFilename": "vendor_setup.exe"}},
        signing={"verify_ok": True, "timestamp_verified": True,
                 "subject": "CN=Vendor", "signature_present": True},
        yara_results={"matched": False, "match_count": 0},
        iocs={"observables": {"domains": [], "urls": [], "ips": []}},
        api_analysis={"returncode": 0, "chain_findings": []},
    )


class FindingTheCase(unittest.TestCase):
    def test_a_module_directory_normalises_back_to_the_case(self) -> None:
        home = Path("C:/cases/abc123")

        self.assertEqual(case_home(home / "dynamic_analysis"), home)
        self.assertEqual(case_home(home / "static_analysis"), home)
        self.assertEqual(case_home(home), home)


class NotRunIsNotFoundNothing(unittest.TestCase):
    """The distinction the loader is most likely to destroy."""

    def test_a_missing_file_loads_as_none(self) -> None:
        loaded = load_case(_case(summary={"sample": {}}))

        self.assertIsNotNone(loaded["summary"])
        self.assertIsNone(loaded["yara_results"])

    def test_an_empty_file_loads_as_a_dict(self) -> None:
        # It ran and produced nothing. Not the same observation.
        loaded = load_case(_case(summary={"sample": {}}, yara_results={}))

        self.assertEqual(loaded["yara_results"], {})

    def test_a_case_with_no_yara_reports_that_category_unknown(self) -> None:
        files = _clean_static()
        del files["yara_results"]
        result = combine_case(_case(**files), write_output=False)

        self.assertIn("known_malware_signature", result["uncollected_categories"])
        self.assertFalse(result["coverage_complete"])

    def test_a_case_with_a_clean_yara_scan_does_not(self) -> None:
        result = combine_case(_case(**_clean_static()), write_output=False)

        self.assertEqual(result["uncollected_categories"], [])
        self.assertTrue(result["coverage_complete"])


class ACaseWithNoDynamicRun(unittest.TestCase):
    def test_it_never_claims_a_clean_baseline(self) -> None:
        result = combine_case(_case(**_clean_static()), write_output=False)

        self.assertEqual(result["verdict"], "No Indicators Found")
        self.assertIn("dynamic", result["modules_absent"])

    def test_static_alone_still_produces_a_verdict(self) -> None:
        result = combine_case(_case(**_clean_static()), write_output=False)

        self.assertEqual(result["modules_run"], ["static"])
        self.assertEqual(result["severity"], "Low")

    def test_an_empty_case_folder_is_insufficient_coverage(self) -> None:
        home = Path(tempfile.mkdtemp()) / "case"
        home.mkdir(parents=True)
        result = combine_case(home, write_output=False)

        self.assertEqual(result["modules_run"], [])


class ADetonationJoinsThePool(unittest.TestCase):
    """Dynamic categories are rebuilt from the run summary, not recomputed.

    The run happened in another process on another machine. Re-deriving its
    categories here would mean a second implementation of the dynamic scorer
    that nothing tests against a real run.
    """

    def _with_run(self, categories):
        home = _case(**_clean_static())
        run = home / "dynamic_analysis" / "dynamic_runs" / "run1" / "metadata"
        run.mkdir(parents=True)
        (run / "dynamic_run_summary.json").write_text(json.dumps({
            "score_detail": {"context_score": 4, "categories": categories}
        }), encoding="utf-8")
        return home

    def test_a_clean_detonation_lets_the_case_claim_a_baseline(self) -> None:
        home = self._with_run([
            {"name": "packed_payload", "module": "dynamic", "collected": True,
             "present": False, "strong": False, "detail": "", "reason": ""},
        ])
        result = combine_case(home, write_output=False)

        self.assertIn("dynamic", result["modules_run"])
        self.assertEqual(result["verdict"], "Benign / Clean Baseline")

    def test_dynamic_evidence_corroborates_static_evidence(self) -> None:
        files = _clean_static()
        files["yara_results"] = {
            "matched": True, "match_count": 1,
            "matches": [{"rule": "Formbook_Stealer", "meta": {}, "tags": []}]}
        home = Path(tempfile.mkdtemp()) / "case"
        (home / "static_analysis").mkdir(parents=True)
        for name, payload in files.items():
            (home / "static_analysis" / f"{name}.json").write_text(
                json.dumps(payload), encoding="utf-8")
        run = home / "dynamic_analysis" / "dynamic_runs" / "run1" / "metadata"
        run.mkdir(parents=True)
        (run / "dynamic_run_summary.json").write_text(json.dumps({
            "score_detail": {"context_score": 0, "categories": [
                {"name": "process_injection", "module": "dynamic",
                 "collected": True, "present": True, "strong": False,
                 "detail": "1 injection", "reason": "Sysmon recorded injection"},
            ]}
        }), encoding="utf-8")

        result = combine_case(home, write_output=False)

        self.assertEqual(result["counts"]["categories_present"], 2)
        self.assertEqual(result["verdict"], "Elevated Attention")
        self.assertEqual({e["module"] for e in result["evidence"]},
                         {"static", "dynamic"})


class VirusTotalCanFloorAndNoMore(unittest.TestCase):
    def test_no_result_is_not_dissent(self) -> None:
        self.assertEqual(virustotal_dissent({}), (False, ""))
        self.assertEqual(virustotal_dissent(None), (False, ""))

    def test_a_clean_result_is_not_dissent(self) -> None:
        fired, _ = virustotal_dissent({"virustotal": {
            "found": True, "malicious": 0, "suspicious": 0, "harmless": 70}})

        self.assertFalse(fired)

    def test_one_or_two_engines_is_noise_not_dissent(self) -> None:
        # The noise floor of multi-engine scanning. A floor that fired here
        # would move a large fraction of ordinary software to Needs Review and
        # teach everyone to ignore the band.
        for malicious in (1, 2):
            with self.subTest(malicious=malicious):
                fired, _ = virustotal_dissent({"virustotal": {
                    "found": True, "malicious": malicious, "suspicious": 0}})

                self.assertFalse(fired)

    def test_five_engines_agreeing_is_dissent(self) -> None:
        fired, detail = virustotal_dissent({"virustotal": {
            "found": True, "malicious": 5, "suspicious": 1}})

        self.assertTrue(fired)
        self.assertIn("not local evidence", detail)

    def test_it_floors_an_otherwise_clean_case(self) -> None:
        files = _clean_static()
        files["summary"] = {"sample": {"filename": "vendor_setup.exe"},
                            "virustotal": {"found": True, "malicious": 60,
                                           "suspicious": 4}}
        result = combine_case(_case(**files), write_output=False)

        self.assertEqual(result["verdict"], "Needs Review")
        self.assertTrue(result["dissent_floor_applied"])
        self.assertIn("60 malicious", result["dissent_floor_reason"])

    def test_the_floor_marks_a_coverage_problem_not_a_finding(self) -> None:
        # A sample sitting here because of the floor is one our collectors
        # failed on. That is the useful reading, and the reason says so.
        files = _clean_static()
        files["summary"] = {"sample": {"filename": "x.exe"},
                            "virustotal": {"found": True, "malicious": 60}}
        result = combine_case(_case(**files), write_output=False)

        self.assertEqual(result["counts"]["categories_present"], 0)
        self.assertIn("check coverage", result["dissent_floor_reason"])


class TheVerdictIsWrittenBesideTheOldOne(unittest.TestCase):
    """Both shapes coexist for one release; the additive one goes in Phase 4b."""

    def test_it_writes_the_new_file_and_a_metadata_copy(self) -> None:
        home = _case(**_clean_static())
        combine_case(home, write_output=True)

        self.assertTrue((home / VERDICT_FILENAME).exists())
        self.assertTrue((home / "metadata" / VERDICT_FILENAME).exists())

    def test_it_does_not_touch_the_additive_output(self) -> None:
        home = _case(**_clean_static())
        (home / "combined_score.json").write_text('{"total_score": 12}',
                                                  encoding="utf-8")
        combine_case(home, write_output=True)

        self.assertEqual(
            json.loads((home / "combined_score.json").read_text()),
            {"total_score": 12})

    def test_the_written_verdict_names_its_model(self) -> None:
        home = _case(**_clean_static())
        combine_case(home, write_output=True)

        written = json.loads((home / VERDICT_FILENAME).read_text())
        self.assertEqual(written["score_model"], "corroboration-v1")


if __name__ == "__main__":
    unittest.main()
