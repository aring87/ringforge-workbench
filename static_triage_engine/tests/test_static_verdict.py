"""The static module's own verdict, and the vocabulary it retired.

Phase 4b of `docs/SCORING.md`. `engine.py` wrote `summary["verdict"]` from
`score_risk` plus `classify_verdict` -- a 0-40 additive score banded at 8/20/30,
in which a clean VirusTotal result could suppress local observations. It writes
a `corroboration-v1` band now, and `summary.json` carries the coverage and the
categories behind it.
"""

import re
import tempfile
import unittest
from pathlib import Path

from static_triage_engine.combine_case import static_verdict_for_case
from static_triage_engine.verdict_rationale import (
    _NEXT_STEP,
    build_static_verdict_rationale,
)

ROOT = Path(__file__).resolve().parents[2]

#: Produced by `classify_verdict`, which no longer exists. Nothing may write
#: them again: two vocabularies in one report is what this phase existed to end.
RETIRED_VERDICTS = ("MALICIOUS", "SUSPICIOUS", "LOW_RISK", "MEDIUM_RISK")


def _case(**files) -> Path:
    home = Path(tempfile.mkdtemp()) / "case"
    (home / "static_analysis").mkdir(parents=True)
    import json
    for name, payload in files.items():
        (home / "static_analysis" / f"{name}.json").write_text(
            json.dumps(payload), encoding="utf-8")
    return home


class TheStaticVerdictIsABand(unittest.TestCase):
    def test_an_anonymous_binary_needs_review(self) -> None:
        home = _case(yara_results={"matched": False, "match_count": 0},
                     signing={"verify_ok": False},
                     api_analysis={"returncode": 0, "chain_findings": []})
        result = static_verdict_for_case(
            home, {"sample": {"filename": "a.exe"}}, {}, {"version_info": {}})

        self.assertEqual(result["verdict"], "Needs Review")
        self.assertEqual(result["severity"], "Medium")

    def test_it_never_returns_a_retired_verdict(self) -> None:
        home = _case(yara_results={"matched": False, "match_count": 0},
                     signing={"verify_ok": False},
                     api_analysis={"returncode": 0, "chain_findings": []})
        result = static_verdict_for_case(
            home, {"sample": {"filename": "a.exe"}}, {}, {"version_info": {}})

        self.assertNotIn(result["verdict"].upper().replace(" ", "_"),
                         RETIRED_VERDICTS)

    def test_it_carries_the_evidence_that_produced_it(self) -> None:
        # The report renders these; a verdict arriving without its reasons is
        # the additive model's failure mode in a new shape.
        home = _case(yara_results={"matched": False, "match_count": 0},
                     signing={"verify_ok": False},
                     api_analysis={"returncode": 0, "chain_findings": []})
        result = static_verdict_for_case(
            home, {"sample": {"filename": "a.exe"}}, {}, {"version_info": {}})

        self.assertTrue(result["suspicious"])
        self.assertTrue(all(text.strip() for text in result["suspicious"]))


class ConfidenceFollowsCoverageFirst(unittest.TestCase):
    def _verdict(self, **files):
        home = _case(**files)
        return static_verdict_for_case(
            home, {"sample": {"filename": "a.exe"}}, {},
            {"version_info": {"CompanyName": "V", "ProductName": "P",
                              "FileDescription": "D", "OriginalFilename": "a.exe"}})

    def test_a_dark_collector_caps_confidence_low(self) -> None:
        # Whatever the verdict says, the thing that would have disagreed was
        # never asked.
        result = self._verdict(signing={"verify_ok": True,
                                        "timestamp_verified": True,
                                        "subject": "CN=V"})

        self.assertFalse(result["coverage_complete"])
        self.assertEqual(result["confidence"], "Low confidence")

    def test_a_clean_static_result_never_reaches_high_confidence(self) -> None:
        # Static can establish that nothing was found. Only watching the sample
        # run can establish that nothing happens.
        result = self._verdict(
            yara_results={"matched": False, "match_count": 0},
            signing={"verify_ok": True, "timestamp_verified": True,
                     "subject": "CN=V", "signature_present": True},
            api_analysis={"returncode": 0, "chain_findings": []})

        self.assertEqual(result["counts"]["categories_present"], 0)
        self.assertEqual(result["confidence"], "Moderate confidence")

    def test_an_emphatic_category_with_full_coverage_is_high(self) -> None:
        result = self._verdict(
            yara_results={"matched": True, "match_count": 1,
                          "matches": [{"rule": "Formbook_Stealer",
                                       "meta": {}, "tags": []}]},
            signing={"verify_ok": True, "timestamp_verified": True,
                     "subject": "CN=V", "signature_present": True},
            api_analysis={"returncode": 0, "chain_findings": []})

        self.assertEqual(result["confidence"], "High confidence")


class TheRetiredVocabularyIsGone(unittest.TestCase):
    def test_no_module_writes_a_retired_verdict(self) -> None:
        # Two verdict vocabularies in one window is what Phase 4 existed to end.
        # Tests and docs may name them; nothing that produces output may.
        offenders = {}
        for path in ROOT.rglob("*.py"):
            rel = path.relative_to(ROOT).as_posix()
            if (rel.startswith((".venv/", "cases/"))
                    or "/tests/" in rel or path.name.startswith("test_")):
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
            # Only literals -- prose in a docstring explaining what was retired
            # is exactly what should be kept.
            hits = [v for v in RETIRED_VERDICTS
                    if re.search(rf'["\']{v}["\']', source)]
            if hits:
                offenders[rel] = hits

        self.assertFalse(offenders, f"retired verdict literals in: {offenders}")


class EveryBandHasAdvice(unittest.TestCase):
    """A verdict with no next step is a verdict nobody can act on."""

    def test_the_advice_table_covers_every_verdict_the_model_produces(self) -> None:
        # Driven through the model rather than read off its source: parsing the
        # file for string literals also picks up the severities, and a guard
        # that cannot tell a band from a verdict is not a guard.
        from verdict import Category, band

        def cat(name, module="dynamic", **kw):
            kw.setdefault("present", False)
            if kw["present"]:
                kw.setdefault("reason", "observed")
            return Category(name=name, module=module, **kw)

        scenarios = [
            ([cat("a")], 0, False),                       # clean, detonated
            ([cat("a", "static")], 0, False),              # clean, static only
            ([cat("a")], 99, False),                       # volume, no category
            ([cat("a", collected=False)], 0, False),       # a dark collector
            ([cat("a", collected=False)], 0, True),        # dark + dissent
            ([cat("a", present=True)], 0, False),          # one category
            ([cat("a", present=True), cat("b", present=True)], 0, False),
            ([cat("a", present=True), cat("b", present=True),
              cat("c", present=True)], 0, False),
        ]

        produced = {band(cats, context_score=ctx,
                         third_party_dissent=dissent).verdict
                    for cats, ctx, dissent in scenarios}

        # Sanity: the scenarios have to actually cover the range, or a table
        # with one entry would pass.
        self.assertGreaterEqual(len(produced), 6, f"only reached {produced}")
        missing = produced - set(_NEXT_STEP)
        self.assertFalse(missing, f"no recommended next step for: {sorted(missing)}")

    def test_each_next_step_says_something_specific(self) -> None:
        for verdict, advice in _NEXT_STEP.items():
            with self.subTest(verdict=verdict):
                self.assertGreater(len(advice), 40)

    def test_coverage_verdicts_point_at_the_bench_not_the_sample(self) -> None:
        # The two that are statements about collection rather than about the
        # file. Advising someone to investigate the sample would be wrong.
        for verdict in ("Insufficient Coverage", "No Findings, Coverage Incomplete"):
            with self.subTest(verdict=verdict):
                self.assertRegex(_NEXT_STEP[verdict], r"collector|bench")


class TheRationaleQuotesTheCategories(unittest.TestCase):
    def test_findings_come_from_the_category_reasons(self) -> None:
        rationale = build_static_verdict_rationale(
            static_score=20, verdict="Needs Review", confidence="Low confidence",
            severity="Medium",
            evidence=[{"name": "stripped_metadata", "module": "static",
                       "strong": False, "reason": "The version-info block is empty."}],
            coverage_complete=True)

        self.assertIn("The version-info block is empty.",
                      rationale["findings"][0])

    def test_virustotal_is_reported_separately_and_labelled(self) -> None:
        rationale = build_static_verdict_rationale(
            static_score=0, verdict="No Indicators Found",
            confidence="Moderate confidence", severity="Low",
            evidence=[], coverage_complete=True,
            vt_found=True, vt_malicious=60, vt_suspicious=2)

        self.assertFalse(rationale["findings"])
        self.assertIn("did not contribute to the verdict",
                      rationale["third_party"][0])

    def test_being_unsigned_is_no_longer_a_reason(self) -> None:
        # It used to be listed as a reason the score went up. Most malware is
        # unsigned and so is most small legitimate tooling.
        rationale = build_static_verdict_rationale(
            static_score=0, verdict="No Indicators Found",
            confidence="Moderate confidence", severity="Low",
            evidence=[], coverage_complete=True)

        joined = " ".join(rationale["findings"] + rationale["notes"])
        self.assertNotIn("unsigned", joined.lower())


if __name__ == "__main__":
    unittest.main()
