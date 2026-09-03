"""The Unified Report's verdict, which had no tests because it had no module.

All four functions lived inside `gui.UnifiedReportWindow`, referenced no
widget, and could not be exercised without a display. Two defects survived that
way into a release whose headline was *One Verdict Model*:

* every verdict the module could produce mapped to `sev-none`, so a case
  reading "High API Spec Risk" rendered in the same neutral grey chip as
  "No Results" -- measured, 13 of 13;
* the fallback derived a band by joining every finding's text and matching
  substrings, so the word `persistence` anywhere in any module's output
  produced "Moderate Risk".

The first is fixed in `severity_class_for_label`, the second by deleting it.
"""

import unittest

from dynamic_analysis.report_theme import severity_class_for_label
from verdict.case_summary import (
    INSUFFICIENT,
    NOTHING,
    extension_score_and_verdict,
    overall_verdict,
    spec_score_and_verdict,
)


class VerdictPreference(unittest.TestCase):
    """The order is a preference between modules, not a computation."""

    def test_a_combined_verdict_wins(self) -> None:
        got = overall_verdict(
            artifacts={}, combined={"verdict": "Likely Malicious"},
            dynamic_summary={"verdict": "Needs Review"})

        self.assertEqual(got, "Likely Malicious")

    def test_combined_severity_is_used_when_it_has_no_verdict(self) -> None:
        self.assertEqual(
            overall_verdict(artifacts={}, combined={"severity": "High"}), "High")

    def test_dynamic_beats_static(self) -> None:
        got = overall_verdict(artifacts={},
                              dynamic_summary={"verdict": "Elevated Attention"},
                              static_summary={"verdict": "Needs Review"})

        self.assertEqual(got, "Elevated Attention")

    def test_static_is_used_when_dynamic_did_not_score(self) -> None:
        self.assertEqual(
            overall_verdict(artifacts={}, static_summary={"verdict": "Needs Review"}),
            "Needs Review")


class NoModuleScoredIt(unittest.TestCase):
    """The replaced fallback, and why the replacement is honest.

    It used to join every finding's text and grep it, so `persistence` in any
    module's output became "Moderate Risk". A band read out of a substring is
    not a band.
    """

    def test_modules_ran_but_none_scored_reports_coverage(self) -> None:
        got = overall_verdict(artifacts={"Static Analysis": {"found": True},
                                         "Dynamic Analysis": {"found": True}})

        self.assertEqual(got, INSUFFICIENT)

    def test_nothing_ran_at_all_says_so_distinctly(self) -> None:
        """"Nothing was collected" and "things ran and found nothing" are
        different facts and must not share a word."""
        self.assertEqual(overall_verdict(artifacts={}), NOTHING)
        self.assertNotEqual(INSUFFICIENT, NOTHING)

    def test_evidence_text_can_no_longer_invent_a_band(self) -> None:
        """The exact input that used to produce "Moderate Risk"."""
        artifacts = {"Static Analysis": {"found": True,
                                         "notes": "persistence and critical"}}

        self.assertEqual(overall_verdict(artifacts=artifacts), INSUFFICIENT)


class DomainOnlyCases(unittest.TestCase):
    def test_a_spec_only_case_bands_on_the_spec_score(self) -> None:
        got = overall_verdict(
            artifacts={"Spec Analysis": {"found": True}},
            spec_summary={"summary": {"high_risk_endpoint_count": 3,
                                      "medium_risk_endpoint_count": 6,
                                      "sensitive_unauthenticated_endpoint_count": 4}})

        self.assertEqual(got, "High API Spec Risk")

    def test_a_spec_case_beside_another_module_does_not(self) -> None:
        """With any peer module present the case is not spec-only, so the
        per-domain wording would misdescribe it."""
        got = overall_verdict(
            artifacts={"Spec Analysis": {"found": True},
                       "Dynamic Analysis": {"found": True}},
            spec_summary={"summary": {"high_risk_endpoint_count": 8}})

        self.assertEqual(got, INSUFFICIENT)

    def test_an_extension_only_case_prefers_the_module_s_own_verdict(self) -> None:
        got = overall_verdict(
            artifacts={"Browser Extension Analysis": {"found": True}},
            extension_summary={"summary": {"risk_verdict": "high", "risk_score": 1}})

        self.assertEqual(got, "High Browser Extension Risk")


class SpecScoring(unittest.TestCase):
    """Arithmetic moved, not rewritten -- changing it would move verdicts."""

    def test_each_component_is_capped(self) -> None:
        score, _ = spec_score_and_verdict(
            {"summary": {"high_risk_endpoint_count": 99,
                         "medium_risk_endpoint_count": 99,
                         "sensitive_unauthenticated_endpoint_count": 99,
                         "auth_gap_count": 99, "schema_issue_endpoint_count": 99,
                         "file_upload_endpoint_count": 99}})

        self.assertEqual(score, 80)  # 30 + 18 + 12 + 8 + 6 + 6

    def test_the_http_server_flag_adds_five(self) -> None:
        with_flag, _ = spec_score_and_verdict(
            {"summary": {}, "scoring": {"http_server_detected": True}})
        without, _ = spec_score_and_verdict({"summary": {}})

        self.assertEqual(with_flag - (without or 0), 5)

    def test_bands(self) -> None:
        cases = [
            # 30 + 18 + 12 = 60
            ({"high_risk_endpoint_count": 3, "medium_risk_endpoint_count": 6,
              "sensitive_unauthenticated_endpoint_count": 4},
             "High API Spec Risk"),
            # 30 + 5 = 35
            ({"high_risk_endpoint_count": 3, "auth_gap_count": 5},
             "Medium API Spec Risk"),
            ({"high_risk_endpoint_count": 2}, "Low API Spec Risk"),
            ({}, "Informational API Spec Review"),
        ]
        for summary, expected in cases:
            _, verdict = spec_score_and_verdict({"summary": summary})
            self.assertEqual(verdict, expected, summary)

    def test_high_risk_endpoints_alone_can_never_reach_the_high_band(self) -> None:
        """A property of the caps, documented rather than hidden.

        `high_risk_endpoint_count` contributes at most 30 and the High band
        starts at 60, so a spec with a hundred high-risk endpoints and nothing
        else scores *Low*. Whether that is the right shape is a product
        question; this pins it so a change to the numbers is deliberate.
        """
        score, verdict = spec_score_and_verdict(
            {"summary": {"high_risk_endpoint_count": 100}})

        self.assertEqual(score, 30)
        self.assertEqual(verdict, "Low API Spec Risk")

    def test_a_non_mapping_is_answered_not_raised(self) -> None:
        self.assertEqual(spec_score_and_verdict(None), (None, None))
        self.assertEqual(spec_score_and_verdict("nope"), (None, None))

    def test_unparseable_counts_do_not_raise(self) -> None:
        score, _ = spec_score_and_verdict(
            {"summary": {"high_risk_endpoint_count": "lots"}})

        self.assertEqual(score, 0)


class ExtensionScoring(unittest.TestCase):
    def test_the_modules_own_verdict_is_preferred_over_the_score(self) -> None:
        score, verdict = extension_score_and_verdict(
            {"summary": {"risk_verdict": "low", "risk_score": 9}})

        self.assertEqual(verdict, "Low Browser Extension Risk")
        self.assertEqual(score, 9)

    def test_the_wording_the_module_actually_writes_is_preferred_too(self) -> None:
        """The test above passes on retired wording, which is how the defect
        lived here: `"low"` is the additive vocabulary, and under
        `corroboration-v1` the field holds a sentence. Every one of those
        missed, so every extension-only case silently banded on `risk_score`.
        """
        for wording, expected in (
                ("Likely Malicious", "High Browser Extension Risk"),
                ("Elevated Attention", "High Browser Extension Risk"),
                ("Needs Review", "Medium Browser Extension Risk"),
                ("Low Suspicion", "Low Browser Extension Risk"),
                ("No Indicators Found", "Low Browser Extension Risk")):
            with self.subTest(wording=wording):
                # A score that would band High on its own, so a pass here is
                # the preference firing rather than the fallback agreeing.
                _, verdict = extension_score_and_verdict(
                    {"summary": {"risk_verdict": wording, "risk_score": 9}})
                self.assertEqual(verdict, expected)

    def test_the_severity_wins_over_the_sentence(self) -> None:
        """The band is the model's output; the sentence is written for a
        reader and its wording follows the domain. Read the band."""
        _, verdict = extension_score_and_verdict(
            {"summary": {"risk_verdict": "Needs Review",
                         "risk_severity": "High", "risk_score": 0}})

        self.assertEqual(verdict, "High Browser Extension Risk")

    def test_an_unknown_band_is_not_dressed_as_a_risk_level(self) -> None:
        """`Unknown` is the model declining to band. Falling through to the
        score would invent the answer it declined to give."""
        _, verdict = extension_score_and_verdict(
            {"summary": {"risk_verdict": "Insufficient Coverage",
                         "risk_severity": "Unknown", "risk_score": 9}})

        self.assertEqual(verdict, INSUFFICIENT)

    def test_the_score_is_returned_whatever_the_band(self) -> None:
        score, _ = extension_score_and_verdict(
            {"summary": {"risk_severity": "High", "risk_score": 12}})

        self.assertEqual(score, 12)

    def test_it_bands_on_the_score_when_no_verdict_is_given(self) -> None:
        for raw, expected in ((9, "High Browser Extension Risk"),
                              (4, "Medium Browser Extension Risk"),
                              (0, "Low Browser Extension Risk")):
            _, verdict = extension_score_and_verdict({"summary": {"risk_score": raw}})
            self.assertEqual(verdict, expected, raw)

    def test_neither_a_verdict_nor_a_usable_score_gives_nothing(self) -> None:
        self.assertEqual(
            extension_score_and_verdict({"summary": {"risk_score": None}}),
            (None, None))


class EveryVerdictRendersWithAColour(unittest.TestCase):
    """The defect this module was extracted to expose.

    Measured 03 Sep: 13 of 13 verdicts the Unified Report could produce mapped
    to `sev-none`, so "High Risk" and "High API Spec Risk" wore the same grey
    chip as "No Results".
    """

    PRODUCED = (
        "High API Spec Risk", "Medium API Spec Risk", "Low API Spec Risk",
        "Informational API Spec Review", "High Browser Extension Risk",
        "Medium Browser Extension Risk", "Low Browser Extension Risk",
        INSUFFICIENT, NOTHING,
    )

    def test_none_of_them_renders_as_the_neutral_chip(self) -> None:
        grey = [v for v in self.PRODUCED
                if severity_class_for_label(v) == "sev-none"]

        self.assertEqual(grey, [], f"these would render grey: {grey}")

    def test_high_reads_as_high(self) -> None:
        for verdict in ("High API Spec Risk", "High Browser Extension Risk"):
            self.assertEqual(severity_class_for_label(verdict), "sev-high", verdict)

    def test_the_retired_wording_still_colours(self) -> None:
        """Case folders written before this change still render."""
        for verdict in ("High Risk", "Moderate Risk", "Low Risk"):
            self.assertNotEqual(severity_class_for_label(verdict), "sev-none", verdict)


if __name__ == "__main__":
    unittest.main()
