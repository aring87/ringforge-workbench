"""The page has to say the finding before it says the number.

Phase 4b left the unified report rewired onto one verdict and never designed.
It opened with a twelve-row key/value table in which the verdict sat between
"Case Path" and five per-module subscores from the retired additive model --
and the evidence, the prose each category carries, appeared nowhere at all.

These pin the *order*, because the order is the argument. A number at the top
is read as the finding and prose at the bottom is read as supporting material;
the model's whole claim is the reverse.
"""

import re
import unittest

from static_triage_engine.verdict_report import render_verdict_report


def _verdict(**over):
    base = {
        "score_model": "corroboration-v1",
        "band": "Strongly Corroborated",
        "domain": "malware",
        "verdict": "Likely Malicious",
        "severity": "High",
        "score": 120,
        "counts": {"categories_present": 3, "categories_strong": 3,
                   "categories_unknown": 0},
        "coverage_complete": True,
        "modules_run": ["dynamic"],
        "modules_absent": ["static", "spec", "api", "extension"],
        "uncollected_categories": [],
        "coverage": {"dynamic": {"collected": ["packed_payload"],
                                 "uncollected": [], "complete": True}},
        "evidence": [
            {"name": "packed_payload", "module": "dynamic", "strong": True,
             "detail": "3 rules matched memory but not disk",
             "reason": "YARA matched in process memory but not on disk."},
        ],
    }
    base.update(over)
    return base


def _order(page: str, *needles: str) -> list[int]:
    return [page.index(n) for n in needles]


class TheFindingComesBeforeTheNumber(unittest.TestCase):
    def test_the_verdict_precedes_the_evidence_precedes_the_coverage(self) -> None:
        page = render_verdict_report(_verdict())

        v, e, c = _order(page, "Likely Malicious", ">Evidence<", "What was looked at")
        self.assertLess(v, e)
        self.assertLess(e, c)

    def test_the_context_score_is_last_and_labelled(self) -> None:
        # It used to sit in the opening table beside the verdict, where a
        # reader takes it for the finding.
        page = render_verdict_report(_verdict())

        score_at = page.index("Context score")
        self.assertGreater(score_at, page.index(">Evidence<"))
        self.assertGreater(score_at, page.index("What was looked at"))
        self.assertIn("descriptive volume", page)

    def test_coverage_precedes_the_per_module_artifacts(self) -> None:
        # A gap qualifies everything after it. A reader who meets the detail
        # first has formed a view before learning what was missing.
        page = render_verdict_report(
            _verdict(), module_artifacts={"dynamic": {"found": True, "paths": ["x"]}})

        self.assertLess(page.index("What was looked at"), page.index(">Artifacts<"))


class TheEvidenceIsOnThePage(unittest.TestCase):
    """The thing the old report did not have at all."""

    def test_each_category_carries_its_reason(self) -> None:
        page = render_verdict_report(_verdict())

        self.assertIn("YARA matched in process memory but not on disk.", page)
        self.assertIn("packed_payload", page)

    def test_an_emphatic_category_says_so(self) -> None:
        page = render_verdict_report(_verdict())

        self.assertIn("emphatic", page)

    def test_no_evidence_does_not_read_as_a_clean_result(self) -> None:
        page = render_verdict_report(_verdict(
            band="No Evidence", verdict="No Indicators Found", severity="Low",
            counts={"categories_present": 0, "categories_strong": 0,
                    "categories_unknown": 0}, evidence=[]))

        self.assertIn("absence of a claim, not a claim of absence", page)


class WhatCouldNotBeSeen(unittest.TestCase):
    def test_a_dark_collector_is_stated_not_implied(self) -> None:
        page = render_verdict_report(_verdict(
            coverage_complete=False,
            uncollected_categories=["known_malware_signature"],
            coverage={"static": {"collected": ["stripped_metadata"],
                                 "uncollected": ["known_malware_signature"],
                                 "complete": False}}))

        self.assertIn("A collector did not run", page)
        self.assertIn("known_malware_signature", page)
        self.assertIn("unknown", page)

    def test_every_module_appears_even_when_it_did_not_run(self) -> None:
        # Silence about a module reads as nothing to report.
        page = render_verdict_report(_verdict())

        for module in ("static", "dynamic", "spec", "api", "extension"):
            with self.subTest(module=module):
                self.assertIn(f">{module}<", page)
        self.assertIn("did not run", page)

    def test_a_case_with_no_detonation_says_what_that_costs(self) -> None:
        page = render_verdict_report(_verdict(
            modules_run=["static"],
            modules_absent=["dynamic", "spec", "api", "extension"]))

        self.assertIn("was not detonated", page)


class TheBandIsExplainedInWords(unittest.TestCase):
    def test_a_reader_need_not_know_the_vocabulary(self) -> None:
        page = render_verdict_report(_verdict())

        self.assertIn("independent kinds of evidence agree", page)

    def test_the_posture_domain_is_worded_for_a_service(self) -> None:
        page = render_verdict_report(_verdict(
            domain="posture", verdict="Serious Exposure",
            modules_run=["spec"], evidence=[]))

        self.assertIn("independent weaknesses", page)
        self.assertIn("whether this is exposed", page)


class TheFloorsAreDistinguished(unittest.TestCase):
    def test_third_party_dissent_says_it_was_not_local_evidence(self) -> None:
        page = render_verdict_report(_verdict(
            band="Single Observation", verdict="Needs Review", severity="Medium",
            evidence=[], dissent_floor_applied=True,
            dissent_floor_reason="60 engines disagree"))

        self.assertIn("not by local evidence", page)

    def test_virustotal_is_under_its_own_heading(self) -> None:
        page = render_verdict_report(
            _verdict(), third_party=["VirusTotal reports 60 malicious."])

        self.assertIn("Third party", page)
        self.assertIn("did not contribute to the verdict", page)

    def test_it_is_absent_when_there_is_nothing_to_say(self) -> None:
        page = render_verdict_report(_verdict())

        self.assertNotIn("Third party", page)


class ThePageIsSelfContained(unittest.TestCase):
    def test_it_carries_the_shared_stylesheet(self) -> None:
        # Not its own. Five stylesheets was the state Phase 4b ended.
        page = render_verdict_report(_verdict())

        self.assertIn("--sev-high-fg", page)
        self.assertEqual(page.count("<style>"), 1)

    def test_untrusted_text_is_escaped(self) -> None:
        page = render_verdict_report(
            _verdict(evidence=[{"name": "x", "module": "dynamic", "strong": False,
                                "detail": "", "reason": "<script>alert(1)</script>"}]),
            case_name="<img src=x onerror=alert(1)>")

        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main()
