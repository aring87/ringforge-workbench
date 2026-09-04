"""The dynamic report's banner, and the fallback page that stands in for it.

**`Unknown` read as clean.** `_severity_class_for_score` was a second severity
mapper beside `report_theme.severity_class_for_label`, with its own vocabulary
-- and that vocabulary was missing `Unknown`, the band `verdict.model` writes
when nothing was collected or nothing could be weighed. It fell past every rung
to the score fallback, where a run that collected nothing scores 0 and comes
out `sev-none`: the chip a clean detonation gets.

Two verdicts were affected, "Insufficient Coverage" and "Findings Not Scored",
which are exactly the two that mean *do not read this as a result*. A third,
"Cancelled", was the same shape by a different route: the orchestrator writes
`severity: "Info"` when an analyst stops a run, and `Info` mapped to the clean
chip too.

The fallback report moved into `html_report` beside the report it replaces, so
what it is *not* producing is visible in the same file.
"""

import unittest

from dynamic_analysis.html_report import (
    _derive_report_verdict,
    _severity_class_for_score,
    build_fallback_dynamic_report,
)
from dynamic_analysis.report_theme import severity_class_for_label

#: What `band` can put in a dynamic run summary, with the severity beside it.
BANDED = (
    ("Likely Malicious", "High"),
    ("Elevated Attention", "High"),
    ("Needs Review", "Medium"),
    ("No Indicators Found", "Low"),
    ("Low Suspicion", "Low"),
    ("Benign / Clean Baseline", "Low"),
    ("No Findings, Coverage Incomplete", "Low"),
    ("Insufficient Coverage", "Unknown"),
    ("Findings Not Scored", "Unknown"),
)


class CoverageIsNotACleanResult(unittest.TestCase):
    """The defect the extraction surfaced."""

    def test_unknown_does_not_wear_the_clean_chip(self) -> None:
        self.assertEqual(_severity_class_for_score(0, "Unknown"), "sev-med")

    def test_both_unknown_verdicts_reach_the_banner_marked(self) -> None:
        for verdict in ("Insufficient Coverage", "Findings Not Scored"):
            with self.subTest(verdict=verdict):
                _, cls = _derive_report_verdict(
                    {"verdict": verdict, "severity": "Unknown", "score": 0})
                self.assertEqual(cls, "sev-med")

    def test_a_cancelled_run_is_not_a_clean_run(self) -> None:
        """`severity: "Info"` is what the orchestrator writes when the analyst
        stops a detonation. The sample was never fully watched."""
        label, cls = _derive_report_verdict(
            {"verdict": "Cancelled", "severity": "Info", "score": 0})

        self.assertIn("Cancelled", label)
        self.assertEqual(cls, "sev-med")

    def test_the_two_mappers_now_agree_on_every_band(self) -> None:
        """They diverged because there were two of them. This is the
        assertion that keeps there being one answer."""
        disagreed = [
            (verdict, severity) for verdict, severity in BANDED
            if _severity_class_for_score(0, severity)
            != severity_class_for_label(severity)]

        self.assertEqual([], disagreed, f"these disagree: {disagreed}")

    def test_an_unrecognised_severity_falls_to_the_score_not_to_clean(self) -> None:
        """A word neither mapper knows must not be painted as a clean result
        just because it was not understood."""
        self.assertEqual(_severity_class_for_score(200, "Elevated"), "sev-high")

    def test_the_words_this_report_alone_accepts_still_work(self) -> None:
        self.assertEqual(_severity_class_for_score(0, "moderate"), "sev-med")
        self.assertEqual(_severity_class_for_score(0, "benign"), "sev-none")
        self.assertEqual(_severity_class_for_score(0, "info"), "sev-none")


class TheBanner(unittest.TestCase):
    def test_the_severity_is_appended_when_it_adds_something(self) -> None:
        label, _ = _derive_report_verdict(
            {"verdict": "Needs Review", "severity": "Medium"})

        self.assertEqual(label, "Needs Review / Medium")

    def test_it_is_not_appended_when_it_only_repeats(self) -> None:
        label, _ = _derive_report_verdict(
            {"verdict": "High Suspicion", "severity": "High"})

        self.assertEqual(label, "High Suspicion")

    def test_a_summary_with_no_verdict_bands_on_the_score(self) -> None:
        for score, expected in ((80, "High Suspicion"), (30, "Needs Review"),
                                (10, "Low Suspicion"),
                                (0, "Benign / Clean Baseline")):
            with self.subTest(score=score):
                label, _ = _derive_report_verdict({"score": score})
                self.assertEqual(label, expected)

    def test_every_banded_verdict_reaches_the_banner(self) -> None:
        for verdict, severity in BANDED:
            with self.subTest(verdict=verdict):
                label, cls = _derive_report_verdict(
                    {"verdict": verdict, "severity": severity, "score": 0})
                self.assertIn(verdict, label)
                self.assertTrue(cls.startswith("sev-"))


class TheFallbackPage(unittest.TestCase):
    """It runs when the real generator fails, and must not look like it."""

    SUMMARY = {
        "sample": {"sample_name": "payload.exe", "sample_path": "C:/s/payload.exe",
                   "sha256": "abc123"},
        "findings": {"highlights": ["Wrote to a Run key"],
                     "counts": {"interesting_events": 4, "persistence_hits": 1}},
    }

    def test_it_announces_itself_in_the_title(self) -> None:
        html = build_fallback_dynamic_report(self.SUMMARY, "payload_case")

        self.assertIn("Dynamic Analysis Report (Fallback)", html)

    def test_it_says_an_empty_section_is_not_a_finding(self) -> None:
        html = build_fallback_dynamic_report(self.SUMMARY, "payload_case")

        self.assertIn("card-alert", html)
        self.assertIn("not rendered", html)
        self.assertIn("nothing found", html)

    def test_its_banner_word_is_not_a_band(self) -> None:
        """It never reached the scorer, so `Fallback` is a statement about the
        document rather than about the sample."""
        html = build_fallback_dynamic_report(self.SUMMARY, "payload_case")

        self.assertIn('<div class="verdict sev-med">Fallback</div>', html)

    def test_it_names_the_producing_module_in_the_footer(self) -> None:
        html = build_fallback_dynamic_report(self.SUMMARY, "payload_case")

        self.assertIn("fallback export", html)

    def test_the_counts_and_highlights_survive(self) -> None:
        html = build_fallback_dynamic_report(self.SUMMARY, "payload_case")

        self.assertIn("Wrote to a Run key", html)
        self.assertIn("<td>4</td>", html)
        self.assertIn("payload.exe", html)

    def test_a_summary_with_findings_at_the_top_level_still_renders(self) -> None:
        """Older summaries did not nest under `findings`."""
        html = build_fallback_dynamic_report(
            {"highlights": ["Top-level highlight"],
             "counts": {"process_creates": 3}}, "case")

        self.assertIn("Top-level highlight", html)
        self.assertIn("<td>3</td>", html)

    def test_an_empty_summary_renders_without_raising(self) -> None:
        html = build_fallback_dynamic_report({}, "")

        self.assertIn("Dynamic Analysis Report (Fallback)", html)
        self.assertIn("None were recorded in the summary.", html)

    def test_a_hostile_highlight_is_escaped(self) -> None:
        html = build_fallback_dynamic_report(
            {"highlights": ["<script>alert(1)</script>"]}, "case")

        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
