"""The Browser Extension report, which could not be tested until it moved.

It lived inline in `gui/extension_window.py` as `_build_html_report`, so
exercising it needed a display and nobody did. Same shape, same outcome as the
other two: a scoring path with no test, and a defect living in it.

**The defect these pin.** The report coloured its verdict chip by uppercasing
`risk_verdict` and matching `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` -- the
additive vocabulary the extension module stopped emitting at `v1.11.0`. Every
sentence `corroboration-v1` writes missed every rung, so every exported
extension report showed its verdict in the grey chip that also means "No
Results". The chip is driven by the model's own `severity` now, and the wording
is consulted only for case folders written before that field was carried.
"""

import unittest

from dynamic_analysis.report_theme import severity_class_for_label
from static_triage_engine.extension_analysis import analyze_extension
from static_triage_engine.extension_report import (
    build_extension_report,
    verdict_class_for,
)

#: Every sentence `verdict.model` can write for this domain. The extension
#: module is in neither `MALWARE_MODULES` nor `POSTURE_MODULES`, so it takes
#: the malware wording by the fallback in `band`.
DOMAIN_VERDICTS = (
    "Insufficient Coverage",
    "No Indicators Found",
    "Needs Review",
    "Elevated Attention",
    "Likely Malicious",
    "Findings Not Scored",
    "No Findings, Coverage Incomplete",
    "Low Suspicion",
)


def _data(**summary_over):
    summary = {
        "name": "Test Extension", "version": "1.0", "description": "-",
        "manifest_version": "3", "permissions": "tabs, storage",
        "host_permissions": "<all_urls>", "background": "service_worker",
        "content_scripts": "1", "web_resources": "-",
        "externally_connectable": "Not set", "update_url": "-",
        "commands": "-", "csp": "-",
        "risk_score": "12", "risk_verdict": "Elevated Attention",
        "risk_severity": "High", "files_found": "3",
    }
    summary.update(summary_over)
    return {
        "source_path": "C:/cases/ext", "working_directory": "C:/tmp/ext",
        "manifest_path": "C:/tmp/ext/manifest.json",
        "summary": summary,
        "risk_notes": ["Requests <all_urls> host access."],
        "file_inventory": ["manifest.json", "background.js"],
        "manifest": {"manifest_version": 3, "name": "Test Extension"},
    }


class TheVerdictChip(unittest.TestCase):
    """The defect the extraction was for."""

    def test_no_domain_verdict_renders_grey(self) -> None:
        """The whole bug in one assertion.

        Before this moved, all eight of these produced `sev-none` -- the same
        chip as "No Results" -- because the report was matching a vocabulary
        nothing writes any more.
        """
        grey = [v for v in DOMAIN_VERDICTS
                if verdict_class_for({"risk_verdict": v,
                                      "risk_severity": "High"}) == "sev-none"]

        self.assertEqual([], grey)

    def test_the_chip_follows_the_severity_not_the_sentence(self) -> None:
        """Two cases with the same sentence and different bands differ."""
        high = verdict_class_for({"risk_verdict": "Needs Review",
                                  "risk_severity": "High"})
        low = verdict_class_for({"risk_verdict": "Needs Review",
                                 "risk_severity": "Low"})

        self.assertEqual("sev-high", high)
        self.assertEqual("sev-low", low)

    def test_every_severity_the_model_emits_has_a_class(self) -> None:
        for severity, expected in (("High", "sev-high"), ("Medium", "sev-med"),
                                   ("Low", "sev-low"), ("Unknown", "sev-med")):
            with self.subTest(severity=severity):
                self.assertEqual(
                    expected, verdict_class_for({"risk_severity": severity}))

    def test_an_older_case_folder_still_colours(self) -> None:
        """`risk_severity` is new. A folder written before it must not go grey.

        The wording is the only thing those exports carry, and
        `severity_class_for_label` knows the corroboration vocabulary for
        exactly this reason.
        """
        for wording, expected in (("Likely Malicious", "sev-high"),
                                  ("Elevated Attention", "sev-high"),
                                  ("Needs Review", "sev-med"),
                                  ("Insufficient Coverage", "sev-med"),
                                  ("Findings Not Scored", "sev-med"),
                                  ("Low Suspicion", "sev-low")):
            with self.subTest(wording=wording):
                self.assertEqual(
                    expected, verdict_class_for({"risk_verdict": wording}))

    def test_an_empty_severity_does_not_mask_the_wording(self) -> None:
        """The field exists and is blank when nothing has been analysed yet."""
        self.assertEqual(
            "sev-high",
            verdict_class_for({"risk_severity": "",
                               "risk_verdict": "Likely Malicious"}))

    def test_findings_not_scored_is_not_the_clean_chip(self) -> None:
        """Observations were made and could not be weighed. Grey reads clean."""
        self.assertEqual("sev-med",
                         severity_class_for_label("Findings Not Scored"))


class ThePage(unittest.TestCase):
    """It renders through the shared shell, and says what it is."""

    def test_it_uses_the_one_page_builder(self) -> None:
        html = build_extension_report(_data())

        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn('<div class="banner">', html)
        self.assertIn("Browser Extension Analysis Report", html)
        self.assertIn("RingForge Workbench &bull; Browser Extension Analysis",
                      html)
        self.assertIn("Generated:", html)

    def test_the_banner_verdict_carries_the_band(self) -> None:
        html = build_extension_report(_data(risk_severity="High"))

        self.assertIn('<div class="verdict sev-high">Elevated Attention</div>',
                      html)

    def test_risk_notes_raise_the_alert_card(self) -> None:
        self.assertIn('<section class="card card-alert">',
                      build_extension_report(_data()))

    def test_no_risk_notes_leaves_the_alert_card_off(self) -> None:
        data = _data()
        data["risk_notes"] = []

        html = build_extension_report(data)

        self.assertNotIn('<section class="card card-alert">', html)
        self.assertIn("<p class='muted'>None</p>", html)

    def test_the_manifest_is_escaped_not_executed(self) -> None:
        data = _data()
        data["manifest"] = {"name": "<script>alert(1)</script>"}

        html = build_extension_report(data)

        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_a_hostile_extension_name_cannot_break_the_table(self) -> None:
        html = build_extension_report(_data(name="</td><td>injected"))

        self.assertNotIn("</td><td>injected", html)
        self.assertIn("&lt;/td&gt;", html)

    def test_it_renders_an_empty_case_without_raising(self) -> None:
        """`_save_latest_to_case` runs before anything is selected."""
        html = build_extension_report({})

        self.assertIn("Browser Extension Analysis Report", html)
        self.assertIn("Entries: 0", html)

    def test_the_counts_are_the_lists_lengths(self) -> None:
        html = build_extension_report(_data())

        self.assertIn("Count: 2", html)   # file inventory
        self.assertIn("Count: 1", html)   # risk notes
        self.assertIn("Entries: 2", html)  # manifest keys


class AgainstTheRealAnalysis(unittest.TestCase):
    """The report's inputs, taken from the analysis rather than invented.

    A fixture can agree with a report and disagree with the engine. This walks
    `analyze_extension` -> the export shape -> the page.
    """

    def _render(self, manifest):
        result = analyze_extension(None, manifest)
        data = _data(risk_verdict=result["verdict"],
                     risk_severity=str(result["severity"]),
                     risk_score=str(result["score"]))
        return result, build_extension_report(data)

    def test_a_high_risk_manifest_reaches_the_page_coloured(self) -> None:
        result, html = self._render({
            "manifest_version": 3,
            "name": "Grabber",
            "permissions": ["tabs", "cookies", "webRequest", "debugger",
                            "nativeMessaging", "downloads"],
            "host_permissions": ["<all_urls>"],
            "update_url": "https://cdn.example.test/updates.xml",
            "content_scripts": [{"matches": ["<all_urls>"], "js": ["c.js"]}],
        })

        self.assertNotEqual("sev-none",
                            verdict_class_for({"risk_severity": result["severity"]}))
        self.assertIn(f'<div class="verdict', html)
        self.assertIn(result["verdict"], html)
        self.assertNotIn('<div class="verdict sev-none">', html)

    def test_a_bare_manifest_is_not_dressed_up(self) -> None:
        result, html = self._render({"manifest_version": 3, "name": "Plain"})

        self.assertIn(result["verdict"], html)
        self.assertNotIn("sev-high", html.split("<style>")[0]
                         + html.split("</style>")[-1])


if __name__ == "__main__":
    unittest.main()
