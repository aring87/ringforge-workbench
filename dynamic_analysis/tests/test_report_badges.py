"""A badge's colour should mean something.

Section badges scaled purely by list length, which is only sensible when a
longer list is a worse result. Several sections are the opposite: "Clean
Baseline Checks" rendered amber at five *passing* checks, and "Windows Baseline
Traffic (context, not findings)" rendered amber while its own title said it was
not a finding.
"""

import re
import unittest

from dynamic_analysis.html_report import _list_section


def badge_class(html: str) -> str:
    match = re.search(r'badge (sev-\w+)', html)
    return match.group(1) if match else ""


class ContextSectionBadgeTests(unittest.TestCase):
    FIVE = ["a", "b", "c", "d", "e"]
    TWELVE = [str(n) for n in range(12)]

    def test_context_sections_stay_neutral_at_any_length(self) -> None:
        for items in ([], ["one"], self.FIVE, self.TWELVE):
            html = _list_section("Clean Baseline Checks", items, context=True)
            self.assertEqual(badge_class(html), "sev-none", f"{len(items)} items")

    def test_finding_sections_still_escalate(self) -> None:
        self.assertEqual(badge_class(_list_section("Contacted External IP Addresses", [])), "sev-none")
        self.assertEqual(badge_class(_list_section("Contacted External IP Addresses", ["1.2.3.4"])), "sev-low")
        self.assertEqual(badge_class(_list_section("Contacted External IP Addresses", self.FIVE)), "sev-med")
        self.assertEqual(badge_class(_list_section("Contacted External IP Addresses", self.TWELVE)), "sev-high")

    def test_count_is_still_shown_for_context_sections(self) -> None:
        # Neutral colour, not a hidden count -- the number is still useful.
        html = _list_section("Windows Baseline Traffic (context, not findings)", self.FIVE, context=True)
        self.assertIn("Count: 5", html)


if __name__ == "__main__":
    unittest.main()
