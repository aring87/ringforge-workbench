"""Two hollowing detectors that existed but said nothing out loud.

Module integrity was JSON-only through its first live finding, which had to be
read out of `memory\\module_integrity.json` by hand -- an image at `0x400000`
claiming to be RegSvcs and demonstrably not being it. A detector nobody reads is
most of the way to not existing, so these assert the sections *render* and that
they distinguish "nothing was wrong" from "nothing could be checked".

That distinction is the one this pipeline has got wrong most often. A section
that renders identically for a clean run and an uncollected one is the
`collection_available` bug with a stylesheet.
"""
import unittest

from dynamic_analysis.html_report import (
    _image_timestamp_section,
    _module_integrity_section,
)

MISMATCH = {
    "process": "RegSvcs.exe", "pid": 12080,
    "recorded": "0x5ff2b99b", "on_disk": "0x68531ee1",
    "hollowing_target": True, "path": r"C:\Windows\RegSvcs.exe",
    "verdict": "mismatch",
}


def _stamps(available=True, mismatches=(), checked=1, comparable=1,
            no_reference=0, unnamed=()):
    return {"crash_summary": {"image_timestamps": {
        "available": available,
        "counts": {
            "checked": checked, "comparable": comparable,
            "mismatch": len(mismatches),
            "mismatch_in_hollowing_target":
                sum(1 for m in mismatches if m.get("hollowing_target")),
            "no_reference": no_reference, "unparsable": 0,
        },
        "mismatches": list(mismatches),
        "no_reference_processes": list(unnamed),
    }}}


class ImageTimestampSection(unittest.TestCase):
    def test_silent_when_no_crash_recorded_a_stamp(self):
        self.assertEqual(_image_timestamp_section(_stamps(checked=0)), "")
        self.assertEqual(_image_timestamp_section({}), "")

    def test_mismatch_renders_and_names_both_stamps(self):
        html = _image_timestamp_section(_stamps(mismatches=[MISMATCH]))
        self.assertIn("RegSvcs.exe", html)
        self.assertIn("0x5ff2b99b", html)
        self.assertIn("0x68531ee1", html)
        self.assertIn("card-alert", html)

    def test_clean_run_renders_but_is_not_an_alert(self):
        html = _image_timestamp_section(_stamps(mismatches=[]))
        self.assertNotIn("card-alert", html)
        self.assertIn("ran the image it was started from", html)

    def test_uncollected_is_not_the_same_as_clean(self):
        # The whole point. Off-guest every comparison is impossible, and that
        # must not render as "everything matched".
        clean = _image_timestamp_section(_stamps(mismatches=[]))
        uncollected = _image_timestamp_section(
            _stamps(available=False, comparable=0, no_reference=1,
                    unnamed=["RegSvcs.exe"]))
        self.assertNotEqual(clean, uncollected)
        self.assertIn("Not Compared", uncollected)
        self.assertIn("not</b> about the sample", uncollected)
        self.assertIn("RegSvcs.exe", uncollected)

    def test_no_reference_count_is_shown_alongside_findings(self):
        html = _image_timestamp_section(
            _stamps(mismatches=[MISMATCH], no_reference=3))
        self.assertIn("3 further crash(es)", html)
        self.assertIn("not agreement", html)


def _integrity(available=True, replaced=(), mismatched=(), no_reference=0,
               unnamed=(), compared=30):
    return {"module_integrity_summary": {
        "available": available,
        "counts": {"identical": compared, "patched": 0,
                   "replaced": len(replaced),
                   "header_mismatch": len(mismatched),
                   "no_reference": no_reference},
        "modules_compared": compared,
        "replaced": list(replaced),
        "header_mismatch": list(mismatched),
        "no_reference_modules": list(unnamed),
    }}


HEADER_MISMATCH = {
    "name": "regsvcs.exe", "base": "0x400000", "verdict": "header_mismatch",
    "differing_fraction": "99.10%", "hollowing_target": True,
    "dump": "RegSvcs.exe_12080_t58.dmp",
}


class ModuleIntegritySection(unittest.TestCase):
    def test_silent_when_the_pass_never_ran(self):
        self.assertEqual(_module_integrity_section({}), "")

    def test_the_real_finding_renders(self):
        html = _module_integrity_section(_integrity(mismatched=[HEADER_MISMATCH]))
        self.assertIn("regsvcs.exe", html)
        self.assertIn("0x400000", html)
        self.assertIn("header_mismatch", html)
        self.assertIn("card-alert", html)

    def test_header_mismatch_is_explained_as_identity_not_degree(self):
        html = _module_integrity_section(_integrity(mismatched=[HEADER_MISMATCH]))
        self.assertIn("by identity and never by degree", html)

    def test_uncollected_is_not_the_same_as_clean(self):
        clean = _module_integrity_section(_integrity())
        uncollected = _module_integrity_section(
            _integrity(available=False, compared=0, no_reference=11,
                       unnamed=[{"name": "regsvcs.exe"}]))
        self.assertNotEqual(clean, uncollected)
        self.assertIn("Not Compared", uncollected)
        self.assertIn("could\n        not tell", uncollected.replace("\r", ""))
        self.assertIn("regsvcs.exe", uncollected)

    def test_no_reference_named_not_only_counted(self):
        html = _module_integrity_section(
            _integrity(mismatched=[HEADER_MISMATCH], no_reference=7))
        self.assertIn("7 module(s)", html)
        self.assertIn("never skipped silently", html)


class WiredIntoThePage(unittest.TestCase):
    """A section function that is never called is indistinguishable from one
    that returns "". Both tests above would still pass; the report would be
    empty. So assert the whole page, not just the fragment."""

    def test_both_sections_reach_the_rendered_report(self):
        from dynamic_analysis.html_report import build_dynamic_html_report

        summary = {}
        summary.update(_stamps(mismatches=[MISMATCH]))
        summary.update(_integrity(mismatched=[HEADER_MISMATCH], compared=10))
        html = build_dynamic_html_report(summary)

        self.assertIn("Running Image vs File On Disk", html)
        self.assertIn("Loaded Modules vs Their Files On Disk", html)
        self.assertIn("0x5ff2b99b", html)
        self.assertIn("0x68531ee1", html)

    def test_an_empty_run_does_not_grow_two_empty_cards(self):
        from dynamic_analysis.html_report import build_dynamic_html_report

        html = build_dynamic_html_report({})
        self.assertNotIn("Running Image vs File On Disk", html)
        self.assertNotIn("Loaded Modules vs Their Files On Disk", html)


if __name__ == "__main__":
    unittest.main()
