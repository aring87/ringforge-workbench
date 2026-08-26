"""Reported, not counted -- the honest middle state between built and calibrated.

The dynamic side reached this first and expressed it in prose: gap 4's detector
is "recorded context-only by decision rather than left awaiting calibration".
Written down, enforced by nobody. This is the same decision in code, and these
are the properties that make it honest rather than convenient.

**The failure it must not have is silence.** A module held here still observes
things, and a mechanism that quietly dropped those observations would be worse
than the over-counting it replaces -- at least the over-counting was visible.
"""

import unittest

from verdict import CONTEXT_ONLY, Category, band
from verdict.combine import combine

#: These exercise the *mechanism*, so they hold a module explicitly rather than
#: relying on whichever ones happen to be held today. `extension` was held when
#: this file was written and was released the same day, once a corpus of 394
#: store extensions replaced a sample of 14 -- a test that silently changed
#: meaning with that release would be testing the registry, not the mechanism.
HELD = {"extension": "held for this test"}


def _cat(name, module, present=False, strong=False, collected=True):
    return Category(name=name, module=module, collected=collected,
                    present=present, strong=strong,
                    reason=f"{name} observed" if present else "")


class TheHoldRemovesOnlyTheCounting(unittest.TestCase):
    def test_a_held_module_cannot_move_a_band(self) -> None:
        # Three present categories is Strongly Corroborated for any counted
        # module. Held, it reaches no band at all.
        counted = band([_cat(f"c{n}", "dynamic", present=True) for n in range(3)],
                       context_only={})
        held = band([_cat(f"c{n}", "extension", present=True) for n in range(3)],
                    context_only=HELD)

        self.assertEqual(counted.band, "Strongly Corroborated")
        self.assertEqual(held.categories_present, 0)

    def test_but_its_findings_are_still_reported(self) -> None:
        # The whole point. A held module that observed three things must not
        # look like a module that observed nothing.
        held = band([_cat(f"c{n}", "extension", present=True) for n in range(3)],
                    context_only=HELD)

        self.assertEqual(held.context_only_present, 3)
        self.assertEqual(held.context_only_names, ("c0", "c1", "c2"))
        self.assertIn("extension", held.modules_context_only)

    def test_it_still_appears_as_a_module_that_ran(self) -> None:
        held = band([_cat("c0", "extension", present=True)], context_only=HELD)

        self.assertIn("extension", held.modules_run)
        self.assertNotIn("extension", held.modules_absent)

    def test_its_coverage_is_still_reported(self) -> None:
        held = band([_cat("c0", "extension", collected=False)], context_only=HELD)

        self.assertFalse(held.coverage_complete)
        self.assertIn("c0", held.unknown_names)


class FindingsNothingCanWeigh(unittest.TestCase):
    """The case the mechanism would otherwise get wrong."""

    def test_a_held_module_alone_does_not_report_a_clean_verdict(self) -> None:
        # Banding on the counted categories alone gives No Evidence, which
        # reads as clean -- about a case where five things were observed and
        # simply could not be weighed.
        held = band([_cat(f"c{n}", "extension", present=True) for n in range(5)],
                    context_only=HELD)

        self.assertEqual(held.severity, "Unknown")
        self.assertEqual(held.verdict, "Findings Not Scored")

    def test_a_held_module_that_found_nothing_is_not_that_case(self) -> None:
        held = band([_cat("c0", "extension"), _cat("c1", "extension")],
                    context_only=HELD)

        self.assertNotEqual(held.verdict, "Findings Not Scored")

    def test_an_uncalibrated_module_cannot_veto_a_calibrated_one(self) -> None:
        # A clean, complete detonation alongside one uncounted extension
        # finding is still a clean detonation. A module that *does* meet the
        # standard looked and found nothing; downgrading that to Unknown would
        # let the held module overrule it.
        mixed = band([_cat("e0", "extension", present=True),
                      _cat("d0", "dynamic")], context_only=HELD)

        self.assertEqual(mixed.verdict, "Benign / Clean Baseline")
        self.assertEqual(mixed.context_only_present, 1)

    def test_a_real_finding_bands_normally_beside_held_ones(self) -> None:
        mixed = band([_cat("e0", "extension", present=True),
                      _cat("e1", "extension", present=True),
                      _cat("d0", "dynamic", present=True)], context_only=HELD)

        self.assertEqual(mixed.band, "Single Observation")
        self.assertEqual(mixed.categories_present, 1)
        self.assertEqual(mixed.context_only_present, 2)


class TheDecisionIsRecordedWithItsReason(unittest.TestCase):
    def test_every_held_module_says_why(self) -> None:
        # "Why does this not affect the verdict" is the first question a reader
        # has, and the answer is a decision somebody made rather than a property
        # of the artifact.
        for module, reason in CONTEXT_ONLY.items():
            with self.subTest(module=module):
                self.assertGreater(len(reason), 60)

    def test_only_the_unmeasured_module_is_held(self) -> None:
        # **The bar is measured, not quiet.** `spec` was considered for this
        # list on 26 Aug -- `unauthenticated_sensitive_endpoint` is present on
        # 32% of 300 APIs.guru specifications -- and deliberately stays out. A
        # rate that is known in the population is the condition for banding;
        # `api` is held because nothing has ever measured it, which is a
        # different thing from a rate somebody dislikes.
        self.assertEqual(set(CONTEXT_ONLY), {"api"})
        self.assertNotIn("spec", CONTEXT_ONLY)

    def test_the_held_modules_are_ones_that_exist(self) -> None:
        from verdict.model import MODULES

        self.assertFalse(set(CONTEXT_ONLY) - set(MODULES))

    def test_the_combiner_carries_the_reasons_through(self) -> None:
        result = combine({"api": ([_cat("c0", "api", present=True)], 0)})

        self.assertEqual(result["modules_context_only"], ["api"])
        self.assertEqual(result["context_only"]["present"], 1)
        self.assertIn("api", result["context_only"]["reasons"])

    def test_an_unheld_case_says_nothing_about_it(self) -> None:
        result = combine({"dynamic": ([_cat("c0", "dynamic", present=True)], 0)})

        self.assertEqual(result["modules_context_only"], [])
        self.assertEqual(result["context_only"]["present"], 0)


class TheHoldIsOverridable(unittest.TestCase):
    """Because it is a deployment decision, not a property of the categoriser.

    The tests that exercise what extension and api categories *say* pass
    `context_only={}`. If flipping the hold silently rewrote what those files
    assert, the hold would be hiding regressions rather than uncounted findings.
    """

    def test_passing_an_empty_map_counts_everything(self) -> None:
        cats = [_cat(f"c{n}", "extension", present=True) for n in range(3)]

        self.assertEqual(band(cats, context_only={}).band, "Strongly Corroborated")
        self.assertEqual(band(cats, context_only=HELD).categories_present, 0)

    def test_a_caller_can_hold_a_module_that_is_not_held_by_default(self) -> None:
        cats = [_cat(f"c{n}", "dynamic", present=True) for n in range(3)]

        self.assertEqual(band(cats, context_only={"dynamic": "for this test"})
                         .categories_present, 0)


if __name__ == "__main__":
    unittest.main()
