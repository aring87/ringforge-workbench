"""The contract, and the failures it exists to prevent.

Phase 0 of `docs/SCORING.md`. Nothing consumes `verdict/` yet, so every
assertion here is about the model rather than about any sample -- which is the
point: this is the last cheap moment to find out the design is wrong.

The bands are carried over unchanged from `dynamic-corroboration-v3`, and
`dynamic_analysis/tests/test_score_discrimination.py` is the test that pins
them against real runs. If Phase 1 has to edit that file, the model changed and
that is a finding, not a chore.
"""

import unittest

from verdict import Category, CategoryError, band, coverage


def _cat(name, module="static", **kw):
    """A present category needs a reason, so supply one by default."""
    kw.setdefault("present", False)
    if kw["present"]:
        kw.setdefault("reason", f"{name} was observed")
    return Category(name=name, module=module, **kw)


class TheCategoryContract(unittest.TestCase):
    def test_a_name_that_is_not_an_identifier_is_refused(self) -> None:
        # Names outlive the code that emits them: they go into
        # combined_score.json and get compared across cases.
        with self.assertRaises(CategoryError):
            Category(name="Packed Payload", module="static")

    def test_an_unknown_module_is_refused(self) -> None:
        # A typo would drop the category out of coverage reporting while it
        # still counted toward the verdict.
        with self.assertRaises(CategoryError):
            Category(name="packed_payload", module="statik")

    def test_present_without_collected_is_refused(self) -> None:
        # A collector that did not run cannot have observed anything.
        with self.assertRaises(CategoryError) as caught:
            Category(name="packed_payload", module="static",
                     collected=False, present=True, reason="x")
        self.assertIn("did not run", str(caught.exception))

    def test_strong_without_present_is_refused(self) -> None:
        with self.assertRaises(CategoryError):
            Category(name="packed_payload", module="static", strong=True)

    def test_present_without_a_reason_is_refused(self) -> None:
        # The reason is the rationale the report prints. Categories nobody can
        # explain are the additive model with extra steps.
        with self.assertRaises(CategoryError) as caught:
            Category(name="packed_payload", module="static", present=True)
        self.assertIn("reason", str(caught.exception))

    def test_a_collector_that_ran_and_found_nothing_is_valid(self) -> None:
        # The ordinary case, and the one that makes absence mean something.
        Category(name="packed_payload", module="static",
                 collected=True, present=False)


class ACategoryFiresOnce(unittest.TestCase):
    """The whole defence against a volume-driven model."""

    def test_the_same_category_twice_is_an_error_not_a_sum(self) -> None:
        # Emitting stripped_metadata once per missing version-info field is the
        # additive model reappearing under a new name. Raising rather than
        # collapsing keeps the bug that produced it visible.
        cats = [_cat("stripped_metadata", present=True),
                _cat("stripped_metadata", present=True)]

        with self.assertRaises(CategoryError) as caught:
            band(cats)
        self.assertIn("twice", str(caught.exception))

    def test_the_same_name_from_two_modules_is_fine(self) -> None:
        # Static and dynamic can both claim network indicators; they are
        # different observations by different means, which is corroboration.
        result = band([_cat("network_indicators", "static", present=True),
                       _cat("network_indicators", "dynamic", present=True)])

        self.assertEqual(result.categories_present, 2)


class TheBands(unittest.TestCase):
    """Carried over unchanged. The single-category floor is load-bearing."""

    def test_nothing_present_after_a_detonation_is_a_clean_baseline(self) -> None:
        result = band([_cat("process_injection", "dynamic")])

        self.assertEqual(result.severity, "Low")
        self.assertEqual(result.verdict, "Benign / Clean Baseline")

    def test_one_weak_category_stays_at_needs_review(self) -> None:
        # This is where the benign memory canary lands, and moving it would
        # cost that control its meaning.
        result = band([_cat("packed_payload", "dynamic", present=True)])

        self.assertEqual(result.severity, "Medium")
        self.assertEqual(result.verdict, "Needs Review")
        self.assertTrue(result.severity_floor_applied)

    def test_one_strong_category_reaches_elevated_attention(self) -> None:
        result = band([_cat("packed_payload", "dynamic",
                            present=True, strong=True)])

        self.assertEqual(result.verdict, "Elevated Attention")

    def test_two_weak_categories_reach_elevated_attention(self) -> None:
        result = band([_cat("packed_payload", "dynamic", present=True),
                       _cat("persistence", "dynamic", present=True)])

        self.assertEqual(result.verdict, "Elevated Attention")

    def test_three_categories_is_likely_malicious(self) -> None:
        result = band([_cat("packed_payload", "dynamic", present=True),
                       _cat("persistence", "dynamic", present=True),
                       _cat("c2_contact", "dynamic", present=True)])

        self.assertEqual(result.severity, "High")
        self.assertEqual(result.verdict, "Likely Malicious")

    def test_two_strong_categories_is_likely_malicious(self) -> None:
        result = band([_cat("packed_payload", "dynamic",
                            present=True, strong=True),
                       _cat("c2_contact", "dynamic",
                            present=True, strong=True)])

        self.assertEqual(result.verdict, "Likely Malicious")

    def test_corroboration_is_counted_across_modules(self) -> None:
        # The reason categories pool rather than being scored per module: a
        # static packer signature and a dynamic injection are two independent
        # kinds of evidence agreeing, and only the union can see that.
        result = band([_cat("known_malware_signature", "static", present=True),
                       _cat("process_injection", "dynamic", present=True)])

        self.assertEqual(result.verdict, "Elevated Attention")
        self.assertEqual(result.modules_run, ("dynamic", "static"))


class VolumeCannotMoveABand(unittest.TestCase):
    def test_context_score_is_capped(self) -> None:
        result = band([_cat("packed_payload", "dynamic")], context_score=9999)

        self.assertEqual(result.context_score, 15)

    def test_a_large_context_score_never_reaches_medium(self) -> None:
        # The old model banded on the total and moved nine points between two
        # runs of the same control, purely from background noise.
        result = band([_cat("packed_payload", "dynamic")], context_score=9999)

        self.assertEqual(result.severity, "Low")


class WhatWasNotCollected(unittest.TestCase):
    def test_an_uncollected_category_is_unknown_not_absent(self) -> None:
        result = band([_cat("known_malware_signature", "static",
                            collected=False),
                       _cat("dangerous_capability", "static")])

        self.assertEqual(result.categories_unknown, 1)
        self.assertFalse(result.coverage_complete)
        self.assertIn("known_malware_signature", result.unknown_names)

    def test_nothing_collected_at_all_is_not_a_clean_verdict(self) -> None:
        # Every collector failing would otherwise produce the cleanest verdict
        # the model can express.
        result = band([_cat("known_malware_signature", "static", collected=False),
                       _cat("dangerous_capability", "static", collected=False)])

        self.assertEqual(result.severity, "Unknown")
        self.assertEqual(result.verdict, "Insufficient Coverage")

    def test_coverage_reports_per_module(self) -> None:
        cover = coverage([_cat("known_malware_signature", "static", collected=False),
                          _cat("dangerous_capability", "static"),
                          _cat("process_injection", "dynamic")])

        self.assertEqual(cover["static"]["uncollected"], ["known_malware_signature"])
        self.assertFalse(cover["static"]["complete"])
        self.assertTrue(cover["dynamic"]["complete"])


class WhichModulesRan(unittest.TestCase):
    """Module-never-ran and collector-failed are different facts."""

    def test_static_only_does_not_claim_a_clean_baseline(self) -> None:
        # "Clean Baseline" is a claim about having watched it run. Static can
        # say nothing was found; it cannot say nothing happens.
        result = band([_cat("known_malware_signature", "static"),
                       _cat("dangerous_capability", "static")])

        self.assertEqual(result.severity, "Low")
        self.assertEqual(result.verdict, "No Indicators Found")
        self.assertIn("dynamic", result.modules_absent)

    def test_a_detonated_sample_may_claim_one(self) -> None:
        result = band([_cat("known_malware_signature", "static"),
                       _cat("process_injection", "dynamic")])

        self.assertEqual(result.verdict, "Benign / Clean Baseline")
        self.assertEqual(result.modules_absent, ("spec", "api", "extension"))


class TheDissentFloor(unittest.TestCase):
    """VirusTotal is not a category, and it is not ignored either."""

    def test_strong_dissent_floors_a_clean_verdict_at_needs_review(self) -> None:
        result = band([_cat("known_malware_signature", "static"),
                       _cat("process_injection", "dynamic")],
                      third_party_dissent=True)

        self.assertEqual(result.severity, "Medium")
        self.assertEqual(result.verdict, "Needs Review")
        self.assertTrue(result.dissent_floor_applied)

    def test_dissent_cannot_reach_the_high_bands(self) -> None:
        # There is no path from somebody else's conclusion about the same file
        # to Elevated Attention or Likely Malicious.
        result = band([_cat("packed_payload", "dynamic")],
                      third_party_dissent=True)

        self.assertEqual(result.severity, "Medium")

    def test_dissent_does_not_change_an_already_higher_band(self) -> None:
        result = band([_cat("packed_payload", "dynamic", present=True),
                       _cat("c2_contact", "dynamic", present=True)],
                      third_party_dissent=True)

        self.assertEqual(result.verdict, "Elevated Attention")
        self.assertFalse(result.dissent_floor_applied)

    def test_dissent_adds_no_points(self) -> None:
        without = band([_cat("packed_payload", "dynamic")])
        with_dissent = band([_cat("packed_payload", "dynamic")],
                            third_party_dissent=True)

        self.assertEqual(with_dissent.score, without.score)

    def test_dissent_lifts_insufficient_coverage_too(self) -> None:
        # Collectors all failed and someone else found something. That is the
        # clearest possible case of a bench defect, and it must not read as a
        # coverage note nobody follows up.
        result = band([_cat("known_malware_signature", "static", collected=False)],
                      third_party_dissent=True)

        self.assertEqual(result.verdict, "Needs Review")
        self.assertTrue(result.dissent_floor_applied)
        self.assertFalse(result.coverage_complete)


class TheOutputIsSelfDescribing(unittest.TestCase):
    def test_it_carries_the_model_version(self) -> None:
        # Output from before this model carries neither this nor total_score,
        # and that absence is how a reader recognises it.
        result = band([_cat("packed_payload", "dynamic")])

        self.assertEqual(result.to_dict()["score_model"], "corroboration-v1")


if __name__ == "__main__":
    unittest.main()
