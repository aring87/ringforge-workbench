"""Pooling every module into one verdict -- `corroboration-v1`.

Phase 4a of `docs/SCORING.md`. What this replaces summed a 0-40 static score, a
0-30 dynamic score and a spec score, clamped to 100, and banded the total with
thresholds derived for the 0-40 scale -- so `MALICIOUS` fired at 30 of 100 while
the VirusTotal branches in the same function tested 50 and 75.

The contract these encode:

    categories pool across modules; scores never add
    a module that did not run is absent, not silent
    serialised categories rebuild with their invariants intact
    VirusTotal can floor a clean verdict and can reach no higher
"""

import unittest

from verdict import Category
from verdict.combine import categories_from_json, combine


def _cat(name, module, present=False, strong=False, collected=True):
    return Category(
        name=name, module=module, collected=collected, present=present,
        strong=strong, detail=f"{name} detail",
        reason=f"{name} was observed" if present else "",
    )


class CategoriesPoolAndScoresDoNot(unittest.TestCase):
    def test_one_category_from_each_of_two_modules_corroborates(self) -> None:
        # The single thing the old combiner could not do. A static packer
        # signature and a dynamic injection are two independent kinds of
        # evidence agreeing, and only the union can see that.
        result = combine({
            "static": ([_cat("known_malware_signature", "static", present=True)], 0),
            "dynamic": ([_cat("process_injection", "dynamic", present=True)], 0),
        })

        self.assertEqual(result["counts"]["categories_present"], 2)
        self.assertEqual(result["verdict"], "Elevated Attention")

    def test_three_across_three_modules_is_likely_malicious(self) -> None:
        result = combine({
            "static": ([_cat("known_malware_signature", "static", present=True)], 0),
            "dynamic": ([_cat("process_injection", "dynamic", present=True)], 0),
            "spec": ([_cat("plaintext_transport", "spec", present=True)], 0),
        })

        self.assertEqual(result["verdict"], "Likely Malicious")

    def test_per_module_scores_are_reported_and_never_banded_on(self) -> None:
        # Volume is capped, and the cap applies to the pooled total rather than
        # per module -- three noisy modules cannot add up to a band.
        result = combine({
            "static": ([_cat("stripped_metadata", "static")], 40),
            "dynamic": ([_cat("process_injection", "dynamic")], 40),
            "spec": ([_cat("plaintext_transport", "spec")], 40),
        })

        self.assertEqual(result["subscores"], {"static": 40, "dynamic": 40, "spec": 40})
        self.assertEqual(result["context_score"], 15)
        self.assertEqual(result["severity"], "Low")

    def test_evidence_is_ordered_with_the_emphatic_first(self) -> None:
        result = combine({
            "static": ([_cat("stripped_metadata", "static", present=True)], 0),
            "dynamic": ([_cat("packed_payload", "dynamic", present=True, strong=True)], 0),
        })

        self.assertEqual(result["evidence"][0]["name"], "packed_payload")

    def test_absent_categories_are_not_in_the_evidence_list(self) -> None:
        result = combine({
            "static": ([_cat("stripped_metadata", "static", present=True),
                        _cat("invalid_signature", "static")], 0),
        })

        self.assertEqual([e["name"] for e in result["evidence"]],
                         ["stripped_metadata"])


class AModuleThatDidNotRunIsAbsent(unittest.TestCase):
    def test_static_only_does_not_claim_a_clean_baseline(self) -> None:
        result = combine({"static": ([_cat("stripped_metadata", "static")], 0)})

        self.assertEqual(result["verdict"], "No Indicators Found")
        self.assertIn("dynamic", result["modules_absent"])

    def test_a_detonated_case_may_claim_one(self) -> None:
        result = combine({
            "static": ([_cat("stripped_metadata", "static")], 0),
            "dynamic": ([_cat("process_injection", "dynamic")], 0),
        })

        self.assertEqual(result["verdict"], "Benign / Clean Baseline")

    def test_coverage_is_reported_per_module(self) -> None:
        result = combine({
            "static": ([_cat("known_malware_signature", "static", collected=False),
                        _cat("stripped_metadata", "static")], 0),
            "dynamic": ([_cat("process_injection", "dynamic")], 0),
        })

        self.assertFalse(result["coverage"]["static"]["complete"])
        self.assertTrue(result["coverage"]["dynamic"]["complete"])
        self.assertEqual(result["uncollected_categories"], ["known_malware_signature"])

    def test_a_dark_collector_anywhere_costs_the_clean_headline(self) -> None:
        result = combine({
            "static": ([_cat("known_malware_signature", "static", collected=False)], 0),
            "dynamic": ([_cat("process_injection", "dynamic")], 0),
        })

        self.assertEqual(result["verdict"], "No Findings, Coverage Incomplete")


class SerialisedCategoriesRebuild(unittest.TestCase):
    """A detonation happens in another process; its categories arrive as JSON."""

    def test_a_round_trip_preserves_the_claim(self) -> None:
        rebuilt = categories_from_json([{
            "name": "packed_payload", "module": "dynamic", "collected": True,
            "present": True, "strong": True, "detail": "5 rules",
            "reason": "YARA matched memory but not disk",
        }])

        self.assertEqual(len(rebuilt), 1)
        self.assertTrue(rebuilt[0].strong)

    def test_the_invariants_still_apply_on_the_way_back_in(self) -> None:
        # A summary claiming a category is present with no reason would produce
        # a verdict nobody can explain. It is dropped, not trusted.
        rebuilt = categories_from_json([{
            "name": "packed_payload", "module": "dynamic",
            "present": True, "reason": "",
        }])

        self.assertEqual(rebuilt, [])

    def test_one_unreadable_row_does_not_make_a_case_unreadable(self) -> None:
        # A summary written months ago should not fail to load because of one
        # bad entry. What is dropped shows up as missing coverage instead.
        rebuilt = categories_from_json([
            {"name": "packed_payload", "module": "dynamic"},
            "not a dict",
            {"name": "NOT AN IDENTIFIER", "module": "dynamic"},
            {"name": "external_contact", "module": "dynamic"},
        ])

        self.assertEqual([c.name for c in rebuilt],
                         ["packed_payload", "external_contact"])

    def test_nothing_at_all_rebuilds_to_nothing(self) -> None:
        self.assertEqual(categories_from_json(None), [])


class TheDissentFloor(unittest.TestCase):
    def test_it_floors_a_clean_verdict(self) -> None:
        result = combine(
            {"static": ([_cat("stripped_metadata", "static")], 0),
             "dynamic": ([_cat("process_injection", "dynamic")], 0)},
            third_party_dissent=True,
            dissent_detail="60 of 70 engines disagree")

        self.assertEqual(result["verdict"], "Needs Review")
        self.assertTrue(result["dissent_floor_applied"])
        self.assertIn("60 of 70", result["dissent_floor_reason"])

    def test_it_cannot_reach_the_high_bands(self) -> None:
        result = combine({"static": ([_cat("stripped_metadata", "static")], 0)},
                         third_party_dissent=True)

        self.assertEqual(result["severity"], "Medium")

    def test_it_leaves_a_higher_band_alone(self) -> None:
        result = combine(
            {"static": ([_cat("known_malware_signature", "static", present=True)], 0),
             "dynamic": ([_cat("process_injection", "dynamic", present=True)], 0)},
            third_party_dissent=True)

        self.assertEqual(result["verdict"], "Elevated Attention")
        self.assertFalse(result["dissent_floor_applied"])

    def test_the_reason_is_empty_when_the_floor_did_not_fire(self) -> None:
        result = combine({"static": ([_cat("stripped_metadata", "static")], 0)},
                         third_party_dissent=False, dissent_detail="unused")

        self.assertEqual(result["dissent_floor_reason"], "")


class TheOutputIsSelfDescribing(unittest.TestCase):
    def test_it_names_the_model(self) -> None:
        result = combine({"static": ([_cat("stripped_metadata", "static")], 0)})

        self.assertEqual(result["score_model"], "corroboration-v1")

    def test_nothing_at_all_is_insufficient_coverage(self) -> None:
        result = combine({})

        self.assertEqual(result["severity"], "Low")
        self.assertEqual(result["modules_run"], [])


if __name__ == "__main__":
    unittest.main()
