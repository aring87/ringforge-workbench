"""A disabled collector must not read as a clean result.

Phase 1 of `docs/SCORING.md`. The bands themselves are pinned by
`test_score_discrimination.py`, which passed unchanged through the lift onto
`verdict/` and is left alone deliberately -- it is the record that the model
did not drift. What is new here is coverage: the difference between *we looked
and found nothing* and *we never looked*.

This is the project's oldest recurring mistake in a new place. A run with
Sysmon switched off produces exactly the silence of a run where Sysmon watched
and saw nothing, and every previous version of this scorer reported them
identically.
"""

import unittest

from dynamic_analysis.orchestrator import (
    CATEGORY_SOURCES,
    _evidence_categories,
    calculate_dynamic_score,
)


def _score(**kwargs):
    """The scorer with everything empty except what a test sets."""
    base = dict(
        findings_summary={"counts": {}},
        task_diff_summary={"counts": {}},
        service_diff_summary={"counts": {}},
        dropped_files_summary={},
        autoruns_diff_summary={"counts": {}},
        sysmon_summary={},
        network_summary={},
        fakenet_summary={},
        memory_yara_summary={},
        powershell_summary={},
        crash_summary={},
        pe_carve_summary={},
    )
    base.update(kwargs)
    return calculate_dynamic_score(**base)


def _all_category_names():
    """Every category the scorer can emit, present or not."""
    return {
        c["name"]
        for c in _evidence_categories(
            memory_only_rules=[],
            sysmon_injections=0,
            unmapped_memory_crashes=0,
            hollowing_target_crashes=0,
            unmapped_pe_images=0,
            unmapped_pe_in_hollowing_target=0,
            sysmon_high=0,
            suspicious_tasks=0,
            suspicious_services=0,
            autoruns_suspicious=0,
            suspicious_dropped=0,
            notable_domains=0,
            host_domains=0,
            external_destinations=0,
            unusual_ports=0,
            suspicious_scriptblocks=0,
        )
    }


class EveryCategoryDeclaresItsCollectors(unittest.TestCase):
    """The map has to keep up with the categories, or it lies by omission."""

    def test_no_category_is_missing_from_the_source_map(self) -> None:
        # A category added without a line in CATEGORY_SOURCES defaults to
        # collected=True forever, claiming coverage it never had -- silently,
        # and in the direction that makes samples look clean.
        missing = _all_category_names() - set(CATEGORY_SOURCES)

        self.assertFalse(
            missing,
            f"{sorted(missing)} can fire but declares no collector. Add it to "
            f"CATEGORY_SOURCES, or its absence will always read as evidence.",
        )

    def test_the_source_map_carries_no_categories_that_have_gone_away(self) -> None:
        stale = set(CATEGORY_SOURCES) - _all_category_names()

        self.assertFalse(stale, f"{sorted(stale)} is mapped but never emitted.")


class ADisabledCollectorIsUnknownNotAbsent(unittest.TestCase):
    def test_a_summary_with_no_available_key_counts_as_collected(self) -> None:
        # The ordinary case. Collectors that ran do not announce themselves.
        result = _score()

        self.assertEqual(result["evidence_counts"]["categories_unknown"], 0)
        self.assertTrue(result["coverage_complete"])

    def test_disabling_memory_yara_makes_the_packer_category_unknown(self) -> None:
        result = _score(memory_yara_summary={
            "available": False,
            "note": "Memory YARA scanning disabled for this run.",
        })

        self.assertEqual(result["uncollected_categories"], ["packed_payload"])
        self.assertFalse(result["coverage_complete"])

    def test_a_dark_detector_costs_the_clean_headline(self) -> None:
        # The band stays Low -- nothing fired, and nothing firing is not a
        # finding. The *claim* is what changes: a run whose packer detector was
        # switched off cannot report Clean Baseline.
        result = _score(memory_yara_summary={"available": False})

        self.assertEqual(result["severity"], "Low")
        self.assertEqual(result["verdict"], "No Findings, Coverage Incomplete")

    def test_a_fully_collected_run_may_claim_one(self) -> None:
        result = _score()

        self.assertEqual(result["verdict"], "Benign / Clean Baseline")

    def test_one_dark_source_of_three_still_counts_as_collected(self) -> None:
        # process_injection can fire from Sysmon, from a crash, or from a carve.
        # Losing one route is a loss of sensitivity, not of the category.
        result = _score(sysmon_summary={"available": False})

        self.assertNotIn("process_injection", result["uncollected_categories"])

    def test_losing_every_source_marks_the_category_unknown(self) -> None:
        result = _score(
            sysmon_summary={"available": False},
            crash_summary={"available": False},
            pe_carve_summary={"available": False},
        )

        self.assertIn("process_injection", result["uncollected_categories"])
        # Sysmon also feeds credential access on its own.
        self.assertIn("credential_access_or_tampering",
                      result["uncollected_categories"])

    def test_a_run_that_collected_nothing_says_so(self) -> None:
        # Every collector dark. Reporting the cleanest verdict the model can
        # express would be the worst answer available.
        result = _score(**{
            name: {"available": False}
            for name in {n for names in CATEGORY_SOURCES.values() for n in names}
        })

        self.assertEqual(result["severity"], "Unknown")
        self.assertEqual(result["verdict"], "Insufficient Coverage")


class CoverageDoesNotSuppressFindings(unittest.TestCase):
    def test_a_category_that_fired_is_unaffected_by_gaps_elsewhere(self) -> None:
        result = _score(
            memory_yara_summary={"available": False},
            powershell_summary={"counts": {"blocks_suspicious": 1}},
        )

        self.assertEqual(result["severity"], "Medium")
        self.assertEqual(result["verdict"], "Needs Review")
        self.assertFalse(result["coverage_complete"])


if __name__ == "__main__":
    unittest.main()
