"""Two snapshots taken by different methods do not make a diff.

The task and service collectors fall back from a PowerShell cmdlet to a
command-line tool when the cmdlet times out, and the two produce differently
shaped records. `benign-wide` `crashhelper_e66cae5f` (6 Oct): `Get-ScheduledTask`
timed out before the run, `schtasks.exe` took the baseline, the cmdlet took
the after, all 260 tasks compared as modified and 99 as suspicious -- which
alone banded a Mozilla crash helper Corroborated.

What matters as much: a like-for-like diff must pass through untouched, or the
fix trades a false positive for a blind spot on every run.
"""

import unittest

from dynamic_analysis.orchestrator import (
    _stored_diff_counts, calculate_dynamic_score, comparable_snapshot_diff,
)

CMDLET = {"success": True, "method": "Get-ScheduledTask", "fallback_used": False}
FALLBACK = {"success": True, "method": "schtasks.exe", "fallback_used": True}
FAILED = {"success": False, "method": "", "error": "timed out"}

#: The measured shape: every task modified, 99 of them suspicious.
MISMATCHED = {"counts": {"new_tasks": 0, "removed_tasks": 0, "modified_tasks": 260,
                         "suspicious_new_or_modified": 99}}
#: A real change: one new suspicious task against a like-for-like baseline.
REAL = {"counts": {"new_tasks": 1, "removed_tasks": 0, "modified_tasks": 0,
                   "suspicious_new_or_modified": 2}}


def persistence(task_diff):
    result = calculate_dynamic_score(
        findings_summary={}, task_diff_summary=task_diff, service_diff_summary={},
        dropped_files_summary={})
    return next(c for c in result["categories"] if c["name"] == "persistence_installed")


class ComparabilityTests(unittest.TestCase):
    def test_the_measured_mismatch_is_not_compared(self) -> None:
        diff = comparable_snapshot_diff(MISMATCHED, FALLBACK, CMDLET, "scheduled task")
        self.assertIs(diff["available"], False)
        self.assertIn("different methods", diff["reason"])
        self.assertFalse(persistence(diff)["present"])

    def test_a_failed_baseline_is_not_compared(self) -> None:
        # An empty "before" makes every entry new -- the Autoruns fault again.
        diff = comparable_snapshot_diff(MISMATCHED, FAILED, CMDLET, "scheduled task")
        self.assertIs(diff["available"], False)
        self.assertIn("before", diff["reason"])

    def test_a_failed_after_is_not_compared(self) -> None:
        diff = comparable_snapshot_diff(MISMATCHED, CMDLET, FAILED, "service")
        self.assertIs(diff["available"], False)
        self.assertIn("after", diff["reason"])

    def test_the_same_method_both_sides_passes_through(self) -> None:
        self.assertIs(comparable_snapshot_diff(REAL, CMDLET, CMDLET, "scheduled task"), REAL)
        self.assertIs(comparable_snapshot_diff(REAL, FALLBACK, FALLBACK, "scheduled task"), REAL)

    def test_a_real_change_still_scores(self) -> None:
        category = persistence(comparable_snapshot_diff(REAL, CMDLET, CMDLET, "scheduled task"))
        self.assertTrue(category["present"])
        self.assertTrue(category["strong"])

    def test_the_marker_survives_storage(self) -> None:
        # The run summary stores diffs flat; a rescore must still see the marker.
        stored = _stored_diff_counts(
            comparable_snapshot_diff(MISMATCHED, FALLBACK, CMDLET, "scheduled task"))
        self.assertIs(stored["available"], False)
        self.assertEqual({"new_tasks": 1, "removed_tasks": 0, "modified_tasks": 0,
                          "suspicious_new_or_modified": 2}, _stored_diff_counts(REAL))


if __name__ == "__main__":
    unittest.main()
