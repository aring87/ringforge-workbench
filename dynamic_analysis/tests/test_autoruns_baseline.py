"""An empty "before" Autoruns snapshot is not a baseline.

When `autorunsc` times out before the run it leaves a 0-byte CSV, the diff
reads every autostart entry on the guest as new, and `persistence_installed`
went strong on it -- 106 "new" entries, identical across unrelated benign
programs. Found 2 Oct: 10 of the first 26 `benign-wide` runs banded
Corroborated 50 on it, and 4 of `mal-112b` carried it too, each with
`autoruns_before_status` reading "timed out after 180 seconds".

What matters most here is the other half: a real diff must still count, or
the fix trades a false positive for a blind spot.
"""

import unittest

from dynamic_analysis.orchestrator import calculate_dynamic_score, trusted_autoruns_diff

#: The measured artifact: `addr2line_ec67b2c5`, run 30 Sep in `benign-wide`.
EMPTY_BEFORE = {"counts": {"before_total": 0, "after_total": 1594, "new_entries": 1594,
                           "suspicious_new_entries": 106,
                           "suspicious_new_or_modified": 106}}

#: A real diff: two entries appeared against a full baseline.
REAL = {"counts": {"before_total": 1593, "after_total": 1595, "new_entries": 2,
                   "suspicious_new_entries": 2, "suspicious_new_or_modified": 2}}


def score(autoruns):
    return calculate_dynamic_score(
        findings_summary={}, task_diff_summary={}, service_diff_summary={},
        dropped_files_summary={}, autoruns_diff_summary=autoruns)


def category(result, name):
    for entry in result.get("categories", []):
        if entry.get("name") == name:
            return entry
    raise AssertionError(f"no category {name!r} in {result.get('categories')}")


class EmptyBaselineTests(unittest.TestCase):
    def test_an_empty_before_snapshot_is_marked_unavailable(self) -> None:
        trusted = trusted_autoruns_diff(EMPTY_BEFORE)
        self.assertIs(trusted["available"], False)
        self.assertEqual({}, trusted["counts"])

    def test_it_no_longer_reads_as_persistence(self) -> None:
        persistence = category(score(EMPTY_BEFORE), "persistence_installed")
        self.assertFalse(persistence["present"])
        self.assertFalse(persistence["strong"])

    def test_it_scores_the_same_as_no_autoruns_at_all(self) -> None:
        self.assertEqual(score(None)["score"], score(EMPTY_BEFORE)["score"])

    def test_a_real_diff_still_counts(self) -> None:
        self.assertIs(trusted_autoruns_diff(REAL), REAL)
        persistence = category(score(REAL), "persistence_installed")
        self.assertTrue(persistence["present"])
        self.assertTrue(persistence["strong"])
        self.assertIn("2 autoruns entry(s)", persistence["detail"])

    def test_a_quiet_run_is_not_mistaken_for_an_empty_baseline(self) -> None:
        # Nothing before *and* nothing after is a run with no entries at all,
        # not a failed snapshot; there is nothing to distrust.
        quiet = {"counts": {"before_total": 0, "after_total": 0}}
        self.assertIs(trusted_autoruns_diff(quiet), quiet)

    def test_an_explicit_unavailable_marker_passes_through(self) -> None:
        marker = {"available": False, "reason": "the before snapshot failed", "counts": {}}
        self.assertIs(trusted_autoruns_diff(marker), marker)


if __name__ == "__main__":
    unittest.main()
