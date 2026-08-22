"""A rule edited and committed is not a rule that will fire.

Hand-written rules are authored in `tools\\yara\\local\\`, which git tracks. They
reach the scanner only when `bootstrap_yara_rules.ps1` copies them into
`tools\\yara\\rules\\local\\`, which is gitignored and rebuilt wholesale. So a rule
can be written, reviewed, committed, pulled onto the guest, and still be absent
from every scan.

That has now cost three runs. `38f27025` on 16 Aug reported `total_matches: 0`
and `rescan_memory_yara.py` was written to explain it. `4bb6b0d5` on 22 Aug
scanned ten dumps against a `local\\` directory dated 16 Aug -- four days older
than the rule it was booked to exercise, which was therefore not in it at all --
and reported one matching rule where three were expected.

**A rule that is absent and a rule that does not fire produce the same number,
and the number is the one people read.** These cover the check that tells them
apart *before* the run, in the preflight strip, rather than after it with a
re-scan.
"""

import tempfile
import unittest
from pathlib import Path

from dynamic_analysis.memory_yara import local_rule_drift, memory_yara_status

RULE = 'rule Example { strings: $a = "alpha" condition: $a }\n'
EDITED = 'rule Example { strings: $a = "alpha" $b = "beta" condition: any of them }\n'


class RuleFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.canonical = root / "local"
        self.rules_dir = root / "rules"
        self.scanned = self.rules_dir / "local"
        self.canonical.mkdir(parents=True)
        self.scanned.mkdir(parents=True)
        self.addCleanup(self._tmp.cleanup)

    def _drift(self):
        return local_rule_drift(self.rules_dir, canonical_dir=self.canonical)

    def test_a_rule_the_scanner_does_not_have_is_reported_missing(self) -> None:
        # Run 4bb6b0d5 exactly: authored, committed, pulled, never copied.
        (self.canonical / "ringforge_etherhiding.yar").write_text(RULE, encoding="utf-8")

        drift = self._drift()

        self.assertEqual(drift["missing"], ["ringforge_etherhiding.yar"])
        self.assertEqual(drift["stale"], [])

    def test_an_edited_rule_is_reported_stale(self) -> None:
        (self.canonical / "r.yar").write_text(EDITED, encoding="utf-8")
        (self.scanned / "r.yar").write_text(RULE, encoding="utf-8")

        drift = self._drift()

        self.assertEqual(drift["stale"], ["r.yar"])
        self.assertEqual(drift["missing"], [])

    def test_missing_and_stale_are_not_conflated(self) -> None:
        # Different mistakes: stale means the bootstrap ran before the last
        # edit, missing means it has not run since the rule was created. They
        # want the same command but tell you different things about the guest.
        (self.canonical / "absent.yar").write_text(RULE, encoding="utf-8")
        (self.canonical / "edited.yar").write_text(EDITED, encoding="utf-8")
        (self.scanned / "edited.yar").write_text(RULE, encoding="utf-8")

        drift = self._drift()

        self.assertEqual(drift["missing"], ["absent.yar"])
        self.assertEqual(drift["stale"], ["edited.yar"])

    def test_identical_copies_raise_nothing(self) -> None:
        # The control. A check that cannot be quiet gets ignored.
        (self.canonical / "r.yar").write_text(RULE, encoding="utf-8")
        (self.scanned / "r.yar").write_text(RULE, encoding="utf-8")

        drift = self._drift()

        self.assertEqual(drift["current"], ["r.yar"])
        self.assertEqual(drift["missing"], [])
        self.assertEqual(drift["stale"], [])

    def test_a_scanned_tree_with_no_local_subdirectory_reports_every_rule(self) -> None:
        # What a freshly bootstrapped tree looks like if the copy step failed:
        # rules present, none of them ours.
        (self.canonical / "a.yar").write_text(RULE, encoding="utf-8")
        (self.canonical / "b.yar").write_text(RULE, encoding="utf-8")
        for path in self.scanned.iterdir():
            path.unlink()
        self.scanned.rmdir()

        self.assertEqual(sorted(self._drift()["missing"]), ["a.yar", "b.yar"])

    def test_no_authored_directory_is_unknown_rather_than_clean(self) -> None:
        # Failing open here would be the same error the check exists to catch:
        # reporting an absence as an all-clear.
        drift = local_rule_drift(self.rules_dir,
                                 canonical_dir=self.canonical / "nope")

        self.assertFalse(drift["checked"])
        self.assertEqual(drift["missing"], [])
        self.assertIn("unknown", drift["note"])

    def test_no_rules_directory_at_all_is_not_an_error(self) -> None:
        drift = local_rule_drift(None, canonical_dir=self.canonical)

        self.assertFalse(drift["checked"])


class ThePreflightStripTests(unittest.TestCase):
    """`warning` is what the operator actually sees before starting a run."""

    def test_drift_does_not_make_scanning_unavailable(self) -> None:
        # The ruleset still compiles and still matches. It is simply not the
        # ruleset the operator believes they are running, and disabling the
        # scan over that would trade a quiet wrong answer for no answer.
        status = memory_yara_status()

        self.assertIn("available", status)
        self.assertIn("local_rules", status)
        self.assertIn("warning", status)

    def test_the_warning_is_empty_when_nothing_has_drifted(self) -> None:
        status = memory_yara_status()
        drift = status["local_rules"]

        if not drift["missing"] and not drift["stale"]:
            self.assertEqual(status["warning"], "")
        else:
            # If this repository's own copies have drifted, the check should be
            # saying so rather than staying silent -- which is the whole point.
            self.assertNotEqual(status["warning"], "")


if __name__ == "__main__":
    unittest.main()
