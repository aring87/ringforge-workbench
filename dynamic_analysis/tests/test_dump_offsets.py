"""Offsets and the process cap belong to the sample, not to the tool.

Two Formbook runs produced nine dumps between them and no image of anything
that mattered:

* The sample spawned its hollowing target at +20s and exited immediately after.
  The standard offsets are [5, 25], so it was captured once at +5s -- before it
  had unpacked -- and never again. The window in which it did the interesting
  work was bracketed on both sides.
* Its chain ran to six processes: itself, powershell.exe, conhost.exe,
  RegSvcs.exe, a second RegSvcs.exe spawned by the first, and WerFault.exe. The
  cap was five, and it fell exactly on the second RegSvcs -- the process most
  likely to hold the payload. Recorded as "process cap reached" rather than
  lost silently, which is how it was found, but the image is gone either way.

Neither is a bug in the defaults so much as proof that they cannot be fixed
constants. The GUI hands offsets over as text, so parsing has to be forgiving:
a blank field or a trailing comma falls back to the profile rather than failing
the run.
"""

import unittest

from dynamic_analysis.memory_dump import DEFAULT_MAX_PROCESSES
from dynamic_analysis.orchestrator import _parse_offsets


class ParseOffsetTests(unittest.TestCase):
    def test_a_typed_list_is_parsed(self) -> None:
        self.assertEqual(_parse_offsets("5, 15, 20"), [5, 15, 20])

    def test_semicolons_and_spacing_are_tolerated(self) -> None:
        self.assertEqual(_parse_offsets(" 5 ;15,  20 "), [5, 15, 20])

    def test_a_blank_field_falls_back_to_the_profile(self) -> None:
        # The caller treats an empty list as "use the default", so this must
        # not raise and must not invent an offset.
        self.assertEqual(_parse_offsets(""), [])
        self.assertEqual(_parse_offsets(None), [])
        self.assertEqual(_parse_offsets("   "), [])

    def test_a_trailing_comma_does_not_fail_the_run(self) -> None:
        self.assertEqual(_parse_offsets("5, 25,"), [5, 25])

    def test_junk_is_dropped_rather_than_raising(self) -> None:
        self.assertEqual(_parse_offsets("5, abc, 20"), [5, 20])

    def test_offsets_are_sorted_and_deduplicated(self) -> None:
        # The watcher pops them in order, and two identical offsets would write
        # two identical images.
        self.assertEqual(_parse_offsets("25, 5, 25, 15"), [5, 15, 25])

    def test_zero_and_negative_offsets_are_dropped(self) -> None:
        # An offset at or before launch cannot be honoured.
        self.assertEqual(_parse_offsets("0, -5, 10"), [10])

    def test_a_list_is_accepted_as_well_as_text(self) -> None:
        # config.json can carry a real list; the GUI carries a string.
        self.assertEqual(_parse_offsets([5, 20, 5]), [5, 20])


class ProcessCapTests(unittest.TestCase):
    def test_the_cap_clears_an_ordinary_loader_chain(self) -> None:
        # The Formbook chain was six processes deep and the cap was five.
        self.assertGreaterEqual(DEFAULT_MAX_PROCESSES, 6)


if __name__ == "__main__":
    unittest.main()
