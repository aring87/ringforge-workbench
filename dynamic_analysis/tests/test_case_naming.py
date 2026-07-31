"""Case names derived from a sample must not overflow Windows' path limit.

MalwareBazaar delivers every sample named as its full SHA-256. That name is
used twice in each artifact path -- once as the case folder, once inside the run
directory name -- so an uncapped name costs roughly 155 characters before the
repo root, the fixed directories, or any filename. The first live sample failed
outright with "The filename or extension is too long".

The cap is duplicated in the GUI, which builds the case folder, and in the
orchestrator, which builds the run directory. Both are asserted here so they
cannot drift apart.
"""

import unittest

from dynamic_analysis.orchestrator import _MAX_NAME_COMPONENT, _slugify

SHA256 = "31a762fdce1008e635a5e6486d7bc50b4bce671c9232006216e70cd8f2a4a7fb"

#: The deepest artifact path the orchestrator writes, with the sample-derived
#: name appearing in both positions.
_PATH_TEMPLATE = (
    r"C:\projects\RingForge_Analyzer\ringforge-workbench"
    r"\cases\{name}\dynamic_analysis\dynamic_runs"
    r"\{name}_20260731_184545_c7b154a5\metadata\dynamic_run_summary.json"
)

MAX_PATH = 260


class CaseNameLengthTests(unittest.TestCase):
    def test_a_full_hash_is_truncated(self) -> None:
        self.assertEqual(len(_slugify(SHA256)), _MAX_NAME_COMPONENT)

    def test_the_resulting_path_fits(self) -> None:
        path = _PATH_TEMPLATE.format(name=_slugify(SHA256))
        self.assertLess(len(path), MAX_PATH, path)

    def test_an_uncapped_name_would_not_have(self) -> None:
        # Guards the test itself: if this ever passes, the template no longer
        # reflects a real path and the check above proves nothing.
        self.assertGreater(len(_PATH_TEMPLATE.format(name=SHA256)), MAX_PATH)

    def test_ordinary_names_are_untouched(self) -> None:
        self.assertEqual(_slugify("mimikatz.upx"), "mimikatz.upx")
        self.assertEqual(_slugify("AgentTesla"), "agenttesla")

    def test_truncation_does_not_leave_trailing_punctuation(self) -> None:
        # Cutting mid-name can land on a separator, which reads as a typo in a
        # directory listing and is invalid as a trailing character on Windows.
        self.assertFalse(_slugify("a" * 23 + "._-junk").endswith(("_", ".", "-")))

    def test_empty_input_still_yields_a_name(self) -> None:
        self.assertTrue(_slugify(""))


class GuiCapMatchesOrchestratorTests(unittest.TestCase):
    def test_both_caps_agree(self) -> None:
        # The GUI names the case folder and the orchestrator names the run
        # directory. A mismatch would silently reintroduce the overflow.
        import re
        from pathlib import Path

        source = (Path(__file__).resolve().parents[2] / "gui" / "dynamic_window.py").read_text(
            encoding="utf-8"
        )
        match = re.search(r"_MAX_CASE_NAME\s*=\s*(\d+)", source)
        self.assertIsNotNone(match, "GUI cap not found")
        self.assertEqual(int(match.group(1)), _MAX_NAME_COMPONENT)


if __name__ == "__main__":
    unittest.main()
