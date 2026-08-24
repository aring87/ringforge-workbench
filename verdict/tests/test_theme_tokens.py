"""One palette, and one report stylesheet, for every medium.

Phase 4b of `docs/SCORING.md`. Before this the desktop application defined 40
colours and the HTML reports defined 17, and the two shared **zero values** --
which is why the workbench and its own reports read as different products.
Behind that were **five** report stylesheets: `report_theme.report_css`, two
near-identical copies in `gui/extension_window.py` and
`gui/unified_report_window.py`, and two ad-hoc sheets in `gui/dynamic_window.py`
and `gui/api_window.py` with entirely different palettes.

These live in `verdict/tests/` rather than a GUI test directory for a practical
reason: `gui/` has no test package, and a rule nothing runs is a rule that has
already been broken.
"""

import re
import unittest
from pathlib import Path

import design_tokens

ROOT = Path(__file__).resolve().parents[2]

HEX = re.compile(r"#[0-9a-fA-F]{6}\b")

#: Where colours are allowed to be written down.
#:
#: `design_tokens.py` is the palette. `report_theme.py` is allowed the two
#: pure-black/white endpoints its shadow and overlays are computed from -- those
#: are not palette choices, they are the ends of the axis.
PALETTE_FILE = ROOT / "design_tokens.py"

#: Files that render into a screen or a page and must therefore use tokens.
_RENDERING_GLOBS = ("gui/*.py", "gui/controllers/*.py",
                    "dynamic_analysis/report_theme.py",
                    "static_triage_engine/report.py")


def _rendering_files():
    for pattern in _RENDERING_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            if path.name.startswith("test_"):
                continue
            yield path


class ThePaletteHasOneHome(unittest.TestCase):
    def test_no_module_that_renders_writes_a_colour_down(self) -> None:
        offenders = {}
        for path in _rendering_files():
            found = HEX.findall(path.read_text(encoding="utf-8", errors="replace"))
            if found:
                offenders[path.relative_to(ROOT).as_posix()] = sorted(set(found))

        self.assertFalse(offenders, (
            f"hex literals outside design_tokens.py: {offenders}. A colour "
            f"written down in a window is a colour the reports will not match; "
            f"add a token instead."))

    def test_the_palette_file_actually_defines_a_palette(self) -> None:
        # Guards the guard: a test asserting "no colours anywhere" would also
        # pass if somebody deleted the palette.
        found = HEX.findall(PALETTE_FILE.read_text(encoding="utf-8"))

        self.assertGreater(len(found), 30)


class BothMediaShareTheSameColours(unittest.TestCase):
    """The property the old arrangement failed: zero shared values."""

    def _report_root(self) -> dict[str, str]:
        from dynamic_analysis.report_theme import report_css

        root = report_css().split("}", 1)[0]
        return dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", root))

    def test_the_report_background_is_the_application_background(self) -> None:
        self.assertEqual(self._report_root()["bg"], design_tokens.BG)

    def test_the_report_accent_is_the_application_accent(self) -> None:
        self.assertEqual(self._report_root()["blue-strong"], design_tokens.ACCENT)

    def test_every_report_colour_comes_from_the_palette(self) -> None:
        # The severity ramp is computed rather than named, so it is checked by
        # derivation below rather than by membership here.
        palette = {v.upper() for k, v in vars(design_tokens).items()
                   if isinstance(v, str) and HEX.fullmatch(v)}
        named = {k: v for k, v in self._report_root().items()
                 if not k.startswith("sev-")}

        strays = {k: v for k, v in named.items() if v.upper() not in palette}
        self.assertFalse(strays, f"report colours not in the palette: {strays}")

    def test_the_severity_ramp_is_derived_from_the_status_colours(self) -> None:
        root = self._report_root()

        self.assertEqual(root["sev-none-fg"],
                         design_tokens.lighten(design_tokens.SUCCESS, 0.55))
        self.assertEqual(root["sev-high-fg"],
                         design_tokens.lighten(design_tokens.DANGER, 0.55))


class ThereIsOneReportStylesheet(unittest.TestCase):
    def test_no_window_carries_its_own(self) -> None:
        # Four windows had one each. A `<style>` block with rules in it, rather
        # than a call to the shared sheet, means a fifth palette is back.
        offenders = []
        for path in sorted(ROOT.glob("gui/*.py")):
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in re.finditer(r"<style>(.*?)</style>", text, re.S):
                body = match.group(1).strip()
                if body != "{report_css()}":
                    offenders.append(path.relative_to(ROOT).as_posix())

        self.assertFalse(offenders,
                         f"window-local stylesheets are back in: {offenders}")

    def test_the_shared_sheet_covers_what_the_windows_needed(self) -> None:
        # Each window-local sheet had a rule or two the others lacked. They were
        # folded in when the copies were deleted; losing one now would silently
        # unstyle whichever report used it.
        from dynamic_analysis.report_theme import report_css

        css = report_css()
        for rule in (".card", ".muted", ".label", ".grid", ".container",
                     ".banner", ".sev-critical", "\npre {", "\nth {"):
            with self.subTest(rule=rule):
                self.assertIn(rule, css)


if __name__ == "__main__":
    unittest.main()
