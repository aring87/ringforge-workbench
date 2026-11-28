"""Two pieces of the GUI that cut their own content off.

Both were found taking the README screenshots (27 Nov), and neither shows at
the size a developer usually runs the window, which is why they lasted:

* **The metric tiles cut a long value off at the edge.** The Static window's
  verdict tile read "Elevated Atte" and its confidence tile "Moderate co" at
  any width short of a maximised window, because a `tk.Label` neither shrinks
  nor wraps. A tile now steps its font down and wraps only as a last resort.
* **The Spec window's three result boxes showed one clipped line each.** They
  asked for 11-12 lines apiece, a column the default 1080-high window cannot
  hold, so grid squeezed every one of them to a sliver with no scrollbar. They
  are now tabs of one scrolling "Findings" card.

These build real widgets and measure them, because what broke was layout, and
layout is only visible after Tk has done it.
"""

import shutil
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from tkinter import font as tkfont

from gui import theme as T
from gui.components import StatTile

REPO = Path(__file__).resolve().parents[2]
PETSTORE = REPO / "test_specs" / "petstore3_openapi.json"


def _root_or_skip(test: unittest.TestCase) -> tk.Tk:
    try:
        root = tk.Tk()
    except tk.TclError as error:  # no display to draw on
        test.skipTest(f"Tk is not available: {error}")
    root.withdraw()
    test.addCleanup(root.destroy)
    return root


def _tile_in_box(root: tk.Tk, width: int, **tile_kwargs) -> StatTile:
    """A tile given exactly `width` pixels, as a uniform grid column gives it."""
    box = tk.Frame(root, width=width, height=300)
    box.pack_propagate(False)
    box.pack()
    tile = StatTile(box, "Verdict", **tile_kwargs)
    tile.pack(fill="x")
    root.deiconify()
    root.update()
    root.update()
    return tile


def _size(tile: StatTile) -> int:
    return tkfont.Font(font=tile.value.cget("font")).actual("size")


def _lines(tile: StatTile) -> int:
    linespace = tkfont.Font(font=tile.value.cget("font")).metrics("linespace")
    return round(tile.value.winfo_reqheight() / linespace)


class TheMetricTile(unittest.TestCase):
    def setUp(self) -> None:
        self.root = _root_or_skip(self)
        self.full = T.f_metric()[1]

    def test_a_value_that_fits_keeps_the_full_size(self) -> None:
        tile = _tile_in_box(self.root, 400, value="41")
        self.assertEqual(_size(tile), self.full)
        self.assertEqual(_lines(tile), 1)

    def test_a_long_value_shrinks_to_fit_on_one_line(self) -> None:
        text = "Elevated Attention"
        # The control: at full size this value is wider than the tile, which
        # is the case that used to be cut off.
        full_width = tkfont.Font(root=self.root, family=T.f_metric()[0], size=self.full,
                                 weight="bold").measure(text)
        width = 240
        self.assertGreater(full_width, width)

        tile = _tile_in_box(self.root, width, value=text)
        self.assertLess(_size(tile), self.full)
        self.assertGreaterEqual(_size(tile), StatTile.MIN_FIT_SIZE)
        self.assertEqual(_lines(tile), 1)
        self.assertLessEqual(tile.value.winfo_reqwidth(), tile.body.winfo_width())

    def test_a_value_too_long_even_at_the_floor_wraps_rather_than_clips(self) -> None:
        tile = _tile_in_box(self.root, 130, value="Moderate confidence")
        self.assertEqual(_size(tile), StatTile.MIN_FIT_SIZE)
        self.assertGreaterEqual(_lines(tile), 2)
        self.assertLessEqual(tile.value.winfo_reqwidth(), tile.body.winfo_width())

    def test_a_new_value_through_the_variable_is_refitted(self) -> None:
        var = tk.StringVar(self.root, value="41")
        tile = _tile_in_box(self.root, 240, textvariable=var)
        self.assertEqual(_size(tile), self.full)

        var.set("Elevated Attention")
        self.root.update()
        self.assertLess(_size(tile), self.full)
        self.assertEqual(_lines(tile), 1)

    def test_fit_false_keeps_the_callers_font_and_only_wraps(self) -> None:
        tile = _tile_in_box(self.root, 200, value=r"G:\cases\515d1070878b\unified_report\unified_report.html",
                            fit=False)
        tile.value.configure(font=T.f_body())  # what the Unified Report does
        self.root.update()
        self.assertEqual(_size(tile), T.f_body()[1])
        self.assertGreaterEqual(_lines(tile), 2)


class TheSpecWindowResults(unittest.TestCase):
    @unittest.skipUnless(PETSTORE.exists(), "the sample spec is not present")
    def test_each_result_box_shows_several_lines_at_the_default_size(self) -> None:
        root = _root_or_skip(self)
        cases = Path(tempfile.mkdtemp(prefix="ringforge-spec-layout-"))
        self.addCleanup(shutil.rmtree, cases, True)
        root.case_root_var = tk.StringVar(root, value=str(cases))
        root.case_var = tk.StringVar(root, value="")
        root.sample_var = tk.StringVar(root, value="")
        root.case_dir_detected = None

        from gui.spec_window import SpecAnalysisWindow

        root.deiconify()  # the window is transient to it, so it is hidden with it
        win = SpecAnalysisWindow(root)
        self.addCleanup(win.destroy)
        win.spec_path_var.set(str(PETSTORE))
        win._parse_spec()
        win.update()
        win.update()

        self.assertFalse(win.getting_started_card.winfo_ismapped())
        for index, name in enumerate(("notes_text", "top_risky_text", "recommended_tests_text")):
            win.findings_notebook.select(index)
            win.update()
            box = getattr(win, name)
            linespace = tkfont.Font(font=box.cget("font")).metrics("linespace")
            with self.subTest(box=name):
                # Three separate boxes showed one line each at this size, and
                # about three once they shared the column equally.
                self.assertGreaterEqual(box.winfo_height() // linespace, 12)
                self.assertTrue(box.get("1.0", "end").strip())


if __name__ == "__main__":
    unittest.main()
