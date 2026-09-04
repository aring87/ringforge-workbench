"""The main window's Results panel, which could not be tested until it moved.

142 lines in `gui/controllers/result_controller.py`, of which about ninety were
pure data work behind a display. Fourth module through this pass, and the one
defect it hid is on the application's front page rather than in an exported
file.

**The Verdict tile was grey for every current case.** It colours itself with
`gui.theme.status_colors` and was handed the verdict *sentence*, while that map
knew only severities and the retired one-word verdicts. Every folder written
before the scoring rewrite coloured; every one written after it did not --
`summary.json` carries `severity` beside `verdict` and nothing read it.
"""

import json
import tempfile
import unittest
from pathlib import Path

from gui import theme as T
from static_triage_engine.case_result import (
    band_for,
    counts_line,
    load_case_result,
    load_virustotal,
    result_headline,
    virustotal_view,
)
from verdict.model import DOMAIN_VERDICTS

#: Every sentence the model can put in `summary.json`, both domains plus the
#: four qualifications `band` writes over a `No Evidence` result.
VERDICT_SENTENCES = tuple(sorted(
    {v for domain in DOMAIN_VERDICTS.values() for v in domain.values()}
    | {"Findings Not Scored", "No Findings, Coverage Incomplete",
       "Low Suspicion", "Benign / Clean Baseline"}))

#: What `status_colors` returns for a word it does not know. Distinct from the
#: deliberate neutral below -- "this is not a risk level" and "I have never
#: heard of this" should not be the same pixel, and are not.
DEFAULT = (T.TEXT_SECONDARY, T.NEUTRAL_SOFT)

#: The chosen neutral, for coverage wording.
NEUTRAL = (T.NEUTRAL, T.NEUTRAL_SOFT)


def _case(**files) -> Path:
    case = Path(tempfile.mkdtemp(prefix="ringforge_case_result_"))
    for name, payload in files.items():
        path = case / name.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    return case


class TheVerdictTileWasGrey(unittest.TestCase):
    """The defect the extraction was for, measured."""

    def test_no_verdict_sentence_falls_through_to_the_default(self) -> None:
        """It was 12 of 12. This is the assertion that would have caught it."""
        unknown = [s for s in VERDICT_SENTENCES
                   if T.status_colors(s) == DEFAULT]

        self.assertEqual([], unknown,
                         f"the colour map does not know these: {unknown}")

    def test_coverage_wording_is_neutral_on_purpose(self) -> None:
        """Not a miss. A statement about the bench is not a clean result and
        must not wear the colour of one."""
        for wording in ("Insufficient Coverage", "Findings Not Scored",
                        "No Findings, Coverage Incomplete"):
            with self.subTest(wording=wording):
                self.assertEqual(T.status_colors(wording), NEUTRAL)

    def test_the_band_is_preferred_over_the_sentence(self) -> None:
        headline = result_headline({"verdict": "Needs Review",
                                    "severity": "High"})

        self.assertEqual(band_for(headline), "High")

    def test_a_folder_without_a_severity_still_colours(self) -> None:
        """A case written before the scoring rewrite carries only the word."""
        headline = result_headline({"verdict": "SUSPICIOUS", "risk_score": 21})

        self.assertEqual(band_for(headline), "SUSPICIOUS")
        self.assertNotEqual(T.status_colors(band_for(headline)), DEFAULT)

    def test_every_severity_the_model_emits_colours(self) -> None:
        for severity in ("High", "Medium", "Low", "Unknown"):
            with self.subTest(severity=severity):
                headline = result_headline({"severity": severity,
                                            "verdict": "Needs Review"})
                self.assertNotEqual(T.status_colors(band_for(headline)),
                                    DEFAULT)

    def test_an_empty_headline_asks_for_nothing(self) -> None:
        """No case loaded. The dash is not a band and falls through, which is
        the one time falling through is the right answer."""
        self.assertEqual(band_for(result_headline({})), "-")
        self.assertEqual(T.status_colors("-"), DEFAULT)


class ReadingTheCaseFolder(unittest.TestCase):
    def test_the_engine_s_own_file_is_not_overwritten_by_a_legacy_name(self) -> None:
        """The merge was `update` in the order report / summary / run_summary,
        so the last name -- one nothing has written for releases -- would win
        over `summary.json`, which the engine writes every run.
        """
        case = _case(**{"summary.json": {"verdict": "Likely Malicious",
                                         "severity": "High"},
                        "report.json": {"verdict": "STALE"},
                        "metadata__run_summary.json": {"verdict": "OLDER"}})

        data = load_case_result(case)

        self.assertEqual(data["verdict"], "Likely Malicious")

    def test_a_legacy_name_still_fills_a_gap(self) -> None:
        case = _case(**{"summary.json": {"verdict": "Likely Malicious"},
                        "report.json": {"confidence": "Moderate confidence"}})

        data = load_case_result(case)

        self.assertEqual(data["verdict"], "Likely Malicious")
        self.assertEqual(data["confidence"], "Moderate confidence")

    def test_a_missing_case_is_answered_not_raised(self) -> None:
        self.assertEqual(load_case_result(Path("nowhere-at-all")), {})

    def test_a_corrupt_file_is_answered_not_raised(self) -> None:
        case = Path(tempfile.mkdtemp(prefix="ringforge_case_result_"))
        (case / "summary.json").write_text("{ not json", encoding="utf-8")

        self.assertEqual(load_case_result(case), {})


class TheHeadline(unittest.TestCase):
    def test_the_score_is_found_wherever_it_hides(self) -> None:
        for payload, expected in (
                ({"score": 12}, "12"),
                ({"risk_score": 21}, "21"),
                ({"static_score": 3}, "3"),
                ({"total_score": 7}, "7"),
                ({"scoring": {"risk_score": 5}}, "5"),
                ({"summary": {"total_score": 9}}, "9"),
                ({"verdict_rationale": {"score": 21}}, "21")):
            with self.subTest(payload=payload):
                self.assertEqual(result_headline(payload)["score"], expected)

    def test_the_whole_record_wins_over_a_nested_block(self) -> None:
        headline = result_headline({"score": 1, "scoring": {"score": 99}})

        self.assertEqual(headline["score"], "1")

    def test_a_block_is_finished_before_the_next_is_tried(self) -> None:
        """Alias-first across blocks would answer 9 here. The controller's
        order was block-first, and changing it silently would change the
        number shown for a folder carrying both.
        """
        headline = result_headline({"scoring": {"risk_score": 5},
                                    "summary": {"score": 9}})

        self.assertEqual(headline["score"], "5")

    def test_a_zero_score_is_a_score(self) -> None:
        """`0` is falsy and this hunts by emptiness, so it is worth pinning."""
        self.assertEqual(result_headline({"score": 0})["score"], "0")

    def test_nothing_found_reads_as_a_dash_not_a_zero(self) -> None:
        headline = result_headline({})

        self.assertEqual(headline["score"], "-")
        self.assertEqual(headline["verdict"], "-")
        self.assertEqual(headline["confidence"], "-")

    def test_a_missing_severity_is_empty_not_a_dash(self) -> None:
        """A dash would be a band the colour map does not know, and would mask
        the wording fallback behind it."""
        self.assertEqual(result_headline({"verdict": "SUSPICIOUS"})["severity"],
                         "")

    def test_a_non_mapping_is_answered_not_raised(self) -> None:
        self.assertEqual(result_headline(None)["verdict"], "-")


class TheVirusTotalLine(unittest.TestCase):
    def test_a_skipped_lookup_is_not_a_found_report(self) -> None:
        """**`found` was read off the permalink.** `engine.py` builds that URL
        from the sha256 in the record it writes when the lookup is skipped, so
        it is there whether or not VirusTotal was asked.
        """
        view = virustotal_view(raw={
            "enabled": False, "found": False, "status": "skipped",
            "lookup_status": "skipped_no_api_key",
            "error": "VT_API_KEY not set",
            "permalink": "https://www.virustotal.com/gui/file/abc",
            "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
        })

        self.assertFalse(view["found"])
        self.assertEqual(view["status"], "VirusTotal: skipped")
        # The link still opens VT's page for the hash; that is useful and is
        # not a claim that a report exists.
        self.assertTrue(view["link"])

    def test_a_permalink_alone_never_makes_a_report_found(self) -> None:
        view = virustotal_view(raw={
            "permalink": "https://www.virustotal.com/gui/file/abc"})

        self.assertFalse(view["found"])
        self.assertEqual(view["status"], "VirusTotal: no report available")

    def test_counts_alone_are_enough_to_be_found(self) -> None:
        view = virustotal_view(raw={"malicious": 4, "undetected": 60})

        self.assertTrue(view["found"])
        self.assertEqual(view["status"], "VirusTotal: report found")

    def test_the_nested_stats_shape_is_read(self) -> None:
        view = virustotal_view(raw={
            "found": True, "status": "done",
            "last_analysis_stats": {"malicious": 51, "suspicious": 2,
                                    "harmless": 0, "undetected": 12},
            "meaningful_name": "invoice.exe"})

        self.assertEqual(view["counts"]["malicious"], 51)
        self.assertEqual(view["name"], "invoice.exe")
        self.assertEqual(view["status"], "VirusTotal: report found")

    def test_the_flat_shape_is_read_too(self) -> None:
        view = virustotal_view(raw={"found": True, "malicious": 7,
                                    "file_name": "dropper.dll"})

        self.assertEqual(view["counts"]["malicious"], 7)
        self.assertEqual(view["name"], "dropper.dll")

    def test_the_raw_file_wins_over_the_embedded_copy(self) -> None:
        view = virustotal_view(raw={"found": True, "malicious": 9},
                               embedded={"found": True, "malicious": 1})

        self.assertEqual(view["counts"]["malicious"], 9)

    def test_the_embedded_copy_is_used_when_there_is_no_file(self) -> None:
        view = virustotal_view(embedded={"found": True, "malicious": 1})

        self.assertEqual(view["counts"]["malicious"], 1)

    def test_a_hash_that_is_not_there_says_so(self) -> None:
        view = virustotal_view(raw={"status": "done",
                                    "lookup_status": "not_found"})

        self.assertEqual(view["status"], "VirusTotal: hash not found")

    def test_a_warning_names_the_lookup_status(self) -> None:
        view = virustotal_view(raw={"status": "warning",
                                    "lookup_status": "rate_limited"})

        self.assertEqual(view["status"],
                         "VirusTotal: warning (rate_limited)")

    def test_no_record_and_no_key_reads_as_disabled(self) -> None:
        view = virustotal_view(api_key_present=False)

        self.assertEqual(view["status"], "VirusTotal: disabled")
        self.assertEqual(view["name"], "-")
        self.assertEqual(view["link"], "")

    def test_no_record_with_a_key_is_a_different_fact(self) -> None:
        view = virustotal_view(api_key_present=True)

        self.assertEqual(view["status"], "VirusTotal: no result available")

    def test_unparseable_counts_do_not_raise(self) -> None:
        view = virustotal_view(raw={"malicious": "lots", "found": True})

        self.assertEqual(view["counts"]["malicious"], 0)

    def test_the_counts_line_holds_its_shape(self) -> None:
        self.assertEqual(
            counts_line({"malicious": 4, "suspicious": 1, "harmless": 2,
                         "undetected": 60}),
            "Counts: mal=4 | susp=1 | harmless=2 | undetected=60")

    def test_the_empty_counts_line_is_all_zeros(self) -> None:
        self.assertEqual(
            counts_line({}),
            "Counts: mal=0 | susp=0 | harmless=0 | undetected=0")

    def test_a_case_without_the_file_reads_empty(self) -> None:
        self.assertEqual(load_virustotal(_case()), {})


class _Var:
    """Enough of a `tk.StringVar` to run the real wiring without a display."""

    def __init__(self, value: str = "") -> None:
        self.value = value
        self._callbacks: list = []

    def set(self, value) -> None:
        self.value = str(value)
        for callback in self._callbacks:
            callback()

    def get(self) -> str:
        return self.value

    def trace_add(self, _mode, callback) -> None:
        self._callbacks.append(lambda: callback())


class _Tile:
    def __init__(self) -> None:
        self.colour = None

    def set_value_color(self, colour) -> None:
        self.colour = colour


class _App:
    """The attributes `ResultController` touches, and the tint closure
    `build_results_section` installs -- reproduced here because the real one
    needs a Tk root and this is the wiring that was broken."""

    def __init__(self) -> None:
        for name in ("score_var", "verdict_var", "confidence_var",
                     "vt_status_var", "vt_name_var", "vt_counts_var",
                     "vt_api_key_var"):
            setattr(self, name, _Var())
        self.vt_link = ""
        self.vt_open_btn = None
        self.verdict_tile = _Tile()
        self.verdict_band = ""
        self.verdict_var.trace_add("write", self._tint)

    def _tint(self) -> None:
        band = str(getattr(self, "verdict_band", "") or "").strip()
        foreground, _ = T.status_colors(band or self.verdict_var.get())
        self.verdict_tile.set_value_color(foreground)


class TheTileEndToEnd(unittest.TestCase):
    """Folder on disk -> controller -> the colour actually applied.

    The unit tests above pass with the band set *after* `verdict_var`, which
    would colour every case with the previous case's band -- the trace fires
    on the `set`. This is the test that catches the order.
    """

    def _run(self, **payload) -> str:
        case = _case(**{"summary.json": payload})
        app = _App()
        from gui.controllers.result_controller import ResultController

        ResultController(app).update_result_summary_from_case(case)
        return app.verdict_tile.colour

    def test_every_current_verdict_reaches_the_tile_coloured(self) -> None:
        for verdict, severity in (("Likely Malicious", "High"),
                                  ("Elevated Attention", "High"),
                                  ("Needs Review", "Medium"),
                                  ("Serious Exposure", "High"),
                                  ("Benign / Clean Baseline", "Low"),
                                  ("Insufficient Coverage", "Unknown")):
            with self.subTest(verdict=verdict):
                colour = self._run(verdict=verdict, severity=severity,
                                   score=12)
                self.assertNotEqual(colour, DEFAULT[0])

    def test_the_band_and_not_the_sentence_decides(self) -> None:
        high = self._run(verdict="Needs Review", severity="High")
        low = self._run(verdict="Needs Review", severity="Low")

        self.assertNotEqual(high, low)

    def test_the_previous_case_s_band_does_not_leak_into_the_next(self) -> None:
        """Set the band after `verdict_var` and this is what breaks."""
        app = _App()
        from gui.controllers.result_controller import ResultController

        controller = ResultController(app)
        controller.update_result_summary_from_case(
            _case(**{"summary.json": {"verdict": "Likely Malicious",
                                      "severity": "High"}}))
        first = app.verdict_tile.colour

        controller.update_result_summary_from_case(
            _case(**{"summary.json": {"verdict": "Benign / Clean Baseline",
                                      "severity": "Low"}}))

        self.assertNotEqual(app.verdict_tile.colour, first)

    def test_resetting_clears_the_band_with_the_wording(self) -> None:
        app = _App()
        from gui.controllers.result_controller import ResultController

        controller = ResultController(app)
        controller.update_result_summary_from_case(
            _case(**{"summary.json": {"verdict": "Likely Malicious",
                                      "severity": "High"}}))
        controller.reset_result_summary()

        self.assertEqual(app.verdict_band, "")
        self.assertEqual(app.verdict_var.get(), "-")
        self.assertEqual(app.verdict_tile.colour, DEFAULT[0])

    def test_the_virustotal_line_reaches_the_panel(self) -> None:
        case = _case(**{"summary.json": {"verdict": "Needs Review"},
                        "virustotal.json": {"found": True, "malicious": 51,
                                            "meaningful_name": "invoice.exe",
                                            "permalink": "https://vt/abc"}})
        app = _App()
        from gui.controllers.result_controller import ResultController

        ResultController(app).update_result_summary_from_case(case)

        self.assertEqual(app.vt_status_var.get(), "VirusTotal: report found")
        self.assertEqual(app.vt_name_var.get(), "VT Name: invoice.exe")
        self.assertIn("mal=51", app.vt_counts_var.get())
        self.assertEqual(app.vt_link, "https://vt/abc")


class AgainstARealCaseFolder(unittest.TestCase):
    """A fixture can agree with the reader and disagree with the engine."""

    CASE = Path("cases/c14cb5b6_payload")

    def setUp(self) -> None:
        if not (self.CASE / "summary.json").exists():
            self.skipTest("reference case folder is not checked out")

    def test_it_reads_the_headline_off_the_folder(self) -> None:
        headline = result_headline(load_case_result(self.CASE))

        self.assertEqual(headline["score"], "21")
        self.assertEqual(headline["verdict"], "SUSPICIOUS")
        self.assertEqual(headline["confidence"], "Moderate confidence")

    def test_this_pre_rewrite_folder_is_exactly_the_one_that_used_to_colour(self) -> None:
        """It carries no `severity`, so it falls back to the word -- and the
        word is retired vocabulary the colour map has always known. That is
        why the regression was invisible: the only case folder on disk was one
        the broken path happened to handle.
        """
        headline = result_headline(load_case_result(self.CASE))

        self.assertEqual(headline["severity"], "")
        self.assertNotEqual(T.status_colors(band_for(headline)), DEFAULT)

    def test_the_skipped_virustotal_record_does_not_read_as_found(self) -> None:
        view = virustotal_view(raw=load_virustotal(self.CASE))

        self.assertEqual(view["status"], "VirusTotal: skipped")
        self.assertFalse(view["found"])


if __name__ == "__main__":
    unittest.main()
