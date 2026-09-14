"""`--json` owns stdout, and the progress markers have to respect that.

`ringforge scan --json` promises stdout carries the verdict and nothing else,
so a consumer can pipe it into `jq` or `ConvertFrom-Json`. Three subfile
progress markers were being printed to stdout, so any sample with subfiles to
triage produced a stream that would not parse.

It hid well. A sample with no subfiles emits no markers, so the small fixtures
this suite scans looked fine, and so did the release workflow's own smoke test
against a 22-byte probe file. It surfaced on `notepad.exe`.

The markers still have to reach the GUI, which drives the engine as a
subprocess with `stderr=subprocess.STDOUT` and parses its output with the
regexes in `gui.controllers.static_analysis_controller`. Merging the streams is
what makes stderr the right channel rather than a breaking change.

**The format is a contract between two modules and had no test.** The engine
emits these strings; the GUI matches them with three regexes. Either side could
have been edited alone. That is what the second class below is for.
"""

from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout

from gui.controllers.static_analysis_controller import (
    SUBFILE_DONE_RE,
    SUBFILE_START_RE,
    SUBFILE_TRIAGE_RE,
)
from static_triage_engine.engine import _progress


class ProgressGoesToStderr(unittest.TestCase):
    def test_stdout_stays_empty(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            _progress("[subfile:triage] selected=3 limit=25")

        self.assertEqual("", out.getvalue(),
                         "a progress marker reached stdout, which --json owns")
        self.assertIn("[subfile:triage]", err.getvalue())

    def test_it_is_flushed(self) -> None:
        # The GUI reads the pipe line by line while the run is in progress. An
        # unflushed marker arrives when the process exits, which is a progress
        # bar that jumps from 0 to 100 and tells the operator nothing.
        err = io.StringIO()
        with redirect_stderr(err):
            _progress("[subfile:start] 1/3 thing.dll")
        self.assertTrue(err.getvalue().endswith("\n"))


class TheFormatTheGuiParses(unittest.TestCase):
    """Emitted text must match the regexes on the other side of the pipe."""

    def _emit(self, message: str) -> str:
        err = io.StringIO()
        with redirect_stderr(err):
            _progress(message)
        return err.getvalue().strip()

    def test_the_triage_marker_matches(self) -> None:
        line = self._emit("[subfile:triage] selected=3 limit=25")
        match = SUBFILE_TRIAGE_RE.match(line)
        self.assertIsNotNone(match, f"SUBFILE_TRIAGE_RE does not match {line!r}")
        self.assertEqual("3", match.group("selected"))
        self.assertEqual("25", match.group("limit"))

    def test_the_start_marker_matches(self) -> None:
        line = self._emit("[subfile:start] 2/7 payload.dll")
        match = SUBFILE_START_RE.match(line)
        self.assertIsNotNone(match, f"SUBFILE_START_RE does not match {line!r}")
        self.assertEqual("2", match.group("idx"))
        self.assertEqual("7", match.group("total"))
        self.assertEqual("payload.dll", match.group("name"))

    def test_the_done_marker_matches(self) -> None:
        line = self._emit("[subfile:done] 2/7 payload.dll score=14 verdict=Likely Malicious")
        match = SUBFILE_DONE_RE.match(line)
        self.assertIsNotNone(match, f"SUBFILE_DONE_RE does not match {line!r}")
        self.assertEqual("2", match.group("idx"))
        self.assertEqual("7", match.group("total"))
        self.assertIn("score=14", match.group("rest"))

    def test_a_name_with_spaces_survives(self) -> None:
        # Archive members routinely have spaces. The name group is greedy to
        # the end of the line for exactly this reason.
        line = self._emit("[subfile:start] 1/1 Program Files helper.exe")
        match = SUBFILE_START_RE.match(line)
        self.assertIsNotNone(match)
        self.assertEqual("Program Files helper.exe", match.group("name"))


if __name__ == "__main__":
    unittest.main()
