"""Every status line carries how long the step before it took.

Two runs were spent guessing at where teardown time goes.

Run `33fe6c3b` spent 24 of its 27 minutes somewhere after observation, and the
pane could not say where: each pass emits one line when it *starts*, so the slow
pass is identified only by being the last line printed -- and a pass that is slow
looks exactly like one that is stuck.

Run `eb3e1273` then showed the first diagnosis of that was wrong. The
module-integrity cache was blamed on `modules_compared: 380`, which turned out to
be a **total across five dumps** rather than a per-dump count that would have
thrashed a 96-entry cache. The real figure was 83 per dump, comfortably inside
the old limit. The cache was never the bottleneck.

Guessing twice is enough, so the instrument goes in before the third attempt.
Timing `_emit` covers every pass at once -- including the ones nobody has
suspected yet -- for one `perf_counter` per line.
"""
import unittest
from pathlib import Path

from dynamic_analysis import orchestrator


class Clock:
    """A perf_counter that only moves when told."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class StatusLinesCarryTheElapsedTime(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self._real = orchestrator.time.perf_counter
        orchestrator.time.perf_counter = self.clock
        self.addCleanup(setattr, orchestrator.time, "perf_counter", self._real)
        orchestrator._reset_emit_clock()
        self.addCleanup(orchestrator._reset_emit_clock)
        self.lines = []

    def emit(self, message):
        orchestrator._emit(self.lines.append, message)

    def test_the_first_line_of_a_run_is_not_tagged(self):
        """There is no previous step for it to describe."""
        self.emit("Collecting sample hashes and metadata...")
        self.assertNotIn("[+", self.lines[0])

    def test_a_slow_step_is_tagged_on_the_line_after_it(self):
        """The elapsed belongs to the step *before* the line, not to it.

        This is the whole reading convention: the pane is a list of starts, so
        the number attaches to what just finished.
        """
        self.emit("Exporting Procmon CSV...")
        self.clock.advance(1374)
        self.emit("Comparing loaded modules against their files...")
        self.assertNotIn("[+", self.lines[0])
        self.assertIn("[+1374s]", self.lines[1])

    def test_a_fast_step_is_left_alone(self):
        """`+0s` on every instant line hides the slow ones."""
        self.emit("Diffing services...")
        self.clock.advance(0.4)
        self.emit("Diffing scheduled tasks...")
        self.assertNotIn("[+", self.lines[1])

    def test_the_floor_is_inclusive(self):
        self.emit("one")
        self.clock.advance(orchestrator._EMIT_TIMING_FLOOR_SECONDS)
        self.emit("two")
        self.assertIn("[+", self.lines[1])

    def test_the_original_message_survives_intact(self):
        # The GUI and the operator both read these; the tag is a suffix, never
        # a rewrite.
        self.emit("first")
        self.clock.advance(60)
        self.emit("Parsing Procmon events...")
        self.assertTrue(self.lines[1].startswith("Parsing Procmon events..."))

    def test_a_new_run_does_not_inherit_the_gap_from_the_last_one(self):
        """Otherwise line 1 of every run is tagged with the idle time before it."""
        self.emit("run one, last line")
        self.clock.advance(9999)
        orchestrator._reset_emit_clock()
        self.emit("run two, first line")
        self.assertNotIn("[+", self.lines[1])

    def test_the_clock_advances_even_with_no_callback(self):
        """A run without a status callback must not mis-time the next one."""
        orchestrator._emit(None, "silent")
        self.clock.advance(30)
        self.emit("audible")
        self.assertIn("[+30s]", self.lines[0])


if __name__ == "__main__":
    unittest.main()


class TheStatusLogSurvivesTheWindow(unittest.TestCase):
    """The run's narrative has to outlive the pane that displayed it.

    The Output pane is a Tk text widget and nothing ever wrote it to disk, so
    the one artefact saying *which pass ran when* died when the window closed.
    That cost three runs: `33fe6c3b` stalled with no record of where,
    `eb3e1273` produced five minutes of silence with no record of what it was
    doing, and `fa23508d` was closed before its timings could be read. The
    summary JSON keeps every result and none of the sequence.
    """

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.log = Path(self._tmp.name) / "metadata" / "status.log"
        self.addCleanup(orchestrator._reset_emit_clock)

    def test_lines_are_written_alongside_the_summary(self):
        orchestrator._reset_emit_clock(self.log)
        orchestrator._emit(None, "Exporting Procmon CSV...")
        self.assertIn("Exporting Procmon CSV...",
                      self.log.read_text(encoding="utf-8"))

    def test_the_parent_directory_is_created(self):
        # `_reset_emit_clock` may run before the metadata directory exists.
        self.assertFalse(self.log.parent.exists())
        orchestrator._reset_emit_clock(self.log)
        self.assertTrue(self.log.exists())

    def test_the_elapsed_tag_reaches_the_file_not_just_the_screen(self):
        """The file is the whole point -- a tag only on screen is what failed."""
        orchestrator._reset_emit_clock(self.log)
        orchestrator._emit(None, "first")
        orchestrator._LAST_EMIT_AT -= 1374
        orchestrator._emit(None, "Comparing loaded modules...")
        self.assertIn("[+1374s]", self.log.read_text(encoding="utf-8"))

    def test_a_new_run_truncates_rather_than_appending(self):
        """Two attempts must not read as one continuous sequence."""
        orchestrator._reset_emit_clock(self.log)
        orchestrator._emit(None, "attempt one")
        orchestrator._reset_emit_clock(self.log)
        orchestrator._emit(None, "attempt two")
        body = self.log.read_text(encoding="utf-8")
        self.assertNotIn("attempt one", body)
        self.assertIn("attempt two", body)

    def test_no_path_means_screen_only(self):
        orchestrator._reset_emit_clock(None)
        lines = []
        orchestrator._emit(lines.append, "nothing on disk")
        self.assertEqual(lines, ["nothing on disk"])
        self.assertFalse(self.log.exists())

    def test_an_unwritable_log_does_not_fail_the_run(self):
        """Losing the log must never lose the detonation.

        **The path is made unwritable, not assumed to be.** This used to point
        at `Z:/no/such/volume/status.log` on the reasoning that no such drive
        exists. On the host that held and the test passed; on the *guest* `Z:`
        is the VirtualBox share, so `mkdir(parents=True)` created
        `Z:\\no\\such\\volume\\` for real and the write succeeded -- littering
        host storage through a share mounted into the detonation VM, and
        exercising the writable branch on the one machine where runs actually
        happen. The assertion could not fail either way, which is why nothing
        noticed until the directory was found by hand.

        A file where a directory must be cannot be traversed on any platform,
        so this needs no drive letter and leaves nothing behind.
        """
        blocker = Path(self._tmp.name) / "not-a-directory"
        blocker.write_text("", encoding="utf-8")
        unwritable = blocker / "metadata" / "status.log"

        orchestrator._reset_emit_clock(unwritable)
        lines = []
        orchestrator._emit(lines.append, "still emitted")

        self.assertEqual(lines, ["still emitted"])
        # The branch this test is named for was genuinely taken.
        self.assertFalse(unwritable.exists())

    def test_it_records_lines_with_no_status_callback(self):
        # A headless/orchestrator-only run has no pane; the file is then the
        # only record there is.
        orchestrator._reset_emit_clock(self.log)
        orchestrator._emit(None, "headless line")
        self.assertIn("headless line", self.log.read_text(encoding="utf-8"))
