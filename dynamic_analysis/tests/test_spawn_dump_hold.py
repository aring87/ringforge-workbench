"""A child is suspended before it is dumped, so it cannot exit first.

**The race, measured.** A hollowed `SecurityHealthHost.exe` was captured on
**1 of 5 attempts** across runs `33fe6c3b`, `eb3e1273`, `fa23508d`, `ff504255`
and `59a705df`. Every failure read the same way:

    Dump 1 error: Target process no longer running.
    0x8007012B  Only part of a ReadProcessMemory request was completed.

The child passes the watcher's liveness check and then dies while ProcDump is
still starting. **Nothing that merely shrinks the window fixes that** -- not a
faster poll, not writing the dump in-process instead of shelling out. The
process can always exit between the check and the attach.

That process was the only one this sample actually hollowed, so missing it is
why gap 5 keeps coming back empty on this control.

The bar these tests hold is the failure mode the fix introduces: **a process
left suspended is worse than one that was never held.** It hangs the sample's
whole chain and the run reports a quiet machine.
"""
import subprocess
import sys
import time
import unittest

from dynamic_analysis.memory_dump import _hold_process, _release_process


def _short_lived(seconds=1.0):
    return subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({seconds})"])


def _alive(proc):
    return proc.poll() is None


def _wait_exit(proc, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _alive(proc):
            return True
        time.sleep(0.05)
    return False


@unittest.skipIf(sys.platform != "win32", "suspends a Windows process")
class HoldingAProcess(unittest.TestCase):
    def test_a_held_process_outlives_its_own_exit(self):
        """The whole point: it must not die on schedule while we dump it."""
        proc = _short_lived(0.5)
        self.addCleanup(lambda: proc.kill() if _alive(proc) else None)
        time.sleep(0.15)

        handle, _reason = _hold_process(proc.pid)
        self.assertIsNotNone(handle, "could not suspend a process we just started")
        try:
            time.sleep(2.0)                      # four times its natural life
            self.assertTrue(_alive(proc),
                            "the process exited while suspended -- the hold does nothing")
        finally:
            _release_process(handle)
        self.assertTrue(_wait_exit(proc), "it never resumed")

    def test_release_lets_it_finish(self):
        # Lives comfortably longer than the settle below. At 0.1s this raced its
        # own setup -- the child was already gone when the hold was attempted,
        # `_hold_process` correctly returned None for a dead pid, and the
        # assertion below then contradicted
        # `test_holding_a_dead_pid_is_a_real_answer_not_an_error` directly. It
        # passed on a host where interpreter startup padded the child's life and
        # failed on a guest where it did not. What this test is for is the
        # release, not the margin.
        proc = _short_lived(2.0)
        self.addCleanup(lambda: proc.kill() if _alive(proc) else None)
        time.sleep(0.15)
        handle, _reason = _hold_process(proc.pid)
        self.assertIsNotNone(handle)
        _release_process(handle)
        self.assertTrue(_wait_exit(proc),
                        "still suspended after release -- this hangs the sample's chain")

    def test_holding_a_dead_pid_is_a_real_answer_not_an_error(self):
        """A child already gone cannot be held, and that is not a failure.

        The dump path then behaves exactly as it did before the hold existed.
        """
        proc = _short_lived(0.05)
        proc.wait(timeout=5)
        handle, reason = _hold_process(proc.pid)
        self.assertIsNone(handle)
        self.assertTrue(reason, "a refused hold must say why")

    def test_releasing_nothing_is_safe(self):
        # The `finally` runs whether or not the hold succeeded.
        _release_process(None)

    def test_release_never_raises_on_a_stale_handle(self):
        """Called from a `finally`; an exception there would mask the real one."""
        proc = _short_lived(0.05)
        time.sleep(0.15)
        handle, _reason = _hold_process(proc.pid)
        _release_process(handle)
        _release_process(handle)          # double release, handle now closed
        proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()


class TheSummaryCarriesWhatTheRecordSets(unittest.TestCase):
    """A field set on a dump record and dropped by the projection is invisible.

    `summarize_memory_dumps` copies a **fixed field set** into the run summary.
    `held` was set on the record and not added there, so run `0d469835` reported
    it absent on every row -- which reads exactly like a guest running code that
    predates the field. The wrong conclusion was drawn from it and the operator
    was sent to check a guest that was already correct.

    That is the same class as the analyzer-attribution bugs this project keeps
    finding: the collection was right and the reporting lost it.
    """

    def _summary(self, record):
        from dynamic_analysis.memory_dump import summarize_memory_dumps
        return summarize_memory_dumps({"dumps": [record], "counts": {}})

    def test_a_successful_dump_reports_whether_it_was_held(self):
        summary = self._summary(
            {"pid": 1, "name": "child.exe", "success": True, "held": True,
             "size": 1024, "trigger": "process-spawn"})
        self.assertIs(summary["dumps"][0]["held"], True)

    def test_a_failed_dump_reports_it_too(self):
        """This is where it matters most.

        A suspended process cannot report "Target process no longer running",
        so a failure carrying `held: true` means something other than the race
        -- and a failure carrying `held: false` says the hold was refused,
        which is the case worth chasing.
        """
        summary = self._summary(
            {"pid": 2, "name": "child.exe", "success": False, "held": False,
             "hold_error": "OpenProcess failed, error 5",
             "error": "Target process no longer running",
             "trigger": "process-spawn"})
        failure = summary["failures"][0]
        self.assertIs(failure["held"], False)
        self.assertIn("OpenProcess", failure["hold_error"])

    def test_an_unheld_dump_is_distinguishable_from_an_old_record(self):
        """`None` must mean "this path does not hold", not "field lost".

        Scheduled and re-dump records never hold anything, so None there is
        correct and readable. What must not happen is a *spawn* record reading
        None because the projection dropped it.
        """
        summary = self._summary(
            {"pid": 3, "name": "p.exe", "success": True, "size": 1,
             "trigger": "scheduled"})
        self.assertIsNone(summary["dumps"][0]["held"])
