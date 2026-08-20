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

        handle = _hold_process(proc.pid)
        self.assertIsNotNone(handle, "could not suspend a process we just started")
        try:
            time.sleep(2.0)                      # four times its natural life
            self.assertTrue(_alive(proc),
                            "the process exited while suspended -- the hold does nothing")
        finally:
            _release_process(handle)
        self.assertTrue(_wait_exit(proc), "it never resumed")

    def test_release_lets_it_finish(self):
        proc = _short_lived(0.1)
        self.addCleanup(lambda: proc.kill() if _alive(proc) else None)
        time.sleep(0.15)
        handle = _hold_process(proc.pid)
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
        self.assertIsNone(_hold_process(proc.pid))

    def test_releasing_nothing_is_safe(self):
        # The `finally` runs whether or not the hold succeeded.
        _release_process(None)

    def test_release_never_raises_on_a_stale_handle(self):
        """Called from a `finally`; an exception there would mask the real one."""
        proc = _short_lived(0.05)
        time.sleep(0.15)
        handle = _hold_process(proc.pid)
        _release_process(handle)
        _release_process(handle)          # double release, handle now closed
        proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
