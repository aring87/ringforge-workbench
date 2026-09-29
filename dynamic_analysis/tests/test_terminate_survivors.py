"""`terminate_survivors`: end the sample's tree after observation, and nothing else.

GuLoader `f306f95f4a9b` (29 Sep) kept three processes running through the
whole post-detonation analysis, which ran 5-8x slower for it and missed the
host's limit. The fix kills what the sample left running -- so what matters
most here is what it must NOT kill: a PID reused by another process, and
Windows Error Reporting mid-dump.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from unittest import mock

import psutil

from dynamic_analysis import memory_dump
from dynamic_analysis.memory_dump import SURVIVOR_EXEMPT_NAMES, terminate_survivors


class FakeHandle:
    def __init__(self, pid: int, name: str, running: bool = True, kill_error=None,
                 dies_on_kill: bool = True) -> None:
        self.pid = pid
        self._name = name
        self.running = running
        self.kill_error = kill_error
        self.dies_on_kill = dies_on_kill
        self.killed = 0

    def name(self) -> str:
        return self._name

    def is_running(self) -> bool:
        return self.running

    def kill(self) -> None:
        self.killed += 1
        if self.kill_error is not None:
            raise self.kill_error
        if self.dies_on_kill:
            self.running = False


def no_wait(procs, timeout=None):
    gone = [p for p in procs if not p.is_running()]
    alive = [p for p in procs if p.is_running()]
    return gone, alive


class TerminateSurvivorsTests(unittest.TestCase):

    def run_on(self, handles, **kwargs):
        with mock.patch.object(memory_dump.psutil, "wait_procs", side_effect=no_wait):
            return {r["pid"]: r for r in terminate_survivors(handles, **kwargs)}

    def test_a_running_sample_process_is_terminated(self) -> None:
        h = FakeHandle(10, "f306f95f4a9b.exe")
        out = self.run_on({10: h})
        self.assertEqual(out[10]["result"], "terminated")
        self.assertEqual(h.killed, 1)

    def test_error_reporting_is_never_killed(self) -> None:
        """WerFault writes the crash dumps collected after this runs."""
        for name in ("WerFault.exe", "wermgr.exe", "WerFaultSecure.exe"):
            h = FakeHandle(20, name)
            out = self.run_on({20: h})
            self.assertEqual(out[20]["result"], "exempt", name)
            self.assertEqual(h.killed, 0, name)
        self.assertIn("werfault.exe", SURVIVOR_EXEMPT_NAMES)

    def test_an_exited_process_is_not_signalled(self) -> None:
        h = FakeHandle(30, "gone.exe", running=False)
        out = self.run_on({30: h})
        self.assertEqual(out[30]["result"], "exited")
        self.assertEqual(h.killed, 0)

    def test_a_reused_pid_is_not_ours(self) -> None:
        """psutil 6 refuses to signal a PID whose creation time changed."""
        h = FakeHandle(40, "svchost.exe", kill_error=psutil.NoSuchProcess(
            40, msg="process no longer exists and its PID has been reused"))
        out = self.run_on({40: h})
        self.assertEqual(out[40]["result"], "not_ours")

    def test_access_denied_is_recorded_not_raised(self) -> None:
        h = FakeHandle(50, "protected.exe", kill_error=psutil.AccessDenied(50))
        out = self.run_on({50: h})
        self.assertEqual(out[50]["result"], "access_denied")

    def test_a_child_spawned_during_the_first_round_is_caught(self) -> None:
        """A resident loader that loses a child tends to spawn another."""
        handles = {60: FakeHandle(60, "loader.exe")}
        spawned = FakeHandle(61, "loader.exe")

        def refresh() -> None:
            if handles[60].killed:
                handles[61] = spawned

        out = self.run_on(handles, refresh=refresh)
        self.assertEqual(out[61]["result"], "terminated")
        self.assertEqual(spawned.killed, 1)

    def test_one_that_outlives_its_kill_is_reported(self) -> None:
        h = FakeHandle(70, "stubborn.exe", dies_on_kill=False)
        out = self.run_on({70: h}, rounds=2)
        self.assertEqual(out[70]["result"], "still_running")
        self.assertEqual(h.killed, 2)

    def test_a_real_process_is_terminated(self) -> None:
        """Against the real psutil and a real process, no fakes."""
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(lambda: child.poll() is None and child.kill())
        handle = psutil.Process(child.pid)
        out = {r["pid"]: r for r in terminate_survivors({child.pid: handle}, wait_seconds=10)}
        self.assertEqual(out[child.pid]["result"], "terminated")
        self.assertIsNotNone(child.wait(timeout=10))
        self.assertFalse(handle.is_running())


if __name__ == "__main__":
    unittest.main()
