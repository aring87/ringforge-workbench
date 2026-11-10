"""`terminate_by_name`: the sample's copies the tracked tree lost.

GuLoader `f306f95f4a9b` re-launches itself in a chain whose parents exit
before the watcher's poll sees each child. On 29 Sep `terminate_survivors`
found its tracked set already gone, ended nothing, and three copies ran on
through two hours of analysis. Matching by name ends those -- so most of this
file is about what a name match must refuse.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from dynamic_analysis import memory_dump
from dynamic_analysis.memory_dump import NAME_MATCH_PROTECTED, terminate_by_name

T0 = 1_000_000.0


class FakeProc:
    def __init__(self, pid: int, name: str, created: float, dies_on_kill: bool = True):
        self.pid = pid
        self._name = name
        self._created = created
        self.running = True
        self.dies_on_kill = dies_on_kill
        self.killed = 0

    def name(self) -> str:
        return self._name

    def create_time(self) -> float:
        return self._created

    def is_running(self) -> bool:
        return self.running

    def kill(self) -> None:
        self.killed += 1
        if self.dies_on_kill:
            self.running = False


def no_wait(procs, timeout=None):
    return ([p for p in procs if not p.is_running()],
            [p for p in procs if p.is_running()])


class TerminateByNameTests(unittest.TestCase):

    def run_on(self, procs, name="f306f95f4a9b.exe", preexisting=(), **kwargs):
        with mock.patch.object(memory_dump.psutil, "wait_procs", side_effect=no_wait):
            return terminate_by_name(
                name, started_after=T0, preexisting_names=set(preexisting),
                iterate=lambda: [p for p in procs if p.running], **kwargs)

    def test_copies_the_tree_lost_are_terminated(self) -> None:
        copies = [FakeProc(pid, "f306f95f4a9b.exe", T0 + 100) for pid in (3300, 6308, 9040)]
        out = self.run_on(copies)

        self.assertEqual(out["refused"], "")
        self.assertEqual({r["pid"]: r["result"] for r in out["outcomes"]},
                         {3300: "terminated", 6308: "terminated", 9040: "terminated"})
        self.assertTrue(all(c.killed == 1 for c in copies))

    def test_the_name_match_ignores_case(self) -> None:
        copy = FakeProc(10, "F306F95F4A9B.EXE", T0 + 1)
        self.run_on([copy], name=r"\VBOXSVR\ringforge\current\f306f95f4a9b.exe")
        self.assertEqual(copy.killed, 1)

    def test_a_process_older_than_the_detonation_is_never_touched(self) -> None:
        old = FakeProc(20, "f306f95f4a9b.exe", T0 - 1)
        out = self.run_on([old])
        self.assertEqual(old.killed, 0)
        self.assertEqual(out["outcomes"], [])

    def test_other_names_are_never_touched(self) -> None:
        other = FakeProc(30, "notepad.exe", T0 + 5)
        self.run_on([other])
        self.assertEqual(other.killed, 0)

    def test_a_name_already_running_before_is_refused(self) -> None:
        # The name is not the sample's alone, so nothing by that name is safe.
        copy = FakeProc(40, "updater.exe", T0 + 5)
        out = self.run_on([copy], name="updater.exe", preexisting={"Updater.exe"})
        self.assertIn("was running before the detonation", out["refused"])
        self.assertEqual(copy.killed, 0)

    def test_windows_and_bench_names_are_refused(self) -> None:
        for name in ("svchost.exe", "explorer.exe", "python.exe", "rundll32.exe",
                     "werfault.exe"):
            with self.subTest(name=name):
                proc = FakeProc(50, name, T0 + 5)
                out = self.run_on([proc], name=name)
                self.assertTrue(out["refused"])
                self.assertEqual(proc.killed, 0)
        self.assertIn("rundll32.exe", NAME_MATCH_PROTECTED)

    def test_no_name_is_refused(self) -> None:
        self.assertEqual(self.run_on([], name="")["refused"], "no sample name")

    def test_a_copy_started_between_rounds_is_caught(self) -> None:
        # What GuLoader does: lose one copy, start another.
        first = FakeProc(60, "f306f95f4a9b.exe", T0 + 5)
        procs = [first]
        respawned = FakeProc(61, "f306f95f4a9b.exe", T0 + 6)
        original_kill = first.kill

        def kill_and_respawn() -> None:
            original_kill()
            procs.append(respawned)

        first.kill = kill_and_respawn
        out = self.run_on(procs, rounds=2)
        results = {r["pid"]: r["result"] for r in out["outcomes"]}
        self.assertEqual(results, {60: "terminated", 61: "terminated"})

    def test_a_session_that_never_started_refuses(self) -> None:
        # No baseline means no way to tell the sample's copies from anything.
        session = memory_dump.MemoryDumpSession(output_dir=tempfile.gettempdir())
        out = session.terminate_by_name("f306f95f4a9b.exe")
        self.assertIn("never started", out["refused"])
        self.assertEqual(out["outcomes"], [])

    def test_nothing_found_is_an_empty_list_not_a_refusal(self) -> None:
        out = self.run_on([])
        self.assertEqual(out, {"name": "f306f95f4a9b.exe", "refused": "", "outcomes": []})

    @unittest.skipUnless(Path(r"C:\Windows\System32\PING.EXE").exists(), "needs Windows")
    def test_a_real_process_is_terminated_by_its_name(self) -> None:
        """Against the real psutil: ping.exe copied under a unique name,
        started after the baseline, and nothing else by that name. (A copy of
        a venv's python.exe will not start without its pyvenv.cfg.)"""
        tmp = Path(tempfile.mkdtemp(prefix="rf-byname-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        exe = tmp / "rfbynametest0123.exe"
        shutil.copy2(r"C:\Windows\System32\PING.EXE", exe)
        started = time.time() - 1
        child = subprocess.Popen([str(exe), "-n", "60", "127.0.0.1"],
                                 stdout=subprocess.DEVNULL)
        self.addCleanup(lambda: child.poll() is None and child.kill())
        time.sleep(1.0)

        out = terminate_by_name(exe.name, started_after=started,
                                preexisting_names=set(), wait_seconds=10)

        self.assertEqual([r["result"] for r in out["outcomes"]], ["terminated"])
        self.assertIsNotNone(child.wait(timeout=10))

if __name__ == "__main__":
    unittest.main()
