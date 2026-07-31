"""A payload process that appears late must still be captured.

Reconstructed from a real AgentTesla run. The sample sat dormant for 77
seconds, launched a second copy of itself, and that copy crashed within a
couple of seconds. Dumps at +5s and +25s both captured the dormant launcher;
the process the payload was staged into was never dumped, and the run reported
"Low Suspicion" on live malware.

No choice of fixed offsets fixes that in general -- the delay differs per
crypter, and a missed window is indistinguishable from a quiet sample. So the
watcher dumps a descendant when it first appears, whatever the clock says.

These tests drive MemoryDumpSession's selection logic directly with a fake
process tree rather than launching real processes, so they assert the decision
being made rather than ProcDump's behaviour.
"""

import unittest
from unittest import mock

from dynamic_analysis.memory_dump import MemoryDumpSession


class SpawnDumpSelectionTests(unittest.TestCase):
    def _session(self, tmp="C:\\cases\\x\\memory"):
        session = MemoryDumpSession(output_dir=tmp, dump_offsets=[5, 25])
        session._root_pid = 100
        session._procdump = "procdump64.exe"
        return session

    def _known(self, session, pids):
        session._known = {
            pid: {"pid": pid, "name": f"p{pid}.exe", "image": "", "parent_pid": 100}
            for pid in pids
        }

    def test_a_late_child_is_dumped_when_it_appears(self) -> None:
        session = self._session()
        self._known(session, [100, 9416])

        dumped = []
        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             mock.patch.object(session, "_dump_one",
                               side_effect=lambda t, o, tr: dumped.append((t["pid"], tr)) or
                               {"pid": t["pid"], "name": "", "path": "x", "size": 1, "success": True}):
            session._dump_spawned_children(elapsed=77.0)

        self.assertEqual(dumped, [(9416, "process-spawn")])

    def test_the_root_is_left_to_the_scheduled_offsets(self) -> None:
        # Dumping the root here would add a near-duplicate image at +0s.
        session = self._session()
        self._known(session, [100])

        dumped = []
        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             mock.patch.object(session, "_dump_one",
                               side_effect=lambda t, o, tr: dumped.append(t["pid"]) or
                               {"pid": t["pid"], "name": "", "path": "x", "size": 1, "success": True}):
            session._dump_spawned_children(elapsed=1.0)

        self.assertEqual(dumped, [])

    def test_a_child_is_only_dumped_once(self) -> None:
        # The watcher ticks twice a second; without this the same process would
        # be dumped on every tick for as long as it lived.
        session = self._session()
        self._known(session, [100, 9416])

        calls = []
        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             mock.patch.object(session, "_dump_one",
                               side_effect=lambda t, o, tr: calls.append(t["pid"]) or
                               {"pid": t["pid"], "name": "", "path": "x", "size": 1, "success": True}):
            session._dump_spawned_children(elapsed=77.0)
            session._dump_spawned_children(elapsed=77.5)
            session._dump_spawned_children(elapsed=78.0)

        self.assertEqual(calls, [9416])

    def test_a_child_that_dies_first_is_recorded_not_ignored(self) -> None:
        # "We saw a process we could not capture" is a finding. Silence here is
        # what let a staged payload produce a clean report.
        session = self._session()
        self._known(session, [100, 9416])

        with mock.patch.object(session, "_pid_alive", return_value=False):
            session._dump_spawned_children(elapsed=77.0)

        self.assertEqual(len(session._skipped), 1)
        self.assertEqual(session._skipped[0]["pid"], 9416)
        self.assertIn("exited before", session._skipped[0]["reason"])

    def test_caps_still_apply(self) -> None:
        session = self._session()
        session.max_total_mb = 0  # already over budget
        self._known(session, [100, 9416])

        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             mock.patch.object(session, "_dump_one") as dump_one:
            session._dump_spawned_children(elapsed=77.0)

        dump_one.assert_not_called()
        self.assertIn("cap", session._skipped[0]["reason"])


if __name__ == "__main__":
    unittest.main()
