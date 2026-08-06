"""A hollowed child has to be dumped twice: when it appears, and once it is full.

Reconstructed from three runs of one .NET loader. It creates RegSvcs.exe
suspended, unmaps the original image, writes a stage-2 payload in and resumes.
The spawn dump fires the moment the child is seen, which is necessarily before
any of that has happened, so all three runs produced ~15 MB of untouched host
image and the payload was only ever recovered from a WER crash dump -- an
artifact that exists only because that particular payload crashed.

A later fixed offset cannot substitute: the same binary spawned its target at
+20s, +24s and +42s, so an offset tuned to one run misses the next. Measured
from the spawn, the delay is a property of the technique rather than of the
sample's dormancy.

Like test_spawn_dumps, these drive the selection logic with a fake process tree
rather than launching processes, so they assert the decision rather than
ProcDump's behaviour.
"""

import unittest
from unittest import mock

from dynamic_analysis.memory_dump import MemoryDumpSession


class SpawnRedumpSelectionTests(unittest.TestCase):
    def _session(self, redump=10, tmp="C:\\cases\\x\\memory"):
        session = MemoryDumpSession(
            output_dir=tmp, dump_offsets=[5, 25], spawn_redump_seconds=redump
        )
        session._root_pid = 100
        session._procdump = "procdump64.exe"
        return session

    def _known(self, session, pids):
        session._known = {
            pid: {"pid": pid, "name": f"p{pid}.exe", "image": "", "parent_pid": 100}
            for pid in pids
        }

    def _dump_recorder(self, session, sink):
        return mock.patch.object(
            session,
            "_dump_one",
            side_effect=lambda t, o, tr: sink.append((t["pid"], o, tr)) or
            {"pid": t["pid"], "name": "", "path": "x", "size": 1, "success": True},
        )

    def test_a_child_is_dumped_again_once_the_delay_has_passed(self) -> None:
        session = self._session(redump=10)
        self._known(session, [100, 9416])

        dumped: list = []
        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             self._dump_recorder(session, dumped):
            session._dump_spawned_children(elapsed=20.0)
            session._dump_spawn_redumps(elapsed=20.5)   # too early
            session._dump_spawn_redumps(elapsed=30.5)   # due

        self.assertEqual(
            dumped,
            [(9416, 20, "process-spawn"), (9416, 30, "spawn-redump")],
        )

    def test_the_delay_runs_from_the_spawn_not_from_launch(self) -> None:
        # The whole reason this is not another fixed offset. Two children of the
        # same sample appearing 22s apart are each re-dumped 10s after their own
        # first sighting.
        session = self._session(redump=10)
        self._known(session, [100, 9416])

        dumped: list = []
        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             self._dump_recorder(session, dumped):
            session._dump_spawned_children(elapsed=20.0)
            self._known(session, [100, 9416, 5120])
            session._dump_spawned_children(elapsed=42.0)
            session._dump_spawn_redumps(elapsed=42.5)
            session._dump_spawn_redumps(elapsed=52.5)

        self.assertEqual(
            [(pid, offset) for pid, offset, trigger in dumped if trigger == "spawn-redump"],
            [(9416, 42), (5120, 52)],
        )

    def test_a_child_is_only_re_dumped_once(self) -> None:
        session = self._session(redump=10)
        self._known(session, [100, 9416])

        dumped: list = []
        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             self._dump_recorder(session, dumped):
            session._dump_spawned_children(elapsed=20.0)
            session._dump_spawn_redumps(elapsed=30.5)
            session._dump_spawn_redumps(elapsed=31.0)
            session._dump_spawn_redumps(elapsed=40.0)

        self.assertEqual(
            [pid for pid, _, trigger in dumped if trigger == "spawn-redump"], [9416]
        )

    def test_the_root_is_never_re_dumped(self) -> None:
        # It is not queued in the first place: only children the spawn dump
        # handled are, and that excludes the root.
        session = self._session(redump=10)
        self._known(session, [100])

        dumped: list = []
        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             self._dump_recorder(session, dumped):
            session._dump_spawned_children(elapsed=1.0)
            session._dump_spawn_redumps(elapsed=30.0)

        self.assertEqual(dumped, [])

    def test_a_child_that_dies_first_is_recorded_not_ignored(self) -> None:
        # This is the loader's own shape: the hollowed process faults and takes
        # the payload with it. "The window closed before we could look again"
        # has to be distinguishable from "we looked and it was empty".
        session = self._session(redump=10)
        self._known(session, [100, 9416])

        alive = iter([True, False])
        with mock.patch.object(session, "_pid_alive", side_effect=lambda pid: next(alive)), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             mock.patch.object(session, "_dump_one",
                               return_value={"pid": 9416, "name": "", "path": "x",
                                             "size": 1, "success": True}):
            session._dump_spawned_children(elapsed=20.0)
            session._dump_spawn_redumps(elapsed=30.5)

        self.assertEqual(len(session._skipped), 1)
        self.assertEqual(session._skipped[0]["pid"], 9416)
        self.assertIn("exited before its +10s re-dump", session._skipped[0]["reason"])

    def test_a_child_the_spawn_dump_could_not_take_is_not_queued(self) -> None:
        # It has been recorded as skipped once already; a re-dump could only
        # record the same thing a second time.
        session = self._session(redump=10)
        self._known(session, [100, 9416])

        with mock.patch.object(session, "_pid_alive", return_value=False):
            session._dump_spawned_children(elapsed=20.0)
            session._dump_spawn_redumps(elapsed=30.5)

        self.assertEqual(len(session._skipped), 1)
        self.assertIn("exited before it could be dumped", session._skipped[0]["reason"])

    def test_an_owed_redump_is_recorded_when_the_run_ends_first(self) -> None:
        # The watcher stops when the tree collapses or the window closes. A
        # re-dump still owed at that point is silence, and silence here would
        # look exactly like a dump that found nothing.
        session = self._session(redump=10)
        self._known(session, [100, 9416])

        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             mock.patch.object(session, "_dump_one",
                               return_value={"pid": 9416, "name": "", "path": "x",
                                             "size": 1, "success": True}):
            session._dump_spawned_children(elapsed=20.0)
            session._flush_pending_redumps(elapsed=24.0)

        self.assertEqual(len(session._skipped), 1)
        self.assertIn("observation ended before", session._skipped[0]["reason"])

    def test_nothing_is_owed_twice(self) -> None:
        session = self._session(redump=10)
        self._known(session, [100, 9416])

        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             mock.patch.object(session, "_dump_one",
                               return_value={"pid": 9416, "name": "", "path": "x",
                                             "size": 1, "success": True}):
            session._dump_spawned_children(elapsed=20.0)
            session._flush_pending_redumps(elapsed=24.0)
            session._flush_pending_redumps(elapsed=24.0)

        self.assertEqual(len(session._skipped), 1)

    def test_zero_disables_it(self) -> None:
        session = self._session(redump=0)
        self._known(session, [100, 9416])

        dumped: list = []
        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             self._dump_recorder(session, dumped):
            session._dump_spawned_children(elapsed=20.0)
            session._dump_spawn_redumps(elapsed=90.0)
            session._flush_pending_redumps(elapsed=90.0)

        self.assertEqual([tr for _, _, tr in dumped], ["process-spawn"])
        self.assertEqual(session._skipped, [])

    def test_caps_still_apply(self) -> None:
        session = self._session(redump=10)
        session.max_total_mb = 0  # already over budget
        session._spawn_seen = {9416: 20.0}
        self._known(session, [100, 9416])

        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             mock.patch.object(session, "_dump_one") as dump_one:
            session._dump_spawn_redumps(elapsed=30.5)

        dump_one.assert_not_called()
        self.assertIn("cap", session._skipped[0]["reason"])

    def test_a_root_that_was_never_dumped_is_recorded(self) -> None:
        # The Remcos run wrote five dumps, all of the dropped child, while the
        # parent -- the process that did the unpacking -- exited at ~t1 with the
        # first offset at +5. The root has only one route to being dumped: an
        # offset coming due while it is alive. The spawn dump excludes it and
        # the exit dump runs when it is already unreadable. `dumps_skipped` read
        # 0, so "the packer held nothing" and "the packer was never opened"
        # looked identical.
        session = self._session()
        self._known(session, [100, 9416])

        session._record_root_never_dumped(elapsed=1.4)

        self.assertEqual(len(session._skipped), 1)
        self.assertEqual(session._skipped[0]["pid"], 100)
        self.assertIn("never dumped", session._skipped[0]["reason"])
        self.assertIn("+5s", session._skipped[0]["reason"])

    def test_a_root_that_was_dumped_is_not_recorded(self) -> None:
        session = self._session()
        self._known(session, [100, 9416])
        session._dumps.append({"pid": 100, "success": True})

        session._record_root_never_dumped(elapsed=30.0)

        self.assertEqual(session._skipped, [])

    def test_the_two_images_of_one_pid_do_not_collide_on_disk(self) -> None:
        # The point of the pair is comparing them, which needs both files. A
        # scheduled offset landing on the same second as the re-dump would
        # otherwise overwrite the only image taken after the payload landed.
        session = self._session(redump=10)
        target = {"pid": 9416, "name": "RegSvcs.exe", "image": "", "parent_pid": 100}

        with mock.patch.object(session, "_suspend", return_value=False), \
             mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            scheduled = session._dump_one(target, 30, "scheduled")
            redump = session._dump_one(target, 30, "spawn-redump")

        self.assertNotEqual(scheduled["path"], redump["path"])
        self.assertTrue(redump["path"].endswith("_redump.dmp"))


if __name__ == "__main__":
    unittest.main()
