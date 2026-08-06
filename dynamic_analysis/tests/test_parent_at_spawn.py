"""The one instant a loader is certainly holding its payload.

Two runs of the same sample, four days of offsets tuning, and the packer image
came down to luck. The parent's useful window is `[unpack, spawn + ~1s]` and this
sample's dormancy has been +20, +23, +24, +42, +48 and +60s, so a fixed offset is
inside that window or it is not:

* 06 Aug 20:23, dormancy +48s. Offsets 1, 25. The +25s dump of the root held
  `SmartOptimization.dll` -- 81,920 bytes, x86 .NET, the payload.
* 06 Aug 21:15, dormancy +23s. The same offsets. The root was imaged at +1s
  before it had unpacked, spawned `RegSvcs` at +23s, exited by +24s, and the +25s
  offset never came due for it. `unmapped_images: 0`, and nothing in the summary
  said the dump that would have held the payload was never taken.

So two changes, tested here. The parent is imaged at the moment it spawns a
child, which is a property of the technique rather than a guess about the clock;
and a process that exits with scheduled offsets still ahead of it says so.

Driven through MemoryDumpSession's selection logic with a fake tree, so these
assert the decision rather than ProcDump's behaviour.
"""

import unittest
from unittest import mock

from dynamic_analysis.memory_dump import MemoryDumpSession


class _Base(unittest.TestCase):
    def _session(self, offsets=(1, 25), tmp="C:\\cases\\x\\memory"):
        session = MemoryDumpSession(output_dir=tmp, dump_offsets=list(offsets))
        session._root_pid = 10488
        session._procdump = "procdump64.exe"
        return session

    def _tree(self, session, tree):
        """`tree` maps pid -> (name, parent_pid)."""
        session._known = {
            pid: {"pid": pid, "name": name, "image": "", "parent_pid": parent}
            for pid, (name, parent) in tree.items()
        }

    def _recorder(self, session, sink):
        return mock.patch.object(
            session,
            "_dump_one",
            side_effect=lambda t, o, tr: sink.append((t["pid"], o, tr)) or
            {"pid": t["pid"], "name": t.get("name", ""), "path": "x", "size": 1,
             "success": True},
        )


class ParentAtSpawnTests(_Base):
    def test_the_parent_is_imaged_when_it_starts_a_child(self) -> None:
        # The 21:15 run's shape: the root spawns RegSvcs at +23s. That is the
        # tick on which the root is holding the decrypted stage it is about to
        # write into the child.
        session = self._session()
        self._tree(session, {10488: ("sample.exe", 1468), 8428: ("RegSvcs.exe", 10488)})
        session._spawn_dumped.add(10488)

        dumped: list = []
        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             self._recorder(session, dumped):
            session._dump_spawned_children(elapsed=23.0)

        self.assertEqual(
            dumped,
            [(10488, 23, "parent-at-spawn"), (8428, 23, "process-spawn")],
        )

    def test_the_parent_comes_first(self) -> None:
        # Ordering is the deliberate part. A dump takes seconds and the root had
        # about one second left after spawning; the child's image has been an
        # empty shell on all seven runs, so it is the cheaper thing to lose.
        session = self._session()
        self._tree(session, {10488: ("sample.exe", 1468), 8428: ("RegSvcs.exe", 10488)})
        session._spawn_dumped.add(10488)

        dumped: list = []
        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             self._recorder(session, dumped):
            session._dump_spawned_children(elapsed=23.0)

        self.assertEqual(dumped[0][2], "parent-at-spawn")

    def test_three_children_in_fifteen_milliseconds_image_the_parent_once(self) -> None:
        # This loader's real shape. Three RegSvcs inside 15 ms would otherwise
        # produce three near-identical images of the parent.
        session = self._session()
        self._tree(session, {
            10488: ("sample.exe", 1468),
            8428: ("RegSvcs.exe", 10488),
            8429: ("RegSvcs.exe", 10488),
            8430: ("RegSvcs.exe", 10488),
        })
        session._spawn_dumped.add(10488)

        dumped: list = []
        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             self._recorder(session, dumped):
            session._dump_spawned_children(elapsed=23.0)

        parents = [pid for pid, _, trigger in dumped if trigger == "parent-at-spawn"]
        self.assertEqual(parents, [10488])

    def test_a_grandchild_images_its_own_parent(self) -> None:
        # RegSvcs -> WerFault. The parent that matters is the one that spawned,
        # not the root.
        session = self._session()
        self._tree(session, {
            10488: ("sample.exe", 1468),
            8428: ("RegSvcs.exe", 10488),
            10096: ("WerFault.exe", 8428),
        })
        session._spawn_dumped.update({10488, 8428})

        dumped: list = []
        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             self._recorder(session, dumped):
            session._dump_spawned_children(elapsed=26.0)

        self.assertIn((8428, 26, "parent-at-spawn"), dumped)

    def test_a_parent_gone_within_the_poll_interval_is_recorded(self) -> None:
        # It says the payload was in a process nobody could reach, which is not
        # the same as a process that held nothing.
        session = self._session()
        self._tree(session, {10488: ("sample.exe", 1468), 8428: ("RegSvcs.exe", 10488)})
        session._spawn_dumped.add(10488)

        with mock.patch.object(session, "_pid_alive", return_value=False):
            session._dump_spawned_children(elapsed=23.0)

        reasons = {s["pid"]: s["reason"] for s in session._skipped}
        self.assertIn("parent exited before", reasons[10488])
        self.assertIn("8428", reasons[10488])

    def test_caps_apply_and_are_recorded(self) -> None:
        session = self._session()
        session.max_total_mb = 0
        self._tree(session, {10488: ("sample.exe", 1468), 8428: ("RegSvcs.exe", 10488)})
        session._spawn_dumped.add(10488)

        with mock.patch.object(session, "_pid_alive", return_value=True), \
             mock.patch.object(session, "_working_set_mb", return_value=10), \
             mock.patch.object(session, "_dump_one") as dump_one:
            session._dump_spawned_children(elapsed=23.0)

        dump_one.assert_not_called()
        self.assertTrue(any("cap" in s["reason"] for s in session._skipped))

    def test_the_filename_says_which_dump_it_is(self) -> None:
        # A parent-at-spawn dump can land on the same whole second as a scheduled
        # one, and overwriting the image taken at the moment of injection with a
        # routine offset would lose exactly the wrong one.
        session = self._session()
        with mock.patch.object(session, "_suspend", return_value=False), \
             mock.patch("subprocess.run", side_effect=OSError("not run")):
            record = session._dump_one(
                {"pid": 10488, "name": "sample.exe"}, 23, "parent-at-spawn"
            )

        self.assertTrue(record["path"].endswith("sample.exe_10488_t23_atspawn.dmp"))


class OffsetsPendingAtExitTests(_Base):
    def test_a_process_that_exits_with_offsets_ahead_of_it_says_so(self) -> None:
        # The 21:15 hole exactly: dumped at +1s, gone before +25s, and the run
        # recorded 9 dumps, 1 skip, 2 failures and nothing about the missing image
        # of the packer.
        session = self._session(offsets=(1, 25))
        self._tree(session, {10488: ("sample.exe", 1468)})
        session._dumps.append({"pid": 10488, "success": True, "offset_seconds": 1})

        with mock.patch.object(session, "_pid_alive", return_value=False):
            session._record_offsets_pending_at_exit(elapsed=24.0, pending=[25])

        self.assertEqual(len(session._skipped), 1)
        self.assertEqual(session._skipped[0]["pid"], 10488)
        self.assertIn("+25s", session._skipped[0]["reason"])
        self.assertIn("still pending", session._skipped[0]["reason"])

    def test_a_process_still_alive_is_not_recorded(self) -> None:
        session = self._session(offsets=(1, 25))
        self._tree(session, {10488: ("sample.exe", 1468)})

        with mock.patch.object(session, "_pid_alive", return_value=True):
            session._record_offsets_pending_at_exit(elapsed=24.0, pending=[25])

        self.assertEqual(session._skipped, [])

    def test_nothing_pending_means_nothing_was_lost(self) -> None:
        session = self._session(offsets=(1, 25))
        self._tree(session, {10488: ("sample.exe", 1468)})

        with mock.patch.object(session, "_pid_alive", return_value=False):
            session._record_offsets_pending_at_exit(elapsed=30.0, pending=[])

        self.assertEqual(session._skipped, [])

    def test_it_is_recorded_once_not_on_every_poll(self) -> None:
        session = self._session(offsets=(1, 25))
        self._tree(session, {10488: ("sample.exe", 1468)})
        session._dumps.append({"pid": 10488, "success": True, "offset_seconds": 1})

        with mock.patch.object(session, "_pid_alive", return_value=False):
            for _ in range(5):
                session._record_offsets_pending_at_exit(elapsed=24.0, pending=[25])

        self.assertEqual(len(session._skipped), 1)

    def test_a_root_that_was_never_dumped_keeps_its_own_record(self) -> None:
        # `_record_root_never_dumped` says something more specific about that
        # case, and two entries about one process is how a skip list stops being
        # read.
        session = self._session(offsets=(1, 25))
        self._tree(session, {10488: ("sample.exe", 1468)})

        with mock.patch.object(session, "_pid_alive", return_value=False):
            session._record_offsets_pending_at_exit(elapsed=24.0, pending=[25])

        self.assertEqual(session._skipped, [])

    def test_a_child_that_exits_early_is_recorded_too(self) -> None:
        # Not only the root. A hollowed child that dies before a late offset took
        # that image with it just as surely.
        session = self._session(offsets=(1, 25))
        self._tree(session, {10488: ("sample.exe", 1468), 8428: ("RegSvcs.exe", 10488)})
        session._dumps.append({"pid": 8428, "success": True, "offset_seconds": 23})

        alive = {10488: True, 8428: False}
        with mock.patch.object(session, "_pid_alive", side_effect=lambda pid: alive[pid]):
            session._record_offsets_pending_at_exit(elapsed=24.0, pending=[25])

        self.assertEqual([s["pid"] for s in session._skipped], [8428])


if __name__ == "__main__":
    unittest.main()
