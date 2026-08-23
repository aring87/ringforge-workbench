"""A dump record must not imply a death it never observed.

The root exiting triggers a dump of **everything still alive beneath it**, so
those records describe live processes. The trigger was called `process-exit` and
the file was suffixed `_exit`, which reads as a statement about the process in
the record. It is a statement about the *tree*.

`SecurityHealthHost.exe_7972_t161_exit.dmp` was read across four runs of `0bw`
as evidence the payload exited at t161. It had not. It was still running an hour
later, holding the guest's clipboard, and was only found by asking the guest's
process table directly. The 36-second "lifetime" derived from that filename was
the *loader* exiting 36 seconds after injecting -- a real and consistent
behaviour, attributed to the wrong process.

Nothing was broken. `_pid_alive` has always used psutil rather than ProcDump's
output, and `_dump_tree` has always dumped only live processes -- the watcher
knew. The name was the defect, and these hold it to saying what it means.
"""

import unittest
from tempfile import TemporaryDirectory

from dynamic_analysis.memory_dump import TRIGGER_SUFFIXES, MemoryDumpSession


class TriggerNamingTests(unittest.TestCase):
    def test_the_root_exit_suffix_does_not_claim_the_process_exited(self) -> None:
        # `_exit` on a live process's image is the whole bug, in one filename.
        self.assertEqual(TRIGGER_SUFFIXES["root-exit"], "_rootexit")

    def test_the_old_suffix_is_still_resolvable(self) -> None:
        # A four-run misreading is exactly when someone goes back to old dumps,
        # so images written before the rename must still map.
        self.assertEqual(TRIGGER_SUFFIXES["process-exit"], "_exit")

    def test_every_trigger_has_a_distinct_suffix(self) -> None:
        # Two dumps of one process in the same second must not collide: that is
        # what the suffix is for, and a duplicate would silently overwrite one.
        self.assertEqual(len(set(TRIGGER_SUFFIXES.values())),
                         len(TRIGGER_SUFFIXES))

    def test_the_old_trigger_name_is_gone_from_the_watcher(self) -> None:
        # Kept in the suffix table so images from earlier runs still map, but
        # nothing should emit it any more.
        import inspect

        from dynamic_analysis import memory_dump

        source = inspect.getsource(memory_dump)
        self.assertIn('trigger="root-exit"', source)
        self.assertNotIn('trigger="process-exit"', source)


class AliveAtDumpTests(unittest.TestCase):
    """The record says whether *this* process was alive, not the tree."""

    def test_the_field_is_recorded(self) -> None:
        import inspect

        from dynamic_analysis import memory_dump

        source = inspect.getsource(memory_dump)
        self.assertIn('"alive_at_dump"', source)

    def test_a_dead_pid_reads_as_not_alive(self) -> None:
        # The half that matters for reading old evidence: a record claiming
        # aliveness must be able to say no.
        with TemporaryDirectory() as tmp:
            session = self._never_seen_pid_session(tmp)

            self.assertFalse(session._pid_alive(999999))
            self.assertFalse(session._pid_alive(None))

    def _never_seen_pid_session(self, tmp: str) -> MemoryDumpSession:
        session = MemoryDumpSession(output_dir=tmp, dump_offsets=[5])
        session._procs = {}
        return session


if __name__ == "__main__":
    unittest.main()
