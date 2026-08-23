"""What is still running when the run ends has to be recorded.

Teardown terminates the launched root and nothing else, so anything the sample
injected outlives the run by design. That was never reported, and it is how two
detonations ended up in one clipboard log: the 19:57 payload was still running
-- and still rewriting the clipboard -- when the 21:08 run started. It was found
by reading the guest's process table by hand, four runs late.

`observation.sample_exited` cannot answer this. It means the *root* returned an
exit code, and for a `.ps1` sample the root is `powershell.exe`, which exits as
soon as it has injected. `SecurityHealthHost.exe` went on clipping for at least
an hour afterwards.
"""

import unittest
from tempfile import TemporaryDirectory

from dynamic_analysis.memory_dump import MemoryDumpSession


class SurvivorsAtTeardownTests(unittest.TestCase):
    def _session(self, tmp: str) -> MemoryDumpSession:
        session = MemoryDumpSession(output_dir=tmp, dump_offsets=[5])
        session._root_pid = 8544
        return session

    def test_the_field_is_always_present(self) -> None:
        # Absent-because-nothing-survived and absent-because-nobody-looked must
        # not be the same reading. That distinction is this file's whole point.
        with TemporaryDirectory() as tmp:
            result = self._session(tmp).stop(timeout=1)

        self.assertIn("descendants_alive_at_end", result)
        self.assertIn("root_alive_at_end", result)
        self.assertIsInstance(result["descendants_alive_at_end"], list)

    def test_dead_descendants_are_not_reported_as_survivors(self) -> None:
        # Pids that were never real cannot be alive, so an empty list here is a
        # genuine "nothing survived" rather than a failure to check.
        with TemporaryDirectory() as tmp:
            session = self._session(tmp)
            session._known = {
                8544: {"pid": 8544, "name": "powershell.exe"},
                999998: {"pid": 999998, "name": "SecurityHealthHost.exe"},
            }
            session._procs = {}

            result = session.stop(timeout=1)

        self.assertEqual(result["descendants_alive_at_end"], [])

    def test_the_root_is_never_listed_as_a_surviving_descendant(self) -> None:
        # The root is terminated by teardown and is reported separately. Listing
        # it among survivors would make the warning fire on every ordinary run,
        # and a warning that always fires is one nobody reads.
        with TemporaryDirectory() as tmp:
            session = self._session(tmp)
            session._known = {8544: {"pid": 8544, "name": "powershell.exe"}}

            result = session.stop(timeout=1)

        self.assertEqual(
            [p for p in result["descendants_alive_at_end"] if p["pid"] == 8544], []
        )

    def test_a_survivor_carries_enough_to_act_on(self) -> None:
        # "Something survived" is not actionable; a pid and a name are. The
        # operator has to be able to find it, and the reader has to be able to
        # tell a hollowed system binary from a leftover conhost.
        import os

        with TemporaryDirectory() as tmp:
            session = self._session(tmp)
            live = os.getpid()          # this test process: definitively alive
            session._known = {
                8544: {"pid": 8544, "name": "powershell.exe"},
                live: {"pid": live, "name": "pretend-payload.exe",
                       "image": "C:\\Windows\\System32\\pretend-payload.exe"},
            }

            import psutil  # the liveness check needs a real handle

            session._procs = {live: psutil.Process(live)}

            survivors = session.stop(timeout=1)["descendants_alive_at_end"]

        self.assertEqual(len(survivors), 1)
        self.assertEqual(survivors[0]["pid"], live)
        self.assertEqual(survivors[0]["name"], "pretend-payload.exe")
        self.assertTrue(survivors[0]["image"])


if __name__ == "__main__":
    unittest.main()
