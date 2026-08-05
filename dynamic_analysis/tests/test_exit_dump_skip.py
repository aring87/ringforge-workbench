"""A dump we chose not to take has to say so.

The root exiting triggers an extra dump of whatever is still alive, and it is
deliberately suppressed when a scheduled offset falls on the same tick -- the
two would be near-identical images. That logic is right. What was missing is
the record.

A Formbook run exited at roughly +24s with the +25s offset due on the same
tick. The exit dump was suppressed, the scheduled dump covered only the
surviving children, and the sample's own process was captured exactly once at
+5s -- before it had spawned powershell.exe or RegSvcs.exe. There is no image
of that sample after it staged anything.

Nothing in the report said so. `skipped` listed two children and not the root,
so "we chose not to take it" looked identical to "there was nothing to take" --
against the rule the rest of the pipeline follows everywhere else.
"""

import unittest
from tempfile import TemporaryDirectory

from dynamic_analysis.memory_dump import MemoryDumpSession


class ExitDumpSkipTests(unittest.TestCase):
    def _session(self, tmp: str) -> MemoryDumpSession:
        session = MemoryDumpSession(output_dir=tmp, dump_offsets=[5, 25])
        session._root_pid = 8544
        session._known = {
            8544: {"pid": 8544, "name": "sample.exe", "image": "C:\\samples\\sample.exe"}
        }
        return session

    def test_a_suppressed_exit_dump_is_recorded(self) -> None:
        with TemporaryDirectory() as tmp:
            session = self._session(tmp)

            # What the watcher does when the root is gone and +25s is due.
            session._root_exit_handled = True
            session._record_skip(
                {"pid": session._root_pid, "name": "sample.exe"},
                24,
                "exit dump not taken: a scheduled dump was due on the same tick (+25s)",
            )

            skipped = session.stop(timeout=1)["skipped"]

        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["pid"], 8544)
        self.assertIn("exit dump not taken", skipped[0]["reason"])
        self.assertIn("+25s", skipped[0]["reason"])

    def test_the_skip_names_the_process_it_belongs_to(self) -> None:
        # An entry that cannot be tied to a process is not much better than no
        # entry: the reader has to know *which* image is missing.
        with TemporaryDirectory() as tmp:
            session = self._session(tmp)
            session._record_skip(
                {"pid": session._root_pid, "name": "sample.exe"}, 24, "exit dump not taken"
            )
            skipped = session.stop(timeout=1)["skipped"]

        self.assertEqual(skipped[0]["name"], "sample.exe")
        self.assertEqual(skipped[0]["offset_seconds"], 24)


if __name__ == "__main__":
    unittest.main()
