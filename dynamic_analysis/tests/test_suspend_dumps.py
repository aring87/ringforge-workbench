"""A process is frozen while it is dumped, and always unfrozen afterwards.

Dumping a running process reads hundreds of megabytes while the target keeps
writing, so the image is a smear rather than a snapshot. More concretely, it
loses payloads: one real sample's second-generation process exited mid-read and
ProcDump reported ERROR_PARTIAL_COPY, writing nothing usable. A suspended
process cannot run the code that would exit it.

The resume path is the part that must not fail. A leaked suspension freezes the
sample for the rest of the run, which is a worse outcome than any dump failure
it could have prevented -- so it is asserted on every path, including the ones
where the dump itself blew up.
"""

import subprocess
import unittest
from unittest import mock

from dynamic_analysis.memory_dump import MemoryDumpSession, _decode_tool_output


class FakeProcess:
    def __init__(self, suspend_error=None, resume_error=None):
        self.suspended = False
        self.resumed = False
        self._suspend_error = suspend_error
        self._resume_error = resume_error

    def suspend(self):
        if self._suspend_error:
            raise self._suspend_error
        self.suspended = True

    def resume(self):
        if self._resume_error:
            raise self._resume_error
        self.resumed = True


class SuspendDuringDumpTests(unittest.TestCase):
    def _session(self, proc):
        session = MemoryDumpSession(output_dir="C:\\cases\\x\\memory", dump_offsets=[5])
        session.procdump = "procdump64.exe"
        session._procs = {7024: proc}
        return session

    def _target(self):
        return {"pid": 7024, "name": "sample.exe", "image": "C:\\s\\sample.exe"}

    def test_the_target_is_suspended_and_resumed(self) -> None:
        proc = FakeProcess()
        session = self._session(proc)

        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            record = session._dump_one(self._target(), 5, "process-spawn")

        self.assertTrue(proc.suspended)
        self.assertTrue(proc.resumed)
        self.assertTrue(record["suspended"])

    def test_it_is_resumed_even_when_procdump_times_out(self) -> None:
        proc = FakeProcess()
        session = self._session(proc)

        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("procdump", 300)):
            record = session._dump_one(self._target(), 5, "scheduled")

        self.assertTrue(proc.resumed, "a timed-out dump left the sample frozen")
        self.assertIn("timed out", record["error"])

    def test_it_is_resumed_even_when_the_dump_raises(self) -> None:
        proc = FakeProcess()
        session = self._session(proc)

        with mock.patch("subprocess.run", side_effect=OSError("boom")):
            session._dump_one(self._target(), 5, "scheduled")

        self.assertTrue(proc.resumed, "a failed dump left the sample frozen")

    def test_a_process_that_cannot_be_suspended_is_still_dumped(self) -> None:
        # Access denied, or the process died between discovery and the freeze.
        # An unsuspended dump beats no dump.
        proc = FakeProcess(suspend_error=RuntimeError("access denied"))
        session = self._session(proc)

        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            record = session._dump_one(self._target(), 5, "process-spawn")

        run.assert_called_once()
        self.assertFalse(record["suspended"])
        # Never suspended, so nothing to resume.
        self.assertFalse(proc.resumed)

    def test_a_failing_resume_does_not_propagate(self) -> None:
        # The process died during its own dump. It cannot be resumed and does
        # not need to be; what matters is that this does not raise into the run.
        proc = FakeProcess(resume_error=RuntimeError("no such process"))
        session = self._session(proc)

        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            session._dump_one(self._target(), 5, "process-spawn")


class ProcDumpOutputDecodingTests(unittest.TestCase):
    #: The real message from the dump that lost the race, which rendered as
    #: "D u m p   1   e r r o r ..." across ten rows of the report.
    MESSAGE = "Dump 1 error: Target process no longer running."

    def test_utf16_without_a_bom_is_decoded(self) -> None:
        self.assertEqual(_decode_tool_output(self.MESSAGE.encode("utf-16-le")), self.MESSAGE)

    def test_utf16_with_a_bom_is_decoded(self) -> None:
        self.assertEqual(_decode_tool_output(self.MESSAGE.encode("utf-16")), self.MESSAGE)

    def test_plain_utf8_still_works(self) -> None:
        self.assertEqual(_decode_tool_output(self.MESSAGE.encode("utf-8")), self.MESSAGE)

    def test_empty_output(self) -> None:
        self.assertEqual(_decode_tool_output(b""), "")


if __name__ == "__main__":
    unittest.main()
