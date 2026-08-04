"""FakeNet's stderr must never be a pipe nobody reads.

The simulated internet answered for about four seconds of every run and then
went silent -- DNS and TCP together, the log stopping mid-request, listeners up
but frozen. A sample's C2 lookup timed out against a FakeNet that was running
and healthy by every check we had.

stderr was a subprocess.PIPE, read only in the startup branch that catches an
immediate exit. Once FakeNet survived the grace period nothing drained it
again. FakeNet echoes every intercepted request including full HTTP headers, so
the OS buffer filled in seconds and FakeNet blocked forever on its next write.

It worked when started by hand because a console drains stderr continuously,
which is exactly why the manual test kept passing while every run failed.

A file cannot fill. It also keeps the output that would have identified this in
one run instead of five.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dynamic_analysis.fakenet_runner import FakeNetSession


class _FakeProc:
    pid = 4242
    returncode = None

    def __init__(self, poll_value=None):
        self._poll = poll_value

    def poll(self):
        return self._poll

    def wait(self, timeout=None):
        return 0


class ExitCodeTests(unittest.TestCase):
    """The shutdown we ask for is not a failure.

    stop() sends CTRL_BREAK_EVENT, and a process that honours it exits with
    STATUS_CONTROL_C_EXIT. The first healthy run to reach the new exit-code
    check reported "FakeNet-NG exited with rc=3221225786" as an error, on a run
    where FakeNet had served an AgentTesla sample's FTP exfiltration from start
    to finish.
    """

    def _stop_with(self, code):
        tmp = Path(tempfile.mkdtemp())
        binary = tmp / "fakenet.exe"
        binary.write_bytes(b"stub")
        session = FakeNetSession(output_dir=tmp, fakenet_path=binary)

        with mock.patch("subprocess.Popen", return_value=_FakeProc()), \
             mock.patch("time.sleep"):
            session.start()

        session.process = _FakeProc(poll_value=code)
        return session.stop()

    def test_the_ctrl_break_exit_is_not_an_error(self) -> None:
        self.assertEqual(self._stop_with(3221225786)["error"], "")

    def test_its_signed_form_is_not_either(self) -> None:
        self.assertEqual(self._stop_with(-1073741510)["error"], "")

    def test_a_clean_exit_is_not_an_error(self) -> None:
        self.assertEqual(self._stop_with(0)["error"], "")

    def test_a_real_crash_is_still_reported(self) -> None:
        result = self._stop_with(1)

        self.assertIn("rc=1", result["error"])


class StderrIsNotAPipeTests(unittest.TestCase):
    def _start(self, poll_value=None):
        tmp = Path(tempfile.mkdtemp())
        binary = tmp / "fakenet.exe"
        binary.write_bytes(b"stub")
        session = FakeNetSession(output_dir=tmp, fakenet_path=binary)

        captured = {}

        def fake_popen(cmd, **kwargs):
            captured.update(kwargs)
            return _FakeProc(poll_value)

        with mock.patch("subprocess.Popen", side_effect=fake_popen), \
             mock.patch("time.sleep"):
            result = session.start()

        # The handle is real even though the process is not.
        self.addCleanup(session._close_stderr)
        return session, captured, result, tmp

    def test_stderr_is_never_a_pipe(self) -> None:
        _, captured, _, _ = self._start()

        self.assertIsNot(captured["stderr"], subprocess.PIPE)

    def test_stderr_goes_to_a_writable_file(self) -> None:
        _, captured, _, tmp = self._start()

        self.assertTrue(hasattr(captured["stderr"], "write"))
        self.assertTrue((tmp / "fakenet.stderr.log").exists())

    def test_stdout_stays_discarded(self) -> None:
        # DEVNULL cannot fill either, so it was never the problem.
        _, captured, _, _ = self._start()

        self.assertIs(captured["stdout"], subprocess.DEVNULL)

    def test_the_handle_is_released_on_stop(self) -> None:
        session, _, _, _ = self._start()

        stopped = session.stop()

        self.assertIsNone(session._stderr_handle)
        self.assertIn("stderr_path", stopped)

    def test_an_immediate_exit_still_reports_what_stderr_said(self) -> None:
        # The startup check used to read the pipe; it reads the file now.
        session, _, _, tmp = self._start(poll_value=1)
        (tmp / "fakenet.stderr.log").write_text("Access is denied", encoding="utf-8")

        message = session._read_stderr()

        self.assertIn("Access is denied", message)

    def test_reading_a_missing_stderr_file_is_not_an_error(self) -> None:
        session = FakeNetSession(output_dir=Path(tempfile.mkdtemp()))

        self.assertEqual(session._read_stderr(), "")

    def test_closing_twice_is_safe(self) -> None:
        session, _, _, _ = self._start()

        session._close_stderr()
        session._close_stderr()

        self.assertIsNone(session._stderr_handle)


if __name__ == "__main__":
    unittest.main()
