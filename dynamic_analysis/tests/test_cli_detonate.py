"""`ringforge detonate`, which is the subcommand that actually runs a sample.

**Why it exists at all.** `scan` never executes anything, and for its first
102 samples the run controller's guest agent called only `scan` and
`combine`. Every swept sample was statically analysed and none was detonated,
which nobody noticed because a case folder full of capa and FLOSS output
looks like a finished analysis until you read `modules_run`.

The orchestrator is never really invoked here -- these tests run on a
developer's host, and the whole point of this subcommand is that it executes
malware. It is mocked, and what is asserted is the wiring: that the config
handed to it is the one `run_config` builds, that a refusal is a refusal, and
that a containment failure is distinguishable from an ordinary one.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ringforge.cli import main


class DetonateWiring(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.sample = self.tmp / "thing.exe"
        self.sample.write_bytes(b"MZ not really")
        self.case = self.tmp / "cases" / "thing"

    def run_detonate(self, *extra, summary=None, side_effect=None):
        """Drive the subcommand with the orchestrator replaced."""
        runner = mock.Mock(return_value=summary or {"verdict": "No Evidence"})
        if side_effect is not None:
            runner.side_effect = side_effect
        with mock.patch("dynamic_analysis.orchestrator.run_dynamic_analysis",
                        runner):
            code = main(["detonate", str(self.sample),
                         "--case-dir", str(self.case), "--quiet", *extra])
        return code, runner

    def test_it_runs_the_sample_through_the_orchestrator(self) -> None:
        code, runner = self.run_detonate()
        self.assertEqual(0, code)
        runner.assert_called_once()

    def test_the_config_is_the_one_run_config_builds(self) -> None:
        # Not a hand-rolled dict: the GUI and the guest have to agree, or a
        # corpus is configured differently from the runs it is compared with.
        from dynamic_analysis.run_config import build_config

        _, runner = self.run_detonate()
        passed = runner.call_args.args[0]
        expected = build_config(self.sample, self.case)
        self.assertEqual(expected, passed)

    def test_the_timeout_can_be_overridden_per_run(self) -> None:
        _, runner = self.run_detonate("--timeout", "240")
        self.assertEqual(240, runner.call_args.args[0]["timeout_seconds"])

    def test_the_case_folder_is_created(self) -> None:
        self.assertFalse(self.case.exists())
        self.run_detonate()
        self.assertTrue(self.case.is_dir())

    def test_a_missing_sample_is_refused_before_anything_runs(self) -> None:
        runner = mock.Mock()
        with mock.patch("dynamic_analysis.orchestrator.run_dynamic_analysis",
                        runner):
            code = main(["detonate", str(self.tmp / "nope.exe"), "--quiet"])
        self.assertEqual(2, code)
        runner.assert_not_called()

    def test_a_directory_is_not_a_sample(self) -> None:
        runner = mock.Mock()
        with mock.patch("dynamic_analysis.orchestrator.run_dynamic_analysis",
                        runner):
            code = main(["detonate", str(self.tmp), "--quiet"])
        self.assertEqual(2, code)
        runner.assert_not_called()

    def test_a_containment_failure_has_its_own_exit_code(self) -> None:
        # A run refused because the guest was not contained is not the same
        # as one that failed, and a sweep has to be able to stop rather than
        # carry on detonating on a machine that can reach the network. The
        # guest agent keys off this: exit 4 is fatal, anything else is a
        # recorded coverage gap.
        from dynamic_analysis.orchestrator import ContainmentError

        code, _ = self.run_detonate(
            side_effect=ContainmentError("nic1 is connected"))
        self.assertEqual(4, code)

    def test_json_goes_to_stdout_alone(self) -> None:
        import contextlib
        import io
        import json

        out, err = io.StringIO(), io.StringIO()
        runner = mock.Mock(return_value={"verdict": "Needs Review", "run_id": "r1"})
        with mock.patch("dynamic_analysis.orchestrator.run_dynamic_analysis",
                        runner), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["detonate", str(self.sample),
                         "--case-dir", str(self.case), "--json"])
        self.assertEqual(0, code)
        # Parses cleanly, which is the contract the rest of the CLI keeps:
        # status to stderr, the payload alone on stdout.
        self.assertEqual("Needs Review",
                         json.loads(out.getvalue())["verdict"])

    def test_the_status_stream_stays_off_stdout(self) -> None:
        import contextlib
        import io
        import json

        out, err = io.StringIO(), io.StringIO()

        def talkative(config, status_cb=None, cancel_event=None):
            if status_cb:
                status_cb("starting procmon")
            return {"verdict": "No Evidence"}

        with mock.patch("dynamic_analysis.orchestrator.run_dynamic_analysis",
                        talkative), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            main(["detonate", str(self.sample),
                  "--case-dir", str(self.case), "--json"])
        self.assertIn("starting procmon", err.getvalue())
        json.loads(out.getvalue())   # would raise if status leaked into it


if __name__ == "__main__":
    unittest.main()
