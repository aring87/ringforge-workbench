"""A fixed window is a guess about dormancy, and dormancy is not fixed.

The same AgentTesla binary sat dormant for 21, 37, 38, 41, 44 and 83 seconds
across six runs of the same file against the same 180-second window. Nothing in
that spread says what the seventh run would have done, and a sample that sleeps
past the window produces a report that reads exactly like a sample that ran and
did nothing.

The window now extends while -- and only while -- waiting longer could still
change the result: the sample is running, and nothing has been observed yet. A
sample that has exited, or that has already spawned something, has given the run
what it came for, and extending would only lengthen every quiet run.

The important case is the last one: when the cap is reached with the sample
still running and still silent, that has to be recorded. Otherwise the run
reports a clean sample and the fact that it was never observed is lost.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from dynamic_analysis import orchestrator


class _FakeProcess:
    """A launched sample that exits after a set number of polls."""

    def __init__(self, exit_after_polls: int | None = None, returncode: int = 0):
        self.pid = 4242
        self._polls = 0
        self._exit_after = exit_after_polls
        self._returncode = returncode
        self.terminated = False

    def poll(self):
        self._polls += 1
        if self._exit_after is not None and self._polls > self._exit_after:
            return self._returncode
        return None

    def terminate(self):
        self.terminated = True


class _Clock:
    """Monotonic time that advances a fixed step per sleep, so no test waits."""

    def __init__(self, step: float = 1.0):
        self.now = 0.0
        self.step = step

    def monotonic(self) -> float:
        return self.now

    def sleep(self, _seconds: float) -> None:
        self.now += self.step


class ObservationWindowTests(unittest.TestCase):
    def _run(self, process: _FakeProcess, **kwargs) -> dict:
        clock = _Clock()
        with TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.exe"
            sample.write_bytes(b"MZ")

            with mock.patch.object(orchestrator.subprocess, "Popen", return_value=process), \
                 mock.patch.object(orchestrator.time, "monotonic", clock.monotonic), \
                 mock.patch.object(orchestrator.time, "sleep", clock.sleep):
                return orchestrator.run_sample(
                    sample,
                    timeout_seconds=kwargs.pop("timeout_seconds", 30),
                    minimum_observation_seconds=kwargs.pop("minimum_observation_seconds", 5),
                    post_exit_observation_seconds=kwargs.pop("post_exit_observation_seconds", 5),
                    **kwargs,
                )

    def test_a_dormant_sample_gets_more_time(self) -> None:
        # Still running, nothing observed: the one case where waiting longer
        # can change what the run finds.
        result = self._run(
            _FakeProcess(),
            timeout_seconds=30,
            max_observation_seconds=90,
            observation_extension_seconds=30,
            activity_probe=lambda: False,
        )

        self.assertTrue(result["extended"])
        self.assertEqual(result["window_seconds"], 90)
        self.assertEqual(result["ended_because"], "extension_cap_reached")

    def test_the_cap_is_honoured(self) -> None:
        result = self._run(
            _FakeProcess(),
            timeout_seconds=30,
            max_observation_seconds=60,
            observation_extension_seconds=30,
            activity_probe=lambda: False,
        )

        self.assertEqual(result["window_seconds"], 60)
        self.assertLessEqual(result["elapsed_seconds"], 61)

    def test_reaching_the_cap_while_silent_is_recorded(self) -> None:
        # The whole point. A clean-looking report from an unobserved sample has
        # to say that it was unobserved.
        result = self._run(
            _FakeProcess(),
            timeout_seconds=10,
            max_observation_seconds=20,
            observation_extension_seconds=10,
            activity_probe=lambda: False,
        )

        self.assertEqual(result["ended_because"], "extension_cap_reached")
        self.assertFalse(result["activity_observed"])
        self.assertFalse(result["sample_exited"])

    def test_a_sample_that_has_acted_is_not_extended(self) -> None:
        # It spawned something; the run got what it came for, and every further
        # second is a second added to a run that already succeeded.
        process = _FakeProcess()
        result = self._run(
            process,
            timeout_seconds=30,
            max_observation_seconds=300,
            activity_probe=lambda: True,
        )

        self.assertFalse(result["extended"])
        self.assertTrue(result["activity_observed"])
        self.assertEqual(result["ended_because"], "window_elapsed_after_activity")
        self.assertTrue(process.terminated)

    def test_an_exited_sample_is_not_extended(self) -> None:
        # Post-exit observation governs this case; extending a window for a
        # process that is gone waits on nothing.
        result = self._run(
            _FakeProcess(exit_after_polls=2, returncode=0),
            timeout_seconds=60,
            minimum_observation_seconds=5,
            post_exit_observation_seconds=5,
            max_observation_seconds=300,
            activity_probe=lambda: False,
        )

        self.assertFalse(result["extended"])
        self.assertTrue(result["sample_exited"])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["ended_because"], "post_exit_observation_complete")

    def test_without_a_probe_the_window_stays_fixed(self) -> None:
        # No memory dump watcher means no way to tell dormant from finished.
        # Extending on no evidence would turn every quiet run into a long one.
        result = self._run(
            _FakeProcess(),
            timeout_seconds=30,
            max_observation_seconds=300,
            activity_probe=None,
        )

        self.assertFalse(result["adaptive_available"])
        self.assertFalse(result["extended"])
        self.assertEqual(result["window_seconds"], 30)
        self.assertEqual(result["ended_because"], "window_elapsed")

    def test_adaptive_can_be_switched_off(self) -> None:
        result = self._run(
            _FakeProcess(),
            timeout_seconds=30,
            max_observation_seconds=300,
            adaptive_observation=False,
            activity_probe=lambda: False,
        )

        self.assertFalse(result["extended"])
        self.assertEqual(result["window_seconds"], 30)

    def test_a_probe_that_throws_does_not_end_the_run(self) -> None:
        # A broken probe must cost the extension decision and nothing else.
        def _angry() -> bool:
            raise RuntimeError("psutil handle gone")

        result = self._run(
            _FakeProcess(),
            timeout_seconds=10,
            max_observation_seconds=20,
            observation_extension_seconds=10,
            activity_probe=_angry,
        )

        self.assertFalse(result["activity_observed"])
        self.assertEqual(result["ended_because"], "extension_cap_reached")

    def test_activity_is_recorded_even_when_the_window_never_expires(self) -> None:
        # The Formbook run ended through post-exit observation at 144s of a
        # 180s window, so the extension branch never ran and the probe was
        # never consulted. The record said activity_observed: false for a
        # sample that had spawned powershell.exe, RegSvcs.exe and two
        # WerFault.exe. "Never asked" must not read as "nothing happened".
        result = self._run(
            _FakeProcess(exit_after_polls=2, returncode=0),
            timeout_seconds=180,
            minimum_observation_seconds=5,
            post_exit_observation_seconds=5,
            max_observation_seconds=600,
            activity_probe=lambda: True,
        )

        self.assertEqual(result["ended_because"], "post_exit_observation_complete")
        self.assertLess(result["elapsed_seconds"], 180)
        self.assertTrue(result["activity_observed"])

    def test_a_genuinely_quiet_sample_still_reports_no_activity(self) -> None:
        # The other half: asking the probe must not turn every run into one
        # that claims activity.
        result = self._run(
            _FakeProcess(exit_after_polls=2, returncode=0),
            timeout_seconds=180,
            minimum_observation_seconds=5,
            post_exit_observation_seconds=5,
            activity_probe=lambda: False,
        )

        self.assertFalse(result["activity_observed"])

    def test_activity_seen_once_stays_seen(self) -> None:
        # A loader that spawns and collapses has acted. A probe reading only
        # live children would go back to False, and the window would then run
        # to the cap waiting for behaviour that already happened.
        answers = iter([True, False, False, False, False, False])
        result = self._run(
            _FakeProcess(),
            timeout_seconds=10,
            max_observation_seconds=60,
            observation_extension_seconds=10,
            activity_probe=lambda: next(answers, False),
        )

        self.assertTrue(result["activity_observed"])
        self.assertFalse(result["extended"])


if __name__ == "__main__":
    unittest.main()
