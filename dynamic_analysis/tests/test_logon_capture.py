import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from dynamic_analysis.logon_capture import (
    DEFAULT_WINDOW_SECONDS,
    MAX_WINDOW_SECONDS,
    TASK_NAME,
    build_arm_argv,
    build_capture_argv,
    build_disarm_argv,
    empty_manifest,
    run_capture,
)

REGISTRY_READS_PMC = (
    Path(__file__).resolve().parent.parent.parent
    / "tools" / "procmon-configs" / "dynamic_registry_reads.pmc"
)


class TaskCommandTests(unittest.TestCase):
    def test_the_task_triggers_on_start_not_on_logon(self) -> None:
        # The whole point. Racing the sample's own ONLOGON task is a coin toss,
        # and losing it misses the first seconds -- which is where `ce0d08be...`
        # did its work both times. ONSTART is running before a session exists.
        argv = build_arm_argv(["python.exe", "capture.py"])

        self.assertIn("/sc", argv)
        self.assertEqual(argv[argv.index("/sc") + 1], "ONSTART")
        self.assertNotIn("ONLOGON", argv)

    def test_it_runs_as_system_and_elevated(self) -> None:
        # Procmon needs administrator to load its driver, and the capture has to
        # exist before any user logs on.
        argv = build_arm_argv(["python.exe", "capture.py"])

        self.assertEqual(argv[argv.index("/ru") + 1], "SYSTEM")
        self.assertEqual(argv[argv.index("/rl") + 1], "HIGHEST")

    def test_rearming_replaces_rather_than_failing(self) -> None:
        self.assertIn("/f", build_arm_argv(["python.exe", "capture.py"]))

    def test_the_task_name_is_not_disguised(self) -> None:
        # An analyzer artifact that hides from the analyzer is how a
        # contaminated run becomes an unexplainable one.
        self.assertIn(TASK_NAME, build_arm_argv(["python.exe", "capture.py"]))
        self.assertIn(TASK_NAME, build_disarm_argv())

    def test_the_capture_command_carries_the_config_when_given(self) -> None:
        argv = build_capture_argv(
            "python.exe", "logon_capture.py", r"C:\out", r"C:\rf_trace64.exe",
            window_seconds=120, config_path=r"C:\reads.pmc",
        )

        self.assertIn("--capture", argv)
        self.assertEqual(argv[argv.index("--window") + 1], "120")
        self.assertEqual(argv[argv.index("--config") + 1], r"C:\reads.pmc")
        self.assertEqual(argv[argv.index("--procmon") + 1], r"C:\rf_trace64.exe")

    def test_no_config_means_no_config_flag(self) -> None:
        argv = build_capture_argv("python.exe", "s.py", r"C:\out", r"C:\p.exe")

        self.assertNotIn("--config", argv)


class ManifestTests(unittest.TestCase):
    def test_a_capture_that_never_ran_says_so(self) -> None:
        # Not an empty event list that reads like a quiet boot. The distinction
        # this module exists to preserve at the run level it must also preserve
        # about itself.
        manifest = empty_manifest("task did not fire")

        self.assertFalse(manifest["completed"])
        self.assertEqual(manifest["reason"], "task did not fire")
        self.assertFalse(manifest["procmon_filter"]["captures_registry_reads"])

    def test_a_failed_capture_writes_a_manifest_rather_than_raising(self) -> None:
        # A scheduled task that dies leaves nothing behind, and nothing is
        # indistinguishable from a boot where the sample did nothing.
        with TemporaryDirectory() as tmp:
            with mock.patch(
                "dynamic_analysis.procmon_runner.start_procmon_capture",
                side_effect=OSError("Procmon not found"),
            ):
                manifest = run_capture(tmp, r"C:\missing.exe", window_seconds=1)

            written = json.loads((Path(tmp) / "logon_capture.json").read_text(encoding="utf-8"))

        self.assertFalse(manifest["completed"])
        self.assertIn("Procmon not found", manifest["reason"])
        self.assertEqual(written["reason"], manifest["reason"])

    def test_the_manifest_records_whether_reads_could_have_been_seen(self) -> None:
        # Read from the file, not the filename. A capture that could not have
        # seen a registry read must never read as having seen none.
        calls = []
        with TemporaryDirectory() as tmp:
            with mock.patch("dynamic_analysis.procmon_runner.start_procmon_capture"), \
                 mock.patch("dynamic_analysis.procmon_runner.terminate_procmon_capture"), \
                 mock.patch("dynamic_analysis.procmon_runner.export_procmon_csv"):
                manifest = run_capture(
                    tmp, r"C:\rf_trace64.exe", window_seconds=5,
                    config_path=REGISTRY_READS_PMC, sleep=calls.append,
                )

        self.assertTrue(manifest["completed"])
        self.assertTrue(manifest["procmon_filter"]["captures_registry_reads"])
        self.assertEqual(calls, [5])

    def test_the_window_is_clamped(self) -> None:
        for asked, expected in ((0, 1), (-5, 1), (MAX_WINDOW_SECONDS * 10, MAX_WINDOW_SECONDS)):
            with self.subTest(asked=asked):
                calls = []
                with TemporaryDirectory() as tmp:
                    with mock.patch("dynamic_analysis.procmon_runner.start_procmon_capture"), \
                         mock.patch("dynamic_analysis.procmon_runner.terminate_procmon_capture"), \
                         mock.patch("dynamic_analysis.procmon_runner.export_procmon_csv"):
                        run_capture(tmp, r"C:\p.exe", window_seconds=asked, sleep=calls.append)
                self.assertEqual(calls, [expected])

    def test_the_default_window_outlasts_a_first_beacon(self) -> None:
        # `ce0d08be...` started its payload 2 seconds after the logon, persisted
        # 12 seconds later, and beaconed on roughly 18 seconds.
        self.assertGreaterEqual(DEFAULT_WINDOW_SECONDS, 60)


if __name__ == "__main__":
    unittest.main()
