import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from dynamic_analysis.logon_capture import (
    DEFAULT_WINDOW_SECONDS,
    MAX_WINDOW_SECONDS,
    TASK_NAME,
    MAX_TR_LENGTH,
    build_arm_argv,
    build_capture_argv,
    build_disarm_argv,
    check_blocking_prompts,
    empty_manifest,
    run_capture,
    write_capture_shim,
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
        argv = build_arm_argv(r"C:\out\run_capture.cmd")

        self.assertIn("/sc", argv)
        self.assertEqual(argv[argv.index("/sc") + 1], "ONSTART")
        self.assertNotIn("ONLOGON", argv)

    def test_it_runs_as_system_and_elevated(self) -> None:
        # Procmon needs administrator to load its driver, and the capture has to
        # exist before any user logs on.
        argv = build_arm_argv(r"C:\out\run_capture.cmd")

        self.assertEqual(argv[argv.index("/ru") + 1], "SYSTEM")
        self.assertEqual(argv[argv.index("/rl") + 1], "HIGHEST")

    def test_rearming_replaces_rather_than_failing(self) -> None:
        self.assertIn("/f", build_arm_argv(r"C:\out\run_capture.cmd"))

    def test_the_task_name_is_not_disguised(self) -> None:
        # An analyzer artifact that hides from the analyzer is how a
        # contaminated run becomes an unexplainable one.
        self.assertIn(TASK_NAME, build_arm_argv(r"C:\out\run_capture.cmd"))
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


class ShimTests(unittest.TestCase):
    def test_the_task_points_at_a_shim_so_tr_stays_under_the_cap(self) -> None:
        # schtasks rejects a /tr over 261 characters and the real command is
        # five absolute paths in one string -- 297 on the first attempt, which
        # is how this was found: on the guest, at the arming step.
        with TemporaryDirectory() as tmp:
            argv = build_capture_argv(
                r"C:\Program Files\Python312\python.exe",
                r"C:\projects\RingForge_Analyzer\ringforge-workbench\scripts\logon_capture.py",
                r"C:\logon-capture",
                r"C:\projects\RingForge_Analyzer\ringforge-workbench\tools\rf_trace64.exe",
                300,
                r"C:\projects\RingForge_Analyzer\ringforge-workbench\tools\procmon-configs\dynamic_registry_reads.pmc",
            )
            self.assertGreater(len(subprocess.list2cmdline(argv)), MAX_TR_LENGTH)

            shim = write_capture_shim(tmp, argv)
            tr = build_arm_argv(str(shim))[-1]

            self.assertLessEqual(len(tr), MAX_TR_LENGTH)
            self.assertIn("--capture", shim.read_text(encoding="utf-8"))
            self.assertIn("rf_trace64.exe", shim.read_text(encoding="utf-8"))


class BlockingPromptTests(unittest.TestCase):
    """Procmon asks questions nobody in session 0 can answer, and `/Quiet`
    suppresses neither of them. Both cost a 300-second capture that reported
    success and recorded nothing."""

    def test_our_own_backing_file_is_removed(self) -> None:
        # "Okay to overwrite event log?" -- ours, so clear it and carry on.
        with TemporaryDirectory() as tmp:
            backing = Path(tmp) / "logon_capture.pml"
            backing.write_bytes(b"stale")
            missing_boot_log = Path(tmp) / "no-such-Procmon.pmb"

            result = check_blocking_prompts(backing, boot_log=missing_boot_log)

            self.assertTrue(result["removed_backing_file"])
            self.assertFalse(backing.exists())
            self.assertEqual(result["blocked_by"], "")

    def test_a_boot_log_is_refused_rather_than_deleted(self) -> None:
        # Not ours. It may be the only copy of a boot nobody can repeat, and it
        # is worth more than one capture.
        with TemporaryDirectory() as tmp:
            boot_log = Path(tmp) / "Procmon.pmb"
            boot_log.write_bytes(b"a boot nobody can repeat")

            result = check_blocking_prompts(Path(tmp) / "logon_capture.pml", boot_log=boot_log)

            self.assertIn("boot log", result["blocked_by"])
            self.assertIn(str(boot_log), result["remedy"])
            self.assertTrue(boot_log.exists())

    def test_a_blocked_capture_never_launches_procmon(self) -> None:
        with TemporaryDirectory() as tmp:
            boot_log = Path(tmp) / "Procmon.pmb"
            boot_log.write_bytes(b"x")

            with mock.patch("dynamic_analysis.procmon_runner.start_procmon_capture") as start:
                manifest = run_capture(tmp, r"C:\p.exe", window_seconds=1, boot_log=boot_log)

            start.assert_not_called()
            self.assertFalse(manifest["completed"])
            self.assertIn("boot log", manifest["reason"])
            self.assertIn("Remedy", manifest["reason"])


class SelfVerificationTests(unittest.TestCase):
    def test_a_procmon_that_writes_nothing_fails_fast_not_silently(self) -> None:
        # The first proving run slept its full 300 seconds against a dialog and
        # reported a capture. Procmon preallocates 256 MB, so a real start shows
        # a backing file within a second or two; no file means it is not
        # capturing, whatever the process table says.
        slept = []
        with TemporaryDirectory() as tmp:
            with mock.patch("dynamic_analysis.procmon_runner.start_procmon_capture"), \
                 mock.patch("dynamic_analysis.procmon_runner.terminate_procmon_capture") as stop, \
                 mock.patch("dynamic_analysis.procmon_runner.export_procmon_csv") as export:
                manifest = run_capture(
                    tmp, r"C:\p.exe", window_seconds=300,
                    sleep=slept.append, boot_log=Path(tmp) / "absent.pmb",
                )

        self.assertFalse(manifest["completed"])
        self.assertIn("no backing file", manifest["reason"])
        export.assert_not_called()
        stop.assert_called_once()
        # Never reached the window: the waits are the one-second polls only.
        self.assertNotIn(300, slept)

    def test_a_killed_capture_does_not_report_its_opening_placeholder(self) -> None:
        # `except Exception` never sees a KeyboardInterrupt, so the first
        # version wrote out `reason: "capture did not start"` -- its own initial
        # value -- as though it were a finding. It had in fact captured for five
        # minutes and been killed.
        with TemporaryDirectory() as tmp:
            backing = Path(tmp) / "logon_capture.pml"

            def start(*_args, **_kwargs):
                backing.write_bytes(b"x" * 4096)

            with mock.patch("dynamic_analysis.procmon_runner.start_procmon_capture", start), \
                 mock.patch("dynamic_analysis.procmon_runner.terminate_procmon_capture"), \
                 mock.patch("dynamic_analysis.procmon_runner.export_procmon_csv"):
                def killed(_seconds):
                    raise KeyboardInterrupt

                with self.assertRaises(KeyboardInterrupt):
                    run_capture(tmp, r"C:\p.exe", window_seconds=300,
                                sleep=killed, boot_log=Path(tmp) / "absent.pmb")

            written = json.loads((Path(tmp) / "logon_capture.json").read_text(encoding="utf-8"))

        self.assertFalse(written["completed"])
        self.assertIn("interrupted while", written["reason"])
        self.assertNotEqual(written["reason"], "capture did not start")
        self.assertEqual(written["backing_file_bytes"], 4096)


class UptimeTests(unittest.TestCase):
    def test_the_manifest_records_how_late_the_capture_was(self) -> None:
        # The whole ONSTART premise is a claim about this number and nothing was
        # measuring it. Measured 31 Aug: the payload ran at 21:32:55 and this
        # capture started at 21:36:46, so ONSTART is earlier than ONLOGON but it
        # is not early.
        with TemporaryDirectory() as tmp:
            boot_log = Path(tmp) / "absent.pmb"
            with mock.patch("dynamic_analysis.procmon_runner.start_procmon_capture"):
                manifest = run_capture(tmp, r"C:\p.exe", window_seconds=1,
                                       sleep=lambda _s: None, boot_log=boot_log)

        self.assertIn("seconds_after_boot", manifest)


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
                manifest = run_capture(tmp, r"C:\missing.exe", window_seconds=1,
                                       boot_log=Path(tmp) / "absent.pmb")

            written = json.loads((Path(tmp) / "logon_capture.json").read_text(encoding="utf-8"))

        self.assertFalse(manifest["completed"])
        self.assertIn("Procmon not found", manifest["reason"])
        self.assertEqual(written["reason"], manifest["reason"])

    def test_the_manifest_records_whether_reads_could_have_been_seen(self) -> None:
        # Read from the file, not the filename. A capture that could not have
        # seen a registry read must never read as having seen none.
        calls = []
        with TemporaryDirectory() as tmp:
            # The mocked start creates the backing file, as a real Procmon does by
            # preallocating. The preflight has just deleted any stale one, so a
            # start that leaves no file is a start that is not capturing.
            def start(*_a, **_k):
                (Path(tmp) / "logon_capture.pml").write_bytes(b"x" * 4096)

            with mock.patch("dynamic_analysis.procmon_runner.start_procmon_capture", start), \
                 mock.patch("dynamic_analysis.procmon_runner.terminate_procmon_capture"), \
                 mock.patch("dynamic_analysis.procmon_runner.export_procmon_csv"):
                manifest = run_capture(
                    tmp, r"C:\rf_trace64.exe", window_seconds=5,
                    config_path=REGISTRY_READS_PMC, sleep=calls.append,
                    boot_log=Path(tmp) / "absent.pmb",
                )

        self.assertTrue(manifest["completed"])
        self.assertTrue(manifest["procmon_filter"]["captures_registry_reads"])
        self.assertEqual(calls, [5])

    def test_the_window_is_clamped(self) -> None:
        for asked, expected in ((0, 1), (-5, 1), (MAX_WINDOW_SECONDS * 10, MAX_WINDOW_SECONDS)):
            with self.subTest(asked=asked):
                calls = []
                with TemporaryDirectory() as tmp:
                    def start(*_a, **_k):
                        (Path(tmp) / "logon_capture.pml").write_bytes(b"x" * 4096)

                    with mock.patch("dynamic_analysis.procmon_runner.start_procmon_capture", start), \
                         mock.patch("dynamic_analysis.procmon_runner.terminate_procmon_capture"), \
                         mock.patch("dynamic_analysis.procmon_runner.export_procmon_csv"):
                        run_capture(tmp, r"C:\p.exe", window_seconds=asked,
                                    sleep=calls.append, boot_log=Path(tmp) / "absent.pmb")
                self.assertEqual(calls, [expected])

    def test_the_default_window_outlasts_a_first_beacon(self) -> None:
        # `ce0d08be...` started its payload 2 seconds after the logon, persisted
        # 12 seconds later, and beaconed on roughly 18 seconds.
        self.assertGreaterEqual(DEFAULT_WINDOW_SECONDS, 60)


if __name__ == "__main__":
    unittest.main()
