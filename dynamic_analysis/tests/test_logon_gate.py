"""The gate: removing the race instead of trying to win it.

The first proving run put an `ONSTART` capture against an `ONLOGON` payload on
the reasoning that ONSTART "runs before any user session exists, so there is no
ordering to get right". Measured 31 Aug: the payload started 21:32:55, the
capture 21:36:46. Task Scheduler delays boot-triggered tasks, and no flag on a
scheduled task changes that.

So the ordering is not raced. `AutoAdminLogon` goes to 0, the guest boots to a
sign-in screen and stops, and no logon session exists for the sample's task to
trigger on. The capture starts whenever it starts, confirms its own backing
file, and signals the host, which then types the credentials. The payload
starts inside a capture already known to be running.

Everything here is about the two ways that can fail silently:

- **A signal that is not sent.** VBoxControl missing, or the call failing, and
  the host waits out its timeout with nothing to say. It has to be reported by
  the guest, in the manifest, where the reason lives.
- **A signal that is stale.** Guest properties outlive a reboot. A leftover
  readiness would be read as this boot's, the credentials would go into a
  machine with no capture running, and the run would look perfect and prove
  nothing. The guest sets it TRANSIENT; the host deletes it before boot.
"""

import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from dynamic_analysis.logon_capture import (
    READY_PROPERTY,
    arm,
    run_capture,
    set_autologon,
    signal_ready,
)


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


class SignalTests(unittest.TestCase):
    def test_the_value_is_set_transient(self) -> None:
        """A property that outlives the VM's power state is a stale readiness
        waiting to happen, and the host cannot tell one from a fresh one."""
        with mock.patch("dynamic_analysis.logon_capture.find_vboxcontrol",
                        return_value=r"C:\Windows\System32\VBoxControl.exe"), \
             mock.patch("subprocess.run", return_value=_completed()) as run:
            result = signal_ready("1|231|2026-09-01T21:36:46")

        self.assertTrue(result["signalled"])
        argv = run.call_args[0][0]
        self.assertIn("--flags", argv)
        self.assertEqual(argv[argv.index("--flags") + 1], "TRANSIENT")
        self.assertIn(READY_PROPERTY, argv)

    def test_a_missing_vboxcontrol_is_reported_not_swallowed(self) -> None:
        """Without this the host waits out fifteen minutes and reports only
        that nothing arrived, while the guest knew at second one."""
        with mock.patch("dynamic_analysis.logon_capture.find_vboxcontrol", return_value=""):
            result = signal_ready("1|231|now")

        self.assertFalse(result["signalled"])
        self.assertIn("VBoxControl.exe not found", result["error"])

    def test_a_failing_call_carries_what_it_said(self) -> None:
        with mock.patch("dynamic_analysis.logon_capture.find_vboxcontrol",
                        return_value=r"C:\Windows\System32\VBoxControl.exe"), \
             mock.patch("subprocess.run",
                        return_value=_completed(1, stderr="VBoxControl: error: not permitted")):
            result = signal_ready("1|231|now")

        self.assertFalse(result["signalled"])
        self.assertIn("not permitted", result["error"])

    def test_a_signal_that_raises_does_not_kill_the_capture(self) -> None:
        """The capture is worth more than the signal. A guest that cannot reach
        the host still records what it was armed to record; the host falls back
        to its timeout and the manifest says why."""
        with mock.patch("dynamic_analysis.logon_capture.find_vboxcontrol",
                        return_value=r"C:\Windows\System32\VBoxControl.exe"), \
             mock.patch("subprocess.run", side_effect=OSError("no such device")):
            result = signal_ready("1|231|now")

        self.assertFalse(result["signalled"])
        self.assertIn("OSError", result["error"])


class CaptureSignalsOnlyWhenItIsReal(unittest.TestCase):
    def _run(self, backing_written: bool):
        signals = []

        with TemporaryDirectory() as tmp:
            backing = Path(tmp) / "logon_capture.pml"

            def start(*_args, **_kwargs):
                if backing_written:
                    backing.write_bytes(b"x" * 4096)

            def fake_signal(value, property_name=READY_PROPERTY):
                signals.append(value)
                return {"signalled": True, "property": property_name,
                        "value": value, "vboxcontrol": "", "error": ""}

            with mock.patch("dynamic_analysis.procmon_runner.start_procmon_capture", start), \
                 mock.patch("dynamic_analysis.procmon_runner.terminate_procmon_capture"), \
                 mock.patch("dynamic_analysis.procmon_runner.export_procmon_csv"), \
                 mock.patch("dynamic_analysis.logon_capture.signal_ready", fake_signal):
                manifest = run_capture(
                    tmp, r"C:\p.exe", window_seconds=5,
                    sleep=lambda _s: None, boot_log=Path(tmp) / "absent.pmb",
                )
            marker = Path(tmp) / "logon_capture.ready"
            marker_exists = marker.is_file()

        return manifest, signals, marker_exists

    def test_it_signals_on_a_growing_backing_file(self) -> None:
        manifest, signals, marker_exists = self._run(backing_written=True)

        self.assertTrue(manifest["completed"])
        self.assertEqual(len(signals), 1)
        self.assertTrue(signals[0].startswith("1|"))
        self.assertTrue(manifest["ready_at"])
        self.assertTrue(manifest["ready_signal"]["signalled"])
        self.assertTrue(marker_exists)

    def test_it_does_not_signal_when_procmon_wrote_nothing(self) -> None:
        """The signal means "the backing file is growing", not "Procmon was
        launched". Launching was true last time while nothing was captured,
        because Procmon was sitting on a modal. Signalling on the launch would
        hand the host the same lie in a new place -- and the host would type
        the credentials into a machine that is not recording."""
        manifest, signals, marker_exists = self._run(backing_written=False)

        self.assertFalse(manifest["completed"])
        self.assertEqual(signals, [])
        self.assertEqual(manifest["ready_at"], "")
        self.assertFalse(marker_exists)

    def test_the_manifest_is_serialisable_with_the_signal_in_it(self) -> None:
        with TemporaryDirectory() as tmp:
            backing = Path(tmp) / "logon_capture.pml"

            with mock.patch("dynamic_analysis.procmon_runner.start_procmon_capture",
                            lambda *a, **k: backing.write_bytes(b"x" * 4096)), \
                 mock.patch("dynamic_analysis.procmon_runner.terminate_procmon_capture"), \
                 mock.patch("dynamic_analysis.procmon_runner.export_procmon_csv"), \
                 mock.patch("dynamic_analysis.logon_capture.find_vboxcontrol", return_value=""):
                run_capture(tmp, r"C:\p.exe", window_seconds=1,
                            sleep=lambda _s: None, boot_log=Path(tmp) / "absent.pmb")

            written = json.loads((Path(tmp) / "logon_capture.json").read_text(encoding="utf-8"))

        # The signal failed; the capture did not.
        self.assertTrue(written["completed"])
        self.assertFalse(written["ready_signal"]["signalled"])
        self.assertIn("VBoxControl.exe not found", written["ready_signal"]["error"])


class GateTests(unittest.TestCase):
    """`_write_autologon` is stubbed throughout: a test that writes to the
    host's own Winlogon key is a test nobody should run, and one that needs
    elevation to pass is one that gets skipped."""

    def test_closing_the_gate_reports_what_it_was(self) -> None:
        with mock.patch("dynamic_analysis.logon_capture.read_autologon",
                        return_value={"readable": True, "auto_admin_logon": "1", "error": ""}), \
             mock.patch("dynamic_analysis.logon_capture._write_autologon", return_value="") as write:
            result = set_autologon(False)

        self.assertTrue(result["changed"])
        self.assertEqual(result["previous"], "1")
        self.assertEqual(result["now"], "0")
        write.assert_called_once_with("0")

    def test_opening_it_again_is_the_one_character_back(self) -> None:
        with mock.patch("dynamic_analysis.logon_capture.read_autologon",
                        return_value={"readable": True, "auto_admin_logon": "0", "error": ""}), \
             mock.patch("dynamic_analysis.logon_capture._write_autologon", return_value="") as write:
            result = set_autologon(True)

        self.assertTrue(result["changed"])
        write.assert_called_once_with("1")

    def test_a_refused_write_is_not_reported_as_a_closed_gate(self) -> None:
        """Believing the gate is closed when it is open is the worst outcome
        available: the machine logs itself in, the payload runs first, and the
        run reads as a successful gated capture."""
        with mock.patch("dynamic_analysis.logon_capture.read_autologon",
                        return_value={"readable": True, "auto_admin_logon": "1", "error": ""}), \
             mock.patch("dynamic_analysis.logon_capture._write_autologon",
                        return_value="Access is denied. Writing HKLM needs Administrator"):
            result = set_autologon(False)

        self.assertFalse(result["changed"])
        self.assertIn("Administrator", result["error"])

    def test_an_unreadable_key_is_not_written_over(self) -> None:
        with mock.patch("dynamic_analysis.logon_capture.read_autologon",
                        return_value={"readable": False, "auto_admin_logon": "", "error": "boom"}), \
             mock.patch("dynamic_analysis.logon_capture._write_autologon") as write:
            result = set_autologon(False)

        self.assertFalse(result["changed"])
        write.assert_not_called()


class ArmOrderingTests(unittest.TestCase):
    def test_the_gate_closes_only_after_the_task_registers(self) -> None:
        """The other order leaves a machine that neither captures nor logs
        anybody in, which on a guest with no console access is a reinstall."""
        with TemporaryDirectory() as tmp:
            with mock.patch("dynamic_analysis.logon_capture._run",
                            return_value={"ok": False, "returncode": 1,
                                          "stdout": "", "stderr": "ERROR: Access denied."}), \
                 mock.patch("dynamic_analysis.logon_capture.set_autologon") as gate:
                result = arm(tmp, r"C:\p.exe", gate_logon=True)

        self.assertFalse(result["ok"])
        gate.assert_not_called()
        self.assertEqual(result["gate"], {})

    def test_arming_without_the_flag_leaves_the_gate_alone(self) -> None:
        with TemporaryDirectory() as tmp:
            with mock.patch("dynamic_analysis.logon_capture._run",
                            return_value={"ok": True, "returncode": 0, "stdout": "", "stderr": ""}), \
                 mock.patch("dynamic_analysis.logon_capture.set_autologon") as gate:
                result = arm(tmp, r"C:\p.exe")

        self.assertTrue(result["ok"])
        gate.assert_not_called()
        self.assertEqual(result["gate"], {})

    def test_arming_with_the_flag_closes_it(self) -> None:
        with TemporaryDirectory() as tmp:
            with mock.patch("dynamic_analysis.logon_capture._run",
                            return_value={"ok": True, "returncode": 0, "stdout": "", "stderr": ""}), \
                 mock.patch("dynamic_analysis.logon_capture.set_autologon",
                            return_value={"changed": True, "previous": "1",
                                          "now": "0", "error": ""}) as gate:
                result = arm(tmp, r"C:\p.exe", gate_logon=True)

        gate.assert_called_once_with(False)
        self.assertTrue(result["gate"]["changed"])


if __name__ == "__main__":
    unittest.main()
