"""dumpcap on disk is not a capture.

`capture_status()` reported `available: True` on finding `dumpcap.exe` and
never looked at the driver underneath it. A Wireshark install whose Npcap
component failed or was declined therefore read as `Capture: ready` and
captured nothing -- and a run with no packets looks exactly like a sample that
made no network connections.

Same shape as `rule_file_count`: a probe answering a nearby question, taken for
the real one. Found on 04 Sep while bootstrapping the analysis VM, where the
driver had to be verified by hand because nothing in this package would.
"""

import unittest
from unittest import mock

from dynamic_analysis import network_capture
from dynamic_analysis.network_capture import capture_status


def _status(npcap, *, dumpcap="C:/Program Files/Wireshark/dumpcap.exe",
            pktmon=False):
    from pathlib import Path

    with mock.patch.object(network_capture, "npcap_available",
                           return_value=npcap), \
         mock.patch.object(network_capture, "find_dumpcap",
                           return_value=Path(dumpcap) if dumpcap else None), \
         mock.patch.object(network_capture, "find_tshark", return_value=None), \
         mock.patch.object(network_capture, "pktmon_available",
                           return_value=pktmon):
        return capture_status()


class TheDriverIsReported(unittest.TestCase):
    def test_a_working_install_carries_no_warning(self) -> None:
        status = _status(True)

        self.assertTrue(status["available"])
        self.assertIs(status["npcap_available"], True)
        self.assertEqual(status["warning"], "")

    def test_a_missing_driver_warns_even_though_dumpcap_is_there(self) -> None:
        """The case that shipped silently. `available` stays true -- the binary
        really is installed -- and the warning is what stops `ready` being the
        whole story, which is the mechanism the telemetry strip already has."""
        status = _status(False)

        self.assertTrue(status["available"])
        self.assertIs(status["npcap_available"], False)
        self.assertIn("Npcap", status["warning"])
        self.assertIn("capture nothing", status["warning"])

    def test_the_note_says_what_to_do_about_it(self) -> None:
        status = _status(False)

        self.assertIn("will not capture", status["note"])
        self.assertIn("Npcap component", status["note"])

    def test_not_knowing_reads_differently_from_knowing_it_is_absent(self) -> None:
        """Tri-state on purpose. A probe that could not run has not established
        that the driver is missing, and the two must not collapse."""
        unknown = _status(None)
        absent = _status(False)

        self.assertIsNone(unknown["npcap_available"])
        self.assertNotEqual(unknown["warning"], absent["warning"])
        self.assertIn("could not confirm", unknown["warning"])

    def test_the_pktmon_fallback_does_not_care_about_npcap(self) -> None:
        """pktmon is the built-in backend and uses no Npcap driver, so a
        missing one is not a warning about it."""
        status = _status(False, dumpcap=None, pktmon=True)

        self.assertEqual(status["backend"], "pktmon")
        self.assertEqual(status["warning"], "")

    def test_no_backend_at_all_is_still_unavailable(self) -> None:
        status = _status(None, dumpcap=None, pktmon=False)

        self.assertFalse(status["available"])


class TheProbeItself(unittest.TestCase):
    def test_it_answers_rather_than_raising(self) -> None:
        self.assertIn(network_capture.npcap_available(), (True, False, None))

    def test_a_failed_query_is_unknown_not_absent(self) -> None:
        import os

        if os.name != "nt":
            self.skipTest("the probe short-circuits off Windows")
        with mock.patch("subprocess.run", side_effect=OSError("boom")):
            self.assertIsNone(network_capture.npcap_available())


if __name__ == "__main__":
    unittest.main()
