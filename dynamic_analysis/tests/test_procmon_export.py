"""`export_procmon_csv`: a timeout must be a ProcmonError, and the limit must fit.

17 of mal-112b's 109 usable runs came home static-only because Procmon's
`/SaveAs` ran past a fixed 120 s limit and `subprocess.TimeoutExpired` -- not a
ProcmonError -- walked past the orchestrator's handler, which exists to carry
on without Procmon rather than lose every other collector's evidence. These
pin the conversion, the cleanup of a partial CSV, and the measured limit.

No Procmon is run: `subprocess.run` is patched, because the contract under test
is what this function does with each of run's outcomes.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dynamic_analysis import procmon_runner
from dynamic_analysis.procmon_runner import (
    EXPORT_TIMEOUT_SECONDS, ProcmonError, export_procmon_csv)


class ExportTimeoutTests(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rf-procmon-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.procmon = self.tmp / "Procmon64.exe"
        self.procmon.write_bytes(b"MZ")
        self.backing = self.tmp / "raw.pml"
        self.backing.write_bytes(b"PML_")
        self.csv = self.tmp / "procmon" / "export.csv"

    def export(self, **kwargs) -> Path:
        return export_procmon_csv(self.procmon, self.backing, self.csv, **kwargs)

    def test_a_timeout_is_a_procmon_error_not_timeout_expired(self) -> None:
        """The orchestrator catches ProcmonError and continues without
        Procmon. TimeoutExpired is not one, and killed the dynamic module."""
        with mock.patch.object(procmon_runner.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("procmon", 900)):
            with self.assertRaises(ProcmonError) as caught:
                self.export()
        self.assertIsInstance(caught.exception.__cause__, subprocess.TimeoutExpired)
        self.assertIn("900s", str(caught.exception))
        self.assertIn("continuing without Procmon", str(caught.exception))

    def test_a_partial_csv_does_not_survive_a_timeout(self) -> None:
        """Procmon writes the CSV as it goes. Killed part-way, the file on
        disk is a fragment that would parse into a false-clean run."""
        def half_written(*_args, **_kwargs):
            self.csv.write_text("Time of Day,Process Name\n12:00,sample.exe\n")
            raise subprocess.TimeoutExpired("procmon", 900)

        with mock.patch.object(procmon_runner.subprocess, "run", side_effect=half_written):
            with self.assertRaises(ProcmonError):
                self.export()
        self.assertFalse(self.csv.exists())

    def test_the_default_limit_is_the_measured_one(self) -> None:
        """120 s cost 17 runs, and the slowest exports that finished took
        99-118 s. The default must clear that with room."""
        self.assertGreaterEqual(EXPORT_TIMEOUT_SECONDS, 600)

        def ok(*_args, **kwargs):
            self.csv.write_text("Time of Day\n")
            return subprocess.CompletedProcess([], 0, "", "")

        with mock.patch.object(procmon_runner.subprocess, "run", side_effect=ok) as run:
            self.export()
        self.assertEqual(run.call_args.kwargs["timeout"], EXPORT_TIMEOUT_SECONDS)

    def test_an_explicit_limit_is_honoured(self) -> None:
        with mock.patch.object(procmon_runner.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("procmon", 5)) as run:
            with self.assertRaises(ProcmonError) as caught:
                self.export(timeout=5)
        self.assertEqual(run.call_args.kwargs["timeout"], 5)
        self.assertIn("5s", str(caught.exception))

    def test_success_is_unchanged(self) -> None:
        def ok(*_args, **_kwargs):
            self.csv.write_text("Time of Day\n")
            return subprocess.CompletedProcess([], 0, "", "")

        with mock.patch.object(procmon_runner.subprocess, "run", side_effect=ok):
            self.assertEqual(self.export(), self.csv)

    def test_a_nonzero_exit_is_still_a_procmon_error(self) -> None:
        with mock.patch.object(procmon_runner.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 3, "", "bad")):
            with self.assertRaises(ProcmonError):
                self.export()


if __name__ == "__main__":
    unittest.main()
