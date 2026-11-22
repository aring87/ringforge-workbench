"""Installer scratch: set aside from `payload_dropped`, unless it was run.

Roadmap Step 3b, 21 Nov. On the held-out benign corpus `payload_dropped` was
the installers' own unpacking -- NSIS's `$PLUGINSDIR`, .NET single-file
extraction, install4j's Java runtime, Advanced Installer's scratch -- in 35 of
44 false Corroborated+ cases. These pin which layouts are set aside, which are
deliberately not, and every route by which a scratch file counts again: the
user's condition for the change was that malware unpacking something there
and running it must still be caught.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from dynamic_analysis.dropped_file_triage import (
    apply_installer_scratch,
    path_is_installer_scratch,
    started_and_persisted,
    summarize_dropped_files,
)

TEMP = "C:\\Users\\adam\\AppData\\Local\\Temp\\"
NSIS = TEMP + "nsk94FA.tmp\\System.dll"


def drop(path: str) -> dict:
    return {"path": path, "reasons": ["path_in_suspicious_location", "classification:library"],
            "suspicious": True}


NOTHING_STARTED = {"names": set(), "started_from_scratch": False}


class WhichLayoutsAreScratch(unittest.TestCase):
    def test_the_five_layouts(self) -> None:
        for path in (NSIS,
                     TEMP + "nsxF4CE.tmp\\nsExec.dll",
                     TEMP + ".net\\34d166831ed1\\1b84\\libvlc\\win-x64\\libvlc.dll",
                     TEMP + "e4j1C11.tmp_dir1794720918\\jre\\bin\\java.exe",
                     TEMP + "AI_EXTUI_BIN_8356\\lzmaextractor.dll",
                     TEMP + "aitmp692\\setup.exe"):
            self.assertTrue(path_is_installer_scratch(path), path)

    def test_what_stays_counted(self) -> None:
        """Install destinations, Inno (two held-out malware used it), the top
        of temp, and the places malware drops to."""
        for path in (TEMP + "is-ABCDE.tmp\\setup.tmp.exe",
                     "C:\\Users\\adam\\AppData\\Local\\Programs\\caption\\Caption.exe",
                     "C:\\Users\\adam\\AppData\\Local\\qobuz\\app-8.2.0\\Qobuz.exe",
                     TEMP + "payload.exe",
                     TEMP + "random\\payload.dll",
                     "C:\\Users\\adam\\AppData\\Roaming\\nsk94FA.tmp\\System.dll",
                     "C:\\ProgramData\\x\\System.dll"):
            self.assertFalse(path_is_installer_scratch(path), path)


class SetAsideUnlessRun(unittest.TestCase):
    def test_scratch_is_set_aside_and_still_listed(self) -> None:
        out = apply_installer_scratch([drop(NSIS)], NOTHING_STARTED)
        self.assertEqual(1, len(out))
        self.assertTrue(out[0]["installer_scratch"])
        self.assertTrue(out[0]["installer_scratch_set_aside"])
        self.assertFalse(out[0]["suspicious"])
        summary = summarize_dropped_files(out)
        self.assertEqual(0, summary["suspicious"])
        self.assertEqual(1, summary["installer_scratch_set_aside"])

    def test_a_real_drop_beside_scratch_still_counts(self) -> None:
        out = apply_installer_scratch([drop(NSIS), drop(TEMP + "stage2.exe")], NOTHING_STARTED)
        self.assertEqual(1, summarize_dropped_files(out)["suspicious"])

    def test_started_by_name_counts_again(self) -> None:
        payload = TEMP + "nsk94FA.tmp\\stage2.exe"
        out = apply_installer_scratch([drop(payload), drop(NSIS)],
                                      {"names": {"stage2.exe"}, "started_from_scratch": False})
        by = {o["path"]: o for o in out}
        self.assertTrue(by[payload]["suspicious"])
        self.assertIn("started", by[payload]["installer_scratch_reinstated_because"])
        self.assertFalse(by[NSIS]["suspicious"], "only the file that ran is reinstated by name")

    def test_anything_started_from_scratch_reinstates_the_whole_case(self) -> None:
        out = apply_installer_scratch([drop(NSIS)], {"names": set(), "started_from_scratch": True})
        self.assertTrue(out[0]["suspicious"])
        self.assertEqual(0, summarize_dropped_files(out)["installer_scratch_set_aside"])
        self.assertEqual(1, summarize_dropped_files(out)["installer_scratch_reinstated"])

    def test_no_evidence_means_no_exemption(self) -> None:
        """Not knowing what was started is not evidence that nothing was."""
        out = apply_installer_scratch([drop(NSIS)], None)
        self.assertTrue(out[0]["suspicious"])
        self.assertIn("could not be read", out[0]["installer_scratch_reinstated_because"])

    def test_compiler_scratch_is_still_set_aside_on_an_old_record(self) -> None:
        record = drop(TEMP + "zrudxjpg\\zrudxjpg.dll")
        out = apply_installer_scratch([record], NOTHING_STARTED)
        self.assertTrue(out[0]["compiler_artifact"])
        self.assertFalse(out[0]["suspicious"])

    def test_a_record_without_reasons_keeps_its_verdict(self) -> None:
        out = apply_installer_scratch([{"path": TEMP + "x.exe", "suspicious": True}], NOTHING_STARTED)
        self.assertTrue(out[0]["suspicious"])


class WhatCountsAsStartedOrPersisted(unittest.TestCase):
    def setUp(self) -> None:
        self.run = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.run, ignore_errors=True)
        for sub in ("sysmon", "procmon", "autoruns", "persistence"):
            (self.run / sub).mkdir()

    def write(self, rel: str, value) -> None:
        (self.run / rel).write_text(json.dumps(value), encoding="utf-8")

    def sysmon_start(self, image: str, command: str) -> dict:
        values = ["-"] * 12
        values[4], values[10] = image, command
        return {"event_id": 1, "event_name": "ProcessCreate", "data_values": values}

    def test_sysmon_process_starts_name_files(self) -> None:
        self.write("sysmon/sysmon_events.json", [
            self.sysmon_start("C:\\Windows\\System32\\rundll32.exe",
                              "rundll32.exe " + TEMP + "nsk94FA.tmp\\evil.dll,Start")])
        ev = started_and_persisted(self.run)
        self.assertIn("evil.dll", ev["names"])
        self.assertTrue(ev["started_from_scratch"])

    def test_a_short_name_path_in_temp_counts_as_from_scratch(self) -> None:
        """Sysmon reported install4j's java.exe as `E4J1C1~1.TMP\\jre\\...`,
        which the long-path shapes do not match."""
        self.write("sysmon/sysmon_events.json", [
            self.sysmon_start(TEMP + "E4J1C1~1.TMP\\jre\\bin\\java.exe", "java.exe -version")])
        self.assertTrue(started_and_persisted(self.run)["started_from_scratch"])

    def test_procmon_process_create_counts_and_file_writes_do_not(self) -> None:
        self.write("procmon/interesting_events.json", [
            {"category": "file_create", "path": TEMP + "nsk94FA.tmp\\quiet.dll"},
            {"category": "process_create", "path": "C:\\x\\loader.exe",
             "detail": "PID: 1, Command line: loader.exe"}])
        ev = started_and_persisted(self.run)
        self.assertIn("loader.exe", ev["names"])
        self.assertNotIn("quiet.dll", ev["names"], "writing a file is not starting it")
        self.assertFalse(ev["started_from_scratch"])

    def test_persistence_diffs_name_files(self) -> None:
        self.write("procmon/interesting_events.json", [])
        (self.run / "autoruns" / "autoruns_diff.json").write_text(
            json.dumps({"new": [{"image_path": TEMP + "nsk94FA.tmp\\keep.dll"}]}), encoding="utf-8")
        self.assertIn("keep.dll", started_and_persisted(self.run)["names"])

    def test_no_process_record_at_all_is_none(self) -> None:
        self.assertIsNone(started_and_persisted(self.run))


class RescoreUsesTheSameRule(unittest.TestCase):
    def test_dropped_part_retriages_the_full_list(self) -> None:
        from runcontrol.rescore import dropped_part
        run = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, run, ignore_errors=True)
        for sub in ("files", "metadata", "procmon"):
            (run / sub).mkdir()
        (run / "procmon" / "interesting_events.json").write_text("[]", encoding="utf-8")
        (run / "files" / "dropped_files.json").write_text(
            json.dumps([drop(NSIS), drop(TEMP + "stage2.exe")]), encoding="utf-8")
        summary = dropped_part(run / "metadata" / "dynamic_run_summary.json", {"suspicious": 2})
        self.assertEqual(1, summary["suspicious"])
        self.assertEqual(1, summary["installer_scratch_set_aside"])

    def test_dropped_part_falls_back_when_the_list_is_missing(self) -> None:
        from runcontrol.rescore import dropped_part
        run = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, run, ignore_errors=True)
        (run / "metadata").mkdir()
        stored = {"suspicious": 3}
        self.assertIs(stored, dropped_part(run / "metadata" / "dynamic_run_summary.json", stored))


if __name__ == "__main__":
    unittest.main()
