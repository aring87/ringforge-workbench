"""What counts as the sample's drop, and what counts as a drop at all.

Both questions came from the same run: the first detonation where file events
reached the findings at all, after the dead path markers were repaired. It
produced two wrong numbers.

`payload_dropped` reached **strong** on 13 suspicious dropped files of which 11
did not exist. They were `WINMM.dll`, `urlmon.dll`, `WININET.dll` and
`iertutil.dll` in `%APPDATA%\\Roaming\\Config` -- `smng.exe` walking the DLL
search order in its own directory. Failed opens, not drops. The true count was
one.

And 12 of 14 persistence hits, plus every row of `top_written_paths`, were
`svchost.exe` rewriting
`C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Work`
-- Windows Update maintaining its own scheduled task. A path keyword says what
kind of thing happened; it cannot say who did it.
"""

import unittest

from dynamic_analysis.dropped_file_triage import (
    collect_dropped_file_candidates,
    result_is_not_found,
)
from dynamic_analysis.findings import (
    _is_independently_notable_path,
    summarize_dynamic_findings,
)

DROP = r"C:\Users\adam\AppData\Roaming\Config\smng.exe"
PROBE = r"C:\Users\adam\AppData\Roaming\Config\WININET.dll"
WU_TASK = r"C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Schedule Work"


def _event(operation, category, process, pid, path, result="SUCCESS", detail=""):
    return {
        "timestamp": "10:54:47 PM",
        "operation": operation,
        "category": category,
        "process_name": process,
        "pid": pid,
        "path": path,
        "result": result,
        "detail": detail,
    }


class ProbeVersusDropTests(unittest.TestCase):
    def test_a_failed_open_is_not_a_drop(self) -> None:
        candidates = collect_dropped_file_candidates(
            [_event("CreateFile", "file_create", "smng.exe", 6736, PROBE,
                    result="NAME NOT FOUND")]
        )

        self.assertEqual(candidates, [])

    def test_the_real_drop_survives(self) -> None:
        candidates = collect_dropped_file_candidates(
            [_event("WriteFile", "file_write", "sample.exe", 9136, DROP)]
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["classification"], "executable")

    def test_a_drop_that_was_deleted_afterwards_still_counts(self) -> None:
        # Deliberately not "keep only what exists on disk": a sample that writes
        # a payload, runs it and deletes it has still dropped a file. The write
        # succeeded, which is what distinguishes it from a probe.
        candidates = collect_dropped_file_candidates(
            [_event("WriteFile", "file_write", "sample.exe", 9136, DROP, result="SUCCESS")]
        )

        self.assertEqual(len(candidates), 1)

    def test_intermediate_results_are_not_treated_as_failures(self) -> None:
        for result in ("REPARSE", "FAST IO DISALLOWED", "SUCCESS", ""):
            with self.subTest(result=result):
                self.assertFalse(result_is_not_found(result))

    def test_the_not_found_family_is_recognised(self) -> None:
        for result in ("NAME NOT FOUND", "PATH NOT FOUND", "name not found"):
            with self.subTest(result=result):
                self.assertTrue(result_is_not_found(result))


class LineageOfPathHitsTests(unittest.TestCase):
    def _findings(self, events):
        return summarize_dynamic_findings(
            events, events, sample_pid=9136, sample_name="sample.exe"
        )

    def test_windows_update_is_not_the_samples_persistence(self) -> None:
        found = self._findings(
            [
                _event("Process Create", "process_create", "sample.exe", 9136,
                       r"C:\Users\adam\AppData\Roaming\Config\smng.exe",
                       detail="PID: 6736, Command line: smng.exe"),
                _event("WriteFile", "file_write", "svchost.exe", 2120, WU_TASK),
            ]
        )

        paths = [h["path"] for h in found["persistence_hits"]]
        self.assertNotIn(WU_TASK, paths)
        # Counted rather than dropped, so the report can still show the machine
        # was busy.
        self.assertEqual(found["counts"]["background_persistence_hits"], 1)

    def test_windows_update_does_not_own_top_written_paths(self) -> None:
        found = self._findings(
            [_event("WriteFile", "file_write", "svchost.exe", 2120, WU_TASK)]
        )

        self.assertEqual(found["top_written_paths"], [])
        self.assertEqual(found["counts"]["file_write_events"], 0)
        self.assertEqual(
            found["background_written_paths"], [{"path": WU_TASK, "count": 1}]
        )

    def test_the_samples_own_run_key_survives(self) -> None:
        run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\TRY150-6P1GV6"
        found = self._findings(
            [_event("RegSetValue", "registry_set", "sample.exe", 9136, run_key,
                    detail='Data: "C:\\Users\\adam\\AppData\\Roaming\\Config\\smng.exe"')]
        )

        self.assertEqual([h["path"] for h in found["persistence_hits"]], [run_key])

    def test_an_executable_dropped_by_anyone_is_still_notable(self) -> None:
        # The half lineage cannot see: a sample can cause a write it does not
        # perform, through injection, COM, a service or WMI. An executable in a
        # user-writable directory stands on its own.
        self.assertTrue(_is_independently_notable_path(r"C:\Users\adam\AppData\Local\Temp\payload.exe"))
        self.assertFalse(_is_independently_notable_path(WU_TASK))

    def test_a_foreign_drop_into_temp_is_kept(self) -> None:
        payload = r"C:\Users\adam\AppData\Local\Temp\payload.exe"
        found = self._findings(
            [_event("WriteFile", "file_write", "explorer.exe", 4321, payload)]
        )

        self.assertIn(payload, [p["path"] for p in found["top_written_paths"]])


class AnalyzerOwnDriverTests(unittest.TestCase):
    def test_fakenets_windivert_is_not_the_samples_activity(self) -> None:
        # FakeNet ships as a PyInstaller one-file build and unpacks into
        # %TEMP%\_MEInnnnn, a path containing none of the workbench's own names,
        # so its driver was landing in the sample's suspicious-path hits.
        driver = r"C:\Users\adam\AppData\Local\Temp\_MEI60562\pydivert\windivert_dll\WinDivert64.sys"
        found = summarize_dynamic_findings(
            [_event("WriteFile", "file_write", "fakenet.exe", 5555, driver)],
            [_event("WriteFile", "file_write", "fakenet.exe", 5555, driver)],
            sample_pid=9136,
            sample_name="sample.exe",
        )

        self.assertEqual(found["suspicious_path_hits"], [])
        self.assertEqual(found["top_written_paths"], [])

    def test_it_is_not_a_dropped_file_either(self) -> None:
        # dropped_file_triage keeps its own analyzer list, separate from the one
        # in findings, so the exclusion has to exist in both. Repairing only the
        # findings side still left `payload_dropped` reaching strong on our own
        # driver plus the sample's one real drop.
        driver = r"C:\Users\adam\AppData\Local\Temp\_MEI60562\pydivert\windivert_dll\WinDivert64.sys"
        candidates = collect_dropped_file_candidates(
            [_event("WriteFile", "file_write", "fakenet.exe", 5555, driver)]
        )

        self.assertEqual(candidates, [])


if __name__ == "__main__":
    unittest.main()
