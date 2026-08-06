"""A drop to %APPDATA% has to reach the findings.

The Remcos run of 06 Aug recorded 8,130 file creates and 11,636 file writes in
Procmon and surfaced exactly zero of each. The sample dropped
`%APPDATA%\\Roaming\\Config\\smng.exe` -- the report proves it, because a process
was created from that path and two Run keys point at it -- and the drop never
became a finding, a written path, or a dropped-file candidate.

The cause was punctuation. The path markers are matched with a plain `in`
substring test but had been written regex-style, `r"\\users\\\\"`, which is a
literal double backslash and appears in no Windows path ever produced. So
`_path_is_user_writable` returned False universally: the only condition on
`file_create`, and half the condition on `file_write` and `image_load`.

The noise list carried the same defect, which is why both are tested here. Had
only the writable markers been repaired, every write the analyzer makes into its
own case directory would have become a finding instead.

These tests assert against real path strings rather than the marker constants,
because the constants are exactly what was wrong.
"""

import unittest

from dynamic_analysis.dropped_file_triage import (
    collect_dropped_file_candidates,
    path_is_excluded,
    path_is_in_suspicious_location,
)
from dynamic_analysis.procmon_parser import (
    _is_high_signal_event,
    _is_noise_path,
    _path_is_user_writable,
    is_suspicious_path,
    is_suspicious_value_path,
)

DROPPED = r"C:\Users\adam\AppData\Roaming\Config\smng.exe"


def _event(category: str, path: str, operation: str = "WriteFile", process: str = "sample.exe"):
    return {
        "category": category,
        "operation": operation,
        "path": path,
        "process_name": process,
    }


class UserWritableMarkerTests(unittest.TestCase):
    def test_the_appdata_drop_is_user_writable(self) -> None:
        self.assertTrue(_path_is_user_writable(DROPPED))

    def test_every_writable_root_matches_a_real_path(self) -> None:
        for path in (
            r"C:\Users\adam\Desktop\thing.exe",
            r"C:\ProgramData\Foo\bar.dll",
            r"C:\Users\adam\AppData\Local\Temp\x.exe",
            r"C:\Windows\Temp\y.exe",
        ):
            with self.subTest(path=path):
                self.assertTrue(_path_is_user_writable(path))

    def test_a_system_path_is_not_user_writable(self) -> None:
        self.assertFalse(_path_is_user_writable(r"C:\Windows\System32\kernel32.dll"))


class HighSignalTests(unittest.TestCase):
    def test_writing_an_executable_to_appdata_is_high_signal(self) -> None:
        # The exact event the Remcos run lost.
        self.assertTrue(_is_high_signal_event(_event("file_write", DROPPED)))

    def test_creating_an_executable_in_appdata_is_high_signal(self) -> None:
        # file_create has only the one condition, so it was dead entirely.
        self.assertTrue(
            _is_high_signal_event(_event("file_create", DROPPED, operation="CreateFile"))
        )

    def test_a_data_file_in_appdata_is_not(self) -> None:
        # The marker fix must not turn every write under a user profile into a
        # finding -- the extension test is what keeps it narrow.
        self.assertFalse(
            _is_high_signal_event(_event("file_write", r"C:\Users\adam\AppData\Roaming\cfg.dat"))
        )

    def test_an_executable_under_system32_is_not(self) -> None:
        self.assertFalse(
            _is_high_signal_event(_event("file_write", r"C:\Windows\System32\drivers\x.sys"))
        )


class NoiseMarkerTests(unittest.TestCase):
    def test_the_analyzers_own_case_directory_is_noise(self) -> None:
        # Repairing the writable markers without this would have flooded the
        # findings with the workbench writing its own dumps and reports.
        path = r"C:\projects\RingForge_Analyzer\ringforge-workbench\cases\aa4d\dynamic_analysis\x.exe"
        self.assertTrue(_is_noise_path(path))
        self.assertFalse(_is_high_signal_event(_event("file_write", path)))

    def test_defender_paths_are_noise(self) -> None:
        self.assertTrue(
            _is_noise_path(r"C:\ProgramData\Microsoft\Windows Defender\Scans\x.exe")
        )

    def test_a_real_drop_is_not_noise(self) -> None:
        self.assertFalse(_is_noise_path(DROPPED))


class SuspiciousPathTests(unittest.TestCase):
    def test_a_run_key_is_suspicious(self) -> None:
        self.assertTrue(
            is_suspicious_path(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\TRY150-6P1GV6")
        )

    def test_a_service_key_matters_only_when_a_value_is_written(self) -> None:
        # This marker carried the same doubled-separator defect, so service
        # persistence had never been detectable. Repairing it put it on the
        # general list first, and `registry_create` went from 5 interesting
        # events to 140 in a run where the sample did nothing -- ordinary
        # service-key churn. What matters is something setting ImagePath.
        service = r"HKLM\System\CurrentControlSet\Services\EvilSvc\ImagePath"
        self.assertFalse(is_suspicious_path(service))
        self.assertTrue(is_suspicious_value_path(service))

    def test_the_value_list_still_covers_the_general_one(self) -> None:
        run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\X"
        self.assertTrue(is_suspicious_value_path(run_key))

    def test_creating_a_service_key_is_not_high_signal(self) -> None:
        self.assertFalse(
            _is_high_signal_event(
                _event("registry_create", r"HKLM\System\CurrentControlSet\Services\Foo",
                       operation="RegCreateKey")
            )
        )

    def test_setting_a_service_image_path_is(self) -> None:
        self.assertTrue(
            _is_high_signal_event(
                _event("registry_set",
                       r"HKLM\System\CurrentControlSet\Services\Foo\ImagePath",
                       operation="RegSetValue")
            )
        )

    def test_an_ordinary_key_is_not(self) -> None:
        self.assertFalse(is_suspicious_path(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes"))


class DroppedFileTriageTests(unittest.TestCase):
    """The second half of the same bug, and the half that mattered more.

    `collect_dropped_file_candidates` discards any candidate whose path is not
    in a suspicious location, and every marker in that list was dead. So
    `total_candidates` was pinned at 0 no matter what the Procmon side produced
    -- fixing the parser alone would have carried the Remcos drop this far and
    then thrown it away here.
    """

    def test_the_appdata_drop_is_a_suspicious_location(self) -> None:
        self.assertTrue(path_is_in_suspicious_location(DROPPED.lower()))

    def test_system32_is_excluded(self) -> None:
        # The exclusions were dead too, so they only start doing work now that
        # the suspicious list does.
        self.assertTrue(path_is_excluded(r"c:\windows\system32\drivers\x.sys"))

    def test_the_analyzers_own_output_is_excluded(self) -> None:
        self.assertTrue(
            path_is_excluded(r"c:\projects\rf\cases\aa4d\dynamic_analysis\reports\x.exe")
        )

    def test_the_drop_becomes_a_candidate(self) -> None:
        candidates = collect_dropped_file_candidates(
            [
                {
                    "category": "file_write",
                    "path": DROPPED,
                    "process_name": "sample.exe",
                    "pid": 8784,
                    "timestamp": "10:54:47 PM",
                }
            ]
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["extension"], ".exe")
        self.assertTrue(candidates[0]["suspicious_path"])

    def test_a_system_write_does_not(self) -> None:
        candidates = collect_dropped_file_candidates(
            [
                {
                    "category": "file_write",
                    "path": r"C:\Windows\System32\drivers\etc\hosts.exe",
                    "process_name": "sample.exe",
                    "pid": 1,
                    "timestamp": "",
                }
            ]
        )

        self.assertEqual(candidates, [])


class NoDeadMarkersAnywhereTests(unittest.TestCase):
    """A guard against the whole class of bug, not just the instances fixed.

    46 markers across four modules had been written regex-style and matched with
    a plain `in` test, so they matched nothing for the life of the project. The
    instances are fixed; this is what stops the next one.

    A literal double backslash cannot occur in a Windows path except in a UNC
    prefix, so any short path-shaped literal containing one is dead by
    construction.
    """

    def test_no_module_holds_a_marker_that_cannot_match(self) -> None:
        import ast
        from pathlib import Path

        backslash = chr(92)
        doubled = backslash * 2
        regex_hints = (backslash + "b", "[", "(", "|", "?", "*", "+", "$")

        package = Path(__file__).resolve().parents[1]
        dead: list[str] = []

        for module in sorted(package.glob("*.py")):
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                    continue
                value = node.value
                if len(value) > 200 or "\n" in value:
                    continue
                body = value[2:] if value.startswith(doubled) else value
                if doubled not in body:
                    continue
                if any(hint in value for hint in regex_hints):
                    continue
                dead.append(f"{module.name}:{node.lineno} {value!r}")

        self.assertEqual(dead, [], "path markers that can never match:\n" + "\n".join(dead))


if __name__ == "__main__":
    unittest.main()
