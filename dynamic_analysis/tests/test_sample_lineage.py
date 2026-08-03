"""A process create is a finding only if the sample caused it.

Filtering background activity by name did not converge. Two runs of the same
mimikatz control reported entirely different sets: the first caught a Group
Policy service host, the second an Intune check-in, OneDrive starting and three
Defender console hosts. Each fix removed the instance in front of it and the
next run produced new ones, because what Windows happens to do during a
five-minute window is not a fixed list. The second run scored 92 on a control
whose only real behaviour is sitting at a prompt.

Lineage is the property that separates them. The sample was pid 8696 and not
one of those six descended from it.

Non-descendants become context rather than disappearing. A sample can cause a
process it does not parent -- through injection, COM, a service or WMI -- and
discarding them outright would destroy that evidence with the same filter that
removes the housekeeping.

The failure this must not have is the inverse: a run whose sample PID was never
recorded must not report an empty findings list, because "nothing descended
from the sample" and "we never established what the sample was" are the same
empty list and only the first is a result.
"""

import unittest

from dynamic_analysis import findings
from dynamic_analysis.findings import (
    _is_windows_baseline_process_create,
    _mark_sample_lineage,
)
from dynamic_analysis.utils import is_analyzer_image


def _create(parent: str, child: str, parent_pid: int, child_pid: int) -> dict:
    return {
        "process_name": parent,
        "child_process_name": child,
        "pid": parent_pid,
        "detail": f"PID: {child_pid}, Command line: {child}",
    }


#: The six spawns from the 2026-08-03 mimikatz.upx run. Sample was pid 8696.
BACKGROUND = [
    _create("Microsoft.Management.Services.IntuneWindowsAgent.exe", "agentexecutor.exe", 4964, 8960),
    _create("agentexecutor.exe", "conhost.exe", 8960, 7236),
    _create("svchost.exe", "onedrivelauncher.exe", 1460, 5536),
    _create("MpCmdRun.exe", "conhost.exe", 8012, 8672),
    _create("MpCmdRun.exe", "conhost.exe", 4276, 5412),
    _create("MpCmdRun.exe", "conhost.exe", 8888, 2928),
]


class SampleLineageTests(unittest.TestCase):
    def test_background_activity_does_not_descend_from_the_sample(self) -> None:
        records = [dict(r) for r in BACKGROUND]

        self.assertTrue(_mark_sample_lineage(records, sample_pid=8696))
        self.assertEqual([r for r in records if r.get("descends_from_sample")], [])

    def test_a_child_of_the_sample_is_a_finding(self) -> None:
        records = [dict(r) for r in BACKGROUND]
        records.append(_create("mimikatz.upx.exe", "cmd.exe", 8696, 9001))

        _mark_sample_lineage(records, sample_pid=8696)

        self.assertTrue(records[-1]["descends_from_sample"])

    def test_a_grandchild_is_reached_too(self) -> None:
        # The whole reason this iterates to a fixed point.
        records = [
            _create("cmd.exe", "whoami.exe", 9001, 9002),
            _create("mimikatz.upx.exe", "cmd.exe", 8696, 9001),
        ]

        _mark_sample_lineage(records, sample_pid=8696)

        self.assertTrue(all(r["descends_from_sample"] for r in records))

    def test_lineage_is_unresolved_without_a_pid_or_a_name(self) -> None:
        # Must read as "cannot tell", never as "nothing descended".
        records = [dict(r) for r in BACKGROUND]

        self.assertFalse(_mark_sample_lineage(records, sample_pid=None, sample_name=""))

    def test_the_name_seeds_lineage_when_no_pid_was_handed_in(self) -> None:
        records = [
            _create("explorer.exe", "sample.exe", 100, 4242),
            _create("sample.exe", "cmd.exe", 4242, 4243),
        ]

        self.assertTrue(_mark_sample_lineage(records, sample_name="sample.exe"))
        self.assertTrue(records[1]["descends_from_sample"])


class QuickFixTests(unittest.TestCase):
    def test_the_capture_backend_counts_as_analyzer_tooling(self) -> None:
        # A CreateRemoteThread into dumpcap raised T1055 against the sample.
        # npcap and npf.sys were listed; the binary capturing was not.
        self.assertTrue(is_analyzer_image(r"C:\Program Files\Wireshark\dumpcap.exe"))
        self.assertTrue(is_analyzer_image(r"C:\Program Files\Wireshark\tshark.exe"))

    def test_the_sample_is_not_analyzer_tooling(self) -> None:
        self.assertFalse(is_analyzer_image(r"C:\samples\mimikatz.upx.exe"))

    def test_conhost_as_a_child_is_baseline(self) -> None:
        self.assertTrue(
            _is_windows_baseline_process_create(
                "MpCmdRun.exe",
                r"C:\WINDOWS\System32\Conhost.exe",
                r"PID: 8672, Command line: \??\C:\WINDOWS\system32\conhost.exe 0xffffffff -ForceV1",
            )
        )

    def test_conhost_as_a_parent_is_still_reported(self) -> None:
        # Console Window Host spawning something is not housekeeping.
        self.assertFalse(
            _is_windows_baseline_process_create(
                "conhost.exe",
                r"C:\Users\adam\AppData\Local\Temp\payload.exe",
                "Command line: payload.exe",
            )
        )


class PathMarkerEscapingTests(unittest.TestCase):
    """Path markers are matched with `in`, not with a regex.

    They were written r"\\temp\\\\" -- regex escaping -- which asks for two
    consecutive backslashes and matches no real Windows path. 5/5 user-writable
    markers, 13/20 noise markers and 8/17 analyzer markers were dead, so
    "an executable running from a user-writable location" had never fired and a
    good deal of intended suppression never happened either.

    A raw string cannot end in a single backslash, which is the trap that
    produced the doubled form. Ordinary strings are the fix, and this test is
    here so the trap cannot be walked into again.
    """

    def test_no_marker_asks_for_a_doubled_backslash(self) -> None:
        for name in (
            "USER_WRITABLE_PATH_MARKERS",
            "KNOWN_NOISE_PATH_SUBSTRINGS",
            "ANALYZER_NOISE_PATH_SUBSTRINGS",
        ):
            for marker in getattr(findings, name):
                self.assertNotIn("\\\\", marker, f"{name}: {marker!r} can never match")

    def test_a_dropped_executable_is_user_writable(self) -> None:
        self.assertTrue(findings._path_is_user_writable(r"C:\Users\a\AppData\Local\Temp\x.exe"))
        self.assertTrue(findings._path_is_user_writable(r"C:\ProgramData\x.exe"))

    def test_system32_is_not_user_writable(self) -> None:
        self.assertFalse(findings._path_is_user_writable(r"C:\Windows\System32\cmd.exe"))

    def test_suppression_markers_match_again(self) -> None:
        self.assertTrue(findings._is_noise_path(r"C:\Users\a\AppData\Local\Google\Chrome\User Data\x"))
        self.assertTrue(findings._is_analyzer_noise_path(r"C:\rf\cases\mimikatz\report.json"))
        self.assertTrue(
            findings._is_defender_or_wbem_noise(
                r"C:\ProgramData\Microsoft\Windows Defender\Scans\x", "a.exe"
            )
        )


if __name__ == "__main__":
    unittest.main()
