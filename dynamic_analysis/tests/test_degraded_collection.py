"""A collector that only worked via its fallback has to say so.

The task and service snapshots try WMI/CIM and fall back to schtasks.exe and
sc.exe. In a real canary run both fell back -- the guest's `root\\cimv2`
namespace was unreadable -- and both recorded `"success": true`, because from
the snapshot's point of view they had succeeded. Nothing in the report
mentioned it.

That is the wrong kind of silence. WMI is a persistence and execution surface
in its own right, so a guest that cannot read its own CIM namespace may also be
failing to record the WMI activity Sysmon is configured to watch. The diffs
stay valid; the environment does not.
"""

import unittest

from dynamic_analysis.html_report import _degraded_collection_section


def _summary(tasks_fell_back: bool = False, services_fell_back: bool = False) -> dict:
    return {
        "tasks_snapshot_status": {
            "success": True,
            "method": "schtasks.exe" if tasks_fell_back else "Get-ScheduledTask",
            "error": (
                "Get-ScheduledTask: Cannot connect to CIM server. Invalid namespace\n"
                "At line:5 char:10\n+ $tasks = Get-ScheduledTask | ForEach-Object {"
                if tasks_fell_back
                else ""
            ),
            "fallback_used": tasks_fell_back,
        },
        "services_snapshot_status": {
            "success": True,
            "method": "sc.exe" if services_fell_back else "Win32_Service",
            "error": "Get-CimInstance: Invalid namespace" if services_fell_back else "",
            "fallback_used": services_fell_back,
        },
    }


class DegradedCollectionTests(unittest.TestCase):
    def test_a_healthy_run_says_nothing(self) -> None:
        self.assertEqual(_degraded_collection_section(_summary()), "")

    def test_one_fallback_is_reported(self) -> None:
        html = _degraded_collection_section(_summary(tasks_fell_back=True))

        self.assertIn("Degraded Collection", html)
        self.assertIn("schtasks.exe", html)
        self.assertIn("Collectors: 1", html)

    def test_both_fallbacks_are_reported(self) -> None:
        html = _degraded_collection_section(
            _summary(tasks_fell_back=True, services_fell_back=True)
        )

        self.assertIn("Collectors: 2", html)
        self.assertIn("sc.exe", html)

    def test_only_the_first_line_of_the_error_is_shown(self) -> None:
        # These carry a full PowerShell stack trace. The namespace error on
        # line one identifies it; the rest fills the table with call sites.
        html = _degraded_collection_section(_summary(tasks_fell_back=True))

        self.assertIn("Invalid namespace", html)
        self.assertNotIn("At line:5", html)

    def test_a_missing_status_is_not_treated_as_a_fallback(self) -> None:
        # An older summary, or a run with the collectors disabled.
        self.assertEqual(_degraded_collection_section({}), "")


if __name__ == "__main__":
    unittest.main()
