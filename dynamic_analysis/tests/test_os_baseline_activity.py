"""Windows acting on itself is not the sample acting.

Both cases here come from the same mimikatz.upx detonation, and both were
reported as the sample's behaviour:

    dwm.exe -> csrss.exe        CreateRemoteThread, severity high
    services.exe -> svchost.exe -k GPSvcGroup

The injection one mattered most. It was the only high-severity finding in the
entire report, and the ATT&CK mapping turned it into "T1055 Process Injection"
with the sample's name on it. On a credential dumper that reads as completely
plausible -- which is exactly why it needs filtering rather than leaving for
the reader to recognise.

Both filters are deliberately narrow. Injection and svchost masquerading are
real techniques, so each requires the genuine System32 image and an unremarkable
command line; a copy of either running from somewhere else is still a finding.
"""

import unittest

from dynamic_analysis.findings import _is_windows_baseline_process_create
from dynamic_analysis.sysmon_collector import _is_os_baseline_event


def _injection(source: str, target: str) -> dict:
    return {
        "event_id": 8,
        "event_name": "CreateRemoteThread",
        "data": {"SourceImage": source, "TargetImage": target},
    }


DWM = r"C:\Windows\System32\dwm.exe"
CSRSS = r"C:\Windows\System32\csrss.exe"


class WindowsInjectionTests(unittest.TestCase):
    def test_dwm_into_csrss_is_os_baseline(self) -> None:
        self.assertTrue(_is_os_baseline_event(_injection(DWM, CSRSS)))

    def test_a_dwm_copy_outside_system32_is_still_a_finding(self) -> None:
        self.assertFalse(
            _is_os_baseline_event(
                _injection(r"C:\Users\adam\AppData\Local\Temp\dwm.exe", CSRSS)
            )
        )

    def test_a_csrss_copy_outside_system32_is_still_a_finding(self) -> None:
        self.assertFalse(
            _is_os_baseline_event(
                _injection(DWM, r"C:\Users\adam\AppData\Local\Temp\csrss.exe")
            )
        )

    def test_the_pair_is_directional(self) -> None:
        # csrss injecting into dwm is not the documented behaviour and is not
        # on the list.
        self.assertFalse(_is_os_baseline_event(_injection(CSRSS, DWM)))

    def test_an_unlisted_pair_is_still_a_finding(self) -> None:
        self.assertFalse(
            _is_os_baseline_event(
                _injection(r"C:\samples\mimikatz.exe", r"C:\Windows\System32\lsass.exe")
            )
        )

    def test_only_createremotethread_is_considered(self) -> None:
        event = _injection(DWM, CSRSS)
        event["event_id"] = 10  # ProcessAccess
        self.assertFalse(_is_os_baseline_event(event))


class ServiceHostStartupTests(unittest.TestCase):
    DETAIL = "PID: 6932, Command line: C:\\WINDOWS\\system32\\svchost.exe -k GPSvcGroup"

    def test_services_starting_a_host_group_is_baseline(self) -> None:
        self.assertTrue(
            _is_windows_baseline_process_create(
                "services.exe", r"C:\WINDOWS\system32\svchost.exe", self.DETAIL
            )
        )

    def test_another_group_is_also_baseline(self) -> None:
        # Which groups appear depends on what the machine does during the run.
        self.assertTrue(
            _is_windows_baseline_process_create(
                "services.exe",
                r"C:\WINDOWS\system32\svchost.exe",
                "Command line: svchost.exe -k netsvcs -p",
            )
        )

    def test_svchost_from_outside_system32_is_still_a_finding(self) -> None:
        self.assertFalse(
            _is_windows_baseline_process_create(
                "services.exe",
                r"C:\Users\adam\AppData\Local\Temp\svchost.exe",
                "Command line: svchost.exe -k netsvcs",
            )
        )

    def test_svchost_without_a_group_is_still_a_finding(self) -> None:
        self.assertFalse(
            _is_windows_baseline_process_create(
                "services.exe",
                r"C:\WINDOWS\system32\svchost.exe",
                "Command line: svchost.exe",
            )
        )

    def test_a_suspicious_command_line_is_still_a_finding(self) -> None:
        self.assertFalse(
            _is_windows_baseline_process_create(
                "services.exe",
                r"C:\WINDOWS\system32\svchost.exe",
                "Command line: svchost.exe -k netsvcs -enc SQBFAFgA",
            )
        )

    def test_a_different_parent_is_still_a_finding(self) -> None:
        # services.exe is the only legitimate launcher of a service host.
        self.assertFalse(
            _is_windows_baseline_process_create(
                "mimikatz.exe",
                r"C:\WINDOWS\system32\svchost.exe",
                "Command line: svchost.exe -k netsvcs",
            )
        )


if __name__ == "__main__":
    unittest.main()
