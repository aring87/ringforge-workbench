"""Background Windows activity must not be attributed to the sample.

Reconstructed from a memory-canary run -- a PowerShell script that assembles a
string and exits. It reported three spawned processes, scored 24, and came back
"Needs Review / Medium". None of the three had the sample as a parent:

    svchost.exe  -> C:\\WINDOWS\\uus\\AMD64\\MoUsoCoreWorker.exe
    svchost.exe  -> C:\\WINDOWS\\system32\\AUDIODG.EXE
    msedgewebview2.exe -> msedgewebview2.exe   (Copilot's WebView host)

MoUsoCoreWorker was already listed as svchost maintenance. It was reported
anyway because the check required the binary to live in System32, and Windows
11 services it out of the Update Universal Store at %WINDIR%\\uus\\<arch>\\
instead. The path requirement is deliberate -- usoclient.exe is a documented
LOLBin and a copy running from somewhere else should still be reported -- so
the fix widens the trusted roots rather than dropping the check.
"""

import unittest

from dynamic_analysis.findings import (
    summarize_dynamic_findings,
    _is_noise_process,
    _is_windows_baseline_process_create,
)


class SvchostMaintenanceTests(unittest.TestCase):
    def test_mousocoreworker_from_the_update_store_is_baseline(self) -> None:
        self.assertTrue(
            _is_windows_baseline_process_create(
                "svchost.exe",
                r"C:\WINDOWS\uus\AMD64\MoUsoCoreWorker.exe",
                'PID: 1100, Command line: "C:\\WINDOWS\\uus\\AMD64\\MoUsoCoreWorker.exe" useprivatenamespaces',
            )
        )

    def test_mousocoreworker_from_system32_still_is(self) -> None:
        # The path that already worked must keep working.
        self.assertTrue(
            _is_windows_baseline_process_create(
                "svchost.exe",
                r"C:\Windows\System32\MoUsoCoreWorker.exe",
                "Command line: MoUsoCoreWorker.exe",
            )
        )

    def test_audiodg_is_baseline(self) -> None:
        self.assertTrue(
            _is_windows_baseline_process_create(
                "svchost.exe",
                r"C:\WINDOWS\system32\AUDIODG.EXE",
                "PID: 8484, Command line: C:\\WINDOWS\\system32\\AUDIODG.EXE 0x51C 0x518",
            )
        )

    def test_a_maintenance_name_from_an_untrusted_path_is_still_reported(self) -> None:
        # The whole reason the roots are checked: a LOLBin name running from
        # somewhere it does not belong is exactly the interesting case.
        self.assertFalse(
            _is_windows_baseline_process_create(
                "svchost.exe",
                r"C:\Users\adam\AppData\Local\Temp\MoUsoCoreWorker.exe",
                "Command line: MoUsoCoreWorker.exe",
            )
        )

    def test_a_trusted_path_with_a_suspicious_command_line_is_still_reported(self) -> None:
        self.assertFalse(
            _is_windows_baseline_process_create(
                "svchost.exe",
                r"C:\Windows\System32\usoclient.exe",
                "Command line: usoclient.exe -enc SQBFAFgA",
            )
        )

    def test_an_unrelated_child_of_svchost_is_not_waved_through(self) -> None:
        self.assertFalse(
            _is_windows_baseline_process_create(
                "svchost.exe",
                r"C:\Windows\System32\cmd.exe",
                "Command line: cmd.exe /c whoami",
            )
        )


class WebViewNoiseTests(unittest.TestCase):
    def test_the_webview_host_is_noise(self) -> None:
        self.assertTrue(_is_noise_process("msedgewebview2.exe"))

    def test_it_is_matched_regardless_of_case(self) -> None:
        self.assertTrue(_is_noise_process("MsEdgeWebView2.exe"))

    def test_the_sample_process_is_not_noise(self) -> None:
        self.assertFalse(_is_noise_process("powershell.exe"))


class NoiseChildTests(unittest.TestCase):
    """On a process create, the created process is the one the path names.

    An AgentTesla run reported a suspicious path hit for

        svchost.exe -> C:\\Users\\adam\\AppData\\Local\\Microsoft\\OneDrive\\
                       26.134.0713.0003\\OneDriveLauncher.exe

    even though onedrivelauncher.exe is listed as a noise process. Only the
    parent was tested against that list, and the parent was svchost. The user-
    writable heuristic had just been repaired, so an executable under AppData
    started registering for the first time -- and the first thing it caught was
    OneDrive starting.
    """

    def _event(self, op, proc, path, detail=""):
        return {
            "Operation": op,
            "Process Name": proc,
            "Path": path,
            "Detail": detail,
            "Time of Day": "5:39:50 PM",
        }

    def _hits(self, events):
        return summarize_dynamic_findings(
            events, events, sample_pid=8744, sample_name="sample.exe"
        )["suspicious_path_hits"]

    def test_a_noise_child_is_not_a_suspicious_path(self) -> None:
        event = self._event(
            "Process Create",
            "svchost.exe",
            r"C:\Users\adam\AppData\Local\Microsoft\OneDrive\26.1\OneDriveLauncher.exe",
            "PID: 8016, Command line: OneDriveLauncher.exe /startInstances",
        )

        self.assertEqual(self._hits([event]), [])

    def test_a_real_dropped_executable_still_is(self) -> None:
        event = self._event(
            "Process Create",
            "svchost.exe",
            r"C:\Users\adam\AppData\Local\Temp\payload.exe",
            "PID: 8017, Command line: payload.exe",
        )

        self.assertEqual(len(self._hits([event])), 1)

    def test_a_file_write_is_judged_on_its_own_terms(self) -> None:
        # The path here is a file, not a process. Reading it as one would
        # suppress on a filename that merely matches a noise process name.
        event = self._event(
            "WriteFile",
            "sample.exe",
            r"C:\Users\adam\AppData\Local\Temp\onedrive.exe",
            "",
        )

        self.assertEqual(len(self._hits([event])), 1)


class CopilotNetworkTests(unittest.TestCase):
    def test_copilot_is_not_the_sample_s_network_traffic(self) -> None:
        self.assertTrue(_is_noise_process("M365Copilot.exe"))

    def test_the_sample_s_own_traffic_still_counts(self) -> None:
        self.assertFalse(_is_noise_process("sample.exe"))


if __name__ == "__main__":
    unittest.main()
