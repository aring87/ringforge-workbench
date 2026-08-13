"""`is_analyzer_image` must work for the inputs its callers actually pass.

Written after a sweep prompted by three attribution bugs in one day -- WerFault
credited to the sample, procdump inflating a false-positive baseline, and a
child's crash dump disowned. All three were "the lineage existed and the
consumer was not using it", so the sweep asked which other consumers are weaker
than the evidence available to them.

What it found was narrower and more specific than expected. The helper's
docstring promises "a path **or image name**", and two of its markers carried
path separators, so they could only ever match the first form:

    is_analyzer_image(r"C:\\rf\\tools\\fakenet\\fakenet.exe")  -> True
    is_analyzer_image("fakenet.exe")                          -> False

Procmon reports a bare `Process Name`, so any pass keyed on that missed FakeNet
-- which runs during every run. `sysmon_collector` passes full `Image` paths and
was unaffected, which is why this survived: the gap only opens for a
name-passing caller, and the first one arrived yesterday.
"""
import unittest

from dynamic_analysis.utils import is_analyzer_image, is_windows_response_process


class BareProcessNames(unittest.TestCase):
    """Every tool the pipeline actually launches, by bare name."""

    LAUNCHED = [
        "procdump64.exe", "procmon64.exe", "procmon.exe", "autorunsc64.exe",
        "sysmon64.exe", "fakenet.exe", "tshark.exe", "dumpcap.exe",
    ]

    def test_every_tool_the_pipeline_runs_is_recognised_by_name(self):
        for name in self.LAUNCHED:
            with self.subTest(name=name):
                self.assertTrue(is_analyzer_image(name),
                                f"{name} is analyzer tooling and was not matched")

    def test_the_same_tools_are_recognised_by_full_path(self):
        for name in self.LAUNCHED:
            with self.subTest(name=name):
                self.assertTrue(
                    is_analyzer_image(rf"C:\rf\tools\{name}"))

    def test_fakenet_specifically(self):
        # The regression. `\fakenet` could not match a bare name.
        self.assertTrue(is_analyzer_image("fakenet.exe"))
        self.assertTrue(is_analyzer_image(r"C:\rf\tools\fakenet\fakenet.exe"))


class DeliberateNonMembers(unittest.TestCase):
    """Things that must NOT be suppressed, so the list stays a filter."""

    def test_wireshark_stays_a_directory_marker(self):
        # Not RingForge tooling -- the pipeline captures with tshark/dumpcap.
        # The marker exists to catch an analyst's installed copy by directory;
        # broadening it would suppress a *sample* named wireshark.exe.
        self.assertTrue(is_analyzer_image(r"C:\Program Files\Wireshark\x.exe"))
        self.assertFalse(is_analyzer_image("wireshark.exe"))

    def test_python_is_not_suppressed(self):
        # The analyzer runs on Python, but so does Cuckoo's agent -- python.exe
        # is on this sample's own anti-analysis blocklist. Suppressing it here
        # would blind the pipeline to a sample that is a Python script.
        self.assertFalse(is_analyzer_image("python.exe"))

    def test_ordinary_software_is_not_suppressed(self):
        for name in ("explorer.exe", "chrome.exe", "svchost.exe", "regsvcs.exe",
                     "notepad.exe", ""):
            with self.subTest(name=name):
                self.assertFalse(is_analyzer_image(name))


class WindowsResponseStillNarrow(unittest.TestCase):
    def test_werfault_family(self):
        for name in ("WerFault.exe", "werfaultsecure.exe", "wermgr.exe",
                     r"C:\Windows\SysWOW64\WerFault.exe"):
            with self.subTest(name=name):
                self.assertTrue(is_windows_response_process(name))

    def test_it_has_not_quietly_grown(self):
        # The list is deliberately three names. A suppression list that grows on
        # speculation is how attribution gets replaced by a name list.
        from dynamic_analysis.utils import WINDOWS_RESPONSE_PROCESSES

        self.assertEqual(len(WINDOWS_RESPONSE_PROCESSES), 3)

    def test_the_sample_and_its_children_are_not_suppressed(self):
        for name in ("regsvcs.exe", "powershell.exe", "explorer.exe"):
            with self.subTest(name=name):
                self.assertFalse(is_windows_response_process(name))


if __name__ == "__main__":
    unittest.main()
