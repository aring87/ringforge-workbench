"""Opening ntdll as a file, which is how self-unhooking starts.

Asserted against full Procmon path strings rather than against the module's own
constants -- the standing rule here after 46 markers in this package were once
written regex-style and matched nothing for the life of the project. A test that
reuses the constant it is testing cannot catch that class of bug.
"""
import unittest

from dynamic_analysis.ntdll_unhooking import (
    classify_unhook_target,
    collect_ntdll_unhooking,
    empty_ntdll_unhooking,
    is_file_open,
)

SYSTEM32 = r"C:\Windows\System32\ntdll.dll"
SYSWOW64 = r"C:\Windows\SysWOW64\ntdll.dll"
NT_PATH = r"\??\ntdll.dll"
DROPPED = r"C:\Users\admin\AppData\Local\Temp\ntdll.dll"


def _open(path, process="RegSvcs.exe", pid=9592, operation="CreateFile"):
    return {
        "process_name": process, "pid": pid, "operation": operation,
        "path": path, "result": "SUCCESS", "timestamp": "10:00:00.1",
        "category": "file_create" if operation == "CreateFile" else "other",
    }


class Classification(unittest.TestCase):
    def test_real_paths_match(self):
        for path in (SYSTEM32, SYSWOW64, NT_PATH, "ntdll.dll"):
            with self.subTest(path=path):
                found = classify_unhook_target(path)
                self.assertIsNotNone(found, path)
                self.assertEqual(found["module"], "ntdll.dll")

    def test_case_and_forward_slashes_do_not_defeat_it(self):
        self.assertIsNotNone(classify_unhook_target(r"C:\WINDOWS\SYSTEM32\NTDLL.DLL"))
        self.assertIsNotNone(classify_unhook_target("C:/Windows/System32/ntdll.dll"))

    def test_a_dropped_same_named_file_is_not_this_finding(self):
        # A copied ntdll.dll in Temp is a dropped payload and belongs to the
        # dropped-file pass. Counting it here would describe one act wrongly
        # and count it twice.
        self.assertIsNone(classify_unhook_target(DROPPED))

    def test_other_system_dlls_classify_but_are_not_primary(self):
        found = classify_unhook_target(r"C:\Windows\System32\kernel32.dll")
        self.assertEqual(found["module"], "kernel32.dll")
        self.assertEqual(found["primary"], "")
        self.assertEqual(classify_unhook_target(SYSTEM32)["primary"], "yes")

    def test_unrelated_paths_are_none(self):
        for path in ("", r"C:\Windows\System32\kernel32.dll.mui",
                     r"C:\Windows\System32\drivers\etc\hosts",
                     r"C:\Windows\System32\ntdllx.dll",
                     r"C:\Windows\System32\wow64.dll"):
            with self.subTest(path=path):
                self.assertIsNone(classify_unhook_target(path))


class OperationGate(unittest.TestCase):
    def test_load_image_is_not_a_file_open(self):
        # Every process maps ntdll. If Load Image counted, this detector would
        # fire on the whole machine and mean nothing.
        self.assertFalse(is_file_open(_open(SYSTEM32, operation="Load Image")))

    def test_createfile_is(self):
        self.assertTrue(is_file_open(_open(SYSTEM32)))

    def test_load_image_of_ntdll_produces_no_hit(self):
        result = collect_ntdll_unhooking(
            [_open(SYSTEM32, operation="Load Image")], {9592})
        self.assertEqual(result["counts"]["ntdll_opens_by_sample"], 0)


class Collection(unittest.TestCase):
    def test_hollowing_target_open_is_the_emphatic_case(self):
        result = collect_ntdll_unhooking([_open(NT_PATH)], {9592})
        self.assertEqual(result["counts"]["ntdll_opens_by_sample"], 1)
        self.assertEqual(result["counts"]["ntdll_opens_in_hollowing_target"], 1)
        self.assertTrue(result["opens"][0]["hollowing_target"])

    def test_non_hollowing_target_counts_but_is_not_emphatic(self):
        result = collect_ntdll_unhooking(
            [_open(SYSTEM32, process="mytool.exe", pid=42)], {42})
        self.assertEqual(result["counts"]["ntdll_opens_by_sample"], 1)
        self.assertEqual(result["counts"]["ntdll_opens_in_hollowing_target"], 0)

    def test_background_opens_are_counted_not_dropped(self):
        # The false-positive baseline. Without it there is no way to know
        # whether this signal is worth anything.
        events = [_open(SYSTEM32, process="svchost.exe", pid=700),
                  _open(NT_PATH, process="RegSvcs.exe", pid=9592)]
        result = collect_ntdll_unhooking(events, {9592})
        self.assertEqual(result["counts"]["ntdll_opens_by_sample"], 1)
        self.assertEqual(result["counts"]["system_dll_opens_by_others"], 1)
        self.assertEqual(result["background_opens"][0]["process"], "svchost.exe")

    def test_unresolved_lineage_counts_everything(self):
        result = collect_ntdll_unhooking([_open(SYSTEM32, pid=700)], None)
        self.assertEqual(result["counts"]["ntdll_opens_by_sample"], 1)
        self.assertFalse(result["attributed_by_lineage"])

    def test_empty_tree_attributes_nothing(self):
        result = collect_ntdll_unhooking([_open(SYSTEM32, pid=700)], set())
        self.assertEqual(result["counts"]["ntdll_opens_by_sample"], 0)
        self.assertEqual(result["counts"]["system_dll_opens_by_others"], 1)

    def test_a_capture_with_no_file_opens_says_so(self):
        # Zero from a config that captured no CreateFile is a statement about
        # the config, not about the sample.
        result = collect_ntdll_unhooking([], {9592})
        self.assertFalse(result["collection_available"])

    def test_a_capture_with_opens_but_no_hits_is_available(self):
        result = collect_ntdll_unhooking(
            [_open(r"C:\Windows\System32\drivers\etc\hosts")], {9592})
        self.assertTrue(result["collection_available"])
        self.assertEqual(result["counts"]["ntdll_opens_by_sample"], 0)

    def test_nothing_here_is_scored(self):
        result = collect_ntdll_unhooking([_open(NT_PATH)], {9592})
        self.assertFalse(result["scored"])
        self.assertFalse(empty_ntdll_unhooking()["scored"])

    def test_modules_lists_what_was_opened(self):
        events = [_open(NT_PATH), _open(r"C:\Windows\System32\kernel32.dll")]
        result = collect_ntdll_unhooking(events, {9592})
        self.assertEqual(result["modules"], ["kernel32.dll", "ntdll.dll"])


class ReportSection(unittest.TestCase):
    def _summary(self, events, pids={9592}):
        return {"ntdll_unhooking": collect_ntdll_unhooking(events, pids)}

    def test_reaches_the_rendered_page(self):
        from dynamic_analysis.html_report import build_dynamic_html_report

        html = build_dynamic_html_report(self._summary([_open(NT_PATH)]))
        self.assertIn("System DLLs Opened As Files", html)
        self.assertIn("RegSvcs.exe", html)

    def test_absent_from_a_run_that_did_not_have_the_pass(self):
        from dynamic_analysis.html_report import build_dynamic_html_report

        self.assertNotIn("System DLLs Opened As Files",
                         build_dynamic_html_report({}))

    def test_uncollected_differs_from_clean(self):
        from dynamic_analysis.html_report import _ntdll_unhooking_section

        clean = _ntdll_unhooking_section(self._summary(
            [_open(r"C:\Windows\System32\drivers\etc\hosts")]))
        uncollected = _ntdll_unhooking_section(self._summary([]))
        self.assertNotEqual(clean, uncollected)
        self.assertIn("Not Collected", uncollected)
        self.assertIn("not</b> about the sample", uncollected)

    def test_badge_stays_neutral_because_nothing_here_is_scored(self):
        # The section heading says "not scored". An amber badge would contradict
        # it, which is exactly what test_report_badges.py exists to prevent.
        from dynamic_analysis.html_report import _ntdll_unhooking_section

        many = [_open(NT_PATH) for _ in range(12)]
        html = _ntdll_unhooking_section(self._summary(many))
        self.assertIn("sev-none", html)
        self.assertNotIn("sev-high", html)


if __name__ == "__main__":
    unittest.main()
