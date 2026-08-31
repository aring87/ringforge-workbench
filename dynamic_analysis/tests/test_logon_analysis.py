import unittest

from dynamic_analysis.logon_analysis import analyse_logon_capture

PAYLOAD = "ce0d08be.exe"
PAYLOAD_PATH = r"C:\Users\adam\AppData\Roaming\PlatformRuntime\ce0d08be.exe"
VBOX_KEY = r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions"


def _create(parent_name, parent_pid, child_path, child_pid):
    return {
        "timestamp": "04:22:05.0 PM",
        "process_name": parent_name,
        "pid": parent_pid,
        "operation": "Process Create",
        "path": child_path,
        "result": "SUCCESS",
        "detail": f"PID: {child_pid}, Command line: {child_path}",
        "category": "process_create",
    }


def _read(process, pid, path, result="SUCCESS"):
    return {
        "timestamp": "04:22:06.0 PM",
        "process_name": process,
        "pid": pid,
        "operation": "RegOpenKey",
        "path": path,
        "result": result,
        "detail": "",
        "category": "registry_read",
    }


class LineageTests(unittest.TestCase):
    def test_a_payload_with_no_launched_pid_is_still_attributed(self) -> None:
        # The case this exists for. Nothing in the run started it -- the Task
        # Scheduler did -- so there is no sample_pid. Seeding on the image name
        # is what `_mark_sample_lineage` already does, and it is enough.
        events = [
            _create("svchost.exe", 984, PAYLOAD_PATH, 3760),
            _read(PAYLOAD, 3760, VBOX_KEY),
        ]

        result = analyse_logon_capture(events, PAYLOAD)

        self.assertTrue(result["lineage_resolved"])
        self.assertIn(3760, result["descendant_pids"])
        self.assertEqual(result["vm_artifact_reads"]["counts"]["vm_specific"], 1)
        self.assertEqual(result["vm_check_and_bail"]["verdict"], "checked_then_quiet")

    def test_a_child_of_the_payload_is_attributed_too(self) -> None:
        events = [
            _create("svchost.exe", 984, PAYLOAD_PATH, 3760),
            _create(PAYLOAD, 3760, r"C:\WINDOWS\SYSTEM32\schtasks.exe", 12228),
            _read("schtasks.exe", 12228, VBOX_KEY),
        ]

        result = analyse_logon_capture(events, PAYLOAD)

        self.assertIn(12228, result["descendant_pids"])
        self.assertEqual(result["vm_artifact_reads"]["counts"]["vm_specific"], 1)

    def test_windows_reading_the_same_key_is_not_the_payload(self) -> None:
        # Measured 31 Aug: 448 VM-artifact reads on one ordinary boot, every one
        # background. Without lineage this pass would report the machine's own
        # boot as the payload checking for a VM.
        events = [
            _create("svchost.exe", 984, PAYLOAD_PATH, 3760),
            _read("services.exe", 984, VBOX_KEY),
            _read("VBoxService.exe", 1724, VBOX_KEY),
        ]

        result = analyse_logon_capture(events, PAYLOAD)

        self.assertEqual(result["vm_artifact_reads"]["counts"]["artifacts_read"], 0)
        self.assertEqual(result["vm_artifact_reads"]["counts"]["background_artifact_reads"], 2)
        self.assertEqual(result["vm_check_and_bail"]["verdict"], "no_vm_check")


class HonestyTests(unittest.TestCase):
    def test_an_unfired_task_is_not_reported_as_a_quiet_payload(self) -> None:
        # Nothing ran the image. That is "cannot tell", not "did nothing", and
        # the note has to say which.
        events = [_read("services.exe", 984, VBOX_KEY)]

        result = analyse_logon_capture(events, PAYLOAD)

        self.assertFalse(result["lineage_resolved"])
        self.assertIn("did not fire", result["note"])
        self.assertNotIn("payload did nothing", result["note"].replace(
            "This is not a statement that the payload did nothing.", ""))

    def test_a_failed_capture_says_so_before_anything_else(self) -> None:
        manifest = {"completed": False, "reason": "ProcmonError: Procmon not found"}

        result = analyse_logon_capture([], PAYLOAD, manifest=manifest)

        self.assertFalse(result["capture_completed"])
        self.assertIn("did not complete", result["note"])
        self.assertIn("Procmon not found", result["note"])

    def test_a_filter_that_could_not_see_reads_is_carried_through(self) -> None:
        # The caveat must not be left behind in the other file.
        manifest = {
            "completed": True,
            "procmon_filter": {"captures_registry_reads": False},
        }
        events = [_create("svchost.exe", 984, PAYLOAD_PATH, 3760)]

        result = analyse_logon_capture(events, PAYLOAD, manifest=manifest)

        self.assertTrue(result["capture_completed"])
        self.assertFalse(result["captures_registry_reads"])
        self.assertIn("could not have seen", result["note"])

    def test_a_clean_run_carries_no_caveat(self) -> None:
        manifest = {
            "completed": True,
            "procmon_filter": {"captures_registry_reads": True},
        }
        events = [
            _create("svchost.exe", 984, PAYLOAD_PATH, 3760),
            _read(PAYLOAD, 3760, r"HKLM\Software\Microsoft\Windows"),
        ]

        result = analyse_logon_capture(events, PAYLOAD, manifest=manifest)

        self.assertEqual(result["note"], "")
        self.assertTrue(result["captures_registry_reads"])


if __name__ == "__main__":
    unittest.main()
