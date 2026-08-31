"""Gap 4's other half: what the sample read about the machine it was on.

The chain-crashed warning refuses to let a crashed chain read as a clean run, and
that is as far as it can go -- from outside the guest a deliberate bail and a
broken payload leave the same trace. The one observation that separates them is
whether the sample enumerated the hypervisor before it went quiet, and nothing in
the pipeline could see that: the Procmon config drops every registry read at
capture time, so `RegQueryValue` on `SystemBiosVersion` never reached the CSV.

These tests assert against full Procmon path strings rather than against the
marker constants, because the constants are exactly what was wrong the last time
this package grew a list of path literals -- 46 of them, dead for the life of the
project, and 332 passing tests over the top.

The collection is not scored. A read is not an action, and ordinary software
reads hardware identity.
"""

import shutil
import unittest
from pathlib import Path

from dynamic_analysis.procmon_parser import (
    INTERESTING_OPS,
    _is_high_signal_event,
    find_interesting_events,
    normalize_procmon_row,
    parse_procmon_csv,
)
from dynamic_analysis.vm_artifact_reads import (
    classify_vm_artifact_path,
    collect_vm_artifact_reads,
    empty_vm_artifact_reads,
    is_registry_read,
)


# Paths exactly as Procmon writes them: a key read gives the key, a value read
# gives key\value.
VBOX_SERVICE_KEY = r"HKLM\System\CurrentControlSet\Services\VBoxGuest"
VBOX_SERVICE_VALUE = r"HKLM\System\CurrentControlSet\Services\VBoxGuest\ImagePath"
BIOS_VERSION = r"HKLM\HARDWARE\DESCRIPTION\System\SystemBiosVersion"
GUEST_ADDITIONS = r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions\Version"
ACPI_TABLE = r"HKLM\HARDWARE\ACPI\DSDT\VBOX__"
DISK_IDENTIFIER = (
    r"HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0"
    r"\Logical Unit Id 0\Identifier"
)
ORDINARY_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"


def _read(path: str, pid: int = 8784, result: str = "SUCCESS",
          operation: str = "RegQueryValue", process: str = "sample.exe"):
    return {
        "category": "registry_read",
        "operation": operation,
        "path": path,
        "result": result,
        "process_name": process,
        "pid": pid,
        "timestamp": "10:54:47 PM",
    }


class MarkersMatchRealPathsTests(unittest.TestCase):
    """Every marker asserted against a path Windows really produces."""

    def test_the_guest_additions_service_key_is_virtualbox_specific(self) -> None:
        hit = classify_vm_artifact_path(VBOX_SERVICE_KEY)

        self.assertIsNotNone(hit)
        self.assertEqual(hit["family"], "virtualbox")
        self.assertEqual(hit["specificity"], "vm_specific")

    def test_a_value_under_that_key_matches_too(self) -> None:
        # A value read appends the value name, so a marker anchored on the key
        # has to survive the suffix.
        self.assertIsNotNone(classify_vm_artifact_path(VBOX_SERVICE_VALUE))

    def test_the_bios_version_is_an_identity_surface_not_a_vm_key(self) -> None:
        # The distinction the whole table exists for. This is where a VM check
        # looks for "VBOX" -- and where an inventory agent looks for a BIOS
        # version. Treating the two alike is how a detector ends up firing on
        # every machine in the estate.
        hit = classify_vm_artifact_path(BIOS_VERSION)

        self.assertEqual(hit["specificity"], "identity_surface")
        self.assertEqual(hit["family"], "firmware identity")

    def test_every_family_matches_something_real(self) -> None:
        for path, family in (
            (GUEST_ADDITIONS, "virtualbox"),
            (ACPI_TABLE, "virtualbox"),
            (r"HKLM\System\CurrentControlSet\Services\VMTools", "vmware"),
            (r"HKLM\System\CurrentControlSet\Services\netkvm\Parameters", "qemu"),
            (r"HKLM\System\CurrentControlSet\Services\xenevtchn", "xen"),
            (r"HKLM\System\CurrentControlSet\Services\vmbus\Enum", "hyper-v"),
            (r"HKLM\SOFTWARE\Wine", "wine"),
            (DISK_IDENTIFIER, "device identity"),
            (r"HKLM\System\CurrentControlSet\Services\mssmbios\Data\SMBiosData",
             "firmware identity"),
            (r"HKLM\System\CurrentControlSet\Enum\IDE", "device identity"),
        ):
            with self.subTest(path=path):
                hit = classify_vm_artifact_path(path)
                self.assertIsNotNone(hit, f"no marker matched {path}")
                self.assertEqual(hit["family"], family)

    def test_an_ordinary_key_matches_nothing(self) -> None:
        self.assertIsNone(classify_vm_artifact_path(ORDINARY_KEY))
        self.assertIsNone(classify_vm_artifact_path(""))


class ReadCategoryTests(unittest.TestCase):
    def test_the_read_operations_are_categorised(self) -> None:
        for operation in ("RegQueryValue", "RegOpenKey"):
            with self.subTest(operation=operation):
                self.assertEqual(INTERESTING_OPS[operation], "registry_read")

    def test_a_csv_row_normalises_to_a_read(self) -> None:
        row = {
            "Time of Day": "10:54:47.1 PM",
            "Process Name": "sample.exe",
            "PID": "8784",
            "Operation": "RegOpenKey",
            "Path": VBOX_SERVICE_KEY,
            "Result": "NAME NOT FOUND",
            "Detail": "Desired Access: Read",
        }

        event = normalize_procmon_row(row)

        self.assertEqual(event["category"], "registry_read")
        self.assertTrue(is_registry_read(event))

    def test_a_read_is_never_a_high_signal_event(self) -> None:
        # Deliberate. Registry reads are the highest-volume operation on a
        # Windows box, and the fall-through in `_is_high_signal_event` matches
        # any suspicious path -- so letting reads through would put every process
        # that so much as reads a Run key into the findings. The one question a
        # read answers has its own pass.
        run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

        self.assertFalse(_is_high_signal_event(_read(run_key, operation="RegQueryValue")))
        self.assertFalse(_is_high_signal_event(_read(VBOX_SERVICE_KEY)))


class LineageTests(unittest.TestCase):
    def test_only_the_samples_tree_is_attributed(self) -> None:
        # Windows reads these keys itself: the Service Control Manager
        # enumerates every service key including the guest additions'. Without
        # lineage this pass would report the machine's own boot as the sample
        # checking for a VM.
        events = [
            _read(VBOX_SERVICE_KEY, pid=8784),
            _read(VBOX_SERVICE_KEY, pid=612, process="services.exe"),
        ]

        result = collect_vm_artifact_reads(events, descendant_pids={8784})

        self.assertEqual(len(result["hits"]), 1)
        self.assertEqual(result["hits"][0]["pid"], 8784)
        self.assertEqual(result["counts"]["background_artifact_reads"], 1)

    def test_the_background_count_is_reported_not_dropped(self) -> None:
        # "Windows read it 400 times and the sample never did" is the answer, not
        # noise to hide. A pass that reported nothing and a pass that was not
        # working must not look alike.
        events = [_read(BIOS_VERSION, pid=612, process="svchost.exe")] * 3

        result = collect_vm_artifact_reads(events, descendant_pids={8784})

        self.assertEqual(result["hits"], [])
        self.assertEqual(result["background_reads"], 3)
        self.assertEqual(result["counts"]["background_artifact_reads"], 3)

    def test_the_background_rows_are_returned_not_only_counted(self) -> None:
        # A count cannot say *who*. On run `ce0d08be...` the three background
        # artifact reads were the only lead the run produced, and the pass
        # reported the number and threw the rows away -- so "the sample never
        # checked" and "the copy it relaunched checked, outside the tree" read
        # identically.
        events = [
            _read(GUEST_ADDITIONS, pid=612, process="svchost.exe"),
            _read(BIOS_VERSION, pid=4021, process="ce0d08be.exe"),
        ]

        result = collect_vm_artifact_reads(events, descendant_pids={8784})

        self.assertEqual(result["hits"], [])
        self.assertEqual(result["counts"]["background_artifact_reads"], 2)
        self.assertEqual(
            [(h["pid"], h["process_name"], h["specificity"]) for h in result["background_hits"]],
            [(612, "svchost.exe", "vm_specific"), (4021, "ce0d08be.exe", "identity_surface")],
        )

    def test_unresolved_lineage_counts_everything(self) -> None:
        # The same degrade the findings, the PowerShell blocks and the dropped
        # files use: None means "could not resolve", not "the tree is empty".
        events = [_read(VBOX_SERVICE_KEY, pid=612, process="services.exe")]

        result = collect_vm_artifact_reads(events, descendant_pids=None)

        self.assertEqual(len(result["hits"]), 1)
        self.assertFalse(result["lineage_resolved"])

    def test_an_empty_tree_attributes_nothing(self) -> None:
        events = [_read(VBOX_SERVICE_KEY, pid=612)]

        result = collect_vm_artifact_reads(events, descendant_pids=set())

        self.assertEqual(result["hits"], [])
        self.assertTrue(result["lineage_resolved"])


class CollectionAvailabilityTests(unittest.TestCase):
    """The two zeroes that mean opposite things."""

    def test_a_stream_with_no_reads_says_the_collection_was_absent(self) -> None:
        # Every run this project has performed is this case: the default Procmon
        # config carries sixteen Operation include rules and none of them is a
        # read, with DestructiveFilter on, so the events do not exist to be
        # parsed. Zero artifacts read here is a statement about the config.
        events = [
            {"category": "file_write", "operation": "WriteFile",
             "path": r"C:\Users\adam\AppData\Roaming\Config\smng.exe", "pid": 8784},
        ]

        result = collect_vm_artifact_reads(events, descendant_pids={8784})

        self.assertFalse(result["collection_available"])
        self.assertEqual(result["reads_in_stream"], 0)
        self.assertIn("did not capture registry reads", result["note"])
        self.assertIn("dynamic_registry_reads.pmc", result["note"])

    def test_reads_present_and_no_artifacts_says_the_sample_did_not_look(self) -> None:
        events = [_read(ORDINARY_KEY, pid=8784)]

        result = collect_vm_artifact_reads(events, descendant_pids={8784})

        self.assertTrue(result["collection_available"])
        self.assertEqual(result["counts"]["artifacts_read"], 0)
        self.assertIn("read none of the known", result["note"])


class ResultTests(unittest.TestCase):
    def test_a_missing_key_records_the_artifact_as_absent(self) -> None:
        # A check for the guest additions on a machine that does not have them
        # comes back NAME NOT FOUND, and that is an answer the sample acted on
        # rather than a failed read. Not what this workbench's guest returns --
        # nothing here removes the additions -- but the module has to report
        # both directions, so both are asserted.
        result = collect_vm_artifact_reads(
            [_read(VBOX_SERVICE_KEY, result="NAME NOT FOUND", operation="RegOpenKey")],
            descendant_pids={8784},
        )

        self.assertIs(result["hits"][0]["artifact_found"], False)
        self.assertEqual(result["counts"]["artifacts_absent"], 1)
        self.assertEqual(result["counts"]["artifacts_found"], 0)

    def test_a_present_key_records_that_the_sample_was_told_it_is_in_a_vm(self) -> None:
        result = collect_vm_artifact_reads(
            [_read(VBOX_SERVICE_KEY, result="SUCCESS", operation="RegOpenKey")],
            descendant_pids={8784},
        )

        self.assertIs(result["hits"][0]["artifact_found"], True)
        self.assertEqual(result["counts"]["artifacts_found"], 1)
        self.assertIn("told it is running in a VM", result["note"])

    def test_buffer_overflow_is_a_successful_read(self) -> None:
        # A value query with an undersized buffer is the ordinary first half of a
        # two-call read. Counting it as a failure would report an artifact absent
        # that the sample went on to read in full.
        result = collect_vm_artifact_reads(
            [_read(BIOS_VERSION, result="BUFFER OVERFLOW")], descendant_pids={8784}
        )

        self.assertIs(result["hits"][0]["artifact_found"], True)

    def test_access_denied_says_only_that_the_sample_asked(self) -> None:
        result = collect_vm_artifact_reads(
            [_read(VBOX_SERVICE_KEY, result="ACCESS DENIED")], descendant_pids={8784}
        )

        self.assertIsNone(result["hits"][0]["artifact_found"])
        self.assertEqual(result["counts"]["artifacts_found"], 0)
        self.assertEqual(result["counts"]["artifacts_absent"], 0)


class ShapeTests(unittest.TestCase):
    def test_a_polled_key_is_one_check_not_a_hundred(self) -> None:
        events = [_read(VBOX_SERVICE_KEY)] * 50

        result = collect_vm_artifact_reads(events, descendant_pids={8784})

        self.assertEqual(len(result["hits"]), 1)
        # The raw read count is still reported: the dedupe is a presentation
        # choice, and a sample polling a key 50 times is worth being able to see.
        self.assertEqual(result["sample_reads"], 50)

    def test_the_same_key_from_two_processes_is_two_checks(self) -> None:
        events = [_read(VBOX_SERVICE_KEY, pid=8784), _read(VBOX_SERVICE_KEY, pid=9592)]

        result = collect_vm_artifact_reads(events, descendant_pids={8784, 9592})

        self.assertEqual(len(result["hits"]), 2)

    def test_families_and_specificity_are_counted(self) -> None:
        events = [
            _read(VBOX_SERVICE_KEY),
            _read(ACPI_TABLE),
            _read(BIOS_VERSION),
            _read(DISK_IDENTIFIER),
        ]

        result = collect_vm_artifact_reads(events, descendant_pids={8784})

        self.assertEqual(result["counts"]["artifacts_read"], 4)
        self.assertEqual(result["counts"]["vm_specific"], 2)
        self.assertEqual(result["counts"]["identity_surface"], 2)
        self.assertEqual(result["families"]["virtualbox"], 2)

    def test_it_does_not_score(self) -> None:
        # Reading SystemBiosVersion is not malicious, and a category that fired
        # on it would fire on installers and inventory agents. Collection only:
        # no present, no strong, no score.
        result = collect_vm_artifact_reads(
            [_read(VBOX_SERVICE_KEY)], descendant_pids={8784}
        )

        for field in ("present", "strong", "score", "category"):
            self.assertNotIn(field, result)

    def test_the_empty_shape_matches_the_collected_one(self) -> None:
        # A run that never reached the pass still has to report the same fields,
        # or the report has to special-case a missing key.
        empty = empty_vm_artifact_reads("not collected")
        real = collect_vm_artifact_reads([], descendant_pids=None)

        self.assertEqual(set(empty), set(real))
        self.assertEqual(set(empty["counts"]), set(real["counts"]))


class FromProcmonCsvTests(unittest.TestCase):
    """The collection path end to end, from a CSV shaped like Procmon's.

    Worth having as well as the unit tests above: the pass reads `pid`, `path`
    and `result` off normalised events, and if the CSV column names were wrong
    every read would arrive with an empty path and classify as nothing. That
    failure would look exactly like a sample that did not check.
    """

    def _csv(self, rows: list[list[str]]) -> str:
        import csv
        import tempfile

        directory = tempfile.mkdtemp()
        path = Path(directory) / "export.csv"
        with path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                ["Time of Day", "Process Name", "PID", "Operation", "Path", "Result", "Detail"]
            )
            writer.writerows(rows)
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        return str(path)

    def test_a_capture_with_reads_produces_the_hits(self) -> None:
        csv_path = self._csv(
            [
                ["10:54:47.1 PM", "RegSvcs.exe", "9592", "RegOpenKey",
                 VBOX_SERVICE_KEY, "SUCCESS", "Desired Access: Read"],
                ["10:54:47.2 PM", "RegSvcs.exe", "9592", "RegQueryValue",
                 BIOS_VERSION, "BUFFER OVERFLOW", "Length: 12"],
                ["10:54:47.3 PM", "svchost.exe", "612", "RegQueryValue",
                 BIOS_VERSION, "SUCCESS", "Type: REG_MULTI_SZ"],
                ["10:54:48.0 PM", "RegSvcs.exe", "9592", "WriteFile",
                 r"C:\Users\adam\AppData\Roaming\Config\smng.exe", "SUCCESS",
                 "Offset: 0, Length: 1,024"],
            ]
        )

        events = parse_procmon_csv(csv_path)
        result = collect_vm_artifact_reads(events, descendant_pids={9592})

        self.assertEqual(result["reads_in_stream"], 3)
        self.assertEqual(result["counts"]["artifacts_read"], 2)
        self.assertEqual(result["counts"]["background_artifact_reads"], 1)
        # And the reads stayed out of the scored evidence: only the drop is a
        # high-signal event.
        interesting = find_interesting_events(events)
        self.assertEqual([e["operation"] for e in interesting], ["WriteFile"])

    def test_a_capture_from_the_default_config_reports_the_collection_absent(self) -> None:
        # What every run this project has performed looks like. The default
        # config's Operation include list has no read in it.
        csv_path = self._csv(
            [
                ["10:54:48.0 PM", "RegSvcs.exe", "9592", "RegSetValue",
                 r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\TRY150", "SUCCESS",
                 "Type: REG_SZ"],
            ]
        )

        result = collect_vm_artifact_reads(parse_procmon_csv(csv_path), descendant_pids={9592})

        self.assertFalse(result["collection_available"])


WER_INFO = r"HKLM\System\CurrentControlSet\Control\SystemInformation"
VBOX_PROVIDER = r"HKLM\System\CurrentControlSet\Services\VBoxSF\NetworkProvider"


class WindowsResponseTests(unittest.TestCase):
    r"""The 07 Aug 14:53 run: nine artifacts read, all nine of them benign.

    That run was the first to capture registry reads at all, and every hit came
    from Windows rather than from the malware. Five were `WerFault.exe` collecting
    machine identity for its crash report -- inside the sample's tree, because
    `RegSvcs` spawned it, and correctly so. Lineage says a process belongs to the
    tree; it cannot say the behaviour belongs to the malware, and for Error
    Reporting it does not. Four were `powershell.exe` walking
    `VBoxSF\NetworkProvider`, which Windows enumerates for any UNC path.

    Both suppressions run *before* attribution, which is the only role a name list
    is allowed here, and both are counted rather than dropped.
    """

    def test_werfault_collecting_machine_identity_is_not_the_sample(self) -> None:
        events = [
            _read(WER_INFO + r"\SystemManufacturer", pid=7180,
                  process="WerFault.exe", result="BUFFER OVERFLOW"),
            _read(WER_INFO + r"\BIOSVersion", pid=7180,
                  process="WerFault.exe", result="BUFFER OVERFLOW"),
        ]

        result = collect_vm_artifact_reads(events, descendant_pids={7180, 2932})

        self.assertEqual(result["counts"]["artifacts_read"], 0)
        self.assertEqual(result["counts"]["windows_response_reads"], 2)
        self.assertEqual(len(result["windows_response_hits"]), 2)

    def test_the_vboxsf_network_provider_is_routine(self) -> None:
        events = [
            _read(VBOX_PROVIDER, pid=7688, process="powershell.exe", operation="RegOpenKey"),
            _read(VBOX_PROVIDER + r"\ProviderPath", pid=7688,
                  process="powershell.exe", result="BUFFER OVERFLOW"),
        ]

        result = collect_vm_artifact_reads(events, descendant_pids={7688})

        self.assertEqual(result["counts"]["artifacts_read"], 0)
        self.assertEqual(result["counts"]["routine_subpath_reads"], 2)

    def test_the_driver_key_itself_is_still_a_check(self) -> None:
        # The narrowing must not cost the signal it was protecting: a sample
        # reading the shared-folder driver's service key is a VM check.
        result = collect_vm_artifact_reads(
            [_read(r"HKLM\System\CurrentControlSet\Services\VBoxSF",
                   pid=5412, process="sample.exe", operation="RegOpenKey")],
            descendant_pids={5412},
        )

        self.assertEqual(result["counts"]["artifacts_read"], 1)
        self.assertEqual(result["counts"]["vm_specific"], 1)

    def test_the_whole_run_replayed_reports_nothing_read(self) -> None:
        events = [
            _read(WER_INFO + r"\SystemManufacturer", pid=7180, process="WerFault.exe"),
            _read(WER_INFO + r"\BIOSVersion", pid=7180, process="WerFault.exe"),
            _read(WER_INFO + r"\SystemProductName", pid=7180, process="WerFault.exe"),
            _read(r"HKLM\Hardware\Description\System\BIOS", pid=7180, process="WerFault.exe"),
            _read(r"HKLM\HARDWARE\DESCRIPTION\System\BIOS\SystemSKU", pid=7180,
                  process="WerFault.exe", result="NAME NOT FOUND"),
            _read(VBOX_PROVIDER, pid=7688, process="powershell.exe", operation="RegOpenKey"),
            _read(VBOX_PROVIDER + r"\name", pid=7688, process="powershell.exe"),
            _read(VBOX_PROVIDER + r"\Class", pid=7688, process="powershell.exe",
                  result="NAME NOT FOUND"),
            _read(VBOX_PROVIDER + r"\ProviderPath", pid=7688, process="powershell.exe"),
        ]

        result = collect_vm_artifact_reads(
            events, descendant_pids={5412, 7688, 2932, 9260, 7180, 7420}
        )

        self.assertEqual(result["counts"]["artifacts_read"], 0)
        self.assertEqual(result["counts"]["windows_response_reads"], 5)
        self.assertEqual(result["counts"]["routine_subpath_reads"], 4)
        self.assertIn("read none of the known", result["note"])


class LoaderRunTests(unittest.TestCase):
    """The shape the loader sample would produce, which is why this was built.

    `422e30ed...` faults deterministically at the same point across six runs, and
    the pipeline cannot say whether that is a bail or a broken crypter. If the
    next detonation shows its `RegSvcs.exe` reading `...\\Services\\VBoxGuest`
    before it faults, that is the first evidence either way.
    """

    def test_a_check_then_quiet_is_visible(self) -> None:
        events = [
            _read(ACPI_TABLE, pid=9592, process="RegSvcs.exe",
                  operation="RegOpenKey", result="NAME NOT FOUND"),
            _read(VBOX_SERVICE_KEY, pid=9592, process="RegSvcs.exe",
                  operation="RegOpenKey", result="SUCCESS"),
            _read(BIOS_VERSION, pid=9592, process="RegSvcs.exe"),
            # Windows doing the same thing at the same time.
            _read(BIOS_VERSION, pid=612, process="svchost.exe"),
        ]

        result = collect_vm_artifact_reads(events, descendant_pids={9592, 10784})

        self.assertEqual(result["counts"]["artifacts_read"], 3)
        self.assertEqual(result["counts"]["vm_specific"], 2)
        self.assertEqual(result["counts"]["artifacts_found"], 2)
        self.assertEqual(result["counts"]["artifacts_absent"], 1)
        self.assertEqual(result["counts"]["background_artifact_reads"], 1)
        self.assertIn("environment checks", result["note"])


if __name__ == "__main__":
    unittest.main()
