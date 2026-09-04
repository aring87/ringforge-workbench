"""Which machine the telemetry strip is describing.

The Dynamic Analysis window reported `Sysmon: not installed | FakeNet: not
installed | Memory: not installed` on a developer workstation, where all three
are correct: those tools install kernel drivers and a system-wide traffic
diverter, and `bootstrap_tools.ps1` refuses physical hardware without `-Force`.

Uncaptioned it reads as a broken bench and invites the wrong fix on the wrong
machine -- a true statement that means something else, which is the shape this
codebase keeps finding.
"""

import unittest

from dynamic_analysis.bench_profile import (
    GUEST_SERVICES,
    VENDOR_PATTERN,
    telemetry_caption,
)


class TheVendorPattern(unittest.TestCase):
    def test_it_matches_the_hypervisors_the_powershell_guard_matches(self) -> None:
        for value in ("SystemManufacturer: innotek GmbH",
                      "SystemProductName: VirtualBox",
                      "BIOSVendor: VMware, Inc.",
                      "SystemManufacturer: QEMU",
                      "SystemProductName: Parallels Virtual Platform",
                      "BIOSVendor: Xen", "SystemProductName: Bochs"):
            with self.subTest(value=value):
                self.assertRegex(value, VENDOR_PATTERN)

    def test_a_bare_virtual_is_not_enough(self) -> None:
        """"Microsoft Virtual Disk" appears on ordinary physical machines and a
        mounted VHD matches "Virtual". Matching those makes the guard a rubber
        stamp, which is why the pattern is vendor-specific."""
        for value in ("Disk: Microsoft Virtual Disk",
                      "SystemProductName: Virtual Machine Bus"):
            with self.subTest(value=value):
                self.assertNotRegex(value, VENDOR_PATTERN)

    def test_hyper_v_availability_is_not_evidence_of_being_a_guest(self) -> None:
        """**The false positive this was caught making.** Hyper-V being
        available on a machine says nothing about whether the machine is one,
        and Windows 11 ships those components widely."""
        self.assertNotRegex("SystemManufacturer: Hyper-V", VENDOR_PATTERN)

    def test_the_heartbeat_service_is_not_a_guest_hint(self) -> None:
        """`vmicheartbeat` was in the service list and made this workstation
        report itself an analysis VM. The Hyper-V integration services are
        registered on hosts that merely have the feature. A guest hint that
        fires on hosts is not a hint."""
        self.assertNotIn("vmicheartbeat", GUEST_SERVICES)

    def test_the_services_that_do_survive_dmi_spoofing_are_listed(self) -> None:
        for service in ("VBoxService", "vmtools", "prl_tools", "xenbus"):
            self.assertIn(service, GUEST_SERVICES)


class TheCaption(unittest.TestCase):
    """Empty on a bench; explicit everywhere else."""

    def test_a_bench_gets_no_caption(self) -> None:
        self.assertEqual(telemetry_caption({"looks_like_vm": True}), "")

    def test_physical_hardware_says_where_to_install_instead(self) -> None:
        caption = telemetry_caption({"looks_like_vm": False})

        self.assertIn("physical hardware", caption)
        self.assertIn("guest", caption)

    def test_not_knowing_reads_differently_from_knowing_it_is_not(self) -> None:
        """Unknown is not no. The caption for a probe that could not run must
        not claim the machine is a workstation."""
        unknown = telemetry_caption({"looks_like_vm": None})
        negative = telemetry_caption({"looks_like_vm": False})

        self.assertNotEqual(unknown, negative)
        self.assertIn("Could not tell", unknown)
        self.assertNotIn("physical hardware", unknown)


class TheProbeItself(unittest.TestCase):
    def test_it_answers_rather_than_raising(self) -> None:
        from dynamic_analysis.bench_profile import bench_profile

        profile = bench_profile()

        self.assertIn(profile["looks_like_vm"], (True, False, None))
        self.assertIsInstance(profile["evidence"], list)
        self.assertTrue(profile["note"])


if __name__ == "__main__":
    unittest.main()
