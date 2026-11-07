"""A DLL sample runs in rundll32, chosen by its header, and the host is ours.

Ten of `mal-112b`'s samples never executed: two named `.dll` were refused by
`build_dynamic_launch_command`, and eight named `.exe` reached CreateProcess
and failed with WinError 193. All ten came home static-only.
"""

import struct
import tempfile
import unittest
from pathlib import Path

from dynamic_analysis.crash_evidence import summarize_crashes
from dynamic_analysis.dll_launch import (
    MACHINE_AMD64,
    MACHINE_I386,
    choose_export,
    is_dll,
    plan_dll_launch,
    read_pe_header,
    rundll32_for,
)
from dynamic_analysis.orchestrator import build_dynamic_launch_command
from dynamic_analysis.tests.test_crash_evidence import _events

ROOT = r"C:\Windows"


def _pe(machine: int, characteristics: int) -> bytes:
    """The smallest file `read_pe_header` accepts: DOS stub, PE, COFF header."""
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", machine, 0, 0, 0, 0, 0, characteristics)
    return bytes(dos) + b"PE\0\0" + coff


class _Files(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path


class HeaderTests(_Files):
    def test_the_dll_flag_decides_not_the_extension(self) -> None:
        # The sideloading shape: a DLL delivered under an .exe name.
        named_exe = self.write("a.exe", _pe(MACHINE_AMD64, 0x2022))
        self.assertTrue(is_dll(named_exe))
        self.assertEqual(read_pe_header(named_exe)["machine"], MACHINE_AMD64)

    def test_an_executable_is_not_a_dll(self) -> None:
        self.assertFalse(is_dll(self.write("b.exe", _pe(MACHINE_AMD64, 0x0022))))

    def test_a_file_that_is_not_a_pe_is_not_a_dll(self) -> None:
        self.assertFalse(is_dll(self.write("c.dll", b"not a PE at all")))
        self.assertIsNone(read_pe_header(self.write("d.dll", b"MZ")))


class HostTests(unittest.TestCase):
    def test_a_32_bit_dll_needs_the_wow64_host(self) -> None:
        self.assertEqual(rundll32_for(MACHINE_I386, ROOT, True),
                         r"C:\Windows\SysWOW64\rundll32.exe")

    def test_a_64_bit_dll_needs_the_native_host(self) -> None:
        self.assertEqual(rundll32_for(MACHINE_AMD64, ROOT, True),
                         r"C:\Windows\System32\rundll32.exe")

    def test_a_32_bit_interpreter_reaches_the_native_host_through_sysnative(self) -> None:
        # From a 32-bit process System32 *is* SysWOW64; the x64 DLL would fail.
        self.assertEqual(rundll32_for(MACHINE_AMD64, ROOT, False),
                         r"C:\Windows\Sysnative\rundll32.exe")

    def test_a_machine_with_no_host_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            rundll32_for(0xAA64, ROOT, True)


class ExportTests(unittest.TestCase):
    def test_an_entry_point_export_wins(self) -> None:
        # STEALERDLL.dll, two of the corpus's ten.
        self.assertEqual(choose_export([(1, "Save"), (2, "Main")])[0], "Main")

    def test_otherwise_the_lowest_ordinal(self) -> None:
        # The MpClient proxies: a dozen real API names, no entry point.
        export, reason = choose_export([(3, "MpConfigOpen"), (1, "MpAllocMemory")])
        self.assertEqual(export, "#1")
        self.assertIn("MpAllocMemory", reason)

    def test_the_ordinal_is_the_real_one_not_an_index(self) -> None:
        self.assertEqual(choose_export([(7, "x"), (9, "y")])[0], "#7")

    def test_no_exports_still_loads_the_dll(self) -> None:
        self.assertEqual(choose_export([]), ("#1", "no exports; DllMain runs on load"))

    def test_an_unreadable_table_says_so(self) -> None:
        self.assertEqual(choose_export(None), ("#1", "export table unreadable"))


class LaunchCommandTests(_Files):
    def test_an_exe_named_dll_launches_in_rundll32(self) -> None:
        sample = self.write("101eb6d5c3c5.exe", _pe(MACHINE_AMD64, 0x2022))
        command = build_dynamic_launch_command(sample)

        self.assertTrue(command[0].lower().endswith("rundll32.exe"))
        self.assertEqual(command[1], f"{sample},#1")

    def test_a_dll_named_dll_is_no_longer_refused(self) -> None:
        sample = self.write("88313d63ba99.dll", _pe(MACHINE_I386, 0x2102))
        command = build_dynamic_launch_command(sample)

        self.assertTrue(command[0].lower().endswith(r"syswow64\rundll32.exe"))

    def test_an_executable_is_launched_as_itself(self) -> None:
        sample = self.write("plain.exe", _pe(MACHINE_AMD64, 0x0022))
        self.assertEqual(build_dynamic_launch_command(sample), [str(sample)])

    def test_a_dll_suffix_on_a_non_pe_is_still_refused(self) -> None:
        with self.assertRaises(ValueError):
            build_dynamic_launch_command(self.write("junk.dll", b"text"))

    def test_the_command_line_keeps_the_comma_outside_the_quotes(self) -> None:
        spaced = self.dir / "with space"
        spaced.mkdir()
        sample = spaced / "x.dll"
        sample.write_bytes(_pe(MACHINE_AMD64, 0x2022))
        plan = plan_dll_launch(sample, ROOT, True)

        self.assertEqual(
            plan["command_line"],
            f'"C:\\Windows\\System32\\rundll32.exe" "{sample}",#1')


class BenchHostCrashTests(unittest.TestCase):
    """The rundll32 the bench started is not a process a loader hollowed.

    `rundll32.exe` is in HOLLOWING_TARGETS because a loader that *starts* one
    and faults in its anonymous memory has hollowed it. When the bench starts
    it to host a DLL, the same fault is the DLL's own unpacked code -- what a
    sample `.exe` faulting in anonymous memory shows, and that is weak. Running
    a sample as a DLL must not make the same behaviour strong.
    """

    HOST = ("rundll32.exe", "unknown", "c0000005", "0x2034")
    CHILD = ("rundll32.exe", "unknown", "c0000005", "0x3000")

    def test_a_fault_in_the_bench_host_is_unmapped_but_not_in_a_target(self) -> None:
        summary = summarize_crashes(_events(self.HOST), sample_pids={0x2034},
                                    host_pids={0x2034})
        counts = summary["counts"]

        self.assertEqual(counts["crashes_in_unmapped_memory"], 1)
        self.assertEqual(counts["crashes_in_hollowing_target"], 0)
        self.assertEqual(counts["unmapped_crashes_in_bench_host"], 1)
        entry = summary["unmapped_memory_crashes"][0]
        self.assertFalse(entry["hollowing_target"])
        self.assertTrue(entry["bench_host"])

    def test_a_rundll32_the_sample_started_is_still_a_target(self) -> None:
        summary = summarize_crashes(_events(self.HOST, self.CHILD),
                                    sample_pids={0x2034, 0x3000},
                                    host_pids={0x2034})

        self.assertEqual(summary["counts"]["crashes_in_hollowing_target"], 1)

    def test_without_a_host_nothing_changes(self) -> None:
        summary = summarize_crashes(_events(self.HOST), sample_pids={0x2034})
        self.assertEqual(summary["counts"]["crashes_in_hollowing_target"], 1)


if __name__ == "__main__":
    unittest.main()
