"""A crash inside unmapped memory is proof of injection.

Formbook hollowed RegSvcs.exe and died inside its own injected region. Windows
logged it and the pipeline ignored it:

    Faulting application name: RegSvcs.exe, version: 4.8.9221.0
    Faulting module name: unknown, version: 0.0.0.0
    Exception code: 0xc0000005
    Fault offset: 0x0150521d

"Faulting module name: unknown" means the fault address belongs to no loaded
image -- execution was in privately allocated memory. Legitimate RegSvcs.exe
never runs from anonymous memory.

That run scored 35 / Needs Review with `sysmon_injection_events: 0`, because
Sysmon Event 8 is CreateRemoteThread and process hollowing does not use it.
The detector had a hole exactly the shape of the most common loader technique,
so "injection has never fired on real malware" was partly a statement about the
detector rather than about the samples.

Application Error 1000 is a legacy provider: its EventData carries *unnamed*
positional <Data> elements. The parser only collected named ones, so every 1000
event arrived with an empty dict and the faulting-module field -- index 3 --
was unreachable.
"""

import unittest

from dynamic_analysis.crash_evidence import (
    parse_crash_event,
    summarize_crashes,
)
from dynamic_analysis.sysmon_collector import parse_rendered_xml

#: The real event, trimmed. Note the unnamed <Data> elements.
CRASH_XML = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Application Error'/>
    <EventID Qualifiers='0'>1000</EventID>
    <TimeCreated SystemTime='2026-08-05T16:14:55.0000000Z'/>
    <Execution ProcessID='4284' ThreadID='1'/>
  </System>
  <EventData>
    <Data>{app}</Data>
    <Data>4.8.9221.0</Data>
    <Data>5ff2b99b</Data>
    <Data>{module}</Data>
    <Data>0.0.0.0</Data>
    <Data>00000000</Data>
    <Data>{code}</Data>
    <Data>0150521d</Data>
    <Data>{pid}</Data>
    <Data>01dcf0a1b2c3d4e5</Data>
    <Data>C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe</Data>
    <Data>unknown</Data>
  </EventData>
</Event>
"""


def _events(*specs):
    xml = "".join(
        CRASH_XML.format(app=app, module=module, code=code, pid=pid)
        for app, module, code, pid in specs
    )
    return parse_rendered_xml(xml)


HOLLOWED = ("RegSvcs.exe", "unknown", "c0000005", "0x2034")
ORDINARY = ("notepad.exe", "ntdll.dll", "c0000005", "0x1111")


class PositionalDataTests(unittest.TestCase):
    def test_unnamed_data_elements_survive_parsing(self) -> None:
        # Application Error writes no Name attributes, so order is the schema.
        event = _events(HOLLOWED)[0]

        self.assertEqual(event["data_values"][0], "RegSvcs.exe")
        self.assertEqual(event["data_values"][3], "unknown")

    def test_fields_are_named_by_position(self) -> None:
        record = parse_crash_event(_events(HOLLOWED)[0])

        self.assertEqual(record["app_name"], "RegSvcs.exe")
        self.assertEqual(record["module_name"], "unknown")
        self.assertEqual(record["exception_code"], "c0000005")
        self.assertEqual(record["fault_offset"], "0150521d")

    def test_a_hex_pid_is_understood(self) -> None:
        # Newer builds write it as 0x2034 rather than decimal.
        record = parse_crash_event(_events(HOLLOWED)[0])

        self.assertEqual(record["pid"], 0x2034)


class UnmappedMemoryTests(unittest.TestCase):
    def test_an_unknown_faulting_module_is_flagged(self) -> None:
        record = parse_crash_event(_events(HOLLOWED)[0])

        self.assertTrue(record["executed_from_unmapped_memory"])

    def test_a_crash_inside_a_real_module_is_not(self) -> None:
        # Ordinary crashes are common and mean nothing on their own.
        record = parse_crash_event(_events(ORDINARY)[0])

        self.assertFalse(record["executed_from_unmapped_memory"])

    def test_the_summary_separates_the_two(self) -> None:
        summary = summarize_crashes(
            _events(HOLLOWED, ORDINARY),
            sample_pids={0x2034, 0x1111},
        )

        self.assertEqual(summary["counts"]["crashes"], 2)
        self.assertEqual(summary["counts"]["crashes_in_unmapped_memory"], 1)
        self.assertEqual(
            summary["unmapped_memory_crashes"][0]["process"], "RegSvcs.exe"
        )


class AttributionTests(unittest.TestCase):
    def test_another_process_crashing_is_not_the_samples_crash(self) -> None:
        # Windows crashes things of its own during a run; a ten-minute window
        # makes that likelier, not less.
        summary = summarize_crashes(_events(ORDINARY), sample_pids={0x2034})

        self.assertEqual(summary["counts"]["crashes"], 0)
        self.assertEqual(summary["counts"]["other_process_crashes_excluded"], 1)

    def test_the_image_name_attributes_when_the_pid_does_not(self) -> None:
        # The PID is absent on some builds, and a hollowed process is
        # identified perfectly well by being the sample's own child.
        summary = summarize_crashes(
            _events(HOLLOWED), sample_pids=set(), sample_names={"regsvcs.exe"}
        )

        self.assertEqual(summary["counts"]["crashes"], 1)

    def test_without_lineage_everything_counts_and_says_so(self) -> None:
        summary = summarize_crashes(_events(HOLLOWED, ORDINARY))

        self.assertEqual(summary["counts"]["crashes"], 2)
        self.assertFalse(summary["attributed_by_lineage"])


if __name__ == "__main__":
    unittest.main()
