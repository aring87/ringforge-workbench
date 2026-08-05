"""PowerShell a sample never ran is not the sample's behaviour.

The mimikatz UPX control spawned nothing: `processes_observed: 1`, no children,
no descendants. It reported `blocks_from_sample: 24` and one suspicious block,
raising a `scripted_execution` evidence category.

The blocks were Windows Troubleshooting --
`C:\\WINDOWS\\TEMP\\SDIAG_*\\TS_DiagnosticHistory.ps1` and `CL_Utility.ps1`,
started by `sdiagnhost.exe` -- which ran because the observation window had
extended to 600 seconds and Windows got round to its idle maintenance.

`collect_scriptblocks` took every 4104 in the window and called it the
sample's unless it matched an analyzer marker. That is attribution by time,
and the run that exposed it is the same class as the network-attribution bug:
a list of everything else, rather than lineage.

The verdict survived by luck -- `packed_payload` was already strong, and one
strong category reaches High on its own. It would not have survived a sample
whose only other evidence was that false category.

4104 carries no EventData ProcessId. The executing PID is an attribute of the
System block's Execution element, which is why this needed a change in the XML
parser as well.
"""

import unittest

from dynamic_analysis.powershell_logging import reassemble, summarize_scriptblocks
from dynamic_analysis.sysmon_collector import parse_rendered_xml

#: A 4104 as wevtutil renders it, trimmed to what matters here.
EVENT_XML = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-PowerShell'/>
    <EventID>4104</EventID>
    <TimeCreated SystemTime='2026-08-05T02:15:32.3502836Z'/>
    <Execution ProcessID='{pid}' ThreadID='4242'/>
  </System>
  <EventData>
    <Data Name='MessageNumber'>1</Data>
    <Data Name='MessageTotal'>1</Data>
    <Data Name='ScriptBlockText'>{text}</Data>
    <Data Name='ScriptBlockId'>{block_id}</Data>
    <Data Name='Path'>{path}</Data>
  </EventData>
</Event>
"""


def _blocks(*specs) -> list:
    xml = "".join(
        EVENT_XML.format(pid=pid, text=text, block_id=block_id, path=path)
        for pid, text, block_id, path in specs
    )
    return reassemble(parse_rendered_xml(xml))


class ExecutionPidTests(unittest.TestCase):
    def test_the_executing_pid_survives_parsing(self) -> None:
        # 4104 has no EventData ProcessId, so this has to come from System.
        blocks = _blocks((9220, "whoami", "id-1", ""))

        self.assertEqual(blocks[0]["process_id"], "9220")


class AttributionTests(unittest.TestCase):
    #: The sample's tree. mimikatz's real one was a single PID.
    SAMPLE_PIDS = {4576}

    def test_windows_own_scheduled_powershell_is_not_the_samples(self) -> None:
        blocks = _blocks(
            (
                7884,
                "Invoke-Expression $something",
                "id-sdiag",
                r"C:\WINDOWS\TEMP\SDIAG_d8f03722\TS_DiagnosticHistory.ps1",
            ),
        )

        summary = summarize_scriptblocks(blocks, sample_pids=self.SAMPLE_PIDS)

        self.assertEqual(summary["counts"]["blocks_from_sample"], 0)
        self.assertEqual(summary["counts"]["blocks_suspicious"], 0)
        self.assertEqual(summary["counts"]["other_process_blocks_excluded"], 1)

    def test_the_samples_own_powershell_still_counts(self) -> None:
        # The Formbook case, which must keep working: the sample spawned
        # powershell.exe to add a Defender exclusion for itself.
        blocks = _blocks(
            (4576, "Add-MpPreference -ExclusionPath C:\\sample.exe", "id-mp", ""),
        )

        summary = summarize_scriptblocks(blocks, sample_pids=self.SAMPLE_PIDS)

        self.assertEqual(summary["counts"]["blocks_from_sample"], 1)
        self.assertEqual(summary["counts"]["blocks_suspicious"], 1)
        self.assertIn("Defender modification", summary["behaviours"])

    def test_both_at_once(self) -> None:
        blocks = _blocks(
            (4576, "Add-MpPreference -ExclusionPath C:\\sample.exe", "id-mp", ""),
            (7884, "Invoke-Expression $x", "id-sdiag", r"C:\WINDOWS\TEMP\SDIAG_x\a.ps1"),
        )

        summary = summarize_scriptblocks(blocks, sample_pids=self.SAMPLE_PIDS)

        self.assertEqual(summary["counts"]["blocks_from_sample"], 1)
        self.assertEqual(summary["counts"]["other_process_blocks_excluded"], 1)
        self.assertTrue(summary["attributed_by_lineage"])

    def test_unresolved_lineage_counts_everything_and_says_so(self) -> None:
        # None means "we could not tell", and the findings degrade by counting
        # everything rather than nothing. An empty set would mean the sample
        # provably ran nothing, which is a different claim.
        blocks = _blocks((7884, "Invoke-Expression $x", "id-1", ""))

        summary = summarize_scriptblocks(blocks, sample_pids=None)

        self.assertEqual(summary["counts"]["blocks_from_sample"], 1)
        self.assertFalse(summary["attributed_by_lineage"])

    def test_an_analyzer_block_is_excluded_before_lineage_is_considered(self) -> None:
        # The workbench drives PowerShell itself for the task and service
        # snapshots, and those run under a PID that is not the sample's either.
        # They stay in their own bucket rather than joining the other-process
        # count, so the two remain tellable apart.
        blocks = _blocks((1234, "Get-ScheduledTask | ConvertTo-Json", "id-a", ""))

        summary = summarize_scriptblocks(blocks, sample_pids=self.SAMPLE_PIDS)

        self.assertEqual(summary["counts"]["analyzer_blocks_excluded"], 1)
        self.assertEqual(summary["counts"]["other_process_blocks_excluded"], 0)


if __name__ == "__main__":
    unittest.main()
