"""ScriptBlock logging and ATT&CK mapping.

Both exist for the same reason as the memory-versus-disk YARA scan: they see
what the sample actually did rather than what it appeared to do. 4104 records
script text after the engine deobfuscates it, and a technique ID turns a finding
into something that joins to detection content.

The failure modes worth testing are not the happy paths. They are: fragments
scanned separately so a pattern straddling a split is missed; the analyzer's own
PowerShell counted as the sample's; and techniques claimed without evidence.
"""

import unittest

from dynamic_analysis.attack_mapping import map_run
from dynamic_analysis.powershell_logging import (
    classify_script,
    reassemble,
    summarize_scriptblocks,
)


def event(block_id, number, total, text, path=""):
    return {
        "event_id": 4104,
        "timestamp": "2026-07-30T20:00:00Z",
        "data": {
            "ScriptBlockId": block_id,
            "MessageNumber": number,
            "MessageTotal": total,
            "ScriptBlockText": text,
            "Path": path,
        },
    }


class ScriptBlockReassemblyTests(unittest.TestCase):
    #: Split so that "FromBase64String" spans the boundary, which is what
    #: PowerShell's fixed-size fragmenting actually does to a long payload.
    SPLIT = [
        event("A", 2, 2, "omBase64String('aGk=')))"),
        event("A", 1, 2, "IEX (New-Object Net.WebClient).DownloadString($([Convert]::Fr"),
    ]

    def test_fragments_are_ordered_by_message_number(self) -> None:
        block = reassemble(self.SPLIT)[0]
        self.assertTrue(block["text"].startswith("IEX"))

    def test_pattern_spanning_a_split_is_only_found_after_joining(self) -> None:
        # Each fragment alone contains no complete indicator.
        for fragment in self.SPLIT:
            text = fragment["data"]["ScriptBlockText"]
            self.assertNotIn("Base64 decoding", [m["label"] for m in classify_script(text)])

        joined = reassemble(self.SPLIT)[0]["text"]
        labels = [m["label"] for m in classify_script(joined)]
        self.assertIn("Base64 decoding", labels)

    def test_missing_fragments_are_flagged_not_hidden(self) -> None:
        block = reassemble([event("E", 1, 3, "Start-Process calc")])[0]
        self.assertFalse(block["complete"])
        self.assertEqual(block["parts_expected"], 3)


class AnalyzerScriptTests(unittest.TestCase):
    def test_the_workbenchs_own_snapshots_are_not_the_samples(self) -> None:
        # The orchestrator drives PowerShell for the task and service snapshots.
        blocks = reassemble([
            event("B", 1, 1, "Get-ScheduledTask | ConvertTo-Json"),
            event("C", 1, 1, "Write-Host hello"),
        ])
        counts = summarize_scriptblocks(blocks)["counts"]
        self.assertEqual(counts["analyzer_blocks_excluded"], 1)
        self.assertEqual(counts["blocks_from_sample"], 1)

    def test_identical_blocks_are_deduplicated(self) -> None:
        # PowerShell re-logs a block every compile, so a loop floods the channel.
        blocks = reassemble([
            event("C", 1, 1, "Write-Host hello"),
            event("D", 1, 1, "Write-Host hello"),
        ])
        self.assertEqual(summarize_scriptblocks(blocks)["counts"]["blocks_from_sample"], 1)


class AttackMappingTests(unittest.TestCase):
    def test_nothing_observed_maps_to_nothing(self) -> None:
        # An over-eager mapping produces coverage claims that do not survive
        # scrutiny, which defeats the purpose of having a join key at all.
        self.assertEqual(map_run({})["counts"]["techniques"], 0)

    def test_memory_only_rules_map_to_the_parent_technique_only(self) -> None:
        # The delta proves the payload was unreadable at rest; it does not say
        # whether that was packing, encryption or download. So T1027, not
        # T1027.002.
        mapping = map_run({"memory_yara_summary": {"memory_only_rules": ["mimikatz"]}})
        ids = [t["id"] for t in mapping["techniques"]]
        self.assertIn("T1027", ids)
        self.assertNotIn("T1027.002", ids)

    def test_every_technique_carries_its_evidence(self) -> None:
        mapping = map_run({"memory_yara_summary": {"memory_only_rules": ["mimikatz"]}})
        for technique in mapping["techniques"]:
            self.assertTrue(technique["evidence"], technique["id"])

    def test_baseline_traffic_cannot_manufacture_a_c2_claim(self) -> None:
        # Local discovery and non-routable addresses are excluded upstream
        # precisely so they cannot appear as command and control here.
        mapping = map_run({"network_iocs": {
            "notable_domains": [], "external_ips": [], "notable_urls": [],
            "local_discovery_domains": ["_googlecast._tcp.local"],
            "non_routable_ips": ["239.255.255.250"],
        }})
        self.assertEqual(mapping["counts"]["techniques"], 0)

    def test_powershell_behaviours_become_techniques(self) -> None:
        mapping = map_run({"powershell_summary": {
            "collected": True, "blocks": [{"x": 1}],
            "behaviours": ["AMSI tampering", "In-memory assembly load"],
        }})
        ids = [t["id"] for t in mapping["techniques"]]
        self.assertIn("T1562.001", ids)   # Impair Defenses
        self.assertIn("T1620", ids)       # Reflective Code Loading
        self.assertIn("T1059.001", ids)   # PowerShell itself


if __name__ == "__main__":
    unittest.main()
