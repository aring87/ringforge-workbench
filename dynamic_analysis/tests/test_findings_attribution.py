"""Analyzer activity must not be attributed to the sample -- and vice versa.

The events here are copied from a real detonation (UPX-packed mimikatz,
2026-07-30), which reported five spawned processes and three LOLBins when the
sample had in fact spawned nothing at all.

The second class of test matters more than the first. Suppressing the sample's
own children would be a silent failure: the report would simply describe a
well-behaved sample, with nothing anywhere to indicate that its behaviour had
been filtered away.
"""

import unittest

from dynamic_analysis.findings import summarize_dynamic_findings
from dynamic_analysis.sysmon_collector import summarize_sysmon_events


def process_create(process_name, path, pid, detail):
    return {
        "Operation": "Process Create",
        "Process Name": process_name,
        "Path": path,
        "PID": pid,
        "Detail": detail,
    }


#: FakeNet's startup: it shells out twice, and one of those shells out again.
#: Only the first two name fakenet.exe as the parent; the third is reachable
#: by lineage alone.
FAKENET_STARTUP = [
    process_create("fakenet.exe", r"C:\WINDOWS\SysWOW64\cmd.exe", 3580,
                   r'PID: 2340, Command line: C:\WINDOWS\system32\cmd.exe /c "ver"'),
    process_create("fakenet.exe", r"C:\WINDOWS\SysWOW64\cmd.exe", 3580,
                   r'PID: 3484, Command line: C:\WINDOWS\system32\cmd.exe /c "ipconfig /flushdns"'),
    process_create("cmd.exe", r"C:\WINDOWS\SysWOW64\ipconfig.exe", 3484,
                   r"PID: 4296, Command line: ipconfig  /flushdns"),
]


class AnalyzerProcessAttributionTests(unittest.TestCase):
    def test_fakenet_startup_chain_is_not_the_samples_activity(self) -> None:
        result = summarize_dynamic_findings(
            FAKENET_STARTUP, FAKENET_STARTUP,
            sample_pid=1636, sample_name="mimikatz.upx.exe",
        )

        self.assertEqual(result["counts"]["process_creates"], 0)
        self.assertEqual(result["counts"]["lolbin_processes"], 0)
        self.assertEqual(result["highlights"], [])

    def test_grandchild_is_reached_by_lineage_not_by_name(self) -> None:
        # ipconfig.exe's parent is cmd.exe, which is indistinguishable by name
        # from a sample shelling out. Only its ancestry condemns it.
        ipconfig_only = FAKENET_STARTUP[2:]
        unaware = summarize_dynamic_findings(ipconfig_only, ipconfig_only)
        self.assertEqual(unaware["counts"]["process_creates"], 1)

        with_parents = summarize_dynamic_findings(FAKENET_STARTUP, FAKENET_STARTUP)
        self.assertEqual(with_parents["counts"]["process_creates"], 0)


class SamplePreservationTests(unittest.TestCase):
    """The sample is launched by the analyzer but is not part of it."""

    LAUNCH_AND_BEHAVIOUR = [
        process_create("python.exe", r"C:\samples\evil.exe", 900,
                       r"PID: 1636, Command line: C:\samples\evil.exe"),
        process_create("evil.exe", r"C:\WINDOWS\system32\cmd.exe", 1636,
                       r'PID: 5000, Command line: cmd.exe /c "whoami"'),
        process_create("cmd.exe", r"C:\WINDOWS\system32\whoami.exe", 5000,
                       r"PID: 5001, Command line: whoami"),
    ]

    def _children(self, **identity):
        result = summarize_dynamic_findings(
            self.LAUNCH_AND_BEHAVIOUR, self.LAUNCH_AND_BEHAVIOUR, **identity
        )
        return {p["child_process_name"] for p in result["spawned_processes"]}

    def test_sample_children_survive_when_identified_by_pid_and_name(self) -> None:
        children = self._children(sample_pid=1636, sample_name="evil.exe")
        self.assertIn("cmd.exe", children)
        self.assertIn("whoami.exe", children)

    def test_sample_children_survive_on_name_alone(self) -> None:
        # The PID is unavailable if the launch callback never fired.
        self.assertIn("cmd.exe", self._children(sample_name="evil.exe"))

    def test_sample_children_survive_on_pid_alone(self) -> None:
        self.assertIn("cmd.exe", self._children(sample_pid=1636))


#: FakeNet's own binary, as Sysmon records it. Confirmed from a real run: every
#: DnsQuery for the guest hostname came from here, not from the sample.
FAKENET = r"C:\projects\RingForge_Analyzer\ringforge-workbench\tools\fakenet\fakenet.exe"


class SysmonAnalyzerHighlightTests(unittest.TestCase):
    def driver_load(self, image):
        return {"event_id": 6, "event_name": "DriverLoad",
                "data": {"ImageLoaded": image, "Signed": "true"}}

    def test_windivert_load_is_excluded_but_still_reported(self) -> None:
        events = [
            self.driver_load(r"C:\Users\a\AppData\Local\Temp\_MEI9999\WinDivert64.sys"),
            self.driver_load(r"C:\Windows\System32\drivers\suspicious.sys"),
        ]
        summary = summarize_sysmon_events(events)

        kept = [h["detail"] for h in summary["highlights"]]
        self.assertEqual(len(kept), 1)
        self.assertIn("suspicious.sys", kept[0])

        # Excluded, but visible and counted rather than silently dropped.
        self.assertEqual(summary["analyzer_highlights_excluded"], 1)
        self.assertTrue(summary["analyzer_highlights"][0]["analyzer_activity"])


class SysmonIndicatorAttributionTests(unittest.TestCase):
    """Indicator lists describe the sample, not the tooling watching it.

    Gating only the highlights left FakeNet's hostname lookups sitting in
    dns_queries, where the report renders them under "Sysmon DNS Queries" as
    though the sample had resolved them.
    """

    EVENTS = [
        {"event_id": 22, "event_name": "DnsQuery",
         "data": {"Image": FAKENET, "QueryName": "win11", "QueryResults": "192.168.56.20;"}},
        {"event_id": 22, "event_name": "DnsQuery",
         "data": {"Image": r"C:\samples\evil.exe", "QueryName": "evil-c2.example", "QueryResults": "1.2.3.4;"}},
        {"event_id": 3, "event_name": "NetworkConnect",
         "data": {"Image": FAKENET, "DestinationIp": "10.0.0.1", "DestinationPort": "53"}},
        {"event_id": 3, "event_name": "NetworkConnect",
         "data": {"Image": r"C:\samples\evil.exe", "DestinationIp": "185.220.101.1", "DestinationPort": "443"}},
    ]

    def test_analyzer_lookups_are_not_the_samples_dns_queries(self) -> None:
        summary = summarize_sysmon_events(self.EVENTS)
        self.assertEqual(summary["dns_queries"], ["evil-c2.example"])

    def test_analyzer_connections_are_not_the_samples_targets(self) -> None:
        summary = summarize_sysmon_events(self.EVENTS)
        self.assertEqual(summary["network_targets"], ["185.220.101.1:443"])

    def test_raw_counts_stay_unfiltered(self) -> None:
        # Sysmon really did observe these. Filtering total_events would
        # misrepresent coverage rather than attribution.
        summary = summarize_sysmon_events(self.EVENTS)
        self.assertEqual(summary["total_events"], 4)
        self.assertEqual(summary["counts"]["DnsQuery"], 2)
        self.assertEqual(summary["analyzer_events_excluded"], 2)


if __name__ == "__main__":
    unittest.main()
