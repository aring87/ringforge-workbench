"""A connection is the sample's for the same reason a process create is.

The AgentTesla run that finally captured an exfiltration also reported svchost
and MpDefenderCoreService among the sample's network events, and listed them in
Top Network Processes. Nothing had gone wrong with those processes -- once
FakeNet could actually intercept, every resident service on the guest started
reaching the simulated internet successfully, because a simulated internet
answers everything.

Naming each one would have been the approach that already failed for spawned
processes: the set differs every run. Lineage is the property that separates
them, and it was already being computed a few lines away for process creates.

Connections are therefore collected during the event loop with their PID and
judged afterwards, because lineage cannot be resolved one event at a time.
"""

import unittest

from dynamic_analysis.findings import summarize_dynamic_findings
from dynamic_analysis.html_report import _background_network_section

SAMPLE = "31a762.exe"


def event(operation, process, pid, path="", detail=""):
    return {
        "Operation": operation,
        "Process Name": process,
        "PID": pid,
        "Path": path,
        "Detail": detail,
        "Time of Day": "10:14:38 PM",
    }


#: The run: the sample launched, relaunched itself, and the second copy
#: exfiltrated over FTP while the machine went about its business.
REAL_RUN = [
    event("Process Create", "python.exe", 1404,
          r"C:\rf\samples\s\31a762.exe", "PID: 9028, Command line: 31a762.exe"),
    event("Process Create", SAMPLE, 9028,
          r"C:\rf\samples\s\31a762.exe", "PID: 4200, Command line: 31a762.exe"),
    event("TCP Connect", SAMPLE, 4200, "192.0.2.123:21"),
    event("TCP Connect", SAMPLE, 4200, "192.0.2.123:60006"),
    event("TCP Connect", "svchost.exe", 4552, "192.0.2.123:443"),
    event("TCP Connect", "MpDefenderCoreService.exe", 3716, "192.0.2.123:443"),
]


class NetworkLineageTests(unittest.TestCase):
    def _run(self, events=None, sample_pid=9028, sample_name=SAMPLE):
        events = REAL_RUN if events is None else events
        return summarize_dynamic_findings(
            events, events, sample_pid=sample_pid, sample_name=sample_name
        )

    def test_only_the_sample_s_connections_count(self) -> None:
        result = self._run()

        self.assertEqual(result["counts"]["network_events"], 2)

    def test_the_exfil_is_what_is_counted(self) -> None:
        # Port 21 and the passive data port, both from the payload process.
        result = self._run()

        self.assertEqual(
            [p["process_name"] for p in result["top_network_processes"]], [SAMPLE]
        )

    def test_the_machine_s_own_traffic_becomes_context(self) -> None:
        result = self._run()
        names = [p["process_name"] for p in result["background_network_processes"]]

        self.assertIn("svchost.exe", names)
        self.assertIn("MpDefenderCoreService.exe", names)
        self.assertEqual(result["counts"]["background_network_events"], 2)

    def test_a_grandchild_of_the_sample_still_counts(self) -> None:
        events = REAL_RUN + [
            event("Process Create", SAMPLE, 4200, r"C:\Windows\System32\cmd.exe",
                  "PID: 5000, Command line: cmd.exe"),
            event("TCP Connect", "cmd.exe", 5000, "192.0.2.123:80"),
        ]

        self.assertEqual(self._run(events)["counts"]["network_events"], 3)

    def test_unresolved_lineage_counts_everything(self) -> None:
        # "We could not tell whose connection this was" must not silently empty
        # the network findings, exactly as for process creates.
        result = self._run(sample_pid=None, sample_name="")

        self.assertEqual(result["counts"]["network_events"], 4)
        self.assertEqual(result["counts"]["background_network_events"], 0)

    def test_analyzer_traffic_is_still_excluded_first(self) -> None:
        events = REAL_RUN + [event("TCP Connect", "procmon64.exe", 900, "1.2.3.4:443")]
        result = self._run(events)

        names = [p["process_name"] for p in result["top_network_processes"]]
        background = [p["process_name"] for p in result["background_network_processes"]]
        self.assertNotIn("procmon64.exe", names)
        self.assertNotIn("procmon64.exe", background)


class BackgroundNetworkSectionTests(unittest.TestCase):
    def test_it_renders_when_there_is_something_to_show(self) -> None:
        html = _background_network_section(
            {"background_network_processes": [{"process_name": "svchost.exe", "count": 3}]}
        )

        self.assertIn("Background Network Activity", html)
        self.assertIn("Count: 3", html)

    def test_it_is_silent_otherwise(self) -> None:
        self.assertEqual(_background_network_section({}), "")


if __name__ == "__main__":
    unittest.main()
