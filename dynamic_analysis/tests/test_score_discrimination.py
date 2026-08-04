"""The verdict has to be able to tell these three runs apart.

Under the old model it could not:

    memory canary (benign)   24   Needs Review / Medium
    mimikatz.upx (packed)    69   Needs Review / Medium
    AgentTesla (live)        60   Needs Review / Medium

Three samples, one of them a control built to be harmless, all reported the
same. High required a score above 120 and nothing ever reached it, because
almost every term in the sum was individually capped. The verdict field could
not support a decision, which is the only thing a verdict is for.

The score also moved nine points between two runs of the same control on
identical code, purely from background noise -- so any model that bands on the
total is banding partly on noise.

What actually separates these runs is not how much happened but how many
unrelated kinds of evidence agree, and how emphatic each one is:

    canary        one memory-only rule, nothing else            -> Medium
    mimikatz.upx  five memory-only rules, nothing else          -> High
    AgentTesla    three memory-only rules AND a C2 contact
                  on a non-standard port                        -> High, and above mimikatz

The canary staying at Medium is a contract, not an accident: `test_specs/
memory_canary/` asserts Needs Review, and a benign marker string in memory is
exactly the single unexplained observation that band is for.
"""

import unittest

from dynamic_analysis.orchestrator import (
    _sample_process_names,
    calculate_dynamic_score,
)


def _score(**kwargs):
    """Run the scorer with everything empty except what a test sets."""
    base = dict(
        findings_summary={"counts": {}},
        task_diff_summary={"counts": {}},
        service_diff_summary={"counts": {}},
        dropped_files_summary={},
        autoruns_diff_summary={"counts": {}},
        sysmon_summary={},
        network_summary={},
        fakenet_summary={},
        memory_yara_summary={},
        powershell_summary={},
    )
    base.update(kwargs)
    return calculate_dynamic_score(**base)


# --- the three reference runs ---------------------------------------------

def _canary():
    """One memory-only rule, built at runtime, and nothing else."""
    return _score(
        findings_summary={"counts": {"interesting_events": 40, "process_creates": 2}},
        memory_yara_summary={
            "memory_only_rules": ["RingForge_Canary_MemoryOnly"],
            "counts": {"total_matches": 1},
        },
    )


def _mimikatz_upx():
    """Five memory-only rules from a payload compressed at rest."""
    return _score(
        findings_summary={"counts": {"interesting_events": 120, "process_creates": 3}},
        memory_yara_summary={
            "memory_only_rules": [
                "HKTL_Mimikatz_SkeletonKey_in_memory_Aug20_1",
                "Powerkatz_DLL_Generic",
                "mimikatz",
                "HKTL_Mimikatz_Strings",
                "Mimikatz_Generic",
            ],
            "counts": {"total_matches": 6},
        },
    )


#: Verbatim from the 03 Aug run's dynamic_run_summary.json. Windows was busy
#: during that window -- OneDrive, M365Copilot and three msedgewebview2
#: processes all connected -- and every one of those lookups and connections
#: appears in FakeNet's log beside the sample's.
AGENT_TESLA_FAKENET = {
    "dns_requests": [
        "self.events.data.microsoft.com",
        "123.2.0.192.in-addr.arpa",
        "255.56.168.192.in-addr.arpa",
        "edge.microsoft.com",
        "ftp.cyberflor.co",
        "1.56.168.192.in-addr.arpa",
        "251.0.0.224.in-addr.arpa",
        "aefd.nelreports.net",
    ],
    "process_requests": [
        {"process": "svchost.exe", "pid": "2212", "protocol": "UDP",
         "destination": "192.168.56.20:53"},
        {"process": "OneDrive.exe", "pid": "8188", "protocol": "TCP",
         "destination": "192.0.2.123:443"},
        {"process": "M365Copilot.exe", "pid": "8800", "protocol": "TCP",
         "destination": "192.0.2.123:443"},
        {"process": "msedgewebview2.exe", "pid": "1580", "protocol": "TCP",
         "destination": "192.0.2.123:443"},
        {"process": "agenttesla.exe", "pid": "2868", "protocol": "TCP",
         "destination": "192.0.2.123:21"},
        {"process": "agenttesla.exe", "pid": "2868", "protocol": "TCP",
         "destination": "192.0.2.123:60009"},
    ],
    "counts": {"dns_requests": 8},
}


def _agent_tesla():
    """Three memory-only rules, plus FTP to a C2 on a passive data port."""
    return _score(
        findings_summary={
            "counts": {
                "interesting_events": 21,
                "process_creates": 2,
                "network_events": 2,
            },
            "top_network_processes": [{"process_name": "agenttesla.exe", "count": 2}],
            "spawned_processes": [
                {"process_name": "python.exe", "child_process_name": "agenttesla.exe"},
                {"process_name": "agenttesla.exe", "child_process_name": "agenttesla.exe"},
            ],
        },
        memory_yara_summary={
            "memory_only_rules": [
                "Windows_Trojan_AgentTesla_d3ac2b2f",
                "Windows_Trojan_AgentTesla_ebf431a8",
                "Windows_Generic_Threat_808f680e",
            ],
            "counts": {"total_matches": 6},
        },
        # Sysmon attributed exactly one lookup to the sample.
        sysmon_summary={"dns_queries": ["ftp.cyberflor.co"]},
        # The real capture recorded no connections at all: it saw multicast and
        # nothing of the FTP session. unusual_ports was 0 on the run where the
        # sample used port 60009.
        network_summary={
            "counts": {"unusual_ports": 0, "unique_destinations": 0},
            "iocs": {"counts": {"external_ips": 0, "notable_urls": 0}},
        },
        fakenet_summary=AGENT_TESLA_FAKENET,
    )


class ReferenceRunTests(unittest.TestCase):
    def test_the_benign_canary_stays_at_needs_review(self) -> None:
        # The control's contract. One memory-only rule floors severity to
        # Medium and must not exceed it, or the canary stops being a canary.
        result = _canary()

        self.assertEqual(result["severity"], "Medium")
        self.assertEqual(result["verdict"], "Needs Review")
        self.assertEqual(result["evidence_counts"]["categories_present"], 1)
        self.assertEqual(result["evidence_counts"]["categories_strong"], 0)

    def test_packed_mimikatz_clears_the_canary(self) -> None:
        # Five independent threat-intel rules agreeing about a payload that was
        # unreadable at rest is a stronger claim than one marker string.
        result = _mimikatz_upx()

        self.assertEqual(result["severity"], "High")
        self.assertGreater(result["score"], _canary()["score"])

    def test_live_agent_tesla_clears_packed_mimikatz(self) -> None:
        # Two unrelated kinds of evidence agreeing beats one, however emphatic.
        result = _agent_tesla()

        self.assertEqual(result["severity"], "High")
        self.assertEqual(result["verdict"], "Likely Malicious")
        self.assertGreater(result["score"], _mimikatz_upx()["score"])

    def test_the_three_reference_runs_are_all_distinguishable(self) -> None:
        # The whole point. Under the old model these read
        # "Needs Review / Medium" three times.
        verdicts = [
            (_canary()["severity"], _canary()["verdict"]),
            (_mimikatz_upx()["severity"], _mimikatz_upx()["verdict"]),
            (_agent_tesla()["severity"], _agent_tesla()["verdict"]),
        ]

        self.assertEqual(len(set(verdicts)), 3)

    def test_agent_tesla_c2_is_seen_despite_no_external_ip(self) -> None:
        # FakeNet answers everything locally, so external_ips is 0 on the run
        # where the sample authenticated to its C2 and uploaded stolen data.
        result = _agent_tesla()
        names = {c["name"] for c in result["evidence_categories"]}

        self.assertIn("external_contact", names)

    def test_the_passive_ftp_port_the_capture_missed_is_still_seen(self) -> None:
        # The pcap recorded unusual_ports: 0 on this run -- it never saw the
        # FTP session. FakeNet's diverter had the sample on :21 and :60009.
        result = _agent_tesla()
        attribution = result["network_attribution"]

        self.assertIn("192.0.2.123:60009", attribution["sample_unusual_ports"])


class AttributionTests(unittest.TestCase):
    """Network evidence must belong to the sample, not to the host.

    FakeNet's log and the pcap both record the whole machine. The 03 Aug
    AgentTesla run had ten names in the FakeNet log, nine of them Windows' own,
    while OneDrive, M365Copilot and three msedgewebview2 processes connected
    during the window. Those nine classified as baseline, so an early version
    of this scorer produced the right number by luck -- one non-baseline lookup
    from any of those processes would have scored as the sample's C2 contact.

    This is the same rule the findings already follow, and the reason it is
    written down: attribute by lineage or by requesting process, never by
    maintaining a list of everything else.
    """

    def test_another_process_calling_home_is_not_the_sample_calling_home(self) -> None:
        result = _score(
            findings_summary={
                "top_network_processes": [{"process_name": "sample.exe", "count": 0}],
                "spawned_processes": [
                    {"process_name": "python.exe", "child_process_name": "sample.exe"}
                ],
            },
            # Sysmon attributed nothing to the sample.
            sysmon_summary={"dns_queries": []},
            fakenet_summary={
                "dns_requests": ["telemetry.corp-analytics.example"],
                "process_requests": [
                    {"process": "msedgewebview2.exe", "protocol": "TCP",
                     "destination": "192.0.2.123:8888"},
                ],
            },
        )
        names = {c["name"] for c in result["evidence_categories"]}

        self.assertNotIn("external_contact", names)
        self.assertEqual(result["severity"], "Low")

    def test_the_hosts_own_lookups_are_counted_not_discarded(self) -> None:
        # Silence must be distinguishable from absence: a run where the host
        # was noisy and the sample quiet has to look different from a run
        # where nothing happened at all.
        result = _score(
            findings_summary={"spawned_processes": [
                {"process_name": "python.exe", "child_process_name": "sample.exe"}
            ]},
            sysmon_summary={"dns_queries": []},
            fakenet_summary={
                "dns_requests": ["telemetry.corp-analytics.example"],
                "process_requests": [
                    {"process": "onedrive.exe", "protocol": "TCP",
                     "destination": "192.0.2.123:443"},
                ],
            },
        )
        attribution = result["network_attribution"]

        self.assertEqual(attribution["other_non_baseline_domains"], 1)
        self.assertEqual(attribution["other_process_requests"], 1)
        self.assertEqual(attribution["sample_domains"], [])

    def test_the_analyzers_own_launcher_is_never_the_sample(self) -> None:
        # The parent of the first spawn record is python.exe -- the workbench
        # launching the sample. Treating a spawn parent as sample lineage would
        # attribute the analyzer's own traffic to the sample.
        names = _sample_process_names(
            {
                "spawned_processes": [
                    {"process_name": "python.exe", "child_process_name": "sample.exe"}
                ]
            }
        )

        self.assertIn("sample.exe", names)
        self.assertNotIn("python.exe", names)


class NoiseTests(unittest.TestCase):
    def test_volume_alone_cannot_reach_a_finding(self) -> None:
        # A chatty installer that does nothing decisive. Every volume counter
        # pinned high, no evidence category: it must not band above Low.
        result = _score(
            findings_summary={
                "counts": {
                    "interesting_events": 5000,
                    "process_creates": 400,
                    "network_events": 300,
                    "file_write_events": 900,
                    "suspicious_path_hits": 80,
                    "persistence_hits": 60,
                    "lolbin_processes": 20,
                }
            },
        )

        self.assertEqual(result["severity"], "Low")
        self.assertEqual(result["evidence_counts"]["categories_present"], 0)

    def test_background_noise_cannot_move_a_band(self) -> None:
        # Two runs of the same sample, differing only in how busy the host was.
        # The nine-point swing that used to be possible must not change the
        # verdict.
        quiet = _score(
            findings_summary={"counts": {"interesting_events": 20}},
            memory_yara_summary={"memory_only_rules": ["R1"], "counts": {}},
        )
        noisy = _score(
            findings_summary={
                "counts": {
                    "interesting_events": 900,
                    "process_creates": 50,
                    "file_write_events": 400,
                }
            },
            memory_yara_summary={"memory_only_rules": ["R1"], "counts": {}},
        )

        self.assertEqual(quiet["severity"], noisy["severity"])
        self.assertEqual(quiet["verdict"], noisy["verdict"])

    def test_a_clean_run_is_reported_as_clean(self) -> None:
        result = _score()

        self.assertEqual(result["severity"], "Low")
        self.assertEqual(result["verdict"], "Benign / Clean Baseline")


class CorroborationTests(unittest.TestCase):
    def test_two_weak_categories_reach_high(self) -> None:
        # Neither is emphatic on its own; agreeing is what makes them a finding.
        result = _score(
            dropped_files_summary={"suspicious": 1},
            task_diff_summary={"counts": {"suspicious_new_or_modified": 1}},
        )

        self.assertEqual(result["severity"], "High")
        self.assertEqual(result["evidence_counts"]["categories_present"], 2)

    def test_three_categories_are_likely_malicious(self) -> None:
        result = _score(
            dropped_files_summary={"suspicious": 1},
            task_diff_summary={"counts": {"suspicious_new_or_modified": 1}},
            sysmon_summary={"injection_events": [{"pid": 1}]},
        )

        self.assertEqual(result["verdict"], "Likely Malicious")

    def test_a_category_fires_once_however_many_events_back_it(self) -> None:
        # Otherwise one chatty behaviour outvotes three quiet ones and the
        # model is volume-driven again under a different name.
        once = _score(sysmon_summary={"injection_events": [{"pid": 1}]})
        many = _score(sysmon_summary={"injection_events": [{"pid": n} for n in range(50)]})

        self.assertEqual(
            once["evidence_counts"]["categories_present"],
            many["evidence_counts"]["categories_present"],
        )

    def test_suspicious_powershell_is_a_category(self) -> None:
        # One of the paths that has never fired on real malware. It scores when
        # it does.
        result = _score(
            powershell_summary={"counts": {"blocks_suspicious": 1}},
        )
        names = {c["name"] for c in result["evidence_categories"]}

        self.assertIn("scripted_execution", names)
        self.assertEqual(result["severity"], "Medium")

    def test_windows_baseline_lookups_are_not_a_c2_contact(self) -> None:
        # Once the guest had a default route, Windows started reaching the
        # simulated internet by itself on every run.
        result = _score(
            sysmon_summary={"dns_queries": ["www.msftconnecttest.com", "wpad"]},
        )

        self.assertEqual(result["evidence_counts"]["categories_present"], 0)


if __name__ == "__main__":
    unittest.main()
