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

from dynamic_analysis.orchestrator import calculate_dynamic_score


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


def _agent_tesla():
    """Three memory-only rules, plus FTP to a C2 on a passive data port."""
    return _score(
        findings_summary={
            "counts": {
                "interesting_events": 90,
                "process_creates": 2,
                "network_events": 2,
            }
        },
        memory_yara_summary={
            "memory_only_rules": [
                "Windows_Trojan_AgentTesla_d3ac2b2f",
                "Windows_Trojan_AgentTesla_ebf431a8",
                "Windows_Generic_Threat_808f680e",
            ],
            "counts": {"total_matches": 4},
        },
        # Everything resolves to the local responder, so the pcap sees no
        # external IP at all. The name is the evidence.
        network_summary={"counts": {"unusual_ports": 2}, "iocs": {"counts": {}}},
        fakenet_summary={"dns_requests": ["ftp.cyberflor.co"]},
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
            fakenet_summary={"dns_requests": ["www.msftconnecttest.com", "wpad"]},
        )

        self.assertEqual(result["evidence_counts"]["categories_present"], 0)


if __name__ == "__main__":
    unittest.main()
