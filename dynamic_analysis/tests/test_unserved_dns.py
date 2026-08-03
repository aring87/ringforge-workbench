"""A lookup the simulated internet never answered is a gap, not a quiet sample.

From a real AgentTesla run. The sample resolved ftp.cyberflor.co and Sysmon
recorded it. FakeNet logged zero DNS requests. The report then said:

    Resolved Domains (excluding Windows baseline): 0
    "Only routine Windows background traffic was resolved. Nothing here is
     attributable to the sample."

    Domains Requested Against Simulated Internet: 0
    "No domains were requested. With no default route the guest generates
     little background traffic, so this is expected for a sample that does not
     use the network."

Every one of those statements was locally true -- the network IOCs come from
the pcap, which never saw the query -- and the conclusion they invited was
wrong. The sample asked for its C2 and got nothing, so its exfil stage never
ran. That is the opposite of a sample that does not use the network, and it is
the difference between "no C2 observed" meaning something and meaning nothing.
"""

import unittest

from dynamic_analysis.html_report import (
    _fakenet_cannot_intercept_section,
    _fakenet_dns_empty_text,
    _fakenet_domains,
    _unserved_dns_section,
)


def _summary(sysmon_queries=None, fakenet_requests=None, enabled=True, parsed=True):
    return {
        "fakenet_enabled": enabled,
        "fakenet_summary": {
            "parsed": parsed,
            "dns_requests": list(fakenet_requests or []),
        },
        "sysmon_summary": {"dns_queries": list(sysmon_queries or [])},
    }


class UnservedDnsTests(unittest.TestCase):
    def test_the_agenttesla_case_warns(self) -> None:
        html = _unserved_dns_section(_summary(sysmon_queries=["ftp.cyberflor.co"]))

        self.assertIn("Name Resolution Was Not Served", html)
        self.assertIn("ftp.cyberflor.co", html)
        self.assertIn("unobserved", html)

    def test_a_genuinely_quiet_sample_says_nothing(self) -> None:
        self.assertEqual(_unserved_dns_section(_summary()), "")

    def test_no_warning_when_fakenet_served_the_lookup(self) -> None:
        html = _unserved_dns_section(
            _summary(
                sysmon_queries=["ftp.cyberflor.co"],
                fakenet_requests=["ftp.cyberflor.co"],
            )
        )

        self.assertEqual(html, "")

    def test_no_warning_when_fakenet_was_disabled(self) -> None:
        # Nothing was meant to answer, so nothing failed to.
        html = _unserved_dns_section(
            _summary(sysmon_queries=["ftp.cyberflor.co"], enabled=False)
        )

        self.assertEqual(html, "")

    def test_no_warning_when_the_fakenet_log_could_not_be_parsed(self) -> None:
        # Absent evidence is not evidence that nothing was served.
        html = _unserved_dns_section(
            _summary(sysmon_queries=["ftp.cyberflor.co"], parsed=False)
        )

        self.assertEqual(html, "")


class ServedComparisonTests(unittest.TestCase):
    """Compared name by name, not "did FakeNet serve anything".

    The first version of this warning asked the latter. Once the guest was
    given a default route and interception started working, Windows began
    reaching the simulated internet on its own -- NCSI checks to
    msftconnecttest.com on every run -- so "FakeNet served something" became
    true regardless of the sample, and the warning would have fallen silent
    exactly when it started to matter.
    """

    def _summary(self, served, sysmon):
        return {
            "fakenet_enabled": True,
            "fakenet_summary": {"parsed": True, "dns_requests": list(served)},
            "sysmon_summary": {"dns_queries": list(sysmon)},
            "network_isolation": {"egress_count": 1},
        }

    def test_windows_traffic_does_not_mask_the_sample_going_unserved(self) -> None:
        html = _unserved_dns_section(
            self._summary(["www.msftconnecttest.com"], ["ftp.cyberflor.co"])
        )

        self.assertIn("Name Resolution Was Not Served", html)
        self.assertIn("ftp.cyberflor.co", html)

    def test_no_warning_once_the_sample_itself_is_served(self) -> None:
        html = _unserved_dns_section(
            self._summary(
                ["www.msftconnecttest.com", "ftp.cyberflor.co"], ["ftp.cyberflor.co"]
            )
        )

        self.assertEqual(html, "")

    def test_case_and_trailing_dot_are_not_a_mismatch(self) -> None:
        html = _unserved_dns_section(
            self._summary(["FTP.CyberFlor.co."], ["ftp.cyberflor.co"])
        )

        self.assertEqual(html, "")

    def test_only_the_unserved_names_are_listed(self) -> None:
        html = _unserved_dns_section(
            self._summary(["a.example.com"], ["a.example.com", "b.example.com"])
        )

        self.assertIn("b.example.com", html)
        self.assertIn("Unanswered: 1", html)


class DomainSplitTests(unittest.TestCase):
    def test_windows_traffic_is_separated_from_the_sample_s(self) -> None:
        summary = {
            "fakenet_summary": {
                "dns_requests": ["www.msftconnecttest.com", "ftp.cyberflor.co"]
            }
        }

        notable, baseline = _fakenet_domains(summary)

        self.assertEqual(notable, ["ftp.cyberflor.co"])
        self.assertEqual(baseline, ["www.msftconnecttest.com"])

    def test_an_empty_log_splits_to_nothing(self) -> None:
        self.assertEqual(_fakenet_domains({}), ([], []))


class CannotInterceptTests(unittest.TestCase):
    """The root cause, not the symptom.

    The guest's route table held only loopback, the on-link /24, multicast and
    broadcast. With no default route Windows rejects a send to any off-link
    address before a packet exists, and FakeNet diverts packets -- so twelve
    listeners sat configured and unreachable.
    """

    def _summary(self, egress_count=0, listeners=12, parsed=True, enabled=True):
        return {
            "fakenet_enabled": enabled,
            "fakenet_summary": {
                "parsed": parsed,
                "dns_requests": [],
                "listeners_configured": [f"L{n}" for n in range(listeners)],
            },
            "sysmon_summary": {"dns_queries": []},
            "network_isolation": {"egress_count": egress_count},
        }

    def test_no_route_means_the_listeners_are_unreachable(self) -> None:
        html = _fakenet_cannot_intercept_section(self._summary())

        self.assertIn("Simulated Internet Cannot Be Reached", html)
        self.assertIn("Listeners idle: 12", html)

    def test_one_egress_path_is_fine(self) -> None:
        # A single default route is what the isolation check already calls
        # contained; it guards against a second adapter, not against having one.
        self.assertEqual(
            _fakenet_cannot_intercept_section(self._summary(egress_count=1)), ""
        )

    def test_silent_when_fakenet_is_disabled(self) -> None:
        self.assertEqual(
            _fakenet_cannot_intercept_section(self._summary(enabled=False)), ""
        )

    def test_silent_without_isolation_data(self) -> None:
        summary = self._summary()
        summary["network_isolation"] = {}
        self.assertEqual(_fakenet_cannot_intercept_section(summary), "")


class EmptyStateWordingTests(unittest.TestCase):
    def test_the_reassuring_reading_is_withheld_when_the_sample_tried(self) -> None:
        text = _fakenet_dns_empty_text(_summary(sysmon_queries=["ftp.cyberflor.co"]))

        self.assertIn("gap in what was observed", text)
        self.assertNotIn("this is expected", text)

    def test_the_reassuring_reading_stands_when_it_is_true(self) -> None:
        text = _fakenet_dns_empty_text(_summary())

        self.assertIn("expected for a sample that does not use the network", text)


if __name__ == "__main__":
    unittest.main()
