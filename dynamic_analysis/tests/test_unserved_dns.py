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

from dynamic_analysis.html_report import _fakenet_dns_empty_text, _unserved_dns_section


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
