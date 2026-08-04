"""Whose lookup it was is decided by who asked, not by the domain.

An AgentTesla run recorded seven DNS queries. One was the sample's; the other
six were Office, OneDrive and Windows resolving their own endpoints while the
sample happened to be running. The unanswered-lookup warning read that list
straight and reported "the sample resolving 7 name(s)", listing Microsoft's
domains as though the malware had asked for them.

Filtering by domain does not work. is_baseline_domain recognised only two of
the six -- wpad and ecs.office.com -- and a suffix list has to be extended
forever while still missing microsoft.microsoftofficehub.

Sysmon event 22 records the requesting image, which settles it directly. The
excluded lookups are kept rather than dropped, so "the sample resolved nothing"
and "its resolution was filtered" stay distinguishable.
"""

import unittest

from dynamic_analysis.sysmon_collector import summarize_sysmon_events

SAMPLE = r"C:\rf\samples\31a7\31a7.exe"
COPILOT = r"C:\Program Files\Microsoft Office\M365Copilot.exe"
ONEDRIVE = r"C:\Users\adam\AppData\Local\Microsoft\OneDrive\OneDrive.exe"


def dns(name: str, image: str) -> dict:
    return {
        "event_id": 22,
        "event_name": "DnsQuery",
        "data": {"QueryName": name, "QueryResults": "-", "Image": image},
    }


#: The seven from the run, with the images Sysmon recorded.
REAL_RUN = [
    dns("aefd.nelreports.net", COPILOT),
    dns("www.microsoft365.com", COPILOT),
    dns("res.public.onecdn.static.microsoft", ONEDRIVE),
    dns("microsoft.microsoftofficehub", COPILOT),
    dns("ecs.office.com", COPILOT),
    dns("ftp.cyberflor.co", SAMPLE),
]


class DnsAttributionTests(unittest.TestCase):
    def test_only_the_sample_s_lookup_is_the_sample_s(self) -> None:
        summary = summarize_sysmon_events(REAL_RUN)

        self.assertEqual(summary["dns_queries"], ["ftp.cyberflor.co"])

    def test_the_others_are_kept_not_dropped(self) -> None:
        summary = summarize_sysmon_events(REAL_RUN)

        self.assertEqual(summary["noise_dns_excluded"], 5)
        self.assertIn("microsoft.microsoftofficehub", summary["noise_dns_queries"])

    def test_a_noise_lookup_is_not_a_finding(self) -> None:
        summary = summarize_sysmon_events(REAL_RUN)
        details = [h["detail"] for h in summary["highlights"]]

        self.assertEqual(details, ["ftp.cyberflor.co -> -"])

    def test_an_unknown_process_is_still_the_sample_s_until_shown_otherwise(self) -> None:
        # Erring towards reporting: an unrecognised image is not evidence of
        # innocence, and a missed lookup is worse than an extra one.
        summary = summarize_sysmon_events(
            [dns("evil.example.com", r"C:\Windows\Temp\unknown.exe")]
        )

        self.assertEqual(summary["dns_queries"], ["evil.example.com"])

    def test_a_lookup_with_no_image_is_still_reported(self) -> None:
        summary = summarize_sysmon_events([dns("evil.example.com", "")])

        self.assertEqual(summary["dns_queries"], ["evil.example.com"])

    def test_other_event_types_are_untouched(self) -> None:
        # The image check is scoped to event 22; a network connect from a noise
        # process is judged by the existing rules, not by this one.
        summary = summarize_sysmon_events(
            [
                {
                    "event_id": 3,
                    "event_name": "NetworkConnect",
                    "data": {"DestinationIp": "1.2.3.4", "DestinationPort": "443",
                             "Image": COPILOT},
                }
            ]
        )

        self.assertEqual(summary["network_targets"], ["1.2.3.4:443"])
        self.assertEqual(summary["noise_dns_excluded"], 0)


if __name__ == "__main__":
    unittest.main()
