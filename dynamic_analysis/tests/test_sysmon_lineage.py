"""The Sysmon highlight pass never asked whose behaviour it was watching.

It tested three things -- the analyzer's own tooling, two exact OS injection
pairs, and noise DNS -- and everything falling through those lists became a
finding *about the sample*. On 07 Aug that cost a verdict band.

`dwm.exe` raised a `CreateRemoteThread` whose `TargetImage` Sysmon could not
resolve. `_OS_INJECTION_PAIRS` holds `("dwm.exe", "csrss.exe")` for exactly this
case and could not match `("dwm.exe", "")`, so the event became the run's only
high-severity highlight. `high_severity_count: 1` made
`credential_access_or_tampering` present in its own right, and the score went
**70 to 90**, Elevated Attention to Likely Malicious, on the Desktop Window
Manager compositing the screen.

The lesson is the one this pipeline keeps relearning: a name list cannot be the
attribution. It has to be extended forever, and an unresolved field defeats it.
The lists stay as suppression aids that run *before* attribution; lineage decides
whose behaviour it was. Fourth time in the same shape, after the network records,
the PowerShell blocks and the dropped files.
"""

import unittest

from dynamic_analysis.sysmon_collector import _actor_pid, summarize_sysmon_events


SAMPLE_TREE = {6200, 9532, 7884, 11164, 6260, 10864}


def _event(event_id, data, execution_pid=""):
    return {
        "event_id": event_id,
        "event_name": f"Event{event_id}",
        "timestamp": "2026-08-07T04:42:49Z",
        "process_id": data.get("ProcessId", ""),
        "execution_process_id": execution_pid,
        "data_values": [],
        "image": data.get("Image", ""),
        "data": data,
    }


def _dwm_injection():
    """The event that cost a band, verbatim in shape: no resolvable target."""
    return _event(8, {
        "SourceImage": r"C:\WINDOWS\system32\dwm.exe",
        "TargetImage": "",
        "SourceProcessId": "1996",
        "ProcessId": "700",
    })


def _sample_injection():
    return _event(8, {
        "SourceImage": r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe",
        "TargetImage": "",
        "SourceProcessId": "11164",
        "ProcessId": "700",
    })


class ActorPidTests(unittest.TestCase):
    def test_an_injection_names_the_injector_not_the_victim(self) -> None:
        # Reading ProcessId here would attribute the injection to the process
        # injected *into*, which on a hollowing run is the sample's own child --
        # so the wrong field would have made this fire more often, not less.
        self.assertEqual(_actor_pid(_dwm_injection()), 1996)

    def test_process_access_is_read_the_same_way(self) -> None:
        event = _event(10, {"SourceProcessId": "4242", "ProcessId": "700"})
        self.assertEqual(_actor_pid(event), 4242)

    def test_everything_else_acts_through_processid(self) -> None:
        self.assertEqual(_actor_pid(_event(22, {"ProcessId": "9532"})), 9532)

    def test_the_system_block_pid_is_the_fallback(self) -> None:
        # Some providers carry no EventData PID at all.
        self.assertEqual(_actor_pid(_event(4104, {}, execution_pid="3464")), 3464)

    def test_an_unreadable_pid_is_none(self) -> None:
        self.assertIsNone(_actor_pid(_event(22, {"ProcessId": ""})))
        self.assertIsNone(_actor_pid(_event(22, {"ProcessId": "0"})))


class HighlightAttributionTests(unittest.TestCase):
    def test_the_dwm_event_no_longer_scores(self) -> None:
        # The whole run, replayed: this was its only high-severity highlight.
        summary = summarize_sysmon_events([_dwm_injection()], descendant_pids=SAMPLE_TREE)

        self.assertEqual(summary["high_severity_count"], 0)
        self.assertEqual(summary["highlights"], [])
        self.assertEqual(summary["injection_events"], [])
        self.assertEqual(summary["other_process_events_excluded"], 1)

    def test_it_is_listed_rather_than_dropped(self) -> None:
        # "Sysmon saw nothing" and "Sysmon saw it and it was somebody else's" are
        # different runs. The event is real and worth being able to find.
        summary = summarize_sysmon_events([_dwm_injection()], descendant_pids=SAMPLE_TREE)

        listed = summary["other_process_highlights"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["actor_pid"], 1996)
        self.assertTrue(listed[0]["other_process"])

    def test_a_real_injection_by_the_sample_still_fires(self) -> None:
        # The filter must not be so tight that the technique it exists for stops
        # registering. This is the case that would make the category earned.
        summary = summarize_sysmon_events([_sample_injection()], descendant_pids=SAMPLE_TREE)

        self.assertEqual(summary["high_severity_count"], 1)
        self.assertEqual(len(summary["injection_events"]), 1)
        self.assertEqual(summary["other_process_events_excluded"], 0)

    def test_both_at_once_keeps_one_and_sets_the_other_aside(self) -> None:
        summary = summarize_sysmon_events(
            [_dwm_injection(), _sample_injection()], descendant_pids=SAMPLE_TREE
        )

        self.assertEqual(summary["high_severity_count"], 1)
        self.assertEqual(len(summary["other_process_highlights"]), 1)
        self.assertIn("RegSvcs", summary["highlights"][0]["detail"])

    def test_unresolved_lineage_counts_everything(self) -> None:
        # The same degrade the findings, the PowerShell blocks and the dropped
        # files use. None means "could not resolve", and dropping evidence on
        # that basis would be worse than over-reporting it -- but the field says
        # so, so the attribution can be read as unproven.
        summary = summarize_sysmon_events([_dwm_injection()], descendant_pids=None)

        self.assertEqual(summary["high_severity_count"], 1)
        self.assertFalse(summary["lineage_resolved"])
        self.assertEqual(summary["other_process_events_excluded"], 0)

    def test_lineage_resolved_says_which_kind_of_zero_it_is(self) -> None:
        resolved = summarize_sysmon_events([], descendant_pids=SAMPLE_TREE)
        self.assertTrue(resolved["lineage_resolved"])

    def test_dns_by_another_process_is_not_the_samples_lookup(self) -> None:
        # The same hole, at low severity: msftconnecttest is Windows' own
        # connectivity check and was listed among the sample's findings.
        event = _event(22, {
            "ProcessId": "1500",
            "Image": r"C:\Windows\System32\svchost.exe",
            "QueryName": "www.msftconnecttest.com",
        })

        summary = summarize_sysmon_events([event], descendant_pids=SAMPLE_TREE)

        self.assertEqual(summary["dns_queries"], [])
        self.assertEqual(summary["other_process_events_excluded"], 1)

    def test_the_samples_own_lookup_survives(self) -> None:
        event = _event(22, {
            "ProcessId": "9532",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "QueryName": "evil.example",
        })

        summary = summarize_sysmon_events([event], descendant_pids=SAMPLE_TREE)

        self.assertEqual(summary["dns_queries"], ["evil.example"])

    def test_the_suppression_lists_still_run_first(self) -> None:
        # Their counts have to keep describing what they removed, so an event that
        # is both the analyzer's and outside the tree is counted as the
        # analyzer's -- not double-counted, and not reclassified.
        analyzer = _event(6, {
            "ImageLoaded": r"C:\Users\adam\AppData\Local\Temp\_MEI93042\pydivert\windivert_dll\WinDivert64.sys",
            "ProcessId": "1234",
        })

        summary = summarize_sysmon_events([analyzer], descendant_pids=SAMPLE_TREE)

        self.assertEqual(summary["analyzer_highlights_excluded"], 1)
        self.assertEqual(summary["other_process_events_excluded"], 0)


if __name__ == "__main__":
    unittest.main()
