"""A process the watcher never saw must not be invisible.

An AgentTesla sample created two copies of itself seven milliseconds apart:

    10:14:35.1148125  9028 -> 7016
    10:14:35.1221064  9028 -> 4200

4200 was caught by the spawn trigger and dumped twice, with three AgentTesla
rules matching its memory. 7016 was never observed at all -- the watcher walks
the process tree twice a second, and it did not outlive an interval. Nothing in
the run mentioned that it had existed.

Sysmon's ProcessCreate is a kernel callback and misses nothing, so the
difference between its tree and the watcher's is exactly what the poll dropped.

These are reported, never dumped. A process that lives milliseconds is gone
long before ProcDump could attach, and shortening the poll only moves the
threshold. What this recovers is the knowledge that something ran, which is the
same gap the spawn trigger was built to close one level up.
"""

import unittest

from dynamic_analysis.memory_dump import reconcile_with_sysmon

SAMPLE = r"C:\rf\samples\31a7\31a762.exe"
UNRELATED = r"C:\Windows\System32\SecurityHealthHost.exe"


def create(pid, parent_pid, image=SAMPLE, timestamp=""):
    return {
        "event_id": 1,
        "event_name": "ProcessCreate",
        "timestamp": timestamp,
        "data": {
            "ProcessId": str(pid),
            "ParentProcessId": str(parent_pid),
            "Image": image,
            "CommandLine": image,
        },
    }


#: The run, as Sysmon recorded it.
REAL_RUN = [
    create(9028, 1404, timestamp="10:13:58.0656976 PM"),
    create(7016, 9028, timestamp="10:14:35.1148125 PM"),
    create(4200, 9028, timestamp="10:14:35.1221064 PM"),
    create(8524, 708, image=UNRELATED, timestamp="10:16:09 PM"),
]

#: What the watcher managed to observe.
OBSERVED = {"observed_processes": [{"pid": 9028}, {"pid": 4200}]}


class ReconciliationTests(unittest.TestCase):
    def test_the_missed_twin_is_recovered(self) -> None:
        missed = reconcile_with_sysmon(
            OBSERVED, REAL_RUN, sample_pid=9028, sample_name="31a762.exe"
        )

        self.assertEqual([m["pid"] for m in missed], [7016])

    def test_it_carries_enough_to_act_on(self) -> None:
        missed = reconcile_with_sysmon(OBSERVED, REAL_RUN, sample_pid=9028)[0]

        self.assertEqual(missed["parent_pid"], 9028)
        self.assertEqual(missed["timestamp"], "10:14:35.1148125 PM")
        self.assertIn("31a762.exe", missed["image"])

    def test_nothing_is_reported_when_the_watcher_caught_everything(self) -> None:
        observed = {"observed_processes": [{"pid": 9028}, {"pid": 7016}, {"pid": 4200}]}

        self.assertEqual(reconcile_with_sysmon(observed, REAL_RUN, sample_pid=9028), [])

    def test_unrelated_processes_are_not_claimed(self) -> None:
        # SecurityHealthHost descends from svchost, not from the sample.
        missed = reconcile_with_sysmon(OBSERVED, REAL_RUN, sample_pid=9028)

        self.assertNotIn(8524, [m["pid"] for m in missed])

    def test_a_grandchild_is_reached(self) -> None:
        events = REAL_RUN + [create(5555, 7016, timestamp="10:14:35.2 PM")]

        missed = reconcile_with_sysmon(OBSERVED, events, sample_pid=9028)

        self.assertEqual(sorted(m["pid"] for m in missed), [5555, 7016])

    def test_the_sample_s_own_image_seeds_lineage_without_a_pid(self) -> None:
        # A dropper relaunching itself, when the launched PID was not recorded.
        missed = reconcile_with_sysmon(
            {"observed_processes": []}, REAL_RUN, sample_name="31a762.exe"
        )

        self.assertEqual(sorted(m["pid"] for m in missed), [4200, 7016, 9028])

    def test_no_sysmon_events_reports_nothing(self) -> None:
        # Absent evidence is not evidence of a missed process.
        self.assertEqual(reconcile_with_sysmon(OBSERVED, [], sample_pid=9028), [])

    def test_no_sample_identity_reports_nothing(self) -> None:
        # Without a seed every process would look like a descendant.
        self.assertEqual(reconcile_with_sysmon(OBSERVED, REAL_RUN), [])

    def test_malformed_pids_are_skipped_not_fatal(self) -> None:
        events = REAL_RUN + [create("", 9028), create("not-a-pid", 9028)]

        missed = reconcile_with_sysmon(OBSERVED, events, sample_pid=9028)

        self.assertEqual([m["pid"] for m in missed], [7016])

    def test_a_pid_is_reported_once(self) -> None:
        events = REAL_RUN + [create(7016, 9028, timestamp="later")]

        missed = reconcile_with_sysmon(OBSERVED, events, sample_pid=9028)

        self.assertEqual([m["pid"] for m in missed], [7016])


if __name__ == "__main__":
    unittest.main()
