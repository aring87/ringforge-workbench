"""The boot window: reading a stage no collector was started for.

A payload behind an `ONLOGON` task runs before the pipeline exists. The Procmon
answer to that has to be armed ahead of a boot and then win a race it lost by
3m51s on 31 Aug. Sysmon has no such problem -- its driver is boot-start -- so
the events were always there and the work is reading them correctly.

Three things can go wrong quietly, and each has a test here:

- **The window can start too late.** `GetTickCount64` excludes time spent
  suspended, so a guest restored from a saved state reports an uptime shorter
  than the wall clock and places the boot *after* the payload started. The
  earlier of the two sources wins for that reason.
- **The read can be truncated from the wrong end.** `wevtutil` is queried
  newest-first, so a capped result drops the *oldest* events -- the boot, the
  logon, the payload's first seconds. A round number of events is the only
  visible symptom, which is no symptom at all.
- **Nothing can be attributed.** A logon-triggered payload has no launched PID.
  Without lineage the summary is the machine's whole boot, and an ordinary boot
  is not quiet.
"""

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from dynamic_analysis import sysmon_collector
from dynamic_analysis.sysmon_collector import (
    BOOT_TIME_TOLERANCE_SECONDS,
    collect_since_boot,
    descendants_from_sysmon,
    payload_appearance,
    resolve_boot_time,
)


BOOT = datetime(2026, 8, 31, 21, 30, 0, tzinfo=timezone.utc)
BOOT_UTC = "2026-08-31T21:30:00.000Z"


def _create(pid, image, parent_pid, at_second):
    """A Sysmon ProcessCreate in the shape `_event_to_dict` produces."""
    stamp = (BOOT + timedelta(seconds=at_second)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    data = {
        "ProcessId": str(pid),
        "ParentProcessId": str(parent_pid),
        "Image": image,
        "ParentImage": "C:\\Windows\\System32\\svchost.exe",
    }
    return {
        "event_id": 1,
        "event_name": "ProcessCreate",
        "timestamp": stamp,
        "process_id": str(pid),
        "execution_process_id": "",
        "data_values": [],
        "image": image,
        "data": data,
    }


PAYLOAD = "C:\\Users\\analyst\\AppData\\Roaming\\PlatformRuntime\\PlatformRuntime.exe"


class ResolveBootTime(unittest.TestCase):
    def test_earlier_source_wins(self):
        """A late window is the failure that costs the finding, so it cannot happen.

        Too early collects background that lineage then attributes away. Too
        late removes the payload's first seconds and reports the rest as the
        whole story.
        """
        ticks = BOOT + timedelta(seconds=400)  # suspended time, unaccounted
        result = resolve_boot_time(ticks=ticks, cim=BOOT)

        self.assertEqual(result["since_utc"], BOOT_UTC)
        self.assertEqual(result["source"], "cim")

    def test_disagreement_beyond_tolerance_is_reported(self):
        ticks = BOOT + timedelta(seconds=BOOT_TIME_TOLERANCE_SECONDS + 60)
        result = resolve_boot_time(ticks=ticks, cim=BOOT)

        self.assertEqual(result["disagreement_seconds"], BOOT_TIME_TOLERANCE_SECONDS + 60)
        self.assertIn("saved state", result["note"])

    def test_small_disagreement_is_not_noise(self):
        result = resolve_boot_time(ticks=BOOT + timedelta(seconds=3), cim=BOOT)

        self.assertEqual(result["since_utc"], BOOT_UTC)
        self.assertEqual(result["note"], "")

    def test_a_single_source_says_nothing_cross_checks_it(self):
        result = resolve_boot_time(ticks=BOOT, cim=None)

        self.assertEqual(result["since_utc"], BOOT_UTC)
        self.assertIn("cross-check", result["note"])


    @unittest.skipUnless(sys.platform == "win32", "GetTickCount64 is Windows-only")
    def test_the_unstubbed_call_works_on_windows(self):
        """Every other test here injects both sources, so none of them touch
        `ctypes` or `powershell` -- and the first real call raised NameError on
        an import this module keeps inside a function. A test that stubs out
        everything it depends on proves the arithmetic and nothing else."""
        result = resolve_boot_time()

        self.assertTrue(result["since_utc"])
        self.assertGreater(result["uptime_seconds"], 0)


class Lineage(unittest.TestCase):
    def test_seeds_on_the_image_and_walks_the_tree(self):
        """Task Scheduler started it, so there is no launched PID to seed from."""
        events = [
            _create(4100, "C:\\Windows\\System32\\svchost.exe", 900, 5),
            _create(5200, PAYLOAD, 4100, 12),
            _create(5300, "C:\\Windows\\System32\\cmd.exe", 5200, 20),
            _create(5400, "C:\\Windows\\System32\\whoami.exe", 5300, 21),
            _create(6100, "C:\\Windows\\explorer.exe", 900, 30),
        ]

        pids = descendants_from_sysmon(events, "PlatformRuntime.exe")

        self.assertEqual(pids, {5200, 5300, 5400})

    def test_grandchild_recorded_before_its_parent_is_still_caught(self):
        """The fixed point exists for this; a single pass would drop 5400."""
        events = [
            _create(5400, "C:\\Windows\\System32\\whoami.exe", 5300, 21),
            _create(5300, "C:\\Windows\\System32\\cmd.exe", 5200, 20),
            _create(5200, PAYLOAD, 4100, 12),
        ]

        self.assertEqual(descendants_from_sysmon(events, "PlatformRuntime.exe"), {5200, 5300, 5400})

    def test_a_second_copy_of_the_payload_is_the_payload(self):
        events = [
            _create(5200, PAYLOAD, 4100, 12),
            _create(7700, "C:\\ProgramData\\PlatformRuntime.exe", 900, 400),
        ]

        self.assertEqual(descendants_from_sysmon(events, "PlatformRuntime.exe"), {5200, 7700})

    def test_absent_image_is_none_not_empty(self):
        """`None` is "the payload never appeared"; an empty set would read as
        "the payload ran and did nothing", which is the confusion this whole
        package exists to prevent."""
        events = [_create(6100, "C:\\Windows\\explorer.exe", 900, 30)]

        self.assertIsNone(descendants_from_sysmon(events, "PlatformRuntime.exe"))

    def test_no_image_given_is_none(self):
        self.assertIsNone(descendants_from_sysmon([_create(5200, PAYLOAD, 4100, 12)], ""))


class PayloadAppearance(unittest.TestCase):
    def test_measures_the_offset_the_capture_has_to_beat(self):
        events = [
            _create(4100, "C:\\Windows\\System32\\svchost.exe", 900, 5),
            _create(5200, PAYLOAD, 4100, 175),
        ]

        appearance = payload_appearance(events, "PlatformRuntime.exe", BOOT_UTC)

        self.assertTrue(appearance["seen"])
        self.assertEqual(appearance["seconds_after_boot"], 175)
        self.assertEqual(appearance["pids"], [5200])

    def test_earliest_start_wins_when_it_relaunches(self):
        events = [
            _create(7700, PAYLOAD, 900, 400),
            _create(5200, PAYLOAD, 4100, 175),
        ]

        appearance = payload_appearance(events, "PlatformRuntime.exe", BOOT_UTC)

        self.assertEqual(appearance["seconds_after_boot"], 175)
        self.assertEqual(appearance["process_creates"], 2)

    def test_not_seen_carries_no_offset(self):
        appearance = payload_appearance([], "PlatformRuntime.exe", BOOT_UTC)

        self.assertFalse(appearance["seen"])
        self.assertIsNone(appearance["seconds_after_boot"])


class CollectSinceBoot(unittest.TestCase):
    """`collect_since_boot` with the two Windows calls stubbed out."""

    def setUp(self):
        self.events = [
            _create(4100, "C:\\Windows\\System32\\svchost.exe", 900, 5),
            _create(5200, PAYLOAD, 4100, 12),
            _create(5300, "C:\\Windows\\System32\\cmd.exe", 5200, 20),
        ]
        self.attempts = [{"strategy": "timediff", "events": 3, "capped": False}]

        self._saved = {
            name: getattr(sysmon_collector, name)
            for name in (
                "resolve_boot_time", "export_evtx", "channel_record_count",
                "is_elevated", "query_events",
            )
        }

        sysmon_collector.resolve_boot_time = lambda: {
            "since_utc": BOOT_UTC, "source": "cim", "from_ticks": BOOT_UTC,
            "from_cim": BOOT_UTC, "disagreement_seconds": 0,
            "uptime_seconds": 3600, "note": "",
        }
        sysmon_collector.export_evtx = lambda path, since: {
            "success": True, "error": "", "path": str(path)
        }
        sysmon_collector.channel_record_count = lambda: 4212
        sysmon_collector.is_elevated = lambda: True

        def _query_events(since_utc, max_events=20000, attempts_out=None):
            if attempts_out is not None:
                attempts_out.extend(self.attempts)
            return self.events

        sysmon_collector.query_events = _query_events

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(sysmon_collector, name, value)

    def _collect(self, image="PlatformRuntime.exe", max_events=20000):
        with TemporaryDirectory() as tmp:
            events, summary, status = collect_since_boot(
                Path(tmp) / "sysmon_boot.evtx", image_name=image, max_events=max_events
            )
            return events, summary, status

    def test_resolves_lineage_and_the_payload_offset(self):
        _, summary, status = self._collect()

        self.assertTrue(status["success"])
        self.assertTrue(status["lineage_resolved"])
        self.assertTrue(summary["lineage_resolved"])
        self.assertEqual(status["payload"]["seconds_after_boot"], 12)

    def test_reads_are_declared_uncovered(self):
        """Sysmon has no read event. An absence here is not evidence about reads,
        and the manifest has to say so or the next reader will assume it is."""
        _, _, status = self._collect()

        self.assertFalse(status["reads_covered"])
        self.assertIn("no registry-read", status["reads_note"])

    def test_a_capped_read_says_the_oldest_events_were_dropped(self):
        """Newest-first truncation removes the payload's first seconds, and a
        round event count is the only other symptom."""
        self.attempts = [{"strategy": "timediff", "events": 20000, "capped": True}]

        _, _, status = self._collect()

        self.assertTrue(status["truncated"])
        self.assertIn("oldest events", status["truncation_note"])

    def test_an_uncapped_read_is_not_flagged(self):
        _, _, status = self._collect()

        self.assertFalse(status["truncated"])

    def test_a_payload_that_never_appears_is_named_as_such(self):
        self.events = [_create(6100, "C:\\Windows\\explorer.exe", 900, 30)]

        _, _, status = self._collect()

        self.assertFalse(status["lineage_resolved"])
        self.assertFalse(status["payload"]["seen"])
        self.assertIn("did not fire", status["lineage_note"])

    def test_no_image_reports_the_whole_boot_and_admits_it(self):
        _, summary, status = self._collect(image="")

        self.assertFalse(status["lineage_resolved"])
        self.assertFalse(summary["lineage_resolved"])
        self.assertIn("whole machine", status["lineage_note"])

    def test_an_unresolvable_boot_time_collects_nothing(self):
        sysmon_collector.resolve_boot_time = lambda: {
            "since_utc": "", "source": "", "from_ticks": "", "from_cim": "",
            "disagreement_seconds": 0, "uptime_seconds": 0,
            "note": "Neither source could be read.",
        }

        events, _, status = self._collect()

        self.assertEqual(events, [])
        self.assertFalse(status["success"])
        self.assertIn("boot time", status["error"])

    def test_the_manifest_is_serialisable(self):
        """It is written with `json.dumps`; a set of PIDs in it would raise at
        the end of a collection that had already succeeded."""
        _, summary, status = self._collect()

        json.dumps({"status": status, "summary": summary}, default=str)


if __name__ == "__main__":
    unittest.main()
