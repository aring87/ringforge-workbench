"""The WER image-timestamp check: hollowing visible from the event log alone.

The case that motivates this is real. On run `3f70058b` Windows recorded
`app_timestamp` `5ff2b99b` for `RegSvcs.exe` while the guest's own
`RegSvcs.exe` is `68531ee1` -- the payload's header, reported faithfully,
in a field the pipeline already parsed and never compared.
"""
import struct
import tempfile
import unittest
from pathlib import Path

from dynamic_analysis.crash_evidence import (
    check_image_timestamp,
    read_pe_timestamp,
    summarize_crashes,
    summarize_image_timestamps,
)

# From the run: stage 3's TimeDateStamp, and the real RegSvcs.exe's.
PAYLOAD_TDS = 0x5FF2B99B
REAL_REGSVCS_TDS = 0x68531EE1


def _pe(timestamp: int, e_lfanew: int = 0x80) -> bytes:
    """A minimal PE far enough to carry a TimeDateStamp."""
    blob = bytearray(e_lfanew + 24)
    blob[0:2] = b"MZ"
    blob[0x3C:0x40] = struct.pack("<I", e_lfanew)
    blob[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<I", blob, e_lfanew + 8, timestamp)
    return bytes(blob)


def _crash(app="RegSvcs.exe", stamp="5ff2b99b", path=r"C:\Windows\RegSvcs.exe"):
    return {"app_name": app, "app_timestamp": stamp, "app_path": path, "pid": 12080}


class ReadPeTimestamp(unittest.TestCase):
    def test_reads_the_stamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.exe"
            p.write_bytes(_pe(REAL_REGSVCS_TDS))
            self.assertEqual(read_pe_timestamp(p), REAL_REGSVCS_TDS)

    def test_missing_file_is_none_not_zero(self):
        # Zero is a legal TimeDateStamp; conflating it with "absent" would make
        # an unreadable file compare equal to a reproducible-build binary.
        self.assertIsNone(read_pe_timestamp(r"C:\nope\nothing-here.exe"))

    def test_not_a_pe_is_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.txt"
            p.write_bytes(b"not a pe at all, no MZ here")
            self.assertIsNone(read_pe_timestamp(p))

    def test_truncated_pe_is_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.exe"
            p.write_bytes(_pe(REAL_REGSVCS_TDS)[:0x50])
            self.assertIsNone(read_pe_timestamp(p))

    def test_absurd_e_lfanew_is_rejected_without_seeking(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.exe"
            blob = bytearray(_pe(REAL_REGSVCS_TDS))
            struct.pack_into("<I", blob, 0x3C, 0xFFFFFFF0)
            p.write_bytes(bytes(blob))
            self.assertIsNone(read_pe_timestamp(p))


class CheckImageTimestamp(unittest.TestCase):
    def test_the_real_run_reads_as_a_mismatch(self):
        entry = check_image_timestamp(_crash(), lambda _p: REAL_REGSVCS_TDS)
        self.assertEqual(entry["verdict"], "mismatch")
        self.assertEqual(entry["recorded"], "0x5ff2b99b")
        self.assertEqual(entry["on_disk"], "0x68531ee1")
        self.assertTrue(entry["hollowing_target"])

    def test_matching_stamp_is_identical(self):
        entry = check_image_timestamp(_crash(), lambda _p: PAYLOAD_TDS)
        self.assertEqual(entry["verdict"], "identical")

    def test_unreadable_file_is_no_reference_not_identical(self):
        entry = check_image_timestamp(_crash(), lambda _p: None)
        self.assertEqual(entry["verdict"], "no_reference")
        self.assertEqual(entry["on_disk"], "")

    def test_blank_timestamp_is_unparsable(self):
        entry = check_image_timestamp(_crash(stamp=""), lambda _p: REAL_REGSVCS_TDS)
        self.assertEqual(entry["verdict"], "unparsable")

    def test_0x_prefixed_stamp_parses(self):
        entry = check_image_timestamp(_crash(stamp="0x5ff2b99b"),
                                      lambda _p: REAL_REGSVCS_TDS)
        self.assertEqual(entry["verdict"], "mismatch")

    def test_non_hollowing_target_still_reported_but_not_emphatic(self):
        entry = check_image_timestamp(
            _crash(app="mygame.exe", path=r"C:\g\mygame.exe"),
            lambda _p: REAL_REGSVCS_TDS)
        self.assertEqual(entry["verdict"], "mismatch")
        self.assertFalse(entry["hollowing_target"])


class Summary(unittest.TestCase):
    def test_counts_split_target_from_the_rest(self):
        crashes = [_crash(), _crash(app="mygame.exe", path=r"C:\g\mygame.exe")]
        s = summarize_image_timestamps(crashes, lambda _p: REAL_REGSVCS_TDS)
        self.assertTrue(s["available"])
        self.assertEqual(s["counts"]["mismatch"], 2)
        self.assertEqual(s["counts"]["mismatch_in_hollowing_target"], 1)

    def test_nothing_comparable_is_unavailable_not_clean(self):
        s = summarize_image_timestamps([_crash()], lambda _p: None)
        self.assertFalse(s["available"])
        self.assertEqual(s["counts"]["mismatch"], 0)
        self.assertEqual(s["counts"]["no_reference"], 1)
        # Named, not merely counted.
        self.assertEqual(s["no_reference_processes"], ["RegSvcs.exe"])

    def test_no_crashes_is_unavailable(self):
        s = summarize_image_timestamps([], lambda _p: REAL_REGSVCS_TDS)
        self.assertFalse(s["available"])
        self.assertEqual(s["counts"]["checked"], 0)


class WiredIntoTheRunSummary(unittest.TestCase):
    """The count has to reach the summary, or nothing downstream can use it."""

    def _events(self):
        return [{
            "event_id": 1000,
            "timestamp": "2026-08-10T12:00:00Z",
            "data_values": [
                "RegSvcs.exe", "4.8.9221.0", "5ff2b99b",
                "unknown", "0.0.0.0", "00000000",
                "c0000005", "0150521d", "12080",
                "2026-08-10T11:59:00Z", r"C:\Windows\RegSvcs.exe", "",
            ],
        }]

    def test_summary_carries_the_mismatch(self):
        summary = summarize_crashes(
            self._events(), sample_pids={12080},
            read_timestamp=lambda _p: REAL_REGSVCS_TDS)
        self.assertEqual(
            summary["counts"]["timestamp_mismatch_in_hollowing_target"], 1)
        self.assertTrue(summary["image_timestamps"]["available"])

    def test_off_guest_reads_as_could_not_tell(self):
        # The bench has a different build of every system binary, so the file
        # is either absent or the wrong one. It must not read as agreement.
        summary = summarize_crashes(
            self._events(), sample_pids={12080}, read_timestamp=lambda _p: None)
        self.assertEqual(
            summary["counts"]["timestamp_mismatch_in_hollowing_target"], 0)
        self.assertFalse(summary["image_timestamps"]["available"])


if __name__ == "__main__":
    unittest.main()
