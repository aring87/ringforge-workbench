"""Reading a sweep back: what answered, what did not, and what belongs elsewhere.

The distinction under test is the one a run turns on. `Geo` answers with
`PluginMessage "Getting geolocation"`; so does `Wifi`; so does `PC`. Calling
those mispaired would flag most of a sweep and hide the two that really were
shifted. Calling them attributed would be worse: a status frame names no
command, so it rests on the position it arrived in, and position is what broke
on 02 Sep when one command answered with two frames.
"""

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.read_beacon_run import STATUS_PACKETS, read


def _exchange(name, responses=None, byte_count=0, closed="read timeout"):
    entry = {
        "candidate": name,
        "reply_bytes_from_client": byte_count,
        "answered": bool(byte_count),
        "closed_by": closed,
    }
    if responses is not None:
        entry["responses"] = [
            {"bytes": 10, "ok": True, "fields": pairs, "answers": dict(pairs).get("Packet")}
            for pairs in responses
        ]
    return entry


def _capture(exchanges, **record):
    base = {"connection": 1, "at": "t", "peer": "127.0.0.1:1", "frames": [],
            "closed_by": "complete frame", "exchanges": exchanges}
    base.update(record)
    return json.dumps(base)


def _run(text: str) -> str:
    with TemporaryDirectory() as tmp:
        path = Path(tmp) / "beacon_listener.jsonl"
        path.write_text(text, encoding="utf-8")
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = read(path)
        assert code == 0
        return buffer.getvalue()


class Reading(unittest.TestCase):
    def test_a_command_that_answers_itself_is_clean(self) -> None:
        out = _run(_capture([
            _exchange("PortSpy", [[["Packet", "PortSpy"], ["Ports", "x"]]], 280)
        ]))

        self.assertIn("PortSpy", out)
        self.assertNotIn("NOT THIS COMMAND", out)
        self.assertIn("mismatched  0", out)

    def test_a_silence_is_counted_and_named(self) -> None:
        out = _run(_capture([_exchange("ProcessSpy", [], 0)]))

        self.assertIn("SILENT (read timeout)", out)
        self.assertIn("silent      1", out)

    def test_a_response_naming_another_command_is_flagged(self) -> None:
        """The real shift: GetWebcams' window held Clipboard's frame."""
        out = _run(_capture([
            _exchange("GetWebcams", [[["Packet", "Clipboard"], ["Text", "x"]]], 384)
        ]))

        self.assertIn("NOT THIS COMMAND", out)
        self.assertIn("mismatched  1", out)

    def test_a_status_reply_is_not_a_mismatch(self) -> None:
        """Geo really does answer with PluginMessage."""
        out = _run(_capture([
            _exchange("Geo", [[["Packet", "PluginMessage"], ["Message", "geo"]]], 82)
        ]))

        self.assertIn("mismatched  0", out)
        self.assertIn("status only 1", out)
        self.assertIn("position only", out)

    def test_every_status_type_the_dispatcher_sends_is_known(self) -> None:
        self.assertEqual(
            STATUS_PACKETS,
            frozenset({"PluginMessage", "Success", "Error", "Info"}),
        )

    def test_two_frames_for_one_command_are_both_shown(self) -> None:
        """GetClipboard acks and then sends. Reading one of them lost the run."""
        out = _run(_capture([
            _exchange("GetClipboard",
                      [[["Packet", "PluginMessage"], ["Message", "sent"]],
                       [["Packet", "Clipboard"], ["Text", "x"]]], 500)
        ]))

        self.assertIn("2 frame(s)", out)
        self.assertIn("'PluginMessage'", out)
        self.assertIn("'Clipboard'", out)


    def test_a_request_answered_by_its_response_is_not_a_mismatch(self) -> None:
        """RegistryRequest is answered by RegistryResponse, measured 02 Sep."""
        out = _run(_capture([
            _exchange("RegistryRequest",
                      [[["Packet", "RegistryResponse"], ["Type", "Roots"]]], 191)
        ]))

        self.assertIn("mismatched  0", out)
        self.assertNotIn("NOT THIS COMMAND", out)

    def test_device_request_pairs_the_same_way(self) -> None:
        out = _run(_capture([
            _exchange("DeviceRequest",
                      [[["Packet", "DeviceResponse"], ["Type", "Devices"]]], 2059)
        ]))

        self.assertIn("mismatched  0", out)

    def test_a_response_for_another_request_still_flags(self) -> None:
        """The convention must not swallow a real shift."""
        out = _run(_capture([
            _exchange("RegistryRequest",
                      [[["Packet", "DeviceResponse"]]], 100)
        ]))

        self.assertIn("mismatched  1", out)


class LegacyCaptures(unittest.TestCase):
    """The 02 Sep shape: one frame per exchange, and no responses list."""

    def test_it_reads_them_and_says_they_are_positional(self) -> None:
        out = _run(_capture([
            {"candidate": "GetWebcams", "reply_bytes_from_client": 384,
             "answered": True, "closed_by": "complete frame",
             "fields": [["Packet", "Clipboard"], ["Text", "x"]]},
        ]))

        self.assertIn("PREDATES THE DRAIN FIX", out)
        self.assertIn("NAMES 'Clipboard'", out)

    def test_a_missing_capture_is_reported_not_raised(self) -> None:
        with TemporaryDirectory() as tmp:
            self.assertEqual(read(Path(tmp) / "nothing.jsonl"), 2)

    def test_a_directory_finds_the_capture_inside_it(self) -> None:
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "beacon_listener.jsonl").write_text(
                _capture([_exchange("Ping", [[["Packet", "Ping"]]], 10)]),
                encoding="utf-8",
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = read(Path(tmp))

        self.assertEqual(code, 0)
        self.assertIn("Ping", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
