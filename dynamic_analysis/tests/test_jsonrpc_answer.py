"""Phase 2 of `0bw`: encoding an answer to a getter nobody has read.

The thing under test is not "does it encode an address" but **does one run test
every hypothesis**. `getData()`'s return shape is unknown, the plausible shapes
are few, and rotation is what turns that from an argument into a sweep: the
implant retrying is the signal that advances the list, so acceptance and
rejection both land in the same log.

The ABI vectors below are hand-checked against the spec rather than against a
library, because a library would be testing itself.
"""

import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from dynamic_analysis.jsonrpc_answer import (
    PLANS,
    PLANS_BY_NAME,
    SINK_HOST,
    TRACER_ADDRESS,
    AnswerError,
    AnswerPlanner,
    encode_address,
    encode_bytes,
    encode_string,
    to_hex,
)
from dynamic_analysis.jsonrpc_responder import JsonRpcResponder, RequestRecorder


def _eth_call_body(identifier: int = 1) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0", "id": identifier, "method": "eth_call",
        "params": [{"to": "0x0F14fc3bfAc3726172aCd08Fe4bFb79B633E76ff",
                    "data": "0x3bc5de30"}, "latest"],
    }).encode()


def _http_post(body: bytes) -> bytes:
    return (
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )


class AbiTests(unittest.TestCase):
    def test_an_address_is_a_left_padded_word(self) -> None:
        encoded = encode_address(TRACER_ADDRESS)

        self.assertEqual(len(encoded), 32)
        self.assertEqual(encoded[:12], b"\x00" * 12)
        self.assertEqual(encoded[12:].hex(), TRACER_ADDRESS[2:].lower())

    def test_a_string_is_offset_length_then_padded_data(self) -> None:
        encoded = encode_string("hi")

        self.assertEqual(len(encoded), 96)
        self.assertEqual(int.from_bytes(encoded[0:32], "big"), 0x20)
        self.assertEqual(int.from_bytes(encoded[32:64], "big"), 2)
        self.assertEqual(encoded[64:66], b"hi")
        self.assertEqual(encoded[66:], b"\x00" * 30)

    def test_data_on_a_32_byte_boundary_gains_no_padding(self) -> None:
        # The off-by-one that a "always add a pad word" implementation gets
        # wrong, and which would make every answer subtly malformed.
        encoded = encode_bytes(b"A" * 32)

        self.assertEqual(len(encoded), 96)
        self.assertEqual(encoded[64:], b"A" * 32)

    def test_a_bad_address_is_refused_rather_than_encoded(self) -> None:
        for bad in ("", "0x", "C0FFEE", "0xnothex" + "0" * 33,
                    "0x" + "0" * 39, "0x" + "0" * 41):
            with self.subTest(bad=bad):
                with self.assertRaises(AnswerError):
                    encode_address(bad)

    def test_hex_round_trips(self) -> None:
        self.assertEqual(to_hex(b"\x00\xff"), "0x00ff")


class PlanTests(unittest.TestCase):
    def test_every_plan_encodes_and_is_described(self) -> None:
        for plan in PLANS:
            with self.subTest(plan=plan.name):
                result = plan.result(TRACER_ADDRESS)
                self.assertTrue(result.startswith("0x"))
                # The reason has to survive into the log; "plan 3 was accepted"
                # is meaningless to a later session without it.
                self.assertTrue(plan.why)

    def test_the_address_plan_is_a_single_word(self) -> None:
        self.assertEqual(len(PLANS_BY_NAME["address"].result(TRACER_ADDRESS)), 2 + 64)

    def test_the_raw_plan_carries_no_abi_framing(self) -> None:
        self.assertEqual(PLANS_BY_NAME["raw_hex"].result(TRACER_ADDRESS),
                         TRACER_ADDRESS)

    def test_the_json_plan_contains_the_address_verbatim(self) -> None:
        result = PLANS_BY_NAME["string_json"].result(TRACER_ADDRESS)
        decoded = bytes.fromhex(result[2:])[64:].rstrip(b"\x00").decode()

        self.assertIn(TRACER_ADDRESS, json.loads(decoded).values())


class RotationTests(unittest.TestCase):
    def test_rotation_advances_only_when_asked_again(self) -> None:
        # The whole trick. One call gets one plan; the implant asking again is
        # what says the last one was rejected.
        planner = AnswerPlanner()

        self.assertEqual(planner.answer()["plan"], PLANS[0].name)
        self.assertEqual(planner.answer()["plan"], PLANS[1].name)
        self.assertEqual(planner.served, [PLANS[0].name, PLANS[1].name])

    def test_the_list_holds_at_the_end_rather_than_cycling(self) -> None:
        # A client still asking after every hypothesis is telling you the list
        # is wrong; cycling would bury that under repetition.
        planner = AnswerPlanner()
        for _ in range(len(PLANS) + 3):
            planner.answer()

        self.assertEqual(planner.served[-1], PLANS[-1].name)
        self.assertTrue(planner.report()["all_plans_exhausted"])

    def test_a_pinned_plan_never_rotates(self) -> None:
        planner = AnswerPlanner(plan="raw_hex")

        self.assertEqual({planner.answer()["plan"] for _ in range(4)}, {"raw_hex"})
        self.assertFalse(planner.report()["all_plans_exhausted"])

    def test_an_unknown_plan_is_refused(self) -> None:
        with self.assertRaises(AnswerError):
            AnswerPlanner(plan="no_such_plan")

    def test_a_bad_address_is_refused_at_construction(self) -> None:
        # Loudly, and before the run: answering with the wrong thing and not
        # answering at all look identical from outside the guest.
        with self.assertRaises(AnswerError):
            AnswerPlanner(address="not-an-address")

    def test_the_tracer_default_is_flagged_as_such(self) -> None:
        self.assertTrue(AnswerPlanner().report()["address_is_tracer"])
        self.assertFalse(
            AnswerPlanner(address="0x" + "ab" * 20).report()["address_is_tracer"])


class RecorderIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())

    def test_without_a_planner_nothing_is_answered(self) -> None:
        # Phase 1 must stay exactly as it was; a summary with no answer block is
        # a run that told the implant nothing.
        recorder = RequestRecorder(self.tmp)
        record = recorder.note_request("p:1", _http_post(_eth_call_body()))
        payload = recorder.response_payload(record)

        self.assertIn("error", payload)
        self.assertEqual(recorder.report()["answer"], {})

    def test_a_target_call_is_answered_and_the_plan_recorded(self) -> None:
        recorder = RequestRecorder(self.tmp, planner=AnswerPlanner())
        record = recorder.note_request("p:1", _http_post(_eth_call_body()))
        payload = recorder.response_payload(record)

        self.assertEqual(payload["result"], PLANS[0].result(TRACER_ADDRESS))
        self.assertEqual(record["served_plan"], PLANS[0].name)
        self.assertEqual(record["served_attempt"], 1)

    def test_a_non_target_call_is_still_refused(self) -> None:
        # Answering questions nobody asked about the contract would make the log
        # unreadable -- and would hand a shape to a client that never wanted it.
        recorder = RequestRecorder(self.tmp, planner=AnswerPlanner())
        body = json.dumps({"jsonrpc": "2.0", "id": 2,
                           "method": "eth_chainId", "params": []}).encode()
        record = recorder.note_request("p:1", _http_post(body))
        payload = recorder.response_payload(record)

        self.assertIn("error", payload)
        self.assertNotIn("served_plan", record)

    def test_the_answer_is_appended_not_rewritten(self) -> None:
        # The request is logged on arrival because the box may die; the answer
        # is only known afterwards, so it lands as a second line.
        recorder = RequestRecorder(self.tmp, planner=AnswerPlanner())
        record = recorder.note_request("p:1", _http_post(_eth_call_body()))
        recorder.response_payload(record)

        kinds = [json.loads(line)["kind"] for line in
                 recorder.requests_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(kinds, ["request", "request_answered"])

    def test_the_summary_carries_what_was_served(self) -> None:
        recorder = RequestRecorder(self.tmp, planner=AnswerPlanner())
        for identifier in (1, 2):
            record = recorder.note_request("p:1", _http_post(_eth_call_body(identifier)))
            recorder.response_payload(record)

        answer = recorder.report()["answer"]
        self.assertEqual(answer["plans_served"], [PLANS[0].name, PLANS[1].name])
        self.assertEqual(answer["address"], TRACER_ADDRESS)


class OverTheWireTests(unittest.TestCase):
    """The whole path, because the encoding has to survive the socket too."""

    def test_a_retrying_client_walks_the_candidate_list(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        responder = JsonRpcResponder(tmp, host="127.0.0.1", port=0,
                                     planner=AnswerPlanner())
        self.assertTrue(responder.start()["started"])
        port = responder._server.server_address[1]
        results = []
        try:
            for identifier in (1, 2, 3):
                with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                    client.settimeout(5)
                    client.sendall(_http_post(_eth_call_body(identifier)))
                    reply = client.recv(65536)
                results.append(json.loads(reply.partition(b"\r\n\r\n")[2])["result"])
        finally:
            summary = responder.stop()

        self.assertEqual(results[0], PLANS[0].result(TRACER_ADDRESS))
        self.assertEqual(results[1], PLANS[1].result(TRACER_ADDRESS))
        self.assertEqual(results[2], PLANS[2].result(TRACER_ADDRESS))
        self.assertEqual(summary["answer"]["plans_served"],
                         [PLANS[0].name, PLANS[1].name, PLANS[2].name])
        self.assertEqual(summary["outcome"], "eth_call")


if __name__ == "__main__":
    unittest.main()


class UrlShapes(unittest.TestCase):
    """Added after run `20260822_141514`, which ruled the address shapes out.

    Three address encodings were served and rejected, and the implant stopped
    asking. Separately the EVM wallet turned out to be hardcoded alongside
    sixteen others, and substitution was observed working with no successful
    fetch at all -- so `getData()` is not delivering a substitution address.
    The beacon has no host anywhere in the config block, which is what makes a
    C2 endpoint the remaining candidate.
    """

    def _decode_string(self, result: str) -> str:
        raw = bytes.fromhex(result[2:])
        length = int.from_bytes(raw[32:64], "big")
        return raw[64:64 + length].decode()

    def test_the_sink_host_is_unregistrable(self) -> None:
        # A shape that escapes the guest must not be able to reach anyone.
        # `.test` is RFC 2606 and can never be registered.
        self.assertTrue(SINK_HOST.endswith(".test"))
        self.assertIn("c0ffee", SINK_HOST)

    def test_the_url_shape_carries_a_usable_url(self) -> None:
        result = PLANS_BY_NAME["url_https"].result(TRACER_ADDRESS, SINK_HOST)

        self.assertEqual(self._decode_string(result), f"https://{SINK_HOST}/")

    def test_the_bare_host_shape_carries_only_the_host(self) -> None:
        result = PLANS_BY_NAME["bare_host"].result(TRACER_ADDRESS, SINK_HOST)

        self.assertEqual(self._decode_string(result), SINK_HOST)

    def test_the_c2_document_carries_host_and_address(self) -> None:
        result = PLANS_BY_NAME["json_c2"].result(TRACER_ADDRESS, SINK_HOST)
        doc = json.loads(self._decode_string(result))

        self.assertEqual(doc["host"], SINK_HOST)
        self.assertEqual(doc["url"], f"https://{SINK_HOST}/")
        self.assertEqual(doc["address"], TRACER_ADDRESS)

    def test_a_custom_sink_host_reaches_the_shapes(self) -> None:
        planner = AnswerPlanner(plan="bare_host", sink_host="elsewhere.test")
        answer = planner.answer()

        self.assertEqual(self._decode_string(answer["result"]), "elsewhere.test")
        self.assertFalse(planner.report()["sink_host_is_default"])

    def test_the_address_shapes_ignore_the_host(self) -> None:
        # Every shape takes both now; the older ones must not start varying.
        a = PLANS_BY_NAME["address"].result(TRACER_ADDRESS, SINK_HOST)
        b = PLANS_BY_NAME["address"].result(TRACER_ADDRESS, "other.test")

        self.assertEqual(a, b)

    def test_the_url_shapes_come_after_the_address_shapes(self) -> None:
        # Rotation order matters: the three already ruled out should not be
        # re-served ahead of the untested ones on a fresh run... but they are
        # kept first deliberately, so a pinned re-run is the way to skip them.
        names = [p.name for p in PLANS]

        self.assertEqual(names[:3], ["address", "string_address", "string_json"])
        self.assertEqual(names[-3:], ["url_https", "bare_host", "json_c2"])
