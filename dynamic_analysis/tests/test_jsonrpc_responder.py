"""Phase 1 of `0bw`: the responder that records the question.

The point of these is that phase 1 must be *unable* to produce an ambiguous
result. A responder that cannot tell "the diverter never routed 8545" from "the
implant connected and said nothing" from "it asked something we did not
recognise" turns a guest run into a coin flip, and this project has already
spent runs on premises that were withdrawn twice before they reproduced.

The request used throughout is the one the sample is expected to send, built
from the config block read out of the carve at file offsets 148728-150541:
contract `0x0F14fc3b...`, selector `0x3bc5de30` (`getData()`).
"""

import json
import socket
import tempfile
import time
import unittest
from pathlib import Path

from dynamic_analysis.jsonrpc_responder import (
    ETHERHIDING_CONTRACT,
    GETDATA_SELECTOR,
    OUTCOME_CONNECTED_SILENT,
    OUTCOME_ETH_CALL,
    OUTCOME_NO_CONNECTION,
    OUTCOME_OTHER_RPC,
    OUTCOME_UNPARSED,
    JsonRpcResponder,
    _is_target_call,
    _parse_http,
    _parse_jsonrpc,
)

#: The contract as it appears in the carve -- EIP-55 mixed case, which is how a
#: caller usually writes it and which must still match the lowercased constant.
CONTRACT_CHECKSUMMED = "0x0F14fc3bfAc3726172aCd08Fe4bFb79B633E76ff"


def _eth_call_body(to: str = CONTRACT_CHECKSUMMED, data: str = GETDATA_SELECTOR) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"],
    }).encode()


def _http_post(body: bytes, path: str = "/") -> bytes:
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: data-seed-prebsc-1-s1.binance.org:8545\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body


class ParsingTests(unittest.TestCase):
    def test_an_http_post_is_split_into_headers_and_body(self) -> None:
        raw = _http_post(_eth_call_body())
        parsed = _parse_http(raw)

        self.assertTrue(parsed["is_http"])
        self.assertEqual(parsed["method"], "POST")
        self.assertEqual(parsed["headers"]["content-type"], "application/json")
        self.assertEqual(json.loads(parsed["body"])["method"], "eth_call")

    def test_bare_lf_headers_are_still_split(self) -> None:
        # Nothing guarantees the implant's HTTP is well-formed. A hand-rolled
        # client that sends LF rather than CRLF must not read as "not HTTP",
        # because that misclassification would be recorded as a finding.
        body = _eth_call_body()
        raw = (f"POST / HTTP/1.1\nContent-Length: {len(body)}\n\n").encode() + body
        parsed = _parse_http(raw)

        self.assertTrue(parsed["is_http"])
        self.assertEqual(parsed["body"], body)

    def test_something_that_is_not_http_keeps_its_bytes(self) -> None:
        # Raw JSON straight onto the socket is a plausible shape for a
        # hand-rolled client, and it is an answer to phase 1's question rather
        # than an error.
        raw = _eth_call_body()
        parsed = _parse_http(raw)

        self.assertFalse(parsed["is_http"])
        self.assertEqual(parsed["body"], raw)

    def test_the_call_fields_are_pulled_out(self) -> None:
        parsed = _parse_jsonrpc(_eth_call_body())
        call = parsed["calls"][0]

        self.assertTrue(parsed["is_jsonrpc"])
        self.assertEqual(call["method"], "eth_call")
        self.assertEqual(call["selector"], GETDATA_SELECTOR)
        self.assertEqual(call["block"], "latest")

    def test_a_batch_is_flattened(self) -> None:
        raw = json.dumps([
            {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
            json.loads(_eth_call_body()),
        ]).encode()
        parsed = _parse_jsonrpc(raw)

        self.assertEqual([c["method"] for c in parsed["calls"]],
                         ["eth_chainId", "eth_call"])

    def test_broken_json_is_recorded_not_raised(self) -> None:
        parsed = _parse_jsonrpc(b"{not json")

        self.assertFalse(parsed["is_jsonrpc"])
        self.assertTrue(parsed["parse_error"])

    def test_checksum_case_still_matches_the_contract(self) -> None:
        # The carve writes the address in EIP-55 mixed case; the constant is
        # lowercase. A case-sensitive compare here would silently miss the one
        # request this whole phase exists to catch.
        call = _parse_jsonrpc(_eth_call_body())["calls"][0]

        self.assertNotEqual(call["to"], ETHERHIDING_CONTRACT)
        self.assertTrue(_is_target_call(call))

    def test_the_selector_alone_is_enough(self) -> None:
        # Contract rotation is the expected way this campaign changes. The
        # durable half of the match is the getter.
        call = _parse_jsonrpc(
            _eth_call_body(to="0x1111111111111111111111111111111111111111")
        )["calls"][0]

        self.assertTrue(_is_target_call(call))

    def test_the_contract_alone_is_enough(self) -> None:
        call = _parse_jsonrpc(_eth_call_body(data="0xdeadbeef"))["calls"][0]

        self.assertTrue(_is_target_call(call))

    def test_an_unrelated_call_is_not_the_target(self) -> None:
        call = _parse_jsonrpc(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": [],
        }).encode())["calls"][0]

        self.assertFalse(_is_target_call(call))


class ResponderTests(unittest.TestCase):
    """Driven over a real socket, because the framing is the thing being tested."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        # Port 0 lets the OS choose, so the suite never collides with a real
        # 8545 or with itself running in parallel.
        self.responder = JsonRpcResponder(self.tmp, host="127.0.0.1", port=0)
        result = self.responder.start()
        self.assertTrue(result["started"], result.get("error"))
        self.port = self.responder._server.server_address[1]

    def tearDown(self) -> None:
        self.responder.stop()

    def _send(self, payload: bytes, read: bool = True) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as client:
            client.sendall(payload)
            if not read:
                return b""
            client.settimeout(5)
            return client.recv(65536)

    def test_the_target_call_is_recorded_and_answered(self) -> None:
        reply = self._send(_http_post(_eth_call_body()))
        summary = self.responder.report()

        self.assertIn(b"200 OK", reply)
        self.assertEqual(summary["outcome"], OUTCOME_ETH_CALL)
        self.assertEqual(summary["target_calls"], 1)
        self.assertEqual(summary["methods"], {"eth_call": 1})

    def test_the_answer_is_well_formed_and_useless(self) -> None:
        # Both halves matter. Well-formed, so a rejection is the parser's
        # decision about content rather than a protocol error; useless, because
        # phase 1 must not change what the implant does. C4 rests on this.
        reply = self._send(_http_post(_eth_call_body()))
        _, _, body = reply.partition(b"\r\n\r\n")
        payload = json.loads(body)

        self.assertEqual(payload["jsonrpc"], "2.0")
        self.assertEqual(payload["id"], 1)
        self.assertIn("error", payload)
        self.assertNotIn("result", payload)

    def test_the_empty_reply_mode_returns_a_successful_nothing(self) -> None:
        # What a real node returns for a contract with no code, which is the
        # truthful answer for this dead contract and a different path through
        # the implant's parser than an error.
        other = JsonRpcResponder(self.tmp / "empty", host="127.0.0.1", port=0,
                                 reply="empty")
        self.assertTrue(other.start()["started"])
        port = other._server.server_address[1]
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(_http_post(_eth_call_body()))
                client.settimeout(5)
                reply = client.recv(65536)
        finally:
            other.stop()

        payload = json.loads(reply.partition(b"\r\n\r\n")[2])
        self.assertEqual(payload["result"], "0x")
        self.assertNotIn("error", payload)

    def test_the_raw_bytes_survive_losslessly(self) -> None:
        # Phase 2 is written against these bytes, so a preview is not enough.
        import base64

        raw = _http_post(_eth_call_body())
        self._send(raw)
        self.responder.stop()

        lines = [json.loads(line) for line in
                 self.responder.requests_path.read_text(encoding="utf-8").splitlines()]
        request = next(entry for entry in lines if entry["kind"] == "request")

        self.assertEqual(base64.b64decode(request["raw_base64"]), raw)

    def test_two_calls_on_one_connection_are_both_recorded(self) -> None:
        # Keep-alive is the default in the reply, so a client that reuses the
        # socket must not have its second request swallowed by the first.
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as client:
            client.settimeout(5)
            client.sendall(_http_post(_eth_call_body()))
            client.recv(65536)
            client.sendall(_http_post(_eth_call_body()))
            client.recv(65536)

        summary = self.responder.report()
        self.assertEqual(summary["requests"], 2)
        self.assertEqual(summary["connections"], 1)

    def test_raw_json_without_http_is_still_captured(self) -> None:
        self._send(_eth_call_body())
        summary = self.responder.report()

        self.assertEqual(summary["outcome"], OUTCOME_ETH_CALL)

    def test_a_handshake_before_the_call_is_visible(self) -> None:
        # C3 predicts this does not happen. The prediction is only falsifiable
        # if the log would show it, so this asserts the instrument, not the
        # sample.
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as client:
            client.settimeout(5)
            handshake = json.dumps({"jsonrpc": "2.0", "id": 0,
                                    "method": "eth_chainId", "params": []}).encode()
            client.sendall(_http_post(handshake))
            client.recv(65536)
            client.sendall(_http_post(_eth_call_body()))
            client.recv(65536)

        summary = self.responder.report()
        self.assertEqual(summary["handshake_methods"], ["eth_chainId"])
        self.assertTrue(summary["handshake_before_target"])

    def test_the_target_call_alone_reports_no_handshake(self) -> None:
        self._send(_http_post(_eth_call_body()))
        summary = self.responder.report()

        self.assertEqual(summary["handshake_methods"], [])
        self.assertFalse(summary["handshake_before_target"])


class OutcomeTests(unittest.TestCase):
    """The five states, which are the reason phase 1 is worth a guest run.

    Each is a different way of learning nothing, and they have different
    causes -- one of them is not about the sample at all.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.responder = JsonRpcResponder(self.tmp, host="127.0.0.1", port=0)
        self.assertTrue(self.responder.start()["started"])
        self.port = self.responder._server.server_address[1]

    def tearDown(self) -> None:
        self.responder.stop()

    def test_nothing_at_all_reads_as_wiring_not_as_the_sample(self) -> None:
        summary = self.responder.report()

        self.assertEqual(summary["outcome"], OUTCOME_NO_CONNECTION)
        self.assertIn("diverter", summary["outcome_note"])

    def test_a_connection_that_says_nothing_is_its_own_state(self) -> None:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5):
            pass
        # The handler notices silence when the peer closes, so give the thread
        # a moment to finish rather than racing it.
        for _ in range(50):
            if self.responder.report()["connections"]:
                break
            import time
            time.sleep(0.02)

        summary = self.responder.report()
        self.assertEqual(summary["outcome"], OUTCOME_CONNECTED_SILENT)
        self.assertEqual(summary["requests"], 0)

    def test_bytes_that_are_not_jsonrpc_are_their_own_state(self) -> None:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as client:
            client.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            client.settimeout(5)
            try:
                client.recv(65536)
            except OSError:
                pass

        summary = self.responder.report()
        self.assertEqual(summary["outcome"], OUTCOME_UNPARSED)
        self.assertEqual(summary["requests"], 1)

    def test_jsonrpc_that_is_not_the_call_is_its_own_state(self) -> None:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as client:
            client.settimeout(5)
            body = json.dumps({"jsonrpc": "2.0", "id": 1,
                               "method": "eth_blockNumber", "params": []}).encode()
            client.sendall(_http_post(body))
            client.recv(65536)

        summary = self.responder.report()
        self.assertEqual(summary["outcome"], OUTCOME_OTHER_RPC)
        self.assertEqual(summary["target_calls"], 0)

    def test_the_summary_is_written_on_stop(self) -> None:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as client:
            client.settimeout(5)
            client.sendall(_http_post(_eth_call_body()))
            client.recv(65536)

        summary = self.responder.stop()
        on_disk = json.loads(self.responder.summary_path.read_text(encoding="utf-8"))

        self.assertEqual(on_disk["outcome"], OUTCOME_ETH_CALL)
        self.assertEqual(on_disk, summary)


class BindingTests(unittest.TestCase):
    def test_a_port_already_held_is_reported_not_raised(self) -> None:
        # FakeNet holding 8545 is the expected way this fails on the guest, and
        # a responder that dies on import would take the whole run with it.
        tmp = Path(tempfile.mkdtemp())
        first = JsonRpcResponder(tmp, host="127.0.0.1", port=0)
        self.assertTrue(first.start()["started"])
        port = first._server.server_address[1]
        try:
            second = JsonRpcResponder(tmp / "second", host="127.0.0.1", port=port)
            result = second.start()

            self.assertFalse(result["started"])
            self.assertIn(str(port), result["error"])
        finally:
            first.stop()


if __name__ == "__main__":
    unittest.main()


#: The first bytes of the ClientHello run `b610dea4` recorded: TLS record type
#: 0x16, version 0x0301, then handshake type 0x01 and TLS 1.2. Taken from the
#: capture rather than composed, because the point is to pin the real shape.
TLS_CLIENT_HELLO = bytes.fromhex("16030101cc010001c80303") + b"\x00" * 64


class ClientSpokeButNotOurProtocol(unittest.TestCase):
    """The case that made `unparsed` unreachable, and cost a detonation's answer.

    On run `b610dea4` the implant opened **TLS** on 8545 -- ClientHello, SNI
    `data-seed-prebsc-1-s1.binance.org`, eleven times, 465 bytes each. The
    handler read them, found them neither HTTP nor JSON, `continue`d to wait for
    more, and the client was waiting for a ServerHello that a plain listener
    cannot send. Nothing was ever recorded and the summary read
    `connected_silent` -- for a client that had spoken every time.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.responder = JsonRpcResponder(self.tmp, host="127.0.0.1", port=0)
        self.assertTrue(self.responder.start()["started"])
        self.port = self.responder._server.server_address[1]

    def tearDown(self) -> None:
        self.responder.stop()

    def _speak_then_wait(self, payload: bytes) -> None:
        """Send, then hold the socket open exactly as a TLS client would."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as client:
            client.sendall(payload)
            client.settimeout(1.0)
            try:
                client.recv(65536)
            except OSError:
                pass

    def test_a_client_that_speaks_and_waits_is_not_recorded_as_silent(self) -> None:
        self.responder.read_timeout = 0.5
        self._speak_then_wait(TLS_CLIENT_HELLO)
        summary = self.responder.stop()

        self.assertNotEqual(summary["outcome"], OUTCOME_CONNECTED_SILENT)
        self.assertEqual(summary["outcome"], OUTCOME_UNPARSED)
        self.assertEqual(summary["requests"], 1)

    def test_the_bytes_survive_so_the_protocol_can_be_identified(self) -> None:
        import base64

        self.responder.read_timeout = 0.5
        self._speak_then_wait(TLS_CLIENT_HELLO)
        self.responder.stop()

        entries = [json.loads(line) for line in
                   self.responder.requests_path.read_text(encoding="utf-8").splitlines()]
        request = next(e for e in entries if e["kind"] == "request")

        self.assertEqual(base64.b64decode(request["raw_base64"]), TLS_CLIENT_HELLO)

    def test_tls_is_named_rather_than_left_as_unparsed(self) -> None:
        # "It sent something we could not parse" and "it tried to negotiate TLS"
        # are different instructions to whoever reads the run.
        self.responder.read_timeout = 0.5
        self._speak_then_wait(TLS_CLIENT_HELLO)
        summary = self.responder.stop()

        self.assertEqual(summary["tls_client_hellos"], 1)
        self.assertIn("TLS", summary["outcome_note"])

    def test_ordinary_binary_is_still_just_unparsed(self) -> None:
        self.responder.read_timeout = 0.5
        self._speak_then_wait(b"\x00\x01\x02\x03not tls at all")
        summary = self.responder.stop()

        self.assertEqual(summary["outcome"], OUTCOME_UNPARSED)
        self.assertEqual(summary["tls_client_hellos"], 0)
        self.assertNotIn("TLS", summary["outcome_note"])

    def test_a_truly_silent_client_still_reads_as_silent(self) -> None:
        # The flush must not turn every connection into a phantom request.
        with socket.create_connection(("127.0.0.1", self.port), timeout=5):
            pass
        for _ in range(50):
            if self.responder.report()["connections"]:
                break
            time.sleep(0.02)
        summary = self.responder.stop()

        self.assertEqual(summary["outcome"], OUTCOME_CONNECTED_SILENT)
        self.assertEqual(summary["requests"], 0)
