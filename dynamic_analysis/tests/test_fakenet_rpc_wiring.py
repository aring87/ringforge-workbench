"""The 8545 wiring for `0bw` phase 1: config generation and the FakeNet handler.

Two things are being protected here.

The generated config must add a listener **without disturbing anything else**.
FakeNet's stock config is mostly comments explaining containment-relevant
switches, and it is the one file on the bench where a silent reformat could mean
traffic leaving the guest. So the base text is asserted to survive byte for byte.

The handler must behave identically to the standalone responder, because they
share a `RequestRecorder` and the whole point of that split is one answer to
"what did the implant ask". A handler that diverged would make the two wirings
produce different verdicts from the same request.
"""

import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from dynamic_analysis.jsonrpc_responder import (
    OUTCOME_CONNECTED_SILENT,
    OUTCOME_ETH_CALL,
    RequestRecorder,
)
from scripts.make_fakenet_config import build, inspect

#: A stand-in for FakeNet's default.ini. Deliberately carries comments and
#: mixed-case option names -- the two things a configparser round-trip destroys.
STOCK_CONFIG = """[FakeNet]
DivertTraffic:  Yes

[Diverter]
# Enable 'RedirectAllTraffic' to divert traffic to unlisted ports.
RedirectAllTraffic:    Yes
DefaultTCPListener:    ProxyTCPListener
BlackListPortsTCP: 139

[RawTCPListener]
Enabled:     True
Port:        1337
Protocol:    TCP
Listener:    RawListener
"""


def _eth_call_request() -> bytes:
    body = json.dumps({
        "jsonrpc": "2.0", "id": 7, "method": "eth_call",
        "params": [{"to": "0x0F14fc3bfAc3726172aCd08Fe4bFb79B633E76ff",
                    "data": "0x3bc5de30"}, "latest"],
    }).encode()
    return (
        b"POST / HTTP/1.1\r\nHost: data-seed-prebsc-1-s1.binance.org:8545\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )


class ConfigGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.base = self.tmp / "default.ini"
        self.base.write_text(STOCK_CONFIG, encoding="utf-8")
        self.out = self.tmp / "generated"

    def test_the_base_config_survives_byte_for_byte(self) -> None:
        # The whole reason this appends text instead of using configparser.
        result = build(self.base, self.out)
        written = Path(str(result["config"])).read_text(encoding="utf-8")

        self.assertTrue(written.startswith(STOCK_CONFIG.rstrip("\n")))
        self.assertIn("# Enable 'RedirectAllTraffic'", written)
        self.assertIn("DefaultTCPListener:    ProxyTCPListener", written)

    def test_the_listener_section_is_added(self) -> None:
        result = build(self.base, self.out)
        written = Path(str(result["config"])).read_text(encoding="utf-8")

        self.assertIn("[EtherHidingRPC]", written)
        self.assertIn("Port:        8545", written)
        self.assertIn("Listener:    RawListener", written)
        self.assertIn("Custom:      etherhiding_response.ini", written)

    def test_both_support_files_land_beside_the_config(self) -> None:
        # FakeNet resolves Custom and TcpDynamic relative to the config's own
        # directory, so this is not tidiness -- it is the mechanism.
        result = build(self.base, self.out)
        config_dir = Path(str(result["config"])).parent

        self.assertTrue((config_dir / "etherhiding_response.ini").is_file())
        self.assertTrue((config_dir / "etherhiding_rpc.py").is_file())

    def test_the_response_config_names_the_listener_instance(self) -> None:
        build(self.base, self.out)
        text = (self.out / "etherhiding_response.ini").read_text(encoding="utf-8")

        self.assertIn("InstanceName: EtherHidingRPC", text)
        self.assertIn("TcpDynamic:   etherhiding_rpc.py", text)

    def test_a_clean_config_reports_no_problems(self) -> None:
        findings = inspect(STOCK_CONFIG)

        self.assertEqual(findings["redirect_all_traffic"], "Yes")
        self.assertFalse(findings["port_blacklisted"])
        self.assertEqual(findings["port_already_used_by"], "")

    def test_a_blacklisted_port_is_noticed(self) -> None:
        # This would route nothing, and the summary would read no_connection --
        # which is indistinguishable from the sample never asking unless the
        # generator says so up front.
        findings = inspect(STOCK_CONFIG.replace("BlackListPortsTCP: 139",
                                                "BlackListPortsTCP: 139, 8545"))

        self.assertTrue(findings["port_blacklisted"])

    def test_a_port_already_taken_is_noticed(self) -> None:
        findings = inspect(STOCK_CONFIG.replace("Port:        1337",
                                                "Port:        8545"))

        self.assertEqual(findings["port_already_used_by"], "RawTCPListener")

    def test_redirect_all_traffic_switched_off_is_noticed(self) -> None:
        findings = inspect(STOCK_CONFIG.replace("RedirectAllTraffic:    Yes",
                                                "RedirectAllTraffic:    No"))

        self.assertEqual(findings["redirect_all_traffic"], "No")

    def test_an_unreadable_base_does_not_raise(self) -> None:
        findings = inspect("[unclosed\nnonsense")

        self.assertFalse(findings["readable"])


class HandlerTests(unittest.TestCase):
    """`HandleTcp` driven over a real socket pair, as FakeNet would call it."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        os.environ["RINGFORGE_RPC_OUTPUT_DIR"] = str(self.tmp)
        os.environ["RINGFORGE_REPO_ROOT"] = str(
            Path(__file__).resolve().parent.parent.parent)
        # Loaded the way FakeNet loads it -- by path, not as a package import --
        # so the test exercises the same entry point the bench will.
        import importlib.util

        path = (Path(__file__).resolve().parent.parent
                / "fakenet_custom" / "etherhiding_rpc.py")
        spec = importlib.util.spec_from_file_location("cr_raw_test", path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def tearDown(self) -> None:
        os.environ.pop("RINGFORGE_RPC_OUTPUT_DIR", None)
        os.environ.pop("RINGFORGE_REPO_ROOT", None)

    def _drive(self, payload: bytes, read: bool = True) -> bytes:
        """Hand the handler one side of a socket pair, as FakeNet does."""
        server, client = socket.socketpair()
        reply = b""
        thread = threading.Thread(target=self.module.HandleTcp, args=(server,))
        thread.start()
        try:
            if payload:
                client.sendall(payload)
            if read and payload:
                client.settimeout(5)
                reply = client.recv(65536)
            client.close()
        finally:
            thread.join(timeout=10)
            server.close()
        return reply

    def test_the_recorder_was_importable(self) -> None:
        # If this fails every other assertion here is meaningless, and on the
        # bench it is the difference between "handler broken" and "implant
        # silent" -- which is the distinction phase 1 exists to preserve.
        self.assertIsNotNone(self.module._RECORDER, self.module._IMPORT_ERROR)

    def test_the_target_call_is_recorded_and_answered(self) -> None:
        reply = self._drive(_eth_call_request())

        self.assertIn(b"200 OK", reply)
        payload = json.loads(reply.partition(b"\r\n\r\n")[2])
        self.assertEqual(payload["id"], 7)
        self.assertIn("error", payload)

    def test_the_summary_is_written_without_a_teardown_callback(self) -> None:
        # FakeNet is stopped with CTRL_BREAK and never calls back into this
        # module, so a summary deferred to shutdown would never be written.
        self._drive(_eth_call_request())
        summary = json.loads((self.tmp / "jsonrpc_summary.json").read_text(encoding="utf-8"))

        self.assertEqual(summary["outcome"], OUTCOME_ETH_CALL)
        self.assertEqual(summary["target_calls"], 1)

    def test_the_wire_bytes_are_kept_not_reconstructed(self) -> None:
        # The reason TcpDynamic was chosen over HttpDynamic: phase 2 is encoded
        # against these bytes, so they must be what actually arrived.
        import base64

        raw = _eth_call_request()
        self._drive(raw)
        lines = [json.loads(line) for line in
                 (self.tmp / "jsonrpc_requests.jsonl").read_text(encoding="utf-8").splitlines()]
        request = next(entry for entry in lines if entry["kind"] == "request")

        self.assertEqual(base64.b64decode(request["raw_base64"]), raw)
        self.assertEqual(request["raw_source"], "wire")

    def test_a_connection_that_says_nothing_is_still_recorded(self) -> None:
        self._drive(b"", read=False)
        summary = json.loads((self.tmp / "jsonrpc_summary.json").read_text(encoding="utf-8"))

        self.assertEqual(summary["outcome"], OUTCOME_CONNECTED_SILENT)

    def test_a_failed_import_still_answers_and_leaves_evidence(self) -> None:
        # A bench problem must not turn into a different experiment: the implant
        # is told the same thing either way, and the log says which happened.
        broken = self.tmp / "broken"
        broken.mkdir()
        saved = self.module._RECORDER
        self.module._RECORDER = None
        self.module._IMPORT_ERROR = "simulated"
        os.environ["RINGFORGE_RPC_OUTPUT_DIR"] = str(broken)
        try:
            reply = self._drive(_eth_call_request())
        finally:
            self.module._RECORDER = saved
            os.environ["RINGFORGE_RPC_OUTPUT_DIR"] = str(self.tmp)

        self.assertIn(b"execution reverted", reply)
        lines = (broken / "jsonrpc_requests.jsonl").read_text(encoding="utf-8")
        self.assertIn("handler_import_failed", lines)

    def test_the_fallback_reply_matches_the_recorders_own(self) -> None:
        # Same shape either way, so a failed import changes what is recorded
        # and never what the implant is told.
        recorder = RequestRecorder(self.tmp / "shape")
        record = recorder.note_request("x:1", _eth_call_request())
        real = json.loads(recorder.response_bytes(record).partition(b"\r\n\r\n")[2])
        fallback = json.loads(self.module._fallback_reply().partition(b"\r\n\r\n")[2])

        self.assertEqual(real["error"], fallback["error"])


if __name__ == "__main__":
    unittest.main()
