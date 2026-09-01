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
from unittest import mock

from dynamic_analysis.jsonrpc_responder import (
    OUTCOME_CONNECTED_SILENT,
    OUTCOME_ETH_CALL,
    RequestRecorder,
)
from scripts.make_fakenet_config import (
    build,
    fakenet_root_from,
    inspect,
    leaf_source,
)
from scripts.make_tls_cert import BACKUP_SUFFIX, LEAF_CERT_NAME

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

    def test_tls_is_terminated_by_default(self) -> None:
        # Measured on run `b610dea4`: the client opens TLS on 8545 and waits for
        # a ServerHello. A plain listener cannot be spoken to at all, so the
        # default has to be the arm that can.
        result = build(self.base, self.out)
        written = Path(str(result["config"])).read_text(encoding="utf-8")

        self.assertIn("UseSSL:      Yes", written)
        self.assertTrue(result["tls"])

    def test_the_plain_arm_is_still_reachable_for_an_ab(self) -> None:
        result = build(self.base, self.out / "plain", tls=False)
        written = Path(str(result["config"])).read_text(encoding="utf-8")

        self.assertIn("UseSSL:      No", written)
        self.assertFalse(result["tls"])

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


class TlsChangesWhatSilenceMeans(unittest.TestCase):
    """`no_connection` has two causes once TLS is on, and they need opposite fixes.

    FakeNet wraps the *listening* socket for `UseSSL: Yes`, so a handshake the
    client refuses fails inside `accept()` and never reaches the handler. The run
    then records nothing -- exactly as if the diverter had not routed the port.
    The summary has to say which world it is in, because the reader cannot tell.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())

    def test_plain_mode_blames_the_diverter(self) -> None:
        report = RequestRecorder(self.tmp).report()

        self.assertEqual(report["outcome"], "no_connection")
        self.assertFalse(report["tls_expected"])
        self.assertIn("diverter", report["outcome_note"])

    def test_tls_mode_names_the_handshake_as_the_other_candidate(self) -> None:
        report = RequestRecorder(self.tmp, tls_expected=True).report()

        self.assertEqual(report["outcome"], "no_connection")
        self.assertTrue(report["tls_expected"])
        self.assertIn("handshake", report["outcome_note"])
        # And it says where to look, because neither answer is in this file.
        self.assertIn("pcap", report["outcome_note"])

    def test_the_flag_does_not_leak_into_a_run_that_saw_traffic(self) -> None:
        # It only reinterprets silence. A run with requests is unaffected.
        recorder = RequestRecorder(self.tmp, tls_expected=True)
        recorder.note_request("p:1", _eth_call_request())
        report = recorder.report()

        self.assertEqual(report["outcome"], OUTCOME_ETH_CALL)
        self.assertNotIn("handshake", report["outcome_note"])


class WhichCertificateIsActuallyServed(unittest.TestCase):
    """The script used to assert "cert is FakeNet's own" without looking.

    That line is read at one moment only: when someone is deciding whether a
    `no_connection` summary means the port was never routed or the client
    refused the certificate. A confident wrong answer there costs an hour and
    can cost a detonation, because the two look identical from the summary and
    are separated only by the pcap.

    The marker is the backup `install` leaves behind. `restore` removes it; a
    hand-copy does not, which is why the bytes are compared as well.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.ssl_utils = self.tmp / "listeners" / "ssl_utils"
        self.ssl_utils.mkdir(parents=True)
        (self.ssl_utils / LEAF_CERT_NAME).write_text("STOCK", encoding="ascii")

    @property
    def _backup(self) -> Path:
        return self.ssl_utils / (LEAF_CERT_NAME + BACKUP_SUFFIX)

    def test_a_stock_install_reports_fakenets_own(self) -> None:
        source, _ = leaf_source(self.tmp)

        self.assertEqual(source, "fakenet")

    def test_a_swapped_leaf_is_recognised(self) -> None:
        self._backup.write_text("STOCK", encoding="ascii")
        (self.ssl_utils / LEAF_CERT_NAME).write_text("RINGFORGE", encoding="ascii")

        source, _ = leaf_source(self.tmp)

        self.assertEqual(source, "ringforge")

    def test_a_backup_whose_bytes_match_the_leaf_means_the_swap_was_undone(self) -> None:
        # Copying the backup back by hand leaves the marker in place. The
        # marker then claims a swap and the served bytes deny it; the bytes win.
        self._backup.write_text("STOCK", encoding="ascii")

        source, detail = leaf_source(self.tmp)

        self.assertEqual(source, "fakenet")
        self.assertIn("by hand", detail)

    def test_no_install_is_reported_as_unknown_rather_than_guessed(self) -> None:
        source, _ = leaf_source(None)

        self.assertEqual(source, "unknown")

    def test_a_directory_that_is_not_a_fakenet_install_is_unknown(self) -> None:
        source, _ = leaf_source(Path(tempfile.mkdtemp()))

        self.assertEqual(source, "unknown")

    def test_a_missing_leaf_is_unknown_rather_than_fakenets_own(self) -> None:
        # An install with no server.pem serves nothing, and calling that
        # "FakeNet's own" would be the same class of confident wrong answer
        # this replaces.
        (self.ssl_utils / LEAF_CERT_NAME).unlink()

        source, _ = leaf_source(self.tmp)

        self.assertEqual(source, "unknown")


class FindingTheInstallTheConfigBelongsTo(unittest.TestCase):
    """`leaf_source` can only answer about an install it was handed.

    If this returns `None` on the guest, every report reads UNKNOWN -- honest,
    and useless, and the kind of degradation nobody notices because it never
    errors. `--fakenet-config` is routinely pointed at `configs/default.ini`
    inside the install, so the walk up from the config is the path that
    actually gets used.

    These passed on the host and failed in the guest, 01 Sep, and the
    difference was the environment rather than the code. `fakenet_root_from`
    tries the *located binary* before the config's own ancestors, deliberately:
    the question it answers is which install will serve this config, and that
    is whichever FakeNet runs. The host has no FakeNet, so the walk-up won by
    default and the assertions passed for a reason unrelated to what they
    claimed to test. The guest has one at `tools\\fakenet`, so it answered
    first and correctly, and the tests called it a failure.

    `find_fakenet` is patched now. A test whose result depends on what is
    installed on the machine running it is not testing the function.
    """

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp()) / "fakenet"
        (self.root / "listeners" / "ssl_utils").mkdir(parents=True)
        (self.root / "configs").mkdir()
        self.config = self.root / "configs" / "default.ini"
        self.config.write_text("[Diverter]\n", encoding="ascii")

    def test_it_walks_up_from_a_config_inside_the_install(self) -> None:
        with mock.patch("scripts.make_fakenet_config.find_fakenet", return_value=None):
            self.assertEqual(fakenet_root_from(self.config), self.root)

    def test_a_config_in_the_install_root_is_found_too(self) -> None:
        loose = self.root / "default.ini"
        loose.write_text("[Diverter]\n", encoding="ascii")

        with mock.patch("scripts.make_fakenet_config.find_fakenet", return_value=None):
            self.assertEqual(fakenet_root_from(loose), self.root)

    def test_a_config_nowhere_near_an_install_gives_none(self) -> None:
        stray = Path(tempfile.mkdtemp()) / "default.ini"
        stray.write_text("[Diverter]\n", encoding="ascii")

        # With the locator pinned, this is an assertion about the walk-up
        # rather than about the bench. It used to accept `None` *or* a real
        # install, which is what an untestable environment dependency looks
        # like once it has been worked around instead of removed.
        with mock.patch("scripts.make_fakenet_config.find_fakenet", return_value=None):
            self.assertIsNone(fakenet_root_from(stray))

    def test_the_located_binary_answers_before_the_config_s_own_install(self) -> None:
        """The precedence the docstring claims, which nothing pinned.

        On a host with no FakeNet this branch never ran, so the ordering was
        asserted only in prose -- and prose is what the guest disagreed with.
        """
        other = Path(tempfile.mkdtemp()) / "fakenet"
        (other / "listeners" / "ssl_utils").mkdir(parents=True)

        with mock.patch("scripts.make_fakenet_config.find_fakenet",
                        return_value=other / "fakenet.exe"):
            self.assertEqual(fakenet_root_from(self.config), other)

