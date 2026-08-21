"""A recording JSON-RPC responder -- phase 1 of the EtherHiding lever (`0bw`).

Run `c14cb5b6`'s payload reads its C2 address from a smart contract, and
containment is what stopped it: FakeNet hands this class of malware a TCP peer,
not a JSON-RPC response, so the implant asked `getData()`, got nothing usable,
and exited at t198. Everything downstream of that fetch -- the substitution
logic, the beacon protocol, the clipboard hook -- has never run.

**This module does not answer the question. It records it.** That split is the
whole design, and the reason is a failure mode rather than caution:
`getData()`'s return encoding is nowhere in the binary. What exists is the
implant's *parser*, and nothing has read its expectations. An answer encoded
against a guess and a responder that never received a byte produce **the same
observable** -- the implant exits at t198, which is what it already does. One of
those is a result and the other is a broken bench, and a run that cannot tell
them apart is not worth the guest time.

So phase 1 replies with a well-formed JSON-RPC error and writes down exactly
what was asked: the method, the params, the block tag, whether a handshake came
first, and the raw bytes underneath all of it. Phase 2 encodes an answer against
a request that has been read rather than assumed.

**What this must never do is hand the implant a live address.** The point of a
responder is that the operator chooses the C2; phase 2 serves a sink under the
operator's control, and phase 1 serves no address at all.

**Routing is the one thing this module cannot verify about itself.** It binds a
port and records what arrives. Whether the guest's diverter actually delivers
`data-seed-prebsc-1-s1.binance.org:8545` here is an operational question that
prediction C1 exists to answer, and a summary reading `no_connection` is a
statement about the wiring, not about the sample. See `report()`.
"""

from __future__ import annotations

import base64
import json
import socket
import socketserver
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

#: The contract `c14cb5b6`'s payload reads, lowercased for comparison because
#: JSON-RPC callers mix EIP-55 checksum case with plain hex freely.
ETHERHIDING_CONTRACT = "0x0f14fc3bfac3726172acd08fe4bfb79b633e76ff"

#: `getData()`. The first four bytes of the `eth_call` data field.
GETDATA_SELECTOR = "0x3bc5de30"

#: BSC testnet's JSON-RPC port, and what the implant connects to.
DEFAULT_PORT = 8545

#: Methods a client sends to orient itself before doing anything interesting.
#: Tracked separately so prediction C3 -- that no handshake precedes the
#: `eth_call` -- is answered by the log rather than by reading it back.
HANDSHAKE_METHODS = {
    "eth_chainid", "net_version", "web3_clientversion", "eth_blocknumber",
    "eth_gasprice", "net_listening",
}

#: How the run is classified. **Silence must be distinguishable from absence**:
#: four of these five are ways of receiving nothing useful, and they have
#: entirely different causes. Collapsing them into "no result" is what makes a
#: negative unreadable.
OUTCOME_NO_CONNECTION = "no_connection"          # wiring, not the sample
OUTCOME_CONNECTED_SILENT = "connected_silent"    # TCP accepted, no bytes sent
OUTCOME_UNPARSED = "unparsed"                    # bytes arrived, not JSON-RPC
OUTCOME_OTHER_RPC = "other_rpc"                  # JSON-RPC, but not the call
OUTCOME_ETH_CALL = "eth_call"                    # the request we came for

#: Cap on a single recorded request. A responder is not a place to buffer
#: something unbounded, and nothing this implant sends is large.
MAX_REQUEST_BYTES = 256 * 1024

#: Enough of the body to read at a glance without decoding the base64.
_PREVIEW_CHARS = 512


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def looks_like_tls(raw: bytes) -> bool:
    """A TLS record header: handshake type, then a plausible protocol version.

    Worth naming rather than leaving as "unparsed bytes". Run `b610dea4` showed
    the implant opening **TLS** on 8545 -- ClientHello, SNI
    `data-seed-prebsc-1-s1.binance.org`, eleven times -- so a plain listener can
    never be spoken to, and "it sent something we could not parse" and "it tried
    to negotiate TLS" are very different instructions to whoever reads the run.
    """
    return (
        len(raw) >= 3
        and raw[0] == 0x16                      # handshake record
        and raw[1] == 0x03 and raw[2] <= 0x04   # SSL 3.0 .. TLS 1.3
    )


def _printable(raw: bytes, limit: int = _PREVIEW_CHARS) -> str:
    """A lossy preview for reading. `raw_base64` is the lossless copy."""
    text = raw[:limit].decode("utf-8", errors="replace")
    return "".join(char if char.isprintable() or char in "\r\n\t" else "." for char in text)


def _parse_http(raw: bytes) -> dict[str, Any]:
    """Split an HTTP request into a start line, headers and a body.

    Best-effort by design: a request that is not HTTP at all still has to be
    recorded, because "the implant spoke raw JSON over the socket" is itself an
    answer to phase 1's question.
    """
    result: dict[str, Any] = {"is_http": False, "method": "", "path": "",
                              "headers": {}, "body": b""}
    separator = raw.find(b"\r\n\r\n")
    gap = 4
    if separator < 0:
        separator = raw.find(b"\n\n")
        gap = 2
    if separator < 0:
        result["body"] = raw
        return result

    head = raw[:separator].decode("latin-1", errors="replace")
    result["body"] = raw[separator + gap:]

    lines = head.replace("\r\n", "\n").split("\n")
    if not lines:
        return result

    parts = lines[0].split()
    if len(parts) >= 3 and parts[2].upper().startswith("HTTP/"):
        result["is_http"] = True
        result["method"] = parts[0]
        result["path"] = parts[1]

    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            result["headers"][key.strip().lower()] = value.strip()
    return result


def _parse_jsonrpc(body: bytes) -> dict[str, Any]:
    """Pull the fields phase 1 exists to learn.

    A batch request is a JSON array, which is legal and which this implant may
    or may not use; both shapes are flattened into a list of calls so the caller
    does not have to care which arrived.
    """
    result: dict[str, Any] = {"is_jsonrpc": False, "calls": [], "parse_error": ""}
    if not body.strip():
        return result
    try:
        document = json.loads(body.decode("utf-8", errors="strict"))
    except Exception as error:
        result["parse_error"] = str(error)
        return result

    entries = document if isinstance(document, list) else [document]
    for entry in entries:
        if not isinstance(entry, dict) or "method" not in entry:
            continue
        call: dict[str, Any] = {
            "method": str(entry.get("method", "")),
            "id": entry.get("id"),
            "params": entry.get("params"),
            "to": "",
            "data": "",
            "selector": "",
            "block": "",
        }
        params = entry.get("params")
        if isinstance(params, list) and params:
            # `eth_call` is [{to, data, ...}, blockTag]. Read defensively: the
            # shape is a convention of the caller's library, not a guarantee.
            first = params[0]
            if isinstance(first, dict):
                call["to"] = str(first.get("to", "") or "")
                call["data"] = str(first.get("data", first.get("input", "")) or "")
                if call["data"].startswith("0x") and len(call["data"]) >= 10:
                    call["selector"] = call["data"][:10].lower()
            if len(params) > 1 and isinstance(params[1], str):
                call["block"] = params[1]
        result["calls"].append(call)

    result["is_jsonrpc"] = bool(result["calls"])
    return result


def _is_target_call(call: dict[str, Any]) -> bool:
    """An `eth_call` naming the contract, the selector, or both.

    Deliberately an OR rather than an AND. A campaign that rotates its contract
    still calls `getData()`, and a variant that renames the getter still reads
    the same address; requiring both would miss the case this is most likely to
    be re-run against.
    """
    if str(call.get("method", "")).lower() != "eth_call":
        return False
    to = str(call.get("to", "") or "").lower()
    selector = str(call.get("selector", "") or "").lower()
    return to == ETHERHIDING_CONTRACT or selector == GETDATA_SELECTOR


def _handshake_first(records: list[dict[str, Any]]) -> bool:
    """True when a handshake method was seen before the first target call."""
    for record in records:
        if record.get("is_target_call"):
            return False
        for method in record.get("methods", []):
            if method.lower() in HANDSHAKE_METHODS:
                return True
    return False


class _Handler(socketserver.BaseRequestHandler):
    """One connection. Records it even if it never says anything."""

    def handle(self) -> None:
        responder: JsonRpcResponder = self.server.responder  # type: ignore[attr-defined]
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        responder.recorder.note_connection(peer)

        self.request.settimeout(responder.read_timeout)
        buffer = b""
        spoke = False

        while not responder._stopping.is_set():
            try:
                chunk = self.request.recv(65536)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break

            spoke = True
            buffer += chunk
            if len(buffer) > MAX_REQUEST_BYTES:
                responder.recorder.note_request(peer, buffer[:MAX_REQUEST_BYTES], truncated=True)
                break

            # A request is complete once the headers are in and the body has
            # reached Content-Length. Anything that is not HTTP is treated as
            # complete as soon as it parses -- waiting for a header that will
            # never come is how a recorder loses the one message it exists for.
            parsed = _parse_http(buffer)
            if parsed["is_http"]:
                declared = parsed["headers"].get("content-length")
                try:
                    expected = int(declared) if declared is not None else 0
                except ValueError:
                    expected = 0
                if len(parsed["body"]) < expected:
                    continue
            elif not _parse_jsonrpc(buffer)["is_jsonrpc"]:
                continue

            record = responder.recorder.note_request(peer, buffer)
            try:
                self.request.sendall(responder.recorder.response_bytes(record))
            except OSError:
                break
            buffer = b""

        # **Whatever is still buffered when the loop ends is still what the
        # client said.** The completeness check above `continue`s on anything
        # that is neither HTTP nor parseable JSON, waiting for more -- and a
        # client waiting on *us* never sends more. Run `b610dea4` lost eleven
        # TLS ClientHellos exactly here and reported `connected_silent` for a
        # client that had spoken 465 bytes, which made the `unparsed` outcome
        # unreachable for the one case that actually occurred.
        if buffer:
            responder.recorder.note_request(peer, buffer)

        if not spoke:
            responder.recorder.note_silent(peer)


class _Server(socketserver.ThreadingTCPServer):
    #: **Never `SO_REUSEADDR` here**, which is what `allow_reuse_address` sets
    #: and what almost every socketserver example turns on. On Windows that flag
    #: does not mean what it means on Unix: it lets a second socket bind a port
    #: another process is already using. A responder started while FakeNet holds
    #: 8545 would report `started: True`, receive nothing, and the summary would
    #: read `no_connection` -- blaming the diverter for a port collision. That is
    #: exactly the ambiguous result this phase exists to make impossible, so the
    #: bind is made exclusive instead and a taken port is an error at start.
    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self) -> None:
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive is not None:
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)
            except OSError:
                # Not fatal: without it the bind is merely non-exclusive, and
                # the caller still learns the port was taken in the common case.
                pass
        super().server_bind()


class RequestRecorder:
    """Recording, classification and the useless answer -- with no socket.

    Split out from `JsonRpcResponder` because there are two ways bytes reach
    this code and only one of them owns a listening port. Under FakeNet the
    diverter owns the socket and hands it to a `HandleTcp` callback, so the
    server half is not merely unnecessary there, it is unavailable. Everything
    that decides what a run *means* lives here, once, and is tested once.
    """

    def __init__(
        self,
        output_dir: str | Path,
        reply: str = "error",
        planner: Any = None,
        tls_expected: bool = False,
    ):
        self.output_dir = Path(output_dir)
        # **Changes what `no_connection` means, so it has to be recorded.**
        # FakeNet wraps the *listening* socket when `UseSSL: Yes`, so a
        # handshake the client rejects fails in `accept()` and never reaches
        # this code at all. The run then looks identical to one where the
        # diverter never routed the port -- and those call for opposite fixes.
        self.tls_expected = bool(tls_expected)
        # Phase 2. When present, a *target* call is answered with an encoded
        # `getData()` result instead of the refusal; everything else still gets
        # the refusal, because a run that answers questions nobody asked about
        # the contract is a run whose log cannot be read straight.
        self.planner = planner
        # `error` is phase 1's default: a well-formed JSON-RPC error, which is
        # what a node returns when a call cannot be executed. `empty` returns a
        # successful `0x`, which is what a node returns for a contract with no
        # code -- the truthful answer for this dead contract, and a different
        # path through the implant's parser. Which one it is matters to C4, so
        # it is a knob rather than a constant.
        self.reply = reply if reply in ("error", "empty") else "error"

        self.requests_path = self.output_dir / "jsonrpc_requests.jsonl"
        self.summary_path = self.output_dir / "jsonrpc_summary.json"

        self._lock = threading.Lock()
        self._connections: list[dict[str, Any]] = []
        self._records: list[dict[str, Any]] = []

    # -- recording ---------------------------------------------------------

    def _append(self, entry: dict[str, Any]) -> None:
        """Write through immediately.

        A detonation can end by killing the whole box, so a record that exists
        only in memory is one that may not survive the run that produced it.
        """
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            with self.requests_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
                handle.flush()
        except Exception:
            # Losing the file must not cost the in-memory summary as well.
            pass

    def note_connection(self, peer: str) -> None:
        entry = {"kind": "connection", "time": _now(), "peer": peer}
        with self._lock:
            self._connections.append(entry)
        self._append(entry)

    def note_silent(self, peer: str) -> None:
        self._append({"kind": "connection_closed_silent", "time": _now(), "peer": peer})

    def note_request(
        self,
        peer: str,
        raw: bytes,
        truncated: bool = False,
        raw_source: str = "wire",
    ) -> dict[str, Any]:
        """Record one request.

        `raw_source` is `wire` when these are the bytes as they arrived, and
        `reconstructed` when they were rebuilt from an already-parsed request.
        Phase 2 is written against `raw_base64`, so which one it is has to be
        on the record rather than inferred from how the run was wired.
        """
        http = _parse_http(raw)
        rpc = _parse_jsonrpc(http["body"] if http["is_http"] else raw)

        entry: dict[str, Any] = {
            "kind": "request",
            "time": _now(),
            "peer": peer,
            "bytes": len(raw),
            "truncated": truncated,
            "raw_source": raw_source,
            "raw_base64": base64.b64encode(raw).decode("ascii"),
            "preview": _printable(raw),
            "is_http": http["is_http"],
            "http_method": http["method"],
            "http_path": http["path"],
            "content_type": http["headers"].get("content-type", ""),
            "host_header": http["headers"].get("host", ""),
            "is_jsonrpc": rpc["is_jsonrpc"],
            "is_tls": looks_like_tls(raw),
            "parse_error": rpc["parse_error"],
            "calls": rpc["calls"],
        }
        entry["methods"] = [call["method"] for call in rpc["calls"]]
        entry["is_target_call"] = any(_is_target_call(call) for call in rpc["calls"])

        with self._lock:
            self._records.append(entry)
        self._append(entry)
        return entry

    # -- answering ---------------------------------------------------------

    def response_payload(self, record: dict[str, Any]) -> dict[str, Any]:
        calls = record.get("calls") or []
        identifier = calls[0].get("id") if calls else None

        if self.planner is not None and record.get("is_target_call"):
            answer = self.planner.answer()
            # Stamped onto the record, not just returned. Which hypothesis was
            # served to which call is the entire result of a phase 2 run, and it
            # has to survive in the log rather than be reconstructed from the
            # order of a list afterwards.
            record["served_plan"] = answer["plan"]
            record["served_attempt"] = answer["attempt"]
            record["served_result"] = answer["result"]
            self._rewrite_last(record)
            return {"jsonrpc": "2.0", "id": identifier, "result": answer["result"]}

        if self.reply == "empty":
            return {"jsonrpc": "2.0", "id": identifier, "result": "0x"}
        return {
            "jsonrpc": "2.0",
            "id": identifier,
            "error": {"code": -32000, "message": "execution reverted"},
        }

    def _rewrite_last(self, record: dict[str, Any]) -> None:
        """Append the record again once the answer is known.

        The request is written the moment it arrives, because a detonation can
        end by killing the box and a record held for later is a record that may
        never exist. The answer is only decided afterwards, so it is appended as
        a second line rather than by rewriting the first -- an append-only log
        cannot lose the earlier entry if the run dies between the two.
        """
        entry = dict(record)
        entry["kind"] = "request_answered"
        self._append(entry)

    def response_bytes(self, record: dict[str, Any]) -> bytes:
        body = json.dumps(self.response_payload(record)).encode("utf-8")
        head = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        ).encode("ascii")
        return head + body

    # -- reading -----------------------------------------------------------

    def report(self, listening: str = "", error: str = "") -> dict[str, Any]:
        """The run's classification, and the evidence for it.

        `outcome` is the field to read first, and `no_connection` is a statement
        about the diverter rather than about the sample -- prediction C1 is what
        separates those, and nothing below it may be written up without it.
        """
        with self._lock:
            connections = list(self._connections)
            records = list(self._records)

        methods: dict[str, int] = {}
        for record in records:
            for method in record.get("methods", []):
                methods[method] = methods.get(method, 0) + 1

        target = [r for r in records if r.get("is_target_call")]
        jsonrpc = [r for r in records if r.get("is_jsonrpc")]

        tls = [r for r in records if r.get("is_tls")]

        if target:
            outcome = OUTCOME_ETH_CALL
        elif jsonrpc:
            outcome = OUTCOME_OTHER_RPC
        elif records:
            outcome = OUTCOME_UNPARSED
        elif connections:
            outcome = OUTCOME_CONNECTED_SILENT
        else:
            outcome = OUTCOME_NO_CONNECTION

        return {
            "listening": listening,
            "reply": self.reply,
            "error": error,
            "outcome": outcome,
            "outcome_note": (
                "Nothing reached this handler, and TLS termination is on -- so "
                "a handshake the client refused would look exactly like this, "
                "because FakeNet wraps the listening socket and a failed "
                "handshake never reaches the handler. Read fakenet.log and the "
                "pcap for a TLS alert before blaming the diverter."
                if outcome == OUTCOME_NO_CONNECTION and self.tls_expected
                else "TLS was offered, not JSON-RPC. The client sent a ClientHello "
                "and waited for a ServerHello this listener cannot give it, so "
                "nothing above the handshake was ever spoken. Terminate TLS "
                "before expecting a request."
                if outcome == OUTCOME_UNPARSED and tls
                else OUTCOME_NOTES[outcome]
            ),
            "connections": len(connections),
            "requests": len(records),
            "jsonrpc_requests": len(jsonrpc),
            "target_calls": len(target),
            "methods": methods,
            # C3: whether anything oriented itself before asking. An empty list
            # with a target call present is C3 holding.
            # Counted separately because it is not a parse failure, it is a
            # different protocol. A run with these and no requests needs TLS
            # termination, not a better parser.
            "tls_client_hellos": sum(1 for r in records if r.get("is_tls")),
            "tls_expected": self.tls_expected,
            "handshake_methods": [m for m in methods if m.lower() in HANDSHAKE_METHODS],
            "handshake_before_target": _handshake_first(records),
            "contract": ETHERHIDING_CONTRACT,
            "selector": GETDATA_SELECTOR,
            "first_seen": records[0]["time"] if records else "",
            "last_seen": records[-1]["time"] if records else "",
            "requests_path": str(self.requests_path),
            # Absent in phase 1, which is the point: a summary carrying no
            # `answer` block is a run that told the implant nothing.
            "answer": self.planner.report() if self.planner is not None else {},
        }

    def write_summary(self, listening: str = "", error: str = "") -> dict[str, Any]:
        summary = self.report(listening=listening, error=error)
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self.summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        except Exception:
            pass
        return summary


class JsonRpcResponder:
    """Binds a port, records what is asked, answers without answering.

    Held as an object because the caller keeps it running across the sample
    detonation, the same shape as `PacketCapture` and `FakeNetSession`. Used
    when nothing else owns the socket; under FakeNet the handler in
    `fakenet_custom` drives the same `RequestRecorder` instead.
    """

    def __init__(
        self,
        output_dir: str | Path,
        host: str = "0.0.0.0",
        port: int = DEFAULT_PORT,
        reply: str = "error",
        read_timeout: float = 15.0,
        planner: Any = None,
    ):
        self.output_dir = Path(output_dir)
        self.host = host
        self.port = int(port)
        self.read_timeout = float(read_timeout)

        self.recorder = RequestRecorder(output_dir, reply, planner=planner)
        self.requests_path = self.recorder.requests_path
        self.summary_path = self.recorder.summary_path

        self.started = False
        self.error = ""
        self._server: Optional[_Server] = None
        self._thread: Optional[threading.Thread] = None
        self._stopping = threading.Event()

    @property
    def reply(self) -> str:
        return self.recorder.reply

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> dict[str, Any]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        try:
            self._server = _Server((self.host, self.port), _Handler)
        except OSError as error:
            # The commonest cause is FakeNet already holding the port, and that
            # is worth saying plainly rather than as an errno.
            self.error = f"could not bind {self.host}:{self.port}: {error}"
            return {"started": False, "error": self.error,
                    "host": self.host, "port": self.port}

        self._server.responder = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="jsonrpc-responder", daemon=True
        )
        self._thread.start()
        self.started = True
        return {"started": True, "host": self.host, "port": self.port,
                "reply": self.reply, "requests_path": str(self.requests_path)}

    def stop(self) -> dict[str, Any]:
        self._stopping.set()
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.started = False

        return self.recorder.write_summary(listening=self._listening(), error=self.error)

    # -- reading -----------------------------------------------------------

    def _listening(self) -> str:
        return f"{self.host}:{self.port}"

    def report(self) -> dict[str, Any]:
        return self.recorder.report(listening=self._listening(), error=self.error)


OUTCOME_NOTES = {
    OUTCOME_NO_CONNECTION:
        "Nothing connected. This is a statement about the diverter, not the "
        "sample -- check C1 before concluding anything about the implant.",
    OUTCOME_CONNECTED_SILENT:
        "TCP was accepted and no bytes followed. The implant reached the port "
        "and said nothing, which is different from never arriving.",
    OUTCOME_UNPARSED:
        "Bytes arrived that are not JSON-RPC. Read raw_base64 -- this is still "
        "an answer to phase 1's question.",
    OUTCOME_OTHER_RPC:
        "JSON-RPC arrived, but no eth_call naming the contract. Read the "
        "methods list; a handshake alone lands here.",
    OUTCOME_ETH_CALL:
        "The request phase 1 was built to capture. Phase 2 encodes its answer "
        "against these bytes.",
}


def main(argv: list[str] | None = None) -> int:
    """Standalone entry point, because phase 1 may run without the orchestrator."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output-dir", default=".",
                        help="where jsonrpc_requests.jsonl and the summary are written")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--reply", choices=("error", "empty"), default="error",
                        help="error: a JSON-RPC error. empty: a successful '0x', "
                             "which is what a node returns for a contract with "
                             "no code -- the truthful answer for this one")
    parser.add_argument("--seconds", type=float, default=0.0,
                        help="stop after this long; 0 waits for Ctrl-C")
    parser.add_argument("--answer", action="store_true",
                        help="phase 2: answer the getData() call instead of "
                             "refusing it, rotating through the candidate "
                             "return shapes as the implant retries")
    parser.add_argument("--address", default="",
                        help="the substitution address to serve. Defaults to a "
                             "synthetic tracer -- NEVER point this at a real "
                             "wallet; the safety argument for a responder is "
                             "that the operator picks a sink")
    parser.add_argument("--plan", default="",
                        help="pin one candidate shape instead of rotating, for "
                             "a focused re-run once the answer is known")
    args = parser.parse_args(argv)

    planner = None
    if args.answer or args.address or args.plan:
        from dynamic_analysis.jsonrpc_answer import TRACER_ADDRESS, AnswerPlanner
        try:
            planner = AnswerPlanner(args.address or TRACER_ADDRESS, args.plan)
        except Exception as error:
            print(f"failed: {error}")
            return 1

    responder = JsonRpcResponder(args.output_dir, args.host, args.port,
                                 args.reply, planner=planner)
    result = responder.start()
    if not result.get("started"):
        print(f"failed: {result.get('error')}")
        return 1

    if planner is None:
        print(f"recording on {args.host}:{args.port}, replying {args.reply!r}")
    else:
        shape = planner.pinned.name if planner.pinned else "rotating"
        print(f"ANSWERING on {args.host}:{args.port} with {shape} shape(s)")
        print(f"  serving address {planner.address}"
              f"{'  (tracer)' if planner.address == TRACER_ADDRESS else ''}")
    print(f"  -> {responder.requests_path}")
    try:
        if args.seconds > 0:
            threading.Event().wait(args.seconds)
        else:
            while True:
                threading.Event().wait(3600)
    except KeyboardInterrupt:
        pass

    summary = responder.stop()
    print(f"\noutcome: {summary['outcome']}")
    print(f"  {summary['outcome_note']}")
    print(f"  connections {summary['connections']}  requests {summary['requests']}  "
          f"target calls {summary['target_calls']}")
    if summary["methods"]:
        print(f"  methods: {summary['methods']}")

    answer = summary.get("answer") or {}
    if answer:
        served = answer.get("plans_served") or []
        print(f"  plans served: {served or 'none'}")
        if answer.get("all_plans_exhausted"):
            print("  every candidate shape was served and it kept asking -- the "
                  "list is what is wrong, not the wiring")
        elif len(served) == 1:
            print(f"  asked once and stopped: {served[0]} was accepted, or it "
                  f"gave up. Process lifetime is what tells those apart")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
