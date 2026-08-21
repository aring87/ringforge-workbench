"""FakeNet-NG custom-response handler for `0bw` phase 1.

FakeNet loads this file with `load_source` and calls `HandleTcp(sock)`, handing
over the socket completely -- it does not read, write or close it afterwards, so
the loop and every exception below are this file's problem.

**Why the wiring goes through FakeNet rather than around it.** The alternative
was to blacklist 8545 in the diverter and bind the port directly, and that
breaks containment: with the port undiverted, the connection follows whatever
address DNS returned, which is not guaranteed to be local. Routing through a
custom response keeps every packet inside FakeNet's diversion and still lets
this project's own code answer. Containment is not a setting to work around.

**`TcpDynamic` rather than `HttpDynamic`, deliberately.** The HTTP hook hands
over an already-parsed request, so the recorded bytes would be a reconstruction
of the wire rather than the wire. Phase 1 exists to read a request nobody has
seen, and phase 2 gets encoded against those bytes, so the raw socket is the
correct level. It also means a client that does not speak HTTP -- a real
possibility for a hand-rolled implant -- is captured rather than mangled.

Configured by environment, because FakeNet starts this file and there is nowhere
else to pass arguments:

    RINGFORGE_RPC_OUTPUT_DIR   where the record and summary are written
    RINGFORGE_RPC_REPLY        `error` (default) or `empty`
    RINGFORGE_REPO_ROOT        the clone, so the tested recorder can be imported
    RINGFORGE_RPC_ANSWER       phase 2: `1` to answer `getData()` rather than
                               refuse it, rotating candidate return shapes
    RINGFORGE_RPC_ADDRESS      the substitution address; defaults to the tracer.
                               **Never a real wallet** -- see `jsonrpc_answer`
    RINGFORGE_RPC_PLAN         pin one candidate shape instead of rotating
    RINGFORGE_RPC_TLS          `1` when the listener runs `UseSSL: Yes`. Only
                               changes what a *missing* connection means -- see
                               below -- because the socket arrives decrypted.

**Under TLS this handler sees plaintext, and sees nothing at all on failure.**
`UseSSL: Yes` makes FakeNet wrap the *listening* socket, so `accept()` returns
an already-negotiated connection and `HandleTcp` receives decrypted bytes with
no work on its part. The cost is at the other end: a handshake the client
refuses -- an untrusted certificate is the expected reason -- fails before
`accept()` returns and never reaches this file. The run then records
`no_connection`, which is also what a diverter that never routed the port
produces. `RINGFORGE_RPC_TLS` exists so the summary can say so rather than
leaving the two indistinguishable.

**A broken import must never read as a silent implant.** If the recorder cannot
be loaded, this file still answers and still writes a record saying why, because
"the handler failed to start" and "the sample never asked" are the two readings
phase 1 is built to keep apart.
"""

import json
import os
import socket
import sys
import time
import traceback
from pathlib import Path

#: Matches `JsonRpcResponder.read_timeout`. Long enough that a client which
#: connects early and asks late is not cut off, short enough that a detonation
#: does not end with threads still parked on a socket.
READ_TIMEOUT = 15.0

MAX_REQUEST_BYTES = 256 * 1024

_DEFAULT_REPO = r"C:\projects\RingForge_Analyzer"


def _output_dir() -> Path:
    return Path(os.environ.get("RINGFORGE_RPC_OUTPUT_DIR") or Path.cwd() / "rpc")


def _load_recorder():
    """Import the tested recorder, or return None and say so.

    The classification, the parsing and the five outcomes live in
    `dynamic_analysis.jsonrpc_responder` and are tested there. Re-implementing
    any of it here would mean two answers to the same question.
    """
    root = os.environ.get("RINGFORGE_REPO_ROOT") or _DEFAULT_REPO
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        from dynamic_analysis.jsonrpc_responder import RequestRecorder
    except Exception:
        return None

    planner = None
    if os.environ.get("RINGFORGE_RPC_ANSWER", "").strip() in ("1", "yes", "true"):
        # Phase 2. A bad address or plan name must fail here, loudly, rather
        # than half-arming the run: answering with the wrong thing and refusing
        # to answer at all look identical from outside the guest.
        from dynamic_analysis.jsonrpc_answer import TRACER_ADDRESS, AnswerPlanner
        planner = AnswerPlanner(
            os.environ.get("RINGFORGE_RPC_ADDRESS") or TRACER_ADDRESS,
            os.environ.get("RINGFORGE_RPC_PLAN", ""),
        )

    return RequestRecorder(
        _output_dir(),
        os.environ.get("RINGFORGE_RPC_REPLY", "error"),
        planner=planner,
        tls_expected=os.environ.get("RINGFORGE_RPC_TLS", "").strip() in ("1", "yes", "true"),
    )


#: One recorder for the life of the FakeNet process. Every connection is a fresh
#: `HandleTcp` call on its own thread, so the totals only add up if the state is
#: shared -- and `RequestRecorder` takes its own lock.
_RECORDER = _load_recorder()
_IMPORT_ERROR = "" if _RECORDER is not None else traceback.format_exc()


def _fallback_reply() -> bytes:
    """What to say when the recorder could not be loaded.

    Deliberately identical in shape to the recorder's own `error` reply, so a
    failed import changes what is *recorded* and not what the implant is told.
    Otherwise a bench problem would silently become a different experiment.
    """
    body = json.dumps({
        "jsonrpc": "2.0", "id": None,
        "error": {"code": -32000, "message": "execution reverted"},
    }).encode("utf-8")
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: keep-alive\r\n\r\n" + body
    )


def _note_broken_import(peer):
    """Leave evidence that the handler ran and the recorder did not load."""
    try:
        directory = _output_dir()
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "jsonrpc_requests.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "kind": "handler_import_failed",
                "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
                "peer": peer,
                "repo_root": os.environ.get("RINGFORGE_REPO_ROOT") or _DEFAULT_REPO,
                "error": _IMPORT_ERROR,
            }) + "\n")
    except Exception:
        pass


def _peer_of(sock) -> str:
    try:
        address = sock.getpeername()
        return "%s:%s" % (address[0], address[1])
    except Exception:
        return "unknown"


def HandleTcp(sock):  # noqa: N802 -- FakeNet requires this exact name
    """One connection, from FakeNet's diverter.

    Mirrors `JsonRpcResponder._Handler.handle`: read until a request is
    complete, record it, answer, and keep the socket open for another because
    JSON-RPC clients reuse connections.
    """
    peer = _peer_of(sock)

    if _RECORDER is None:
        _note_broken_import(peer)
        try:
            sock.sendall(_fallback_reply())
        except Exception:
            pass
        return

    from dynamic_analysis.jsonrpc_responder import _parse_http, _parse_jsonrpc

    _RECORDER.note_connection(peer)
    try:
        sock.settimeout(READ_TIMEOUT)
    except Exception:
        pass

    buffer = b""
    spoke = False

    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        except Exception:
            break
        if not chunk:
            break

        spoke = True
        buffer += chunk
        if len(buffer) > MAX_REQUEST_BYTES:
            _RECORDER.note_request(peer, buffer[:MAX_REQUEST_BYTES], truncated=True)
            break

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

        record = _RECORDER.note_request(peer, buffer)
        try:
            sock.sendall(_RECORDER.response_bytes(record))
        except Exception:
            break
        buffer = b""

    # **Whatever is still buffered when the loop ends is still what the client
    # said.** The completeness check above `continue`s on anything that is
    # neither HTTP nor parseable JSON, waiting for more -- and a client waiting
    # on *us* never sends more. Run `b610dea4` lost eleven TLS ClientHellos
    # exactly here and reported `connected_silent` for a client that had spoken
    # 465 bytes each time.
    if buffer:
        _RECORDER.note_request(peer, buffer)

    if not spoke:
        _RECORDER.note_silent(peer)

    # Written after every connection rather than at shutdown: FakeNet is stopped
    # with CTRL_BREAK and this module gets no teardown callback, so a summary
    # deferred to the end is a summary that never exists.
    try:
        _RECORDER.write_summary(listening="fakenet:8545")
    except Exception:
        pass
