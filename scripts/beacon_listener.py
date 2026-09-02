"""Answer the beacon on 127.0.0.1:7372, and find out who speaks first.

    python scripts\\beacon_listener.py --minutes 10
    python scripts\\beacon_listener.py --minutes 10 --hello

**Runs in the guest.** The C2 is loopback -- measured 01 Sep, 212 attempts in an
hour, every one to `win11:7372` -- so nothing on the host-only network can
answer it and FakeNet is the wrong instrument. This binds the port the sample is
already knocking on.

**The silent run has been done, and it answered two questions at once.**
02 Sep, five connections in three minutes: the client sends **418 bytes without
being spoken to**, and those bytes are a **TLS ClientHello** --
`16 03 01 01 9d 01 00 01 99 03 03`, offering TLS 1.3 down to 1.0 in
`supported_versions`, x25519 and secp256r1 key shares, and no SNI, which fits a
client dialling an address rather than a name.

So **"server speaks first" is retracted** -- it came from reading the sample
rather than watching it, and nothing had ever accepted its connection. And the
`stuff.dll` frame is the **inner** protocol: `0xDEADBEEF` never appears on the
wire because everything above the handshake is encrypted.

**`--tls-cert` is therefore the mode that matters now.** Without it the run
stops at the ClientHello. With it, the handshake is the experiment: if the
client completes it, the inner frames arrive decrypted and the `stuff.dll`
model gets its first test against real bytes. If it drops after the certificate
flight, it validates or pins -- which is an answer, and the same shape of answer
`make_tls_cert.py` was written for on `0bw`. The CA minted alongside the leaf
can then be installed in the guest's root store and the run repeated.

The timing also changes once connections are accepted: refused connects retry
every 17.03 s, accepted ones came 35 s apart, the difference being how long the
client waits on a server that never speaks.

**Every byte is kept, whatever the parser makes of it.** Frames are decoded with
`dynamic_analysis.beacon_frame`, whose model is read out of `stuff.dll` IL and
has never been seen on the wire. A mismatch is a finding about the model, so
raw bytes go to disk before anything tries to interpret them, and the parser
reports disagreements rather than raising.

**`--hello` sends a frame first**, built to that model with an empty payload:
magic, zero lengths, flag 0, CRC of nothing. If the client answers it, the frame
layout is confirmed on the wire. If it disconnects immediately, that is
information too -- and the raw log will show whether it read the header at all.

Containment: the guest has no internet-facing adapter connected during a run,
and this listener binds loopback only unless `--any-address` is passed.
"""

from __future__ import annotations

import argparse
import binascii
import json
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dynamic_analysis.beacon_frame import (  # noqa: E402
    HEADER_SIZE,
    build_frame,
    decode_dictionary,
    frame_length,
    parse_frame,
)
from dynamic_analysis.beacon_reply import (  # noqa: E402
    DESTRUCTIVE,
    ReplyPlan,
    parse_command_lines,
)

DEFAULT_PORT = 7372
DEFAULT_HOST = "127.0.0.1"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _hexdump(data: bytes, limit: int = 512) -> list[str]:
    lines = []
    shown = data[:limit]
    for offset in range(0, len(shown), 16):
        chunk = shown[offset:offset + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset:04x}  {hexpart:<47}  {text}")
    if len(data) > limit:
        lines.append(f"  ... {len(data) - limit} more bytes")
    return lines


def _tls_context(cert: Path, key: Path) -> "ssl.SSLContext":
    """A permissive server context, because the question is what the client does.

    Measured 02 Sep: the client opens with a **TLS ClientHello** -- so the
    `stuff.dll` frame is the *inner* protocol and nothing of it is visible until
    a handshake completes. The ClientHello offers TLS 1.3 down to 1.0 in
    `supported_versions` and carries no SNI, which fits a client dialling an
    address rather than a name.

    Everything here is set as wide as the library allows: any protocol version
    the client offers, no client certificate wanted, and the default cipher list
    relaxed. A handshake that fails should fail because *the client* refused,
    which is a finding about the sample, and not because this end declined a
    version or a suite, which is a finding about nothing.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    context.verify_mode = ssl.CERT_NONE
    context.check_hostname = False
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return context


def serve(
    out_dir: Path,
    minutes: int,
    hello: bool,
    host: str,
    port: int,
    read_timeout: float,
    tls_cert: Path | None = None,
    tls_key: Path | None = None,
    plan: "ReplyPlan | None" = None,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(exist_ok=True)
    log_path = out_dir / "beacon_listener.jsonl"

    summary = {
        "started_at": _now(),
        "ended_at": "",
        "host": host,
        "port": port,
        "mode": "hello" if hello else "silent",
        "tls": bool(tls_cert),
        "tls_handshakes_completed": 0,
        "tls_handshakes_failed": 0,
        "tls_failures": [],
        "read_timeout_seconds": read_timeout,
        "connections": 0,
        "connections_that_sent_bytes": 0,
        "total_bytes_received": 0,
        "frames_parsed": 0,
        "frames_ok": 0,
        "answered_replies": 0,
        "reply_plan": [],
        "note": "",
    }

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(8)
    listener.settimeout(1.0)

    deadline = time.time() + minutes * 60
    print(f"listening on {host}:{port} for {minutes} minute(s), "
          f"mode={'hello' if hello else 'silent'}")
    print(f"writing to {out_dir}")

    context = _tls_context(tls_cert, tls_key) if tls_cert and tls_key else None
    if context:
        print(f"TLS enabled, serving {tls_cert.name}")

    log = log_path.open("a", encoding="utf-8")

    try:
        while time.time() < deadline:
            try:
                conn, peer = listener.accept()
            except socket.timeout:
                continue

            summary["connections"] += 1
            index = summary["connections"]
            record = {
                "connection": index,
                "at": _now(),
                "peer": f"{peer[0]}:{peer[1]}",
                "sent_hello": False,
                "bytes_received": 0,
                "frames": [],
                "closed_by": "",
            }
            print(f"\n[{record['at']}] connection {index} from {record['peer']}")

            with conn:
                conn.settimeout(read_timeout)

                if context is not None:
                    # The handshake is the experiment. A client that refuses
                    # our certificate drops here, and that refusal is the
                    # finding -- so it is recorded rather than swallowed.
                    try:
                        conn = context.wrap_socket(conn, server_side=True)
                    except (ssl.SSLError, OSError) as error:
                        summary["tls_handshakes_failed"] += 1
                        detail = f"{type(error).__name__}: {error}"
                        summary["tls_failures"].append(detail)
                        record["closed_by"] = f"TLS handshake failed -- {detail}"
                        print(f"  ! TLS handshake failed: {detail}")
                        log.write(json.dumps(record) + "\n")
                        log.flush()
                        continue
                    summary["tls_handshakes_completed"] += 1
                    record["tls"] = {
                        "version": conn.version(),
                        "cipher": conn.cipher(),
                    }
                    print(f"  TLS up: {conn.version()} {conn.cipher()[0]}")

                if hello:
                    frame = build_frame(b"")
                    conn.sendall(frame)
                    record["sent_hello"] = True
                    record["hello_hex"] = frame.hex()
                    print(f"  sent hello frame, {len(frame)} bytes: {frame.hex()}")

                received = b""
                while True:
                    try:
                        chunk = conn.recv(65536)
                    except socket.timeout:
                        record["closed_by"] = "read timeout"
                        break
                    except OSError as error:
                        record["closed_by"] = f"error: {error}"
                        break
                    if not chunk:
                        record["closed_by"] = "client closed"
                        break
                    received += chunk
                    # Stop once a whole frame is in hand, so the log has one
                    # message per entry rather than a stream nobody can split.
                    if len(received) >= HEADER_SIZE:
                        want = frame_length(received[:HEADER_SIZE])
                        if want and len(received) >= want:
                            record["closed_by"] = "complete frame"
                            break

                record["bytes_received"] = len(received)
                summary["total_bytes_received"] += len(received)

                # The reply, and then whatever the client makes of it. This is
                # the only part of the protocol nobody has ever seen: the
                # client has never been answered, so no command has reached it.
                # A held-open session, not one command per connection.
                #
                # Measured 02 Sep: the client answered `Ping` and then stopped
                # reconnecting for nine minutes. A valid reply moves it into a
                # connected state where it no longer re-dials, so a sweep that
                # closes after each command gets exactly one candidate per run
                # -- 165 restarts for the recovered vocabulary. The panel
                # evidently drives a persistent session, and the client sent
                # its second frame immediately, so this holds the socket and
                # walks the list down it.
                if plan is not None and received:
                    exchange = 0
                    while not plan.exhausted():
                        candidate = plan.next_candidate()
                        frame = candidate.frame()
                        exchange += 1
                        try:
                            conn.sendall(frame)
                        except OSError as error:
                            record.setdefault("reply_errors", []).append(
                                f"{candidate.name}: {error}"
                            )
                            print(f"  ! could not send {candidate.name}: {error}")
                            break

                        print(f"  [{exchange}] sent {candidate.name} "
                              f"({len(frame)} bytes)")

                        # Drain every frame the client offers, not one.
                        #
                        # Measured 02 Sep: `GetClipboard` answers TWICE -- an
                        # acknowledgement and then the clipboard contents as a
                        # separate frame. A loop that reads one frame per
                        # command consumed the ack here and handed the data to
                        # the *next* command, shifting every attribution after
                        # it by one. Positional pairing was never sound.
                        #
                        # It is also unnecessary: every response names the
                        # command it belongs to in its own `Packet` field, so
                        # correlation is by content and the shift cannot recur.
                        buffered = b""
                        frames: list[bytes] = []
                        closed = "read timeout"
                        while True:
                            if len(buffered) >= HEADER_SIZE:
                                want = frame_length(buffered[:HEADER_SIZE])
                                if want and len(buffered) >= want:
                                    frames.append(buffered[:want])
                                    buffered = buffered[want:]
                                    continue
                            try:
                                chunk = conn.recv(65536)
                            except socket.timeout:
                                closed = "read timeout"
                                break
                            except OSError as error:
                                closed = f"error: {error}"
                                break
                            if not chunk:
                                closed = "client closed"
                                break
                            buffered += chunk

                        received_bytes = sum(len(f) for f in frames) + len(buffered)
                        outcome = plan.record(candidate, received_bytes, closed)
                        outcome["frames_received"] = len(frames)
                        outcome["responses"] = []
                        record.setdefault("exchanges", []).append(outcome)

                        if frames:
                            summary["answered_replies"] += 1
                            print(f"      {len(frames)} frame(s), "
                                  f"{received_bytes} bytes")
                        for position, raw in enumerate(frames, 1):
                            answer = parse_frame(raw)
                            entry: dict = {"bytes": len(raw), "ok": answer["ok"]}
                            label = "unparsed"
                            if answer["ok"]:
                                body = decode_dictionary(answer["decompressed"])
                                fields = body["pairs"]
                                entry["fields"] = fields
                                label = dict(fields).get("Packet", "?")
                                entry["answers"] = label
                            else:
                                entry["problems"] = answer["problems"]
                            outcome["responses"].append(entry)

                            blob = (raw_dir /
                                    f"conn{index:04d}-{exchange:03d}"
                                    f"-{candidate.name}-{position}-{label}.bin")
                            blob.write_bytes(raw)

                            # The response's own Packet value, not the command
                            # that happened to precede it.
                            marker = "" if label == candidate.name else "   <- not this command"
                            print(f"      -> Packet={label}{marker}")
                            if answer["ok"]:
                                for key, value in entry["fields"]:
                                    shown = value if len(str(value)) <= 90 else (
                                        str(value)[:87] + "..."
                                    )
                                    if key != "Packet":
                                        print(f"           {key} = {shown!r}")

                        if not frames:
                            print(f"      no answer ({closed})")

                        if closed == "client closed":
                            print("      session ended by the client")
                            break

                if received:
                    summary["connections_that_sent_bytes"] += 1
                    blob = raw_dir / f"conn{index:04d}.bin"
                    blob.write_bytes(received)
                    print(f"  received {len(received)} bytes -> {blob.name}")
                    for line in _hexdump(received):
                        print(line)

                    parsed = parse_frame(received)
                    summary["frames_parsed"] += 1
                    if parsed["ok"]:
                        summary["frames_ok"] += 1
                    record["frames"].append({
                        "ok": parsed["ok"],
                        "problems": parsed["problems"],
                        "magic": (f"0x{parsed['magic']:08x}"
                                  if parsed["magic"] is not None else None),
                        "payload_length": parsed["payload_length"],
                        "original_size": parsed["original_size"],
                        "compressed": parsed["compressed"],
                        "crc_stated": parsed["crc_stated"],
                        "crc_computed": parsed["crc_computed"],
                        "payload_hex": parsed["payload"][:2048].hex(),
                        "decompressed_hex": parsed["decompressed"][:2048].hex(),
                    })
                    if parsed["ok"]:
                        print("  frame OK -- the model read out of stuff.dll holds")
                    else:
                        for problem in parsed["problems"]:
                            print(f"  ! {problem}")
                else:
                    print(f"  no bytes ({record['closed_by']})")

            log.write(json.dumps(record) + "\n")
            log.flush()
    except KeyboardInterrupt:
        summary["note"] = "interrupted"
    finally:
        listener.close()
        log.close()

    if plan is not None:
        summary["reply_plan"] = plan.results
        summary["reply_summary"] = plan.summary()

    summary["ended_at"] = _now()
    if summary["connections"] == 0:
        summary["note"] = (
            "Nothing connected. The payload attempts every 17.03 s, so a run of "
            "even one minute should see three. Check it is still resident and "
            "that nothing else holds the port."
        )
    elif summary["connections_that_sent_bytes"] == 0:
        summary["note"] = (
            "Connections were accepted and the client sent nothing before "
            "giving up. That is the first real test of 'server speaks first', "
            "and it passed -- run again with --hello."
        )
    else:
        summary["note"] = (
            "The client sent bytes without being spoken to first. "
            "'Server speaks first' is wrong, and this is its opening message."
        )

    (out_dir / "beacon_listener.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=r"C:\beacon-listen", help="output directory")
    parser.add_argument("--minutes", type=int, default=10)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument(
        "--any-address", action="store_true",
        help="bind 0.0.0.0 rather than loopback; the sample does not need it",
    )
    parser.add_argument(
        "--hello", action="store_true",
        help="send a frame on connect instead of staying silent",
    )
    parser.add_argument("--read-timeout", type=float, default=20.0)
    parser.add_argument(
        "--tls-cert",
        help="PEM certificate to serve; enables TLS termination. The client "
             "opens with a ClientHello, so nothing of the inner protocol is "
             "visible without this",
    )
    parser.add_argument("--tls-key", help="PEM private key for --tls-cert")
    parser.add_argument(
        "--respond", action="store_true",
        help="reply to the check-in, one candidate per connection, and record "
             "what the client does with it",
    )
    parser.add_argument(
        "--commands",
        help="a file of command names, one per line, to use instead of the "
             "built-in guesses. Extract them from the payload assembly with "
             "dotnet_meta.py --strings user. A line may carry the fields its "
             "handler reads, tab-separated: 'ProcessSpy	Command=List'. "
             "Build one with scripts/build_command_sweep.py",
    )
    parser.add_argument(
        "--allow", action="append", default=[], metavar="NAME",
        help="release one withheld command by name, repeatable. For a run "
             "designed to measure a specific held command -- Report is the "
             "one it was written for -- without releasing the other 33",
    )
    parser.add_argument(
        "--include-destructive", action="store_true",
        help=f"also send the {len(DESTRUCTIVE)} commands withheld by default. "
             "The client acts on what it is sent, and these destroy data, deny "
             "access, or change configuration a restore is needed to undo",
    )
    args = parser.parse_args(argv)

    host = "0.0.0.0" if args.any_address else args.host

    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert and --tls-key go together")

    plan = None
    if args.respond:
        if args.commands:
            try:
                specs = parse_command_lines(
                    Path(args.commands).read_text(encoding="utf-8").splitlines()
                )
            except ValueError as error:
                # A malformed field is refused here rather than sent. The
                # client receives null for a field it cannot find, and null is
                # what crashed it on 02 Sep.
                parser.error(f"{args.commands}: {error}")
            try:
                plan = ReplyPlan.from_specs(
                    specs,
                    include_destructive=args.include_destructive,
                    allow=args.allow,
                )
            except ValueError as error:
                parser.error(str(error))
            with_fields = sum(1 for s in specs if s.fields)
            print(f"replying from {len(plan.candidates)} of {len(specs)} "
                  f"command(s) in {args.commands}, {with_fields} carrying fields")
            if plan.released:
                print("RELEASED, deliberately: " + ", ".join(plan.released))
                print("  these are withheld by default; the client acts on "
                      "what it is sent")
            if plan.withheld:
                print(f"withholding {len(plan.withheld)} destructive: "
                      + ", ".join(plan.withheld[:8])
                      + (" ..." if len(plan.withheld) > 8 else ""))
                print("  --include-destructive sends them; the client acts on "
                      "what it is sent")
        else:
            plan = ReplyPlan()
            print(f"replying from {len(plan.candidates)} built-in candidates -- "
                  "these are GUESSES; --commands takes names from the payload")

    summary = serve(
        Path(args.out),
        minutes=args.minutes,
        hello=args.hello,
        host=host,
        port=args.port,
        read_timeout=args.read_timeout,
        tls_cert=Path(args.tls_cert) if args.tls_cert else None,
        tls_key=Path(args.tls_key) if args.tls_key else None,
        plan=plan,
    )

    print("\n" + json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
