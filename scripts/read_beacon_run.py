"""Read a `beacon_listener` capture and say what answered what.

    python scripts/read_beacon_run.py C:\\beacon-fields

A sweep produces one JSONL record per connection and a lot of frames, and the
question asked of it is always the same: which commands answered, which said
nothing, and does each answer belong to the command it arrived after.

**That last part is not a formality.** On 02 Sep a sweep paired responses to
commands by position and every attribution after the eighth was wrong, because
`GetClipboard` answers with two frames -- an acknowledgement and then the data.
The run appeared to show `Preview` generating WLAN profiles. Every response
carries the command it answers in its own `Packet` field, so this correlates by
that and flags anything whose `Packet` is not what was sent.

**It reads the old shape too**, and says so. Captures written before the drain
fix have one frame per exchange and no `responses` list; their per-exchange
attribution is positional and is not sound. This prints those under a warning
rather than refusing them, because re-reading exactly such a capture is what
explained four commands that had been recorded as unexplained silences.

**A silence is a result and gets its own column.** "Answered nothing" and "was
never given a chance to answer" are different findings: a command that times
out mid-sweep was measured, and one that is last in a sweep running a frame
behind was not.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dynamic_analysis.beacon_frame import decode_dictionary  # noqa: E402


#: Reply types that are a status, not an answer naming its command.
#:
#: These carry no attribution: `Geo` answers with `PluginMessage "Getting
#: geolocation"`, and so does `Wifi`, and so does `PC`. Flagging them as
#: mispaired would cry wolf on most of a sweep and bury the real shifts -- but
#: the converse matters more and is the reason this set is written down: **a
#: status frame cannot be attributed by content**, so it falls back on the
#: position it arrived in, and position is only sound while nothing has
#: shifted. One command answering with two frames breaks that for everything
#: after it, and a run of status replies is where the break hides.
STATUS_PACKETS = frozenset({"PluginMessage", "Success", "Error", "Info"})


def _fields_of(entry: dict) -> list[tuple[str, str]]:
    """The pairs a recorded response carries, whichever shape it is in."""
    pairs = entry.get("fields")
    if isinstance(pairs, list):
        return [(str(k), str(v)) for k, v in pairs]
    hexed = entry.get("decompressed_hex") or entry.get("payload_hex") or ""
    if hexed:
        decoded = decode_dictionary(bytes.fromhex(hexed))
        return [(str(k), str(v)) for k, v in decoded.get("pairs") or []]
    return []


def _packet_of(pairs: list[tuple[str, str]]) -> str:
    for key, value in pairs:
        if key == "Packet":
            return value
    return ""


def _shorten(value: str, limit: int = 70) -> str:
    text = str(value)
    return text if len(text) <= limit else f"<{len(text)} chars>"


def read(path: Path) -> int:
    if path.is_dir():
        path = path / "beacon_listener.jsonl"
    if not path.exists():
        print(f"no capture at {path}", file=sys.stderr)
        return 2

    sent = answered = silent = mismatched = status_only = 0
    legacy = False

    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)

        tls = record.get("tls") or {}
        print(f"\n=== connection {record.get('connection')} "
              f"from {record.get('peer')} at {record.get('at')}")
        if tls:
            print(f"    TLS {tls.get('version')} {(tls.get('cipher') or [''])[0]}")
        print(f"    closed by: {record.get('closed_by')}")

        for frame in record.get("frames") or []:
            pairs = _fields_of(frame)
            if pairs:
                print(f"    check-in: Packet={_packet_of(pairs)!r}")
                for key, value in pairs:
                    if key != "Packet":
                        print(f"      {key} = {_shorten(value)!r}")

        exchanges = record.get("exchanges") or []
        if not exchanges:
            continue

        print(f"\n    {len(exchanges)} command(s) sent")
        for exchange in exchanges:
            sent += 1
            name = exchange.get("candidate", "?")
            responses = exchange.get("responses")

            if responses is None:
                # Pre-drain-fix capture: one frame per exchange, positional.
                legacy = True
                pairs = _fields_of(exchange)
                if not pairs:
                    silent += 1
                    print(f"      {name:<18} SILENT "
                          f"({exchange.get('closed_by')})")
                    continue
                packet = _packet_of(pairs)
                answered += 1
                if packet == name:
                    flag = ""
                elif packet in STATUS_PACKETS:
                    status_only += 1
                    flag = f"  ({packet}, attributed by position only)"
                else:
                    mismatched += 1
                    flag = f"  <- NAMES {packet!r}"
                print(f"      {name:<18} {exchange.get('reply_bytes_from_client')} "
                      f"bytes{flag}")
                continue

            if not responses:
                silent += 1
                print(f"      {name:<18} SILENT ({exchange.get('closed_by')})")
                continue

            answered += 1
            print(f"      {name:<18} {len(responses)} frame(s), "
                  f"{exchange.get('reply_bytes_from_client')} bytes")
            for entry in responses:
                pairs = _fields_of(entry)
                packet = _packet_of(pairs) or "<unparsed>"
                if packet == name:
                    flag = ""
                elif packet in STATUS_PACKETS:
                    status_only += 1
                    flag = "   (status; attributed by position only)"
                else:
                    mismatched += 1
                    flag = "   <- NOT THIS COMMAND"
                print(f"        -> Packet={packet!r}{flag}")
                for key, value in pairs:
                    if key != "Packet":
                        print(f"           {key} = {_shorten(value)!r}")

    print("\n--- summary")
    print(f"    sent        {sent}")
    print(f"    answered    {answered}")
    print(f"    silent      {silent}")
    print(f"    mismatched  {mismatched}")
    print(f"    status only {status_only}")
    if mismatched:
        print("    A response naming a DIFFERENT COMMAND belongs to an earlier "
              "one.")
        print("    Read those by Packet, never by position.")
    if status_only:
        print("    A status reply (PluginMessage/Success/Error/Info) names no "
              "command,")
        print("    so it is attributed by position -- sound only while nothing "
              "has shifted.")
    if legacy:
        print("\n    THIS CAPTURE PREDATES THE DRAIN FIX. It recorded one frame")
        print("    per command, so a command answering with two frames shifts")
        print("    every attribution after it. The frames are correct; the")
        print("    per-exchange pairing is not.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("capture", type=Path,
                        help="beacon_listener.jsonl, or the --out directory")
    args = parser.parse_args(argv)
    return read(args.capture)


if __name__ == "__main__":
    raise SystemExit(main())
