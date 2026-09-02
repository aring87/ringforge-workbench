"""What to answer `listinfo` with, and how to tell whether it worked.

The client has never received a reply. It connects to `127.0.0.1:7372`, opens
TLS, sends one `Packet: listinfo` check-in, and -- measured 02 Sep -- goes quiet
once that lands. Everything after the check-in is unobserved: no command has
ever reached this sample.

**This enumerates rather than guesses, for the reason `jsonrpc_answer` did.**
The 0bw work turned four failed detonations into one successful one by sweeping
a list of candidate shapes in a single run instead of betting a run on one
hypothesis. The same applies here and for the same reason: nothing on disk says
what a valid reply looks like, so the cheapest way to find out is to try several
and record which one changes the client's behaviour.

**The candidates in `GUESSES` are guesses and are labelled as such.** The real
vocabulary is in the payload assembly, not in `stuff.dll` -- `stuff.dll` is the
transport and carries no command names. Extract the payload's user strings with
`scripts/dotnet_meta.py --strings user` and pass them with `--commands`, and
this stops guessing. Until then the list is conventional RAT replies and its
failure proves nothing about the protocol.

**The readout is behavioural, not semantic.** Nothing here can tell a "correct"
reply from an ignored one by inspection, so what is measured instead is what
the client *does*:

    a second message      the reply was understood and answered. This is the
                          objective, and its contents are the command channel
    connection held open  the reply was at least not rejected
    immediate FIN         refused, or unparseable
    reconnect sooner      the client treats the exchange as failed and retries

`beacon_listener.py --respond` walks the list one candidate per connection, so
a run of a few minutes sweeps it. At 17.03 s between retries the whole default
list costs about two minutes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from dynamic_analysis.beacon_frame import LENGTH, build_frame


def encode_dictionary(pairs: Iterable[tuple[str, str]]) -> bytes:
    """The body format, confirmed against the real check-in on 02 Sep.

    `[uint32 count]` then per pair `[uint32 len][key][uint32 len][value]`, all
    UTF-8, all little-endian.
    """
    pairs = list(pairs)
    out = LENGTH.pack(len(pairs))
    for key, value in pairs:
        for text in (key, value):
            raw = text.encode("utf-8")
            out += LENGTH.pack(len(raw)) + raw
    return out


def build_reply(pairs: Iterable[tuple[str, str]]) -> bytes:
    """A complete frame carrying this dictionary."""
    return build_frame(encode_dictionary(pairs))


@dataclass
class Candidate:
    """One reply shape, and why it is worth a connection."""

    name: str
    pairs: list[tuple[str, str]]
    rationale: str

    def frame(self) -> bytes:
        return build_reply(self.pairs)


#: Conventional shapes, in the order worth trying. **Guesses.**
#:
#: `listinfo` is the client announcing itself to a panel, so the replies most
#: likely to mean something are an acknowledgement of that announcement or an
#: immediate first command. Ordered cheapest-assumption first: an empty body
#: tests whether the client tolerates a well-formed frame at all, before any
#: guess about vocabulary is layered on top.
GUESSES: list[Candidate] = [
    Candidate(
        "empty",
        [],
        "A well-formed frame with no fields. Tests the framing alone: if this "
        "is answered or even tolerated, the transport is right and only the "
        "vocabulary is in question.",
    ),
    Candidate(
        "echo",
        [("Packet", "listinfo")],
        "The panel acknowledging the packet it was sent. Many families reply "
        "with the same type name.",
    ),
    Candidate(
        "ping",
        [("Packet", "ping")],
        "A keepalive, and the commonest first thing a panel sends.",
    ),
    Candidate(
        "pong",
        [("Packet", "pong")],
        "The other half of that convention, in case the client considers its "
        "check-in the ping.",
    ),
    Candidate(
        "ok",
        [("Packet", "ok")],
        "A bare acknowledgement.",
    ),
    Candidate(
        "connected",
        [("Packet", "connected")],
        "A session-established notice, which is what a panel would send before "
        "issuing commands.",
    ),
]


@dataclass
class ReplyPlan:
    """Walks the candidates, one per connection, and records what each did."""

    candidates: list[Candidate] = field(default_factory=lambda: list(GUESSES))
    index: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_commands(cls, commands: Iterable[str]) -> "ReplyPlan":
        """A plan over command names extracted from the payload assembly.

        This is the version that is not guessing. `stuff.dll` carries no
        command names -- it is the transport -- so the vocabulary comes from
        the payload's own user-string heap.
        """
        candidates = [
            Candidate(
                name,
                [("Packet", name)],
                "From the payload's own string heap, so it is a name the "
                "client's dispatcher knows.",
            )
            for name in commands
        ]
        return cls(candidates=candidates or list(GUESSES))

    def next_candidate(self) -> Candidate:
        candidate = self.candidates[self.index % len(self.candidates)]
        self.index += 1
        return candidate

    def record(self, candidate: Candidate, reply_bytes: int, closed_by: str) -> dict:
        """What the client did with it.

        `answered` is the readout that matters: bytes back after our reply mean
        the reply was parsed and acted on, which is the objective. Everything
        else is context for reading a negative.
        """
        result = {
            "candidate": candidate.name,
            "rationale": candidate.rationale,
            "reply_bytes_from_client": reply_bytes,
            "answered": reply_bytes > 0,
            "closed_by": closed_by,
        }
        self.results.append(result)
        return result

    def summary(self) -> dict[str, Any]:
        answered = [r for r in self.results if r["answered"]]
        return {
            "candidates_tried": len(self.results),
            "answered": [r["candidate"] for r in answered],
            "note": (
                f"{answered[0]['candidate']} was answered -- the client parsed "
                "the reply and wrote back. Its bytes are the command channel."
                if answered
                else "Nothing was answered. With guessed candidates that says "
                "nothing about the protocol; extract the payload's user "
                "strings and pass them with --commands before concluding."
            ),
        }
