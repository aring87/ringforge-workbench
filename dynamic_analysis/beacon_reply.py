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


#: Commands withheld unless asked for explicitly.
#:
#: **Measured 02 Sep: the client acts on what it is sent.** It answered `Ping`
#: on the first candidate, so a sweep is not a probe -- it is a sequence of
#: instructions to a live RAT. The list below is every recovered name that
#: destroys data, denies access to the machine, or changes its configuration
#: in a way a restore is needed to undo.
#:
#: `Jigsaw` is the one that decides the default. It is a ransomware family
#: name sitting beside `Encrypt` and `Decrypt`, and the guest disk holds the
#: run's own outputs -- a sweep that reaches it takes the evidence with it.
#:
#: The guest is snapshotted and disposable, so this is not about safety of the
#: bench. It is about not destroying a run in progress, and about a sweep being
#: a decision rather than a side effect of ordering.
DESTRUCTIVE = frozenset({
    # data and availability
    "Jigsaw", "Encrypt", "Decrypt", "Melt", "StopMelt", "BSOD", "DDOS",
    "DDOSstop", "Shutdown", "Restart", "LogOff", "Kill", "ChangePassword",
    "Empty", "StopEmpty", "forkbomb",
    # input and display denial -- recoverable, but they end a session you are
    # trying to observe
    "Lock", "BlockInput", "TrapMouse", "HideMouse", "Screamer",
    # configuration changes that outlive the run
    "Defender", "Bypass", "HideFile", "AddToStartup", "Startup", "StartupTask",
    "regdisable", "taskdisable", "cmddisable", "ChangeIcons", "Wallpaper",
    "Update", "Uninstall", "Disconnect",
    # Kills the client, measured 02 Sep, and the decompiled dispatcher says
    # exactly why:
    #
    #     case "Report":
    #         string asString10 = unpack.GetAsString("Name");
    #         pm = new ProcessMonitor();
    #         pm.Start(asString10);        // null -> NullReferenceException
    #
    # Unhandled, out of HandlePacket+<Run>d__62.MoveNext(), exit 0xe0434352.
    # The exception surfaces on a background thread about a second later, which
    # is why two further commands were answered before the process died --
    # and why the crash was first misattributed to `Notify`, the command in
    # flight when it went.
    #
    # It destroys nothing on the host and is here because it costs the rest of
    # the sweep: the client does not reconnect after its session ends, and its
    # ONLOGON task only re-launches at the next logon, so one careless
    # candidate is one logon.
    #
    # `Report` with a `Name` field may well be safe. Withheld until that is
    # measured rather than assumed.
    "Report",
})

#: Sent already, on 02 Sep, in this order. A resume starts after these.
#:
#: Kept in code rather than in a hand-edited list because the alternative is an
#: operator remembering where a sweep stopped, and a repeat of `Notify` costs a
#: logon.
ALREADY_TRIED = (
    "Ping", "Connect", "Clientinfo", "Task", "Request", "Report", "Survival",
    "Notify",
)


def partition(names: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split a command list into what is safe to send and what is not."""
    names = list(names)
    safe = [n for n in names if n not in DESTRUCTIVE]
    held = [n for n in names if n in DESTRUCTIVE]
    return safe, held


@dataclass
class ReplyPlan:
    """Walks the candidates, one per connection, and records what each did."""

    candidates: list[Candidate] = field(default_factory=lambda: list(GUESSES))
    index: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)
    withheld: list[str] = field(default_factory=list)

    def exhausted(self) -> bool:
        """True once every candidate has been sent at least once.

        A held-open session walks the whole list in one connection, so unlike
        the per-connection sweep it can finish -- and a run that keeps sending
        after it has finished is only re-testing.
        """
        return self.index >= len(self.candidates)

    @classmethod
    def from_commands(
        cls,
        commands: Iterable[str],
        include_destructive: bool = False,
    ) -> "ReplyPlan":
        """A plan over command names extracted from the payload assembly.

        This is the version that is not guessing. `stuff.dll` carries no
        command names -- it is the transport -- so the vocabulary comes from
        the payload's own user-string heap.

        ``include_destructive`` is off because the client was measured acting
        on what it is sent. The withheld names are listed on the plan so a run
        says what it declined to try rather than quietly shortening its own
        sweep.
        """
        safe, held = partition(commands)
        chosen = list(commands) if include_destructive else safe
        candidates = [
            Candidate(
                name,
                [("Packet", name)],
                "From the payload's own string heap, so it is a name the "
                "client's dispatcher knows.",
            )
            for name in chosen
        ]
        plan = cls(candidates=candidates or list(GUESSES))
        plan.withheld = [] if include_destructive else held
        return plan

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
            "candidates_total": len(self.candidates),
            "withheld_as_destructive": self.withheld,
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
