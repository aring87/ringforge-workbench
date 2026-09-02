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

import base64
import struct
from dataclasses import dataclass, field
from typing import Any, Iterable

from dynamic_analysis.beacon_frame import LENGTH, build_frame

#: A four-byte little-endian signed integer, which is what an Integer field is.
INT32 = struct.Struct("<i")


def encode_dictionary(pairs: Iterable[tuple[str, str]]) -> bytes:
    """The body format, confirmed against the real check-in on 02 Sep.

    `[uint32 count]` then per pair `[uint32 len][key][uint32 len][value]`, all
    UTF-8, all little-endian.
    """
    pairs = list(pairs)
    out = LENGTH.pack(len(pairs))
    for key, value in pairs:
        for text in (key, value):
            # A value is not always text. An Integer field is four raw bytes,
            # and sending its digits instead is what ended the 02 Sep sweep.
            raw = text.encode("utf-8") if isinstance(text, str) else bytes(text)
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
    # Added 02 Sep, after reading the case rather than the name:
    #
    #     case "Share":
    #         ShareClient.Clone(GetAsString("Host"), GetAsString("Port"));
    #
    # It clones the running client to another address. That is propagation and
    # a configuration change in one, and it is the mechanism behind the
    # payload's own string "This client was shared to you from someone".
    # Nothing on this bench should send it, and a sweep that reached it by
    # accident would be sending a RAT somewhere.
    "Share",
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


@dataclass(frozen=True)
class CommandSpec:
    """One command name and the fields to send with it.

    **Why this exists.** Until 02 Sep every candidate was `{"Packet": name}`
    and nothing else, which is the right shape for discovering *whether* a name
    is a real dispatcher case and the wrong one for finding out what it does.
    32 of the 151 cases read a field, and a case that reads a field from a
    packet that has none gets null -- which is how `Report` crashed the client
    and cost a logon.

    **The fields are not always the ones the dispatcher reads.** Five cases
    delegate to a handler class that reads its own: `ProcessSpy`, `Programs`
    and `Services` switch on `Command`, `RegistryRequest` and `DeviceRequest`
    on `Action`. Sent bare they match nothing, fall off the end of the switch
    and return without replying -- which is exactly what four of them did on
    02 Sep and was recorded as unexplained silence.
    """

    name: str
    fields: tuple[tuple[str, str], ...] = ()
    note: str = ""

    def pairs(self) -> list[tuple[str, str]]:
        """`Packet` first, then the fields, in the order they were written.

        Order is not cosmetic: the body is a list of pairs rather than a map,
        and the client reads `Packet` before anything else.
        """
        return [("Packet", self.name), *self.fields]


#: How an integer rides in the body, measured 02 Sep from a crash and a reply.
#:
#: `Stuff.Unpack.GetAsInteger` is `BitConverter.ToInt32(value, 0)` over the
#: value's raw bytes. It is NOT a decimal string. Sending `Volume=50` as the
#: two characters "50" threw `System.ArgumentException` out of
#: `BitConverter.ToInt32` and ended the session at the sweep's first integer
#: field -- the whole tail of the run, `Report` included, went unsent.
#:
#: The client had already said as much in the other direction: `FileSearch`
#: answers with `Progress = "\x00\x00\x00\x00"`, four raw bytes.
#:
#: A MISSING integer key is safe -- `HandleProcessManager.Run` reads
#: `ProcessId` unconditionally and answered fine without it. A key that is
#: present and not exactly four bytes is fatal. So the dangerous value is not
#: the absent one, it is the plausible one.
INT_TAG = "int:"

#: Raw bytes, base64 in the file. For a ByteArray field, or any value that is
#: not text.
BYTES_TAG = "b64:"

#: An explicit "this really is text", for a value that would otherwise be read
#: as a tag.
TEXT_TAG = "str:"


def encode_value(text: str) -> str | bytes:
    """Read one `key=value` right-hand side into what goes on the wire.

    Untagged values stay text, which is what the body is made of and what every
    field written before this was.
    """
    if text.startswith(INT_TAG):
        return INT32.pack(int(text[len(INT_TAG):]))
    if text.startswith(BYTES_TAG):
        return base64.b64decode(text[len(BYTES_TAG):], validate=True)
    if text.startswith(TEXT_TAG):
        return text[len(TEXT_TAG):]
    return text


#: The separator between a command and its fields, and between fields.
#:
#: A tab rather than a space because a value may contain spaces -- `Notepad`
#: takes a `Content`, `MsgBox` takes a `Message` -- and a key may not contain a
#: tab.
FIELD_SEPARATOR = "\t"


def parse_command_lines(lines: Iterable[str]) -> list[CommandSpec]:
    """Read a commands file, which may now carry fields.

    One command per line. A bare name still means a bare packet, so every file
    written before this existed parses unchanged. With fields, the name and
    each `key=value` are separated by tabs::

        Ping
        ProcessSpy<TAB>Command=List
        RegistryRequest<TAB>Action=GetRoots<TAB>Path=HKEY_CURRENT_USER

    A `#` in the first column starts a comment line. A tab followed by `#`
    after the fields is kept as the spec's note rather than dropped: why a
    value was chosen belongs in the run log beside what it did.

    A token with no `=` raises. Guessing which half was meant is how a null
    reaches a handler, and null is what crashed the client on 02 Sep.
    """
    specs: list[CommandSpec] = []
    for line in lines:
        text = line.rstrip("\r\n")
        if not text.strip() or text.lstrip().startswith("#"):
            continue

        note = ""
        marker = FIELD_SEPARATOR + "#"
        if marker in text:
            text, _, note = text.partition(marker)
            note = note.strip()

        parts = [p for p in text.split(FIELD_SEPARATOR) if p.strip()]
        if not parts:
            continue

        name = parts[0].strip()
        fields: list[tuple[str, str]] = []
        for part in parts[1:]:
            key, separator, value = part.partition("=")
            if not separator:
                raise ValueError(
                    f"{name}: field {part.strip()!r} is not key=value"
                )
            fields.append((key.strip(), encode_value(value)))
        specs.append(CommandSpec(name, tuple(fields), note))
    return specs


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
    #: Withheld names deliberately released for this run, via `allow`.
    released: list[str] = field(default_factory=list)

    def exhausted(self) -> bool:
        """True once every candidate has been sent at least once.

        A held-open session walks the whole list in one connection, so unlike
        the per-connection sweep it can finish -- and a run that keeps sending
        after it has finished is only re-testing.
        """
        return self.index >= len(self.candidates)

    @classmethod
    def from_specs(
        cls,
        specs: Iterable[CommandSpec],
        include_destructive: bool = False,
        allow: Iterable[str] = (),
    ) -> "ReplyPlan":
        """A plan over commands that carry their handlers' fields.

        Withholding is by name, exactly as for bare commands: a destructive
        command is no less destructive for being properly formed, and one that
        arrives with the right fields is *more* likely to do what it says.

        ``allow`` releases named commands from the withheld set without
        releasing the rest. It exists because `Report` is the one withheld
        name a run may specifically be designed to measure -- it was withheld
        for crashing the client with a null `Name`, and whether a real `Name`
        is safe cannot be settled by continuing to withhold it. Releasing 33
        commands to ask about one is not a trade worth making, so this is the
        narrow instrument. Released names are recorded on the plan, because a
        run that deliberately sent a held command must say so.
        """
        specs = list(specs)
        allow = {str(name) for name in allow}

        unknown = sorted(allow - {s.name for s in specs})
        if unknown:
            raise ValueError(
                "--allow names not in the sweep: " + ", ".join(unknown)
            )
        not_withheld = sorted(allow - DESTRUCTIVE)
        if not_withheld:
            raise ValueError(
                "--allow names that were never withheld: "
                + ", ".join(not_withheld)
            )

        def held(name: str) -> bool:
            return name in DESTRUCTIVE and name not in allow

        withheld = [s.name for s in specs if held(s.name)]
        chosen = specs if include_destructive else [
            s for s in specs if not held(s.name)
        ]
        candidates = [
            Candidate(
                spec.name,
                spec.pairs(),
                spec.note or (
                    f"{len(spec.fields)} field(s) its handler reads: "
                    + ", ".join(k for k, _ in spec.fields)
                    if spec.fields
                    else "From the payload's own string heap, so it is a name "
                    "the client's dispatcher knows."
                ),
            )
            for spec in chosen
        ]
        plan = cls(candidates=candidates or list(GUESSES))
        plan.withheld = [] if include_destructive else withheld
        plan.released = sorted(allow)
        return plan

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
            "released_deliberately": self.released,
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
