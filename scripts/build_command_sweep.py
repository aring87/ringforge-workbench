"""Build a properly formed command sweep for `ce0d08be...`, from the table.

    python scripts/build_command_sweep.py --out tls-commands.txt

**Why a generator and not a hand-written list.** The client reads a field by
name and gets null when it is missing. On 02 Sep that cost a logon: `Report`
read `Name` from a bare packet, handed null to `ProcessMonitor.Start`, and the
unhandled exception ended the session -- so every command after it went
unsent. A file typed from memory has exactly that failure mode one typo away,
so every field name here is checked against `command_table.tsv`, which was
parsed out of the decompiled dispatcher, and a name that is not in it is an
error rather than a null on the wire.

**Two sources of field names, because the table can only see one level.**
`command_table.tsv` records what `HandlePacket` itself reads. Five commands
read nothing there and delegate to a handler class that reads its own fields:

    ProcessSpy       HandleProcessManager.Run       Command, ProcessId
    Programs         HandlePrograms.Run             Command, Name
    Services         HandleServices.Run             Command, Name
    RegistryRequest  RegistryClientHandler.HM       Action, Path
    DeviceRequest    DeviceManagerHandler.HM        Action, DeviceId

Sent bare, each falls off the end of its own switch and returns without
replying. Four of those five were recorded on 02 Sep as unexplained silence.
They are not silent; they were asked nothing. `HANDLER_FIELDS` below is read
from the IL of those five methods and is the second source.

**Sub-actions decide destructiveness, not command names.** `RegistryRequest`
is a read command with `Action=GetRoots` and a destructive one with
`Action=DeleteKey`; the withheld-by-name set in `beacon_reply` cannot express
that. `REFUSED_SUB_ACTIONS` does, and this refuses to emit one.

**Every value is inert by choice, and each choice is written down.** The guest
is disposable, so this is not about the bench: it is about the run staying
readable. A command that changes what a later command sees -- a clipper timer,
a GDI overlay -- makes the rest of the sweep harder to interpret, so those go
last.

**`CustomGDI` goes last of all, and that is load-bearing.** It paints an
overlay across the desktop and there is no way to stop it: the client accepts
no commands outside a session and does not reconnect after one ends, so
everything ordered after it is unreachable and the payload has to be killed.
On 02 Sep it ran second-to-last, with `Report` behind it, and that ordering is
the only reason the run's headline result was collected before the guest
became unusable.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dynamic_analysis.beacon_reply import (  # noqa: E402
    DESTRUCTIVE,
    parse_command_lines,
)

DEFAULT_TABLE = Path(r"G:\ringforge-artifacts\ce0d08be-payload\command_table.tsv")

#: Fields read by a handler class rather than by `HandlePacket`, from its IL.
#:
#: Read 02 Sep from the payload's own methods, disassembled with
#: `dotnet_meta.py`. The values are the sub-command each switch accepts.
HANDLER_FIELDS: dict[str, dict[str, tuple[str, ...]]] = {
    "ProcessSpy": {"Command": ("List", "Kill", "Pause", "Resume", "Info"),
                   "ProcessId": ()},
    "Programs": {"Command": ("List", "Uninstall"), "Name": ()},
    "Services": {"Command": ("List", "Start", "Stop", "Restart"), "Name": ()},
    "RegistryRequest": {"Action": ("GetRoots", "GetSubKeys", "GetValues",
                                   "ModifyValue", "DeleteValue", "CreateKey",
                                   "DeleteKey", "RenameKey", "CopyKey"),
                        "Path": ()},
    "DeviceRequest": {"Action": ("GetDevices", "RefreshDevices",
                                 "EnableDevice", "DisableDevice",
                                 "UpdateDriver"),
                      "DeviceId": ()},
}

#: Accessor types for handler-level fields, where the table has none.
HANDLER_TYPES: dict[tuple[str, str], str] = {
    ("ProcessSpy", "ProcessId"): "Integer",
}

#: Accessor type -> the tag its value must carry in the commands file.
#:
#: `Integer` is the one that has already cost a session. `GetAsInteger` is
#: `BitConverter.ToInt32` over the raw value bytes, so digits are not an
#: integer and a two-byte array throws. `ByteArray` is the same argument,
#: made before it is paid for.
REQUIRED_TAG = {"Integer": "int:", "ByteArray": "b64:"}

#: Sub-actions this refuses to emit, whatever is asked for.
#:
#: Each of these changes the guest in a way that outlives the command, and none
#: is reachable through the withheld-by-name set: their command names are
#: read-only in every other use.
REFUSED_SUB_ACTIONS: dict[str, frozenset[str]] = {
    "ProcessSpy": frozenset({"Kill"}),
    "Programs": frozenset({"Uninstall"}),
    "Services": frozenset({"Start", "Stop", "Restart"}),
    "RegistryRequest": frozenset({"ModifyValue", "DeleteValue", "CreateKey",
                                  "DeleteKey", "RenameKey", "CopyKey"}),
    "DeviceRequest": frozenset({"EnableDevice", "DisableDevice",
                                "UpdateDriver"}),
}

#: A 1x1 transparent PNG, base64. The smallest thing that is a real image.
TINY_PNG = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
    "YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)

#: Obviously-fake wallet addresses, the same rule `jsonrpc_answer` set: a real
#: address in a clipper's config proves nothing except that the bench was
#: pointed somewhere it should not have been.
TRACER = "ringforge-tracer-not-a-wallet"

#: Group 1 -- the five whose fields the table cannot see, plus the one whose
#: 02 Sep result was never actually measured.
SUB_DISPATCHERS: list[tuple[str, list[tuple[str, str]], str]] = [
    ("ProcessSpy", [("Command", "List")],
     "the sub-command its handler switches on; bare it matched nothing"),
    ("Programs", [("Command", "List")],
     "same shape as ProcessSpy, read from HandlePrograms.Run"),
    ("Services", [("Command", "List")],
     "a sixth sub-dispatcher the table records as taking no fields"),
    ("RegistryRequest", [("Action", "GetRoots")],
     "the read action; GetRoots needs no Path"),
    ("RegistryRequest", [("Action", "GetSubKeys"),
                         ("Path", "HKEY_CURRENT_USER\\Software")],
     "the second read action, which does need a Path"),
    ("DeviceRequest", [("Action", "GetDevices")],
     "the read action; enable/disable/update are refused here"),
    ("Preview", [],
     "no fields. Re-asked because its 02 Sep silence was unmeasured, not "
     "observed: it was the last command of a sweep running one frame behind"),
]

#: Group 2 -- the dispatcher-level field takers, with inert values.
#:
#: The comment on each is the reason for the value, not for the command.
SAFE_FIELDS: list[tuple[str, list[tuple[str, str]], str]] = [
    ("Hosts", [("Content", "123ratonpro")],
     "the hardcoded magic that selects the READ path. Any other Content is "
     "base64-decoded and written over the hosts file"),
    ("StartShell", [],
     "measured 02 Sep: Shell answered nothing because CmdShell opens by "
     "returning when there is no live shell process. This makes one"),
    ("Shell", [("Command", "ver")],
     "prints a version banner into the session StartShell made"),
    ("CommandPrompt", [("Command", "ver")],
     "same, down the other of the two command paths"),
    ("Execute", [("Type", "Batch"), ("Code", "rem ringforge-probe")],
     "a batch script whose only line is a comment"),
    ("Compiler", [("Type", "cs"), ("Code", "class R { }")],
     "measured 02 Sep: a Type that is neither vb nor cs does NOT fall "
     "through, it compiles as C#. So this is the smallest valid C# rather "
     "than a comment, which produced a compiler error"),
    ("FileSearch", [("Extension", ".ringforge-none")],
     "an extension nothing on the guest has"),
    ("Notepad", [("Title", "ringforge"), ("Content", "ringforge probe")],
     "writes one temp file and opens it"),
    ("Notify", [("title", "ringforge"), ("content", "probe")],
     "a balloon tip. Lower-case keys, which is how the case reads them"),
    ("MsgBox", [("Title", "ringforge"), ("Message", "probe"),
                ("Icon", "None"), ("Options", "OK")],
     "a dialog the operator dismisses"),
    ("TTS", [("Text", "ringforge probe")],
     "speaks one phrase"),
    ("Volume", [("Volume", "int:50")],
     "four raw bytes, not the characters 50. The text form ended the "
     "02 Sep sweep here, at its first integer field"),
    ("Webcam", [("Cam", "int:0")],
     "GetWebcams already answered 'No cameras found', so this exercises the "
     "integer field and should return an error"),
    ("Website", [("URL", "http://127.0.0.1:1/")],
     "Process.Start on a dead loopback port. It opens a browser window"),
    ("StartProxy", [("Port", "int:18080")],
     "a SOCKS5 listener inside the contained guest"),
    ("ClosePort", [("Port", "int:65533")],
     "kills the process owning the port. 65533 owns nothing -- NEVER 7372, "
     "which is this session"),
    ("Draw", [("data", TINY_PNG), ("w", "int:1"), ("h", "int:1")],
     "the smallest real image"),
    ("Clipboard", [("Text", "ringforge-clipboard-probe")],
     "overwrites the guest clipboard, which the operator's own staging "
     "command was sitting in on 02 Sep"),
    ("Clipper", [("BTC", TRACER), ("ETH", TRACER), ("LTC", TRACER),
                 ("XMR", TRACER), ("SOLANA", TRACER)],
     "starts a 2-second clipboard-rewrite timer that runs for the rest of the "
     "session, so it goes after everything that reads the clipboard"),
]

#: Group 3 -- byte arrays, then the effects that outlive the command.
RISKY_TAIL: list[tuple[str, list[tuple[str, str]], str]] = [
    ("Chat", [],
     "measured 02 Sep: ChatMessage answered 'The chat is closed, nice try...' "
     "until a chat exists. The third precondition of its kind, after the "
     "sub-dispatchers and the shell"),
    ("ChatMessage", [("Message", "ringforge probe"),
                     ("img", "b64:cmluZ2Zvcmdl")],
     "the img bytes are only base64-encoded, never parsed as an image"),
    ("PlayAudio", [("Audio", "b64:cmluZ2Zvcmdl")],
     "measured 02 Sep: answers Success and then 'Invalid MP3 file - no MP3 "
     "Frames Detected'. The bytes arrive as bytes; it wants an MP3"),
    ("Report", [("Name", "explorer")],
     "measured 02 Sep and SAFE with a Name: it answers an Alert naming the "
     "process it detected. Bare, its null Name ends the session, which is why "
     "FATAL_WITHOUT refuses that shape rather than the command"),
    ("CustomGDI", [("Image", TINY_PNG)],
     "LAST, and it must stay last. It paints a persistent overlay and there "
     "is no way to stop it: the client takes no commands outside a session "
     "and does not reconnect after one ends, so the payload has to be killed. "
     "On 02 Sep it ran second-to-last and cost the guest"),
]


def load_table(path: Path) -> dict[str, dict[str, str]]:
    """Command -> {field: accessor type}, from the parsed table.

    The type is kept rather than discarded. It was in the table from the
    day it was parsed -- `Volume:Integer`, `Port:Integer`,
    `Audio:ByteArray` -- and nothing read it, so the 02 Sep sweep sent
    `Volume=50` as two characters of text and `BitConverter.ToInt32` threw
    on the two-byte array. The type was on disk the whole time.
    """
    table: dict[str, dict[str, str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        name = parts[0].strip()
        fields: dict[str, str] = {}
        if len(parts) > 1 and parts[1].strip():
            for entry in parts[1].split(","):
                key, _, kind = entry.strip().partition(":")
                if key.strip():
                    fields[key.strip()] = kind.strip() or "String"
        table[name] = fields
    return table


def check(
    groups: list[tuple[str, list[tuple[str, str]], str]],
    table: dict[str, dict[str, str]],
) -> list[str]:
    """Every emitted field must be read by something, and carry its type."""
    problems: list[str] = []
    for name, fields, _ in groups:
        if name not in table:
            problems.append(f"{name}: not a command in the table")
            continue
        handler = HANDLER_FIELDS.get(name, {})
        known = set(table[name]) | set(handler)
        for key, value in fields:
            if key not in known:
                problems.append(
                    f"{name}: field {key!r} is read by nothing "
                    f"(table has {sorted(table[name]) or 'none'}, "
                    f"handler has {sorted(handler) or 'none'})"
                )
                continue

            kind = (table[name].get(key)
                    or HANDLER_TYPES.get((name, key), "String"))
            tag = REQUIRED_TAG.get(kind)
            if tag and not value.startswith(tag):
                problems.append(
                    f"{name}: field {key!r} is {kind} and must be sent as "
                    f"{tag}<value>, not the text {value!r}. The value is "
                    "read as raw bytes, and text of the wrong length "
                    "throws inside the client"
                )

            refused = REFUSED_SUB_ACTIONS.get(name, frozenset())
            if value in refused:
                problems.append(
                    f"{name}: sub-action {value!r} is refused -- it changes "
                    "the guest in a way the command name does not admit to"
                )
    return problems


def render(
    groups: list[tuple[str, str, list[tuple[str, str]], str]],
) -> tuple[list[str], list[str]]:
    """The file, and which of its lines the listener will withhold.

    Everything is emitted as a real line, a withheld name included. The
    withholding decision belongs to the listener, which owns `DESTRUCTIVE` and
    `--allow` and prints what it declined. Making it here as well would put one
    rule in two places, and `--allow Report` would then fail against a sweep
    that had already commented `Report` out.
    """
    lines = [
        "# Properly formed command sweep for ce0d08be..., generated by",
        "# scripts/build_command_sweep.py. Do not hand-edit: every field name",
        "# here was checked against command_table.tsv and the handler IL.",
        "#",
        "# One TLS session walks this list in order. The client does not",
        "# reconnect after a session ends and its ONLOGON task only relaunches",
        "# it at the next logon, so a sweep that kills it costs a logon.",
    ]
    withheld: list[str] = []
    for heading, name, fields, note in groups:
        if heading:
            lines.extend(["", f"# --- {heading}"])
        if name in DESTRUCTIVE:
            withheld.append(name)
        parts = [name] + [f"{key}={value}" for key, value in fields]
        row = "\t".join(parts)
        if note:
            row += f"\t# {note}"
        lines.append(row)
    return lines, withheld


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--table", type=Path, default=DEFAULT_TABLE,
                        help=f"command_table.tsv (default: {DEFAULT_TABLE})")
    parser.add_argument("--out", type=Path, help="write here instead of stdout")
    args = parser.parse_args(argv)

    table = load_table(args.table)

    everything = SUB_DISPATCHERS + SAFE_FIELDS + RISKY_TAIL
    problems = check(everything, table)
    if problems:
        for problem in problems:
            print(f"REFUSED: {problem}", file=sys.stderr)
        return 2

    groups: list[tuple[str, str, list[tuple[str, str]], str]] = []
    for heading, block in (
        ("fields the table cannot see: five sub-dispatchers, and one re-ask",
         SUB_DISPATCHERS),
        ("dispatcher-level field takers, inert values", SAFE_FIELDS),
        ("preconditions and byte arrays, then the one with no way back",
         RISKY_TAIL),
    ):
        for index, (name, fields, note) in enumerate(block):
            groups.append((heading if index == 0 else "", name, fields, note))

    lines, withheld = render(groups)
    text = "\n".join(lines) + "\n"

    # The file has to parse as the thing that will read it, or the run finds
    # out at the socket.
    specs = parse_command_lines(lines)
    print(f"{len(specs)} command(s), "
          f"{sum(1 for s in specs if s.fields)} carrying fields", file=sys.stderr)
    if withheld:
        print(f"{len(withheld)} of which the listener withholds by default: "
              f"{', '.join(withheld)}", file=sys.stderr)
        print("  Send one anyway with --allow NAME, and only if the run is "
              "designed to measure it", file=sys.stderr)

    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
