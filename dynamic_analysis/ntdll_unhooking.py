"""Processes that open `ntdll.dll` *as a file*, which is how unhooking starts.

Every process on Windows has `ntdll` mapped -- the loader does it before any
user code runs, and it raises `Load Image`, not `CreateFile`. A process that
goes on to **open the file** is asking for a second, clean copy off disk, and
there is one common reason to want one: the copy in memory has had its syscall
stubs patched by an EDR or a sandbox, and overwriting `.text` with the on-disk
bytes removes the hooks.

The sample this pipeline has run eleven times does exactly that. Stage 3 maps a
clean `ntdll` off disk and calls `Nt*` stubs out of its own copy, which is why
hooking export addresses saw nothing and the emulator went quiet at 87 API
calls. It also does its own `Wow64Transition` fixup at `0x202f457` -- the step
that makes self-unhooking work on a real machine.

**This is collection, not scoring, and the distinction is deliberate.** Reading
`ntdll.dll` off disk is not by itself malicious: debuggers, symbol handlers,
version-info readers, integrity checkers and installers all open system DLLs,
and this pass has never run against a live capture. Naming a detector before
measuring what it fires on is the mistake this project has now made and
corrected several times -- the `registry_create` count going 5 to 140 the moment
a marker was repaired, and the ATT&CK mapping deliberately withheld from gap 4b
for the same reason. So: attributed by lineage, background counted rather than
dropped, nothing scored, and a `collection_available` that refuses to let an
uncollected run read as a clean one.

What makes it worth having anyway is the *pairing*, the same argument as the
spawn re-dump. A hollowing target opening `ntdll.dll` is a different claim from
any process doing it: nothing legitimate starts `RegSvcs.exe` and has it read
`ntdll` off disk.
"""

from __future__ import annotations

from typing import Any

from dynamic_analysis.crash_evidence import is_hollowing_target

#: Procmon operations that open a file. `CreateFile` is the open, whatever the
#: disposition -- Windows names it that even for a read of an existing file.
#:
#: `Load Image` is deliberately absent. That is the loader mapping a module, it
#: happens for `ntdll` in every process that has ever run, and counting it would
#: produce a detector that fires on the entire machine.
FILE_OPEN_OPERATIONS = {"createfile"}

FILE_OPEN_CATEGORY = "file_create"

#: `(filename, why_it_matters)`. Matched against the last path component so
#: `\??\ntdll.dll`, `C:\Windows\System32\ntdll.dll` and the SysWOW64 copy are
#: one marker rather than three.
#:
#: `ntdll` is the emphatic one: it is where the syscall stubs live, so it is
#: what an unhooking routine needs. The others are included because the same
#: technique is routinely applied to them, and because a pass that only ever
#: looked for one filename could not tell "this sample unhooks ntdll only" from
#: "this pass only looks for ntdll".
UNHOOK_TARGETS = (
    ("ntdll.dll", "syscall stubs -- the usual unhooking target"),
    ("kernel32.dll", "Win32 layer, hooked by most user-mode EDR"),
    ("kernelbase.dll", "Win32 layer, hooked by most user-mode EDR"),
    ("advapi32.dll", "token and registry API surface"),
    ("user32.dll", "input API surface"),
)

PRIMARY_TARGET = "ntdll.dll"

#: Paths that are a *different* file with the same name. A dropped or copied
#: `ntdll.dll` in a user-writable directory is its own finding and belongs to
#: the dropped-file pass; treating it as unhooking would double-count one act
#: and describe it wrongly.
SYSTEM_DIRECTORY_MARKERS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\systemroot\\system32\\",
    "\\systemroot\\syswow64\\",
)

#: `\??\ntdll.dll` and bare `ntdll.dll` name the system copy by NT path or by
#: search order, with no directory to check.
_UNQUALIFIED_PREFIXES = ("\\??\\", "")


def _lower(value: object) -> str:
    return str(value or "").strip().lower()


def is_file_open(event: dict[str, Any]) -> bool:
    if str(event.get("category", "")) == FILE_OPEN_CATEGORY:
        return True
    return _lower(event.get("operation")) in FILE_OPEN_OPERATIONS


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def classify_unhook_target(path: object) -> dict[str, str] | None:
    """The system DLL a path names, or ``None``.

    Returns ``None`` for a same-named file outside a system directory: that is a
    dropped payload, not an unhooking read, and the dropped-file pass owns it.
    """
    # Normalise separators once, here. Doing it only in `_basename` left the
    # directory check below testing backslash markers against a path that still
    # had forward slashes, so `C:/Windows/System32/ntdll.dll` classified as a
    # dropped file -- the marker-matching bug this module's docstring warns
    # about, reintroduced two functions away from the warning.
    lowered = _lower(path).replace("/", "\\")
    if not lowered:
        return None

    name = _basename(lowered)
    for target, reason in UNHOOK_TARGETS:
        if name != target:
            continue
        qualified = lowered != name and not lowered.startswith("\\??\\")
        if qualified and not any(m in lowered for m in SYSTEM_DIRECTORY_MARKERS):
            return None
        return {"module": target, "reason": reason,
                "primary": "yes" if target == PRIMARY_TARGET else ""}
    return None


def _event_pid(event: dict[str, Any]) -> int | None:
    try:
        return int(event.get("pid"))
    except (TypeError, ValueError):
        return None


def collect_ntdll_unhooking(
    events: list[dict[str, Any]],
    descendant_pids: set[int] | None = None,
) -> dict[str, Any]:
    """System DLLs the sample's own processes opened as files.

    ``descendant_pids`` is the sample's tree, resolved the way every other pass
    resolves it. ``None`` means lineage could not be resolved and everything is
    counted; an empty set means the tree resolved to nothing and nothing is
    attributed.

    Opens by processes outside the tree are counted rather than discarded. That
    background number is the only thing that will say whether this detector is
    worth scoring: if Windows opens `ntdll.dll` two hundred times a run on its
    own, the signal is worthless however good the reasoning behind it was.
    """
    opens_in_stream = 0
    sample_opens = 0
    background_opens = 0

    hits: list[dict[str, Any]] = []
    background_hits: list[dict[str, Any]] = []

    for event in events:
        if not is_file_open(event):
            continue
        opens_in_stream += 1

        classified = classify_unhook_target(event.get("path"))
        if classified is None:
            continue

        pid = _event_pid(event)
        mine = descendant_pids is None or (pid is not None and pid in descendant_pids)

        entry = {
            "process": event.get("process_name", ""),
            "pid": pid,
            "module": classified["module"],
            "reason": classified["reason"],
            "path": event.get("path", ""),
            "result": event.get("result", ""),
            "timestamp": event.get("timestamp", ""),
            "hollowing_target": is_hollowing_target(event.get("process_name")),
        }
        if mine:
            sample_opens += 1
            hits.append(entry)
        else:
            background_opens += 1
            background_hits.append(entry)

    primary = [h for h in hits if h["module"] == PRIMARY_TARGET]
    in_target = [h for h in primary if h["hollowing_target"]]

    return {
        # Whether file opens existed in the stream at all. A zero from a capture
        # that recorded no CreateFile is a statement about the config.
        "collection_available": opens_in_stream > 0,
        "attributed_by_lineage": descendant_pids is not None,
        "scored": False,
        "counts": {
            "file_opens_in_stream": opens_in_stream,
            "system_dll_opens_by_sample": sample_opens,
            "ntdll_opens_by_sample": len(primary),
            # The emphatic subset, by the rule the crash evidence and the carver
            # already use.
            "ntdll_opens_in_hollowing_target": len(in_target),
            "system_dll_opens_by_others": background_opens,
        },
        "opens": hits[:50],
        # Kept, not dropped: this is the false-positive baseline, and until a
        # live run produces one nothing here should be scored.
        "background_opens": background_hits[:20],
        "modules": sorted({h["module"] for h in hits}),
    }


def empty_ntdll_unhooking(reason: str = "not collected") -> dict[str, Any]:
    return {
        "collection_available": False,
        "attributed_by_lineage": False,
        "scored": False,
        "note": reason,
        "counts": {
            "file_opens_in_stream": 0,
            "system_dll_opens_by_sample": 0,
            "ntdll_opens_by_sample": 0,
            "ntdll_opens_in_hollowing_target": 0,
            "system_dll_opens_by_others": 0,
        },
        "opens": [],
        "background_opens": [],
        "modules": [],
    }
