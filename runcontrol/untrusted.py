"""Validating a name the guest chose.

**After a detonation the case folder is attacker-influenced input.** It was
written by a machine that ran malware, and the host is about to walk it, build
paths from its filenames and hand those to parsers written for files this tool
produced. Same code, different threat model.

Nothing here touches the filesystem. It answers one question -- may this name
become a path component on the host -- so the rules can be tested exhaustively
without a guest, and so the collector has one place to point at when it refuses
something.

**Windows is the whole difficulty.** Traversal is the obvious attack and the
least interesting one. The cases that actually surprise people:

* `C:foo` is *drive-relative*: it means "foo relative to the current directory
  on C:", which is not `C:\foo` and is not under the destination either.
* `CON`, `NUL`, `COM1` and friends are device names in every directory, and
  `CON.txt` is still `CON`. Opening one does not create a file.
* A trailing dot or space is silently stripped by the Win32 layer, so
  `evil.txt ` and `evil.txt` are the same file. A checker that compares the
  decorated name against a list sees two different strings; the filesystem
  sees one.
* An alternate data stream rides on a colon: `report.json:hidden` writes bytes
  no directory listing will show.
* Unicode normalisation and case-folding both collapse names, so a refusal
  list matched literally can be walked around.

The rule is allow-list, not deny-list. A name is rejected unless it is made of
characters we are prepared to defend.

**The allow-list is ASCII, and that is a decision with a consequence.** A
sample that drops a file with a Cyrillic or CJK name has a legitimate artifact
whose name this refuses. That is the right default for the *case folder*, whose
every filename this tool chose. It is the wrong default for dropped-file
artifacts, whose names the sample chose and which are evidence in themselves.
Those want storing under a content-hash name with the original kept as
metadata, which is what a sandbox that collects them should do -- so the
refusal never has to be a silent loss. Not yet built; recorded so the next
reader does not widen this list instead.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

#: Characters a component may contain. Everything else is refused rather than
#: escaped or replaced -- a rewritten name silently disagrees with the manifest
#: the guest wrote, and a case whose files have been renamed is worse than a
#: case that reported a refusal.
_ALLOWED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]*$")

#: Reserved in every directory on Windows, with or without an extension.
_DEVICE_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
    + [f"COM{d}" for d in "123456789"]
    + [f"LPT{d}" for d in "123456789"]
)

#: Long enough for any name this tool writes; short enough that a path built
#: from several of them stays clear of MAX_PATH on a default install. The
#: `capa-rules` tree blew that limit at 132 characters relative, so the ceiling
#: is not theoretical.
MAX_COMPONENT = 100


@dataclass(frozen=True)
class Verdict:
    """Why a name was refused, or that it was not."""

    ok: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


ACCEPT = Verdict(True)


def _refuse(reason: str) -> Verdict:
    return Verdict(False, reason)


def check_component(name: str) -> Verdict:
    """Whether `name` may be used as a single path component on the host."""
    if not name:
        return _refuse("empty name")

    # Traversal first, so it is *named* as traversal. Ordering matters for the
    # reason and not for the outcome: the strip check below also rejects `..`,
    # but it reports a trailing dot, and a refusal whose reason points at the
    # wrong thing is the `tools/` message that named a directory it did not
    # mean.
    if name in (".", ".."):
        return _refuse("relative traversal")

    # The Win32 layer strips these, so every check after it would otherwise be
    # inspecting a string the filesystem will not use.
    if name != name.rstrip(". "):
        return _refuse("trailing dot or space is stripped by Windows")

    if len(name) > MAX_COMPONENT:
        return _refuse(f"longer than {MAX_COMPONENT} characters")

    # NFKC first: distinct code points can fold to the same name on disk, so a
    # literal comparison against the rules below is not enough on its own.
    if unicodedata.normalize("NFKC", name) != name:
        return _refuse("not Unicode NFKC normalised")

    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        return _refuse("control character")

    if ":" in name:
        return _refuse("colon: drive-relative path or alternate data stream")

    if "/" in name or "\\" in name:
        return _refuse("path separator inside a component")

    # Device names are reserved with any extension, so test the stem.
    if name.split(".")[0].upper() in _DEVICE_NAMES:
        return _refuse("reserved Windows device name")

    if not _ALLOWED.match(name):
        return _refuse("character outside the allowed set")

    return ACCEPT


def check_relative_path(path: str) -> Verdict:
    """Whether `path` is a safe *relative* path: every component, and no root.

    Takes the path as the guest wrote it, separators and all, because that is
    the form a manifest carries.
    """
    if not path:
        return _refuse("empty path")

    if path[:1] in ("/", "\\"):
        return _refuse("absolute path")

    # \\?\\ and \\server\\share, and the extended forms.
    if path[:2] in ("\\\\", "//"):
        return _refuse("UNC or extended-length path")

    # `C:` anywhere means drive-relative or absolute; `check_component` also
    # catches it, but saying so about the whole path gives a better reason.
    if re.match(r"^[A-Za-z]:", path):
        return _refuse("drive-qualified path")

    components = [c for c in re.split(r"[/\\]", path) if c != ""]
    if not components:
        return _refuse("no usable components")

    for component in components:
        verdict = check_component(component)
        if not verdict:
            return _refuse(f"{component!r}: {verdict.reason}")

    return ACCEPT
