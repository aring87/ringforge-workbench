"""Copying a case folder off a guest that ran malware.

`untrusted.py` answers whether a *name* may become a path component. This
answers the rest of it: walking a tree nobody trustworthy wrote, and landing
its contents somewhere on the host without being led out of the destination.

**The guest is powered off before any of this runs.** That is the controller's
job, not this module's, but it is the assumption everything here is written
against and it is what removes the interesting race: a host process parsing a
path a *live* guest controls is racing an attacker who can rewrite it between
the `stat` and the `open`. Against an inert disk image, a check that passed
stays passed.

Even so, this does not trust what it walks:

* **Names are checked, never rewritten.** A sanitised name silently disagrees
  with the manifest the guest wrote, and a case whose files have been renamed
  is worse than a case that reported a refusal.
* **Nothing is followed.** A symlink, junction or any other reparse point is
  refused rather than resolved. `copytree` without `symlinks=False` is how a
  directory pointing at `C:\\Windows` becomes a host copy of `C:\\Windows`, and
  a junction is not obvious from a listing.
* **Every destination is re-checked after joining.** Component checks should
  make this impossible, so it is defence in depth for the case where they have
  a hole -- which is the case worth designing for.
* **Caps are refusals, not truncations.** A file over the cap is skipped
  whole and recorded. A partial artifact that looks complete is the failure
  mode this project exists to avoid.

Everything refused is returned. A silent skip would make a thin case look like
a quiet sample, which is the same mistake as a rule set that never compiled
reading as a clean scan.
"""

from __future__ import annotations

import os
import shutil
import stat as stat_module
from dataclasses import dataclass, field
from pathlib import Path

from runcontrol.untrusted import check_component

#: Ceilings, chosen from what a real case holds rather than from round numbers.
#: A Procmon PML for a 240-second run is the biggest single thing here, and
#: memory dumps of a process tree are the bulk of the total.
@dataclass(frozen=True)
class Limits:
    #: One file. A 2 GB PML is plausible; 8 GB is a guest filling the disk.
    max_file_bytes: int = 4 * 1024 * 1024 * 1024

    #: The whole case. Reached means the sweep stops importing, not that it
    #: imports a truncated case quietly.
    max_total_bytes: int = 24 * 1024 * 1024 * 1024

    #: Enough for a case with per-process dumps and a parsed Procmon export.
    max_files: int = 20_000

    #: `cases/<name>/dynamic_analysis/memory/<pid>/...` is four. Sixteen is
    #: generous and still nowhere near MAX_PATH once joined to a host root.
    max_depth: int = 16


@dataclass(frozen=True)
class Refusal:
    """One thing not copied, and why.

    `path` is as the guest presented it, relative to the source root, because
    the record has to be comparable with what the guest wrote.
    """

    path: str
    reason: str


@dataclass
class Collected:
    files: int = 0
    directories: int = 0
    total_bytes: int = 0
    refusals: list[Refusal] = field(default_factory=list)

    #: A cap stopped the walk. The case on disk is incomplete, and any verdict
    #: read from it is describing part of a run.
    truncated: bool = False

    @property
    def complete(self) -> bool:
        return not self.truncated and not self.refusals

    def summary(self) -> str:
        parts = [f"{self.files} files", f"{self.total_bytes / 1024**2:.1f} MiB"]
        if self.refusals:
            parts.append(f"{len(self.refusals)} refused")
        if self.truncated:
            parts.append("TRUNCATED")
        return ", ".join(parts)


def _is_reparse_point(entry: os.DirEntry) -> bool:
    """Whether `entry` is a link of any kind, without following it.

    `is_symlink()` alone is not enough on Windows: a directory junction is a
    reparse point that `is_symlink` reports False for on some Python versions,
    and a junction to `C:\\Windows` walked as a directory copies `C:\\Windows`.
    The attribute bit is the reliable answer.
    """
    if entry.is_symlink():
        return True
    try:
        attributes = entry.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        # Not Windows, or the entry vanished. Non-Windows has no junctions and
        # `is_symlink` above already covers its links.
        return False
    return bool(attributes & stat_module.FILE_ATTRIBUTE_REPARSE_POINT)


def collect_case(source: Path, destination: Path,
                 limits: Limits | None = None) -> Collected:
    """Copy the tree at `source` into `destination`, refusing what is unsafe.

    `source` is the case folder as the guest wrote it -- a mounted results
    disk, or a share the guest could write. `destination` is on the host and is
    created. Returns what was taken and what was not.
    """
    limits = limits or Limits()
    source = Path(source)
    destination = Path(destination)

    if not source.is_dir():
        raise NotADirectoryError(f"no case folder at {source}")

    destination.mkdir(parents=True, exist_ok=True)
    # Resolved once, so the containment check below compares real paths rather
    # than ones that still contain a link to somewhere else.
    root = destination.resolve(strict=True)

    result = Collected()
    # (source directory, relative path as the guest wrote it, depth)
    queue: list[tuple[Path, str, int]] = [(source, "", 0)]

    while queue:
        here, relative, depth = queue.pop(0)

        if depth > limits.max_depth:
            result.refusals.append(
                Refusal(relative or ".", f"deeper than {limits.max_depth}"))
            continue

        try:
            entries = sorted(os.scandir(here), key=lambda e: e.name)
        except OSError as error:
            result.refusals.append(
                Refusal(relative or ".", f"cannot list: {error.strerror}"))
            continue

        for entry in entries:
            shown = f"{relative}/{entry.name}" if relative else entry.name

            verdict = check_component(entry.name)
            if not verdict:
                result.refusals.append(Refusal(shown, verdict.reason))
                continue

            if _is_reparse_point(entry):
                # Not followed and not recreated. A link in a case folder is
                # either a mistake or an attack, and neither is evidence.
                result.refusals.append(
                    Refusal(shown, "symlink, junction or reparse point"))
                continue

            target = root / relative / entry.name if relative else root / entry.name
            # Defence in depth: the component check should make escape
            # impossible, so this catches the hole it does not know it has.
            try:
                if not target.resolve().is_relative_to(root):
                    result.refusals.append(
                        Refusal(shown, "resolves outside the destination"))
                    continue
            except OSError as error:
                result.refusals.append(
                    Refusal(shown, f"cannot resolve: {error.strerror}"))
                continue

            if entry.is_dir(follow_symlinks=False):
                target.mkdir(parents=True, exist_ok=True)
                result.directories += 1
                queue.append((Path(entry.path), shown, depth + 1))
                continue

            if not entry.is_file(follow_symlinks=False):
                # Sockets, devices, anything else. Refused by kind rather than
                # attempted and reported as an error.
                result.refusals.append(Refusal(shown, "not a regular file"))
                continue

            try:
                size = entry.stat(follow_symlinks=False).st_size
            except OSError as error:
                result.refusals.append(
                    Refusal(shown, f"cannot stat: {error.strerror}"))
                continue

            if size > limits.max_file_bytes:
                result.refusals.append(Refusal(
                    shown,
                    f"{size} bytes exceeds the {limits.max_file_bytes} cap"))
                continue

            if result.files >= limits.max_files:
                result.refusals.append(
                    Refusal(shown, f"more than {limits.max_files} files"))
                result.truncated = True
                return result

            if result.total_bytes + size > limits.max_total_bytes:
                result.refusals.append(Refusal(
                    shown, f"case exceeds the {limits.max_total_bytes} total cap"))
                result.truncated = True
                return result

            try:
                # `copyfile`, not `copy2`: metadata from a guest that ran
                # malware is not worth carrying, and timestamps from it are
                # actively misleading in a case folder.
                shutil.copyfile(entry.path, target, follow_symlinks=False)
            except OSError as error:
                result.refusals.append(
                    Refusal(shown, f"copy failed: {error.strerror}"))
                continue

            result.files += 1
            result.total_bytes += size

    return result
