"""Strip the byte-order marks the guest's PowerShell left on a finished run.

Windows PowerShell 5.1's `-Encoding utf8` always writes a BOM, and Python's
`json.load` refuses a file that starts with one. Three of the guest agent's
outputs carried it -- `scan.json`, `combined.json` and `pruned_artifacts.json`
-- so the agent's own analysis results were unreadable by the obvious call in
the language the rest of the analyzer is written in. That is fixed at the
writer in `scripts/guest_run_agent.ps1`, but **a corpus already on disk cannot
be fixed by the writer**: the guest self-updates only when booted with no
sample, which is exactly what stops a sweep updating mid-corpus, so every case
produced by a run that was already going keeps its BOMs. This is the other
half.

Why this is a module with tests rather than a script
----------------------------------------------------

`cases/` is not in git. There is no safety net under a corpus, and this is the
only tool in the bench that *edits* one in place. Every other host-side tool
reads. So it is written where it can be tested, driven the same way the sweep
is -- `python -m runcontrol.debom` -- and it refuses far more than it does.

What it will not do
-------------------

**It will not touch a run that is still going.** The manifest must be in a
terminal state and no `runcontrol.sweep` process may be alive. A sweep writes
into `cases/` as it collects, and rewriting a file underneath that is how a
corpus entry ends up half one run and half another.

**It will not change a byte other than the first three.** Every file is proved
three ways before its replacement is kept: the original parses as JSON with
`utf-8-sig`, the replacement parses as JSON with plain `utf-8`, and the two
parse to *equal objects*. The tail bytes are compared directly as well. A file
that fails any of those is left exactly as it was and reported.

**It will not delete the original.** Each file is copied under
`<run>/bom-originals/`, keeping its path, before anything is written. The run
stays one directory that can be moved or archived whole, which is the same
property the sweep gives it.

**It does not rewrite the manifest.** The manifest is the record of what was
attempted and this changed none of that. What it did is its own record, in
`bom_strip.json` beside the manifest, with a SHA-256 for every file before and
after -- so "these bytes were edited after the run, and here is exactly how"
is answerable later rather than inferred from mtimes.

Idempotent: a second pass finds no BOMs and does nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

#: What a UTF-8 byte-order mark looks like on disk.
BOM = b"\xef\xbb\xbf"

#: Written beside manifest.json, never inside cases/.
RECORD_NAME = "bom_strip.json"

#: Originals land here, keeping their path under the run directory.
BACKUP_DIR = "bom-originals"

#: States a run can be in and still be safe to edit. `running` is refused
#: loudly; `refused` and `dry_run` produced no cases to edit.
TERMINAL = ("completed", "aborted")


class DebomRefused(RuntimeError):
    """The run is not in a state where editing its cases is safe."""


def _extended(path) -> str:
    r"""A path Windows will accept past MAX_PATH.

    **Measured on this corpus, not anticipated.** Three samples in,
    `benign-102-v2` already held a 258-character path and the Windows limit is
    260 -- the case name appears *twice* (`cases/<case>/<case>/`, the doubled
    segment the transport produces) and `dynamic_runs/<long run id>/` sits
    under it. Mirroring that tree under `bom-originals/` adds fourteen more
    characters to every one of them, which is precisely the operation that
    overflows, and the failure is a `FileNotFoundError` naming a directory
    that looks like it should exist.

    `\\?\` turns the limit off for a fully-qualified path. Applied to the
    writes this tool performs rather than to the reads: a file it found by
    walking is, by definition, already a path this machine can open.
    """
    if os.name != "nt":
        return str(path)
    resolved = os.path.abspath(str(path))
    if resolved.startswith("\\\\?\\"):
        return resolved
    if resolved.startswith("\\\\"):
        return "\\\\?\\UNC\\" + resolved[2:]
    return "\\\\?\\" + resolved


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class FileResult:
    """One file, and what was done to it or why it was left alone."""

    path: str
    stripped: bool = False
    reason: str = ""
    bytes_before: int = 0
    bytes_after: int = 0
    sha256_before: str = ""
    sha256_after: str = ""
    backup: str = ""


@dataclass
class DebomResult:
    run_id: str
    directory: Path
    dry_run: bool
    files: list[FileResult] = field(default_factory=list)

    @property
    def stripped(self) -> int:
        return sum(1 for f in self.files if f.stripped)

    @property
    def refused(self) -> int:
        return sum(1 for f in self.files if not f.stripped and f.reason)


def find_bommed(root: Path) -> list[Path]:
    """Every .json under `root` whose first three bytes are a BOM.

    Read rather than assumed: the fix at the writer means a later corpus has
    none of these, and a tool that predicted which files *ought* to have one
    would go wrong the first time the agent changed.
    """
    found: list[Path] = []
    for path in sorted(Path(root).rglob("*.json")):
        if not path.is_file():
            continue
        try:
            with open(path, "rb") as handle:
                if handle.read(3) == BOM:
                    found.append(path)
        except OSError:
            continue
    return found


def _sweep_running() -> bool:
    """Whether a controller is alive. Unknown counts as running.

    The conservative direction: refusing to edit a corpus that is in fact
    finished costs a re-run of this tool, and editing one that is still being
    written costs the corpus.
    """
    try:
        import psutil
    except Exception:                                 # noqa: BLE001
        return True
    try:
        for process in psutil.process_iter(["name", "cmdline"]):
            name = process.info.get("name") or ""
            if "python" in name.lower():
                line = " ".join(process.info.get("cmdline") or [])
                if "runcontrol.sweep" in line:
                    return True
        return False
    except Exception:                                 # noqa: BLE001
        return True


def strip_file(path: Path, backup_root: Path, run_directory: Path, *,
               dry_run: bool) -> FileResult:
    """Remove a leading BOM, having proved the rest of the file is unchanged.

    The equality check on the parsed objects is the actual guarantee. Byte
    comparison alone would pass a file that was valid JSON before and is not
    after; parsing alone would pass one whose content silently changed. Both,
    plus the tail bytes, leaves nothing for it to be wrong about.
    """
    result = FileResult(path=str(path))
    try:
        original = path.read_bytes()
    except OSError as error:
        result.reason = f"cannot read: {error.strerror}"
        return result

    result.bytes_before = len(original)
    result.sha256_before = sha256_of_bytes(original)

    if not original.startswith(BOM):
        result.reason = "no BOM"
        return result

    stripped = original[len(BOM):]

    try:
        before = json.loads(original.decode("utf-8-sig"))
    except Exception as error:                        # noqa: BLE001
        result.reason = f"does not parse as JSON even with the BOM: {error}"
        return result
    try:
        after = json.loads(stripped.decode("utf-8"))
    except Exception as error:                        # noqa: BLE001
        result.reason = f"would not parse without the BOM: {error}"
        return result
    if before != after:
        result.reason = "the parsed content would differ; left alone"
        return result
    if original[len(BOM):] != stripped:
        result.reason = "the tail bytes would differ; left alone"
        return result

    result.bytes_after = len(stripped)
    result.sha256_after = sha256_of_bytes(stripped)

    if dry_run:
        return result

    # The original is kept before anything is written, not after. There is no
    # git under cases/.
    try:
        relative = path.relative_to(run_directory)
    except ValueError:
        relative = Path(path.name)
    backup = Path(backup_root) / relative
    os.makedirs(_extended(backup.parent), exist_ok=True)
    shutil.copy2(_extended(path), _extended(backup))
    result.backup = str(backup)

    # A short suffix, and extended-length for the same reason as the backup:
    # the deepest file in this corpus is 258 characters and the temporary name
    # has to fit beside it. Replaced atomically, as the manifest is.
    temporary = path.with_name(path.name + ".tmp")
    with open(_extended(temporary), "wb") as handle:
        handle.write(stripped)
    os.replace(_extended(temporary), _extended(path))

    result.stripped = True
    return result


def debom(run_directory: Path, *, dry_run: bool = False,
          on_event: Callable[[str], None] | None = None) -> DebomResult:
    """Strip BOMs from every JSON in a finished run's cases.

    Raises `DebomRefused` rather than editing anything it is not certain about.
    """
    say = on_event or (lambda _message: None)
    run_directory = Path(run_directory)
    manifest_path = run_directory / "manifest.json"

    if not manifest_path.is_file():
        raise DebomRefused(
            f"no manifest at {manifest_path}. This edits a sweep's cases in "
            f"place and will not do that to a directory it cannot identify as "
            f"a sweep.")
    try:
        # utf-8-sig, not utf-8. `Manifest.save` writes no BOM, so this should
        # never matter -- but a tool whose entire job is that BOMs make files
        # unreadable should not be the thing defeated by one on its own input.
        # Found by a test harness that wrote its manifest from PowerShell.
        document = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except Exception as error:                        # noqa: BLE001
        raise DebomRefused(
            f"{manifest_path} will not parse ({type(error).__name__}). That "
            f"file is the record of what these cases are; nothing is edited "
            f"until it can be read.") from error

    state = document.get("state")
    if state not in TERMINAL:
        raise DebomRefused(
            f"the run is state={state!r}, and this only edits a finished one "
            f"({' or '.join(TERMINAL)}). A sweep writes into cases/ as it "
            f"collects, and rewriting a file underneath that is how a corpus "
            f"entry ends up half one run and half another.")

    if _sweep_running():
        raise DebomRefused(
            "a runcontrol.sweep process is still alive (or the process table "
            "could not be read). The manifest says the run finished, so this "
            "is either another run or a controller still shutting down -- "
            "either way, not while it is going.")

    cases = run_directory / "cases"
    if not cases.is_dir():
        raise DebomRefused(f"no cases directory under {run_directory}")

    run_id = document.get("run_id") or run_directory.name
    result = DebomResult(run_id=run_id, directory=run_directory,
                         dry_run=dry_run)

    targets = find_bommed(cases)
    say(f"{run_id}: {len(targets)} JSON files carry a BOM"
        + (" (dry run)" if dry_run else ""))
    if not targets:
        say("nothing to do")
        return result

    backup_root = run_directory / BACKUP_DIR
    for path in targets:
        outcome = strip_file(path, backup_root, run_directory, dry_run=dry_run)
        result.files.append(outcome)
        if outcome.reason:
            say(f"  left alone: {path.name} -- {outcome.reason}")

    say(f"{'would strip' if dry_run else 'stripped'}: {result.stripped}"
        + (f", left alone: {result.refused}" if result.refused else ""))

    if not dry_run and result.stripped:
        record = {
            "tool": "runcontrol.debom",
            "at": _now(),
            "run_id": run_id,
            "why": ("Windows PowerShell 5.1 writes a BOM with -Encoding utf8 "
                    "and json.load refuses it. Fixed at the writer in "
                    "scripts/guest_run_agent.ps1; this run was produced before "
                    "that reached the guest, which self-updates only when "
                    "booted with no sample."),
            "originals": str(backup_root),
            "stripped": result.stripped,
            "left_alone": result.refused,
            "files": [asdict(f) for f in result.files],
        }
        record_path = run_directory / RECORD_NAME
        text = json.dumps(record, indent=2, sort_keys=False)
        # Same reason as Manifest.save: an explicit newline and bytes, so the
        # file does not change shape depending on which machine wrote it.
        record_path.write_bytes(text.encode("utf-8") + b"\n")
        say(f"record: {record_path}")
        say(f"originals: {backup_root}")

    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m runcontrol.debom",
        description="Strip the byte-order marks PowerShell left on a "
                    "finished run's JSON, having proved nothing else changes.",
        epilog="Only runs against a finished sweep with no controller alive. "
               "Originals are kept under <run>/bom-originals/ and what it did "
               "is recorded in bom_strip.json beside the manifest.",
    )
    parser.add_argument("run_directory", type=Path,
                        help="the sweep directory holding manifest.json")
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would change and edit nothing")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        debom(args.run_directory, dry_run=args.dry_run,
              on_event=lambda message: print(message, flush=True))
    except DebomRefused as error:
        print(f"error: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
