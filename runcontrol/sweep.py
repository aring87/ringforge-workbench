"""Many samples, and a written record of what was *attempted*.

`loop.run_one` detonates one sample and never raises, which is most of a
sweep. What it does not give you is the thing a corpus measurement actually
needs: **a list, written before the first sample runs, of every sample this
sweep intended to process.** Without it an absent result is merely missing.
With it, an absent result is a row that says `pending`, and the difference
between "the controller never got to it" and "it ran and observed nothing" is
readable rather than reconstructed from timestamps.

That distinction is the same one the scoring model is built on, one level up.
A run that observed nothing must not read as a quiet sample; a sample that was
never attempted must not read as a sample that produced no findings. A
confusion matrix built from a directory listing of `cases/` silently drops the
second kind, and it drops exactly the samples a broken bench failed on --
which is a bias towards whatever the bench happens to handle.

So the manifest is written **before** anything is detonated, rewritten after
every attempt, and closed at the end. If the controller is killed mid-sweep,
the file on disk already names every sample that was planned.

What this module deliberately does not do
-----------------------------------------

**It does not retry by default.** A void run is a measurement, and silently
retrying until something works biases the corpus towards samples that happen
to cooperate on a second boot. Retries exist (`attempts`), they fire only on a
*void* outcome, and every attempt lands in the manifest as its own row -- so a
corpus entry that needed three goes is visible as one that needed three goes.

**It does not rename anything to avoid a collision.** `run_one` derives a case
name from the sample's stem, so `thing.exe` and `thing.dll` in the same
directory both want `cases/thing`, and the second would overwrite the first
with no error anywhere. Those are found during enumeration and recorded as
skipped, with both paths named. Renaming them apart would put a name in the
corpus that is not the operator's name for the sample, and a corpus you cannot
join back to its labels is not a corpus.

**It does not run two guests.** See `guest.py`: two guests on one host-only
adapter can see each other, and a sample that scans its subnet lands traffic
in the other run's capture attributed to the wrong sample.

Host-testable
-------------

Nothing here needs a hypervisor to exercise. `--dry-run` enumerates, hashes,
finds the collisions and writes a complete manifest with every sample
`not_attempted`, which is also how you check a corpus directory before
committing a machine to it for eight hours.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from runcontrol.collect import Limits
from runcontrol.guest import Guest, GuestError, check_ready
from runcontrol.loop import Outcome, run_one
from runcontrol.untrusted import check_component

#: Bumped when a field changes meaning, not when one is added. A consumer
#: joining labels to results has to be able to tell whether it understands the
#: file, and "the keys I need are present" is not the same question.
SCHEMA = 1

#: The manifest's name inside the sweep directory. Fixed, because the first
#: thing anyone does with a sweep is look for it.
MANIFEST_NAME = "manifest.json"

#: Sample states. A row is in exactly one of these at any time, and the file
#: is rewritten often enough that the on-disk state is the live one.
PENDING = "pending"            # planned, not yet reached
RUNNING = "running"            # the controller is on it now
ATTEMPTED = "attempted"        # run_one returned, see `attempts` for what it said
SKIPPED = "skipped"            # refused during enumeration, never delivered
NOT_ATTEMPTED = "not_attempted"  # the sweep ended before reaching it


def _now() -> str:
    """UTC, ISO 8601, seconds resolution.

    UTC rather than local because a corpus outlives a timezone, and this
    bench's runs already span a clock change.
    """
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_of(path: Path, chunk: int = 1024 * 1024) -> str:
    """The sample's hash, which is how a manifest row joins to a label.

    Chunked because a corpus sample can be an installer, and because reading a
    few hundred megabytes into memory per sample for no reason is the kind of
    thing that only shows up on the sample that is 4 GB.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    return digest.hexdigest()


@dataclass
class Attempt:
    """One call to `run_one`, whatever it returned."""

    n: int
    started: str
    finished: str = ""
    seconds: float = 0.0
    outcome: str = ""
    void: bool = True
    usable: bool = False
    #: `(step, seconds, note)` as `RunReport` recorded them. Kept in full: the
    #: readiness time is the number that says whether a timeout was generous
    #: or lucky, and it is not derivable from anything else here.
    steps: list[list] = field(default_factory=list)
    case_dir: str = ""
    collected: dict | None = None
    error: str = ""


@dataclass
class SampleRow:
    """One sample's whole story, planned before it runs."""

    path: str
    name: str
    case: str
    size: int | None = None
    sha256: str | None = None
    state: str = PENDING
    #: Why it was skipped or not attempted. Empty for a row that ran.
    reason: str = ""
    attempts: list[Attempt] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return any(a.usable for a in self.attempts)

    @property
    def void(self) -> bool:
        """Attempted, and every attempt observed too little to conclude from."""
        return bool(self.attempts) and all(a.void for a in self.attempts)


def _case_folder(case_dir: Path, case: str) -> Path:
    """Where the analysis actually landed inside the imported case.

    The guest agent sets `CASE_ROOT_DIR` to the exchange working directory
    *and* passes `--case <name>`, so the guest writes `work/<case>/`; the host
    collects the whole of `work/` into `cases/<case>/`, and the segment
    doubles to `cases/<case>/<case>/`. Both halves are behaving correctly and
    neither is obviously wrong on its own.

    That was cosmetic while a human read one case folder. A manifest that
    quotes a path a consumer will open is not the place to leave it implicit,
    so the doubled segment is resolved here and recorded as found rather than
    assumed in either direction -- if the transport is fixed later, this
    returns the outer directory and nothing downstream changes.
    """
    inner = case_dir / case
    return inner if inner.is_dir() else case_dir


def enumerate_samples(
    source: Path,
    *,
    recursive: bool = False,
    extensions: Sequence[str] | None = None,
    limit: int | None = None,
) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Every sample a sweep would attempt, and everything refused up front.

    Returns `(planned, skipped)`, where `skipped` is `(path, reason)`. Refusals
    are returned rather than raised because they belong in the manifest: a
    corpus directory with three unusable filenames should produce a sweep over
    the rest plus three rows saying why, not an error message and no sweep.

    Refused here, and each for a reason that would otherwise bite mid-sweep:

    * a filename that may not become a path component on the host -- the same
      allow-list `collect.py` applies to what the guest writes, applied to what
      the host delivers, because a sample called `-r.exe` ends up as a command
      argument to capa on the way back
    * a stem two samples share, because `run_one` names the case from the stem
      and the second would overwrite the first in silence
    * anything that is not a regular file
    """
    source = Path(source)
    if source.is_file():
        candidates = [source]
    elif source.is_dir():
        walk = source.rglob("*") if recursive else source.iterdir()
        candidates = sorted((p for p in walk), key=lambda p: str(p).lower())
    else:
        raise FileNotFoundError(f"no sample or directory at {source}")

    wanted = None
    if extensions:
        wanted = {e.lower() if e.startswith(".") else f".{e.lower()}"
                  for e in extensions}

    planned: list[Path] = []
    skipped: list[tuple[Path, str]] = []

    for path in candidates:
        if not path.is_file():
            continue
        if wanted is not None and path.suffix.lower() not in wanted:
            continue

        verdict = check_component(path.name)
        if not verdict:
            skipped.append((path, f"unsafe filename: {verdict.reason}"))
            continue

        stem_verdict = check_component(path.stem) if path.stem else None
        if stem_verdict is not None and not stem_verdict:
            skipped.append(
                (path, f"unsafe case name {path.stem!r}: {stem_verdict.reason}"))
            continue

        planned.append(path)

    # Collisions, found across the whole plan rather than pairwise as we go,
    # so *both* sides of a collision are reported. Skipping only the second
    # would run the first and leave a corpus row whose case folder a reader
    # cannot be sure belongs to it.
    by_case: dict[str, list[Path]] = {}
    for path in planned:
        by_case.setdefault(path.stem.lower(), []).append(path)

    colliding = {p for group in by_case.values() if len(group) > 1 for p in group}
    if colliding:
        for group in by_case.values():
            if len(group) < 2:
                continue
            others = ", ".join(p.name for p in group)
            for path in group:
                skipped.append((
                    path,
                    f"case name {path.stem!r} is shared by {len(group)} samples "
                    f"({others}); each would overwrite the last"))
        planned = [p for p in planned if p not in colliding]

    skipped.sort(key=lambda item: str(item[0]).lower())

    if limit is not None and limit >= 0:
        planned = planned[:limit]

    return planned, skipped


class Manifest:
    """The record, owned by one sweep and rewritten after every attempt.

    **Written atomically, every time.** A sweep is hours long and the manifest
    is the only durable record of it; a process killed during a plain write
    leaves a truncated JSON file, which is worse than no file because it looks
    like corruption of the results rather than an interrupted run.
    """

    def __init__(self, path: Path, header: dict) -> None:
        self.path = Path(path)
        self.header = header
        self.rows: list[SampleRow] = []

    def document(self) -> dict:
        attempted = [r for r in self.rows if r.state == ATTEMPTED]
        return {
            **self.header,
            "totals": {
                "planned": sum(1 for r in self.rows
                               if r.state not in (SKIPPED,)),
                "attempted": len(attempted),
                "usable": sum(1 for r in attempted if r.usable),
                "void": sum(1 for r in attempted if r.void),
                "skipped": sum(1 for r in self.rows if r.state == SKIPPED),
                "pending": sum(1 for r in self.rows
                               if r.state in (PENDING, RUNNING)),
                "not_attempted": sum(1 for r in self.rows
                                     if r.state == NOT_ATTEMPTED),
            },
            "samples": [asdict(row) for row in self.rows],
        }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".json.tmp")
        text = json.dumps(self.document(), indent=2, sort_keys=False)
        # `write_bytes` with an explicit newline, not `write_text`: on Windows
        # the text path rewrites `\n` to `\r\n`, and a manifest that changes
        # shape depending on which machine wrote it is a diff nobody wants to
        # read. Same reason `docs/HANDOFF.md` is `-text` in `.gitattributes`.
        temporary.write_bytes(text.encode("utf-8") + b"\n")
        os.replace(temporary, self.path)


@dataclass
class SweepResult:
    """What the sweep did, for a caller that is not reading the JSON."""

    run_id: str
    directory: Path
    manifest: Path
    rows: list[SampleRow]
    state: str
    preflight: list[str] = field(default_factory=list)

    @property
    def usable(self) -> int:
        return sum(1 for r in self.rows if r.usable)

    @property
    def void(self) -> int:
        return sum(1 for r in self.rows if r.void)

    @property
    def attempted(self) -> int:
        return sum(1 for r in self.rows if r.state == ATTEMPTED)


def sweep(
    source: Path,
    guest: Guest,
    hypervisor,
    exchange: Path,
    out_root: Path,
    *,
    run_id: str | None = None,
    recursive: bool = False,
    extensions: Sequence[str] | None = None,
    limit: int | None = None,
    attempts: int = 1,
    abort_after_consecutive_void: int = 3,
    ignore_preflight: bool = False,
    dry_run: bool = False,
    limits: Limits | None = None,
    sleep: Callable[[float], None] = time.sleep,
    on_event: Callable[[str], None] | None = None,
) -> SweepResult:
    """Detonate every sample under `source`, recording what was attempted.

    Results land in `out_root/<run_id>/`: `manifest.json` beside `cases/`, so
    a sweep is one directory that can be moved, archived or handed over whole.
    Two sweeps over the same corpus do not overwrite each other, which is the
    point of measuring twice.

    `attempts` above 1 retries **only** a void outcome, and records each try.
    `abort_after_consecutive_void` stops the sweep when the bench itself looks
    broken -- three samples in a row that never signalled readiness is a guest
    problem, and the remaining rows stay `pending` rather than becoming a
    hundred void entries in the corpus.

    Never raises for a sample that went wrong. Raises only for a sweep that
    cannot be set up at all.
    """
    say = on_event or (lambda _message: None)
    source = Path(source)
    exchange = Path(exchange)
    run_id = run_id or f"sweep-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    directory = Path(out_root) / run_id
    case_root = directory / "cases"
    limits = limits or Limits()

    planned, skipped = enumerate_samples(
        source, recursive=recursive, extensions=extensions, limit=limit)

    # Provenance of the *host* half. The guest records its own, and the two
    # disagreeing is itself worth being able to see -- the guest's clone has
    # been a different commit before now.
    try:
        from verdict.provenance import analyzer_provenance

        analyzer = analyzer_provenance()
    except Exception as error:                        # noqa: BLE001
        analyzer = {"error": f"{type(error).__name__}: {error}"}

    header = {
        "schema": SCHEMA,
        "run_id": run_id,
        "state": "running",
        "started": _now(),
        "finished": None,
        "source": str(source),
        "exchange": str(exchange),
        "case_root": str(case_root),
        "controller": {
            "analyzer": analyzer,
            "python": platform.python_version(),
            "host": platform.node(),
            "platform": platform.platform(),
        },
        "guest": {
            "vm": guest.vm,
            "baseline": guest.baseline,
            "internet_nic": guest.internet_nic,
            "hostonly_nic": guest.hostonly_nic,
            "readiness_timeout": guest.readiness_timeout,
            "run_timeout": guest.run_timeout,
        },
        "limits": asdict(limits),
        "policy": {
            "attempts": attempts,
            # Named rather than implied: a reader should not have to know
            # which outcomes `Outcome.void` covers to interpret the corpus.
            "retry_on": [Outcome.NO_READINESS.value, Outcome.FAILED.value],
            "abort_after_consecutive_void": abort_after_consecutive_void,
            "recursive": recursive,
            "extensions": list(extensions) if extensions else None,
            "limit": limit,
            "dry_run": dry_run,
            "preflight_ignored": ignore_preflight,
        },
        "preflight": [],
    }

    manifest = Manifest(directory / MANIFEST_NAME, header)

    for path in planned:
        try:
            size = path.stat().st_size
            digest = sha256_of(path)
        except OSError as error:
            manifest.rows.append(SampleRow(
                path=str(path), name=path.name, case=path.stem,
                state=SKIPPED, reason=f"cannot read: {error.strerror}"))
            continue
        manifest.rows.append(SampleRow(
            path=str(path), name=path.name, case=path.stem,
            size=size, sha256=digest,
            state=NOT_ATTEMPTED if dry_run else PENDING,
            reason="dry run: nothing was detonated" if dry_run else ""))

    for path, reason in skipped:
        manifest.rows.append(SampleRow(
            path=str(path), name=path.name, case=path.stem,
            state=SKIPPED, reason=reason))

    # Written here, before a single sample is delivered. Everything after this
    # point only ever *updates* rows that already exist on disk.
    manifest.save()
    say(f"{run_id}: {len(planned)} planned, {len(skipped)} skipped -> "
        f"{manifest.path}")

    if dry_run:
        header["state"] = "dry_run"
        header["finished"] = _now()
        manifest.save()
        return SweepResult(run_id, directory, manifest.path, manifest.rows,
                           "dry_run")

    problems = check_ready(guest, hypervisor)
    header["preflight"] = problems
    if problems and not ignore_preflight:
        # Refused, not attempted one-by-one. A sweep that dies on the second
        # sample after twenty minutes on the first is worse than one that will
        # not start, and every row is already on disk saying it never ran.
        for row in manifest.rows:
            if row.state == PENDING:
                row.state = NOT_ATTEMPTED
                row.reason = "sweep refused to start: " + "; ".join(problems)
        header["state"] = "refused"
        header["finished"] = _now()
        manifest.save()
        say("refused to start:\n  " + "\n  ".join(problems))
        return SweepResult(run_id, directory, manifest.path, manifest.rows,
                           "refused", problems)
    if problems:
        say("preflight problems ignored:\n  " + "\n  ".join(problems))

    consecutive_void = 0
    aborted = ""

    for row in manifest.rows:
        if row.state != PENDING:
            continue
        if aborted:
            row.state = NOT_ATTEMPTED
            row.reason = aborted
            continue

        row.state = RUNNING
        manifest.save()
        say(f"-> {row.name}")

        for n in range(1, max(1, attempts) + 1):
            attempt = Attempt(n=n, started=_now())
            began = time.monotonic()
            try:
                report = run_one(Path(row.path), guest, hypervisor, exchange,
                                 case_root, limits=limits, sleep=sleep)
            except KeyboardInterrupt:
                # The guest is left wherever `run_one`'s `finally` put it,
                # which is the baseline. Record the interruption against this
                # sample rather than losing it.
                attempt.finished = _now()
                attempt.error = "interrupted"
                row.attempts.append(attempt)
                row.state = ATTEMPTED
                aborted = "sweep interrupted before this sample was reached"
                manifest.save()
                break

            attempt.finished = _now()
            attempt.seconds = round(time.monotonic() - began, 2)
            attempt.outcome = report.outcome.value
            attempt.void = report.outcome.void
            attempt.usable = report.usable
            attempt.steps = [list(step) for step in report.steps]
            attempt.error = report.error
            if report.collected is not None:
                case_dir = _case_folder(case_root / report.case, report.case)
                attempt.case_dir = str(case_dir)
                attempt.collected = {
                    "files": report.collected.files,
                    "directories": report.collected.directories,
                    "bytes": report.collected.total_bytes,
                    "truncated": report.collected.truncated,
                    "refusals": [asdict(r) for r in report.collected.refusals],
                }
            row.attempts.append(attempt)
            manifest.save()

            say(f"   {report.outcome.value}"
                f"{' (void)' if report.outcome.void else ''}"
                f" in {attempt.seconds:.0f}s"
                + (f" -- {report.collected.summary()}"
                   if report.collected else "")
                + (f" -- {report.error}" if report.error else ""))

            if not report.outcome.void:
                break

        if row.state != ATTEMPTED:
            row.state = ATTEMPTED

        if row.void:
            consecutive_void += 1
            if (not aborted and abort_after_consecutive_void
                    and consecutive_void >= abort_after_consecutive_void):
                aborted = (
                    f"sweep aborted after {consecutive_void} consecutive void "
                    f"runs; the bench, not the samples")
                say(aborted)
        else:
            consecutive_void = 0

        manifest.save()

    header["state"] = "aborted" if aborted else "completed"
    header["finished"] = _now()
    manifest.save()

    result = SweepResult(run_id, directory, manifest.path, manifest.rows,
                         header["state"], problems)
    say(f"{header['state']}: {result.attempted} attempted, "
        f"{result.usable} usable, {result.void} void")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m runcontrol.sweep",
        description="Detonate every sample in a directory, one guest at a "
                    "time, and write a manifest of what was attempted.",
        epilog="--dry-run enumerates, hashes and writes the manifest without "
               "touching a hypervisor. Run it against a corpus directory "
               "before committing a machine to it.",
    )
    parser.add_argument("source", type=Path,
                        help="a sample, or a directory of them")
    parser.add_argument("--vm", required=True, help="the guest, as the "
                        "hypervisor knows it")
    parser.add_argument("--baseline", required=True,
                        help="snapshot every run starts from. Must have been "
                             "taken from poweroff: a snapshot taken while the "
                             "VM ran restores to 'saved', resumes instead of "
                             "booting, and no ONSTART task ever fires")
    parser.add_argument("--exchange", type=Path, required=True,
                        help="directory both host and guest can see")
    parser.add_argument("--out", type=Path, default=Path("cases"),
                        help="where the sweep directory is created "
                             "(default: cases)")
    parser.add_argument("--run-id", default=None,
                        help="name the sweep directory (default: a timestamp)")
    parser.add_argument("--recursive", action="store_true",
                        help="descend into subdirectories")
    parser.add_argument("--ext", action="append", default=None, metavar="EXT",
                        help="only samples with this extension; repeatable")
    parser.add_argument("--limit", type=int, default=None,
                        help="attempt at most this many samples")
    parser.add_argument("--attempts", type=int, default=1,
                        help="tries per sample; a retry fires only on a void "
                             "outcome and every try is recorded (default: 1)")
    parser.add_argument("--abort-after", type=int, default=3, metavar="N",
                        help="stop the sweep after N consecutive void runs; "
                             "0 disables (default: 3)")
    parser.add_argument("--internet-nic", type=int, default=1,
                        help="adapter cut from the host before boot")
    parser.add_argument("--hostonly-nic", type=int, default=2,
                        help="adapter left connected")
    parser.add_argument("--readiness-timeout", type=float, default=600.0,
                        help="seconds to wait for collection to come up. "
                             "Measured on this bench at 231s and 277s; keep "
                             "it generous (default: 600)")
    parser.add_argument("--run-timeout", type=float, default=1800.0,
                        help="seconds for the run itself (default: 1800)")
    parser.add_argument("--ignore-preflight", action="store_true",
                        help="start despite preflight problems. Recorded in "
                             "the manifest, because a corpus built this way "
                             "should be identifiable as one")
    parser.add_argument("--dry-run", action="store_true",
                        help="enumerate and write the manifest; detonate "
                             "nothing, and never touch the hypervisor")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        guest = Guest(
            vm=args.vm, baseline=args.baseline,
            internet_nic=args.internet_nic, hostonly_nic=args.hostonly_nic,
            readiness_timeout=args.readiness_timeout,
            run_timeout=args.run_timeout,
        )
    except GuestError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    hypervisor = None
    if not args.dry_run:
        # Imported only when it will be used, so `--dry-run` works on a
        # machine with no VirtualBox installed -- which is where a corpus
        # directory is usually assembled.
        from runcontrol.hypervisor import HypervisorError, VirtualBox

        try:
            hypervisor = VirtualBox()
        except HypervisorError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2

    try:
        result = sweep(
            args.source, guest, hypervisor, args.exchange, args.out,
            run_id=args.run_id, recursive=args.recursive,
            extensions=args.ext, limit=args.limit, attempts=args.attempts,
            abort_after_consecutive_void=args.abort_after,
            ignore_preflight=args.ignore_preflight, dry_run=args.dry_run,
            on_event=lambda message: print(message, flush=True),
        )
    except (FileNotFoundError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if result.state == "refused":
        return 1
    # A sweep that attempted nothing is not a success, whatever the rows say.
    if result.state != "dry_run" and result.attempted == 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
