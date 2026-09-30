"""Re-combine a finished corpus's verdicts against the current scoring code.

    python -m runcontrol.recombine <run-directory> [--dry-run]

**The third tool that edits a corpus in place**, beside `debom` and `rescore`,
and it refuses on exactly their terms: a terminal manifest, no controller
alive, an unreadable process table counts as running, originals kept first,
a hashed record after.

**Why it exists: a static scoring change reaches no corpus through `rescore`.**
`rescore` recomputes the *dynamic* score from the run summary and regenerates
`combined_verdict.json` only when that score changed -- right for a dynamic
fix, and a no-op for a static one. It also only visits cases with a dynamic
run, so a static-only case is never reached at all. The socket-family change
to `dangerous_capability` (29 Sep) is static: this is how it reaches the
corpora it was measured on.

**What it rewrites: `combined_verdict.json`, and its copy under `metadata/`,
and only where the decision changed.** Each case is re-combined in memory
first. Left byte for byte: a case the manifest records as **not usable** (a
void run's folder is a partial copy); a case identical but for timestamp and
provenance; one whose only difference is context volume (`subscores`,
`context_score`), which no band reads; and one whose fresh verdict ran *fewer
modules* than the stored -- the case is missing files its stored verdict was
made from, and writing would delete evidence. The rest are backed up and
written. Nothing else in a case is touched -- the evidence is
re-read, never re-made -- and no sample is detonated.

**A host re-combine reproduces a guest verdict.** It did not until 29 Sep: the
technique term of the static context score read `capa.json` at the case path
the summary recorded -- the guest's work directory -- so 20 of 208 cases lost
1-4 context points on the host. Fixed in `combine_case` alongside this tool;
without that fix, this would have quietly rewritten twenty scores for a
reason nobody asked for.
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

from runcontrol.debom import TERMINAL, DebomRefused, _extended, _sweep_running

RECORD_NAME = "recombine.json"

#: Its own, not `bom-originals/` or `rescore-originals/`: three tools edit a
#: corpus, and a restore must never be ambiguous about which change it undoes.
BACKUP_DIR = "recombine-originals"

VERDICT_NAME = "combined_verdict.json"

#: Fields that change on every combine and say nothing about the decision.
#: A difference only here is not a change.
_VOLATILE = ("generated_utc", "provenance")

#: Volume, never a band input. A case whose only difference is here is left
#: as it is and counted as `context_only`: the 29 Sep dry run found ~50 benign
#: cases whose static context subscore moved 1 -> 2 when the technique count
#: was fixed, and rewriting fifty verdicts for a number no band reads is churn
#: in the one directory with no git under it.
_CONTEXT = ("subscores", "context_score")


class RecombineRefused(DebomRefused):
    """The run is not in a state where re-combining its cases is safe."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(Path(_extended(path)).read_bytes()).hexdigest()
    except OSError:
        return ""


@dataclass
class CaseResult:
    case: str
    home: str
    changed: bool = False
    #: Why a case was not written: `not_usable` (the manifest says so),
    #: `context_only`, or `modules_missing` -- see `recombine` and
    #: `recombine_one`.
    skipped: str = ""
    band_before: str = ""
    band_after: str = ""
    score_before: object = None
    score_after: object = None
    fields_changed: list = field(default_factory=list)
    sha256_before: str = ""
    sha256_after: str = ""
    backup: str = ""
    error: str = ""


@dataclass
class RecombineResult:
    run_id: str
    directory: Path
    dry_run: bool
    cases: list = field(default_factory=list)

    @property
    def changed(self) -> int:
        return sum(1 for c in self.cases if c.changed and not c.error)

    @property
    def unchanged(self) -> int:
        return sum(1 for c in self.cases if not c.changed and not c.error and not c.skipped)

    @property
    def skipped(self) -> int:
        return sum(1 for c in self.cases if c.skipped and not c.error)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.cases if c.error)


def find_case_homes(cases: Path) -> list[Path]:
    """Every case home under a corpus: the directory holding its verdict.

    `cases/<case>/<case>/`, the transport's doubled segment. The copy under
    `metadata/` is one level deeper and is not a home.
    """
    return sorted(p.parent for p in Path(cases).glob(f"*/*/{VERDICT_NAME}"))


def unusable_cases(manifest: dict) -> set[str]:
    """Cases the sweep manifest records as not usable -- void, failed, or
    timed out. A manifest without per-case rows names none."""
    rows = next((v for v in manifest.values()
                 if isinstance(v, list) and v and isinstance(v[0], dict)
                 and "case" in v[0]), [])
    return {row["case"] for row in rows
            if not (row.get("attempts") or [{}])[-1].get("usable")}


def _decision(verdict: dict) -> dict:
    return {k: v for k, v in verdict.items() if k not in _VOLATILE}


def recombine_one(home: Path, run_directory: Path, *, dry_run: bool,
                  combine: Callable | None = None) -> CaseResult:
    """Re-combine one case; write only if the decision changed."""
    if combine is None:
        from static_triage_engine.combine_case import combine_case as combine

    result = CaseResult(case=home.name, home=str(home))
    stored_path = home / VERDICT_NAME
    try:
        stored = json.loads(stored_path.read_text(encoding="utf-8-sig"))
    except Exception as error:                        # noqa: BLE001
        result.error = f"cannot read the stored verdict: {error}"
        return result

    try:
        fresh = combine(home, write_output=False)
    except Exception as error:                        # noqa: BLE001
        result.error = f"combine raised: {type(error).__name__}: {error}"
        return result

    result.band_before, result.score_before = stored.get("band", ""), stored.get("score")
    result.band_after, result.score_after = fresh.get("band", ""), fresh.get("score")
    before, after = _decision(stored), _decision(fresh)
    if before == after:
        return result
    result.fields_changed = sorted(k for k in set(before) | set(after)
                                   if before.get(k) != after.get(k))

    # **Fewer modules than the stored verdict means the case is missing files
    # the stored verdict was made from -- never that it has less evidence.**
    # Found by the 30 Sep dry run: `Microsoft.VisualStudio.Setup.ToastNotification`
    # would have fallen from Strongly Corroborated 105 to No Evidence 1. That
    # case turned out to be a void run whose dynamic summary never reached the
    # host (`not_usable` now catches it first); this guard stays for any case
    # that loses a module some other way. Writing would delete evidence.
    lost = set(stored.get("modules_run") or ()) - set(fresh.get("modules_run") or ())
    if lost:
        result.skipped = "modules_missing"
        result.fields_changed.append(f"modules lost: {', '.join(sorted(lost))}")
        return result

    if set(result.fields_changed) <= set(_CONTEXT):
        result.skipped = "context_only"
        return result

    result.changed = True
    result.sha256_before = _sha256(stored_path)
    if dry_run:
        return result

    # Kept before anything is written. There is no git under cases/.
    try:
        relative = home.relative_to(run_directory)
    except ValueError:
        relative = Path(home.name)
    backup = run_directory / BACKUP_DIR / relative
    try:
        os.makedirs(_extended(backup), exist_ok=True)
        shutil.copy2(_extended(stored_path), _extended(backup / VERDICT_NAME))
        meta = home / "metadata" / VERDICT_NAME
        if meta.exists():
            os.makedirs(_extended(backup / "metadata"), exist_ok=True)
            shutil.copy2(_extended(meta), _extended(backup / "metadata" / VERDICT_NAME))
        result.backup = str(backup)
    except OSError as error:
        result.error = f"could not keep the original: {error}"
        result.changed = False
        return result

    try:
        combine(home, write_output=True)
        result.sha256_after = _sha256(stored_path)
    except Exception as error:                        # noqa: BLE001
        result.error = (f"combine failed while writing ({type(error).__name__}: "
                        f"{error}); the original is at {backup}")
    return result


def recombine(run_directory: Path, *, dry_run: bool = False,
              on_event: Callable[[str], None] | None = None,
              combine: Callable | None = None) -> RecombineResult:
    """Re-combine every case in a finished corpus. Raises `RecombineRefused`
    rather than editing anything it is unsure about."""
    say = on_event or (lambda _message: None)
    run_directory = Path(run_directory)
    manifest_path = run_directory / "manifest.json"
    if not manifest_path.is_file():
        raise RecombineRefused(
            f"no manifest at {manifest_path}. This edits a sweep's cases in place "
            f"and will not do that to a directory it cannot identify as a sweep.")
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except Exception as error:                        # noqa: BLE001
        raise RecombineRefused(
            f"{manifest_path} will not parse ({type(error).__name__}); nothing is "
            f"edited until the record can be read.") from error
    state = document.get("state")
    if state not in TERMINAL:
        raise RecombineRefused(
            f"the run is state={state!r}, and this only re-combines a finished one "
            f"({' or '.join(TERMINAL)}). A sweep writes into cases/ as it collects.")
    if _sweep_running():
        raise RecombineRefused(
            "a runcontrol.sweep process is still alive (or the process table could "
            "not be read). Not while a controller is going.")
    cases = run_directory / "cases"
    if not cases.is_dir():
        raise RecombineRefused(f"no cases directory under {run_directory}")

    run_id = document.get("run_id") or run_directory.name
    result = RecombineResult(run_id=run_id, directory=run_directory, dry_run=dry_run)
    homes = find_case_homes(cases)
    unusable = unusable_cases(document)
    say(f"{run_id}: {len(homes)} case(s) to re-combine" + (" (dry run)" if dry_run else ""))

    for home in homes:
        if home.name in unusable:
            # **A void run's folder is a partial copy, not a case.** Found 30
            # Sep: `benign-102-v2`'s two void runs failed collection part-way
            # (`WinError 206`, before the collector's MAX_PATH fix) and left a
            # guest-written verdict beside a case missing its dynamic summary.
            # Re-combining one would score what happened to arrive.
            result.cases.append(CaseResult(case=home.name, home=str(home),
                                           skipped="not_usable"))
            continue
        outcome = recombine_one(home, run_directory, dry_run=dry_run, combine=combine)
        result.cases.append(outcome)
        if outcome.error:
            say(f"  FAILED  {outcome.case}: {outcome.error}")
        elif outcome.skipped == "modules_missing":
            say(f"  SKIPPED {outcome.case}: re-combining would drop a module the "
                f"stored verdict had ({outcome.fields_changed[-1]}); left as it was")
        elif outcome.changed:
            say(f"  {outcome.case}: {outcome.band_before} {outcome.score_before} -> "
                f"{outcome.band_after} {outcome.score_after}  "
                f"[{', '.join(outcome.fields_changed)}]")

    context_only = sum(1 for c in result.cases if c.skipped == "context_only")
    unreadable = sum(1 for c in result.cases if c.skipped == "modules_missing")
    void = sum(1 for c in result.cases if c.skipped == "not_usable")
    say(f"{'would change' if dry_run else 'changed'}: {result.changed}, "
        f"unchanged: {result.unchanged}, context-only (left): {context_only}"
        + (f", not usable in the manifest (left): {void}" if void else "")
        + (f", modules missing (left): {unreadable}" if unreadable else "")
        + (f", FAILED: {result.failed}" if result.failed else ""))

    if not dry_run and (result.changed or result.failed or unreadable):
        try:
            from verdict.provenance import analyzer_provenance
            analyzer = analyzer_provenance()
        except Exception as error:                    # noqa: BLE001
            analyzer = {"error": f"{type(error).__name__}: {error}"}
        record = {
            "tool": "runcontrol.recombine",
            "at": _now(),
            "run_id": run_id,
            "why": ("A static scoring change reaches a corpus only by re-combining "
                    "its verdicts; rescore does not, and never visits static-only "
                    "cases. Re-combined from the files each case already holds; "
                    "only verdicts whose decision changed were written, and no "
                    "sample was detonated again."),
            "analyzer": analyzer,
            "originals": str(run_directory / BACKUP_DIR),
            "changed": result.changed,
            "unchanged": result.unchanged,
            "context_only_left": context_only,
            "not_usable_left": void,
            "modules_missing_left": unreadable,
            "failed": result.failed,
            "cases": [asdict(c) for c in result.cases
                      if c.changed or c.error or c.skipped in ("modules_missing", "not_usable")],
        }
        path = run_directory / RECORD_NAME
        if path.exists():
            # A second pass keeps the first's record beside it, never over it.
            path = run_directory / f"recombine-{datetime.now():%Y%m%dT%H%M%S}.json"
        path.write_bytes(json.dumps(record, indent=2).encode("utf-8") + b"\n")
        say(f"record: {path}")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m runcontrol.recombine",
        description="Re-combine a finished corpus's verdicts against the current "
                    "scoring code, writing only the ones whose decision changed.",
        epilog="Only runs against a finished sweep with no controller alive. "
               "Originals are kept under <run>/recombine-originals/ and what "
               "changed is recorded in recombine.json. Detonates nothing.")
    parser.add_argument("run_directory", type=Path,
                        help="the sweep directory holding manifest.json")
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would change and edit nothing")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = recombine(args.run_directory, dry_run=args.dry_run,
                           on_event=lambda message: print(message, flush=True))
    except RecombineRefused as error:
        print(f"error: {error}", file=sys.stderr)
        return 3
    return 1 if result.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
