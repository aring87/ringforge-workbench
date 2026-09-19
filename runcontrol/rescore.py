"""Re-score a finished corpus against the current scoring code.

A corpus is scored **in the guest, at detonation time**. The dynamic score
lands in `dynamic_run_summary.json` and `combine` reads it back rather than
recomputing it -- which means a scoring fix made after a run started cannot
reach that run's cases, however many times `combine` is re-run. That was
established the hard way on 18 Sep: `combine` reproduced a verdict of 70
*after* the fix was applied, because it was reading the stored number.

`benign-102-v2` is the case in point. Its tenth sample,
`aura-wallpaper-editor`, banded `Corroborated`/70 on a connection to
`127.0.0.1:11001` -- its own service, over local IPC -- because
`external_contact` was strong on any unusual port and nothing excluded
loopback. The fix landed mid-corpus, the guest self-updates only on a boot
carrying no sample, and so all 102 cases are scored by the code the run
started with.

What makes this possible at all is that `dynamic_run_summary.json` embeds
every input `calculate_dynamic_score` takes -- findings, both network
summaries, sysmon, autoruns, dropped files, memory, crash, PE carve, module
integrity. Verified present in a pruned case: nothing the scorer needs is
among what pruning drops. So the run can be re-scored from what it already
wrote, with no detonation.

What it changes, and what it does not
-------------------------------------

Exactly the four fields the orchestrator derives from the scorer --
`score`, `severity`, `verdict` and `score_detail` -- and then
`combined_verdict.json`, by calling `combine_case` the way the CLI does.
Nothing else in the run summary is touched: the observation window, the
collector statuses, the sample's hashes and every raw summary stay as the run
wrote them. **The evidence is not being re-made, only re-read.**

A cancelled run is skipped. Its score was replaced wholesale with
`Cancelled`/`Info` rather than derived from evidence, and recomputing one
would invent a verdict for a run that never finished.

Refusals, and why they are the same as `debom`'s
------------------------------------------------

`cases/` is not in git. This and `runcontrol.debom` are the only two tools in
the bench that edit a corpus in place, so they refuse on the same terms: the
manifest must be in a terminal state, no `runcontrol.sweep` process may be
alive, and an unreadable process table counts as running. Originals are kept
before anything is written and what changed is recorded with a hash per file.

Idempotent: scoring is deterministic, so a second pass recomputes the same
numbers, finds nothing changed and writes nothing.
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

from runcontrol.debom import (
    TERMINAL, DebomRefused, _extended, _sweep_running,
)

#: Written beside manifest.json, as `debom`'s record is.
RECORD_NAME = "rescore.json"

#: Its own, not `debom`'s `bom-originals/`. Two tools edit this corpus and
#: their originals are answers to different questions -- "what did the guest
#: write" and "what did the guest score" -- so mixing them in one tree would
#: make a restore ambiguous about which change it was undoing.
BACKUP_DIR = "rescore-originals"

#: What the orchestrator derives from the scorer, and therefore the only
#: fields this is entitled to replace. See `orchestrator.py`, where the run
#: summary is assembled.
SCORED_FIELDS = ("score", "severity", "verdict", "score_detail")

#: The summary a dynamic run writes, and the file this rewrites.
RUN_SUMMARY = "dynamic_run_summary.json"


class RescoreRefused(DebomRefused):
    """The run is not in a state where re-scoring its cases is safe.

    A subclass, because a caller that already handles one of these wants the
    same answer for the other: both mean "not touching this corpus".
    """


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class CaseResult:
    """One dynamic run, and what re-scoring it did or why it did not."""

    case: str
    summary_path: str
    changed: bool = False
    skipped: str = ""
    score_before: object = None
    score_after: object = None
    severity_before: str = ""
    severity_after: str = ""
    verdict_before: str = ""
    verdict_after: str = ""
    band_before: str = ""
    band_after: str = ""
    sha256_before: str = ""
    sha256_after: str = ""
    backup: str = ""
    error: str = ""


@dataclass
class RescoreResult:
    run_id: str
    directory: Path
    dry_run: bool
    cases: list[CaseResult] = field(default_factory=list)

    @property
    def changed(self) -> int:
        return sum(1 for c in self.cases if c.changed)

    @property
    def unchanged(self) -> int:
        return sum(1 for c in self.cases if not c.changed and not c.skipped
                   and not c.error)

    @property
    def skipped(self) -> int:
        return sum(1 for c in self.cases if c.skipped)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.cases if c.error)


def find_run_summaries(cases: Path) -> list[Path]:
    """Every dynamic run summary under a corpus, in a stable order.

    A case can hold more than one dynamic run -- a retry leaves both -- and
    each carries its own score, so each is re-scored. Sorted because two
    passes over one corpus must visit it the same way.
    """
    return sorted(Path(cases).rglob(RUN_SUMMARY))


def _case_home(summary_path: Path) -> Path:
    """The case directory `combine_case` wants, from the summary's path.

    `<case>/dynamic_analysis/dynamic_runs/<run>/metadata/<this file>`, so the
    case is five levels up. Derived rather than searched, because a corpus has
    nested directories named for the case twice over (the doubled segment the
    transport produces) and "the first ancestor that looks like a case" would
    pick the wrong one.
    """
    return summary_path.parents[4]


def rescore_one(summary_path: Path, run_directory: Path, *,
                dry_run: bool) -> CaseResult:
    """Recompute one run's score from what it already recorded."""
    from dynamic_analysis.orchestrator import calculate_dynamic_score
    from static_triage_engine.combine_case import combine_case

    home = _case_home(summary_path)
    result = CaseResult(case=home.name, summary_path=str(summary_path))

    try:
        original = summary_path.read_bytes()
        document = json.loads(original.decode("utf-8-sig"))
    except Exception as error:                        # noqa: BLE001
        result.error = f"cannot read the run summary: {error}"
        return result

    result.sha256_before = hashlib.sha256(original).hexdigest()

    if document.get("cancelled"):
        # Its verdict was assigned, not derived. Recomputing would invent one.
        result.skipped = "the run was cancelled; its verdict was not derived from evidence"
        return result

    def part(name: str) -> dict:
        value = document.get(name)
        return value if isinstance(value, dict) else {}

    try:
        scored = calculate_dynamic_score(
            findings_summary=part("findings"),
            task_diff_summary=part("task_diff_summary"),
            service_diff_summary=part("service_diff_summary"),
            dropped_files_summary=part("dropped_files_summary"),
            autoruns_diff_summary=part("autoruns_diff_summary"),
            sysmon_summary=part("sysmon_summary"),
            network_summary=part("network_summary"),
            fakenet_summary=part("fakenet_summary"),
            memory_yara_summary=part("memory_yara_summary"),
            powershell_summary=part("powershell_summary"),
            crash_summary=part("crash_summary"),
            pe_carve_summary=part("pe_carve_summary"),
            module_integrity_summary=part("module_integrity_summary"),
        )
    except Exception as error:                        # noqa: BLE001
        result.error = f"the scorer raised: {type(error).__name__}: {error}"
        return result

    result.score_before = document.get("score")
    result.severity_before = str(document.get("severity") or "")
    result.verdict_before = str(document.get("verdict") or "")
    result.score_after = scored.get("score")
    result.severity_after = str(scored.get("severity") or "")
    result.verdict_after = str(scored.get("verdict") or "")

    unchanged = (
        result.score_before == result.score_after
        and result.severity_before == result.severity_after
        and result.verdict_before == result.verdict_after
        and document.get("score_detail") == scored
    )
    if unchanged:
        return result

    result.changed = True
    verdict_path = home / "combined_verdict.json"
    try:
        before = json.loads(verdict_path.read_text(encoding="utf-8-sig"))
        result.band_before = str(before.get("band") or "")
    except Exception:                                 # noqa: BLE001
        result.band_before = "(unreadable)"

    if dry_run:
        return result

    # Kept before anything is written. There is no git under cases/.
    try:
        relative = summary_path.relative_to(run_directory)
    except ValueError:
        relative = Path(summary_path.name)
    backup = run_directory / BACKUP_DIR / relative
    try:
        os.makedirs(_extended(backup.parent), exist_ok=True)
        shutil.copy2(_extended(summary_path), _extended(backup))
        result.backup = str(backup)
    except OSError as error:
        result.error = f"could not keep the original: {error}"
        result.changed = False
        return result

    document["score"] = scored["score"]
    document["severity"] = scored["severity"]
    document["verdict"] = scored["verdict"]
    document["score_detail"] = scored

    try:
        text = json.dumps(document, indent=2, sort_keys=False)
        temporary = summary_path.with_name(summary_path.name + ".tmp")
        with open(_extended(temporary), "wb") as handle:
            handle.write(text.encode("utf-8") + b"\n")
        os.replace(_extended(temporary), _extended(summary_path))
        result.sha256_after = hashlib.sha256(
            summary_path.read_bytes()).hexdigest()
    except Exception as error:                        # noqa: BLE001
        result.error = f"could not write the run summary: {error}"
        result.changed = False
        return result

    # The verdict is derived from the summary, so leaving it stale would put
    # two different answers in one case folder -- which is worse than either.
    try:
        after = combine_case(home, write_output=True)
        result.band_after = str((after or {}).get("band") or "")
    except Exception as error:                        # noqa: BLE001
        result.error = (
            f"the run summary was re-scored but combine_case failed "
            f"({type(error).__name__}: {error}); combined_verdict.json is now "
            f"stale against it")

    return result


def rescore(run_directory: Path, *, dry_run: bool = False,
            on_event: Callable[[str], None] | None = None) -> RescoreResult:
    """Re-score every dynamic run in a finished corpus.

    Raises `RescoreRefused` rather than editing anything it is unsure about.
    """
    say = on_event or (lambda _message: None)
    run_directory = Path(run_directory)
    manifest_path = run_directory / "manifest.json"

    if not manifest_path.is_file():
        raise RescoreRefused(
            f"no manifest at {manifest_path}. This edits a sweep's cases in "
            f"place and will not do that to a directory it cannot identify as "
            f"a sweep.")
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except Exception as error:                        # noqa: BLE001
        raise RescoreRefused(
            f"{manifest_path} will not parse ({type(error).__name__}); "
            f"nothing is edited until the record can be read.") from error

    state = document.get("state")
    if state not in TERMINAL:
        raise RescoreRefused(
            f"the run is state={state!r}, and this only re-scores a finished "
            f"one ({' or '.join(TERMINAL)}). A sweep writes into cases/ as it "
            f"collects.")

    if _sweep_running():
        raise RescoreRefused(
            "a runcontrol.sweep process is still alive (or the process table "
            "could not be read). Not while a controller is going.")

    cases = run_directory / "cases"
    if not cases.is_dir():
        raise RescoreRefused(f"no cases directory under {run_directory}")

    run_id = document.get("run_id") or run_directory.name
    result = RescoreResult(run_id=run_id, directory=run_directory,
                           dry_run=dry_run)

    summaries = find_run_summaries(cases)
    say(f"{run_id}: {len(summaries)} dynamic run(s) to re-score"
        + (" (dry run)" if dry_run else ""))
    if not summaries:
        say("nothing to do")
        return result

    for path in summaries:
        outcome = rescore_one(path, run_directory, dry_run=dry_run)
        result.cases.append(outcome)
        if outcome.error:
            say(f"  FAILED  {outcome.case}: {outcome.error}")
        elif outcome.skipped:
            say(f"  skipped {outcome.case}: {outcome.skipped}")
        elif outcome.changed:
            say(f"  {outcome.case}: {outcome.score_before} -> "
                f"{outcome.score_after} ({outcome.severity_before} -> "
                f"{outcome.severity_after})"
                + (f", band {outcome.band_before} -> {outcome.band_after}"
                   if outcome.band_after else ""))

    say(f"{'would change' if dry_run else 'changed'}: {result.changed}, "
        f"unchanged: {result.unchanged}, skipped: {result.skipped}"
        + (f", FAILED: {result.failed}" if result.failed else ""))

    if not dry_run and (result.changed or result.failed):
        record = {
            "tool": "runcontrol.rescore",
            "at": _now(),
            "run_id": run_id,
            "why": ("A corpus is scored in the guest at detonation time and "
                    "combine reads that score back rather than recomputing "
                    "it, so a scoring fix made after the run started cannot "
                    "reach it. Re-scored from the inputs the run already "
                    "recorded; no sample was detonated again."),
            "analyzer": _analyzer(),
            "originals": str(run_directory / BACKUP_DIR),
            "changed": result.changed,
            "unchanged": result.unchanged,
            "skipped": result.skipped,
            "failed": result.failed,
            "cases": [asdict(c) for c in result.cases],
        }
        path = run_directory / RECORD_NAME
        text = json.dumps(record, indent=2, sort_keys=False)
        path.write_bytes(text.encode("utf-8") + b"\n")
        say(f"record: {path}")

    return result


def _analyzer() -> dict:
    """Which code did the re-scoring, which is now part of the provenance."""
    try:
        from verdict.provenance import analyzer_provenance

        return analyzer_provenance()
    except Exception as error:                        # noqa: BLE001
        return {"error": f"{type(error).__name__}: {error}"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m runcontrol.rescore",
        description="Re-score a finished corpus against the current scoring "
                    "code, from the inputs each run already recorded.",
        epilog="Only runs against a finished sweep with no controller alive. "
               "Originals are kept under <run>/rescore-originals/ and what "
               "changed is recorded in rescore.json beside the manifest. "
               "Detonates nothing.",
    )
    parser.add_argument("run_directory", type=Path,
                        help="the sweep directory holding manifest.json")
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would change and edit nothing")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = rescore(args.run_directory, dry_run=args.dry_run,
                         on_event=lambda message: print(message, flush=True))
    except RescoreRefused as error:
        print(f"error: {error}", file=sys.stderr)
        return 3
    return 1 if result.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
