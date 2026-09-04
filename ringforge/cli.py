"""`ringforge` — the command line over the analysis modules.

**Why this exists.** Every module's logic is importable now, but four of the
five were still GUI-only: to combine a case you opened a window and clicked
Scan. That blocks automation, batch corpora, scheduled re-scoring, and anything
downstream that wants the verdict as data.

**`--json` writes the verdict to stdout and nothing else.** Progress and
diagnostics go to stderr, so `ringforge combine <case> --json | jq` works and a
pipeline can trust the stream. That is the contract this file has to keep.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

#: Bands `verdict.model` can return, weakest first. `--fail-on` names one and
#: everything at or above it exits non-zero.
BAND_ORDER = (
    "Nothing Collected",
    "No Evidence",
    "Single Observation",
    "Corroborated",
    "Strongly Corroborated",
)


def _err(message: str) -> None:
    """Human output goes to stderr so `--json` owns stdout alone."""
    print(message, file=sys.stderr)


def _emit(payload: Mapping[str, Any], pretty: bool) -> None:
    json.dump(payload, sys.stdout,
              indent=2 if pretty else None,
              ensure_ascii=False, default=str)
    sys.stdout.write("\n")


def _band_rank(band: str) -> int:
    try:
        return BAND_ORDER.index(str(band))
    except ValueError:
        return -1


def _summarise(result: Mapping[str, Any]) -> str:
    """The verdict as a person reads it, including what did not run.

    Coverage is on the same screen as the band deliberately. A verdict without
    it is the thing this project's scoring model was rewritten to stop
    producing.
    """
    lines = [
        f"verdict   : {result.get('verdict', '-')}",
        f"severity  : {result.get('severity', '-')}",
        f"band      : {result.get('band', '-')}",
        f"score     : {result.get('score', '-')}  ({result.get('score_model', '-')})",
    ]
    run = result.get("modules_run") or []
    absent = result.get("modules_absent") or []
    lines.append(f"modules   : ran {', '.join(run) or 'none'}"
                 + (f" | absent {', '.join(absent)}" if absent else ""))

    if not result.get("coverage_complete", True):
        uncollected = result.get("uncollected_categories") or []
        lines.append("coverage  : INCOMPLETE"
                     + (f" — {', '.join(uncollected)} not checked"
                        if uncollected else ""))

    evidence = [e for e in (result.get("evidence") or []) if e.get("reason")]
    if evidence:
        lines.append("evidence  :")
        lines += [f"  - [{e.get('module', '?')}] {e.get('reason', '')}"
                  for e in evidence]
    return "\n".join(lines)


def cmd_combine(args: argparse.Namespace) -> int:
    from static_triage_engine.combine_case import case_home, combine_case

    home = case_home(Path(args.case_dir))
    if not home.exists():
        _err(f"case folder does not exist: {home}")
        return 2

    # **`--no-write` matters more than it looks.** `cases/` is gitignored, so
    # writing `combined_verdict.json` is an unversioned overwrite. A pipeline
    # that only wants to read a verdict should not have to mutate the case to
    # get one.
    result = combine_case(home, write_output=not args.no_write)

    if args.json:
        _emit(result, args.pretty)
    else:
        print(_summarise(result))
        if not args.no_write:
            _err(f"wrote {home / 'combined_verdict.json'}")

    if args.fail_on:
        threshold = _band_rank(args.fail_on)
        if threshold >= 0 and _band_rank(result.get("band", "")) >= threshold:
            return 1
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from static_triage_engine.engine import run_case

    # Progress writes to stdout, which would corrupt a JSON stream.
    show_progress = not (args.no_progress or args.json)
    result = run_case(args.sample, case_name=args.case,
                      show_progress=show_progress)

    if args.json:
        _emit(result, args.pretty)
        return 0

    print(f"case      : {result.get('case_dir')}")
    print(f"verdict   : {result.get('verdict', '-')}")
    print(f"severity  : {result.get('severity', '-')}")
    print(f"score     : {result.get('risk_score', '-')}")
    print(f"report    : {result.get('report_html')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ringforge",
        description="Static, dynamic, API-spec and browser-extension triage "
                    "with one corroboration-based verdict model.")
    sub = parser.add_subparsers(dest="command", required=True)

    combine = sub.add_parser(
        "combine",
        help="pool every module that ran on a case and band it once",
        description="Reads whatever each module left in the case folder and "
                    "produces one verdict. Modules that did not run are "
                    "reported as absent rather than counted as clean.")
    combine.add_argument("case_dir",
                         help="case folder, or any module directory inside one")
    combine.add_argument("--json", action="store_true",
                         help="write the verdict to stdout as JSON")
    combine.add_argument("--pretty", action="store_true",
                         help="indent the JSON")
    combine.add_argument("--no-write", action="store_true",
                         help="do not write combined_verdict.json")
    combine.add_argument("--fail-on", metavar="BAND", choices=BAND_ORDER,
                         help="exit 1 when the band reaches this or higher: "
                              + ", ".join(BAND_ORDER))
    combine.set_defaults(func=cmd_combine)

    scan = sub.add_parser("scan", help="run static triage on one sample")
    scan.add_argument("sample")
    scan.add_argument("--case", default=None, help="case name (default: stem)")
    scan.add_argument("--json", action="store_true",
                      help="write the run summary to stdout as JSON")
    scan.add_argument("--pretty", action="store_true", help="indent the JSON")
    scan.add_argument("--no-progress", action="store_true")
    scan.set_defaults(func=cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _err("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
