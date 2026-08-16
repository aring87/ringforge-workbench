"""Re-run the memory YARA pass over a finished run's dumps, without detonating.

Written 16 Aug 2026, after run `38f27025` reported `dumps_scanned: 12,
total_matches: 0` with a ruleset that did not contain the rule the run was
booked to exercise. Nothing about the detonation was wrong -- `RegSvcs.exe` was
dumped six times, the hollowing evidence landed -- so re-detonating to fix a
scan would have paid a whole run for a directory copy.

The dumps live in the case directory until the next revert. Point this at that
directory and it re-runs exactly the orchestrator's pass over them.

    ..\\.venv\\Scripts\\python.exe rescan_memory_yara.py <run-case-dir>
    ..\\.venv\\Scripts\\python.exe rescan_memory_yara.py <run-case-dir> --rules-dir tools\\yara\\rules

WHY IT REFUSES TO REPORT A BARE ZERO.

`rule_file_count: 1542` with `total_matches: 0` was reported by two consecutive
runs of this sample, and read both times as "the rules do not cover it". The
real cause was that `tools\\yara\\rules\\` held only the two downloaded rulesets:
hand-written rules live in `tools\\yara\\local\\` and reach the scanned tree only
when `bootstrap_yara_rules.ps1` copies them to `tools\\yara\\rules\\local\\`. A
`git pull` leaves them one directory away from anything that reads them.

So a rule that is absent and a rule that did not match produce the same number,
and the number is the one people read. This script separates them: it reports
which rule files are local, and `--expect` fails the run outright when a named
rule is not in the compiled set. Use it. An unguarded zero from this script is
worth no more than the one it was written to explain.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dynamic_analysis.memory_yara import scan_memory_dumps  # noqa: E402
from static_triage_engine.yara_scan import _collect_rule_files  # noqa: E402


def _relocate(records: list[dict], case_dir: Path) -> list[dict]:
    """Point each record at the file as it exists here, not where it was written.

    The recorded paths are the guest's (`C:\\projects\\...`). Run this against a
    case directory copied out to the host and every scan fails `file not found`
    while the counts still read `dumps_scanned: 11` -- which is the same
    zero-that-looks-like-coverage this script exists to break up. Caught by
    running the script against a copied-out run rather than by reading it.
    """
    memory = case_dir / "memory"
    for record in records:
        recorded = Path(record.get("path", ""))
        if recorded.is_file():
            continue
        for candidate in (memory / recorded.name,
                          memory / "crash_dumps" / recorded.name):
            resolved = _readable(candidate)
            if resolved:
                record["path"] = resolved
                record["relocated_from"] = str(recorded)
                break
    return records


def _readable(path: Path) -> str:
    """The form of this path that can actually be opened, or "".

    A dump named after a 64-character sha256, under a case directory copied
    somewhere deep, exceeds MAX_PATH -- the same wall `bootstrap_yara_rules.ps1`
    hit on the Elastic archive. The extended-length prefix is the way past it,
    and yara takes the prefixed path as happily as a plain one.
    """
    if path.is_file():
        return str(path)
    try:
        extended = Path("\\\\?\\" + str(path.resolve()))
        if extended.is_file():
            return str(extended)
    except OSError:
        pass
    return ""


def _load_dump_records(case_dir: Path) -> tuple[list[dict], str]:
    """Dump records and the sample path, from whichever file the run left."""
    dumps_json = case_dir / "memory" / "memory_dumps.json"
    summary_json = case_dir / "metadata" / "dynamic_run_summary.json"

    sample_path = ""
    if summary_json.is_file():
        summary = json.loads(summary_json.read_text(encoding="utf-8", errors="replace"))
        sample = summary.get("sample") or {}
        sample_path = sample.get("path") or sample.get("image") or ""

    if dumps_json.is_file():
        data = json.loads(dumps_json.read_text(encoding="utf-8", errors="replace"))
        records = [d for d in data.get("dumps", [])
                   if d.get("success") and d.get("path")]
        if records:
            return _relocate(records, case_dir), sample_path

    # Fall back to the summary, then to the files themselves. A case directory
    # copied out of the guest often loses one of these and keeps the .dmp files,
    # and the scan is worth running on the files alone.
    if summary_json.is_file():
        summary = json.loads(summary_json.read_text(encoding="utf-8", errors="replace"))
        records = [d for d in (summary.get("memory_summary") or {}).get("dumps", [])
                   if d.get("path")]
        if records:
            return _relocate(records, case_dir), sample_path

    found = sorted((case_dir / "memory").rglob("*.dmp"))
    return ([{"path": str(p), "name": p.name, "pid": 0, "trigger": "recovered"}
             for p in found], sample_path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case_dir", help="the run's case directory")
    ap.add_argument("--rules-dir", default=None,
                    help="defaults to the same resolution the orchestrator uses")
    ap.add_argument("--expect", action="append", default=[],
                    help="a rule name that must be in the compiled set; repeatable. "
                         "Absent means exit 3 rather than a zero that reads as coverage")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--json-out", default=None,
                    help="write the full result beside the run rather than only printing")
    args = ap.parse_args(argv)

    case_dir = Path(args.case_dir)
    if not case_dir.is_dir():
        print(f"!! not a directory: {case_dir}")
        return 2

    records, sample_path = _load_dump_records(case_dir)
    if not records:
        print(f"!! no dump records and no .dmp files under {case_dir / 'memory'}")
        return 2
    print(f"{len(records)} dump(s) from {case_dir}")
    if sample_path:
        print(f"sample: {sample_path}")

    # -- what is actually in the ruleset, before anything is scanned
    rules_dir = Path(args.rules_dir) if args.rules_dir else None
    if rules_dir is not None:
        files = _collect_rule_files(rules_dir)
        local = [p for p in files.values() if "local" in Path(p).parts]
        print(f"\nruleset: {len(files)} file(s) under {rules_dir}")
        print(f"  {len(local)} of them in a 'local' subdirectory")
        if not local:
            print("  !! NO LOCAL RULES ARE INSTALLED. Hand-written rules live in")
            print("     tools\\yara\\local\\ and reach the scan only via")
            print("     tools\\yara\\rules\\local\\. A zero below would mean they were")
            print("     never compiled, not that they did not match.")
        for p in sorted(local):
            print(f"     {Path(p).name}")

    result = scan_memory_dumps(
        records,
        sample_path=sample_path or records[0]["path"],
        rules_dir=args.rules_dir,
        timeout=args.timeout,
        status_cb=lambda m: print(f"  [scan] {m}"),
    )

    if result.get("error"):
        print(f"\n!! {result['error']}")
        return 2

    print(f"\nrules_dir      {result['rules_dir']}")
    print(f"rule_file_count {result['rule_file_count']}")
    print(f"counts         {json.dumps(result['counts'])}")

    print("\nper dump:")
    for d in result.get("per_dump", result.get("dumps", [])):
        name = Path(d.get("path", "")).name
        rules = ", ".join(d.get("rules") or []) or "-"
        err = f"  !! {d['error']}" if d.get("error") else ""
        print(f"  {name:44} {rules}{err}")

    memory_only = result.get("memory_only_rules") or []
    print(f"\nmemory-only rules: {', '.join(memory_only) or 'none'}")

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nwritten to {out}")

    # -- the guard the whole script exists for
    if args.expect:
        seen = {r for d in result.get("per_dump", result.get("dumps", []))
                for r in (d.get("rules") or [])}
        compiled_names = set()
        files = _collect_rule_files(Path(result["rules_dir"])) if result.get("rules_dir") else {}
        for path in files.values():
            try:
                compiled_names.update(
                    line.split()[1].strip("{ ")
                    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.startswith("rule ")
                )
            except OSError:
                continue
        missing = [name for name in args.expect if name not in compiled_names]
        if missing:
            print(f"\n*** EXPECTED RULE NOT IN THE RULESET: {', '.join(missing)}")
            print("    The zero above says nothing about whether it matches.")
            print("    Install it and run this again:")
            print("      Copy-Item tools\\yara\\local\\<rule>.yar tools\\yara\\rules\\local\\ -Force")
            return 3

        # A rule cannot be said to have missed a dump that was never read. This
        # guard is here because the first version of this script printed
        # "compiled but did not match" over eleven scans that all failed
        # file-not-found.
        failed = int(result["counts"].get("dumps_failed", 0))
        if failed:
            print(f"\n*** VOID: {failed} of {result['counts'].get('dumps_scanned', 0)} "
                  f"dumps could not be read, so a non-match means nothing.")
            for d in result.get("per_dump", result.get("dumps", [])):
                if d.get("error"):
                    print(f"    {Path(d.get('path','')).name}: {d['error']}")
            return 4

        for name in args.expect:
            state = "matched" if name in seen else "compiled, read every dump, did not match"
            print(f"  {name}: {state}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
