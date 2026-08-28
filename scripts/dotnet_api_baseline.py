"""How common is each .NET API reference in benign software?

**Renaming reached half the managed blind spot and no further.** It recovers 5
of the 22 samples nothing else fires on; 8 of the rest are .NET assemblies with
entirely ordinary identifiers, invisible because nothing reads what a managed
binary *calls*. `MemberRef` names every external method in plain text, so the
data was never the problem.

**The problem is deciding what counts as interesting, and this file refuses to
decide it by hand.** A list of suspicious .NET APIs written while looking at the
malware corpus is tuned to the test set -- the error `_ALWAYS_SIGNS` was rebuilt
to avoid, and the one that made `stripped_metadata` look like the strongest
signal in the table for a week. Instead this measures **prevalence**: what
fraction of benign managed assemblies reference each method. A reference no
benign assembly makes is interesting because of that fact, not because someone
thought it sounded alarming.

    .venv\\Scripts\\python.exe scripts\\dotnet_api_baseline.py --out G:\\dotnet-api-baseline.json
    .venv\\Scripts\\python.exe scripts\\dotnet_api_baseline.py --report G:\\dotnet-api-baseline.json

Draws from every benign source that has one: the two case corpora, and any
`benign_survey.py` JSON, whose rows carry the paths.

**No category ships from this yet, and none should until the malware side is
measured.** The output is a prevalence table, not a threshold. What it enables
is the honest question -- *how many references does this assembly make that
essentially no benign software makes* -- asked against a number rather than an
intuition.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_DEFAULT_CASES = (
    r"G:\static-corpus-full\cases",
    r"G:\pf-corpus\cases",
)
_DEFAULT_SURVEYS = (
    r"G:\benign-survey.json",
    r"G:\installer-survey.json",
    r"G:\installer-survey-pf.json",
)


def _binaries_from_cases(root: Path):
    for case in sorted(p for p in root.iterdir() if p.is_dir()):
        summary = case / "summary.json"
        if not summary.is_file():
            continue
        try:
            info = (json.loads(summary.read_text(encoding="utf-8",
                                                 errors="replace"))
                    .get("sample") or {})
        except Exception:
            continue
        for key in ("path_case", "path_original"):
            candidate = info.get(key)
            if candidate and Path(candidate).is_file():
                yield Path(candidate)
                break


def _binaries_from_survey(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return
    for row in data.get("rows", []):
        # Only what the survey already identified as managed, so this does not
        # re-parse several hundred native binaries to learn nothing.
        if not row.get("managed"):
            continue
        candidate = row.get("path")
        if candidate and Path(candidate).is_file():
            yield Path(candidate)


def build(cases: list[Path], surveys: list[Path]) -> dict[str, Any]:
    from scripts.dotnet_summary import extract_dotnet_metadata

    seen: set[str] = set()
    paths: list[Path] = []
    for root in cases:
        if root.is_dir():
            for p in _binaries_from_cases(root):
                if str(p).lower() not in seen:
                    seen.add(str(p).lower())
                    paths.append(p)
    for survey in surveys:
        if survey.is_file():
            for p in _binaries_from_survey(survey):
                if str(p).lower() not in seen:
                    seen.add(str(p).lower())
                    paths.append(p)

    assemblies = 0
    unparseable = 0
    prevalence: Counter[str] = Counter()
    per_assembly: list[int] = []
    for index, path in enumerate(paths, 1):
        meta = extract_dotnet_metadata(path)
        if not meta.get("collected"):
            unparseable += 1
            continue
        if not meta.get("is_managed"):
            continue
        refs = meta.get("member_refs") or []
        if not refs:
            continue
        assemblies += 1
        per_assembly.append(len(refs))
        # Once per assembly, not once per call site: prevalence is "how many
        # programs use this", not "how often is it used".
        prevalence.update(set(refs))
        if index % 200 == 0:
            print(f"  {index}/{len(paths)} scanned, {assemblies} managed")

    return {
        "assemblies": assemblies,
        "candidates_scanned": len(paths),
        "unparseable": unparseable,
        "median_refs": sorted(per_assembly)[len(per_assembly) // 2]
        if per_assembly else 0,
        "prevalence": dict(prevalence.most_common()),
    }


def report(data: dict[str, Any], rare_at: float) -> None:
    total = data["assemblies"]
    prevalence: dict[str, int] = data["prevalence"]
    print(f"\n=== {total} benign managed assemblies, "
          f"{len(prevalence)} distinct API references")
    print(f"    {data['candidates_scanned']} binaries scanned, "
          f"{data['unparseable']} unparseable, "
          f"median {data['median_refs']} references per assembly")

    counts = sorted(prevalence.values(), reverse=True)
    once = sum(1 for c in counts if c == 1)
    print(f"\n  {once} references ({100.0 * once / len(prevalence):.1f}%) appear "
          f"in exactly one assembly")
    for cut in (0.50, 0.20, 0.05, 0.01):
        n = sum(1 for c in counts if c / total >= cut)
        print(f"    used by >= {cut:5.0%} of assemblies: {n:6}")

    print(f"\n  the most universal -- a reference here says nothing at all")
    for ref, count in list(prevalence.items())[:8]:
        print(f"      {100.0 * count / total:5.1f}%  {ref[:66]}")

    print(f"\n  what a rarity rule would key on: references under "
          f"{rare_at:.0%} of benign assemblies")
    print(f"      {sum(1 for c in counts if c / total < rare_at)} of "
          f"{len(prevalence)} references qualify as rare")
    print(f"      -- which is most of them, so rarity alone is not the rule.")
    print(f"      The malware side has to say how many rare references an")
    print(f"      assembly makes before that count means anything.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="")
    parser.add_argument("--report", default="")
    parser.add_argument("--cases", action="append", default=[])
    parser.add_argument("--survey", action="append", default=[])
    parser.add_argument("--rare-at", type=float, default=0.01)
    args = parser.parse_args(argv)

    if args.report:
        path = Path(args.report)
        if not path.is_file():
            print(f"failed: {path} does not exist")
            return 1
        report(json.loads(path.read_text(encoding="utf-8")), args.rare_at)
        return 0

    if not args.out:
        print("failed: pass --out to build, or --report to read one back")
        return 1

    cases = [Path(c) for c in (args.cases or list(_DEFAULT_CASES))]
    surveys = [Path(s) for s in (args.survey or list(_DEFAULT_SURVEYS))]
    data = build(cases, surveys)
    Path(args.out).write_text(json.dumps(data, indent=1), encoding="utf-8")
    print(f"written: {args.out}")
    report(data, args.rare_at)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
