"""How much of an assembly's API surface is unknown to benign software?

Renaming reached 5 of the 22 samples nothing else fires on. The other 8 managed
ones have ordinary identifiers, so the only remaining question is what they
*call*. `dotnet_api_baseline.py` measured how common each `MemberRef` is across
228 benign managed assemblies; this scores one corpus against that.

**Rarity alone is not the signal and this does not pretend otherwise.** 60.2% of
benign references appear in exactly one assembly, so "uses rare APIs" would fire
on nearly everything. The metric here is a *proportion*: of the references this
assembly makes, what share does no benign assembly make.

**The benign side is scored leave-one-out, or the comparison is circular.** The
228 assemblies built the table, so scoring them against it would credit each one
for its own references. A reference with global prevalence 1 is used by exactly
one assembly -- the one holding it -- so for benign, "unseen by any other" is
precisely "prevalence == 1". Malware contributed nothing to the table, so for
malware it is "absent from the table". The two are then the same question.

    .venv\\Scripts\\python.exe scripts\\dotnet_api_compare.py --cases C:\\mal-bazaar-cases\\cases
    .venv\\Scripts\\python.exe scripts\\dotnet_api_compare.py --cases G:\\pf-corpus\\cases --in-baseline

`--in-baseline` says this corpus helped build the table, and switches to the
leave-one-out reading. Getting it wrong in either direction produces a number
that looks fine.

Reads `dotnet_metadata.json` from each case, so `scripts/refresh_dotnet.py` has
to have been over the corpus first.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

#: Derived by `dotnet_api_baseline.py` from the host's benign corpora and
#: committed so the guest, which has no benign software on it, can use it.
#: Pruned to references seen in more than one assembly: anything absent is rare
#: by construction, so the pruning loses nothing the metric asks about.
_BASELINE = Path(__file__).resolve().parent.parent / "data" / "dotnet_api_prevalence.json"

#: Below this an assembly makes too few references for a proportion to mean
#: anything, the same reasoning as the 50-identifier floor on renaming.
_MIN_REFS = 30


def load_baseline(path: Path) -> tuple[dict[str, int], int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["prevalence"], int(data["assemblies"])


def score(case: Path, prevalence: dict[str, int], in_baseline: bool):
    meta_path = next((p for p in (case / "dotnet_metadata.json",
                                  case / "static_analysis" / "dotnet_metadata.json")
                      if p.is_file()), None)
    if meta_path is None:
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    if not meta.get("collected") or not meta.get("is_managed"):
        return None
    refs = meta.get("member_refs") or []
    if len(refs) < _MIN_REFS:
        return None
    if in_baseline:
        # This assembly is in the table, so a reference it shares with nobody
        # has prevalence exactly 1.
        unseen = [r for r in refs if prevalence.get(r, 0) <= 1]
    else:
        unseen = [r for r in refs if r not in prevalence]
    return {"case": case.name, "refs": len(refs), "unseen": len(unseen),
            "fraction": round(len(unseen) / len(refs), 4),
            "examples": sorted(unseen)[:6]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", required=True)
    parser.add_argument("--baseline", default=str(_BASELINE))
    parser.add_argument("--in-baseline", action="store_true",
                        help="this corpus helped build the table; score it "
                             "leave-one-out")
    parser.add_argument("--show", type=int, default=10)
    args = parser.parse_args(argv)

    root = Path(args.cases)
    baseline = Path(args.baseline)
    if not root.is_dir():
        print(f"failed: {root} is not a directory")
        return 1
    if not baseline.is_file():
        print(f"failed: {baseline} does not exist -- "
              f"run scripts/dotnet_api_baseline.py on the host")
        return 1

    prevalence, built_from = load_baseline(baseline)
    rows = [r for r in (score(c, prevalence, args.in_baseline)
                        for c in sorted(p for p in root.iterdir() if p.is_dir()))
            if r]
    print(f"\n=== {len(rows)} managed assemblies in {root.parent.name}, scored "
          f"against {built_from} benign"
          f"{' (leave-one-out)' if args.in_baseline else ''}")
    if not rows:
        print("    none -- has scripts/refresh_dotnet.py been over this corpus?")
        return 0

    fractions = sorted((r["fraction"] for r in rows), reverse=True)
    mid = fractions[len(fractions) // 2]
    print(f"    median unseen fraction {mid:.3f}, "
          f"highest {fractions[0]:.3f}, lowest {fractions[-1]:.3f}")
    for cut in (0.10, 0.20, 0.30, 0.50):
        n = sum(1 for f in fractions if f >= cut)
        print(f"    >= {cut:.2f}   {n:4}   {100.0 * n / len(rows):5.1f}%")

    print(f"\n  highest, with references no benign assembly makes:")
    for r in sorted(rows, key=lambda r: -r["fraction"])[:args.show]:
        print(f"    {r['fraction']:.3f}  {r['unseen']:4}/{r['refs']:<5} "
              f"{r['case'][:34]}")
        for ref in r["examples"][:3]:
            print(f"           {ref[:72]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
