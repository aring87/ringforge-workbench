"""What the `dangerous_capability` double-count fixes do to real VERDICTS.

`capability_sweep.py` measures how often the category fires under each
variant. A firing rate is not a verdict: a category that stops firing may or
may not move a band, depending on what else the case carries. This measures
the part a reader sees -- the band -- over every usable detonated case:

    .venv\\Scripts\\python.exe scripts\\capability_verdicts.py

**Read-only.** Each case is re-combined with `combine_case(write_output=False)`
while `categories.high_signal_matches` -- what the category counts -- is
patched for the duration. Nothing under `cases/` is written.

**The socket-family fix shipped 29 Sep** on the result below, so the control
is now the shipped behaviour and "before 29 Sep" is the old one. The corpora
were re-combined (`runcontrol.recombine`) so the control reproduces them.

**The unpatched pass is the control** and must reproduce every stored band.
Measured 28 Sep: all 208 bands reproduced; 20 cases differed in score by 1-4
points, every one of them in the static *context* score, which never affects
a band. If the control ever reproduces fewer bands than there are cases,
nothing below it means anything.

**Result, 28 Sep, 98 benign (`benign-102-v2`) and 110 malware (`mal-112b` +
`mal-112b-s1`):**

* socket family counts once -- benign: 1 band down (Aura-Wallpaper-Service,
  Corroborated -> Single Observation); malware: **no band moves**, though
  strong `dangerous_capability` falls 21 -> 12.
* no redundant c2 parent -- benign: 1 band down (ArmourySwAgent); malware:
  **3 bands down**, all Amadey, Corroborated 42 -> Single Observation 22.

Nothing here edits the set.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

#: Detonated corpora by side. The diagnostic runs repeat samples counted here.
_RUNS = {
    "benign": [r"G:\ringforge-runs\benign-102-v2"],
    "malware": [r"G:\ringforge-runs\mal-112b", r"G:\ringforge-runs\mal-112b-s1"],
}


def usable_homes(run_directory: Path):
    """(case, case home) for every usable row of a sweep manifest."""
    manifest = json.loads((run_directory / "manifest.json").read_text(encoding="utf-8"))
    rows = next(v for v in manifest.values()
                if isinstance(v, list) and v and isinstance(v[0], dict) and "case" in v[0])
    for row in rows:
        if (row.get("attempts") or [{}])[-1].get("usable"):
            case = row["case"]
            # The transport's doubled `cases/<case>/<case>/` segment.
            yield case, run_directory / "cases" / case / case


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args(argv)

    import static_triage_engine.categories as categories
    import static_triage_engine.combine_case as combine
    from capability_sweep import _REDUNDANT_PARENT
    from static_triage_engine.scoring import HIGH_SIGNAL_CAPABILITIES, high_signal_matches

    # **What `dangerous_capability` counts is `categories.high_signal_matches`**,
    # so that is what each variant replaces. Until 29 Sep this patched
    # `categories.HIGH_SIGNAL_CAPABILITIES`; the category stopped reading that
    # name when the socket fix shipped, and patching it would now change
    # nothing -- every variant silently reproducing the control.
    variants = {
        "control (shipped: socket once)": high_signal_matches,
        "before 29 Sep (each socket member)": (
            lambda ns: sorted(set(ns or ()) & HIGH_SIGNAL_CAPABILITIES)),
        "shipped + no redundant c2 parent": (
            lambda ns: [m for m in high_signal_matches(ns) if m != _REDUNDANT_PARENT]),
    }
    control = "control (shipped: socket once)"

    cases = {side: [c for run in runs if Path(run).is_dir()
                    for c in usable_homes(Path(run))]
             for side, runs in _RUNS.items()}
    if not all(cases.values()):
        print("one side has no detonated cases on this host; nothing to compare")
        return 1

    stored = {}
    for side, pairs in cases.items():
        for name, home in pairs:
            verdict = json.loads((home / "combined_verdict.json").read_text(encoding="utf-8-sig"))
            stored[(side, name)] = verdict["band"]

    original = categories.high_signal_matches
    results = {}
    try:
        for label, count in variants.items():
            categories.high_signal_matches = count
            for side, pairs in cases.items():
                for name, home in pairs:
                    verdict = combine.combine_case(home, write_output=False)
                    dc = next((e for e in verdict.get("evidence", [])
                               if e["name"] == "dangerous_capability"), None)
                    results[(label, side, name)] = (
                        verdict["band"], verdict["score"],
                        None if dc is None else ("strong" if dc.get("strong") else "present"))
    finally:
        categories.high_signal_matches = original

    reproduced = sum(1 for (side, name), band in stored.items()
                     if results[(control, side, name)][0] == band)
    print(f"CONTROL: {reproduced} of {len(stored)} stored bands reproduced")
    if reproduced != len(stored):
        print("  the control does not reproduce the corpus; stopping here")
        return 1

    for side, pairs in cases.items():
        n = len(pairs)
        print(f"\n=== {side}: {n} cases")
        print(f"{'variant':26} {'dc present':>11} {'dc strong':>10} "
              f"{'>No Ev':>7} {'>=Corr':>7} {'Strong':>7}")
        for label in variants:
            rows = [results[(label, side, name)] for name, _ in pairs]
            present = sum(1 for r in rows if r[2])
            strong = sum(1 for r in rows if r[2] == "strong")
            above = sum(1 for r in rows if r[0] != "No Evidence")
            corroborated = sum(1 for r in rows
                               if r[0] in ("Corroborated", "Strongly Corroborated"))
            top = sum(1 for r in rows if r[0] == "Strongly Corroborated")
            print(f"{label:26} {present:4} {100 * present / n:5.1f}% "
                  f"{strong:3} {100 * strong / n:5.1f}% {100 * above / n:6.1f}% "
                  f"{100 * corroborated / n:6.1f}% {100 * top / n:6.1f}%")
            moves = collections.Counter()
            for name, _ in pairs:
                before = results[(control, side, name)]
                after = results[(label, side, name)]
                if before[0] != after[0]:
                    moves[f"{before[0]} -> {after[0]}"] += 1
                    print(f"{'':28}{name}: {before[0]} {before[1]} -> "
                          f"{after[0]} {after[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
