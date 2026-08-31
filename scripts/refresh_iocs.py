"""Re-run only the strings and IOC steps over an existing corpus.

**`embedded_network_indicators` has never been able to fire.** `step_strings`
shelled out to `strings`, which is not on PATH on Windows; it wrote the empty
stdout to `strings.txt` anyway, and `step_iocs` read that empty file, found
nothing and returned success. The category therefore reported
`collected=True, present=False` -- a clean bill from a tool that was never
installed -- across 829 samples on four corpora, 229 of them real malware which
between them yielded zero domains, zero URLs and zero IPs.

That row is void everywhere and has to be measured again. Re-running the whole
engine to do it would be absurd: capa and FLOSS dominate the cost and neither
feeds this category. **Every case directory already holds its own sample**,
because `run_case` copies it there, so the two cheap steps can simply be run
again in place.

    .venv\\Scripts\\python.exe scripts\\refresh_iocs.py --cases C:\\mal-bazaar-cases\\cases
    .venv\\Scripts\\python.exe scripts\\benign_rates.py --module static --cases C:\\mal-bazaar-cases\\cases

Roughly a second per case rather than a minute. Nothing else in the case is
touched: capa, YARA, signing, PE metadata and the run log are left exactly as
they were, so the only number that can move is the one that was wrong.

Runs wherever the cases are. For the malware corpora that is the analysis
guest, and nothing here executes a sample -- it reads bytes and matches
patterns.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

#: The sample `run_case` copied in. Anything else in the directory is output.
_NOT_A_SAMPLE = {
    ".json", ".txt", ".log", ".csv", ".html", ".md", ".yar", ".yara",
}


def find_sample(case: Path) -> Path | None:
    """The binary a case was built from, or None.

    `run_case` copies the sample into the case directory under the case name,
    so it is the one file there that is not analysis output.
    """
    best: Path | None = None
    for entry in case.iterdir():
        if not entry.is_file():
            continue
        if entry.suffix.lower() in _NOT_A_SAMPLE:
            continue
        # Prefer the one named after the case; fall back to any non-output file
        # so a renamed or extensionless sample is still found.
        if entry.stem == case.name:
            return entry
        if best is None:
            best = entry
    return best


def refresh(case: Path, skip_strings: bool = False) -> dict[str, Any]:
    """Re-run strings and IOC extraction for one case. Never raises.

    `skip_strings` re-runs only the extraction, against the dump already in the
    case. That is what a change to `ioc_extract.py` needs -- the strings are not
    what moved -- and it means a corpus whose dumps were produced elsewhere can
    be re-extracted on a machine with no `strings` binary at all, which is the
    situation on this host.
    """
    from static_triage_engine.steps import step_iocs, step_strings

    started = time.time()
    sample = find_sample(case)
    if sample is None and not skip_strings:
        return {"case": case.name, "ok": False, "reason": "no sample in case dir"}

    try:
        if skip_strings:
            dump = case / "strings.txt"
            if not dump.is_file() or dump.stat().st_size == 0:
                return {"case": case.name, "ok": False,
                        "reason": "no strings.txt to re-extract from"}
            strings_result = {"returncode": 0, "string_count": 0}
        else:
            strings_result = step_strings(sample, case)
        if int(strings_result.get("returncode", 0) or 0) != 0:
            return {"case": case.name, "ok": False,
                    "reason": f"strings failed: {strings_result.get('stderr','')[:80]}"}

        ioc_result = step_iocs(case)
        counts = ioc_result.get("counts") or {}
        observables = sum(v for k, v in counts.items()
                          if k in ("urls", "domains", "ips", "emails",
                                   "paths", "registry_keys", "unc_paths")
                          and isinstance(v, int))
        return {"case": case.name, "ok": True,
                "strings": strings_result.get("string_count", 0),
                "observables": observables,
                "counts": {k: v for k, v in counts.items() if v},
                "seconds": round(time.time() - started, 2)}
    except Exception as error:
        return {"case": case.name, "ok": False,
                "reason": f"{type(error).__name__}: {error}"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", required=True,
                        help="the `cases` directory of a corpus")
    parser.add_argument("--limit", type=int, default=0,
                        help="stop after this many, for a quick look")
    parser.add_argument("--out", default="",
                        help="write the per-case detail here")
    parser.add_argument("--skip-strings", action="store_true",
                        help="re-extract IOCs from the dump already in each "
                             "case; needs no `strings` binary")
    args = parser.parse_args(argv)

    root = Path(args.cases)
    if not root.is_dir():
        print(f"failed: {root} is not a directory")
        return 1

    cases = sorted(p for p in root.iterdir() if p.is_dir())
    if args.limit:
        cases = cases[:args.limit]
    print(f"{len(cases)} cases in {root}")

    results: list[dict[str, Any]] = []
    started = time.time()
    for index, case in enumerate(cases, 1):
        results.append(refresh(case, skip_strings=args.skip_strings))
        if index % 25 == 0 or index == len(cases):
            ok = sum(1 for r in results if r.get("ok"))
            found = sum(1 for r in results if r.get("observables"))
            print(f"  {index}/{len(cases)}  {ok} ok, {found} with observables, "
                  f"{time.time() - started:.0f}s elapsed")

    ok = [r for r in results if r.get("ok")]
    bad = [r for r in results if not r.get("ok")]
    with_obs = [r for r in ok if r.get("observables")]

    print()
    print(f"refreshed {len(ok)} of {len(cases)}")
    if bad:
        reasons: dict[str, int] = {}
        for r in bad:
            key = str(r.get("reason", "?")).split(":")[0]
            reasons[key] = reasons.get(key, 0) + 1
        print("  failed:", reasons)
    if ok:
        total_strings = sum(r.get("strings", 0) for r in ok)
        print(f"  {total_strings:,} strings extracted "
              f"(was 0 -- `strings` was never installed)")
        print(f"  {len(with_obs)} of {len(ok)} cases now carry observables")
        rollup: dict[str, int] = {}
        for r in with_obs:
            for k, v in (r.get("counts") or {}).items():
                rollup[k] = rollup.get(k, 0) + int(v)
        for k, v in sorted(rollup.items(), key=lambda kv: -kv[1]):
            print(f"      {k:>18}: {v}")

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"written: {args.out}")

    print()
    print("Re-measure with:")
    print(f"    .venv\\Scripts\\python.exe scripts\\benign_rates.py "
          f"--module static --cases {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
