"""Extract CLR facts over an existing corpus, without re-running the engine.

**The 22 samples that survive every static category are 59% managed code**, and
nothing in the pipeline reads CLR metadata. `scripts/dotnet_summary.py` is the
collector; this applies it to a corpus already on disk, the same way
`refresh_version_info.py` applied the version-info fix. Re-running the engine to
read one heap would mean capa and FLOSS again, and neither feeds this.

    .venv\\Scripts\\python.exe scripts\\refresh_dotnet.py --cases C:\\mal-bazaar-cases\\cases --apply
    .venv\\Scripts\\python.exe scripts\\refresh_dotnet.py --cases C:\\mal-bazaar-cases\\cases --report

Writes `dotnet_metadata.json` beside the other collector output and touches
nothing else. `--report` prints the distribution rather than the per-case detail,
which is the number a category would be chosen from.

**No category exists yet, deliberately.** The benign floor is measured -- 592
binaries, 39 of them measurable managed assemblies, highest unreadable-identifier
fraction 0.099 on `protobuf-net.Core.dll`, and zero protector markers. Nothing
fires at any cut from 0.10 upward. The malware side is unmeasured because the
samples are on the guest, and picking a threshold before seeing it would be
choosing a number and calling it a measurement.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.dotnet_summary import extract_dotnet_metadata  # noqa: E402
from scripts.refresh_iocs import find_sample  # noqa: E402

_CUTS = (0.10, 0.20, 0.30, 0.40, 0.50)


def refresh(case: Path, apply: bool) -> dict[str, Any]:
    started = time.time()
    sample = find_sample(case)
    if sample is None:
        return {"case": case.name, "ok": False, "reason": "no sample in case dir"}
    try:
        meta = extract_dotnet_metadata(sample)
    except Exception as error:  # the extractor should not raise, but a corpus
        return {"case": case.name, "ok": False,   # pass must not die on one file
                "reason": f"{type(error).__name__}: {error}"}
    if apply:
        try:
            out = case / "dotnet_metadata.json"
            temp = out.with_suffix(".json.tmp")
            temp.write_text(json.dumps(meta, indent=2, sort_keys=True),
                            encoding="utf-8")
            temp.replace(out)
        except Exception as error:
            return {"case": case.name, "ok": False,
                    "reason": f"write failed: {type(error).__name__}: {error}"}
    return {"case": case.name, "ok": True, "meta": meta,
            "seconds": round(time.time() - started, 3)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", required=True)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--apply", action="store_true",
                        help="write dotnet_metadata.json; without it, report only")
    parser.add_argument("--report", action="store_true",
                        help="print the distribution a category would be chosen from")
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    root = Path(args.cases)
    if not root.is_dir():
        print(f"failed: {root} is not a directory")
        return 1

    cases = sorted(p for p in root.iterdir() if p.is_dir())
    if args.limit:
        cases = cases[:args.limit]
    print(f"{len(cases)} cases in {root}"
          f"{'' if args.apply else '   (dry run -- pass --apply to write)'}")

    results = []
    started = time.time()
    for index, case in enumerate(cases, 1):
        results.append(refresh(case, args.apply))
        if index % 25 == 0 or index == len(cases):
            ok = sum(1 for r in results if r.get("ok"))
            print(f"  {index}/{len(cases)}  {ok} ok, {time.time() - started:.0f}s")

    ok = [r for r in results if r.get("ok")]
    bad = [r for r in results if not r.get("ok")]
    metas = [r["meta"] for r in ok]
    managed = [m for m in metas if m.get("is_managed")]
    unparsed = [m for m in metas if not m.get("collected")]
    il_only = [m for m in managed if m.get("il_only")]
    measurable = [m for m in il_only if m.get("identifiers_sufficient")]

    print()
    print(f"{'wrote' if args.apply else 'would write'} {len(ok)} of {len(cases)}")
    if bad:
        print(f"  left untouched: {len(bad)}")
        for r in bad[:5]:
            print(f"      {r['case'][:44]}  {r.get('reason', '?')[:50]}")
    print(f"  managed            {len(managed):4} of {len(ok)}")
    print(f"  IL-only            {len(il_only):4}   "
          f"({len(managed) - len(il_only)} mixed-mode C++/CLI excluded)")
    print(f"  measurable         {len(measurable):4}   "
          f"(at least 50 identifiers)")
    if unparsed:
        print(f"  unparseable        {len(unparsed):4}   <-- reported unknown, not clean")

    if args.report and measurable:
        rates = sorted(((m["unreadable_fraction"], m.get("identifier_count", 0))
                        for m in measurable), reverse=True)
        print(f"\n  unreadable-identifier fraction, {len(measurable)} measurable:")
        for cut in _CUTS:
            hit = sum(1 for r, _ in rates if r >= cut)
            print(f"      >= {cut:.2f}   {hit:4}   "
                  f"{100.0 * hit / len(ok):5.1f}% of corpus")
        print("  highest:")
        for r, ids in rates[:8]:
            print(f"      {r:.3f}   {ids:6} identifiers")
        protectors: dict[str, int] = {}
        for m in managed:
            for p in m.get("protectors") or []:
                protectors[p] = protectors.get(p, 0) + 1
        print(f"  protector markers: {protectors or 'none'}")

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"written: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
