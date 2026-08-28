"""A wide, cheap benign corpus for calibrating thresholds -- not for measuring rates.

**Three thresholds are currently set against 592 binaries, and each is limited
by a different thinness in that corpus.**

* `_ALWAYS_SIGNS` in `deceptive_file_identity` holds 8 vendors, because those
  are the ones System32 and Program Files carry at four samples or more. A
  bazaar sample claiming `Windows Defender` and a datalake sample claiming
  `Avira GmbH` both go uncaught for want of a benign baseline naming them.
* `obfuscated_managed_code` is calibrated on **39** measurable managed
  assemblies. Commercial .NET is legitimately obfuscated -- Dotfuscator and
  SmartAssembly are products people buy -- and 39 is far too few to say what
  that population looks like.
* `high_entropy_sections` sits at 7.5 partly because both corpora are
  *installed* software and contain almost none of the installers where
  legitimate packing lives.

**This does not run capa, YARA or the IOC pass, and that is the point.** None of
the three questions above touches them, and they cost 30-85 seconds a binary
against roughly one for everything here. A survey of 1,200 binaries is twenty
minutes; the same corpus through `static_corpus.py` is most of a day.

    .venv\\Scripts\\python.exe scripts\\benign_survey.py --out G:\\benign-survey.json
    .venv\\Scripts\\python.exe scripts\\benign_survey.py --report G:\\benign-survey.json

**It is a calibration corpus and must not be read as a category corpus.** The
rates in `docs/ROADMAP.md` come from cases where every collector ran; nothing
here can move them, because four of the eight categories cannot fire on what
this collects. It answers "what does ordinary software look like on these three
axes", which is a different question from "how often does a category fire".

Every sample is *presumed* benign because of where it was installed from. That
presumption is this script's weak point and is stated rather than hidden.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

#: Installed software, which is presumed benign because something installed it.
#: `Downloads` is deliberately absent: on this bench it holds the malware
#: corpora, and an analyst's download folder is the wrong place to learn what
#: ordinary software looks like.
_DEFAULT_ROOTS = (
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Windows\SysWOW64",
)
_EXTENSIONS = (".exe", ".dll")

#: Draw evenly across vendors rather than across files. A uniform draw over
#: Program Files returns 40% Microsoft, which is how the first version of every
#: corpus in this project went wrong.
_PER_VENDOR = 8


def _vendor_of(path: Path, root: Path) -> str:
    """The top directory under the root -- the closest thing to a publisher."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return root.name
    return rel.parts[0] if len(rel.parts) > 1 else root.name


def _candidates(root: Path, max_depth: int) -> dict[str, list[Path]]:
    by_vendor: dict[str, list[Path]] = defaultdict(list)
    root_depth = len(root.parts)
    for path in root.rglob("*"):
        try:
            if len(path.parts) - root_depth > max_depth:
                continue
            if path.suffix.lower() not in _EXTENSIONS or not path.is_file():
                continue
        except OSError:
            continue
        by_vendor[_vendor_of(path, root)].append(path)
    return by_vendor


def _survey_one(path: Path) -> dict[str, Any]:
    from static_triage_engine.engine import verify_authenticode_cached
    from scripts.dotnet_summary import extract_dotnet_metadata
    from scripts.pe_meta import extract_pe_metadata

    row: dict[str, Any] = {"path": str(path), "name": path.name}
    try:
        signing = verify_authenticode_cached(path, {})
        row["verify_ok"] = bool(signing.get("verify_ok"))
        row["timestamp_verified"] = bool(signing.get("timestamp_verified"))
        row["subject"] = str(signing.get("subject") or "")[:120]
    except Exception as error:
        row["signing_error"] = f"{type(error).__name__}: {error}"[:120]
    try:
        pe = extract_pe_metadata(path)
        version = pe.get("version_info") or {}
        row["company"] = str(version.get("CompanyName") or "").strip()
        row["version_fields"] = len([v for v in version.values() if str(v).strip()])
        row["version_collected"] = bool(pe.get("version_info_collected"))
        sections = [s for s in (pe.get("sections") or [])
                    if (s.get("raw_size") or 0) > 0]
        row["exec_entropy"] = round(max(
            (float(s.get("entropy") or 0) for s in sections
             if int(s.get("characteristics") or 0) & 0x20000000), default=0.0), 4)
    except Exception as error:
        row["pe_error"] = f"{type(error).__name__}: {error}"[:120]
    try:
        dotnet = extract_dotnet_metadata(path)
        row["managed"] = bool(dotnet.get("is_managed"))
        row["il_only"] = bool(dotnet.get("il_only"))
        row["identifiers_sufficient"] = bool(dotnet.get("identifiers_sufficient"))
        row["unreadable_fraction"] = dotnet.get("unreadable_fraction")
        row["protectors"] = dotnet.get("protectors") or []
    except Exception as error:
        row["dotnet_error"] = f"{type(error).__name__}: {error}"[:120]
    return row


def collect(roots: list[Path], count: int, per_vendor: int, seed: int,
            depth: int, workers: int) -> dict[str, Any]:
    rng = random.Random(seed)
    chosen: list[Path] = []
    provenance: dict[str, Any] = {"roots": [], "seed": seed,
                                  "per_vendor": per_vendor, "max_depth": depth}
    for root in roots:
        if not root.is_dir():
            provenance["roots"].append({"root": str(root), "present": False})
            continue
        by_vendor = _candidates(root, depth)
        picked = 0
        for vendor, files in sorted(by_vendor.items()):
            rng.shuffle(files)
            take = files[:per_vendor]
            chosen.extend(take)
            picked += len(take)
        provenance["roots"].append({
            "root": str(root), "present": True, "vendors": len(by_vendor),
            "available": sum(len(v) for v in by_vendor.values()), "picked": picked})

    rng.shuffle(chosen)
    if count and len(chosen) > count:
        chosen = chosen[:count]
    provenance["sampled"] = len(chosen)

    rows: list[dict[str, Any]] = []
    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for index, row in enumerate(pool.map(_survey_one, chosen), 1):
            rows.append(row)
            if index % 100 == 0 or index == len(chosen):
                print(f"  {index}/{len(chosen)}  {time.time() - started:.0f}s")
    return {"provenance": provenance, "rows": rows}


def report(data: dict[str, Any], min_samples: int, threshold: float) -> None:
    rows = data["rows"]
    print(f"\n=== {len(rows)} binaries surveyed")
    for entry in data["provenance"]["roots"]:
        if entry.get("present"):
            print(f"    {entry['root']:34} {entry['vendors']:4} vendors, "
                  f"{entry['available']:6} files, {entry['picked']:5} drawn")

    from static_triage_engine.categories import _ALWAYS_SIGNS, _vendor_key

    tally: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    example: dict[str, str] = {}
    for r in rows:
        key = _vendor_key(r.get("company") or "")
        if not key:
            continue
        tally[key][0] += 1
        tally[key][1] += int(bool(r.get("verify_ok")) and bool(r.get("timestamp_verified")))
        example.setdefault(key, r.get("company") or "")

    qualified = sorted((k, n, s) for k, (n, s) in tally.items()
                       if n >= min_samples and s / n >= threshold)
    new = [k for k, _, _ in qualified if k not in _ALWAYS_SIGNS]
    lost = [k for k in _ALWAYS_SIGNS
            if k in tally and tally[k][0] >= min_samples
            and tally[k][1] / tally[k][0] < threshold]
    print(f"\n  vendors at >= {min_samples} samples and >= {threshold:.0%} signed: "
          f"{len(qualified)}")
    print(f"    already in _ALWAYS_SIGNS : "
          f"{len([k for k, _, _ in qualified if k in _ALWAYS_SIGNS])}")
    print(f"    NEW                      : {len(new)}")
    for key, n, s in qualified:
        if key in new:
            print(f"        {s:4}/{n:<4} {s / n:6.1%}  {key:<18} {example[key][:36]}")
    if lost:
        print(f"    would LOSE their place   : {lost}"
              f"   <-- the wider corpus disagrees with the narrow one")

    managed = [r for r in rows if r.get("managed")]
    measurable = [r for r in managed if r.get("il_only")
                  and r.get("identifiers_sufficient")
                  and r.get("unreadable_fraction") is not None]
    print(f"\n  managed assemblies: {len(managed)}, measurable {len(measurable)}"
          f"   (was 39 in the 592-binary corpus)")
    if measurable:
        fracs = sorted((float(r["unreadable_fraction"]) for r in measurable),
                       reverse=True)
        over = sum(1 for f in fracs if f >= 0.20)
        print(f"    highest: " + ", ".join(f"{f:.3f}" for f in fracs[:8]))
        print(f"    >= 0.20 (the shipped cut): {over}"
              + ("   <-- benign false positives" if over else "   none"))
    protectors: dict[str, int] = defaultdict(int)
    for r in managed:
        for p in r.get("protectors") or []:
            protectors[p] += 1
    print(f"    named protectors in benign: {dict(protectors) or 'none'}")

    ent = sorted((float(r.get("exec_entropy") or 0.0) for r in rows), reverse=True)
    print(f"\n  executable-section entropy")
    for cut in (7.0, 7.2, 7.5, 7.8):
        hit = sum(1 for e in ent if e >= cut)
        print(f"    >= {cut}   {hit:5}   {100.0 * hit / len(rows):5.2f}% of corpus")
    print(f"    highest: " + ", ".join(f"{e:.2f}" for e in ent[:8]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="", help="write the survey here")
    parser.add_argument("--report", default="",
                        help="read a survey written earlier and report on it")
    parser.add_argument("--root", action="append", default=[])
    parser.add_argument("--count", type=int, default=1200)
    parser.add_argument("--per-vendor", type=int, default=_PER_VENDOR)
    parser.add_argument("--depth", type=int, default=6)
    parser.add_argument("--seed", type=int, default=20260828)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--min-samples", type=int, default=4)
    parser.add_argument("--threshold", type=float, default=0.95)
    args = parser.parse_args(argv)

    if args.report:
        path = Path(args.report)
        if not path.is_file():
            print(f"failed: {path} does not exist")
            return 1
        report(json.loads(path.read_text(encoding="utf-8")),
               args.min_samples, args.threshold)
        return 0

    if not args.out:
        print("failed: pass --out to collect, or --report to read one back")
        return 1

    roots = [Path(r) for r in (args.root or list(_DEFAULT_ROOTS))]
    print(f"surveying up to {args.count} binaries, {args.per_vendor} per vendor, "
          f"seed {args.seed}")
    data = collect(roots, args.count, args.per_vendor, args.seed,
                   args.depth, args.workers)
    Path(args.out).write_text(json.dumps(data, indent=1), encoding="utf-8")
    print(f"written: {args.out}")
    report(data, args.min_samples, args.threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
