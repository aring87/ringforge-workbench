"""A wide, cheap benign corpus for calibrating thresholds -- not for measuring rates.

**Written on 28 Aug because three thresholds were set against 592 binaries and
each was limited by a different thinness in that corpus. All three are now
answered, and the answers are the reason to keep this script rather than retire
it.**

* `_ALWAYS_SIGNS` in `deceptive_file_identity` held 8 vendors. It now holds 13
  over 1,219 samples -- and the widening turned up a *third qualifying rule*
  rather than more vendors: `ffmpeg` passed the first two at 7 of 7 signed with
  0 of the 7 signed by FFmpeg, so a vendor must now be shown to sign its own
  releases. See `scripts/derive_signers.py`.
* `obfuscated_managed_code` was calibrated on **39** measurable managed
  assemblies and now rests on 129. Nothing benign reaches the 0.20 cut and no
  named protector appears in any of 161 managed binaries.
* `high_entropy_sections` sits at 7.5 because both case corpora are *installed*
  software. A 210-binary installer corpus measured that gap on 28 Aug: 0.95% of
  installers fire against 0.00% of installed software, which is why the
  category is still not `strong`.

**What is still open is what this cannot reach.** Adobe, Avira, Opera and
Windows Defender are absent from `_ALWAYS_SIGNS` because none is installed on
this bench at four samples or more, and going from 592 to 1,492 binaries added
none of them. The bound is one machine's installed software; widening within it
will not help again.

**This does not run capa, YARA or the IOC pass, and that is the point.** None of
the three questions above touches them, and they cost 30-85 seconds a binary
against roughly one for everything here. A survey of 1,200 binaries is twenty
minutes; the same corpus through `static_corpus.py` is most of a day.

    .venv\\Scripts\\python.exe scripts\\benign_survey.py --out G:\\benign-survey.json
    .venv\\Scripts\\python.exe scripts\\benign_survey.py --report G:\\benign-survey.json

`--name-glob` narrows to files whose name matches, which is how the installer
corpus was drawn out of trees that are mostly not installers:

    --root "C:\\ProgramData\\Package Cache" --root "C:\\Windows\\Installer"
    --root "C:\\Program Files" --name-glob "*setup*.exe" --name-glob "unins*.exe"

It selects on the name a publisher chose, which is a claim: an installer called
`app.exe` is missed and a library called `installer.dll` is drawn.

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
from fnmatch import fnmatch
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


def _candidates(root: Path, max_depth: int,
                name_globs: list[str] | None = None) -> dict[str, list[Path]]:
    by_vendor: dict[str, list[Path]] = defaultdict(list)
    root_depth = len(root.parts)
    for path in root.rglob("*"):
        try:
            if len(path.parts) - root_depth > max_depth:
                continue
            if path.suffix.lower() not in _EXTENSIONS or not path.is_file():
                continue
            # **A name filter, not a content one.** `--name-glob "*setup*.exe"`
            # picks installers out of a tree that is mostly not installers. It
            # selects on what the file is called, which is a claim by whoever
            # shipped it and can be wrong -- an installer named `app.exe` is
            # missed and a library named `installer.dll` is drawn.
            if name_globs and not any(
                    fnmatch(path.name.lower(), g.lower()) for g in name_globs):
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
            depth: int, workers: int,
            name_globs: list[str] | None = None) -> dict[str, Any]:
    rng = random.Random(seed)
    chosen: list[Path] = []
    provenance: dict[str, Any] = {"roots": [], "seed": seed,
                                  "per_vendor": per_vendor, "max_depth": depth,
                                  "name_globs": list(name_globs or [])}
    for root in roots:
        if not root.is_dir():
            provenance["roots"].append({"root": str(root), "present": False})
            continue
        by_vendor = _candidates(root, depth, name_globs)
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

    # **The vendor list has one derivation and it is not here.**
    # `scripts/derive_signers.py --survey` applies all three rules, including
    # the self-signing one this report has no business re-implementing: two
    # copies of a qualifying rule is how the copies start disagreeing about who
    # signs. What belongs here is how much evidence this survey adds.
    from static_triage_engine.categories import _ALWAYS_SIGNS, _vendor_key

    tally: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in rows:
        key = _vendor_key(r.get("company") or "")
        if not key:
            continue
        tally[key][0] += 1
        tally[key][1] += int(bool(r.get("verify_ok"))
                             and bool(r.get("timestamp_verified")))
    with_enough = [k for k, (n, _) in tally.items() if n >= min_samples]
    print(f"\n  vendors: {len(tally)} distinct, {len(with_enough)} at "
          f">= {min_samples} samples")
    print(f"    already in _ALWAYS_SIGNS : "
          f"{len([k for k in with_enough if k in _ALWAYS_SIGNS])} of {len(_ALWAYS_SIGNS)}")
    print(f"    not yet listed           : "
          f"{sorted(k for k in with_enough if k not in _ALWAYS_SIGNS)}")
    print(f"    -> for the list itself:  scripts/derive_signers.py --survey <this file>")

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
    parser.add_argument("--name-glob", action="append", default=[],
                        help="only files whose name matches; repeatable. "
                             "Selects on the name a publisher chose, which is "
                             "a claim and can be wrong.")
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
                   args.depth, args.workers, args.name_glob)
    Path(args.out).write_text(json.dumps(data, indent=1), encoding="utf-8")
    print(f"written: {args.out}")
    report(data, args.min_samples, args.threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
