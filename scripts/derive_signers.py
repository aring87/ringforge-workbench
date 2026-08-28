"""Regenerate `_ALWAYS_SIGNS` from the benign corpora.

**The list is derived, not chosen.** `deceptive_file_identity` accuses a binary
of claiming a vendor it cannot be, which is only fair if "vendors who sign
everything" was established from software nobody here curated. A list written by
reading the malware corpus for impersonated names is tuned to the test set, and
would report a detection rate that means nothing.

A vendor qualifies on three measured facts: it appears on at least
`--min-samples` benign binaries, at least `--threshold` of them carry a
signature that verifies, and at least `--threshold` of those signatures name
the vendor itself.

**The third rule is the one that matters.** A 900-binary survey qualified
`ffmpeg` on the first two at 7 of 7 signed -- and 0 of the 7 were signed by
FFmpeg. OBS Project, Chengdu Yiwo Tech and Microsoft 3rd Party had signed them,
because FFmpeg is redistributed far more than it is shipped. Listing it would
have accused every unsigned FFmpeg build, which is the ordinary case, of
impersonation.

    .venv\\Scripts\\python.exe scripts\\derive_signers.py

Prints the constant to paste into `static_triage_engine/categories.py`, and the
vendors that just missed, because those are the interesting ones.

**Microsoft is the threshold case**, at 399 of 403 -- the four exceptions are
unsigned COM interop stubs shipped inside other vendors' installers. A strict
100% rule would drop the single most impersonated vendor in the malware corpora
(thirteen of the twenty impersonations seen), which is why the bar is a measured
threshold rather than perfection.

**The list only covers vendors the benign corpora contain.** Impersonations of
Adobe, Avira and Opera were all present in the malware and none is caught,
because none of the three appears in benign software here often enough to earn a
place. Widening the benign corpus widens the list; reading the malware does not.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from static_triage_engine.categories import _vendor_key  # noqa: E402

#: The corpora that are *presumed benign*. That presumption is this script's
#: weak point and is stated rather than hidden: a vendor that ships malware
#: signed would be learned as trustworthy here.
_DEFAULT_CORPORA = (
    r"G:\static-corpus-full\cases",
    r"G:\pf-corpus\cases",
)


def _rows(root: Path):
    from static_triage_engine.combine_case import case_home, load_case

    for case in sorted(p for p in root.iterdir() if p.is_dir()):
        log = case / "analysis.log"
        try:
            if not (log.exists() and "CASE_DONE" in
                    log.read_text(encoding="utf-8", errors="replace")):
                continue
        except OSError:
            continue
        try:
            loaded = load_case(case_home(case))
        except Exception:
            continue
        pe = loaded.get("pe_meta") or {}
        # A corpus collected before the version-info fix cannot answer this.
        if not pe.get("version_info_collected"):
            continue
        company = str((pe.get("version_info") or {}).get("CompanyName") or "").strip()
        signing = loaded.get("signing") or {}
        trusted = (bool(signing.get("verify_ok"))
                   and bool(signing.get("timestamp_verified")))
        yield company, trusted, str(signing.get("subject") or "").lower()


def _survey_rows(path: Path):
    """Rows from `scripts/benign_survey.py`, which reaches far wider than the
    case corpora because it skips the collectors these questions do not need."""
    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    for row in data.get("rows", []):
        if not row.get("version_collected"):
            continue
        trusted = (bool(row.get("verify_ok"))
                   and bool(row.get("timestamp_verified")))
        yield (str(row.get("company") or "").strip(), trusted,
               str(row.get("subject") or "").lower())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", action="append", default=[],
                        help="a benign corpus `cases` directory; repeatable")
    parser.add_argument("--survey", action="append", default=[],
                        help="a benign_survey.py JSON; repeatable. The shipped "
                             "list is derived from the case corpora plus "
                             "G:\\benign-survey.json")
    parser.add_argument("--min-samples", type=int, default=4)
    parser.add_argument("--threshold", type=float, default=0.95)
    args = parser.parse_args(argv)

    roots = [Path(c) for c in (args.cases or list(_DEFAULT_CORPORA))]
    missing = [r for r in roots if not r.is_dir()]
    if missing:
        for r in missing:
            print(f"failed: {r} is not a directory")
        return 1

    # samples, verifying signatures, signatures naming the vendor itself
    tally: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    example: dict[str, str] = {}
    uncollected = 0
    sources = [_rows(root) for root in roots]
    for survey in args.survey:
        path = Path(survey)
        if not path.is_file():
            print(f"failed: {path} is not a file")
            return 1
        sources.append(_survey_rows(path))
    for source in sources:
        for company, trusted, subject in source:
            if not company:
                continue
            key = _vendor_key(company)
            if not key:
                continue
            tally[key][0] += 1
            tally[key][1] += int(trusted)
            # **Signed is not the same as self-signed.** A vendor whose
            # binaries are signed by whoever redistributes them has not shown
            # that it signs, and accusing an unsigned copy would be wrong.
            tally[key][2] += int(trusted and key in subject)
            example.setdefault(key, company)

    if not tally:
        print("no samples carried a collected version block -- "
              "run scripts/refresh_version_info.py first")
        return 1

    qualified, missed, redistributed = [], [], []
    for key, (n, signed, own) in sorted(tally.items(), key=lambda kv: -kv[1][0]):
        if n < args.min_samples:
            continue
        if signed / n < args.threshold:
            missed.append((key, n, signed))
        elif not signed or own / signed < args.threshold:
            redistributed.append((key, n, signed, own))
        else:
            qualified.append((key, n, signed))

    print(f"\n{sum(v[0] for v in tally.values())} samples, "
          f"{len(tally)} distinct vendors, "
          f"{len(qualified)} qualifying at >= {args.min_samples} samples "
          f"and >= {args.threshold:.0%} signed\n")
    for key, n, signed in qualified:
        print(f"    {signed:4}/{n:<4} {signed / n:6.1%}  {key:<16} {example[key][:40]}")

    if missed:
        print(f"\n  did not qualify -- these ship unsigned, honestly:\n")
        for key, n, signed in missed:
            print(f"    {signed:4}/{n:<4} {signed / n:6.1%}  {key:<16} {example[key][:40]}")
    if redistributed:
        print(f"\n  signed, but not by them -- excluded, an unsigned copy is"
              f" ordinary:\n")
        for key, n, signed, own in redistributed:
            print(f"    {own:4}/{signed:<4} own {key:<16} {example[key][:40]}")

    print("\n\n_ALWAYS_SIGNS = frozenset({")
    line = "    "
    for key, _, _ in sorted(qualified):
        if len(line) + len(key) + 4 > 76:
            print(line.rstrip())
            line = "    "
        line += f'"{key}", '
    if line.strip():
        print(line.rstrip())
    print("})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
