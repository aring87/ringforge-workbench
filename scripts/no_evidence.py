"""What is in the No Evidence band, and why nothing fired on it.

**A sample nothing fires on is a result, not a blank.** Fixing
`stripped_metadata` on 28 Aug took 56 of 227 malware samples from *some
evidence* to *none* -- No Evidence went 0.0% -> 19.7% and 3.0% -> 31.0% --
because a signal that did not exist had been the only thing covering them.
Choosing a new category to close that gap without first asking what is in it is
how the additive model was built.

    .venv\\Scripts\\python.exe scripts\\no_evidence.py --cases C:\\mal-bazaar-cases\\cases

Reads what is already in each case directory; runs nothing and writes nothing.

**It answers a different question on the host than on the guest, and the
difference is the point.** `stripped_metadata` reports `unknown` wherever
`pe_metadata.json` predates the collector fix, and an uncollected category
cannot be present, so those cases fall into No Evidence here that would not on
a refreshed corpus. Run it where the corpus is current. The `uncollected`
column says how much of the band is a gap in collection rather than a property
of the samples -- if that number is large, the band is measuring the pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

IMAGE_SCN_MEM_EXECUTE = 0x20000000

#: Where `high_entropy_sections` was measured to sit on 28 Aug: 0.3% and 0.0%
#: on the two benign corpora, 35.4% and 28.0% on the two malware ones.
_ENTROPY_STRONG = 7.5

#: Vendors who sign everything they ship, so their name in a version block is a
#: claim that can be checked. Naming one without a signature that verifies is an
#: authored act; a small open-source project naming itself is not. Measured
#: 28 Aug: 0 of 292 System32 and 4 of 300 Program Files would fire, the four
#: being unsigned Microsoft redistributables carried inside another installer.
_MAJOR_VENDORS = (
    "microsoft", "adobe", "google", "apple", "oracle", "intel", "nvidia",
    "symantec", "mcafee", "kaspersky", "avast", "windows defender", "vmware",
    "cisco", "dell", "hewlett", "ibm", "amazon", "meta platforms",
)


def _claims_major_vendor(company: str) -> bool:
    low = company.lower()
    return any(name in low for name in _MAJOR_VENDORS)


def _describe(case: Path, cats, loaded: dict[str, Any]) -> dict[str, Any]:
    pe = loaded.get("pe_meta") or {}
    sections = [s for s in (pe.get("sections") or []) if (s.get("raw_size") or 0) > 0]
    exec_entropy = max(
        (float(s.get("entropy") or 0) for s in sections
         if int(s.get("characteristics") or 0) & IMAGE_SCN_MEM_EXECUTE),
        default=0.0)
    any_entropy = max((float(s.get("entropy") or 0) for s in sections), default=0.0)
    signing = loaded.get("signing") or {}
    sample = (loaded.get("summary") or {}).get("sample") or {}
    observables = (loaded.get("iocs") or {}).get("observables") or {}
    version = pe.get("version_info") or {}
    imports = [i for i in (pe.get("imports") or []) if isinstance(i, dict)]
    dlls = [str(i.get("dll") or "").lower() for i in imports]
    functions = sum(len(i.get("imports") or []) for i in imports)
    # A managed binary imports the CLR shim and nothing else: the real call
    # graph is in .NET metadata, which none of these categories reads.
    managed = bool(dlls) and all(
        d.startswith(("mscoree", "mscorlib")) for d in dlls)
    return {
        "managed": managed,
        "import_dlls": len(dlls),
        "import_functions": functions,
        "case": case.name,
        "uncollected": sorted(c.name for c in cats if not c.collected),
        "signed": bool(signing.get("subject") or signing.get("signature_present")),
        "trusted": bool(signing.get("verify_ok")) and bool(signing.get("timestamp_verified")),
        "version_fields": len([v for v in version.values() if str(v).strip()]),
        "version_collected": bool(pe.get("version_info_collected")),
        "company": str(version.get("CompanyName") or "").strip(),
        "exec_entropy": round(exec_entropy, 2),
        "any_entropy": round(any_entropy, 2),
        "iocs": sum(len(v) for v in observables.values() if isinstance(v, list)),
        "size_kb": round(int(sample.get("size_bytes") or 0) / 1024),
        "sections": len(sections),
    }


def survey(root: Path) -> tuple[list[dict[str, Any]], int]:
    from static_triage_engine.combine_case import (
        case_home, load_case, static_categories_for_case)
    from verdict.model import band

    rows: list[dict[str, Any]] = []
    total = 0
    for case in sorted(p for p in root.iterdir() if p.is_dir()):
        # **A case that never finished is not a sample.** `benign_rates` excludes
        # these on the same marker; counting them here would put every category's
        # `unknown` into the band and report a gap that is an aborted run.
        log = case / "analysis.log"
        try:
            if not (log.exists() and "CASE_DONE" in
                    log.read_text(encoding="utf-8", errors="replace")):
                continue
        except OSError:
            continue
        try:
            home = case_home(case)
            loaded = load_case(home)
            cats, context = static_categories_for_case(
                home, **{k: loaded[k] for k in
                         ("summary", "iocs", "pe_meta", "api_analysis",
                          "yara_results", "signing")})
        except Exception:
            continue
        if not cats:
            continue
        total += 1
        # `band` is the authority on what counts -- context-only categories are
        # reported but not counted, and reimplementing that rule here is how the
        # copies start disagreeing.
        if band(cats, context_score=context).band == "No Evidence":
            rows.append(_describe(case, cats, loaded))
    return rows, total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", required=True, help="a corpus `cases` directory")
    parser.add_argument("--out", default="", help="write the per-case detail here")
    args = parser.parse_args(argv)

    root = Path(args.cases)
    if not root.is_dir():
        print(f"failed: {root} is not a directory")
        return 1

    rows, total = survey(root)
    if not total:
        print("no readable cases")
        return 1

    print(f"\n=== No Evidence: {len(rows)} of {total} "
          f"({100.0 * len(rows) / total:.1f}%) in {root.parent.name}")
    if not rows:
        return 0

    uncollected = Counter(n for r in rows for n in r["uncollected"])
    print(f"\n  why nothing fired -- collection gaps in this band")
    if uncollected:
        for name, count in uncollected.most_common():
            print(f"      {name:32} unknown on {count:3} of {len(rows)}")
    else:
        print("      none: every category was collected on every one of these")

    complete = sum(1 for r in rows if r["version_fields"] >= 4)
    named = sum(1 for r in rows if r["company"])
    print(f"\n  what these samples look like")
    print(f"      carry a company name           {named:3} of {len(rows)}")
    print(f"      four or more version fields    {complete:3} of {len(rows)}")
    print(f"      signed at all                  "
          f"{sum(1 for r in rows if r['signed']):3} of {len(rows)}")
    print(f"      signature verifies             "
          f"{sum(1 for r in rows if r['trusted']):3} of {len(rows)}")
    print(f"      zero IOCs extracted            "
          f"{sum(1 for r in rows if r['iocs'] == 0):3} of {len(rows)}")

    # **Both shipped on 28 Aug, so on a current corpus these must read zero** --
    # a sample either would catch has already left the band. A non-zero count is
    # not a finding about the samples; it means a category is not firing when it
    # should, and this is the cheapest place that shows.
    hi = sum(1 for r in rows if r["exec_entropy"] >= _ENTROPY_STRONG)
    hi_any = sum(1 for r in rows if r["any_entropy"] >= 7.2)
    print(f"\n  invariant -- a shipped category must not leave its own catch here")
    print(f"      exec section >= {_ENTROPY_STRONG}          {hi:3}"
          f"   {'OK' if hi == 0 else '<-- high_entropy_sections is not firing'}")
    print(f"      any section >= 7.2             {hi_any:3}"
          f"   -- the looser cut this deliberately does not use")

    # **Two candidate signals, and the only number that matters is the overlap.**
    # Either one alone looks like progress; if they cover the same samples,
    # shipping both recovers no more of the band than shipping one.
    def packed(r):
        return r["exec_entropy"] >= _ENTROPY_STRONG

    def impersonates(r):
        return bool(r["company"]) and _claims_major_vendor(r["company"]) \
            and not r["trusted"]

    both = sum(1 for r in rows if packed(r) and impersonates(r))
    only_p = sum(1 for r in rows if packed(r) and not impersonates(r))
    only_i = sum(1 for r in rows if impersonates(r) and not packed(r))
    neither = sum(1 for r in rows if not packed(r) and not impersonates(r))
    imp = sum(1 for r in rows if impersonates(r))
    print(f"      claims a major vendor unsigned {imp:3}"
          f"   {'OK' if imp == 0 else '<-- wider than the shipped _ALWAYS_SIGNS'}")
    if only_p or only_i or both:
        print(f"      (packed only {only_p}, vendor only {only_i}, "
              f"both {both}, neither {neither})")

    # **What is left after every shipped category has had its turn.** The band
    # is no longer "nothing looked"; it is "everything looked and saw nothing",
    # which is a different and more interesting claim.
    managed = sum(1 for r in rows if r["managed"])
    thin = sum(1 for r in rows if 0 < r["import_functions"] <= 5)
    near = sum(1 for r in rows
               if 7.0 <= r["exec_entropy"] < _ENTROPY_STRONG)
    print(f"\n  why static cannot see them")
    print(f"      managed (.NET) binaries        {managed:3} of {len(rows)}"
          f"   -- call graph is in CLR metadata, not the import table")
    print(f"      five or fewer imported symbols {thin:3} of {len(rows)}"
          f"   -- APIs resolved at run time")
    print(f"      exec entropy 7.0 to {_ENTROPY_STRONG}        {near:3} of {len(rows)}"
          f"   -- packed, just under the measured threshold")
    print(f"      signature verifies             "
          f"{sum(1 for r in rows if r['trusted']):3} of {len(rows)}"
          f"   -- a signature that verifies; nothing left to doubt statically")
    # **No compile-year line here, on purpose.** `timestamp_epoch` is not a
    # date: reproducible builds put a content hash in the field, and System32
    # alone spans 1971 to 2099 because of it. Reporting that as "compiled"
    # would publish a fake with the same confidence as a real measurement.

    companies = Counter(r["company"] for r in rows if r["company"])
    if companies:
        print(f"\n  company names claimed in this band")
        for name, count in companies.most_common(8):
            print(f"      {count:3}  {name[:56]}")

    if args.out:
        Path(args.out).write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"\nwritten: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
