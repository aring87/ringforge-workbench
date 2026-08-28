"""Re-extract only the version-info block over an existing corpus.

**`stripped_metadata` was never measuring metadata.** `_pe_string_table` reads
a version-info block that no collector wrote, so it returned `{}` on all 819
corpus samples, `missing` was always all four fields, and the category reduced
to `not trusted_signed` -- a second copy of `invalid_signature`. Signing data
alone reproduced the published column to the decimal on every corpus:
0.0 / 10.3 / 100.0 / 95.0. Only the tests ever built the block, by hand, which
is why they passed throughout.

`scripts/pe_meta.py` now walks the resource directory. This script applies that
one addition to a corpus already on disk, because re-running the whole engine
to recover four strings would be absurd -- capa and FLOSS dominate the cost and
neither feeds this category. **Every case directory already holds its own
sample**, because `run_case` copies it there.

    .venv\\Scripts\\python.exe scripts\\refresh_version_info.py --cases C:\\mal-bazaar-cases\\cases
    .venv\\Scripts\\python.exe scripts\\benign_rates.py --module static --cases C:\\mal-bazaar-cases\\cases

Well under a second per case. Only the four `version_info*` keys are written;
sections, imports, imphash, tlsh, ssdeep and every other field are left exactly
as they were, so the only number that can move is the one that was wrong.

**A case whose sample is missing, or whose resource directory will not parse,
is left untouched** -- it keeps reporting `unknown` rather than acquiring a
`version_info_collected: True` it did not earn. That distinction is the whole
point of the fix and this script must not undo it.

The two benign corpora were done on the host on 28 Aug. The malware corpora
need the guest, because the copies on the host hold analysis output only.
Nothing here executes a sample: it parses a resource directory.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.pe_meta import _VERSION_KEYS, _version_info  # noqa: E402
from scripts.refresh_iocs import find_sample  # noqa: E402

#: The four `stripped_metadata` actually asks about. Reported separately so a
#: corpus that carries a block but not these is visible as such.
_SCORED_FIELDS = ("CompanyName", "ProductName", "FileDescription",
                  "OriginalFilename")


def _pe_metadata_path(case: Path) -> Path | None:
    for candidate in (case / "pe_metadata.json",
                      case / "metadata" / "pe_metadata.json",
                      case / "static_analysis" / "pe_metadata.json"):
        if candidate.is_file():
            return candidate
    return None


def refresh(case: Path, apply: bool) -> dict[str, Any]:
    """Re-extract version info for one case. Never raises."""
    import pefile

    started = time.time()
    meta_path = _pe_metadata_path(case)
    if meta_path is None:
        return {"case": case.name, "ok": False, "reason": "no pe_metadata.json"}
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as error:
        return {"case": case.name, "ok": False,
                "reason": f"unreadable pe_metadata.json: {type(error).__name__}"}

    sample = find_sample(case)
    if sample is None:
        return {"case": case.name, "ok": False, "reason": "no sample in case dir"}

    pe = None
    try:
        # Only the resource directory. Parsing the imports again would cost the
        # bulk of the time and rewrite fields this script has no business
        # touching.
        pe = pefile.PE(str(sample), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        fields, found = _version_info(pe)
    except Exception as error:
        return {"case": case.name, "ok": False,
                "reason": f"{type(error).__name__}: {error}"}
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass

    scored = {k: v for k, v in fields.items() if k in _VERSION_KEYS}
    meta["version_info"] = scored
    meta["version_info_all"] = fields
    meta["version_info_collected"] = True
    meta["version_info_present"] = bool(found)

    if apply:
        try:
            temp = meta_path.with_suffix(".json.tmp")
            temp.write_text(json.dumps(meta, indent=2, sort_keys=True),
                            encoding="utf-8")
            temp.replace(meta_path)
        except Exception as error:
            return {"case": case.name, "ok": False,
                    "reason": f"write failed: {type(error).__name__}: {error}"}

    complete = all((scored.get(f) or "").strip() for f in _SCORED_FIELDS)
    return {"case": case.name, "ok": True, "block": bool(found),
            "complete": complete,
            "missing": [f for f in _SCORED_FIELDS
                        if not (scored.get(f) or "").strip()],
            "seconds": round(time.time() - started, 3)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", required=True,
                        help="the `cases` directory of a corpus")
    parser.add_argument("--limit", type=int, default=0,
                        help="stop after this many, for a quick look")
    parser.add_argument("--apply", action="store_true",
                        help="write the files; without it, report only")
    parser.add_argument("--out", default="",
                        help="write the per-case detail here")
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

    results: list[dict[str, Any]] = []
    started = time.time()
    for index, case in enumerate(cases, 1):
        results.append(refresh(case, args.apply))
        if index % 25 == 0 or index == len(cases):
            ok = sum(1 for r in results if r.get("ok"))
            print(f"  {index}/{len(cases)}  {ok} ok, "
                  f"{time.time() - started:.0f}s elapsed")

    ok = [r for r in results if r.get("ok")]
    bad = [r for r in results if not r.get("ok")]

    print()
    print(f"{'refreshed' if args.apply else 'would refresh'} {len(ok)} of {len(cases)}")
    if bad:
        reasons: dict[str, int] = {}
        for r in bad:
            key = str(r.get("reason", "?")).split(":")[0]
            reasons[key] = reasons.get(key, 0) + 1
        print("  left untouched (these keep reporting `unknown`):", reasons)
    if ok:
        block = sum(1 for r in ok if r.get("block"))
        complete = sum(1 for r in ok if r.get("complete"))
        print(f"  {block} of {len(ok)} carry a StringFileInfo block")
        print(f"  {complete} of {len(ok)} carry all four scored fields")
        print(f"  {len(ok) - complete} would fire `stripped_metadata` "
              f"if unsigned")

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
