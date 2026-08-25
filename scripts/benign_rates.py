"""How often each category fires on software that is not malicious.

**Nothing scores that has not been measured.** That standard is quoted at the
top of `docs/ROADMAP.md` and the dynamic side meets it -- module integrity at 0
mismatches across 300 modules in 12 programs, the WER check at 0 across 35 real
crashes. The four scorers rewritten on 24 Aug meet it nowhere: static, spec,
extension and api have categories and no benign corpus at all.

That gap is sharpest for the extension scorer, because the one it replaced was
*saturated* -- every non-trivial extension rated `Critical`. The replacement is
known to rate a synthetic jQuery bundle `Low`. It is not known to rate real
store extensions anything in particular, and those are two very different
claims.

**A false positive here is the expensive kind.** A missed detection on this
bench gets caught by the next module or the next run; a category that fires on
ordinary software teaches its reader to discount the band, and a discounted band
is worth less than no band.

**What this measures and what it does not.** Every corpus below is *presumed*
benign rather than verified -- signed Microsoft binaries, extensions installed
in a working browser profile, specification fixtures. That presumption is the
weak point and it is stated rather than hidden: a category firing here is a
finding to investigate, not automatically a false positive. What the numbers
support is a rate, and a rate is what the standard asks for.

    .venv\\Scripts\\python.exe scripts\\benign_rates.py --module extension
    .venv\\Scripts\\python.exe scripts\\benign_rates.py --module static --limit 200
    .venv\\Scripts\\python.exe scripts\\benign_rates.py --module all --out benign_rates.json

Runs on the HOST. It reads local software and touches no network.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from static_triage_engine.categories import spec_categories, static_categories  # noqa: E402
from static_triage_engine.extension_analysis import (  # noqa: E402
    extension_categories,
    scan_sources,
)
from verdict import Category, band  # noqa: E402

#: Browser profiles that keep unpacked extensions on disk. Real installs from
#: real stores, which is the whole point -- a corpus written by the same person
#: who wrote the scorer measures the author's imagination, not the population.
EXTENSION_ROOTS = (
    r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions",
    r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions",
    r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Extensions",
    r"%LOCALAPPDATA%\Google\Chrome\User Data\Profile 1\Extensions",
)

#: Signed system binaries. Not a flattering corpus -- Microsoft fills in version
#: info and signs everything -- which is exactly why a category firing here
#: would matter.
STATIC_ROOTS = (
    r"%SystemRoot%\System32",
)


def _expand(paths: Iterable[str]) -> list[Path]:
    out = []
    for raw in paths:
        expanded = Path(os.path.expandvars(raw))
        if expanded.is_dir():
            out.append(expanded)
    return out


def _report(name: str, results: list[tuple[str, Any, list[Category]]],
            note: str = "") -> dict[str, Any]:
    """Rates per category and the band distribution, printed and returned."""
    fired = collections.Counter()
    strong = collections.Counter()
    unknown = collections.Counter()
    bands = collections.Counter()
    offenders: dict[str, list[str]] = collections.defaultdict(list)

    for label, verdict, cats in results:
        bands[verdict.band] += 1
        for c in cats:
            if not c.collected:
                unknown[c.name] += 1
            elif c.present:
                fired[c.name] += 1
                if c.strong:
                    strong[c.name] += 1
                if len(offenders[c.name]) < 5:
                    offenders[c.name].append(label)

    total = len(results)
    print()
    print(f"=== {name}: {total} samples {note}")
    if not total:
        print("    no corpus found -- NOT MEASURED")
        return {"module": name, "total": 0, "measured": False, "note": note}

    every = sorted({c.name for _, _, cats in results for c in cats})
    width = max(len(n) for n in every)
    print(f"    {'category':<{width}}  fired  strong  unknown   rate")
    for cname in every:
        f, s, u = fired[cname], strong[cname], unknown[cname]
        looked = total - u
        rate = (f / looked * 100) if looked else 0.0
        flag = "  <-- " + ", ".join(offenders[cname][:3]) if f else ""
        print(f"    {cname:<{width}}  {f:>5}  {s:>6}  {u:>7}  {rate:5.1f}%{flag}")

    print()
    print("    bands:", ", ".join(f"{b} {c}" for b, c in bands.most_common()))
    return {
        "module": name,
        "total": total,
        "measured": True,
        "note": note,
        "fired": dict(fired),
        "strong": dict(strong),
        "unknown": dict(unknown),
        "bands": dict(bands),
        "examples": {k: v for k, v in offenders.items()},
    }


# ---------------------------------------------------------------------------
# extension
# ---------------------------------------------------------------------------

def measure_extensions(limit: int, corpus: str = "") -> dict[str, Any]:
    """Installed extensions by default; a downloaded corpus when given one.

    The installed set is fourteen on this machine -- enough to find four
    defects, not enough to found a rate on. `scripts/extension_corpus.py`
    builds the larger one.
    """
    if corpus:
        return _measure_extension_corpus(Path(corpus), limit)

    results = []
    for root in _expand(EXTENSION_ROOTS):
        for manifest_path in sorted(root.glob("*/*/manifest.json")):
            if len(results) >= limit:
                break
            try:
                manifest = json.loads(
                    manifest_path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
            if not isinstance(manifest, dict):
                continue
            package = manifest_path.parent
            sources = scan_sources(package)
            cats, context = extension_categories(manifest, sources)
            label = str(manifest.get("name", package.parent.name))[:40]
            # The hold is lifted here too. `extension` is held context-only by
            # decision, and this is the measurement that decision is waiting on
            # -- banding with the hold on would report "Findings Not Scored"
            # for every sample and measure nothing.
            results.append((label, band(cats, context_score=context,
                                        context_only={}), cats))
    return _report("extension", results,
                   "(installed browser extensions, presumed benign)")


def _measure_extension_corpus(root: Path, limit: int) -> dict[str, Any]:
    results = []
    for manifest_path in sorted(root.glob("*/manifest.json")):
        if len(results) >= limit:
            break
        try:
            manifest = json.loads(
                manifest_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(manifest, dict):
            continue
        package = manifest_path.parent
        cats, context = extension_categories(manifest, scan_sources(package))
        label = str(manifest.get("name", package.name))[:40]
        results.append((label, band(cats, context_score=context,
                                    # The hold is lifted: this measures what the
                                    # categories say, which is the question the
                                    # hold is waiting on an answer to.
                                    context_only={}), cats))
    return _report("extension", results,
                   f"(downloaded corpus, {root.name}, presumed benign)")


# ---------------------------------------------------------------------------
# static
# ---------------------------------------------------------------------------

def _version_info(path: Path) -> dict[str, Any] | None:
    """The PE version-info table, or None if the file is not a readable PE.

    `None` rather than `{}` deliberately: a file that could not be parsed did
    not report an empty version block, and the category contract turns the
    second into a finding.
    """
    try:
        import pefile
    except ImportError:
        return None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except Exception:
        return None

    table: dict[str, str] = {}
    for entry in getattr(pe, "FileInfo", []) or []:
        for item in (entry if isinstance(entry, list) else [entry]):
            for st in getattr(item, "StringTable", []) or []:
                for key, value in st.entries.items():
                    table[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
    pe.close()
    return {"version_info": table}


def measure_static(limit: int, signed: bool) -> dict[str, Any]:
    """**A deliberately partial measurement, and it says so.**

    Running the whole static engine over hundreds of binaries means capa, FLOSS
    and YARA on each -- hours, and not what is in question. The three categories
    that need only the file are measured; the three that need collectors are
    passed `None` and come back `unknown`, which is the honest report and
    exactly what the contract is for.
    """
    results = []
    for root in _expand(STATIC_ROOTS):
        for path in sorted(root.glob("*.exe")):
            if len(results) >= limit:
                break
            pe_meta = _version_info(path)
            if pe_meta is None:
                continue
            cats, context = static_categories(
                summary={"sample": {"filename": path.name}},
                pe_meta=pe_meta,
                # System32 is Microsoft-signed; asserting it rather than running
                # Authenticode per file, and flagged in the note so the reader
                # knows which half of `stripped_metadata` was exercised.
                signing=({"verify_ok": True, "timestamp_verified": True,
                          "subject": "CN=Microsoft Windows",
                          "signature_present": True} if signed else None),
                iocs=None, api_analysis=None, yara_results=None,
                techniques=None, capa_match_count=None,
            )
            results.append((path.name, band(cats, context_score=context), cats))
    note = ("(System32 executables, signature asserted)" if signed
            else "(System32 executables, signature NOT asserted)")
    return _report("static", results, note)


# ---------------------------------------------------------------------------
# spec
# ---------------------------------------------------------------------------

def measure_specs(paths: list[Path]) -> dict[str, Any]:
    from static_triage_engine.api_spec_analysis import analyze_api_spec
    import tempfile

    results = []
    for path in paths:
        try:
            with tempfile.TemporaryDirectory() as tmp:
                spec = analyze_api_spec(path, tmp)
        except Exception:
            continue
        cats, context = spec_categories(spec)
        results.append((path.name, band(cats, context_score=context), cats))
    return _report("spec", results, "(local specification fixtures, mixed)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--module", default="all",
                        choices=("all", "extension", "static", "spec", "api"))
    parser.add_argument("--limit", type=int, default=250)
    parser.add_argument("--corpus", default="",
                        help="a directory of unpacked extensions from "
                             "scripts/extension_corpus.py")
    parser.add_argument("--specs", default="",
                        help="directory of specification files to measure")
    parser.add_argument("--unsigned", action="store_true",
                        help="do not assert a valid signature on System32")
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    out: list[dict[str, Any]] = []
    if args.module in ("all", "extension"):
        out.append(measure_extensions(args.limit, args.corpus))
    if args.module in ("all", "static"):
        out.append(measure_static(args.limit, signed=not args.unsigned))
    if args.module in ("all", "spec"):
        specs: list[Path] = []
        if args.specs:
            root = Path(args.specs)
            for pattern in ("*.json", "*.yaml", "*.yml"):
                specs += sorted(root.glob(pattern))
        out.append(measure_specs(specs) if specs
                   else _report("spec", [], "(no --specs directory given)"))
    if args.module in ("all", "api"):
        # **Named, not skipped.** An unmeasured scorer that is simply absent
        # from the report reads like one with nothing to report.
        out.append(_report("api", [], "(no corpus of real HTTP responses)"))

    print()
    print("Every corpus here is *presumed* benign, not verified. A category")
    print("firing is a finding to investigate before it is a false positive.")

    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"written: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
