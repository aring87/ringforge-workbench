"""How often each category fires on software that is not malicious.

**Nothing scores that has not been measured.** That standard is quoted at the
top of `docs/ROADMAP.md` and the dynamic side meets it -- module integrity at 0
mismatches across 300 modules in 12 programs, the WER check at 0 across 35 real
crashes. The four scorers rewritten on 24 Aug met it nowhere. As of 26 Aug all
four have a corpus, and every one of them is a random sample from a population
nobody here curated, with the seed recorded:

    static      300 System32 executables      (local)
    extension   394 store extensions          scripts/extension_corpus.py
    spec        300 APIs.guru specifications  scripts/spec_corpus.py
    api         103 replayed spec servers     scripts/api_corpus.py

**Each corpus disagreed with the intuition formed before it.** The extension
categories were nearly cut on a sample of fourteen installed extensions; `spec`
reported a rate that turned out to be a fact about how API documentation is
written; `api` read three quarters of ordinary public traffic as a finding
until 103 real responses said so. A rate measured on a convenience sample is
not a rate, and that lesson cost more than all four scripts put together.

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

from static_triage_engine.api_response_analysis import (  # noqa: E402
    analyze_response,
    api_categories,
)
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
            # **`context_only={}` always, whatever the registry says.** A
            # held module bands as "Findings Not Scored" for every sample,
            # which measures nothing -- and this is the measurement a hold
            # waits on, so it must not depend on whether one is in force.
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
        # Independent of the registry, as above: this measures what the
        # categories say, which is the question a hold waits on an answer to.
        results.append((label, band(cats, context_score=context,
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


def measure_static_cases(root: Path) -> dict[str, Any]:
    """Case directories from `scripts/static_corpus.py`, read as production does.

    **The whole scorer, not the cheap half.** `measure_static` below passes
    `None` for the three collectors that cost real time, so
    `known_malware_signature`, `dangerous_capability` and
    `embedded_network_indicators` came back `unknown` and were never measured
    at all. These cases have YARA, capa, the API analysis and the IOC pass
    actually run, and they are read through `static_verdict_for_case` -- the
    same function `engine.run_case` calls -- rather than a reimplementation.
    """
    from static_triage_engine.combine_case import (
        case_home,
        load_case,
        static_categories_for_case,
    )

    results = []
    unreadable = 0
    for case in sorted(p for p in root.glob("*") if p.is_dir()):
        try:
            home = case_home(case)
            loaded = load_case(home)
            cats, context = static_categories_for_case(
                home, **{k: loaded[k] for k in
                         ("summary", "iocs", "pe_meta", "api_analysis",
                          "yara_results", "signing")})
        except Exception:
            unreadable += 1
            continue
        if not cats:
            unreadable += 1
            continue
        results.append((case.name, band(cats, context_score=context), cats))

    # **Do not assert what the corpus is.** This said "signed Microsoft
    # binaries" unconditionally, and printed that over a corpus of live malware
    # -- a label that would have survived into the JSON and out into a report.
    note = f"(full engine over {root.parent.name})"
    if unreadable:
        note += f" [{unreadable} case(s) unreadable, excluded]"
    return _report("static", results, note)


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

def measure_specs(paths: list[Path], note: str = "") -> dict[str, Any]:
    from static_triage_engine.api_spec_analysis import analyze_api_spec
    import tempfile

    results = []
    unreadable = 0
    for path in paths:
        try:
            with tempfile.TemporaryDirectory() as tmp:
                spec = analyze_api_spec(path, tmp)
        except Exception:
            # **Counted, not swallowed.** A file the analyser could not open is
            # not a clean sample; dropping it silently shrinks the corpus
            # without shrinking the number the corpus is reported as.
            unreadable += 1
            continue
        cats, context = spec_categories(spec)
        results.append((path.name, band(cats, context_score=context), cats))
    if unreadable:
        note = (note + f" [{unreadable} file(s) unreadable, excluded]").strip()
    return _report("spec", results,
                   note or "(local specification fixtures, mixed)")


# ---------------------------------------------------------------------------
# api
# ---------------------------------------------------------------------------

def measure_api(root: Path) -> dict[str, Any]:
    """Recorded HTTP responses from `scripts/api_corpus.py`.

    **The last unmeasured scorer.** `api` was the only module left in
    `verdict.CONTEXT_ONLY`, held there because nothing had ever measured it --
    not because anything was wrong with it. This is the measurement that hold
    was waiting on, and it released it on 26 Aug.
    """
    results = []
    errors = 0
    for path in sorted(root.glob("*.response.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(record, dict):
            continue
        if record.get("error") or "status" not in record:
            # A request that never arrived is not a response. Counted so the
            # corpus size and the sample size stay the same number.
            errors += 1
            continue
        analysis = analyze_response(
            method=str(record.get("method", "GET")),
            url=str(record.get("url", "")),
            status=record.get("status", 0),
            # Pairs when the recording has them: a `dict` of the headers keeps
            # one `Set-Cookie` out of however many the server sent.
            response_headers=([tuple(p) for p in record["header_pairs"]]
                              if isinstance(record.get("header_pairs"), list)
                              else record.get("headers") or {}),
            body=str(record.get("body", "")),
        )
        cats, context = api_categories(analysis)
        label = str(record.get("title") or record.get("spec") or path.stem)[:40]
        # The hold is lifted here, exactly as it is for `extension`: banding
        # with it on reports "Findings Not Scored" for every sample and
        # measures nothing.
        results.append((label, band(cats, context_score=context,
                                    context_only={}), cats))
    note = f"(replayed spec servers, {root.name}, presumed benign)"
    if errors:
        note += f" [{errors} request(s) never arrived, excluded]"
    return _report("api", results, note)


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
    parser.add_argument("--responses", default="",
                        help="a directory of recorded HTTP responses from "
                             "scripts/api_corpus.py")
    parser.add_argument("--cases", default="",
                        help="a directory of engine case dirs from "
                             "scripts/static_corpus.py; measures the whole "
                             "static scorer rather than the cheap fields")
    parser.add_argument("--unsigned", action="store_true",
                        help="do not assert a valid signature on System32")
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    out: list[dict[str, Any]] = []
    if args.module in ("all", "extension"):
        out.append(measure_extensions(args.limit, args.corpus))
    if args.module in ("all", "static"):
        cases = Path(args.cases) if args.cases else None
        out.append(measure_static_cases(cases) if cases and cases.is_dir()
                   else measure_static(args.limit, signed=not args.unsigned))
    if args.module in ("all", "spec"):
        specs: list[Path] = []
        note = ""
        if args.specs:
            root = Path(args.specs)
            for pattern in ("*.json", "*.yaml", "*.yml"):
                # `_sample.json` is the manifest `scripts/spec_corpus.py`
                # writes beside the corpus. It parses, it has no `paths`, and
                # it would otherwise be measured as one more clean spec.
                specs += [p for p in sorted(root.glob(pattern))
                          if not p.name.startswith("_")]
            note = f"(downloaded corpus, {root.name}, presumed benign)"
        # No `--limit` here, unlike the other modules: the specs directory is
        # one the caller built deliberately with a recorded seed, and silently
        # measuring 250 of it would report a rate over a sample nobody chose.
        out.append(measure_specs(specs, note) if specs
                   else _report("spec", [], "(no --specs directory given)"))
    if args.module in ("all", "api"):
        # **Named, not skipped.** An unmeasured scorer that is simply absent
        # from the report reads like one with nothing to report.
        responses = Path(args.responses) if args.responses else None
        out.append(measure_api(responses) if responses and responses.is_dir()
                   else _report("api", [], "(no --responses directory given)"))

    print()
    print("Every corpus here is *presumed* benign, not verified. A category")
    print("firing is a finding to investigate before it is a false positive.")

    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"written: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
