"""Which modules ran on a case, and what each of them found.

**Why this is a module and not methods on the window.** `verdict/case_summary.py`
took the Unified Report's *verdict* functions out of `gui.UnifiedReportWindow`
early in this thread; this is the other half -- the artifact detection and the
finding extraction, about 500 lines that referenced no widget, could not be
imported without a display, and had no tests. Seventh and last module through
this pass, and it was carrying the defect that matters most on a case page.

**The case verdict never reached the page.** `_detect_artifacts` reported the
module under the name `"Case Verdict"`; `_build_detailed_findings` looked it up
as `"Combined Score"`, the retired name, and got nothing. So the section for
`combined_verdict.json` -- the file the whole `corroboration-v1` model exists to
produce -- was **permanently empty**, while the artifact list above it said
`[FOUND] Case Verdict` with the path. Nothing failed; a section was blank.

**A stale legacy file could outrank the engine's own output.** Every candidate
list here is written canonical-first, or newest-run-first where that is the
question. The window then passed the whole list to a helper that sorted it by
*modification time* and took the newest, throwing the ordering away. A case
holding both `static_analysis/summary.json` and a legacy root `summary.json`
reported whichever had been touched last -- and since `overall_verdict` returns
the static module's verdict when there is no combined one, a case the engine
called `Likely Malicious` could show `LOW_RISK` off a stale file.

The rule is one line now: **the first candidate that exists wins**, and the
caller orders its candidates.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from static_triage_engine.spec_report import auth_line

#: The module rows a case page shows, in the order it shows them. The key is
#: the display name and the value is the findings bucket.
#:
#: **`Case Verdict` was `Combined Score` in half the code**, which is the whole
#: reason this constant exists in one place. The rename came with
#: `combined_score.json` -> `combined_verdict.json`; the producer moved and two
#: consumers did not.
MODULES: dict[str, str] = {
    "Static Analysis": "static",
    "Dynamic Analysis": "dynamic",
    "Manual API Tester": "api",
    "Spec Analysis": "spec",
    "Browser Extension Analysis": "extension",
    "Case Verdict": "combined",
}

#: The retired display name, still accepted when reading an artifacts mapping
#: written by an older build so a stored case does not lose its verdict row.
RETIRED_MODULE_NAMES = {"Combined Score": "Case Verdict"}

CASE_VERDICT = "Case Verdict"


def _read_json(path: str | Path | None) -> Any:
    if path is None:
        return None
    try:
        path = Path(path)
        if not (path.exists() and path.is_file()):
            return None
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return json.load(handle)
    except Exception:
        return None


def load_json(path: str | Path | None) -> dict[str, Any] | None:
    data = _read_json(path)
    return data if isinstance(data, dict) else None


def first_existing(paths: Iterable[Path]) -> Path | None:
    """The first candidate that is on disk.

    **Preference, not modification time.** The lists below are ordered: the
    canonical location first, then the layouts this tool has used before, and
    for the dynamic module the newest run before any of them. Sorting by mtime
    -- which is what this replaced -- discards every one of those decisions and
    lets a file that was merely *touched* most recently speak for the case.
    """
    for path in paths or []:
        try:
            if Path(path).exists():
                return Path(path)
        except Exception:
            continue
    return None


def existing_paths(paths: Iterable[Path]) -> list[str]:
    """Every candidate that exists, deduplicated, order preserved."""
    found: list[str] = []
    seen: set[str] = set()
    for path in paths or []:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            if Path(path).exists():
                found.append(str(path))
        except Exception:
            continue
    return found


def _newest_children(parent: Path) -> list[Path]:
    try:
        if not parent.exists() or not parent.is_dir():
            return []
        dirs = [p for p in parent.iterdir() if p.is_dir()]
        return sorted(dirs, key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        return []


def _newest_glob(root: Path, pattern: str) -> list[Path]:
    """Run history, newest first. **This** is the case where time is the
    question -- which run happened last -- rather than which layout is
    canonical."""
    try:
        if not root.exists():
            return []
        return sorted(root.glob(pattern),
                      key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Where each module leaves its work, canonical first
# ---------------------------------------------------------------------------

def static_summary_candidates(case_dir: Path) -> list[Path]:
    return [
        case_dir / "static_analysis" / "summary.json",
        case_dir / "static_analysis" / "metadata" / "static_run_summary.json",
        case_dir / "metadata" / "static_run_summary.json",
        case_dir / "summary.json",
        case_dir / "report.json",
    ]


def dynamic_summary_candidates(case_dir: Path) -> list[Path]:
    runs = case_dir / "dynamic_analysis" / "dynamic_runs"
    return [
        *_newest_glob(runs, "*/metadata/dynamic_run_summary.json"),
        case_dir / "dynamic_analysis" / "metadata" / "dynamic_run_summary.json",
        case_dir / "dynamic_analysis" / "dynamic_run_summary.json",
        case_dir / "metadata" / "dynamic_run_summary.json",
        case_dir / "reports" / "dynamic_run_summary.json",
        case_dir / "dynamic_run_summary.json",
    ]


def dynamic_findings_candidates(case_dir: Path) -> list[Path]:
    runs = case_dir / "dynamic_analysis" / "dynamic_runs"
    return [
        *_newest_glob(runs, "*/reports/dynamic_findings.json"),
        *_newest_glob(runs, "*/dynamic_findings.json"),
        case_dir / "dynamic_analysis" / "reports" / "dynamic_findings.json",
        case_dir / "dynamic_analysis" / "dynamic_findings.json",
        case_dir / "reports" / "dynamic_findings.json",
        case_dir / "dynamic_findings.json",
    ]


def spec_summary_candidates(case_dir: Path) -> list[Path]:
    return [
        case_dir / "spec_analysis" / "api_spec_analysis.json",
        case_dir / "spec_analysis" / "metadata" / "api_spec_analysis.json",
        case_dir / "spec_analysis" / "spec_inventory_latest.json",
        case_dir / "spec" / "spec_inventory_latest.json",
        case_dir / "spec" / "api_spec_analysis.json",
        case_dir / "api_spec_analysis.json",
        case_dir / "reports" / "api_spec_analysis.json",
    ]


def extension_summary_candidates(case_dir: Path) -> list[Path]:
    root = case_dir / "browser_extension_analysis"
    return [
        root / "browser_extension_analysis.json",
        root / "metadata" / "browser_extension_analysis.json",
        *_newest_glob(root / "runs", "*/browser_extension_analysis.json"),
        case_dir / "extension_analysis" / "extension_analysis.json",
        case_dir / "extension_analysis" / "reports" / "extension_analysis.json",
        case_dir / "extension_analysis.json",
        case_dir / "reports" / "extension_analysis.json",
    ]


def api_summary_candidates(case_dir: Path) -> list[Path]:
    return [
        case_dir / "api_analysis" / "manual_api_latest.json",
        case_dir / "api" / "manual_api_latest.json",
    ]


def case_verdict_candidates(case_dir: Path) -> list[Path]:
    return [
        case_dir / "combined_verdict.json",
        case_dir / "metadata" / "combined_verdict.json",
    ]


def detection_candidates(case_dir: Path) -> dict[str, list[Path]]:
    """Everything that counts as evidence a module ran, including its reports.

    Presence is the test, not readability -- a module that wrote a file did
    run. Whether that file can be *read* is a separate question, and
    `load_summary` answers it separately so a corrupt artifact shows as a
    module that ran and produced nothing rather than as a module that did not.
    """
    case_dir = Path(case_dir)
    extension_runs = _newest_children(
        case_dir / "browser_extension_analysis" / "runs")
    return {
        "Static Analysis": [
            *static_summary_candidates(case_dir),
            case_dir / "static_analysis" / "report.html",
            case_dir / "static_analysis" / "report.md",
            case_dir / "static_analysis" / "iocs.json",
            case_dir / "static_analysis" / "pe_metadata.json",
            case_dir / "static_analysis" / "lief_metadata.json",
            case_dir / "metadata" / "run_summary.json",
            case_dir / "yara_results.json",
            case_dir / "reports" / "report.html",
            case_dir / "reports" / "static_report.html",
        ],
        "Dynamic Analysis": [
            *dynamic_summary_candidates(case_dir),
            *dynamic_findings_candidates(case_dir),
            case_dir / "dynamic_analysis" / "reports" / "dynamic_report.html",
        ],
        "Manual API Tester": [
            *api_summary_candidates(case_dir),
            case_dir / "api_analysis" / "manual_api_latest.html",
            case_dir / "api" / "manual_api_latest.html",
        ],
        "Spec Analysis": [
            *spec_summary_candidates(case_dir),
            case_dir / "spec_analysis" / "spec_inventory_latest.html",
            case_dir / "spec" / "spec_inventory_latest.html",
        ],
        "Browser Extension Analysis": [
            *extension_summary_candidates(case_dir),
            case_dir / "browser_extension_analysis" / "browser_extension_report.html",
            *extension_runs,
            case_dir / "ringforge_extension_reports",
        ],
        CASE_VERDICT: case_verdict_candidates(case_dir),
    }


def detect_artifacts(case_dir: str | Path) -> dict[str, dict[str, Any]]:
    """Which modules left something behind, and where."""
    case_dir = Path(case_dir)
    results: dict[str, dict[str, Any]] = {}
    for module, candidates in detection_candidates(case_dir).items():
        paths = existing_paths(candidates)
        results[module] = {"found": bool(paths), "paths": paths}
    return results


_SUMMARY_CANDIDATES = {
    "Static Analysis": static_summary_candidates,
    "Dynamic Analysis": dynamic_summary_candidates,
    "Spec Analysis": spec_summary_candidates,
    "Browser Extension Analysis": extension_summary_candidates,
    "Manual API Tester": api_summary_candidates,
    CASE_VERDICT: case_verdict_candidates,
}


def load_summary(case_dir: str | Path | None,
                 module: str) -> dict[str, Any] | None:
    """One module's summary, from the first candidate location that exists."""
    if not case_dir:
        return None
    module = RETIRED_MODULE_NAMES.get(module, module)
    build = _SUMMARY_CANDIDATES.get(module)
    if build is None:
        return None
    return load_json(first_existing(build(Path(case_dir))))


# ---------------------------------------------------------------------------
# What each module found, as lines for the page
# ---------------------------------------------------------------------------

def _line(label: str, value: Any) -> str:
    return f"{label}: {value}"


def static_findings(data: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    for key, label in (("score", "Score"), ("verdict", "Verdict"),
                       ("confidence", "Confidence")):
        if key in data:
            out.append(_line(label, data[key]))

    sample = data.get("sample")
    if "sample_path" in data:
        out.append(_line("Sample", Path(str(data["sample_path"])).name))
    elif isinstance(sample, Mapping):
        path = (sample.get("sample_path") or sample.get("path")
                or sample.get("target_path"))
        if path:
            out.append(_line("Sample", Path(str(path)).name))

    for key, label in (("engine", "YARA engine"),
                       ("match_count", "YARA match count"),
                       ("rule_file_count", "YARA rule files loaded")):
        if key in data:
            out.append(_line(label, data[key]))

    if data.get("matched") is True:
        out.append("YARA produced one or more matches")
    elif data.get("matched") is False:
        out.append("YARA produced no matches")

    matches = data.get("matches")
    if isinstance(matches, list) and matches:
        names = [str(m.get("rule", "unknown")) if isinstance(m, Mapping) else str(m)
                 for m in matches[:10]]
        out.append("Matched rules: " + ", ".join(names))

    if data.get("error"):
        out.append(_line("YARA error", data["error"]))
    return out


def dynamic_findings(data: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    for key, label in (("score", "Score"), ("severity", "Severity"),
                       ("verdict", "Verdict")):
        if key in data:
            out.append(_line(label, data[key]))

    source = data.get("findings")
    source = source if isinstance(source, Mapping) else data

    highlights = source.get("highlights")
    if isinstance(highlights, list):
        out.extend(str(x).strip() for x in highlights[:10] if str(x).strip())

    spawned = source.get("spawned_processes")
    if isinstance(spawned, list) and spawned:
        # Counted before the preview is truncated. The count is a measurement
        # and the preview is presentation; taking the first from the second
        # would report ten spawns for a run that made forty.
        out.append(_line("Spawned processes", len(spawned)))
        names: list[str] = []
        for item in spawned[:10]:
            if isinstance(item, Mapping):
                raw = item.get("path") or item.get("process_name") or "unknown"
                name = Path(str(raw)).name
                if name not in names:
                    names.append(name)
        if names:
            out.append("Spawned process names: " + ", ".join(names))

    counts = source.get("counts")
    if isinstance(counts, Mapping):
        for key, label in (("interesting_events", "Interesting events"),
                           ("process_creates", "Process creates"),
                           ("network_events", "Network events"),
                           ("file_write_events", "File write events"),
                           ("persistence_hits", "Persistence hits")):
            if key in counts:
                out.append(_line(label, counts[key]))
    return out


def api_findings(data: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    request = data.get("request")
    request = request if isinstance(request, Mapping) else {}
    response = data.get("response")
    response = response if isinstance(response, Mapping) else {}

    for value, label in ((data.get("module") or data.get("tool"), "Tool"),
                         (data.get("saved_at"), "Saved at"),
                         (data.get("redaction"), "Redaction")):
        if value:
            out.append(_line(label, value))

    for key, label in (("method", "Method"), ("url", "URL"),
                       ("verify_ssl", "Verify SSL")):
        if key in request:
            out.append(_line(label, request[key]))
    if "timeout_seconds" in request:
        out.append(_line("Timeout", f"{request['timeout_seconds']} seconds"))

    # Both schemas the Manual API Tester has written.
    status = response.get("status", response.get("status_code"))
    if status not in (None, ""):
        out.append(_line("HTTP status", status))
    for key, label in (("reason", "Reason"), ("content_type", "Content-Type"),
                       ("elapsed", "Elapsed"), ("size", "Response size")):
        if response.get(key):
            out.append(_line(label, response[key]))

    analysis = data.get("analysis")
    if isinstance(analysis, str) and analysis.strip():
        lines = [line.strip() for line in analysis.splitlines() if line.strip()]
        lines = [line for line in lines
                 if line.startswith("[") or line.lower().startswith("note:")]
        if lines:
            out.append("Analysis findings:")
            out.extend(f"  {line}" for line in lines[:12])

    for key, label in (("html_report", "Latest HTML"),
                       ("user_saved_html_report", "Exported HTML")):
        if data.get(key):
            out.append(_line(label, data[key]))
    return out


def spec_findings(data: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    for key, label in (("title", "Spec title"), ("version", "Spec version"),
                       ("spec_type", "Spec type"), ("format", "Format"),
                       ("confidence", "Parser confidence")):
        if data.get(key):
            out.append(_line(label, data[key]))

    summary = data.get("summary")
    summary = summary if isinstance(summary, Mapping) else {}
    scoring = data.get("scoring")
    scoring = scoring if isinstance(scoring, Mapping) else {}

    if summary:
        for key, label in (
                ("endpoint_count", "Endpoints"),
                ("unauthenticated_endpoint_count", "Unauthenticated endpoints"),
                ("sensitive_unauthenticated_endpoint_count",
                 "Sensitive unauthenticated endpoints"),
                ("high_risk_endpoint_count", "High-risk endpoints"),
                ("medium_risk_endpoint_count", "Medium-risk endpoints"),
                ("schema_issue_endpoint_count", "Schema issue endpoints")):
            out.append(_line(label, summary.get(key, 0)))

    if scoring:
        out.append(_line("HTTP server detected",
                         scoring.get("http_server_detected", False)))
        out.append(_line("File upload endpoints",
                         scoring.get("file_upload_endpoints", 0)))
        out.append(_line("Auth gap count", scoring.get("auth_gap_count", 0)))

    # **Through the spec module's own vocabulary.** This printed the scheme
    # names as the spec author wrote them, so a case page said `bearerAuth`
    # where the spec report -- reading the same file -- said `bearer`.
    out.append(_line("Auth schemes", auth_line(data.get("auth_summary"))))

    notes = data.get("risk_notes")
    if isinstance(notes, list) and notes:
        out.append("Risk notes:")
        out.extend(f"  - {note}" for note in notes[:10])

    endpoints = data.get("top_risky_endpoints")
    if isinstance(endpoints, list) and endpoints:
        out.append("Notable endpoints:")
        out.extend(
            f"  - {ep.get('method', '')} {ep.get('path', '')} "
            f"[{ep.get('risk_level', '')} | score={ep.get('risk_score', 0)}]"
            for ep in endpoints[:8] if isinstance(ep, Mapping))
    return out


#: The extension summary fields a case page shows, in order. This was written
#: out twice, once for a run directory and once for a file, and the two copies
#: had drifted: only the file branch reported risk notes when the summary block
#: was missing.
_EXTENSION_FIELDS = (
    ("name", "Extension name", "-"),
    ("version", "Extension version", "-"),
    ("manifest_version", "Manifest version", "-"),
    ("risk_verdict", "Extension verdict", "-"),
    ("risk_score", "Extension risk score", "0"),
    ("files_found", "Files found", "0"),
    ("permissions", "Permissions", "-"),
    ("host_permissions", "Host permissions", "-"),
    ("background", "Background", "-"),
    ("content_scripts", "Content scripts", "-"),
    ("web_resources", "Web resources", "-"),
    ("externally_connectable", "Externally connectable", "-"),
    ("update_url", "Update URL", "-"),
    ("csp", "CSP", "-"),
)


def extension_findings(data: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    summary = data.get("summary")
    if isinstance(summary, Mapping):
        out.extend(_line(label, summary.get(key, default))
                   for key, label, default in _EXTENSION_FIELDS)
        if summary.get("risk_severity"):
            out.append(_line("Extension band", summary["risk_severity"]))

    notes = data.get("risk_notes")
    if isinstance(notes, list) and notes:
        out.append("Risk notes:")
        out.extend(f"  {note}" for note in notes[:12])
    return out


def case_verdict_findings(data: Mapping[str, Any]) -> list[str]:
    """What `combined_verdict.json` says.

    **Nothing reached this before.** The producer named the module
    `Case Verdict` and the consumer asked for `Combined Score`, so the section
    was empty on every case page that had one.
    """
    out: list[str] = []
    total = data.get("total_score", data.get("score"))
    if total is not None:
        out.append(_line("Total score", total))
    for key, label in (("severity", "Severity"), ("verdict", "Verdict"),
                       ("band", "Band"), ("score_model", "Score model")):
        if data.get(key):
            out.append(_line(label, data[key]))

    subscores = data.get("subscores")
    if isinstance(subscores, Mapping):
        scores = {name: subscores.get(name)
                  for name in ("static", "dynamic", "spec")}
    else:
        scores = {"static": data.get("static_score"),
                  "dynamic": data.get("dynamic_score"),
                  "spec": data.get("spec_score")}
    for name, value in scores.items():
        if value is not None:
            out.append(_line(f"{name.capitalize()} score", value))

    for key, label in (("modules_run", "Modules run"),
                       ("modules_absent", "Modules absent")):
        names = data.get(key)
        if isinstance(names, list) and names:
            out.append(_line(label, ", ".join(str(n) for n in names)))
    return out


_EXTRACTORS = {
    "static": static_findings,
    "dynamic": dynamic_findings,
    "api": api_findings,
    "spec": spec_findings,
    "extension": extension_findings,
    "combined": case_verdict_findings,
}

#: Modules where every artifact is read and merged, rather than the first that
#: parses. Static spreads its answer across `summary.json`, `yara_results.json`
#: and the metadata copies; the rest carry one document.
_MERGE_ALL = {"static"}


def _dedupe(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _extension_documents(path: Path) -> list[dict[str, Any]]:
    """A run directory holds the JSON; a candidate may be either."""
    if path.is_dir():
        documents = []
        for name in ("browser_extension_analysis.json",
                     "*_extension_analysis.json"):
            for candidate in sorted(path.glob(name)):
                data = load_json(candidate)
                if data:
                    documents.append(data)
        return documents
    data = load_json(path)
    return [data] if data else []


def build_findings(artifacts: Mapping[str, Any]) -> dict[str, list[str]]:
    """Every module's findings, keyed by bucket.

    Reads the paths `detect_artifacts` recorded, so a page shows findings from
    exactly the files it listed as found.
    """
    findings: dict[str, list[str]] = {bucket: [] for bucket in MODULES.values()}

    for module, bucket in MODULES.items():
        meta = artifacts.get(module)
        if meta is None:
            for retired, current in RETIRED_MODULE_NAMES.items():
                if current == module:
                    meta = artifacts.get(retired)
                    break
        if not isinstance(meta, Mapping):
            continue

        extract = _EXTRACTORS[bucket]
        for raw in meta.get("paths") or []:
            path = Path(raw)
            documents = (_extension_documents(path) if bucket == "extension"
                         else [d for d in [load_json(path)] if d])
            if not documents:
                continue
            for document in documents:
                findings[bucket].extend(extract(document))
            if bucket not in _MERGE_ALL:
                break

    return {bucket: _dedupe(items) for bucket, items in findings.items()}
